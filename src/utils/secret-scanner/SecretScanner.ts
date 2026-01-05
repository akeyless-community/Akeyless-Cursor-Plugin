import * as vscode from 'vscode';
import { HardcodedSecret, ScannerConfig } from './types';
import { PatternRegistry } from './PatternRegistry';
import { ScannerConfigManager } from './utils/ScannerConfig';
import { FalsePositiveFilter } from './utils/FalsePositiveFilter';
import { EnhancedEntropyAnalyzer } from './utils/EnhancedEntropyAnalyzer';
import { logger } from '../logger';

/**
 * Main secret scanner class
 * Refactored to use dependency injection for better testability and modularity
 */
export class SecretScanner {
    private readonly patternRegistry: PatternRegistry;
    private configManager: ScannerConfigManager;
    private falsePositiveFilter: FalsePositiveFilter;

    constructor(
        patternRegistry?: PatternRegistry,
        configManager?: ScannerConfigManager
    ) {
        this.configManager = configManager || ScannerConfigManager.default();
        this.patternRegistry = patternRegistry || new PatternRegistry();
        this.falsePositiveFilter = new FalsePositiveFilter(this.configManager.get());
    }

    /**
     * Scans a document for hardcoded secrets
     */
    async scanDocument(document: vscode.TextDocument): Promise<HardcodedSecret[]> {
        const secrets: HardcodedSecret[] = [];
        
        // Check file size using line count as a proxy (avoids loading full text)
        // JavaScript max string length is approximately 2^30 - 24 characters (~1GB)
        // We'll set a more reasonable limit to avoid memory issues
        // Estimate: average line length ~100 chars, so 500k lines ≈ 50MB
        const MAX_LINES = 500000; // ~50MB estimated
        
        if (document.lineCount > MAX_LINES) {
            logger.warn(`Skipping file ${document.fileName} - file too large (${document.lineCount} lines). Maximum: ${MAX_LINES} lines`);
            return [];
        }
        
        let fullText: string;
        let lines: string[];
        
        try {
            // Try to get text - this can throw RangeError for very large files
            fullText = document.getText();
            
            // Check actual size after loading
            const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
            if (fullText.length > MAX_FILE_SIZE) {
                logger.warn(`Skipping file ${document.fileName} - file too large (${(fullText.length / 1024 / 1024).toFixed(2)}MB). Maximum size: ${MAX_FILE_SIZE / 1024 / 1024}MB`);
                return [];
            }
            
            // Try to split into lines - this can also throw RangeError
            try {
                lines = fullText.split('\n');
            } catch (splitError) {
                if (splitError instanceof RangeError && splitError.message.includes('Invalid string length')) {
                    logger.warn(`Skipping file ${document.fileName} - file too large to split into lines`);
                    return [];
                }
                throw splitError;
            }
        } catch (error) {
            if (error instanceof RangeError && (error.message.includes('Invalid string length') || error.message.includes('Maximum call stack'))) {
                logger.warn(`Skipping file ${document.fileName} - file too large to process: ${error.message}`);
                return [];
            }
            throw error;
        }
        
        // Get ALL patterns to ensure comprehensive detection of all suspected secrets
        const allPatterns = this.patternRegistry.getAll();
        logger.debug(`Scanning with ${allPatterns.length} secret detection patterns`);

        // Separate patterns that need full-text matching (multiline/dotAll) from single-line patterns
        // Patterns with 's' (dotAll) flag can match across newlines, so they need full text
        // Patterns with 'm' (multiline) can also benefit from full-text matching for accuracy
        const multilinePatterns = allPatterns.filter(p => p.pattern.flags.includes('s') || p.pattern.flags.includes('m'));
        const singleLinePatterns = allPatterns.filter(p => !p.pattern.flags.includes('s') && !p.pattern.flags.includes('m'));

        // First, scan full text for multiline patterns
        for (const pattern of multilinePatterns) {
            try {
                // Ensure global flag is set for multiline patterns
                let flags = pattern.pattern.flags;
                if (!flags.includes('g')) {
                    flags += 'g';
                }
                const regex = new RegExp(pattern.pattern.source, flags);
                let match;
                let lastIndex = 0;
                const maxIterations = 10000; // Safety limit to prevent infinite loops
                let iterations = 0;

                while ((match = regex.exec(fullText)) !== null && iterations < maxIterations) {
                    iterations++;
                    // For patterns with multiple capture groups, prefer the last non-empty group (usually the value)
                    // This handles cases like: export VAR_NAME="value" where match[1] is VAR_NAME and match[2] is value
                    let value = match[0];
                    for (let i = match.length - 1; i >= 1; i--) {
                        if (match[i] && match[i].trim()) {
                            value = match[i];
                            break;
                        }
                    }
                    
                    // Calculate line number from match position
                    const textBeforeMatch = fullText.substring(0, match.index);
                    const lineNumber = (textBeforeMatch.match(/\n/g) || []).length + 1;
                    const lineStart = textBeforeMatch.lastIndexOf('\n') + 1;
                    const nextNewline = fullText.indexOf('\n', match.index);
                    const line = nextNewline !== -1 
                        ? fullText.substring(lineStart, nextNewline)
                        : fullText.substring(lineStart);
                    
                    // Calculate column position - find where the value actually starts in the line
                    let valueStart = match.index;
                    const valueIndexInMatch = match[0].indexOf(value);
                    if (valueIndexInMatch >= 0) {
                        valueStart = match.index + valueIndexInMatch;
                    }
                    const column = valueStart - lineStart + 1;
                    const context = line.trim();

                    secrets.push({
                        fileName: document.fileName,
                        lineNumber,
                        column,
                        value,
                        type: pattern.suggestion,
                        context
                    });

                    // Prevent infinite loop if regex doesn't advance
                    if (regex.lastIndex === lastIndex) {
                        regex.lastIndex++;
                    }
                    lastIndex = regex.lastIndex;
                }
            } catch (error) {
                logger.warn(`Error applying multiline pattern ${pattern.name}: ${error instanceof Error ? error.message : String(error)}`);
            }
        }

        // Then, scan line by line for single-line patterns (more efficient)
        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            const line = lines[lineIndex];
            const lineNumber = lineIndex + 1;

            for (const pattern of singleLinePatterns) {
                try {
                    // Ensure global flag is set for proper matching
                    let flags = pattern.pattern.flags;
                    if (!flags.includes('g')) {
                        flags += 'g';
                    }
                    const regex = new RegExp(pattern.pattern.source, flags);
                    let match;
                    let lastIndex = 0;
                    const maxIterations = 1000; // Safety limit per line
                    let iterations = 0;

                    while ((match = regex.exec(line)) !== null && iterations < maxIterations) {
                        iterations++;
                        // For patterns with multiple capture groups, prefer the last non-empty group (usually the value)
                        // This handles cases like: export VAR_NAME="value" where match[1] is VAR_NAME and match[2] is value
                        let value = match[0];
                        for (let i = match.length - 1; i >= 1; i--) {
                            if (match[i] && match[i].trim()) {
                                value = match[i];
                                break;
                            }
                        }

                        // Calculate the actual range of the value in the line
                        let valueStart = match.index;
                        const valueIndexInMatch = match[0].indexOf(value);
                        if (valueIndexInMatch >= 0) {
                            valueStart = match.index + valueIndexInMatch;
                        }

                        const column = valueStart + 1;
                        const context = line.trim();

                        secrets.push({
                            fileName: document.fileName,
                            lineNumber,
                            column,
                            value,
                            type: pattern.suggestion,
                            context
                        });

                        // Prevent infinite loop if regex doesn't advance
                        if (regex.lastIndex === lastIndex) {
                            regex.lastIndex++;
                        }
                        lastIndex = regex.lastIndex;
                    }
                } catch (error) {
                    logger.warn(`Error applying pattern ${pattern.name} on line ${lineNumber}: ${error instanceof Error ? error.message : String(error)}`);
                }
            }
        }

        // Entropy-based detection for high-entropy strings that don't match specific patterns
        // This catches secrets that don't have known patterns
        if (this.configManager.get().minEntropy > 0) {
            const entropySecrets = this.detectHighEntropySecrets(lines, document.fileName, secrets);
            secrets.push(...entropySecrets);
        }

        // Deduplicate secrets - same value at same location should only appear once
        const deduplicatedSecrets = this.deduplicateSecrets(secrets);
        logger.debug(`Deduplicated ${secrets.length} detected secrets to ${deduplicatedSecrets.length}`);

        // Apply false positive filtering
        const filteredSecrets = this.falsePositiveFilter.filter(deduplicatedSecrets);
        
        logger.debug(`Filtered ${deduplicatedSecrets.length} detected secrets to ${filteredSecrets.length} after false positive filtering`);
        
        return filteredSecrets;
    }

    /**
     * Deduplicates secrets - removes duplicates where the same value is detected at the same location
     * Prefers higher confidence classifications and removes redundant detections
     */
    private deduplicateSecrets(secrets: HardcodedSecret[]): HardcodedSecret[] {
        const seen = new Map<string, HardcodedSecret>();
        const confidenceOrder: { [key: string]: number } = {
            'high': 3,
            'medium': 2,
            'low': 1
        };

        for (const secret of secrets) {
            // Create a unique key based on file, line, column, and value
            const key = `${secret.fileName}:${secret.lineNumber}:${secret.column}:${secret.value.toLowerCase()}`;
            
            const existing = seen.get(key);
            if (!existing) {
                seen.set(key, secret);
            } else {
                // If we've seen this before, keep the one with higher confidence or more specific type
                const existingConfidence = confidenceOrder[existing.type.toLowerCase().includes('high') ? 'high' : 
                    existing.type.toLowerCase().includes('medium') ? 'medium' : 'low'] || 1;
                const newConfidence = confidenceOrder[secret.type.toLowerCase().includes('high') ? 'high' : 
                    secret.type.toLowerCase().includes('medium') ? 'medium' : 'low'] || 1;
                
                // Prefer more specific types (e.g., "Google API Key" over "API Key")
                const existingSpecificity = existing.type.split(' ').length;
                const newSpecificity = secret.type.split(' ').length;
                
                if (newConfidence > existingConfidence || 
                    (newConfidence === existingConfidence && newSpecificity > existingSpecificity) ||
                    (newConfidence === existingConfidence && newSpecificity === existingSpecificity && 
                     secret.type.length > existing.type.length)) {
                    seen.set(key, secret);
                }
            }
        }

        // Also remove duplicates where the same value appears multiple times with different types
        // but at overlapping positions (e.g., "Token" and "Twilio Auth Token" for same value)
        const valueMap = new Map<string, HardcodedSecret[]>();
        for (const secret of Array.from(seen.values())) {
            const _valueKey = `${secret.fileName}:${secret.lineNumber}:${secret.value.toLowerCase()}`;
            if (!valueMap.has(_valueKey)) {
                valueMap.set(_valueKey, []);
            }
            valueMap.get(_valueKey)!.push(secret);
        }

        const finalSecrets: HardcodedSecret[] = [];
        for (const [_valueKey, duplicates] of valueMap.entries()) {
            if (duplicates.length === 1) {
                finalSecrets.push(duplicates[0]);
            } else {
                // Multiple detections of same value at same location - keep the most specific
                duplicates.sort((a, b) => {
                    const aSpecificity = a.type.split(' ').length;
                    const bSpecificity = b.type.split(' ').length;
                    if (aSpecificity !== bSpecificity) {
                        return bSpecificity - aSpecificity; // More specific first
                    }
                    // Prefer types that don't include generic terms
                    const aIsGeneric = /^(token|secret|key|api[_-]?key)$/i.test(a.type);
                    const bIsGeneric = /^(token|secret|key|api[_-]?key)$/i.test(b.type);
                    if (aIsGeneric && !bIsGeneric) return 1;
                    if (!aIsGeneric && bIsGeneric) return -1;
                    return 0;
                });
                finalSecrets.push(duplicates[0]);
            }
        }

        return finalSecrets;
    }

    /**
     * Detects high-entropy strings that might be secrets but don't match specific patterns
     * Scans for strings in common secret variable contexts with high entropy
     */
    private detectHighEntropySecrets(
        lines: string[],
        fileName: string,
        existingSecrets: HardcodedSecret[]
    ): HardcodedSecret[] {
        const entropySecrets: HardcodedSecret[] = [];
        const config = this.configManager.get();
        const minEntropy = config.minEntropy;

        // Pattern to find potential secret assignments
        // Matches: key = "value", secret: "value", password="value", etc.
        const secretAssignmentPattern = /(?:secret|key|token|password|auth|api[_-]?key|access[_-]?token|private[_-]?key|credential|passwd|pwd)\s*[:=]\s*["']([^"']{16,})["']/gi;

        // Track already detected values to avoid duplicates
        const detectedValues = new Set(existingSecrets.map(s => s.value.toLowerCase()));

        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            const line = lines[lineIndex];
            const lineNumber = lineIndex + 1;

            // Skip if line is a comment
            if (/^\s*(\/\/|\/\*|#|<!--)/.test(line.trim())) {
                continue;
            }

            let match;
            while ((match = secretAssignmentPattern.exec(line)) !== null) {
                const value = match[1];
                const valueLower = value.toLowerCase();

                // Skip if already detected by pattern matching
                if (detectedValues.has(valueLower)) {
                    continue;
                }

                // Check entropy
                const entropyScore = EnhancedEntropyAnalyzer.calculateEntropyScore(value);
                
                if (entropyScore >= minEntropy) {
                    // Additional validation: should look like a secret
                    if (EnhancedEntropyAnalyzer.isHighEntropy(value, 0.5)) {
                        const column = match.index + match[0].indexOf(match[1]) + 1;
                        
                        entropySecrets.push({
                            fileName,
                            lineNumber,
                            column,
                            value,
                            type: 'High Entropy Secret',
                            context: line.trim(),
                            confidence: Math.min(0.6 + (entropyScore - minEntropy) * 0.5, 0.9),
                            entropy: entropyScore
                        });

                        detectedValues.add(valueLower);
                    }
                }
            }
        }

        return entropySecrets;
    }

    /**
     * Scans the entire workspace for hardcoded secrets
     */
    async scanWorkspace(): Promise<{ results: Map<string, HardcodedSecret[]>, totalFilesScanned: number }> {
        const results = new Map<string, HardcodedSecret[]>();
        let totalSecrets = 0;

        logger.info('Scanning current project for hardcoded secrets');

        const files = await vscode.workspace.findFiles(
            '**/*.{js,jsx,ts,tsx,json,env,yml,yaml,properties,ini,cfg,conf,env.local,env.development,env.production,txt,md,go,py,java,cs,php,rb,swift,kt,rs,cpp,c,cc,h,hpp,cxx,mm,m,vue,svelte,html,css,scss,less,sass,sh,bash,zsh,fish,ps1,ps,bat,cmd,tf,tfvars,hcl,dockerfile,sql,plsql,mysql,pgsql,r,R,lua,pl,perl,vb,vbs,f,f90,f95,f03,ml,mli,fs,fsx,ex,exs,erl,hrl,nim,cr,zig,v,vala,d,jl,el,lisp,cl,hs,lhs,elm,purescript,ocaml,scala,groovy,clj,cljs,dart,asm,s,scm,rkt,coffee,litcoffee,iced,styl,stylus,jade,pug,haml,slim,ejs,hbs,handlebars,mustache,erb,rhtml,edn,re,rei,res,resi,toml,xml,xsd,xsl,xslt}',
            '**/node_modules/**,**/dist/**,**/build/**,**/.git/**,**/coverage/**,**/.nyc_output/**,**/vendor/**,**/out/**,**/target/**,**/bin/**,**/obj/**,**/.vscode-test/**,**/coverage/**,**/.nyc_output/**,**/logs/**,**/temp/**,**/tmp/**,**/.venv/**,**/venv/**,**/site-packages/**,**/__pycache__/**,**/.pytest_cache/**,**/*.rtf,**/*.doc,**/*.docx,**/*.pdf,**/*.odt'
        );

        logger.info(`Found ${files.length} files to scan`);

        for (const file of files) {
            try {
                const document = await vscode.workspace.openTextDocument(file);
                const secrets = await this.scanDocument(document);

                if (secrets.length > 0) {
                    results.set(file.fsPath, secrets);
                    totalSecrets += secrets.length;
                    logger.debug(`Found ${secrets.length} secrets in ${vscode.workspace.asRelativePath(file.fsPath)}`);
                }
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                if (error instanceof RangeError && (errorMessage.includes('Invalid string length') || errorMessage.includes('Maximum call stack'))) {
                    logger.warn(` Skipping file ${vscode.workspace.asRelativePath(file.fsPath)} - file too large to process (${errorMessage})`);
                } else {
                    logger.error(` Error scanning file ${vscode.workspace.asRelativePath(file.fsPath)}:`, error);
                }
            }
        }

        logger.info(`Scan complete: Found ${totalSecrets} potential secrets in ${results.size} files`);
        return { results, totalFilesScanned: files.length };
    }

    /**
     * Scans only the current active file
     */
    async scanCurrentFile(): Promise<{ results: Map<string, HardcodedSecret[]>, totalFilesScanned: number }> {
        const results = new Map<string, HardcodedSecret[]>();

        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
            logger.info('No active editor found');
            return { results, totalFilesScanned: 0 };
        }

        logger.info(`Scanning current file: ${activeEditor.document.fileName}`);

        try {
            const secrets = await this.scanDocument(activeEditor.document);
            if (secrets.length > 0) {
                results.set(activeEditor.document.fileName, secrets);
                logger.info(`Found ${secrets.length} potential secrets in current file`);
            } else {
                logger.info('No secrets found in current file');
            }
        } catch (error) {
            if (error instanceof RangeError && error.message.includes('Invalid string length')) {
                logger.warn(` File ${activeEditor.document.fileName} is too large to scan`);
                vscode.window.showWarningMessage(`File is too large to scan for secrets (maximum size: 50MB)`);
            } else {
                logger.error(` Error scanning current file:`, error);
            }
        }

        return { results, totalFilesScanned: 1 };
    }

    /**
     * Scans only the current project directory (excludes libraries)
     */
    async scanCurrentProject(): Promise<{ results: Map<string, HardcodedSecret[]>, totalFilesScanned: number }> {
        const results = new Map<string, HardcodedSecret[]>();
        let totalSecrets = 0;

        logger.info('Scanning current project directory for hardcoded secrets');

        const workspaceRoot = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceRoot) {
            logger.error('No workspace root found');
            return { results, totalFilesScanned: 0 };
        }

        const files = await vscode.workspace.findFiles(
            '**/*.{js,jsx,ts,tsx,json,env,yml,yaml,properties,ini,cfg,conf,env.local,env.development,env.production,txt,md,go,py,java,cs,php,rb,swift,kt,rs,cpp,c,cc,h,hpp,cxx,mm,m,vue,svelte,html,css,scss,less,sass,sh,bash,zsh,fish,ps1,ps,bat,cmd,tf,tfvars,hcl,dockerfile,sql,plsql,mysql,pgsql,r,R,lua,pl,perl,vb,vbs,f,f90,f95,f03,ml,mli,fs,fsx,ex,exs,erl,hrl,nim,cr,zig,v,vala,d,jl,el,lisp,cl,hs,lhs,elm,purescript,ocaml,scala,groovy,clj,cljs,dart,asm,s,scm,rkt,coffee,litcoffee,iced,styl,stylus,jade,pug,haml,slim,ejs,hbs,handlebars,mustache,erb,rhtml,edn,re,rei,res,resi,toml,xml,xsd,xsl,xslt}',
            '**/node_modules/**,**/dist/**,**/build/**,**/.git/**,**/coverage/**,**/.nyc_output/**,**/vendor/**,**/out/**,**/target/**,**/bin/**,**/obj/**,**/.vscode-test/**,**/logs/**,**/temp/**,**/tmp/**,**/.venv/**,**/venv/**,**/site-packages/**,**/__pycache__/**,**/.pytest_cache/**,**/package-lock.json,**/yarn.lock,**/*.rtf,**/*.doc,**/*.docx,**/*.pdf,**/*.odt'
        );

        logger.info(`Found ${files.length} files to scan`);

        for (const file of files) {
            try {
                const document = await vscode.workspace.openTextDocument(file);
                const secrets = await this.scanDocument(document);

                if (secrets.length > 0) {
                    results.set(file.fsPath, secrets);
                    totalSecrets += secrets.length;
                    logger.debug(`Found ${secrets.length} secrets in ${vscode.workspace.asRelativePath(file.fsPath)}`);
                }
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                if (error instanceof RangeError && (errorMessage.includes('Invalid string length') || errorMessage.includes('Maximum call stack'))) {
                    logger.warn(` Skipping file ${vscode.workspace.asRelativePath(file.fsPath)} - file too large to process (${errorMessage})`);
                } else {
                    logger.error(` Error scanning file ${vscode.workspace.asRelativePath(file.fsPath)}:`, error);
                }
            }
        }

        logger.info(`Project scan complete: Found ${totalSecrets} potential secrets in ${results.size} files`);
        return { results, totalFilesScanned: files.length };
    }

    /**
     * Configures the scanner behavior
     */
    configure(options: {
        developmentMode?: boolean;
        minEntropy?: number;
        skipDevelopmentValues?: boolean;
    }): void {
        const updates: Partial<ScannerConfig> = {};

        if (options.developmentMode !== undefined) {
            updates.developmentMode = options.developmentMode;
        }
        if (options.minEntropy !== undefined) {
            updates.minEntropy = options.minEntropy;
        }
        if (options.skipDevelopmentValues !== undefined) {
            updates.skipDevelopmentValues = options.skipDevelopmentValues;
        }

        this.configManager = this.configManager.with(updates);
        this.falsePositiveFilter.updateConfig(this.configManager.get());

        logger.info('Scanner configuration updated:', this.configManager.get());
    }

    /**
     * Generates a suggested name for a secret based on its context
     */
    generateSecretName(secret: HardcodedSecret, fileName: string): string {
        const baseName = fileName.split('/').pop()?.replace(/\.[^/.]+$/, '') || 'unknown';
        const timestamp = Date.now();

        const contextLower = secret.context.toLowerCase();
        let type = 'secret';

        if (contextLower.includes('api') || contextLower.includes('key')) {
            type = 'api-key';
        } else if (contextLower.includes('password') || contextLower.includes('passwd')) {
            type = 'password';
        } else if (contextLower.includes('token')) {
            type = 'token';
        } else if (contextLower.includes('database') || contextLower.includes('db')) {
            type = 'database-url';
        }

        return `/secrets/${baseName}-${type}-${timestamp}`;
    }

    // Static methods for backward compatibility
    private static defaultInstance: SecretScanner | null = null;

    private static getDefaultInstance(): SecretScanner {
        if (!SecretScanner.defaultInstance) {
            SecretScanner.defaultInstance = new SecretScanner();
        }
        return SecretScanner.defaultInstance;
    }

    static async scanDocument(document: vscode.TextDocument): Promise<HardcodedSecret[]> {
        return SecretScanner.getDefaultInstance().scanDocument(document);
    }

    static async scanWorkspace(): Promise<{ results: Map<string, HardcodedSecret[]>, totalFilesScanned: number }> {
        return SecretScanner.getDefaultInstance().scanWorkspace();
    }

    static async scanCurrentFile(): Promise<{ results: Map<string, HardcodedSecret[]>, totalFilesScanned: number }> {
        return SecretScanner.getDefaultInstance().scanCurrentFile();
    }

    static async scanCurrentProject(): Promise<{ results: Map<string, HardcodedSecret[]>, totalFilesScanned: number }> {
        return SecretScanner.getDefaultInstance().scanCurrentProject();
    }

    static configure(options: {
        developmentMode?: boolean;
        minEntropy?: number;
        skipDevelopmentValues?: boolean;
    }): void {
        SecretScanner.getDefaultInstance().configure(options);
    }

    static generateSecretName(secret: HardcodedSecret, fileName: string): string {
        return SecretScanner.getDefaultInstance().generateSecretName(secret, fileName);
    }
}

