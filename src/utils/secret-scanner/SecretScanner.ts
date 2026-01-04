import * as vscode from 'vscode';
import { HardcodedSecret, ScannerConfig, DetectedRange } from './types';
import { PatternRegistry } from './PatternRegistry';
import { ScannerConfigManager } from './utils/ScannerConfig';
import { logger } from '../logger';

/**
 * Main secret scanner class
 * Refactored to use dependency injection for better testability and modularity
 */
export class SecretScanner {
    private readonly patternRegistry: PatternRegistry;
    private configManager: ScannerConfigManager;

    constructor(
        patternRegistry?: PatternRegistry,
        configManager?: ScannerConfigManager
    ) {
        this.configManager = configManager || ScannerConfigManager.default();
        this.patternRegistry = patternRegistry || new PatternRegistry();
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
        let lowerText: string;
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
            
            // Only create lowercase version if file is reasonably sized
            // For very large files, we'll process line by line without full lowercase copy
            if (fullText.length < 10 * 1024 * 1024) { // < 10MB, safe to create lowercase copy
                try {
                    lowerText = fullText.toLowerCase();
                } catch (lowerError) {
                    if (lowerError instanceof RangeError && lowerError.message.includes('Invalid string length')) {
                        logger.warn(`Skipping file ${document.fileName} - file too large to create lowercase copy`);
                        lowerText = ''; // Process without lowercase copy
                    } else {
                        throw lowerError;
                    }
                }
            } else {
                // For larger files, we'll create lowercase on-demand per line
                lowerText = '';
            }
        } catch (error) {
            if (error instanceof RangeError && (error.message.includes('Invalid string length') || error.message.includes('Maximum call stack'))) {
                logger.warn(`Skipping file ${document.fileName} - file too large to process: ${error.message}`);
                return [];
            }
            throw error;
        }
        
        // Early exit: Skip if this is a scan report or RTF document
        // Only check if we have lowercase text, otherwise check line by line
        if (lowerText) {
            if (this.isScanReportDocument(fullText, lowerText, document.fileName)) {
                logger.debug(`Skipping scan report/document: ${document.fileName}`);
                return [];
            }
        } else {
            // For large files, do a quick check on first few lines
            const firstLines = lines.slice(0, 10).join('\n').toLowerCase();
            if (this.isScanReportDocument(fullText.substring(0, 1000), firstLines, document.fileName)) {
                logger.debug(`Skipping scan report/document: ${document.fileName}`);
                return [];
            }
        }
        const detectedRanges: DetectedRange[] = [];

        const sortedPatterns = this.patternRegistry.getSortedByConfidence();

        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            const line = lines[lineIndex];
            const lineNumber = lineIndex + 1;

            for (const pattern of sortedPatterns) {
                let match;
                const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);

                while ((match = regex.exec(line)) !== null) {
                    const value = match[1] || match[0]; // Use capture group if available, otherwise full match

                    // Calculate the actual range of the value in the line
                    let valueStart = match.index;
                    let valueEnd = match.index + match[0].length;

                    // If we have a capture group, adjust the range to the captured value
                    if (match[1]) {
                        valueStart = match.index + match[0].indexOf(match[1]);
                        valueEnd = valueStart + match[1].length;
                    }

                    // Check if this range is fully contained within an existing high-confidence detected range
                    const isContainedInHighConfidence = detectedRanges.some(range =>
                        range.confidence === 'high' &&
                        valueStart >= range.start &&
                        valueEnd <= range.end
                    );

                    if (isContainedInHighConfidence) {
                        logger.debug(`Skipping ${pattern.name} "${value}" - contained within high-confidence range`);
                        continue;
                    }

                    // Add this detection to our ranges
                    detectedRanges.push({
                        start: valueStart,
                        end: valueEnd,
                        confidence: pattern.confidence,
                        type: pattern.name
                    });

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
                }
            }
        }

        return secrets;
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
                    logger.warn(`⚠️ Skipping file ${vscode.workspace.asRelativePath(file.fsPath)} - file too large to process (${errorMessage})`);
                } else {
                    logger.error(`❌ Error scanning file ${vscode.workspace.asRelativePath(file.fsPath)}:`, error);
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
                logger.warn(`⚠️ File ${activeEditor.document.fileName} is too large to scan`);
                vscode.window.showWarningMessage(`File is too large to scan for secrets (maximum size: 50MB)`);
            } else {
                logger.error(`❌ Error scanning current file:`, error);
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

        const filteredFiles = files.filter(file => {
            const filePath = file.fsPath.toLowerCase();
            const shouldExclude = filePath.includes('node_modules') ||
                filePath.includes('dist') ||
                filePath.includes('build') ||
                filePath.includes('.git') ||
                filePath.includes('coverage') ||
                filePath.includes('vendor') ||
                filePath.includes('out') ||
                filePath.includes('target') ||
                filePath.includes('bin') ||
                filePath.includes('obj') ||
                filePath.includes('.vscode-test') ||
                filePath.includes('logs') ||
                filePath.includes('temp') ||
                filePath.includes('tmp') ||
                filePath.includes('.venv') ||
                filePath.includes('venv/') ||
                filePath.includes('site-packages') ||
                filePath.includes('__pycache__') ||
                filePath.includes('.pytest_cache') ||
                filePath.endsWith('package-lock.json') ||
                filePath.endsWith('yarn.lock') ||
                filePath.endsWith('.rtf') ||
                filePath.endsWith('.doc') ||
                filePath.endsWith('.docx') ||
                filePath.endsWith('.pdf') ||
                filePath.endsWith('.odt');

            if (shouldExclude) {
                logger.debug(`Excluding library file: ${vscode.workspace.asRelativePath(file.fsPath)}`);
            }

            return !shouldExclude;
        });

        logger.info(`Found ${files.length} total files, filtered to ${filteredFiles.length} project files to scan`);

        for (const file of filteredFiles) {
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
                    logger.warn(`⚠️ Skipping file ${vscode.workspace.asRelativePath(file.fsPath)} - file too large to process (${errorMessage})`);
                } else {
                    logger.error(`❌ Error scanning file ${vscode.workspace.asRelativePath(file.fsPath)}:`, error);
                }
            }
        }

        logger.info(`Project scan complete: Found ${totalSecrets} potential secrets in ${results.size} files`);
        return { results, totalFilesScanned: filteredFiles.length };
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

    /**
     * Checks if a document is a scan report or RTF/document file that should be skipped
     */
    private isScanReportDocument(fullText: string, lowerText: string, fileName: string): boolean {
        const lowerFileName = fileName.toLowerCase();
        
        // Skip RTF and document files by extension
        if (lowerFileName.endsWith('.rtf') ||
            lowerFileName.endsWith('.doc') ||
            lowerFileName.endsWith('.docx') ||
            lowerFileName.endsWith('.pdf') ||
            lowerFileName.endsWith('.odt')) {
            return true;
        }
        
        // Check for RTF format markers
        if (fullText.includes('{\\rtf1') ||
            fullText.includes('\\cocoartf') ||
            fullText.includes('\\fonttbl') ||
            fullText.includes('\\colortbl')) {
            return true;
        }
        
        // Check for scan report content indicators
        if (lowerText.includes('hardcoded secrets scan results') ||
            (lowerText.includes('scan results') && lowerText.includes('secrets found')) ||
            (lowerText.includes('file:') && lowerText.includes('path:') && 
             lowerText.includes('location: line') && lowerText.includes('value:'))) {
            // Additional check: if it has multiple "FILE:" entries, it's definitely a report
            const fileMatches = (lowerText.match(/file:/gi) || []).length;
            if (fileMatches >= 2) {
                return true;
            }
        }
        
        // Check for scan report structure (even with fewer FILE: entries)
        // Pattern: FILE: ... Path: ... Location: Line ... Value: ... Context: ...
        const hasReportStructure = lowerText.includes('file:') &&
            lowerText.includes('path:') &&
            (lowerText.includes('location:') || lowerText.includes('location: line')) &&
            lowerText.includes('value:') &&
            (lowerText.includes('context:') || lowerText.includes('scan completed'));
        
        if (hasReportStructure) {
            return true;
        }
        
        return false;
    }
}

