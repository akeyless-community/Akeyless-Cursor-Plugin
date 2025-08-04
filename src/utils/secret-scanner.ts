import * as vscode from 'vscode';
import { logger } from './logger';

export interface HardcodedSecret {
    fileName: string;
    lineNumber: number;
    column: number;
    value: string;
    type: string;
    context: string;
}

export class SecretScanner {
    private static readonly SECRET_PATTERNS = [
        // Cloud Provider Keys
        {
            name: 'Google API Key',
            pattern: /AIza[0-9A-Za-z\-_]{35}/g,
            suggestion: 'Google API Key',
            confidence: 'high'
        },
        {
            name: 'AWS Access Key',
            pattern: /AKIA[0-9A-Z]{16}/g,
            suggestion: 'AWS Access Key',
            confidence: 'high'
        },
        {
            name: 'AWS Secret Key',
            pattern: /[0-9a-zA-Z/+]{40}(?![0-9a-zA-Z/+])/g,
            suggestion: 'AWS Secret Key',
            confidence: 'high'
        },
        {
            name: 'AWS Session Token',
            pattern: /(?:aws[_-]?session[_-]?token|session_token)\s*[:=]\s*[\"\']?([A-Za-z0-9+/]{300,})[\"\']?/gi,
            suggestion: 'AWS Session Token',
            confidence: 'high'
        },
        {
            name: 'Azure Storage Account Key',
            pattern: /[a-zA-Z0-9]{88}/g,
            suggestion: 'Azure Storage Account Key',
            confidence: 'high'
        },
        {
            name: 'GCP Service Account Key',
            pattern: /\"type\":\s*\"service_account\".*\"private_key\":\s*\"-----BEGIN\s+PRIVATE\s+KEY-----/gs,
            suggestion: 'GCP Service Account Key',
            confidence: 'high'
        },
        
        // API Keys & Tokens
        {
            name: 'GitHub Token',
            pattern: /gh[po][_][0-9a-zA-Z]{36}/g,
            suggestion: 'GitHub Token',
            confidence: 'high'
        },
        {
            name: 'GitHub App Token',
            pattern: /ghs_[a-zA-Z0-9]{36}/g,
            suggestion: 'GitHub App Token',
            confidence: 'high'
        },
        {
            name: 'Slack Token',
            pattern: /xox[p|b|o|a]-[A-Za-z0-9\-]+/g,
            suggestion: 'Slack Token',
            confidence: 'high'
        },
        {
            name: 'Stripe Key',
            pattern: /sk_live_[0-9a-zA-Z]{24}/g,
            suggestion: 'Stripe Key',
            confidence: 'high'
        },
        {
            name: 'Stripe Publishable Key',
            pattern: /pk_live_[0-9a-zA-Z]{24}/g,
            suggestion: 'Stripe Publishable Key',
            confidence: 'high'
        },
        {
            name: 'Firebase Key',
            pattern: /AIza[0-9A-Za-z\-_]{35}/g,
            suggestion: 'Firebase Key',
            confidence: 'high'
        },
        {
            name: 'Discord Bot Token',
            pattern: /[MN][a-zA-Z0-9]{23}\.[\w-]{6}\.[\w-]{27}/g,
            suggestion: 'Discord Bot Token',
            confidence: 'high'
        },
        {
            name: 'Telegram Bot Token',
            pattern: /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/g,
            suggestion: 'Telegram Bot Token',
            confidence: 'high'
        },
        
        // Cryptographic Keys
        {
            name: 'Private Key',
            pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\\s\\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
            suggestion: 'Private Key',
            confidence: 'high'
        },
        {
            name: 'SSH Private Key',
            pattern: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\\s\\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----/g,
            suggestion: 'SSH Private Key',
            confidence: 'high'
        },
        {
            name: 'PGP Private Key',
            pattern: /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/g,
            suggestion: 'PGP Private Key',
            confidence: 'high'
        },
        
        // Tokens & Authentication
        {
            name: 'JWT Token',
            pattern: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*/g,
            suggestion: 'JWT Token',
            confidence: 'high'
        },
        {
            name: 'OAuth Token',
            pattern: /(?:oauth[_-]?token|access[_-]?token|bearer[_-]?token)\s*[:=]\s*[\"\']?([a-zA-Z0-9\-._~+/]{20,})[\"\']?/gi,
            suggestion: 'OAuth Token',
            confidence: 'medium'
        },
        
        // Database Credentials
        {
            name: 'MongoDB Connection String',
            pattern: /mongodb(\+srv)?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=]+/g,
            suggestion: 'MongoDB Connection String',
            confidence: 'high'
        },
        {
            name: 'PostgreSQL Connection String',
            pattern: /postgresql:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=]+/g,
            suggestion: 'PostgreSQL Connection String',
            confidence: 'high'
        },
        {
            name: 'MySQL Connection String',
            pattern: /mysql:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=]+/g,
            suggestion: 'MySQL Connection String',
            confidence: 'high'
        },
        
        // MEDIUM CONFIDENCE PATTERNS (Context-based detection)
        {
            name: 'Gemini API Key',
            pattern: /(?:gemini[_-]?api[_-]?key|gemini_api_key)\s*[:=]\s*[\"\']?([^\"\'\s]{20,})[\"\']?/gi,
            suggestion: 'Gemini API Key',
            confidence: 'medium'
        },
        {
            name: 'OpenAI API Key',
            pattern: /(?:openai[_-]?api[_-]?key|openai_api_key)\s*[:=]\s*[\"\']?([^\"\'\s]{20,})[\"\']?/gi,
            suggestion: 'OpenAI API Key',
            confidence: 'medium'
        },
        {
            name: 'API Key',
            pattern: /(?:api[_-]?key|apikey|api_key)\s*[:=]\s*[\"\']?([^\"\'\s]{20,})[\"\']?/gi,
            suggestion: 'API Key',
            confidence: 'medium'
        },
        {
            name: 'Password',
            pattern: /(?:password|passwd|pwd)\s*[:=]\s*[\"\']?([^\"\'\s]{8,})[\"\']?/gi,
            suggestion: 'Password',
            confidence: 'medium'
        },
        {
            name: 'Token',
            pattern: /(?:token|access[_-]?token)\s*[:=]\s*[\"\']?([^\"\'\s]{20,100})[\"\']?/gi,
            suggestion: 'Token',
            confidence: 'medium'
        },
        {
            name: 'Database URL',
            pattern: /(?:database|db)[_-]?url\s*[:=]\s*[\"\']?([^\"\'\s]{20,})[\"\']?/gi,
            suggestion: 'Database URL',
            confidence: 'medium'
        },
        {
            name: 'Connection String',
            pattern: /(?:connection[_-]?string|conn[_-]?string)\s*[:=]\s*[\"\']?([^\"\'\s]{20,})[\"\']?/gi,
            suggestion: 'Connection String',
            confidence: 'medium'
        },
        {
            name: 'Secret',
            pattern: /(?:secret|private[_-]?key)\s*[:=]\s*[\"\']?([^\"\'\s]{20,})[\"\']?/gi,
            suggestion: 'Secret',
            confidence: 'medium'
        },
        {
            name: 'Go Secret Assignment',
            pattern: /(?:secret|key|token|password)\s*[:=]\s*[\"\']([^\"\']{10,})[\"\']/gi,
            suggestion: 'Go Secret Assignment',
            confidence: 'medium'
        },
        
        // Cloud Provider Specific
        {
            name: 'AWS IAM Role ARN',
            pattern: /arn:aws:iam::[0-9]{12}:role\/[a-zA-Z0-9\-_]+/g,
            suggestion: 'AWS IAM Role ARN',
            confidence: 'medium'
        },
        {
            name: 'AWS S3 Bucket',
            pattern: /s3:\/\/[a-zA-Z0-9\-_]+/g,
            suggestion: 'AWS S3 Bucket',
            confidence: 'medium'
        },
        
        // Environment Variables
        {
            name: 'Environment Variable',
            pattern: /(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*[:=]\s*[\"\']([^\"\']{10,})[\"\']/g,
            suggestion: 'Environment Variable',
            confidence: 'medium'
        }
    ];

    private static readonly SCANNER_CONFIG = {
        // Set to true to be more lenient with development environments
        developmentMode: true,
        minEntropy: 4.0, // Increased for Go files
        // Skip common development values
        skipDevelopmentValues: true,
        // Enhanced entropy thresholds for different secret types
        entropyThresholds: {
            apiKey: 3.5, // Increased for Go files
            password: 3.0, // Increased for Go files
            token: 4.0, // Increased for Go files
            connectionString: 3.5 // Increased for Go files
        }
    };

    /**
     * Scans a document for hardcoded secrets
     */
    static async scanDocument(document: vscode.TextDocument): Promise<HardcodedSecret[]> {
        const secrets: HardcodedSecret[] = [];
        const lines = document.getText().split('\n');
        const detectedRanges: Array<{
            start: number;
            end: number;
            confidence: string;
            type: string;
        }> = [];

        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            const line = lines[lineIndex];
            const lineNumber = lineIndex + 1;

            // Sort patterns by confidence (high first) to prioritize better matches
            const sortedPatterns = [...this.SECRET_PATTERNS].sort((a, b) => {
                if (a.confidence === 'high' && b.confidence !== 'high') return -1;
                if (b.confidence === 'high' && a.confidence !== 'high') return 1;
                return 0;
            });

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
                    
                    // Skip if it's a false positive
                    if (this.isFalsePositive(value, line, pattern)) {
                        continue;
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
    static async scanWorkspace(): Promise<{results: Map<string, HardcodedSecret[]>, totalFilesScanned: number}> {
        const results = new Map<string, HardcodedSecret[]>();
        let totalSecrets = 0;
        
        logger.info('Scanning current project for hardcoded secrets');
        
        // Only scan the current project files, exclude all library and build directories
        const files = await vscode.workspace.findFiles(
            '**/*.{js,jsx,ts,tsx,json,env,yml,yaml,properties,ini,cfg,conf,env.local,env.development,env.production,txt,md}',
            '**/node_modules/**,**/dist/**,**/build/**,**/.git/**,**/coverage/**,**/.nyc_output/**,**/vendor/**,**/out/**,**/target/**,**/bin/**,**/obj/**,**/.vscode-test/**,**/coverage/**,**/.nyc_output/**,**/logs/**,**/temp/**,**/tmp/**'
        );

        logger.info(`Found ${files.length} files to scan`);

        // Scan files sequentially (simpler and more reliable)
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
                logger.error(`❌ Error scanning file ${file.fsPath}:`, error);
            }
        }

        logger.info(`Scan complete: Found ${totalSecrets} potential secrets in ${results.size} files`);
        return { results, totalFilesScanned: files.length };
    }

    /**
     * Scans only the current active file
     */
    static async scanCurrentFile(): Promise<{results: Map<string, HardcodedSecret[]>, totalFilesScanned: number}> {
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
            logger.error(`❌ Error scanning current file:`, error);
        }

        return { results, totalFilesScanned: 1 };
    }

    /**
     * Scans only the current project directory (excludes libraries)
     */
    static async scanCurrentProject(): Promise<{results: Map<string, HardcodedSecret[]>, totalFilesScanned: number}> {
        const results = new Map<string, HardcodedSecret[]>();
        let totalSecrets = 0;
        
        logger.info('Scanning current project directory for hardcoded secrets');
        
        // Get the workspace root
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceRoot) {
            logger.error('No workspace root found');
            return { results, totalFilesScanned: 0 };
        }

        // Only scan files in the current project, exclude all library directories
        const files = await vscode.workspace.findFiles(
            '**/*.{js,jsx,ts,tsx,json,env,yml,yaml,properties,ini,cfg,conf,env.local,env.development,env.production,txt,md}',
            '**/node_modules/**,**/dist/**,**/build/**,**/.git/**,**/coverage/**,**/.nyc_output/**,**/vendor/**,**/out/**,**/target/**,**/bin/**,**/obj/**,**/.vscode-test/**,**/logs/**,**/temp/**,**/tmp/**,**/package-lock.json,**/yarn.lock'
        );

        // Additional filter to exclude node_modules and other library files
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
                   filePath.endsWith('package-lock.json') ||
                   filePath.endsWith('yarn.lock');
            
            if (shouldExclude) {
                logger.debug(`Excluding library file: ${vscode.workspace.asRelativePath(file.fsPath)}`);
            }
            
            return !shouldExclude;
        });

        logger.info(`Found ${files.length} total files, filtered to ${filteredFiles.length} project files to scan`);

        // Scan files sequentially
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
                logger.error(`❌ Error scanning file ${file.fsPath}:`, error);
            }
        }

        logger.info(`Project scan complete: Found ${totalSecrets} potential secrets in ${results.size} files`);
        return { results, totalFilesScanned: filteredFiles.length };
    }

    /**
     * Configures the scanner behavior
     */
    static configure(options: {
        developmentMode?: boolean;
        minEntropy?: number;
        skipDevelopmentValues?: boolean;
    }): void {
        if (options.developmentMode !== undefined) {
            this.SCANNER_CONFIG.developmentMode = options.developmentMode;
        }
        if (options.minEntropy !== undefined) {
            this.SCANNER_CONFIG.minEntropy = options.minEntropy;
        }
        if (options.skipDevelopmentValues !== undefined) {
            this.SCANNER_CONFIG.skipDevelopmentValues = options.skipDevelopmentValues;
        }
        
        logger.info('Scanner configuration updated:', this.SCANNER_CONFIG);
    }


    /**
     * Calculates entropy of a string (measure of randomness)
     */
    private static calculateEntropy(str: string): number {
        if (!str || str.length === 0) return 0;
        
        const charCounts = new Map<string, number>();
        for (const char of str) {
            charCounts.set(char, (charCounts.get(char) || 0) + 1);
        }
        
        let entropy = 0;
        const length = str.length;
        
        for (const count of charCounts.values()) {
            const probability = count / length;
            entropy -= probability * Math.log2(probability);
        }
        
        // Consider character set diversity
        const uniqueChars = charCounts.size;
        const maxPossibleChars = 95; // Printable ASCII characters
        const diversityBonus = Math.min(uniqueChars / maxPossibleChars, 1) * 0.5;
        
        // Length bonus for longer strings
        const lengthBonus = Math.min(str.length / 50, 1) * 0.3;
        
        return entropy + diversityBonus + lengthBonus;
    }

    /**
     * Checks if a detected value is a false positive using sophisticated analysis
     */
    private static isFalsePositive(value: string, line: string, pattern?: any): boolean {
        const lowerValue = value.toLowerCase();
        const lowerLine = line.toLowerCase();
        
        // Apply stricter filtering for Go files
        const isGoFile = line.includes('.go') || lowerLine.includes('package ') || 
                        lowerLine.includes('import ') || lowerLine.includes('func ') ||
                        lowerLine.includes('var ') || lowerLine.includes('const ') ||
                        lowerLine.includes('type ') || lowerLine.includes('struct ') ||
                        lowerLine.includes('interface ') || lowerLine.includes('fmt.') ||
                        lowerLine.includes('log.') || lowerLine.includes('http.') ||
                        lowerLine.includes('mux.') || lowerLine.includes('gin.') ||
                        lowerLine.includes('echo.') || lowerLine.includes('fiber.');
        
        if (pattern && pattern.confidence === 'high') {
            // Only filter high confidence patterns if they're clearly false positives
            if (this.isClearlyFalsePositive(value, line)) {
                logger.debug(`Filtered high-confidence pattern "${pattern.name}": "${value}"`);
                return true;
            }
            return false;
        }
        

        if (pattern && pattern.confidence === 'medium') {
            const entropy = this.calculateEntropy(value);
            
            // Get specific threshold based on pattern type
            let threshold = this.SCANNER_CONFIG.minEntropy;
            if (pattern.name.toLowerCase().includes('api')) {
                threshold = this.SCANNER_CONFIG.entropyThresholds.apiKey;
            } else if (pattern.name.toLowerCase().includes('password')) {
                threshold = this.SCANNER_CONFIG.entropyThresholds.password;
            } else if (pattern.name.toLowerCase().includes('token')) {
                threshold = this.SCANNER_CONFIG.entropyThresholds.token;
            } else if (pattern.name.toLowerCase().includes('connection')) {
                threshold = this.SCANNER_CONFIG.entropyThresholds.connectionString;
            }
            
            // Apply stricter filtering for Go files
            if (isGoFile) {
                threshold += 0.5; // Increase threshold for Go files
            }
            
            // Low entropy indicates it's likely not a real secret
            if (entropy < threshold) {
                logger.debug(`Filtered by low entropy (${entropy.toFixed(2)} < ${threshold}): "${value}"`);
                return true;
            }
        }
        
        // Skip if contains common false positive keywords
        if (lowerValue.includes('example') || lowerValue.includes('dummy') || 
            lowerValue.includes('placeholder') || lowerValue.includes('sample') ||
            lowerValue.includes('your-') || lowerValue.includes('your_') ||
            lowerValue.includes('replace-') || lowerValue.includes('replace_') ||
            lowerValue.includes('add-') || lowerValue.includes('add_')) {
            logger.debug(`Filtered by false positive keyword: "${value}"`);
            return true;
        }
        
        // Only skip 'test' if it's clearly a test pattern, not if it's part of a real key
        if (lowerValue === 'test' || lowerValue === 'testing') {
            logger.debug(`Filtered by test keyword: "${value}"`);
            return true;
        }
        
        // Skip common HTTP headers and content types
        if (lowerValue.includes('application/json') || lowerValue.includes('application/xml') || 
            lowerValue.includes('text/html') || lowerValue.includes('text/plain') ||
            lowerValue.includes('multipart/form-data') || lowerValue.includes('application/x-www-form-urlencoded')) {
            logger.debug(`Filtered by content type: "${value}"`);
            return true;
        }
        
        // Skip common MIME types
        if (lowerValue.includes('image/') || lowerValue.includes('video/') || lowerValue.includes('audio/')) {
            logger.debug(`Filtered by MIME type: "${value}"`);
            return true;
        }
        
        // Skip common HTTP methods
        if (lowerValue === 'get' || lowerValue === 'post' || lowerValue === 'put' || 
            lowerValue === 'delete' || lowerValue === 'patch') {
            logger.debug(`Filtered by HTTP method: "${value}"`);
            return true;
        }
        
        // Skip common HTTP status codes
        if (lowerValue === '200' || lowerValue === '201' || lowerValue === '400' || 
            lowerValue === '401' || lowerValue === '403' || lowerValue === '404' || 
            lowerValue === '500' || lowerValue === '502' || lowerValue === '503') {
            logger.debug(`Filtered by HTTP status code: "${value}"`);
            return true;
        }
        
        // Skip common file extensions and paths
        if (lowerValue.includes('.js') || lowerValue.includes('.ts') || lowerValue.includes('.jsx') || 
            lowerValue.includes('.tsx') || lowerValue.includes('.json') || lowerValue.includes('.css') ||
            lowerValue.includes('.html') || lowerValue.includes('.svg') || lowerValue.includes('.png') ||
            lowerValue.includes('.jpg') || lowerValue.includes('.jpeg') || lowerValue.includes('.gif') ||
            lowerValue.includes('/bin/') || lowerValue.includes('/dist/') || lowerValue.includes('/node_modules/') ||
            lowerValue.includes('/src/') || lowerValue.includes('/build/') || lowerValue.includes('/public/')) {
            logger.debug(`Filtered by file extension/path: "${value}"`);
            return true;
        }
        
        // Skip common programming terms and build tools
        if (lowerValue.includes('function') || lowerValue.includes('const') || lowerValue.includes('let') ||
            lowerValue.includes('var') || lowerValue.includes('return') || lowerValue.includes('import') ||
            lowerValue.includes('export') || lowerValue.includes('default') || lowerValue.includes('async') ||
            lowerValue.includes('await') || lowerValue.includes('try') || lowerValue.includes('catch') ||
            lowerValue.includes('rollup') || lowerValue.includes('autoprefixer') || lowerValue.includes('webpack') ||
            lowerValue.includes('babel') || lowerValue.includes('eslint') || lowerValue.includes('prettier') ||
            lowerValue.includes('jest') || lowerValue.includes('mocha') || lowerValue.includes('chai')) {
            logger.debug(`Filtered by programming term: "${value}"`);
            return true;
        }
        
        // Go-specific false positives
        if (lowerValue.includes('.') && (lowerValue.includes('request') || lowerValue.includes('response') ||
            lowerValue.includes('finding') || lowerValue.includes('extrafields') || lowerValue.includes('addr') ||
            lowerValue.includes('http') || lowerValue.includes('service') || lowerValue.includes('session') ||
            lowerValue.includes('context') || lowerValue.includes('error') || lowerValue.includes('result') ||
            lowerValue.includes('data') || lowerValue.includes('config') || lowerValue.includes('client') ||
            lowerValue.includes('server') || lowerValue.includes('handler') || lowerValue.includes('router') ||
            lowerValue.includes('middleware') || lowerValue.includes('database') || lowerValue.includes('store') ||
            lowerValue.includes('model') || lowerValue.includes('struct') || lowerValue.includes('interface'))) {
            logger.debug(`Filtered by Go struct field access: "${value}"`);
            return true;
        }
        
        // Skip Go package imports and struct field access patterns
        if (value.includes('.') && !value.includes('=') && !value.includes(':') && 
            (value.match(/^[A-Z][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*/) || 
             value.match(/^[a-z][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*/) ||
             value.match(/^[a-z][a-zA-Z0-9]*\.[a-z][a-zA-Z0-9]*/))) {
            logger.debug(`Filtered by Go package/struct pattern: "${value}"`);
            return true;
        }
        
        // Don't filter out JWT tokens (they contain dots but are valid secrets)
        if (value.startsWith('eyJ') && value.includes('.') && value.length > 50) {
            logger.debug(`Not filtering JWT token: "${value}"`);
            return false;
        }
        
        // IMPROVED: Better development vs production detection
        if (this.SCANNER_CONFIG.skipDevelopmentValues && this.isDevelopmentValue(value, line)) {
            logger.debug(`Filtered by development value: "${value}"`);
            return true;
        }
        
        // SPECIAL CASE: Markdown files often contain documentation and examples
        if (pattern && pattern.confidence === 'medium' && 
            (lowerValue.includes('your-') || lowerValue.includes('your_') || 
             lowerValue.includes('example-') || lowerValue.includes('example_') ||
             lowerValue.includes('sample-') || lowerValue.includes('sample_') ||
             lowerValue.includes('placeholder-') || lowerValue.includes('placeholder_'))) {
            logger.debug(`Filtered example value in documentation: "${value}"`);
            return true;
        }
        
        // SPECIAL CASE: AWS Session Token handling
        // If this is an AWS Secret Key pattern and the line contains SESSION_TOKEN,
        // and the value is exactly 40 characters, it's likely a substring of the session token
        if (pattern && pattern.name === 'AWS Secret Key' && 
            lowerLine.includes('session_token') && value.length === 40) {
            logger.debug(`Filtered AWS Secret Key as part of AWS Session Token: "${value}"`);
            return true;
        }
        
        // SPECIAL CASE: Very long tokens (likely session tokens) should not be matched by generic patterns
        if (pattern && pattern.confidence === 'medium' && value.length > 200) {
            logger.debug(`Filtered very long token by generic pattern: "${value}"`);
            return true;
        }
        
        // SPECIAL CASE: Environment variable names (not actual secrets)
        if (value.includes('_') && value === value.toUpperCase() && 
            (value.includes('AWS_') || value.includes('GCP_') || value.includes('AZURE_') || 
             value.includes('DATABASE_') || value.includes('API_') || value.includes('SECRET_'))) {
            logger.debug(`Filtered environment variable name: "${value}"`);
            return true;
        }
        
        // SPECIAL CASE: README files often contain example values
        if (pattern && pattern.confidence === 'medium' && 
            (lowerValue.includes('your-') || lowerValue.includes('your_') || 
             lowerValue.includes('example-') || lowerValue.includes('example_') ||
             lowerValue.includes('sample-') || lowerValue.includes('sample_'))) {
            logger.debug(`Filtered example value in README: "${value}"`);
            return true;
        }
        
        // Skip if it's clearly not a secret (too short, too simple, or just common words)
        if (value.length < 10 || /^[a-z]+$/i.test(value) || 
            lowerValue.includes('true') || lowerValue.includes('false') || lowerValue.includes('null') ||
            lowerValue.includes('undefined') || lowerValue.includes('nan')) {
            logger.debug(`Filtered by simple value: "${value}"`);
            return true;
        }
        
        return false;
    }

    /**
     * NEW: Checks if a value is likely a development/test value
     */
    private static isDevelopmentValue(value: string, line: string): boolean {
        const lowerValue = value.toLowerCase();
        const lowerLine = line.toLowerCase();
        
        // Skip common development passwords
        if (lowerValue === 'password' || lowerValue === 'pass' || lowerValue === 'pwd' ||
            lowerValue === 'admin' || lowerValue === 'root' || lowerValue === 'user' ||
            lowerValue === 'test' || lowerValue === 'demo' || lowerValue === 'dev' ||
            lowerValue === 'development' || lowerValue === 'staging') {
            return true;
        }
        
        // Skip localhost URLs and common dev ports
        if (lowerValue.includes('localhost') || lowerValue.includes('127.0.0.1') ||
            lowerValue.includes(':3000') || lowerValue.includes(':8080') || 
            lowerValue.includes(':5432') || lowerValue.includes(':27017') ||
            lowerValue.includes(':6379') || lowerValue.includes(':7687')) {
            return true;
        }
        
        // Skip common development database credentials
        if (lowerValue === 'neo4j' || lowerValue === 'postgres' || lowerValue === 'mysql' ||
            lowerValue === 'mongodb' || lowerValue === 'redis') {
            return true;
        }
        
        // Skip if the line contains development indicators
        if (lowerLine.includes('debug') || lowerLine.includes('development') || 
            lowerLine.includes('staging') || lowerLine.includes('test') ||
            lowerLine.includes('optional') || lowerLine.includes('local')) {
            return true;
        }
        
        // Go-specific development patterns
        if (lowerLine.includes('fmt.printf') || lowerLine.includes('log.printf') || 
            lowerLine.includes('fmt.fprintf') || lowerLine.includes('log.fatal') ||
            lowerLine.includes('http.handlefunc') || lowerLine.includes('mux.handlefunc') ||
            lowerLine.includes('func(') || lowerLine.includes('return') ||
            lowerLine.includes('if ') || lowerLine.includes('for ') || lowerLine.includes('switch ') ||
            lowerLine.includes('case ') || lowerLine.includes('default:') ||
            lowerLine.includes('var ') || lowerValue.includes('const ') ||
            lowerLine.includes('type ') || lowerLine.includes('struct ') ||
            lowerLine.includes('interface ') || lowerLine.includes('package ')) {
            return true;
        }
        
        // Skip if it's a simple boolean or common dev value
        if (lowerValue === 'true' || lowerValue === 'false' || lowerValue === 'yes' || 
            lowerValue === 'no' || lowerValue === 'on' || lowerValue === 'off') {
            return true;
        }
        
        return false;
    }

    /**
     * Checks if a high-confidence pattern is clearly a false positive
     */
    private static isClearlyFalsePositive(value: string, line: string): boolean {
        const lowerValue = value.toLowerCase();
        const lowerLine = line.toLowerCase();
        
        // Skip if contains common false positive keywords
        if (lowerValue.includes('example') || lowerValue.includes('dummy') || 
            lowerValue.includes('placeholder') || lowerValue.includes('sample')) {
            return true;
        }
        
        // Skip if it's clearly a test or example
        if (lowerValue === 'test' || lowerValue === 'testing' || lowerValue === 'example') {
            return true;
        }
        
        // Skip common HTTP headers and content types
        if (lowerValue.includes('application/json') || lowerValue.includes('application/xml') || 
            lowerValue.includes('text/html') || lowerValue.includes('text/plain')) {
            return true;
        }
        
        // Skip if it's clearly not a secret (too short or simple)
        if (value.length < 10 || /^[a-z]+$/i.test(value)) {
            return true;
        }
        
        // Skip Go struct field access patterns (e.g., "finding.Finding.ExtraFields")
        if (value.includes('.') && !value.includes('=') && !value.includes(':') && 
            (value.match(/^[a-zA-Z][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*/) ||
             value.match(/^[a-zA-Z][a-zA-Z0-9]*\.[a-zA-Z][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*/))) {
            return true;
        }
        
        // Don't filter out JWT tokens (they contain dots but are valid secrets)
        if (value.startsWith('eyJ') && value.includes('.') && value.length > 50) {
            return false;
        }
        
        return false;
    }

    /**
     * Generates a suggested name for a secret based on its context
     */
    static generateSecretName(secret: HardcodedSecret, fileName: string): string {
        const baseName = fileName.split('/').pop()?.replace(/\.[^/.]+$/, '') || 'unknown';
        const timestamp = Date.now();
        
        // Try to extract a meaningful name from the context
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
} 