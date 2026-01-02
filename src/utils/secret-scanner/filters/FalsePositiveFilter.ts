import { SecretPattern, ScannerConfig } from '../types';
import { EntropyCalculator } from '../utils/EntropyCalculator';
import { logger } from '../../logger';

/**
 * Filters false positives from secret detections
 * Breaks down complex filtering logic into smaller, testable methods
 */
export class FalsePositiveFilter {
    private readonly config: ScannerConfig;

    constructor(config: ScannerConfig) {
        this.config = config;
    }

    /**
     * Main method to check if a detected value is a false positive
     */
    isFalsePositive(value: string, line: string, pattern?: SecretPattern): boolean {
        const lowerValue = value.toLowerCase();
        const lowerLine = line.toLowerCase();
        const isGoFile = this.isGoFile(line, lowerLine);

        // Early exit checks for common false positives
        // Check if this is scan report content (meta-scanning)
        if (this.isScanReportContent(lowerLine)) {
            logger.debug(`Filtered scan report content: "${value}"`);
            return true;
        }

        if (this.isJsonSchemaReference(value)) {
            logger.debug(`Filtered JSON schema reference: "${value}"`);
            return true;
        }

        if (this.isFilePathOrBundleName(value)) {
            logger.debug(`Filtered file path/bundle name: "${value}"`);
            return true;
        }

        if (this.isJsonSchemaProperty(value, lowerLine)) {
            logger.debug(`Filtered JSON schema property: "${value}"`);
            return true;
        }

        if (this.isTypeOrClassName(value, lowerLine)) {
            logger.debug(`Filtered type/class name: "${value}"`);
            return true;
        }

        // High confidence patterns - only filter if clearly false positive
        if (pattern?.confidence === 'high') {
            // Special handling for Elasticsearch pattern - filter if it doesn't have ://
            if (pattern.name === 'Elasticsearch Connection String') {
                const cleanValue = value.replace(/^["']|["';]+$/g, '').trim();
                // If it doesn't contain ://, it's definitely not a connection string
                if (!cleanValue.includes('://')) {
                    // It's a file path or import, filter it
                    logger.debug(`Filtered Elasticsearch pattern (no ://): "${value}"`);
                    return true;
                }
                // Even if it has ://, check if it's still a file path
                if (this.isFilePathOrImportPath(value, lowerLine)) {
                    logger.debug(`Filtered Elasticsearch pattern (file path): "${value}"`);
                    return true;
                }
                // Additional check: if it starts with "es/" and is in import context, filter it
                if (cleanValue.startsWith('es/') && (lowerLine.includes('import') || lowerLine.includes('from '))) {
                    logger.debug(`Filtered Elasticsearch pattern (es/ import path): "${value}"`);
                    return true;
                }
            }
            
            if (this.isClearlyFalsePositive(value, line)) {
                logger.debug(`Filtered high-confidence pattern "${pattern.name}": "${value}"`);
                return true;
            }
            return false;
        }

        // Medium confidence patterns - apply entropy filtering
        if (pattern?.confidence === 'medium') {
            if (this.failsEntropyCheck(value, pattern, isGoFile)) {
                return true;
            }
        }

        // Common false positive patterns
        if (this.hasFalsePositiveKeywords(lowerValue)) {
            logger.debug(`Filtered by false positive keyword: "${value}"`);
            return true;
        }

        if (this.isTestKeyword(lowerValue)) {
            logger.debug(`Filtered by test keyword: "${value}"`);
            return true;
        }

        if (this.isHttpContentType(lowerValue)) {
            logger.debug(`Filtered by content type: "${value}"`);
            return true;
        }

        if (this.isMimeType(lowerValue)) {
            logger.debug(`Filtered by MIME type: "${value}"`);
            return true;
        }

        if (this.isHttpMethod(lowerValue)) {
            logger.debug(`Filtered by HTTP method: "${value}"`);
            return true;
        }

        if (this.isHttpStatusCode(lowerValue)) {
            logger.debug(`Filtered by HTTP status code: "${value}"`);
            return true;
        }

        if (this.isFileExtensionOrPath(lowerValue)) {
            logger.debug(`Filtered by file extension/path: "${value}"`);
            return true;
        }

        if (this.isProgrammingTerm(lowerValue)) {
            logger.debug(`Filtered by programming term: "${value}"`);
            return true;
        }

        if (this.isGoStructFieldAccess(lowerValue)) {
            logger.debug(`Filtered by Go struct field access: "${value}"`);
            return true;
        }

        if (this.isGoPackageOrStructPattern(value)) {
            logger.debug(`Filtered by Go package/struct pattern: "${value}"`);
            return true;
        }

        // Don't filter JWT tokens
        if (this.isJwtToken(value)) {
            logger.debug(`Not filtering JWT token: "${value}"`);
            return false;
        }

        // Development value filtering
        if (this.config.skipDevelopmentValues && this.isDevelopmentValue(value, line)) {
            logger.debug(`Filtered by development value: "${value}"`);
            return true;
        }

        // Special cases
        if (this.isExampleInDocumentation(lowerValue, pattern)) {
            logger.debug(`Filtered example value in documentation: "${value}"`);
            return true;
        }

        if (this.isAwsSessionTokenSubstring(value, lowerLine, pattern)) {
            logger.debug(`Filtered AWS Secret Key as part of AWS Session Token: "${value}"`);
            return true;
        }

        if (this.isVeryLongToken(value, pattern)) {
            logger.debug(`Filtered very long token by generic pattern: "${value}"`);
            return true;
        }

        if (this.isEnvironmentVariableName(value)) {
            logger.debug(`Filtered environment variable name: "${value}"`);
            return true;
        }

        if (this.isSimpleValue(value, lowerValue, pattern)) {
            logger.debug(`Filtered by simple value: "${value}"`);
            return true;
        }

        // Check for file paths and import statements (e.g., "es/share/", "es/configure-ui")
        if (this.isFilePathOrImportPath(value, lowerLine)) {
            logger.debug(`Filtered file path/import: "${value}"`);
            return true;
        }

        // Check for enum values or simple identifiers (e.g., "encryption_key" in enum definitions)
        if (this.isEnumValueOrIdentifier(value, lowerLine, pattern)) {
            logger.debug(`Filtered enum/identifier: "${value}"`);
            return true;
        }

        // Check for placeholder/example secret names
        if (this.isPlaceholderSecretName(value)) {
            logger.debug(`Filtered placeholder secret name: "${value}"`);
            return true;
        }

        // Check for secret name references (not secret values)
        if (this.isSecretNameReference(value, lowerLine)) {
            logger.debug(`Filtered secret name reference: "${value}"`);
            return true;
        }

        return false;
    }

    /**
     * Checks if a high-confidence pattern is clearly a false positive
     */
    isClearlyFalsePositive(value: string, line: string): boolean {
        const lowerValue = value.toLowerCase();
        const lowerLine = line.toLowerCase();

        if (this.isJsonSchemaReference(value)) {
            return true;
        }

        if (value.includes('/') && (value.includes('.js') || value.includes('.ts') ||
            value.includes('main-') || value.includes('bundle-') || value.includes('chunk-'))) {
            return true;
        }

        if (value.match(/^[a-zA-Z0-9_-]+\.(js|ts|jsx|tsx|json|css|html|png|jpg|jpeg|gif|svg)$/i)) {
            return true;
        }

        // Check for file paths and import statements (e.g., "es/share/", "es/configure-ui")
        if (this.isFilePathOrImportPath(value, lowerLine)) {
            return true;
        }

        if (lowerValue.includes('example') || lowerValue.includes('dummy') ||
            lowerValue.includes('placeholder') || lowerValue.includes('sample')) {
            return true;
        }

        if (lowerValue === 'test' || lowerValue === 'testing' || lowerValue === 'example') {
            return true;
        }

        if (lowerValue.includes('application/json') || lowerValue.includes('application/xml') ||
            lowerValue.includes('text/html') || lowerValue.includes('text/plain')) {
            return true;
        }

        if (value.length < 10 || /^[a-z]+$/i.test(value)) {
            return true;
        }

        if (value.includes('.') && !value.includes('=') && !value.includes(':') &&
            (value.match(/^[a-zA-Z][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*/) ||
             value.match(/^[a-zA-Z][a-zA-Z0-9]*\.[a-zA-Z][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*/))) {
            return true;
        }

        if (value.includes('Config') && (value.includes('AuthConfig') || value.includes('ServiceAccount') ||
            value.includes('Google') || value.includes('Azure') || value.includes('AWS'))) {
            if (lowerLine.includes('$ref') || lowerLine.includes('#/$defs') ||
                lowerLine.includes('"type"') || lowerLine.includes('"properties"')) {
                return true;
            }
        }

        if (this.isJwtToken(value)) {
            return false;
        }

        return false;
    }

    /**
     * Checks if a value is likely a development/test value
     */
    isDevelopmentValue(value: string, line: string): boolean {
        const lowerValue = value.toLowerCase();
        const lowerLine = line.toLowerCase();

        // Common development passwords
        if (['password', 'pass', 'pwd', 'admin', 'root', 'user', 'test', 'demo', 'dev',
            'development', 'staging'].includes(lowerValue)) {
            return true;
        }

        // Localhost URLs and common dev ports
        if (lowerValue.includes('localhost') || lowerValue.includes('127.0.0.1') ||
            lowerValue.includes(':3000') || lowerValue.includes(':8080') ||
            lowerValue.includes(':5432') || lowerValue.includes(':27017') ||
            lowerValue.includes(':6379') || lowerValue.includes(':7687')) {
            return true;
        }

        // Common development database credentials
        if (['neo4j', 'postgres', 'mysql', 'mongodb', 'redis'].includes(lowerValue)) {
            return true;
        }

        // Development indicators in line
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

        // Simple boolean or common dev value
        if (['true', 'false', 'yes', 'no', 'on', 'off'].includes(lowerValue)) {
            return true;
        }

        return false;
    }

    // Private helper methods

    private isGoFile(line: string, lowerLine: string): boolean {
        return line.includes('.go') || lowerLine.includes('package ') ||
            lowerLine.includes('import ') || lowerLine.includes('func ') ||
            lowerLine.includes('var ') || lowerLine.includes('const ') ||
            lowerLine.includes('type ') || lowerLine.includes('struct ') ||
            lowerLine.includes('interface ') || lowerLine.includes('fmt.') ||
            lowerLine.includes('log.') || lowerLine.includes('http.') ||
            lowerLine.includes('mux.') || lowerLine.includes('gin.') ||
            lowerLine.includes('echo.') || lowerLine.includes('fiber.');
    }

    /**
     * Checks if the line contains scan report content (meta-scanning detection)
     */
    private isScanReportContent(lowerLine: string): boolean {
        // Check for common scan report indicators - comprehensive detection
        // RTF/scan report format patterns
        if (lowerLine.includes('hardcoded secrets scan results') ||
            lowerLine.includes('scan results') ||
            lowerLine.includes('scan completed at') ||
            lowerLine.includes('scanner configured') ||
            lowerLine.includes('potential secrets') ||
            lowerLine.includes('files scanned') ||
            lowerLine.includes('found') && lowerLine.includes('secrets') && lowerLine.includes('files')) {
            return true;
        }
        
        // Report structure patterns
        if (lowerLine.includes('file:') || 
            (lowerLine.includes('path:') && (lowerLine.includes('/users/') || lowerLine.includes('/home/'))) ||
            lowerLine.includes('location: line') ||
            lowerLine.includes('location:') && lowerLine.match(/line\s+\d+:\d+/) ||
            lowerLine.includes('value:') && (lowerLine.includes('"es/') || lowerLine.includes("'es/")) ||
            lowerLine.includes('context:') ||
            lowerLine.includes('secrets found')) {
            return true;
        }
        
        // Secret type patterns in reports
        if ((lowerLine.includes('elasticsearch connection string') ||
             lowerLine.includes('go secret assignment') ||
             lowerLine.includes('aws access key') ||
             lowerLine.includes('aws secret key') ||
             lowerLine.includes('api key') ||
             lowerLine.includes('password') ||
             lowerLine.includes('token')) &&
            (lowerLine.includes('location:') || 
             lowerLine.includes('value:') || 
             lowerLine.includes('context:') ||
             lowerLine.includes('line'))) {
            return true;
        }
        
        // RTF format markers
        if (lowerLine.includes('\\rtf1') ||
            lowerLine.includes('\\cocoartf') ||
            lowerLine.includes('\\fonttbl') ||
            lowerLine.includes('\\colortbl') ||
            lowerLine.includes('\\paperw') ||
            lowerLine.includes('\\pard') ||
            lowerLine.includes('\\f0\\fs24')) {
            return true;
        }
        
        // Report formatting patterns
        if (lowerLine.match(/^={20,}$/) || // ==== separator lines
            lowerLine.includes('=====================================')) {
            return true;
        }
        
        return false;
    }

    private isJsonSchemaReference(value: string): boolean {
        return value.includes('$ref') || value.includes('#/$defs') || value.includes('#/definitions') ||
            value.startsWith('#/') || (value.startsWith('$') && !value.includes('='));
    }

    private isFilePathOrBundleName(value: string): boolean {
        if (value.includes('.js') || value.includes('.ts') ||
            value.includes('main-') || value.includes('bundle-') || value.includes('chunk-') ||
            value.match(/^[a-zA-Z0-9_-]+\.(js|ts|jsx|tsx|json|css|html|png|jpg|jpeg|gif|svg)$/i)) {
            return value.includes('/') || value.includes('\\') || value.match(/\.[a-z0-9]{2,4}$/i) !== null;
        }
        return false;
    }

    private isJsonSchemaProperty(value: string, lowerLine: string): boolean {
        return (value.includes('Config') || value.includes('AuthConfig') || value.includes('ServiceAccount')) &&
            (lowerLine.includes('$ref') || lowerLine.includes('#/$defs') || lowerLine.includes('#/definitions') ||
            lowerLine.includes('"type"') || lowerLine.includes('"properties"') ||
            lowerLine.includes('"description"') || lowerLine.includes('"required"') ||
            lowerLine.includes('"$defs"') || lowerLine.includes('"definitions"'));
    }

    private isTypeOrClassName(value: string, lowerLine: string): boolean {
        return value.match(/^[A-Z][a-zA-Z0-9]*(Config|Account|Service|Provider|Client|Manager|Handler|Controller)[a-zA-Z0-9]*$/) !== null &&
            (lowerLine.includes('"type"') || lowerLine.includes('"$ref"') || lowerLine.includes('"class"'));
    }

    private failsEntropyCheck(value: string, pattern: SecretPattern, isGoFile: boolean): boolean {
        const entropy = EntropyCalculator.calculate(value);
        let threshold = this.config.minEntropy;

        const patternNameLower = pattern.name.toLowerCase();
        if (patternNameLower.includes('api')) {
            threshold = this.config.entropyThresholds.apiKey;
        } else if (patternNameLower.includes('password')) {
            threshold = this.config.entropyThresholds.password;
        } else if (patternNameLower.includes('token')) {
            threshold = Math.min(this.config.entropyThresholds.token, 3.5);
            if (value.length >= 30 && /^[a-zA-Z0-9\-_./+]+$/.test(value)) {
                threshold = 3.0;
            }
        } else if (patternNameLower.includes('connection')) {
            threshold = this.config.entropyThresholds.connectionString;
        }

        if (patternNameLower.includes('client') && value.length < 15) {
            threshold = 2.0;
        }

        if (isGoFile) {
            threshold += 0.5;
        }

        if (entropy < threshold && !(patternNameLower.includes('client') && value.length < 15)) {
            logger.debug(`Filtered by low entropy (${entropy.toFixed(2)} < ${threshold}): "${value}"`);
            return true;
        }

        return false;
    }

    private hasFalsePositiveKeywords(lowerValue: string): boolean {
        return lowerValue.includes('example') || lowerValue.includes('dummy') ||
            lowerValue.includes('placeholder') || lowerValue.includes('sample') ||
            lowerValue.includes('your-') || lowerValue.includes('your_') ||
            lowerValue.includes('replace-') || lowerValue.includes('replace_') ||
            lowerValue.includes('add-') || lowerValue.includes('add_');
    }

    private isTestKeyword(lowerValue: string): boolean {
        return lowerValue === 'test' || lowerValue === 'testing';
    }

    private isHttpContentType(lowerValue: string): boolean {
        return lowerValue.includes('application/json') || lowerValue.includes('application/xml') ||
            lowerValue.includes('text/html') || lowerValue.includes('text/plain') ||
            lowerValue.includes('multipart/form-data') || lowerValue.includes('application/x-www-form-urlencoded');
    }

    private isMimeType(lowerValue: string): boolean {
        return lowerValue.includes('image/') || lowerValue.includes('video/') || lowerValue.includes('audio/');
    }

    private isHttpMethod(lowerValue: string): boolean {
        return ['get', 'post', 'put', 'delete', 'patch'].includes(lowerValue);
    }

    private isHttpStatusCode(lowerValue: string): boolean {
        return ['200', '201', '400', '401', '403', '404', '500', '502', '503'].includes(lowerValue);
    }

    private isFileExtensionOrPath(lowerValue: string): boolean {
        return lowerValue.includes('.js') || lowerValue.includes('.ts') || lowerValue.includes('.jsx') ||
            lowerValue.includes('.tsx') || lowerValue.includes('.json') || lowerValue.includes('.css') ||
            lowerValue.includes('.html') || lowerValue.includes('.svg') || lowerValue.includes('.png') ||
            lowerValue.includes('.jpg') || lowerValue.includes('.jpeg') || lowerValue.includes('.gif') ||
            lowerValue.includes('/bin/') || lowerValue.includes('/dist/') || lowerValue.includes('/node_modules/') ||
            lowerValue.includes('/src/') || lowerValue.includes('/build/') || lowerValue.includes('/public/');
    }

    private isProgrammingTerm(lowerValue: string): boolean {
        return lowerValue.includes('function') || lowerValue.includes('const') || lowerValue.includes('let') ||
            lowerValue.includes('var') || lowerValue.includes('return') || lowerValue.includes('import') ||
            lowerValue.includes('export') || lowerValue.includes('default') || lowerValue.includes('async') ||
            lowerValue.includes('await') || lowerValue.includes('try') || lowerValue.includes('catch') ||
            lowerValue.includes('rollup') || lowerValue.includes('autoprefixer') || lowerValue.includes('webpack') ||
            lowerValue.includes('babel') || lowerValue.includes('eslint') || lowerValue.includes('prettier') ||
            lowerValue.includes('jest') || lowerValue.includes('mocha') || lowerValue.includes('chai');
    }

    private isGoStructFieldAccess(lowerValue: string): boolean {
        return lowerValue.includes('.') && (lowerValue.includes('request') || lowerValue.includes('response') ||
            lowerValue.includes('finding') || lowerValue.includes('extrafields') || lowerValue.includes('addr') ||
            lowerValue.includes('http') || lowerValue.includes('service') || lowerValue.includes('session') ||
            lowerValue.includes('context') || lowerValue.includes('error') || lowerValue.includes('result') ||
            lowerValue.includes('data') || lowerValue.includes('config') || lowerValue.includes('client') ||
            lowerValue.includes('server') || lowerValue.includes('handler') || lowerValue.includes('router') ||
            lowerValue.includes('middleware') || lowerValue.includes('database') || lowerValue.includes('store') ||
            lowerValue.includes('model') || lowerValue.includes('struct') || lowerValue.includes('interface'));
    }

    private isGoPackageOrStructPattern(value: string): boolean {
        return value.includes('.') && !value.includes('=') && !value.includes(':') &&
            (value.match(/^[A-Z][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*/) !== null ||
             value.match(/^[a-z][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*/) !== null ||
             value.match(/^[a-z][a-zA-Z0-9]*\.[a-z][a-zA-Z0-9]*/) !== null);
    }

    private isJwtToken(value: string): boolean {
        return value.startsWith('eyJ') && value.includes('.') && value.length > 50;
    }

    private isExampleInDocumentation(lowerValue: string, pattern?: SecretPattern): boolean {
        return pattern?.confidence === 'medium' &&
            (lowerValue.includes('your-') || lowerValue.includes('your_') ||
             lowerValue.includes('example-') || lowerValue.includes('example_') ||
             lowerValue.includes('sample-') || lowerValue.includes('sample_') ||
             lowerValue.includes('placeholder-') || lowerValue.includes('placeholder_'));
    }

    private isAwsSessionTokenSubstring(value: string, lowerLine: string, pattern?: SecretPattern): boolean {
        return pattern?.name === 'AWS Secret Key' &&
            lowerLine.includes('session_token') && value.length === 40;
    }

    private isVeryLongToken(value: string, pattern?: SecretPattern): boolean {
        return pattern?.confidence === 'medium' && value.length > 200;
    }

    private isEnvironmentVariableName(value: string): boolean {
        // Generic pattern: ALL_CAPS with underscores (environment variable naming convention)
        if (/^[A-Z][A-Z0-9_]+$/.test(value) && value.includes('_')) {
            // Must be reasonable length for a variable name
            if (value.length >= 5 && value.length < 60) {
                // Check if it contains common variable name patterns
                // Pattern: contains common suffixes/words that indicate it's a variable name
                const variableNameIndicators = [
                    /_URL$/i,
                    /_PATH$/i,
                    /_NAME$/i,
                    /_ID$/i,
                    /_KEY$/i,
                    /_SECRET$/i,
                    /_TOKEN$/i,
                    /_PASSWORD$/i,
                    /_HOST$/i,
                    /_PORT$/i,
                    /_VERSION$/i,
                    /_CONFIG$/i,
                    /_CONF$/i,
                    /_ENV$/i,
                    /_REPO$/i,
                    /_ACCESS$/i,
                    /_AUTH$/i,
                    /^[A-Z]+_[A-Z]+/  // Pattern: PREFIX_SUFFIX
                ];
                
                // If it matches common variable name patterns, it's likely a variable name
                if (variableNameIndicators.some(pattern => pattern.test(value))) {
                    return true;
                }
                
                // Generic: if it's ALL_CAPS with multiple underscores (likely a variable name)
                const underscoreCount = (value.match(/_/g) || []).length;
                if (underscoreCount >= 2 && value.length > 8) {
                    return true;
                }
            }
        }
        return false;
    }

    private isSimpleValue(value: string, lowerValue: string, pattern?: SecretPattern): boolean {
        const isClientPattern = pattern && (pattern.name.toLowerCase().includes('client') ||
            pattern.name.toLowerCase().includes('access_token'));
        const minLength = isClientPattern ? 6 : 10;

        return value.length < minLength || /^[a-z]+$/i.test(value) ||
            lowerValue.includes('true') || lowerValue.includes('false') || lowerValue.includes('null') ||
            lowerValue.includes('undefined') || lowerValue.includes('nan');
    }

    /**
     * Checks if value is a file path or import statement (e.g., "es/share/", "es/configure-ui")
     */
    private isFilePathOrImportPath(value: string, lowerLine: string): boolean {
        // Clean the value (remove quotes, semicolons, etc.)
        const cleanValue = value.replace(/^["']|["';]+$/g, '').trim();
        const lowerValue = cleanValue.toLowerCase();
        
        // Check if it looks like a file path or import path
        if (cleanValue.includes('/') || cleanValue.includes('\\')) {
            // Check if it's in an import statement or path configuration
            const isInImportContext = lowerLine.includes('import') || 
                lowerLine.includes('from ') || 
                lowerLine.includes('require(') ||
                lowerLine.includes('"path"') ||
                lowerLine.includes('"paths"') ||
                lowerLine.includes('"include"') ||
                lowerLine.includes('"exclude"') ||
                lowerLine.includes('"testmatch"') ||
                lowerLine.includes('"transform"') ||
                lowerLine.includes('module') ||
                lowerLine.includes('alias') ||
                lowerLine.includes('resolve') ||
                lowerLine.includes('@akeyless') ||
                lowerLine.includes('automation/');
            
            // If it's in import context, it's definitely a path, not a secret
            if (isInImportContext) {
                return true;
            }
            
            // Check for common path patterns
            // Match paths like: es/path, es/path/to/file, path/to/file.ext
            const pathPattern = /^[a-zA-Z0-9_-]+(\/[a-zA-Z0-9_.-]+)+(\.[a-zA-Z0-9]+)?$/;
            
            // Check for file extensions
            const hasFileExtension = /\.(ts|tsx|js|jsx|json|constants|types|store|config|test|spec)$/i.test(cleanValue);
            
            // Check for common path segments
            const hasPathSegments = cleanValue.includes('/') && 
                (cleanValue.includes('.constants') || 
                 cleanValue.includes('.types') ||
                 cleanValue.includes('.store') ||
                 cleanValue.includes('/pages/') ||
                 cleanValue.includes('/components/') ||
                 cleanValue.includes('/utils/') ||
                 cleanValue.includes('/stores/') ||
                 cleanValue.includes('/types/') ||
                 cleanValue.includes('/constants/'));
            
            // If it has file extension OR has path segments, it's likely a path
            if (hasFileExtension || hasPathSegments || pathPattern.test(cleanValue)) {
                // Additional check: if it starts with common path prefixes and doesn't look like a connection string
                if (!cleanValue.includes('://') && !cleanValue.includes('@') && 
                    !cleanValue.match(/^[a-z]+:\/\//i)) {
                    return true;
                }
            }
            
            // Special case: paths that look like system paths (e.g., android system images)
            if (lowerValue.includes('android') || 
                lowerValue.includes('system-images') ||
                lowerValue.includes('kernel') ||
                lowerValue.includes('ramdisk') ||
                lowerValue.includes('/tmp/') ||
                lowerValue.includes('/users/') ||
                lowerValue.includes('/home/')) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if value is an enum value or simple identifier (e.g., "encryption_key" in enum)
     */
    private isEnumValueOrIdentifier(value: string, lowerLine: string, pattern?: SecretPattern): boolean {
        // Check if it's a Go Secret Assignment pattern or similar
        if (pattern?.name === 'Go Secret Assignment' || pattern?.name === 'Secret') {
            const lowerValue = value.toLowerCase();
            
            // Check if it's a simple identifier (snake_case, kebab-case, camelCase, or plain text)
            // Allow letters, numbers, hyphens, underscores, and spaces
            const isSimpleIdentifier = /^[a-zA-Z][a-zA-Z0-9_\s-]*$/.test(value);
            
            // Check if it's in a const/let/var declaration context
            const isInDeclaration = lowerLine.includes('const ') || 
                lowerLine.includes('let ') || 
                lowerLine.includes('var ') ||
                (lowerLine.includes('=') && (lowerLine.includes('const') || lowerLine.includes('let') || lowerLine.includes('var')));
            
            // Check if it's a descriptive string (contains spaces, common words)
            const isDescriptiveString = value.includes(' ') && 
                (lowerValue.includes('click') || 
                 lowerValue.includes('fill') || 
                 lowerValue.includes('enter') ||
                 lowerValue.includes('select') ||
                 lowerValue.includes('choose') ||
                 lowerValue.includes('generate') ||
                 lowerValue.includes('verify') ||
                 lowerValue.includes('generated') ||
                 lowerValue.includes('field') ||
                 lowerValue.includes('key') ||
                 lowerValue.includes('private') ||
                 lowerValue.includes('public') ||
                 lowerValue.includes('on ') || // "Click on generate token"
                 lowerValue.includes(' the ') || // "Verify the key"
                 lowerValue.match(/^[a-z][a-z\s]+$/)); // All lowercase with spaces
            
            // Check if it's a kebab-case or snake_case identifier (common in constants/enums)
            const isKebabOrSnakeCase = /^[a-z][a-z0-9_-]+$/.test(value) && 
                (value.includes('-') || value.includes('_'));
            
            // Common enum/constant identifiers that are definitely not secrets
            const commonEnumValues = ['encryption_key', 'dynamic_secret', 'rotated_secret', 
                'static_secret', 'access_key', 'secret_key', 'api_key', 'auth_token'];
            if (commonEnumValues.includes(lowerValue)) {
                return true;
            }
            
            // If it's a simple identifier in a declaration context, likely not a secret
            if (isSimpleIdentifier && isInDeclaration) {
                // Filter if it's short and doesn't look like a secret
                if (value.length < 50 && 
                    !value.includes('://') && 
                    !value.includes('@') &&
                    !value.match(/^[a-zA-Z0-9+/=]{20,}$/) && // Not base64-like
                    !value.match(/^[a-f0-9]{32,}$/i)) { // Not hex hash
                    return true;
                }
            }
            
            // Filter descriptive strings (like "Click on generate token", "Verify sub Claims key", "Fill private key")
            if (isDescriptiveString && value.length < 100) {
                return true;
            }
            
            // Filter kebab-case/snake_case identifiers that are clearly not secrets
            if (isKebabOrSnakeCase && value.length < 50 && isInDeclaration) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if value is a placeholder/example secret name using generic patterns
     */
    private isPlaceholderSecretName(value: string): boolean {
        const lowerValue = value.toLowerCase();
        
        // Generic pattern: starts with common placeholder prefixes
        // Pattern: "my_*", "my-*", "your_*", "your-*", "test_*", "test-*", "example_*", "example-*"
        if (/^(my|your|test|example|sample|demo|placeholder)[-_]/.test(lowerValue)) {
            return true;
        }
        
        // Generic pattern: "name-of-existing-*" or "name_of_existing_*"
        if (/^name[-_]of[-_]existing/.test(lowerValue)) {
            return true;
        }
        
        // Generic pattern: contains placeholder indicators followed by secret-related words
        const placeholderWords = ['example', 'sample', 'placeholder', 'test', 'demo', 'dummy', 'fake'];
        const secretWords = ['secret', 'key', 'token', 'password', 'credential', 'auth'];
        
        for (const placeholder of placeholderWords) {
            if (lowerValue.includes(placeholder)) {
                // Check if it's followed by a secret-related word
                for (const secret of secretWords) {
                    if (lowerValue.includes(secret)) {
                        return true;
                    }
                }
            }
        }
        
        // Generic pattern: very short kebab-case/snake_case that looks like a placeholder
        // e.g., "test-secret", "demo-key" (2-3 words, short)
        if (/^[a-z]+[-_][a-z]+$/.test(lowerValue) && value.length < 25) {
            const words = lowerValue.split(/[-_]/);
            // If it contains common placeholder words or is very generic
            if (words.some(w => placeholderWords.includes(w) || secretWords.includes(w))) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Checks if value is a secret name reference (not the secret value itself) using generic patterns
     * e.g., "akeyless-auth" in YAML config: gatewayCredentialsExistingSecret: akeyless-auth
     */
    private isSecretNameReference(value: string, lowerLine: string): boolean {
        const lowerLineLower = lowerLine.toLowerCase();
        
        // Generic pattern: check if it's in a context that suggests it's a secret name reference
        // Look for patterns like: *secret*, *credential*, *key*, *auth* followed by colon/equals
        const secretNameContextPatterns = [
            /existing[-_]?secret/i,
            /secret[-_]?name/i,
            /secret[-_]?ref/i,
            /credential[-_]?secret/i,
            /.*secret\s*[:=]/i,  // "secret:" or "secret="
            /.*credential.*\s*[:=]/i,
            /.*key.*\s*[:=]/i,
            /.*auth.*\s*[:=]/i
        ];
        
        const isSecretNameContext = secretNameContextPatterns.some(pattern => pattern.test(lowerLineLower));
        
        // Generic pattern: kebab-case or snake_case identifier that looks like a name reference
        if (isSecretNameContext) {
            // Pattern: kebab-case or snake_case (lowercase with hyphens/underscores)
            // Short to medium length, descriptive (not a hash or token)
            if (/^[a-z][a-z0-9_-]+$/.test(value) && 
                value.length >= 5 && value.length < 60 &&
                (value.includes('-') || value.includes('_'))) {
                // Check if it looks like a name, not a secret value
                if (!value.includes('://') && 
                    !value.includes('@') && 
                    !value.match(/^[a-zA-Z0-9+/=]{20,}$/) && // Not base64-like
                    !value.match(/^[a-f0-9]{32,}$/i) && // Not hex hash
                    !value.match(/^[a-zA-Z0-9]{40,}$/)) { // Not long alphanumeric token
                    // Additional check: if it's in a YAML/config context and looks descriptive
                    if (lowerLineLower.includes('.yaml') || 
                        lowerLineLower.includes('.yml') ||
                        lowerLineLower.includes('values') ||
                        lowerLineLower.includes('config')) {
                        return true;
                    }
                }
            }
        }
        
        // Generic pattern: very short kebab-case identifiers (likely names, not values)
        // e.g., "akeyless-auth", "gw-metrics" (2-4 words, descriptive)
        if (/^[a-z]+([-_][a-z]+){1,3}$/.test(value) && value.length < 40) {
            // Check if it's in a config/YAML context
            if (isSecretNameContext || 
                lowerLineLower.includes('.yaml') || 
                lowerLineLower.includes('.yml') ||
                lowerLineLower.includes('values') ||
                lowerLineLower.includes('config') ||
                lowerLineLower.includes('helm')) {
                // Make sure it doesn't look like a secret value
                if (!value.match(/^[a-zA-Z0-9+/=]{20,}$/) && 
                    !value.match(/^[a-f0-9]{32,}$/i)) {
                    return true;
                }
            }
        }
        
        return false;
    }
}

