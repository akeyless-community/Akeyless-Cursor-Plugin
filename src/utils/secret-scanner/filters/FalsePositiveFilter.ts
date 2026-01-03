import { SecretPattern, ScannerConfig } from '../types';
import { EntropyCalculator } from '../utils/EntropyCalculator';
import { logger } from '../../logger';
import { MLFalsePositiveClassifier } from '../ml/MLFalsePositiveClassifier';

/**
 * Filters false positives from secret detections
 * Breaks down complex filtering logic into smaller, testable methods
 */
export class FalsePositiveFilter {
    private readonly config: ScannerConfig;
    private readonly mlClassifier: MLFalsePositiveClassifier;

    constructor(config: ScannerConfig) {
        this.config = config;
        const mlEnabled = config.mlEnabled ?? true;
        this.mlClassifier = new MLFalsePositiveClassifier(mlEnabled);
        if (config.mlConfidenceThreshold !== undefined) {
            this.mlClassifier.setThreshold(config.mlConfidenceThreshold);
        }
    }

    /**
     * Main method to check if a detected value is a false positive
     */
    isFalsePositive(value: string, line: string, pattern?: SecretPattern, fileName?: string): boolean {
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

        // Check if value matches the variable/key name (common false positive)
        // e.g., EVENT_SMTP_PASSWORD = "event_smtp_password"
        if (this.isValueMatchingKeyName(value, line)) {
            logger.debug(`Filtered value matching key name: "${value}"`);
            return true;
        }

        // Language-agnostic code pattern detection (works for all languages)
        if (this.isCodePattern(value, line, lowerLine, fileName)) {
            logger.debug(`Filtered code pattern: "${value}"`);
            return true;
        }

        // Language-agnostic false positive detection
        if (this.isVariableOrParameterName(value, line, lowerLine)) {
            logger.debug(`Filtered variable/parameter name: "${value}"`);
            return true;
        }

        if (this.isFunctionOrMethodCall(value, line, lowerLine)) {
            logger.debug(`Filtered function/method call: "${value}"`);
            return true;
        }

        if (this.isTemplateString(value)) {
            logger.debug(`Filtered template string: "${value}"`);
            return true;
        }

        if (this.isApiEndpointPath(value, lowerLine)) {
            logger.debug(`Filtered API endpoint path: "${value}"`);
            return true;
        }

        if (this.isProtobufMetadata(value, line)) {
            logger.debug(`Filtered Protobuf metadata: "${value}"`);
            return true;
        }

        if (fileName && this.isTestFile(fileName)) {
            if (this.isTestDataPattern(value, line)) {
                logger.debug(`Filtered test data pattern: "${value}"`);
                return true;
            }
        }

        if (this.isObjectOrStructFieldAssignment(value, line, lowerLine)) {
            logger.debug(`Filtered object/struct field assignment: "${value}"`);
            return true;
        }

        if (this.isHashValueInTestContext(value, fileName, lowerLine)) {
            logger.debug(`Filtered hash value in test context: "${value}"`);
            return true;
        }

        // ML-based classification as final check (after all rule-based filters)
        // This helps catch edge cases that rule-based filters might miss
        if (pattern && fileName) {
            if (this.mlClassifier.isFalsePositive(value, line, pattern, fileName)) {
                return true;
            }
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
     * Language-agnostic: Checks if value is a file path or import statement
     * Works for: JavaScript/TypeScript, Python, Go, Java, C#, Ruby, PHP, etc.
     */
    private isFilePathOrImportPath(value: string, lowerLine: string): boolean {
        // Clean the value (remove quotes, semicolons, etc.)
        const cleanValue = value.replace(/^["']|["';]+$/g, '').trim();
        const lowerValue = cleanValue.toLowerCase();
        
        // Check if it looks like a file path or import path
        if (cleanValue.includes('/') || cleanValue.includes('\\')) {
            // Language-agnostic import/require patterns
            const isInImportContext = 
                // JavaScript/TypeScript
                lowerLine.includes('import') || 
                lowerLine.includes('from ') || 
                lowerLine.includes('require(') ||
                // Python
                lowerLine.includes('import ') ||
                lowerLine.includes('from ') ||
                // Go
                lowerLine.includes('import ') ||
                // Java
                lowerLine.includes('import ') ||
                lowerLine.includes('package ') ||
                // C#
                lowerLine.includes('using ') ||
                // Ruby
                lowerLine.includes('require ') ||
                lowerLine.includes('require_relative ') ||
                // PHP
                lowerLine.includes('require ') ||
                lowerLine.includes('include ') ||
                // Configuration files
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
            
            // Language-agnostic file extensions
            const hasFileExtension = /\.(ts|tsx|js|jsx|json|constants|types|store|config|test|spec|py|go|java|cs|rb|php|cpp|h|hpp|cc|cxx|swift|kt|scala|clj|r|m|mm|pl|pm|sh|bash|zsh|fish)$/i.test(cleanValue);
            
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

    /**
     * Checks if the detected value matches the variable/key name
     * Supports: All naming conventions (snake_case, PascalCase, camelCase, kebab-case)
     * This catches cases like: 
     * - EVENT_SMTP_PASSWORD = "event_smtp_password"
     * - AuthPathGetShareToken = "/share-token"
     * where the value is just a string literal matching the variable name
     */
    private isValueMatchingKeyName(value: string, line: string): boolean {
        const lowerValue = value.toLowerCase().replace(/^["']|["']$/g, '').replace(/^\/+|\/+$/g, ''); // Remove quotes and leading/trailing slashes
        const lowerLine = line.toLowerCase();
        
        // Extract the key/variable name from the line (before = or :)
        // Pattern: VariableName =, variableName =, VARIABLE_NAME =, variable_name =
        // Supports PascalCase, camelCase, snake_case, UPPER_CASE
        const keyMatch = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*[:=]/);
        if (!keyMatch) {
            return false;
        }
        
        const keyName = keyMatch[1];
        const lowerKeyName = keyName.toLowerCase();
        
        // Split key name into words (handle PascalCase, camelCase, snake_case, UPPER_CASE)
        const keyWords = this.splitIntoWords(keyName).map(w => w.toLowerCase()).filter(w => w.length > 1);
        
        // Split value into words (handle kebab-case, snake_case, paths)
        const valueWords = lowerValue.split(/[\/\-_\s]+/).filter(w => w.length > 1);
        
        if (keyWords.length === 0 || valueWords.length === 0) {
            return false;
        }
        
        // Normalize both (remove separators) for exact match check
        const normalizeKey = keyWords.join('').toLowerCase();
        const normalizeValue = valueWords.join('').toLowerCase();
        
        // Check if normalized values match (exact match)
        if (normalizeKey === normalizeValue) {
            return true;
        }
        
        // Check if value is a substring of key (e.g., "share-token" in "AuthPathGetShareToken")
        // or key contains value words
        const valueWordsStr = valueWords.join('');
        if (normalizeKey.includes(valueWordsStr) || valueWordsStr.includes(normalizeKey)) {
            // Check if significant words from key appear in value
            const significantKeyWords = keyWords.filter(w => w.length > 2);
            const matchingWords = significantKeyWords.filter(kw => 
                valueWords.some(vw => vw === kw || vw.includes(kw) || kw.includes(vw))
            );
            
            // If 50%+ of significant words match, or if value words are all in key
            if (matchingWords.length >= Math.ceil(significantKeyWords.length * 0.5) ||
                valueWords.every(vw => keyWords.some(kw => kw.includes(vw) || vw.includes(kw)))) {
                return true;
            }
        }
        
        // Special case: Path-like values that match constant name pattern
        // e.g., AuthPathGetShareToken = "/share-token"
        // Check if value words are a subset of key words
        if (valueWords.length <= keyWords.length) {
            const allValueWordsInKey = valueWords.every(vw => 
                keyWords.some(kw => kw === vw || kw.includes(vw) || vw.includes(kw))
            );
            if (allValueWordsInKey && valueWords.length >= 2) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Splits a variable name into words, handling all naming conventions
     * PascalCase: AuthPathGetShareToken -> [Auth, Path, Get, Share, Token]
     * camelCase: authPathGetShareToken -> [auth, Path, Get, Share, Token]
     * snake_case: auth_path_get_share_token -> [auth, path, get, share, token]
     * UPPER_CASE: AUTH_PATH_GET_SHARE_TOKEN -> [AUTH, PATH, GET, SHARE, TOKEN]
     */
    private splitIntoWords(name: string): string[] {
        // Handle snake_case and UPPER_CASE
        if (name.includes('_')) {
            return name.split('_').filter(w => w.length > 0);
        }
        
        // Handle PascalCase and camelCase
        // Split on capital letters: AuthPathGetShareToken -> [Auth, Path, Get, Share, Token]
        const words: string[] = [];
        let currentWord = '';
        
        for (let i = 0; i < name.length; i++) {
            const char = name[i];
            if (char >= 'A' && char <= 'Z' && currentWord.length > 0) {
                // Found uppercase letter, start new word
                words.push(currentWord);
                currentWord = char;
            } else {
                currentWord += char;
            }
        }
        
        if (currentWord.length > 0) {
            words.push(currentWord);
        }
        
        return words.length > 0 ? words : [name];
    }

    /**
     * Language-agnostic: Detects if value is a variable or parameter name
     * Works for: JavaScript/TypeScript, Go, Python, Java, C#, Ruby, PHP, etc.
     */
    private isVariableOrParameterName(value: string, line: string, lowerLine: string): boolean {
        const trimmedValue = value.trim();
        const lowerValue = trimmedValue.toLowerCase();
        
        // Pattern: variable name followed by comma, semicolon, or assignment
        // Examples: "password,", "secret;", "token:", "apiKey,"
        const isVariablePattern = /^[a-zA-Z_][a-zA-Z0-9_]*[,;:]?\s*$/.test(trimmedValue);
        
        // Kebab-case pattern: path-to-secret, path-to-dynamic-secr
        const isKebabCase = /^[a-z][a-z0-9-]+$/i.test(trimmedValue) && trimmedValue.includes('-');
        
        // Snake_case pattern: path_to_secret, path_with_many_items
        const isSnakeCase = /^[a-z][a-z0-9_]+$/i.test(trimmedValue) && 
                           trimmedValue.includes('_') && 
                           !trimmedValue.match(/^[A-Z_]+$/); // Not ALL_CAPS (those are env vars)
        
        // Test variable patterns: secret_name_TestValidateCacheUpdateSecretValue
        const isTestVariable = /^(test|mock|fake|secret_name_|path_)[A-Z]/.test(trimmedValue) ||
                              /^(test|mock|fake|secret_name_|path_)[a-z0-9_-]+$/i.test(trimmedValue);
        
        if (isVariablePattern || isKebabCase || isSnakeCase || isTestVariable) {
            // Check if it's in a function parameter context
            // Pattern: function(param: Type), func(param Type), def func(param):
            const isInFunctionParam = /(function|func|def|method|procedure)\s*\([^)]*/.test(lowerLine) ||
                /\([^)]*:\s*(string|int|bool|Type|interface)/.test(lowerLine) ||
                /:\s*(string|int|bool|Type|interface|Dictionary)/.test(lowerLine);
            
            // Check if it's in a variable declaration context
            // Pattern: var/let/const/val/final/private/public variable
            const isInDeclaration = /\b(var|let|const|val|final|private|public|protected|static)\s+/.test(lowerLine) ||
                /\b(type|interface|struct|class)\s+/.test(lowerLine);
            
            // Check if it's in a struct/object literal
            // Pattern: FieldName: variableName,
            const isInStructLiteral = /:\s*[a-zA-Z_][a-zA-Z0-9_]*[,}]/.test(line);
            
            // Check if it's in a usage/example context
            // Pattern: Usage: $0 <path-to-dynamic-secret>
            const isInUsageExample = /usage:|example:|path-to|path_to|path_with/i.test(lowerLine);
            
            // Check if it's a parameter placeholder
            // Pattern: <path-to-secret>, [path-to-secret], {path-to-secret}
            const isParameterPlaceholder = /[<\[{][^>\]}]*/.test(line) && 
                                          (trimmedValue.includes('-') || trimmedValue.includes('_'));
            
            if (isInFunctionParam || isInDeclaration || isInStructLiteral || isInUsageExample || isParameterPlaceholder) {
                // Additional check: if it's a common variable name pattern
                const commonVarPatterns = [
                    /^(password|secret|token|key|apiKey|clientSecret|privateKey|accessToken)[,;:]?$/i,
                    /^(value|val|data|param|arg|item|obj|result|response)[,;:]?$/i,
                    /^(path|file|dir|url|uri|name|id|key|secret)[-_]?[a-z0-9_-]*$/i,
                    /^path[-_]?(to|with|output|per)[-_]?[a-z0-9_-]*$/i
                ];
                
                if (commonVarPatterns.some(p => p.test(trimmedValue))) {
                    return true;
                }
                
                // If it's kebab-case or snake_case and reasonable length, filter it
                if ((isKebabCase || isSnakeCase) && trimmedValue.length < 60 && 
                    !trimmedValue.includes('://') && !trimmedValue.includes('@')) {
                    return true;
                }
                
                // If it's short and looks like a variable name, filter it
                if (trimmedValue.length < 30 && !trimmedValue.includes('://') && !trimmedValue.includes('@')) {
                    return true;
                }
                
                // Test variable patterns - more aggressive filtering
                if (isTestVariable && trimmedValue.length < 80) {
                    return true;
                }
            }
            
            // Standalone kebab-case or snake_case values that look like variable names
            if ((isKebabCase || isSnakeCase) && 
                trimmedValue.length < 50 && 
                !trimmedValue.includes('://') && 
                !trimmedValue.includes('@') &&
                (lowerLine.includes('path') || lowerLine.includes('variable') || lowerLine.includes('param'))) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Language-agnostic: Detects if value is part of a function or method call
     * Works for: All languages (Go, Python, Java, C#, JavaScript/TypeScript, Ruby, PHP, Rust, Swift, Kotlin, C/C++, etc.)
     */
    private isFunctionOrMethodCall(value: string, line: string, lowerLine: string): boolean {
        const trimmedValue = value.trim();
        
        // ===== TYPE CONVERSIONS & CASTS (All Languages) =====
        // Go: string(variable), []byte(data), int(value)
        // C/C++: (int)value, static_cast<int>(value)
        // Java/C#: (String)value, value as String
        // Python: str(value), int(value), bytes(value)
        // Rust: value as Type
        if (/string\([^)]+\)|\[\]byte\([^)]+\)|int\([^)]+\)|float64\([^)]+\)|bool\([^)]+\)|uint\([^)]+\)/.test(line) ||
            /\(int\)|\(string\)|\(char\)|\(float\)|\(double\)|\(bool\)|\(boolean\)/.test(line) ||
            /static_cast|dynamic_cast|reinterpret_cast/.test(line) ||
            /as\s+(String|Int|Float|Double|Bool|Boolean)/i.test(line) ||
            /str\(|int\(|float\(|bool\(|bytes\(|list\(|dict\(|tuple\(/.test(lowerLine)) {
            // Check if value is the result of a type conversion
            if (/^string\(|^\[\]byte\(|^int\(|^float64\(|^bool\(|^uint\(|^\(int\)|^\(string\)|^as\s+/i.test(trimmedValue)) {
                return true;
            }
            // Check if value appears in a type conversion context
            const typeConversionPattern = /(string|\[\]byte|int|float64|bool|uint|str|int|float|bytes|list|dict|tuple|\(int\)|\(string\)|as\s+)/i.test(line);
            if (typeConversionPattern && /^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue)) {
                return true;
            }
        }
        
        // ===== CONSTRUCTOR CALLS (All OOP Languages) =====
        // Go: &TypeName{}, TypeName{}
        // Java/C#/Kotlin: new TypeName(), new TypeName {}
        // JavaScript/TypeScript: new TypeName()
        // Python: TypeName()
        // C++: new TypeName(), TypeName()
        // Ruby: TypeName.new
        // PHP: new TypeName()
        if (/&[A-Z][a-zA-Z0-9]*\{/.test(line) || 
            /^[A-Z][a-zA-Z0-9]*\{/.test(line.trim()) ||
            /new\s+[A-Z][a-zA-Z0-9]*\s*[({]/.test(line)) {
            // Check if value is part of constructor/initialization
            if (/^&[A-Z]|^[A-Z][a-zA-Z0-9]*\{|^new\s+[A-Z]/i.test(trimmedValue) ||
                /^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue)) {
                return true;
            }
        }
        
        // ===== FUNCTION/METHOD CALL PATTERNS (All Languages) =====
        const functionCallPatterns = [
            /[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*/,      // function( - most languages
            /\.[a-zA-Z_][a-zA-Z0-9_]*\s*\(/,         // .method( - OOP languages
            /::[a-zA-Z_][a-zA-Z0-9_]*\s*\(/,         // ::method( - C++/PHP
            /->[a-zA-Z_][a-zA-Z0-9_]*\s*\(/,         // ->method( - PHP/C++
            /\[:['"]\w+['"]\]\s*\(/,                  // [:method]( - Ruby
        ];
        
        const isInFunctionCall = functionCallPatterns.some(pattern => pattern.test(line) || pattern.test(lowerLine));
        
        if (isInFunctionCall) {
            // Check if value appears to be a function name or parameter
            const commonFunctionPatterns = [
                // Common function prefixes
                /^(validate|hash|encode|decode|encrypt|decrypt|get|set|create|update|delete|parse|stringify|serialize|deserialize)/i,
                // Standard library patterns
                /^(Base64|String|Utils|Helper|Manager|Service|Client|Factory|Builder)\./i,
                /^(System|Math|Object|Array|List|Map|Collection|Stream)\./i,
                // Language-specific standard libraries
                /^(encoding_ex|encoding|json|xml|yaml|base64|crypto|hashlib)\./i,  // Go/Python
                /^(java\.|javax\.|org\.|com\.)/i,  // Java packages
                /^(System\.|Microsoft\.|Microsoft\.Extensions\.)/i,  // C#/.NET
                /^(fs\.|path\.|os\.|util\.|http\.)/i,  // Node.js/Python
                /^[A-Z][a-zA-Z0-9]*\.(Base64Encode|Base64Decode|Marshal|Unmarshal|Parse|ToString)/i,  // Go/Java/C#
            ];
            
            // Check if value is a function name pattern
            if (commonFunctionPatterns.some(p => p.test(value))) {
                return true;
            }
            
            // Check if it's a method call on the value
            // Pattern: value.method() or value->method() or value::method()
            if (/^[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*\(/.test(value) ||
                /^[a-zA-Z_][a-zA-Z0-9_]*->[a-zA-Z_][a-zA-Z0-9_]*\(/.test(value) ||
                /^[a-zA-Z_][a-zA-Z0-9_]*::[a-zA-Z_][a-zA-Z0-9_]*\(/.test(value)) {
                return true;
            }
            
            // Method chaining: object.Method().AnotherMethod()
            if (/[a-zA-Z_][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*\(/.test(line) ||
                /[a-zA-Z_][a-zA-Z0-9]*->[a-zA-Z][a-zA-Z0-9]*\(/.test(line)) {
                if (/^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue)) {
                    return true;
                }
            }
        }
        
        // ===== FUNCTION CALLS WITH VARIABLE NAMES (All Languages) =====
        if (/[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)/.test(line)) {
            // If value looks like a function name or variable in function call
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue) && 
                trimmedValue.length < 50 && 
                !trimmedValue.includes('://') && 
                !trimmedValue.includes('@')) {
                // Additional check: is it in a function call context?
                const funcCallMatch = line.match(/([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/);
                if (funcCallMatch && funcCallMatch[1]) {
                    // If value contains or matches function name pattern
                    if (trimmedValue.includes(funcCallMatch[1]) || 
                        trimmedValue.length < 30) {
                        return true;
                    }
                }
            }
        }
        
        // ===== LANGUAGE-SPECIFIC PATTERNS =====
        
        // Python: lambda functions, list/dict comprehensions
        if (/lambda\s+\w+:|\[.*for\s+\w+\s+in|{.*for\s+\w+\s+in/.test(lowerLine)) {
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,}\])]?\s*$/.test(trimmedValue) && trimmedValue.length < 40) {
                return true;
            }
        }
        
        // Ruby: method calls with blocks, symbol methods
        if (/\.each\s*\{|\.map\s*\{|\.select\s*\{|\.find\s*\{|\[:['"]\w+['"]\]/.test(line)) {
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,}\])]?\s*$/.test(trimmedValue) && trimmedValue.length < 40) {
                return true;
            }
        }
        
        // JavaScript/TypeScript: arrow functions, optional chaining
        if (/=>|\.\?\.|\.\?\?/.test(line)) {
            if (/^[a-zA-Z_$][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 40) {
                return true;
            }
        }
        
        // Rust: method calls with ::, trait methods
        if (/::[a-zA-Z_][a-zA-Z0-9_]*\(|\.unwrap\(|\.expect\(|\.ok\(|\.unwrap_or\(/.test(line)) {
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 40) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Language-agnostic: Detects code patterns that are commonly false positives
     * Works for: Go, Python, Java, C#, JavaScript/TypeScript, Ruby, PHP, Rust, Swift, Kotlin, C/C++, and more
     */
    private isCodePattern(value: string, line: string, lowerLine: string, fileName?: string): boolean {
        const trimmedValue = value.trim();
        const fileExt = fileName ? fileName.split('.').pop()?.toLowerCase() : '';
        
        // ===== TYPE CONVERSIONS & CASTS =====
        // Go: string(variable), []byte(data), int(value)
        // C/C++: (int)value, static_cast<int>(value)
        // Java/C#: (String)value, value as String
        // Python: str(value), int(value), bytes(value)
        // Rust: value as Type, Type::from(value)
        if (/string\([^)]+\)|\[\]byte\([^)]+\)|int\([^)]+\)|float64\([^)]+\)|bool\([^)]+\)|uint\([^)]+\)/.test(line) ||
            /\(int\)|\(string\)|\(char\)|\(float\)|\(double\)|\(bool\)|\(boolean\)/.test(line) ||
            /static_cast|dynamic_cast|reinterpret_cast/.test(line) ||
            /as\s+(String|Int|Float|Double|Bool|Boolean)/i.test(line) ||
            /str\(|int\(|float\(|bool\(|bytes\(|list\(|dict\(|tuple\(/.test(lowerLine)) {
            // If value is the result of type conversion/cast
            if (/^string\(|^\[\]byte\(|^int\(|^float64\(|^bool\(|^uint\(|^\(int\)|^\(string\)|^as\s+/i.test(trimmedValue)) {
                return true;
            }
            // If value is a variable name in type conversion context
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 50) {
                return true;
            }
        }
        
        // ===== CONSTRUCTOR CALLS & OBJECT INITIALIZATION =====
        // Go: &TypeName{}, TypeName{}
        // Java/C#/Kotlin: new TypeName(), new TypeName {}
        // JavaScript/TypeScript: new TypeName(), new TypeName {}
        // Python: TypeName(), TypeName()
        // C++: TypeName(), new TypeName()
        // Ruby: TypeName.new, TypeName.new()
        // PHP: new TypeName(), new TypeName
        if (/&[A-Z][a-zA-Z0-9]*\{|^[A-Z][a-zA-Z0-9]*\{/.test(line) ||
            /new\s+[A-Z][a-zA-Z0-9]*\s*[({]/.test(line) ||
            /[A-Z][a-zA-Z0-9]*\s*\([^)]*\)/.test(line) && /new\s+/.test(lowerLine)) {
            // Check if value is part of constructor/initialization
            if (/^&[A-Z]|^[A-Z][a-zA-Z0-9]*\{|^new\s+[A-Z]/i.test(trimmedValue)) {
                return true;
            }
            // Check if value is a field name or variable in object literal
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 60) {
                return true;
            }
        }
        
        // ===== METHOD CALLS =====
        // All languages: object.method(), Class.method(), object->method()
        if (/[a-zA-Z_][a-zA-Z0-9]*\.[a-zA-Z_][a-zA-Z0-9]*\(/.test(line) ||
            /[a-zA-Z_][a-zA-Z0-9]*->[a-zA-Z_][a-zA-Z0-9]*\(/.test(line) ||
            /[a-zA-Z_][a-zA-Z0-9]*::[a-zA-Z_][a-zA-Z0-9]*\(/.test(line)) {
            // Check if value is a method name or result
            if (/^[a-zA-Z_][a-zA-Z0-9]*\.[a-zA-Z]/.test(trimmedValue) ||
                /^[a-zA-Z_][a-zA-Z0-9]*->[a-zA-Z]/.test(trimmedValue) ||
                /^[a-zA-Z_][a-zA-Z0-9]*::[a-zA-Z]/.test(trimmedValue) ||
                (/^[a-zA-Z_][a-zA-Z0-9]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 50)) {
                return true;
            }
        }
        
        // ===== FUNCTION CALLS =====
        // All languages: functionName(param), Class.functionName(param)
        if (/[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)/.test(line)) {
            // If value looks like a function name or variable in function call
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue) && 
                trimmedValue.length < 50 && 
                !trimmedValue.includes('://') && 
                !trimmedValue.includes('@') &&
                !trimmedValue.match(/^[a-f0-9]{32,}$/i)) { // Not a hex hash
                // Check if it's in a function call context
                const funcCallMatch = line.match(/([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/);
                if (funcCallMatch && funcCallMatch[1]) {
                    // If value contains or matches function name pattern
                    if (trimmedValue.includes(funcCallMatch[1]) || 
                        trimmedValue.length < 30) {
                        return true;
                    }
                }
            }
        }
        
        // ===== PROPERTY/FIELD ACCESS =====
        // JavaScript/TypeScript/Python: obj.property, obj.field
        // Go: obj.Field, obj.PrivateKey
        // Java/C#/Kotlin: obj.field, obj.getField()
        // C++: obj->field, obj.field
        // Ruby: obj.field, obj[:field]
        // PHP: $obj->field, $obj['field']
        if (/[a-zA-Z_$][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9]*/.test(line) && 
            !line.includes('(')) { // Not a method call
            if (/^[a-zA-Z_$][a-zA-Z0-9]*\.[a-zA-Z]/.test(trimmedValue) ||
                /^[a-zA-Z_$][a-zA-Z0-9]*\[/.test(trimmedValue) ||
                (/^[a-zA-Z_$][a-zA-Z0-9]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 40)) {
                return true;
            }
        }
        
        // ===== PACKAGE/MODULE IMPORTS =====
        // Go: encoding_ex.Base64Encode, types.Secret
        // Python: json.dumps, base64.b64encode
        // Java: java.util.Map, org.apache.commons
        // JavaScript/TypeScript: fs.readFile, path.join
        // C#: System.IO, Microsoft.Extensions
        // Ruby: require 'json', JSON.parse
        // PHP: use Namespace\Class, \Namespace\Class
        if (/[a-z][a-zA-Z0-9_]*\.[A-Z]/.test(line) && 
            (lowerLine.includes('import') || lowerLine.includes('from ') || 
             lowerLine.includes('require') || lowerLine.includes('using ') ||
             lowerLine.includes('package ') || lowerLine.includes('include'))) {
            if (/^[a-z][a-zA-Z0-9_]*\.[A-Z]/.test(trimmedValue) ||
                /^[a-z][a-zA-Z0-9_]*\.[a-z]/.test(trimmedValue)) {
                return true;
            }
        }
        
        // ===== LANGUAGE-SPECIFIC PATTERNS =====
        
        // Python: dict/list comprehensions, lambda functions
        if (fileExt === 'py' || lowerLine.includes('lambda ') || lowerLine.includes('[') && lowerLine.includes('for ')) {
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,}\])]?\s*$/.test(trimmedValue) && trimmedValue.length < 40) {
                return true;
            }
        }
        
        // Java/C#: getter/setter patterns, builder patterns
        if (/\.get[A-Z]|\.set[A-Z]|\.is[A-Z]|\.has[A-Z]/.test(line)) {
            if (/^[a-zA-Z_][a-zA-Z0-9]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 40) {
                return true;
            }
        }
        
        // JavaScript/TypeScript: optional chaining, nullish coalescing
        if (/\.\?\.|\.\?\?/.test(line)) {
            if (/^[a-zA-Z_$][a-zA-Z0-9]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 40) {
                return true;
            }
        }
        
        // Ruby: method calls with symbols, hash access
        if (/\[:|\['|\["|\.new|\.each|\.map|\.select/.test(line)) {
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,}\])]?\s*$/.test(trimmedValue) && trimmedValue.length < 40) {
                return true;
            }
        }
        
        // Rust: method calls with ::, trait methods
        if (/::[a-zA-Z_][a-zA-Z0-9_]*\(|\.unwrap\(|\.expect\(|\.ok\(/.test(line)) {
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 40) {
                return true;
            }
        }
        
        // C/C++: pointer dereference, struct member access
        if (/->[a-zA-Z_]|\.\w+\s*=|struct\s+\w+\s*\{/.test(line)) {
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 40) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Language-agnostic: Detects template strings/placeholders
     * Works for: Template engines, SQL templates, configuration templates
     */
    private isTemplateString(value: string): boolean {
        // Common template patterns:
        // {{variable}}, {{.Field}}, ${variable}, #{variable}, %{variable}, {variable}
        const templatePatterns = [
            /\{\{[^}]+\}\}/,           // {{variable}}
            /\{\{\.[^}]+\}\}/,         // {{.Field}}
            /\$\{[^}]+\}/,             // ${variable}
            /#\{[^}]+\}/,               // #{variable} (Ruby)
            /%\{[^}]+\}/,               // %{variable}
            /\{[a-zA-Z_][a-zA-Z0-9_]+\}/, // {variable}
            /<[a-zA-Z_][a-zA-Z0-9_]+>/,  // <variable>
            /\[\[[^\]]+\]\]/,          // [[variable]]
        ];
        
        // Check if value contains template syntax
        if (templatePatterns.some(pattern => pattern.test(value))) {
            return true;
        }
        
        // Check for common template variable names
        const templateVarNames = ['{{name}}', '{{username}}', '{{password}}', '{{token}}', 
                                 '{{key}}', '{{secret}}', '{{value}}', '{{id}}'];
        if (templateVarNames.some(template => value.includes(template))) {
            return true;
        }
        
        return false;
    }

    /**
     * Language-agnostic: Detects API endpoint paths
     * Works for: All languages that define API routes
     */
    private isApiEndpointPath(value: string, lowerLine: string): boolean {
        const cleanValue = value.replace(/^["']|["';]+$/g, '').trim();
        
        // Pattern: paths starting with /api/, /config/, /v1/, /v2/, etc.
        if (/^\/api\//.test(cleanValue) || 
            /^\/config\//.test(cleanValue) ||
            /^\/v\d+\//.test(cleanValue) ||
            /^\/change-/.test(cleanValue) ||
            /^\/reset-/.test(cleanValue) ||
            /^\/rotate-/.test(cleanValue) ||
            /^\/gen-/.test(cleanValue) ||
            /^\/refresh-/.test(cleanValue)) {
            
            // Check if it's in a route/endpoint definition context
            const isRouteContext = lowerLine.includes('route') ||
                lowerLine.includes('endpoint') ||
                lowerLine.includes('path') ||
                lowerLine.includes('const') && lowerLine.includes('path') ||
                lowerLine.includes('=') && (lowerLine.includes('/api/') || lowerLine.includes('/config/'));
            
            if (isRouteContext || cleanValue.length < 100) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Language-agnostic: Detects Protobuf metadata
     * Works for: All languages using Protobuf
     */
    private isProtobufMetadata(value: string, line: string): boolean {
        // Pattern: protobuf tags like "bytes,1,opt,name=key,proto3"
        if (/bytes,\d+,opt,name=/.test(value) ||
            /protobuf_key:/.test(line) ||
            /protobuf_val:/.test(line) ||
            /protobuf:"bytes/.test(line)) {
            return true;
        }
        
        return false;
    }

    /**
     * Language-agnostic: Detects test files
     * Works for: All languages with test file conventions
     */
    private isTestFile(fileName: string): boolean {
        const lowerFileName = fileName.toLowerCase();
        
        // Common test file patterns
        const testPatterns = [
            /_test\./,           // *_test.go, *_test.py, *_test.js
            /\.test\./,         // *.test.js, *.test.ts
            /\.spec\./,         // *.spec.js, *.spec.ts
            /test_/,            // test_*.py
            /\/test\//,         // test/ directory
            /\/tests\//,        // tests/ directory
            /\/spec\//,         // spec/ directory
            /\/__tests__\//,    // __tests__/ directory
            /testdata/,         // testdata directory
            /testutils/,        // testutils directory
        ];
        
        return testPatterns.some(pattern => pattern.test(lowerFileName));
    }

    /**
     * Language-agnostic: Detects test data patterns
     * Works for: All languages
     * Enhanced with more comprehensive test patterns
     */
    private isTestDataPattern(value: string, line: string): boolean {
        const lowerLine = line.toLowerCase();
        const lowerValue = value.toLowerCase();
        
        // Common test password patterns (expanded list)
        const testPasswords = [
            'password123', 'test123', 'target1234', 'admin123', 
            'testpassword', 'dummypassword', 'mockpassword',
            'newpassword123!', 'newpassword123', 'password123!',
            'testpassword123', 'adminpass', 'testpass',
            '2federatem0re', 'saPassword', 'oldPass'
        ];
        if (testPasswords.includes(lowerValue)) {
            return true;
        }
        
        // AWS Account ID pattern in test context (123456789012, 123456789042, etc.)
        // These are commonly used test account IDs
        if (/^1234567890\d{2}$/.test(value) || /^9\d{11}$/.test(value)) {
            // Check if it's in a test context
            if (lowerLine.includes('test') || 
                lowerLine.includes('mock') || 
                lowerLine.includes('example') ||
                lowerLine.includes('acc-') ||
                lowerLine.includes('account') ||
                lowerLine.includes('arn:aws')) {
                return true;
            }
        }
        
        // Pattern: test variable names
        if (/^(test|mock|fake|dummy|stub|spy)[A-Z]/.test(value) ||
            /^(expected|actual|result|tmp|temp)[A-Z]/.test(value)) {
            return true;
        }
        
        // Pattern: test token patterns (expanded)
        if (/^test[-_]token/i.test(value) ||
            /^mock[-_]secret/i.test(value) ||
            /^fake[-_]key/i.test(value) ||
            /^secret_name_test/i.test(value) ||
            /^test[-_]secret/i.test(value) ||
            /^dummy[-_]token/i.test(value)) {
            return true;
        }
        
        // Pattern: test hash/token values (low entropy, common in tests)
        // e.g., "e2n64jlr9gpamtn6oolikbxmh8f2vtce", "e6f2a011900dbb2a7ee579aaeca22087"
        if (/^[a-f0-9]{20,40}$/i.test(value) && value.length >= 20 && value.length <= 40) {
            // Check if it's in a test context and has low entropy
            const entropy = this.calculateSimpleEntropy(value);
            if (entropy < 3.5 && (lowerLine.includes('test') || 
                                  lowerLine.includes('mock') || 
                                  lowerLine.includes('dummy') ||
                                  lowerLine.includes('fake'))) {
                return true;
            }
        }
        
        // Pattern: simple test values
        if (value.length < 15 && /^[a-z0-9_-]+$/i.test(value) && 
            (lowerLine.includes('test') || lowerLine.includes('mock') || lowerLine.includes('fake'))) {
            return true;
        }
        
        // Pattern: test passwords with special characters but common patterns
        if (/^(test|mock|fake|dummy|admin|password)[0-9!@#$%^&*]+$/i.test(value)) {
            return true;
        }
        
        // Pattern: Go test struct field assignments with test values
        // e.g., Password: "NewPassword123!", Key: "key01-updated"
        if (lowerLine.includes(':') && 
            (lowerValue.includes('updated') || 
             lowerValue.includes('test') ||
             lowerValue.match(/^(new|old|test|mock|fake|dummy)[a-z0-9!@#$%^&*]+$/i))) {
            // Check if it's a struct field assignment
            if (/[A-Z][a-zA-Z0-9_]*:\s*["']?/.test(line)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Simple entropy calculation for test pattern detection
     */
    private calculateSimpleEntropy(str: string): number {
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
        
        return entropy;
    }

    /**
     * Language-agnostic: Detects object/struct field assignments
     * Works for: JavaScript/TypeScript, Go, Python, Java, C#, Ruby, etc.
     */
    private isObjectOrStructFieldAssignment(value: string, line: string, lowerLine: string): boolean {
        // Pattern: FieldName: variableName, or field_name: variable_name
        // Examples: Password: passwordValue, secret: secretValue, private_key: privateKey
        const fieldAssignmentPatterns = [
            /[A-Z][a-zA-Z0-9_]*:\s*[a-zA-Z_][a-zA-Z0-9_]*[,}]/,  // Go/JS: FieldName: variable,
            /[a-z_][a-zA-Z0-9_]*:\s*[a-zA-Z_][a-zA-Z0-9_]*[,}]/, // Python/JS: field_name: variable,
            /"[a-zA-Z_][a-zA-Z0-9_]*":\s*[a-zA-Z_][a-zA-Z0-9_]*[,}]/, // JSON: "field": variable,
        ];
        
        const isFieldAssignment = fieldAssignmentPatterns.some(pattern => pattern.test(line) || pattern.test(lowerLine));
        
        if (isFieldAssignment) {
            // Check if value matches a variable name pattern
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,}]?\s*$/.test(value.trim())) {
                // Check if it's a common field name
                const commonFieldNames = ['password', 'secret', 'token', 'key', 'apiKey', 
                                         'clientSecret', 'privateKey', 'accessToken', 'value'];
                if (commonFieldNames.some(name => value.toLowerCase().includes(name))) {
                    return true;
                }
                
                // If it's short and looks like a variable, filter it
                if (value.length < 40 && !value.includes('://') && !value.includes('@')) {
                    return true;
                }
            }
        }
        
        return false;
    }

    /**
     * Language-agnostic: Detects hash values in test context
     * Works for: All languages
     */
    private isHashValueInTestContext(value: string, fileName: string | undefined, lowerLine: string): boolean {
        if (!fileName) {
            return false;
        }
        
        // Check if it's a test file
        if (!this.isTestFile(fileName)) {
            return false;
        }
        
        // Pattern: SHA256, MD5, SHA1 hashes
        const hashPatterns = [
            /^[a-f0-9]{64}$/i,  // SHA256
            /^[a-f0-9]{32}$/i,  // MD5
            /^[a-f0-9]{40}$/i,  // SHA1
        ];
        
        const cleanValue = value.replace(/^["']|["';]+$/g, '').trim();
        
        if (hashPatterns.some(pattern => pattern.test(cleanValue))) {
            // Check if it's in a test context (test data, mock data, etc.)
            if (lowerLine.includes('test') || 
                lowerLine.includes('mock') || 
                lowerLine.includes('dummy') ||
                lowerLine.includes('fake') ||
                lowerLine.includes('signature') ||
                lowerLine.includes('fingerprint') ||
                lowerLine.includes('hash')) {
                return true;
            }
        }
        
        return false;
    }
}

