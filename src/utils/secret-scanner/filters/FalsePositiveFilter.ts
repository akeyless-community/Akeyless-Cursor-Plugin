import { SecretPattern, ScannerConfig } from '../types';
import { EntropyCalculator } from '../utils/EntropyCalculator';
import { logger } from '../../logger';

/**
 * Filters false positives from secret detections
 * Breaks down complex filtering logic into smaller, testable methods
 */
export class FalsePositiveFilter {
    constructor(private readonly config: ScannerConfig) {}

    /**
     * Main method to check if a detected value is a false positive
     */
    isFalsePositive(value: string, line: string, pattern?: SecretPattern): boolean {
        const lowerValue = value.toLowerCase();
        const lowerLine = line.toLowerCase();
        const isGoFile = this.isGoFile(line, lowerLine);

        // Early exit checks for common false positives
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
        return value.includes('_') && value === value.toUpperCase() &&
            (value.includes('AWS_') || value.includes('GCP_') || value.includes('AZURE_') ||
             value.includes('DATABASE_') || value.includes('API_') || value.includes('SECRET_'));
    }

    private isSimpleValue(value: string, lowerValue: string, pattern?: SecretPattern): boolean {
        const isClientPattern = pattern && (pattern.name.toLowerCase().includes('client') ||
            pattern.name.toLowerCase().includes('access_token'));
        const minLength = isClientPattern ? 6 : 10;

        return value.length < minLength || /^[a-z]+$/i.test(value) ||
            lowerValue.includes('true') || lowerValue.includes('false') || lowerValue.includes('null') ||
            lowerValue.includes('undefined') || lowerValue.includes('nan');
    }
}

