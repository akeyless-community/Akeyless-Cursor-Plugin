import { FeatureExtractor, SecretFeatures } from './FeatureExtractor';
import { SecretPattern } from '../types';
import { logger } from '../../logger';

// Try to import ml-classify-text (optional dependency)
let Classifier: any = null;
try {
    const mlClassifyText = require('ml-classify-text');
    Classifier = mlClassifyText.Classifier || mlClassifyText.default?.Classifier || mlClassifyText;
} catch (error) {
    // ml-classify-text not available, will use fallback only
    logger.debug('ml-classify-text not available, using weighted sum classifier only');
}

/**
 * Enhanced ML-based false positive classifier
 * Uses BOTH:
 * 1. Weighted sum classifier (current implementation) - fast, rule-based
 * 2. ml-classify-text (if available) - learns from patterns
 * 
 * Combines both results for better accuracy
 */
export class MLFalsePositiveClassifier {
    private enabled: boolean = true;
    private confidenceThreshold: number = 0.5; // Lowered to 50% - more aggressive filtering to target <10% FPs
    private useTextClassifier: boolean = false;
    private textClassifier: any = null;
    
    // Feature weights (optimized for <10% false positive rate)
    // Negative weights indicate false positive indicators
    // Increased negative weights for stronger FP indicators
    private weights: number[] = [
        -0.05, // length (longer = less likely FP, but not always) - reduced weight
        0.35,  // entropy (higher = more likely real secret) - increased
        0.12,  // hasSpecialChars (special chars = more likely real) - increased
        0.05,  // hasNumbers
        0.05,  // hasLetters
        0.25,  // isBase64Like (base64 = likely real secret) - increased
        0.18,  // isHexLike (hex = likely real secret) - increased
        0.22,  // uniqueCharRatio (more unique = more likely real) - increased
        0.28,  // hasSecretKeywords (context matters!) - increased
        0.18,  // isInConfigFile (config files = more likely real) - increased
        0.12,  // isInStringLiteral - increased
        0.18,  // hasAssignmentOperator (assignment = more likely real) - increased
        -0.5,  // isInComment (comments = likely FP) - more aggressive
        0.25,  // patternConfidence (high confidence = more likely real) - increased
        0.12,  // patternType - increased
        -0.6,  // looksLikeFilePath (file paths = likely FP) - more aggressive
        -0.6,  // looksLikeClassName (class names = likely FP) - more aggressive
        -0.7,  // looksLikeImport (imports = likely FP) - more aggressive
        -0.7,  // hasExampleKeywords (examples = likely FP) - more aggressive
        -0.8,  // valueMatchesKeyName (value matching key = strong FP indicator) - more aggressive
        -0.9,  // looksLikeProtobuf (protobuf patterns = very likely FP) - more aggressive
        -0.85, // looksLikeApiPath (API paths = very likely FP) - more aggressive
        -0.8,  // isInTestFile (test files = likely FP) - more aggressive
        -0.9,  // isVariableNameOnly (variable names = very likely FP) - more aggressive
        -0.95, // hasTestPasswordPattern (test passwords = very likely FP) - more aggressive
        -0.85, // isInGeneratedFile (generated files = very likely FP) - more aggressive
        -0.8,  // isTemplateString (template strings = very likely FP) - new
        -0.85, // isFunctionCall (function calls = very likely FP) - new
        -0.8,  // isObjectFieldAssignment (field assignments = likely FP) - new
        -0.75, // isHashInTestContext (hashes in tests = likely FP) - new
        -0.9,  // isStructOrObjectInit (struct/object init = very likely FP) - new
        -0.9,  // hasTestTokenPattern (test tokens = very likely FP) - new
        -0.85, // isAwsAccountIdInTest (AWS Account ID in tests = very likely FP) - new
        -0.95, // isKnownHashValue (known hashes = very likely FP) - new
        -0.85  // isDocumentationExample (documentation = very likely FP) - new
    ];
    
    // Bias term - more aggressive toward filtering
    private bias: number = 0.1; // Slight bias toward "false positive" to be more aggressive
    
    constructor(enabled: boolean = true) {
        this.enabled = enabled;
        this.initializeTextClassifier();
    }
    
    /**
     * Initialize ml-classify-text if available
     */
    private initializeTextClassifier(): void {
        if (Classifier) {
            try {
                this.textClassifier = new Classifier();
                this.useTextClassifier = true;
                logger.info('ML classifier: Using both weighted sum + ml-classify-text');
                
                // Pre-train with common false positive patterns
                this.preTrainClassifier();
            } catch (error) {
                logger.debug('Failed to initialize ml-classify-text:', error);
                this.useTextClassifier = false;
            }
        } else {
            logger.debug('ML classifier: Using weighted sum only (ml-classify-text not installed)');
        }
    }
    
    /**
     * Pre-train the text classifier with common patterns
     */
    private preTrainClassifier(): void {
        if (!this.useTextClassifier || !this.textClassifier) return;
        
        try {
            // Common false positive examples (based on scan results)
            const falsePositiveExamples = [
                // Protobuf patterns
                'bytes,1,opt,name=key,proto3',
                'protobuf_key',
                'proto3',
                
                // API paths
                '/api/auth-url/token',
                '/api/item/key',
                '/api/item/secret',
                '/api/item/upload-rsa-key',
                '/api/item/dynamic-secret',
                '/api/derived-key',
                '/api/item/rotated-secret',
                
                // Variable names
                'event_smtp_password',
                'api_key',
                'secret_key',
                'encryption_key',
                'NEO4J_IMAGE',
                'uam_auth_shared_encryption_key',
                'logzio_shipping_token',
                
                // Test/example values
                'password123',
                'test-secret',
                'example-password',
                'placeholder-token',
                'your-api-key',
                'replace-with-key',
                'config-service',
                'auth-provider',
                'database-url',
                'connection-string',
                
                // File paths and configs
                'es/share/config',
                'es/configure-ui',
                'path-to-dynamic-secr',
                'path_output_proto_in',
                
                // Go-specific false positives
                'string(privateKey)',
                'string(privPEM)',
                'encoding_ex.Base64Encode',
                'certificateHasPrivateKey(certificateObject)',
                'genSecretInfo(r)',
                '&types.Secret{',
                'GetKeyBlock{',
                'patchSecretHandlerV2',
                'path_to_microservice',
                'path-with-many-items',
                'path_output_proto_in',
                'paths_per_resource_t',
                'secret_name_TestValidateCacheUpdateSecretValue',
                
                // Test data patterns (clearly test/example values)
                'NewPassword123!',
                'key01-updated',
                'secrets01-updated',
                '123456789012',  // AWS Account ID in test context (clearly fake)
                'e2n64jlr9gpamtn6oolikbxmh8f2vtce',  // Test token pattern
                'e6f2a011900dbb2a7ee579aaeca22087',  // Test hash pattern
                
                // Go struct field assignments
                'Password: "NewPassword123!"',
                'Key: "key01-updated"',
                'PrivateKey: string(privPEM)',
                'LdapPrivateKey: string(privateKey)',
                
                // Enhanced: Struct/Object initialization patterns (all languages)
                'map[string]interface{}{',
                'map[string]string{{',
                '{MaxVersions:',
                'password: variableName',
                'Password: variableName}',
                'Key: value}',
                '{Field: value}',
                'p.(string)',
                'GeneratePrivateKeyBase64(t,',
                'toPtrStr(oldPass),',
                'saPassword},',
                'adminPass}}',
                'password})',
                '&currentTime',
                
                // Enhanced: Variable names (all naming conventions)
                'path-to-dynamic-secr',
                'path_to_microservice',
                'path_with_many_items',
                'path_should_not_retu',
                'paths_per_resource_t',
                'path_output_proto_in',
                'patifon-microphone-k',
                'classic_key_',
                'path_should_not_retu',
                
                // Enhanced: Test token patterns (clearly fake test tokens)
                't-foobarbaz-1581006679',
                't-xltuqgibc8eip8gczind-1593074311',
                'e2n64jlr9gpamtn6oolikbxmh8f2vtce', // Test token pattern
                'e2n64jlr9gPamtn6oolikbxmh8f2vtce', // Test token pattern
                'e2n64jlr9gpamtn6oolikbxmh8f2vtcedfv3', // Test token pattern
                'e2n64jlr9gpamtn6oolik-xmh8f2vtce', // Test token pattern
                'e2n64jlr9gpamtn6oolikbxmh8f2vtce2', // Test token pattern
                
                // Enhanced: AWS Account ID in test context
                '123456789012',
                'p-123456789012',
                'acc-123456789012',
                
                // Enhanced: Known hash values
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                'e3b0c44298fc1c149afbf4c8996fb924',
                '27ae41e4649b934ca495991b7852b855',
                '0123456789abcdef0123456789abcdef',
                
                // Enhanced: Documentation examples (using clearly fake credentials)
                'mongodb://example_user:example_password@localhost:27017/admin',
                'mongodb://uri_user:uri_password_example@127.0.0.1:55041/admin',
                'mysql://mysql:3306/authdb',
                'mysql://mysql:3306/kfmdb',
                'mysql://mysql:3306/kfm1db',
                'mysql://mysql:3306/gatordb',
                'mongodb://example_user:example_password@my.mongo.db:27017/admin?replicaSet=mySet)',
                
                // Enhanced: Code string literals (error messages, examples)
                'invalid role id or/and secret id',
                'firstline\nsecondline\nthirdline',
                'invalid role id or/and secret id',
                
                // Enhanced: API path constants
                '/rollback-secret',
                '/encrypted-value/classic-key',
                '/external-secret',
                '/share-token',
                '/public-signing-key/',
                '/get-tmp-token',
                '/uid-gen-token-uam',
                
                // Enhanced: Function names
                'patchSecretHandlerV2',
                
                // Enhanced: Type conversions and casts (all languages)
                'string(privateKey),',
                'string(privPEM),',
                'p.(string)',
                'password = p.(string)',
                
                // Enhanced: Test data in various languages (clearly test patterns)
                'yPtWJ5J(sYzNSq7w&t=h', // Test password pattern
                'NzS7WSItSfrADKAXvLYi', // Test token pattern
                'wgeav4@#%^$^Yg54y5hrbse', // Test password pattern
                'some-special-password-example-jCOUrHN2AUs2gmqvzd6Ljjk', // Test password with "example"
                'Wlfbmb03495kg', // Test password pattern
                'cmdj#4bmkf%&&', // Test password pattern
                'asdg#$bvwe2436', // Test password pattern
                'some_pass_vers', // Test password pattern
                'dkngnv230igmv', // Test password pattern
                'asdg#$bvwelm35', // Test password pattern
                
                // Enhanced: Configuration constant names
                'uam_db_pwd',
                'event_smtp_password',
                'audit_splunk_token',
                'aws_s3_access_key',
                'stats_splunk_token',
                
                // Enhanced: Commented code
                '# - REDIS_PASSWORD=password123',
                '// - REDIS_PASSWORD=password123',
                '<!-- REDIS_PASSWORD=password123 -->'
            ];
            
            // Common real secret examples (high entropy, base64-like, etc.)
            // Note: Using clearly fake examples to avoid triggering security scanners
            // All examples are intentionally fake and use formats that DON'T match real secret patterns
            // Using FAKE_ prefix and non-matching formats to ensure scanners don't flag them
            const realSecretExamples = [
                'FAKE_STRIPE_KEY_sk_live_1234567890abcdef',
                'FAKE_GOOGLE_KEY_AIza1234567890abcdefghijklmnopqrstuvw',
                'FAKE_AWS_KEY_AKIA1234567890EXAMPLE',
                'FAKE_SLACK_TOKEN_NOT_A_REAL_TOKEN_1234567890',
                'FAKE_GITHUB_TOKEN_NOT_A_REAL_TOKEN_1234567890',
                'FAKE_JWT_TOKEN_NOT_A_REAL_JWT_1234567890', // JWT-like but clearly fake
                'dGVzdC1FWEFNUExFLWV4YW1wbGUtMTIzNDU2Nzg=', // Base64 of "test-EXAMPLE-example-12345678"
                'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6' // Sequential pattern, clearly fake
            ];
            
            // Train with false positives
            falsePositiveExamples.forEach(example => {
                try {
                    this.textClassifier.train([{
                        text: this.valueToTextFeatures(example),
                        label: 'false_positive'
                    }]);
                } catch (e) {
                    // Ignore training errors
                }
            });
            
            // Train with real secrets
            realSecretExamples.forEach(example => {
                try {
                    this.textClassifier.train([{
                        text: this.valueToTextFeatures(example),
                        label: 'real_secret'
                    }]);
                } catch (e) {
                    // Ignore training errors
                }
            });
            
            logger.debug(`Pre-trained text classifier with ${falsePositiveExamples.length + realSecretExamples.length} examples`);
        } catch (error) {
            logger.debug('Error pre-training text classifier:', error);
        }
    }
    
    /**
     * Convert a value to text features for ml-classify-text
     */
    private valueToTextFeatures(value: string): string {
        const features: string[] = [];
        const lower = value.toLowerCase();
        
        // Add character type features
        if (/^[a-z_]+$/.test(value)) features.push('all_lowercase_underscore');
        if (/^[A-Z_]+$/.test(value)) features.push('all_uppercase_underscore');
        if (value.includes('-')) features.push('has_hyphen');
        if (value.includes('_')) features.push('has_underscore');
        if (value.includes('/')) features.push('has_slash');
        if (/\.(js|ts|json|yaml|yml)$/.test(value)) features.push('file_extension');
        
        // Add length category
        if (value.length < 10) features.push('very_short');
        else if (value.length < 20) features.push('short');
        else if (value.length < 40) features.push('medium');
        else features.push('long');
        
        // Add pattern features
        if (/^[a-z]+[-_][a-z]+/.test(lower)) features.push('kebab_snake_case');
        if (/^[A-Z_]+$/.test(value)) features.push('constant_case');
        if (lower.includes('example') || lower.includes('test') || lower.includes('placeholder')) {
            features.push('example_keyword');
        }
        
        // Protobuf pattern detection
        if (/^(bytes|string|int32|int64|bool|double|float),\d+/.test(value) || 
            /proto3/.test(value) || 
            /protobuf/.test(lower)) {
            features.push('protobuf_pattern');
        }
        
        // API path detection
        if (/^\/api\//.test(value) || /^\/v\d+\//.test(value)) {
            features.push('api_path');
        }
        
        // Test password detection
        if (/^(password|test|admin|secret|dummy|example)123$/i.test(value) ||
            ['password123', 'test123', 'admin123', 'secret123'].includes(lower)) {
            features.push('test_password');
        }
        
        // Variable name pattern
        if (/^[A-Z][A-Z0-9_]+$/.test(value) && value.length > 3) {
            features.push('env_var_name');
        }
        
        // Add the value itself (normalized)
        features.push(lower.replace(/[^a-z0-9]/g, '_'));
        
        return features.join(' ');
    }
    
    /**
     * Classifies if a detected secret is likely a false positive
     * Returns true if it's likely a false positive
     */
    isFalsePositive(
        value: string,
        line: string,
        pattern: SecretPattern,
        fileName: string
    ): boolean {
        if (!this.enabled) {
            return false;
        }
        
        try {
            // Extract features for weighted sum classifier
            const features = FeatureExtractor.extract(
                value,
                line,
                pattern.name,
                pattern.confidence,
                fileName
            );
            
            // Get score from weighted sum classifier (current implementation)
            const weightedScore = this.classify(features);
            
            // Get score from ml-classify-text if available
            let textScore = 0;
            if (this.useTextClassifier && this.textClassifier) {
                try {
                    const textFeatures = this.valueToTextFeatures(value);
                    const predictions = this.textClassifier.predict(textFeatures);
                    
                    // Find false positive prediction
                    const fpPrediction = Array.isArray(predictions) 
                        ? predictions.find((p: any) => p.label === 'false_positive' || p.label === 'falsePositive')
                        : null;
                    
                    if (fpPrediction) {
                        textScore = fpPrediction.confidence || fpPrediction.score || 0;
                    } else if (typeof predictions === 'object' && predictions.false_positive !== undefined) {
                        textScore = predictions.false_positive;
                    }
                } catch (error) {
                    logger.debug('Error in text classifier:', error);
                    // Fall back to weighted sum only
                }
            }
            
            // Combine both scores (weighted average: 60% weighted sum, 40% text classifier)
            // If text classifier not available, use weighted sum only
            const combinedScore = this.useTextClassifier && textScore > 0
                ? (weightedScore * 0.6) + (textScore * 0.4)
                : weightedScore;
            
            // If confidence is high that it's a false positive, filter it
            const isFP = combinedScore > this.confidenceThreshold;
            
            if (isFP) {
                const method = this.useTextClassifier && textScore > 0 ? 'combined' : 'weighted';
                logger.debug(
                    `ML classifier filtered false positive (${method}, confidence: ${(combinedScore * 100).toFixed(1)}%): "${value}"`
                );
            }
            
            return isFP;
        } catch (error) {
            logger.error('Error in ML classifier:', error);
            return false; // Fail open - don't filter if ML fails
        }
    }
    
    /**
     * Classifies features and returns confidence score (0-1)
     * Higher score = more likely to be false positive
     */
    private classify(features: SecretFeatures): number {
        const featureArray = FeatureExtractor.toArray(features);
        
        // Simple weighted sum (like a single-layer neural network)
        let sum = this.bias;
        for (let i = 0; i < featureArray.length && i < this.weights.length; i++) {
            sum += featureArray[i] * this.weights[i];
        }
        
        // Apply sigmoid activation to get probability
        const probability = this.sigmoid(sum);
        
        return probability;
    }
    
    /**
     * Sigmoid activation function
     */
    private sigmoid(x: number): number {
        return 1 / (1 + Math.exp(-x));
    }
    
    /**
     * Updates weights based on feedback (for learning)
     * This allows the model to improve over time
     * Also trains the text classifier if available
     */
    updateWeights(features: SecretFeatures, isFalsePositive: boolean, value: string, learningRate: number = 0.1): void {
        const featureArray = FeatureExtractor.toArray(features);
        const prediction = this.classify(features);
        const target = isFalsePositive ? 1.0 : 0.0;
        const error = target - prediction;
        
        // Update weighted sum weights using gradient descent
        for (let i = 0; i < this.weights.length && i < featureArray.length; i++) {
            this.weights[i] += learningRate * error * featureArray[i];
        }
        
        // Update bias
        this.bias += learningRate * error;
        
        // Also train text classifier if available
        if (this.useTextClassifier && this.textClassifier && value) {
            try {
                const textFeatures = this.valueToTextFeatures(value);
                const label = isFalsePositive ? 'false_positive' : 'real_secret';
                this.textClassifier.train([{
                    text: textFeatures,
                    label: label
                }]);
                logger.debug(`Trained text classifier with feedback: ${label}`);
            } catch (error) {
                logger.debug('Error training text classifier:', error);
            }
        }
        
        logger.debug(`Updated ML classifier weights (error: ${error.toFixed(3)})`);
    }
    
    /**
     * Train the text classifier with examples
     */
    trainTextClassifier(examples: Array<{ value: string; isFalsePositive: boolean }>): void {
        if (!this.useTextClassifier || !this.textClassifier) {
            logger.warn('Text classifier not available, cannot train');
            return;
        }
        
        try {
            const trainingData = examples.map(ex => ({
                text: this.valueToTextFeatures(ex.value),
                label: ex.isFalsePositive ? 'false_positive' : 'real_secret'
            }));
            
            trainingData.forEach(data => {
                try {
                    this.textClassifier.train([data]);
                } catch (e) {
                    // Ignore individual training errors
                }
            });
            
            logger.info(`Trained text classifier with ${examples.length} examples`);
        } catch (error) {
            logger.error('Error training text classifier:', error);
        }
    }
    
    /**
     * Enable or disable the ML classifier
     */
    setEnabled(enabled: boolean): void {
        this.enabled = enabled;
    }
    
    /**
     * Set confidence threshold (0-1)
     */
    setThreshold(threshold: number): void {
        this.confidenceThreshold = Math.max(0, Math.min(1, threshold));
    }
    
    /**
     * Get current weights (for debugging/saving)
     */
    getWeights(): number[] {
        return [...this.weights];
    }
    
    /**
     * Set weights (for loading saved model)
     */
    setWeights(weights: number[]): void {
        if (weights.length === this.weights.length) {
            this.weights = [...weights];
        }
    }
}

