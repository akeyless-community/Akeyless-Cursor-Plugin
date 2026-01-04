/**
 * Pre-trained model for false positive detection
 * 
 * This module provides pre-trained weights and patterns that work out-of-the-box
 * without requiring training data. The model is based on analysis of common false
 * positive patterns from FPSecretBench and real-world secret detection scenarios.
 * 
 * Benefits:
 * - No training required - works immediately
 * - Pre-optimized weights based on extensive analysis
 * - Can be updated/improved without retraining
 * - Lightweight and fast
 */

import { logger } from '../../logger';

/**
 * Pre-trained weights optimized for false positive detection
 * These weights were derived from analysis of FPSecretBench dataset and
 * common false positive patterns across multiple secret detection tools.
 */
export const PRETRAINED_WEIGHTS = [
    // Value characteristics (0-7)
    -0.08, // length - slightly negative (longer values can be FPs if they're paths/names)
    0.38,  // entropy - strong positive (high entropy = real secret)
    0.15,  // hasSpecialChars - positive (special chars = more likely real)
    0.06,  // hasNumbers
    0.06,  // hasLetters
    0.28,  // isBase64Like - strong positive (base64 = likely real secret)
    0.20,  // isHexLike - positive (hex = likely real secret)
    0.25,  // uniqueCharRatio - positive (more unique = more likely real)
    
    // Context features (8-12)
    0.30,  // hasSecretKeywords - strong positive (context matters!)
    0.20,  // isInConfigFile - positive (config files = more likely real)
    0.14,  // isInStringLiteral
    0.20,  // hasAssignmentOperator - positive (assignment = more likely real)
    -0.55, // isInComment - strong negative (comments = very likely FP)
    
    // Pattern features (13-14)
    0.28,  // patternConfidence - strong positive (high confidence = more likely real)
    0.14,  // patternType
    
    // False positive indicators (15-32)
    -0.65, // looksLikeFilePath - strong negative (file paths = very likely FP)
    -0.65, // looksLikeClassName - strong negative (class names = very likely FP)
    -0.75, // looksLikeImport - very strong negative (imports = very likely FP)
    -0.75, // hasExampleKeywords - very strong negative (examples = very likely FP)
    -0.85, // valueMatchesKeyName - very strong negative (value matching key = strong FP)
    -0.92, // looksLikeProtobuf - very strong negative (protobuf = very likely FP)
    -0.88, // looksLikeApiPath - very strong negative (API paths = very likely FP)
    -0.82, // isInTestFile - strong negative (test files = very likely FP)
    -0.92, // isVariableNameOnly - very strong negative (variable names = very likely FP)
    -0.96, // hasTestPasswordPattern - very strong negative (test passwords = very likely FP)
    -0.88, // isInGeneratedFile - very strong negative (generated files = very likely FP)
    -0.82, // isTemplateString - strong negative (template strings = very likely FP)
    -0.88, // isFunctionCall - very strong negative (function calls = very likely FP)
    -0.82, // isObjectFieldAssignment - strong negative (field assignments = very likely FP)
    -0.78, // isHashInTestContext - strong negative (hashes in tests = very likely FP)
    -0.92, // isStructOrObjectInit - very strong negative (struct/object init = very likely FP)
    -0.92, // hasTestTokenPattern - very strong negative (test tokens = very likely FP)
    -0.88, // isAwsAccountIdInTest - very strong negative (AWS Account ID in tests = very likely FP)
    -0.96, // isKnownHashValue - very strong negative (known hashes = very likely FP)
    -0.88  // isDocumentationExample - very strong negative (documentation = very likely FP)
];

/**
 * Pre-trained bias term
 * Slight bias toward filtering false positives
 */
export const PRETRAINED_BIAS = 0.12;

/**
 * Pre-trained false positive patterns
 * These patterns are known to be false positives based on analysis
 * of FPSecretBench and real-world secret detection results.
 */
export const PRETRAINED_FALSE_POSITIVE_PATTERNS = {
    // Protobuf patterns
    protobuf: [
        /^bytes,\d+.*proto3?$/i,
        /^protobuf[_-]?key$/i,
        /^proto3$/i,
        /protobuf:"bytes,\d+/i
    ],
    
    // API paths
    apiPaths: [
        /^\/api\/[a-z0-9-]+\/[a-z0-9-]+$/i,
        /^\/v\d+\/[a-z0-9-]+$/i,
        /^\/[a-z]+(-[a-z]+)*\/[a-z]+$/i
    ],
    
    // Variable names and storage keys
    variableNames: [
        /^[A-Z][A-Z0-9_]+$/,  // UPPER_CASE constants
        /^[a-z][a-z0-9_]+$/,  // snake_case variables
        /^[a-z][a-z0-9-]+$/,  // kebab-case variables
        /^[A-Z][a-zA-Z0-9]*$/, // PascalCase
        /^akeyless_[a-z_]+$/,  // Akeyless storage keys
        /^secrets_manager_[a-z_]+$/,  // Secrets manager storage keys
        /^user_[a-z_]+$/,  // User storage keys
    ],
    
    // Test patterns
    testPatterns: [
        /^(password|test|admin|secret|dummy|example)123?$/i,
        /^t-[a-z0-9-]+-\d+$/i,  // Test tokens
        /^123456789012$/,       // AWS Account ID in tests
    ],
    
    // File paths
    filePaths: [
        /^[a-zA-Z0-9_-]+\.(js|ts|jsx|tsx|json|css|html|png|jpg|jpeg|gif|svg)$/i,
        /^[/\\].*\.(js|ts|json|yaml|yml)$/i,
        /^es\/[a-z0-9-]+$/i,  // Elasticsearch paths
    ],
    
    // Known hash values
    knownHashes: [
        /^e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855$/, // SHA256 empty
        /^da39a3ee5e6b4b0d3255bfef95601890afd80709$/, // SHA1 empty
        /^d41d8cd98f00b204e9800998ecf8427e$/, // MD5 empty
    ],
    
    // Documentation examples
    documentation: [
        /mongodb:\/\/example_[a-z]+:example_[a-z]+@/i,
        /mysql:\/\/mysql:\d+\/[a-z]+db$/i,
        /your-[a-z-]+/i,
        /replace-[a-z-]+/i,
        /placeholder-[a-z-]+/i,
        /^urn:ietf:wg:oauth:2\.0:oob$/i,  // Standard OAuth redirect URI
    ],
    
    // Code patterns
    codePatterns: [
        /^string\([a-zA-Z_][a-zA-Z0-9_]*\)$/i,  // Type conversions
        /^&[A-Z][a-zA-Z0-9]*\{$/i,  // Go structs
        /^map\[string\](interface|string)\{\{$/i,  // Go maps
        /^[a-zA-Z_][a-zA-Z0-9_]*\([a-z]+,$/i,  // Function calls with test params
        /^(typeof|instanceof)\s+[a-zA-Z_][a-zA-Z0-9_]*\s*===?$/i,  // Type checking code fragments
        /^\([a-zA-Z_][a-zA-Z0-9_]*\s*as\s+any\)$/i,  // Type assertions
        /^[a-zA-Z_][a-zA-Z0-9_]*\?\.(value|scores|password)$/i,  // Optional chaining property access
        /^\{[a-z_]+\}$/i,  // JSX prop names like {password}
        /^,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,?\s*$/i,  // Code fragments in logger/log statements
        /^[a-z_]+:\s*'[a-z_]+'\s*as\s+keyof/i,  // TypeScript 'property' as keyof Type
    ],
    
    // Storage key assignments
    storageKeys: [
        /^akeyless_[a-z_]+$/i,  // Akeyless storage keys
        /^secrets_manager_[a-z_]+$/i,  // Secrets manager storage keys
        /^user_[a-z_]+$/i,  // User storage keys
        /^[a-z_]+_[a-z_]+_key$/i,  // Generic storage key pattern
        /^[a-z_]+_[a-z_]+_timestamp$/i,  // Timestamp key pattern
    ]
};

/**
 * Pre-trained real secret patterns
 * These patterns are strong indicators of real secrets
 */
export const PRETRAINED_REAL_SECRET_PATTERNS = {
    // High entropy patterns
    highEntropy: [
        /^[A-Za-z0-9+/=]{40,}$/,  // Long base64
        /^[0-9a-fA-F]{32,}$/,     // Long hex
    ],
    
    // Secret-like patterns
    secretLike: [
        /^sk_live_[a-zA-Z0-9]{32,}$/i,  // Stripe keys
        /^AKIA[0-9A-Z]{16}$/i,  // AWS access keys
        /^ghp_[a-zA-Z0-9]{36}$/i,  // GitHub tokens
        /^xox[baprs]-[0-9a-zA-Z-]{10,}$/i,  // Slack tokens
    ],
    
    // Connection strings
    connectionStrings: [
        /^[a-z]+:\/\/[^:]+:[^@]+@[^/]+\//i,  // Database URLs with credentials
        /^mongodb\+srv:\/\/[^:]+:[^@]+@/i,  // MongoDB connection strings
    ]
};

/**
 * Check if a value matches pre-trained false positive patterns
 * This is a fast pattern-based check that doesn't require ML
 */
export function matchesFalsePositivePattern(value: string): boolean {
    const allPatterns = [
        ...PRETRAINED_FALSE_POSITIVE_PATTERNS.protobuf,
        ...PRETRAINED_FALSE_POSITIVE_PATTERNS.apiPaths,
        ...PRETRAINED_FALSE_POSITIVE_PATTERNS.testPatterns,
        ...PRETRAINED_FALSE_POSITIVE_PATTERNS.filePaths,
        ...PRETRAINED_FALSE_POSITIVE_PATTERNS.knownHashes,
        ...PRETRAINED_FALSE_POSITIVE_PATTERNS.documentation,
        ...PRETRAINED_FALSE_POSITIVE_PATTERNS.codePatterns,
        ...PRETRAINED_FALSE_POSITIVE_PATTERNS.storageKeys
    ];
    
    // Check variable name patterns (with length constraints)
    if (value.length >= 3 && value.length <= 50) {
        for (const pattern of PRETRAINED_FALSE_POSITIVE_PATTERNS.variableNames) {
            if (pattern.test(value)) {
                return true;
            }
        }
    }
    
    // Check storage key patterns
    for (const pattern of PRETRAINED_FALSE_POSITIVE_PATTERNS.storageKeys) {
        if (pattern.test(value)) {
            return true;
        }
    }
    
    // Check all other patterns
    for (const pattern of allPatterns) {
        if (pattern.test(value)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Check if a value matches pre-trained real secret patterns
 * This helps identify high-confidence real secrets
 */
export function matchesRealSecretPattern(value: string): boolean {
    const allPatterns = [
        ...PRETRAINED_REAL_SECRET_PATTERNS.highEntropy,
        ...PRETRAINED_REAL_SECRET_PATTERNS.secretLike,
        ...PRETRAINED_REAL_SECRET_PATTERNS.connectionStrings
    ];
    
    for (const pattern of allPatterns) {
        if (pattern.test(value)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Pre-trained model configuration
 */
export interface PreTrainedModelConfig {
    weights: number[];
    bias: number;
    version: string;
    description: string;
}

/**
 * Get the default pre-trained model configuration
 */
export function getPreTrainedModel(): PreTrainedModelConfig {
    return {
        weights: PRETRAINED_WEIGHTS,
        bias: PRETRAINED_BIAS,
        version: '1.0.0',
        description: 'Pre-trained model based on FPSecretBench analysis and real-world patterns'
    };
}

/**
 * Validate that weights array matches expected feature count
 */
export function validateModel(model: PreTrainedModelConfig, expectedFeatureCount: number): boolean {
    if (model.weights.length !== expectedFeatureCount) {
        logger.warn(
            `Pre-trained model has ${model.weights.length} weights, expected ${expectedFeatureCount}. ` +
            `Model may not work correctly.`
        );
        return false;
    }
    return true;
}

