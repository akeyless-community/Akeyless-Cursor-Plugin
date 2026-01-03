/**
 * Extracts features from detected secrets for ML classification
 * These features help distinguish real secrets from false positives
 */
export interface SecretFeatures {
    // Value characteristics
    length: number;
    entropy: number;
    hasSpecialChars: number; // 0 or 1
    hasNumbers: number; // 0 or 1
    hasLetters: number; // 0 or 1
    isBase64Like: number; // 0 or 1
    isHexLike: number; // 0 or 1
    uniqueCharRatio: number; // unique chars / total length
    
    // Context features
    hasSecretKeywords: number; // 0 or 1 (api_key, password, token, etc.)
    isInConfigFile: number; // 0 or 1
    isInStringLiteral: number; // 0 or 1
    hasAssignmentOperator: number; // 0 or 1
    isInComment: number; // 0 or 1
    
    // Pattern features
    patternConfidence: number; // 0.5 for medium, 1.0 for high
    patternType: number; // encoded pattern type
    
    // False positive indicators
    looksLikeFilePath: number; // 0 or 1
    looksLikeClassName: number; // 0 or 1
    looksLikeImport: number; // 0 or 1
    hasExampleKeywords: number; // 0 or 1
    valueMatchesKeyName: number; // 0 or 1 (value matches variable/key name)
    
    // New features for better false positive detection
    looksLikeProtobuf: number; // 0 or 1 (protobuf metadata patterns)
    looksLikeApiPath: number; // 0 or 1 (API endpoint paths)
    isInTestFile: number; // 0 or 1 (test files, examples, docs)
    isVariableNameOnly: number; // 0 or 1 (variable name, not value)
    hasTestPasswordPattern: number; // 0 or 1 (password123, test123, etc.)
    isInGeneratedFile: number; // 0 or 1 (.pb.go, generated files)
    
    // Language-agnostic features
    isTemplateString: number; // 0 or 1 ({{variable}}, ${var}, etc.)
    isFunctionCall: number; // 0 or 1 (function calls, method invocations)
    isObjectFieldAssignment: number; // 0 or 1 (object/struct field assignments)
    isHashInTestContext: number; // 0 or 1 (hash values in test files)
    
    // Enhanced features for better false positive detection
    isStructOrObjectInit: number; // 0 or 1 (struct/object initialization patterns - all languages)
    hasTestTokenPattern: number; // 0 or 1 (test token patterns like t- prefix)
    isAwsAccountIdInTest: number; // 0 or 1 (AWS Account ID in test context)
    isKnownHashValue: number; // 0 or 1 (known hash values like empty string SHA256)
    isDocumentationExample: number; // 0 or 1 (documentation examples, commented code)
}

export class FeatureExtractor {
    /**
     * Extracts features from a detected secret value and its context
     */
    static extract(
        value: string,
        line: string,
        patternName: string,
        patternConfidence: 'high' | 'medium',
        fileName: string
    ): SecretFeatures {
        const lowerLine = line.toLowerCase();
        
        // Calculate entropy (reuse existing calculator logic)
        const entropy = this.calculateEntropy(value);
        
        // Value characteristics
        const length = value.length;
        const hasSpecialChars = /[^a-zA-Z0-9]/.test(value) ? 1 : 0;
        const hasNumbers = /\d/.test(value) ? 1 : 0;
        const hasLetters = /[a-zA-Z]/.test(value) ? 1 : 0;
        const isBase64Like = /^[A-Za-z0-9+/=]+$/.test(value) && value.length > 20 ? 1 : 0;
        const isHexLike = /^[0-9a-fA-F]+$/.test(value) && value.length > 10 ? 1 : 0;
        const uniqueChars = new Set(value).size;
        const uniqueCharRatio = length > 0 ? uniqueChars / length : 0;
        
        // Context features
        const secretKeywords = /(api[_-]?key|password|token|secret|credential|auth|access[_-]?key)/i;
        const hasSecretKeywords = secretKeywords.test(line) ? 1 : 0;
        const isInConfigFile = /\.(env|config|conf|properties|ini|yaml|yml|json)$/i.test(fileName) ? 1 : 0;
        const isInStringLiteral = /["'`]/.test(line) ? 1 : 0;
        const hasAssignmentOperator = /[:=]/.test(line) ? 1 : 0;
        const isInComment = /\/\/|\/\*|#/.test(line.trim()) ? 1 : 0;
        
        // Pattern features
        const confidenceValue = patternConfidence === 'high' ? 1.0 : 0.5;
        const patternType = this.encodePatternType(patternName);
        
        // False positive indicators
        const looksLikeFilePath = /[/\\]|\.(js|ts|jsx|tsx|json|css|html|png|jpg|svg)$/i.test(value) ? 1 : 0;
        const looksLikeClassName = /^[A-Z][a-zA-Z0-9]*(Config|Account|Service|Provider|Client|Manager)$/.test(value) ? 1 : 0;
        const looksLikeImport = /^(import|from|require|include)\s/.test(lowerLine.trim()) ? 1 : 0;
        const hasExampleKeywords = /(example|dummy|placeholder|sample|test|your-|replace-)/i.test(value) ? 1 : 0;
        
        // Check if value matches the key/variable name (e.g., EVENT_SMTP_PASSWORD = "event_smtp_password")
        const valueMatchesKeyName = this.checkValueMatchesKeyName(value, line) ? 1 : 0;
        
        // New features for better false positive detection
        const looksLikeProtobuf = this.checkProtobufPattern(value, line) ? 1 : 0;
        const looksLikeApiPath = this.checkApiPath(value) ? 1 : 0;
        const isInTestFile = this.checkTestFile(fileName) ? 1 : 0;
        const isVariableNameOnly = this.checkVariableNameOnly(value, line) ? 1 : 0;
        const hasTestPasswordPattern = this.checkTestPassword(value) ? 1 : 0;
        const isInGeneratedFile = this.checkGeneratedFile(fileName) ? 1 : 0;
        
        // Language-agnostic features
        const isTemplateString = this.checkTemplateString(value) ? 1 : 0;
        const isFunctionCall = this.checkFunctionCall(value, line) ? 1 : 0;
        const isObjectFieldAssignment = this.checkObjectFieldAssignment(value, line) ? 1 : 0;
        const isHashInTestContext = this.checkHashInTestContext(value, fileName, lowerLine) ? 1 : 0;
        
        // Enhanced features for better false positive detection
        const isStructOrObjectInit = this.checkStructOrObjectInit(value, line) ? 1 : 0;
        const hasTestTokenPattern = this.checkTestTokenPattern(value, fileName) ? 1 : 0;
        const isAwsAccountIdInTest = this.checkAwsAccountIdInTest(value, fileName) ? 1 : 0;
        const isKnownHashValue = this.checkKnownHashValue(value) ? 1 : 0;
        const isDocumentationExample = this.checkDocumentationExample(value, line, fileName) ? 1 : 0;
        
        return {
            length: this.normalize(length, 0, 200),
            entropy: this.normalize(entropy, 0, 8),
            hasSpecialChars,
            hasNumbers,
            hasLetters,
            isBase64Like,
            isHexLike,
            uniqueCharRatio,
            hasSecretKeywords,
            isInConfigFile,
            isInStringLiteral,
            hasAssignmentOperator,
            isInComment,
            patternConfidence: confidenceValue,
            patternType,
            looksLikeFilePath,
            looksLikeClassName,
            looksLikeImport,
            hasExampleKeywords,
            valueMatchesKeyName,
            looksLikeProtobuf,
            looksLikeApiPath,
            isInTestFile,
            isVariableNameOnly,
            hasTestPasswordPattern,
            isInGeneratedFile,
            isTemplateString,
            isFunctionCall,
            isObjectFieldAssignment,
            isHashInTestContext,
            isStructOrObjectInit,
            hasTestTokenPattern,
            isAwsAccountIdInTest,
            isKnownHashValue,
            isDocumentationExample
        };
    }
    
    /**
     * Converts features to array for ML model input
     */
    static toArray(features: SecretFeatures): number[] {
        return [
            features.length,
            features.entropy,
            features.hasSpecialChars,
            features.hasNumbers,
            features.hasLetters,
            features.isBase64Like,
            features.isHexLike,
            features.uniqueCharRatio,
            features.hasSecretKeywords,
            features.isInConfigFile,
            features.isInStringLiteral,
            features.hasAssignmentOperator,
            features.isInComment,
            features.patternConfidence,
            features.patternType,
            features.looksLikeFilePath,
            features.looksLikeClassName,
            features.looksLikeImport,
            features.hasExampleKeywords,
            features.valueMatchesKeyName,
            features.looksLikeProtobuf,
            features.looksLikeApiPath,
            features.isInTestFile,
            features.isVariableNameOnly,
            features.hasTestPasswordPattern,
            features.isInGeneratedFile,
            features.isTemplateString,
            features.isFunctionCall,
            features.isObjectFieldAssignment,
            features.isHashInTestContext,
            features.isStructOrObjectInit,
            features.hasTestTokenPattern,
            features.isAwsAccountIdInTest,
            features.isKnownHashValue,
            features.isDocumentationExample
        ];
    }
    
    /**
     * Simple entropy calculation (Shannon entropy)
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
        
        return entropy;
    }
    
    /**
     * Encodes pattern type as a number (simple hash)
     */
    private static encodePatternType(patternName: string): number {
        const types: Record<string, number> = {
            'api': 0.1,
            'password': 0.2,
            'token': 0.3,
            'key': 0.4,
            'secret': 0.5,
            'credential': 0.6,
            'connection': 0.7,
            'aws': 0.8,
            'azure': 0.9,
            'gcp': 1.0
        };
        
        const lower = patternName.toLowerCase();
        for (const [key, value] of Object.entries(types)) {
            if (lower.includes(key)) {
                return value;
            }
        }
        
        return 0.5; // default
    }
    
    /**
     * Normalizes a value to 0-1 range
     */
    private static normalize(value: number, min: number, max: number): number {
        if (max === min) return 0;
        return Math.max(0, Math.min(1, (value - min) / (max - min)));
    }
    
    /**
     * Checks if the value matches the key/variable name
     * Supports: All naming conventions (snake_case, PascalCase, camelCase, kebab-case)
     * e.g., EVENT_SMTP_PASSWORD = "event_smtp_password"
     * e.g., AuthPathGetShareToken = "/share-token"
     */
    private static checkValueMatchesKeyName(value: string, line: string): boolean {
        const lowerValue = value.toLowerCase().replace(/^["']|["']$/g, '').replace(/^\/+|\/+$/g, ''); // Remove quotes and leading/trailing slashes
        const lowerLine = line.toLowerCase();
        
        // Extract key name before = or : (supports PascalCase, camelCase, snake_case, UPPER_CASE)
        // Pattern: VariableName =, variableName =, VARIABLE_NAME =, variable_name =
        const keyMatch = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*[:=]/);
        if (!keyMatch) {
            return false;
        }
        
        const keyName = keyMatch[1];
        const lowerKeyName = keyName.toLowerCase();
        
        // Split key name into words (handle PascalCase, camelCase, snake_case, UPPER_CASE)
        // PascalCase: AuthPathGetShareToken -> [auth, path, get, share, token]
        // snake_case: auth_path_get_share_token -> [auth, path, get, share, token]
        // UPPER_CASE: AUTH_PATH_GET_SHARE_TOKEN -> [auth, path, get, share, token]
        const keyWords = this.splitIntoWords(keyName).map(w => w.toLowerCase()).filter(w => w.length > 1);
        
        // Split value into words (handle kebab-case, snake_case, paths)
        // /share-token -> [share, token]
        // share-token -> [share, token]
        // share_token -> [share, token]
        const valueWords = lowerValue.split(/[\/\-_\s]+/).filter(w => w.length > 1);
        
        if (keyWords.length === 0 || valueWords.length === 0) {
            return false;
        }
        
        // Normalize both (remove separators) for exact match check
        const normalizeKey = keyWords.join('').toLowerCase();
        const normalizeValue = valueWords.join('').toLowerCase();
        
        // Exact match after normalization
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
    private static splitIntoWords(name: string): string[] {
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
     * Checks if value looks like protobuf metadata pattern
     * e.g., "bytes,1,opt,name=key,proto3"
     */
    private static checkProtobufPattern(value: string, line: string): boolean {
        // Check for protobuf metadata patterns
        if (/^(bytes|string|int32|int64|bool|double|float),\d+/.test(value)) {
            return true;
        }
        
        // Check for protobuf field tags
        if (/protobuf:"bytes,\d+/.test(line) || /proto3/.test(line)) {
            return true;
        }
        
        // Check for protobuf key/value patterns
        if (/protobuf_key:"bytes,1,opt,name=key,proto3"/.test(line)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Checks if value looks like an API endpoint path
     * e.g., "/api/auth-url/token", "/api/item/key"
     */
    private static checkApiPath(value: string): boolean {
        // API paths typically start with /api/, /v1/, /v2/, etc.
        if (/^\/api\//.test(value) || /^\/v\d+\//.test(value)) {
            return true;
        }
        
        // Check for common API path patterns
        if (/^\/[a-z]+(-[a-z]+)*\/[a-z]+/.test(value) && value.length < 50) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Checks if file is in test/example/documentation directory
     */
    private static checkTestFile(fileName: string): boolean {
        const lowerFileName = fileName.toLowerCase();
        
        // Test directories
        if (/\/test\//.test(lowerFileName) || 
            /\/tests\//.test(lowerFileName) ||
            /\/spec\//.test(lowerFileName) ||
            /\/examples?\//.test(lowerFileName) ||
            /\/docs?\//.test(lowerFileName) ||
            /\/sample/.test(lowerFileName)) {
            return true;
        }
        
        // Test file patterns
        if (/_test\.|\.test\.|_spec\.|\.spec\./.test(lowerFileName)) {
            return true;
        }
        
        // Documentation files
        if (/readme|\.md$|\.txt$/.test(lowerFileName)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Checks if the detected value is actually a variable name, not a value
     * Supports: All languages with various naming conventions
     * e.g., export NEO4J_IMAGE="${NEO4J_IMAGE:-neo4j:5.26.3-community}"
     * e.g., path-to-dynamic-secr, path_to_microservice, path_with_many_items
     */
    private static checkVariableNameOnly(value: string, line: string): boolean {
        const trimmedValue = value.trim().replace(/^["']|["']$/g, '');
        const lowerLine = line.toLowerCase();
        
        // Check if value is all uppercase with underscores (common for env var names)
        if (/^[A-Z][A-Z0-9_]+$/.test(trimmedValue) && trimmedValue.length > 3) {
            // Check if it's being used as a variable name in the line
            if (new RegExp(`\\b${trimmedValue}\\b`).test(line) && 
                (/\$\{/.test(line) || /export\s+/.test(line) || /const\s+/.test(line) || /let\s+/.test(line))) {
                return true;
            }
        }
        
        // Check for variable declarations where value matches variable name pattern
        // Snake_case: path_to_secret, path_with_many_items
        if (/^[a-z][a-z0-9_]+$/.test(trimmedValue) && trimmedValue.length > 3 && trimmedValue.length < 50) {
            if (new RegExp(`\\b${trimmedValue}\\s*[:=]`).test(lowerLine) ||
                new RegExp(`\\b${trimmedValue}\\s*[,};)]`).test(lowerLine)) {
                return true;
            }
        }
        
        // Kebab-case: path-to-dynamic-secr, path-to-secret
        if (/^[a-z][a-z0-9-]+$/.test(trimmedValue) && trimmedValue.length > 3 && trimmedValue.length < 50) {
            if (new RegExp(`\\b${trimmedValue.replace(/-/g, '[-_]')}\\b`).test(lowerLine) ||
                /usage:|example:|parameter|argument|option/i.test(lowerLine)) {
                return true;
            }
        }
        
        // Truncated variable patterns: path_should_not_retu, path_output_proto_in
        if (/^[a-z][a-z0-9_]+$/.test(trimmedValue) && trimmedValue.length > 10 && trimmedValue.length < 35) {
            // Check if it looks like a truncated variable name (ends mid-word)
            if (!/[aeiou]$/i.test(trimmedValue) && /_[a-z]{1,4}$/.test(trimmedValue)) {
                if (new RegExp(`\\b${trimmedValue}\\b`).test(lowerLine)) {
                    return true;
                }
            }
        }
        
        // Test variable patterns: secret_name_TestValidateCacheUpdateSecretValue
        if (/^(test|mock|fake|secret_name_|path_)[A-Z]/.test(trimmedValue)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Checks if value matches common test password patterns
     * e.g., "password123", "test123", "admin123"
     */
    private static checkTestPassword(value: string): boolean {
        const lowerValue = value.toLowerCase();
        
        // Common test passwords
        const testPasswords = [
            'password123',
            'password',
            'test123',
            'test',
            'admin123',
            'admin',
            'secret123',
            'secret',
            'dummy123',
            'dummy',
            'example123',
            'example'
        ];
        
        if (testPasswords.includes(lowerValue)) {
            return true;
        }
        
        // Pattern: word + 123
        if (/^(password|test|admin|secret|dummy|example)123$/i.test(value)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Checks if file is a generated file (protobuf, etc.)
     */
    private static checkGeneratedFile(fileName: string): boolean {
        const lowerFileName = fileName.toLowerCase();
        
        // Protobuf generated files
        if (/\.pb\.go$/.test(lowerFileName) || 
            /\.pb\.ts$/.test(lowerFileName) ||
            /\.pb\.js$/.test(lowerFileName) ||
            /_pb2\.py$/.test(lowerFileName)) {
            return true;
        }
        
        // Other generated file patterns
        if (/generated|\.gen\.|_gen\./.test(lowerFileName)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Language-agnostic: Checks if value is a template string
     */
    private static checkTemplateString(value: string): boolean {
        const templatePatterns = [
            /\{\{[^}]+\}\}/,           // {{variable}}
            /\{\{\.[^}]+\}\}/,         // {{.Field}}
            /\$\{[^}]+\}/,             // ${variable}
            /#\{[^}]+\}/,               // #{variable}
            /%\{[^}]+\}/,               // %{variable}
            /\{[a-zA-Z_][a-zA-Z0-9_]+\}/, // {variable}
        ];
        return templatePatterns.some(pattern => pattern.test(value));
    }
    
    /**
     * Language-agnostic: Checks if value is part of a function call
     * Works for: All languages (Go, Python, Java, C#, JavaScript/TypeScript, Ruby, PHP, Rust, Swift, Kotlin, C/C++, etc.)
     */
    private static checkFunctionCall(value: string, line: string): boolean {
        const lowerLine = line.toLowerCase();
        const trimmedValue = value.trim();
        
        // ===== TYPE CONVERSIONS & CASTS (All Languages) =====
        // Go: string(variable), []byte(data), int(value), p.(string) - type assertions
        // C/C++: (int)value, static_cast<int>(value)
        // Java/C#: (String)value, value as String
        // Python: str(value), int(value), bytes(value)
        // Rust: value as Type
        if (/string\([^)]+\)|\[\]byte\([^)]+\)|int\([^)]+\)|float64\([^)]+\)/.test(line) ||
            /\(int\)|\(string\)|\(char\)|\(float\)|\(double\)|\(bool\)|\(boolean\)/.test(line) ||
            /static_cast|dynamic_cast|reinterpret_cast/.test(line) ||
            /as\s+(String|Int|Float|Double|Bool|Boolean)/i.test(line) ||
            /str\(|int\(|float\(|bool\(|bytes\(|list\(|dict\(|tuple\(/.test(lowerLine) ||
            /[a-zA-Z_][a-zA-Z0-9_]*\.\([^)]+\)/.test(line)) {  // Go type assertions: p.(string)
            if (/^string\(|^\[\]byte\(|^int\(|^float64\(|^\(int\)|^\(string\)|^as\s+/i.test(trimmedValue) ||
                /^[a-zA-Z_][a-zA-Z0-9_]*\.\(|^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue)) {
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
        if (/&[A-Z][a-zA-Z0-9]*\{|^[A-Z][a-zA-Z0-9]*\{/.test(line) ||
            /new\s+[A-Z][a-zA-Z0-9]*\s*[({]/.test(line)) {
            if (/^&[A-Z]|^[A-Z][a-zA-Z0-9]*\{|^new\s+[A-Z]/i.test(trimmedValue) ||
                /^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue)) {
                return true;
            }
        }
        
        // ===== FUNCTION CALLS WITH TEST PARAMETERS =====
        // Pattern: FunctionName(t, or FunctionName(test, etc.
        // Go: GeneratePrivateKeyBase64(t,
        // Python: generate_key(test,
        // Java: generateKey(test,
        if (/[A-Z][a-zA-Z0-9]*\([a-z]+,/.test(line) ||  // Go: GeneratePrivateKeyBase64(t,
            /[a-z_][a-zA-Z0-9_]*\([a-z]+,/.test(lowerLine)) {  // Python/Java: generate_key(test,
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 50) {
                return true;
            }
        }
        
        // ===== FUNCTION CALL PATTERNS (All Languages) =====
        const functionPatterns = [
            /[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*/,      // function( - most languages
            /\.[a-zA-Z_][a-zA-Z0-9_]*\s*\(/,         // .method( - OOP languages
            /::[a-zA-Z_][a-zA-Z0-9_]*\s*\(/,         // ::method( - C++/PHP
            /->[a-zA-Z_][a-zA-Z0-9_]*\s*\(/,         // ->method( - PHP/C++
            /[a-zA-Z_][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*\(/,  // Go/Java/C# method calls
        ];
        
        const isInFunctionCall = functionPatterns.some(pattern => pattern.test(line));
        
        if (isInFunctionCall) {
            // Check if value is a function name or parameter
            const commonFunctionPatterns = [
                /^(validate|hash|encode|decode|encrypt|decrypt|get|set|create|update|delete|parse|stringify|serialize|deserialize)/i,
                /^(Base64|String|Utils|Helper|Manager|Service|Client|Factory|Builder)\./i,
                /^(System|Math|Object|Array|List|Map|Collection|Stream)\./i,
                /^(encoding_ex|encoding|json|xml|yaml|base64|crypto|hashlib)\./i,  // Go/Python
                /^(java\.|javax\.|org\.|com\.)/i,  // Java packages
                /^(System\.|Microsoft\.|Microsoft\.Extensions\.)/i,  // C#/.NET
                /^(fs\.|path\.|os\.|util\.|http\.)/i,  // Node.js/Python
                /^[A-Z][a-zA-Z0-9]*\.(Base64Encode|Base64Decode|Marshal|Unmarshal|Parse|ToString)/i,  // Go/Java/C#
                /^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/,  // Variable name pattern
            ];
            
            if (commonFunctionPatterns.some(p => p.test(trimmedValue))) {
                return true;
            }
            
            // Method chaining: object.Method().AnotherMethod()
            if (/[a-zA-Z_][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*\(/.test(line) ||
                /[a-zA-Z_][a-zA-Z0-9]*->[a-zA-Z][a-zA-Z0-9]*\(/.test(line)) {
                if (/^[a-zA-Z_][a-zA-Z0-9]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 50) {
                    return true;
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
        
        // Ruby: method calls with blocks
        if (/\.each\s*\{|\.map\s*\{|\.select\s*\{|\.find\s*\{/.test(line)) {
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
        if (/::[a-zA-Z_][a-zA-Z0-9_]*\(|\.unwrap\(|\.expect\(|\.ok\(/.test(line)) {
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 40) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Language-agnostic: Checks if value is an object/struct field assignment
     */
    private static checkObjectFieldAssignment(value: string, line: string): boolean {
        const fieldPatterns = [
            /[A-Z][a-zA-Z0-9_]*:\s*[a-zA-Z_][a-zA-Z0-9_]*[,}]/,
            /[a-z_][a-zA-Z0-9_]*:\s*[a-zA-Z_][a-zA-Z0-9_]*[,}]/,
        ];
        return fieldPatterns.some(pattern => pattern.test(line)) &&
               /^[a-zA-Z_][a-zA-Z0-9_]*[,}]?\s*$/.test(value.trim());
    }
    
    /**
     * Language-agnostic: Checks if value is a hash in test context
     */
    private static checkHashInTestContext(value: string, fileName: string, lowerLine: string): boolean {
        if (!this.checkTestFile(fileName)) {
            return false;
        }
        const cleanValue = value.replace(/^["']|["';]+$/g, '').trim();
        const hashPatterns = [
            /^[a-f0-9]{64}$/i,  // SHA256
            /^[a-f0-9]{32}$/i,  // MD5
            /^[a-f0-9]{40}$/i,  // SHA1
        ];
        return hashPatterns.some(pattern => pattern.test(cleanValue)) &&
               (lowerLine.includes('test') || lowerLine.includes('mock') || lowerLine.includes('signature'));
    }
    
    /**
     * Language-agnostic: Checks if value is part of struct/object initialization
     * Supports: Go, Java, C#, JavaScript/TypeScript, Python, Rust, Swift, Kotlin, etc.
     */
    private static checkStructOrObjectInit(value: string, line: string): boolean {
        const trimmedValue = value.trim();
        const lowerLine = line.toLowerCase();
        
        // Go: map[string]interface{}{, map[string]string{{
        if (/map\[string\]interface\{\{|map\[string\]string\{\{|map\[string\]int\{\{/.test(line)) {
            return true;
        }
        
        // Go: &TypeName{}, TypeName{Field: value}
        // Java/C#: new TypeName { Field = value }
        // JavaScript/TypeScript: { field: value }
        // Python: {'field': value}, {"field": value}
        // Rust: TypeName { field: value }
        if (/\{[A-Z][a-zA-Z0-9_]*:|[A-Z][a-zA-Z0-9_]*:\s*[a-zA-Z_][a-zA-Z0-9_]*[,}]/.test(line)) {
            // Check if value is a struct field name or variable reference
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 50) {
                return true;
            }
        }
        
        // Struct field patterns: {MaxVersions:, Password: variableName}
        if (/\{[A-Z][a-zA-Z0-9_]*:\s*[a-zA-Z_][a-zA-Z0-9_]*[,}]/.test(line)) {
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue)) {
                return true;
            }
        }
        
        // Object/struct initialization with variable references
        // Go: password: variableName}, Key: value}
        // JavaScript: password: variableName}, key: value}
        if (/[a-z_][a-zA-Z0-9_]*:\s*[a-zA-Z_][a-zA-Z0-9_]*[,}]/.test(lowerLine)) {
            if (/^[a-zA-Z_][a-zA-Z0-9_]*[,};)]?\s*$/.test(trimmedValue) && trimmedValue.length < 50) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Checks if value matches test token patterns
     * e.g., t-foobarbaz-1581006679, t-xltuqgibc8eip8gczind-1593074311
     */
    private static checkTestTokenPattern(value: string, fileName: string): boolean {
        const trimmedValue = value.trim().replace(/^["']|["']$/g, '');
        
        // Test token pattern: t-<alphanumeric>-<timestamp>
        if (/^t-[a-z0-9-]+-\d+$/i.test(trimmedValue)) {
            return true;
        }
        
        // Test token pattern: e2n64jlr9gpamtn6oolikbxmh8f2vtce (low entropy, in test files)
        if (this.checkTestFile(fileName)) {
            // Low entropy alphanumeric strings (likely test tokens)
            if (/^[a-z0-9]{20,40}$/i.test(trimmedValue)) {
                const entropy = this.calculateEntropy(trimmedValue);
                // Low entropy (< 4.0) suggests it's a test token, not a real secret
                if (entropy < 4.0) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Checks if value is an AWS Account ID in test context
     * e.g., 123456789012 (12 digits, common in test files)
     */
    private static checkAwsAccountIdInTest(value: string, fileName: string): boolean {
        const trimmedValue = value.trim().replace(/^["']|["']$/g, '');
        
        // AWS Account ID pattern: exactly 12 digits
        if (/^123456789012$/.test(trimmedValue) || /^p-123456789012/.test(trimmedValue)) {
            // Only flag in test files
            if (this.checkTestFile(fileName)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Checks if value is a known hash value (like empty string SHA256)
     * e.g., e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     */
    private static checkKnownHashValue(value: string): boolean {
        const trimmedValue = value.trim().replace(/^["']|["']$/g, '');
        
        // Known hash values (empty string SHA256)
        const knownHashes = [
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // SHA256 of empty string
            'da39a3ee5e6b4b0d3255bfef95601890afd80709', // SHA1 of empty string
            'd41d8cd98f00b204e9800998ecf8427e', // MD5 of empty string
        ];
        
        if (knownHashes.includes(trimmedValue.toLowerCase())) {
            return true;
        }
        
        // Check for common test hash patterns (low entropy hex strings)
        if (/^[a-f0-9]{32,64}$/i.test(trimmedValue)) {
            const entropy = this.calculateEntropy(trimmedValue);
            // Very low entropy (< 3.5) for hex strings suggests known/test hash
            if (entropy < 3.5) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Checks if value is in documentation example or commented code
     * Supports: All languages with comment syntax
     */
    private static checkDocumentationExample(value: string, line: string, fileName: string): boolean {
        const lowerLine = line.toLowerCase();
        const lowerFileName = fileName.toLowerCase();
        
        // Documentation files
        if (/readme|\.md$|\.txt$|\.rst$|\.adoc$/.test(lowerFileName)) {
            return true;
        }
        
        // Commented code patterns
        // Single line comments: //, #, <!--
        if (/^\s*(\/\/|#|<!--)/.test(line.trim())) {
            return true;
        }
        
        // Documentation keywords in line
        if (/(example|usage|sample|demo|placeholder|your-|replace-|see below|as shown)/i.test(lowerLine)) {
            return true;
        }
        
        // Usage examples: Usage: $0 <path>, Example: command
        if (/^(usage|example|sample|demo):/i.test(lowerLine.trim())) {
            return true;
        }
        
        // Commented environment variables: # - REDIS_PASSWORD=password123
        if (/^\s*#\s*-?\s*[A-Z_]+=/.test(line)) {
            return true;
        }
        
        // Help text patterns: help:, description:, etc.
        if (/help:|description:|note:|warning:|info:/i.test(lowerLine)) {
            return true;
        }
        
        return false;
    }
}

