/**
 * Analyzes context around detected secrets to identify false positives
 * Checks file paths, code context, comments, and common patterns
 */
export class ContextAnalyzer {
    /**
     * Common false positive patterns in file paths
     */
    private static readonly FALSE_POSITIVE_PATHS = [
        /test/i,
        /spec/i,
        /example/i,
        /sample/i,
        /demo/i,
        /mock/i,
        /fixture/i,
        /dummy/i,
        /template/i,
        /\.test\./i,
        /\.spec\./i,
        /\.example\./i,
        /\.sample\./i,
        /testdata/i,
        /test_data/i,
        /__tests__/i,
        /__mocks__/i,
        /docs?/i,
        /documentation/i,
        /readme/i,
        /changelog/i,
        /license/i,
        /\.md$/i,
        /\.txt$/i,
        /\.example$/i,
        /\.sample$/i,
        /\.template$/i,
        /\.dist$/i,
        /\.example\./i,
        /\.sample\./i,
        /vendor/i,
        /third[_-]?party/i,
        /node_modules/i,
        /\.min\./i,
        /\.bundle\./i
    ];

    /**
     * Common false positive keywords in code context
     */
    private static readonly FALSE_POSITIVE_KEYWORDS = [
        /example/i,
        /sample/i,
        /test/i,
        /dummy/i,
        /placeholder/i,
        /your[_-]?key/i,
        /your[_-]?secret/i,
        /your[_-]?token/i,
        /your[_-]?api[_-]?key/i,
        /replace[_-]?me/i,
        /change[_-]?me/i,
        /todo/i,
        /fixme/i,
        /xxx/i,
        /yyy/i,
        /zzz/i,
        /fake/i,
        /mock/i,
        /demo/i,
        /default[_-]?value/i,
        /config[_-]?example/i,
        /\.env\.example/i,
        /\.env\.sample/i,
        /\.env\.template/i
    ];

    /**
     * Common false positive values
     */
    private static readonly FALSE_POSITIVE_VALUES = [
        /^example$/i,
        /^test$/i,
        /^sample$/i,
        /^dummy$/i,
        /^placeholder$/i,
        /^your[_-]?key$/i,
        /^your[_-]?secret$/i,
        /^your[_-]?token$/i,
        /^replace[_-]?me$/i,
        /^change[_-]?me$/i,
        /^xxx$/i,
        /^yyy$/i,
        /^zzz$/i,
        /^fake$/i,
        /^mock$/i,
        /^demo$/i,
        /^default$/i,
        /^password$/i,
        /^secret$/i,
        /^key$/i,
        /^token$/i,
        /^api[_-]?key$/i,
        /^sk[_-]?test/i,
        /^pk[_-]?test/i,
        /^test[_-]?key/i,
        /^dev[_-]?key/i,
        /^development$/i,
        /^local$/i,
        /^localhost$/i,
        /^127\.0\.0\.1$/,
        /^0\.0\.0\.0$/,
        /^00000000[_-]?0000[_-]?0000[_-]?0000[_-]?0000[_-]?00000000$/i,
        /^deadbeef/i,
        /^cafebabe/i,
        /^12345678/i,
        /^abcdefgh/i
    ];

    /**
     * Known public API endpoints that should not be flagged as secrets
     */
    private static readonly PUBLIC_API_ENDPOINTS = [
        /^https?:\/\/api\.akeyless\.io/i,
        /^https?:\/\/api\.github\.com/i,
        /^https?:\/\/api\.stripe\.com/i,
        /^https?:\/\/api\.twilio\.com/i,
        /^https?:\/\/api\.sendgrid\.com/i,
        /^https?:\/\/api\.mailgun\.com/i,
        /^https?:\/\/api\.slack\.com/i,
        /^https?:\/\/api\.googleapis\.com/i,
        /^https?:\/\/[a-z0-9-]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com/i,
        /^https?:\/\/[a-z0-9-]+\.cloudfunctions\.net/i,
        /^https?:\/\/[a-z0-9-]+\.appspot\.com/i,
        /^https?:\/\/[a-z0-9-]+\.run\.app/i,
        /^https?:\/\/[a-z0-9-]+\.vercel\.app/i,
        /^https?:\/\/[a-z0-9-]+\.netlify\.app/i,
        /^https?:\/\/[a-z0-9-]+\.herokuapp\.com/i,
        /^https?:\/\/[a-z0-9-]+\.azurewebsites\.net/i,
        /^https?:\/\/[a-z0-9-]+\.cloudapp\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.servicebus\.windows\.net/i,
        /^https?:\/\/[a-z0-9-]+\.blob\.core\.windows\.net/i,
        /^https?:\/\/[a-z0-9-]+\.queue\.core\.windows\.net/i,
        /^https?:\/\/[a-z0-9-]+\.table\.core\.windows\.net/i,
        /^https?:\/\/[a-z0-9-]+\.file\.core\.windows\.net/i,
        /^https?:\/\/[a-z0-9-]+\.documents\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.database\.windows\.net/i,
        /^https?:\/\/[a-z0-9-]+\.vault\.azure\.net/i,
        /^https?:\/\/[a-z0-9-]+\.keyvault\.azure\.net/i,
        /^https?:\/\/[a-z0-9-]+\.servicebus\.windows\.net/i,
        /^https?:\/\/[a-z0-9-]+\.redis\.cache\.windows\.net/i,
        /^https?:\/\/[a-z0-9-]+\.search\.windows\.net/i,
        /^https?:\/\/[a-z0-9-]+\.cognitiveservices\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.openai\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.speech\.microsoft\.com/i,
        /^https?:\/\/[a-z0-9-]+\.translator\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.cognitiveservices\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.openai\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.speech\.microsoft\.com/i,
        /^https?:\/\/[a-z0-9-]+\.translator\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.cognitiveservices\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.openai\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.speech\.microsoft\.com/i,
        /^https?:\/\/[a-z0-9-]+\.translator\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.cognitiveservices\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.openai\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.speech\.microsoft\.com/i,
        /^https?:\/\/[a-z0-9-]+\.translator\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.cognitiveservices\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.openai\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.speech\.microsoft\.com/i,
        /^https?:\/\/[a-z0-9-]+\.translator\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.cognitiveservices\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.openai\.azure\.com/i,
        /^https?:\/\/[a-z0-9-]+\.speech\.microsoft\.com/i,
        /^https?:\/\/[a-z0-9-]+\.translator\.azure\.com/i
    ];

    /**
     * Known public model identifiers that should not be flagged as secrets
     */
    private static readonly PUBLIC_MODEL_NAMES = [
        /^gemini-[0-9.]+-flash$/i,
        /^gemini-[0-9.]+-pro$/i,
        /^gpt-[0-9.]+$/i,
        /^gpt-[0-9.]+-turbo$/i,
        /^gpt-[0-9.]+-turbo-preview$/i,
        /^gpt-[0-9.]+-instruct$/i,
        /^text-davinci-[0-9]+$/i,
        /^text-curie-[0-9]+$/i,
        /^text-babbage-[0-9]+$/i,
        /^text-ada-[0-9]+$/i,
        /^claude-[0-9.]+$/i,
        /^claude-[0-9.]+-sonnet$/i,
        /^claude-[0-9.]+-opus$/i,
        /^llama-[0-9]+$/i,
        /^mistral-[0-9.]+$/i,
        /^palm-[0-9]+$/i,
        /^bert-[a-z0-9-]+$/i,
        /^roberta-[a-z0-9-]+$/i,
        /^distilbert-[a-z0-9-]+$/i,
        /^albert-[a-z0-9-]+$/i,
        /^xlnet-[a-z0-9-]+$/i,
        /^electra-[a-z0-9-]+$/i,
        /^t5-[a-z0-9-]+$/i,
        /^bart-[a-z0-9-]+$/i,
        /^pegasus-[a-z0-9-]+$/i,
        /^prophetnet-[a-z0-9-]+$/i,
        /^reformer-[a-z0-9-]+$/i,
        /^longformer-[a-z0-9-]+$/i,
        /^bigbird-[a-z0-9-]+$/i,
        /^deberta-[a-z0-9-]+$/i,
        /^debertav2-[a-z0-9-]+$/i,
        /^debertav3-[a-z0-9-]+$/i,
        /^layoutlm-[a-z0-9-]+$/i,
        /^layoutlmv2-[a-z0-9-]+$/i,
        /^layoutlmv3-[a-z0-9-]+$/i,
        /^canine-[a-z0-9-]+$/i,
        /^splinter-[a-z0-9-]+$/i,
        /^squeezebert-[a-z0-9-]+$/i,
        /^mobilebert-[a-z0-9-]+$/i,
        /^tinybert-[a-z0-9-]+$/i,
        /^minilm-[a-z0-9-]+$/i,
        /^funnel-[a-z0-9-]+$/i,
        /^led-[a-z0-9-]+$/i,
        /^blenderbot-[a-z0-9-]+$/i,
        /^dialo-[a-z0-9-]+$/i,
        /^convbert-[a-z0-9-]+$/i,
        /^phobert-[a-z0-9-]+$/i,
        /^camembert-[a-z0-9-]+$/i,
        /^flaubert-[a-z0-9-]+$/i,
        /^xlm-[a-z0-9-]+$/i,
        /^xlm-roberta-[a-z0-9-]+$/i,
        /^xlm-mlm-[a-z0-9-]+$/i,
        /^xlm-clm-[a-z0-9-]+$/i,
        /^xlm-mlm-xnli-[a-z0-9-]+$/i,
        /^xlm-mlm-17-1280$/i,
        /^xlm-mlm-100-1280$/i,
        /^xlm-clm-enfr-1024$/i,
        /^xlm-clm-ende-1024$/i,
        /^xlm-mlm-xnli15-1024$/i,
        /^xlm-mlm-tlm-xnli15-1024$/i,
        /^xlm-clm-xnli15-1024$/i,
        /^xlm-mlm-ende-1024$/i,
        /^xlm-mlm-enfr-1024$/i,
        /^xlm-mlm-enro-1024$/i,
        /^xlm-mlm-tlm-xnli15-1024$/i,
        /^xlm-clm-xnli15-1024$/i,
        /^xlm-mlm-ende-1024$/i,
        /^xlm-mlm-enfr-1024$/i,
        /^xlm-mlm-enro-1024$/i
    ];

    /**
     * Comment patterns that indicate false positives
     */
    private static readonly COMMENT_PATTERNS = [
        /\/\/.*(?:example|sample|test|dummy|placeholder|replace|change|todo|fixme)/i,
        /\/\*.*(?:example|sample|test|dummy|placeholder|replace|change|todo|fixme).*\*\//i,
        /#.*(?:example|sample|test|dummy|placeholder|replace|change|todo|fixme)/i,
        /<!--.*(?:example|sample|test|dummy|placeholder|replace|change|todo|fixme).*-->/i
    ];

    /**
     * Checks if file path indicates a false positive
     */
    static isFalsePositivePath(filePath: string): boolean {
        const normalizedPath = filePath.toLowerCase();
        return this.FALSE_POSITIVE_PATHS.some(pattern => pattern.test(normalizedPath));
    }

    /**
     * Checks if the context line contains false positive indicators
     */
    static isFalsePositiveContext(context: string): boolean {
        const normalizedContext = context.toLowerCase();
        
        // Check for false positive keywords
        if (this.FALSE_POSITIVE_KEYWORDS.some(pattern => pattern.test(normalizedContext))) {
            return true;
        }

        // Check if it's in a comment
        if (this.COMMENT_PATTERNS.some(pattern => pattern.test(context))) {
            return true;
        }

        return false;
    }

    /**
     * Checks if the detected value is a known false positive
     */
    static isFalsePositiveValue(value: string): boolean {
        if (this.FALSE_POSITIVE_VALUES.some(pattern => pattern.test(value))) {
            return true;
        }
        
        // Check if it's a public API endpoint
        if (this.PUBLIC_API_ENDPOINTS.some(pattern => pattern.test(value))) {
            return true;
        }
        
        // Check if it's a public model name
        if (this.PUBLIC_MODEL_NAMES.some(pattern => pattern.test(value))) {
            return true;
        }
        
        // Check if it's a shell variable reference
        if (this.isShellVariableReference(value)) {
            return true;
        }
        
        return false;
    }

    /**
     * Checks if value is a shell variable reference (e.g., $HOME, ${VAR}, $VAR/path)
     * These are not secrets, just variable expansions
     */
    static isShellVariableReference(value: string): boolean {
        // Check for shell variable syntax: $VAR or ${VAR}
        // Pattern matches: $VAR, ${VAR}, $VAR/path, ${VAR}/path, $VAR_$OTHER, etc.
        const shellVarPattern = /\$\{?[A-Z_][A-Z0-9_]*\}?/;
        
        // If the value contains shell variable references, check if it's primarily variable references
        if (shellVarPattern.test(value)) {
            // Remove all shell variable references and see what's left
            // Replace $VAR and ${VAR} patterns
            const withoutVars = value.replace(/\$\{?[A-Z_][A-Z0-9_]*\}?/g, '');
            
            // If what remains is mostly path separators, common path characters, or very short,
            // it's likely a path with variable references, not a secret
            const remainingChars = withoutVars.replace(/[/\\\s\-_.]/g, '');
            
            // If remaining is mostly empty or very short (just separators and common path chars),
            // and the original contains variable references, it's a false positive
            if (remainingChars.length === 0 || (remainingChars.length < 5 && value.length > 10)) {
                return true;
            }
            
            // If the value starts with a variable reference and is mostly variable references
            // e.g., $HOME/Downloads, $DOWNLOADS_PATH/file.json
            if (/^\$\{?[A-Z_][A-Z0-9_]*\}?/.test(value)) {
                // Check if it's mostly variable references and path separators
                const varAndPathChars = value.replace(/[^$A-Z0-9_{}/\\\-_.]/g, '');
                if (varAndPathChars.length / value.length > 0.7) {
                    return true;
                }
            }
        }
        
        return false;
    }

    /**
     * Checks if the detected value is actually a variable name (not a secret value)
     * This helps filter cases where patterns match variable names instead of values
     */
    static isVariableName(value: string, context: string): boolean {
        // Check if value looks like a variable name (all caps with underscores)
        if (/^[A-Z_][A-Z0-9_]*$/.test(value) && value.length > 3) {
            // Check if it appears in context as a variable name (before assignment)
            // Patterns like: VAR_NAME=, export VAR_NAME, VAR_NAME:, etc.
            const varNamePattern = new RegExp(`(?:^|\\s|export\\s+|const\\s+|let\\s+|var\\s+)(?:\\$)?${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*[:=]`, 'i');
            if (varNamePattern.test(context)) {
                return true;
            }
            
            // Additional check: if value appears before = in context and context shows assignment pattern
            // e.g., DOWNLOADS_PATH="$HOME/Downloads" - DOWNLOADS_PATH is the variable name, not the value
            const assignmentMatch = context.match(/^([A-Z_][A-Z0-9_]*)\s*[:=]\s*["']/);
            if (assignmentMatch && assignmentMatch[1] === value) {
                return true;
            }
            
            // Check for common variable name patterns that end with _PATH, _FILE, _DIR, etc.
            if (/_(PATH|FILE|DIR|DIRECTORY|URL|URI|HOST|PORT|NAME|ID|KEY|VALUE|CONFIG|SETTING|OPTION|PARAM|ARG|VAR|ENV)$/i.test(value)) {
                // If it appears before = in context, it's likely a variable name
                const beforeEquals = context.split(/[:=]/)[0].trim();
                if (beforeEquals === value || beforeEquals.endsWith(' ' + value) || beforeEquals.endsWith('\t' + value)) {
                    return true;
                }
            }
            
            // Check if it's a common environment variable name pattern
            if (/^(PATH|HOME|USER|SHELL|PWD|TMP|TEMP|LANG|LC_|DISPLAY|EDITOR|VISUAL|PAGER|MANPATH|INFOPATH|LD_LIBRARY_PATH|DYLD_LIBRARY_PATH|PYTHONPATH|NODE_PATH|GOPATH|GOROOT|JAVA_HOME|ANDROID_HOME|FLUTTER_ROOT|CARGO_HOME|RUSTUP_HOME|NVM_DIR|RBENV_ROOT|PYENV_ROOT|NODENV_ROOT|GOENV_ROOT|JENV_ROOT|PLENV_ROOT|PHENV_ROOT|RVM_PATH|ASDF_DATA_DIR|ASDF_CONFIG_FILE|ASDF_DEFAULT_TOOL_VERSIONS_FILE|ASDF_PLUGIN_PATH|ASDF_INSTALL_PATH|ASDF_SHELL|ASDF_DIR|ASDF_USER_SHIMS|ASDF_GLOBAL_DEFAULT_TOOL_VERSIONS_FILE|ASDF_LOCAL_DEFAULT_TOOL_VERSIONS_FILE|ASDF_TOOL_VERSIONS|ASDF_CONFIG|ASDF_DATA|ASDF_INSTALL|ASDF_PLUGIN|ASDF_SHELL|ASDF_USER|ASDF_GLOBAL|ASDF_LOCAL|ASDF_TOOL|ASDF_VERSION|ASDF_VERSION_FILE|ASDF_VERSION_MANAGER|ASDF_VERSION_MANAGER_FILE|ASDF_VERSION_MANAGER_DIR|ASDF_VERSION_MANAGER_INSTALL|ASDF_VERSION_MANAGER_PLUGIN|ASDF_VERSION_MANAGER_SHELL|ASDF_VERSION_MANAGER_USER|ASDF_VERSION_MANAGER_GLOBAL|ASDF_VERSION_MANAGER_LOCAL|ASDF_VERSION_MANAGER_TOOL|ASDF_VERSION_MANAGER_VERSION|ASDF_VERSION_MANAGER_VERSION_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER|ASDF_VERSION_MANAGER_VERSION_MANAGER_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_DIR|ASDF_VERSION_MANAGER_VERSION_MANAGER_INSTALL|ASDF_VERSION_MANAGER_VERSION_MANAGER_PLUGIN|ASDF_VERSION_MANAGER_VERSION_MANAGER_SHELL|ASDF_VERSION_MANAGER_VERSION_MANAGER_USER|ASDF_VERSION_MANAGER_VERSION_MANAGER_GLOBAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_LOCAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_TOOL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_DIR|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_INSTALL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_PLUGIN|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_SHELL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_USER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_GLOBAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_LOCAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_TOOL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_DIR|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_INSTALL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_PLUGIN|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_SHELL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_USER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_GLOBAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_LOCAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_TOOL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_DIR|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_INSTALL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_PLUGIN|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_SHELL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_USER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_GLOBAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_LOCAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_TOOL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_DIR|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_INSTALL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_PLUGIN|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_SHELL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_USER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_GLOBAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_LOCAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_TOOL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_DIR|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_INSTALL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_PLUGIN|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_SHELL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_USER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_GLOBAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_LOCAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_TOOL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_DIR|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_INSTALL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_PLUGIN|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_SHELL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_USER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_GLOBAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_LOCAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_TOOL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_DIR|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_INSTALL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_PLUGIN|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_SHELL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_USER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_GLOBAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_LOCAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_TOOL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_FILE|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_DIR|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_INSTALL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_PLUGIN|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_SHELL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_USER|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_GLOBAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_LOCAL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_TOOL|ASDF_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION_MANAGER_VERSION)$/i.test(value)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Checks if value appears to be a development/test value
     */
    static isDevelopmentValue(value: string, context: string): boolean {
        const lowerValue = value.toLowerCase();
        const lowerContext = context.toLowerCase();

        // Check for common dev/test patterns
        const devPatterns = [
            /^dev[_-]?/i,
            /^test[_-]?/i,
            /^local[_-]?/i,
            /^staging[_-]?/i,
            /_dev$/i,
            /_test$/i,
            /_local$/i,
            /_staging$/i,
            /localhost/i,
            /127\.0\.0\.1/,
            /0\.0\.0\.0/,
            /^sk_test_/i,
            /^pk_test_/i,
            /test[_-]?mode/i,
            /development[_-]?mode/i
        ];

        if (devPatterns.some(pattern => pattern.test(lowerValue) || pattern.test(lowerContext))) {
            return true;
        }

        // Check for very short values (likely placeholders)
        if (value.length < 8 && /^(test|dev|local|demo|sample|example)$/i.test(value)) {
            return true;
        }

        return false;
    }

    /**
     * Checks if value is in a string literal that's clearly a placeholder
     */
    static isPlaceholderString(context: string, value: string): boolean {
        const contextLower = context.toLowerCase();
        const valueLower = value.toLowerCase();

        // Check if context contains placeholder indicators
        const placeholderIndicators = [
            /placeholder/i,
            /replace[_-]?here/i,
            /change[_-]?this/i,
            /enter[_-]?your/i,
            /your[_-]?value/i,
            /your[_-]?key/i,
            /your[_-]?secret/i,
            /add[_-]?your/i,
            /insert[_-]?your/i
        ];

        if (placeholderIndicators.some(pattern => pattern.test(contextLower))) {
            return true;
        }

        // Check if value itself is a placeholder
        if (/^(your|replace|change|enter|add|insert)[_-]?(key|secret|token|value|api[_-]?key)/i.test(valueLower)) {
            return true;
        }

        return false;
    }

    /**
     * Analyzes the full context to determine if it's likely a false positive
     */
    static analyzeContext(
        filePath: string,
        context: string,
        value: string
    ): { isFalsePositive: boolean; reason?: string } {
        // Check file path
        if (this.isFalsePositivePath(filePath)) {
            return { isFalsePositive: true, reason: 'File path indicates test/example/documentation' };
        }

        // Check value itself
        if (this.isFalsePositiveValue(value)) {
            return { isFalsePositive: true, reason: 'Value matches known false positive pattern' };
        }

        // Check context
        if (this.isFalsePositiveContext(context)) {
            return { isFalsePositive: true, reason: 'Context contains false positive indicators' };
        }

        // Check for placeholder strings
        if (this.isPlaceholderString(context, value)) {
            return { isFalsePositive: true, reason: 'Appears to be a placeholder value' };
        }

        // Check for development values
        if (this.isDevelopmentValue(value, context)) {
            return { isFalsePositive: true, reason: 'Appears to be a development/test value' };
        }

        // Check if it's a variable name
        if (this.isVariableName(value, context)) {
            return { isFalsePositive: true, reason: 'Variable name detected instead of secret value' };
        }

        return { isFalsePositive: false };
    }

    /**
     * Gets the file type category for additional filtering
     */
    static getFileCategory(filePath: string): 'test' | 'example' | 'documentation' | 'config' | 'source' | 'other' {
        const lowerPath = filePath.toLowerCase();

        if (/test|spec|mock|fixture/.test(lowerPath)) {
            return 'test';
        }
        if (/example|sample|demo|template/.test(lowerPath)) {
            return 'example';
        }
        if (/readme|changelog|license|\.md$|\.txt$|docs?|documentation/.test(lowerPath)) {
            return 'documentation';
        }
        if (/\.env|config|settings|\.properties|\.ini|\.conf/.test(lowerPath)) {
            return 'config';
        }
        if (/\.(js|ts|jsx|tsx|py|java|go|rs|cpp|c|cs|php|rb|swift|kt)$/.test(lowerPath)) {
            return 'source';
        }

        return 'other';
    }
}

