/**
 * Validates detected secrets against expected formats and patterns
 * Helps reduce false positives by verifying structure
 */
export class PatternValidator {
    /**
     * Validates AWS Access Key format
     */
    static isValidAWSAccessKey(value: string): boolean {
        // AKIA followed by 16 uppercase alphanumeric characters
        return /^AKIA[0-9A-Z]{16}$/.test(value);
    }

    /**
     * Validates AWS Secret Key format
     */
    static isValidAWSSecretKey(value: string): boolean {
        // Base64-like string, typically 40 characters
        return /^[A-Za-z0-9/+=]{40}$/.test(value);
    }

    /**
     * Validates Google API Key format
     */
    static isValidGoogleAPIKey(value: string): boolean {
        // AIza followed by 35 alphanumeric, dash, or underscore characters
        return /^AIza[0-9A-Za-z\-_]{35}$/.test(value);
    }

    /**
     * Validates GitHub token format
     */
    static isValidGitHubToken(value: string): boolean {
        // ghp_, gho_, ghu_, or ghs_ followed by 36 alphanumeric characters
        return /^gh[po][_][0-9a-zA-Z]{36}$/.test(value) || /^ghs_[a-zA-Z0-9]{36}$/.test(value);
    }

    /**
     * Validates JWT token format
     */
    static isValidJWT(value: string): boolean {
        // Three base64url-encoded segments separated by dots
        const parts = value.split('.');
        if (parts.length !== 3) return false;
        
        // Each part should be base64url encoded
        const base64UrlPattern = /^[A-Za-z0-9\-_]+$/;
        return parts.every(part => base64UrlPattern.test(part) && part.length > 0);
    }

    /**
     * Validates Stripe key format
     */
    static isValidStripeKey(value: string): boolean {
        // sk_live_, pk_live_, sk_test_, pk_test_, or rk_live_ followed by alphanumeric
        return /^(sk|pk|rk)_(live|test)_[0-9a-zA-Z]{24,}$/.test(value);
    }

    /**
     * Validates private key format
     */
    static isValidPrivateKey(value: string): boolean {
        // Should contain BEGIN and END markers
        return /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/.test(value) &&
               /-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/.test(value);
    }

    /**
     * Validates connection string format
     */
    static isValidConnectionString(value: string, type: string): boolean {
        const lowerType = type.toLowerCase();
        
        if (lowerType.includes('mongodb')) {
            return /^mongodb(\+srv)?:\/\//.test(value);
        }
        if (lowerType.includes('postgres') || lowerType.includes('postgresql')) {
            return /^postgresql?:\/\//.test(value);
        }
        if (lowerType.includes('mysql')) {
            return /^mysql:\/\//.test(value);
        }
        
        // Generic connection string should have protocol
        return /^[a-z]+:\/\//.test(value);
    }

    /**
     * Validates API key format based on type
     */
    static isValidAPIKey(value: string, type: string): boolean {
        const lowerType = type.toLowerCase();
        
        if (lowerType.includes('aws') && lowerType.includes('access')) {
            return this.isValidAWSAccessKey(value);
        }
        if (lowerType.includes('google')) {
            return this.isValidGoogleAPIKey(value);
        }
        if (lowerType.includes('github')) {
            return this.isValidGitHubToken(value);
        }
        if (lowerType.includes('stripe')) {
            return this.isValidStripeKey(value);
        }
        
        // For generic API keys, check minimum length and character diversity
        if (value.length < 16) return false;
        if (!/[A-Za-z0-9]/.test(value)) return false;
        
        return true;
    }

    /**
     * Validates token format based on type
     */
    static isValidToken(value: string, type: string): boolean {
        const lowerType = type.toLowerCase();
        
        if (lowerType.includes('jwt')) {
            return this.isValidJWT(value);
        }
        if (lowerType.includes('github')) {
            return this.isValidGitHubToken(value);
        }
        
        // Generic tokens should be reasonably long
        if (value.length < 20) return false;
        
        return true;
    }

    /**
     * Validates a detected secret based on its type
     */
    static validate(value: string, type: string): boolean {
        const lowerType = type.toLowerCase();
        
        // Validate based on type
        if (lowerType.includes('api') && lowerType.includes('key')) {
            return this.isValidAPIKey(value, type);
        }
        if (lowerType.includes('token')) {
            return this.isValidToken(value, type);
        }
        if (lowerType.includes('private') && lowerType.includes('key')) {
            return this.isValidPrivateKey(value);
        }
        if (lowerType.includes('connection') || lowerType.includes('database')) {
            return this.isValidConnectionString(value, type);
        }
        if (lowerType.includes('aws')) {
            if (lowerType.includes('access')) {
                return this.isValidAWSAccessKey(value);
            }
            if (lowerType.includes('secret')) {
                return this.isValidAWSSecretKey(value);
            }
        }
        
        // Default: if we can't validate, assume it's valid (don't filter out)
        return true;
    }

    /**
     * Checks if value has minimum characteristics of a secret
     */
    static hasSecretCharacteristics(value: string): boolean {
        // Too short to be a real secret
        if (value.length < 8) return false;
        
        // Should have some character diversity
        const hasLetters = /[A-Za-z]/.test(value);
        const hasDigits = /[0-9]/.test(value);
        const hasSpecial = /[^A-Za-z0-9]/.test(value);
        
        // At least two character types
        const diversity = [hasLetters, hasDigits, hasSpecial].filter(Boolean).length;
        if (diversity < 2 && value.length < 32) return false;
        
        return true;
    }
}

