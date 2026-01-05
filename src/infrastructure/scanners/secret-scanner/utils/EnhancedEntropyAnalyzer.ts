/**
 * Enhanced entropy analyzer for detecting secrets based on randomness
 * Uses multiple entropy calculation methods and character set analysis
 */
export class EnhancedEntropyAnalyzer {
    /**
     * Calculates Shannon entropy of a string
     */
    static calculateShannonEntropy(str: string): number {
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
     * Calculates character set diversity score
     */
    static calculateCharSetDiversity(str: string): number {
        if (!str || str.length === 0) return 0;

        const charSets = {
            lowercase: /[a-z]/.test(str),
            uppercase: /[A-Z]/.test(str),
            digits: /[0-9]/.test(str),
            special: /[^a-zA-Z0-9]/.test(str),
            base64: /[A-Za-z0-9+/=]/.test(str) && /^[A-Za-z0-9+/=]+$/.test(str),
            hex: /^[0-9a-fA-F]+$/.test(str)
        };

        let diversity = 0;
        if (charSets.lowercase) diversity += 0.25;
        if (charSets.uppercase) diversity += 0.25;
        if (charSets.digits) diversity += 0.25;
        if (charSets.special) diversity += 0.25;

        // Bonus for base64 or hex patterns (common in secrets)
        if (charSets.base64 && str.length >= 16) diversity += 0.2;
        if (charSets.hex && str.length >= 32) diversity += 0.15;

        return Math.min(diversity, 1.0);
    }

    /**
     * Calculates overall entropy score combining multiple factors
     */
    static calculateEntropyScore(str: string): number {
        if (!str || str.length < 8) return 0;

        const shannonEntropy = this.calculateShannonEntropy(str);
        const diversity = this.calculateCharSetDiversity(str);
        
        // Normalize Shannon entropy (max is log2(95) ≈ 6.57 for printable ASCII)
        const normalizedEntropy = Math.min(shannonEntropy / 6.57, 1.0);
        
        // Length factor (longer strings are more likely to be secrets)
        const lengthFactor = Math.min(str.length / 64, 1.0) * 0.2;
        
        // Combine factors
        const score = (normalizedEntropy * 0.5) + (diversity * 0.3) + lengthFactor;
        
        return Math.min(score, 1.0);
    }

    /**
     * Checks if a string has high entropy (likely a secret)
     */
    static isHighEntropy(str: string, threshold: number = 0.6): boolean {
        return this.calculateEntropyScore(str) >= threshold;
    }

    /**
     * Analyzes entropy for different secret types
     */
    static analyzeForType(str: string, type: string): { entropy: number; isLikelySecret: boolean } {
        const entropy = this.calculateEntropyScore(str);
        
        // Type-specific thresholds
        const thresholds: Record<string, number> = {
            'apiKey': 0.55,
            'token': 0.6,
            'password': 0.5,
            'privateKey': 0.65,
            'connectionString': 0.4,
            'secret': 0.55
        };

        const threshold = thresholds[type.toLowerCase()] || 0.55;
        const isLikelySecret = entropy >= threshold;

        return { entropy, isLikelySecret };
    }
}

