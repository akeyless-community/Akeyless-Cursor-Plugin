/**
 * Enhanced entropy analyzer for detecting secrets based on randomness
 * Uses multiple entropy calculation methods and character set analysis
 * Implements type-specific thresholds, normalized entropy, length weighting, and chi-square tests
 */
export class EnhancedEntropyAnalyzer {
    /**
     * Detects the type of string based on character set
     * Returns: 'hex', 'base64', or 'general'
     */
    static detectStringType(str: string): 'hex' | 'base64' | 'general' {
        if (!str || str.length === 0) return 'general';
        
        // Check for hex (all characters in [0-9a-fA-F])
        if (/^[0-9a-fA-F]+$/i.test(str)) {
            return 'hex';
        }
        
        // Check for base64 (all characters in [A-Za-z0-9+/=] and padded with '=')
        // Spec: padded base64 ends with '=' and length is valid (multiple of 4)
        if (/^[A-Za-z0-9+/=]+$/.test(str) && str.endsWith('=') && str.length % 4 === 0) {
            return 'base64';
        }
        
        return 'general';
    }
    
    /**
     * Gets type-specific entropy threshold
     */
    static getTypeSpecificThreshold(type: 'hex' | 'base64' | 'general'): number {
        const thresholds = {
            'hex': 3.0,      // Random hex ~3.5-4.0 bits/char
            'base64': 4.3,   // Random base64 ~5.0-6.0 bits/char
            'general': 4.0   // General text threshold
        };
        return thresholds[type];
    }
    /**
     * Calculates Shannon entropy of a string
     * Uses the formula: entropy = -Σ(p * log2(p)) where p is the probability of each character
     * Only computes if length >= 20 to avoid inflated entropy from small samples
     */
    static calculateShannonEntropy(str: string): number {
        if (!str || str.length === 0) return 0.0;
        
        // Skip very short strings (inflated entropy due to small samples)
        if (str.length < 20) {
            return 0.0;
        }

        const charCounts = new Map<string, number>();
        for (const char of str) {
            charCounts.set(char, (charCounts.get(char) || 0) + 1);
        }

        let entropy = 0.0;
        const length = str.length;

        for (const count of charCounts.values()) {
            const p = count / length;
            entropy -= p * Math.log2(p);
        }

        return entropy;
    }
    
    /**
     * Calculates normalized entropy: H_norm = H / log2(|A|)
     * Where |A| is the number of unique characters (alphabet size)
     * True secrets (uniform random) approach 1.0; patterned strings are <0.8
     */
    static calculateNormalizedEntropy(str: string): number {
        if (!str || str.length === 0) return 0.0;
        
        const shannonEntropy = this.calculateShannonEntropy(str);
        if (shannonEntropy === 0.0) return 0.0;
        
        // Get unique character count (alphabet size)
        const uniqueChars = new Set(str).size;
        if (uniqueChars <= 1) return 0.0;
        
        const maxEntropy = Math.log2(uniqueChars);
        if (maxEntropy === 0) return 0.0;
        
        const normalized = shannonEntropy / maxEntropy;
        // Clamp to 1.0 (impossible for uniform, indicates calculation issue)
        return Math.min(normalized, 1.0);
    }
    
    /**
     * Calculates length-weighted entropy score
     * Effective score = H - (k / length), where k tunes down short strings
     * Also penalizes very long strings (>200 chars) that are likely code
     */
    static calculateLengthWeightedEntropy(str: string, k: number = 15): number {
        if (!str || str.length === 0) return 0.0;
        
        const entropy = this.calculateShannonEntropy(str);
        if (entropy === 0.0) return 0.0;
        
        // Penalize short strings
        let score = entropy - (k / str.length);
        
        // Penalize very long strings (likely code, not secrets)
        if (str.length > 200) {
            score -= (str.length - 200) * 0.01; // Small penalty per char over 200
        } else if (str.length > 100) {
            score -= (str.length - 100) * 0.005; // Smaller penalty for 100-200 chars
        }
        
        return Math.max(score, 0.0);
    }
    
    /**
     * Performs chi-square goodness-of-fit test for uniformity
     * Tests if character distribution is uniform (true for random secrets).
     *
     * Returns:
     * - chiSquare statistic
     * - isUniform: true if p >= 0.05
     * - pValue: P(Χ² >= chiSquare) using chi-square survival function
     */
    static chiSquareUniformityTest(str: string): { chiSquare: number; isUniform: boolean; pValue: number } {
        if (!str || str.length < 20) {
            return { chiSquare: 0, isUniform: false, pValue: 0 };
        }
        
        const charCounts = new Map<string, number>();
        for (const char of str) {
            charCounts.set(char, (charCounts.get(char) || 0) + 1);
        }
        
        const length = str.length;
        const alphabetSize = charCounts.size;
        if (alphabetSize <= 1) {
            return { chiSquare: Infinity, isUniform: false, pValue: 0 };
        }
        
        const expected = length / alphabetSize;
        let chiSquare = 0.0;
        
        for (const count of charCounts.values()) {
            const diff = count - expected;
            chiSquare += (diff * diff) / expected;
        }
        
        // Degrees of freedom = alphabetSize - 1
        const degreesOfFreedom = alphabetSize - 1;

        const pValue = this.chiSquareSurvivalFunction(chiSquare, degreesOfFreedom);
        const isUniform = pValue >= 0.05;
        return { chiSquare, isUniform, pValue };
    }

    /**
     * Chi-square survival function: P(Χ² >= x) for df degrees of freedom.
     * p-value = Q(df/2, x/2) where Q is the regularized upper incomplete gamma.
     */
    static chiSquareSurvivalFunction(x: number, df: number): number {
        if (!isFinite(x) || x < 0 || df <= 0) return 0;
        return this.regularizedGammaQ(df / 2, x / 2);
    }

    /**
     * Regularized upper incomplete gamma Q(a, x).
     * Uses series expansion for P(a,x) when x < a+1, otherwise continued fraction for Q(a,x).
     */
    static regularizedGammaQ(a: number, x: number): number {
        if (!isFinite(a) || !isFinite(x) || a <= 0 || x < 0) return 0;
        if (x === 0) return 1;

        // If x < a+1 compute P and return Q = 1-P
        if (x < a + 1) {
            const p = this.regularizedGammaP_series(a, x);
            return Math.max(0, Math.min(1, 1 - p));
        }

        // Else compute Q directly via continued fraction
        return this.regularizedGammaQ_contfrac(a, x);
    }

    private static regularizedGammaP_series(a: number, x: number): number {
        const ITMAX = 200;
        const EPS = 3e-7;

        const gln = this.logGamma(a);
        let ap = a;
        let sum = 1 / a;
        let del = sum;

        for (let n = 1; n <= ITMAX; n++) {
            ap += 1;
            del *= x / ap;
            sum += del;
            if (Math.abs(del) < Math.abs(sum) * EPS) {
                const p = sum * Math.exp(-x + a * Math.log(x) - gln);
                return Math.max(0, Math.min(1, p));
            }
        }

        const p = sum * Math.exp(-x + a * Math.log(x) - gln);
        return Math.max(0, Math.min(1, p));
    }

    private static regularizedGammaQ_contfrac(a: number, x: number): number {
        const ITMAX = 200;
        const EPS = 3e-7;
        const FPMIN = 1e-30;

        const gln = this.logGamma(a);
        let b = x + 1 - a;
        let c = 1 / FPMIN;
        let d = 1 / Math.max(b, FPMIN);
        let h = d;

        for (let i = 1; i <= ITMAX; i++) {
            const an = -i * (i - a);
            b += 2;
            d = an * d + b;
            if (Math.abs(d) < FPMIN) d = FPMIN;
            c = b + an / c;
            if (Math.abs(c) < FPMIN) c = FPMIN;
            d = 1 / d;
            const del = d * c;
            h *= del;
            if (Math.abs(del - 1.0) < EPS) break;
        }

        const q = Math.exp(-x + a * Math.log(x) - gln) * h;
        return Math.max(0, Math.min(1, q));
    }

    /**
     * Natural log of gamma function via Lanczos approximation.
     */
    static logGamma(z: number): number {
        // Lanczos coefficients (g=7, n=9)
        const p = [
            0.99999999999980993,
            676.5203681218851,
            -1259.1392167224028,
            771.32342877765313,
            -176.61502916214059,
            12.507343278686905,
            -0.13857109526572012,
            9.9843695780195716e-6,
            1.5056327351493116e-7
        ];

        if (z < 0.5) {
            // Reflection formula
            return Math.log(Math.PI) - Math.log(Math.sin(Math.PI * z)) - this.logGamma(1 - z);
        }

        z -= 1;
        let x = p[0];
        for (let i = 1; i < p.length; i++) {
            x += p[i] / (z + i);
        }
        const t = z + p.length - 0.5;
        return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(x);
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

