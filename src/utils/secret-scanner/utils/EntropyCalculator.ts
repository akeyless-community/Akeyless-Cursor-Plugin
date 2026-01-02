/**
 * Calculates entropy of strings to determine randomness
 * Higher entropy indicates more random/secret-like values
 */
export class EntropyCalculator {
    /**
     * Calculates entropy of a string (measure of randomness)
     * @param str The string to calculate entropy for
     * @returns Entropy value (higher = more random)
     */
    static calculate(str: string): number {
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
        
        // Consider character set diversity
        const uniqueChars = charCounts.size;
        const maxPossibleChars = 95; // Printable ASCII characters
        const diversityBonus = Math.min(uniqueChars / maxPossibleChars, 1) * 0.5;
        
        // Length bonus for longer strings
        const lengthBonus = Math.min(str.length / 50, 1) * 0.3;
        
        return entropy + diversityBonus + lengthBonus;
    }
}

