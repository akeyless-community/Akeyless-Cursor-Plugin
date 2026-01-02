import { SecretPattern } from './types';
import { SECRET_PATTERNS } from './patterns';

/**
 * Manages and provides access to secret detection patterns
 */
export class PatternRegistry {
    private readonly patterns: SecretPattern[];

    constructor(patterns: SecretPattern[] = SECRET_PATTERNS) {
        this.patterns = patterns;
    }

    /**
     * Get all patterns
     */
    getAll(): ReadonlyArray<SecretPattern> {
        return [...this.patterns];
    }

    /**
     * Get patterns sorted by confidence (high first)
     */
    getSortedByConfidence(): SecretPattern[] {
        return [...this.patterns].sort((a, b) => {
            if (a.confidence === 'high' && b.confidence !== 'high') return -1;
            if (b.confidence === 'high' && a.confidence !== 'high') return 1;
            return 0;
        });
    }

    /**
     * Get patterns by confidence level
     */
    getByConfidence(confidence: 'high' | 'medium'): SecretPattern[] {
        return this.patterns.filter(p => p.confidence === confidence);
    }

    /**
     * Get pattern count
     */
    getCount(): number {
        return this.patterns.length;
    }
}

