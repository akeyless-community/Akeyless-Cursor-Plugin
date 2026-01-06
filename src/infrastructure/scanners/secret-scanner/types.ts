/**
 * Types and interfaces for the secret scanner module
 */

export interface HardcodedSecret {
    fileName: string;
    lineNumber: number;
    column: number;
    value: string;
    type: string;
    context: string;
    confidence?: number; // 0.0 to 1.0
    entropy?: number;
    detectionReason?: string; // Why this secret was flagged (e.g., "Pattern match: API Key", "High entropy string")
    /**
     * Confidence of the rule/pattern that produced the finding (when applicable).
     * Used for "high-confidence bypass" logic.
     */
    patternConfidence?: 'high' | 'medium';
}

export interface SecretPattern {
    name: string;
    pattern: RegExp;
    suggestion: string;
    confidence: 'high' | 'medium';
}

export interface ScannerConfig {
    minEntropy: number;
    entropyThresholds: {
        apiKey: number;
        password: number;
        token: number;
        connectionString: number;
    };
    filters: {
        /**
         * If true, findings from "high confidence" rules are never filtered out by any mechanism.
         */
        highConfidenceBypass: boolean;
        /**
         * Denylist of known non-secrets. If a match contains a denylist substring or matches a denylist regex, it is skipped.
         */
        denylist: {
            enabled: boolean;
            caseInsensitiveSubstrings: boolean;
            substrings: string[];
            /**
             * Stored as string patterns; compiled to RegExp at runtime.
             */
            regexes: string[];
        };
        /**
         * Skip values that clearly look like function calls / getter invocations.
         */
        functionCall: {
            enabled: boolean;
        };
        /**
         * Skip obvious test/example placeholders.
         */
        testData: {
            enabled: boolean;
            substrings: string[];
        };
        /**
         * Entropy tuning knobs.
         */
        entropy: {
            /**
             * For non-base64 strings, raise the entropy threshold by this delta.
             */
            nonBase64Delta: number;
            applyNonBase64Delta: boolean;
        };
        /**
         * Optional filename-based filtering to ignore findings in test/generated files.
         */
        filename: {
            enabled: boolean;
            caseInsensitive: boolean;
            /**
             * If file path contains any of these substrings, skip findings (unless high-confidence bypass applies).
             */
            substrings: string[];
            /**
             * If file path ends with any of these suffixes, skip findings (unless high-confidence bypass applies).
             */
            suffixes: string[];
        };
    };
}

export interface ScanResult {
    results: Map<string, HardcodedSecret[]>;
    totalFilesScanned: number;
}

export interface DetectedRange {
    start: number;
    end: number;
    confidence: string;
    type: string;
}

