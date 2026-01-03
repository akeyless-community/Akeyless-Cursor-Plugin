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
}

export interface SecretPattern {
    name: string;
    pattern: RegExp;
    suggestion: string;
    confidence: 'high' | 'medium';
}

export interface ScannerConfig {
    developmentMode: boolean;
    minEntropy: number;
    skipDevelopmentValues: boolean;
    entropyThresholds: {
        apiKey: number;
        password: number;
        token: number;
        connectionString: number;
    };
    mlEnabled?: boolean; // Enable ML-based false positive classification
    mlConfidenceThreshold?: number; // ML confidence threshold (0-1, default 0.7)
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

