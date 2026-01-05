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
    isFalsePositive?: boolean;
    filterReason?: string;
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

