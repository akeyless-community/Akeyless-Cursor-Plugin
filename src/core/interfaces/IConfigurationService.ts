/**
 * Configuration service interface
 * Centralizes configuration management
 */
export interface IConfigurationService {
    /**
     * Gets a configuration value
     */
    get<T>(key: string, defaultValue?: T): T;

    /**
     * Sets a configuration value
     */
    set(key: string, value: any): Promise<void>;

    /**
     * Checks if auto-scan on save is enabled
     */
    isAutoScanOnSaveEnabled(): boolean;

    /**
     * Gets scanner configuration
     */
    getScannerConfig(): {
        minEntropy: number;
        filters?: {
            highConfidenceBypass?: boolean;
            denylist?: {
                enabled?: boolean;
                caseInsensitiveSubstrings?: boolean;
                substrings?: string[];
                regexes?: string[];
            };
            functionCall?: {
                enabled?: boolean;
            };
            testData?: {
                enabled?: boolean;
                substrings?: string[];
            };
            entropy?: {
                nonBase64Delta?: number;
                applyNonBase64Delta?: boolean;
            };
            filename?: {
                enabled?: boolean;
                caseInsensitive?: boolean;
                substrings?: string[];
                suffixes?: string[];
            };
        };
    };
}



