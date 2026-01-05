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
    };
}



