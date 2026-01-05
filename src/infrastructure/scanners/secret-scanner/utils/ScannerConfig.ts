import { ScannerConfig } from '../types';

/**
 * Immutable scanner configuration
 * Use with() method to create new instances with updated values
 */
export class ScannerConfigManager {
    private readonly config: ScannerConfig;

    constructor(config?: Partial<ScannerConfig>) {
        this.config = {
            developmentMode: config?.developmentMode ?? true,
            minEntropy: config?.minEntropy ?? 4.0,
            skipDevelopmentValues: config?.skipDevelopmentValues ?? true,
            entropyThresholds: {
                apiKey: config?.entropyThresholds?.apiKey ?? 3.5,
                password: config?.entropyThresholds?.password ?? 3.0,
                token: config?.entropyThresholds?.token ?? 4.0,
                connectionString: config?.entropyThresholds?.connectionString ?? 3.5
            }
        };
    }

    /**
     * Get the current configuration (read-only)
     */
    get(): Readonly<ScannerConfig> {
        return Object.freeze({
            ...this.config,
            entropyThresholds: Object.freeze({ ...this.config.entropyThresholds })
        });
    }

    /**
     * Create a new configuration instance with updated values
     * @param updates Partial configuration updates
     * @returns New ScannerConfigManager instance
     */
    with(updates: Partial<ScannerConfig>): ScannerConfigManager {
        return new ScannerConfigManager({
            ...this.config,
            ...updates,
            entropyThresholds: {
                ...this.config.entropyThresholds,
                ...updates.entropyThresholds
            }
        });
    }

    /**
     * Get default configuration
     */
    static default(): ScannerConfigManager {
        return new ScannerConfigManager();
    }
}

