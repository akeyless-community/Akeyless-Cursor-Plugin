import { ScannerConfig } from '../types';

/**
 * Immutable scanner configuration
 * Use with() method to create new instances with updated values
 */
export class ScannerConfigManager {
    private readonly config: ScannerConfig;

    constructor(config?: Partial<ScannerConfig>) {
        this.config = {
            minEntropy: config?.minEntropy ?? 4.0,
            entropyThresholds: {
                apiKey: config?.entropyThresholds?.apiKey ?? 3.5,
                password: config?.entropyThresholds?.password ?? 3.0,
                token: config?.entropyThresholds?.token ?? 4.0,
                connectionString: config?.entropyThresholds?.connectionString ?? 3.5
            },
            filters: {
                highConfidenceBypass: config?.filters?.highConfidenceBypass ?? true,
                denylist: {
                    enabled: config?.filters?.denylist?.enabled ?? true,
                    caseInsensitiveSubstrings: config?.filters?.denylist?.caseInsensitiveSubstrings ?? true,
                    substrings: config?.filters?.denylist?.substrings ?? [
                        // Conservative defaults: common placeholders / docs examples
                        'REPLACE_ME',
                        'REPLACE-WITH',
                        'CHANGE_ME',
                        'CHANGEME',
                        'INSERT_KEY',
                        'INSERT_TOKEN',
                        'YOUR_API_KEY',
                        'YOUR-API-KEY',
                        'YOUR_TOKEN',
                        'YOUR_SECRET',

                        // Common across projects: obvious non-secret indicators
                        'example',
                        'test',
                        'dummy',
                        'sample',
                        'placeholder',
                        'mock',
                        'stub',
                        'localhost'
                    ],
                    regexes: config?.filters?.denylist?.regexes ?? [
                        // Common placeholder patterns
                        '/^(?:your|insert|replace|change)[\\s_-]*(?:api[_-]?key|token|secret|password)$/i'
                    ]
                },
                /**
                 * Code-pattern denylist: filters out common code patterns that look like secrets
                 * but are actually variable names, function names, etc.
                 */
                codePatternDenylist: {
                    enabled: config?.filters?.codePatternDenylist?.enabled ?? true,
                    caseInsensitive: config?.filters?.codePatternDenylist?.caseInsensitive ?? true,
                    substrings: config?.filters?.codePatternDenylist?.substrings ?? [
                        'path',
                        'Path',
                        'patch',
                        'proto',
                        'handler',
                        'test',
                        'example',
                        'dummy',
                        'mock',
                        'stub',
                        'localhost'
                    ]
                },
                functionCall: {
                    enabled: config?.filters?.functionCall?.enabled ?? true
                },
                testData: {
                    enabled: config?.filters?.testData?.enabled ?? true,
                    substrings: config?.filters?.testData?.substrings ?? [
                        'example.',
                        'test.',
                        'stub',
                        'mock',
                        'sample',
                        'dummy',
                        'placeholder'
                    ]
                },
                entropy: {
                    nonBase64Delta: config?.filters?.entropy?.nonBase64Delta ?? 0.5,
                    applyNonBase64Delta: config?.filters?.entropy?.applyNonBase64Delta ?? true
                },
                filename: {
                    enabled: config?.filters?.filename?.enabled ?? true,
                    caseInsensitive: config?.filters?.filename?.caseInsensitive ?? true,
                    substrings: config?.filters?.filename?.substrings ?? [
                        '_test.',
                        'testdata',
                        'mock',
                        'fixture'
                    ],
                    suffixes: config?.filters?.filename?.suffixes ?? [
                        '.pb.go'
                    ]
                }
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
            },
            filters: {
                ...this.config.filters,
                ...updates.filters,
                denylist: {
                    ...this.config.filters.denylist,
                    ...(updates.filters?.denylist ?? {})
                },
                functionCall: {
                    ...this.config.filters.functionCall,
                    ...(updates.filters?.functionCall ?? {})
                },
                testData: {
                    ...this.config.filters.testData,
                    ...(updates.filters?.testData ?? {})
                },
                entropy: {
                    ...this.config.filters.entropy,
                    ...(updates.filters?.entropy ?? {})
                },
                filename: {
                    ...this.config.filters.filename,
                    ...(updates.filters?.filename ?? {})
                },
                codePatternDenylist: {
                    ...this.config.filters.codePatternDenylist,
                    ...(updates.filters?.codePatternDenylist ?? {})
                }
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

