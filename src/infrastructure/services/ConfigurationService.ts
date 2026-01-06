import * as vscode from 'vscode';
import { IConfigurationService } from '../../core/interfaces/IConfigurationService';
import { ConfigurationError } from '../../core/errors';

/**
 * Configuration Service implementation
 * Centralizes VS Code configuration management
 */
export class ConfigurationService implements IConfigurationService {
    private readonly config: vscode.WorkspaceConfiguration;
    private readonly section: string = 'akeyless';

    constructor() {
        this.config = vscode.workspace.getConfiguration(this.section);
    }

    private getEnv(key: string): string | undefined {
        // VS Code extensions run in Node; env vars are available via process.env.
        return process.env[key];
    }

    private parseEnvBool(key: string): boolean | undefined {
        const raw = this.getEnv(key);
        if (raw === undefined) return undefined;
        const v = raw.trim().toLowerCase();
        if (['1', 'true', 'yes', 'y', 'on'].includes(v)) return true;
        if (['0', 'false', 'no', 'n', 'off'].includes(v)) return false;
        return undefined;
    }

    private parseEnvNumber(key: string): number | undefined {
        const raw = this.getEnv(key);
        if (raw === undefined) return undefined;
        const n = Number(raw.trim());
        return Number.isFinite(n) ? n : undefined;
    }

    private parseEnvList(key: string): string[] | undefined {
        const raw = this.getEnv(key);
        if (raw === undefined) return undefined;
        const trimmed = raw.trim();
        if (!trimmed) return [];
        // Support either JSON array or comma-separated list
        if (trimmed.startsWith('[')) {
            try {
                const parsed = JSON.parse(trimmed);
                if (Array.isArray(parsed)) return parsed.map(String);
            } catch {
                // fall through
            }
        }
        return trimmed.split(',').map(s => s.trim()).filter(Boolean);
    }

    get<T>(key: string, defaultValue?: T): T {
        const fullKey = key.startsWith(this.section) ? key : `${this.section}.${key}`;
        return this.config.get<T>(fullKey, defaultValue as T);
    }

    async set(key: string, value: any): Promise<void> {
        try {
            const fullKey = key.startsWith(this.section) ? key : `${this.section}.${key}`;
            await this.config.update(fullKey, value, vscode.ConfigurationTarget.Global);
        } catch (error) {
            throw new ConfigurationError(
                `Failed to set configuration: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    isAutoScanOnSaveEnabled(): boolean {
        return this.get<boolean>('autoScanOnSave', true);
    }

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
    } {
        // Env var overrides (optional)
        const envMinEntropy = this.parseEnvNumber('AKEYLESS_SCANNER_MIN_ENTROPY');
        const envHighConfidenceBypass = this.parseEnvBool('AKEYLESS_SCANNER_FILTERS_HIGH_CONFIDENCE_BYPASS');
        const envDenylistEnabled = this.parseEnvBool('AKEYLESS_SCANNER_FILTERS_DENYLIST_ENABLED');
        const envDenylistCaseInsensitive = this.parseEnvBool('AKEYLESS_SCANNER_FILTERS_DENYLIST_CASE_INSENSITIVE');
        const envDenylistSubstrings = this.parseEnvList('AKEYLESS_SCANNER_FILTERS_DENYLIST_SUBSTRINGS');
        const envDenylistRegexes = this.parseEnvList('AKEYLESS_SCANNER_FILTERS_DENYLIST_REGEXES');
        const envFunctionCallEnabled = this.parseEnvBool('AKEYLESS_SCANNER_FILTERS_FUNCTIONCALL_ENABLED');
        const envTestDataEnabled = this.parseEnvBool('AKEYLESS_SCANNER_FILTERS_TESTDATA_ENABLED');
        const envTestDataSubstrings = this.parseEnvList('AKEYLESS_SCANNER_FILTERS_TESTDATA_SUBSTRINGS');
        const envApplyNonBase64Delta = this.parseEnvBool('AKEYLESS_SCANNER_FILTERS_ENTROPY_APPLY_NON_BASE64_DELTA');
        const envNonBase64Delta = this.parseEnvNumber('AKEYLESS_SCANNER_FILTERS_ENTROPY_NON_BASE64_DELTA');
        const envFilenameEnabled = this.parseEnvBool('AKEYLESS_SCANNER_FILTERS_FILENAME_ENABLED');
        const envFilenameCaseInsensitive = this.parseEnvBool('AKEYLESS_SCANNER_FILTERS_FILENAME_CASE_INSENSITIVE');
        const envFilenameSubstrings = this.parseEnvList('AKEYLESS_SCANNER_FILTERS_FILENAME_SUBSTRINGS');
        const envFilenameSuffixes = this.parseEnvList('AKEYLESS_SCANNER_FILTERS_FILENAME_SUFFIXES');

        return {
            minEntropy: envMinEntropy ?? this.get<number>('scanner.minEntropy', 3.0),
            filters: {
                highConfidenceBypass: envHighConfidenceBypass ?? this.get<boolean>('scanner.filters.highConfidenceBypass', true),
                denylist: {
                    enabled: envDenylistEnabled ?? this.get<boolean>('scanner.filters.denylist.enabled', true),
                    caseInsensitiveSubstrings: envDenylistCaseInsensitive ?? this.get<boolean>('scanner.filters.denylist.caseInsensitiveSubstrings', true),
                    // Note: leave undefined if not configured so ScannerConfigManager defaults apply.
                    substrings: envDenylistSubstrings ?? this.get<string[] | undefined>('scanner.filters.denylist.substrings'),
                    regexes: envDenylistRegexes ?? this.get<string[] | undefined>('scanner.filters.denylist.regexes')
                },
                functionCall: {
                    enabled: envFunctionCallEnabled ?? this.get<boolean>('scanner.filters.functionCall.enabled', true)
                },
                testData: {
                    enabled: envTestDataEnabled ?? this.get<boolean>('scanner.filters.testData.enabled', true),
                    substrings: envTestDataSubstrings ?? this.get<string[] | undefined>('scanner.filters.testData.substrings')
                },
                entropy: {
                    nonBase64Delta: envNonBase64Delta ?? this.get<number>('scanner.filters.entropy.nonBase64Delta', 0.5),
                    applyNonBase64Delta: envApplyNonBase64Delta ?? this.get<boolean>('scanner.filters.entropy.applyNonBase64Delta', true)
                },
                filename: {
                    enabled: envFilenameEnabled ?? this.get<boolean>('scanner.filters.filename.enabled', true),
                    caseInsensitive: envFilenameCaseInsensitive ?? this.get<boolean>('scanner.filters.filename.caseInsensitive', true),
                    substrings: envFilenameSubstrings ?? this.get<string[] | undefined>('scanner.filters.filename.substrings'),
                    suffixes: envFilenameSuffixes ?? this.get<string[] | undefined>('scanner.filters.filename.suffixes')
                }
            }
        };
    }
}

