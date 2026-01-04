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
        developmentMode: boolean;
        minEntropy: number;
        skipDevelopmentValues: boolean;
    } {
        return {
            developmentMode: this.get<boolean>('scanner.developmentMode', true),
            minEntropy: this.get<number>('scanner.minEntropy', 3.0),
            skipDevelopmentValues: this.get<boolean>('scanner.skipDevelopmentValues', true),
        };
    }
}

