import * as vscode from 'vscode';
import { IAkeylessRepository } from '../../core/interfaces/IAkeylessRepository';
import { AkeylessItem } from '../../types';
import { AkeylessCLI } from '../../services/akeyless-cli';
import { RepositoryError } from '../../core/errors';
import { logger } from '../../utils/logger';
import { customerFragmentCliHint } from '../../utils/gatewayHints';
import { getSecretValueViaRest } from '../../services/akeylessRestClient';

/**
 * Adapter Pattern: Bridges old AkeylessCLI to new IAkeylessRepository interface
 * Enables gradual migration from old to new code
 */
export class AkeylessCLIAdapter implements IAkeylessRepository {
    constructor(private readonly akeylessCLI: AkeylessCLI) {
        logger.info('🔌 AkeylessCLIAdapter initialized');
    }

    async listItems(): Promise<AkeylessItem[]> {
        try {
            return await this.akeylessCLI.listItems();
        } catch (error) {
            throw new RepositoryError(
                `Failed to list items: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    async getSecretValue(path: string, options?: { item?: AkeylessItem }): Promise<string> {
        const cfg = vscode.workspace.getConfiguration('akeyless');
        const profile = cfg.get<string>('cliProfile', 'default');
        const item = options?.item;
        const cliOpts = {
            profile: profile.trim() || undefined,
            itemAccessibility:
                item && typeof item.item_accessibility === 'number' ? item.item_accessibility : undefined,
        };

        // Custom-protection-key secrets: use REST flow (vault + gateway) first,
        // matching the browser extension's proven path. Falls back to CLI on error.
        if (item?.with_customer_fragment) {
            logger.info(
                'Custom protection key detected — using REST flow (secret-access-creds → get-gw-basic-info → derived-key → decrypt)'
            );
            try {
                const apiEndpoint = cfg.get<string>('apiEndpoint')?.trim() || undefined;
                return await getSecretValueViaRest({
                    secretName: path,
                    profile: profile.trim() || 'default',
                    itemAccessibility:
                        typeof item.item_accessibility === 'number' ? item.item_accessibility : 0,
                    itemId: item.item_id || undefined,
                    apiEndpoint,
                });
            } catch (restErr) {
                const restMsg = restErr instanceof Error ? restErr.message : String(restErr);
                logger.warn(`REST custom-key flow failed (will try CLI fallback): ${restMsg}`);
            }
        }

        try {
            logger.info(`Calling CLI get-secret-value for: ${path}`);
            const result = await this.akeylessCLI.getSecretValue(path, cliOpts);

            if (typeof result === 'string') {
                return result;
            }

            if (result && typeof result === 'object') {
                if (result.value !== undefined) {
                    if (typeof result.value === 'string') {
                        return result.value;
                    }
                    if (typeof result.value === 'object') {
                        return JSON.stringify(result.value, null, 2);
                    }
                    return String(result.value);
                }

                for (const key of ['secret', 'data', 'content']) {
                    if (result[key] !== undefined) {
                        const value = result[key];
                        if (typeof value === 'string') {
                            return value;
                        }
                        if (typeof value === 'object') {
                            return JSON.stringify(value, null, 2);
                        }
                        return String(value);
                    }
                }

                return JSON.stringify(result, null, 2);
            }

            return String(result || '');
        } catch (error) {
            let msg = error instanceof Error ? error.message : String(error);
            if (item?.with_customer_fragment) {
                msg += customerFragmentCliHint(profile, item.gateway_details);
            }
            throw new RepositoryError(`Failed to get secret value: ${msg}`);
        }
    }

    async createSecret(path: string, value: string, _itemType: string = 'STATIC_SECRET'): Promise<void> {
        try {
            await this.akeylessCLI.createStaticSecret(path, value);
        } catch (error) {
            throw new RepositoryError(
                `Failed to create secret: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    async updateSecret(path: string, value: string): Promise<void> {
        try {
            await this.akeylessCLI.updateStaticSecret(path, value);
        } catch (error) {
            throw new RepositoryError(
                `Failed to update secret: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    async deleteSecret(_path: string): Promise<void> {
        throw new RepositoryError('Delete operation not implemented in AkeylessCLI adapter');
    }

    async searchSecrets(pattern: string): Promise<AkeylessItem[]> {
        try {
            const allItems = await this.listItems();
            const lowerPattern = pattern.toLowerCase();
            return allItems.filter(item => 
                item.item_name.toLowerCase().includes(lowerPattern)
            );
        } catch (error) {
            throw new RepositoryError(
                `Failed to search secrets: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    // Additional methods from AkeylessCLI that might be needed
    async listItemsPage(paginationToken?: string): Promise<{ items: AkeylessItem[], nextPage: string | null }> {
        try {
            return await this.akeylessCLI.listItemsPage(paginationToken);
        } catch (error) {
            throw new RepositoryError(
                `Failed to list items page: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    async getDynamicSecretValue(secretName: string): Promise<any> {
        try {
            return await this.akeylessCLI.getDynamicSecretValue(secretName);
        } catch (error) {
            throw new RepositoryError(
                `Failed to get dynamic secret value: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    async getRotatedSecretValue(secretName: string): Promise<any> {
        try {
            return await this.akeylessCLI.getRotatedSecretValue(secretName);
        } catch (error) {
            throw new RepositoryError(
                `Failed to get rotated secret value: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }
}

