import { IAkeylessRepository } from '../../core/interfaces/IAkeylessRepository';
import { AkeylessItem } from '../../types';
import { AkeylessCLI } from '../../services/akeyless-cli';
import { RepositoryError } from '../../core/errors';
import { logger } from '../../utils/logger';

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

    async getSecretValue(path: string): Promise<string> {
        try {
            const result = await this.akeylessCLI.getSecretValue(path);
            
            // Handle different response formats from Akeyless CLI
            if (typeof result === 'string') {
                return result;
            }
            
            if (result && typeof result === 'object') {
                // Try common property names for the secret value
                if (result.value !== undefined) {
                    // If value is a string, return it; if it's an object, stringify it
                    return typeof result.value === 'string' ? result.value : JSON.stringify(result.value);
                }
                
                // If the object itself is the value (single property), extract it
                const keys = Object.keys(result);
                if (keys.length === 1 && keys[0] === 'value') {
                    const value = result.value;
                    return typeof value === 'string' ? value : JSON.stringify(value);
                }
                
                // If it's a simple object with string values, try to extract the first meaningful value
                for (const key of ['value', 'secret', 'data', 'content']) {
                    if (result[key] !== undefined) {
                        const value = result[key];
                        return typeof value === 'string' ? value : JSON.stringify(value);
                    }
                }
                
                // Last resort: stringify the entire object
                return JSON.stringify(result);
            }
            
            return String(result || '');
        } catch (error) {
            throw new RepositoryError(
                `Failed to get secret value: ${error instanceof Error ? error.message : String(error)}`
            );
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
        // AkeylessCLI doesn't have update method, so we'll create a new one
        // In a real scenario, you'd add update method to AkeylessCLI or use repository directly
        await this.createSecret(path, value);
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

