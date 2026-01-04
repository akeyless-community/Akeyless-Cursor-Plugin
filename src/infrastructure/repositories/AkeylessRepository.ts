import { IAkeylessRepository } from '../../core/interfaces/IAkeylessRepository';
import { AkeylessItem } from '../../types';
import { RepositoryError } from '../../core/errors';
import { logger } from '../../utils/logger';
import { promisify } from 'util';
import { exec, ExecOptions } from 'child_process';

/**
 * Akeyless Repository implementation
 * Implements Repository Pattern for data access
 */
export class AkeylessRepository implements IAkeylessRepository {
    private readonly akeylessPath: string;
    private readonly execAsync: (command: string, options?: ExecOptions) => Promise<{ stdout: string; stderr: string }>;

    constructor(akeylessPath: string = 'akeyless') {
        this.akeylessPath = akeylessPath;
        
        // Create exec function with increased maxBuffer
        const execWithBuffer = (command: string, options?: ExecOptions) => {
            return promisify(exec)(command, {
                maxBuffer: 50 * 1024 * 1024, // 50MB buffer
                ...options
            });
        };
        this.execAsync = execWithBuffer;
    }

    async listItems(): Promise<AkeylessItem[]> {
        try {
            logger.info('📋 Getting items from Akeyless CLI with pagination...');
            
            // Check if akeyless CLI is available
            await this.verifyCLIAvailable();
            
            const allItems: AkeylessItem[] = [];
            let nextPage: string | null = null;
            let pageCount = 0;
            
            do {
                pageCount++;
                logger.info(`📄 Fetching page ${pageCount}...`);
                
                const command = this.buildListCommand(nextPage);
                const { stdout } = await this.execAsync(command);
                
                try {
                    const response = JSON.parse(stdout);
                    const items: AkeylessItem[] = response.items || [];
                    allItems.push(...items);
                    nextPage = response.next_page_token || null;
                } catch (parseError) {
                    logger.error('Failed to parse Akeyless CLI response:', parseError);
                    throw new RepositoryError('Failed to parse Akeyless CLI response');
                }
            } while (nextPage);
            
            logger.info(`✅ Retrieved ${allItems.length} items from Akeyless`);
            return allItems;
        } catch (error) {
            if (error instanceof RepositoryError) {
                throw error;
            }
            throw new RepositoryError(`Failed to list items: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    async getSecretValue(path: string): Promise<string> {
        try {
            logger.info(`🔍 Getting secret value for path: ${path}`);
            const command = `${this.akeylessPath} get-secret-value --path "${path}" --json`;
            const { stdout } = await this.execAsync(command);
            
            try {
                const response = JSON.parse(stdout);
                return response.value || '';
            } catch (parseError) {
                throw new RepositoryError('Failed to parse secret value response');
            }
        } catch (error) {
            if (error instanceof RepositoryError) {
                throw error;
            }
            throw new RepositoryError(`Failed to get secret value: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    async createSecret(path: string, value: string, itemType: string = 'STATIC_SECRET'): Promise<void> {
        try {
            logger.info(`💾 Creating secret at path: ${path}`);
            const command = `${this.akeylessPath} create-secret --path "${path}" --value "${value}" --type ${itemType} --json`;
            await this.execAsync(command);
            logger.info(`✅ Secret created successfully at: ${path}`);
        } catch (error) {
            throw new RepositoryError(`Failed to create secret: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    async updateSecret(path: string, value: string): Promise<void> {
        try {
            logger.info(`🔄 Updating secret at path: ${path}`);
            const command = `${this.akeylessPath} update-secret-value --path "${path}" --value "${value}" --json`;
            await this.execAsync(command);
            logger.info(`✅ Secret updated successfully at: ${path}`);
        } catch (error) {
            throw new RepositoryError(`Failed to update secret: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    async deleteSecret(path: string): Promise<void> {
        try {
            logger.info(`🗑️ Deleting secret at path: ${path}`);
            const command = `${this.akeylessPath} delete-item --path "${path}" --json`;
            await this.execAsync(command);
            logger.info(`✅ Secret deleted successfully at: ${path}`);
        } catch (error) {
            throw new RepositoryError(`Failed to delete secret: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    async searchSecrets(pattern: string): Promise<AkeylessItem[]> {
        try {
            logger.info(`🔍 Searching secrets with pattern: ${pattern}`);
            const allItems = await this.listItems();
            const lowerPattern = pattern.toLowerCase();
            return allItems.filter(item => 
                item.item_name.toLowerCase().includes(lowerPattern)
            );
        } catch (error) {
            throw new RepositoryError(`Failed to search secrets: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Lists a single page of items (for pagination support)
     */
    async listItemsPage(paginationToken?: string): Promise<{ items: AkeylessItem[], nextPage: string | null }> {
        try {
            logger.info(`📄 Fetching page with token: ${paginationToken || 'none'}`);
            const command = this.buildListCommand(paginationToken || null);
            const { stdout } = await this.execAsync(command);
            
            try {
                const data = JSON.parse(stdout);
                const validTypes = ['STATIC_SECRET', 'DYNAMIC_SECRET', 'ROTATED_SECRET', 'CLASSIC_KEY'];
                const filteredItems = (data.items || []).filter((item: any) => 
                    validTypes.includes(item.item_type)
                );
                
                return {
                    items: filteredItems,
                    nextPage: data.next_page || null
                };
            } catch (parseError) {
                throw new RepositoryError('Failed to parse Akeyless CLI response');
            }
        } catch (error) {
            if (error instanceof RepositoryError) {
                throw error;
            }
            throw new RepositoryError(`Failed to list items page: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Gets dynamic secret value
     */
    async getDynamicSecretValue(secretName: string): Promise<any> {
        try {
            logger.info(`🔄 Getting dynamic secret value for: ${secretName}`);
            const command = `${this.akeylessPath} get-dynamic-secret-value --name "${secretName}" --json`;
            const { stdout } = await this.execAsync(command);
            return JSON.parse(stdout);
        } catch (error) {
            throw new RepositoryError(`Failed to get dynamic secret value: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Gets rotated secret value
     */
    async getRotatedSecretValue(secretName: string): Promise<any> {
        try {
            logger.info(`🔄 Getting rotated secret value for: ${secretName}`);
            const command = `${this.akeylessPath} get-rotated-secret-value --name "${secretName}" --json`;
            const { stdout } = await this.execAsync(command);
            return JSON.parse(stdout);
        } catch (error) {
            throw new RepositoryError(`Failed to get rotated secret value: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    private async verifyCLIAvailable(): Promise<void> {
        try {
            await this.execAsync(`${this.akeylessPath} --version`);
        } catch (error) {
            throw new RepositoryError(
                'Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli'
            );
        }
    }

    private buildListCommand(nextPage: string | null): string {
        let command = `${this.akeylessPath} list-items --json`;
        if (nextPage) {
            command += ` --pagination-token "${nextPage}"`;
        }
        return command;
    }
}

