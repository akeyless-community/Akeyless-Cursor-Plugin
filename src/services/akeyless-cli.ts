import { AkeylessItem } from '../types';
import { logger } from '../utils/logger';
import { promisify } from 'util';
import { exec, ExecOptions } from 'child_process';

// Create exec function with increased maxBuffer to handle large secret lists
const execWithBuffer = (command: string, options?: ExecOptions) => {
    return promisify(exec)(command, {
        maxBuffer: 50 * 1024 * 1024, // 50MB buffer to handle large secret lists
        ...options
    });
};

const execAsync = execWithBuffer;

export class AkeylessCLI {
    constructor() {
        logger.info('🔧 AkeylessCLI initialized');
    }

    /**
     * Lists all items from Akeyless using CLI directly with pagination support
     */
    async listItems(): Promise<AkeylessItem[]> {
        try {
            logger.info('📋 Getting items from Akeyless CLI with pagination...');
            
            // Use akeyless from system PATH
            const akeylessPath = 'akeyless';
            
            // Check if akeyless CLI is available
            try {
                await execAsync(`${akeylessPath} --version`);
            } catch (error) {
                throw new Error('Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli');
            }
            
            const allItems: AkeylessItem[] = [];
            let nextPage: string | null = null;
            let pageCount = 0;
            
            do {
                pageCount++;
                logger.info(`📄 Fetching page ${pageCount}...`);
                
                // Build command with pagination
                let command = `${akeylessPath} list-items --json`;
                if (nextPage) {
                    command += ` --pagination-token "${nextPage}"`;
                }
                
                const { stdout } = await execAsync(command);
                const data = JSON.parse(stdout);
                
                // Check if response is empty (no items and no next_page)
                if (!data.items || data.items.length === 0) {
                    logger.info(`📭 Empty response received, stopping pagination`);
                    break;
                }
                
                logger.info(`📦 Received ${data.items.length} items from page ${pageCount}`);
                
                // Filter items to only include the types we want (CLI returns uppercase)
                const validTypes = ['STATIC_SECRET', 'DYNAMIC_SECRET', 'ROTATED_SECRET', 'CLASSIC_KEY'];
                const filteredItems = data.items.filter((item: any) => {
                    return validTypes.includes(item.item_type);
                });
                
                logger.info(`🔍 Filtered to ${filteredItems.length} items of valid types from page ${pageCount}`);
                allItems.push(...filteredItems);
                
                // Get next page token
                nextPage = data.next_page || null;
                
                if (nextPage) {
                    logger.info(`🔄 Next page token: ${nextPage}`);
                } else {
                    logger.info(`✅ No more pages available`);
                }
                
            } while (nextPage && pageCount < 100); // Limit to 100 pages to prevent infinite loops
            
            logger.info(`🎉 Completed listing items. Total pages: ${pageCount}, Total items: ${allItems.length}`);
            return allItems;
        } catch (error) {
            logger.error('❌ Failed to list items from CLI:', error);
            throw new Error(`Failed to list items: ${error}`);
        }
    }

    /**
     * Lists a single page of items from Akeyless using CLI
     */
    async listItemsPage(paginationToken?: string): Promise<{ items: AkeylessItem[], nextPage: string | null }> {
        try {
            logger.info(`📄 Fetching page with token: ${paginationToken || 'none'}`);
            
            // Use akeyless from system PATH
            const akeylessPath = 'akeyless';
            
            // Check if akeyless CLI is available
            try {
                await execAsync(`${akeylessPath} --version`);
            } catch (error) {
                throw new Error('Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli');
            }
            
            // Build command with pagination
            let command = `${akeylessPath} list-items --json`;
            if (paginationToken) {
                command += ` --pagination-token "${paginationToken}"`;
            }
            
            logger.info(`🔧 Executing CLI command: ${command}`);
            const { stdout } = await execAsync(command);
            logger.info(`📥 Raw CLI response length: ${stdout.length} characters`);
            
            const data = JSON.parse(stdout);
            logger.info(`📊 Parsed response structure:`, {
                hasItems: !!data.items,
                itemsLength: data.items?.length || 0,
                hasNextPage: !!data.next_page,
                nextPageToken: data.next_page || null
            });
            
            // Check if response is empty
            if (!data.items || data.items.length === 0) {
                logger.info(`📭 Empty response received`);
                return { items: [], nextPage: null };
            }
            
            logger.info(`📦 Received ${data.items.length} items from page`);
            
            // Filter items to only include the types we want (CLI returns uppercase)
            const validTypes = ['STATIC_SECRET', 'DYNAMIC_SECRET', 'ROTATED_SECRET', 'CLASSIC_KEY'];
            const filteredItems = data.items.filter((item: any) => {
                return validTypes.includes(item.item_type);
            });
            
            logger.info(`🔍 Filtered to ${filteredItems.length} items of valid types`);
            
            // Log sample items for debugging
            if (filteredItems.length > 0) {
                logger.info(`📋 Sample filtered items:`);
                filteredItems.slice(0, 3).forEach((item: any, index: number) => {
                    logger.info(`   ${index + 1}. ${item.item_name} (${item.item_type})`);
                });
            }
            
            return {
                items: filteredItems,
                nextPage: data.next_page || null
            };
        } catch (error) {
            logger.error('❌ Failed to list items page from CLI:', error);
            throw new Error(`Failed to list items page: ${error}`);
        }
    }

    /**
     * Gets the value of a specific secret using CLI directly
     */
    async getSecretValue(secretName: string): Promise<any> {
        try {
            logger.info(`🔐 Getting secret value for: ${secretName}`);
            
            // Use akeyless from system PATH
            const akeylessPath = 'akeyless';
            
            // Check if akeyless CLI is available
            try {
                await execAsync(`${akeylessPath} --version`);
            } catch (error) {
                throw new Error('Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli');
            }
            
            // Use CLI directly to get secret value
            const { stdout } = await execAsync(`${akeylessPath} get-secret-value --name "${secretName}" --json`);
            const data = JSON.parse(stdout);
            
            logger.info(`✅ Secret value retrieved successfully`);
            return data;
        } catch (error) {
            logger.error('❌ Failed to get secret value from CLI:', error);
            throw new Error(`Failed to get secret value: ${error}`);
        }
    }

    /**
     * Gets the value of a dynamic secret using CLI directly
     */
    async getDynamicSecretValue(secretName: string): Promise<any> {
        try {
            logger.info(`🔄 Getting dynamic secret value for: ${secretName}`);
            
            // Use akeyless from system PATH
            const akeylessPath = 'akeyless';
            
            // Check if akeyless CLI is available
            try {
                await execAsync(`${akeylessPath} --version`);
            } catch (error) {
                throw new Error('Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli');
            }
            
            // Use CLI directly to get dynamic secret value
            const { stdout } = await execAsync(`${akeylessPath} get-dynamic-secret-value --name "${secretName}" --json`);
            const data = JSON.parse(stdout);
            
            logger.info(`✅ Dynamic secret value retrieved successfully`);
            return data;
        } catch (error) {
            logger.error('❌ Failed to get dynamic secret value from CLI:', error);
            throw new Error(`Failed to get dynamic secret value: ${error}`);
        }
    }

    /**
     * Gets the value of a rotated secret using CLI directly
     */
    async getRotatedSecretValue(secretName: string): Promise<any> {
        try {
            logger.info(`🔄 Getting rotated secret value for: ${secretName}`);
            
            // Use akeyless from system PATH
            const akeylessPath = 'akeyless';
            
            // Check if akeyless CLI is available
            try {
                await execAsync(`${akeylessPath} --version`);
            } catch (error) {
                throw new Error('Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli');
            }
            
            // Use CLI directly to get rotated secret value
            const { stdout } = await execAsync(`${akeylessPath} get-rotated-secret-value --name "${secretName}" --json`);
            const data = JSON.parse(stdout);
            
            logger.info(`✅ Rotated secret value retrieved successfully`);
            return data;
        } catch (error) {
            logger.error('❌ Failed to get rotated secret value from CLI:', error);
            throw new Error(`Failed to get rotated secret value: ${error}`);
        }
    }

    /**
     * Creates a new static secret in Akeyless
     */
    async createStaticSecret(secretName: string, secretValue: string): Promise<any> {
        try {
            logger.info(`💾 Creating static secret: ${secretName}`);
            
            // Use akeyless from system PATH
            const akeylessPath = 'akeyless';
            
            // Check if akeyless CLI is available
            try {
                await execAsync(`${akeylessPath} --version`);
            } catch (error) {
                throw new Error('Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli');
            }
            
            // Use CLI to create static secret (correct command)
            // Escape the secret value to handle special characters
            const escapedValue = secretValue.replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r');
            const command = `${akeylessPath} create-secret --name "${secretName}" --value "${escapedValue}" --json`;
            logger.info(`🔧 Executing CLI command: ${command}`);
            
            const { stdout } = await execAsync(command);
            const data = JSON.parse(stdout);
            
            logger.info(`✅ Static secret created successfully: ${secretName}`);
            return data;
        } catch (error) {
            logger.error('❌ Failed to create static secret:', error);
            throw new Error(`Failed to create static secret: ${error}`);
        }
    }

} 