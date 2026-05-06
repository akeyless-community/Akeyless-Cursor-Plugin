import { AkeylessItem } from '../types';
import { logger } from '../utils/logger';
import {
    augmentListItemsFailureMessage,
    buildCreateSecretCommands,
    buildGetSecretValueCommands,
    buildUpdateSecretCommands,
    escapeShellDoubleQuotedArg,
    execFirstSuccessful,
    GetSecretValueCliOpts,
    normalizeListItemsNextPage,
    warnIfCliBelowListItemsMinimum,
} from '../utils/akeylessCliCompat';
import { promisify } from 'util';
import { exec, execFile, ExecOptions } from 'child_process';

const execFileAsync = promisify(execFile);

// Create exec function with increased maxBuffer to handle large secret lists
const execWithBuffer = (command: string, options?: ExecOptions) => {
    return promisify(exec)(command, {
        maxBuffer: 50 * 1024 * 1024, // 50MB buffer to handle large secret lists
        ...options
    });
};

const execAsync = execWithBuffer;

/** Max time for single secret-fetch CLI ops (describe-item / configure / get-secret-value). Avoids indefinite hang. */
const CLI_FETCH_TIMEOUT_MS = 180_000;

function execFetch(command: string): Promise<{ stdout: string; stderr: string }> {
    return execWithBuffer(command, { timeout: CLI_FETCH_TIMEOUT_MS });
}

export class AkeylessCLI {
    constructor() {
        logger.info(' AkeylessCLI initialized');
    }

    /**
     * Lists all items from Akeyless using CLI directly with pagination support
     */
    async listItems(): Promise<AkeylessItem[]> {
        try {
            logger.info(' Getting items from Akeyless CLI with pagination...');
            
            // Use akeyless from system PATH
            const akeylessPath = 'akeyless';
            
            // Check if akeyless CLI is available
            try {
                await execAsync(`${akeylessPath} --version`);
            } catch (error) {
                throw new Error('Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli');
            }

            await warnIfCliBelowListItemsMinimum(async () => {
                const { stdout, stderr } = await execAsync(`${akeylessPath} --version`);
                return stdout + stderr;
            });
            
            const allItems: AkeylessItem[] = [];
            let nextPage: string | null = null;
            let pageCount = 0;
            
            do {
                pageCount++;
                logger.info(` Fetching page ${pageCount}...`);
                
                // Build command with pagination
                let command = `${akeylessPath} list-items --json`;
                if (nextPage) {
                    command += ` --pagination-token "${nextPage}"`;
                }
                
                const { stdout } = await execAsync(command);
                const data = JSON.parse(stdout);
                
                // Check if response is empty (no items and no next_page)
                if (!data.items || data.items.length === 0) {
                    logger.info(` Empty response received, stopping pagination`);
                    break;
                }
                
                logger.info(` Received ${data.items.length} items from page ${pageCount}`);
                
                // Filter items to only include the types we want (CLI returns uppercase)
                const validTypes = ['STATIC_SECRET', 'DYNAMIC_SECRET', 'ROTATED_SECRET', 'CLASSIC_KEY'];
                const filteredItems = data.items.filter((item: any) => {
                    return validTypes.includes(item.item_type);
                });
                
                logger.info(` Filtered to ${filteredItems.length} items of valid types from page ${pageCount}`);
                allItems.push(...filteredItems);
                
                // Get next page token
                nextPage = normalizeListItemsNextPage(data);
                
                if (nextPage) {
                    logger.info(` Next page token: ${nextPage}`);
                } else {
                    logger.info(` No more pages available`);
                }
                
            } while (nextPage && pageCount < 100); // Limit to 100 pages to prevent infinite loops
            
            logger.info(` Completed listing items. Total pages: ${pageCount}, Total items: ${allItems.length}`);
            return allItems;
        } catch (error) {
            logger.error(' Failed to list items from CLI:', error);
            const msg = error instanceof Error ? error.message : String(error);
            throw new Error(augmentListItemsFailureMessage(`Failed to list items: ${msg}`));
        }
    }

    /**
     * Lists a single page of items from Akeyless using CLI
     */
    async listItemsPage(paginationToken?: string): Promise<{ items: AkeylessItem[], nextPage: string | null }> {
        try {
            logger.info(` Fetching page with token: ${paginationToken || 'none'}`);
            
            // Use akeyless from system PATH
            const akeylessPath = 'akeyless';
            
            // Check if akeyless CLI is available
            try {
                await execAsync(`${akeylessPath} --version`);
            } catch (error) {
                throw new Error('Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli');
            }

            await warnIfCliBelowListItemsMinimum(async () => {
                const { stdout, stderr } = await execAsync(`${akeylessPath} --version`);
                return stdout + stderr;
            });
            
            // Build command with pagination
            let command = `${akeylessPath} list-items --json`;
            if (paginationToken) {
                command += ` --pagination-token "${paginationToken}"`;
            }
            
            logger.info(` Executing CLI command: ${command}`);
            const { stdout } = await execAsync(command);
            logger.info(` Raw CLI response length: ${stdout.length} characters`);
            
            const data = JSON.parse(stdout);
            logger.info(` Parsed response structure:`, {
                hasItems: !!data.items,
                itemsLength: data.items?.length || 0,
                hasNextPage: !!normalizeListItemsNextPage(data),
                nextPageToken: normalizeListItemsNextPage(data),
            });
            
            // Check if response is empty
            if (!data.items || data.items.length === 0) {
                logger.info(` Empty response received`);
                return { items: [], nextPage: null };
            }
            
            logger.info(` Received ${data.items.length} items from page`);
            
            // Filter items to only include the types we want (CLI returns uppercase)
            const validTypes = ['STATIC_SECRET', 'DYNAMIC_SECRET', 'ROTATED_SECRET', 'CLASSIC_KEY'];
            const filteredItems = data.items.filter((item: any) => {
                return validTypes.includes(item.item_type);
            });
            
            logger.info(` Filtered to ${filteredItems.length} items of valid types`);
            
            // Log sample items for debugging
            if (filteredItems.length > 0) {
                logger.info(` Sample filtered items:`);
                filteredItems.slice(0, 3).forEach((item: any, index: number) => {
                    logger.info(`   ${index + 1}. ${item.item_name} (${item.item_type})`);
                });
            }
            
            return {
                items: filteredItems,
                nextPage: normalizeListItemsNextPage(data),
            };
        } catch (error) {
            logger.error(' Failed to list items page from CLI:', error);
            const msg = error instanceof Error ? error.message : String(error);
            throw new Error(augmentListItemsFailureMessage(`Failed to list items page: ${msg}`));
        }
    }

    /**
     * Lists Gateway clusters for the account (`cluster_url`, `customer_fragments`).
     * Prefer this over describe-item when resolving Default Gateway URL for custom-key secrets.
     */
    async listGateways(profile?: string): Promise<unknown> {
        logger.info(`CLI: list-gateways (timeout ${CLI_FETCH_TIMEOUT_MS / 1000}s)`);
        const args = ['list-gateways', '--json'];
        if (profile?.trim()) {
            args.push('--profile', profile.trim());
        }
        try {
            const { stdout } = await execFileAsync('akeyless', args, {
                timeout: CLI_FETCH_TIMEOUT_MS,
                maxBuffer: 50 * 1024 * 1024,
            });
            logger.info('CLI: list-gateways completed');
            return JSON.parse(stdout);
        } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            if (msg.includes('timeout') || msg.includes('ETIMEDOUT')) {
                throw new Error(
                    `list-gateways timed out after ${CLI_FETCH_TIMEOUT_MS / 1000}s. ${msg}`
                );
            }
            throw e;
        }
    }

    /**
     * Item details including gateway cluster URL (`--gateway-details`).
     */
    async describeItemWithGatewayDetails(secretName: string, cliOpts?: GetSecretValueCliOpts): Promise<unknown> {
        const akeylessPath = 'akeyless';
        await execAsync(`${akeylessPath} --version`);
        const n = escapeShellDoubleQuotedArg(secretName);
        const parts: string[] = [
            akeylessPath,
            'describe-item',
            '--name',
            `"${n}"`,
            '--gateway-details=true',
            '--json',
        ];
        if (cliOpts?.profile?.trim()) {
            parts.push('--profile', `"${escapeShellDoubleQuotedArg(cliOpts.profile.trim())}"`);
        }
        if (cliOpts?.itemAccessibility === 1) {
            parts.push('--accessibility', 'personal');
        }
        const cmd = parts.join(' ');
        logger.info(
            `CLI: describe-item --gateway-details (timeout ${CLI_FETCH_TIMEOUT_MS / 1000}s) — ${secretName}`
        );
        try {
            const { stdout } = await execFetch(cmd);
            logger.info('CLI: describe-item completed');
            return JSON.parse(stdout);
        } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            if (msg.includes('timeout') || msg.includes('ETIMEDOUT')) {
                throw new Error(
                    `describe-item timed out after ${CLI_FETCH_TIMEOUT_MS / 1000}s (network/gateway?). ${msg}`
                );
            }
            throw e;
        }
    }

    /**
     * Sets Default Gateway URL on the CLI profile (same as `akeyless configure --gateway-url`).
     */
    async configureGatewayUrl(profile: string, gatewayUrl: string): Promise<void> {
        logger.info(`CLI: configure --gateway-url for profile "${profile}"`);
        try {
            // execFile (no shell) avoids hangs from stdin/TTY quirks that affect some `exec` shells.
            await execFileAsync(
                'akeyless',
                ['configure', '--profile', profile, '--gateway-url', gatewayUrl, '--json'],
                {
                    timeout: CLI_FETCH_TIMEOUT_MS,
                    maxBuffer: 50 * 1024 * 1024,
                }
            );
            logger.info('CLI: configure --gateway-url completed');
        } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            if (msg.includes('timeout') || msg.includes('ETIMEDOUT')) {
                throw new Error(
                    `configure --gateway-url timed out after ${CLI_FETCH_TIMEOUT_MS / 1000}s. ${msg}`
                );
            }
            throw e;
        }
    }

    /**
     * Gets the value of a specific secret using CLI directly
     */
    async getSecretValue(secretName: string, cliOpts?: GetSecretValueCliOpts): Promise<any> {
        try {
            logger.info(` Getting secret value for: ${secretName}`);
            
            // Use akeyless from system PATH
            const akeylessPath = 'akeyless';
            
            // Check if akeyless CLI is available
            try {
                await execAsync(`${akeylessPath} --version`);
            } catch (error) {
                throw new Error('Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli');
            }
            
            logger.info(
                `CLI: get-secret-value (timeout ${CLI_FETCH_TIMEOUT_MS / 1000}s) — ${secretName}`
            );
            const { stdout } = await execFirstSuccessful(
                execFetch,
                buildGetSecretValueCommands(akeylessPath, secretName, cliOpts),
                'get-secret-value'
            );
            
            const data = JSON.parse(stdout);
            
            logger.info(` Secret value retrieved successfully`);
            return data;
        } catch (error) {
            logger.error(' Failed to get secret value from CLI:', error);
            const msg = error instanceof Error ? error.message : String(error);
            if (msg.includes('timeout') || msg.includes('ETIMEDOUT')) {
                throw new Error(
                    `Failed to get secret value: CLI timed out after ${CLI_FETCH_TIMEOUT_MS / 1000}s (check VPN/network/gateway). ${msg}`
                );
            }
            throw new Error(`Failed to get secret value: ${error}`);
        }
    }

    /**
     * Gets the value of a dynamic secret using CLI directly
     */
    async getDynamicSecretValue(secretName: string): Promise<any> {
        try {
            logger.info(` Getting dynamic secret value for: ${secretName}`);
            
            // Use akeyless from system PATH
            const akeylessPath = 'akeyless';
            
            // Check if akeyless CLI is available
            try {
                await execAsync(`${akeylessPath} --version`);
            } catch (error) {
                throw new Error('Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli');
            }
            
            const dn = escapeShellDoubleQuotedArg(secretName);
            const { stdout } = await execAsync(`${akeylessPath} get-dynamic-secret-value --name "${dn}" --json`);
            const data = JSON.parse(stdout);
            
            logger.info(` Dynamic secret value retrieved successfully`);
            return data;
        } catch (error) {
            logger.error(' Failed to get dynamic secret value from CLI:', error);
            throw new Error(`Failed to get dynamic secret value: ${error}`);
        }
    }

    /**
     * Gets the value of a rotated secret using CLI directly
     */
    async getRotatedSecretValue(secretName: string): Promise<any> {
        try {
            logger.info(` Getting rotated secret value for: ${secretName}`);
            
            // Use akeyless from system PATH
            const akeylessPath = 'akeyless';
            
            // Check if akeyless CLI is available
            try {
                await execAsync(`${akeylessPath} --version`);
            } catch (error) {
                throw new Error('Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli');
            }
            
            const rn = escapeShellDoubleQuotedArg(secretName);
            const { stdout } = await execAsync(`${akeylessPath} get-rotated-secret-value --name "${rn}" --json`);
            const data = JSON.parse(stdout);
            
            logger.info(` Rotated secret value retrieved successfully`);
            return data;
        } catch (error) {
            logger.error(' Failed to get rotated secret value from CLI:', error);
            throw new Error(`Failed to get rotated secret value: ${error}`);
        }
    }

    /**
     * Creates a new static secret in Akeyless
     */
    async createStaticSecret(secretName: string, secretValue: string): Promise<any> {
        try {
            logger.info(` Creating static secret: ${secretName}`);
            
            // Use akeyless from system PATH
            const akeylessPath = 'akeyless';
            
            // Check if akeyless CLI is available
            try {
                await execAsync(`${akeylessPath} --version`);
            } catch (error) {
                throw new Error('Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli');
            }
            
            const { stdout } = await execFirstSuccessful(
                execAsync,
                buildCreateSecretCommands(akeylessPath, secretName, secretValue),
                'create-secret'
            );
            logger.info(` create-static-secret: succeeded with one of the CLI variants`);
            const data = JSON.parse(stdout);
            
            logger.info(` Static secret created successfully: ${secretName}`);
            return data;
        } catch (error) {
            logger.error(' Failed to create static secret:', error);
            throw new Error(`Failed to create static secret: ${error}`);
        }
    }

    /**
     * Updates an existing static secret value using CLI
     */
    async updateStaticSecret(secretName: string, secretValue: string): Promise<any> {
        try {
            logger.info(` Updating static secret: ${secretName}`);

            const akeylessPath = 'akeyless';

            try {
                await execAsync(`${akeylessPath} --version`);
            } catch (error) {
                throw new Error('Akeyless CLI not found. Please install it first: https://docs.akeyless.io/docs/install-akeyless-cli');
            }

            const { stdout } = await execFirstSuccessful(
                execAsync,
                buildUpdateSecretCommands(akeylessPath, secretName, secretValue),
                'update-secret-val'
            );
            logger.info(` update-static-secret: succeeded with one of the CLI variants`);
            const data = JSON.parse(stdout);

            logger.info(` Static secret updated successfully: ${secretName}`);
            return data;
        } catch (error) {
            logger.error(' Failed to update static secret:', error);
            throw new Error(`Failed to update static secret: ${error}`);
        }
    }

} 