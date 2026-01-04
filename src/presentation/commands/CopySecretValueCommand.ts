import * as vscode from 'vscode';
import { BaseCommand } from './base/BaseCommand';
import { IAkeylessRepository } from '../../core/interfaces/IAkeylessRepository';
import { AkeylessItem } from '../../types';
import { logger } from '../../utils/logger';

/**
 * Copy Secret Value Command
 * Copies a secret value to clipboard
 * Handles different secret types (static, dynamic, rotated)
 */
export class CopySecretValueCommand extends BaseCommand {
    constructor(private readonly repository: IAkeylessRepository) {
        super();
    }

    getId(): string {
        return 'akeyless.copySecretValue';
    }

    getTitle(): string {
        return 'Copy Secret Value';
    }

    async execute(...args: any[]): Promise<void> {
        this.logExecution();
        
        try {
            // Get the selected item from command arguments
            const selectedItem = args[0];
            if (!selectedItem || !selectedItem.item) {
                vscode.window.showErrorMessage('No item selected');
                return;
            }

            const item = selectedItem.item as AkeylessItem;
            const secretName = item.item_name;
            const itemType = item.item_type;

            logger.info(`🔐 Getting secret value for: ${secretName} (type: ${itemType})`);
            vscode.window.showInformationMessage('Getting secret value...');
            
            let secretValue: string;
            
            // Use appropriate method based on secret type
            if (itemType === 'DYNAMIC_SECRET') {
                // Use adapter's method if available
                const adapter = this.repository as any;
                if (adapter.getDynamicSecretValue) {
                    const response = await adapter.getDynamicSecretValue(secretName);
                    // Handle response - could be object or string
                    if (typeof response === 'string') {
                        secretValue = response;
                    } else if (response && typeof response === 'object') {
                        // Extract value from object if it exists, otherwise stringify
                        secretValue = response.value !== undefined 
                            ? (typeof response.value === 'string' ? response.value : JSON.stringify(response.value, null, 2))
                            : JSON.stringify(response, null, 2);
                    } else {
                        // Handle other types - if it's an object, stringify it; otherwise convert to string
                        if (response && typeof response === 'object') {
                            secretValue = JSON.stringify(response, null, 2);
                        } else {
                            secretValue = String(response || '');
                        }
                    }
                } else {
                    secretValue = await this.repository.getSecretValue(secretName);
                }
            } else if (itemType === 'ROTATED_SECRET') {
                const adapter = this.repository as any;
                if (adapter.getRotatedSecretValue) {
                    const response = await adapter.getRotatedSecretValue(secretName);
                    // Handle response - could be object or string
                    if (typeof response === 'string') {
                        secretValue = response;
                    } else if (response && typeof response === 'object') {
                        // Extract value from object if it exists, otherwise stringify
                        secretValue = response.value !== undefined 
                            ? (typeof response.value === 'string' ? response.value : JSON.stringify(response.value, null, 2))
                            : JSON.stringify(response, null, 2);
                    } else {
                        // Handle other types - if it's an object, stringify it; otherwise convert to string
                        if (response && typeof response === 'object') {
                            secretValue = JSON.stringify(response, null, 2);
                        } else {
                            secretValue = String(response || '');
                        }
                    }
                } else {
                    secretValue = await this.repository.getSecretValue(secretName);
                }
            } else {
                // For static secrets, getSecretValue already returns a string
                secretValue = await this.repository.getSecretValue(secretName);
            }
            
            if (!secretValue) {
                throw new Error(`Secret value is undefined or empty for: ${secretName}`);
            }
            
            await vscode.env.clipboard.writeText(secretValue);
            
            // Show simple notification - no "View Full Content" option
            vscode.window.showInformationMessage(`✅ Secret value copied to clipboard!`);
        } catch (error) {
            this.handleError(error, 'copy operation');
            const errorMessage = error instanceof Error ? error.message : String(error);
            vscode.window.showErrorMessage(`Failed to copy secret value: ${errorMessage}`);
        }
    }
}

