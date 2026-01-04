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
            
            let response: any;
            
            // Use appropriate method based on secret type
            if (itemType === 'DYNAMIC_SECRET') {
                // Use adapter's method if available
                const adapter = this.repository as any;
                if (adapter.getDynamicSecretValue) {
                    response = await adapter.getDynamicSecretValue(secretName);
                } else {
                    response = await this.repository.getSecretValue(secretName);
                }
            } else if (itemType === 'ROTATED_SECRET') {
                const adapter = this.repository as any;
                if (adapter.getRotatedSecretValue) {
                    response = await adapter.getRotatedSecretValue(secretName);
                } else {
                    response = await this.repository.getSecretValue(secretName);
                }
            } else {
                const value = await this.repository.getSecretValue(secretName);
                response = { value };
            }
            
            // Convert response to string
            const secretValue = typeof response === 'string' 
                ? response 
                : JSON.stringify(response, null, 2);
            
            if (!secretValue) {
                throw new Error(`Secret value is undefined or empty for: ${secretName}`);
            }
            
            await vscode.env.clipboard.writeText(secretValue);
            
            const preview = secretValue.length > 200 
                ? secretValue.substring(0, 200) + '...' 
                : secretValue;
            
            if (secretValue.length > 200) {
                const action = await vscode.window.showInformationMessage(
                    `✅ Secret value copied to clipboard!\n\nPreview:\n${preview}`,
                    'View Full Content'
                );
                
                if (action === 'View Full Content') {
                    const document = await vscode.workspace.openTextDocument({
                        content: secretValue,
                        language: 'json'
                    });
                    await vscode.window.showTextDocument(document);
                }
            } else {
                vscode.window.showInformationMessage(`✅ Secret value copied to clipboard!`);
            }
        } catch (error) {
            this.handleError(error, 'copy operation');
            const errorMessage = error instanceof Error ? error.message : String(error);
            vscode.window.showErrorMessage(`Failed to copy secret value: ${errorMessage}`);
        }
    }
}

