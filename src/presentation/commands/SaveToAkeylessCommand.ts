import * as vscode from 'vscode';
import { BaseCommand } from './base/BaseCommand';
import { SaveSecretUseCase } from '../../application/use-cases/SaveSecretUseCase';
import { SecretsTreeProvider } from '../../providers/secrets-tree-provider';
import { ValidationError } from '../../core/errors';

/**
 * Save to Akeyless Command
 * Saves selected text as a secret to Akeyless
 */
export class SaveToAkeylessCommand extends BaseCommand {
    constructor(
        private readonly saveUseCase: SaveSecretUseCase,
        private readonly treeProvider: SecretsTreeProvider
    ) {
        super();
    }

    getId(): string {
        return 'akeyless.saveToAkeyless';
    }

    getTitle(): string {
        return 'Save to Akeyless';
    }

    async execute(): Promise<void> {
        this.logExecution();
        
        try {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showErrorMessage('No active text editor found');
                return;
            }
            
            const selection = editor.selection;
            const selectedText = editor.document.getText(selection);
            
            if (!selectedText || selectedText.trim() === '') {
                vscode.window.showErrorMessage('Please select some text to save to Akeyless');
                return;
            }
            
            // Confirm text
            const confirmText = await vscode.window.showInputBox({
                prompt: 'Confirm the text to save (you can edit if needed)',
                placeHolder: 'Selected text will appear here',
                value: selectedText,
                validateInput: (input) => {
                    if (!input || input.trim() === '') {
                        return 'Text to save cannot be empty.';
                    }
                    return null;
                }
            });
            
            if (!confirmText) {
                return;
            }
            
            // Get secret name
            const secretName = await vscode.window.showInputBox({
                prompt: 'Enter a name for this secret in Akeyless',
                placeHolder: 'e.g., /my-project/api-key',
                value: '',
                validateInput: (input) => {
                    if (!input || input.trim() === '') {
                        return 'Please provide a secret name.';
                    }
                    if (!input.startsWith('/')) {
                        return 'Secret name must start with /';
                    }
                    return null;
                }
            });
            
            if (!secretName) {
                return;
            }
            
            // Save secret
            await this.saveUseCase.execute(secretName, confirmText);
            
            vscode.window.showInformationMessage(`✅ Secret saved to Akeyless: ${secretName}`);
            
            // Refresh tree
            await this.treeProvider.refresh();
        } catch (error) {
            this.handleError(error, 'save operation');
            
            if (error instanceof ValidationError) {
                vscode.window.showErrorMessage(`Validation error: ${error.message}`);
            } else {
                vscode.window.showErrorMessage(`Failed to save to Akeyless: ${error instanceof Error ? error.message : String(error)}`);
            }
        }
    }
}

