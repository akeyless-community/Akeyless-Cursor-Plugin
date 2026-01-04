import * as vscode from 'vscode';
import { BaseCommand } from './base/BaseCommand';
import { SecretsTreeProvider } from '../../providers/secrets-tree-provider';
import { MESSAGES } from '../../constants';

/**
 * Search Command
 * Searches for secrets in the tree
 */
export class SearchCommand extends BaseCommand {
    constructor(private readonly treeProvider: SecretsTreeProvider) {
        super();
    }

    getId(): string {
        return 'akeyless.search';
    }

    getTitle(): string {
        return 'Search Secrets';
    }

    async execute(): Promise<void> {
        this.logExecution();
        
        try {
            const searchTerm = await vscode.window.showInputBox({
                prompt: 'Enter search term',
                placeHolder: 'Search for secrets...'
            });

            if (searchTerm !== undefined) {
                this.treeProvider.setSearchTerm(searchTerm);
                if (searchTerm) {
                    vscode.window.showInformationMessage(`${MESSAGES.SEARCHING} ${searchTerm}`);
                } else {
                    vscode.window.showInformationMessage(MESSAGES.SEARCH_CLEARED);
                }
            }
        } catch (error) {
            this.handleError(error, 'search operation');
            vscode.window.showErrorMessage(MESSAGES.SEARCH_FAILED);
        }
    }
}

