import * as vscode from 'vscode';
import { BaseCommand } from './base/BaseCommand';
import { SecretsTreeProvider } from '../../providers/secrets-tree-provider';
import { MESSAGES } from '../../constants';

/**
 * Refresh Command
 * Refreshes the secrets tree
 */
export class RefreshCommand extends BaseCommand {
    constructor(private readonly treeProvider: SecretsTreeProvider) {
        super();
    }

    getId(): string {
        return 'akeyless.refresh';
    }

    getTitle(): string {
        return 'Refresh Secrets';
    }

    async execute(): Promise<void> {
        this.logExecution();
        
        try {
            vscode.window.showInformationMessage(MESSAGES.REFRESHING);
            await this.treeProvider.refresh();
            vscode.window.showInformationMessage(MESSAGES.REFRESH_SUCCESS);
        } catch (error) {
            this.handleError(error, 'refresh operation');
            vscode.window.showErrorMessage(MESSAGES.REFRESH_FAILED);
        }
    }
}

