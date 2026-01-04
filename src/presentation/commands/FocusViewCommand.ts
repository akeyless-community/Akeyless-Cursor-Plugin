import * as vscode from 'vscode';
import { BaseCommand } from './base/BaseCommand';
import { VIEWS } from '../../constants';

/**
 * Focus View Command
 * Focuses the Akeyless Security view
 */
export class FocusViewCommand extends BaseCommand {
    getId(): string {
        return 'akeyless.focusView';
    }

    getTitle(): string {
        return 'Focus on Akeyless Security View';
    }

    async execute(): Promise<void> {
        this.logExecution();
        
        try {
            // Focus the view using VS Code's built-in command
            // The command format is: workbench.view.extension.<viewContainerId>
            await vscode.commands.executeCommand('workbench.view.extension.akeyless-secrets');
        } catch (error) {
            this.handleError(error, 'focus view operation');
            // The view might already be focused or the command might not be available
            // This is not a critical error, so we don't show an error message
        }
    }
}

