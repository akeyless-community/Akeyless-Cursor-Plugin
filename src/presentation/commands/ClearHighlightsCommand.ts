import { BaseCommand } from './base/BaseCommand';
import { DiagnosticsManager } from '../managers/DiagnosticsManager';
import { HighlightingManager } from '../managers/HighlightingManager';
import * as vscode from 'vscode';

/**
 * Clear Highlights Command
 * Clears all secret highlights
 */
export class ClearHighlightsCommand extends BaseCommand {
    constructor(
        private readonly diagnosticsManager: DiagnosticsManager,
        private readonly highlightingManager: HighlightingManager
    ) {
        super();
    }

    getId(): string {
        return 'akeyless.clearSecretHighlights';
    }

    getTitle(): string {
        return 'Clear Secret Highlights';
    }

    async execute(): Promise<void> {
        this.logExecution();
        
        this.diagnosticsManager.clear();
        this.highlightingManager.clear();
        
        vscode.window.showInformationMessage('Secret highlights cleared');
    }
}

