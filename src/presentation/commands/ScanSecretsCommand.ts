import * as vscode from 'vscode';
import { BaseCommand } from './base/BaseCommand';
import { ScanForSecretsUseCase } from '../../application/use-cases/ScanForSecretsUseCase';
import { DiagnosticsManager } from '../managers/DiagnosticsManager';
import { HighlightingManager } from '../managers/HighlightingManager';
import { ScanResult } from '../../domain/entities/ScanResult';
import { logger } from '../../utils/logger';

/**
 * Scan Secrets Command
 * Scans for hardcoded secrets in the project
 */
export class ScanSecretsCommand extends BaseCommand {
    constructor(
        private readonly scanUseCase: ScanForSecretsUseCase,
        private readonly diagnosticsManager: DiagnosticsManager,
        private readonly highlightingManager: HighlightingManager
    ) {
        super();
    }

    getId(): string {
        return 'akeyless.scanHardcodedSecrets';
    }

    getTitle(): string {
        return 'Scan for Hardcoded Secrets';
    }

    async execute(): Promise<void> {
        this.logExecution();
        
        try {
            vscode.window.showInformationMessage('Scanning current project for hardcoded secrets...');
            
            const scanResult = await this.scanUseCase.execute();
            
            if (!scanResult.hasSecrets()) {
                this.diagnosticsManager.clear();
                this.highlightingManager.clear();
                vscode.window.showInformationMessage('No hardcoded secrets found! Previous scan results cleared.');
                return;
            }
            
            // Highlight secrets
            await this.diagnosticsManager.highlightSecrets(scanResult.secrets);
            await this.highlightingManager.highlightSecrets(scanResult.secrets);
            
            // Show results
            this.showResults(scanResult);
            
            vscode.window.showInformationMessage(
                `Found ${scanResult.getTotalSecrets()} secrets. Previous scan results have been cleared.`
            );
        } catch (error) {
            this.handleError(error, 'scan operation');
            
            const errorMessage = error instanceof Error ? error.message : String(error);
            if (errorMessage.includes('Invalid string length')) {
                vscode.window.showErrorMessage(
                    'Scan failed: One or more files are too large to process. Large files (>50MB) are automatically skipped.',
                    'View Log'
                ).then(selection => {
                    if (selection === 'View Log') {
                        logger.showOutput();
                    }
                });
            } else {
                vscode.window.showErrorMessage(`Failed to scan for hardcoded secrets: ${errorMessage}`);
            }
        }
    }

    private showResults(scanResult: ScanResult): void {
        // Implementation for showing results in output
        const secretsByFile = scanResult.getSecretsByFile();
        let output = `\n=== Secret Scan Results ===\n`;
        output += `Total files scanned: ${scanResult.totalFilesScanned}\n`;
        output += `Total secrets found: ${scanResult.getTotalSecrets()}\n\n`;
        
        for (const [fileName, secrets] of secretsByFile.entries()) {
            output += `File: ${fileName}\n`;
            for (const secret of secrets) {
                output += `  Line ${secret.lineNumber}, Column ${secret.column}: ${secret.type}\n`;
                output += `  Value: ${secret.value.substring(0, 50)}${secret.value.length > 50 ? '...' : ''}\n`;
            }
            output += '\n';
        }
        
        logger.info(output);
    }
}

