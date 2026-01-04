import * as vscode from 'vscode';
import { IConfigurationService } from '../../core/interfaces/IConfigurationService';
import { ScanForSecretsUseCase } from '../../application/use-cases/ScanForSecretsUseCase';
import { DiagnosticsManager } from '../managers/DiagnosticsManager';
import { HighlightingManager } from '../managers/HighlightingManager';
import { logger } from '../../utils/logger';

/**
 * Auto Scan Handler
 * Handles automatic scanning on file save
 * Extracted from CommandManager to follow Single Responsibility Principle
 */
export class AutoScanHandler {
    constructor(
        private readonly configService: IConfigurationService,
        private readonly scanUseCase: ScanForSecretsUseCase,
        private readonly diagnosticsManager: DiagnosticsManager,
        private readonly highlightingManager: HighlightingManager
    ) {}

    /**
     * Registers auto-scan on save functionality
     */
    register(context: vscode.ExtensionContext): void {
        logger.info('🔧 Registering auto-scan on save functionality...');

        const onDidSaveDocument = vscode.workspace.onDidSaveTextDocument(async (document: vscode.TextDocument) => {
            // Check if auto-scan is enabled
            if (!this.configService.isAutoScanOnSaveEnabled()) {
                return;
            }

            // Only scan certain file types
            const fileExtensions = ['.js', '.jsx', '.ts', '.tsx', '.json', '.env', '.yml', '.yaml', '.py', '.go', '.java'];
            const shouldScan = fileExtensions.some(ext => document.fileName.endsWith(ext));

            if (!shouldScan) {
                return;
            }

            try {
                logger.debug(`🔍 Auto-scanning file: ${document.fileName}`);
                
                const scanResult = await this.scanUseCase.scanFile();

                if (scanResult.hasSecrets()) {
                    logger.info(`🚨 Found ${scanResult.getTotalSecrets()} secrets in ${document.fileName}`);
                    
                    await this.diagnosticsManager.highlightSecrets(scanResult.secrets);
                    await this.highlightingManager.highlightSecrets(scanResult.secrets);
                    
                    vscode.window.showWarningMessage(
                        `Found ${scanResult.getTotalSecrets()} potential secret${scanResult.getTotalSecrets() > 1 ? 's' : ''} in ${document.fileName}`,
                        'View Details'
                    );
                } else {
                    logger.debug(`✅ No secrets found in ${document.fileName}`);
                }
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                if (errorMessage.includes('Invalid string length')) {
                    logger.warn(`⚠️ Skipping file ${document.fileName} - file too large to scan`);
                } else {
                    logger.error(`❌ Error auto-scanning ${document.fileName}:`, error);
                }
            }
        });

        context.subscriptions.push(onDidSaveDocument);
        logger.info('✅ Auto-scan on save functionality registered');
    }
}

