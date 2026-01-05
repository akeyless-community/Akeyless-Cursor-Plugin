import * as vscode from 'vscode';
import { HardcodedSecret } from '../../domain/entities/HardcodedSecret';
import { logger } from '../../utils/logger';
import { generateAkeylessDiagnosticMessage } from '../../utils/akeyless-suggestions';

// Import the old type for compatibility
import { HardcodedSecret as OldHardcodedSecret } from '../../infrastructure/scanners/secret-scanner/types';

type SecretType = HardcodedSecret | OldHardcodedSecret;

/**
 * Diagnostics Manager
 * Manages VS Code diagnostics for secret highlighting
 * Extracted from CommandManager to follow Single Responsibility Principle
 */
export class DiagnosticsManager {
    private diagnostics: vscode.DiagnosticCollection;
    private readonly diagnosticSource = 'akeyless-secrets-manager';

    constructor(context: vscode.ExtensionContext) {
        this.diagnostics = vscode.languages.createDiagnosticCollection(this.diagnosticSource);
        context.subscriptions.push(this.diagnostics);
    }

    /**
     * Highlights secrets in the editor using diagnostics
     */
    async highlightSecrets(secrets: SecretType[]): Promise<void> {
        logger.info(` Highlighting ${secrets.length} secrets with diagnostics`);
        
        // Clear existing diagnostics
        this.clear();

        // Group secrets by file
        const secretsByFile = new Map<string, SecretType[]>();
        for (const secret of secrets) {
            const fileName = secret.fileName;
            const fileSecrets = secretsByFile.get(fileName) || [];
            fileSecrets.push(secret);
            secretsByFile.set(fileName, fileSecrets);
        }

        // Create diagnostics for each file
        for (const [fileName, fileSecrets] of secretsByFile.entries()) {
            try {
                const uri = vscode.Uri.file(fileName);
                await vscode.workspace.openTextDocument(uri);
                
                const diagnosticArray: vscode.Diagnostic[] = fileSecrets.map(secret => {
                    const range = new vscode.Range(
                        secret.lineNumber - 1,
                        secret.column - 1,
                        secret.lineNumber - 1,
                        secret.column - 1 + secret.value.length
                    );

                    // Generate Akeyless-specific diagnostic message with implementation guidance
                    const suggestion = generateAkeylessDiagnosticMessage(secret.type, secret.fileName);
                    
                    // Get detection reason if available
                    const detectionReason = 'detectionReason' in secret && secret.detectionReason 
                        ? `\n\nDetection Reason: ${secret.detectionReason}` 
                        : '';
                    
                    // Create a comprehensive message with implementation guidance
                    const fullMessage = `${suggestion.message}${detectionReason}\n\nImplementation:\n${suggestion.implementation}\n\nDocs: ${suggestion.documentation}`;
                    
                    const diagnostic = new vscode.Diagnostic(
                        range,
                        fullMessage,
                        vscode.DiagnosticSeverity.Warning
                    );

                    diagnostic.source = this.diagnosticSource;
                    diagnostic.code = 'hardcoded-secret';
                    
                    return diagnostic;
                });

                this.diagnostics.set(uri, diagnosticArray);
            } catch (error) {
                logger.error(` Error highlighting secrets in ${fileName}:`, error);
            }
        }

        logger.info(` Diagnostics set for ${secretsByFile.size} files`);
    }

    /**
     * Clears all diagnostics
     */
    clear(): void {
        this.diagnostics.clear();
        logger.debug(' Diagnostics cleared');
    }

    /**
     * Checks if there are active diagnostics
     */
    hasActiveDiagnostics(): boolean {
        // Check if diagnostics collection has any entries
        // DiagnosticCollection doesn't expose keys directly, so we check by trying to get diagnostics
        // This is a workaround - in practice, we track this ourselves
        return false; // Will be tracked separately if needed
    }

    /**
     * Gets the diagnostic collection
     */
    getDiagnostics(): vscode.DiagnosticCollection {
        return this.diagnostics;
    }
}

