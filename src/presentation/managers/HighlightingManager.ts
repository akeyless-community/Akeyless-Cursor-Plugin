import * as vscode from 'vscode';
import { HardcodedSecret } from '../../domain/entities/HardcodedSecret';
import { logger } from '../../utils/logger';

// Import the old type for compatibility
import { HardcodedSecret as OldHardcodedSecret } from '../../utils/secret-scanner/types';

type SecretType = HardcodedSecret | OldHardcodedSecret;

/**
 * Highlighting Manager
 * Manages text editor decorations for secret highlighting
 * Extracted from CommandManager to follow Single Responsibility Principle
 */
export class HighlightingManager {
    private decorations: Map<string, vscode.TextEditorDecorationType> = new Map();
    private readonly decorationType = vscode.window.createTextEditorDecorationType({
        backgroundColor: new vscode.ThemeColor('editorWarning.background'),
        borderColor: new vscode.ThemeColor('editorWarning.border'),
        borderWidth: '1px',
        borderStyle: 'solid',
        overviewRulerColor: new vscode.ThemeColor('editorWarning.foreground'),
        overviewRulerLane: vscode.OverviewRulerLane.Right
    });

    /**
     * Highlights secrets in all open editors
     */
    async highlightSecrets(secrets: SecretType[]): Promise<void> {
        logger.info(`🎨 Highlighting ${secrets.length} secrets with decorations`);
        
        // Group secrets by file
        const secretsByFile = new Map<string, SecretType[]>();
        for (const secret of secrets) {
            const fileName = secret.fileName;
            const fileSecrets = secretsByFile.get(fileName) || [];
            fileSecrets.push(secret);
            secretsByFile.set(fileName, fileSecrets);
        }

        // Highlight in all open editors
        for (const editor of vscode.window.visibleTextEditors) {
            const fileName = editor.document.fileName;
            const fileSecrets = secretsByFile.get(fileName);
            
            if (fileSecrets && fileSecrets.length > 0) {
                const ranges = fileSecrets.map(secret => {
                    return new vscode.Range(
                        secret.lineNumber - 1,
                        secret.column - 1,
                        secret.lineNumber - 1,
                        secret.column - 1 + secret.value.length
                    );
                });

                editor.setDecorations(this.decorationType, ranges);
                logger.debug(` Highlighted ${ranges.length} secrets in ${fileName}`);
            } else {
                editor.setDecorations(this.decorationType, []);
            }
        }
    }

    /**
     * Clears all highlighting
     */
    clear(): void {
        for (const editor of vscode.window.visibleTextEditors) {
            editor.setDecorations(this.decorationType, []);
        }
        this.decorations.clear();
        logger.debug(' Highlighting cleared');
    }

    /**
     * Disposes of resources
     */
    dispose(): void {
        this.clear();
        this.decorationType.dispose();
    }
}

