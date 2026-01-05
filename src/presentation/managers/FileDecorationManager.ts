import * as vscode from 'vscode';
import { HardcodedSecret } from '../../domain/entities/HardcodedSecret';
import { logger } from '../../utils/logger';

// Import the old type for compatibility
import { HardcodedSecret as OldHardcodedSecret } from '../../infrastructure/scanners/secret-scanner/types';

type SecretType = HardcodedSecret | OldHardcodedSecret;

/**
 * File Decoration Manager
 * Adds visual indicators (badges/icons) to files in the explorer that contain hardcoded secrets
 */
export class FileDecorationManager {
    private fileDecorationProvider: vscode.FileDecorationProvider;
    private filesWithSecrets: Map<string, number> = new Map(); // fileName -> secret count
    private disposable: vscode.Disposable | undefined;
    private onDidChangeFileDecorationsEmitter: vscode.EventEmitter<vscode.Uri | vscode.Uri[] | undefined>;
    public readonly onDidChangeFileDecorations: vscode.Event<vscode.Uri | vscode.Uri[] | undefined>;

    constructor() {
        // Create event emitter for decoration changes
        this.onDidChangeFileDecorationsEmitter = new vscode.EventEmitter<vscode.Uri | vscode.Uri[] | undefined>();
        this.onDidChangeFileDecorations = this.onDidChangeFileDecorationsEmitter.event;

        // Create file decoration provider
        this.fileDecorationProvider = {
            onDidChangeFileDecorations: this.onDidChangeFileDecorations,
            provideFileDecoration: (uri: vscode.Uri, _token: vscode.CancellationToken) => {
                const fileName = uri.fsPath;
                const secretCount = this.filesWithSecrets.get(fileName);

                if (secretCount && secretCount > 0) {
                    return new vscode.FileDecoration(
                        `🔒 ${secretCount}`,
                        `${secretCount} hardcoded secret${secretCount > 1 ? 's' : ''} detected`,
                        new vscode.ThemeColor('notificationsWarningIcon.foreground')
                    );
                }

                return undefined;
            }
        };
    }

    /**
     * Registers the file decoration provider
     */
    register(context: vscode.ExtensionContext): void {
        logger.info(' Registering file decoration provider for secret indicators');
        
        this.disposable = vscode.window.registerFileDecorationProvider(this.fileDecorationProvider);
        context.subscriptions.push(this.disposable);
        
        logger.info(' File decoration provider registered');
    }

    /**
     * Updates file decorations based on detected secrets
     */
    updateDecorations(secrets: SecretType[]): void {
        logger.info(` Updating file decorations for ${secrets.length} secrets`);
        
        // Get list of files that had secrets before (to clear their decorations)
        const previousFiles = Array.from(this.filesWithSecrets.keys()).map(f => vscode.Uri.file(f));
        
        // Clear existing decorations
        this.filesWithSecrets.clear();

        // Group secrets by file and count them
        const updatedFiles: vscode.Uri[] = [];
        for (const secret of secrets) {
            const fileName = secret.fileName;
            const currentCount = this.filesWithSecrets.get(fileName) || 0;
            this.filesWithSecrets.set(fileName, currentCount + 1);
            
            // Track files that need decoration updates
            const uri = vscode.Uri.file(fileName);
            if (!updatedFiles.find(u => u.fsPath === uri.fsPath)) {
                updatedFiles.push(uri);
            }
        }

        logger.info(` File decorations updated for ${this.filesWithSecrets.size} files`);
        
        // Trigger decoration refresh for all affected files
        const allAffectedFiles = [...previousFiles, ...updatedFiles];
        if (allAffectedFiles.length > 0) {
            this.onDidChangeFileDecorationsEmitter.fire(allAffectedFiles);
        }
    }

    /**
     * Clears all file decorations
     */
    clear(): void {
        logger.info(' Clearing file decorations');
        
        // Get list of files that had secrets (to clear their decorations)
        const filesToClear = Array.from(this.filesWithSecrets.keys()).map(f => vscode.Uri.file(f));
        this.filesWithSecrets.clear();
        
        // Trigger decoration refresh for all affected files
        if (filesToClear.length > 0) {
            this.onDidChangeFileDecorationsEmitter.fire(filesToClear);
        }
    }

    /**
     * Gets the count of secrets for a specific file
     */
    getSecretCount(fileName: string): number {
        return this.filesWithSecrets.get(fileName) || 0;
    }

    /**
     * Checks if a file has secrets
     */
    hasSecrets(fileName: string): boolean {
        return this.filesWithSecrets.has(fileName) && (this.filesWithSecrets.get(fileName) || 0) > 0;
    }

    /**
     * Disposes of resources
     */
    dispose(): void {
        this.clear();
        if (this.disposable) {
            this.disposable.dispose();
        }
        this.onDidChangeFileDecorationsEmitter.dispose();
    }
}

