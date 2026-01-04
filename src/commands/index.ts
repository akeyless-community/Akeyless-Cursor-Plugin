import * as vscode from 'vscode';
import { AkeylessCLI } from '../services/akeyless-cli';
import { SecretsTreeProvider } from '../providers/secrets-tree-provider';
import { COMMANDS, MESSAGES } from '../constants';
import { logger } from '../utils/logger';
import { STATUS_TYPES } from '../constants';
import { SecretScanner, HardcodedSecret } from '../utils/secret-scanner';

export class CommandManager {
    // Static properties for managing secret highlighting
    private static secretDiagnostics?: vscode.DiagnosticCollection;
    private static secretDecorations?: Map<string, vscode.TextEditorDecorationType>;
    private static statusBarItem?: vscode.StatusBarItem;
    
    private akeylessCLI: AkeylessCLI;
    private secretsTreeProvider: SecretsTreeProvider;
    
    constructor(
        akeylessCLI: AkeylessCLI,
        secretsTreeProvider: SecretsTreeProvider
    ) {
        this.akeylessCLI = akeylessCLI;
        this.secretsTreeProvider = secretsTreeProvider;
    }

    /**
     * Registers all commands for the extension
     */
    registerCommands(context: vscode.ExtensionContext): void {
        logger.info('🔧 Registering extension commands...');

        context.subscriptions.push(
            vscode.commands.registerCommand(COMMANDS.REFRESH, this.handleRefreshCommand.bind(this)),
            vscode.commands.registerCommand(COMMANDS.SEARCH, this.handleSearchCommand.bind(this)),
            vscode.commands.registerCommand(COMMANDS.LOAD_MORE, this.handleLoadMoreCommand.bind(this)),
            vscode.commands.registerCommand(COMMANDS.COPY_SECRET_VALUE, this.handleCopySecretValueCommand.bind(this)),
            vscode.commands.registerCommand(COMMANDS.SAVE_TO_AKEYLESS, this.handleSaveToAkeylessCommand.bind(this)),
            vscode.commands.registerCommand(COMMANDS.SCAN_HARDCODED_SECRETS, this.handleScanHardcodedSecretsCommand.bind(this)),
            vscode.commands.registerCommand(COMMANDS.CLEAR_SECRET_HIGHLIGHTS, this.handleClearSecretHighlightsCommand.bind(this)),
            vscode.commands.registerCommand('akeyless.checkDiagnosticsStatus', this.handleCheckDiagnosticsStatusCommand.bind(this)),
            vscode.commands.registerCommand('akeyless.forceClearAllDiagnostics', this.handleForceClearAllDiagnosticsCommand.bind(this)),
            vscode.commands.registerCommand('akeyless.generateSecretName', this.handleGenerateSecretNameCommand.bind(this))
        );

        // Register auto-scan on save functionality
        this.registerAutoScanOnSave(context);

        logger.info('✅ All commands registered successfully');
    }



    /**
     * Handles the refresh command
     */
    private async handleRefreshCommand(): Promise<void> {
        logger.info('🔄 Manual refresh initiated');
        try {
            vscode.window.showInformationMessage(MESSAGES.REFRESHING);
            await this.secretsTreeProvider.refresh();
            vscode.window.showInformationMessage(MESSAGES.REFRESH_SUCCESS);
        } catch (error) {
            logger.error('❌ Refresh error:', error);
            vscode.window.showErrorMessage(MESSAGES.REFRESH_FAILED);
        }
    }

    /**
     * Handles the save to Akeyless command for creating secrets
     */
    private async handleSaveToAkeylessCommand(): Promise<void> {
        try {
            logger.info('💾 Save to Akeyless command triggered');
            
            // Get the active text editor
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showErrorMessage('No active text editor found');
                return;
            }
            
            // Get the selected text
            const selection = editor.selection;
            const selectedText = editor.document.getText(selection);
            
            if (!selectedText || selectedText.trim() === '') {
                vscode.window.showErrorMessage('Please select some text to save to Akeyless');
                return;
            }
            
            logger.info(`📝 Selected text length: ${selectedText.length} characters`);
            logger.info(`📝 Selected text preview: ${selectedText.substring(0, 100)}${selectedText.length > 100 ? '...' : ''}`);
            
            // Show the selected text to the user for confirmation
            const confirmText = await vscode.window.showInputBox({
                prompt: 'Confirm the text to save (you can edit if needed)',
                placeHolder: 'Selected text will appear here',
                value: selectedText,
                validateInput: (input) => {
                    if (!input || input.trim() === '') {
                        return 'Text to save cannot be empty.';
                    }
                    if (input.trim().length < 1) {
                        return 'Text to save must contain at least 1 character.';
                    }
                    return null; // Valid input
                }
            });
            
            if (!confirmText) {
                logger.info('User cancelled text confirmation');
                return;
            }
            
            // Additional validation after input
            if (!confirmText.trim()) {
                vscode.window.showErrorMessage('Text to save cannot be empty. Please provide valid content.');
                return;
            }
            
            // Prompt for secret name (empty by default)
            const secretName = await vscode.window.showInputBox({
                prompt: `Enter a name for this secret in Akeyless`,
                placeHolder: 'e.g., /my-project/api-key',
                value: '', // Empty by default - no auto-generated name
                validateInput: (input) => {
                    if (!input || input.trim() === '') {
                        return 'Please provide a secret name.';
                    }
                    return null; // Valid input - any non-empty name is accepted
                }
            });
            
            if (!secretName) {
                logger.info('User cancelled secret name input');
                return;
            }
            
            // Additional validation after input
            if (!secretName.trim()) {
                vscode.window.showErrorMessage('Secret name cannot be empty. Please provide a valid name.');
                return;
            }
            
            logger.info(`💾 Creating secret: ${secretName}`);
            
            // Create the secret in Akeyless using create-secret
            await this.akeylessCLI.createStaticSecret(secretName, confirmText);
            
            logger.info(`✅ Secret created successfully: ${secretName}`);
            
            // Show success message
            vscode.window.showInformationMessage(`✅ Secret saved to Akeyless: ${secretName}`);
            
            // Refresh the secrets tree to show the new secret
            this.secretsTreeProvider.refresh();
            
        } catch (error) {
            logger.error('❌ Failed to save to Akeyless:', error);
            vscode.window.showErrorMessage(`Failed to save to Akeyless: ${error}`);
        }
    }

    /**
     * Handles the scan hardcoded secrets command
     */
    private async handleScanHardcodedSecretsCommand(): Promise<void> {
        try {
            logger.info('Scan hardcoded secrets command triggered');
            
            // Show progress notification
            vscode.window.showInformationMessage('Scanning current project for hardcoded secrets...');
            
            // Configure scanner for development environment
            SecretScanner.configure({
                developmentMode: true,
                skipDevelopmentValues: true,
                minEntropy: 3.0
            });
            
            // Scan only the current project (excludes libraries)
            const scanResult = await SecretScanner.scanCurrentProject();
            const workspaceResults = scanResult.results;
            const totalFilesScanned = scanResult.totalFilesScanned;
            
            // Safely flatten results - this can fail with very large arrays
            let secrets: HardcodedSecret[];
            try {
                secrets = Array.from(workspaceResults.values()).flat();
            } catch (error) {
                if (error instanceof RangeError && error.message.includes('Invalid string length')) {
                    logger.warn('Too many secrets found - flattening results in chunks');
                    // Flatten in chunks to avoid memory issues
                    secrets = [];
                    for (const fileSecrets of workspaceResults.values()) {
                        secrets.push(...fileSecrets);
                    }
                } else {
                    throw error;
                }
            }
            
            if (secrets.length === 0) {
                // Clear any existing diagnostics if no secrets found
                if (CommandManager.secretDiagnostics) {
                    CommandManager.clearSecretHighlights();
                    vscode.window.showInformationMessage('No hardcoded secrets found! Previous scan results cleared.');
                } else {
                    vscode.window.showInformationMessage('No hardcoded secrets found!');
                }
                return;
            }
            
            // Add visual highlighting and diagnostic markers
            await CommandManager.highlightSecretsInEditor(secrets);
            
            // Show results in a popup
            CommandManager.showScanResults(secrets, totalFilesScanned);
            
            // Show notification about clearing previous results
            vscode.window.showInformationMessage(`Found ${secrets.length} secrets. Previous scan results have been cleared.`);
            
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            logger.error('Failed to scan for hardcoded secrets:', error);
            
            // Provide more helpful error message
            if (error instanceof RangeError && errorMessage.includes('Invalid string length')) {
                vscode.window.showErrorMessage(
                    'Scan failed: One or more files are too large to process. Large files (>50MB) are automatically skipped. Check the output log for details.',
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

    /**
     * Registers auto-scan on save functionality
     */
    registerAutoScanOnSave(context: vscode.ExtensionContext): void {
        logger.info('🔧 Registering auto-scan on save functionality...');

        // Listen for document save events
        const onDidSaveDocument = vscode.workspace.onDidSaveTextDocument(async (document: vscode.TextDocument) => {
            // Scan JavaScript/TypeScript and JSON files
            if (document.fileName.endsWith('.js') || document.fileName.endsWith('.ts') || 
                document.fileName.endsWith('.jsx') || document.fileName.endsWith('.tsx') ||
                document.fileName.endsWith('.json')) {
                
                logger.info(`🔍 Auto-scanning saved file: ${document.fileName}`);
                
                try {
                    // Import SecretScanner dynamically to avoid circular imports
                    const { SecretScanner } = await import('../utils/secret-scanner');
                    
                    // Configure scanner for auto-scan (same as full scanner)
                    SecretScanner.configure({
                        developmentMode: true,
                        skipDevelopmentValues: true,
                        minEntropy: 3.0
                    });
                    
                    // Scan the document
                    const secrets = await SecretScanner.scanDocument(document);
                    
                    if (secrets.length > 0) {
                        logger.info(`🚨 Found ${secrets.length} secrets in ${document.fileName}`);
                        
                        // Use the same highlighting system as full scanner
                        await CommandManager.highlightSecretsInEditor(secrets);
                        
                        // Use the same results display as full scanner
                        CommandManager.showScanResults(secrets, 1);
                        
                        // Show notification
                        vscode.window.showWarningMessage(
                            `Found ${secrets.length} potential secret${secrets.length > 1 ? 's' : ''} in ${document.fileName}`,
                            'View Details'
                        );
                        
                    } else {
                        logger.debug(`✅ No secrets found in ${document.fileName}`);
                    }
                    
                } catch (error) {
                    if (error instanceof RangeError && error.message.includes('Invalid string length')) {
                        logger.warn(`⚠️ Skipping file ${document.fileName} - file too large to scan`);
                    } else {
                        logger.error(`❌ Error scanning ${document.fileName}:`, error);
                    }
                }
            }
        });
        
        context.subscriptions.push(onDidSaveDocument);
        logger.info('✅ Auto-scan on save functionality registered');
    }

    /**
     * Shows scan results in the output channel
     */
    private static showScanResults(secrets: HardcodedSecret[], totalFilesScanned: number): void {
        const outputChannel = vscode.window.createOutputChannel('Akeyless Scanner');
        
        // Group secrets by file
        const secretsByFile = new Map<string, HardcodedSecret[]>();
        for (const secret of secrets) {
            if (!secretsByFile.has(secret.fileName)) {
                secretsByFile.set(secret.fileName, []);
            }
            secretsByFile.get(secret.fileName)!.push(secret);
        }

        // Build output content
        let output = 'HARDCODED SECRETS SCAN RESULTS\n';
        output += '=====================================\n';
        output += `Found ${secrets.length} potential secrets in ${secretsByFile.size} files\n`;
        output += `Scan completed at ${new Date().toLocaleString()}\n`;
        output += `Scanner configured for development environment (filtering common dev values)\n\n`;

        // Display results grouped by file
        for (const [fileName, fileSecrets] of secretsByFile) {
            const relativePath = vscode.workspace.asRelativePath(fileName);
            output += `FILE: ${relativePath}\n`;
            output += `   Path: ${fileName}\n`;
            output += `   ${fileSecrets.length} secrets found\n\n`;

            for (const secret of fileSecrets) {
                output += `   ${secret.type}\n`;
                output += `      Location: Line ${secret.lineNumber}:${secret.column}\n`;
                output += `      Value: "${secret.value}"\n`;
                output += `      Context: ${secret.context}\n\n`;
            }
        }

        output += `\nSUMMARY\n`;
        output += `=======\n`;
        output += `Total files scanned: ${totalFilesScanned}\n`;
        output += `Files with secrets: ${secretsByFile.size}\n`;
        output += `Total secrets found: ${secrets.length}\n`;

        // Show in output channel
        outputChannel.append(output);
        outputChannel.show();

        // Show notification with actions
        vscode.window.showInformationMessage(
            `Found ${secrets.length} potential secrets in ${secretsByFile.size} files (previous results cleared)`,
            'Copy Results',
            'Open First File',
            'View Details',
            'Clear Diagnostics'
        ).then(selection => {
            if (selection === 'Copy Results') {
                vscode.env.clipboard.writeText(output);
                vscode.window.showInformationMessage('Scan results copied to clipboard');
            } else if (selection === 'Open First File' && secrets.length > 0) {
                const firstSecret = secrets[0];
                vscode.workspace.openTextDocument(firstSecret.fileName).then(doc => {
                    vscode.window.showTextDocument(doc).then(editor => {
                        const position = new vscode.Position(firstSecret.lineNumber - 1, firstSecret.column - 1);
                        editor.selection = new vscode.Selection(position, position);
                        editor.revealRange(new vscode.Range(position, position));
                    });
                });
            } else if (selection === 'View Details') {
                // The output channel is already shown, just focus it
                outputChannel.show();
            } else if (selection === 'Clear Diagnostics') {
                // Clear all diagnostics
                CommandManager.clearSecretHighlights();
                vscode.window.showInformationMessage('Secret diagnostics cleared');
            }
        });
    }

    /**
     * Highlights secrets in the editor with diagnostic markers and decorations
     */
    private static async highlightSecretsInEditor(secrets: HardcodedSecret[]): Promise<void> {
        try {
            logger.info(`🎨 Highlighting ${secrets.length} secrets in editor`);
            
            // Check configuration to see if we should use Problems tab
            const config = vscode.workspace.getConfiguration('akeyless.diagnostics');
            const enableProblemsTab = config.get<boolean>('enableProblemsTab', true);
            const showInOutputOnly = config.get<boolean>('showInOutputOnly', false);
            
            if (showInOutputOnly) {
                logger.info('📋 Configuration set to show results in Output panel only - skipping Problems tab');
                // Only show decorations, no diagnostics
                await CommandManager.highlightSecretsWithDecorationsOnly(secrets);
                return;
            }
            
            if (!enableProblemsTab) {
                logger.info('📋 Configuration disabled Problems tab - using Output panel only');
                // Only show decorations, no diagnostics
                await CommandManager.highlightSecretsWithDecorationsOnly(secrets);
                return;
            }
            
            // IMPORTANT: Clear ALL existing diagnostics first to prevent accumulation
            // This is the key fix - we need to clear everything before creating new diagnostics
            if (CommandManager.secretDiagnostics) {
                logger.info('🧹 Clearing existing diagnostics before new scan');
                CommandManager.secretDiagnostics.clear();
                CommandManager.secretDiagnostics.dispose();
                CommandManager.secretDiagnostics = undefined;
            }
            
            // Also clear any existing decorations
            if (CommandManager.secretDecorations) {
                logger.info('🧹 Clearing existing decorations before new scan');
                for (const decorationType of CommandManager.secretDecorations.values()) {
                    decorationType.dispose();
                }
                CommandManager.secretDecorations.clear();
                CommandManager.secretDecorations = undefined;
            }
            
            // SIMPLE BUT EFFECTIVE: Clear all existing diagnostics by creating a new collection
            // and immediately clearing it for all known files
            logger.info('🧹 Clearing all existing diagnostics with simple approach');
            
            // Create a temporary collection and clear it immediately to reset VS Code's diagnostic state
            const tempCollection = vscode.languages.createDiagnosticCollection(`akeyless-temp-${Date.now()}`);
            tempCollection.clear();
            tempCollection.dispose();
            
            // Create diagnostic collection for secrets with unique name
            const timestamp = Date.now();
            const diagnosticCollection = vscode.languages.createDiagnosticCollection(`akeyless-secrets-${timestamp}`);
            
            // Group secrets by file
            const secretsByFile = new Map<string, HardcodedSecret[]>();
            for (const secret of secrets) {
                if (!secretsByFile.has(secret.fileName)) {
                    secretsByFile.set(secret.fileName, []);
                }
                secretsByFile.get(secret.fileName)!.push(secret);
            }
            
            // Process each file
            for (const [fileName, fileSecrets] of secretsByFile) {
                try {
                    const document = await vscode.workspace.openTextDocument(fileName);
                    const diagnostics: vscode.Diagnostic[] = [];
                    const decorations: vscode.DecorationOptions[] = [];
                    
                    for (const secret of fileSecrets) {
                        // Create diagnostic marker
                        const range = new vscode.Range(
                            secret.lineNumber - 1, 
                            secret.column - 1, 
                            secret.lineNumber - 1, 
                            secret.column - 1 + secret.value.length
                        );
                        
                        const diagnostic = new vscode.Diagnostic(
                            range,
                            `HARDCODED SECRET: ${secret.type}\nValue: "${secret.value.substring(0, 20)}${secret.value.length > 20 ? '...' : ''}"\n\nTo fix this:\na. Save the key to Akeyless directly from Cursor by highlighting the key\nb. Press the right click of the mouse button\nc. Select "Save to Akeyless"\nd. Pull the secret from Akeyless: https://docs.akeyless.io/reference/getsecretvalue-1`,
                            vscode.DiagnosticSeverity.Warning
                        );
                        
                        // Removed source, code, and relatedInformation to clean up the diagnostic
                        
                        diagnostics.push(diagnostic);
                        
                        // Create decoration for visual highlighting (no hover message to avoid duplication)
                        const decoration = {
                            range: range
                        };
                        
                        decorations.push(decoration);
                    }
                    
                    // IMPORTANT: Clear any existing diagnostics for this file first
                    // This ensures we don't accumulate diagnostics
                    diagnosticCollection.set(document.uri, []);
                    
                    // Now set the new diagnostics
                    diagnosticCollection.set(document.uri, diagnostics);
                    
                    // Add decorations to active editor if this file is open
                    const activeEditor = vscode.window.activeTextEditor;
                    if (activeEditor && activeEditor.document.uri.fsPath === fileName) {
                        const decorationType = vscode.window.createTextEditorDecorationType({
                            backgroundColor: new vscode.ThemeColor('errorForeground'),
                            border: '2px solid',
                            borderColor: new vscode.ThemeColor('errorForeground'),
                            after: {
                                contentText: ' SECRET',
                                color: new vscode.ThemeColor('errorForeground'),
                                margin: '0 0 0 10px'
                            }
                        });
                        
                        activeEditor.setDecorations(decorationType, decorations);
                        
                        // Store decoration type for cleanup
                        if (!CommandManager.secretDecorations) {
                            CommandManager.secretDecorations = new Map();
                        }
                        CommandManager.secretDecorations.set(fileName, decorationType);
                    }
                    
                } catch (error) {
                    logger.error(`Error highlighting secrets in ${fileName}:`, error);
                }
            }
            
            // Store diagnostic collection for cleanup
            CommandManager.secretDiagnostics = diagnosticCollection;
            
            // Update status bar to show active diagnostics
            CommandManager.updateStatusBar(secrets.length);
            
            logger.info(`✅ Successfully highlighted ${secrets.length} secrets in editor`);
            
        } catch (error) {
            logger.error('Error highlighting secrets in editor:', error);
        }
    }

    /**
     * Clears all secret highlighting and diagnostic markers
     */
    private static clearSecretHighlights(): void {
        try {
            // Clear diagnostic collection
            if (CommandManager.secretDiagnostics) {
                CommandManager.secretDiagnostics.clear();
                CommandManager.secretDiagnostics.dispose();
                CommandManager.secretDiagnostics = undefined;
            }
            
            // Clear decorations
            if (CommandManager.secretDecorations) {
                for (const decorationType of CommandManager.secretDecorations.values()) {
                    decorationType.dispose();
                }
                CommandManager.secretDecorations.clear();
                CommandManager.secretDecorations = undefined;
            }
            
            // Clear status bar
            if (CommandManager.statusBarItem) {
                CommandManager.statusBarItem.dispose();
                CommandManager.statusBarItem = undefined;
            }
            
            logger.info('🧹 Cleared all secret highlighting');
        } catch (error) {
            logger.error('Error clearing secret highlights:', error);
        }
    }

    /**
     * Updates the status bar to show active diagnostics
     */
    private static updateStatusBar(secretCount: number): void {
        try {
            // Dispose of existing status bar item
            if (CommandManager.statusBarItem) {
                CommandManager.statusBarItem.dispose();
            }
            
            // Create new status bar item
            CommandManager.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
            CommandManager.statusBarItem.text = `🔍 ${secretCount} secrets found`;
            CommandManager.statusBarItem.tooltip = `Click to clear secret diagnostics`;
            CommandManager.statusBarItem.command = 'akeyless.clearSecretHighlights';
            CommandManager.statusBarItem.show();
            
            logger.info(`📊 Status bar updated: ${secretCount} secrets`);
        } catch (error) {
            logger.error('Error updating status bar:', error);
        }
    }

    /**
     * Highlights secrets with decorations only (no Problems tab diagnostics)
     */
    private static async highlightSecretsWithDecorationsOnly(secrets: HardcodedSecret[]): Promise<void> {
        try {
            logger.info(`🎨 Highlighting ${secrets.length} secrets with decorations only (no Problems tab)`);
            
            // Clear any existing decorations
            if (CommandManager.secretDecorations) {
                for (const decorationType of CommandManager.secretDecorations.values()) {
                    decorationType.dispose();
                }
                CommandManager.secretDecorations.clear();
                CommandManager.secretDecorations = undefined;
            }
            
            // Group secrets by file
            const secretsByFile = new Map<string, HardcodedSecret[]>();
            for (const secret of secrets) {
                if (!secretsByFile.has(secret.fileName)) {
                    secretsByFile.set(secret.fileName, []);
                }
                secretsByFile.get(secret.fileName)!.push(secret);
            }
            
            // Process each file for decorations only
            for (const [fileName, fileSecrets] of secretsByFile) {
                try {
                    const decorations: vscode.DecorationOptions[] = [];
                    
                    for (const secret of fileSecrets) {
                        const range = new vscode.Range(
                            secret.lineNumber - 1, 
                            secret.column - 1, 
                            secret.lineNumber - 1, 
                            secret.column - 1 + secret.value.length
                        );
                        
                        const decoration = { range };
                        decorations.push(decoration);
                    }
                    
                    // Add decorations to active editor if this file is open
                    const activeEditor = vscode.window.activeTextEditor;
                    if (activeEditor && activeEditor.document.uri.fsPath === fileName) {
                        const decorationType = vscode.window.createTextEditorDecorationType({
                            backgroundColor: new vscode.ThemeColor('errorForeground'),
                            border: '2px solid',
                            borderColor: new vscode.ThemeColor('errorForeground'),
                            after: {
                                contentText: ' SECRET',
                                color: new vscode.ThemeColor('errorForeground'),
                                margin: '0 0 0 10px'
                            }
                        });
                        
                        activeEditor.setDecorations(decorationType, decorations);
                        
                        // Store decoration type for cleanup
                        if (!CommandManager.secretDecorations) {
                            CommandManager.secretDecorations = new Map();
                        }
                        CommandManager.secretDecorations.set(fileName, decorationType);
                    }
                    
                } catch (error) {
                    logger.error(`Error highlighting decorations in ${fileName}:`, error);
                }
            }
            
            // Update status bar
            CommandManager.updateStatusBar(secrets.length);
            
            logger.info(`✅ Successfully highlighted ${secrets.length} secrets with decorations only`);
            
        } catch (error) {
            logger.error('Error highlighting secrets with decorations only:', error);
        }
    }

    /**
     * Checks if there are currently active secret diagnostics
     */
    public static hasActiveDiagnostics(): boolean {
        return CommandManager.secretDiagnostics !== undefined;
    }

    /**
     * Static method to clear diagnostics (can be called from extension.ts on deactivate)
     */
    public static clearAllDiagnostics(): void {
        try {
            if (CommandManager.secretDiagnostics) {
                CommandManager.secretDiagnostics.clear();
                CommandManager.secretDiagnostics.dispose();
                CommandManager.secretDiagnostics = undefined;
            }
            
            // Clear status bar
            if (CommandManager.statusBarItem) {
                CommandManager.statusBarItem.dispose();
                CommandManager.statusBarItem = undefined;
            }
            
            logger.info('🧹 Cleared all diagnostics from extension deactivation');
        } catch (error) {
            logger.error('Error clearing diagnostics on deactivation:', error);
        }
    }

    /**
     * Handles the clear secret highlights command
     */
    private async handleClearSecretHighlightsCommand(): Promise<void> {
        try {
            logger.info('Clear secret highlights command triggered');
            
            if (!CommandManager.secretDiagnostics) {
                vscode.window.showInformationMessage('No secret diagnostics to clear');
                return;
            }
            
            CommandManager.clearSecretHighlights();
            vscode.window.showInformationMessage('Secret highlights cleared');
        } catch (error) {
            logger.error('Failed to clear secret highlights:', error);
            vscode.window.showErrorMessage(`Failed to clear secret highlights: ${error}`);
        }
    }

    /**
     * Handles the check diagnostics status command
     */
    private async handleCheckDiagnosticsStatusCommand(): Promise<void> {
        try {
            logger.info('Check diagnostics status command triggered');
            
            if (CommandManager.hasActiveDiagnostics()) {
                vscode.window.showInformationMessage('Secret diagnostics are currently active. Use "Clear Secret Highlights" to remove them.');
            } else {
                vscode.window.showInformationMessage('No active secret diagnostics found.');
            }
        } catch (error) {
            logger.error('Failed to check diagnostics status:', error);
            vscode.window.showErrorMessage(`Failed to check diagnostics status: ${error}`);
        }
    }

    /**
     * Handles the force clear all diagnostics command (nuclear option)
     */
    private async handleForceClearAllDiagnosticsCommand(): Promise<void> {
        try {
            logger.info('Force clear all diagnostics command triggered');
            
            // Nuclear option: Clear everything and reset VS Code's diagnostic state
            if (CommandManager.secretDiagnostics) {
                CommandManager.secretDiagnostics.clear();
                CommandManager.secretDiagnostics.dispose();
                CommandManager.secretDiagnostics = undefined;
            }
            
            // Clear decorations
            if (CommandManager.secretDecorations) {
                for (const decorationType of CommandManager.secretDecorations.values()) {
                    decorationType.dispose();
                }
                CommandManager.secretDecorations.clear();
                CommandManager.secretDecorations = undefined;
            }
            
            // Clear status bar
            if (CommandManager.statusBarItem) {
                CommandManager.statusBarItem.dispose();
                CommandManager.statusBarItem = undefined;
            }
            
            // Create a temporary collection to force clear any remaining diagnostics
            const tempCollection = vscode.languages.createDiagnosticCollection(`force-clear-${Date.now()}`);
            tempCollection.clear();
            tempCollection.dispose();
            
            vscode.window.showInformationMessage('All diagnostics forcefully cleared. Problems tab should now be empty.');
            logger.info('🧹 Force cleared all diagnostics');
        } catch (error) {
            logger.error('Failed to force clear all diagnostics:', error);
            vscode.window.showErrorMessage(`Failed to force clear all diagnostics: ${error}`);
        }
    }

    /**
     * Handles the generate secret name command
     */
    private async handleGenerateSecretNameCommand(): Promise<void> {
        try {
            logger.info('Generate secret name command triggered');
            
            const activeEditor = vscode.window.activeTextEditor;
            if (!activeEditor) {
                vscode.window.showErrorMessage('No active text editor found');
                return;
            }
            
            const fileName = activeEditor.document.fileName.split('/').pop()?.replace(/\.[^/.]+$/, '') || 'secret';
            const generatedName = `/secrets/${fileName}-${Date.now()}`;
            
            // Copy the generated name to clipboard
            await vscode.env.clipboard.writeText(generatedName);
            
            vscode.window.showInformationMessage(`Generated secret name copied to clipboard: ${generatedName}`);
            logger.info(`✅ Generated secret name: ${generatedName}`);
        } catch (error) {
            logger.error('Failed to generate secret name:', error);
            vscode.window.showErrorMessage(`Failed to generate secret name: ${error}`);
        }
    }



    /**
     * Handles the load more command (triggered on scroll)
     */
    private async handleLoadMoreCommand(): Promise<void> {
        logger.info('📜 Load more triggered');
        logger.info('📜 Command handler called - checking if provider has more pages...');
        
        try {
            const hasMore = this.secretsTreeProvider.hasMorePagesToLoad();
            logger.info(`📜 Has more pages to load: ${hasMore}`);
            
            if (hasMore) {
                logger.info('📜 Calling onScrollToBottom...');
                
                const result = await this.secretsTreeProvider.onScrollToBottom();
                
                // Show detailed popup with results
                const message = `📦 Loaded ${result.itemsLoaded} new items\n` +
                              `📊 Total items: ${this.secretsTreeProvider.getCachedItems().length}\n` +
                              `📄 Next token: ${result.nextToken || 'null'}\n` +
                              `🔄 Has more pages: ${result.hasMore}`;
                
                vscode.window.showInformationMessage(message);
                logger.info('📜 onScrollToBottom completed');
            } else {
                logger.info('📜 No more pages to load or currently loading');
                vscode.window.showInformationMessage('No more pages to load');
            }
        } catch (error) {
            logger.error('❌ Load more error:', error);
            vscode.window.showErrorMessage(`Load more failed: ${error}`);
        }
    }

    /**
     * Handles the search command
     */
    private async handleSearchCommand(): Promise<void> {
        logger.info('🔍 Search initiated');
        try {
            const searchTerm = await vscode.window.showInputBox({
                prompt: 'Search secrets by name or type',
                placeHolder: 'Enter search term...'
            });

            if (searchTerm !== undefined) {
                logger.info('🔍 Setting search term:', searchTerm);
                this.secretsTreeProvider.setSearchTerm(searchTerm);
                
                if (searchTerm) {
                    vscode.window.showInformationMessage(`${MESSAGES.SEARCHING} ${searchTerm}`);
                    
                    // Get search results and display them globally
                    await this.displayGlobalSearchResults(searchTerm);
                } else {
                    vscode.window.showInformationMessage(MESSAGES.SEARCH_CLEARED);
                }
            }
        } catch (error) {
            logger.error('❌ Search error:', error);
            vscode.window.showErrorMessage(MESSAGES.SEARCH_FAILED);
        }
    }

    /**
     * Displays search results globally regardless of current view
     */
    private async displayGlobalSearchResults(searchTerm: string): Promise<void> {
        try {
            // Get current items to search through
            const items = this.secretsTreeProvider.getCachedItems();
            if (!items || items.length === 0) {
                vscode.window.showInformationMessage('No secrets available to search');
                return;
            }

            // Filter items based on search term
            const matchingItems = items.filter((item: any) => {
                if (item.status.type !== STATUS_TYPES.NORMAL) return false;
                return item.item.item_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                       item.item.item_type.toLowerCase().includes(searchTerm.toLowerCase());
            });

            if (matchingItems.length === 0) {
                vscode.window.showInformationMessage(`No secrets found matching "${searchTerm}"`);
                return;
            }

            // Create a detailed message with results
            const resultsMessage = this.formatSearchResults(matchingItems, searchTerm);
            
            // Show results in multiple ways for maximum visibility
            await this.showGlobalResults(resultsMessage, matchingItems, searchTerm);
            
        } catch (error) {
            logger.error('❌ Global search results error:', error);
            vscode.window.showErrorMessage('Error displaying search results');
        }
    }

    /**
     * Formats search results into a readable message
     */
    private formatSearchResults(items: any[], searchTerm: string): string {
        const itemNames = items.map(item => {
            const name = item.item.item_name.split('/').pop() || item.item.item_name;
            return `• ${name} (${item.item.item_type})`;
        }).slice(0, 10); // Limit to first 10 results

        let message = `Found ${items.length} secrets matching "${searchTerm}":\n${itemNames.join('\n')}`;
        
        if (items.length > 10) {
            message += `\n... and ${items.length - 10} more`;
        }

        return message;
    }

    /**
     * Shows search results globally in multiple ways
     */
    private async showGlobalResults(message: string, items: any[], searchTerm: string): Promise<void> {
        // Method 1: Status bar message
        const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
        statusBarItem.text = `🔍 ${items.length} secrets found for "${searchTerm}"`;
        statusBarItem.tooltip = message;
        statusBarItem.command = 'akeyless.focusView';
        statusBarItem.show();
        
        // Auto-hide after 10 seconds
        setTimeout(() => {
            statusBarItem.dispose();
        }, 10000);

        // Method 2: Simple notification with button to view results
        const action = await vscode.window.showInformationMessage(
            `Found ${items.length} secrets matching "${searchTerm}". Click to view in sidebar.`,
            'View Results'
        );

        if (action === 'View Results') {
            // Try to focus the Akeyless view
            try {
                await vscode.commands.executeCommand('workbench.view.extension.akeyless-secrets');
            } catch (error) {
                vscode.window.showErrorMessage('Please click the Akeyless icon in the sidebar to view results');
            }
        }

        // Method 3: Log detailed results
        logger.info(`🔍 Search results for "${searchTerm}":`, items.map(item => item.item.item_name));
    }

    /**
     * Copies individual secret based on the selected action
     */
    private async copyIndividualSecret(item: any, action: string): Promise<void> {
        try {
            const secretValue = await this.akeylessCLI.getSecretValue(item.item.item_name);
            
            if (!secretValue) {
                vscode.window.showWarningMessage('Could not retrieve secret value');
                return;
            }
            
            let clipboardText = '';
            
            if (action === 'Copy Secret Value') {
                const value = typeof secretValue === 'object' ? JSON.stringify(secretValue) : String(secretValue);
                clipboardText = value;
            } else if (action === 'Copy Username') {
                const username = secretValue.username || secretValue.user || 'N/A';
                clipboardText = username;
            } else if (action === 'Copy Password') {
                const password = secretValue.password || secretValue.pass || 'N/A';
                clipboardText = password;
            } else if (action === 'Copy Both') {
                const username = secretValue.username || secretValue.user || 'N/A';
                const password = secretValue.password || secretValue.pass || 'N/A';
                clipboardText = `Username: ${username}\nPassword: ${password}`;
            }
            
            if (clipboardText) {
                await vscode.env.clipboard.writeText(clipboardText);
                vscode.window.showInformationMessage(`Copied ${action.toLowerCase()} to clipboard`);
            }
            
        } catch (error) {
            logger.error(`❌ Copy individual secret error:`, error);
            vscode.window.showErrorMessage('Error copying secret value');
        }
    }

    /**
     * Handles the copy secret value command
     */
    private async handleCopySecretValueCommand(...args: any[]): Promise<void> {
        logger.info('📋 Copy secret value initiated');
        try {
            // Get the selected item from command arguments
            const selectedItem = args[0];
            if (!selectedItem || !selectedItem.item) {
                logger.error('❌ No item selected');
                vscode.window.showErrorMessage('No item selected');
                return;
            }

            const item = selectedItem.item;
            const secretName = item.item_name;
            const itemType = item.item_type;

            logger.info(`🔐 Getting secret value for: ${secretName} (type: ${itemType})`);
            vscode.window.showInformationMessage('Getting secret value...');
            
            let response;
            
            // Use appropriate CLI command based on secret type
            if (itemType === 'DYNAMIC_SECRET') {
                logger.info(`🔄 Using get-dynamic-secret-value for dynamic secret: ${secretName}`);
                response = await this.akeylessCLI.getDynamicSecretValue(secretName);
            } else if (itemType === 'ROTATED_SECRET') {
                logger.info(`🔄 Using get-rotated-secret-value for rotated secret: ${secretName}`);
                response = await this.akeylessCLI.getRotatedSecretValue(secretName);
            } else {
                logger.info(`🔐 Using get-secret-value for static secret: ${secretName}`);
                response = await this.akeylessCLI.getSecretValue(secretName);
            }
            
            // Copy the entire response as JSON for all secret types
            logger.info('🔍 Processing secret response');
            logger.debug('🔍 Secret response structure:', JSON.stringify(response, null, 2));
            
            const secretValue = JSON.stringify(response, null, 2);
            logger.info('📋 Copying entire secret response');
            
            // Ensure secretValue is a string and not undefined
            if (!secretValue) {
                throw new Error(`Secret value is undefined or empty for: ${secretName}`);
            }
            
            const secretValueString = String(secretValue);
            logger.info(`📋 Copying secret value to clipboard: ${secretValueString.substring(0, 10)}...`);
            
            // Copy to clipboard
            await vscode.env.clipboard.writeText(secretValueString);
            
            // Show success message with preview of copied content
            const preview = secretValueString.length > 200 
                ? secretValueString.substring(0, 200) + '...' 
                : secretValueString;
            
            // Show a more detailed message with option to view full content
            const message = `✅ Secret value copied to clipboard!\n\nPreview:\n${preview}`;
            
            if (secretValueString.length > 200) {
                // For long content, show option to view full content
                const action = await vscode.window.showInformationMessage(
                    message,
                    'View Full Content'
                );
                
                if (action === 'View Full Content') {
                    // Open a new document with the full content
                    const document = await vscode.workspace.openTextDocument({
                        content: secretValueString,
                        language: 'json'
                    });
                    await vscode.window.showTextDocument(document);
                }
            } else {
                // For shorter content, just show the message
                vscode.window.showInformationMessage(message);
            }
            logger.info('✅ Secret value copied to clipboard');
        } catch (error) {
            logger.error('❌ Copy secret value error:', error);
            
            // Show the actual CLI error message
            let errorMessage = 'Failed to get secret value';
            
            if (error instanceof Error && error.message) {
                // Extract the actual error message from the CLI response
                if (error.message.includes('Command failed:')) {
                    // Parse the CLI error message
                    const cliErrorMatch = error.message.match(/failed to get the value of the requested secrets: (.+)/);
                    if (cliErrorMatch) {
                        errorMessage = cliErrorMatch[1];
                    } else {
                        // Fallback to the full error message
                        errorMessage = error.message.replace('Command failed:', '').trim();
                    }
                } else {
                    errorMessage = error.message;
                }
            }
            
            vscode.window.showErrorMessage(errorMessage);
        }
    }

    /**
     * Handles the copy username command
     */
    private async handleCopyUsernameCommand(...args: any[]): Promise<void> {
        logger.info('📋 Copy username initiated');
        try {
            // Get the selected item from command arguments
            const selectedItem = args[0];
            if (!selectedItem || !selectedItem.item) {
                logger.error('❌ No item selected');
                vscode.window.showErrorMessage('No item selected');
                return;
            }

            const item = selectedItem.item;
            const secretName = item.item_name;
            const itemType = item.item_type;

            logger.info(`🔐 Getting secret value for: ${secretName} (type: ${itemType})`);
            vscode.window.showInformationMessage('Getting username...');
            
            let response;
            let username = null;
            
            // Use appropriate CLI command based on secret type
            if (itemType === 'ROTATED_SECRET') {
                logger.info(`🔄 Using get-rotated-secret-value for rotated secret: ${secretName}`);
                response = await this.akeylessCLI.getRotatedSecretValue(secretName);
                
                // For rotated secrets, extract username from value object
                if (response.value && response.value.username) {
                    username = response.value.username;
                    logger.info('👤 Username found in rotated secret');
                }
            } else {
                // For static secrets with password sub-type, use get-secret-value
                logger.info(`🔐 Using get-secret-value for static secret: ${secretName}`);
                response = await this.akeylessCLI.getSecretValue(secretName);
                
                // Debug: Log the response structure
                logger.info('🔍 Response structure:', JSON.stringify(response, null, 2));
                
                // Extract the username from the response
                // Try different possible response structures
                if (response.username) {
                    username = response.username;
                } else if (response[secretName] && typeof response[secretName] === 'object' && response[secretName].username) {
                    username = response[secretName].username;
                } else if (typeof response === 'object' && response[secretName]) {
                    // If the response is a simple key-value pair, try to parse it as JSON
                    const secretValue = response[secretName];
                    if (typeof secretValue === 'string') {
                        try {
                            const parsed = JSON.parse(secretValue);
                            if (parsed.username) {
                                username = parsed.username;
                            }
                        } catch (e) {
                            // Not JSON, ignore
                        }
                    }
                }
            }
            
            if (!username) {
                logger.error('❌ Username not found in response structure:', response);
                throw new Error(`Username not found in response for: ${secretName}. Response structure: ${JSON.stringify(response)}`);
            }
            
            // Copy to clipboard
            await vscode.env.clipboard.writeText(username);
            vscode.window.showInformationMessage(MESSAGES.COPY_USERNAME_SUCCESS);
            logger.info('✅ Username copied to clipboard');
        } catch (error) {
            logger.error('❌ Copy username error:', error);
            vscode.window.showErrorMessage(MESSAGES.COPY_USERNAME_FAILED);
        }
    }

    /**
     * Handles the copy password command
     */
    private async handleCopyPasswordCommand(...args: any[]): Promise<void> {
        logger.info('📋 Copy password initiated');
        try {
            // Get the selected item from command arguments
            const selectedItem = args[0];
            if (!selectedItem || !selectedItem.item) {
                logger.error('❌ No item selected');
                vscode.window.showErrorMessage('No item selected');
                return;
            }

            const item = selectedItem.item;
            const secretName = item.item_name;
            const itemType = item.item_type;

            logger.info(`🔐 Getting secret value for: ${secretName} (type: ${itemType})`);
            vscode.window.showInformationMessage('Getting password...');
            
            let response;
            let password = null;
            
            // Use appropriate CLI command based on secret type
            if (itemType === 'ROTATED_SECRET') {
                logger.info(`🔄 Using get-rotated-secret-value for rotated secret: ${secretName}`);
                response = await this.akeylessCLI.getRotatedSecretValue(secretName);
                
                // For rotated secrets, extract password from value object
                if (response.value && response.value.password) {
                    password = response.value.password;
                    logger.info('🔐 Password found in rotated secret');
                }
            } else {
                // For static secrets with password sub-type, use get-secret-value
                logger.info(`🔐 Using get-secret-value for static secret: ${secretName}`);
                response = await this.akeylessCLI.getSecretValue(secretName);
                
                // Debug: Log the response structure
                logger.info('🔍 Response structure:', JSON.stringify(response, null, 2));
                
                // Extract the password from the response
                // Try different possible response structures
                if (response.password) {
                    password = response.password;
                } else if (response[secretName] && typeof response[secretName] === 'object' && response[secretName].password) {
                    password = response[secretName].password;
                } else if (typeof response === 'object' && response[secretName]) {
                    // If the response is a simple key-value pair, try to parse it as JSON
                    const secretValue = response[secretName];
                    if (typeof secretValue === 'string') {
                        try {
                            const parsed = JSON.parse(secretValue);
                            if (parsed.password) {
                                password = parsed.password;
                            }
                        } catch (e) {
                            // Not JSON, ignore
                        }
                    }
                }
            }
            
            if (!password) {
                logger.error('❌ Password not found in response structure:', response);
                throw new Error(`Password not found in response for: ${secretName}. Response structure: ${JSON.stringify(response)}`);
            }
            
            // Copy to clipboard
            await vscode.env.clipboard.writeText(password);
            vscode.window.showInformationMessage(MESSAGES.COPY_PASSWORD_SUCCESS);
            logger.info('✅ Password copied to clipboard');
        } catch (error) {
            logger.error('❌ Copy password error:', error);
            vscode.window.showErrorMessage(MESSAGES.COPY_PASSWORD_FAILED);
        }
    }
} 