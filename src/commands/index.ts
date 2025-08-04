import * as vscode from 'vscode';
import { AkeylessCLI } from '../services/akeyless-cli';
import { SecretsTreeProvider } from '../providers/secrets-tree-provider';
import { COMMANDS, MESSAGES } from '../constants';
import { logger } from '../utils/logger';
import { isValidAccessId, isValidAccessKey } from '../utils/helpers';
import { STATUS_TYPES } from '../constants';
import { SecretScanner, HardcodedSecret } from '../utils/secret-scanner';

export class CommandManager {
    // Static properties for managing secret highlighting
    private static secretDiagnostics?: vscode.DiagnosticCollection;
    private static secretDecorations?: Map<string, vscode.TextEditorDecorationType>;
    
    constructor(
        private akeylessCLI: AkeylessCLI,
        private secretsTreeProvider: SecretsTreeProvider
    ) {}

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
            vscode.commands.registerCommand(COMMANDS.CLEAR_SECRET_HIGHLIGHTS, this.handleClearSecretHighlightsCommand.bind(this))
        );

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
                value: selectedText
            });
            
            if (!confirmText) {
                logger.info('❌ User cancelled text confirmation');
                return;
            }
            
            // Prompt for secret name
            const secretName = await vscode.window.showInputBox({
                prompt: 'Enter a name for this secret in Akeyless',
                placeHolder: 'e.g., /my-project/api-key',
                value: `/secrets/${editor.document.fileName.split('/').pop()?.replace(/\.[^/.]+$/, '')}-${Date.now()}`
            });
            
            if (!secretName) {
                logger.info('❌ User cancelled secret name input');
                return;
            }
            
            logger.info(`💾 Creating secret: ${secretName}`);
            
            // Create the secret in Akeyless using create-secret
            const result = await this.akeylessCLI.createStaticSecret(secretName, confirmText);
            
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
            const secrets = Array.from(workspaceResults.values()).flat();
            
            if (secrets.length === 0) {
                vscode.window.showInformationMessage('No hardcoded secrets found!');
                return;
            }
            
            // Add visual highlighting and diagnostic markers
            await CommandManager.highlightSecretsInEditor(secrets);
            
            // Show results in a popup
            CommandManager.showScanResults(secrets, totalFilesScanned);
            
        } catch (error) {
            logger.error('Failed to scan for hardcoded secrets:', error);
            vscode.window.showErrorMessage(`Failed to scan for hardcoded secrets: ${error}`);
        }
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
            `Found ${secrets.length} potential secrets in ${secretsByFile.size} files`,
            'Copy Results',
            'Open First File',
            'View Details'
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
            }
        });
    }

    /**
     * Highlights secrets in the editor with diagnostic markers and decorations
     */
    private static async highlightSecretsInEditor(secrets: HardcodedSecret[]): Promise<void> {
        try {
            logger.info(`🎨 Highlighting ${secrets.length} secrets in editor`);
            
            // Create diagnostic collection for secrets
            const diagnosticCollection = vscode.languages.createDiagnosticCollection('akeyless-secrets');
            
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
                    
                    // Set diagnostics for this file
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
            
            logger.info('🧹 Cleared all secret highlighting');
        } catch (error) {
            logger.error('Error clearing secret highlights:', error);
        }
    }

    /**
     * Handles the clear secret highlights command
     */
    private async handleClearSecretHighlightsCommand(): Promise<void> {
        try {
            logger.info('Clear secret highlights command triggered');
            CommandManager.clearSecretHighlights();
            vscode.window.showInformationMessage('Secret highlights cleared');
        } catch (error) {
            logger.error('Failed to clear secret highlights:', error);
            vscode.window.showErrorMessage(`Failed to clear secret highlights: ${error}`);
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
            const itemName = item.item.item_name.split('/').pop() || item.item.item_name;
            
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