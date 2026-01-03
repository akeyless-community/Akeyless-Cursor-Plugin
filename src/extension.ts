import * as vscode from 'vscode';
import { AkeylessCLI } from './services/akeyless-cli';
import { SecretsTreeProvider } from './providers/secrets-tree-provider';
import { SecretCompletionProvider } from './providers/secret-completion-provider';
import { CommandManager } from './commands';
import { VIEWS, MESSAGES } from './constants';
import { logger } from './utils/logger';

export function activate(context: vscode.ExtensionContext) {
    logger.info('🎯 Akeyless Secrets Manager extension is now active!');

    try {
        // Initialize services
        const akeylessCLI = new AkeylessCLI();
        logger.info('✅ AkeylessCLI service initialized');

        // Initialize providers
        const secretsTreeProvider = new SecretsTreeProvider(akeylessCLI);
        logger.info('✅ SecretsTreeProvider initialized');

        // Register tree data provider
        logger.info('📋 Registering tree data provider for secrets explorer');
        vscode.window.registerTreeDataProvider(VIEWS.SECRETS_EXPLORER, secretsTreeProvider);

        // Register completion provider for secret name autocomplete
        logger.info('💡 Registering completion provider for secret name suggestions');
        const completionProvider = new SecretCompletionProvider(secretsTreeProvider);
        const completionDisposable = vscode.languages.registerCompletionItemProvider(
            { scheme: 'file' }, // Works for all file types
            completionProvider,
            '/', // Trigger on forward slash (common in secret paths)
            '"', // Trigger on double quote
            "'", // Trigger on single quote
            '`'  // Trigger on backtick
        );
        context.subscriptions.push(completionDisposable);

        // Initialize and register commands
        const commandManager = new CommandManager(akeylessCLI, secretsTreeProvider);
        commandManager.registerCommands(context);

        // Show a notification that the extension is loaded
        vscode.window.showInformationMessage(MESSAGES.EXTENSION_LOADED);

        logger.info('✅ Extension activation completed successfully');

    } catch (error) {
        logger.error('❌ Error during extension activation:', error);
        vscode.window.showErrorMessage(`Extension activation failed: ${error}`);
    }
}

export function deactivate() {
    logger.info('👋 Akeyless Secrets Manager extension deactivated');
    
    // Clean up any remaining diagnostics and decorations
    try {
        CommandManager.clearAllDiagnostics();
        logger.info('🧹 Cleanup completed on deactivation');
    } catch (error) {
        logger.error('❌ Error during cleanup on deactivation:', error);
    }
} 