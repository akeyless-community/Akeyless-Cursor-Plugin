import * as vscode from 'vscode';
import { AkeylessCLI } from './services/akeyless-cli';
import { SecretsTreeProvider } from './providers/secrets-tree-provider';
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
} 