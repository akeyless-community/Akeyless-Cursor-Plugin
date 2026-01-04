import * as vscode from 'vscode';
import { ServiceFactory } from './core/factories/ServiceFactory';
import { CommandFactory } from './core/factories/CommandFactory';
import { CommandRegistry } from './presentation/commands/CommandRegistry';
import { VIEWS, MESSAGES } from './constants';
import { logger } from './utils/logger';
import { SecretsTreeProvider } from './providers/secrets-tree-provider';
import { SecretCompletionProvider } from './providers/secret-completion-provider';
import { SERVICE_KEYS } from './core/container/ServiceContainer';

/**
 * Extension Activation
 * Uses Dependency Injection and proper design patterns
 */
export function activate(context: vscode.ExtensionContext) {
    logger.info('Akeyless Secrets Manager extension is now active!');

    try {
        // Initialize DI container
        logger.info('Initializing dependency injection container...');
        const container = ServiceFactory.initialize(context);
        logger.info('DI container initialized');

        // Get services from container
        const treeProvider = container.resolve<SecretsTreeProvider>(SERVICE_KEYS.SECRETS_TREE_PROVIDER);
        const autoScanHandler = container.resolve<any>(SERVICE_KEYS.AUTO_SCAN_HANDLER);

        // Register tree data provider
        logger.info('Registering tree data provider for secrets explorer');
        vscode.window.registerTreeDataProvider(VIEWS.SECRETS_EXPLORER, treeProvider);

        // Register completion provider
        logger.info('Registering completion provider for secret name suggestions');
        const completionProvider = new SecretCompletionProvider(treeProvider);
        const completionDisposable = vscode.languages.registerCompletionItemProvider(
            { scheme: 'file' },
            completionProvider,
            '/', '"', "'", '`'
        );
        context.subscriptions.push(completionDisposable);

        // Create and register all commands
        logger.info('Creating and registering commands...');
        const commands = CommandFactory.createAllCommands(container);
        const commandRegistry = new CommandRegistry();
        commandRegistry.registerAll(commands);
        commandRegistry.registerWithVSCode(context);
        logger.info('All commands registered');

        // Register auto-scan on save
        logger.info('Registering auto-scan on save...');
        autoScanHandler.register(context);
        logger.info('Auto-scan on save registered');

        // Show notification
        vscode.window.showInformationMessage(MESSAGES.EXTENSION_LOADED);

        logger.info('Extension activation completed successfully');

    } catch (error) {
        logger.error('Error during extension activation:', error);
        vscode.window.showErrorMessage(`Extension activation failed: ${error}`);
    }
}

export function deactivate() {
    logger.info('Akeyless Secrets Manager extension deactivated');
    
    try {
        // Cleanup is handled by VS Code's subscription system
        // Diagnostics and decorations are automatically disposed
        logger.info('Cleanup completed on deactivation');
    } catch (error) {
        logger.error('Error during cleanup on deactivation:', error);
    }
} 