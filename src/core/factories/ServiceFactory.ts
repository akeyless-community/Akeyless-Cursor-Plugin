import * as vscode from 'vscode';
import { ServiceContainer, SERVICE_KEYS } from '../container/ServiceContainer';
import { IAkeylessRepository } from '../interfaces/IAkeylessRepository';
import { ISecretScanner } from '../interfaces/ISecretScanner';
import { IConfigurationService } from '../interfaces/IConfigurationService';
import { ConfigurationService } from '../../infrastructure/services/ConfigurationService';
import { SecretScannerAdapter } from '../../infrastructure/scanners/SecretScannerAdapter';
import { AkeylessCLIAdapter } from '../../infrastructure/adapters/AkeylessCLIAdapter';
import { AkeylessCLI } from '../../services/akeyless-cli';
import { SecretsTreeProvider } from '../../providers/secrets-tree-provider';
import { SecretManagementService } from '../../application/services/SecretManagementService';
import { DiagnosticsManager } from '../../presentation/managers/DiagnosticsManager';
import { HighlightingManager } from '../../presentation/managers/HighlightingManager';
import { AutoScanHandler } from '../../presentation/handlers/AutoScanHandler';
import { logger } from '../../utils/logger';

/**
 * Service Factory
 * Implements Factory Pattern for service creation and DI container setup
 */
export class ServiceFactory {
    private static container: ServiceContainer;

    /**
     * Initializes the service container with all dependencies
     */
    static initialize(context: vscode.ExtensionContext): ServiceContainer {
        if (this.container) {
            return this.container;
        }

        this.container = ServiceContainer.getInstance();

        // Register VS Code context
        this.container.registerInstance(SERVICE_KEYS.VSCODE_CONTEXT, context);

        // Register logger (already a singleton)
        this.container.registerInstance(SERVICE_KEYS.LOGGER, logger);

        // Register configuration service
        this.container.register<IConfigurationService>(
            SERVICE_KEYS.CONFIGURATION_SERVICE,
            () => new ConfigurationService(),
            true
        );

        // Register Akeyless repository
        // Use adapter for backward compatibility with old AkeylessCLI
        this.container.register<IAkeylessRepository>(
            SERVICE_KEYS.AKEYLESS_REPOSITORY,
            () => {
                const oldCLI = new AkeylessCLI();
                return new AkeylessCLIAdapter(oldCLI);
            },
            true
        );

        // Register secret scanner (using adapter to remove static methods)
        this.container.register<ISecretScanner>(
            SERVICE_KEYS.SECRET_SCANNER,
            () => {
                const configService = this.container.resolve<IConfigurationService>(
                    SERVICE_KEYS.CONFIGURATION_SERVICE
                );
                const scannerConfig = configService.getScannerConfig();
                
                const scanner = new SecretScannerAdapter();
                scanner.configure(scannerConfig);
                return scanner;
            },
            true
        );

        // Register SecretsTreeProvider
        this.container.register<SecretsTreeProvider>(
            SERVICE_KEYS.SECRETS_TREE_PROVIDER,
            () => {
                // For now, use adapter - later can use repository directly
                const oldCLI = new AkeylessCLI();
                return new SecretsTreeProvider(oldCLI);
            },
            true
        );

        // Register Secret Management Service (Facade)
        this.container.register<SecretManagementService>(
            SERVICE_KEYS.SECRET_MANAGEMENT_SERVICE,
            () => {
                const repository = this.container.resolve<IAkeylessRepository>(SERVICE_KEYS.AKEYLESS_REPOSITORY);
                const scanner = this.container.resolve<ISecretScanner>(SERVICE_KEYS.SECRET_SCANNER);
                return new SecretManagementService(repository, scanner);
            },
            true
        );

        // Register Diagnostics Manager
        this.container.register<DiagnosticsManager>(
            SERVICE_KEYS.DIAGNOSTICS_MANAGER,
            () => {
                const context = this.container.resolve<vscode.ExtensionContext>(SERVICE_KEYS.VSCODE_CONTEXT);
                return new DiagnosticsManager(context);
            },
            true
        );

        // Register Highlighting Manager
        this.container.register<HighlightingManager>(
            SERVICE_KEYS.HIGHLIGHTING_MANAGER,
            () => new HighlightingManager(),
            true
        );

        // Register Auto Scan Handler
        this.container.register<AutoScanHandler>(
            SERVICE_KEYS.AUTO_SCAN_HANDLER,
            () => {
                const configService = this.container.resolve<IConfigurationService>(SERVICE_KEYS.CONFIGURATION_SERVICE);
                const scanUseCase = this.container.resolve<SecretManagementService>(SERVICE_KEYS.SECRET_MANAGEMENT_SERVICE).scanUseCase;
                const diagnosticsManager = this.container.resolve<DiagnosticsManager>(SERVICE_KEYS.DIAGNOSTICS_MANAGER);
                const highlightingManager = this.container.resolve<HighlightingManager>(SERVICE_KEYS.HIGHLIGHTING_MANAGER);
                return new AutoScanHandler(configService, scanUseCase, diagnosticsManager, highlightingManager);
            },
            true
        );

        logger.info('✅ Service container initialized with all dependencies');
        return this.container;
    }

    /**
     * Gets the service container
     */
    static getContainer(): ServiceContainer {
        if (!this.container) {
            throw new Error('Service container not initialized. Call initialize() first.');
        }
        return this.container;
    }

    /**
     * Resolves a service from the container
     */
    static resolve<T>(key: string): T {
        return this.getContainer().resolve<T>(key);
    }
}

