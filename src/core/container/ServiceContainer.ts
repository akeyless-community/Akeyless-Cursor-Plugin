/**
 * Dependency Injection Container
 * Implements Service Locator pattern with proper dependency management
 */
export class ServiceContainer {
    private static instance: ServiceContainer;
    private services: Map<string, any> = new Map();
    private singletons: Map<string, any> = new Map();

    private constructor() {}

    /**
     * Gets the singleton instance of the container
     */
    static getInstance(): ServiceContainer {
        if (!ServiceContainer.instance) {
            ServiceContainer.instance = new ServiceContainer();
        }
        return ServiceContainer.instance;
    }

    /**
     * Registers a service with a factory function
     */
    register<T>(key: string, factory: () => T, singleton: boolean = true): void {
        if (singleton) {
            this.services.set(key, () => {
                if (!this.singletons.has(key)) {
                    this.singletons.set(key, factory());
                }
                return this.singletons.get(key);
            });
        } else {
            this.services.set(key, factory);
        }
    }

    /**
     * Registers an instance directly
     */
    registerInstance<T>(key: string, instance: T): void {
        this.singletons.set(key, instance);
        this.services.set(key, () => instance);
    }

    /**
     * Resolves a service by key
     */
    resolve<T>(key: string): T {
        const factory = this.services.get(key);
        if (!factory) {
            throw new Error(`Service '${key}' not found in container`);
        }
        return factory() as T;
    }

    /**
     * Checks if a service is registered
     */
    has(key: string): boolean {
        return this.services.has(key);
    }

    /**
     * Clears all services (useful for testing)
     */
    clear(): void {
        this.services.clear();
        this.singletons.clear();
    }
}

/**
 * Service keys for type-safe dependency injection
 */
export const SERVICE_KEYS = {
    AKEYLESS_REPOSITORY: 'akeyless.repository',
    SECRET_SCANNER: 'secret.scanner',
    CONFIGURATION_SERVICE: 'configuration.service',
    LOGGER: 'logger',
    VSCODE_CONTEXT: 'vscode.context',
    SECRETS_TREE_PROVIDER: 'secrets.tree.provider',
    SECRET_MANAGEMENT_SERVICE: 'secret.management.service',
    DIAGNOSTICS_MANAGER: 'diagnostics.manager',
    HIGHLIGHTING_MANAGER: 'highlighting.manager',
    AUTO_SCAN_HANDLER: 'auto.scan.handler',
    SCAN_RESULTS_OUTPUT_MANAGER: 'scan.results.output.manager',
} as const;

