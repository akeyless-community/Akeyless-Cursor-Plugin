import { AkeylessItem } from '../../types';

/**
 * Repository interface for Akeyless operations
 * Follows Repository Pattern for data access abstraction
 */
export interface IAkeylessRepository {
    /**
     * Lists all items from Akeyless
     */
    listItems(): Promise<AkeylessItem[]>;

    /**
     * Gets a secret value by path
     */
    getSecretValue(path: string): Promise<string>;

    /**
     * Creates a new secret in Akeyless
     */
    createSecret(path: string, value: string, itemType?: string): Promise<void>;

    /**
     * Updates an existing secret
     */
    updateSecret(path: string, value: string): Promise<void>;

    /**
     * Deletes a secret
     */
    deleteSecret(path: string): Promise<void>;

    /**
     * Searches for secrets by name pattern
     */
    searchSecrets(pattern: string): Promise<AkeylessItem[]>;
}



