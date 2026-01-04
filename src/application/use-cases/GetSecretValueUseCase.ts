import { IAkeylessRepository } from '../../core/interfaces/IAkeylessRepository';
import { SecretPath } from '../../domain/value-objects/SecretPath';
import { RepositoryError } from '../../core/errors';
import { logger } from '../../utils/logger';

/**
 * Use Case: Get Secret Value
 * Encapsulates the business logic for retrieving secret values
 */
export class GetSecretValueUseCase {
    constructor(private readonly repository: IAkeylessRepository) {}

    /**
     * Gets the value of a secret
     */
    async execute(path: string): Promise<string> {
        logger.info(` Executing get secret value use case: ${path}`);
        
        try {
            const secretPath = SecretPath.from(path);
            const value = await this.repository.getSecretValue(secretPath.toString());
            
            if (!value) {
                throw new RepositoryError(`Secret value not found for path: ${path}`);
            }
            
            return value;
        } catch (error) {
            logger.error(' Error in get secret value use case:', error);
            if (error instanceof RepositoryError) {
                throw error;
            }
            throw new RepositoryError(`Failed to get secret value: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
}

