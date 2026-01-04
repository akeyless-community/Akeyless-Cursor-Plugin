import { IAkeylessRepository } from '../../core/interfaces/IAkeylessRepository';
import { SecretPath } from '../../domain/value-objects/SecretPath';
import { RepositoryError } from '../../core/errors';
import { logger } from '../../utils/logger';

/**
 * Use Case: Save Secret to Akeyless
 * Encapsulates the business logic for saving secrets
 */
export class SaveSecretUseCase {
    constructor(private readonly repository: IAkeylessRepository) {}

    /**
     * Saves a secret to Akeyless
     */
    async execute(path: string, value: string, itemType: string = 'STATIC_SECRET'): Promise<void> {
        logger.info(` Executing save secret use case: ${path}`);
        
        try {
            // Validate inputs
            const secretPath = SecretPath.from(path);
            
            if (!value || value.trim().length === 0) {
                throw new RepositoryError('Secret value cannot be empty');
            }
            
            // Check if secret already exists (optional - could be handled by repository)
            // For now, we'll just try to create it
            
            await this.repository.createSecret(secretPath.toString(), value, itemType);
            
            logger.info(` Secret saved successfully: ${path}`);
        } catch (error) {
            if (error instanceof RepositoryError) {
                throw error;
            }
            throw new RepositoryError(`Failed to save secret: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
}

