import { IAkeylessRepository } from '../../core/interfaces/IAkeylessRepository';
import { Secret, SecretType } from '../../domain/entities/Secret';
import { RepositoryError } from '../../core/errors';
import { logger } from '../../utils/logger';

/**
 * Use Case: List Secrets from Akeyless
 * Encapsulates the business logic for listing secrets
 */
export class ListSecretsUseCase {
    constructor(private readonly repository: IAkeylessRepository) {}

    /**
     * Lists all secrets from Akeyless
     */
    async execute(): Promise<Secret[]> {
        logger.info('📋 Executing list secrets use case');
        
        try {
            const items = await this.repository.listItems();
            
            // Convert to domain entities
            return items.map(item => new Secret(
                item.item_name,
                item.public_value || '',
                this.mapItemType(item.item_type),
                {
                    itemId: item.item_id,
                    displayId: item.display_id,
                    subType: item.item_sub_type,
                    tags: item.item_tags,
                    isEnabled: item.is_enabled,
                    creationDate: item.creation_date,
                    modificationDate: item.modification_date
                }
            ));
        } catch (error) {
            logger.error('❌ Error in list secrets use case:', error);
            if (error instanceof RepositoryError) {
                throw error;
            }
            throw new RepositoryError(`Failed to list secrets: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Searches for secrets by pattern
     */
    async search(pattern: string): Promise<Secret[]> {
        logger.info(`🔍 Executing search secrets use case: ${pattern}`);
        
        try {
            const items = await this.repository.searchSecrets(pattern);
            
            return items.map(item => new Secret(
                item.item_name,
                item.public_value || '',
                this.mapItemType(item.item_type),
                {
                    itemId: item.item_id,
                    displayId: item.display_id,
                    subType: item.item_sub_type
                }
            ));
        } catch (error) {
            logger.error('❌ Error in search secrets use case:', error);
            throw new RepositoryError(`Failed to search secrets: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    private mapItemType(itemType: string): SecretType {
        switch (itemType) {
            case 'STATIC_SECRET':
                return SecretType.STATIC;
            case 'DYNAMIC_SECRET':
                return SecretType.DYNAMIC;
            case 'ROTATED_SECRET':
                return SecretType.ROTATED;
            case 'CLASSIC_KEY':
                return SecretType.CLASSIC_KEY;
            case 'FOLDER':
                return SecretType.FOLDER;
            default:
                return SecretType.STATIC;
        }
    }
}

