import { ISecretScanner } from '../../core/interfaces/ISecretScanner';
import { ScanResult } from '../../domain/entities/ScanResult';
import { HardcodedSecret } from '../../domain/entities/HardcodedSecret';
import { HardcodedSecret as OldHardcodedSecret } from '../../utils/secret-scanner/types';
import { logger } from '../../utils/logger';

/**
 * Use Case: Scan for Hardcoded Secrets
 * Encapsulates the business logic for scanning code for secrets
 */
export class ScanForSecretsUseCase {
    constructor(private readonly scanner: ISecretScanner) {}

    /**
     * Scans the current project for hardcoded secrets
     */
    async execute(): Promise<ScanResult> {
        logger.info(' Executing scan for secrets use case');
        
        try {
            const result = await this.scanner.scanCurrentProject();
            
            // Convert to domain entities
            const secrets: HardcodedSecret[] = [];
            for (const [_fileName, fileSecrets] of result.results.entries()) {
                for (const secret of fileSecrets) {
                    secrets.push(this.convertToDomainEntity(secret));
                }
            }
            
            return new ScanResult(secrets, result.totalFilesScanned);
        } catch (error) {
            logger.error(' Error in scan for secrets use case:', error);
            throw error;
        }
    }

    /**
     * Scans a single file
     */
    async scanFile(): Promise<ScanResult> {
        logger.info(' Executing single file scan use case');
        
        try {
            const result = await this.scanner.scanCurrentFile();
            
            const secrets: HardcodedSecret[] = [];
            for (const [_fileName, fileSecrets] of result.results.entries()) {
                for (const secret of fileSecrets) {
                    secrets.push(this.convertToDomainEntity(secret));
                }
            }
            
            return new ScanResult(secrets, result.totalFilesScanned);
        } catch (error) {
            logger.error(' Error in single file scan use case:', error);
            throw error;
        }
    }

    /**
     * Converts old HardcodedSecret interface to domain entity
     */
    private convertToDomainEntity(secret: OldHardcodedSecret): HardcodedSecret {
        return new HardcodedSecret(
            secret.fileName,
            secret.lineNumber,
            secret.column,
            secret.value,
            secret.type,
            secret.context
        );
    }
}

