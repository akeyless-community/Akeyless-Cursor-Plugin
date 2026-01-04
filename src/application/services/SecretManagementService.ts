import { IAkeylessRepository } from '../../core/interfaces/IAkeylessRepository';
import { ISecretScanner } from '../../core/interfaces/ISecretScanner';
import { ScanForSecretsUseCase } from '../use-cases/ScanForSecretsUseCase';
import { SaveSecretUseCase } from '../use-cases/SaveSecretUseCase';
import { ListSecretsUseCase } from '../use-cases/ListSecretsUseCase';
import { GetSecretValueUseCase } from '../use-cases/GetSecretValueUseCase';

/**
 * Secret Management Service
 * Facade pattern - provides simplified interface to complex subsystem
 */
export class SecretManagementService {
    public readonly scanUseCase: ScanForSecretsUseCase;
    public readonly saveUseCase: SaveSecretUseCase;
    public readonly listUseCase: ListSecretsUseCase;
    public readonly getValueUseCase: GetSecretValueUseCase;

    constructor(
        repository: IAkeylessRepository,
        scanner: ISecretScanner
    ) {
        this.scanUseCase = new ScanForSecretsUseCase(scanner);
        this.saveUseCase = new SaveSecretUseCase(repository);
        this.listUseCase = new ListSecretsUseCase(repository);
        this.getValueUseCase = new GetSecretValueUseCase(repository);
    }
}

