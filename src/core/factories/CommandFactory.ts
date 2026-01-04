import { ServiceContainer, SERVICE_KEYS } from '../container/ServiceContainer';
import { ICommand } from '../interfaces/ICommand';
import { RefreshCommand } from '../../presentation/commands/RefreshCommand';
import { ScanSecretsCommand } from '../../presentation/commands/ScanSecretsCommand';
import { SaveToAkeylessCommand } from '../../presentation/commands/SaveToAkeylessCommand';
import { CopySecretValueCommand } from '../../presentation/commands/CopySecretValueCommand';
import { ClearHighlightsCommand } from '../../presentation/commands/ClearHighlightsCommand';
import { SearchCommand } from '../../presentation/commands/SearchCommand';
import { LoadMoreCommand } from '../../presentation/commands/LoadMoreCommand';
import { FocusViewCommand } from '../../presentation/commands/FocusViewCommand';
import { logger } from '../../utils/logger';

/**
 * Command Factory
 * Creates and wires all command instances
 */
export class CommandFactory {
    /**
     * Creates all commands with their dependencies
     */
    static createAllCommands(container: ServiceContainer): ICommand[] {
        logger.info('🏭 Creating all commands...');

        const commands: ICommand[] = [];

        // Get required services
        const treeProvider = container.resolve<any>(SERVICE_KEYS.SECRETS_TREE_PROVIDER);
        const secretManagementService = container.resolve<any>(SERVICE_KEYS.SECRET_MANAGEMENT_SERVICE);
        const diagnosticsManager = container.resolve<any>(SERVICE_KEYS.DIAGNOSTICS_MANAGER);
        const highlightingManager = container.resolve<any>(SERVICE_KEYS.HIGHLIGHTING_MANAGER);
        const repository = container.resolve<any>(SERVICE_KEYS.AKEYLESS_REPOSITORY);

        // Create commands
        commands.push(new RefreshCommand(treeProvider));
        commands.push(new SearchCommand(treeProvider));
        commands.push(new LoadMoreCommand(treeProvider));
        commands.push(new CopySecretValueCommand(repository));
        commands.push(new SaveToAkeylessCommand(secretManagementService.saveUseCase, treeProvider));
        commands.push(new ScanSecretsCommand(
            secretManagementService.scanUseCase,
            diagnosticsManager,
            highlightingManager
        ));
        commands.push(new ClearHighlightsCommand(diagnosticsManager, highlightingManager));
        commands.push(new FocusViewCommand());

        logger.info(`✅ Created ${commands.length} commands`);
        return commands;
    }
}

