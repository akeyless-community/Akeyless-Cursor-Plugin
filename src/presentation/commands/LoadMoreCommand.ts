import { BaseCommand } from './base/BaseCommand';
import { SecretsTreeProvider } from '../../providers/secrets-tree-provider';

/**
 * Load More Command
 * Loads the next page of secrets
 */
export class LoadMoreCommand extends BaseCommand {
    constructor(private readonly treeProvider: SecretsTreeProvider) {
        super();
    }

    getId(): string {
        return 'akeyless.loadMore';
    }

    getTitle(): string {
        return 'Load More';
    }

    async execute(): Promise<void> {
        this.logExecution();
        
        try {
            await this.treeProvider.loadNextPage();
        } catch (error) {
            this.handleError(error, 'load more operation');
        }
    }
}

