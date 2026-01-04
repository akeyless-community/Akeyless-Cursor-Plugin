import { AkeylessItem, TreeItemStatus } from '../../types';

/**
 * Interface for Secrets Tree Provider
 * Abstracts the tree provider for dependency injection
 */
export interface ISecretsTreeProvider {
    refresh(): Promise<void>;
    setSearchTerm(term: string): void;
    loadNextPage(): Promise<{ itemsLoaded: number, nextToken: string | null, hasMore: boolean }>;
    getCachedItems(): Array<{ item: AkeylessItem; status: TreeItemStatus }>;
}

