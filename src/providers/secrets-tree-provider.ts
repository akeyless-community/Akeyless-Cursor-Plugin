import * as vscode from 'vscode';
import * as path from 'path';
import { AkeylessCLI } from '../services/akeyless-cli';
import { AkeylessItem, TreeItemStatus } from '../types';
import { ICONS, MESSAGES, STATUS_TYPES, VIEWS } from '../constants';
import { logger } from '../utils/logger';
import { extractSecretName, formatItemType, createMockItem } from '../utils/helpers';

export class SecretsTreeProvider implements vscode.TreeDataProvider<SecretTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<SecretTreeItem | undefined | null | void> = new vscode.EventEmitter<SecretTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<SecretTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;
    
    private cachedItems: SecretTreeItem[] = [];
    private searchTerm: string = '';
    private nextPageToken: string | null = null;
    private isLoading: boolean = false;
    private hasMorePages: boolean = true;

    constructor(private akeylessCLI: AkeylessCLI) {
        logger.info('🌳 SecretsTreeProvider initialized');
    }

    setSearchTerm(term: string): void {
        logger.info('🔍 Setting search term:', term);
        this.searchTerm = term.toLowerCase();
        this._onDidChangeTreeData.fire();
    }

    async refresh(): Promise<void> {
        logger.info('🔄 Manual refresh initiated');
        
        // Clear cache to force fresh data
        this.cachedItems = [];
        this.nextPageToken = null;
        this.hasMorePages = true;
        this.isLoading = false;
        this._onDidChangeTreeData.fire();
    }

    /**
     * Loads the next page of items
     */
    async loadNextPage(): Promise<{ itemsLoaded: number, nextToken: string | null, hasMore: boolean }> {
        if (this.isLoading || !this.hasMorePages) {
            logger.info(`🚫 Skipping load - isLoading: ${this.isLoading}, hasMorePages: ${this.hasMorePages}`);
            return { itemsLoaded: 0, nextToken: this.nextPageToken, hasMore: this.hasMorePages };
        }

        this.isLoading = true;
        logger.info(`🔄 Starting to load next page...`);
        logger.info(`📊 Current state - Cached items: ${this.cachedItems.length}, Next token: ${this.nextPageToken || 'none'}, Has more: ${this.hasMorePages}`);
        
        try {
            const tokenParam = this.nextPageToken ? `--pagination-token "${this.nextPageToken}"` : '';
            logger.info(`📡 Making CLI call: akeyless list-items --json ${tokenParam}`);
            
            const result = await this.akeylessCLI.listItemsPage(this.nextPageToken || undefined);
            
            logger.info(`✅ CLI call successful!`);
            logger.info(`📦 Received ${result.items.length} items from page`);
            logger.info(`📄 Next page token: ${result.nextPage || 'null'}`);
            
            if (result.items.length > 0) {
                logger.info(`📋 Sample items from this page:`);
                result.items.slice(0, 3).forEach((item, index) => {
                    logger.info(`   ${index + 1}. ${item.item_name} (${item.item_type})`);
                });
            }
            
            let itemsLoaded = 0;
            if (result.items.length > 0) {
                const treeItems = result.items.map(item => new SecretTreeItem(item, { type: STATUS_TYPES.NORMAL }));
                this.cachedItems.push(...treeItems);
                itemsLoaded = treeItems.length;
                logger.info(`✅ Added ${treeItems.length} items to cache`);
            }
            
            this.nextPageToken = result.nextPage;
            this.hasMorePages = result.nextPage !== null;
            
            logger.info(`📊 Updated state - Total cached items: ${this.cachedItems.length}`);
            logger.info(`🔄 Has more pages: ${this.hasMorePages}`);
            
            if (!this.hasMorePages) {
                logger.info('✅ No more pages available');
            }
            
            return { itemsLoaded, nextToken: result.nextPage, hasMore: this.hasMorePages };
            
        } catch (error) {
            logger.error('❌ Error loading next page:', error);
            this.hasMorePages = false;
            logger.info(`🔄 Set hasMorePages to false due to error`);
            this.cachedItems.push(new SecretTreeItem(createMockItem(`${MESSAGES.ERROR_LOADING} ${error}`, 'ERROR'), { type: STATUS_TYPES.ERROR }));
            return { itemsLoaded: 0, nextToken: null, hasMore: false };
        } finally {
            this.isLoading = false;
            logger.info(`🏁 Finished loading attempt. isLoading: ${this.isLoading}`);
            this._onDidChangeTreeData.fire();
            logger.info(`🔄 UI refresh triggered`);
        }
    }

    getTreeItem(element: SecretTreeItem): vscode.TreeItem {
        return element;
    }

    async getChildren(element?: SecretTreeItem): Promise<SecretTreeItem[]> {
        if (element) {
            // If element is a folder, return its children
            if (element.item.item_type === 'FOLDER') {
                return this.getFolderChildren(element.item.item_name);
            }
            return [];
        }

        // Root level - load first page if no items cached
        if (this.cachedItems.length === 0 && !this.isLoading && this.hasMorePages) {
            // Show loading state
            this._onDidChangeTreeData.fire();
            
            // Load first page
            await this.loadNextPage();
            
            // Return the updated children
            return this.getChildren();
        }

        if (this.cachedItems.length === 0 && !this.hasMorePages) {
            return [new SecretTreeItem(createMockItem('No secrets found', 'EMPTY'), { type: STATUS_TYPES.EMPTY } as TreeItemStatus)];
        }

        // Apply search filter to cached items
        const filteredItems = this.filterItems(this.cachedItems);
        
        if (filteredItems.length === 0 && this.searchTerm) {
            return [new SecretTreeItem(createMockItem(`No secrets found matching "${this.searchTerm}"`, 'EMPTY'), { type: STATUS_TYPES.EMPTY } as TreeItemStatus)];
        }

        // Create hierarchical structure with filtered items
        const hierarchicalItems = this.createHierarchicalStructure(filteredItems);
        
        // Add "Load More" item at the bottom if there are more pages (but not during search)
        if (this.hasMorePages && !this.isLoading && !this.searchTerm) {
            const loadMoreItem = new SecretTreeItem(createMockItem('Load More...', 'LOAD_MORE'), { type: STATUS_TYPES.LOAD_MORE } as TreeItemStatus);
            hierarchicalItems.push(loadMoreItem);
        } else if (this.isLoading && !this.searchTerm) {
            const loadingItem = new SecretTreeItem(createMockItem('Loading...', 'LOADING'), { type: STATUS_TYPES.LOADING } as TreeItemStatus);
            hierarchicalItems.push(loadingItem);
        }
        
        return hierarchicalItems;
    }

    private createHierarchicalStructure(items: SecretTreeItem[]): SecretTreeItem[] {
        const folderMap = new Map<string, SecretTreeItem[]>();
        const rootItems: SecretTreeItem[] = [];
        
        // When searching, track which folders contain matching items
        const matchingFolders = new Set<string>();
        if (this.searchTerm) {
            for (const item of items) {
                if (item.status.type === STATUS_TYPES.NORMAL) {
                    const pathParts = item.item.item_name.split('/').filter(part => part.length > 0);
                    if (pathParts.length > 1) {
                        // Add all parent folders of this matching item
                        let currentPath = '';
                        for (let i = 0; i < pathParts.length - 1; i++) {
                            currentPath += `/${pathParts[i]}`;
                            matchingFolders.add(currentPath);
                        }
                    }
                }
            }
        }

        for (const item of items) {
            const pathParts = item.item.item_name.split('/').filter(part => part.length > 0);
            
            if (pathParts.length === 1) {
                // Root level item
                rootItems.push(item);
            } else if (pathParts.length > 1) {
                // Item with path - create nested folder structure
                const itemName = pathParts[pathParts.length - 1]; // Last part is the item name
                const folderPath = pathParts.slice(0, -1); // All parts except last are folders
                
                // Create nested folder structure
                let currentLevel = rootItems;
                let currentPath = '';
                
                for (let i = 0; i < folderPath.length; i++) {
                    const folderName = folderPath[i];
                    currentPath += `/${folderName}`;
                    
                    // When searching, only create folders that contain matching items
                    if (this.searchTerm && !matchingFolders.has(currentPath)) {
                        continue;
                    }
                    
                    // Find or create folder at current level
                    let folderItem = currentLevel.find(item => 
                        item.item.item_type === 'FOLDER' && 
                        item.item.item_name === currentPath
                    );
                    
                    if (!folderItem) {
                        // Create new folder
                        const folderItemData = createMockItem(folderName, 'FOLDER');
                        folderItemData.item_name = currentPath;
                        folderItem = new SecretTreeItem(folderItemData, { type: STATUS_TYPES.SUCCESS } as TreeItemStatus);
                        currentLevel.push(folderItem);
                        folderMap.set(currentPath, []);
                    }
                    
                    // Move to next level (folder children)
                    if (i === folderPath.length - 1) {
                        // This is the final folder level, add the item here
                        const childItem = { ...item.item };
                        childItem.item_name = itemName;
                        const childTreeItem = new SecretTreeItem(childItem, { type: STATUS_TYPES.SUCCESS } as TreeItemStatus);
                        folderMap.get(currentPath)!.push(childTreeItem);
                    } else {
                        // This is an intermediate folder, continue to next level
                        currentLevel = folderMap.get(currentPath) || [];
                    }
                }
            }
        }

        // Add folder children
        for (const [folderPath, children] of folderMap) {
            const folderItem = rootItems.find(item => 
                item.item.item_type === 'FOLDER' && 
                item.item.item_name === folderPath
            );
            if (folderItem) {
                folderItem.children = children;
            }
        }

        return rootItems;
    }

    private getFolderChildren(folderPath: string): SecretTreeItem[] {
        if (!this.cachedItems) return [];
        
        const folderName = folderPath.replace('/', '');
        const folderDepth = folderPath.split('/').filter(part => part.length > 0).length;
        
        const children = this.cachedItems
            .filter(item => {
                const pathParts = item.item.item_name.split('/').filter(part => part.length > 0);
                const itemDepth = pathParts.length;
                
                // Check if this item belongs to this folder level
                if (itemDepth <= folderDepth) return false;
                
                // Check if the path starts with this folder path
                const itemPath = '/' + pathParts.slice(0, folderDepth).join('/');
                if (itemPath !== folderPath) return false;
                
                // When searching, only include items that match the search term
                if (this.searchTerm) {
                    const itemName = pathParts[pathParts.length - 1];
                    const fullItemName = item.item.item_name;
                    return itemName.toLowerCase().includes(this.searchTerm) ||
                           fullItemName.toLowerCase().includes(this.searchTerm) ||
                           item.item.item_type.toLowerCase().includes(this.searchTerm);
                }
                
                return true;
            })
            .map(item => {
                const pathParts = item.item.item_name.split('/').filter(part => part.length > 0);
                const itemName = pathParts[pathParts.length - 1];
                const remainingPath = pathParts.slice(folderDepth);
                
                if (remainingPath.length === 1) {
                    // This is a direct child (secret item)
                    const childItem = { ...item.item };
                    childItem.item_name = itemName;
                    return new SecretTreeItem(childItem, { type: STATUS_TYPES.SUCCESS } as TreeItemStatus);
                } else {
                    // This is a subfolder
                    const subfolderName = remainingPath[0];
                    const subfolderPath = folderPath + '/' + subfolderName;
                    const subfolderItem = createMockItem(subfolderName, 'FOLDER');
                    subfolderItem.item_name = subfolderPath;
                    return new SecretTreeItem(subfolderItem, { type: STATUS_TYPES.SUCCESS } as TreeItemStatus);
                }
            });
        
        return children;
    }



    private filterItems(items: SecretTreeItem[]): SecretTreeItem[] {
        if (!this.searchTerm) {
            return items;
        }
        
        const filtered = items.filter(item => {
            if (item.status.type !== STATUS_TYPES.NORMAL) {
                return true; // Keep non-normal items (errors, loading, etc.)
            }
            return item.item.item_name.toLowerCase().includes(this.searchTerm) ||
                   item.item.item_type.toLowerCase().includes(this.searchTerm);
        });
        
        logger.debug(`🔍 Filtered ${items.length} items to ${filtered.length} items for search term: "${this.searchTerm}"`);
        return filtered;
    }

    /**
     * Gets the current search term
     */
    getCurrentSearchTerm(): string {
        return this.searchTerm || '';
    }

    /**
     * Gets the cached items for external access
     */
    getCachedItems(): SecretTreeItem[] {
        return this.cachedItems;
    }

    /**
     * Gets whether there are more pages to load
     */
    hasMorePagesToLoad(): boolean {
        return this.hasMorePages && !this.isLoading;
    }

    /**
     * Gets the current next page token
     */
    getNextPageToken(): string | null {
        return this.nextPageToken;
    }

    /**
     * Triggers loading the next page when user scrolls to bottom
     */
    async onScrollToBottom(): Promise<{ itemsLoaded: number, nextToken: string | null, hasMore: boolean }> {
        logger.info(`📜 onScrollToBottom called - hasMorePagesToLoad: ${this.hasMorePagesToLoad()}`);
        if (this.hasMorePagesToLoad()) {
            logger.info('📜 User scrolled to bottom, loading next page...');
            return await this.loadNextPage();
        } else {
            logger.info('📜 Scroll detected but no more pages to load or currently loading');
            return { itemsLoaded: 0, nextToken: this.nextPageToken, hasMore: this.hasMorePages };
        }
    }
}

export class SecretTreeItem extends vscode.TreeItem {
    public readonly status: TreeItemStatus;
    public iconPath: vscode.ThemeIcon | { light: vscode.Uri; dark: vscode.Uri } | undefined;
    public tooltip: string | undefined;
    public contextValue: string | undefined;
    public description: string | undefined;
    public resourceUri: vscode.Uri | undefined;
    public children?: SecretTreeItem[];

    constructor(
        public readonly item: AkeylessItem,
        status: TreeItemStatus
    ) {
        // Extract the secret name (part after last /)
        const secretName = extractSecretName(item.item_name);
        
        // Set collapsible state based on item type
        const collapsibleState = item.item_type === 'FOLDER' 
            ? vscode.TreeItemCollapsibleState.Collapsed 
            : vscode.TreeItemCollapsibleState.None;
        
        super(secretName, collapsibleState);
        
        this.item = item;
        this.status = status;
        
        // Don't show type description - just show the secret name
        this.description = undefined;
        
        // Set human-readable tooltip with type and subtype
        this.tooltip = this.formatTypeForTooltip(item.item_type, item.item_sub_type);
        
        // Set icon and context value based on status
        switch (status.type) {
            case STATUS_TYPES.ERROR:
                this.iconPath = new vscode.ThemeIcon(ICONS.ERROR.icon, new vscode.ThemeColor(ICONS.ERROR.color));
                this.contextValue = 'akeyless-error';
                break;
            case STATUS_TYPES.LOADING:
                this.iconPath = new vscode.ThemeIcon(ICONS.LOADING.icon, new vscode.ThemeColor(ICONS.LOADING.color));
                this.contextValue = 'akeyless-loading';
                break;
            case STATUS_TYPES.AUTH_REQUIRED:
                // Use Akeyless logo for authentication required
                const authIconPath = path.join(__dirname, '..', '..', ICONS.AKEYLESS_LOGO);
                logger.debug(`🔐 Using Akeyless logo for auth required: ${authIconPath}`);
                this.iconPath = {
                    light: vscode.Uri.file(authIconPath),
                    dark: vscode.Uri.file(authIconPath)
                };
                this.contextValue = 'akeyless-auth-required';
                break;
            case STATUS_TYPES.EMPTY:
                this.iconPath = new vscode.ThemeIcon(ICONS.EMPTY.icon, new vscode.ThemeColor(ICONS.EMPTY.color));
                this.contextValue = 'akeyless-empty';
                break;
            case STATUS_TYPES.LOAD_MORE:
                this.iconPath = new vscode.ThemeIcon(ICONS.LOAD_MORE.icon, new vscode.ThemeColor(ICONS.LOAD_MORE.color));
                this.contextValue = 'akeyless-load-more';
                break;
            default:
                // Set icon based on item type with custom SVG icons
                const iconConfig = this.getIconForItemType(item.item_type, item.item_sub_type); // Pass sub_type
                logger.debug(`🎨 Icon config for ${item.item_name}:`, iconConfig);
                
                if (iconConfig.icon.startsWith('resources/')) {
                    // Use custom SVG icon
                    const iconPath = path.join(__dirname, '..', '..', iconConfig.icon);
                    logger.debug(`📁 Using custom SVG icon: ${iconPath}`);
                    this.iconPath = {
                        light: vscode.Uri.file(iconPath),
                        dark: vscode.Uri.file(iconPath)
                    };
                } else {
                    // Use VS Code theme icon
                    this.iconPath = new vscode.ThemeIcon(iconConfig.icon, new vscode.ThemeColor(iconConfig.color));
                }

                // Set context value with item type information for context menu filtering
                this.contextValue = `akeyless-item-${item.item_type}-${item.item_sub_type || 'unknown'}`;
        }
    }

    private getIconForItemType(itemType: string, itemSubType?: string): { icon: string; color: string } {
        // Only check item_sub_type for password detection
        if (itemSubType === 'password') {
            return { icon: ICONS.PASSWORD, color: 'charts.grey' };
        }
        
        // Use item_type for all other cases
        switch (itemType) {
            case 'STATIC_SECRET':
                return { icon: ICONS.STATIC_SECRET, color: 'charts.green' };
            case 'DYNAMIC_SECRET':
                return { icon: ICONS.DYNAMIC_SECRET, color: 'charts.orange' };
            case 'ROTATED_SECRET':
                return { icon: ICONS.ROTATED_SECRET, color: 'charts.purple' };
            case 'FOLDER':
                return { icon: ICONS.FOLDER, color: 'charts.blue' };
            case 'CLASSIC_KEY':
                return { icon: ICONS.KEY, color: 'charts.red' };

            default:
                return { icon: ICONS.PASSWORD, color: 'charts.grey' };
        }
    }

    private formatTypeForTooltip(itemType: string, itemSubType?: string): string {
        // Format item type to human-readable
        const formatType = (type: string): string => {
            return type.toLowerCase()
                .split('_')
                .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                .join(' ');
        };

        const readableType = formatType(itemType);
        
        if (itemSubType && itemSubType !== 'unknown') {
            const readableSubType = formatType(itemSubType);
            return `${readableType} (${readableSubType})`;
        }
        
        return readableType;
    }
} 