import * as vscode from 'vscode';
import { SecretsTreeProvider } from './secrets-tree-provider';
import { logger } from '../utils/logger';
import { AkeylessItem } from '../types';

/**
 * Provides autocomplete suggestions for Akeyless secret names while coding
 */
export class SecretCompletionProvider implements vscode.CompletionItemProvider {
    private secretsTreeProvider: SecretsTreeProvider;

    constructor(secretsTreeProvider: SecretsTreeProvider) {
        this.secretsTreeProvider = secretsTreeProvider;
        logger.info('💡 SecretCompletionProvider initialized');
    }

    /**
     * Provides completion items for Akeyless secret names
     */
    provideCompletionItems(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken,
        context: vscode.CompletionContext
    ): vscode.ProviderResult<vscode.CompletionItem[] | vscode.CompletionList> {
        try {
            // Get the line text up to the cursor position
            const linePrefix = document.lineAt(position).text.substring(0, position.character);
            
            // Check if we're in a context where secret names might be used
            // Common patterns: config files, environment variables, string literals, etc.
            const shouldSuggest = this.shouldSuggestSecrets(linePrefix, document);
            
            if (!shouldSuggest) {
                return [];
            }

            // Get cached secrets from the tree provider
            const cachedItems = this.secretsTreeProvider.getCachedItems();
            
            if (!cachedItems || cachedItems.length === 0) {
                logger.debug('No cached secrets available for autocomplete');
                return [];
            }

            // Extract secret names from cached items
            const secretNames = cachedItems
                .filter(item => item.status.type === 'normal' && item.item)
                .map(item => item.item.item_name)
                .filter((name, index, self) => self.indexOf(name) === index); // Remove duplicates

            if (secretNames.length === 0) {
                return [];
            }

            // Get item details for better completion info
            const itemMap = new Map<string, AkeylessItem>();
            cachedItems
                .filter(item => item.status.type === 'normal' && item.item)
                .forEach(item => {
                    if (!itemMap.has(item.item.item_name)) {
                        itemMap.set(item.item.item_name, item.item);
                    }
                });

            // Create completion items
            const completionItems: vscode.CompletionItem[] = secretNames.map(secretName => {
                const item = itemMap.get(secretName);
                const secretNameOnly = secretName.split('/').pop() || secretName;
                
                const completionItem = new vscode.CompletionItem(
                    {
                        label: secretName,
                        description: item ? `${item.item_type}${item.item_sub_type ? ` • ${item.item_sub_type}` : ''}` : ''
                    },
                    vscode.CompletionItemKind.Value
                );

                // Use the full path as the insert text
                completionItem.insertText = secretName;
                
                // Add documentation with type information
                let docText = `**Akeyless Secret**\n\n`;
                docText += `**Path:** \`${secretName}\`\n\n`;
                if (item) {
                    docText += `**Type:** ${item.item_type}`;
                    if (item.item_sub_type) {
                        docText += ` (${item.item_sub_type})`;
                    }
                    docText += `\n\n`;
                }
                docText += `Use this path to reference the secret stored in Akeyless.`;
                
                completionItem.documentation = new vscode.MarkdownString(docText);

                // Add detail showing it's from Akeyless
                completionItem.detail = `Akeyless Secret${item ? ` • ${item.item_type}` : ''}`;
                
                // Set filter text to help with matching (include both full path and name)
                completionItem.filterText = `${secretName} ${secretNameOnly}`;
                
                // Add a sort text to prioritize shorter/more relevant names
                // Prioritize by depth (fewer slashes = higher priority)
                const depth = (secretName.match(/\//g) || []).length;
                completionItem.sortText = `${String(depth).padStart(3, '0')}_${secretName}`;

                return completionItem;
            });

            // Filter based on what user is typing
            const filteredItems = this.filterCompletions(completionItems, linePrefix);

            logger.debug(`💡 Providing ${filteredItems.length} secret name suggestions`);
            
            return new vscode.CompletionList(filteredItems, false);
            
        } catch (error) {
            logger.error('Error providing completion items:', error);
            return [];
        }
    }

    /**
     * Determines if we should suggest secrets based on the context
     */
    private shouldSuggestSecrets(linePrefix: string, document: vscode.TextDocument): boolean {
        const fileName = document.fileName.toLowerCase();
        const languageId = document.languageId;

        // Always suggest in config files
        if (fileName.includes('.env') || 
            fileName.includes('config') || 
            fileName.includes('settings') ||
            fileName.includes('secrets') ||
            fileName.includes('credentials')) {
            return true;
        }

        // Suggest in string contexts (quoted strings) - most common case
        const inStringContext = this.isInStringContext(linePrefix);
        if (inStringContext) {
            // Check if we're after a key that suggests a secret value
            const keyPattern = /(?:secret|password|api[_-]?key|token|credential|value|akeyless)[\s:=]+["'`]?/i;
            if (keyPattern.test(linePrefix)) {
                return true;
            }
            // Also suggest if we're typing a path-like string (starts with /)
            if (linePrefix.match(/["'`][^"'`]*\/[^"'`]*$/)) {
                return true;
            }
        }

        // Suggest after common patterns
        const commonPatterns = [
            /akeyless/i,
            /secret/i,
            /password/i,
            /api[_-]?key/i,
            /token/i,
            /credential/i,
            /config/i,
            /env/i,
            /value/i,
            /getSecret/i,
            /get.*secret/i
        ];

        for (const pattern of commonPatterns) {
            if (pattern.test(linePrefix)) {
                return true;
            }
        }

        // Suggest in YAML/JSON files (common for config)
        if (['yaml', 'yml', 'json', 'jsonc'].includes(languageId)) {
            return true;
        }

        // Suggest in environment variable files
        if (languageId === 'properties' || fileName.endsWith('.env')) {
            return true;
        }

        return false;
    }

    /**
     * Checks if cursor is inside a string literal
     */
    private isInStringContext(linePrefix: string): boolean {
        // Simple check: count quotes (single and double)
        const singleQuotes = (linePrefix.match(/'/g) || []).length;
        const doubleQuotes = (linePrefix.match(/"/g) || []).length;
        
        // If odd number of quotes, we're likely inside a string
        return (singleQuotes % 2 === 1) || (doubleQuotes % 2 === 1);
    }

    /**
     * Filters completion items based on what the user is typing
     */
    private filterCompletions(
        items: vscode.CompletionItem[],
        linePrefix: string
    ): vscode.CompletionItem[] {
        // Extract potential search term from line prefix
        // Look for text after common patterns like "=", ":", quotes, etc.
        const match = linePrefix.match(/(?:["'`]?)([^"'`=\s:]+)$/);
        const searchTerm = match ? match[1].toLowerCase() : '';

        if (!searchTerm || searchTerm.length < 1) {
            // If no search term, return all items (VS Code will handle filtering)
            return items;
        }

        // Filter items that match the search term
        return items.filter(item => {
            const label = typeof item.label === 'string' 
                ? item.label 
                : item.label.label;
            
            return label.toLowerCase().includes(searchTerm) ||
                   label.toLowerCase().split('/').some(part => part.includes(searchTerm));
        });
    }
}

