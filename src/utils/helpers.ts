import { AkeylessItem } from '../types';

/**
 * Extracts the secret name from a full path
 * @param fullPath - The full path of the secret
 * @returns The secret name (part after last '/')
 */
export function extractSecretName(fullPath: string): string {
    const parts = fullPath.split('/');
    return parts[parts.length - 1] || fullPath;
}

/**
 * Formats item type to a readable format
 * @param itemType - The raw item type from API
 * @returns Formatted item type string
 */
export function formatItemType(itemType: string): string {
    switch (itemType) {
        case 'STATIC_SECRET':
            return 'Static Secret';
        case 'DYNAMIC_SECRET':
            return 'Dynamic Secret';
        case 'ROTATED_SECRET':
            return 'Rotated Secret';
        case 'FOLDER':
            return 'Folder';
        case 'CLASSIC_KEY':
            return 'Classic Key';
        default:
            return itemType;
    }
}

/**
 * Creates a mock AkeylessItem for display purposes
 * @param itemName - The name to display
 * @param itemType - The type of item
 * @returns A mock AkeylessItem
 */
export function createMockItem(itemName: string, itemType: string): AkeylessItem {
    return {
        item_name: itemName,
        item_id: 0,
        display_id: '',
        item_type: itemType,
        item_sub_type: '',
        item_metadata: '',
        item_tags: null,
        item_size: 0,
        last_version: 0,
        with_customer_fragment: false,
        is_enabled: false,
        public_value: '',
        certificates: '',
        protection_key_name: '',
        client_permissions: [],
        item_general_info: {},
        is_access_request_enabled: false,
        access_request_status: '',
        delete_protection: false,
        creation_date: '',
        modification_date: '',
        access_date_display: '',
        gateway_details: null
    };
}

/**
 * Validates if a string is a valid Access ID format
 * @param accessId - The access ID to validate
 * @returns True if valid format
 */
export function isValidAccessId(accessId: string): boolean {
    return accessId.startsWith('p-') && accessId.length > 2;
}

/**
 * Validates if a string is a valid Access Key format
 * @param accessKey - The access key to validate
 * @returns True if valid format
 */
export function isValidAccessKey(accessKey: string): boolean {
    return accessKey.length > 0;
}

/**
 * Debounces a function call
 * @param func - The function to debounce
 * @param wait - The wait time in milliseconds
 * @returns Debounced function
 */
export function debounce<T extends (...args: any[]) => any>(
    func: T,
    wait: number
): (...args: Parameters<T>) => void {
    let timeout: NodeJS.Timeout;
    return (...args: Parameters<T>) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => func(...args), wait);
    };
} 