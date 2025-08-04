export interface AkeylessItem {
    item_name: string;
    item_id: number;
    display_id: string;
    item_type: string;
    item_sub_type: string;
    item_metadata: string;
    item_tags: any;
    item_size: number;
    last_version: number;
    with_customer_fragment: boolean;
    is_enabled: boolean;
    public_value: string;
    certificates: string;
    protection_key_name: string;
    client_permissions: string[];
    item_general_info: any;
    is_access_request_enabled: boolean;
    access_request_status: string;
    delete_protection: boolean;
    creation_date: string;
    modification_date: string;
    access_date_display: string;
    gateway_details: any;
}



export interface TreeItemStatus {
    type: 'normal' | 'success' | 'error' | 'loading' | 'auth-required' | 'empty' | 'load-more';
    message?: string;
} 