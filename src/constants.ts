// Extension constants and configuration
export const EXTENSION_NAME = 'akeyless-secrets-manager';
export const EXTENSION_DISPLAY_NAME = 'Akeyless Secrets Manager';



// Command IDs
export const COMMANDS = {
    SIGN_IN: 'akeyless.signIn',
    REFRESH: 'akeyless.refresh',
    SEARCH: 'akeyless.search',
    LOAD_MORE: 'akeyless.loadMore',
    COPY_SECRET_VALUE: 'akeyless.copySecretValue',
    COPY_USERNAME: 'akeyless.copyUsername',
    COPY_PASSWORD: 'akeyless.copyPassword',
    SAVE_TO_AKEYLESS: 'akeyless.saveToAkeyless',
    SCAN_HARDCODED_SECRETS: 'akeyless.scanHardcodedSecrets',
    CLEAR_SECRET_HIGHLIGHTS: 'akeyless.clearSecretHighlights'
} as const;

// View IDs
export const VIEWS = {
    SECRETS_EXPLORER: 'akeyless-secrets-explorer'
} as const;

// Item Types (CLI returns uppercase)
export const ITEM_TYPES = {
    STATIC_SECRET: 'STATIC_SECRET',
    DYNAMIC_SECRET: 'DYNAMIC_SECRET',
    ROTATED_SECRET: 'ROTATED_SECRET',
    FOLDER: 'FOLDER',
    CLASSIC_KEY: 'CLASSIC_KEY'
} as const;

export const ITEM_SUB_TYPES = {
    GENERIC: 'generic',
    PASSWORD: 'password',
    SSH: 'ssh',
    CERTIFICATE: 'certificate',
    API_KEY: 'api-key',
    DATABASE: 'database',
    AWS: 'aws',
    AZURE: 'azure',
    GCP: 'gcp'
} as const;

export const FILTERED_ITEM_TYPES = [
    ITEM_TYPES.STATIC_SECRET,
    ITEM_TYPES.DYNAMIC_SECRET,
    ITEM_TYPES.ROTATED_SECRET,
    ITEM_TYPES.CLASSIC_KEY
] as const;

export const FILTERED_ITEM_SUB_TYPES = [
    ITEM_SUB_TYPES.GENERIC,
    ITEM_SUB_TYPES.PASSWORD
] as const;

// Status Types
export const STATUS_TYPES = {
    NORMAL: 'normal',
    SUCCESS: 'success',
    ERROR: 'error',
    LOADING: 'loading',
    AUTH_REQUIRED: 'auth-required',
    EMPTY: 'empty',
    WAITING: 'waiting',
    LOAD_MORE: 'load-more'
} as const;

// Icon paths
export const ICONS = {
    AKEYLESS_LOGO: 'resources/icons/akeyless-logo.svg',
    STATIC_SECRET: 'resources/icons/static-secret.svg',
    DYNAMIC_SECRET: 'resources/icons/dynamic-secret.svg',
    ROTATED_SECRET: 'resources/icons/rotated-secret.svg',
    PASSWORD: 'resources/icons/password-icon.svg',
    KEY: 'resources/icons/static-secret.svg',
    FOLDER: 'resources/icons/folder-icon.svg',
    // Status icons (using VS Code theme icons)
    ERROR: { icon: 'error', color: 'errorForeground' },
    LOADING: { icon: 'loading~spin', color: 'progressBar.background' },
    AUTH_REQUIRED: { icon: 'key', color: 'notificationsInfoIcon.foreground' },
    EMPTY: { icon: 'info', color: 'notificationsInfoIcon.foreground' },
    LOAD_MORE: { icon: 'refresh', color: 'notificationsInfoIcon.foreground' }
} as const;

// Messages
export const MESSAGES = {
    EXTENSION_LOADED: 'Akeyless Secrets Manager loaded! Click the Akeyless icon in the sidebar.',
    AUTHENTICATING: 'Authenticating with Akeyless...',
    AUTH_SUCCESS: 'Successfully authenticated with Akeyless!',
    AUTH_FAILED: 'Authentication failed. Please check your credentials.',
    REFRESHING: 'Refreshing Akeyless secrets...',
    REFRESH_SUCCESS: 'Secrets refreshed successfully!',
    REFRESH_FAILED: 'Failed to refresh secrets',
    SEARCHING: 'Searching for:',
    SEARCH_CLEARED: 'Cleared search filter',
    SEARCH_FAILED: 'Search failed',
    NO_ITEMS: 'No secrets found in your Akeyless account',
    NOT_AUTHENTICATED: 'Not authenticated - Click "Sign In" button above',
    CLICK_TO_LOAD: 'Click "Sign In" to load secrets',
    ERROR_LOADING: 'Error loading secrets:',
    COPY_SECRET_VALUE_SUCCESS: 'Secret value copied to clipboard!',
    COPY_SECRET_VALUE_FAILED: 'Failed to copy secret value',
    COPY_USERNAME_SUCCESS: 'Username copied to clipboard!',
    COPY_USERNAME_FAILED: 'Failed to copy username',
    COPY_PASSWORD_SUCCESS: 'Password copied to clipboard!',
    COPY_PASSWORD_FAILED: 'Failed to copy password'
} as const;

 