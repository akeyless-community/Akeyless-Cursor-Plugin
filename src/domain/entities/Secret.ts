/**
 * Domain Entity: Secret
 * Represents a secret in Akeyless
 */
export class Secret {
    constructor(
        public readonly name: string,
        public readonly value: string,
        public readonly type: SecretType,
        public readonly metadata?: SecretMetadata
    ) {}

    /**
     * Checks if the secret is valid
     */
    isValid(): boolean {
        return this.name.length > 0 && this.value.length > 0;
    }

    /**
     * Gets the display name (last part of path)
     */
    getDisplayName(): string {
        const parts = this.name.split('/');
        return parts[parts.length - 1] || this.name;
    }
}

export enum SecretType {
    STATIC = 'STATIC_SECRET',
    DYNAMIC = 'DYNAMIC_SECRET',
    ROTATED = 'ROTATED_SECRET',
    CLASSIC_KEY = 'CLASSIC_KEY',
    FOLDER = 'FOLDER'
}

export interface SecretMetadata {
    itemId?: number;
    displayId?: string;
    subType?: string;
    tags?: any;
    isEnabled?: boolean;
    creationDate?: string;
    modificationDate?: string;
}

