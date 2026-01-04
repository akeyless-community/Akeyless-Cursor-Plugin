/**
 * Value Object: SecretPath
 * Immutable representation of a secret path
 */
export class SecretPath {
    private constructor(private readonly path: string) {
        if (!path || path.trim().length === 0) {
            throw new Error('Secret path cannot be empty');
        }
        if (!path.startsWith('/')) {
            throw new Error('Secret path must start with /');
        }
    }

    /**
     * Creates a SecretPath from a string
     */
    static from(path: string): SecretPath {
        return new SecretPath(path.trim());
    }

    /**
     * Gets the path as a string
     */
    toString(): string {
        return this.path;
    }

    /**
     * Gets the name (last segment) of the path
     */
    getName(): string {
        const parts = this.path.split('/').filter(p => p.length > 0);
        return parts[parts.length - 1] || '';
    }

    /**
     * Gets the parent path
     */
    getParent(): SecretPath | null {
        const parts = this.path.split('/').filter(p => p.length > 0);
        if (parts.length <= 1) {
            return null;
        }
        parts.pop();
        return SecretPath.from('/' + parts.join('/'));
    }

    /**
     * Checks if this path is a child of another path
     */
    isChildOf(parent: SecretPath): boolean {
        return this.path.startsWith(parent.toString() + '/');
    }

    /**
     * Equality check
     */
    equals(other: SecretPath): boolean {
        return this.path === other.path;
    }
}

