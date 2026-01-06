import { HardcodedSecret } from './HardcodedSecret';

/**
 * Domain Entity: ScanResult
 * Represents the result of a secret scan operation
 */
export class ScanResult {
    constructor(
        public readonly secrets: HardcodedSecret[],
        public readonly totalFilesScanned: number,
        public readonly scanDate: Date = new Date(),
        public readonly filteredSecretsCount: number = 0,
        public readonly entropyThreshold: number = 4.0,
        public readonly filteredByFilename: number = 0,
        public readonly filteredByDenylist: number = 0,
        public readonly filteredByFunctionCall: number = 0,
        public readonly filteredByTestData: number = 0,
        public readonly filteredByStricterEntropy: number = 0,
        public readonly nonBase64EntropyDelta: number = 0
    ) {}

    /**
     * Gets the total number of secrets found
     */
    getTotalSecrets(): number {
        return this.secrets.length;
    }

    /**
     * Gets secrets grouped by file
     */
    getSecretsByFile(): Map<string, HardcodedSecret[]> {
        const grouped = new Map<string, HardcodedSecret[]>();
        for (const secret of this.secrets) {
            const fileSecrets = grouped.get(secret.fileName) || [];
            fileSecrets.push(secret);
            grouped.set(secret.fileName, fileSecrets);
        }
        return grouped;
    }

    /**
     * Checks if scan found any secrets
     */
    hasSecrets(): boolean {
        return this.secrets.length > 0;
    }
}

