/**
 * Domain Entity: HardcodedSecret
 * Represents a detected hardcoded secret in code
 */
export class HardcodedSecret {
    constructor(
        public readonly fileName: string,
        public readonly lineNumber: number,
        public readonly column: number,
        public readonly value: string,
        public readonly type: string,
        public readonly context: string,
        public readonly detectionReason?: string
    ) {}

    /**
     * Gets a unique identifier for this secret
     */
    getId(): string {
        return `${this.fileName}:${this.lineNumber}:${this.column}`;
    }

    /**
     * Checks if this secret is in the same location as another
     */
    isSameLocation(other: HardcodedSecret): boolean {
        return this.fileName === other.fileName &&
               this.lineNumber === other.lineNumber &&
               this.column === other.column;
    }
}

