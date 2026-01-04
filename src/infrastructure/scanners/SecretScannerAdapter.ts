import { ISecretScanner } from '../../core/interfaces/ISecretScanner';
import { SecretScanner } from '../../utils/secret-scanner/SecretScanner';
import * as vscode from 'vscode';
import { HardcodedSecret } from '../../utils/secret-scanner/types';

/**
 * Adapter: Adapts SecretScanner to ISecretScanner interface
 * Removes static methods and makes it instance-based
 */
export class SecretScannerAdapter implements ISecretScanner {
    private scanner: SecretScanner;

    constructor() {
        this.scanner = new SecretScanner();
    }

    async scanDocument(document: vscode.TextDocument): Promise<HardcodedSecret[]> {
        return this.scanner.scanDocument(document);
    }

    async scanWorkspace(): Promise<{ results: Map<string, HardcodedSecret[]>, totalFilesScanned: number }> {
        return this.scanner.scanWorkspace();
    }

    async scanCurrentFile(): Promise<{ results: Map<string, HardcodedSecret[]>, totalFilesScanned: number }> {
        return this.scanner.scanCurrentFile();
    }

    async scanCurrentProject(): Promise<{ results: Map<string, HardcodedSecret[]>, totalFilesScanned: number }> {
        return this.scanner.scanCurrentProject();
    }

    /**
     * Configures the scanner
     */
    configure(options: {
        developmentMode?: boolean;
        minEntropy?: number;
        skipDevelopmentValues?: boolean;
    }): void {
        this.scanner.configure(options);
    }
}

