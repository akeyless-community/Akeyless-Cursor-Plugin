import { ISecretScanner } from '../../core/interfaces/ISecretScanner';
import { SecretScanner } from './secret-scanner/SecretScanner';
import * as vscode from 'vscode';
import { HardcodedSecret } from './secret-scanner/types';

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
        const result = await this.scanner.scanDocument(document);
        return result.secrets;
    }

    async scanWorkspace(): Promise<{
        results: Map<string, HardcodedSecret[]>;
        totalFilesScanned: number;
        filteredSecretsCount: number;
        filteredByFilename: number;
        filteredByDenylist: number;
        filteredByFunctionCall: number;
        filteredByTestData: number;
        filteredByStricterEntropy: number;
        entropyThreshold: number;
        nonBase64EntropyDelta: number;
    }> {
        return this.scanner.scanWorkspace();
    }

    async scanCurrentFile(): Promise<{
        results: Map<string, HardcodedSecret[]>;
        totalFilesScanned: number;
        filteredSecretsCount: number;
        filteredByFilename: number;
        filteredByDenylist: number;
        filteredByFunctionCall: number;
        filteredByTestData: number;
        filteredByStricterEntropy: number;
        entropyThreshold: number;
        nonBase64EntropyDelta: number;
    }> {
        return this.scanner.scanCurrentFile();
    }

    async scanCurrentProject(): Promise<{
        results: Map<string, HardcodedSecret[]>;
        totalFilesScanned: number;
        filteredSecretsCount: number;
        filteredByFilename: number;
        filteredByDenylist: number;
        filteredByFunctionCall: number;
        filteredByTestData: number;
        filteredByStricterEntropy: number;
        entropyThreshold: number;
        nonBase64EntropyDelta: number;
    }> {
        return this.scanner.scanCurrentProject();
    }

    /**
     * Configures the scanner
     */
    configure(options: {
        minEntropy?: number;
        filters?: any;
    }): void {
        this.scanner.configure(options);
    }
}

