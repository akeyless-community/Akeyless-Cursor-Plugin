import * as vscode from 'vscode';
import { HardcodedSecret } from '../../infrastructure/scanners/secret-scanner/types';

/**
 * Interface for secret scanning operations
 * Follows Interface Segregation Principle
 */
export interface ISecretScanner {
    /**
     * Scans a document for hardcoded secrets
     */
    scanDocument(document: vscode.TextDocument): Promise<HardcodedSecret[]>;

    /**
     * Scans the entire workspace
     */
    scanWorkspace(): Promise<{
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
    }>;

    /**
     * Scans only the current active file
     */
    scanCurrentFile(): Promise<{
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
    }>;

    /**
     * Scans only the current project directory
     */
    scanCurrentProject(): Promise<{
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
    }>;
}

