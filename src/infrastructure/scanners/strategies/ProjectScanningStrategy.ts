import * as vscode from 'vscode';
import { IScanningStrategy } from './IScanningStrategy';
import { ISecretScanner } from '../../../core/interfaces/ISecretScanner';
import { HardcodedSecret } from '../../../utils/secret-scanner/types';

/**
 * Project Scanning Strategy
 * Scans only the current project (excludes libraries)
 */
export class ProjectScanningStrategy implements IScanningStrategy {
    constructor(private readonly scanner: ISecretScanner) {}

    async scan(): Promise<{ results: Map<string, HardcodedSecret[]>, totalFilesScanned: number }> {
        return this.scanner.scanCurrentProject();
    }
}

