import { IScanningStrategy } from './IScanningStrategy';
import { ISecretScanner } from '../../../core/interfaces/ISecretScanner';
import { HardcodedSecret } from '../secret-scanner/types';

/**
 * Workspace Scanning Strategy
 * Scans the entire workspace
 */
export class WorkspaceScanningStrategy implements IScanningStrategy {
    constructor(private readonly scanner: ISecretScanner) {}

    async scan(): Promise<{ results: Map<string, HardcodedSecret[]>, totalFilesScanned: number }> {
        return this.scanner.scanWorkspace();
    }
}

