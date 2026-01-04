import * as vscode from 'vscode';
import { HardcodedSecret } from '../../../utils/secret-scanner/types';

/**
 * Scanning Strategy Interface
 * Strategy Pattern for different scanning approaches
 */
export interface IScanningStrategy {
    /**
     * Scans using this strategy
     */
    scan(): Promise<{ results: Map<string, HardcodedSecret[]>, totalFilesScanned: number }>;
}

