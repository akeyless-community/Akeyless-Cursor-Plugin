import * as vscode from 'vscode';
import { ScanResult } from '../../domain/entities/ScanResult';

/**
 * Scan Results Output Manager
 * Manages the dedicated output channel for displaying secret scan results
 */
export class ScanResultsOutputManager {
    private outputChannel: vscode.OutputChannel;

    constructor() {
        this.outputChannel = vscode.window.createOutputChannel('Akeyless Secret Scan Results');
    }

    /**
     * Shows scan results in the dedicated output channel
     */
    public showResults(scanResult: ScanResult): void {
        // Clear previous results
        this.outputChannel.clear();

        // Write header
        const scanDate = scanResult.scanDate.toLocaleString();
        this.outputChannel.appendLine('═══════════════════════════════════════════════════════════════');
        this.outputChannel.appendLine('SECRET SCAN RESULTS');
        this.outputChannel.appendLine('═══════════════════════════════════════════════════════════════');
        this.outputChannel.appendLine(`Scan Date: ${scanDate}`);
        this.outputChannel.appendLine(`Files Scanned: ${scanResult.totalFilesScanned}`);
        this.outputChannel.appendLine(`Total Secrets Found: ${scanResult.getTotalSecrets()}`);
        this.outputChannel.appendLine(`Files with Secrets: ${scanResult.getSecretsByFile().size}`);
        
        // Add entropy filtering note (always show if threshold is set, or if secrets were filtered)
        if (scanResult.entropyThreshold > 0) {
            if (scanResult.filteredSecretsCount > 0) {
                this.outputChannel.appendLine(`Filtered Low-Entropy Secrets: ${scanResult.filteredSecretsCount}`);
            }
            if (scanResult.filteredByStricterEntropy > 0) {
                this.outputChannel.appendLine(
                    `Filtered by Stricter Entropy (non-base64 Δ=${scanResult.nonBase64EntropyDelta}): ${scanResult.filteredByStricterEntropy}`
                );
            }
            if (scanResult.filteredByFilename > 0) {
                this.outputChannel.appendLine(`Filtered by Filename Rules: ${scanResult.filteredByFilename}`);
            }
            if (scanResult.filteredByDenylist > 0) {
                this.outputChannel.appendLine(`Filtered by Denylist: ${scanResult.filteredByDenylist}`);
            }
            if (scanResult.filteredByFunctionCall > 0) {
                this.outputChannel.appendLine(`Filtered as Function Calls: ${scanResult.filteredByFunctionCall}`);
            }
            if (scanResult.filteredByTestData > 0) {
                this.outputChannel.appendLine(`Filtered as Test/Example Data: ${scanResult.filteredByTestData}`);
            }
            this.outputChannel.appendLine(`Applied entropy filtering (threshold: ${scanResult.entropyThreshold}) to reduce false positives from paths, URLs, and model names.`);
        }
        
        this.outputChannel.appendLine('');

        if (!scanResult.hasSecrets()) {
            this.outputChannel.appendLine('No hardcoded secrets found!');
            this.outputChannel.appendLine('');
            this.outputChannel.appendLine('Your codebase appears to be free of hardcoded secrets.');
            this.outputChannel.appendLine('═══════════════════════════════════════════════════════════════');
        } else {
            // Group secrets by file
            const secretsByFile = scanResult.getSecretsByFile();
            
            let fileIndex = 1;
            for (const [fileName, secrets] of secretsByFile.entries()) {
                const relativePath = vscode.workspace.asRelativePath(fileName, false);
                
                this.outputChannel.appendLine('───────────────────────────────────────────────────────────────');
                this.outputChannel.appendLine(`File ${fileIndex}: ${relativePath}`);
                this.outputChannel.appendLine(`   Secrets found: ${secrets.length}`);
                this.outputChannel.appendLine('───────────────────────────────────────────────────────────────');
                
                secrets.forEach((secret, index) => {
                    this.outputChannel.appendLine('');
                    this.outputChannel.appendLine(`   Secret ${index + 1}:`);
                    this.outputChannel.appendLine(`   ┌─ Type: ${secret.type}`);
                    this.outputChannel.appendLine(`   ├─ File: ${relativePath}`);
                    this.outputChannel.appendLine(`   ├─ Location: Line ${secret.lineNumber}, Column ${secret.column}`);
                    
                    // Show detection reason (handle multiline with proper formatting)
                    if (secret.detectionReason) {
                        const reasonLines = secret.detectionReason.split('\n');
                        reasonLines.forEach((line, idx) => {
                            if (idx === 0) {
                                this.outputChannel.appendLine(`   ├─ Detection Reason: ${line}`);
                            } else {
                                this.outputChannel.appendLine(`   │  ${line}`);
                            }
                        });
                    }
                    
                    // Show truncated value
                    const maxValueLength = 80;
                    const truncatedValue = secret.value.length > maxValueLength 
                        ? secret.value.substring(0, maxValueLength) + '...' 
                        : secret.value;
                    this.outputChannel.appendLine(`   ├─ Value: ${truncatedValue}`);
                    
                    if (secret.context) {
                        const maxContextLength = 100;
                        const truncatedContext = secret.context.length > maxContextLength
                            ? secret.context.substring(0, maxContextLength) + '...'
                            : secret.context;
                        this.outputChannel.appendLine(`   └─ Context: ${truncatedContext}`);
                    } else {
                        this.outputChannel.appendLine(`   └─ Context: (none)`);
                    }
                });
                
                this.outputChannel.appendLine('');
                fileIndex++;
            }
            
            this.outputChannel.appendLine('═══════════════════════════════════════════════════════════════');
            this.outputChannel.appendLine('Tip: Click on the file paths above to navigate to the secrets');
            this.outputChannel.appendLine('═══════════════════════════════════════════════════════════════');
        }

        // Show the output channel
        this.outputChannel.show(true);
    }

    /**
     * Clears the output channel
     */
    public clear(): void {
        this.outputChannel.clear();
    }

    /**
     * Disposes the output channel
     */
    public dispose(): void {
        this.outputChannel.dispose();
    }
}

