import * as vscode from 'vscode';
import * as path from 'path';
import { ScanResult } from '../../domain/entities/ScanResult';
import { logger } from '../../utils/logger';

/**
 * Scan Results Webview Manager
 * Manages the dedicated webview panel for displaying secret scan results
 */
export class ScanResultsWebviewManager {
    private panel: vscode.WebviewPanel | undefined;
    private readonly viewType = 'akeyless.scanResults';
    private readonly title = 'Secret Scan Results';

    constructor(private readonly context: vscode.ExtensionContext) {}

    /**
     * Shows scan results in a dedicated webview panel
     */
    public showResults(scanResult: ScanResult): void {
        // If panel already exists, reuse it
        if (this.panel) {
            this.panel.reveal();
        } else {
            // Create new panel
            this.panel = vscode.window.createWebviewPanel(
                this.viewType,
                this.title,
                vscode.ViewColumn.Beside,
                {
                    enableScripts: true,
                    retainContextWhenHidden: true,
                    localResourceRoots: [
                        vscode.Uri.file(path.join(this.context.extensionPath, 'resources'))
                    ]
                }
            );

            // Handle panel disposal
            this.panel.onDidDispose(() => {
                this.panel = undefined;
            }, null, this.context.subscriptions);
        }

        // Update panel content
        this.panel.webview.html = this.getWebviewContent(scanResult);

        // Handle messages from webview
        this.panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'openFile':
                        this.openFile(message.fileName, message.lineNumber, message.column);
                        break;
                    case 'copyValue':
                        vscode.env.clipboard.writeText(message.value);
                        vscode.window.showInformationMessage('Secret value copied to clipboard');
                        break;
                }
            },
            null,
            this.context.subscriptions
        );
    }

    /**
     * Opens a file at a specific line and column
     */
    private async openFile(fileName: string, lineNumber: number, column: number): Promise<void> {
        try {
            const uri = vscode.Uri.file(fileName);
            const document = await vscode.workspace.openTextDocument(uri);
            const editor = await vscode.window.showTextDocument(document);
            
            // Reveal the line and column
            const position = new vscode.Position(lineNumber - 1, column - 1);
            editor.revealRange(new vscode.Range(position, position));
            editor.selection = new vscode.Selection(position, position);
        } catch (error) {
            logger.error(`Failed to open file ${fileName}:`, error);
            vscode.window.showErrorMessage(`Failed to open file: ${fileName}`);
        }
    }

    /**
     * Generates HTML content for the webview
     */
    private getWebviewContent(scanResult: ScanResult): string {
        const secretsByFile = scanResult.getSecretsByFile();
        const totalSecrets = scanResult.getTotalSecrets();
        const scanDate = scanResult.scanDate.toLocaleString();

        // Generate file sections
        let fileSections = '';
        for (const [fileName, secrets] of secretsByFile.entries()) {
            const relativePath = vscode.workspace.asRelativePath(fileName, false);
            fileSections += this.generateFileSection(relativePath, fileName, secrets);
        }

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secret Scan Results</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size);
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            padding: 20px;
            line-height: 1.6;
        }
        
        .header {
            background-color: var(--vscode-editor-background);
            border-bottom: 2px solid var(--vscode-panel-border);
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        
        .header h1 {
            color: var(--vscode-textLink-foreground);
            margin-bottom: 10px;
            font-size: 24px;
        }
        
        .stats {
            display: flex;
            gap: 30px;
            margin-top: 15px;
            flex-wrap: wrap;
        }
        
        .stat-item {
            display: flex;
            flex-direction: column;
        }
        
        .stat-label {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
            text-transform: uppercase;
            margin-bottom: 5px;
        }
        
        .stat-value {
            font-size: 20px;
            font-weight: bold;
            color: var(--vscode-textLink-foreground);
        }
        
        .file-section {
            background-color: var(--vscode-editor-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 4px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .file-header {
            background-color: var(--vscode-sideBar-background);
            padding: 15px 20px;
            border-bottom: 1px solid var(--vscode-panel-border);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
        }
        
        .file-header:hover {
            background-color: var(--vscode-list-hoverBackground);
        }
        
        .file-path {
            font-family: var(--vscode-editor-font-family);
            font-size: 14px;
            color: var(--vscode-foreground);
            flex: 1;
        }
        
        .file-count {
            background-color: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .file-content {
            display: none;
            padding: 0;
        }
        
        .file-content.expanded {
            display: block;
        }
        
        .secret-item {
            padding: 15px 20px;
            border-bottom: 1px solid var(--vscode-panel-border);
            transition: background-color 0.2s;
        }
        
        .secret-item:last-child {
            border-bottom: none;
        }
        
        .secret-item:hover {
            background-color: var(--vscode-list-hoverBackground);
        }
        
        .secret-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .secret-location {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .secret-line {
            font-family: var(--vscode-editor-font-family);
            color: var(--vscode-textLink-foreground);
            cursor: pointer;
            text-decoration: underline;
        }
        
        .secret-line:hover {
            color: var(--vscode-textLink-activeForeground);
        }
        
        .secret-type {
            background-color: var(--vscode-textBlockQuote-background);
            color: var(--vscode-textBlockQuote-border);
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .secret-value {
            font-family: var(--vscode-editor-font-family);
            background-color: var(--vscode-textCodeBlock-background);
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            word-break: break-all;
            position: relative;
        }
        
        .secret-value-text {
            color: var(--vscode-textPreformat-foreground);
            font-size: 13px;
        }
        
        .copy-button {
            position: absolute;
            top: 5px;
            right: 5px;
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            padding: 4px 8px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 11px;
            opacity: 0.8;
        }
        
        .copy-button:hover {
            opacity: 1;
            background-color: var(--vscode-button-hoverBackground);
        }
        
        .secret-context {
            margin-top: 10px;
            padding: 10px;
            background-color: var(--vscode-textBlockQuote-background);
            border-left: 3px solid var(--vscode-textBlockQuote-border);
            border-radius: 2px;
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
            font-family: var(--vscode-editor-font-family);
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--vscode-descriptionForeground);
        }
        
        .empty-state h2 {
            margin-bottom: 10px;
            color: var(--vscode-foreground);
        }
        
        .icon {
            font-size: 48px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Secret Scan Results</h1>
        <div class="stats">
            <div class="stat-item">
                <span class="stat-label">Total Secrets</span>
                <span class="stat-value">${totalSecrets}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Files with Secrets</span>
                <span class="stat-value">${secretsByFile.size}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Files Scanned</span>
                <span class="stat-value">${scanResult.totalFilesScanned}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Scan Date</span>
                <span class="stat-value" style="font-size: 14px;">${scanDate}</span>
            </div>
        </div>
    </div>
    
    ${totalSecrets > 0 ? fileSections : `
        <div class="empty-state">
            <div class="icon">✓</div>
            <h2>No Secrets Found</h2>
            <p>Great! No hardcoded secrets were detected in your project.</p>
        </div>
    `}
    
    <script>
        const vscode = acquireVsCodeApi();
        
        // Handle file section expansion
        document.querySelectorAll('.file-header').forEach(header => {
            header.addEventListener('click', () => {
                const content = header.nextElementSibling;
                content.classList.toggle('expanded');
            });
        });
        
        // Handle secret line clicks
        document.querySelectorAll('.secret-line').forEach(line => {
            line.addEventListener('click', () => {
                const fileName = line.getAttribute('data-file');
                const lineNumber = parseInt(line.getAttribute('data-line'));
                const column = parseInt(line.getAttribute('data-column'));
                vscode.postMessage({
                    command: 'openFile',
                    fileName: fileName,
                    lineNumber: lineNumber,
                    column: column
                });
            });
        });
        
        // Handle copy button clicks
        document.querySelectorAll('.copy-button').forEach(button => {
            button.addEventListener('click', (e) => {
                e.stopPropagation();
                const value = button.getAttribute('data-value');
                vscode.postMessage({
                    command: 'copyValue',
                    value: value
                });
            });
        });
        
        // Expand all file sections by default
        document.querySelectorAll('.file-content').forEach(content => {
            content.classList.add('expanded');
        });
    </script>
</body>
</html>`;
    }

    /**
     * Generates HTML for a file section
     */
    private generateFileSection(relativePath: string, absolutePath: string, secrets: any[]): string {
        let secretItems = '';
        
        for (const secret of secrets) {
            const truncatedValue = secret.value.length > 100 
                ? secret.value.substring(0, 100) + '...' 
                : secret.value;
            
            secretItems += `
                <div class="secret-item">
                    <div class="secret-header">
                        <div class="secret-location">
                            <span class="secret-line" 
                                  data-file="${this.escapeHtml(absolutePath)}" 
                                  data-line="${secret.lineNumber}" 
                                  data-column="${secret.column}">
                                Line ${secret.lineNumber}, Column ${secret.column}
                            </span>
                        </div>
                        <span class="secret-type">${this.escapeHtml(secret.type)}</span>
                    </div>
                    <div class="secret-value">
                        <button class="copy-button" data-value="${this.escapeHtml(secret.value)}">Copy</button>
                        <div class="secret-value-text">${this.escapeHtml(truncatedValue)}</div>
                    </div>
                    ${secret.detectionReason ? `
                        <div class="secret-detection-reason">
                            <strong>Detection Reason:</strong><br>
                            ${this.escapeHtml(secret.detectionReason).replace(/\n/g, '<br>')}
                        </div>
                    ` : ''}
                    ${secret.context ? `
                        <div class="secret-context">
                            <strong>Context:</strong> ${this.escapeHtml(secret.context)}
                        </div>
                    ` : ''}
                </div>
            `;
        }
        
        return `
            <div class="file-section">
                <div class="file-header">
                    <span class="file-path">${this.escapeHtml(relativePath)}</span>
                    <span class="file-count">${secrets.length} secret${secrets.length !== 1 ? 's' : ''}</span>
                </div>
                <div class="file-content">
                    ${secretItems}
                </div>
            </div>
        `;
    }

    /**
     * Escapes HTML special characters
     */
    private escapeHtml(text: string): string {
        const map: { [key: string]: string } = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    /**
     * Disposes the webview panel
     */
    public dispose(): void {
        if (this.panel) {
            this.panel.dispose();
            this.panel = undefined;
        }
    }
}

