import * as vscode from 'vscode';

export class Logger {
    private static instance: Logger;
    private outputChannel: vscode.OutputChannel;

    private constructor() {
        this.outputChannel = vscode.window.createOutputChannel('Akeyless Secrets Manager');
    }

    public static getInstance(): Logger {
        if (!Logger.instance) {
            Logger.instance = new Logger();
        }
        return Logger.instance;
    }

    public info(message: string, ...args: any[]): void {
        const timestamp = new Date().toISOString();
        const logMessage = `[INFO] ${timestamp}: ${message}`;
        console.log(logMessage, ...args);
        this.outputChannel.appendLine(logMessage);
    }

    public error(message: string, error?: any): void {
        const timestamp = new Date().toISOString();
        const logMessage = `[ERROR] ${timestamp}: ${message}`;
        console.error(logMessage, error);
        this.outputChannel.appendLine(logMessage);
        if (error) {
            this.outputChannel.appendLine(`Error details: ${error}`);
        }
    }

    public debug(message: string, ...args: any[]): void {
        const timestamp = new Date().toISOString();
        const logMessage = `[DEBUG] ${timestamp}: ${message}`;
        console.log(logMessage, ...args);
        this.outputChannel.appendLine(logMessage);
    }

    public warn(message: string, ...args: any[]): void {
        const timestamp = new Date().toISOString();
        const logMessage = `[WARN] ${timestamp}: ${message}`;
        console.warn(logMessage, ...args);
        this.outputChannel.appendLine(logMessage);
    }

    public showOutput(): void {
        this.outputChannel.show();
    }

    public clear(): void {
        this.outputChannel.clear();
    }
}

// Convenience function
export const logger = Logger.getInstance(); 