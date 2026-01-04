import * as vscode from 'vscode';

/**
 * Command interface following Command Pattern
 * Encapsulates a request as an object
 */
export interface ICommand {
    /**
     * Executes the command
     */
    execute(...args: any[]): Promise<void> | void;

    /**
     * Gets the command ID
     */
    getId(): string;

    /**
     * Gets the command title
     */
    getTitle(): string;
}

