import * as vscode from 'vscode';
import { ICommand } from '../../core/interfaces/ICommand';
import { logger } from '../../utils/logger';

/**
 * Command Registry
 * Manages registration and execution of commands
 * Implements Registry Pattern
 */
export class CommandRegistry {
    private commands: Map<string, ICommand> = new Map();

    /**
     * Registers a command
     */
    register(command: ICommand): void {
        this.commands.set(command.getId(), command);
        logger.debug(`Registered command: ${command.getId()}`);
    }

    /**
     * Registers multiple commands
     */
    registerAll(commands: ICommand[]): void {
        for (const command of commands) {
            this.register(command);
        }
    }

    /**
     * Gets a command by ID
     */
    get(commandId: string): ICommand | undefined {
        return this.commands.get(commandId);
    }

    /**
     * Registers all commands with VS Code
     */
    registerWithVSCode(context: vscode.ExtensionContext): void {
        logger.info(' Registering commands with VS Code...');
        
        const disposables: vscode.Disposable[] = [];
        
        for (const [commandId, command] of this.commands.entries()) {
            const disposable = vscode.commands.registerCommand(
                commandId,
                async (...args: any[]) => {
                    try {
                        await command.execute(...args);
                    } catch (error) {
                        logger.error(` Error executing command ${commandId}:`, error);
                        throw error;
                    }
                }
            );
            
            disposables.push(disposable);
        }
        
        disposables.forEach(d => context.subscriptions.push(d));
        
        logger.info(` Registered ${this.commands.size} commands with VS Code`);
    }

    /**
     * Gets all registered command IDs
     */
    getCommandIds(): string[] {
        return Array.from(this.commands.keys());
    }
}

