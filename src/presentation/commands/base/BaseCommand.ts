import { ICommand } from '../../../core/interfaces/ICommand';
import { logger } from '../../../utils/logger';

/**
 * Base Command class
 * Provides common functionality for all commands
 * Implements Command Pattern
 */
export abstract class BaseCommand implements ICommand {
    /**
     * Executes the command
     */
    abstract execute(...args: any[]): Promise<void> | void;

    /**
     * Gets the command ID
     */
    abstract getId(): string;

    /**
     * Gets the command title
     */
    abstract getTitle(): string;

    /**
     * Handles errors consistently
     */
    protected handleError(error: unknown, context: string): void {
        logger.error(` Error in ${this.getId()}: ${context}`, error);
    }

    /**
     * Logs command execution
     */
    protected logExecution(): void {
        logger.info(` Executing command: ${this.getTitle()} (${this.getId()})`);
    }
}

