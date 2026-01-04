/**
 * Base application error class
 * Follows best practices for error handling
 */
export class AppError extends Error {
    public readonly code: string;
    public readonly statusCode?: number;
    public readonly isOperational: boolean;

    constructor(
        message: string,
        code: string,
        statusCode?: number,
        isOperational: boolean = true
    ) {
        super(message);
        this.name = this.constructor.name;
        this.code = code;
        this.statusCode = statusCode;
        this.isOperational = isOperational;

        // Maintains proper stack trace for where our error was thrown
        Error.captureStackTrace(this, this.constructor);
    }
}

/**
 * Repository-related errors
 */
export class RepositoryError extends AppError {
    constructor(message: string, code: string = 'REPOSITORY_ERROR') {
        super(message, code, 500);
    }
}

/**
 * Scanner-related errors
 */
export class ScannerError extends AppError {
    constructor(message: string, code: string = 'SCANNER_ERROR') {
        super(message, code, 500);
    }
}

/**
 * Configuration errors
 */
export class ConfigurationError extends AppError {
    constructor(message: string, code: string = 'CONFIGURATION_ERROR') {
        super(message, code, 400);
    }
}

/**
 * Validation errors
 */
export class ValidationError extends AppError {
    constructor(message: string, code: string = 'VALIDATION_ERROR') {
        super(message, code, 400);
    }
}

