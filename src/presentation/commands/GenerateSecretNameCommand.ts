import * as vscode from 'vscode';
import { BaseCommand } from './base/BaseCommand';
import { HardcodedSecret } from '../../domain/entities/HardcodedSecret';

/**
 * Generate Secret Name Command
 * Generates a suggested name for a secret
 */
export class GenerateSecretNameCommand extends BaseCommand {
    getId(): string {
        return 'akeyless.generateSecretName';
    }

    getTitle(): string {
        return 'Generate Secret Name';
    }

    async execute(...args: any[]): Promise<void> {
        this.logExecution();
        
        const secret = args[0] as HardcodedSecret;
        const fileName = args[1] as string;
        
        if (!secret || !fileName) {
            return;
        }
        
        const baseName = fileName.split('/').pop()?.replace(/\.[^/.]+$/, '') || 'unknown';
        const timestamp = Date.now();

        const contextLower = secret.context.toLowerCase();
        let type = 'secret';

        if (contextLower.includes('api') || contextLower.includes('key')) {
            type = 'api-key';
        } else if (contextLower.includes('password') || contextLower.includes('passwd')) {
            type = 'password';
        } else if (contextLower.includes('token')) {
            type = 'token';
        } else if (contextLower.includes('database') || contextLower.includes('db')) {
            type = 'database-url';
        }

        const generatedName = `/secrets/${baseName}-${type}-${timestamp}`;
        
        // Copy to clipboard
        await vscode.env.clipboard.writeText(generatedName);
        vscode.window.showInformationMessage(`Secret name generated and copied: ${generatedName}`);
    }
}

