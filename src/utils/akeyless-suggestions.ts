/**
 * Utility for generating Akeyless-specific security suggestions
 * Based on Akeyless security documentation and best practices
 */

export interface AkeylessSuggestion {
    message: string;
    implementation: string;
    documentation: string;
}

/**
 * Detects programming language from file extension
 */
function detectLanguage(fileName: string): string {
    const ext = fileName.toLowerCase().split('.').pop() || '';
    
    const languageMap: Record<string, string> = {
        'go': 'go',
        'py': 'python',
        'js': 'javascript',
        'jsx': 'javascript',
        'ts': 'typescript',
        'tsx': 'typescript',
        'java': 'java',
        'cs': 'csharp',
        'cpp': 'cpp',
        'c': 'c',
        'rs': 'rust',
        'rb': 'ruby',
        'php': 'php',
        'swift': 'swift',
        'kt': 'kotlin',
        'scala': 'scala',
        'sh': 'bash',
        'bash': 'bash',
        'ps1': 'powershell',
        'tf': 'terraform',
        'hcl': 'terraform',
        'yaml': 'yaml',
        'yml': 'yaml',
        'json': 'json',
        'env': 'env',
        'properties': 'properties',
        'ini': 'ini',
        'toml': 'toml'
    };
    
    return languageMap[ext] || 'generic';
}

/**
 * Gets Akeyless implementation suggestion based on language and secret type
 */
function getImplementationSuggestion(language: string, secretType: string): string {
    const suggestions: Record<string, Record<string, string>> = {
        go: {
            default: `// Store secret in Akeyless and retrieve at runtime:
import "github.com/akeylesslabs/akeyless-go/v3"
client := akeyless.NewClient()
secret, err := client.GetSecretValue("/path/to/secret")`,
            'Go Secret Assignment': `// Replace hardcoded value with Akeyless retrieval:
secret := os.Getenv("AKEYLESS_SECRET_PATH")
value, err := akeylessClient.GetSecretValue(secret)`,
            'Go Function Call Secret': `// Use Akeyless SDK instead of hardcoded defaults:
value, err := akeylessClient.GetSecretValue(secretName)`
        },
        python: {
            default: `# Store secret in Akeyless and retrieve at runtime:
from akeyless import ApiClient, GetSecretValue
client = ApiClient()
secret = client.get_secret_value("/path/to/secret")`,
            'Python Secret Assignment': `# Replace hardcoded value with Akeyless:
from akeyless import ApiClient
client = ApiClient()
secret_value = client.get_secret_value("/path/to/secret")`
        },
        javascript: {
            default: `// Store secret in Akeyless and retrieve at runtime:
const akeyless = require('akeyless');
const client = new akeyless.ApiClient();
const secret = await client.getSecretValue('/path/to/secret');`,
            'JavaScript Secret Assignment': `// Replace hardcoded value with Akeyless:
const secret = await akeylessClient.getSecretValue('/path/to/secret');`
        },
        typescript: {
            default: `// Store secret in Akeyless and retrieve at runtime:
import { ApiClient } from 'akeyless';
const client = new ApiClient();
const secret = await client.getSecretValue('/path/to/secret');`,
            'TypeScript Secret Assignment': `// Replace hardcoded value with Akeyless:
const secret = await akeylessClient.getSecretValue('/path/to/secret');`
        },
        java: {
            default: `// Store secret in Akeyless and retrieve at runtime:
import com.akeyless.sdk.ApiClient;
ApiClient client = new ApiClient();
String secret = client.getSecretValue("/path/to/secret");`,
            'Java Secret Assignment': `// Replace hardcoded value with Akeyless:
String secret = akeylessClient.getSecretValue("/path/to/secret");`
        },
        csharp: {
            default: `// Store secret in Akeyless and retrieve at runtime:
using Akeyless.Api;
var client = new ApiClient();
var secret = await client.GetSecretValueAsync("/path/to/secret");`,
            'C# Secret Assignment': `// Replace hardcoded value with Akeyless:
var secret = await akeylessClient.GetSecretValueAsync("/path/to/secret");`
        },
        terraform: {
            default: `# Use Akeyless provider to retrieve secrets:
data "akeyless_secret" "example" {
  path = "/path/to/secret"
}

resource "example" "resource" {
  secret = data.akeyless_secret.example.value
}`
        },
        generic: {
            default: `Store the secret in Akeyless and retrieve it at runtime using the appropriate Akeyless SDK or CLI.`
        }
    };
    
    const langSuggestions = suggestions[language] || suggestions.generic;
    return langSuggestions[secretType] || langSuggestions.default;
}

/**
 * Generates an Akeyless-specific diagnostic message with implementation guidance
 */
export function generateAkeylessDiagnosticMessage(
    secretType: string,
    fileName: string
): AkeylessSuggestion {
    const language = detectLanguage(fileName);
    const implementation = getImplementationSuggestion(language, secretType);
    
    // Create a user-friendly message
    const secretTypeDisplay = secretType.replace(/([A-Z])/g, ' $1').trim();
    const message = `Hardcoded ${secretTypeDisplay} detected. Store in Akeyless and retrieve at runtime per Akeyless security best practices.`;
    
    return {
        message,
        implementation,
        documentation: 'https://docs.akeyless.io/docs/security-best-practices'
    };
}

