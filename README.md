# Akeyless Secrets Manager

A VS Code extension for managing your Akeyless secrets directly from your editor. Browse, search, and manage secrets with built-in secret scanning capabilities to find hardcoded secrets in your code.

## Overview

This extension provides a complete Akeyless integration for VS Code, allowing you to:
- **Manage Akeyless Secrets**: Browse, search, and retrieve secrets from your Akeyless vault
- **Save Secrets**: Quickly save selected text as secrets to Akeyless
- **Scan for Hardcoded Secrets**: Detect hardcoded secrets in your codebase using advanced pattern matching and entropy analysis

## Features

### Akeyless Secret Management

- **Secrets Tree View**: Browse your Akeyless secrets organized by type (Static, Dynamic, Rotated, Classic Keys)
- **Search Secrets**: Search through your Akeyless secrets collection
- **Get Secret Values**: Copy secret values directly from the tree view
- **Save to Akeyless**: Save selected text as a secret to Akeyless with a single command
- **Auto-completion**: Get secret name suggestions as you type

### Secret Scanning Capabilities

The extension includes a powerful secret scanner that helps you find hardcoded secrets in your code:

- **Pattern-Based Detection**: Recognizes 400+ known secret formats (API keys, tokens, passwords, private keys)
- **Entropy Analysis**: Detects random-looking strings that might be secrets
- **Multi-Language Support**: Works with JavaScript, TypeScript, Python, Go, Java, C#, C++, Rust, Ruby, PHP, and many more
- **Smart Filtering**: Reduces false positives by filtering out URLs, paths, test data, and function calls
- **Visual Highlighting**: Secrets are highlighted in your code with diagnostic markers

## Getting Started

### Prerequisites

- Akeyless account and CLI configured

### Installation

1. Install the extension from the VS Code marketplace
2. Configure your Akeyless CLI credentials
3. Start using the extension

## Usage

### Managing Akeyless Secrets

#### View Secrets
1. Open the **Akeyless Security** view from the Activity Bar
2. Browse your secrets organized by type (Static, Dynamic, Rotated, Classic Keys)
3. Click **Refresh** to reload secrets from Akeyless

#### Search Secrets
1. Click the search icon in the Akeyless Security view
2. Enter your search pattern
3. Browse filtered results

#### Get Secret Value
1. Navigate to a secret in the Akeyless Security tree view
2. Right-click on the secret
3. Select **Get Value** to copy the secret value to your clipboard

#### Save a Secret to Akeyless
1. Select the text you want to save as a secret in your editor
2. Right-click and choose **Save to Akeyless**
3. Follow the prompts to name and save your secret

### Scanning for Hardcoded Secrets

#### How to Run a Scan

1. Open the Command Palette (`Cmd+Shift+P` on Mac, `Ctrl+Shift+P` on Windows/Linux)
2. Run the command: **`Akeyless: Scan for Hardcoded Secrets`**
3. The scan will process your project files

#### Monitoring the Scan Process

**During Scanning:**
- A notification appears: "Scanning current project for hardcoded secrets..."
- The scan processes files in your project (excluding library directories like `node_modules`, `dist`, `build`)

**Scan Progress:**
- You can monitor the scan progress in the **Output panel**
- Open the Output panel: `View` → `Output` → Select "Akeyless Secret Manager" from the dropdown

#### Viewing Scan Results

Scan results are displayed in two locations:

**1. Output Panel (Detailed Report)**
- Open: `View` → `Output` → Select "Akeyless Secret Scan Results"
- Shows:
  - Scan date and time
  - Total files scanned
  - Total secrets found
  - Files with secrets
  - Detailed list of each secret with:
    - File path
    - Line number and column
    - Secret value (truncated for security)
    - Secret type/classification
    - Context (surrounding code)
  - Filter statistics (how many secrets were filtered and why)

**2. Problems Tab (Quick Navigation)**
- Open: `View` → `Problems` (or `Cmd+Shift+M` / `Ctrl+Shift+M`)
- Shows secrets as warnings/errors
- Click on any entry to navigate directly to the secret in your code
- Each entry shows:
  - File name
  - Line number
  - Secret type
  - Secret value preview

#### Understanding Scan Results

**Secret Information:**
- **File**: The file where the secret was found
- **Line/Column**: Exact location in the file
- **Type**: Classification (e.g., "Stripe Key", "API Key", "High Entropy Secret")
- **Value**: The detected secret (truncated in output for security)
- **Context**: The line of code containing the secret

**Filter Statistics:**
The scan report includes statistics about filtered secrets:
- **Filtered by Entropy**: Low-randomness strings that were filtered out
- **Filtered by Filename**: Files excluded from scanning
- **Filtered by Denylist**: Known non-secrets that were skipped
- **Filtered by Function Call**: Function calls that were filtered
- **Filtered by Test Data**: Test placeholders that were removed

#### Clearing Scan Highlights

To remove secret highlights from your code:
1. Open the Command Palette
2. Run: **`Akeyless: Clear Secret Highlights`**

This clears both the visual highlights and the Problems tab entries.

## Supported File Types

The secret scanner supports scanning for secrets in:

- **Code files**: JavaScript, TypeScript, Python, Go, Java, C#, C++, Rust, Ruby, PHP
- **Configuration files**: JSON, YAML, XML, properties, INI, TOML
- **Scripts**: Shell scripts, PowerShell, batch files
- **Infrastructure**: Dockerfile, Terraform files
- **And many more!**

The scanner automatically excludes common library directories:
- `node_modules`, `dist`, `build`
- `.git`, `vendor`, `target`
- `coverage`, `logs`, `temp`
- And other common build/dependency directories

## Commands

| Command | Description |
|---------|-------------|
| `akeyless.refresh` | Refresh the secrets tree view |
| `akeyless.search` | Search for secrets in Akeyless |
| `akeyless.scanHardcodedSecrets` | Scan the project for hardcoded secrets |
| `akeyless.clearSecretHighlights` | Clear secret highlights from the editor |
| `akeyless.saveToAkeyless` | Save selected text as a secret to Akeyless |
| `akeyless.copySecretValue` | Copy the value of a secret |
| `akeyless.focusView` | Focus on the Akeyless Security view |

## Configuration

The extension provides configuration options:

- **`akeyless.diagnostics.enableProblemsTab`**: Show detected secrets in the Problems tab (default: `true`)
- **`akeyless.diagnostics.showInOutputOnly`**: Show scan results only in the Output panel, not in the Problems tab (default: `false`)

## Requirements

- Akeyless CLI configured with valid credentials

## Contributing

Contributions are welcome! Please visit our [GitHub repository](https://github.com/akeyless-community/Akeyless-Cursor-Plugin) to submit issues or pull requests.

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Publisher

Published by **Akeyless**

---

**Note**: This extension requires the Akeyless CLI to be installed and configured on your system. Make sure you have valid Akeyless credentials before using the extension.
