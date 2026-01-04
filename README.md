# Akeyless Secrets Manager

Find and fix hardcoded secrets in your code by integrating directly with Akeyless. Now with auto-scan on save!

## Features

### Secret Scanning
- **Automatic scanning**: Automatically scan for hardcoded secrets when files are saved (configurable)
- **Manual scanning**: Scan your entire project for hardcoded secrets with a single command
- **Multi-language support**: Works with JavaScript, TypeScript, Python, Go, Java, C#, C++, Rust, Ruby, PHP, and many more
- **Smart detection**: Identifies API keys, passwords, tokens, and other sensitive credentials
- **Visual highlighting**: Secrets are highlighted in your code with diagnostic markers

### Akeyless Integration
- **Secrets tree view**: Browse and manage your Akeyless secrets directly from VS Code
- **Save to Akeyless**: Quickly save selected text as a secret to Akeyless
- **Get secret values**: Copy secret values directly from the tree view
- **Search secrets**: Search through your Akeyless secrets collection
- **Auto-completion**: Get secret name suggestions as you type

### Results Management
- **Problems tab**: View detected secrets in the Problems tab for easy navigation
- **Output panel**: Detailed scan results in a dedicated output channel
- **Clear highlights**: Remove secret highlights when no longer needed
- **Auto-clear**: Automatically clear previous scan results on new scans

## Getting Started

### Prerequisites
- VS Code or Cursor version 1.74.0 or higher
- Akeyless account and CLI configured

### Installation
1. Install the extension from the VS Code marketplace
2. Configure your Akeyless CLI credentials
3. Start using the extension!

## Usage

### Scanning for Secrets

#### Automatic Scanning
The extension can automatically scan files when you save them. This feature is enabled by default and can be configured in settings.

#### Manual Scanning
1. Open the Command Palette (`Cmd+Shift+P` on Mac, `Ctrl+Shift+P` on Windows/Linux)
2. Run the command: `Akeyless: Scan for Hardcoded Secrets`
3. View results in the Problems tab or Output panel

### Managing Secrets

#### View Secrets
- Open the **Akeyless Security** view from the Activity Bar
- Browse your secrets organized by type (Static, Dynamic, Rotated, Classic Keys)

#### Save a Secret to Akeyless
1. Select the text you want to save as a secret in your editor
2. Right-click and choose **Save to Akeyless**
3. Follow the prompts to name and save your secret

#### Get Secret Value
1. Navigate to a secret in the Akeyless Security tree view
2. Right-click on the secret
3. Select **Get Value** to copy the secret value

#### Search Secrets
1. Click the search icon in the Akeyless Security view
2. Enter your search pattern
3. Browse filtered results

### Clearing Highlights
To remove secret highlights from your code:
1. Open the Command Palette
2. Run: `Akeyless: Clear Secret Highlights`

## Configuration

The extension provides several configuration options:

- **`akeyless.autoScanOnSave`**: Automatically scan for hardcoded secrets when a file is saved (default: `true`)
- **`akeyless.diagnostics.enableProblemsTab`**: Show detected secrets in the Problems tab (default: `true`)
- **`akeyless.diagnostics.autoClearOnNewScan`**: Automatically clear previous diagnostics when starting a new scan (default: `true`)
- **`akeyless.diagnostics.showInOutputOnly`**: Show scan results only in the Output panel, not in the Problems tab (default: `false`)

## Supported Languages

The extension supports scanning for secrets in the following languages and file types:

- JavaScript/TypeScript (`.js`, `.ts`, `.jsx`, `.tsx`)
- Python (`.py`)
- Go (`.go`)
- Java (`.java`)
- C# (`.cs`)
- C/C++ (`.c`, `.cpp`, `.h`, `.hpp`)
- Rust (`.rs`)
- Ruby (`.rb`)
- PHP (`.php`)
- Shell scripts (`.sh`, `.bash`)
- PowerShell (`.ps1`)
- Dockerfile
- Terraform (`.tf`, `.hcl`)
- Configuration files (`.json`, `.yaml`, `.yml`, `.xml`, `.properties`, `.ini`, `.toml`)
- And many more!

## Commands

- `akeyless.refresh` - Refresh the secrets tree view
- `akeyless.search` - Search for secrets in Akeyless
- `akeyless.scanHardcodedSecrets` - Scan the project for hardcoded secrets
- `akeyless.clearSecretHighlights` - Clear secret highlights from the editor
- `akeyless.saveToAkeyless` - Save selected text as a secret to Akeyless
- `akeyless.copySecretValue` - Copy the value of a secret
- `akeyless.focusView` - Focus on the Akeyless Security view

## Requirements

- VS Code version 1.74.0 or higher
- Akeyless CLI configured with valid credentials

## Extension Settings

Configure the extension behavior through VS Code settings:

```json
{
  "akeyless.autoScanOnSave": true,
  "akeyless.diagnostics.enableProblemsTab": true,
  "akeyless.diagnostics.autoClearOnNewScan": true,
  "akeyless.diagnostics.showInOutputOnly": false
}
```

## Known Issues

- Large files (>50MB) are automatically skipped during scanning
- If you experience accumulation issues with diagnostics, disable the Problems tab display

## Contributing

Contributions are welcome! Please visit our [GitHub repository](https://github.com/akeyless-community/Akeyless-Cursor-Plugin) to submit issues or pull requests.

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Publisher

Published by **Akeyless**

---

**Note**: This extension requires the Akeyless CLI to be installed and configured on your system. Make sure you have valid Akeyless credentials before using the extension.

