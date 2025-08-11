# Akeyless Secrets Manager for Cursor

This extension helps you find and fix hardcoded secrets (like API keys and passwords) in your code by integrating directly with Akeyless.

## What It Does

The Akeyless Secrets Manager extension brings enterprise-grade secret management directly into your Cursor development environment. It automatically detects hardcoded secrets in your code and provides seamless integration with your Akeyless vault.

## Key Features

### **Automatic Secret Detection**
Scans your code and highlights potential secrets as you type.

![Secret Detection Demo](https://raw.githubusercontent.com/akeyless-community/Akeyless-Cursor-Plugin/main/resources/gifs/scan_for_secrets.gif)

### **Save to Akeyless**
Right-click on a highlighted secret to move it securely to your Akeyless vault.

![Save to Akeyless Demo](https://raw.githubusercontent.com/akeyless-community/Akeyless-Cursor-Plugin/main/resources/gifs/save_secrets_to_akeyless.gif)

### **Integrated Experience**
View alerts in the "Problems" panel and manage all your Akeyless secrets from a dedicated sidebar within Cursor.



### **Command Palette Integration**
Use Cursor's command palette to scan your entire codebase for hardcoded secrets.

## Getting Started

### **Step 1: Install Akeyless CLI**
Before using the extension, you must have the Akeyless CLI installed and be authenticated.

```bash
# Install Akeyless CLI (macOS)
brew install akeyless/tap/akeyless

# Or follow instructions on the Akeyless docs for other platforms
# https://docs.akeyless.io/docs/install-cli

# Authenticate with your Akeyless account
akeyless auth
```

### **Step 2: Install the Extension**
1. Open Cursor
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "Akeyless Secrets Manager"
4. Click Install



### **Step 3: Start Using**
1. Open any code file
2. Press `Ctrl+Shift+P` and run "Akeyless: Scan for Hardcoded Secrets"
3. Right-click on highlighted secrets to save them to Akeyless
4. Use the sidebar to browse and manage your secrets

## How to Use

### **Scan for Secrets**
Press `Ctrl+Shift+P` and run "Akeyless: Scan for Hardcoded Secrets".

### **Save to Akeyless**
Right-click a detected secret in your code and select "Save to Akeyless".

### **Manage Secrets**
Click the Akeyless icon in the sidebar to browse, search, and copy secrets without leaving your editor.

## Features in Detail

### **Real-Time Detection**
- Scans for API keys, passwords, tokens, and credentials
- Highlights potential secrets as you type
- Supports multiple secret patterns and formats
- Works across all file types and languages

### **One-Click Migration**
- Right-click to save secrets to Akeyless

### **Integrated Management**
- Browse all secrets from the sidebar
- Search across your entire vault
- Copy values with one click

### **Controlling Diagnostic Behavior**
The extension shows detected secrets in the "Problems" tab. To control this behavior:

- **Automatic Cleanup**: Each new scan automatically clears previous results
- **Manual Clear**: Use "Akeyless: Clear Secret Highlights" to remove diagnostics
- **Status Bar**: Shows active diagnostics count with quick clear option
- **Extension Deactivation**: Automatically cleans up all diagnostics

**Note**: If you see accumulated problems in the Problems tab, run the scanner again or use the clear command to reset them.

### **Configuration Options (NEW!)**
You can now control diagnostic behavior through VS Code settings:

1. **Open Settings**: `Ctrl+,` (or `Cmd+,` on Mac)
2. **Search for "akeyless"**
3. **Configure these options**:
   - `akeyless.diagnostics.enableProblemsTab`: Enable/disable Problems tab (default: true)
   - `akeyless.diagnostics.autoClearOnNewScan`: Auto-clear on new scans (default: true)
   - `akeyless.diagnostics.showInOutputOnly`: Show results only in Output panel (default: false)

**Recommended for accumulation issues**: Set `akeyless.diagnostics.showInOutputOnly` to `true`

## Troubleshooting

### **Problems Tab Shows Accumulated Results**
If you see multiple scan results accumulating in the Problems tab:

1. **Run a new scan**: This automatically clears previous results
2. **Use Clear Command**: Press `Ctrl+Shift+P` and run "Akeyless: Clear Secret Highlights"
3. **Force Clear All**: Press `Ctrl+Shift+P` and run "akeyless.forceClearAllDiagnostics" (nuclear option)
4. **Check Status Bar**: Look for the diagnostic count indicator
5. **Restart Extension**: Reload the window if issues persist

### **No Secrets Found After Scan**
- Check that you're scanning the correct project directory
- Verify file types are supported (JS, TS, JSON, ENV, YAML, etc.)
- Ensure the scanner is configured for your environment










## License

This extension is part of the Akeyless Secret Management platform. For more information about Akeyless and our enterprise secret management solutions, visit [akeyless.io](https://akeyless.io/).

## Get Involved

Akeyless Secrets Manager for Cursor is an open source project maintained by the Akeyless community. We'd love your help in making it even better!

**Report Issues & Share Ideas**: Found a bug or have a feature request? [Create an issue](https://github.com/akeyless-community/Akeyless-Cursor-Plugin/issues/new) to let us know what you think.

**Join the Development**: Interested in contributing code or improvements? Check out our [existing issues](https://github.com/akeyless-community/Akeyless-Cursor-Plugin/issues) or [start a discussion](https://github.com/akeyless-community/Akeyless-Cursor-Plugin/issues/new) about your ideas. See our [development guide](DEVELOPMENT.md) for getting started.

**Source Code**: [View the project on GitHub](https://github.com/akeyless-community/Akeyless-Cursor-Plugin)

---

**Start securing your code today with Akeyless Secrets Manager for Cursor!** 