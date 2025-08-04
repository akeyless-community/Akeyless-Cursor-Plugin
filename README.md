# Akeyless Secrets Manager for Cursor

This extension helps you find and fix hardcoded secrets (like API keys and passwords) in your code by integrating directly with Akeyless.

## What It Does

The Akeyless Secrets Manager extension brings enterprise-grade secret management directly into your Cursor development environment. It automatically detects hardcoded secrets in your code and provides seamless integration with your Akeyless vault.

## Key Features

### **Automatic Secret Detection**
Scans your code and highlights potential secrets as you type.

![Secret Detection Demo](https://github.com/akeyless-community/Akeyless-Cursor-Plugin/blob/main/resources/gifs/scan_for_secrets.gif)

### **Save to Akeyless**
Right-click on a highlighted secret to move it securely to your Akeyless vault.

![Save to Akeyless Demo](https://github.com/akeyless-community/Akeyless-Cursor-Plugin/blob/main/resources/gifs/save_secrets_to_akeyless.gif)

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










## License

This extension is part of the Akeyless Secret Management platform. For more information about Akeyless and our enterprise secret management solutions, visit [akeyless.io](https://akeyless.io/).

---

**Start securing your code today with Akeyless Secrets Manager for Cursor!** 