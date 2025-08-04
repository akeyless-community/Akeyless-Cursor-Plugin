# Development Guide - Akeyless Secrets Manager for Cursor

## Quick Start

### Prerequisites
- Node.js (v16 or higher)
- npm or yarn
- Cursor IDE
- Akeyless CLI (for testing)

### Setup
1. Clone the repository
2. Install dependencies: `npm install`
3. Build the extension: `npm run compile`

## Development Mode

### Running in Development
1. Open the project in Cursor
2. Press `F5` or go to Run and Debug
3. Select "Run Extension" configuration
4. A new Cursor window will open with your extension loaded

### Development Workflow
1. Make changes to the TypeScript files in `src/`
2. The extension will automatically recompile
3. Use "Developer: Reload Window" (Cmd+Shift+P) to reload the extension
4. Test your changes in the new Cursor window

### Watch Mode
For automatic compilation on file changes:
```bash
npm run watch
```

### Linting
Check for code quality issues:
```bash
npm run lint
```

## Project Structure

```
src/
├── commands/          # Command handlers
├── providers/         # Tree view providers
├── services/          # Akeyless CLI integration
├── utils/            # Utility functions
├── constants.ts      # Constants and messages
├── extension.ts      # Main extension entry point
└── types.ts          # TypeScript type definitions
```

## Key Features

### Secret Detection
- Scans code for hardcoded secrets
- Highlights potential security issues
- Configurable detection patterns

### Akeyless Integration
- Browse secrets from Akeyless vault
- Save detected secrets to Akeyless
- Copy secret values to clipboard

### UI Components
- Sidebar tree view for secrets
- Context menu integration
- Command palette integration

## Testing

### Manual Testing
1. Run the extension in development mode
2. Test secret scanning functionality
3. Test Akeyless integration (requires Akeyless CLI setup)
4. Test UI interactions

### Automated Testing
```bash
npm test
```

## Building for Distribution

### Package the Extension
```bash
npm run package
```

This creates a `.vsix` file that can be installed in Cursor.

### Install Locally
1. Build the package: `npm run package`
2. In Cursor: Extensions → Install from VSIX
3. Select the generated `.vsix` file

## Configuration

### Akeyless CLI Setup
1. Install Akeyless CLI: `brew install akeyless/tap/akeyless`
2. Authenticate: `akeyless auth`
3. Configure your Akeyless account

### Extension Settings
The extension uses VS Code's configuration system. Key settings:
- `akeyless.enableSecretDetection`: Enable/disable secret scanning
- `akeyless.scanOnSave`: Scan files when saved
- `akeyless.entropyThreshold`: Minimum entropy for secret detection

## Debugging

### Extension Host Logs
1. Open Command Palette (Cmd+Shift+P)
2. Run "Developer: Show Logs"
3. Select "Extension Host"

### Console Output
The extension uses a custom logger. Check the Output panel for "Akeyless" channel.

## Common Issues

### Extension Not Loading
- Check the Extension Host logs
- Ensure all dependencies are installed
- Verify TypeScript compilation

### Akeyless CLI Issues
- Ensure Akeyless CLI is installed and authenticated
- Check network connectivity
- Verify Akeyless account permissions

### Secret Detection Not Working
- Check entropy threshold settings
- Verify file types are supported
- Review detection patterns in `secret-scanner.ts`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This extension is part of the Akeyless Secret Management platform. 