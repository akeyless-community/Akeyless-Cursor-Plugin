#!/bin/bash

# Development script for Akeyless Secrets Manager Extension

echo "Building Akeyless Secrets Manager Extension..."
npm run compile

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo ""
    echo "To run the extension in development mode:"
    echo "1. Open this project in Cursor"
    echo "2. Press F5 or go to Run and Debug"
    echo "3. Select 'Run Extension' configuration"
    echo "4. A new Cursor window will open with your extension loaded"
    echo ""
    echo "Or use the command palette:"
    echo "   - Press Cmd+Shift+P"
    echo "   - Type 'Developer: Reload Window' to reload after changes"
    echo ""
    echo "To watch for changes:"
    echo "   npm run watch"
else
    echo "Build failed!"
    exit 1
fi 