/**
 * Secret Scanner Module
 * Modular, testable secret detection system
 */

// Export types
export * from './types';

// Export main scanner
export { SecretScanner } from './SecretScanner';

// Export utilities
export { EntropyCalculator } from './utils/EntropyCalculator';
export { EnhancedEntropyAnalyzer } from './utils/EnhancedEntropyAnalyzer';
export { ScannerConfigManager } from './utils/ScannerConfig';


// Export pattern registry
export { PatternRegistry } from './PatternRegistry';

// Export patterns
export { SECRET_PATTERNS } from './patterns';

