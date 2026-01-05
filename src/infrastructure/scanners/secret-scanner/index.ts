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
export { FalsePositiveFilter } from './utils/FalsePositiveFilter';
export { ContextAnalyzer } from './utils/ContextAnalyzer';
export { PatternValidator } from './utils/PatternValidator';


// Export pattern registry
export { PatternRegistry } from './PatternRegistry';

// Export patterns
export { SECRET_PATTERNS } from './patterns';

