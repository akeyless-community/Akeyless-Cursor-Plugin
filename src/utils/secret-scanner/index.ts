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
export { ScannerConfigManager } from './utils/ScannerConfig';

// Export filters
export { FalsePositiveFilter } from './filters/FalsePositiveFilter';

// Export pattern registry
export { PatternRegistry } from './PatternRegistry';

// Export patterns
export { SECRET_PATTERNS } from './patterns';

