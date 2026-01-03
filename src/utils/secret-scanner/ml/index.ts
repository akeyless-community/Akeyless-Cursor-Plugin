/**
 * ML-based false positive classification module
 * 
 * This module provides machine learning capabilities to reduce false positives
 * in secret detection. It uses a lightweight feature-based classifier that runs
 * locally without requiring external dependencies or cloud services.
 * 
 * Features:
 * - Extracts 19 features from detected secrets and their context
 * - Uses a simple neural network-like classifier (weighted sum + sigmoid)
 * - Can learn from user feedback to improve over time
 * - Runs entirely locally - no data leaves the user's machine
 * 
 * Usage:
 * The ML classifier is automatically integrated into FalsePositiveFilter
 * and can be enabled/disabled via configuration.
 */

export { FeatureExtractor, SecretFeatures } from './FeatureExtractor';
export { MLFalsePositiveClassifier } from './MLFalsePositiveClassifier';

