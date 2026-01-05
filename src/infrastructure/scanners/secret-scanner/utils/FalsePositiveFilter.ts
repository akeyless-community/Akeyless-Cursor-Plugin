import { HardcodedSecret } from '../types';
import { ContextAnalyzer } from './ContextAnalyzer';
import { PatternValidator } from './PatternValidator';
import { EnhancedEntropyAnalyzer } from './EnhancedEntropyAnalyzer';
import { ScannerConfig } from '../types';

/**
 * Comprehensive false positive filter
 * Combines multiple heuristics to reduce false positives
 */
export class FalsePositiveFilter {
    private config: ScannerConfig;

    constructor(config: ScannerConfig) {
        this.config = config;
    }

    /**
     * Filters out false positives from detected secrets
     */
    filter(secrets: HardcodedSecret[]): HardcodedSecret[] {
        const filtered: HardcodedSecret[] = [];
        const config = this.config;

        for (const secret of secrets) {
            const analysis = this.analyzeSecret(secret);
            
            if (analysis.isFalsePositive) {
                // Mark as false positive but optionally keep for reporting
                secret.isFalsePositive = true;
                secret.filterReason = analysis.reason;
                secret.confidence = analysis.confidence;
                
                // Skip if configured to filter out false positives
                if (config.skipDevelopmentValues && analysis.isDevelopment) {
                    continue;
                }
            } else {
                secret.isFalsePositive = false;
                secret.confidence = analysis.confidence;
                secret.entropy = analysis.entropy;
            }

            filtered.push(secret);
        }

        return filtered;
    }

    /**
     * Analyzes a single secret to determine if it's a false positive
     */
    private analyzeSecret(secret: HardcodedSecret): {
        isFalsePositive: boolean;
        reason?: string;
        confidence: number;
        entropy?: number;
        isDevelopment?: boolean;
    } {
        let confidence = 0.7; // Default medium confidence
        let isFalsePositive = false;
        let reason: string | undefined;
        let isDevelopment = false;

        // 1. Check if it's a variable name (not a value)
        if (ContextAnalyzer.isVariableName(secret.value, secret.context)) {
            isFalsePositive = true;
            reason = 'Variable name detected instead of secret value';
            confidence = 0.1;
            return { isFalsePositive, reason, confidence };
        }

        // 2. Context analysis
        const contextAnalysis = ContextAnalyzer.analyzeContext(
            secret.fileName,
            secret.context,
            secret.value
        );

        if (contextAnalysis.isFalsePositive) {
            isFalsePositive = true;
            reason = contextAnalysis.reason;
            confidence = 0.1; // Very low confidence
        }

        // 3. Entropy analysis
        const entropyAnalysis = EnhancedEntropyAnalyzer.analyzeForType(
            secret.value,
            secret.type
        );
        const entropy = entropyAnalysis.entropy;

        if (!entropyAnalysis.isLikelySecret && !isFalsePositive) {
            // Low entropy might indicate false positive, but not always
            confidence *= 0.6;
            if (entropy !== undefined && entropy < 0.3) {
                isFalsePositive = true;
                reason = reason || 'Low entropy value';
                confidence = 0.2;
            }
        } else if (entropyAnalysis.isLikelySecret) {
            confidence *= 1.2; // Boost confidence for high entropy
            confidence = Math.min(confidence, 0.95);
        }

        // 4. Pattern validation
        const isValidPattern = PatternValidator.validate(secret.value, secret.type);
        if (!isValidPattern && !isFalsePositive) {
            confidence *= 0.7;
            // Don't mark as false positive just because pattern doesn't match
            // Some secrets might have variations
        } else if (isValidPattern) {
            confidence *= 1.1;
            confidence = Math.min(confidence, 0.95);
        }

        // 5. Secret characteristics check
        const hasCharacteristics = PatternValidator.hasSecretCharacteristics(secret.value);
        if (!hasCharacteristics && !isFalsePositive) {
            confidence *= 0.5;
            if (secret.value.length < 8) {
                isFalsePositive = true;
                reason = reason || 'Value too short to be a secret';
                confidence = 0.1;
            }
        }

        // 6. Development mode filtering
        if (this.config.developmentMode && this.config.skipDevelopmentValues) {
            const isDev = ContextAnalyzer.isDevelopmentValue(secret.value, secret.context);
            if (isDev) {
                isDevelopment = true;
                if (!isFalsePositive) {
                    isFalsePositive = true;
                    reason = 'Development/test value';
                    confidence = 0.2;
                }
            }
        }

        // 7. File category check
        const fileCategory = ContextAnalyzer.getFileCategory(secret.fileName);
        if (fileCategory === 'test' || fileCategory === 'example' || fileCategory === 'documentation') {
            if (!isFalsePositive) {
                confidence *= 0.5;
                // Don't automatically mark as false positive, but reduce confidence
            }
        }

        // 8. Final confidence adjustment based on type
        if (secret.type.toLowerCase().includes('high')) {
            confidence = Math.min(confidence * 1.1, 0.95);
        }

        return {
            isFalsePositive,
            reason,
            confidence: Math.max(0.0, Math.min(1.0, confidence)),
            entropy,
            isDevelopment
        };
    }

    /**
     * Updates the configuration
     */
    updateConfig(config: Partial<ScannerConfig>): void {
        this.config = { ...this.config, ...config };
    }
}

