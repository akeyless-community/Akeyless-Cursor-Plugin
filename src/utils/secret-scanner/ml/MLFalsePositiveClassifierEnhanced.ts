/**
 * Enhanced ML-based false positive classifier using ml-classify-text
 * 
 * This is an alternative implementation that uses the ml-classify-text library
 * for better classification performance. To use this:
 * 
 * 1. Install: npm install ml-classify-text
 * 2. Replace MLFalsePositiveClassifier with this class
 * 3. Train the model with examples (see train() method)
 * 
 * Benefits:
 * - Better accuracy with proper training
 * - Can learn from user feedback
 * - Still lightweight (~20KB)
 * - Designed specifically for text classification
 */

import { FeatureExtractor, SecretFeatures } from './FeatureExtractor';
import { SecretPattern } from '../types';
import { logger } from '../../logger';

// Uncomment when ml-classify-text is installed:
// import { Classifier } from 'ml-classify-text';

export class MLFalsePositiveClassifierEnhanced {
    private enabled: boolean = true;
    private confidenceThreshold: number = 0.7;
    // private classifier: Classifier | null = null;
    private useEnhanced: boolean = false; // Set to true when ml-classify-text is available
    
    // Fallback to simple classifier if ml-classify-text not available
    // Updated to match new features (26 features total)
    private fallbackWeights: number[] = [
        -0.1, 0.3, 0.1, 0.05, 0.05, 0.2, 0.15, 0.2, 0.25, 0.15,
        0.1, 0.15, -0.3, 0.2, 0.1, -0.4, -0.4, -0.5, -0.5, -0.6,
        -0.8, -0.7, -0.6, -0.7, -0.8, -0.7  // New features: protobuf, apiPath, testFile, varName, testPassword, generated
    ];
    private fallbackBias: number = -0.2;
    
    constructor(enabled: boolean = true) {
        this.enabled = enabled;
        this.initializeClassifier();
    }
    
    /**
     * Initialize the classifier (with ml-classify-text if available)
     */
    private initializeClassifier(): void {
        try {
            // Uncomment when ml-classify-text is installed:
            // const { Classifier } = require('ml-classify-text');
            // this.classifier = new Classifier();
            // this.useEnhanced = true;
            // logger.info('ML classifier: Using ml-classify-text');
            
            logger.info('ML classifier: Using fallback implementation (install ml-classify-text for enhanced mode)');
        } catch (error) {
            logger.debug('ml-classify-text not available, using fallback');
            this.useEnhanced = false;
        }
    }
    
    /**
     * Train the classifier with examples
     * Call this with labeled examples to improve accuracy
     */
    train(examples: Array<{ features: SecretFeatures; isFalsePositive: boolean }>): void {
        if (!this.useEnhanced) {
            logger.warn('Enhanced classifier not available, cannot train');
            return;
        }
        
        // Uncomment when ml-classify-text is installed:
        /*
        const trainingData = examples.map(ex => ({
            text: this.featuresToText(ex.features),
            label: ex.isFalsePositive ? 'false_positive' : 'real_secret'
        }));
        
        this.classifier.train(trainingData);
        logger.info(`Trained classifier with ${examples.length} examples`);
        */
    }
    
    /**
     * Convert features to text representation for ml-classify-text
     */
    private featuresToText(features: SecretFeatures): string {
        const parts: string[] = [];
        
        if (features.hasSecretKeywords) parts.push('has_secret_keywords');
        if (features.isInConfigFile) parts.push('in_config_file');
        if (features.looksLikeFilePath) parts.push('looks_like_file_path');
        if (features.looksLikeClassName) parts.push('looks_like_class_name');
        if (features.looksLikeImport) parts.push('looks_like_import');
        if (features.hasExampleKeywords) parts.push('has_example_keywords');
        if (features.valueMatchesKeyName) parts.push('value_matches_key');
        if (features.isInComment) parts.push('in_comment');
        if (features.isBase64Like) parts.push('base64_like');
        if (features.isHexLike) parts.push('hex_like');
        
        parts.push(`entropy_${Math.round(features.entropy * 10)}`);
        parts.push(`length_${Math.round(features.length * 100)}`);
        
        return parts.join(' ');
    }
    
    /**
     * Classify if a detected secret is likely a false positive
     */
    isFalsePositive(
        value: string,
        line: string,
        pattern: SecretPattern,
        fileName: string
    ): boolean {
        if (!this.enabled) {
            return false;
        }
        
        try {
            const features = FeatureExtractor.extract(value, line, pattern.name, pattern.confidence, fileName);
            
            if (this.useEnhanced) {
                return this.classifyEnhanced(features);
            } else {
                return this.classifyFallback(features, value);
            }
        } catch (error) {
            logger.error('Error in ML classifier:', error);
            return false;
        }
    }
    
    /**
     * Enhanced classification using ml-classify-text
     */
    private classifyEnhanced(features: SecretFeatures): boolean {
        // Uncomment when ml-classify-text is installed:
        /*
        const text = this.featuresToText(features);
        const classifier = this.classifier as any; // Type assertion needed
        const predictions = classifier.predict(text);
        
        // Get probability of false positive
        const fpProb = predictions.find((p: any) => p.label === 'false_positive')?.confidence || 0;
        
        if (fpProb > this.confidenceThreshold) {
            logger.debug(`Enhanced ML filtered (confidence: ${(fpProb * 100).toFixed(1)}%)`);
            return true;
        }
        */
        
        return false;
    }
    
    /**
     * Fallback classification using weighted sum (current implementation)
     */
    private classifyFallback(features: SecretFeatures, value: string): boolean {
        const featureArray = FeatureExtractor.toArray(features);
        
        let sum = this.fallbackBias;
        for (let i = 0; i < featureArray.length && i < this.fallbackWeights.length; i++) {
            sum += featureArray[i] * this.fallbackWeights[i];
        }
        
        const probability = this.sigmoid(sum);
        const isFP = probability > this.confidenceThreshold;
        
        if (isFP) {
            logger.debug(`ML classifier filtered (confidence: ${(probability * 100).toFixed(1)}%): "${value}"`);
        }
        
        return isFP;
    }
    
    private sigmoid(x: number): number {
        return 1 / (1 + Math.exp(-x));
    }
    
    setEnabled(enabled: boolean): void {
        this.enabled = enabled;
    }
    
    setThreshold(threshold: number): void {
        this.confidenceThreshold = Math.max(0, Math.min(1, threshold));
    }
}

