import * as vscode from 'vscode';
import { HardcodedSecret, ScannerConfig } from './types';
import { PatternRegistry } from './PatternRegistry';
import { ScannerConfigManager } from './utils/ScannerConfig';
import { EnhancedEntropyAnalyzer } from './utils/EnhancedEntropyAnalyzer';
import { logger } from '../../../utils/logger';

/**
 * Main secret scanner class
 * Refactored to use dependency injection for better testability and modularity
 */
export class SecretScanner {
    private readonly patternRegistry: PatternRegistry;
    private configManager: ScannerConfigManager;
    private cachedDenylistRegexes: RegExp[] | null = null;

    constructor(
        patternRegistry?: PatternRegistry,
        configManager?: ScannerConfigManager
    ) {
        this.configManager = configManager || ScannerConfigManager.default();
        this.patternRegistry = patternRegistry || new PatternRegistry();
    }

    /**
     * Scans a document for hardcoded secrets
     * Returns both the filtered secrets and the count of filtered-out secrets
     */
    async scanDocument(document: vscode.TextDocument): Promise<{
        secrets: HardcodedSecret[];
        filteredCount: number;
        filterStats: {
            filteredByEntropy: number;
            filteredByStricterEntropy: number;
            filteredByDenylist: number;
            filteredByFunctionCall: number;
            filteredByTestData: number;
            filteredByFilename: number;
        };
    }> {
        const secrets: HardcodedSecret[] = [];
        
        // Check file size using line count as a proxy (avoids loading full text)
        // JavaScript max string length is approximately 2^30 - 24 characters (~1GB)
        // We'll set a more reasonable limit to avoid memory issues
        // Estimate: average line length ~100 chars, so 500k lines ≈ 50MB
        const MAX_LINES = 500000; // ~50MB estimated
        
        if (document.lineCount > MAX_LINES) {
            logger.warn(`Skipping file ${document.fileName} - file too large (${document.lineCount} lines). Maximum: ${MAX_LINES} lines`);
            return {
                secrets: [],
                filteredCount: 0,
                filterStats: {
                    filteredByEntropy: 0,
                    filteredByStricterEntropy: 0,
                    filteredByDenylist: 0,
                    filteredByFunctionCall: 0,
                    filteredByTestData: 0,
                    filteredByFilename: 0
                }
            };
        }
        
        let fullText: string;
        let lines: string[];
        
        try {
            // Try to get text - this can throw RangeError for very large files
            fullText = document.getText();
            
            // Check actual size after loading
            const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
            if (fullText.length > MAX_FILE_SIZE) {
                logger.warn(`Skipping file ${document.fileName} - file too large (${(fullText.length / 1024 / 1024).toFixed(2)}MB). Maximum size: ${MAX_FILE_SIZE / 1024 / 1024}MB`);
                return {
                    secrets: [],
                    filteredCount: 0,
                    filterStats: {
                        filteredByEntropy: 0,
                        filteredByStricterEntropy: 0,
                        filteredByDenylist: 0,
                        filteredByFunctionCall: 0,
                        filteredByTestData: 0,
                        filteredByFilename: 0
                    }
                };
            }
            
            // Try to split into lines - this can also throw RangeError
            try {
                lines = fullText.split('\n');
            } catch (splitError) {
                if (splitError instanceof RangeError && splitError.message.includes('Invalid string length')) {
                    logger.warn(`Skipping file ${document.fileName} - file too large to split into lines`);
                    return {
                        secrets: [],
                        filteredCount: 0,
                        filterStats: {
                            filteredByEntropy: 0,
                            filteredByStricterEntropy: 0,
                            filteredByDenylist: 0,
                            filteredByFunctionCall: 0,
                            filteredByTestData: 0,
                            filteredByFilename: 0
                        }
                    };
                }
                throw splitError;
            }
        } catch (error) {
            if (error instanceof RangeError && (error.message.includes('Invalid string length') || error.message.includes('Maximum call stack'))) {
                logger.warn(`Skipping file ${document.fileName} - file too large to process: ${error.message}`);
                return {
                    secrets: [],
                    filteredCount: 0,
                    filterStats: {
                        filteredByEntropy: 0,
                        filteredByStricterEntropy: 0,
                        filteredByDenylist: 0,
                        filteredByFunctionCall: 0,
                        filteredByTestData: 0,
                        filteredByFilename: 0
                    }
                };
            }
            throw error;
        }
        
        // Get ALL patterns to ensure comprehensive detection of all suspected secrets
        const allPatterns = this.patternRegistry.getAll();
        logger.debug(`Scanning with ${allPatterns.length} secret detection patterns`);

        // Separate patterns that need full-text matching (multiline/dotAll) from single-line patterns
        // Patterns with 's' (dotAll) flag can match across newlines, so they need full text
        // Patterns with 'm' (multiline) can also benefit from full-text matching for accuracy
        const multilinePatterns = allPatterns.filter(p => p.pattern.flags.includes('s') || p.pattern.flags.includes('m'));
        const singleLinePatterns = allPatterns.filter(p => !p.pattern.flags.includes('s') && !p.pattern.flags.includes('m'));

        // First, scan full text for multiline patterns
        for (const pattern of multilinePatterns) {
            try {
                // Ensure global flag is set for multiline patterns
                let flags = pattern.pattern.flags;
                if (!flags.includes('g')) {
                    flags += 'g';
                }
                const regex = new RegExp(pattern.pattern.source, flags);
                let match;
                let lastIndex = 0;
                const maxIterations = 10000; // Safety limit to prevent infinite loops
                let iterations = 0;

                while ((match = regex.exec(fullText)) !== null && iterations < maxIterations) {
                    iterations++;
                    // For patterns with multiple capture groups, prefer the last non-empty group (usually the value)
                    // This handles cases like: export VAR_NAME="value" where match[1] is VAR_NAME and match[2] is value
                    let value = match[0];
                    for (let i = match.length - 1; i >= 1; i--) {
                        if (match[i] && match[i].trim()) {
                            value = match[i];
                            break;
                        }
                    }
                    
                    // Calculate line number from match position
                    const textBeforeMatch = fullText.substring(0, match.index);
                    const lineNumber = (textBeforeMatch.match(/\n/g) || []).length + 1;
                    const lineStart = textBeforeMatch.lastIndexOf('\n') + 1;
                    const nextNewline = fullText.indexOf('\n', match.index);
                    const line = nextNewline !== -1 
                        ? fullText.substring(lineStart, nextNewline)
                        : fullText.substring(lineStart);
                    
                    // Calculate column position - find where the value actually starts in the line
                    let valueStart = match.index;
                    const valueIndexInMatch = match[0].indexOf(value);
                    if (valueIndexInMatch >= 0) {
                        valueStart = match.index + valueIndexInMatch;
                    }
                    const column = valueStart - lineStart + 1;
                    const context = line.trim();

                    secrets.push({
                        fileName: document.fileName,
                        lineNumber,
                        column,
                        value,
                        type: pattern.suggestion,
                        context,
                        patternConfidence: pattern.confidence,
                        detectionReason: `Pattern match: ${pattern.name} (${pattern.confidence} confidence)\nPattern: ${pattern.pattern.source}`
                    });

                    // Prevent infinite loop if regex doesn't advance
                    if (regex.lastIndex === lastIndex) {
                        regex.lastIndex++;
                    }
                    lastIndex = regex.lastIndex;
                }
            } catch (error) {
                logger.warn(`Error applying multiline pattern ${pattern.name}: ${error instanceof Error ? error.message : String(error)}`);
            }
        }

        // Then, scan line by line for single-line patterns (more efficient)
        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            const line = lines[lineIndex];
            const lineNumber = lineIndex + 1;

            for (const pattern of singleLinePatterns) {
                try {
                    // Ensure global flag is set for proper matching
                    let flags = pattern.pattern.flags;
                    if (!flags.includes('g')) {
                        flags += 'g';
                    }
                    const regex = new RegExp(pattern.pattern.source, flags);
                    let match;
                    let lastIndex = 0;
                    const maxIterations = 1000; // Safety limit per line
                    let iterations = 0;

                    while ((match = regex.exec(line)) !== null && iterations < maxIterations) {
                        iterations++;
                        // For patterns with multiple capture groups, prefer the last non-empty group (usually the value)
                        // This handles cases like: export VAR_NAME="value" where match[1] is VAR_NAME and match[2] is value
                        let value = match[0];
                        for (let i = match.length - 1; i >= 1; i--) {
                            if (match[i] && match[i].trim()) {
                                value = match[i];
                                break;
                            }
                        }

                        // Calculate the actual range of the value in the line
                        let valueStart = match.index;
                        const valueIndexInMatch = match[0].indexOf(value);
                        if (valueIndexInMatch >= 0) {
                            valueStart = match.index + valueIndexInMatch;
                        }

                        const column = valueStart + 1;
                        const context = line.trim();

                        secrets.push({
                            fileName: document.fileName,
                            lineNumber,
                            column,
                            value,
                            type: pattern.suggestion,
                            context,
                            patternConfidence: pattern.confidence,
                            detectionReason: `Pattern match: ${pattern.name} (${pattern.confidence} confidence)\nPattern: ${pattern.pattern.source}`
                        });

                        // Prevent infinite loop if regex doesn't advance
                        if (regex.lastIndex === lastIndex) {
                            regex.lastIndex++;
                        }
                        lastIndex = regex.lastIndex;
                    }
                } catch (error) {
                    logger.warn(`Error applying pattern ${pattern.name} on line ${lineNumber}: ${error instanceof Error ? error.message : String(error)}`);
                }
            }
        }

        // Entropy-based detection for high-entropy strings that don't match specific patterns
        // This catches secrets that don't have known patterns
        if (this.configManager.get().minEntropy > 0) {
            const entropySecrets = this.detectHighEntropySecrets(lines, document.fileName, secrets);
            secrets.push(...entropySecrets);
        }

        // Apply entropy filtering to reduce false positives
        // Filter out secrets with low entropy (e.g., paths, URLs, model names)
        const entropyThreshold = this.configManager.get().minEntropy;
        const entropyFiltered = this.filterByEntropy(secrets, entropyThreshold);
        const filteredSecrets = entropyFiltered.secrets;

        // Apply additional false-positive filters (denylist/function-call/test-data), after entropy filtering
        const postFiltered = this.applyPostEntropyFilters(filteredSecrets);
        
        // Deduplicate secrets - same value at same location should only appear once
        const deduplicatedSecrets = this.deduplicateSecrets(postFiltered.secrets);
        logger.debug(`Deduplicated ${postFiltered.secrets.length} detected secrets to ${deduplicatedSecrets.length}`);
        
        // Calculate filtered count (secrets removed by entropy filtering + other post-filters)
        const filterStats = {
            filteredByEntropy: entropyFiltered.stats.filteredByEntropy,
            filteredByStricterEntropy: entropyFiltered.stats.filteredByStricterEntropy,
            filteredByDenylist: postFiltered.stats.filteredByDenylist,
            filteredByFunctionCall: postFiltered.stats.filteredByFunctionCall,
            filteredByTestData: postFiltered.stats.filteredByTestData,
            filteredByFilename: postFiltered.stats.filteredByFilename
        };

        const filteredCount =
            filterStats.filteredByEntropy +
            filterStats.filteredByFilename +
            filterStats.filteredByDenylist +
            filterStats.filteredByFunctionCall +
            filterStats.filteredByTestData;
        
        return { secrets: deduplicatedSecrets, filteredCount, filterStats };
    }

    /**
     * Deduplicates secrets - removes duplicates where the same value is detected at the same location
     * Prefers higher confidence classifications and removes redundant detections
     */
    private deduplicateSecrets(secrets: HardcodedSecret[]): HardcodedSecret[] {
        const seen = new Map<string, HardcodedSecret>();
        const confidenceOrder: { [key: string]: number } = {
            'high': 3,
            'medium': 2,
            'low': 1
        };

        for (const secret of secrets) {
            // Create a unique key based on file, line, column, and value
            const key = `${secret.fileName}:${secret.lineNumber}:${secret.column}:${secret.value.toLowerCase()}`;
            
            const existing = seen.get(key);
            if (!existing) {
                seen.set(key, secret);
            } else {
                // If we've seen this before, keep the one with higher confidence or more specific type
                const existingConfidence = confidenceOrder[existing.type.toLowerCase().includes('high') ? 'high' : 
                    existing.type.toLowerCase().includes('medium') ? 'medium' : 'low'] || 1;
                const newConfidence = confidenceOrder[secret.type.toLowerCase().includes('high') ? 'high' : 
                    secret.type.toLowerCase().includes('medium') ? 'medium' : 'low'] || 1;
                
                // Prefer more specific types (e.g., "Google API Key" over "API Key")
                const existingSpecificity = existing.type.split(' ').length;
                const newSpecificity = secret.type.split(' ').length;
                
                if (newConfidence > existingConfidence || 
                    (newConfidence === existingConfidence && newSpecificity > existingSpecificity) ||
                    (newConfidence === existingConfidence && newSpecificity === existingSpecificity && 
                     secret.type.length > existing.type.length)) {
                    seen.set(key, secret);
                }
            }
        }

        // Also remove duplicates where the same value appears multiple times with different types
        // but at overlapping positions (e.g., "Token" and "Twilio Auth Token" for same value)
        const valueMap = new Map<string, HardcodedSecret[]>();
        for (const secret of Array.from(seen.values())) {
            const _valueKey = `${secret.fileName}:${secret.lineNumber}:${secret.value.toLowerCase()}`;
            if (!valueMap.has(_valueKey)) {
                valueMap.set(_valueKey, []);
            }
            valueMap.get(_valueKey)!.push(secret);
        }

        const finalSecrets: HardcodedSecret[] = [];
        for (const [_valueKey, duplicates] of valueMap.entries()) {
            if (duplicates.length === 1) {
                finalSecrets.push(duplicates[0]);
            } else {
                // Multiple detections of same value at same location - keep the most specific
                duplicates.sort((a, b) => {
                    const aSpecificity = a.type.split(' ').length;
                    const bSpecificity = b.type.split(' ').length;
                    if (aSpecificity !== bSpecificity) {
                        return bSpecificity - aSpecificity; // More specific first
                    }
                    // Prefer types that don't include generic terms
                    const aIsGeneric = /^(token|secret|key|api[_-]?key)$/i.test(a.type);
                    const bIsGeneric = /^(token|secret|key|api[_-]?key)$/i.test(b.type);
                    if (aIsGeneric && !bIsGeneric) return 1;
                    if (!aIsGeneric && bIsGeneric) return -1;
                    return 0;
                });
                finalSecrets.push(duplicates[0]);
            }
        }

        return finalSecrets;
    }

    /**
     * Cleans a value for entropy calculation by removing variable references and common patterns
     * This helps identify truly random strings vs structured data like paths, URLs, model names
     */
    private cleanValueForEntropy(value: string): string {
        // Remove shell variable references like $HOME, $VAR, ${VAR}
        let cleaned = value.replace(/\$\{?[A-Z_][A-Z0-9_]*\}?/g, '');
        
        // Remove common URL patterns (protocol://domain)
        cleaned = cleaned.replace(/https?:\/\/[^\s"'`]+/gi, '');
        
        // Remove common path patterns (starting with / or containing multiple /)
        if (/^\/[^\s"'`]*$/.test(value) || value.split('/').length > 2) {
            // If it looks like a path, remove path separators and common path components
            cleaned = cleaned.replace(/\/+/g, '');
        }
        
        return cleaned || value; // Return original if cleaning removes everything
    }

    /**
     * Checks if a value looks like a false positive (path, URL, model name, etc.)
     */
    private isFalsePositive(value: string): { isFalsePositive: boolean; reason?: string } {
        // Check for URLs
        if (/^https?:\/\/[^\s"'`]+$/i.test(value)) {
            return { isFalsePositive: true, reason: 'URL pattern' };
        }
        
        // Check for paths (absolute, relative, or with variables)
        if (/^(\/|\.\/|~\/|\$[A-Z_][A-Z0-9_]*\/)[^\s"'`]*$/.test(value) || 
            (value.includes('/') && value.split('/').length > 2 && 
             !/[A-Za-z0-9+/=]{20,}/.test(value))) { // Not base64-like
            return { isFalsePositive: true, reason: 'path pattern' };
        }
        
        // Check for model names (common patterns like "model-version" or "provider-model")
        if (/^[a-z0-9]+[-.][0-9.]+[-a-z0-9]*$/i.test(value) && value.length < 50) {
            return { isFalsePositive: true, reason: 'model name pattern' };
        }
        
        // Check for common environment variable patterns that aren't secrets
        if (/^\$[A-Z_][A-Z0-9_]*(\/|$)/.test(value)) {
            return { isFalsePositive: true, reason: 'environment variable path' };
        }
        
        return { isFalsePositive: false };
    }

    private isHighConfidenceDetection(secret: HardcodedSecret): boolean {
        if (secret.patternConfidence === 'high') return true;
        // Backward compatible: parse from detectionReason if present
        return /\(high confidence\)/i.test(secret.detectionReason ?? '');
    }

    private getDenylistRegexes(): RegExp[] {
        if (this.cachedDenylistRegexes) return this.cachedDenylistRegexes;
        const regexStrings = this.configManager.get().filters.denylist.regexes;
        const compiled: RegExp[] = [];
        for (const pattern of regexStrings) {
            try {
                // Support either "rawPattern" or "/rawPattern/flags" (e.g. "/foo/i")
                const trimmed = pattern.trim();
                const slashDelim = trimmed.startsWith('/') && trimmed.lastIndexOf('/') > 0;
                if (slashDelim) {
                    const lastSlash = trimmed.lastIndexOf('/');
                    const body = trimmed.slice(1, lastSlash);
                    const flags = trimmed.slice(lastSlash + 1);
                    compiled.push(new RegExp(body, flags));
                } else {
                    compiled.push(new RegExp(trimmed));
                }
            } catch (e) {
                logger.warn(`Invalid denylist regex skipped: ${pattern} (${e instanceof Error ? e.message : String(e)})`);
            }
        }
        this.cachedDenylistRegexes = compiled;
        return compiled;
    }

    private matchesDenylist(value: string): boolean {
        const cfg = this.configManager.get().filters.denylist;
        if (!cfg.enabled) return false;

        const haystack = cfg.caseInsensitiveSubstrings ? value.toLowerCase() : value;
        for (const entry of cfg.substrings) {
            if (!entry) continue;
            const needle = cfg.caseInsensitiveSubstrings ? entry.toLowerCase() : entry;
            if (needle && haystack.includes(needle)) {
                return true;
            }
        }

        for (const re of this.getDenylistRegexes()) {
            if (re.test(value)) return true;
        }

        return false;
    }

    private looksLikeFunctionCall(value: string): boolean {
        return value.includes('(') && value.includes(')');
    }

    private looksLikeTestData(value: string): boolean {
        const cfg = this.configManager.get().filters.testData;
        if (!cfg.enabled) return false;
        const v = value.toLowerCase();
        return cfg.substrings.some(s => s && v.includes(s.toLowerCase()));
    }

    private applyPostEntropyFilters(secrets: HardcodedSecret[]): {
        secrets: HardcodedSecret[];
        stats: { filteredByFilename: number; filteredByDenylist: number; filteredByFunctionCall: number; filteredByTestData: number };
    } {
        const cfg = this.configManager.get().filters;
        const out: HardcodedSecret[] = [];
        const stats = { filteredByFilename: 0, filteredByDenylist: 0, filteredByFunctionCall: 0, filteredByTestData: 0 };

        for (const secret of secrets) {
            // Always preserve high-confidence detections (configurable)
            if (cfg.highConfidenceBypass && this.isHighConfidenceDetection(secret)) {
                out.push(secret);
                continue;
            }

            if (cfg.filename.enabled && this.matchesFilenameFilter(secret.fileName)) {
                stats.filteredByFilename++;
                continue;
            }

            if (cfg.denylist.enabled && this.matchesDenylist(secret.value)) {
                stats.filteredByDenylist++;
                continue;
            }

            if (cfg.functionCall.enabled && this.looksLikeFunctionCall(secret.value)) {
                stats.filteredByFunctionCall++;
                continue;
            }

            if (cfg.testData.enabled && this.looksLikeTestData(secret.value)) {
                stats.filteredByTestData++;
                continue;
            }

            out.push(secret);
        }

        return { secrets: out, stats };
    }

    private matchesFilenameFilter(filePath: string): boolean {
        const cfg = this.configManager.get().filters.filename;
        if (!cfg.enabled) return false;

        const haystack = cfg.caseInsensitive ? filePath.toLowerCase() : filePath;

        for (const sub of cfg.substrings) {
            if (!sub) continue;
            const needle = cfg.caseInsensitive ? sub.toLowerCase() : sub;
            if (needle && haystack.includes(needle)) return true;
        }

        for (const suf of cfg.suffixes) {
            if (!suf) continue;
            const needle = cfg.caseInsensitive ? suf.toLowerCase() : suf;
            if (needle && haystack.endsWith(needle)) return true;
        }

        return false;
    }

    /**
     * Filters secrets using advanced entropy analysis with type-specific thresholds,
     * normalized entropy, length weighting, and chi-square uniformity tests
     * @returns Filtered secrets array
     */
    private filterByEntropy(secrets: HardcodedSecret[], defaultThreshold: number): {
        secrets: HardcodedSecret[];
        stats: { filteredByEntropy: number; filteredByStricterEntropy: number };
    } {
        const cfg = this.configManager.get().filters;
        const filtered: HardcodedSecret[] = [];
        const stats = { filteredByEntropy: 0, filteredByStricterEntropy: 0 };

        for (const secret of secrets) {
            // Always preserve high-confidence detections (configurable)
            if (cfg.highConfidenceBypass && this.isHighConfidenceDetection(secret)) {
                filtered.push(secret);
                continue;
            }

            // First check for obvious false positives
            const falsePositiveCheck = this.isFalsePositive(secret.value);
            if (falsePositiveCheck.isFalsePositive) {
                logger.debug(`Filtered out ${falsePositiveCheck.reason}: ${secret.type} at ${secret.fileName}:${secret.lineNumber} (value: ${secret.value.substring(0, 50)})`);
                stats.filteredByEntropy++;
                continue;
            }
            
            // Clean the value to remove variable references, URLs, and path structures
            const cleanedValue = this.cleanValueForEntropy(secret.value);
            
            // Skip if cleaned value is too short (minimum length requirement)
            if (cleanedValue.length < 20) {
                logger.debug(`Filtered out short string: ${secret.type} at ${secret.fileName}:${secret.lineNumber} (length: ${cleanedValue.length}, min: 20)`);
                stats.filteredByEntropy++;
                continue;
            }
            
            // Detect string type (hex, base64, or general)
            const stringType = EnhancedEntropyAnalyzer.detectStringType(cleanedValue);
            // Respect configured baseline, but keep existing type-specific minimums
            const baseTypeThreshold = Math.max(
                EnhancedEntropyAnalyzer.getTypeSpecificThreshold(stringType),
                defaultThreshold
            );
            const nonBase64Delta = (cfg.entropy.applyNonBase64Delta && stringType !== 'base64') ? cfg.entropy.nonBase64Delta : 0;
            const effectiveTypeThreshold = baseTypeThreshold + nonBase64Delta;
            
            // Calculate various entropy metrics
            const shannonEntropy = EnhancedEntropyAnalyzer.calculateShannonEntropy(cleanedValue);
            const normalizedEntropy = EnhancedEntropyAnalyzer.calculateNormalizedEntropy(cleanedValue);
            const lengthWeightedEntropy = EnhancedEntropyAnalyzer.calculateLengthWeightedEntropy(cleanedValue);
            const chiSquareTest = EnhancedEntropyAnalyzer.chiSquareUniformityTest(cleanedValue);
            
            // Apply multiple filtering criteria
            let shouldFilter = false;
            let filterReason = '';
            
            // 1. Type-specific entropy threshold
            if (shannonEntropy < effectiveTypeThreshold) {
                shouldFilter = true;
                filterReason = `entropy ${shannonEntropy.toFixed(2)} < ${stringType} threshold ${effectiveTypeThreshold.toFixed(2)}`;
                if (nonBase64Delta > 0 && shannonEntropy >= baseTypeThreshold) {
                    stats.filteredByStricterEntropy++;
                }
            }
            
            // 2. Normalized entropy check (should be >= 0.8 for uniform random)
            if (!shouldFilter && normalizedEntropy < 0.8) {
                shouldFilter = true;
                filterReason = `normalized entropy ${normalizedEntropy.toFixed(2)} < 0.8 (non-uniform distribution)`;
            }
            
            // 3. Length-weighted entropy check
            if (!shouldFilter && lengthWeightedEntropy < effectiveTypeThreshold) {
                shouldFilter = true;
                filterReason = `length-weighted entropy ${lengthWeightedEntropy.toFixed(2)} < ${stringType} threshold ${effectiveTypeThreshold.toFixed(2)}`;
                if (nonBase64Delta > 0 && lengthWeightedEntropy >= baseTypeThreshold) {
                    stats.filteredByStricterEntropy++;
                }
            }
            
            // 4. Chi-square uniformity test (p-value < 0.05 suggests non-uniform, likely FP)
            if (!shouldFilter && !chiSquareTest.isUniform && chiSquareTest.pValue < 0.05) {
                shouldFilter = true;
                filterReason = `chi-square test indicates non-uniform distribution (p=${chiSquareTest.pValue.toFixed(4)}, χ²=${chiSquareTest.chiSquare.toFixed(2)})`;
            }
            
            // 5. Very long strings (>200 chars) need higher entropy
            if (!shouldFilter && cleanedValue.length > 200 && shannonEntropy < effectiveTypeThreshold + 0.5) {
                shouldFilter = true;
                filterReason = `very long string (${cleanedValue.length} chars) with insufficient entropy ${shannonEntropy.toFixed(2)}`;
            }
            
            if (shouldFilter) {
                logger.debug(`Filtered out finding: ${secret.type} at ${secret.fileName}:${secret.lineNumber} (${filterReason}, type: ${stringType}, value: ${secret.value.substring(0, 50)})`);
                stats.filteredByEntropy++;
            } else {
                filtered.push(secret);
            }
        }

        if (stats.filteredByEntropy > 0) {
            logger.info(`Advanced entropy filtering: Removed ${stats.filteredByEntropy} low-entropy/non-uniform secrets`);
        }

        return { secrets: filtered, stats };
    }

    /**
     * Detects high-entropy strings that might be secrets but don't match specific patterns
     * Scans for strings in common secret variable contexts with high entropy
     */
    private detectHighEntropySecrets(
        lines: string[],
        fileName: string,
        existingSecrets: HardcodedSecret[]
    ): HardcodedSecret[] {
        const entropySecrets: HardcodedSecret[] = [];
        const config = this.configManager.get();
        const minEntropy = config.minEntropy;

        // Pattern to find potential secret assignments
        // Matches: key = "value", secret: "value", password="value", etc.
        const secretAssignmentPattern = /(?:secret|key|token|password|auth|api[_-]?key|access[_-]?token|private[_-]?key|credential|passwd|pwd)\s*[:=]\s*["']([^"']{16,})["']/gi;

        // Track already detected values to avoid duplicates
        const detectedValues = new Set(existingSecrets.map(s => s.value.toLowerCase()));

        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            const line = lines[lineIndex];
            const lineNumber = lineIndex + 1;

            // Skip if line is a comment
            if (/^\s*(\/\/|\/\*|#|<!--)/.test(line.trim())) {
                continue;
            }

            let match;
            while ((match = secretAssignmentPattern.exec(line)) !== null) {
                const value = match[1];
                const valueLower = value.toLowerCase();

                // Skip if already detected by pattern matching
                if (detectedValues.has(valueLower)) {
                    continue;
                }

                // Check entropy
                const entropyScore = EnhancedEntropyAnalyzer.calculateEntropyScore(value);
                
                if (entropyScore >= minEntropy) {
                    // Additional validation: should look like a secret
                    if (EnhancedEntropyAnalyzer.isHighEntropy(value, 0.5)) {
                        const column = match.index + match[0].indexOf(match[1]) + 1;
                        
                        entropySecrets.push({
                            fileName,
                            lineNumber,
                            column,
                            value,
                            type: 'High Entropy Secret',
                            context: line.trim(),
                            confidence: Math.min(0.6 + (entropyScore - minEntropy) * 0.5, 0.9),
                            entropy: entropyScore,
                            detectionReason: `High entropy string (entropy: ${entropyScore.toFixed(2)}, threshold: ${minEntropy})`
                        });

                        detectedValues.add(valueLower);
                    }
                }
            }
        }

        return entropySecrets;
    }

    /**
     * Scans the entire workspace for hardcoded secrets
     */
    async scanWorkspace(): Promise<{
        results: Map<string, HardcodedSecret[]>;
        totalFilesScanned: number;
        filteredSecretsCount: number;
        filteredByFilename: number;
        filteredByDenylist: number;
        filteredByFunctionCall: number;
        filteredByTestData: number;
        filteredByStricterEntropy: number;
        entropyThreshold: number;
        nonBase64EntropyDelta: number;
    }> {
        const results = new Map<string, HardcodedSecret[]>();
        let totalSecrets = 0;

        logger.info('Scanning current project for hardcoded secrets');

        const files = await vscode.workspace.findFiles(
            '**/*.{js,jsx,ts,tsx,json,env,yml,yaml,properties,ini,cfg,conf,env.local,env.development,env.production,txt,md,go,py,java,cs,php,rb,swift,kt,rs,cpp,c,cc,h,hpp,cxx,mm,m,vue,svelte,html,css,scss,less,sass,sh,bash,zsh,fish,ps1,ps,bat,cmd,tf,tfvars,hcl,dockerfile,sql,plsql,mysql,pgsql,r,R,lua,pl,perl,vb,vbs,f,f90,f95,f03,ml,mli,fs,fsx,ex,exs,erl,hrl,nim,cr,zig,v,vala,d,jl,el,lisp,cl,hs,lhs,elm,purescript,ocaml,scala,groovy,clj,cljs,dart,asm,s,scm,rkt,coffee,litcoffee,iced,styl,stylus,jade,pug,haml,slim,ejs,hbs,handlebars,mustache,erb,rhtml,edn,re,rei,res,resi,toml,xml,xsd,xsl,xslt}',
            '**/node_modules/**,**/dist/**,**/build/**,**/.git/**,**/coverage/**,**/.nyc_output/**,**/vendor/**,**/out/**,**/target/**,**/bin/**,**/obj/**,**/.vscode-test/**,**/coverage/**,**/.nyc_output/**,**/logs/**,**/temp/**,**/tmp/**,**/.venv/**,**/venv/**,**/site-packages/**,**/__pycache__/**,**/.pytest_cache/**,**/*.rtf,**/*.doc,**/*.docx,**/*.pdf,**/*.odt'
        );

        logger.info(`Found ${files.length} files to scan`);

        let totalEntropyFilteredCount = 0;
        let filteredByFilename = 0;
        let filteredByDenylist = 0;
        let filteredByFunctionCall = 0;
        let filteredByTestData = 0;
        let filteredByStricterEntropy = 0;
        for (const file of files) {
            try {
                const document = await vscode.workspace.openTextDocument(file);
                const scanResult = await this.scanDocument(document);
                const secrets = scanResult.secrets;
                totalEntropyFilteredCount += scanResult.filterStats.filteredByEntropy;
                filteredByFilename += scanResult.filterStats.filteredByFilename;
                filteredByDenylist += scanResult.filterStats.filteredByDenylist;
                filteredByFunctionCall += scanResult.filterStats.filteredByFunctionCall;
                filteredByTestData += scanResult.filterStats.filteredByTestData;
                filteredByStricterEntropy += scanResult.filterStats.filteredByStricterEntropy;

                if (secrets.length > 0) {
                    results.set(file.fsPath, secrets);
                    totalSecrets += secrets.length;
                    logger.debug(`Found ${secrets.length} secrets in ${vscode.workspace.asRelativePath(file.fsPath)}`);
                }
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                if (error instanceof RangeError && (errorMessage.includes('Invalid string length') || errorMessage.includes('Maximum call stack'))) {
                    logger.warn(` Skipping file ${vscode.workspace.asRelativePath(file.fsPath)} - file too large to process (${errorMessage})`);
                } else {
                    logger.error(` Error scanning file ${vscode.workspace.asRelativePath(file.fsPath)}:`, error);
                }
            }
        }

        const cfg = this.configManager.get();
        const entropyThreshold = cfg.minEntropy;
        const nonBase64EntropyDelta = (cfg.filters.entropy.applyNonBase64Delta ? cfg.filters.entropy.nonBase64Delta : 0);
        logger.info(
            `Scan complete: Found ${totalSecrets} potential secrets in ${results.size} files ` +
            `(filtered by entropy: ${totalEntropyFilteredCount}, filename: ${filteredByFilename}, denylist: ${filteredByDenylist}, ` +
            `function call: ${filteredByFunctionCall}, test data: ${filteredByTestData}, ` +
            `stricter entropy: ${filteredByStricterEntropy})`
        );
        return {
            results,
            totalFilesScanned: files.length,
            filteredSecretsCount: totalEntropyFilteredCount,
            filteredByFilename,
            filteredByDenylist,
            filteredByFunctionCall,
            filteredByTestData,
            filteredByStricterEntropy,
            entropyThreshold,
            nonBase64EntropyDelta
        };
    }

    /**
     * Scans only the current active file
     */
    async scanCurrentFile(): Promise<{
        results: Map<string, HardcodedSecret[]>;
        totalFilesScanned: number;
        filteredSecretsCount: number;
        filteredByFilename: number;
        filteredByDenylist: number;
        filteredByFunctionCall: number;
        filteredByTestData: number;
        filteredByStricterEntropy: number;
        entropyThreshold: number;
        nonBase64EntropyDelta: number;
    }> {
        const results = new Map<string, HardcodedSecret[]>();

        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
            logger.info('No active editor found');
            const cfg = this.configManager.get();
            const entropyThreshold = cfg.minEntropy;
            const nonBase64EntropyDelta = (cfg.filters.entropy.applyNonBase64Delta ? cfg.filters.entropy.nonBase64Delta : 0);
            return {
                results,
                totalFilesScanned: 0,
                filteredSecretsCount: 0,
                filteredByFilename: 0,
                filteredByDenylist: 0,
                filteredByFunctionCall: 0,
                filteredByTestData: 0,
                filteredByStricterEntropy: 0,
                entropyThreshold,
                nonBase64EntropyDelta
            };
        }

        logger.info(`Scanning current file: ${activeEditor.document.fileName}`);

        let entropyFilteredCount = 0;
        let filteredByFilename = 0;
        let filteredByDenylist = 0;
        let filteredByFunctionCall = 0;
        let filteredByTestData = 0;
        let filteredByStricterEntropy = 0;
        try {
            const scanResult = await this.scanDocument(activeEditor.document);
            const secrets = scanResult.secrets;
            entropyFilteredCount = scanResult.filterStats.filteredByEntropy;
            filteredByFilename = scanResult.filterStats.filteredByFilename;
            filteredByDenylist = scanResult.filterStats.filteredByDenylist;
            filteredByFunctionCall = scanResult.filterStats.filteredByFunctionCall;
            filteredByTestData = scanResult.filterStats.filteredByTestData;
            filteredByStricterEntropy = scanResult.filterStats.filteredByStricterEntropy;
            if (secrets.length > 0) {
                results.set(activeEditor.document.fileName, secrets);
                logger.info(`Found ${secrets.length} potential secrets in current file`);
            } else {
                logger.info('No secrets found in current file');
            }
        } catch (error) {
            if (error instanceof RangeError && error.message.includes('Invalid string length')) {
                logger.warn(` File ${activeEditor.document.fileName} is too large to scan`);
                vscode.window.showWarningMessage(`File is too large to scan for secrets (maximum size: 50MB)`);
            } else {
                logger.error(` Error scanning current file:`, error);
            }
        }

        const cfg = this.configManager.get();
        const entropyThreshold = cfg.minEntropy;
        const nonBase64EntropyDelta = (cfg.filters.entropy.applyNonBase64Delta ? cfg.filters.entropy.nonBase64Delta : 0);
        return {
            results,
            totalFilesScanned: 1,
            filteredSecretsCount: entropyFilteredCount,
            filteredByFilename,
            filteredByDenylist,
            filteredByFunctionCall,
            filteredByTestData,
            filteredByStricterEntropy,
            entropyThreshold,
            nonBase64EntropyDelta
        };
    }

    /**
     * Scans only the current project directory (excludes libraries)
     */
    async scanCurrentProject(): Promise<{
        results: Map<string, HardcodedSecret[]>;
        totalFilesScanned: number;
        filteredSecretsCount: number;
        filteredByFilename: number;
        filteredByDenylist: number;
        filteredByFunctionCall: number;
        filteredByTestData: number;
        filteredByStricterEntropy: number;
        entropyThreshold: number;
        nonBase64EntropyDelta: number;
    }> {
        const results = new Map<string, HardcodedSecret[]>();
        let totalSecrets = 0;

        logger.info('Scanning current project directory for hardcoded secrets');

        const workspaceRoot = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceRoot) {
            logger.error('No workspace root found');
            const cfg = this.configManager.get();
            const entropyThreshold = cfg.minEntropy;
            const nonBase64EntropyDelta = (cfg.filters.entropy.applyNonBase64Delta ? cfg.filters.entropy.nonBase64Delta : 0);
            return {
                results,
                totalFilesScanned: 0,
                filteredSecretsCount: 0,
                filteredByFilename: 0,
                filteredByDenylist: 0,
                filteredByFunctionCall: 0,
                filteredByTestData: 0,
                filteredByStricterEntropy: 0,
                entropyThreshold,
                nonBase64EntropyDelta
            };
        }

        const files = await vscode.workspace.findFiles(
            '**/*.{js,jsx,ts,tsx,json,env,yml,yaml,properties,ini,cfg,conf,env.local,env.development,env.production,txt,md,go,py,java,cs,php,rb,swift,kt,rs,cpp,c,cc,h,hpp,cxx,mm,m,vue,svelte,html,css,scss,less,sass,sh,bash,zsh,fish,ps1,ps,bat,cmd,tf,tfvars,hcl,dockerfile,sql,plsql,mysql,pgsql,r,R,lua,pl,perl,vb,vbs,f,f90,f95,f03,ml,mli,fs,fsx,ex,exs,erl,hrl,nim,cr,zig,v,vala,d,jl,el,lisp,cl,hs,lhs,elm,purescript,ocaml,scala,groovy,clj,cljs,dart,asm,s,scm,rkt,coffee,litcoffee,iced,styl,stylus,jade,pug,haml,slim,ejs,hbs,handlebars,mustache,erb,rhtml,edn,re,rei,res,resi,toml,xml,xsd,xsl,xslt}',
            '**/node_modules/**,**/dist/**,**/build/**,**/.git/**,**/coverage/**,**/.nyc_output/**,**/vendor/**,**/out/**,**/target/**,**/bin/**,**/obj/**,**/.vscode-test/**,**/logs/**,**/temp/**,**/tmp/**,**/.venv/**,**/venv/**,**/site-packages/**,**/__pycache__/**,**/.pytest_cache/**,**/package-lock.json,**/yarn.lock,**/*.rtf,**/*.doc,**/*.docx,**/*.pdf,**/*.odt'
        );

        logger.info(`Found ${files.length} files to scan`);

        let totalEntropyFilteredCount = 0;
        let filteredByFilename = 0;
        let filteredByDenylist = 0;
        let filteredByFunctionCall = 0;
        let filteredByTestData = 0;
        let filteredByStricterEntropy = 0;
        for (const file of files) {
            try {
                const document = await vscode.workspace.openTextDocument(file);
                const scanResult = await this.scanDocument(document);
                const secrets = scanResult.secrets;
                totalEntropyFilteredCount += scanResult.filterStats.filteredByEntropy;
                filteredByFilename += scanResult.filterStats.filteredByFilename;
                filteredByDenylist += scanResult.filterStats.filteredByDenylist;
                filteredByFunctionCall += scanResult.filterStats.filteredByFunctionCall;
                filteredByTestData += scanResult.filterStats.filteredByTestData;
                filteredByStricterEntropy += scanResult.filterStats.filteredByStricterEntropy;

                if (secrets.length > 0) {
                    results.set(file.fsPath, secrets);
                    totalSecrets += secrets.length;
                    logger.debug(`Found ${secrets.length} secrets in ${vscode.workspace.asRelativePath(file.fsPath)}`);
                }
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                if (error instanceof RangeError && (errorMessage.includes('Invalid string length') || errorMessage.includes('Maximum call stack'))) {
                    logger.warn(` Skipping file ${vscode.workspace.asRelativePath(file.fsPath)} - file too large to process (${errorMessage})`);
                } else {
                    logger.error(` Error scanning file ${vscode.workspace.asRelativePath(file.fsPath)}:`, error);
                }
            }
        }

        const cfg = this.configManager.get();
        const entropyThreshold = cfg.minEntropy;
        const nonBase64EntropyDelta = (cfg.filters.entropy.applyNonBase64Delta ? cfg.filters.entropy.nonBase64Delta : 0);
        logger.info(
            `Project scan complete: Found ${totalSecrets} potential secrets in ${results.size} files ` +
            `(filtered by entropy: ${totalEntropyFilteredCount}, filename: ${filteredByFilename}, denylist: ${filteredByDenylist}, ` +
            `function call: ${filteredByFunctionCall}, test data: ${filteredByTestData}, ` +
            `stricter entropy: ${filteredByStricterEntropy})`
        );
        return {
            results,
            totalFilesScanned: files.length,
            filteredSecretsCount: totalEntropyFilteredCount,
            filteredByFilename,
            filteredByDenylist,
            filteredByFunctionCall,
            filteredByTestData,
            filteredByStricterEntropy,
            entropyThreshold,
            nonBase64EntropyDelta
        };
    }

    /**
     * Configures the scanner behavior
     */
    configure(options: {
        minEntropy?: number;
        filters?: Partial<ScannerConfig['filters']>;
    }): void {
        const updates: Partial<ScannerConfig> = {};

        if (options.minEntropy !== undefined) {
            updates.minEntropy = options.minEntropy;
        }
        if (options.filters !== undefined) {
            updates.filters = options.filters as Partial<ScannerConfig['filters']> as any;
            // invalidate cached regexes when denylist changes
            this.cachedDenylistRegexes = null;
        }

        this.configManager = this.configManager.with(updates);

        logger.info('Scanner configuration updated:', this.configManager.get());
    }

    /**
     * Generates a suggested name for a secret based on its context
     */
    generateSecretName(detected: HardcodedSecret, fileName: string): string {
        const baseName = fileName.split('/').pop()?.replace(/\.[^/.]+$/, '') || 'unknown';
        const timestamp = Date.now();

        const contextLower = detected.context.toLowerCase();
        let type = 'secret';

        if (contextLower.includes('api') || contextLower.includes('key')) {
            type = 'api-key';
        } else if (contextLower.includes('password') || contextLower.includes('passwd')) {
            type = 'password';
        } else if (contextLower.includes('token')) {
            type = 'token';
        } else if (contextLower.includes('database') || contextLower.includes('db')) {
            type = 'database-url';
        }

        return `/secrets/${baseName}-${type}-${timestamp}`;
    }

    // Static methods for backward compatibility
    private static defaultInstance: SecretScanner | null = null;

    private static getDefaultInstance(): SecretScanner {
        if (!SecretScanner.defaultInstance) {
            SecretScanner.defaultInstance = new SecretScanner();
        }
        return SecretScanner.defaultInstance;
    }

    static async scanDocument(document: vscode.TextDocument): Promise<{
        secrets: HardcodedSecret[];
        filteredCount: number;
        filterStats: {
            filteredByEntropy: number;
            filteredByStricterEntropy: number;
            filteredByDenylist: number;
            filteredByFunctionCall: number;
            filteredByTestData: number;
            filteredByFilename: number;
        };
    }> {
        return SecretScanner.getDefaultInstance().scanDocument(document);
    }

    static async scanWorkspace(): Promise<{
        results: Map<string, HardcodedSecret[]>;
        totalFilesScanned: number;
        filteredSecretsCount: number;
        filteredByFilename: number;
        filteredByDenylist: number;
        filteredByFunctionCall: number;
        filteredByTestData: number;
        filteredByStricterEntropy: number;
        entropyThreshold: number;
        nonBase64EntropyDelta: number;
    }> {
        return SecretScanner.getDefaultInstance().scanWorkspace();
    }

    static async scanCurrentFile(): Promise<{
        results: Map<string, HardcodedSecret[]>;
        totalFilesScanned: number;
        filteredSecretsCount: number;
        filteredByFilename: number;
        filteredByDenylist: number;
        filteredByFunctionCall: number;
        filteredByTestData: number;
        filteredByStricterEntropy: number;
        entropyThreshold: number;
        nonBase64EntropyDelta: number;
    }> {
        return SecretScanner.getDefaultInstance().scanCurrentFile();
    }

    static async scanCurrentProject(): Promise<{
        results: Map<string, HardcodedSecret[]>;
        totalFilesScanned: number;
        filteredSecretsCount: number;
        filteredByFilename: number;
        filteredByDenylist: number;
        filteredByFunctionCall: number;
        filteredByTestData: number;
        filteredByStricterEntropy: number;
        entropyThreshold: number;
        nonBase64EntropyDelta: number;
    }> {
        return SecretScanner.getDefaultInstance().scanCurrentProject();
    }

    static configure(options: {
        minEntropy?: number;
        filters?: Partial<ScannerConfig['filters']>;
    }): void {
        SecretScanner.getDefaultInstance().configure(options);
    }

    static generateSecretName(detected: HardcodedSecret, fileName: string): string {
        return SecretScanner.getDefaultInstance().generateSecretName(detected, fileName);
    }
}

