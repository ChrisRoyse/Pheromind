# Logging Best Practices: F3 - Self-adaptive `interpretationLogic` for Scribe (Phase 1)

## 1. Introduction

This document outlines best practices for implementing the enhanced logging system for the Pheromone Scribe. The logging system is a critical component of Phase 1 of the Self-adaptive `interpretationLogic` for Scribe feature, as it will provide the data foundation for future analysis and self-adaptation capabilities.

## 2. Logging Format and Structure

### 2.1 JSONL as the Optimal Format

JSONL (JSON Lines) is recommended as the optimal format for the Scribe's interpretation logs for several reasons:

1. **One Entry Per Line**: Each log entry is a complete, self-contained JSON object on a single line, making it easy to append new entries without reading the entire file.

2. **Structured Data**: Unlike plain text logs, JSONL preserves the structured nature of the data, maintaining relationships between different elements of the interpretation process.

3. **Schema Flexibility**: The format can evolve over time to include additional fields without breaking existing log processing tools.

4. **Tool Support**: Many log analysis tools and libraries support JSONL natively.

5. **Human Readability**: With appropriate formatting, JSONL logs can be reasonably human-readable for debugging purposes.

### 2.2 Log Entry Schema

A well-designed log entry schema should balance completeness with efficiency. The recommended schema includes:

#### Core Fields

```json
{
  "version": "1.0",
  "timestamp": "2025-05-15T16:30:00.000Z",
  "scribe_version": "1.2.3",
  "session_id": "abcd1234",
  "summary": "...",
  "handoff_reason_code": "...",
  "source_orchestrator": "...",
  "interpretation_results": {
    "document_matches": [...],
    "signal_matches": [...],
    "unmatched_segments": [...]
  },
  "processing_stats": {...},
  "config_hash": "sha256:..."
}
```

#### Document Match Fields

```json
{
  "pattern_id": "doc_pattern_1",
  "pattern_index": 2,
  "pattern": "...",
  "matched_text": "...",
  "match_position": [start, end],
  "extracted_data": {...},
  "confidence": 0.95,
  "generated_doc_entry": {...}
}
```

#### Signal Match Fields

```json
{
  "rule_id": "signal_rule_3",
  "rule_index": 5,
  "condition_type": "...",
  "condition_value": "...",
  "matched_text": "...",
  "confidence": 0.85,
  "generated_signal": {...}
}
```

#### Unmatched Segment Fields

```json
{
  "text": "...",
  "position": [start, end],
  "potential_matches": [
    {
      "pattern_id": "doc_pattern_4",
      "confidence": 0.3,
      "reason": "partial_match"
    }
  ]
}
```

#### Processing Stats Fields

```json
{
  "duration_ms": 12,
  "patterns_evaluated": 8,
  "rules_evaluated": 12,
  "memory_usage_kb": 256
}
```

### 2.3 Schema Versioning

Include a version field in the log schema to facilitate future evolution:

```json
{
  "version": "1.0",
  // Other fields...
}
```

When the schema changes significantly, increment the version number and document the changes. This allows log processing tools to handle different versions appropriately.

## 3. Confidence Scoring Methodology

### 3.1 Principles for Effective Confidence Scoring

1. **Objectivity**: Scores should be based on objective criteria where possible.
2. **Consistency**: Similar matches should receive similar scores.
3. **Meaningfulness**: Scores should correlate with the quality of the match.
4. **Transparency**: The factors contributing to a score should be clear.
5. **Calibration**: Scores should be calibrated to use the full range from 0.0 to 1.0 effectively.

### 3.2 Document Pattern Confidence Factors

For document patterns, consider these factors in confidence scoring:

1. **Pattern Specificity**: More specific patterns (e.g., with more literal text and fewer wildcards) should yield higher confidence.
   ```javascript
   function calculatePatternSpecificity(pattern) {
     const literalCharCount = pattern.replace(/\\\w|\\[pP]\{[^}]+\}|\[[^\]]+\]|\(\?[^)]+\)|\.|\\[dDwWsS]|\+|\*|\?|\{\d+,\d*\}/g, '').length;
     const totalLength = pattern.length;
     return literalCharCount / totalLength;
   }
   ```

2. **Match Coverage**: What percentage of the pattern is matched?
   ```javascript
   function calculateMatchCoverage(pattern, match) {
     // For regex patterns, this is typically 100% or 0%
     // For fuzzy matching, this could be partial
     return match ? 1.0 : 0.0;
   }
   ```

3. **Capture Group Completeness**: Are all expected capture groups present and non-empty?
   ```javascript
   function calculateCaptureGroupCompleteness(expectedGroups, actualGroups) {
     if (expectedGroups.length === 0) return 1.0;
     
     const filledGroups = expectedGroups.filter(group => 
       actualGroups[group] && actualGroups[group].trim().length > 0
     );
     
     return filledGroups.length / expectedGroups.length;
   }
   ```

4. **Context Relevance**: Does the match appear in a relevant context?
   ```javascript
   function calculateContextRelevance(summary, matchPosition, relevantKeywords) {
     const contextWindow = 50; // characters
     const start = Math.max(0, matchPosition[0] - contextWindow);
     const end = Math.min(summary.length, matchPosition[1] + contextWindow);
     const context = summary.substring(start, end);
     
     return relevantKeywords.some(keyword => context.includes(keyword)) ? 1.0 : 0.7;
   }
   ```

### 3.3 Signal Rule Confidence Factors

For signal rules, consider these factors:

1. **Condition Type Confidence**:
   - `handoff_reason_code_match`: Binary (1.0 for exact match, 0.0 for no match)
   - `summary_keywords`: Proportion of keywords found
   - `pattern_match`: Similar to document pattern confidence

2. **Keyword Match Quality**:
   ```javascript
   function calculateKeywordMatchQuality(keywords, summary) {
     const foundKeywords = keywords.filter(keyword => 
       summary.toLowerCase().includes(keyword.toLowerCase())
     );
     
     const baseScore = foundKeywords.length / keywords.length;
     
     // Bonus for keyword proximity
     const proximityBonus = calculateKeywordProximity(foundKeywords, summary);
     
     return Math.min(baseScore + proximityBonus, 1.0);
   }
   ```

3. **Rule Specificity**:
   ```javascript
   function calculateRuleSpecificity(rule) {
     // More specific conditions get higher scores
     switch (rule.conditionType) {
       case 'handoff_reason_code_match':
         return 1.0; // Very specific
       case 'summary_keywords':
         return 0.5 + (rule.keywords.length * 0.05); // More keywords = more specific
       case 'pattern_match':
         return 0.7 + calculatePatternSpecificity(rule.pattern) * 0.3;
       default:
         return 0.5;
     }
   }
   ```

### 3.4 Composite Confidence Score

Combine individual factors into a composite score:

```javascript
function calculateDocumentPatternConfidence(pattern, match, summary) {
  const specificity = calculatePatternSpecificity(pattern) * 0.3;
  const coverage = calculateMatchCoverage(pattern, match) * 0.3;
  const completeness = calculateCaptureGroupCompleteness(pattern.captureGroups, match.groups) * 0.3;
  const relevance = calculateContextRelevance(summary, match.position, relevantKeywords) * 0.1;
  
  return specificity + coverage + completeness + relevance;
}

function calculateSignalRuleConfidence(rule, match, summary) {
  const conditionConfidence = calculateConditionConfidence(rule, match, summary) * 0.7;
  const specificity = calculateRuleSpecificity(rule) * 0.3;
  
  return conditionConfidence + specificity;
}
```

## 4. Logging Implementation Strategies

### 4.1 Asynchronous Logging

Implement logging asynchronously to minimize performance impact:

```javascript
class AsyncLogger {
  constructor(options) {
    this.options = options;
    this.queue = [];
    this.processing = false;
    this.writer = this.createWriter();
  }
  
  createWriter() {
    // Create appropriate writer based on options
    if (this.options.useRotation) {
      return new RotatingFileWriter(this.options);
    } else {
      return new SimpleFileWriter(this.options);
    }
  }
  
  log(entry) {
    // Add timestamp if not present
    if (!entry.timestamp) {
      entry.timestamp = new Date().toISOString();
    }
    
    // Add to queue
    this.queue.push(entry);
    
    // Process queue if not already processing
    if (!this.processing) {
      this.processQueue();
    }
  }
  
  async processQueue() {
    this.processing = true;
    
    try {
      while (this.queue.length > 0) {
        const batch = this.queue.splice(0, this.options.batchSize || 10);
        await this.writer.writeBatch(batch);
      }
    } catch (error) {
      console.error('Error processing log queue:', error);
    } finally {
      this.processing = false;
    }
  }
}
```

### 4.2 Log File Rotation

Implement log file rotation to manage log growth:

```javascript
class RotatingFileWriter {
  constructor(options) {
    this.options = options;
    this.currentFile = this.determineCurrentFile();
    this.currentSize = this.getCurrentFileSize();
  }
  
  determineCurrentFile() {
    // Logic to determine current log file based on rotation strategy
    // (e.g., daily rotation, size-based rotation)
    return `${this.options.baseFilePath}.${this.getRotationSuffix()}`;
  }
  
  getRotationSuffix() {
    if (this.options.rotationStrategy === 'daily') {
      return new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    } else {
      // Size-based rotation
      return '1'; // Start with 1, increment as needed
    }
  }
  
  getCurrentFileSize() {
    try {
      const stats = fs.statSync(this.currentFile);
      return stats.size;
    } catch (error) {
      return 0; // File doesn't exist yet
    }
  }
  
  async writeBatch(entries) {
    const lines = entries.map(entry => JSON.stringify(entry)).join('\n') + '\n';
    const lineSize = Buffer.byteLength(lines);
    
    // Check if rotation is needed
    if (this.currentSize + lineSize > this.options.maxFileSize) {
      await this.rotate();
    }
    
    // Write to current file
    await fs.appendFile(this.currentFile, lines);
    this.currentSize += lineSize;
  }
  
  async rotate() {
    // Logic to rotate log files
    // (e.g., create new file, archive old file)
    this.currentFile = this.determineCurrentFile();
    this.currentSize = 0;
    
    // Prune old log files if needed
    await this.pruneOldLogs();
  }
  
  async pruneOldLogs() {
    if (!this.options.maxFiles) return;
    
    // Logic to identify and remove old log files
    // to keep only the most recent `maxFiles` logs
  }
}
```

### 4.3 Buffering and Batching

Implement buffering and batching to improve performance:

```javascript
class BufferedLogger {
  constructor(options) {
    this.options = options;
    this.buffer = [];
    this.lastFlush = Date.now();
    this.flushInterval = setInterval(() => this.flushIfNeeded(), 
                                    options.flushIntervalMs || 5000);
  }
  
  log(entry) {
    this.buffer.push(entry);
    
    if (this.buffer.length >= this.options.maxBufferSize) {
      this.flush();
    }
  }
  
  flushIfNeeded() {
    const now = Date.now();
    if (this.buffer.length > 0 && 
        (now - this.lastFlush) >= this.options.flushIntervalMs) {
      this.flush();
    }
  }
  
  async flush() {
    if (this.buffer.length === 0) return;
    
    const entries = [...this.buffer];
    this.buffer = [];
    this.lastFlush = Date.now();
    
    try {
      await this.options.writer.writeBatch(entries);
    } catch (error) {
      console.error('Error flushing log buffer:', error);
      // Consider adding entries back to buffer or to a recovery queue
    }
  }
  
  destroy() {
    clearInterval(this.flushInterval);
    return this.flush(); // Final flush
  }
}
```

## 5. Configuration Best Practices

### 5.1 Flexible Configuration Options

Provide flexible configuration options to accommodate different environments and use cases:

```json
{
  "scribeSettings": {
    "logging": {
      "enabled": true,
      "level": "detailed",
      "format": "jsonl",
      "output": {
        "type": "file",
        "path": "./logs/scribe-interpretation.jsonl",
        "rotation": {
          "enabled": true,
          "strategy": "size",
          "maxSize": "10MB",
          "maxFiles": 5
        }
      },
      "content": {
        "includeFullSummary": true,
        "includeUnmatched": true,
        "includeProcessingStats": true
      },
      "performance": {
        "async": true,
        "batchSize": 10,
        "flushIntervalMs": 5000,
        "maxBufferSize": 100
      }
    }
  }
}
```

### 5.2 Environment-Specific Defaults

Provide sensible defaults for different environments:

```javascript
function getDefaultLoggingConfig(environment) {
  const baseConfig = {
    enabled: true,
    level: "detailed",
    format: "jsonl",
    content: {
      includeFullSummary: true,
      includeUnmatched: true,
      includeProcessingStats: true
    }
  };
  
  switch (environment) {
    case 'development':
      return {
        ...baseConfig,
        output: {
          type: "file",
          path: "./logs/scribe-interpretation.jsonl",
          rotation: {
            enabled: false
          }
        },
        performance: {
          async: true,
          batchSize: 1, // Immediate logging for debugging
          flushIntervalMs: 1000
        }
      };
    
    case 'production':
      return {
        ...baseConfig,
        level: "standard", // Less verbose
        output: {
          type: "file",
          path: "./logs/scribe-interpretation.jsonl",
          rotation: {
            enabled: true,
            strategy: "size",
            maxSize: "50MB",
            maxFiles: 10
          }
        },
        performance: {
          async: true,
          batchSize: 20,
          flushIntervalMs: 10000,
          maxBufferSize: 200
        }
      };
    
    default:
      return baseConfig;
  }
}
```

### 5.3 Dynamic Configuration

Support dynamic configuration changes without requiring a restart:

```javascript
class ConfigurableLogger {
  constructor(initialConfig) {
    this.config = initialConfig;
    this.writer = this.createWriter();
  }
  
  updateConfig(newConfig) {
    const configChanged = JSON.stringify(this.config) !== JSON.stringify(newConfig);
    
    if (configChanged) {
      // Flush any pending logs with old configuration
      this.flush();
      
      // Update configuration
      this.config = newConfig;
      
      // Recreate writer if output configuration changed
      if (JSON.stringify(this.config.output) !== JSON.stringify(newConfig.output)) {
        this.writer = this.createWriter();
      }
    }
  }
  
  // Other methods...
}
```

## 6. Performance Optimization

### 6.1 Selective Logging

Implement selective logging to reduce volume while maintaining value:

```javascript
function shouldLogInterpretation(summary, results, config) {
  // Always log if detailed logging is enabled
  if (config.level === 'detailed') return true;
  
  // Always log errors
  if (results.error) return true;
  
  // Always log low-confidence interpretations
  const hasLowConfidence = results.document_matches.some(m => m.confidence < 0.5) ||
                          results.signal_matches.some(m => m.confidence < 0.5);
  if (hasLowConfidence) return true;
  
  // Always log if there are unmatched segments
  if (results.unmatched_segments.length > 0) return true;
  
  // For standard level, log a percentage of normal interpretations
  if (config.level === 'standard') {
    // Log 20% of normal interpretations
    return Math.random() < 0.2;
  }
  
  // For minimal level, only log unusual interpretations
  return false;
}
```

### 6.2 Memory Management

Implement efficient memory management to reduce overhead:

```javascript
function createLogEntry(summary, results, config) {
  // Base entry with required fields
  const entry = {
    version: "1.0",
    timestamp: new Date().toISOString(),
    session_id: getCurrentSessionId()
  };
  
  // Add fields based on configuration
  if (config.content.includeFullSummary) {
    entry.summary = summary;
  } else {
    // Include only a truncated summary
    entry.summary_truncated = summary.length > 100 
      ? summary.substring(0, 100) + '...' 
      : summary;
  }
  
  // Include only necessary result fields
  entry.interpretation_results = {
    document_matches: results.document_matches.map(simplifyDocumentMatch),
    signal_matches: results.signal_matches.map(simplifySignalMatch)
  };
  
  if (config.content.includeUnmatched && results.unmatched_segments.length > 0) {
    entry.interpretation_results.unmatched_segments = results.unmatched_segments;
  }
  
  if (config.content.includeProcessingStats) {
    entry.processing_stats = results.processing_stats;
  }
  
  return entry;
}

function simplifyDocumentMatch(match) {
  // Return only the fields needed for analysis
  return {
    pattern_id: match.pattern_id,
    confidence: match.confidence,
    extracted_data: match.extracted_data,
    generated_doc_entry: {
      file_path: match.generated_doc_entry.file_path,
      type: match.generated_doc_entry.type
    }
  };
}
```

### 6.3 Compression

Consider compression for log storage:

```javascript
class CompressedFileWriter {
  constructor(options) {
    this.options = options;
    this.currentFile = this.determineCurrentFile();
  }
  
  async writeBatch(entries) {
    const lines = entries.map(entry => JSON.stringify(entry)).join('\n') + '\n';
    
    // Compress the data
    const compressed = await this.compress(lines);
    
    // Write compressed data
    await fs.appendFile(this.currentFile, compressed);
  }
  
  async compress(data) {
    return new Promise((resolve, reject) => {
      zlib.gzip(data, (err, compressed) => {
        if (err) reject(err);
        else resolve(compressed);
      });
    });
  }
}
```

## 7. Log Analysis Preparation

### 7.1 Indexing Considerations

Design logs with future indexing in mind:

1. **Include Unique Identifiers**: Each log entry should have a unique identifier (e.g., `session_id` + timestamp).

2. **Consistent Field Names**: Use consistent field names across all log entries to facilitate querying.

3. **Normalized Data**: Where possible, normalize data (e.g., use consistent enum values for condition types).

4. **Hierarchical Structure**: Use a hierarchical structure that groups related fields, making it easier to query specific aspects.

### 7.2 Search Optimization

Include fields that will be commonly searched:

```json
{
  "metadata": {
    "project_id": "project-123",
    "orchestrator_type": "feature_implementation",
    "summary_length": 256,
    "has_unmatched_segments": true,
    "confidence_min": 0.3,
    "confidence_max": 0.95,
    "confidence_avg": 0.72,
    "document_types": ["implementation", "test"],
    "signal_types": ["task_completed", "dependency_identified"]
  }
}
```

### 7.3 Aggregation Support

Include fields that support efficient aggregation:

```json
{
  "metrics": {
    "pattern_count": 5,
    "rule_count": 3,
    "match_count": 2,
    "unmatched_count": 1,
    "processing_time_ms": 12
  }
}
```

## 8. Security and Privacy Considerations

### 8.1 Sensitive Data Handling

Implement practices to protect sensitive data:

1. **Data Minimization**: Log only what's necessary for analysis.

2. **Data Anonymization**: Consider anonymizing sensitive information:
   ```javascript
   function anonymizeSummary(summary) {
     // Replace potential sensitive information
     return summary
       .replace(/password[s]?[\s:=]+\S+/gi, 'password: [REDACTED]')
       .replace(/token[s]?[\s:=]+\S+/gi, 'token: [REDACTED]')
       .replace(/key[s]?[\s:=]+\S+/gi, 'key: [REDACTED]');
   }
   ```

3. **Access Control**: Implement appropriate access controls for log files.

### 8.2 Log File Security

Secure log files appropriately:

1. **File Permissions**: Set restrictive permissions on log files.
   ```javascript
   // After creating a new log file
   fs.chmod(logFilePath, 0o600); // Owner read/write only
   ```

2. **Secure Storage**: Store logs in a secure location.

3. **Encryption**: Consider encrypting sensitive logs.
   ```javascript
   async function encryptLogEntry(entry, encryptionKey) {
     const iv = crypto.randomBytes(16);
     const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
     
     let encrypted = cipher.update(JSON.stringify(entry), 'utf8', 'hex');
     encrypted += cipher.final('hex');
     
     const authTag = cipher.getAuthTag();
     
     return {
       iv: iv.toString('hex'),
       encrypted: encrypted,
       tag: authTag.toString('hex')
     };
   }
   ```

## 9. Conclusion

Implementing a robust logging system for the Pheromone Scribe requires careful consideration of format, content, performance, and security. By following the best practices outlined in this document, the logging system can provide valuable data for future analysis while minimizing impact on the Scribe's core functionality.

Key recommendations:

1. **Use JSONL Format**: Structured, efficient, and widely supported.
2. **Implement Comprehensive Schema**: Include all information needed for future analysis.
3. **Develop Meaningful Confidence Scoring**: Based on objective criteria and calibrated appropriately.
4. **Use Asynchronous Logging**: Minimize performance impact through buffering and batching.
5. **Implement Log Rotation**: Manage log growth and retention.
6. **Provide Flexible Configuration**: Accommodate different environments and use cases.
7. **Optimize Performance**: Use selective logging and efficient memory management.
8. **Design for Analysis**: Include fields that facilitate searching, indexing, and aggregation.
9. **Address Security Concerns**: Protect sensitive data and secure log files.

By implementing these practices, the Enhanced Scribe Logging system will provide a solid foundation for the future phases of the Self-adaptive `interpretationLogic` for Scribe feature.