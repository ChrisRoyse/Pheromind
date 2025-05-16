# Adaptive Scribe - Enhanced Logging (Phase 1)

This module provides enhanced logging capabilities for the Pheromind Scribe, enabling it to record detailed information about its interpretation process. This is the first phase of the Self-adaptive `interpretationLogic` for Scribe feature.

## Features

- Detailed JSONL logging of the Scribe's interpretation process
- Confidence scoring for matched patterns and rules
- Tracking of unmatched segments
- Log rotation and management
- Configurable logging options

## Structure

- `logging/`: Logging utilities
  - `index.js`: Main entry point for the logging module
  - `logger.js`: ScribeLogger class for writing log entries
  - `schema.js`: Schema definition for log entries
  - `confidence.js`: Utilities for calculating confidence scores

## Log Entry Schema

Each log entry includes:

- `timestamp`: When the log entry was created
- `original_summary`: The natural language summary that was processed
- `handoff_reason_code`: The handoff reason code provided with the summary
- `source_orchestrator`: The orchestrator that provided the summary
- `matched_document_patterns`: Document patterns that were matched
  - `pattern`: The pattern that was matched
  - `type`: The document type assigned
  - `priority`: The priority of the pattern
  - `matched_text`: The text that was matched
  - `file_path`: The extracted file path
  - `confidence`: Confidence score for this match
- `triggered_signal_rules`: Signal rules that were triggered
  - `condition_type`: The condition type of the rule
  - `condition`: The condition of the rule
  - `signal_type`: The signal type generated
  - `target`: The target assigned to the signal
  - `category`: The category assigned to the signal
  - `strength`: The strength assigned to the signal
  - `priority`: The priority of the rule
  - `matched_text`: The text that was matched
  - `confidence`: Confidence score for this match
- `unmatched_segments`: Segments of the summary that weren't matched
  - `text`: The unmatched text
  - `start_index`: The start index in the original summary
  - `end_index`: The end index in the original summary
- `overall_confidence`: Overall confidence score for the interpretation
- `generated_signal_id`: The ID of the signal that was generated
- `documentation_updates_count`: Number of documents added or updated

## Usage

To integrate this logging module with the Scribe, modify the Scribe's implementation to:

1. Initialize the logger:
   ```javascript
   const { ScribeLogger, createLogEntry } = require('./tools/adaptive_scribe/logging');
   
   const logger = new ScribeLogger({
     logDir: './logs/scribe',
     logFileName: 'interpretation_log',
     enabled: true
   });
   ```

2. Create and populate a log entry during interpretation:
   ```javascript
   const logEntry = createLogEntry();
   logEntry.original_summary = summary;
   logEntry.handoff_reason_code = handoffReasonCode;
   logEntry.source_orchestrator = sourceOrchestrator;
   
   // Add matched document patterns
   // Add triggered signal rules
   // Add unmatched segments
   // Calculate overall confidence
   
   logEntry.generated_signal_id = generatedSignal.id;
   logEntry.documentation_updates_count = documentationUpdates;
   ```

3. Write the log entry:
   ```javascript
   logger.logInterpretation(logEntry);
   ```

## Configuration

The logger can be configured with the following options:

- `logDir`: Directory to store log files
- `logFileName`: Base name for log files
- `enabled`: Whether logging is enabled
- `maxLogSize`: Maximum size of log file in bytes before rotation
- `maxLogFiles`: Maximum number of log files to keep

## Future Phases

This enhanced logging is the foundation for future phases of the Self-adaptive `interpretationLogic` for Scribe feature:

- **Phase 2**: Analysis & Suggestion Engine - Analyze logs to generate rule suggestions
- **Phase 3**: Human-in-the-Loop Review & Integration UI - Review and approve suggested rules