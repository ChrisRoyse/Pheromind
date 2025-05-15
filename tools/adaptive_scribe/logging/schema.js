/**
 * Schema for Scribe interpretation log entries
 */
const logEntrySchema = {
  /**
   * Timestamp when the log entry was created
   * @type {string} ISO 8601 format
   */
  timestamp: "",
  
  /**
   * The original natural language summary that was processed
   * @type {string}
   */
  original_summary: "",
  
  /**
   * The handoff reason code that was provided with the summary, if any
   * @type {string|null}
   */
  handoff_reason_code: null,
  
  /**
   * The name of the orchestrator that provided the summary
   * @type {string}
   */
  source_orchestrator: "",
  
  /**
   * Information about document patterns that were matched
   * @type {Array<Object>}
   */
  matched_document_patterns: [
    {
      /**
       * The pattern that was matched
       * @type {string}
       */
      pattern: "",
      
      /**
       * The document type assigned
       * @type {string}
       */
      type: "",
      
      /**
       * The priority of the pattern
       * @type {number}
       */
      priority: 0,
      
      /**
       * The matched text
       * @type {string}
       */
      matched_text: "",
      
      /**
       * The extracted file path
       * @type {string}
       */
      file_path: "",
      
      /**
       * Confidence score for this match (0-1)
       * @type {number}
       */
      confidence: 0
    }
  ],
  
  /**
   * Information about signal rules that were triggered
   * @type {Array<Object>}
   */
  triggered_signal_rules: [
    {
      /**
       * The condition type of the rule
       * @type {string}
       */
      condition_type: "",
      
      /**
       * The condition of the rule
       * @type {string}
       */
      condition: "",
      
      /**
       * The signal type generated
       * @type {string}
       */
      signal_type: "",
      
      /**
       * The target assigned to the signal
       * @type {string|null}
       */
      target: null,
      
      /**
       * The category assigned to the signal
       * @type {string|null}
       */
      category: null,
      
      /**
       * The strength assigned to the signal
       * @type {number}
       */
      strength: 0,
      
      /**
       * The priority of the rule
       * @type {number}
       */
      priority: 0,
      
      /**
       * The matched text
       * @type {string}
       */
      matched_text: "",
      
      /**
       * Confidence score for this match (0-1)
       * @type {number}
       */
      confidence: 0
    }
  ],
  
  /**
   * Segments of the summary that weren't matched by any rules
   * @type {Array<Object>}
   */
  unmatched_segments: [
    {
      /**
       * The unmatched text
       * @type {string}
       */
      text: "",
      
      /**
       * The start index in the original summary
       * @type {number}
       */
      start_index: 0,
      
      /**
       * The end index in the original summary
       * @type {number}
       */
      end_index: 0
    }
  ],
  
  /**
   * Overall confidence score for the interpretation (0-1)
   * @type {number}
   */
  overall_confidence: 0,
  
  /**
   * The ID of the signal that was generated
   * @type {string}
   */
  generated_signal_id: "",
  
  /**
   * The number of documents added or updated in the documentation registry
   * @type {number}
   */
  documentation_updates_count: 0
};

module.exports = {
  logEntrySchema
};