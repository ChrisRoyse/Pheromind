/**
 * Adaptive Scribe Logging Module
 * 
 * This module provides utilities for logging and analyzing the Scribe's interpretation process.
 */

const ScribeLogger = require('./logger');
const { logEntrySchema } = require('./schema');
const {
  calculateDocumentPatternConfidence,
  calculateSignalRuleConfidence,
  calculateOverallConfidence
} = require('./confidence');

/**
 * Create a new log entry object with default values
 * @returns {Object} - A new log entry object based on the schema
 */
function createLogEntry() {
  return {
    timestamp: new Date().toISOString(),
    original_summary: "",
    handoff_reason_code: null,
    source_orchestrator: "",
    matched_document_patterns: [],
    triggered_signal_rules: [],
    unmatched_segments: [],
    overall_confidence: 0,
    generated_signal_id: "",
    documentation_updates_count: 0
  };
}

/**
 * Create a new document pattern match entry
 * @param {Object} match - The match data
 * @returns {Object} - A document pattern match entry
 */
function createDocumentPatternMatch(match) {
  const entry = {
    pattern: match.pattern || "",
    type: match.type || "",
    priority: match.priority || 0,
    matched_text: match.matched_text || "",
    file_path: match.file_path || "",
    confidence: 0
  };
  
  // Calculate confidence if not provided
  if (!match.confidence) {
    entry.confidence = calculateDocumentPatternConfidence(entry);
  } else {
    entry.confidence = match.confidence;
  }
  
  return entry;
}

/**
 * Create a new signal rule match entry
 * @param {Object} match - The match data
 * @returns {Object} - A signal rule match entry
 */
function createSignalRuleMatch(match) {
  const entry = {
    condition_type: match.condition_type || "",
    condition: match.condition || "",
    signal_type: match.signal_type || "",
    target: match.target || null,
    category: match.category || null,
    strength: match.strength || 0,
    priority: match.priority || 0,
    matched_text: match.matched_text || "",
    confidence: 0
  };
  
  // Calculate confidence if not provided
  if (!match.confidence) {
    entry.confidence = calculateSignalRuleConfidence(entry);
  } else {
    entry.confidence = match.confidence;
  }
  
  return entry;
}

/**
 * Create a new unmatched segment entry
 * @param {Object} segment - The segment data
 * @returns {Object} - An unmatched segment entry
 */
function createUnmatchedSegment(segment) {
  return {
    text: segment.text || "",
    start_index: segment.start_index || 0,
    end_index: segment.end_index || 0
  };
}

module.exports = {
  ScribeLogger,
  logEntrySchema,
  calculateDocumentPatternConfidence,
  calculateSignalRuleConfidence,
  calculateOverallConfidence,
  createLogEntry,
  createDocumentPatternMatch,
  createSignalRuleMatch,
  createUnmatchedSegment
};