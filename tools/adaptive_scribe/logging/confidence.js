/**
 * Confidence scoring utilities for the Adaptive Scribe
 */

/**
 * Calculate confidence score for a document pattern match
 * @param {Object} match - The document pattern match
 * @param {string} match.pattern - The pattern that was matched
 * @param {string} match.matched_text - The text that was matched
 * @param {string} match.file_path - The extracted file path
 * @param {number} match.priority - The priority of the pattern
 * @returns {number} - Confidence score between 0 and 1
 */
function calculateDocumentPatternConfidence(match) {
  let score = 0.5; // Base score
  
  // Adjust based on pattern complexity (more complex patterns are more reliable)
  const patternComplexity = (match.pattern.length / 50); // Normalize to ~0-1 range
  score += Math.min(0.2, patternComplexity * 0.2); // Max +0.2 for complexity
  
  // Adjust based on file path validity
  if (match.file_path && match.file_path.includes('/')) {
    score += 0.1; // Looks like a valid path
    
    // Check for common file extensions
    const commonExtensions = ['.md', '.js', '.ts', '.py', '.json', '.html', '.css', '.txt'];
    if (commonExtensions.some(ext => match.file_path.endsWith(ext))) {
      score += 0.1; // Has a common file extension
    }
  }
  
  // Adjust based on priority (higher priority patterns are more specific)
  if (match.priority > 0) {
    score += Math.min(0.1, match.priority * 0.02); // Max +0.1 for priority
  }
  
  // Ensure score is between 0 and 1
  return Math.max(0, Math.min(1, score));
}

/**
 * Calculate confidence score for a signal rule match
 * @param {Object} match - The signal rule match
 * @param {string} match.condition_type - The condition type of the rule
 * @param {string} match.condition - The condition of the rule
 * @param {string} match.matched_text - The text that was matched
 * @param {number} match.priority - The priority of the rule
 * @returns {number} - Confidence score between 0 and 1
 */
function calculateSignalRuleConfidence(match) {
  let score = 0.5; // Base score
  
  // Adjust based on condition type
  if (match.condition_type === 'regex') {
    score += 0.15; // Regex patterns are more specific
  } else if (match.condition_type === 'handoff_reason') {
    score += 0.2; // Handoff reasons are very reliable
  }
  
  // Adjust based on condition complexity
  const conditionComplexity = (match.condition.length / 30); // Normalize to ~0-1 range
  score += Math.min(0.15, conditionComplexity * 0.15); // Max +0.15 for complexity
  
  // Adjust based on matched text length (longer matches are more reliable)
  if (match.matched_text) {
    const matchLength = match.matched_text.length / 100; // Normalize to ~0-1 range
    score += Math.min(0.1, matchLength * 0.1); // Max +0.1 for match length
  }
  
  // Adjust based on priority (higher priority rules are more specific)
  if (match.priority > 0) {
    score += Math.min(0.1, match.priority * 0.02); // Max +0.1 for priority
  }
  
  // Ensure score is between 0 and 1
  return Math.max(0, Math.min(1, score));
}

/**
 * Calculate overall confidence score for an interpretation
 * @param {Object} interpretation - The interpretation data
 * @param {Array} interpretation.matched_document_patterns - Document patterns that were matched
 * @param {Array} interpretation.triggered_signal_rules - Signal rules that were triggered
 * @param {Array} interpretation.unmatched_segments - Segments that weren't matched
 * @param {string} interpretation.original_summary - The original summary
 * @returns {number} - Overall confidence score between 0 and 1
 */
function calculateOverallConfidence(interpretation) {
  // If no patterns or rules were matched, confidence is low
  if (
    (!interpretation.matched_document_patterns || interpretation.matched_document_patterns.length === 0) &&
    (!interpretation.triggered_signal_rules || interpretation.triggered_signal_rules.length === 0)
  ) {
    return 0.1; // Very low confidence
  }
  
  // Calculate average confidence for document patterns
  let docPatternConfidence = 0;
  if (interpretation.matched_document_patterns && interpretation.matched_document_patterns.length > 0) {
    const confidences = interpretation.matched_document_patterns.map(match => match.confidence || calculateDocumentPatternConfidence(match));
    docPatternConfidence = confidences.reduce((sum, conf) => sum + conf, 0) / confidences.length;
  }
  
  // Calculate average confidence for signal rules
  let signalRuleConfidence = 0;
  if (interpretation.triggered_signal_rules && interpretation.triggered_signal_rules.length > 0) {
    const confidences = interpretation.triggered_signal_rules.map(match => match.confidence || calculateSignalRuleConfidence(match));
    signalRuleConfidence = confidences.reduce((sum, conf) => sum + conf, 0) / confidences.length;
  }
  
  // Calculate coverage (how much of the summary was matched)
  let coverage = 1; // Default to full coverage
  if (interpretation.unmatched_segments && interpretation.unmatched_segments.length > 0 && interpretation.original_summary) {
    const unmatchedLength = interpretation.unmatched_segments.reduce((sum, segment) => sum + segment.text.length, 0);
    const totalLength = interpretation.original_summary.length;
    coverage = 1 - (unmatchedLength / totalLength);
  }
  
  // Weight the components
  const docWeight = interpretation.matched_document_patterns && interpretation.matched_document_patterns.length > 0 ? 0.4 : 0;
  const signalWeight = interpretation.triggered_signal_rules && interpretation.triggered_signal_rules.length > 0 ? 0.4 : 0;
  const coverageWeight = 0.2;
  
  // Calculate weighted average
  const totalWeight = docWeight + signalWeight + coverageWeight;
  if (totalWeight === 0) return 0.1; // Avoid division by zero
  
  const weightedScore = (
    (docPatternConfidence * docWeight) +
    (signalRuleConfidence * signalWeight) +
    (coverage * coverageWeight)
  ) / totalWeight;
  
  // Ensure score is between 0 and 1
  return Math.max(0, Math.min(1, weightedScore));
}

module.exports = {
  calculateDocumentPatternConfidence,
  calculateSignalRuleConfidence,
  calculateOverallConfidence
};