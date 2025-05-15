# Feature Specification: F3 - Self-adaptive interpretationLogic for Scribe

**Document ID:** `agent-specs/enhancements/adaptive_scribe/F3_Adaptive_Scribe_Overall_Spec.md`
**Parent Plan:** [`README_Enhancements_Implementation_Plan.md`](../README_Enhancements_Implementation_Plan.md)
**Version:** 1.0
**Date:** 2025-05-15

## 1. Introduction & Goals

This document outlines the specification for enhancing the `✍️ @orchestrator-pheromone-scribe` with self-adaptive capabilities for its `interpretationLogic`. The long-term goal is to enable the Scribe to learn from the summaries it processes and suggest improvements or additions to its rules in `.swarmConfig`, thereby improving interpretation accuracy and reducing manual configuration effort.

This feature will be developed in phases due to its complexity.

**Key Goals:**
* Improve the Scribe's ability to extract structured signals and document references from novel or evolving natural language summaries.
* Reduce the need for manual tuning of `interpretationLogic` in `.swarmConfig`.
* Provide a mechanism for human oversight and approval of suggested rule changes.
* Maintain the robustness and predictability of the Scribe's core function.

## 2. Phased Development Approach

* **Phase 1: Enhanced Scribe Logging & Data Collection**
    * Focus: Modify the Scribe to log detailed information about its interpretation process.
    * Detailed Spec: [`F3_Adaptive_Scribe_P1_Scribe_Logging_Spec.md`](./F3_Adaptive_Scribe_P1_Scribe_Logging_Spec.md)
* **Phase 2: Offline Analysis & Suggestion Engine**
    * Focus: Develop a tool or a separate "Meta-Scribe" agent to analyze these logs and generate potential rule suggestions (for `documentPatterns` and `signalRules`).
    * Detailed Spec: [`F3_Adaptive_Scribe_P2_Analysis_Suggestion_Engine_Spec.md`](./F3_Adaptive_Scribe_P2_Analysis_Suggestion_Engine_Spec.md)
* **Phase 3: Human-in-the-Loop Review & Integration UI**
    * Focus: Create a UI (potentially integrated with the `.swarmConfig` Tuning UI) for users to review, modify, and approve/reject suggested rule changes. Implement mechanisms to update `.swarmConfig`.
    * Detailed Spec: [`F3_Adaptive_Scribe_P3_Review_UI_Spec.md`](./F3_Adaptive_Scribe_P3_Review_UI_Spec.md)

## 3. Conceptual Architecture Overview

+---------------------------------+     (NL Summary)     +---------------------------------+| Task Orchestrators              |--------------------->| ✍️ @orchestrator-pheromone-scribe |+---------------------------------+                      | (Enhanced with Logging)         |+--------------+------------------+|| (Writes Detailed Logs)v+---------------------------------+| Interpretation Logs             || (e.g., JSONL files, Database)   |+--------------+------------------+|| (Analyzed by)v+---------------------------------+| Phase 2: Analysis & Suggestion  || Engine (Offline Tool/Meta-Scribe|+--------------+------------------+|| (Generates Suggestions)v+---------------------------------+ (Loads .swarmConfig) +---------------------------------+| .swarmConfig File               |<---------------------| Phase 3: Suggestion Review UI   |+---------------------------------+ (Updates .swarmConfig)| (Integrated with Config UI)     ||                      +----------------+----------------+|                                       ^|                                       | (Human Review & Approval)+---------------------------------------+
## 4. Key Metrics for "Good" Interpretation & Learning

Defining success for self-adaptation requires metrics:

* **Coverage:** Percentage of summaries for which specific (non-default) `documentPatterns` and `signalRules` are matched.
* **Accuracy:**
    * For `documentPatterns`: Precision and recall of extracted document paths and types (can be partially assessed if ground truth is available or via human spot-checks).
    * For `signalRules`: Relevance and correctness of generated signals (qualitative, human review).
* **Confidence Score:** The Scribe (or analysis engine) should assign a confidence score to its interpretations and suggestions.
* **Reduction in Unmatched Summaries:** Decrease in the number of summaries that result in very generic signals or no document extraction.
* **User Feedback:** Number of suggested rules accepted by a human reviewer.

## 5. Data Privacy & Security

* Interpretation logs will contain content from orchestrator summaries. If these summaries contain sensitive project information, access to logs and the analysis engine must be appropriately controlled.
* The system is primarily for local use, but if any cloud-based analysis were ever considered, data anonymization or strict access controls would be paramount.

## 6. Overall Workflow for Self-Adaptation

1.  **Scribe Operation & Logging (Phase 1):** The `✍️ @orchestrator-pheromone-scribe` processes summaries as usual but logs detailed metadata about each interpretation attempt, including matched rules, extracted entities, confidence, and any parts of the summary it couldn't fully process.
2.  **Log Analysis (Phase 2):** Periodically, an offline process or a dedicated "Meta-Scribe" agent analyzes the accumulated interpretation logs. It looks for:
    * Recurring patterns in summaries that failed to match existing rules.
    * Frequently mentioned file paths or document types that are not being captured.
    * Correlations between `handoff_reason_codes` and summary content that could inform new `signalRules`.
3.  **Suggestion Generation (Phase 2):** Based on the analysis, the engine generates candidate rules (new or modifications to existing ones) for `documentPatterns` or `signalRules`. Each suggestion includes supporting evidence (e.g., example summaries).
4.  **Review & Approval (Phase 3):** The suggested rules are presented to a human administrator via a UI. The admin can:
    * View the suggestion and its evidence.
    * Accept the suggestion (which then updates the live `.swarmConfig` file).
    * Edit the suggestion before accepting.
    * Reject the suggestion.
5.  **Continuous Improvement:** The Scribe uses the updated `.swarmConfig`. The cycle of logging, analysis, and suggestion continues, ideally leading to ongoing improvements in interpretation quality.

This iterative, human-in-the-loop approach balances automated learning with necessary oversight to ensure the stability and correctness of the Scribe's critical functions.
