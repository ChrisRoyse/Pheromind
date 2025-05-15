# Feature Specification: F2 - Advanced .swarmConfig Tuning & Validation UI

**Document ID:** `agent-specs/enhancements/swarmconfig_ui/F2_SwarmConfig_UI_Overall_Spec.md`
**Parent Plan:** [`README_Enhancements_Implementation_Plan.md`](../README_Enhancements_Implementation_Plan.md)
**Version:** 1.0
**Date:** 2025-05-15

## 1. Introduction & Goals

This document specifies the requirements for the "Advanced `.swarmConfig` Tuning & Validation UI." The goal is to create a standalone web application that allows users to easily load, view, edit, validate, and save `.swarmConfig` JSON files. This tool aims to simplify the management of the Scribe's `interpretationLogic` and other swarm parameters.

Key goals:
* Provide a user-friendly interface for `.swarmConfig` manipulation.
* Ensure schema adherence and prevent syntax errors through validation.
* Offer both raw JSON editing and a structured, form-based approach for complex rules.
* (Future) Allow testing of `interpretationLogic` rules against sample summaries.

## 2. User Stories

* As a Pheromind admin/developer, I want to load an existing `.swarmConfig` file into the UI.
* As a Pheromind admin/developer, I want to view and edit the `.swarmConfig` content as raw JSON.
* As a Pheromind admin/developer, I want to use a structured form-based editor to define/modify `interpretationLogic.documentPatterns` and `interpretationLogic.signalRules` to reduce the chance of errors.
* As a Pheromind admin/developer, I want the UI to validate the `.swarmConfig` against its JSON schema and show me any errors.
* As a Pheromind admin/developer, I want to download the modified `.swarmConfig` file.
* As a Pheromind admin/developer, I want to test a sample natural language summary against the current `interpretationLogic` to see how it would be processed (Future Goal).

## 3. Chosen Technical Approach

* **Type:** Frontend Single Page Application (SPA). No backend is strictly necessary for core functionality if file operations (load/save) are handled entirely by the browser.
* **Frontend:** **React with TypeScript**. Styling with **Tailwind CSS**.
* **JSON Handling:**
    * Native browser JSON parsing (`JSON.parse`, `JSON.stringify`).
    * **JSONEditor (josdejong/jsoneditor):** For the raw JSON view/edit component. This library also offers schema validation capabilities.
    * Custom React components for the structured form-based editor.
* **Schema Validation:**
    * A formal **JSON Schema** defining the structure of `.swarmConfig` will be created.
    * Client-side validation using **`ajv`** (Another JSON Validator).
* **File Operations:** Browser's native `<input type="file">` for loading and generating a download link for saving.

## 4. High-Level Architecture

+-------------------------------------------+| User's Local File System                  ||-------------------------------------------|| - .swarmConfig (JSON file)                |+------------------+------------------------+^| (File Load via Browser Dialog)| (File Save via Browser Download)v+----------------------------------------------------+| .swarmConfig UI (React SPA in Browser)             ||----------------------------------------------------|| - State Management (React Context/Zustand)         ||   - Holds current .swarmConfig JSON object         ||   - Validation status & errors                     || - Components:                                      ||   - File Input/Output Controls                     ||   - Raw JSON Editor (e.g., integrated JSONEditor)  ||   - Structured Editor (for interpretationLogic)    ||     - Document Pattern Form                        ||     - Signal Rule Form                             ||   - Validation Display Area                        ||   - (Future) Rule Tester                           || - JSON Schema for .swarmConfig                     || - Validation Logic (using ajv)                     |+----------------------------------------------------+
## 5. Data Flow

1.  **Load:** User clicks "Load .swarmConfig" and selects a local file using the browser's file dialog.
2.  The frontend reads the file content as text.
3.  The text is parsed into a JavaScript object (`JSON.parse`). Error handling for invalid JSON.
4.  The parsed object is stored in the application's state and populates the editors.
5.  **Edit:** User modifies the configuration using either the raw JSON editor or the structured form-based editors.
6.  Changes in the UI update the application's state (the JavaScript object representing `.swarmConfig`).
7.  **Validate:**
    * On demand (e.g., "Validate" button) or on-the-fly as changes are made.
    * The current state object is validated against the predefined JSON Schema using `ajv`.
    * Validation results (success or error messages with paths) are displayed to the user.
8.  **Save:** User clicks "Save/Download .swarmConfig".
9.  The current state object is stringified (`JSON.stringify` with pretty-printing).
10. A download is triggered in the browser with the content, typically named `.swarmConfig`.

## 6. Core Features & Modules

* **File Operations Module:** Handles loading from local disk and initiating download.
* **Raw JSON Editor Module:** Integrates a library like `JSONEditor` or a simpler `textarea` with syntax highlighting if feasible.
* **Structured Editor Module (for `interpretationLogic`):**
    * `DocumentPatternsEditor`: Component to manage a list of document pattern rules with forms for each.
    * `SignalRulesEditor`: Component to manage a list of signal rules with forms for each.
* **Schema & Validation Module:**
    * Stores/defines the JSON Schema for `.swarmConfig`.
    * Provides functions to validate a `.swarmConfig` object against this schema using `ajv`.
* **Main UI Shell:** Orchestrates the different views and controls.
* **State Management:** Holds the live `.swarmConfig` object and validation status.

## 7. Non-Functional Requirements

* **Usability:** Intuitive interface, especially for the structured editors. Clear error messages.
* **Performance:** Should handle reasonably sized `.swarmConfig` files without lag. Validation should be quick.
* **Accuracy:** Validation must correctly identify deviations from the schema. Saved files must accurately reflect the edited state.
* **Browser Compatibility:** Modern evergreen browsers (Chrome, Firefox, Edge, Safari).

## 8. JSON Schema for `.swarmConfig`

A separate JSON Schema file (e.g., `swarmConfig.schema.json`) needs to be defined. This schema will be crucial for the validation feature. It should cover all aspects of the `.swarmConfig` structure, including:
* `pheromoneDynamics` (and its sub-properties like `evaporationRate`, `amplificationRules`)
* `scribeSettings` (and its sub-properties like `defaultSignalStrength`, `signalTypes` array, `categories` array)
* `scribeSettings.interpretationLogic` (and its sub-properties `documentPatterns` array, `signalRules` array)
    * Detailed schema for `documentPattern` objects.
    * Detailed schema for `signalRule` objects, including conditional properties based on `conditionType`.
* `generalSettings`

## 9. Future Considerations (Out of Scope for v1)

* **Rule Tester:** Interface to input sample NL summaries and see which rules match and what signals/docs are generated.
* **Integration with Scribe's Self-adaptive Suggestions:** Displaying suggestions from the Scribe and allowing users to accept/reject them into the current `.swarmConfig`.
* Direct saving back to the file system (would require backend or more advanced browser APIs like File System Access API with write permissions).
* Version control or history for `.swarmConfig` changes within the tool.

## 10. Detailed Specifications

* **Frontend UI/UX Details:** See [`F2_SwarmConfig_UI_Frontend_Spec.md`](./F2_SwarmConfig_UI_Frontend_Spec.md)
