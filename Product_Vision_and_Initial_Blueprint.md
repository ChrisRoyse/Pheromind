# Product Vision & Initial Blueprint

## 1. Project Overview

* **Project Name:** Pheromind Enhancements Suite
* **Version:** 1.0 (Initial Agentic Buildout of Enhancement Features)
* **Date Prepared:** 2025-05-15
* **Prepared By:** Pheromind Core Team (Architect: AI Language Model)
* **Primary Contact:** project-lead@pheromind.dev

## 2. Vision & Goals

### 2.1. Core Product Vision
To significantly elevate the Pheromind framework's usability, observability, and intelligence by providing developers and administrators with powerful tools for visualizing swarm activity, configuring agent behavior, and enabling a more adaptive and self-improving interpretation mechanism for the Pheromone Scribe. This will lead to more efficient project management, easier debugging, and a more robust and intelligent AI swarm.

### 2.2. Primary Goals for Initial Agentic Buildout (v1.0 of Enhancements)
1.  **Deliver Core Visualizer:** Implement and deliver a functional "Visual Pheromone & Documentation Landscape Tool" (Feature F1) capable of real-time display of `.pheromone` signals and documentation registry, as per its detailed specification.
2.  **Deliver Core SwarmConfig UI:** Implement and deliver a functional "Advanced `.swarmConfig` Tuning & Validation UI" (Feature F2) allowing loading, raw editing, schema validation, and saving of `.swarmConfig` files, as per its detailed specification.
3.  **Establish Foundation for Adaptive Scribe:** Implement Phase 1 (Enhanced Scribe Logging) of the "Self-adaptive `interpretationLogic` for Scribe" (Feature F3), ensuring the Scribe produces detailed interpretation logs.
4.  **Developer-Ready Tools:** Ensure the developed tools (F1, F2) are well-structured, scaffolded with corresponding tests, and documented, ready for use and potential future contributions.
5.  **Integrated Planning Artifacts:** Produce all necessary `agent-specs` (like this document and the detailed feature specs), a `research` folder (if any specific UI/backend technology choices require further agent-driven research beyond the specs), and an `implementation-plan` for the buildout of these enhancement features.

*(This blueprint, along with detailed feature specifications located in `agent-specs/enhancements/`, will guide the AI swarm.)*

## 3. Key Features / Epics (for This Enhancements Buildout)

* **Epic 1: F1 - Visual Pheromone & Documentation Landscape Tool**
    * Purpose: Provide a real-time or near real-time UI to visualize `.pheromone` signals and `documentationRegistry`.
    * Key Aspects for Scaffolding/Implementation:
        * Backend: Node.js server with file watching (`chokidar`) for `.pheromone`, WebSocket communication (`socket.io`).
        * Frontend: React SPA with TypeScript, displaying signal timeline, (optional v1: basic signal stats), and documentation registry explorer.
    * Reference: `agent-specs/enhancements/visualizer/F1_Visualizer_Overall_Spec.md` (and its linked frontend/backend specs).

* **Epic 2: F2 - Advanced `.swarmConfig` Tuning & Validation UI**
    * Purpose: Provide a UI to easily load, view, edit (raw JSON), validate against a schema, and save `.swarmConfig` files.
    * Key Aspects for Scaffolding/Implementation:
        * Frontend: React SPA with TypeScript, integrating a JSON editor component (e.g., `jsoneditor-react`), client-side schema validation (`ajv`).
        * File handling (load/save) via browser mechanisms.
    * Reference: `agent-specs/enhancements/swarmconfig_ui/F2_SwarmConfig_UI_Overall_Spec.md` (and its linked frontend spec).

* **Epic 3: F3 - Self-adaptive `interpretationLogic` for Scribe (Phased)**
    * Purpose: Enhance the Pheromone Scribe to learn and suggest improvements to its own interpretation rules.
    * **Phase 1 (Current Buildout Focus): Enhanced Scribe Logging**
        * Key Aspects: Modify `✍️ @orchestrator-pheromone-scribe` to produce detailed JSONL logs of its interpretation process, including matched rules, confidence scores (heuristic), and unparsed elements.
        * Reference: `agent-specs/enhancements/adaptive_scribe/F3_Adaptive_Scribe_P1_Scribe_Logging_Spec.md`
    * **Phase 2 (Future Buildout): Analysis & Suggestion Engine**
        * Key Aspects: Offline tool/agent to analyze logs and generate rule suggestions.
        * Reference: `agent-specs/enhancements/adaptive_scribe/F3_Adaptive_Scribe_P2_Analysis_Suggestion_Engine_Spec.md`
    * **Phase 3 (Future Buildout): Review UI & Integration**
        * Key Aspects: UI for human review and approval of Scribe's suggestions, integrated with F2.
        * Reference: `agent-specs/enhancements/adaptive_scribe/F3_Adaptive_Scribe_P3_Review_UI_Spec.md`

## 4. Core Non-Functional Requirements (NFRs) - Initial Directives

* **Performance (Visualizer - F1):**
    * UI should update within 1-2 seconds of `.pheromone` file changes.
    * Handle `.pheromone` files up to the Scribe's pruning limit (e.g., 400 lines of signals) without significant UI lag.
* **Performance (SwarmConfig UI - F2):**
    * Loading and validation of typical `.swarmConfig` files should be near-instantaneous.
* **Usability (F1, F2):**
    * Interfaces must be intuitive for developers familiar with Pheromind concepts.
    * Clear error messages and status indicators.
* **Reliability (Visualizer Backend - F1):**
    * File watcher must be robust and consistently detect changes.
    * WebSocket server should maintain stable connections with the frontend.
* **Accuracy (SwarmConfig UI - F2):**
    * Schema validation must be accurate according to the defined `.swarmConfig` JSON schema.
    * Saved files must perfectly reflect the state in the editor.
* **Accuracy (Scribe Logging - F3 P1):**
    * Logs must accurately reflect the Scribe's interpretation process and data points as specified.
* **Maintainability (All Features):**
    * Code should be modular, well-commented, and follow good TypeScript/React/Node.js practices.
    * Testable components with unit/integration tests where appropriate.

## 5. Technology Preferences & Constraints (Initial Guidance)

* **Visualizer Frontend (F1):** React with TypeScript, Tailwind CSS, Vis.js (or React Flow), Recharts (or Chart.js).
* **Visualizer Backend (F1):** Node.js with Express.js, `chokidar`, `socket.io`.
* **SwarmConfig UI Frontend (F2):** React with TypeScript, Tailwind CSS, `jsoneditor-react` (or similar), `ajv`.
* **Scribe Logging (F3 P1):** Modifications to the existing Pheromind Scribe (presumably JavaScript/TypeScript if running in Node.js environment of Roo Code). Log output in JSONL format.
* **Development Environment:** Node.js LTS.
* **Build Tools:** Vite (preferred for frontend) or Create React App.

## 6. Key Assumptions for This Buildout

1.  The detailed feature specifications in `agent-specs/enhancements/` provide sufficient detail for AI coding agents.
2.  The Pheromind core agent execution environment (Roo Code) allows for the Scribe modifications (for logging) and can run the Node.js backend for the Visualizer locally alongside the main swarm.
3.  The primary goal for F1 and F2 is local developer tooling, not publicly hosted applications.
4.  The JSON Schema for `.swarmConfig` will be accurately defined and provided to the F2 UI development agent.

## 7. Out of Scope for Initial Buildout (v1.0 of Enhancements)

* **F1 - Visualizer:**
    * Historical data analysis beyond current file content.
    * User accounts or cloud deployment.
    * Advanced analytical queries.
* **F2 - SwarmConfig UI:**
    * Direct saving back to the file system (will use browser download).
    * Version control for `.swarmConfig` within the tool.
    * Fully implemented Rule Tester (basic structure might be scaffolded if time permits).
* **F3 - Adaptive Scribe:**
    * Full implementation of Phase 2 (Analysis Engine) and Phase 3 (Review UI). Only Phase 1 (Scribe Logging) is in scope for this initial buildout.

## 8. Desired Outputs from This Agentic Buildout

1.  **Visualizer Application (F1):**
    * Source code for the React frontend in `/tools/visualizer/frontend`.
    * Source code for the Node.js backend in `/tools/visualizer/backend`.
    * Basic usage documentation.
    * Scaffolded tests for key components.
2.  **SwarmConfig UI Application (F2):**
    * Source code for the React frontend in `/tools/swarmconfig_ui/frontend`.
    * A defined `swarmConfig.schema.json` file.
    * Basic usage documentation.
    * Scaffolded tests for key components.
3.  **Enhanced Pheromone Scribe (F3 P1):**
    * Modified source code for the `✍️ @orchestrator-pheromone-scribe` agent incorporating the specified logging capabilities.
    * Updated `.roomodes` entry for the Scribe reflecting these changes.
    * Documentation on the log format and configuration.
4.  **Project Artifacts:**
    * This `Product_Vision_and_Initial_Blueprint.md` file.
    * All detailed feature specification markdown files in `agent-specs/enhancements/`.
    * An `implementation-plan/` directory for this "Pheromind Enhancements Suite" project, detailing phases for building F1, F2, and F3P1.
    * A `/research` directory (if any specific research tasks are delegated, e.g., comparing specific charting libraries beyond initial recommendations).

## 9. High-Level Data Concepts (for Scaffolding Guidance)

* **`.pheromone` file structure:** (as already defined by Pheromind)
    * `signals`: array of signal objects.
    * `documentationRegistry`: object mapping document keys to metadata.
* **`.swarmConfig` file structure:** (as defined by Pheromind and the new JSON Schema to be created for F2)
    * `pheromoneDynamics`, `scribeSettings` (including `interpretationLogic` with `documentPatterns`, `signalRules`), `generalSettings`.
* **Scribe Interpretation Log Entry structure:** (as defined in `F3_Adaptive_Scribe_P1_Scribe_Logging_Spec.md`).
* **Suggestion File structure (for future F3 P2/P3):** (as defined in `F3_Adaptive_Scribe_P2_Analysis_Suggestion_Engine_Spec.md`).

## 10. Known External System Interactions (for Scaffolding Interfaces)

* **Local File System:**
    * Visualizer Backend (F1): Reading `.pheromone`.
    * SwarmConfig UI (F2): Loading `.swarmConfig` via browser file input, triggering download of modified `.swarmConfig`.
    * Scribe (F3 P1): Writing to its interpretation log file.
* **WebSockets (F1):** Communication between Visualizer backend and frontend.
* **Browser APIs (F1, F2):** File API, Download mechanism.
