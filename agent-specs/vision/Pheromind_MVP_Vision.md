# Pheromind Enhancement Design Specification

## 1. Visual Pheromone & Documentation Landscape Tool

This tool aims to provide a real-time or near real-time visual representation of the `.pheromone` file's signals and `documentationRegistry`.

### 1.1. Goals
* Provide an intuitive overview of the swarm's current state and activity.
* Visualize the evolution of signals over time (e.g., strength, type).
* Easily navigate and inspect individual signals and documentation entries.
* Help users understand the flow of information and decision-making within the swarm.
* Identify patterns or anomalies in swarm behavior.

### 1.2. Technical Implementation Methods

**Option A: Local Web Application with File Watching (Recommended for Development)**

* **Frontend:** HTML, CSS, JavaScript (React, Vue, or Svelte recommended for managing complex UI).
* **Backend (Lightweight, optional for direct file access):** Node.js with a simple server (e.g., Express.js) if browser file system access is too restrictive or for more complex operations.
    * The backend would use Node.js `fs.watch` or a library like `chokidar` to monitor `.pheromone` for changes.
    * When a change is detected, it reads the file, parses the JSON, and pushes the update to the frontend via WebSockets.
* **Direct Browser File Access (Alternative for simpler setup, more user interaction):**
    * Use the File System Access API (requires user permission for the directory containing `.pheromone`). The browser itself would poll or watch the file. This is more modern but might have stricter security/permission hurdles.
    * Alternatively, a manual "Load .pheromone file" button.
* **Data Parsing:** Robust JSON parsing on the frontend or backend.
* **Visualization Libraries:**
    * **D3.js:** Highly flexible for custom visualizations (e.g., force-directed graphs for signal relationships, timelines). Steep learning curve.
    * **Vis.js (Network, Timeline):** Good for network graphs of signals/targets and timelines of signal creation/updates. Easier to get started with than D3 for these specific types.
    * **Chart.js / Recharts / Apache ECharts:** For statistical views (e.g., signal type distribution, strength over time).
    * **Cytoscape.js:** Powerful graph theory library for network visualization, good for complex relationships.

**Option B: IDE Plugin / Extension (e.g., for VS Code)**

* Leverages the IDE's file system access and UI capabilities.
* Can provide a more integrated experience.
* Development is specific to the IDE's extension API.

### 1.3. Design Specifications (UI & Features)

**Main Dashboard:**

* **File Status:** Indicator for `.pheromone` file (last updated, path).
* **Overall Stats:**
    * Total active signals.
    * Signal types distribution (pie/bar chart).
    * Number of documents in registry.
* **Main Views (Tabs or Sections):**
    * Signal Timeline/Stream
    * Signal Network/Graph
    * Documentation Registry Explorer

**A. Signal Timeline/Stream View:**

* **Layout:** Chronological list or timeline of signals.
* **Display:** Each signal represented as a card or entry showing:
    * `id`, `signalType`, `target`, `strength`, `timestamp_created`, `last_updated_timestamp`.
    * A snippet of the `message`.
    * Color-coding by `signalType` or `category`.
* **Filtering & Sorting:**
    * Filter by `signalType`, `target`, `category`, date range.
    * Sort by timestamp, strength.
* **Interaction:**
    * Click to expand/view full JSON of a signal.
    * Hover for quick details.
* **Real-time Updates:** New signals appear at the top/bottom automatically.

**B. Signal Network/Graph View:**

* **Layout:** Force-directed graph or similar network visualization.
* **Nodes:** Represent `targets` (e.g., project name, feature module) or even individual signals.
* **Edges:** Represent relationships or the flow of signals (e.g., a signal targeting a module). Edge thickness/color could represent signal `strength` or `type`.
* **Display:**
    * Node labels: `target` name.
    * Edge labels (on hover): `signalType` or `message` snippet.
* **Interaction:**
    * Click on a node to highlight its related signals or filter the timeline view.
    * Zoom/pan.
    * Filter nodes/edges based on signal properties.
* **Potential:** Could visualize how different orchestrators/agents are influencing specific parts of the project.

**C. Documentation Registry Explorer View:**

* **Layout:** Tree view (if paths are nested) or a sortable, filterable table.
* **Display Columns:** `file_path`, `description`, `type`, `last_updated_timestamp`, `generatedBy` (if available).
* **Interaction:**
    * Click on `file_path` to (ideally) open the document in the default system editor or an integrated viewer if possible (might be complex for a web app to open local files directly without backend help or specific browser APIs).
    * Filter by `type`, keywords in `description` or `file_path`.
    * Sort by any column.

**D. Signal Detail View:**

* Modal or dedicated panel showing the full raw JSON of a selected signal.
* Pretty-printed and syntax-highlighted.

### 1.4. Data Flow
1.  File watcher (backend or browser) detects change in `.pheromone`.
2.  File is read and parsed into a JSON object.
3.  Data is processed/transformed for visualization (e.g., creating node/edge lists for graphs).
4.  Processed data is sent to the frontend (via WebSocket if backend exists, or directly manipulated if frontend-only).
5.  Frontend components re-render with new data.

## 2. Advanced `.swarmConfig` Tuning & Validation UI

This tool aims to provide a user-friendly interface for editing, validating, and understanding the `.swarmConfig` file, especially the `interpretationLogic`.

### 2.1. Goals
* Simplify the process of defining and modifying `interpretationLogic` rules.
* Prevent syntax errors and ensure the `.swarmConfig` adheres to its schema.
* Provide a clearer understanding of how rules are structured.
* Potentially allow testing of interpretation rules against sample summaries.

### 2.2. Technical Implementation Methods

* **Frontend:** HTML, CSS, JavaScript (React, Vue, or Svelte highly recommended).
* **JSON Editor Libraries:**
    * **JSONEditor (josdejong):** A popular web-based tool to view, edit, format, and validate JSON. Can be integrated and customized. Supports JSON Schema validation.
    * **React-JSON-View or similar:** For displaying and editing JSON structures within a React application.
* **Schema Validation:**
    * Define a JSON Schema for `.swarmConfig`.
    * Use a library like `ajv` (JavaScript) for validation on the frontend or a lightweight backend.
* **Rule Builder UI (Advanced):**
    * A custom UI that allows users to build `interpretationLogic` rules (especially `documentPatterns` and `signalRules`) through forms and dropdowns rather than raw JSON editing. This would abstract the JSON complexity.
* **File Handling:**
    * User uploads `.swarmConfig` file.
    * UI allows editing.
    * User downloads the modified file.
    * (Optional, more complex) If a local backend is used (as in Visualizer Option A), it could read/write the file directly with user permission.

### 2.3. Design Specifications (UI & Features)

**Main Interface:**

* **File Operations:** Load `.swarmConfig`, Save/Download `.swarmConfig`.
* **Validation Status:** Clear indication of whether the current configuration is valid against the schema. Display validation errors.
* **Navigation:** Tabs or sections for different parts of `.swarmConfig` (e.g., `pheromoneDynamics`, `scribeSettings`, `interpretationLogic`).

**A. Raw JSON Editor View:**

* An embedded JSON editor (like JSONEditor) for direct editing of the entire file.
* Syntax highlighting, code folding, error marking.

**B. Structured `interpretationLogic` Editor (Recommended):**

* **`documentPatterns` Editor:**
    * Display patterns as a list.
    * Each pattern is editable via a form:
        * Input field for `pattern` (regex) with a regex tester/helper.
        * Input for `docType`.
        * Input for `captureGroups` (e.g., comma-separated list).
        * Input for `descriptionTemplate` (if applicable).
    * Add/Remove pattern buttons.
* **`signalRules` Editor:**
    * Display rules as a list.
    * Each rule editable via a form:
        * Dropdown for `conditionType` (e.g., `handoff_reason_code_match`, `summary_keywords`).
        * Input field for `value` or `keywords` or `pattern` based on `conditionType`.
        * Sub-form for `generatesSignal` object:
            * Input for `signalType` / `signalTypeTemplate`.
            * Dropdown for `category`.
            * Textarea for `messageTemplate`.
            * Fields for `dataFromPattern` (if applicable).
        * Checkbox for `updatesDocumentation`.
    * Add/Remove rule buttons.
* **Other `scribeSettings`:** Forms for `signalTypes`, `categories`, `defaultSignalStrength`.

**C. Validation Section:**

* Button: "Validate Configuration".
* Output area: Displays schema validation errors clearly, pointing to the problematic path in the JSON.

**D. (Advanced) Rule Tester:**

* Text area to paste a sample "Natural Language Summary" from an orchestrator.
* Button: "Test Interpretation".
* Output: Shows which `documentPatterns` would match and what `documentationRegistry` entries would be proposed.
* Output: Shows which `signalRules` would be triggered and what `:signal` would be generated.

### 2.4. Data Flow
1.  User loads `.swarmConfig` or starts with a default template.
2.  UI parses JSON and populates editor fields/forms.
3.  User edits content via raw editor or structured forms.
4.  On change or on "Validate" click, the current UI state is converted back to JSON.
5.  The JSON is validated against the predefined JSON Schema.
6.  Validation results are displayed.
7.  User can download the valid (or invalid, with warning) JSON.

## 3. Self-adaptive `interpretationLogic`

This is the most complex feature, aiming for the `✍️ @orchestrator-pheromone-scribe` to learn and suggest improvements to its own `interpretationLogic` in `.swarmConfig`.

### 3.1. Goals
* Improve the accuracy and coverage of the Scribe's NL summary interpretation over time.
* Reduce manual tuning of `.swarmConfig`.
* Help the Scribe adapt to new patterns or terminology in orchestrator summaries.

### 3.2. Conceptual Approach

**Phase 1: Data Collection & Anomaly Detection (Scribe Internal)**

1.  **Enhanced Logging by Scribe:**
    * When the Scribe processes a summary, it logs:
        * The original NL summary.
        * The `handoff_reason_code`.
        * Which `documentPatterns` matched and the extracted data.
        * Which `signalRules` were triggered and the generated signal.
        * A "confidence score" for each interpretation (e.g., based on specificity of the rule, number of keywords matched).
        * Instances where no specific `documentPattern` or `signalRule` matched, and a default/fallback was used.
2.  **Pattern Analysis (Offline or by a dedicated "Meta-Scribe" agent):**
    * Analyze these logs to find recurring patterns in summaries that are *not* currently well-handled:
        * Frequently occurring phrases associated with document creation that don't match existing `documentPatterns`.
        * Summaries with specific `handoff_reason_codes` that consistently lead to generic signals, suggesting a more specific `signalRule` could be beneficial.
        * High-frequency unparsed entities (e.g., file paths of a new type).

**Phase 2: Suggestion Generation**

1.  **Rule Candidate Generation:**
    * Based on the analysis, the system (or Meta-Scribe) proposes new or modified rules:
        * **New `documentPattern`:** If summaries frequently mention "Research artifact saved to `X`" and `X` is a path not caught, suggest a pattern like `"Research artifact saved to ['\"]?(?<filePath>[^'\"]+)['\"]?"` with `docType: "research_artifact"`.
        * **New `signalRule`:** If `handoff_reason_code: "feature_X_blocked_by_dependency_Y"` often appears, but only a generic signal is made, suggest a new rule for this code to create a more specific signal like `signalType: "dependency_blocker_identified", target: "feature_X", data: { "dependency": "Y" }`.
        * **Modification of existing rules:** If a rule is too broad or too narrow, suggest adjustments.
2.  **Confidence Scoring for Suggestions:** Each suggested rule change could have a confidence score based on the frequency and clarity of the supporting data.

**Phase 3: Human-in-the-Loop Review & Approval**

1.  **Suggestion Dashboard/Interface:**
    * A UI (could be part of the `.swarmConfig` Tuning UI) displays suggested changes to `interpretationLogic`.
    * For each suggestion:
        * Show the proposed rule (new or diff for modification).
        * Show example summaries from the logs that led to this suggestion.
        * Explain the rationale.
2.  **Human Review:** A project admin or architect reviews these suggestions.
    * Accept: The rule is automatically added/updated in `.swarmConfig`.
    * Reject: The suggestion is dismissed.
    * Edit: The user can modify the suggestion before accepting.
3.  **Feedback Loop:** The Scribe's performance with new/updated rules is monitored.

### 3.3. Technical Considerations

* **Log Storage:** Where and how to store the Scribe's interpretation logs (e.g., local files, a simple database if the volume grows).
* **Pattern Recognition:** NLP techniques (e.g., TF-IDF for keyword extraction, regex generation from examples, simple clustering) could be used for analyzing summaries and proposing rules. This can range from simple heuristics to more advanced ML.
* **Metrics for "Good" Interpretation:** Defining what constitutes a successful or high-confidence interpretation is key. This could involve:
    * Specificity of rules triggered (specific rules are better than generic fallbacks).
    * Number of documents correctly identified and categorized.
    * Feedback from users (e.g., if a human later has to manually correct a signal or document entry).
* **Complexity Management:** Self-adaptation can lead to an overly complex `.swarmConfig`. The review process is crucial.
* **Bootstrapping:** How does the system start learning? Initially, it relies on the hand-crafted `.swarmConfig`.

### 3.4. Iterative Rollout
* **Start Simple:** Begin with logging and manual analysis of Scribe's interpretations.
* **Develop Suggestion Heuristics:** Implement basic algorithms to suggest new document patterns based on uncaptured file paths.
* **Build Review UI:** Create the interface for humans to approve/reject suggestions.
* **Gradually Enhance:** Add more sophisticated analysis for signal rule suggestions.

This self-adaptation is a long-term vision and would require significant development effort, but it could greatly enhance Pheromind's intelligence and reduce manual upkeep.
This design specification provides a comprehensive overview of how you might approach building these powerful new tools and capabilities for Pheromind. Each of these is a substantial project in itself, but they would significantly elevate the framework's usability and intelligence.