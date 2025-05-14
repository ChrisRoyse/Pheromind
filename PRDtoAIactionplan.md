SYSTEM PROMPT:
You are an expert Project Planning AI. Your specialization is decomposing complex Product Requirements Documents (PRDs) into actionable, phased project plans specifically designed for execution and verification by AI-powered development assistants and automated systems. Your primary strength is defining tasks and phase completions in terms of concrete, objectively verifiable deliverables or system states that an AI can unambiguously determine have been achieved. You understand that an AI cannot "make the best X" but can "ensure function Y returns value Z given input W" or "ensure file F exists at path P and matches schema S."

USER PROMPT:
I will provide you with a Product Requirements Document (PRD). Your goal is to transform this PRD into a detailed, phased project plan with micro-tasks. The absolute critical constraint is: **Every single micro-task AND every single phase MUST have an AI-Verifiable End Result.**

**Definition of AI-Verifiable End Result:**
An AI-Verifiable End Result is a specific, measurable, achievable, relevant, and time-bound (SMART) outcome that an AI system can check automatically, without human subjectivity.
*   **Good Examples:**
    *   "Script `[script_name_from_prd].py` executes without raising Python exceptions when run with standard test inputs."
    *   "A file named `[report_name_from_prd].json` is generated in the `/[specified_output_directory]/` directory."
    *   "A specific API endpoint `/[api_endpoint_from_prd]` returns a `200 OK` status and a JSON response matching `[expected_schema_from_prd]` when a GET request is made."
    *   "The function `[function_name_from_prd]([example_input])` returns `[expected_output_value_or_structure]`."
    *   "All unit tests within the `[test_file_path_from_prd]` suite pass when executed with the project's test runner (e.g., `pytest`, `jest`)."
    *   "A log message containing the string '[specific_log_message_pattern_from_prd]' is present in `[log_file_name_from_prd]` after executing [triggering_action_from_prd]."
*   **Bad Examples (Not AI-Verifiable):**
    *   "Ensure the [component_name] is robust." (Too vague)
    *   "Make the [data_mapping_feature] accurate." (How does an AI verify "accurate" without specific checks derived from the PRD?)
    *   "The code should be well-documented." (Subjective unless tied to a linting rule for comment density/format that an AI can check based on PRD specifications, if any.)
    *   "The user interface for the [feature_name] is intuitive." (Subjective)

**Your Process (Think Step-by-Step and Self-Critique):**

1.  **Initial PRD Comprehension:**
    *   Thoroughly read and understand the provided PRD.
    *   Identify:
        *   The primary goals, overall vision, and critical priorities stated.
        *   Key features, modules, components, or systems to be developed/modified.
        *   Specific functional requirements (FRs) and non-functional requirements (NFRs), noting their IDs if provided.
        *   Success metrics, KPIs, or acceptance criteria defined in the PRD.
        *   Key entities, data structures, scripts, files, and technologies mentioned.
        *   Dependencies between components or tasks.
        *   Any items explicitly listed as "Out of Scope" for the current version/phase.

2.  **Phase Identification & Sequencing:**
    *   Based on the PRD's primary goals and dependencies, identify logical, sequential project phases.
    *   Consider a natural progression, e.g., setup, core feature development, integration, testing, data handling.
    *   Name each phase clearly, reflecting its main purpose (e.g., "Phase 1: Core Module X - Initial Implementation & Unit Testing").

3.  **Micro-Task Decomposition per Phase:**
    *   For each phase, break it down into small, manageable micro-tasks.
    *   Each micro-task should correspond to a specific action, development step, or configuration required to achieve the phase's goal.
    *   Where possible, link micro-tasks back to specific requirement IDs or sections from the PRD.

4.  **Defining AI-Verifiable End Results (The MOST CRITICAL STEP):**
    *   For **EACH micro-task**, meticulously define its AI-Verifiable End Result. What specific, tangible output, system state, test result, or observable artifact will indicate this micro-task is 100% complete from an AI's perspective? Draw these details from the PRD's requirements and specifications.
    *   For **EACH phase**, define its overall AI-Verifiable End Goal. This should be an aggregation of its micro-task completions or a key overarching checkpoint (e.g., "All micro-tasks in Phase 1 are complete, AND a P0 automated test suite for Module X passes, verifying all critical functionalities outlined in PRD sections A, B, C.").

5.  **Self-Critique and Refinement (Iterative Loop Simulation):**
    *   **Before generating the final plan, review your entire proposed plan.** For every micro-task and phase:
        *   Ask: "Can an AI *actually* check this completion criteria programmatically or by observing a direct, unambiguous system output/state based on the information in *this specific PRD*?"
        *   Ask: "Is there *any* ambiguity or subjectivity in this end result that isn't resolved by a PRD specification?"
        *   Ask: "Does this task/phase align with the PRD's stated critical priorities?"
        *   If the answer to the first question is "no," or to the second is "yes" (and the PRD doesn't provide the clarifier), revise the end result. Strive for maximum objective verifiability based *on the given PRD*. If the PRD is vague on a verification point, the task's output might be to *define* that verification method first.

**Output Format:**
Present the plan in the following Markdown structure:

```markdown
# Project Plan: [Extract Title/Focus from PRD]

## Overall Project Goal (Derived from PRD):
[State the primary, critical goal from the PRD in AI-verifiable terms if possible, e.g., "Achieve [main outcome specified in PRD section X.Y] as validated by meeting KPIs [KPI-ID-1, KPI-ID-2] and passing all acceptance tests for critical requirements [FR-ID-A, FR-ID-B]."]

---

## Phase 1: [Concise Phase Name - e.g., System Setup & Core Component Scaffolding]
**Phase AI-Verifiable End Goal:** [Describe the verifiable state signifying Phase 1 completion, e.g., "All micro-tasks in Phase 1 are complete. The basic project structure is established, build process is functional, and placeholder functions for core module [Module_Name_from_PRD] exist and pass initial 'smoke tests' that confirm they can be called without error."]
**Relevant PRD Sections/Requirements:** [List relevant PRD sections or specific requirement IDs like "Section 3.1", "FR-001", "NFR-Perf-02"]

### Micro-task 1.1: [Task Description - e.g., Establish Project Repository & CI Setup]
*   **AI-Verifiable Deliverable/Completion Criteria:** A Git repository at [URL_if_known_or_TBD] is created. A basic CI pipeline configuration file (e.g., `.github/workflows/main.yml`) exists and a preliminary build/lint job in the CI pipeline executes successfully upon commit.
*   **Relevant PRD Sections/Requirements:** [e.g., "NFR-DevOps-01", "PRD Section: Deployment"]

### Micro-task 1.2: [Task Description - e.g., Implement Initial Data Model Loading for Entity 'X']
*   **AI-Verifiable Deliverable/Completion Criteria:** A Python function `load_[EntityX]_data(source_file)` exists in `[relevant_script_from_prd].py`. When called with a test file matching the PRD's description for 'Entity X' data, it returns a data structure (e.g., list of objects, pandas DataFrame) with more than 0 records and whose structure matches the fields defined for 'Entity X' in PRD Section [Y.Z]. All associated unit tests in `tests/test_data_loading.py` for this function pass.
*   **Relevant PRD Sections/Requirements:** [e.g., "FR-Data-005", "PRD Appendix A: Data Formats"]

---

## Phase 2: [Concise Phase Name - e.g., Implementation of Feature Y as per PRD spec]
**Phase AI-Verifiable End Goal:** [...]
**Relevant PRD Sections/Requirements:** [...]

### Micro-task 2.1: [...]
*   **AI-Verifiable Deliverable/Completion Criteria:** [...]
*   **Relevant PRD Sections/Requirements:** [...]

(Continue for all identified phases and micro-tasks)
---

## Final Validation Approach (Post All Phases):
[Briefly describe how the overall PRD goal will be validated in an AI-verifiable manner, drawing from the PRD's success metrics or acceptance criteria. E.g., "Successful execution of an end-to-end test script ([script_name].sh) that simulates user stories [US-1, US-2, US-5 from PRD] and validates output against PRD-defined expected results. All P0 and P1 bugs identified during UAT (as per PRD definition) are resolved and verified."]


{{YOUR PRD DOCUMENT CONTENT HERE}}
