# 🐜 Pheromind: Autonomous AI Swarm Orchestration Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Framework: Roo Code](https://img.shields.io/badge/Framework-Roo%20Code-brightgreen)](https://roo.ai)
[![LLM: Claude 3.x Compatible](https://img.shields.io/badge/LLM-Claude%203.x%20Compatible-orange)](https://www.anthropic.com/)
[![Coordination: Swarm Intelligence](https://img.shields.io/badge/Coordination-Swarm%20Intelligence-red)](.)
[![Communication: Interpreted Pheromone Signals](https://img.shields.io/badge/Communication-Interpreted%20Pheromone%20Signals-purple)](.)
[![Methodology: AI-Verifiable Outcomes](https://img.shields.io/badge/Methodology-AI--Verifiable%20Outcomes-dodgerblue)](.)

## 🌌 Welcome to Pheromind: The Future of AI-Driven Project Execution

**Pheromind** is a cutting-edge AI agent orchestration framework designed for the autonomous management and execution of complex projects, particularly geared towards intricate software development lifecycles adhering to an **AI-Verifiable Methodology**. This methodology ensures that project progress is tracked through concrete, measurable, and AI-confirmable outcomes.

At its heart, Pheromind employs a **pheromone-based swarm intelligence model**. A diverse collective of specialized AI agents collaborates and adapts by interacting indirectly through a shared state medium. A cornerstone of Pheromind's innovation is its **`✍️ @orchestrator-pheromone-scribe`**. This central agent interprets rich, natural language summaries from high-level Task Orchestrators—narratives detailing project progress and AI-verifiable results—and translates them into structured, actionable "digital pheromones" or **`:signals`** and human-centric **documentation registry** updates. These are stored in the `.pheromone` file, guiding the swarm's behavior, enabling dynamic task allocation, robust state management, and emergent problem-solving, all while maintaining a clear, human-auditable trail.

Pheromind isn't just about automating tasks; it's about creating an adaptive, intelligent system that can navigate the complexities of modern project execution with a focus on verifiable deliverables and a level of autonomy previously unattainable.

Pheromind Discord Server: https://discord.gg/rTq3PBeThX

---

## 🚀 Quick Setup & Video Guide

Watch the full setup video to see these steps in action:

<p align="center">
  <a href="https://www.youtube.com/watch?v=0sIws94A1U0" target="_blank" title="Pheromind Setup Video - Click to Watch">
    <img src="https://img.youtube.com/vi/0sIws94A1U0/hqdefault.jpg" alt="Pheromind Setup Video Thumbnail" width="480">
  </a>
</p>

## ✨ Core Concepts: Understanding the Pheromind Swarm

To grasp the power of Pheromind, familiarize yourself with these foundational principles:

*   **🧠 Pheromone-Based Swarm Intelligence (Stigmergy):**
    Inspired by social insects, Pheromind agents interact indirectly through a shared environment – the `.pheromone` file. This file contains structured JSON `:signals` representing project state and a `documentationRegistry` tracking human-readable project artifacts. Agents "sense" these signals and Task Orchestrators provide natural language summaries that the Pheromone Scribe uses to "deposit" new trails. This "pheromone landscape" guides agent actions, fostering decentralized yet coordinated work.

*   **🎯 AI-Verifiable Project Execution:**
    Pheromind champions a methodology where project progression is defined by tasks with **AI-Verifiable End Results**. The `🌟 @orchestrator-project-initialization` creates a **Master Project Plan** detailing phases and micro-tasks, each with specific, programmatically checkable completion criteria (e.g., file existence with correct schema, script execution without error, all tests in a suite passing). Task Orchestrators ensure their delegated worker tasks adhere to these verifiable outcomes, making progress unambiguous and AI-auditable.

*   **⚙️ Autonomous Task Orchestration with Verifiable Outcomes:**
    Once initiated with a high-level objective (e.g., a User Blueprint), Pheromind autonomously manages the project workflow. The `🧐 @uber-orchestrator` strategically delegates phases to Task-Specific Orchestrators, guided by the current `.pheromone` state. These orchestrators, in turn, assign granular tasks to Worker Agents, ensuring each task has an AI-verifiable end result. Progress, reported as rich natural language summaries detailing these verifiable outcomes, is processed by the Pheromone Scribe to update the global state, allowing the system to dynamically adjust its strategy.

*   **💬 Structured `:signals` – The Language of the Swarm's Interpreted State:**
    `:signals` are the lifeblood of Pheromind's internal state representation. Generated *exclusively* by the `✍️ @orchestrator-pheromone-scribe`'s interpretation of natural language summaries, they are machine-readable, structured JSON objects stored in the `.pheromone` file's `signals` array. Each `:signal` influences swarm behavior and typically includes:
    *   `id`, `signalType`, `target`, `category`, `strength`, `message`, `data` (extracted specifics), `timestamp_created` & `last_updated_timestamp`.
    These `:signals` are dynamic, subject to rules (evaporation, amplification, pruning) governed by the separate `.swarmConfig` file, which the Scribe uses.

*   **🗣️ Natural Language Summary Interpretation – The Scribe's Keystone Role:**
    This is where Pheromind translates complex progress into structured state:
    1.  **Worker Agents** complete granular tasks, producing AI-verifiable outputs (e.g., a spec file, tested code) and a detailed, **natural language `Summary` report** of their actions, outcomes, and verification status for their parent Task Orchestrator.
    2.  **Task-Specific Orchestrators** aggregate these worker summaries and details of their own phase-management activities (which also involve tracking AI-verifiable phase goals) into a single, comprehensive **natural language summary report**.
    3.  This narrative is dispatched to the **`✍️ @orchestrator-pheromone-scribe`**.
    4.  The **Pheromone Scribe**, using sophisticated `interpretationLogic` (defined in the external `.swarmConfig` file), *translates* this rich natural language summary into precise, **structured JSON `:signals`** and updates to the `documentationRegistry` within the `.pheromone` file. This unique capability allows the swarm to react to nuanced updates, beyond rigid protocols, and track human-readable documentation.

*   **📖 Human-Centric Documentation Trail:**
    Throughout the project, agents (especially workers like spec writers, architects, coders with TDD, and dedicated documentation writers) produce human-readable artifacts (plans, specifications, architectural documents, code, test reports, final documentation). The Pheromone Scribe, through its interpretation of summaries, populates a `documentationRegistry` within the `.pheromone` file. This registry tracks these vital documents, making project progress, decisions, and potential issues transparent and understandable to human supervisors and developers.

## 🏛️ System Architecture: Agents & Key Files

Pheromind's architecture revolves around specialized AI agents, a central state file managed by the Scribe, and a configuration file guiding the Scribe's interpretation.

### Key Files:
1.  **The `.pheromone` File: The Swarm's Shared Understanding & Documentation Hub**
    This single JSON file, exclusively managed by the `✍️ @orchestrator-pheromone-scribe`, acts as the central repository for the swarm's current interpreted state and documentation pointers. It contains two primary top-level keys:
    *   **`signals`**: An array of structured JSON `:signal` objects representing the current "pheromone landscape."
    *   **`documentationRegistry`**: A JSON object mapping to and describing key human-readable project documents (specifications, architecture, plans, reports), essential for human oversight and agent context.
    The Scribe *never* writes configuration data (from `.swarmConfig` or `.roomodes`) into this file.

2.  **The `.swarmConfig` File: The Scribe's Interpretation Rulebook**
    A separate JSON file (e.g., `project_root/.swarmConfig`) containing all operational parameters for signal dynamics and, most importantly, the **`interpretationLogic`**. This logic (rules, patterns, semantic mappings) dictates how the Pheromone Scribe translates incoming natural language summaries into structured `:signals` and `documentationRegistry` updates. The Scribe loads this file at the start of its cycle and *never* modifies it.

3.  **The `.roomodes` File: Agent Definitions**
    This file contains the JSON definitions for all Pheromind agents, detailing their roles, specific instructions, and capabilities.

### Core Agents:
1.  **`✍️ @orchestrator-pheromone-scribe` (The Pheromone Scribe)**
    The intelligent gatekeeper and *sole manipulator* of the `.pheromone` file.
    *   Loads `interpretationLogic` from the `.swarmConfig` file.
    *   Loads the current `.pheromone` file (or bootstraps an empty one: `{"signals": [], "documentationRegistry": {}}`).
    *   Receives comprehensive natural language summaries and handoff reason codes from Task Orchestrators.
    *   **Interprets** this NL summary using its `interpretationLogic` to understand completed work, AI-verifiable outcomes, new needs, problems, and generated documentation.
    *   **Generates/Updates** structured JSON `:signals` in the `signals` array and entries in the `documentationRegistry`.
    *   Manages signal dynamics (evaporation, amplification, pruning) applied *only* to signals.
    *   Persists the updated `signals` and `documentationRegistry` to the `.pheromone` file.
    *   Activates the `🎩 @head-orchestrator` to continue the project flow.

2.  **`🎩 @head-orchestrator` (Plan Custodian Initiator)**
    Initiates the project by passing its initial prompt (e.g., User Blueprint details) directly to the `🧐 @uber-orchestrator`.

3.  **`🧐 @uber-orchestrator` (Pheromone-Guided Delegator & Verifiability Enforcer)**
    The primary strategic decision-maker.
    *   **State & Documentation Awareness:** Reads the `.pheromone` file (signals and `documentationRegistry`) and consults referenced documents to understand the global project state and ensure human programmer clarity.
    *   **Strategic Delegation to Orchestrators:** Based on project goals and the current "pheromone landscape," delegates major work phases *exclusively* to appropriate **Task-Specific Orchestrators**.
    *   **Ensuring AI-Verifiable Tasks:** Crucially, it instructs selected Task Orchestrators to define tasks with clear, AI-verifiable end results and to ensure their subsequent worker delegations also adhere to this principle. It also tells them to consult the `.pheromone` file and relevant docs for context.

4.  **Task-Specific Orchestrators (e.g., `🌟 @orchestrator-project-initialization`, `🛠️ @orchestrator-framework-scaffolding`, `⚙️ @orchestrator-feature-implementation-tdd`)**
    Manage distinct, large-scale project phases, enforcing AI-verifiable outcomes.
    *   **Phase Management with Verifiability:** Decompose their phase into logical sub-tasks, each with an AI-verifiable end result (e.g., `@orchestrator-project-initialization` creates a Master Project Plan where every task has an AI-verifiable deliverable).
    *   **Worker Delegation (AI-Verifiable):** Assign sub-tasks to specialized Worker Agents, providing them with instructions that define AI-verifiable completion criteria.
    *   **Synthesis of Outcomes:** Collect rich natural language `Summary` reports (detailing verifiable results) from workers. Synthesize these, plus their own phase management narrative, into a *single, comprehensive natural language summary*.
    *   **Reporting to Scribe:** Send this comprehensive NL summary and a handoff reason code to the Pheromone Scribe for interpretation. They *do not* generate structured `:signals`. Their summary must explain its intent for Scribe interpretation based on `swarmConfig`. They also pass through original directive details to the Scribe.

5.  **Worker Agents (e.g., `👨‍💻 @coder-test-driven`, `📝 @spec-writer-feature-overview`, `🔎 @research-planner-strategic`, `🧪 @tester-tdd-master`)**
    Specialists performing granular, hands-on tasks that produce AI-verifiable results.
    *   **Focused Execution for Verifiable Outcomes:** Execute narrowly defined roles (e.g., write code to pass specific tests, generate a spec document matching a schema, run tests verifying AI-Actionable End Results from a Test Plan).
    *   **Rich Natural Language Reporting:** Primary output to their parent Task Orchestrator is a detailed, natural language `Summary` in their `task_completion` message. This summary meticulously describes actions taken, AI-verifiable results achieved (and how they were verified), files created/modified (which become part of the human-readable documentation trail), issues, and potential next steps.
    *   Worker Agents *do not* create or propose structured `:signals`. Their narrative `Summary` is raw input for aggregation and eventual Scribe interpretation. The `🧪 @tester-tdd-master` is crucial for verifying AI-Verifiable End Results using London School TDD and recursive testing.

## 🔄 Workflow: The AI-Verifiable "Boomerang Task" Lifecycle

Pheromind operates via a cyclical "boomerang" process: tasks are delegated downwards with AI-verifiable criteria, and rich narrative results (confirming these verifications) flow upwards for interpretation and state update.

1.  **Initiation:** A project launches. `🎩 @head-orchestrator` passes the initial User Blueprint/Change Request to `🧐 @uber-orchestrator`.
2.  **Pheromone-Guided Phase Assignment with Verifiability Mandate:** `🧐 @uber-orchestrator` consults the `.pheromone` file (signals and `documentationRegistry` + referenced docs). It delegates the next major phase to a suitable **Task-Specific Orchestrator** (e.g., `🌟 @orchestrator-project-initialization`), instructing it to ensure all sub-tasks have AI-verifiable outcomes and to consult pheromones/docs.
3.  **Task Orchestration & Verifiable Worker Tasking:** The **Task-Specific Orchestrator** (e.g., `@orchestrator-project-initialization`) breaks down its phase. It defines sub-tasks for **Worker Agents**, each with an AI-verifiable end result. (e.g., `@orchestrator-project-initialization` might task `@spec-writer-feature-overview` to produce a spec file at `path/to/spec.md` with defined sections, and later create the Master Project Plan with verifiable tasks).
4.  **Worker Execution & Narrative Summary (AI-Verified):** A **Worker Agent** (e.g., `📝 @spec-writer-feature-overview`) completes its task (e.g., creates `docs/specs/AddTask_overview.md`). Its `Summary` details actions, confirms the AI-verifiable outcome (e.g., "Specification created at `docs/specs/AddTask_overview.md` matching schema requirements"), and is sent to its parent.
    *   *Example Worker `Summary` for TDD Coder*: `"Coding for 'AddTaskModule' complete. All tests in 'tests/test_add_task.py' (15 tests) are now passing, confirming adherence to specifications and AI-verifiable criteria defined in Test Plan. Code pushed to 'feature/add-task' branch. Output log from 'pytest' attached. Module ready for integration."*
5.  **Task Orchestrator Aggregation & Comprehensive NL Summary:** The **Task-Specific Orchestrator** collects `Summary` reports. It synthesizes them with its own phase management narrative into a single, comprehensive NL summary. This summary explicitly mentions AI-verifiable milestones achieved and explains its intent for Scribe interpretation.
    *   *Example Task Orchestrator NL Summary (Excerpt)*: "... `🌟 @orchestrator-project-initialization` reports: Feasibility study by `@research-planner-strategic` (report at `docs/research/feasibility.md` added to documentation registry) confirmed project viability. Specs for 'AddTask' (`docs/specs/AddTask_overview.md`) and 'ViewTasks' (`docs/specs/ViewTasks_overview.md`) created by `@spec-writer-feature-overview`, verified against blueprint sections A1-A5. Master Project Plan (`docs/Master_Project_Plan.md`), detailing all phases with AI-verifiable micro-tasks, has been generated and added to documentation registry. Project initialization phase achieved its AI-verifiable goal: 'Master Project Plan in place'. This comprehensive natural language summary details collective worker outcomes for interpretation by `✍️ @orchestrator-pheromone-scribe` using its `swarmConfig.interpretationLogic` to update `.pheromone` signals and documentation registry, indicating readiness for framework scaffolding for 'TodoApp'..."
6.  **Handoff to Scribe:** The Task-Specific Orchestrator sends its comprehensive NL summary, handoff reason code, and original directive details to the `✍️ @orchestrator-pheromone-scribe`.
7.  **Scribe's Interpretation & State Update:** The Pheromone Scribe:
    *   Loads its `interpretationLogic` from `.swarmConfig`.
    *   Analyzes the incoming NL summary.
    *   Identifies AI-verified events, documentation paths, needs.
    *   Generates/updates structured JSON `:signals` (e.g., `signalType: "project_initialization_complete_verified"`, `target: "TodoApp"`) and updates the `documentationRegistry` (e.g., adding `Master_Project_Plan.md`).
    *   Applies pheromone dynamics to signals.
    *   Persists updated `signals` and `documentationRegistry` to `.pheromone`.
    *   Activates `🎩 @head-orchestrator`.
8.  **Cycle Continuation:** The `🎩 @head-orchestrator` re-engages `🧐 @uber-orchestrator`. The UBER Orchestrator reads the *newly updated* `.pheromone` file. Fresh, potent signals (e.g., reflecting `framework_scaffolding_needed_for_TodoApp_verified`) and new documentation entries directly influence its next delegation, continuing autonomous, verifiable project progression.

## 🌟 Key Features & Capabilities

*   **AI-Verifiable Project Execution:** Ensures progress is tracked via concrete, measurable, and AI-confirmable outcomes.
*   **Autonomous Project Management:** Manages complex lifecycles with minimal human intervention post-initiation.
*   **Human-Centric Documentation Trail:** Actively tracks and registers human-readable documents for transparency and oversight.
*   **Sophisticated NL-Driven State Updates:** The Scribe translates rich narrative summaries into structured state and documentation links, guided by `.swarmConfig`.
*   **Dynamic & Adaptive Tasking:** Evolves project direction based on real-time, interpreted state.
*   **Resilience & Modularity:** Decentralized coordination and clear role specialization promote robustness.
*   **Centralized State Interpretation:** The Pheromone Scribe's exclusive management of `.pheromone` ensures coherent state updates.

## 💡 Why Pheromind? The Design Philosophy

*   **Verifiable Progress:** Pheromind isn't just about doing tasks; it's about *proving* they're done correctly via AI-verifiable criteria.
*   **The Power of Interpreted Narratives:** Leverages natural language for rich communication, with the Scribe performing the heavy lifting of translation into formal state based on `.swarmConfig`. This allows flexibility and expressiveness beyond rigid message formats.
*   **Stigmergy for Scalable Coordination:** Indirect communication via the `.pheromone` medium enables adaptability and scalability.
*   **Centralized Interpretation, Decentralized Action:** The Pheromone Scribe centralizes state interpretation for consistency, while agents act with role-specific autonomy.
*   **Emergent Behavior Guided by Explicit Logic:** Complex project management emerges from agent interactions governed by defined roles (`.roomodes`) and the Scribe's explicit `interpretationLogic` (`.swarmConfig`).
*   **Transparency and Human Oversight:** AI-verifiable outcomes and a maintained `documentationRegistry` provide clear insight into the swarm's operations for human developers.

## 🧬 The Pheromone Ecosystem: `.pheromone`, `.swarmConfig`, and `.roomodes`

These three components are crucial:

### 1. The `.pheromone` File
*   The swarm's interpreted shared state, exclusively written to by the Pheromone Scribe.
*   Contains:
    *   `signals`: An array of structured JSON `:signal` objects.
        ```json
        // Example Signal in .pheromone's "signals" array
        {
          "id": "signal-xyz-789",
          "signalType": "feature_implementation_verified_tdd_complete",
          "target": "UserAuthenticationModule",
          "category": "task_status_verified",
          "strength": 9.2,
          "message": "TDD cycle for UserAuthenticationModule completed. All 42 unit tests passed, verifying AI-actionable end results from Test Plan TP-003. Ready for integration.",
          "data": {
            "featureBranch": "feature/user-auth-v2",
            "commitSha": "fedcba987654",
            "testPlanId": "TP-003",
            "verifiedResultCount": 42,
            "relevantDocRegistryKey": "doc_user_auth_test_report_final"
          },
          "timestamp_created": "2023-11-15T14:00:00Z",
          "last_updated_timestamp": "2023-11-15T14:00:00Z"
        }
        ```
    *   `documentationRegistry`: A JSON object mapping keys to metadata about project documents (path, description, timestamp), enabling human and AI access to critical information.
        ```json
        // Example entry in .pheromone's "documentationRegistry"
        "doc_master_project_plan_v1": {
          "path": "docs/Master_Project_Plan.md",
          "description": "Master Project Plan with AI-verifiable micro-tasks and phases for Project Phoenix.",
          "lastUpdated": "2023-11-10T10:00:00Z",
          "generatedBy": "orchestrator-project-initialization"
        }
        ```

### 2. The `.swarmConfig` File
*   A separate JSON file defining the Pheromone Scribe's "brain" and pheromone dynamics.
*   **Crucially contains `interpretationLogic`:** Rules, patterns, semantic mappings for the Scribe to parse NL summaries and generate/update `:signals` and `documentationRegistry` entries.
*   Also defines `evaporationRates`, `amplificationRules`, `signalPriorities`, valid `signalTypes`, `category` definitions, etc.
*   Loaded by the Scribe; *never* modified by the Scribe. Careful tuning enables sophisticated emergent behavior.

### 3. The `.roomodes` File
*   Contains detailed JSON definitions for all AI agent modes, specifying their roles, `customInstructions`, and capabilities, forming the behavioral blueprint of the swarm.

## 🚀 Getting Started with Pheromind

1.  **Setup Environment:**
    *   Ensure a compatible Roo Code environment.
    *   Configure your LLM (e.g., Claude 3.x) and API keys.
2.  **Define Agent Modes (`.roomodes`):**
    *   Craft your agent definitions in the `.roomodes` file (as provided in your example).
3.  **Create `swarmConfig` File:**
    *   Prepare your initial `.swarmConfig` JSON file in the project root. This file *must* exist, as the Pheromone Scribe loads its `interpretationLogic` from here. Define rules for signal dynamics and especially the `interpretationLogic` for NL summary-to-signal translation.
4.  **Prepare `.pheromone` File (Optional First Run):**
    *   The `✍️ @orchestrator-pheromone-scribe`, on its first run, if the `.pheromone` file (e.g., `./.pheromone`) is missing, will bootstrap an empty one: `{"signals": [], "documentationRegistry": {}}`. For subsequent runs, it loads and updates the existing file.
5.  **Craft Your Input:**
    *   For a new project: A detailed User Blueprint (e.g., `MyProject_Blueprint.md`). This will feed into the `Master Project Plan` creation with AI-verifiable tasks.
    *   For changes: A Change Request or Bug Report.
6.  **Initiate the Swarm:**
    *   Activate the `🎩 @head-orchestrator` with parameters like:
        *   `Original_User_Directive_Type_Field`
        *   `Original_User_Directive_Payload_Path_Field`
        *   `Original_Project_Root_Path_Field`
        *   `Pheromone_File_Path` (path to `.pheromone`)
        *   (The Head Orchestrator will pass these to the UBER Orchestrator, which needs the pheromone file path. The Scribe will also use its pheromone file path.)
7.  **Observe & Iterate:** Monitor agent logs and inspect the `.pheromone` file (read-only) and generated documents in the `documentationRegistry` to track autonomous, AI-verifiable progress.

## ✍️ Crafting Effective Inputs: The User Blueprint & Change Requests

High-quality initial input is key.

*   **User Blueprint:** Detail goals, features, constraints, and *measurable success criteria* that can translate into AI-verifiable outcomes in the Master Project Plan.
*   **Change Requests/Bug Reports:** Clearly define scope, problem, expected *verifiable* behavior, and context.

The Pheromone Scribe's interpretation of summaries derived from these inputs will shape early-stage signals and documentation.

## (Optional) Contextual Terminology in `interpretationLogic`

The `swarmConfig.interpretationLogic` is powerful. Design it to recognize specific keywords, phrases, or patterns in Task Orchestrator summaries (e.g., "AI-verifiable outcome XYZ achieved," "Master Plan section 2.3 complete," "tests for ABC passed"). The Scribe uses this to generate precise signals (e.g., `:BlueprintAnalysisComplete_Verified`, `:FeatureSpecApproved_AI_Checked`) and update the `documentationRegistry` accurately, enhancing swarm coordination and human understanding.

## 🤝 Contributing & Future Evolution

Pheromind is an evolving framework. We welcome contributions!
*(Standard contributing guidelines would go here.)*

**Potential Future Directions:**
*   Visual Pheromone & Documentation Landscape: Tools to visualize `.pheromone` signals and `documentationRegistry`.
*   Advanced `swarmConfig` Tuning & Validation UI.
*   Self-adaptive `interpretationLogic`: Scribe suggests improvements to its own rules.
*   Expanded Agent Ecosystem for diverse AI-verifiable project types.
*   Enhanced Analytics on signal/documentation patterns for project health.

---

Unleash the collective, verifiable intelligence of Pheromind and transform how your complex projects are executed.
