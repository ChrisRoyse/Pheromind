# 🐜 Pheromind: Autonomous AI Swarm Orchestration Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Framework: Roo Code](https://img.shields.io/badge/Framework-Roo%20Code-brightgreen)](https://roo.ai)
[![LLM: Claude 3.x Compatible](https://img.shields.io/badge/LLM-Claude%203.x%20Compatible-orange)](https://www.anthropic.com/)
[![Coordination: Swarm Intelligence](https://img.shields.io/badge/Coordination-Swarm%20Intelligence-red)](.)
[![Communication: Interpreted Pheromone Signals](https://img.shields.io/badge/Communication-Interpreted%20Pheromone%20Signals-purple)](.)
[![Methodology: AI-Verifiable Outcomes](https://img.shields.io/badge/Methodology-AI--Verifiable%20Outcomes-dodgerblue)](.)

## 🌌 Welcome to Pheromind: The Future of AI-Driven Project Execution

**Pheromind** is a cutting-edge AI agent orchestration framework designed for the autonomous management and execution of complex projects. It is particularly geared towards intricate software development lifecycles adhering to an **AI-Verifiable Methodology**, ensuring project progress is tracked through concrete, measurable, and AI-confirmable outcomes.

A key capability of Pheromind is **Architect-Driven Project Jumpstarting**. This allows for the rapid initialization of new software projects by leveraging detailed specifications provided by a senior architect (typically within an `agent-specs` folder). The swarm then autonomously conducts research, formulates a phased implementation plan, and scaffolds the entire application end-to-end, preparing a comprehensive foundation for a human development team.

At its heart, Pheromind employs a **pheromone-based swarm intelligence model**. A diverse collective of specialized AI agents collaborates and adapts by interacting indirectly through a shared state medium. A cornerstone of Pheromind's innovation is its **`✍️ @orchestrator-pheromone-scribe`**. This central agent interprets rich, natural language summaries from high-level Task Orchestrators—narratives detailing project progress and AI-verifiable results—and translates them into structured, actionable "digital pheromones" or **`:signals`** and human-centric **documentation registry** updates. These are stored in the `.pheromone` file, guiding the swarm's behavior, enabling dynamic task allocation, robust state management, and emergent problem-solving, all while maintaining a clear, human-auditable trail.

Pheromind isn't just about automating tasks; it's about creating an adaptive, intelligent system that can navigate the complexities of modern project execution with a focus on verifiable deliverables, from initial project jumpstarting to ongoing development and refinement, achieving a level of autonomy previously unattainable.

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

* **🧠 Pheromone-Based Swarm Intelligence (Stigmergy):**
    Inspired by social insects, Pheromind agents interact indirectly through a shared environment – the `.pheromone` file. This file contains structured JSON `:signals` representing project state and a `documentationRegistry` tracking human-readable project artifacts. Agents "sense" these signals, and Task Orchestrators provide natural language summaries that the Pheromone Scribe uses to "deposit" new trails. This "pheromone landscape" guides agent actions, fostering decentralized yet coordinated work.

* **🎯 AI-Verifiable Project Execution:**
    Pheromind champions a methodology where project progression is defined by tasks with **AI-Verifiable End Results**. Whether jumpstarting a new project or developing features, plans like the **Master Project Plan** or a **Phased Implementation Plan** detail phases and micro-tasks, each with specific, programmatically checkable completion criteria. Task Orchestrators ensure their delegated worker tasks adhere to these verifiable outcomes, making progress unambiguous and AI-auditable.

* **🏗️ Architect-Driven Project Jumpstarting (New Capability):**
    Pheromind can rapidly initialize new projects from a rich set of specifications provided by a senior architect (typically in an `agent-specs` folder, with vision documents in `agent-specs/vision/`).
    1.  **Specification Ingestion:** The swarm processes these architect-provided documents.
    2.  **Research Phase:** A `🔎 @research-planner-strategic` agent conducts deep research based on the architect's vision, storing findings in a `/research` folder.
    3.  **Phased Implementation Planning:** A `🗺️ @orchestrator-implementation-planner` agent, using the architect's specs and research, drafts a robust, end-to-end implementation plan and work roadmap. This plan, stored in `/implementation-plan`, splits the product into key phases, each with detailed documentation and test considerations designed for AI-assisted developer handoff.
    4.  **End-to-End Scaffolding:** A `🛠️ @orchestrator-end-to-end-application-scaffolder` agent then creates the complete file and folder structure for the application's source code (in `/src` or similar) and tests (in `/tests` or similar). This scaffold represents all intended functionality with placeholders, ready for a development team. Specialized workers like `👨‍💻 @coder-scaffolder` and `🏗️ @test-scaffolder` execute the detailed scaffolding.
    This process ensures that new projects start with a well-researched plan and a comprehensive structural foundation.

* **⚙️ Autonomous Task Orchestration with Verifiable Outcomes:**
    Once initiated with a high-level objective (e.g., a User Blueprint or an Architect's Specification for jumpstarting), Pheromind autonomously manages the project workflow. The `🧐 @uber-orchestrator` strategically delegates phases to Task-Specific Orchestrators, guided by the current `.pheromone` state. These orchestrators, in turn, assign granular tasks to Worker Agents, ensuring each task has an AI-verifiable end result. Progress, reported as rich natural language summaries detailing these verifiable outcomes, is processed by the Pheromone Scribe to update the global state.

* **💬 Structured `:signals` – The Language of the Swarm's Interpreted State:**
    Generated *exclusively* by the `✍️ @orchestrator-pheromone-scribe`'s interpretation of natural language summaries, these are machine-readable, structured JSON objects influencing swarm behavior.

* **🗣️ Natural Language Summary Interpretation – The Scribe's Keystone Role:**
    Worker Agents produce AI-verifiable outputs and natural language `Summary` reports. Task-Specific Orchestrators aggregate these into a comprehensive NL summary dispatched to the Pheromone Scribe. The Scribe, using `interpretationLogic` (from `.swarmConfig`), translates this summary into structured `:signals` and `documentationRegistry` updates.

* **📖 Human-Centric Documentation Trail:**
    The Pheromone Scribe populates a `documentationRegistry` within the `.pheromone` file, tracking vital project documents (architect specs, research reports, implementation plans, code, test reports, etc.), making progress transparent.

## 🏛️ System Architecture: Agents & Key Files

### Key Input/Output Locations for Project Jumpstarting:
* **`agent-specs/`**: Input directory provided by the senior architect.
    * `agent-specs/vision/`: Contains the primary vision/blueprint document(s).
    * Other subdirectories for detailed feature specs, NFRs, data models, etc.
* **`research/`**: Output directory for the `🔎 @research-planner-strategic` agent.
* **`implementation-plan/`**: Output directory for the `🗺️ @orchestrator-implementation-planner`.
    * `implementation-plan/Roadmap.md`: Overall project roadmap.
    * `implementation-plan/overall_acceptance_tests/`: High-level E2E tests.
    * `implementation-plan/<phase_name>/`: Per-phase documentation and test considerations.
* **`src/`** (or similar): Output directory for scaffolded application source code.
* **`tests/`** (or similar): Output directory for scaffolded application test structures.

### Key Files:
1.  **The `.pheromone` File:** Swarm's shared understanding & documentation hub (managed by Scribe).
2.  **The `.swarmConfig` File:** Scribe's interpretation rulebook (contains `interpretationLogic`).
3.  **The `.roomodes` File:** Agent definitions, including specialized agents for jumpstarting.

### Core Agents (Selected Highlights):
* **`✍️ @orchestrator-pheromone-scribe`**: Sole manipulator of `.pheromone`, interpreter of summaries.
* **`🎩 @head-orchestrator`**: Initiates project by passing the initial directive (e.g., to jumpstart from a blueprint) to `🧐 @uber-orchestrator`.
* **`🧐 @uber-orchestrator`**: Primary strategic delegator. For jumpstarting, it identifies architect specs in `agent-specs/` and orchestrates the kickstart, planning, and scaffolding sequence.
* **Specialized Jumpstart Orchestrators:**
    * **`🚀 @orchestrator-project-kickstart`**: Processes architect specs from `agent-specs/`, initiates research (output to `research/`), and sets up initial project directories (including `implementation-plan/`).
    * **`🗺️ @orchestrator-implementation-planner`**: Creates the phased implementation plan and roadmap in `implementation-plan/`, using inputs from `agent-specs/` and `research/`.
    * **`🛠️ @orchestrator-end-to-end-application-scaffolder`**: Oversees the complete scaffolding of source code (e.g., in `src/`) and test structures (e.g., in `tests/`) based on `agent-specs/` and the `implementation-plan/`.
* **Specialized Jumpstart Workers:**
    * **`🔎 @research-planner-strategic`**: Conducts deep research based on architect's vision.
    * **`👨‍💻 @coder-scaffolder`**: Generates placeholder source code for structural completeness.
    * **`🏗️ @test-scaffolder`**: Generates placeholder test structures without making them pass by altering app logic.
* **Other Task-Specific Orchestrators & Worker Agents:** Pheromind includes a suite of agents for detailed specification, TDD coding, testing, refinement, documentation, and DevOps, which are utilized after the initial jumpstart or for other project workflows.

## 🔄 Workflow: The AI-Verifiable Lifecycle

Pheromind operates via a cyclical "boomerang" process. For project jumpstarting, this is adapted:

1.  **Initiation (Jumpstart):**
    * A senior architect prepares detailed specifications in the `agent-specs/` folder, including a primary vision/blueprint document (e.g., `agent-specs/vision/Product_Vision.md`).
    * The `🎩 @head-orchestrator` is activated with a directive like `"PROJECT_BLUEPRINT_KICKSTART"`, pointing to this blueprint.
2.  **Uber Orchestration (Jumpstart):** `🧐 @uber-orchestrator` receives the directive.
    * It tasks `🚀 @orchestrator-project-kickstart` to process `agent-specs/`, manage research (output to `research/`), and ensure `implementation-plan/` directory creation.
    * `🚀 @orchestrator-project-kickstart` delegates to `🔎 @research-planner-strategic` and other setup agents. Workers report summaries. `🚀 @orchestrator-project-kickstart` synthesizes these for the Scribe.
3.  **Implementation Planning:** Based on Scribe updates, `🧐 @uber-orchestrator` tasks `🗺️ @orchestrator-implementation-planner`.
    * This orchestrator uses `agent-specs/` and `research/` outputs to create the detailed phased plan in `implementation-plan/`. It delegates documentation and overall test definition tasks. It reports a comprehensive summary to the Scribe.
4.  **End-to-End Scaffolding:** Based on Scribe updates, `🧐 @uber-orchestrator` tasks `🛠️ @orchestrator-end-to-end-application-scaffolder`.
    * This orchestrator uses `agent-specs/` and `implementation-plan/` to manage the creation of all source code files (with placeholders by `👨‍💻 @coder-scaffolder`) and test files (with placeholders by `🏗️ @test-scaffolder`). It reports a comprehensive summary to the Scribe.
5.  **Scribe's Interpretation & State Update (Throughout):** At each handoff from a Task Orchestrator, the `✍️ @orchestrator-pheromone-scribe` loads `interpretationLogic` from `.swarmConfig`, analyzes the incoming NL summary, generates/updates structured JSON `:signals`, updates the `documentationRegistry` (with paths to architect specs, research docs, plans, scaffold reports), and activates `🎩 @head-orchestrator`.
6.  **Cycle Continuation:** The `🎩 @head-orchestrator` re-engages `🧐 @uber-orchestrator`, which reads the *newly updated* `.pheromone` file, guiding the next step in the jumpstart or subsequent development phases.
7.  **Developer Handoff:** After the jumpstart, the repository contains a fully scaffolded application structure, research, and a detailed implementation plan, ready for a development team to begin focused, AI-assisted implementation.

## 🌟 Key Features & Capabilities

* **Architect-Driven Project Jumpstarting:** Rapidly initializes new projects with a complete scaffold and plan from architect specifications.
* **AI-Verifiable Project Execution:** Ensures progress is tracked via concrete, measurable, and AI-confirmable outcomes.
* **Autonomous Project Management:** Manages complex lifecycles with minimal human intervention.
* **Human-Centric Documentation Trail:** Actively tracks and registers human-readable documents.
* **Sophisticated NL-Driven State Updates:** The Scribe translates rich narrative summaries into structured state.
* **Dynamic & Adaptive Tasking:** Evolves project direction based on real-time, interpreted state.

## 💡 Why Pheromind? The Design Philosophy

* **Verifiable Progress:** Pheromind is about *proving* tasks are done correctly.
* **The Power of Interpreted Narratives:** Leverages natural language for rich communication.
* **Architect-Centric Initialization:** For new projects, respects and builds upon the detailed vision and specifications provided by senior architects.
* **Scaffolding for Acceleration:** Provides a comprehensive structural foundation to accelerate development.
* **Transparency and Human Oversight:** AI-verifiable outcomes and a maintained `documentationRegistry` provide clear insight.

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

### For a New Project Jumpstart:
1.  **Architect Preparation:**
    * A senior architect creates the `agent-specs/` directory in the new project root.
    * Populate `agent-specs/vision/` with a primary blueprint document (e.g., `Product_Vision.md` based on the template provided).
    * Add any other detailed specifications, NFRs, data models, etc., into relevant subdirectories within `agent-specs/`.
2.  **Setup Pheromind Environment:**
    * Ensure a compatible Roo Code environment.
    * Configure your LLM (e.g., Claude 3.x) and API keys.
    * Place the Pheromind `.roomodes` (with jumpstart agent definitions) and `.swarmConfig` (with updated `interpretationLogic` for jumpstart artifacts) files in the project root.
3.  **Initiate the Swarm for Jumpstarting:**
    * Activate the `🎩 @head-orchestrator` with parameters such as:
        * `Original_User_Directive_Type_Field`: `"PROJECT_BLUEPRINT_KICKSTART"`
        * `Original_User_Directive_Payload_Path_Field`: Path to your main blueprint file (e.g., `"./agent-specs/vision/Product_Vision.md"`)
        * `Original_Project_Root_Path_Field`: `"."`
        * `Pheromone_File_Path`: `"./.pheromone"`
        * Optionally, `Project_Name` and paths for `research`, `implementation-plan`, `src`, `tests` if they need to be explicitly passed rather than derived by convention by the `uber-orchestrator`.
4.  **Observe & Iterate:** Monitor agent logs, the `.pheromone` file, and the generated directories (`research/`, `implementation-plan/`, `src/`, `tests/`) to track the autonomous, AI-verifiable progress of the project initialization and scaffolding.
5.  **Developer Handoff:** Once the jumpstart process is complete, the repository is ready for a development team to review the plans and begin building out the scaffolded functionality.

### For Ongoing Development (Post-Jumpstart or Standard Projects):
*(Follows the original Pheromind guidelines, using a User Blueprint or Change Request for the `🌟 @orchestrator-sparc-specification-master-test-plan` or other relevant orchestrators for feature development.)*

## ✍️ Crafting Effective Inputs

### For Project Jumpstarting:
* **Architect Specifications (`agent-specs/` folder):**
    * **Primary Blueprint/Vision Document (e.g., `agent-specs/vision/Product_Vision.md`):** This is paramount. It should clearly define the project name, vision, goals for the initial buildout, key features/epics, high-level NFRs, technology considerations/constraints, key assumptions, out-of-scope items, success criteria for the agentic buildout, and high-level data/integration concepts. Use the provided template as a guide.
    * **Supporting Documents:** Include detailed specs for features, data models, specific NFRs, etc., in other subdirectories of `agent-specs/` and reference them from the main blueprint. Clarity and completeness here directly impact the quality of the research, planning, and scaffolding.

### For Standard Pheromind Workflow (User Blueprint & Change Requests):
*(Original content largely applies here.)*

## (Optional) Contextual Terminology in `interpretationLogic`

*(Original content largely applies. For jumpstarting, the `swarmConfig.interpretationLogic` should be tuned to recognize keywords and paths related to architect specs, research outputs, phased plans, and scaffolding reports, e.g., "architect vision processed from agent-specs/vision/", "research on XYZ technology complete in research/tech_xyz/", "implementation plan phase 1 documented in implementation-plan/phase_01/", "source code scaffold for module ABC created in src/abc/".)*

## 🤝 Contributing & Future Evolution

*(Standard contributing guidelines. Potential future directions could include more sophisticated scaffold generation, automated feedback loops on architect specs, etc.)*

---

## 🤝 Support & Contribution

This is an open-source project under the MIT License.

<div align="center">
  <h2>⭐ SUPPORT Pheromind ⭐</h2>
  <p><b>Help fund continued development and new features!</b></p>
  
  <a href="https://paypal.me/ChrisRoyseAI" target="_blank">
    <img src="https://img.shields.io/badge/DONATE_NOW-00457C?style=for-the-badge&logo=paypal&logoColor=white" alt="Donate Now" width="300"/>
  </a>
  
  <h3>❤️ Your support makes a huge difference! ❤️</h3>
  <p>Pheromind is maintained by a single developer<br>Every donation directly helps improve the tool</p>
</div>

Unleash the collective, verifiable intelligence of Pheromind and transform how your complex projects are initiated and executed.