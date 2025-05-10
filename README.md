# 🐜 Pheromind: Autonomous AI Swarm Orchestration Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Framework: Roo Code](https://img.shields.io/badge/Framework-Roo%20Code-brightgreen)](https://roo.ai)
[![LLM: Claude 3.x Compatible](https://img.shields.io/badge/LLM-Claude%203.x%20Compatible-orange)](https://www.anthropic.com/)
[![Coordination: Swarm Intelligence](https://img.shields.io/badge/Coordination-Swarm%20Intelligence-red)](.)
[![Communication: Pheromone Signals](https://img.shields.io/badge/Communication-Pheromone%20Signals-purple)](.)

## 🌌 Welcome to Pheromind: The Future of AI-Driven Project Execution

**Pheromind** is a cutting-edge AI agent orchestration framework designed for the autonomous management and execution of complex projects, particularly geared towards intricate software development lifecycles and similar multi-step workflows.

At its heart, Pheromind employs a **pheromone-based swarm intelligence model**. This allows a diverse collective of specialized AI agents to collaborate, adapt, and drive projects to completion. A cornerstone of Pheromind's innovation is its ability to interpret rich, natural language summaries from high-level orchestrator agents and translate them into structured, actionable "digital pheromones" or **`:signals`**. These signals guide the swarm's behavior, enabling dynamic task allocation, robust state management, and emergent problem-solving capabilities.

Pheromind isn't just about automating tasks; it's about creating an adaptive, intelligent system that can navigate the complexities of modern project execution with a level of autonomy and resilience previously unattainable.

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
    Inspired by the way social insects like ants coordinate, Pheromind agents don't rely on direct peer-to-peer commands. Instead, they interact indirectly through a shared environment – the `.pheromone` file. Agents "sense" and "deposit" digital trails (structured JSON `:signals`) that reflect the project's current state, needs, completed work, or emerging problems. This "pheromone landscape" guides the actions of other agents, fostering a decentralized yet coordinated system.

*   **⚙️ Autonomous Task Orchestration:**
    Once initiated with a high-level objective (e.g., a detailed User Blueprint), Pheromind autonomously manages the entire project workflow. Tasks are delegated hierarchically, progress is monitored through continuous updates to the pheromone state, and the system dynamically adjusts its strategy based on the evolving signal landscape.

*   **💬 Structured `:signals` – The Language of the Swarm:**
    `:signals` are the lifeblood of Pheromind. They are machine-readable, structured JSON objects stored centrally in the `.pheromone` file. Each `:signal` serves as a piece of information influencing the swarm's behavior and typically includes:
    *   `id`: A unique identifier for the signal.
    *   `signalType`: Defines the nature of the signal (e.g., `feature_spec_complete`, `coding_needed`, `critical_bug_identified`).
    *   `target`: The specific entity the signal pertains to (e.g., a project name, a feature module, a file path).
    *   `category`: A broader classification (e.g., `system_event`, `task_status`, `identified_need`, `problem_report`).
    *   `strength`: A numerical value indicating the signal's intensity, which can change over time.
    *   `message`: A human-readable description of the signal.
    *   `data`: A flexible JSON object to carry additional structured information relevant to the signal (e.g., file paths, specific metrics, error details).
    *   `timestamp_created` & `last_updated_timestamp`: Temporal metadata for tracking signal age and updates.
    These `:signals` are dynamic, subject to rules like evaporation (decaying over time), amplification (strengthening if reinforced), and pruning (removal if too weak or outdated), all governed by the `swarmConfig`.

*   **🗣️ Natural Language Summary Interpretation – The Scribe's Keystone Role:**
    This is where Pheromind truly shines. The flow is:
    1.  **Worker Agents** (e.g., coders, testers) complete their granular tasks and produce detailed, **natural language `Summary` reports** of their actions and outcomes for their parent orchestrator.
    2.  **Task-Specific Orchestrators** aggregate these worker summaries and details of their own phase-management activities into a single, comprehensive **natural language summary report**.
    3.  This comprehensive narrative is then dispatched to the **`✍️ @orchestrator-pheromone-scribe`**.
    4.  The **Pheromone Scribe**, using sophisticated interpretation logic defined in `swarmConfig.interpretationLogic` (involving semantic analysis, keyword/pattern matching), *translates* this rich natural language summary into precise, **structured JSON `:signals`**.
    This unique capability allows the swarm to react to complex, nuanced updates from its constituent parts, moving beyond rigid, pre-coded communication protocols.

## 🏛️ System Architecture: Agents & Components

Pheromind's architecture revolves around a hierarchy of specialized AI agents and a central state mechanism:

### 1. The `.pheromone` File: The Swarm's Shared Brain
This single JSON file acts as the central repository for the swarm's collective knowledge and current state. It's meticulously managed and consists of two primary top-level keys:
*   **`swarmConfig`**: A JSON object detailing all operational parameters for the swarm. This includes rules for signal dynamics (evaporation, amplification), signal type definitions, priority weightings, conflict resolution strategies, and, most importantly, the **`interpretationLogic`** which empowers the Pheromone Scribe to convert natural language summaries into structured `:signals`.
*   **`signals`**: An array of the structured JSON `:signal` objects described above. This array represents the current "pheromone landscape," guiding the swarm's decisions.

### 2. `✍️ @orchestrator-pheromone-scribe` (The Pheromone Scribe)
The Scribe is the intelligent gatekeeper and sole manipulator of the `.pheromone` file. Its critical duties include:
*   **Receiving Task Orchestrator Summaries:** Processes the comprehensive natural language `Incoming_task_Orchestrator_Summary_Text_Optional` and `Incoming_Handoff_Reason_Code_Optional` from completing Task-Specific Orchestrators.
*   **Intelligent Interpretation:** Analyzes the received narrative content using its `swarmConfig.interpretationLogic` to understand completed work, newly identified needs, problems, or critical state changes.
*   **Structured Signal Generation & Updates:** Translates its interpretation into new structured JSON `:signal` objects or updates existing ones within the `.pheromone` file. This involves determining appropriate signal types, targets, strengths, messages, and populating the `data` field with specifics extracted from the summary.
*   **Pheromone Dynamics Management:** Applies configured rules for signal evaporation, amplification, pruning (e.g., maintaining file size limits like 500 lines by removing the weakest signals if necessary), and conflict resolution to the global list of signals.
*   **State Persistence:** Saves the fully updated `swarmConfig` and the processed `signals` array back to the `.pheromone` file, ensuring the swarm's state is accurately recorded.
*   **Initiating the Next Cycle:** Once the state is updated, it activates the `@head-orchestrator` to continue the overall project flow.

### 3. `🎩 @head-orchestrator` (Plan Custodian & UBER Tasker)
This agent is responsible for initiating and overseeing the project at the highest level.
*   Receives the initial project directive (e.g., User Blueprint path, project root).
*   Upon activation by the Pheromone Scribe (after a state update cycle), it passes the original project directive and relevant context to the `@uber-orchestrator`.

### 4. `🧐 @uber-orchestrator` (Pheromone-Guided Delegator)
The UBER Orchestrator serves as the primary strategic decision-maker for task delegation.
*   **State Awareness:** Reads (but *never* writes to) the current `.pheromone` file to understand the global project state via its `:signal` data.
*   **Strategic Delegation:** Based on the overall project goals and the current "pheromone landscape," it determines the next major phase of work.
*   **Orchestrator Tasking:** Delegates this phase *exclusively* to an appropriate **Task-Specific Orchestrator** (agents with "orchestrator" in their slug). It does not directly task Worker Agents.

### 5. Task-Specific Orchestrators (e.g., `🌟 @orchestrator-project-initialization`, `🛠️ @orchestrator-framework-scaffolding`, `⚙️ @orchestrator-feature-implementation-tdd`)
These orchestrators manage distinct, large-scale phases of the project lifecycle.
*   **Phase Management:** Decompose their assigned phase into logical sub-tasks.
*   **Worker Delegation:** Assign these sub-tasks to specialized Worker Agents.
*   **Synthesis of Outcomes:** Collect detailed natural language `Summary` reports from their workers. They then synthesize these individual reports, along with a narrative of their own management activities and phase status, into a *single, comprehensive natural language summary*.
*   **Reporting to the Scribe:** This comprehensive summary, packaged as `Incoming_task_Orchestrator_Summary_Text_Optional` along with a `Incoming_Handoff_Reason_Code_Optional`, is sent to the `✍️ @orchestrator-pheromone-scribe` for interpretation and global state update. Task Orchestrators *do not* generate structured `:signals` themselves. They may have operational limits (e.g., token constraints) necessitating handoff of partial work with an explanatory summary.

### 6. Worker Agents (e.g., `👨‍💻 @coder-test-driven`, `📝 @spec-writer-feature-overview`, `🔎 @research-planner-strategic`)
Worker agents are the specialists performing the granular, hands-on tasks of the project.
*   **Focused Execution:** Execute their narrowly defined roles (e.g., write code, generate specifications, perform research, execute tests).
*   **Rich Natural Language Reporting:** Upon task completion, their primary output to their parent Task Orchestrator is a detailed, natural language `Summary` field within their `task_completion` message. This summary meticulously describes actions taken, results achieved, files created or modified, any issues encountered, and potential needs for subsequent tasks.
*   Worker Agents *do not* create or propose structured `:signals`. Their narrative `Summary` is the raw input for the hierarchical aggregation and eventual interpretation process.

## 🔄 Workflow: The "Boomerang Task" Lifecycle & Information Flow

Pheromind operates via a cyclical "boomerang" process: tasks are delegated downwards, and rich narrative results flow upwards, leading to intelligent state updates that drive subsequent cycles.

1.  **Initiation:** A project is launched when the `🎩 @head-orchestrator` receives an initial User Blueprint or Change Request.
2.  **Top-Level Delegation:** The `@head-orchestrator` activates the `🧐 @uber-orchestrator`.
3.  **Pheromone-Guided Phase Assignment:** The `@uber-orchestrator` consults the `.pheromone` file. Based on the existing signals (or lack thereof for a new project), it delegates the next major project phase to a suitable **Task-Specific Orchestrator** (e.g., `🌟 @orchestrator-project-initialization`).
4.  **Task Orchestration & Worker Tasking:** The assigned **Task-Specific Orchestrator** breaks down its phase and delegates granular tasks to appropriate **Worker Agents**.
5.  **Worker Execution & Narrative Summary:** A **Worker Agent** (e.g., `📝 @spec-writer-feature-overview`) completes its task and provides a detailed natural language `Summary` of its work to its parent Task Orchestrator.
    *   *Example Worker `Summary`*: `"Feature Overview specification for 'AddTask' has been created and saved to docs/specs/AddTask_overview.md. This spec includes user stories, acceptance criteria, and high-level requirements. The feature AddTask specification is now complete and ready for architectural review or test planning."*
6.  **Task Orchestrator Aggregation & Comprehensive Summary:** The **Task-Specific Orchestrator** collects `Summary` reports from its workers and synthesizes them, along with its own phase management activities, into a single, comprehensive natural language summary.
    *   *Example Task Orchestrator `Incoming_task_Orchestrator_Summary_Text_Optional`*: `"Project Initialization task is nearing completion. @ResearchPlanner_Strategic reported completion of initial feasibility study (report at docs/research/feasibility.md), finding the project viable. @SpecWriter_Feature_Overview created specs for AddTask (docs/specs/AddTask_overview.md) and ViewTasks (docs/specs/ViewTasks_overview.md). @Architect_HighLevel_Module then defined the overall architecture (docs/architecture/main_arch.md), noting a dependency of ViewTasks on AddTask data structure. Master_Project_Plan.md has been generated in /docs/. This task indicates project initialization is complete and framework scaffolding is now needed for the TodoApp project."*
7.  **Handoff to the Scribe:** The Task-Specific Orchestrator sends its comprehensive summary and a handoff reason code to the `✍️ @orchestrator-pheromone-scribe`.
8.  **The Scribe's Interpretation & State Update:** The Pheromone Scribe:
    *   Analyzes the incoming natural language summary using `swarmConfig.interpretationLogic`.
    *   Identifies key events, achievements, needs (e.g., "project initialization is complete," "framework scaffolding is now needed," file paths for specs).
    *   Generates or updates relevant structured JSON `:signals` reflecting this understanding (e.g., `signalType: "project_initialization_complete"`, `signalType: "feature_spec_complete", data: {specPath: "..."}`).
    *   Applies pheromone dynamics (evaporation, amplification, pruning).
    *   Persists the new state (updated `swarmConfig` and `signals` array) to the `.pheromone` file.
    *   Activates the `🎩 @head-orchestrator` to initiate the next project cycle.
9.  **Cycle Continuation:** The `@head-orchestrator` re-engages the `🧐 @uber-orchestrator`, which reads the *newly updated* `.pheromone` file. The presence of fresh, potent signals (e.g., `framework_scaffolding_needed`) directly influences its next delegation decision, thus continuing the autonomous project progression.

## 🌟 Key Features & Capabilities

*   **Autonomous Project Execution:** Manages complex software development lifecycles with minimal human intervention post-initiation.
*   **Dynamic & Adaptive Tasking:** Project direction and task allocation evolve based on the real-time state communicated through pheromone signals.
*   **Sophisticated NL-Driven State Updates:** The Pheromone Scribe's ability to translate rich narrative summaries into structured, actionable data is a core differentiator, enabling nuanced state management.
*   **Resilience Through Swarm Intelligence:** Decentralized coordination allows the system to adapt to unforeseen challenges and continue making progress.
*   **Clear Role Specialization:** Agents possess well-defined responsibilities, promoting modularity and focused expertise.
*   **Centralized, Interpreted State:** The `.pheromone` file, under the exclusive control of the Scribe, provides a single, authoritative source of the swarm's understanding.
*   **Operational Robustness:** Handles complexities like agent operational limits (e.g., token counts) and manages the growth of the state file.

## 💡 Why Pheromind? The Design Philosophy

Pheromind is engineered around several key design principles:

*   **The Power of Interpreted Narratives:** Traditional agent systems often rely on rigid, pre-defined messages. Pheromind leverages the richness of natural language. Task Orchestrators can communicate complex scenarios, dependencies, and unexpected outcomes in their summaries. The Pheromone Scribe then shoulders the burden of translating this into a formal, structured state, allowing for more flexible and expressive inter-agent "understanding."
*   **Stigmergy for Scalable Coordination:** The pheromone model (indirect communication via a shared medium) allows the system to scale. Agents react to the "scent" of work needed or accomplished, rather than requiring intricate knowledge of every other agent's status. This promotes adaptability and reduces brittleness.
*   **Centralized Interpretation, Decentralized Action:** While individual agents act with a degree of autonomy, the crucial step of interpreting broad outcomes and updating the global state is centralized in the Pheromone Scribe. This ensures consistency and coherence in the swarm's collective understanding.
*   **Emergent Behavior:** By defining agent roles, their communication method (summaries to the Scribe), and the rules of the pheromone environment (`swarmConfig`), complex and intelligent project management behaviors can emerge from the interactions of simpler components.

## 🧬 The `.pheromone` File & `swarmConfig`: The Swarm's DNA

These two components are crucial to Pheromind's operation:

### The `.pheromone` File
*   **Dynamic Repository:** Contains the `swarmConfig` and the `signals` array.
*   **Structured JSON `:signals`:** Each signal is an object with fields like `id`, `signalType`, `target`, `category`, `strength`, `message`, `data`, `timestamp_created`, `last_updated_timestamp`.
    *   **Example Signal:**
        ```json
        {
          "id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
          "signalType": "feature_coding_complete",
          "target": "UserAuthenticationModule",
          "category": "task_status",
          "strength": 8.5,
          "message": "Coding for UserAuthenticationModule completed, all unit tests passing.",
          "data": {
            "featureBranch": "feature/user-auth",
            "commitSha": "abcdef123456"
          },
          "timestamp_created": "2023-10-27T10:30:00Z",
          "last_updated_timestamp": "2023-10-27T10:30:00Z"
        }
        ```
*   **Exclusively Scribe-Managed:** Only the Pheromone Scribe writes to this file, ensuring data integrity and consistent application of dynamics.

### The `swarmConfig` Object (within `.pheromone`)
This object is the rulebook for the Pheromone Scribe and the pheromone environment itself. Key conceptual fields include:
*   **`version`**: Configuration version.
*   **`evaporationRates`**: Defines how quickly signal strengths decay over time, based on category or type.
*   **`amplificationRules`**: Logic for increasing signal strength (e.g., if multiple agents report the same need).
*   **`signalPriorities`**: Baseline priorities for different `signalTypes`.
*   **`signalTypes`**: A list or map defining valid signal types (e.g., `project_directive_received`, `feature_spec_complete`, `coding_needed`, `bug_report_critical`).
*   **`category`**: Definitions of valid signal categories (e.g., `system_event`, `task_status`, `resource_availability`, `error_report`).
*   **`conflictResolution`**: Strategies for when conflicting signals arise.
*   **`dependencySignals`**: Rules for managing dependencies between tasks or features via signals.
*   **`emergencyThresholds`**: Signal strength thresholds that might trigger urgent responses.
*   **`anticipatorySignals`**: Configuration for generating signals about potential future needs.
*   **`analyticsTracking`**: Flags for enabling logging of signal history for advanced analysis.
*   **`explorationRate`**: A parameter for the UBER orchestrator to occasionally explore less dominant tasks.
*   **`interpretationLogic`**: **This is paramount.** A conceptual structure containing rules, keywords, regex patterns, semantic mappings, and data extraction templates that the Pheromone Scribe uses to parse the `Incoming_task_Orchestrator_Summary_Text_Optional` and generate appropriate structured JSON `:signals`. For instance, it might map phrases like "feature X implementation complete" to `signalType: "feature_implementation_complete", target: "X"`, or extract file paths mentioned in the summary into a signal's `data` field.

Understanding and (carefully) tuning `swarmConfig` allows for sophisticated customization of Pheromind's emergent intelligence.

## 🚀 Getting Started with Pheromind

1.  **Setup Environment:**
    *   Ensure you have a compatible Roo Code environment.
    *   Configure your chosen LLM (e.g., Claude 3.x series) and obtain necessary API keys.
2.  **Define Agent Modes (`.roomodes`):**
    *   The `.roomodes` file will contain the JSON definitions for all Pheromind agents (Pheromone Scribe, Head, UBER, Task Orchestrators, Workers), including their roles and detailed `customInstructions`. The Pheromone Scribe's instructions will reference its need for a comprehensive `swarmConfig` (usually loaded from the `.pheromone` file itself).
3.  **Bootstrap `.pheromone` File:**
    *   On the very first run for a project, the `✍️ @orchestrator-pheromone-scribe` will create a `.pheromone` file with a default/bootstrap `swarmConfig` and an empty `signals` array if one doesn't exist.
    *   Subsequently, it will load and update this file.
4.  **Craft Your Input:**
    *   For a new project, prepare a detailed **User Blueprint** (e.g., `MyProject_Blueprint.md`).
    *   For modifications, prepare a **Change Request** or **Bug Report** document.
5.  **Initiate the Swarm:**
    *   Activate the `🎩 @head-orchestrator` with the necessary initial parameters:
        *   `Original_User_Directive_Type_Field`: (e.g., 'NEW_PROJECT')
        *   `Original_User_Directive_Payload_Path_Field`: (path to your Blueprint/Change Request)
        *   `Original_Project_Root_Path_Field`: (path to your project's root directory)
        *   `Pheromone_File_Path`: (path to the `.pheromone` file, e.g., `./.pheromone`)
6.  **Observe & Iterate:** Monitor the swarm's activity (e.g., through agent logs or by inspecting the `.pheromone` file read-only). The system will autonomously progress through its cycles.

## ✍️ Crafting Effective Inputs: The User Blueprint & Change Requests

The quality of Pheromind's output is heavily dependent on the clarity and detail of your initial input.

*   **User Blueprint (for new projects):** Provide comprehensive details on goals, target users, core features, non-negotiable constraints, desired technologies (if any), and success criteria. The more context the swarm has, the better its initial planning and subsequent execution.
*   **Change Requests/Bug Reports (for existing projects):** Clearly define the scope of the change, the specific problem or bug, affected areas, expected behavior, and any relevant context from the existing system.

The `🧐 @uber-orchestrator` and various Task-Specific Orchestrators will rely on information derived from these initial documents, which gets encoded into early-stage pheromone signals.

## (Optional) Contextual Terminology: Enhancing Signal Precision

Pheromind's `swarmConfig.interpretationLogic` can be designed to recognize specific contextual terms within orchestrator summaries. For example:

*   `:BlueprintAnalysisComplete`
*   `:FeatureSpecificationApproved`
*   `:CriticalSecurityFlawFound`
*   `:ModuleReadyForIntegration`

When the Pheromone Scribe detects these (or similar configured patterns) in an incoming summary, it can generate highly specific and actionable `:signals`, further refining the swarm's understanding and response.

## 🤝 Contributing & Future Evolution

Pheromind is an evolving framework. We welcome contributions from the community!
*(Standard contributing guidelines like forking, PRs, issue tracking would go here.)*

**Potential Future Directions:**
*   **Visual Pheromone Landscape:** Tools to visualize the current signal state in the `.pheromone` file.
*   **Advanced `swarmConfig` Tuning UI:** A more user-friendly way to manage and optimize `swarmConfig` parameters.
*   **Self-healing `interpretationLogic`:** Mechanisms for the Pheromone Scribe to suggest improvements to its own interpretation rules based on feedback loops or observed inefficiencies.
*   **Broader Agent Ecosystem:** Expanding the library of specialized worker and orchestrator agents for diverse project types.
*   **Enhanced Analytics:** More sophisticated analysis of signal patterns to detect bottlenecks, recurring issues, or predict project trajectories.

---

Unleash the collective intelligence of Pheromind and transform how your complex projects are managed and executed.
