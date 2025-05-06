# 🚀 SPARC-SAPPO Agentic Development Framework (v3 - Swarm Orchestration Edition)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Roo Code Compatible](https://img.shields.io/badge/Roo%20Code-Compatible-brightgreen)](https://roo.ai)
[![Perplexity API](https://img.shields.io/badge/Perplexity-API%20(Tiered)-blue)](https://perplexity.ai)
[![Uses Claude 3.7 Sonnet](https://img.shields.io/badge/Uses-Claude%203.7%20Sonnet-orange)](https://www.anthropic.com/news/claude-3-5-sonnet)
[![Ontology-Guided (SAPPO)](https://img.shields.io/badge/Ontology-Guided%20(SAPPO)-purple)](.)
[![SPARC Methodology](https://img.shields.io/badge/Methodology-SPARC-orange)](.)
[![Swarm Orchestration](https://img.shields.io/badge/Coordination-Swarm%20Orchestration-red)](.)
[![cline MCP Installer](https://img.shields.io/badge/cline-MCP%20Installer-orange)](https://cline.tools)

## 🌌 Introducing the Evolution: AI Swarm Orchestration

Welcome to **Version 3** of the SPARC-SAPPO Agentic Development Framework, now supercharged with a **Pheromone-Based Swarm Orchestration Engine**! This isn't just an update; it's a paradigm shift in how AI agents collaborate to build software.

Built on Roo Code, this framework leverages the meticulous planning of **SPARC**, the semantic precision of the **SAPPO Ontology**, our robust **Dual-Strategy TDD cycle**, and strategic **Tiered RDD research**. The new Swarm Engine introduces an emergent, adaptive layer of coordination, enabling a collective of specialized AI agents powered by Anthropic's Claude 3.7 Sonnet to tackle complex software projects with unprecedented autonomy and resilience.

Inspired by [Rueven Cohen's original SPARC/Boomerang](https://gist.github.com/ruvnet/a206de8d484e710499398e4c39fa6299) concepts and your custom [Software Architecture Problem Prediction Ontology (SAPPO)](https://github.com/ChrisRoyse/Coding-Agent-Ontology), this evolution drives development through a stigmergic process where agents communicate and coordinate via digital "pheromones," leading to intelligent, decentralized decision-making.

**Core Tenets of the Swarm Edition:**

1. **👑 Meta-Orchestration & Phased Delegation:** A `👑 Meta-Orchestrator (Swarm Director)` oversees the entire project lifecycle, dynamically activating specialized Phase Orchestrators (e.g., `🌟 Orchestrator (Project Initialization)`, `⚙️ Orchestrator (Feature Implementation - Test-Driven)`) based on the collective state signaled by the swarm.
2. **🐜 Pheromone-Based Coordination (Stigmergy):** Agents "deposit" signals into a shared `.pheromone` file, indicating project state, needs, problems, and priorities. This board guides the Meta-Orchestrator and allows the system to self-organize and adapt.
3. **🎯 Specialized Agent Roles:** A rich ecosystem of agents, each with specific instructions and tools (defined in `.roomodes`), contribute to different facets of development—from research and spec writing to coding, testing, and DevOps.
4. **📊 Dynamic Prioritization & Conflict Resolution:** The `swarmConfig` within `.roomodes` defines how signals evaporate, amplify, and influence task prioritization, enabling the system to respond to critical issues like bugs or security vulnerabilities automatically.
5. **🧬 Emergent Intelligence & Adaptability:** The swarm doesn't just follow a rigid plan; it adapts based on real-time feedback (test results, identified problems, changing priorities) reflected in the pheromone signals.
6. **⛓️ Dependency-Aware Workflow:** The system tracks feature and component dependencies via signals, ensuring a logical progression of work.
7. **Robust TDD as a Signaling Mechanism:** The Dual-Strategy TDD cycle remains central. Test PASS/FAIL results directly translate into powerful pheromone signals, guiding the Coder/Debugger loop and informing the overall project status.
8. **Tiered RDD for Efficient Research:** Specialist agents continue to use Perplexity MCP tools strategically.
9. **Unified LLM (Claude 3.7 Sonnet), Dual-Mode:** Individual agents leverage "Thinking" (high-temp) and "Instruct" (low-temp) modes for optimal performance within Claude 3.7 Sonnet's ~200k context window. The swarm orchestrates many such focused agents.

**The Grand Idea:** You provide a **detailed User Blueprint** (for new projects) or a **Change Request** (for existing ones) to the `👑 Meta-Orchestrator`. This initiates a cascade of pheromone signals. The Meta-Orchestrator interprets these signals and delegates entire project phases to specialized Orchestrators. These Orchestrators, in turn, break down their phase into micro-tasks for worker agents (Coders, Testers, etc.). Each completed task and test result generates new pheromone signals, continually updating the swarm's collective understanding and guiding the next actions. This decentralized yet coordinated approach enables robust, adaptive, and scalable AI-assisted software development.

## 📺 Quick Start & Methodology Video Guide (Swarm Edition)

**(Placeholder: The previous video needs an update to cover Swarm Orchestration!)**

<!-- [![Watch the Setup & Best Practices Guide (Swarm Edition)](https://img.youtube.com/vi/Y HematO_NEW_VIDEO_ID_HERE/maxresdefault.jpg)](https://youtu.be/YOUR_NEW_VIDEO_ID_HERE) -->
**(Coming Soon! A new video will walk through the Swarm Orchestration setup and workflow.)**

A future video will cover:
* Setting up Roo Code with the new Swarm Orchestration `.roomodes`.
* Understanding the `.pheromone` file and `swarmConfig`.
* Crafting effective User Blueprints to kickstart the swarm.
* Observing the Meta-Orchestrator, Phase Orchestrators, and specialist agents in action.
* How Dual-Strategy TDD fuels the pheromone signaling system.
* Managing complex projects with adaptive, decentralized AI collaboration.

## 🏛️ System Architecture Overview

The system follows a hierarchical yet adaptive structure:

1. **User Input:** The User initiates a project with a Blueprint or a Change Request.
2. **Meta-Orchestrator (👑):** This is the top-level director. It reads the overall project state from the `.pheromone` file and, guided by `swarmConfig`, delegates entire project phases to specialized Phase Orchestrators.
3. **Pheromone System (`.pheromone` file & `swarmConfig`):** This is the central nervous system.
   * `.pheromone` file: A shared "digital scent trail" where all agents deposit signals (status updates, needs, problems, priorities).
   * `swarmConfig`: Defines the rules for how signals are processed (e.g., evaporation, amplification, prioritization).
4. **Phase Orchestrators (🌟, 🛠️, 🎯, ⚙️, 🔗, 🔄):** Each Phase Orchestrator manages a specific stage of the development lifecycle (e.g., Initialization, Scaffolding, Test Generation, Feature Implementation). They break down their phase into smaller tasks and delegate to Specialist Agents. They also read and write to the `.pheromone` file to coordinate within their phase and signal completion to the Meta-Orchestrator.
5. **Specialist Agents (🔎, 📝, 👨‍💻, 🧪, 🎯, etc.):** These are the worker bees. They perform specific tasks like research, writing specifications, coding, testing, debugging, integration, etc. Their actions and results directly generate new pheromone signals.
6. **MCP Tools (Perplexity, Firecrawl, etc.):** Utilized by relevant specialist agents for external information gathering (e.g., research, documentation lookup).

All agents, from the Meta-Orchestrator down to the individual specialists, interact with and are guided by the `.pheromone` file, creating a dynamic, self-organizing system.

## 🧠🛠️ Unified LLM, Dual-Mode Strategy (Claude 3.7 Sonnet @ ~200k Context)

Even within the swarm, individual agent effectiveness relies on **Anthropic's Claude 3.7 Sonnet** (~200k context window) with role-based temperature control:

1. **🧠 Thinking Mode (Temperature: ~0.7)**
   * **Model:** Claude 3.7 Sonnet
   * **Purpose:** Strategic planning, architectural design, complex reasoning, user interaction, interpreting pheromone signals.
   * **Primary Users:** `👑 Meta-Orchestrator`, Phase Orchestrators (`🌟 Init`, `🛠️ Scaffolding`, etc.), `📝 Spec Writer`, `🏛️ Architect`, `❓ Ask Guide`, `📘 Tutorial`.

2. **🛠️ Instruct Mode (Temperature: ~0.25)**
   * **Model:** Claude 3.7 Sonnet
   * **Purpose:** Precise code/test generation, debugging, specific tool execution, security checks, documentation generation following strict guidance.
   * **Primary Users:** `👨‍💻 Coder`, `🧪 Tester`, `🎯 Debugger`, `🛡️ Security Reviewer`, `🔌 Integrator`, `🧹 Optimizer`, `📚 Docs Writer`, `🔩 DevOps`, `⚙️ MCP Tool Specialist`.

**Why Claude 3.7 Sonnet & ~200k Window + Swarm (Cost-Efficiency & Scalability by Design):**

* **Focused Agent Execution:** Each agent tackles a well-defined, smaller part of the problem, making the ~200k context window highly effective for its specific task.
* **Distributed Cognition:** The overall project "memory" and "state" are not solely reliant on one massive LLM context. Instead, it's distributed:
  * Partially in the `.pheromone` file (current needs, problems, overall progress).
  * Partially in the artifacts produced (code, tests, specs, docs on disk).
  * Partially in the structured TDD cycle (the test suite *is* a form of persistent memory and specification).
* **Methodology Over Raw Context:** Rigorous TDD, SAPPO-guided tasks, and focused RDD, now coordinated by the swarm, mean individual agents don't need to "know everything" all the time.
* **Scalable Complexity Management:** The swarm can orchestrate numerous focused agents, tackling larger and more complex projects than might be feasible with a single LLM, while keeping individual agent calls relatively lean.
* **Cost Implications:** While a swarm involves many agent interactions, each is typically smaller and more targeted. This can be more cost-effective than attempting to manage an entire complex project within a multi-million token window of a monolithic LLM, which can incur very high per-call costs and diminishing returns in coherence. **The goal is effective distribution of work and intelligence.**

## ✨ Key Features & Methodology (Swarm Edition)

### 🐜 Pheromonic Swarm Intelligence & Coordination
* **Dynamic Tasking:** `👑 Meta-Orchestrator` assigns high-level phases based on active signals in the `.pheromone` file.
* **Signal-Driven Workflow:** `swarmConfig` dictates signal processing:
  * **Categories:** `state`, `need`, `problem`, `priority` drive different behaviors.
  * **Evaporation & Amplification:** Keeps signals relevant and allows urgent issues to rise.
  * **Priorities & Conflict Resolution:** Ensures critical tasks (e.g., `critical_bug_in_feature_X`) are addressed promptly.
  * **Dependency Tracking:** Ensures, for example, `feature_X_depends_on_feature_Y` is respected.
  * **Anticipatory Signals:** System pre-emptively flags upcoming needs (e.g., `anticipate_integration_soon_for_feature_X`).
* **Adaptive Behavior:** The swarm can pivot based on new problem signals (e.g., test failures, security alerts) without direct human intervention for every step.

### 🏛️ SAPPO-Guided Tasks
* Still core: SAPPO terms (`:Problem`, `:Solution`, etc.) structure agent tasks and reporting, now flowing through the pheromone system.

### 🔍 Tiered Research-Driven Development (RDD)
* Specialist agents like `🔎 Research Planner` or `👨‍💻 Coder` use Perplexity MCP tools (`search`, `get_documentation`) based on clear tiers (**MUST/SHOULD/MAY/DO NOT USE**) for efficient and justified research.

### ✅ Dual-Strategy Test-Driven Development (TDD) as a Core Signaling Mechanism
* **Immediate "Boomerang" Testing Cycle:** `🧪 Tester` runs immediately after `👨‍💻 Coder`.
* **Test Results -> Pheromone Signals:**
  * **PASS:** Deposits positive signals (e.g., `coding_complete_for_feature_X`), reducing "need" signals.
  * **FAIL:** Deposits problem signals (e.g., `critical_bug_in_feature_X`), increases "need" for debugging, and guides the `🎯 Debugger`.
* **Dual Strategy:**
  1. **Cumulative Testing:** Prevents regressions, ensuring system stability.
  2. **Recursive Testing:** Addresses complex algorithms.
* This TDD cycle is now a fundamental driver of the swarm's adaptive behavior.

### 📄 Detailed Planning is Paramount: The User Blueprint
* **User Responsibility:** The quality of the initial **User Blueprint** (for new projects) or **Change Request** (for existing ones) is CRITICAL. This provides the initial "scent" for the swarm.
* The AI swarm executes and adapts; it doesn't intuit your high-level goals from scratch.

## 🔄 The Swarm Workflow Loop (Simplified)

1. **You (User):**
   * For **New Project:** Provide a detailed `User_Blueprint.md` to the `👑 Meta-Orchestrator`.
   * For **Existing Project:** Provide `Change_Request.md` or `Bug_Report.md` to `👑 Meta-Orchestrator`.
2. **👑 Meta-Orchestrator (Thinking Mode, Claude @ ~0.7):**
   * Parses your input.
   * Deposits initial signals into `.pheromone` (e.g., `project_state_new_blueprint_available`).
   * **Continuously:** Reads the `.pheromone` file (applying evaporation, amplification, priorities from `swarmConfig`).
   * Identifies the highest priority phase (e.g., `project_initialization_needed`).
   * Delegates: `new_task @Orchestrator_Project_Initialization User_Blueprint_Path: ..., Project_Root: ...`
3. **Phase Orchestrator (e.g., `🌟 Orchestrator_Project_Initialization`, Thinking Mode):**
   * Receives phase task.
   * Breaks it down, delegating to specialist agents:
     * `new_task @ResearchPlanner_Strategic Blueprint_Path: ...`
     * `new_task @SpecWriter_Feature_Overview Feature_Name: ...`
4. **Specialist Agent (e.g., `👨‍💻 Coder_Test_Driven`, Instruct Mode, Claude @ ~0.25):**
   * Receives micro-task (e.g., "Implement function X to pass these tests Y, Z").
   * Performs task (coding, testing, researching via Tiered RDD).
   * Reports `attempt_completion`. Crucially, its `customInstructions` (in `.roomodes`) define **Pheromone Deposits** based on its outcome.
     * Example (Coder successful): `PheromoneDeposit: [{signalType: 'coding_complete_for_feature_X', target: 'FeatureA', delta: 10.0, category: 'state'}, {signalType: 'coding_needed_for_feature_X', target: 'FeatureA', delta: -5.0, category: 'need'}]`
     * Example (Tester finds bug): `PheromoneDeposit: [{signalType: 'critical_bug_in_feature_X', target: 'FeatureA', delta: 7.0, category: 'problem'}]`
5. **Signal Propagation & Next Cycle:**
   * New signals update the `.pheromone` file.
   * The `👑 Meta-Orchestrator` (or the current Phase Orchestrator if managing sub-phases) re-evaluates the pheromone landscape in its next cycle.
   * If `critical_bug_in_feature_X` is high, it might prioritize calling `🎯 Debugger` or tasking `🔄 Orchestrator_Refinement_And_Maintenance`.
   * If `coding_complete_for_feature_X` is signaled, and tests pass, it might signal `integration_needed_for_features_XYZ`.
6. **Loop Continues:** This cycle of signal interpretation, delegation, execution, and new signal deposition continues until the overall project goals (derived from your initial input) are met, or the system reaches a stable state awaiting further user input.

## ✨ Why the Swarm Edition is a Game Changer

* 👑 **Autonomous Project Progression:** Less hand-holding needed once the initial Blueprint is clear.
* 🐜 **Adaptive & Emergent Problem Solving:** The swarm can identify and prioritize fixing bugs, security issues, or integration conflicts based on real-time signals.
* 📈 **Scalable Complexity Management:** Breaks down huge projects into manageable, coordinated phases and micro-tasks handled by specialized agents.
* 🔗 **Robust Dependency Handling:** Built-in signals for feature and component dependencies prevent out-of-order work.
* 🛡️ **Enhanced Resilience:** The system can dynamically re	

route efforts if one path is blocked (e.g., a stubborn bug can halt a feature but allow others to proceed if independent).
* 📊 **Transparent Progress & Bottlenecks:** The `.pheromone` file (though not for manual editing) can be inspected (or a future UI could visualize it) to understand current priorities, needs, and blockers.
* 💰 **Efficient Resource Utilization:** While involving many agents, each uses its Claude 3.7 Sonnet context (~200k) effectively for focused tasks. The distributed nature of swarm memory avoids the extreme costs and diminishing returns of attempting to manage entire projects in hypothetical terabyte-scale single contexts.
* 🧪 **TDD as a True Guiding Force:** Test outcomes directly shape the swarm's behavior.

## 🛠️ The Core Components of the Swarm

1. **SPARC-SAPPO Swarm Agent Army (`.roomodes` file):**
   * **`swarmConfig`:** Defines the physics of your pheromone system (evaporation, amplification, priorities, signal categories, recruitment thresholds for specialist debuggers/optimizers, etc.). THIS IS KEY.
   * **`customModes`:** JSON definitions for all agents (`👑 Meta-Orchestrator`, Phase Orchestrators, `👨‍💻 Coder`, `🧪 Tester`, `🔎 ResearchPlanner_Strategic`, etc.). Each agent has:
     * `roleDefinition`: Its purpose.
     * `customInstructions`: Detailed step-by-step logic, including **when and what Pheromone Signals to deposit** upon `attempt_completion`.
     * `groups`: Permitted Roo Code tools (read, edit, command, mcp).
2. **The Pheromone Board (`.pheromone` file):**
   * The dynamic, shared "whiteboard" or "scent map" for the swarm.
   * Stores an array of signal objects, each with `signalType`, `target`, `strength`, `timestamp`, `category`, etc.
   * **CRITICAL: Managed ENTIRELY by the agents. DO NOT MANUALLY EDIT THIS FILE.** Corrupting it can confuse the swarm. (Okay to delete if you need a hard reset, then re-initiate with Meta-Orchestrator).
3. **SPARC Syntax & SAPPO Ontology:** Embedded within agent instructions to guide task structuring, problem anticipation, and decision documentation.
4. **Perplexity Research Tools (MCP):** Used by specialist agents via `⚙️ MCP Tool Specialist` or directly if configured for `mcp` group.
5. **Unified LLM Engine (Claude 3.7 Sonnet):** With dual temperature profiles.

## 🎬 See It In Action (A Glimpse of the Swarm)

**User:** Provides `MyCoolApp_Blueprint.md` to `👑 Meta-Orchestrator`.

**Meta-Orchestrator:**
1. Reads blueprint.
2. Writes to `.pheromone`: `[{signalType: "project_state_new_blueprint_available", strength: 10.0, ...}, {signalType: "project_initialization_needed", strength: 8.0, ...}]`
3. Sees `project_initialization_needed` is high.
4. `new_task @Orchestrator_Project_Initialization Blueprint_Path: "MyCoolApp_Blueprint.md" ...`

**🌟 Orchestrator_Project_Initialization:**
1. Tasks `🔎 ResearchPlanner_Strategic`.
2. `🔎 ResearchPlanner_Strategic` completes, deposits its findings (indirectly causing updates to `.pheromone` via the Orchestrator).
3. Eventually, `🌟 Orchestrator_Project_Initialization` reports `attempt_completion`.
4. Its `PheromoneDeposit` in `customInstructions` updates `.pheromone`: `[{signalType: "project_initialization_complete", strength: 10.0, ...}, {signalType: "framework_scaffolding_needed", strength: 7.0, ...}]` (and negative delta on "project_initialization_needed").

**(Later, a Coder and Tester interact via the `⚙️ Orchestrator_Feature_Implementation_TDD`)**

**👨‍💻 Coder_Test_Driven (after an attempt):**
* `attempt_completion` (code written).
* Implicitly, the Feature Orchestrator tasks the Tester.

**🧪 Tester_TDD_Master (after running tests):**
* If FAIL: `attempt_completion` Summary: "Test Run Complete. Result: FAIL. Test_X_Failed...".
* Its `PheromoneDeposit` updates `.pheromone`: `[{signalType: "critical_bug_in_feature_X", target: "MyFeature", strength: 6.5 (priority adjusted), ...}]`.

**👑 Meta-Orchestrator (or `⚙️ Orchestrator_Feature_Implementation_TDD`):**
1. Sees new `critical_bug_in_feature_X` signal.
2. Consults `swarmConfig.recruitmentThresholds`. If `critical_bug_in_feature_X` strength is high enough for `Debugger_Targeted`.
3. `new_task @Debugger_Targeted Target_Feature_Name: "MyFeature" ...`
4. The cycle continues, adaptively.

**Example snippet from `.pheromone` (illustrative):**
```json
{
  "signals": [
    {
      "signalType": "framework_scaffolding_complete",
      "target": "project_root",
      "strength": 9.8,
      "timestamp": "...",
      "category": "state"
    },
    {
      "signalType": "test_planning_needed_for_feature_X",
      "target": "UserLogin",
      "strength": 6.5,
      "timestamp": "...",
      "category": "need"
    },
    {
      "signalType": "coding_needed_for_feature_X",
      "target": "UserProfile",
      "strength": 0.8,
      "timestamp": "...",
      "category": "need"
    },
    {
      "signalType": "critical_bug_in_feature_X",
      "target": "PaymentModule",
      "strength": 7.2,
      "timestamp": "...",
      "category": "problem",
      "priorityBoost": 2.5
    }
  ],
  "analytics": { /* history, bottleneck info */ }
}
```

## 🔧 Get Started (Unleash the Swarm!)

Ready for intelligent, adaptive, AI-driven development?

### Prerequisites
* VS Code + Roo Code extension.
* Anthropic API Key (Claude 3.7 Sonnet access).
* Perplexity API Key (for Tiered RDD).

### Configuration: The Holy Trinity (`.roomodes`, `.pheromone`, LLM Profiles)

1. **Create `.roomodes` File:**
   * In the root of your project directory, create a file named exactly `.roomodes`.
   * Copy the entire JSON content (the full JSON configuration you provided previously, starting with `{"swarmConfig": ...}` and ending with the last `]`) into this `.roomodes` file. Save it.
   * This file is your swarm's DNA.

2. **Create `.pheromone` File:**
   * In the root of your project directory, create an empty file named exactly `.pheromone`.
   * **DO NOT** add any content to it initially. The swarm populates and manages this.

3. **Perplexity MCP Setup (RDD Tools):**
   * Use `cline` (recommended): Install "Perplexity AI" provider, enter key, copy MCP URL/Header.
   * Paste URL/Header into Roo Code's Perplexity MCP settings. (Tools like Firecrawl in your `.roomodes` also use MCP, so ensure that provider is set up if you intend to use it).

4. **Dual-Mode LLM Configuration (CRITICAL for Agent Roles!):**
   * Create **TWO** model profiles in Roo Code settings, **BOTH** pointing to your Anthropic Claude 3.7 Sonnet endpoint:
     * **Profile 1 (Thinking):** Name: `claude-3.7-sonnet-thinking`. Endpoint: [Your Claude 3.7 Sonnet Endpoint]. Default Temperature: ~0.7.
     * **Profile 2 (Instruct):** Name: `claude-3.7-sonnet-instruct`. Endpoint: [Your Claude 3.7 Sonnet Endpoint]. Default Temperature: ~0.25.
   * **Manual Profile Switching:** The `.roomodes` define which agents are intended for thinking vs. instruct tasks. You **MUST** manually select the correct profile (thinking or instruct) in the Roo Code UI before invoking or allowing delegation to an agent that typically uses that mode.
     * Generally: Use `thinking` for `👑 Meta-Orchestrator` and Phase Orchestrators.
     * Switch to `instruct` if a Coder, Tester, Debugger, or other specialist "Instruct Mode" agent is about to run.
     * Switch back to `thinking` when control returns to an Orchestrator.

5. **Reload Roo Code Modes:**
   * After saving `.roomodes`, use the VS Code command palette (`Ctrl+Shift+P` or `Cmd+Shift+P`): `Roo Code: Reload Custom Modes`. Or restart VS Code.

### Igniting the Swarm: Your First Project

1. **Craft a Detailed User Blueprint:**
   * Create a Markdown file (e.g., `my_project_blueprint.md`). This is your primary input for the swarm. See *The User Blueprint Format* section below for crucial details on what to include. The more detail, the better the swarm performs.
2. Open a Roo Code Chat.
3. Manually select the `claude-3.7-sonnet-thinking` profile.
4. Select the `👑 Meta-Orchestrator (Swarm Director)` mode from the Roo Code mode dropdown.
5. Provide the initial directive:
   ```
   @Meta-Orchestrator (Swarm Director)
   User_Directive_Type_Field: 'NEW_PROJECT'
   User_Directive_Payload_Path_Field: 'path/to/your/my_project_blueprint.md'
   Project_Root_Path_Field: '.' // (or the relative/absolute path to your project root if different)
   ```
   * Replace `path/to/your/my_project_blueprint.md` with the actual path.
6. **Observe!** The `👑 Meta-Orchestrator` will start its loop, reading/writing to `.pheromone`, and delegating to Phase Orchestrators. You'll see tasks being created for other agents.
7. **Manage LLM Profiles:** Remember to switch between `thinking` and `instruct` profiles as different agent types become active if you are manually stepping through or observing closely. (Full automation of this is a Roo Code feature for the future).

### Modifying an Existing Project with the Swarm

1. **Prepare a Change Request / Bug Report:**
   * Create a Markdown file (e.g., `feature_enhancement_01.md` or `bug_fix_auth_module.md`) detailing the required changes or the bug.
2. Open Roo Code Chat, select `claude-3.7-sonnet-thinking` profile.
3. Select `👑 Meta-Orchestrator (Swarm Director)` mode.
4. Provide the directive:
   ```
   @Meta-Orchestrator (Swarm Director)
   User_Directive_Type_Field: 'EXISTING_PROJECT_MODIFICATION'
   User_Directive_Payload_Path_Field: 'path/to/your/feature_enhancement_01.md'
   Project_Root_Path_Field: '.'
   ```
5. The `👑 Meta-Orchestrator` will initiate signals and likely delegate to `🔄 Orchestrator (Refinement & Maintenance)`.

## 📄 The User Blueprint (Essential Input for New Projects)

Your `.roomodes` specify what `🌟 Orchestrator (Project Initialization & Vision)` expects. A comprehensive User Blueprint is critical. It should be a Markdown file and ideally cover:

* **Big Picture Elevator Pitch:** What is it? Who is it for? Why build it?
* **Problem:** The core problem this software solves.
* **Why:** The motivation behind solving this problem.
* **Users Primary:** Detailed description of the target users.
* **Goals:** What users will achieve with this software.
* **Features Core Actions:** A list of primary actions/features. E.g., "User can register," "User can create a post," "Admin can manage users."
* **Deep Dive (for complex features):** More detailed explanation of intricate features.
* **Information Needed:** What data will the system manage? (e.g., user profiles, product details, order history).
* **Relationships:** How different pieces of information relate (e.g., an order belongs to a user and contains products).
* **Look & Feel Style:** General aesthetic preferences, brand guidelines if any.
* **Similar Programs:** Links or descriptions of existing applications that have similar features or style (likes/dislikes).
* **Platform Environment:** Target platforms (web, mobile, desktop), desired OS, browser compatibility.
* **Rules & Boundaries Must-Haves:** Non-negotiable constraints, compliance requirements (e.g., GDPR, HIPAA if applicable).
* **Avoid:** Things to explicitly not do or technologies/patterns to avoid.
* **Success Criteria Scenarios:** High-level user scenarios that, if functional, would define success. (e.g., "A new user can sign up, create a profile, and post their first message within 5 minutes.").
* **Inspirations Similar Functionality:** Specific examples of functionality you like.
* **Likes/Dislikes:** General preferences.
* **Future Dreams (Optional):** Ideas for v2, v3, etc.
* **Technical Preferences (Optional):** Preferred programming languages, frameworks, databases, architectural styles (but be prepared for the AI to research and recommend).

The more specific and clear your Blueprint, the better the `🔎 Research Planner` and subsequent agents can build an accurate initial plan.

## 🐜 Understanding the Pheromone System (`.pheromone` & `swarmConfig`)

The heart of the swarm is the communication system.

### `.pheromone` File:
* **Dynamic State:** Stores an array of "signal" objects. Each signal has a `signalType` (e.g., `coding Wanted_for_feature_X`), `target` (e.g., "FeatureName"), `strength`, `timestamp`, `category` (`state`, `need`, `problem`, `priority`), and potentially other metadata like `relatedTarget` for dependencies.
* **Agent-Managed:** Agents deposit signals based on their `customInstructions` when they `attempt_completion`. The `👑 Meta-Orchestrator` (and sometimes Phase Orchestrators) reads and processes these signals.
* **Evolution:** Signal strengths change due to:
  * **New Deposits:** Agents adding or modifying signals.
  * **Evaporation:** `swarmConfig.evaporationRates` cause signals to weaken over time, keeping the board focused on current needs.
  * **Amplification:** `swarmConfig.signalAmplification` boosts repeated signals, highlighting persistent needs or successful discoveries.
  * **Pruning:** Weak signals below `swarmConfig.signalPruneThreshold` are removed.
* **Read-Only for Humans:** For observation or debugging, you can look at it. But **DO NOT MANUALLY EDIT IT**. A hard reset involves deleting it and re-initiating with the Meta-Orchestrator.

### `swarmConfig` (in `.roomodes`):
Defines the "laws of physics" for your pheromone system. Key aspects:
* `evaporationRates`: How quickly different signal categories fade.
* `explorationRate` (ε): Small chance for the Meta-Orchestrator to pick a non-top-priority task to avoid getting stuck.
* `signalCategories` & `signalTypes`: The vocabulary of the swarm.
* `signalPriorities`: Certain signals (e.g., `critical_bug_in_feature_X`) inherently get higher importance.
* `dependencySignals`: Configuration for tracking inter-feature/component dependencies.
* `conflictResolution`: How the Meta-Orchestrator chooses when multiple needs compete.
* `anticipatorySignals`: Enables the system to proactively flag future needs.
* `analyticsTracking`: For advanced features like bottleneck or oscillation detection.
* `emergencyThresholds`: Critical signal strengths that trigger immediate priority shifts.
* `recruitmentThresholds`: Signal strengths that trigger specialized agents like `🎯 Debugger_Targeted` or `🧹 Optimizer_Module`.

Familiarize yourself with these `swarmConfig` settings in your `.roomodes` to understand how the swarm will behave. Tuning these (carefully!) allows for advancedÂ advanced customization of the swarm's intelligence.

## 🚦 Navigating the Swarm: Best Practices

* **Detailed Inputs are King:** The User Blueprint (or Change Request) is your most powerful steering tool. Garbage-in, garbage-out (or at least, a very confused swarm).
* **Trust The Process (Mostly):** The swarm is designed to be adaptive. Let it work through its phases. Intervene at the Meta-Orchestrator level if the overall direction seems off, rather than trying to micromanage individual specialist agents (unless debugging a specific agent's behavior).
* **TDD is Your Friend:** The swarm heavily relies on test outcomes as signals. Well-defined tests (planned by `🎯 Orchestrator (Test Specification & Generation)`) are crucial for the `⚙️ Orchestrator (Feature Implementation - Test-Driven)` to guide Coders effectively.
* **Iterative Refinement:** For very complex projects, you might provide an initial Blueprint for an MVP, let the swarm build it, then provide Change Requests for subsequent features.
* **Understand Agent Roles:** Review the `roleDefinition` and `customInstructions` (especially `PheromoneDeposit` logic) for key orchestrators and specialists in your `.roomodes` to grasp how they contribute and communicate.
* **Monitor (Don't Edit) `.pheromone`:** If things seem stalled, peeking into `.pheromone` (read-only!) can give clues about what signals the Meta-Orchestrator is currently seeing.
* **Patience with Exploration:** The `explorationRate` means the swarm might occasionally try a less obvious path. This is a feature to prevent local optima.

## 🔎 Troubleshooting the Swarm

* **Swarm Seems Stalled:**
  * Check the last few outputs from the `👑 Meta-Orchestrator` or active Phase Orchestrator.
  * (Carefully) view the `.pheromone` file. Are there very strong "problem" signals? Are "need" signals not being addressed? Is there an unfulfilled dependency?
  * Ensure your LLM API keys are valid and you have credits.
* **Agents Not Behaving as Expected:**
  * Double-check the `customInstructions` for that specific agent in `.roomodes`.
  * Ensure the correct LLM profile (Thinking/Instruct) was active when that agent was invoked.
  * Simplify the input or task for that agent to see if it's a complexity issue.
* **Hard Reset:**
  * If the `.pheromone` file seems corrupted or the swarm is in an unrecoverable loop, you can:
    * Stop any active Roo Code processes.
    * Delete the `.pheromone` file.
    * Re-create an empty `.pheromone` file.
    * Re-initiate the project from scratch with the `👑 Meta-Orchestrator` and your original User Blueprint/Change Request.
* **Vague Blueprint Issues:** If the swarm is thrashing or producing irrelevant output early on, your User Blueprint likely lacks clarity or contains conflicting requirements. Refine it and restart.

## 🌌 SPARC Syntax Overview
*(This section remains relevant as SPARC principles are still encoded in agent instructions)*

The symbolic syntax (`Φ•Ω`, `Γ•Μ•Υ`, etc.) represents core principles encoded in agent instructions. Key concepts include:
* `Φ•Ω` [Core•Flow]: Workflow clarity, systematic extension, code quality (§͟qual), confirmation (⊦confirm).
* `Γ•Μ•Υ` [Context]: Doc/context-driven action (⊦⟨doc⟩ ⟨ctx⟩ → ⟨action⟩), arch boundaries (⊤⟨arch⟩), tech management (⊢{...} ⊥newΔ). Swarm helps manage distributed context.
* `Τ•Ρ` [Tasks]: Micro-tasks (⊦⟨micro⟩), tiered RDD for uncertainty (‼️Ρ{pMCP tiers}→{search|...}✓findings), self-verify (⊗self{...}→⊦complete).
* `Κ•Σ` [Code]: Best practices (⊢{bestPractice}), conventions (≡⟨conventions⟩), modularity (⊤⟨module⟩), size limits (⟨file⟩≤350Λ), DRY (¬⟨duplication⟩).
* `Χ` [Refactor]: Improve code, verify via tests (⊨{⋈intact}⇒{⊦tester-tdd}).
* `Δ` [Testing]: Test-driven (⊢⟨test→code⟩), high coverage (⊤∀⟨coverage⟩), completion gated by passing dual-strategy tests (‼️✓⟨tests pass:dual⟩→⊦complete). Crucial for swarm signaling.
* `Β` [Debug]: SAPPO root cause (⊙{⟨root⟩:SAPPO}), precise logs. Triggered by pheromone signals.
* `Ξ` [Security]: Server-logic (⊤{server-logic}), validation (‼️⊤⟨validate⟩), no hardcoded secrets. Agents like `🛡️ SecurityReviewer_Module` are triggered by signals or phase plans.
* `Ψ•Ε` [VCS•Env]: Git usage, env-agnostic code.
* `Λ` [Docs]: Accurate, including test strategy.
* `Θ` [Limits]: File size, abstract credentials.

## 🙏 Acknowledgements

* Builds heavily on Reuven Cohen's SPARC methodology and 'Boomerang Tasks' concept.
* Reference: 🪃 [Boomerang Tasks by Reuven Cohen](https://gist.github.com/ruvnet/a206de8d484e710499398e4c39fa6299)
* The Pheromone-Based Swarm Orchestration engine is a new layer inspired by stigmergic communication in natural systems.
* SAPPO is a custom ontology for this framework.

## 📜 License

MIT License - see [LICENSE](LICENSE) file.

## 🙏 Support Development

<div align="center">
<p>Found this framework valuable? Consider supporting its development.</p>
<a href="https://paypal.me/ChrisRoyseAI" target="_blank"><img src="https://img.shields.io/badge/Support_via_PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white" alt="Support via PayPal" width="250"/></a>
<p style="margin-top: 10px;">Your support helps offset API costs and allows for further refinement and evolution of this AI swarm system.</p>
<p>Thank you!</p>
</div>

## 🔗 Related Resources

* [Roo Code Docs](https://roo.ai)
* [Perplexity API Docs](https://perplexity.ai)
* [Anthropic API Docs (Claude)](https://www.anthropic.com/api)
* [SAPPO Ontology](https://github.com/ChrisRoyse/Coding-Agent-Ontology) (Placeholder)
* [cline MCP Installer](https://cline.tools)
* [MCP Standard](https://perplexity.ai/mcp)

## 👤 Connect

🔗 [LinkedIn - Christopher Royse](https://www.linkedin.com/in/christopher-royse)

Embrace the future of software development with structured, ontology-driven, Dual-Strategy TDD-powered AI Swarm Orchestration. Plan meticulously with detailed User Blueprints, and let the swarm intelligently and adaptively build your vision!
