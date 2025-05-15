# Pheromind Agent Configuration: Standard SDLC & Feature Development

## Overview

This `.roomodes` file contains the **standard configuration** of Pheromind AI agents, designed to manage the **full software development lifecycle (SDLC)** for new features or entire projects. It leverages the SPARC (Specification, Pseudocode, Architecture, Refinement, Completion) methodology and emphasizes a Test-Driven Development (TDD) approach with AI-verifiable outcomes.

This configuration is intended for:
* Developing new features within an existing project structure.
* Managing complex projects from detailed specification through to completion and maintenance.
* Iterative refinement of code quality, security, and performance.
* Projects where the initial, comprehensive scaffolding (as provided by the "MVP Jumpstart" configuration) is already complete or not the primary immediate goal.

## Core Workflow Enabled by This Configuration

When using this standard `.roomodes` file, Pheromind typically executes the SPARC workflow for feature development or project execution:

1.  **Specification (SPARC: Specification):**
    * The `🌟 @orchestrator-sparc-specification-master-test-plan` orchestrates the creation of detailed feature specifications, a Master Project Plan with AI-verifiable tasks, and high-level end-to-end acceptance tests. This phase often starts from a User Blueprint or a detailed change request.
    * Worker agents like `📝 @spec-writer-feature-overview` and `✅ @tester-acceptance-plan-writer` (for high-level tests) are involved.
2.  **Architecture & Design (SPARC: Pseudocode, Architecture):**
    * Orchestrators like `🧐 @uber-orchestrator` delegate architectural design tasks (e.g., to `🏛️ @architect-highlevel-module`) based on the specifications.
    * Framework scaffolding (if needed, via `🛠️ @orchestrator-framework-scaffolding` or similar, though this is less emphasized than in the MVP jumpstart for *initial* setup) might occur here or be assumed to exist.
3.  **Implementation (SPARC: Refinement - Initial Coding):**
    * The `⚙️ @orchestrator-feature-implementation-tdd` manages the Test-Driven Development of specific features.
    * It first ensures granular test plans are created (e.g., via `🎯 @orchestrator-test-specification-and-generation`, which uses `🗺️ @spec-to-testplan-converter`).
    * Then, `👨‍💻 @coder-test-driven` writes code to pass these tests, with `🧪 @tester-tdd-master` verifying outcomes.
    * Emphasis is placed on self-reflection by the coder regarding code quality.
4.  **Refinement & Maintenance (SPARC: Refinement - Iterative Improvement):**
    * The `🔄 @orchestrator-refinement-and-maintenance` manages bug fixes, enhancements, and dedicated refinement cycles.
    * It employs specialized worker agents for debugging (`🎯 @debugger-targeted`), code comprehension (`🧐 @code-comprehension-assistant-v2`), optimization (`🧹 @optimizer-module`), and security reviews (`🛡️ @security-reviewer-module`).
5.  **Completion (SPARC: Completion):**
    * Focuses on final testing, documentation updates (via `📚 @docs-writer-feature`), and deployment (via `🚀 @devops-pipeline-manager`).
6.  **Continuous State Management:** As with all Pheromind configurations, the `✍️ @orchestrator-pheromone-scribe` interprets natural language summaries from orchestrators, updating the `.pheromone` file.

## Key Agents in the Standard Configuration

This configuration utilizes a broad range of Pheromind agents, each specialized for different stages of the SDLC:

* **Core Orchestrators:**
    * `✍️ @orchestrator-pheromone-scribe`
    * `🎩 @head-orchestrator`
    * `🧐 @uber-orchestrator`
* **SPARC Phase Orchestrators:**
    * `🌟 @orchestrator-sparc-specification-master-test-plan`
    * `🎯 @orchestrator-test-specification-and-generation`
    * `⚙️ @orchestrator-feature-implementation-tdd`
    * `🔄 @orchestrator-refinement-and-maintenance`
    * (And potentially others like `🛠️ @orchestrator-framework-scaffolding` if needed for substantial structural changes post-initial setup).
* **Specialized Worker Agents:**
    * `📝 @spec-writer-feature-overview`
    * `🗺️ @spec-to-testplan-converter`
    * `👨‍💻 @coder-test-driven`
    * `🧪 @tester-tdd-master`
    * `🎯 @debugger-targeted`
    * `🧐 @code-comprehension-assistant-v2`
    * `🏛️ @architect-highlevel-module`
    * `🧹 @optimizer-module`
    * `🛡️ @security-reviewer-module`
    * `📚 @docs-writer-feature`
    * `🔩 @devops-foundations-setup`
    * `🧱 @coder-framework-boilerplate`
    * `🚀 @devops-pipeline-manager`
    * `🔎 @research-planner-strategic` (can be used for targeted research during any phase).

## How This Differs from the MVP Jumpstart Configuration

The "MVP Jumpstart & Scaffolding" `.roomodes` configuration (detailed in `roomodes_readme_mvp.md`) is a specialized subset and adaptation of Pheromind agents focused *exclusively* on the **initial creation and structural scaffolding of a new project repository**.

* **Focus:**
    * **MVP Jumpstart:** Initial setup, research, planning, and *structural scaffolding* of an entire application from an architect's detailed vision. Its output is a non-functional but complete code and test *structure*.
    * **Standard SDLC (This File):** Full development lifecycle for features *within* an existing (or newly scaffolded) project. It focuses on writing functional code, detailed testing, refinement, and maintenance.
* **Primary Input:**
    * **MVP Jumpstart:** Architect-provided specifications in an `agent-specs/` folder.
    * **Standard SDLC:** User Blueprints, Change Requests, or tasks derived from a Master Project Plan / Phased Implementation Plan.
* **Key Specialized Agents (in MVP Jumpstart, less central here for *initial* setup):**
    * `🚀 @orchestrator-project-kickstart`
    * `🗺️ @orchestrator-implementation-planner`
    * `🛠️ @orchestrator-end-to-end-application-scaffolder`
    * `👨‍💻 @coder-scaffolder`
    * `🏗️ @test-scaffolder`
* **Outcome:**
    * **MVP Jumpstart:** A comprehensive, structurally complete but non-functional project scaffold and detailed implementation plan, ready for a development team.
    * **Standard SDLC:** Working software features, refined code, completed project phases, and maintained applications.

In essence, the MVP Jumpstart configuration prepares the "empty house" with all rooms framed and a blueprint for finishing. This Standard SDLC configuration then "builds out" the rooms, installs plumbing and electricity, and furnishes the house according to that blueprint.

## Usage

This standard `.roomodes` file is suitable for:
1.  Developing new features once a project has been initiated (either manually or via the MVP Jumpstart configuration).
2.  Managing the entire lifecycle of projects that do not require the specific "architect-first, full-scaffold" approach of the MVP Jumpstart.
3.  Ongoing maintenance and refinement of existing Pheromind-managed projects.

To use this configuration, ensure it is the active `.roomodes` file in your project, alongside the corresponding `.swarmConfig` and `.pheromone` files. Initiate tasks via the `🎩 @head-orchestrator` with User Blueprints or other appropriate directives for feature development.

Refer to the main Pheromind `README.md` for more general information on the framework and agent interactions.
