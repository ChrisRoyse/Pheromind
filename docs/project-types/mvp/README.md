# Pheromind Agent Configuration: Initial Project Jumpstart & MVP Scaffolding

## Overview

This `.roomodes` file contains a specialized configuration of Pheromind AI agents, meticulously designed and optimized for the **initial jumpstarting and comprehensive scaffolding of new software projects**. The primary goal of this configuration is to rapidly transform an architect's vision and detailed specifications into a well-structured, developer-ready repository, laying a complete foundation for subsequent Minimum Viable Product (MVP) development.

This configuration prioritizes:
* **Architect-Driven Design:** Leveraging detailed specifications provided by a senior architect as the primary input (typically located in an `agent-specs/` folder).
* **Upfront Research & Planning:** Automating foundational research and the creation of a detailed, phased implementation plan.
* **End-to-End Structural Scaffolding:** Generating the complete file and folder structure for the application's source code and tests, ensuring all intended functionality is represented by placeholders and clear comments.
* **Developer Handoff Readiness:** Producing a repository that allows a development team to quickly understand the project's intent, architecture, and planned phases.

## Core Workflow Enabled by This Configuration

When using this `.roomodes` file, Pheromind executes a specialized "Project Jumpstart" workflow:

1.  **Specification Ingestion:** The `🧐 @uber-orchestrator`, guided by an initial directive (e.g., `"PROJECT_BLUEPRINT_KICKSTART"`), identifies and processes the architect's specifications from the `agent-specs/` directory.
2.  **Initial Kickstart & Research:** The `🚀 @orchestrator-project-kickstart` takes the lead. It coordinates:
    * Setting up foundational project directories (including `/research` and `/implementation-plan`).
    * Delegating in-depth research tasks to `🔎 @research-planner-strategic` based on the architect's vision, with outputs stored in `/research`.
3.  **Phased Implementation Planning:** The `🗺️ @orchestrator-implementation-planner` utilizes the architect's specifications and research findings to:
    * Define overall high-level acceptance tests (via `✅ @tester-acceptance-plan-writer`).
    * Create a comprehensive project roadmap (`/implementation-plan/Roadmap.md`).
    * Generate detailed documentation for each development phase within `/implementation-plan/<phase_name>/`, including specific goals, features to be scaffolded, implementation notes, and test considerations for developer handoff.
4.  **End-to-End Application Scaffolding:** The `🛠️ @orchestrator-end-to-end-application-scaffolder` orchestrates the creation of the entire application structure:
    * `👨‍💻 @coder-scaffolder` generates the source code file/folder structure (e.g., in `/src`) with placeholder functions, classes, and detailed comments reflecting all intended functionality.
    * `🏗️ @test-scaffolder` generates the corresponding test file/folder structure (e.g., in `/tests`) with placeholder test cases aligned with the phased implementation plan, without attempting to make them pass by overwriting application logic.
5.  **Continuous State Management:** Throughout this process, the `✍️ @orchestrator-pheromone-scribe` interprets natural language summaries from these orchestrators, updating the `.pheromone` file's signals and `documentationRegistry` to reflect the project's progress and generated artifacts.

## Key Agents Specific to This Jumpstart Configuration

While this `.roomodes` file includes a full suite of Pheromind agents, the following are central to the initial project jumpstart and scaffolding workflow:

* **Core Orchestrators (Modified for Jumpstart):**
    * `✍️ @orchestrator-pheromone-scribe`
    * `🎩 @head-orchestrator`
    * `🧐 @uber-orchestrator`
* **Specialized Jumpstart Orchestrators:**
    * `🚀 @orchestrator-project-kickstart`
    * `🗺️ @orchestrator-implementation-planner`
    * `🛠️ @orchestrator-end-to-end-application-scaffolder`
* **Specialized Jumpstart Worker Agents:**
    * `🔎 @research-planner-strategic` (adapted for initial research)
    * `✅ @tester-acceptance-plan-writer` (for defining overall acceptance tests early)
    * `👨‍💻 @coder-scaffolder` (for source code structure)
    * `🏗️ @test-scaffolder` (for test structure)
    * `🔩 @devops-foundations-setup` (for initial directory setup)

Other agents like `👨‍💻 @coder-test-driven`, `🧪 @tester-tdd-master`, and various refinement orchestrators are intended for use in subsequent development phases *after* this initial jumpstart and scaffolding are complete, as guided by the generated implementation plan.

## Intended Outcome

The use of this `.roomodes` configuration aims to significantly accelerate the setup of new projects. The output is not a fully functional application but rather a comprehensive, well-planned, and structurally complete foundation. This allows human development teams (potentially AI-assisted) to hit the ground running with a clear understanding of the architecture, intended features, and a pre-defined roadmap, drastically reducing the initial overhead of starting a new software endeavor.

## Usage

To utilize this configuration for a new project:
1.  Prepare your architect's specifications in an `agent-specs/` folder within your new project repository, including a main vision/blueprint document (e.g., `agent-specs/vision/Product_Vision.md`).
2.  Ensure this `.roomodes` file, along with the corresponding `.swarmConfig` and an initial (empty) `.pheromone` file, are present in the project root.
3.  Initiate the `🎩 @head-orchestrator` with the appropriate directive (e.g., `PROJECT_BLUEPRINT_KICKSTART`) pointing to your main architect blueprint.

Refer to the main Pheromind `README.md` for more general information on the framework and agent interactions.
