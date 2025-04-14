# 🚀 SPARC-Omega Vibe Coding: Ontology-Guided AI + Perplexity!

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Roo Code Compatible](https://img.shields.io/badge/Roo%20Code-Compatible-brightgreen)](https://roo.ai)
[![Perplexity API](https://img.shields.io/badge/Perplexity-API-blue)](https://perplexity.ai)
[![Anthropic Claude](https://img.shields.io/badge/Requires-Claude%203.5%20Sonnet-purple)](https://www.anthropic.com/news/claude-3-5-sonnet)
[![Ontology-Guided](https://img.shields.io/badge/Ontology-Guided-purple)](.)
[![SPARC Methodology](https://img.shields.io/badge/Methodology-SPARC-orange)](.)
[![cline MCP Installer](https://img.shields.io/badge/cline-MCP%20Installer-orange)](https://cline.tools)

## 🎧 What is This? (The SPARC-Omega Vibe Explained)

Step into the future of AI-assisted development with **SPARC-Omega Vibe Coding**. This framework elevates coding beyond simple autocompletion by integrating:

1.  **Ontology-Guided Prompts:** A structured way to leverage the AI's internal knowledge about software architecture concepts (`:Problem` types, `:ArchitecturalPattern`s, `:TechnologyVersion`s, `:Context`).
2.  **SPARC-Omega Methodology:** An enhanced workflow (Specification, Pseudocode, Architecture, Refinement, Completion), inspired by Reuven Cohen's SPARC and Boomerang Tasks, guiding development lifecycle stages.
3.  **Perplexity Research:** Real-time knowledge infusion via Perplexity's MCP tools (`search`, `get_documentation`, etc.).
4.  **Dual-Mode LLM Strategy:** Optimized AI performance using **Anthropic's Claude 3.7 Sonnet** at specific **temperatures** tailored to task types – higher for creativity/planning, lower for precision/execution.
5.  **Roo Code Multi-Agent System:** The platform hosting specialized AI agents collaborating on your project.

You define the goal. The SPARC-Omega Orchestrator, operating in **"Thinking Mode" (Claude 3.7 Sonnet @ Temp 0.7)**, analyzes it using Ontology concepts and delegates tasks to specialized agents. Agents focused on planning, design, and documentation also use Thinking Mode. Agents responsible for concrete implementation, testing, debugging, and operations switch to **"Instruct Mode" (Claude 3.7 Sonnet Instruct @ Temp 0.25)** for high-fidelity execution. All agents leverage Ontology prompts and Perplexity tools as needed.

This creates a synergistic system where structured architectural thinking, targeted research, and optimized AI reasoning work together for superior results.

## 📺 Quick Start Video Guide

[![Watch the SPARC-Omega Vibe Coding Setup Guide](https://img.youtube.com/vi/EEXAcMqRv3E/maxresdefault.jpg)](https://youtu.be/EEXAcMqRv3E)

👆 **Click the image above for a complete setup walkthrough!** This video guide will help you quickly install and configure SPARC-Omega Vibe Coding with all its components.

## 🔄 NEW: Dual-Mode LLM Strategy with Claude 3.7 Sonnet

This is the core engine optimization. Different tasks require different AI "mindsets." SPARC-Omega leverages this by using **Anthropic's Claude 3.7 Sonnet** with two distinct temperature settings:

1.  🧠 **Thinking Mode (Temperature: 0.7)**
    *   **Model:** Claude 3.7 Sonnet
    *   **Purpose:** Brainstorming, planning, high-level design, creative writing, exploring possibilities, complex reasoning. Higher temperature allows for more diverse and novel outputs.
    *   **Used By:**
        *   `⚡️ SPARC Orchestrator (sparc)`
        *   `📋 Specification Writer (spec-pseudocode)`
        *   `🏗️ Architect (architect)`
        *   `📚 Documentation Writer (docs-writer)`
        *   `❓ Ask (ask)`
        *   `📘 Tutorial (tutorial)`

2.  🛠️ **Instruct Mode (Temperature: 0.25)**
    *   **Model:** Claude 3.7 Sonnet
    *   **Purpose:** Precise code generation, detailed implementation, debugging, testing against specific criteria, following instructions strictly, generating factual and consistent output. Lower temperature reduces randomness and increases focus.
    *   **Used By:**
        *   `🧠 Auto-Coder (code)`
        *   `🧪 Tester (TDD, tdd)`
        *   `🪲 Debugger (debug)`
        *   `🛡️ Security Reviewer (security-review)`
        *   `🔗 System Integrator (integration)`
        *   `🚀 DevOps (devops)`
        *   `📈 Deployment Monitor (post-deployment-monitoring-mode)`
        *   `🧹 Optimizer (refinement-optimization-mode)`

**Why this matters:** Using the right temperature for the job maximizes the AI's effectiveness. You get creative exploration when needed (design) and precise execution when required (coding), leading to better overall quality and efficiency. Implementing this typically requires configuring Roo Code carefully, potentially using tools like **Requestly** to dynamically adjust API call parameters if native switching per mode isn't feasible (see Getting Started).

## ✨ Ontology Integration & SPARC-Omega Methodology

While leveraging the powerful dual-mode LLM, the framework remains grounded in:

### 🏛️ Ontology-Guided Reasoning

-   **Prompt-Based:** Uses conceptual labels (`:Problem`, `:Solution`, `:ArchitecturalPattern`, `:Context`, etc.) within agent instructions.
-   **Guides LLM Focus:** These prompts direct Claude 3.7 Sonnet to access relevant parts of its internal knowledge and structure its thinking around sound software engineering principles.
-   **Consistent & Proactive:** Ensures agents anticipate issues (e.g., `:CompatibilityIssue`) and apply appropriate patterns (e.g., `:Microservices`).

### ✨ SPARC-Omega Workflow (Ontology & LLM-Tuned)

1.  **Specification (`sparc` -> `spec-pseudocode`, *Thinking Mode*)**: Define goals, `:Context`. Frame requirements using Ontology terms. High-level research via Perplexity.
2.  **Pseudocode (`spec-pseudocode`, *Thinking Mode*)**: High-level logic, TDD anchors, anticipating `:Problem` areas. API research via Perplexity.
3.  **Architecture (`sparc` -> `architect`, *Thinking Mode*)**: Design using `:ArchitecturalPattern`s, avoiding `:AntiPattern`s. Technology selection justified via `:Context`. Perplexity research on patterns/tech.
4.  **Refinement (`sparc` -> various agents, *Instruct Mode primarily*)**:
    *   `code`: Implement features precisely.
    *   `tdd`: Write & run specific tests.
    *   `debug`: Identify & fix bugs methodically.
    *   `security-review`: Audit against known `:SecurityVulnerability` types.
    *   `refinement-optimization-mode`: Apply concrete `:Solution`s to `:Problem`s.
    *   Extensive use of Perplexity tools (`get_documentation`, `check_deprecated_code`, `search`).
5.  **Completion (`sparc` -> various agents, *Mixed Modes*)**:
    *   `integration` (*Instruct Mode*): Connect components, resolve `:CompatibilityIssue`.
    *   `docs-writer` (*Thinking Mode*): Document `:ArchitectureConcept`s, setup.
    *   `devops` (*Instruct Mode*): Deploy, manage `:EnvironmentContext`.
    *   `post-deployment-monitoring-mode` (*Instruct Mode*): Observe for `:Problem`s.

## ✨ Why It's a Game Changer

This combination is potent:

-   🧠 **Optimized AI Performance**: Dual-mode temperatures tailor Claude 3.7 Sonnet's output for maximum creativity *or* precision as needed.
-   🏛️ **Structured Architectural Thinking**: Ontology guidance ensures robust, maintainable designs.
-   🎯 **Proactive Risk Management**: Anticipate `:Problem` types *before* coding begins.
-   💡 **Deep Research Power**: Perplexity provides targeted, real-time knowledge.
-   ✅ **Higher Quality Outputs**: More modular, testable, secure, and aligned code.
-   🔄 **Full Lifecycle Awareness**: Coherent process from idea to monitoring.
-   🤝 **Enhanced Collaboration**: Shared Ontology vocabulary + optimized AI reasoning.

## 🛠️ The Core Components

1.  **SPARC-Omega Agent Army (.roomodes)**: Specialized AI personas defined in the `.roomodes` file, each assigned a default "Thinking" or "Instruct" mode context and relevant Perplexity tools.
2.  **Ontology-Guided Prompts**: Instructions embedded with Ontology concepts to steer LLM reasoning.
3.  **Perplexity Research Tools (MCP)**: `search`, `get_documentation`, `find_apis`, `check_deprecated_code`.
4.  **Dual-Mode LLM Engine**: Requires Claude 3.7 Sonnet access configured for Temperature 0.7 (Thinking) and 0.25 (Instruct).

## 🎬 See It In Action (Dual-Mode Examples)

### Example 1: Designing a Feature (Thinking -> Instruct)

**User**: "Let's design and implement a recommendation feed feature based on user history."

**⚡️ SPARC (Thinking Mode: Claude 3.7 Sonnet @ 0.7)**: "Intriguing! Recommendation engine. Assigning `architect`. Task: Design architecture for a recommendation feed. Consider `:Scalability`, `:PerformanceIssue`s (cold start), relevant `:ArchitecturalPattern`s (e.g., Content-Based Filtering, Collaborative Filtering). Research options via Perplexity `search`. Output diagram, component roles, API ideas. `attempt_completion`."

**(Later) 🏗️ Architect (Thinking Mode: Claude 3.7 Sonnet @ 0.7)**: "Designed architecture using a hybrid `:ArchitecturalPattern`. Identified `:Scalability` concern for user history processing, suggesting an async `:ComponentRole`. Researched via Perplexity. Diagram attached. Ready for implementation planning. `attempt_completion`."

**⚡️ SPARC (Thinking Mode: Claude 3.7 Sonnet @ 0.7)**: "Architecture approved. Assigning `code`. Task: Implement the core user history tracking API endpoint based on the spec. Use `:NodeJS` v20, `:PostgreSQL`. Ensure data integrity. `attempt_completion`. *Delegate will use Instruct Mode context.*"

**(Later) 🧠 Code (Instruct Mode: Claude 3.7 Sonnet @ 0.25)**: "Implemented `/users/{id}/history` POST endpoint precisely as specified. `:TechnologyVersion`s used. Added input validation and database transaction logic. Code follows style guide. `attempt_completion`."

## 🔧 Get Started (Join the Vibe!)

Ready for Ontology-guided, dual-mode AI development with Claude 3.5 Sonnet?

### Prerequisites
1.  **VS Code** with the **Roo Code extension** installed.
2.  **Anthropic API Key** with access to **Claude 3.7 Sonnet**.
3.  **Perplexity API Key**.

### Configuration: The Dual-Mode Challenge
Setting up the two different temperature modes using the *same base model* (Claude 3.7 Sonnet) requires careful configuration:

1.  **Perplexity MCP Setup**:
    *   Use [cline](https://cline.tools) (easiest) or manually set up an MCP server for Perplexity.
    *   Search for and install the "Perplexity AI" provider in cline.
    *   Follow prompts, enter your API key, and copy the MCP URL/Header details.
    *   Paste these into Roo Code's Perplexity MCP settings.

2.  **Claude 3.7 Sonnet Setup (IMPORTANT!)**:
    *   You need to configure Roo Code to talk to Claude 3.7 Sonnet via the Anthropic API.
    *   **Crucially, you need a way to apply Temperature 0.7 for 'Thinking' modes and 0.25 for 'Instruct' modes.** Roo Code might not natively support dynamic temperature switching based on the active *mode* easily when using a single model endpoint. Potential solutions:
        *   **Ideal (Requires Roo Feature/Flexibility):** If Roo Code allows defining multiple configurations *for the same model* pointing to the same Anthropic API endpoint but with different default parameters (like temperature), create two: `claude-3.7-sonnet-thinking` (temp 0.7) and `claude-3.7-sonnet-instruct` (temp 0.25). Then *modify the `.roomodes` definitions* in your JSON to explicitly reference the appropriate configuration slug for each mode. (Check Roo Code documentation if this is possible).
        *   **Requestly Workaround:** Configure *one* Claude 3.7 Sonnet endpoint in Roo Code. Use a tool like **Requestly** (browser extension/desktop app) to intercept the API calls from VS Code to your Claude endpoint. The rule would need to inspect the request payload (possibly identifying the mode from the prompt or meta-data if Roo includes it) and **modify the `temperature` parameter in the JSON payload** before it's sent to Anthropic. This requires Requestly setup and might be fragile.
        *   **Manual Selection (Less Ideal):** If you can define the two configurations (`...-thinking`, `...-instruct`) in Roo Code, you might need to manually switch the *active model configuration* in the Roo Code chat UI depending on which *type* of mode (Thinking vs Instruct) you intend to invoke next. This demands user vigilance.
    *   *Consult Roo Code documentation or community for the best current practice on managing distinct parameter sets for the same base model per mode invocation.*

3.  **Install the SPARC-Omega RooModes**:
    *   Copy the `.roomodes` JSON content provided earlier into a file named `.roomodes` in your project root (or a parent directory Roo Code checks).
    *   Alternatively, use the Roo Code UI ("Modes" section) to create/paste each mode definition from the provided JSON. Ensure the `slug`, `name`, `roleDefinition`, and `customInstructions` match exactly.
    *   Restart VS Code or refresh Roo Code.

### Start Vibing!
1.  Open a Roo Code chat.
2.  Select a SPARC-Omega mode (e.g., `⚡️ SPARC Orchestrator`). **Ensure your environment is correctly configured to apply the appropriate temperature (0.7 for Thinking modes, 0.25 for Instruct modes) when invoking tasks.**
3.  Provide your objective and watch the Ontology-guided, temperature-tuned agents collaborate! Use `❓Ask` if you need guidance on mode selection or Ontology terms.

## 🙏 Acknowledgements

This framework builds upon the visionary work of Reuven Cohen, especially his SPARC methodology and 'Boomerang Tasks' concept, foundational to structured AI development workflows in Roo Code.

-   Reference: [🪃 Boomerang Tasks: Automating Code Development with Roo Code and SPARC Orchestration by Reuven Cohen](https://www.linkedin.com/pulse/boomerang-tasks-automating-code-development-roo-sparc-reuven-cohen-nr3zc/)

## 📜 License
Licensed under the MIT License—see the `LICENSE` file for details.

## 🔗 Related Resources
-   [Roo Code Docs](https://roo.ai/docs)
-   [Perplexity API Docs](https://docs.perplexity.ai/)
-   [Anthropic API Docs](https://docs.anthropic.com/claude/reference/messages_post) (Check `temperature` parameter)
-   [Claude 3.5 Sonnet Announcement](https://www.anthropic.com/news/claude-3-5-sonnet)
-   [Requestly](https://requestly.io/) (Potential tool for temperature modification workaround)
-   [MCP Standard](https://mcp.ai)
-   [cline Setup](https://cline.tools)

---
## 👤 Connect
- [🔗 LinkedIn - Christopher Royse](https://www.linkedin.com/in/christopher-royse-b624b596/)

---

Code smarter, not just faster. Embrace the Ontology-guided, dual-mode Vibe with Claude 3.5 Sonnet!
