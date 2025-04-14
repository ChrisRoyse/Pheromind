# 🚀 SPARC-Omega Vibe Coding: Knowledge-Guided AI + Ontology + Perplexity!

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Roo Code Compatible](https://img.shields.io/badge/Roo%20Code-Compatible-brightgreen)](https://roo.ai)
[![Perplexity API](https://img.shields.io/badge/Perplexity-API-blue)](https://perplexity.ai)
[![Ontology-Guided](https://img.shields.io/badge/Ontology-Guided-purple)](.)
[![SPARC Methodology](https://img.shields.io/badge/Methodology-SPARC-orange)](.)
[![cline MCP Installer](https://img.shields.io/badge/cline-MCP%20Installer-orange)](https://cline.tools)

## 🎧 What is This? (The SPARC-Omega Vibe Explained)

Forget coding in the dark. This is **SPARC-Omega Vibe Coding** – a sophisticated framework for AI-driven software development. It deeply integrates a **Software Architecture Ontology** conceptual model with the power of Perplexity's AI research capabilities, all orchestrated within the **SPARC-Omega methodology** running on the Roo Code multi-agent platform.

**Inspired by and extending the original SPARC methodology and 'Boomerang Tasks' concept developed by Reuven Cohen for Roo Code**, SPARC-Omega uses structured, Ontology-aware prompts to guide the AI's vast internal knowledge and leverage Perplexity for targeted research. This allows for **proactive problem prediction, adherence to best practices, and creation of robust, maintainable systems.**

Here's the flow: You have an objective. The SPARC-Omega Orchestrator analyzes it, considering relevant **Ontology concepts** (like `:Problem` types, `:ArchitecturalPattern` choices, `:TechnologyVersion` specifics, `:Context` factors). It then delegates tasks to a specialized crew of AI agents, each guided by Ontology terms and empowered by Perplexity tools:

-   🌟 **SPARC Orchestrator (⚡️ SPARC)**: The maestro, breaking down goals using SPARC phases, assigning Ontology-aware tasks, and coordinating Perplexity research.
-   📋 **Specification Writer (spec-pseudocode)**: Captures requirements, defines `:Context`, and drafts modular pseudocode anticipating potential `:Problem` areas. Uses Perplexity (`search`, `get_documentation`) for clarification.
-   🏗️ **Architect (architect)**: Designs scalable architectures using `:ArchitecturalPattern` knowledge, defining `:ComponentRole`s, avoiding `:ArchitecturalAntiPattern`s. Leverages Perplexity (`search`, `find_apis`, `get_documentation`) for pattern/technology research.
-   🧠 **Auto-Coder (code)**: Implements features using specified `:TechnologyVersion`s, guided by architecture, checking for `:DependencyIssue`s or potential `:SecurityVulnerability` hints. Uses Perplexity (`get_documentation`, `check_deprecated_code`, `search`) for implementation details.
-   🧪 **Tester (TDD, tdd)**: Writes tests first, targeting requirements and potential Ontology `:Problem` scenarios (edge cases, vulnerabilities). Uses Perplexity for testing framework details (`get_documentation`, `search`).
-   🛡️ **Security Reviewer (security-review)**: Audits code specifically looking for `:SecurityVulnerability` types (OWASP, env leaks), using Perplexity (`check_deprecated_code`, `search` for CVEs) to inform the review.
-   🚀 **DevOps (devops)**: Manages infrastructure, deployments, and configurations based on `:EnvironmentContext`, avoiding `:ConfigurationIssue`s. Uses Perplexity (`get_documentation`, `search`) for platform specifics.
-   ❓ **Ask (ask)**: Your interactive guide to using SPARC, Ontology terms, Perplexity tools, and effective task delegation.
-   📘 **Tutorial (tutorial)**: Onboards new users to the SPARC-Omega + Ontology + Perplexity way of working.
-   ...and others (Debugging, Docs, Integration, Optimization, Monitoring) – each thinking and operating with an Ontology-aware mindset and utilizing Perplexity for necessary external knowledge.

This isn't just code generation; it's **proactive, knowledge-guided, Ontology-structured, research-backed development** powered by specialized AI agents collaborating effectively.

## 🔄 NEW: SPARC-Omega Methodology & Ontology Integration

This framework uses a **prompt-based, knowledge-guided approach** instead of loading a formal ontology file. Ontology concepts are embedded within the custom instructions (`.roomodes`) of each agent.

### 🏛️ Ontology-Guided Reasoning via Structured Prompts

How it works:

1.  **Conceptual Labels**: Instructions use terms like `:Problem`, `:Solution`, `:ArchitecturalPattern`, `:TechnologyVersion`, `:EnvironmentContext`, `:SecurityVulnerability`, etc.
2.  **Focused LLM Knowledge**: These labels act as **structured prompts**, guiding the underlying Large Language Model (LLM) to access relevant parts of its vast internal training data regarding software design, common pitfalls, best practices, and specific technologies.
3.  **Consistent Analysis**: This ensures the agents consistently consider potential issues (e.g., predicting a `:CompatibilityIssue` between two `:TechnologyVersion`s) and apply relevant patterns (e.g., choosing an appropriate `:ArchitecturalPattern` based on `:ProjectContext`).
4.  **Targeted Research**: Prompts also guide the *strategic* use of Perplexity MCP tools (like using `check_deprecated_code` when a `:DependencyIssue` is suspected).

### ✨ SPARC-Omega Workflow (Ontology-Infused)

The SPARC phases leverage this guided approach:

1.  **Specification (⚡️ SPARC -> 📋 spec-pseudocode)**: Clarify objectives, define scope, and critically identify `:ProjectContext` and `:EnvironmentContext`. Use Ontology terms to frame requirements and potential `:Problem` areas. Leverage Perplexity (`search`, `chat_perplexity`) for high-level understanding. Never hard-code environment variables.
2.  **Pseudocode (📋 spec-pseudocode)**: Define high-level logic with TDD anchors. Frame modules considering potential `:Problem` types (e.g., error handling, edge cases related to `:Context`). Use Perplexity (`get_documentation`, `search`) for API clarifications.
3.  **Architecture (⚡️ SPARC -> 🏗️ architect)**: Design extensible system diagrams and service boundaries. Explicitly select `:ArchitecturalPattern`s (e.g., `:Microservices`, `:APIGatewayRole`) and choose appropriate `:Technology` stacks, justifying choices based on `:ProjectContext` and proactively avoiding known `:ArchitecturalAntiPattern`s (e.g., `:GodObject`). Use Perplexity (`find_apis`, `get_documentation`, `search`) to evaluate patterns and technologies.
4.  **Refinement (⚡️ SPARC -> 🧠 code, 🧪 tdd, 🪲 debug, 🛡️ security-review, 🧹 refinement-optimization-mode)**: Implement using TDD, addressing potential Ontology `:Problem`s (e.g., testing for `:SecurityVulnerability` inputs, specific `:CompatibilityIssue` scenarios). Debug failures, identifying the root `:Problem` type. Conduct security audits focusing on Ontology-defined `:SecurityVulnerability` types. Optimize based on performance data (`:PerformanceIssue`) or refactor `:ArchitecturalAntiPattern`s. Use Perplexity tools extensively (`check_deprecated_code`, `get_documentation`, `search`).
5.  **Completion (⚡️ SPARC -> 🔗 integration, 📚 docs-writer, 🚀 devops, 📈 post-deployment-monitoring-mode)**: Integrate components, verifying compatibility (`:CompatibilityIssue`). Document the system, referencing implemented `:ArchitectureConcept`s and required `:Context`. Deploy using DevOps practices, managing `:EnvironmentContext`. Monitor for runtime `:Problem`s like `:PerformanceIssue`s.

This **Ontology-guided** approach significantly improves the quality, resilience, and maintainability of the software by embedding structured architectural thinking and proactive risk assessment directly into the AI's workflow.

## ✨ Why It's a Game Changer (Ontology + Perplexity Edition)

Traditional AI coding assistants often lack deep architectural awareness. SPARC-Omega changes the game:

-   🧠 **Structured Thinking**: The Ontology concepts provide a shared vocabulary and mental model, guiding the AI towards architecturally sound solutions.
-   🎯 **Proactive Risk Management**: Leverages the LLM's internal knowledge, *focused by Ontology prompts*, to anticipate common `:Problem` types (security, compatibility, performance) *before* they get coded.
-   💡 **Deep Research Power**: Perplexity MCP tools (`search`, `get_documentation`, `find_apis`, `check_deprecated_code`) provide targeted, real-time information directly relevant to the task and Ontology context.
-   ✅ **Higher Quality Outputs**: Code is more modular, testable, secure, and aligned with architectural goals due to the integrated Ontology guidance.
-   🔄 **Full Lifecycle Awareness**: Covers the entire development process from conception to deployment and monitoring, all viewed through the lens of the Ontology.
-   🤝 **Improved Collaboration**: The shared Ontology vocabulary enhances communication between human users and the AI agent team.
-   🎓 **Built-in Mentoring**: The `ask` and `tutorial` modes help users learn and apply the SPARC-Omega + Ontology methodology effectively.

## 🛠️ The Core Components

This framework integrates:

### 1. The SPARC-Omega Multi-Agent Army (.roomodes) 🤖

Your specialized AI team defined in the `.roomodes` file (provided), each mode equipped with specific Ontology-aware instructions and Perplexity MCP tools:

-   `sparc`: The Ontology-aware orchestrator.
-   `spec-pseudocode`: Context & Problem-focused planning.
-   `architect`: Pattern & Anti-pattern driven design.
-   `code`: TechnologyVersion & Pattern implementation.
-   `tdd`: Problem & Requirement-focused testing.
-   `debug`: Root Problem identification.
-   `security-review`: SecurityVulnerability focused audits.
-   `docs-writer`: Ontology Concept documentation.
-   `integration`: CompatibilityIssue resolution.
-   `post-deployment-monitoring-mode`: Runtime Problem detection.
-   `refinement-optimization-mode`: Problem & Anti-pattern remediation.
-   `devops`: EnvironmentContext & ConfigurationIssue management.
-   `ask`: Your guide to SPARC + Ontology + Perplexity.
-   `tutorial`: Onboarding to the SPARC-Omega system.

(Review the included `.roomodes` JSON for the full custom instructions and capabilities!)

### 2. Ontology-Guided Knowledge Integration 🏛️

As described above, this uses **structured prompts** with Ontology terms embedded within agent instructions to guide the LLM's internal knowledge and structure its reasoning—**no external ontology file is loaded or queried**.

### 3. Perplexity Research Power 💡

Integrated via MCP for real-time, context-aware knowledge retrieval:

-   `search`: General web search for concepts, errors, examples.
-   `get_documentation`: Fetch specific documentation for APIs, libraries, frameworks.
-   `find_apis`: Discover potential APIs for integration.
-   `check_deprecated_code`: Identify outdated functions or known vulnerabilities in dependencies based on `:TechnologyVersion`.
-   `chat_perplexity`: Engage in conversational Q&A for broader understanding.

## 🎬 See It In Action (Ontology-Guided Examples)

### Example 1: Designing an API with Ontology Awareness

**User**: "Design a REST API for a user profile service using Node.js and PostgreSQL. Needs basic CRUD."

**⚡️ SPARC**: "Okay, kicking off the SPARC flow! 🚀 Assigning to `architect`. Task: Design API structure for user profile service. Technology stack: `:NodeJS` (specify version?), `:PostgreSQL`. Focus on REST principles (`:ArchitecturalPattern`). Define `:ComponentRole`s (e.g., controller, service, repository). Consider potential `:Scalability` issues and `:SecurityVulnerability` points (e.g., input validation). Avoid `:AntiPattern` like direct DB access in controllers. Use Perplexity `search` for REST best practices for NodeJS and `get_documentation` for the chosen Node ORM. Output: Mermaid diagram, data flow description, endpoint definitions. `attempt_completion`."

**(Later) 🏗️ Architect**: "Designed API following REST principles. Chosen `:ArchitecturalPattern` includes layered architecture (Controller, Service, Repository). Defined `:ComponentRole`s. Identified need for strong input validation to mitigate common `:SecurityVulnerability`. Using `:PostgreSQL` via TypeORM (`:Technology`). Research via Perplexity confirmed patterns. Mermaid diagram attached. Endpoints defined. `attempt_completion`"

### Example 2: Coding & Security Review with Ontology Focus

**User**: "Implement the `POST /users` endpoint based on the architecture spec."

**⚡️ SPARC**: "Got it. Assigning to `code`. Task: Implement `POST /users` endpoint for user creation. Follow architecture spec. `:Technology`: NodeJS v18, TypeORM vX. Pay attention to data validation logic to prevent `:SecurityVulnerability` like injection. Use environment variables for DB config (avoid `:ConfigurationIssue`). Ensure code modularity (< 500 lines per file). Use Perplexity `get_documentation` for TypeORM usage examples. `attempt_completion`. Then, assign `security-review`."

**(Later) 🧠 Code**: "Implemented `POST /users` using specified `:TechnologyVersion`s. Added validation layer addressing potential injection `:SecurityVulnerability`. Config loaded via `process.env`. Code is modular. TypeORM docs checked via `get_documentation`. `attempt_completion`"

**⚡️ SPARC**: "Code complete. Assigning to `security-review`. Task: Review the new user creation code. Focus on input validation, potential data leakage, dependency vulnerabilities (use `check_deprecated_code` on used libraries), and adherence to secure coding practices regarding the identified `:SecurityVulnerability` points. `attempt_completion`."

**(Later) 🛡️ Security Reviewer**: "Reviewed code. Input validation looks robust for common injection `:SecurityVulnerability`. Ran `check_deprecated_code` - no known vulnerable dependencies found for specified versions. Confirmed no hardcoded secrets (`:ConfigurationIssue`). Recommend adding rate limiting as a defense-in-depth measure (`:Solution`). `attempt_completion`"

## 🔧 Get Started (Join the Vibe!)

Ready to code with Ontology-guided AI and deep research power?

### Prerequisites
-   VS Code with the Roo Code extension installed.
-   A Perplexity API key.

### Easiest MCP Setup: Use cline!
1.  Install [cline](https://cline.tools).
2.  In cline, search for and install the MCP provider: "**Perplexity AI**".
3.  Follow cline's prompts (it uses AI to set up the Perplexity MCP server, likely asking for your API key).
4.  Copy the MCP settings (URL, headers/token) cline provides.

### Configure Roo Code
1.  Open Roo Code settings in VS Code (Ctrl+Shift+P -> "Roo Code: Open Settings").
2.  Paste the Perplexity MCP details copied from cline into the "Model Context Protocol (MCP) Settings" section for Perplexity.

### Install the SPARC-Omega RooModes
1.  Copy the `.roomodes` JSON content provided earlier into a file named `.roomodes` in the root directory of your project (or a parent directory Roo Code can access). You can also create/paste these modes using the Roo Code UI's "Modes" section.
2.  Roo Code should automatically detect and load the modes upon restarting VS Code or refreshing Roo Code.
    *   *Note*: The core Ontology-guided logic, SPARC flow adherence, and Perplexity usage instructions are all embedded within the `customInstructions` of each mode definition in this `.roomodes` file.

### Start Vibing!
1.  Open a Roo Code chat in VS Code (usually accessible via the Roo icon in the activity bar).
2.  Select a SPARC-Omega mode (e.g., start with `⚡️ SPARC Orchestrator` or `❓Ask`) from the mode selector dropdown at the top of the chat window.
3.  Give it a high-level objective, referencing Ontology concepts where helpful (e.g., "Design a system considering `:Scalability` for a chat app"). Watch the knowledge-guided, research-enabled AI agents collaborate!

## 🙏 Acknowledgements

The SPARC-Omega Vibe framework is deeply inspired by the foundational work of Reuven Cohen, particularly his development of the SPARC methodology (Specification, Pseudocode, Architecture, Refinement, Completion) and the 'Boomerang Tasks' concept within the Roo Code ecosystem. His insights into structuring AI-driven development workflows were instrumental in shaping this project.

For more background on the original concepts, please see his article:
- [🪃 Boomerang Tasks: Automating Code Development with Roo Code and SPARC Orchestration by Reuven Cohen](https://www.linkedin.com/pulse/boomerang-tasks-automating-code-development-roo-sparc-reuven-cohen-nr3zc/)

## 📜 License
Licensed under the MIT License—see the `LICENSE` file for details.

## 🔗 Related Resources
-   [Roo Code Docs](https://roo.ai/docs)
-   [Perplexity API Docs](https://docs.perplexity.ai/)
-   [MCP Standard](https://mcp.ai) (Underlying protocol)
-   [cline Setup](https://cline.tools) (Easiest MCP Server Setup for Perplexity)

---

Built with ❤️ by SPARC-Omega vibe coders. Let's automate the future, guided by knowledge and Ontology!
