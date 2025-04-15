# 🚀 SPARC-SAPPO Agentic Development Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Roo Code Compatible](https://img.shields.io/badge/Roo%20Code-Compatible-brightgreen)](https://roo.ai)
[![Perplexity API](https://img.shields.io/badge/Perplexity-API-blue)](https://perplexity.ai)
[![Gemini 2.5 Pro](https://img.shields.io/badge/Uses-Gemini%202.5%20Pro-blueviolet)](https://deepmind.google/technologies/gemini/)
[![GPT-4.1](https://img.shields.io/badge/Uses-GPT--4.1-lightgreen)](https://openai.com/index/hello-gpt-4.1/)
[![Ontology-Guided (SAPPO)](https://img.shields.io/badge/Ontology-Guided%20(SAPPO)-purple)](.)
[![SPARC Methodology](https://img.shields.io/badge/Methodology-SPARC-orange)](.)
[![cline MCP Installer](https://img.shields.io/badge/cline-MCP%20Installer-orange)](https://cline.tools)

## 🌌 What is This? (The SPARC-SAPPO Framework Explained)

Welcome to the SPARC-SAPPO Agentic Development Framework, a highly structured system for AI-assisted software engineering built on Roo Code. This framework combines several key principles for robust, efficient, and high-quality code generation:

1.  **SPARC Agentic Development Syntax:** A concise symbolic language (see top of `README.md` source or [SPARC Syntax Details](#-sparc-syntax-overview) below) defining core principles like clarity, extensibility, testing, and collaboration. These principles are embedded within the agent instructions.
2.  **SAPPO (Software Architecture Problem Prediction Ontology):** A custom ontology used explicitly by AI agents to frame tasks, identify potential problems (`:Problem`), apply solutions (`:Solution`), understand context (`:Context`), and leverage architectural knowledge (`:ArchitecturalPattern`, `:TechnologyVersion`).
3.  **Micro-Task Orchestration:** A central `🧠 SAPPO Orchestrator` agent breaks down user-defined plans into hyper-specific, single micro-tasks, minimizing context window usage and enabling fast feedback loops.
4.  **Mandatory RDD (Research-Driven Development) via Perplexity:** All specialized agents **MUST** use Perplexity MCP tools (`search`, `get_documentation`, etc.) to resolve ambiguities, verify best practices, or look up API details *before* acting.
5.  **Dual-Model LLM Strategy:** Utilizes distinct LLMs and temperature settings for different cognitive tasks:
    *   **🧠 Thinking Mode (Gemini 2.5 Pro @ Temp 0.7):** For planning, design, specification, architectural reasoning, and documentation.
    *   **🛠️ Instruct Mode (GPT-4.1 @ Temp 0.25):** For precise code implementation, testing, debugging, and operations following strict instructions.
6.  **Integrative & Cumulative TDD:** A dedicated `🧪 Tester (Integrative & Cumulative TDD)` agent writes tests for each new unit *and* re-runs all relevant prior tests to ensure no regressions are introduced.
7.  **Roo Code Multi-Agent System:** Hosted within VS Code's Roo Code extension, enabling seamless collaboration between the specialized AI agents defined in the `.roomodes` file.

**The Core Idea:** You provide a **detailed, multi-phase plan**. The `Orchestrator` (using Gemini 2.5 Pro) interprets this plan, anticipates SAPPO `:Problem`s, and delegates **one micro-task at a time** using precise SAPPO terminology to a specialist agent. Specialists (like the `Coder` using GPT-4.1) execute their single task, leveraging Perplexity for RDD, and report back with `attempt_completion`, including SAPPO/MCP summaries. The `Tester` ensures continuous integration validity. This cycle repeats until your plan is complete, emphasizing **good practices and structured planning** over raw model size.

## 📺 Quick Start & Methodology Video Guide:

[![Watch the Setup & Best Practices Guide](https://img.youtube.com/vi/EEXAcMqRv3E/maxresdefault.jpg)](https://youtu.be/mmRU-24RNhU)

👆 **Click the image above for a complete walkthrough!** This video covers:
*   Setting up Roo Code with the SPARC-SAPPO modes.
*   Configuring the Dual-Model LLM profiles (Gemini 2.5 Pro & GPT-4.1).
*   Best practices for **structuring your plans** effectively.
*   Understanding the **micro-tasking workflow** and **TDD strategy**.
*   The importance of **context window management** (<~200k goal for instruct tasks).

## 🧠🛠️ NEW: Dual-Model LLM Strategy (Gemini 2.5 Pro + GPT-4.1)

This framework leverages the strengths of different cutting-edge LLMs by assigning them roles based on the cognitive demands of the task:

1.  **🧠 Thinking Mode (Temperature: 0.7)**
    *   **Model:** **Google Gemini 2.5 Pro**
    *   **Purpose:** High-level planning, creative problem-solving, architectural design, writing detailed specifications, documentation, complex reasoning, and understanding user intent. Higher temperature encourages broader exploration.
    *   **Used By:**
        *   `🧠 SAPPO Orchestrator (orchestrator)`
        *   `📝 Spec Writer (spec-writer)`
        *   `🏗️ Architect (architect)`
        *   `📚 Docs Writer (docs-writer)`
        *   `❓ Ask Guide (ask)`
        *   `📘 Tutorial (tutorial)`

2.  **🛠️ Instruct Mode (Temperature: 0.25)**
    *   **Model:** **OpenAI GPT-4.1**
    *   **Purpose:** Precise code generation following specs, implementing specific algorithms, writing unit and integration tests, debugging specific errors, performing security audits, executing DevOps commands, and integrating components accurately. Lower temperature ensures focus and fidelity to instructions.
    *   **Used By:**
        *   `🧠 Coder (code)`
        *   `🧪 Tester (tester-tdd)`
        *   `🪲 Debugger (debug)`
        *   `🛡️ Security Reviewer (security-reviewer)`
        *   `🔗 Integrator (integrator)`
        *   `📈 Monitor (monitor)`
        *   `🧹 Optimizer (optimizer)`
        *   `🚀 DevOps (devops)`

**Why this split?** It optimizes performance and cost. Gemini 2.5 Pro excels at reasoning and planning, while GPT-4.1 is highly capable at precise instruction following and code generation. By assigning tasks appropriately and keeping instruct tasks focused (aiming for completion within ~100-200k context tokens to manage costs and maintain focus, even with larger available windows), the system balances capability with efficiency. **Your detailed plan is the key driver enabling this efficiency.**

## ✨ Key Features & Methodology

This framework enforces a robust development process:

### 🏛️ SAPPO-Guided Micro-Tasking
-   **Ontology Integration:** SAPPO terms (`:Problem`, `:Solution`, `:TechnologyVersion`, `:ArchitecturalPattern`, `:Context`, etc.) are *mandated* in task framing by the Orchestrator and referenced in completions by Specialists.
-   **Hyper-Granularity:** The `Orchestrator` decomposes your plan into the smallest logical units of work, enabling rapid iterations and precise context management.
-   **Role Specialization:** Each agent (Coder, Tester, Architect...) has a sharply defined role and collaborates through the Orchestrator.

### 🔍 Mandatory Research-Driven Development (RDD)
-   **Perplexity MCP Integration:** Every specialist agent is instructed to **proactively use** `search`, `get_documentation`, `check_deprecated_code`, etc., via Perplexity MCP for *any* ambiguity, best practice check, or API lookup. No guessing allowed.

### ✅ Integrative & Cumulative TDD
-   **Phase-Based Testing:** The `Tester` agent validates each micro-task's output upon completion.
-   **Regression Prevention:** Critically, the `Tester` **re-runs all relevant previous tests** cumulatively to ensure the new code integrates correctly without breaking existing functionality. **Your plan should include clear testing phases/requirements.**

### 📄 Detailed Planning is Crucial
-   **User Responsibility:** The success of this framework hinges on **you providing a well-structured, detailed, multi-phase plan.** The AI executes *your* plan.
-   **Good Practices > Model Power:** As highlighted in the video, even the most advanced LLMs cannot compensate for poor planning or methodology. Focusing on clear phases, testable units, and modular design is paramount.

### 🔄 The Workflow Loop
1.  **You:** Provide a detailed plan to the `Orchestrator`.
2.  **Orchestrator (Gemini 2.5 Pro):** Identifies the *next single micro-task*, frames it using SAPPO terms (`new_task @specialist...`).
3.  **Specialist (e.g., Coder - GPT-4.1):** Receives task, performs **mandatory RDD via MCP**, executes the single task (e.g., writes one function).
4.  **Specialist:** Returns control with `attempt_completion`, providing a summary including work done, SAPPO concepts addressed, and MCP tools used.
5.  **(If applicable) Tester (GPT-4.1):** Tests the completed unit AND re-runs cumulative tests. Reports pass/fail with SAPPO/MCP details via `attempt_completion`.
6.  **Orchestrator:** Analyzes completion/test results, identifies the *next* micro-task from your plan, loops back to step 2.

## ✨ Why It's a Game Changer

-   🏛️ **Structured & Predictable:** SAPPO and micro-tasking create a disciplined workflow.
-   💡 **Accurate & Current:** Mandatory RDD via Perplexity ensures reliance on up-to-date information and best practices.
-   ✅ **Robust & Reliable:** Cumulative TDD drastically reduces regressions.
-   🧠 **Optimized AI Usage:** Dual-model strategy leverages the best of Gemini 2.5 Pro and GPT-4.1 for their respective tasks.
-   💰 **Cost-Aware:** Hyper-granularity aims to keep instruct task context windows small (~100-200k goal), managing LLM costs effectively.
-   📈 **Higher Quality:** Leads to more modular, testable, secure, and well-documented code aligned with architectural principles.
-   🤝 **Clear Collaboration:** Shared SAPPO vocabulary and explicit task handoffs improve traceability.

## 🛠️ The Core Components

1.  **SPARC-SAPPO Agent Army (.roomodes):** The JSON definitions of all specialized agents (Orchestrator, Coder, Tester, etc.) with their SAPPO-aware instructions, assigned LLM types (Thinking/Instruct), and mandatory MCP usage rules. Found at the top of this document source.
2.  **SPARC Syntax:** The underlying symbolic principles guiding agent behavior. [See Overview](#-sparc-syntax-overview).
3.  **SAPPO (Software Architecture Problem Prediction Ontology):** The conceptual framework used for task definition and architectural reasoning.
4.  **Perplexity Research Tools (MCP):** Integrated via `search`, `get_documentation`, etc.
5.  **Dual-Model LLM Engine:** Requires access to **Google Gemini 2.5 Pro** and **OpenAI GPT-4.1** configured with appropriate temperatures.

## 🎬 See It In Action (Micro-Task Example)

**User Plan Snippet:** "Phase 2: Implement user login. Step 2.1: Create DB migration for 'users' table password hash column. Step 2.2: Implement backend login handler function. Step 2.3: Write tests for login handler."

**▶️ Orchestrator (Gemini 2.5 Pro @ 0.7):** "Received plan. Next micro-task: DB Migration. `new_task @architect Design the :AlterTable :Solution for adding a 'password_hash' :DataSchemaField to the 'users' table. Specify :SQL datatype. Consider existing :ProjectContext. Use MCP search for secure hashing column type best practices.`"

**(Later) 🏗️ Architect (Gemini 2.5 Pro @ 0.7):** "`attempt_completion` Designed `ALTER TABLE users ADD COLUMN password_hash VARCHAR(255);` SQL snippet. SAPPO :Solution = :AlterTable. MCP `search` confirmed VARCHAR(255) suitable for common hash outputs. Returning control."

**▶️ Orchestrator:** "Migration designed. Next: Implement login handler. `new_task @coder Implement the 'handleLogin' function for :UserAuth :ComponentRole using :NodeJS v20. Follow :JWT :ArchitecturalPattern provided in specs. Fetch user by email, verify hash using bcrypt library, issue JWT. Mandatory RDD: Use MCP get_documentation for precise bcrypt API usage. Watch for :TimingAttack :SecurityVulnerability. Handle :UserNotFound :Problem.`"

**(Later) 🧠 Coder (GPT-4.1 @ 0.25):** "`attempt_completion` Implemented `handleLogin` function in `authController.js` using NodeJS v20 and JWT pattern. Used MCP `get_documentation` for `bcrypt.compare` async signature. Included checks for user existence (:UserNotFound :Problem) and basic input presence. Used placeholder secret handling as per spec. Returning control."

**▶️ Orchestrator:** "Code complete. Next: Test login handler. `new_task @tester-tdd Write integrative tests for the 'handleLogin' function. Cover success case (valid credentials), failure (:UserNotFound, wrong password). Explicitly test against :TimingAttack :SecurityVulnerability if possible via mock timing (research via MCP search 'testing timing attacks nodejs'). Run these tests AND cumulative tests for User Profile module. All must pass.`"

**(Later) 🧪 Tester (GPT-4.1 @ 0.25):** "`attempt_completion` Wrote 3 tests for `handleLogin` (success, invalid email, invalid pass) using Jest and supertest. Targeted SAPPO :UserNotFound, :LogicError. MCP `search` indicated direct timing attack tests complex; ensured constant-time compare function (`bcrypt.compare`) used based on Coder's MCP confirmation. Ran new tests + 5 prior User Profile tests. ALL PASSED. Returning control."

**▶️ Orchestrator:** "Login handler implemented and tested. Proceeding to next step in user plan..."

## 🔧 Get Started (Join the Vibe!)

Ready for SAPPO-driven, dual-model AI development?

### Prerequisites
1.  **VS Code** with the **Roo Code extension** installed.
2.  **Google AI API Key** with access to **Gemini 2.5 Pro**.
3.  **OpenAI API Key** with access to **GPT-4.1**.
4.  **Perplexity API Key**.

### Configuration: Setting Up Dual Models & MCP

1.  **Perplexity MCP Setup:**
    *   Use **[cline](https://cline.tools)** (recommended): Search for and install the "Perplexity AI" provider, enter your key, and copy the MCP URL/Header.
    *   Manual Setup: Follow MCP standard guidelines if preferred.
    *   Paste the MCP URL and Header details into Roo Code's Perplexity MCP settings.

2.  **Dual LLM Configuration (IMPORTANT!):**
    *   You need *two separate* model profiles configured in Roo Code:
        *   **Profile 1 (Thinking):** Pointing to **Gemini 2.5 Pro**. Set the default **Temperature to 0.7**. Give it a clear name (e.g., `gemini-2.5-pro-thinking`).
        *   **Profile 2 (Instruct):** Pointing to **GPT-4.1**. Set the default **Temperature to 0.25**. Give it a clear name (e.g., `gpt-4.1-instruct`).
    *   Consult Roo Code documentation for creating multiple profiles for different models/providers.
    *   **The `.roomodes` JSON provided *does not* explicitly assign models.** Roo Code currently selects the *globally active* model. **You MUST manually select the correct profile (Thinking/Instruct) in the Roo Code UI *before* invoking a task** intended for that type of agent (e.g., select `gemini-2.5-pro-thinking` before talking to the `Orchestrator`, then switch to `gpt-4.1-instruct` before the Orchestrator delegates to the `Coder`). *This requires user diligence during the workflow.* (Future Roo Code versions might allow mode-specific model assignments).

3.  **Install the SPARC-SAPPO RooModes:**
    *   Copy the entire JSON object provided at the very top of this document source (`{ "customModes": [...] }`).
    *   Go to Roo Code settings in VS Code (often via the Roo icon in the sidebar).
    *   Find the "Edit Global Modes" or similar option.
    *   Paste the copied JSON into the editor, replacing any existing content. Save the changes.
    *   Alternatively, manually create each mode via the Roo Code UI, carefully copying `slug`, `name`, `roleDefinition`, and `customInstructions` for every mode in the JSON.
    *   Restart VS Code or use the Roo Code command palette (`Roo Code: Reload Custom Modes`) to ensure they are loaded.

### Start Developing!
1.  Open a Roo Code chat in VS Code.
2.  **Manually select the `gemini-2.5-pro-thinking` profile.**
3.  Select the `🧠 SAPPO Orchestrator` mode.
4.  Provide your detailed, phased development plan.
5.  Observe the micro-tasking workflow. **Remember to manually switch to the `gpt-4.1-instruct` profile in Roo Code when the Orchestrator indicates it's about to delegate an Instruct task (to Coder, Tester, etc.)**, and switch back to the thinking profile when control returns to the Orchestrator or another thinking agent.
6.  Use the `❓ Ask Guide` mode if you need help structuring plans or understanding SAPPO/RDD concepts.

## <a name="sparc-syntax-overview"></a>🌌 SPARC Syntax Overview

The symbolic syntax at the top of this document source (`Φ•Ω`, `Γ•Μ•Υ`, etc.) represents core guiding principles encoded within the agent instructions. Here's a brief interpretation of key concepts:

*   **Φ•Ω [Core•Flow]:** Focuses on overall workflow. Maintain clarity (`§͟min ⟨clarity⟩`), avoid complexity (`¬⟨complex⟩`), extend functionality systematically (`⊙{task}⊡ ⊥extend`), ensure clean/tested/documented/secure code (`§͟qual ⊤{...}`), and handle ambiguity via confirmation (`⋈team...→ ⊦confirm`).
*   **Γ•Μ•Υ [Context]:** Emphasizes context understanding. Action driven by docs/context (`⊦⟨doc⟩ ⟨ctx⟩ → ⟨action⟩`), respecting architecture boundaries (`⊤⟨arch⟩{boundSpec}`), managing tech versions/patterns (`⊢{...} ⊥newΔ`), and recording decisions (`≡{Μbanк}⇒⟨decisions⟩`).
*   **Τ•Ρ [Tasks]:** Defines task handling. Micro-tasks include specs/pseudo/arch (`⊦⟨micro⟩ = {...}`), mandatory research for uncertainty (`‼️Ρ{pMCP}→{search|...}✓findings`), conditional task execution (`Σ⊗ [if→task]`), and self-verification (`⊗self{...}→⊦complete`).
*   **Κ•Σ [Code]:** Governs code quality. Adhere to best practices (`⊢{bestPractice}⟨lang⟩`), conventions (`≡⟨conventions⟩`), modularity/scalability/clarity (`⊤⟨module⟩+...`), reasonable file size (`⟨file⟩≤350Λ`), DRY/abstraction (`¬⟨duplication⟩+⟨abstract⟩`), linting/formatting (`⊤{lint|format}config`).
*   **Χ [Refactor]:** Addresses code improvement based on readability, redundancy, performance, or architecture (`⋉{...}`), ensuring functionality remains intact via testing (`⊨{⋈intact}⇒{⊦tester-tdd}`).
*   **Δ [Testing]:** Focuses on robust testing. Code driven by tests (`⊢⟨test→code⟩`), aiming for high coverage (`⊤∀⟨coverage⟩`), with task completion gated by passing tests (`‼️✓⟨tests⟩→⊦complete`).
*   **Β [Debug]:** Guides debugging. Root cause analysis using SAPPO (`⊙{⟨root⟩:SAPPO}`), with sparse but precise logging (`⊢⟨log⟩→{sparse|precise}`).
*   **Ξ [Security]:** Enforces security practices. Server-side logic preferred (`⊤{server-logic}`), mandatory validation/sanitization (`‼️⊤⟨validate⟩+⟨sanitize⟩`), no hardcoded secrets (`¬⟨hardcode⟩→⊢⟨env⟩`).
*   **Ψ•Ε [VCS•Env]:** Covers version control and environment management. Proper Git usage (`⊤⟨git⟩{...}`), environment-agnostic code via config (`⟨code⟩→⟨agnostic⟩⇒⟨config⟩`).
*   **Λ [Docs]:** Mandates accurate documentation (`⊤⟨mirror-reality⟩+⟨structure⟩`).
*   **Θ [Limits]:** Sets constraints like file size (`⟨file⟩≤350Λ`) and abstracting credentials (`¬⟨credentials⟩→⟨abstract⟩`).

These symbols provide a dense representation of the methodology baked into the custom mode instructions.

## 🙏 Acknowledgements

This framework heavily builds upon the pioneering work of **Reuven Cohen**, particularly his SPARC methodology and the 'Boomerang Tasks' concept, which are fundamental to structured AI agent workflows within Roo Code.

-   Reference: [🪃 Boomerang Tasks: Automating Code Development with Roo Code and SPARC Orchestration by Reuven Cohen](https://www.linkedin.com/pulse/boomerang-tasks-automating-code-development-roo-sparc-reuven-cohen-nr3zc/)
-   The Software Architecture Problem Prediction Ontology (SAPPO) is a custom ontology developed for this project.

## 📜 License
Licensed under the MIT License—see the `LICENSE` file for details.

## 🙏 Support Development

<div align="center">
  <p>If you find this framework valuable, please consider supporting its continued development and maintenance.</p>

  <a href="https://paypal.me/ChrisRoyseAI" target="_blank">
    <img src="https://img.shields.io/badge/Support_via_PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white" alt="Support via PayPal" width="250"/>
  </a>

  <p style="margin-top: 10px;">Developing and experimenting with advanced AI tools incurs API costs. Your contributions help offset these expenses, allowing for further refinement, feature additions, and the creation of helpful resources for the community.</p>
  <p>Thank you for your support!</p>
</div>

## 🔗 Related Resources
-   [Roo Code Docs](https://roo.ai/docs)
-   [Perplexity API Docs](https://docs.perplexity.ai/)
-   [Google AI Gemini API Docs](https://ai.google.dev/docs)
-   [OpenAI API Docs](https://platform.openai.com/docs/api-reference)
-   [SAPPO Ontology (Placeholder - Add Link if Public)](.) - *Consider linking if you host the ontology schema publicly.*
-   [Requestly](https://requestly.io/) (Might be useful for advanced API call interception/modification if needed)
-   [MCP Standard](https://mcp.ai)
-   [cline Setup](https://cline.tools)

---
## 👤 Connect
- [🔗 LinkedIn - Christopher Royse](https://www.linkedin.com/in/christopher-royse-b624b596/)

---

Embrace structured, ontology-driven, AI-accelerated development. Plan diligently, execute precisely!
