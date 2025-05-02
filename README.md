# 🚀 SPARC Agentic Development Framework (v3 - Framework-First, Test-Plan-Driven w/ Tiered RDD)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Roo Code Compatible](https://img.shields.io/badge/Roo%20Code-Compatible-brightgreen)](https://roo.ai)
[![Perplexity API (Tiered)](https://img.shields.io/badge/Perplexity-API%20(Tiered)-blue)](https://perplexity.ai)
[![Uses AI Model (e.g., Claude 3.7 Sonnet)](https://img.shields.io/badge/Uses-AI%20Model-orange)](https://www.anthropic.com/news/claude-3-5-sonnet)
[![SPARC Methodology](https://img.shields.io/badge/Methodology-SPARC-orange)](.)
[![cline MCP Installer](https://img.shields.io/badge/cline-MCP%20Installer-orange)](https://cline.tools)

## 🌌 What is This? (The SPARC Framework: Framework-First, Test-Plan-Driven)

Welcome to the SPARC Agentic Development Framework, a structured system for AI-assisted software engineering using Roo Code. This framework emphasizes **building a solid foundation first, meticulously planning testing upfront, and then executing feature development rigorously against that plan**, all while leveraging **strategic Research-Driven Development (RDD)** via Perplexity AI.

**Key Pillars:**

1.  **SPARC Principles:** Core symbolic guidelines (Specification, Pseudocode, Architecture, Refinement, Completion) embedded within agent instructions ensure clarity, extensibility, testability, and maintainability.
2.  **Framework-First Workflow:** Development follows distinct phases: Specification/Architecture -> **Framework Implementation** -> **Comprehensive Test Plan Generation** -> Phased Feature Implementation & Testing -> Integration & Final Validation -> Refinement/Deployment.
3.  **Test-Plan-Driven Development:** A central `TEST_PLAN.md` document, created *after* the framework exists using its context, serves as the **single source of truth for quality**. It defines testing phases, tasks, required test types (unit, integration, cumulative, recursive), and success criteria.
4.  **Tiered Research-Driven Development (RDD):** Specialist agents strategically use Perplexity MCP tools (`search`, `get_documentation`, etc.) based on defined tiers (**MUST/SHOULD/MAY/DO NOT USE**), optimizing API usage and ensuring research is applied cost-effectively only when needed.
5.  **Deep Research Capability:** A dedicated `@deep-research` mode handles extensive, foundational research tasks separately, keeping specialist agents focused.
6.  **Rigorous Planned Testing:** `@tdd` agent executes tests *strictly according to the `TEST_PLAN.md`* for each feature. The `@integration` agent runs the *entire* test suite defined in the plan as final validation. Includes explicit support for **cumulative** (regression) and **recursive** testing when defined in the plan.

**The Core Idea:** Start with clear specs and architecture. Build the application's structural framework. **Then, create a detailed, comprehensive `TEST_PLAN.md` that considers the framework and overall goals.** Implement features one by one, testing each **rigorously against the predefined plan**. Finally, integrate everything and run the **full test plan** to ensure system integrity. This structured approach emphasizes predictability, maintainability, and quality through upfront planning and methodical execution, supported by strategic AI research.

## 📺 Quick Start & Methodology Video Guide:

[![Watch the Setup & Best Practices Guide](https://img.youtube.com/vi/X0qIr-dEViU/maxresdefault.jpg)](https://youtu.be/X0qIr-dEViU)

👆 **Click the image above for a walkthrough!** (Note: The video may demonstrate earlier concepts like the Boomerang Task or Dual Testing. This README reflects the **current Framework-First, Test-Plan-Driven** workflow. Setup and core agent interactions remain similar, but the overall development *strategy* is different.)

## ✨ Key Features & Methodology

### 🏛️ Framework-First Approach
-   **Foundation Building:** Prioritizes implementing the core application structure, configuration, and interfaces *before* full feature development.
-   **Context for Planning:** Ensures the subsequent Test Plan is created with a solid understanding of the system's architecture.

### 📝 Test-Plan-Driven Development
-   **Central `TEST_PLAN.md`:** `@docs-writer` creates this critical artifact using framework context. Defines phases, tasks, test types, cumulative/recursive requirements, and success criteria.
-   **Execution Blueprint:** `@tdd` executes tests precisely as specified in the plan for each feature.
-   **Final Validation:** `@integration` validates the entire system against the *full* `TEST_PLAN.md`.

### 🔄 Cumulative & Recursive Testing
-   **Planned Regression:** The `TEST_PLAN.md` explicitly defines which previous tests must be re-run (cumulative) to catch regressions during development.
-   **Planned Recursive Checks:** For recursive algorithms, the plan specifies required tests (base cases, steps, edge cases).
-   **Systematic Execution:** `@tdd` performs these checks as mandated by the plan section for the current task.

### 🔍 Tiered Research-Driven Development (RDD)
-   **Strategic Perplexity Use:** Specialist agents use MCP tools based on clear tiers:
    *   **MUST USE:** For critical unknowns, complex algorithms, specific API/library details.
    *   **SHOULD USE:** For best practices, confirming implementation patterns.
    *   **MAY USE:** For examples, exploration.
    *   **DO NOT USE:** For basic knowledge, simple tasks.
-   **Optimized & Justified Research:** Focuses AI assistance where it adds most value, managing costs.
-   **Dedicated Deep Research:** `@deep-research` handles large-scale information gathering separately.

### 🔄 The Workflow Loop (Framework-First, Test-Plan-Driven)
1.  **You:** Provide overall objectives and constraints to the `⚡️ SPARC Orchestrator`.
2.  **Phase 1: Spec & Arch:** Orchestrator delegates to `@spec-pseudocode` / `@architect` for high-level design. RDD used strategically.
3.  **Phase 2: Framework Code:** Orchestrator delegates to `@code` to build the application skeleton based on architecture.
4.  **Phase 3: Test Plan Generation:** Orchestrator provides framework context -> delegates **`new_task @docs-writer Create TEST_PLAN.md based on framework context... Plan phases for Feature A, Feature B... Define cumulative tests for Phase 2... Define recursive tests for function X...`**
5.  **Phase 4: Phased Implementation & Testing (Iterative based on `TEST_PLAN.md`):**
    a.  Orchestrator assigns feature coding: `new_task @code Implement Feature A part 1 as per spec, ready for testing per TEST_PLAN.md section 3.1.`
    b.  Orchestrator assigns testing: `new_task @tdd Execute tests for Feature A part 1 per TEST_PLAN.md section 3.1. Include cumulative/recursive checks as specified. Report PASS/FAIL.`
    c.  **If FAIL:** Orchestrator assigns debugging: `new_task @debug Fix failure reported by @tdd for TEST_PLAN.md section 3.1...` -> Loop back to 5b.
    d.  **If PASS:** Orchestrator proceeds to the next task/feature in the `TEST_PLAN.md`.
6.  **Phase 5: Integration:** Once all plan phases PASS, Orchestrator delegates: `new_task @integration Merge all features and run the COMPLETE test suite from TEST_PLAN.md.`
7.  **Phase 6: Final Steps:** Security review (`@security-review`), final docs (`@docs-writer`), optimization (`@refinement-optimization-mode`), deployment (`@devops`).

## ✨ Why This Approach?

-   🏛️ **Structured & Predictable:** Framework-First builds a solid base; Test-Plan-Driven ensures quality gates are defined upfront.
-   📝 **Comprehensive Testing:** The Test Plan ensures systematic coverage, including crucial regression (cumulative) and algorithmic (recursive) checks.
-   💡 **Accurate & Efficient Research:** Tiered RDD focuses AI research; Deep Research mode handles large tasks.
-   ✅ **Robust Quality Assurance:** Testing follows a defined strategy, culminating in full validation against the plan.
-   📈 **Maintainable & Scalable:** Building the framework first promotes better long-term structure.
-   💰 **Cost-Effective RDD:** Strategic use of Perplexity API prevents unnecessary calls.

## 🛠️ The Core Components

1.  **SPARC Agent Army (.roomodes):** JSON definitions for the Framework-First, Plan-Driven workflow with Tiered RDD.
2.  **SPARC Syntax:** Underlying symbolic principles guiding agents. [See Overview](#sparc-syntax-overview).
3.  **Perplexity Research Tools (MCP):** Integrated for Tiered RDD.
4.  **Deep Research Mode:** Dedicated agent for extensive research.
5.  **AI Engine (e.g., Claude 3.7 Sonnet):** The underlying language model executing instructions.

## 🎬 See It In Action (Framework-First, Plan-Driven Example)

**User:** "Start project: Simple Blog Platform."

**▶️ Orchestrator:** (Phase 1) `new_task @spec-pseudocode Define core blog features (posts CRUD, basic comments)...` -> `new_task @architect Design framework (e.g., Express routes, basic data models)...`

**(Later) ▶️ Orchestrator:** (Phase 2) `new_task @code Implement framework: Setup Express app, define base routes (`/posts`, `/comments`), placeholder data models...`

**(Later) ▶️ Orchestrator:** (Phase 3 - CRITICAL) `new_task @docs-writer **ACTION: Analyze framework code [link/context]. Create comprehensive TEST_PLAN.md.** Plan Phase 1: Posts CRUD (Unit & Integration tests). Plan Phase 2: Comments CRUD (Unit & Integration). **Cumulative Req:** After implementing comments, re-run Post listing integration tests. **Recursive Req:** N/A for this example.`

**(Later) ▶️ Orchestrator:** (Phase 4 - Following `TEST_PLAN.md` Phase 1) `new_task @code Implement 'Create Post' endpoint (POST /posts) per spec.`

**(Later) ▶️ Orchestrator:** `new_task @tdd Execute tests for 'Create Post' as defined in **TEST_PLAN.md section 'Phase 1 - Posts CRUD - Create Post Tests'**. Report PASS/FAIL.`

**(Later, after @tdd reports PASS for 'Create Post') ▶️ Orchestrator:** `new_task @code Implement 'List Posts' endpoint (GET /posts) per spec.`

**(Later) ▶️ Orchestrator:** `new_task @tdd Execute tests for 'List Posts' per **TEST_PLAN.md section 'Phase 1 - Posts CRUD - List Posts Tests'**. Report PASS/FAIL.`

*(...Continues executing Phase 1 tasks per the plan...)*

**(Later, starts Phase 2) ▶️ Orchestrator:** `new_task @code Implement 'Create Comment' endpoint (POST /posts/:postId/comments) per spec.`

**(Later) ▶️ Orchestrator:** `new_task @tdd Execute 'Create Comment' tests per **TEST_PLAN.md section 'Phase 2 - Comments CRUD - Create Comment Tests'**. ALSO execute **cumulative tests defined in plan (re-run Post Listing tests)**. Report PASS/FAIL.`

*(...Continues until all TEST_PLAN.md phases are complete...)*

**(Finally) ▶️ Orchestrator:** (Phase 5) `new_task @integration All features implemented and passed phase testing. Merge all branches. Execute the **ENTIRE TEST SUITE from TEST_PLAN.md** for final validation.`

## 🔧 Get Started

Ready for structured, plan-driven AI development?

### Prerequisites
1.  **VS Code** + **Roo Code extension**.
2.  **AI Model API Key** (e.g., Anthropic for Claude, OpenAI, etc.). Configure in Roo Code.
3.  **Perplexity API Key** (for RDD).

### Configuration:

1.  **Perplexity MCP Setup (RDD Tools):**
    *   Use **[cline](https://cline.tools)** (recommended): Install "Perplexity AI" provider, enter key, copy MCP URL/Header.
    *   Paste URL/Header into Roo Code's Perplexity MCP settings.

2.  **AI Model Configuration:**
    *   Configure your chosen LLM (e.g., Claude 3.7 Sonnet, GPT-4o) in Roo Code's model settings. Set appropriate default temperatures if needed (typically moderate, ~0.5-0.7, as roles aren't strictly split by temperature in this Roomode set).

3.  **Install SPARC Roomodes (This Version):**
    *   Copy the entire JSON object from the `*.roomodes` file source representing the **Framework-First, Test-Plan-Driven (v3)** workflow.
    *   Go to Roo Code settings -> "Edit Global Modes".
    *   Paste the JSON, replacing existing content. Save.
    *   Reload Roo Code (`Roo Code: Reload Custom Modes` or restart VS Code).

### Start Developing!
1.  Open a Roo Code chat.
2.  Select your configured AI Model profile.
3.  Select the `⚡️ SPARC Orchestrator` mode.
4.  Provide your high-level project objectives.
5.  Guide the orchestrator through the phases: Specify/Architect -> Build Framework -> **Generate Test Plan** -> Implement Features according to Plan -> Integrate & Final Test.
6.  Observe the structured workflow and how testing is driven by the `TEST_PLAN.md`.
7.  Use `❓ Ask Guide` for help understanding the workflow or formulating requests for specific phases.
8.  For major research tasks, instruct the orchestrator: `new_task @deep-research Research best practices for [topic relevant to project]...`

## <a name="sparc-syntax-overview"></a>🌌 SPARC Syntax Overview

The symbolic syntax (`Φ•Ω`, `Γ•Μ•Υ`, etc.) represents core principles encoded in agent instructions. Key concepts relevant to this framework:

*   **Φ•Ω [Core•Flow]:** Workflow clarity (Specification, Architecture, **Framework**, **Test Plan**, Implementation, Integration), systematic extension, code quality (`§͟qual`), confirmation (`⊦confirm`).
*   **Γ•Μ•Υ [Context]:** **Framework context drives Test Plan** (`⊦⟨framework_ctx⟩ → ⟨TEST_PLAN.md⟩`), Doc/context-driven action (`⊦⟨doc⟩ ⟨ctx⟩ → ⟨action⟩`), Arch boundaries (`⊤⟨arch⟩`), tech management (`⊢{...} ⊥newΔ`).
*   **Τ•Ρ [Tasks]:** Plan-driven tasks (`⊦⟨plan_task⟩`), **tiered RDD** for uncertainty (`‼️Ρ{pMCP tiers}→{search|...}✓findings`), self-verify (`⊗self{...}→⊦complete`). `@deep-research` for large RDD (`🔍deep-research`).
*   **Κ•Σ [Code]:** Best practices (`⊢{bestPractice}`), modularity (`⊤⟨module⟩`), size limits (`⟨file⟩≤500Λ`).
*   **Χ [Refactor]:** Improve code (`⋉{...}`), **verify via existing planned tests** (`⊨{⋈intact}⇒{⊦tdd}`).
*   **Δ [Testing]:** **Driven by `TEST_PLAN.md`** (`⊢⟨TEST_PLAN.md⟩ → ⟨test_execution⟩`), defines coverage, cumulative, recursive needs (`🎯⟨coverage:plan_defined⟩`), completion gated by **passing planned tests** (`‼️✓⟨tests pass:plan⟩→⊦complete`). Final validation runs **full plan** (`‼️✓⟨tests pass:full_plan⟩→⊦integration_complete`).
*   **Β [Debug]:** Fix based on test failure reports (`⊙{⟨root⟩}`), precise logs (`⊢⟨log⟩`). Enables Plan-Driven cycle continuation.
*   **Ξ [Security]:** Server-logic (`⊤{server-logic}`), validation (`‼️⊤⟨validate⟩`), no hardcoded secrets (`¬⟨hardcode⟩`).
*   **Ψ•Ε [VCS•Env]:** Git usage (`⊤⟨git⟩`), env-agnostic code (`⟨code⟩→⟨agnostic⟩`).
*   **Λ [Docs]:** **`TEST_PLAN.md` creation is key.** Final docs accurate (`⊤⟨mirror-reality⟩`).
*   **Θ [Limits]:** File size (`⟨file⟩≤500Λ`), abstract credentials (`¬⟨credentials⟩`).

## 🙏 Acknowledgements

Builds on **Reuven Cohen**'s original SPARC methodology concepts.

## 📜 License
MIT License - see `LICENSE` file.

## 🙏 Support Development

<div align="center">
  <p>Found this framework valuable? Consider supporting its development.</p>
  <a href="https://paypal.me/ChrisRoyseAI" target="_blank"><img src="https://img.shields.io/badge/Support_via_PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white" alt="Support via PayPal" width="250"/></a>
  <p style="margin-top: 10px;">Your support helps offset API costs and allows for further refinement.</p>
  <p>Thank you!</p>
</div>

## 🔗 Related Resources
-   [Roo Code Docs](https://roo.ai/docs)
-   [Perplexity API Docs](https://docs.perplexity.ai/)
-   [AI Model Provider Docs (e.g., Anthropic, OpenAI)](...)
-   [cline MCP Installer](https://cline.tools)
-   [MCP Standard](https://mcp.ai)

---
## 👤 Connect
- [🔗 LinkedIn - Christopher Royse](https://www.linkedin.com/in/christopher-royse-b624b596/)

---

Embrace structured, plan-driven, AI-accelerated development with built-in quality assurance!

---
