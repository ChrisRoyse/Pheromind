# 🚀 SPARC-SAPPO Agentic Development Framework (v2 - Enhanced TDD & Tiered RDD)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Roo Code Compatible](https://img.shields.io/badge/Roo%20Code-Compatible-brightgreen)](https://roo.ai)
[![Perplexity API](https://img.shields.io/badge/Perplexity-API%20(Tiered)-blue)](https://perplexity.ai)
[![Uses Claude 3.7 Sonnet](https://img.shields.io/badge/Uses-Claude%203.7%20Sonnet-orange)](https://www.anthropic.com/news/claude-3-5-sonnet)
[![Ontology-Guided (SAPPO)](https://img.shields.io/badge/Ontology-Guided%20(SAPPO)-purple)](.)
[![SPARC Methodology](https://img.shields.io/badge/Methodology-SPARC-orange)](.)
[![cline MCP Installer](https://img.shields.io/badge/cline-MCP%20Installer-orange)](https://cline.tools)

## 🌌 What is This? (The Evolved SPARC-SAPPO Framework Explained)

Welcome to the refined SPARC-SAPPO Agentic Development Framework, a highly structured system for AI-assisted software engineering built on Roo Code. This framework leverages **meticulous planning, ontological guidance, a robust dual-strategy TDD cycle, and strategic AI research** to deliver high-quality, cost-effective results using Anthropic's Claude 3.7 Sonnet. Inspired by [Rueven Cohen's original SPARC/Boomerang](https://gist.github.com/ruvnet/a206de8d484e710499398e4c39fa6299) concepts, this evolution emphasises Micro-Tasking, Research Driven Development, and backed by my custom made [Software Architecture Problem Prediction Ontology](https://github.com/ChrisRoyse/Coding-Agent-Ontology)(SAPPO).

**Key Pillars:**

1.  **SPARC Principles:** Core symbolic guidelines (Clarity, Extensibility, Testing, Collaboration) embedded within agent instructions.
2.  **SAPPO Ontology:** A custom ontology (`:Problem`, `:Solution`, `:Context`, `:ArchitecturalPattern`, `:TechnologyVersion`) explicitly used by agents to structure tasks, anticipate issues, and document decisions.
3.  **Micro-Task Orchestration & "Boomerang" TDD Cycle:** A central `🧠 SAPPO Orchestrator` breaks down plans into single micro-tasks. Crucially, it manages an immediate **Code -> Test -> Fix -> Re-Test** cycle for every implementation unit, driven by explicit PASS/FAIL reporting from the Tester.
4.  **Tiered Research-Driven Development (RDD):** Specialist agents strategically use Perplexity MCP tools (`search`, `get_documentation`, etc.) based on defined tiers (**MUST/SHOULD/MAY/DO NOT USE**), optimizing API usage and ensuring research is applied only when truly necessary.
5.  **Dual-Strategy Test-Driven Development (TDD):** A dedicated `🧪 Tester` employs a **powerful dual approach within the TDD cycle:**
    *   **Cumulative Testing:** Rerunning all relevant prior tests alongside new unit tests to prevent regressions and ensure system-wide stability.
    *   **Recursive Testing:** Applying specific techniques (testing base cases, recursive steps, edge cases) when `:RecursiveAlgorithm` patterns are involved, ensuring algorithmic correctness and targeting potential SAPPO `:Problem`s like `:StackOverflowError` or `:LogicError`.
6.  **Unified LLM, Dual-Mode Strategy (Claude 3.7 Sonnet):** Utilizes **Anthropic's Claude 3.7 Sonnet (~200k token context window)** with distinct temperature settings:
    *   **🧠 Thinking Mode (Temp ~0.7):** For planning, design, architecture, complex reasoning.
    *   **🛠️ Instruct Mode (Temp ~0.25):** For precise code, test generation, debugging following instructions.

**The Core Idea:** Provide a **detailed plan**. The `Orchestrator` (Thinking Mode) delegates **one micro-task**, framed with SAPPO. The Specialist (e.g., `Coder` - Instruct Mode) executes, using **Tiered RDD** for targeted research. The `Tester` (Instruct Mode) then *immediately* runs **Dual-Strategy TDD** (Recursive checks + Cumulative suite). Based on **PASS/FAIL**, the Orchestrator either initiates a fix micro-task (Coder/Debugger -> Tester) or proceeds with the plan. This **methodology drastically reduces the need for massive context windows**, making development **robust AND cost-effective**. I prioritize structure and testing over excessive context, proving that ~200k tokens, used wisely, is highly effective and economical.

## 📺 Quick Start & Methodology Video Guide:

[![Watch the Setup & Best Practices Guide](https://img.youtube.com/vi/EEXAcMqRv3E/maxresdefault.jpg)](https://youtu.be/mmRU-24RNhU)

👆 **Click the image above for a complete walkthrough!** This video covers:
*   Setting up Roo Code with the SPARC-SAPPO modes.
*   Configuring the **Claude 3.7 Sonnet** dual profiles (Thinking & Instruct).
*   Structuring effective plans for micro-tasking and the **Boomerang TDD cycle**.
*   Understanding **Dual-Strategy TDD** (Cumulative & Recursive).
*   Why this methodology enables **cost-effective context management (~200k sufficient)**.

## 🧠🛠️ Unified LLM, Dual-Mode Strategy (Claude 3.7 Sonnet @ ~200k Context)

Leveraging **Anthropic's Claude 3.7 Sonnet** (~200k context) with role-based temperature control:

1.  **🧠 Thinking Mode (Temperature: ~0.7)**
    *   **Model:** Claude 3.7 Sonnet
    *   **Purpose:** Planning, design, architecture, specs, documentation, complex reasoning.
    *   **Agents:** Orchestrator, Spec Writer, Architect, Docs Writer, Ask Guide, Tutorial.

2.  **🛠️ Instruct Mode (Temperature: ~0.25)**
    *   **Model:** Claude 3.7 Sonnet
    *   **Purpose:** Precise code/test generation, debugging, security checks, integration, operations following strict guidance.
    *   **Agents:** Coder, Tester, Debugger, Security Reviewer, Integrator, Monitor, Optimizer, DevOps.

**Why Claude 3.7 Sonnet & the ~200k Window Strategy (Cost-Efficiency by Design):**

*   **Peak Capability, Optimized Cost:** Claude 3.7 Sonnet offers leading performance within a generous yet manageable ~200k context.
*   **Methodology Trumps Raw Context:** This framework **intentionally avoids multi-million token dependency.** Our **rigorous Dual-Strategy TDD** (especially cumulative testing) acts as the *persistent state memory* and quality gate. Combined with **micro-tasking** and **focused RDD**, vast context becomes **methodologically unnecessary and economically wasteful.**
*   **The Dual-Strategy TDD Advantage:** Cumulative testing validates each step against the *verified history* embodied by the test suite. Recursive testing ensures complex logic is sound. The LLM doesn't *need* to reread everything constantly; the tests confirm integration and correctness.
*   **Dramatic Cost Savings:** Extremely large context windows incur significantly higher, often quadratic, API costs (potentially **$0.30 to $2.00+ per call**). Our micro-tasking and TDD keep Instruct calls lean (often 50k-150k), staying *well below* the 200k limit and **slashing LLM expenses** without sacrificing quality.
*   **Structure Over Size:** Success hinges on **your detailed plan** and the framework's structured execution (SAPPO, TDD Cycle), enabling Claude 3.7 Sonnet to excel within its efficient ~200k window. Rigor beats brute force.

## ✨ Key Features & Methodology

### 🏛️ SAPPO-Guided Micro-Tasking
-   **Ontology Mandate:** SAPPO terms (`:Problem`, `:Solution`, `:TechnologyVersion`, etc.) structure tasks and completion summaries.
-   **Granularity:** Orchestrator breaks plans into minimal, testable units.
-   **Specialization:** Agents collaborate via the Orchestrator, using appropriate Claude 3.7 modes.

### 🔍 Tiered Research-Driven Development (RDD)
-   **Strategic Perplexity Use:** Specialist agents use MCP tools (`search`, `get_documentation`, etc.) based on **clear tiers**:
    *   **MUST USE:** For critical unknowns, unfamiliar APIs, complex errors, vulnerability checks.
    *   **SHOULD USE:** For best practices, specific technology/pattern nuances.
    *   **MAY USE:** For examples, broader context understanding.
    *   **DO NOT USE:** For basic knowledge, straightforward tasks.
-   **Optimized & Justified Research:** Avoids unnecessary API calls while ensuring accuracy when needed.

### ✅ Dual-Strategy Test-Driven Development (TDD)
-   **Immediate Testing Cycle ("Boomerang"):** `🧪 Tester` runs immediately after `Coder` completion.
-   **Comprehensive Validation (Dual Strategy):**
    1.  **Cumulative Testing:** *Always* runs new unit tests **AND** all relevant prior tests to catch regressions and ensure system-wide stability. **Acts as reliable system state memory.**
    2.  **Recursive Testing (If Applicable):** When `:RecursiveAlgorithm` is involved, applies *specific tests* targeting **base cases, recursive steps, and edge cases** (e.g., potential `:StackOverflowError`, `:LogicError`), becoming part of the cumulative suite.
-   **PASS/FAIL Driven Workflow:** Tester's explicit PASS/FAIL result dictates the Orchestrator's next step (fix or proceed).
-   **Plan Integration:** Your plan should anticipate testing phases and highlight expected recursive logic for targeted testing.

### 📄 Detailed Planning is Paramount
-   **User Responsibility:** Success requires a **well-structured, phased plan**. The AI executes *your* strategy.
-   **Methodology > Model Size:** Good planning + strong TDD are essential for quality and **cost-efficiency**, regardless of LLM context size.

### 🔄 The Workflow Loop (Featuring the Boomerang TDD Cycle)
1.  **You:** Provide a detailed plan to the `Orchestrator`.
2.  **Orchestrator (Claude 3.7 Sonnet @ ~0.7):** Identifies next micro-task, frames with SAPPO, delegates (e.g., `new_task @coder Implement X... using :RecursiveAlgorithm...`).
3.  **Coder (Claude 3.7 Sonnet @ ~0.25):** Receives task, performs **Tiered RDD (if needed)**, implements the single unit.
4.  **Coder:** Reports `attempt_completion` (mentions pattern used, SAPPO considerations, RDD usage if any). States **"Ready for immediate testing via @tester-tdd"**.
5.  **Orchestrator:** Immediately assigns testing task: `new_task @tester-tdd Apply DUAL TESTING STRATEGY to X... Report PASS/FAIL.`
6.  **Tester (Claude 3.7 Sonnet @ ~0.25):** Writes new tests, applies **Recursive Testing** (if applicable), runs these **PLUS all cumulative tests**.
7.  **Tester:** Reports `attempt_completion` with **explicit "Result: PASS" or "Result: FAIL [details...]"**, confirms dual strategy application.
8.  **Orchestrator (Analyzes Test Result):**
    *   **IF PASS:** Proceeds to the next step in your plan (e.g., integration, docs).
    *   **IF FAIL:** Initiates fix cycle: assigns fix task to `@coder` or `@debugger` (`new_task @coder Fix :LogicError in X identified by test Y...`), awaits fix `attempt_completion`, then **loops back to Step 5** to re-assign testing to `@tester-tdd`.
9.  Cycle Repeats until the plan is complete.

## ✨ Why It's a Game Changer

-   🏛️ **Structured & Predictable:** SAPPO + Micro-tasking + TDD cycle create discipline.
-   💡 **Accurate & Efficient Research:** Tiered RDD ensures up-to-date info without waste.
-   ✅ **Highly Robust:** Dual-Strategy TDD (Cumulative + Recursive) drastically reduces bugs and ensures algorithmic + integration correctness. **Provides reliable state context.**
-   🧠 **Optimized AI Usage:** Leverages Claude 3.7 Sonnet's strengths via Thinking/Instruct modes within its efficient ~200k window.
-   💰 **MASSIVELY Cost-Effective:** Methodology (Micro-tasks + Dual TDD) **makes >200k context unnecessary**. Keeps API calls lean (often 50k-150k Instruct), **slashing LLM costs** versus huge context models. Avoid budget blowouts!
-   📈 **Superior Quality:** Leads to modular, rigorously tested, secure, documented code.
-   🤝 **Clear Collaboration:** Explicit SAPPO terms, TDD cycle steps, and PASS/FAIL reports improve traceability.

## 🛠️ The Core Components

1.  **SPARC-SAPPO Agent Army (.roomodes):** JSON definitions with SAPPO/TDD/RDD instructions, Thinking/Instruct roles, Tiered MCP rules.
2.  **SPARC Syntax:** Underlying symbolic principles. [See Overview](#-sparc-syntax-overview).
3.  **SAPPO Ontology:** Conceptual framework.
4.  **Perplexity Research Tools (MCP):** Integrated via `search`, `get_documentation`, etc., used according to tiers.
5.  **Unified LLM Engine (Claude 3.7 Sonnet):** Configured with two temperature profiles (~200k context limit).

## 🎬 See It In Action (Micro-Task & TDD Cycle Example)

**User Plan Snippet:** "Phase 3: Implement recursive file search. Step 3.1: Specify `findFilesRecursive` function. Step 3.2: Code `findFilesRecursive`. Step 3.3: Apply Dual-Strategy TDD. Step 3.4: Document."

**▶️ Orchestrator (Claude @ 0.7):** "`new_task @spec-writer Specify `findFilesRecursive(dir, pattern)` using :RecursiveAlgorithm. Detail base case (not dir or empty), step (recurse subdirs). Note potential :StackOverflowError :Problem. Define TDD anchors (base, recursive, edge cases like symlinks).`"

**(Later) 📝 Spec Writer (Claude @ 0.7):** "`attempt_completion` Spec written. Notes :RecursiveAlgorithm, base/step, potential :StackOverflowError. Provides TDD anchors for base (empty dir), recursion (nested), edge (symlink loop). Used MCP `search` (SHOULD USE tier) for robust symlink loop detection patterns. Returning."

**▶️ Orchestrator:** "`new_task @coder Implement `findFilesRecursive` per spec... Use :NodeJS v20... Handle symlink loops (:LogicError). Manage depth to mitigate :StackOverflowError.`"

**(Later) 🧠 Coder (Claude @ 0.25):** "`attempt_completion` Implemented `findFilesRecursive`. Used :RecursiveAlgorithm pattern, added depth limit and visited set for symlink loops. Used MCP `get_documentation` (MUST USE tier) for `fs.promises.readdir` `withFileTypes` option. Code complete, ready for immediate testing via @tester-tdd. Returning."

**▶️ Orchestrator:** "`new_task @tester-tdd Apply DUAL TESTING STRATEGY to `findFilesRecursive`. Test base/recursive/edge cases (symlinks, deep nesting). Run CUMULATIVE suite. Report PASS/FAIL.`"

**(Later) 🧪 Tester (Claude @ 0.25):** "`attempt_completion` **Applied Dual Testing Strategy.** RECURSIVE TESTING: Tested base case (empty dir), recursive step (nested match), edge cases (symlink loop handled, depth limit respected). CUMULATIVE TESTING: Ran new tests + 15 prior tests. Used Jest mocks. **Result: PASS**. All 19 tests passed. Returning control."
*(If FAIL: `... Result: FAIL. Test 'test_deep_nesting_stackoverflow' failed. Suspected :StackOverflowError despite limit. Suggest reviewing depth counter logic... Returning control.` The orchestrator would then trigger the fix cycle.)*

**▶️ Orchestrator:** "Implementation tested (Passed TDD cycle). Proceeding to documentation..."

## 🔧 Get Started (Join the Vibe!)

Ready for structured, TDD-powered, cost-effective AI development?

### Prerequisites
1.  **VS Code** + **Roo Code extension**.
2.  **Anthropic API Key** (Claude 3.7 Sonnet access).
3.  **Perplexity API Key**.

### Configuration: Claude 3.7 Sonnet Dual Profiles & RDD Tools

1.  **Perplexity MCP Setup (RDD Tools):**
    *   Use **[cline](https://cline.tools)** (recommended): Install "Perplexity AI" provider, enter key, copy MCP URL/Header.
    *   Paste URL/Header into Roo Code's Perplexity MCP settings.

2.  **Dual-Mode LLM Configuration (CRITICAL!):**
    *   Create **TWO** model profiles in Roo Code settings, **BOTH** pointing to your **Anthropic Claude 3.7 Sonnet** endpoint:
        *   **Profile 1 (Thinking):** Name: `claude-3.7-sonnet-thinking`. Endpoint: [Your Claude 3.7 Sonnet Endpoint]. **Default Temperature: ~0.7**.
        *   **Profile 2 (Instruct):** Name: `claude-3.7-sonnet-instruct`. Endpoint: [Your Claude 3.7 Sonnet Endpoint]. **Default Temperature: ~0.25**.
    *   **Why two profiles?** To easily switch between high-temp Thinking (Orchestrator, Architect, etc.) and low-temp Instruct (Coder, Tester, etc.) as required by the framework roles, optimizing Claude 3.7 Sonnet's performance within its ~200k context.
    *   **Manual Switching Required:** The `.roomodes` does NOT auto-assign profiles. **You MUST manually select the correct profile (`thinking` or `instruct`) in the Roo Code UI *before* invoking or allowing delegation to an agent.** Select `thinking` for Orchestrator interactions, switch to `instruct` when an Instruct agent (Coder, Tester) takes over, then switch back to `thinking` when control returns to Orchestrator. Diligence is key here.

3.  **Install SPARC-SAPPO RooModes:**
    *   Copy the entire JSON object from the `*.roomodes` file source provided earlier.
    *   Go to Roo Code settings -> "Edit Global Modes".
    *   Paste the JSON, replacing existing content. Save.
    *   Reload Roo Code (`Roo Code: Reload Custom Modes` or restart VS Code).

### Start Developing!
1.  Open a Roo Code chat.
2.  **Manually select the `claude-3.7-sonnet-thinking` profile.**
3.  Select the `🧠 SAPPO Orchestrator` mode.
4.  Provide your detailed, phased plan (mentioning testing needs, recursive parts).
5.  Observe the micro-tasking and **Boomerang TDD Cycle**.
6.  **Remember to manually switch profiles (Thinking <-> Instruct) based on which agent is active.** Keep Instruct context minimal.
7.  Use `❓ Ask Guide` (Thinking profile) for help structuring plans or understanding the Dual-Strategy TDD/cost-efficiency rationale.

## <a name="sparc-syntax-overview"></a>🌌 SPARC Syntax Overview

The symbolic syntax (`Φ•Ω`, `Γ•Μ•Υ`, etc.) represents core principles encoded in agent instructions. Key concepts include:

*   **Φ•Ω [Core•Flow]:** Workflow clarity, systematic extension, code quality (`§͟qual`), confirmation (`⊦confirm`).
*   **Γ•Μ•Υ [Context]:** Doc/context-driven action (`⊦⟨doc⟩ ⟨ctx⟩ → ⟨action⟩`), arch boundaries (`⊤⟨arch⟩`), tech management (`⊢{...} ⊥newΔ`). **Effective context mgmt + TDD avoids huge token needs.**
*   **Τ•Ρ [Tasks]:** Micro-tasks (`⊦⟨micro⟩`), **tiered RDD** for uncertainty (`‼️Ρ{pMCP tiers}→{search|...}✓findings`), self-verify (`⊗self{...}→⊦complete`).
*   **Κ•Σ [Code]:** Best practices (`⊢{bestPractice}`), conventions (`≡⟨conventions⟩`), modularity (`⊤⟨module⟩`), size limits (`⟨file⟩≤350Λ`), DRY (`¬⟨duplication⟩`).
*   **Χ [Refactor]:** Improve code based on specific triggers (`⋉{...}`), **verify via tests** (`⊨{⋈intact}⇒{⊦tester-tdd}`).
*   **Δ [Testing]:** **Test-driven** (`⊢⟨test→code⟩`), high coverage (`⊤∀⟨coverage⟩`), completion gated by **passing dual-strategy tests** (`‼️✓⟨tests pass:dual⟩→⊦complete`). Includes recursive validation. **Cumulative tests provide system state.**
*   **Β [Debug]:** SAPPO root cause (`⊙{⟨root⟩:SAPPO}`), precise logs (`⊢⟨log⟩`). Supports TDD cycle.
*   **Ξ [Security]:** Server-logic (`⊤{server-logic}`), validation/sanitization (`‼️⊤⟨validate⟩`), no hardcoded secrets (`¬⟨hardcode⟩`).
*   **Ψ•Ε [VCS•Env]:** Git usage (`⊤⟨git⟩`), env-agnostic code (`⟨code⟩→⟨agnostic⟩`).
*   **Λ [Docs]:** Accurate (`⊤⟨mirror-reality⟩`), including test strategy. Aids context recall.
*   **Θ [Limits]:** File size (`⟨file⟩≤350Λ`), abstract credentials (`¬⟨credentials⟩`).

## 🙏 Acknowledgements

Builds heavily on **Reuven Cohen**'s SPARC methodology and 'Boomerang Tasks' concept.
-   Reference: [🪃 Boomerang Tasks by Reuven Cohen](https://www.linkedin.com/pulse/boomerang-tasks-automating-code-development-roo-sparc-reuven-cohen-nr3zc/)
-   SAPPO is a custom ontology for this framework.

## 📜 License
MIT License - see `LICENSE` file.

## 🙏 Support Development

<div align="center">
  <p>Found this framework valuable? Consider supporting its development.</p>
  <a href="https://paypal.me/ChrisRoyseAI" target="_blank"><img src="https://img.shields.io/badge/Support_via_PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white" alt="Support via PayPal" width="250"/></a>
  <p style="margin-top: 10px;">Your support helps offset API costs (even with efficient models/methods) and allows for further refinement.</p>
  <p>Thank you!</p>
</div>

## 🔗 Related Resources
-   [Roo Code Docs](https://roo.ai/docs)
-   [Perplexity API Docs](https://docs.perplexity.ai/)
-   [Anthropic API Docs (Claude)](https://docs.anthropic.com/claude/reference/getting-started-with-the-api)
-   [SAPPO Ontology (Placeholder)](.)
-   [cline MCP Installer](https://cline.tools)
-   [Requestly (Useful for API mocking/testing)](https://requestly.io/)
-   [MCP Standard](https://mcp.ai)

---
## 👤 Connect
- [🔗 LinkedIn - Christopher Royse](https://www.linkedin.com/in/christopher-royse-b624b596/)

---

Embrace structured, ontology-driven, **dual-strategy TDD-powered**, and **cost-effective** AI-accelerated development. Plan meticulously, execute precisely, test rigorously!

---
