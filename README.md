# 🚀 SPARC-SAPPO Agentic Development Framework (v3 - Targeted TDD & Tiered RDD)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Roo Code Compatible](https://img.shields.io/badge/Roo%20Code-Compatible-brightgreen)](https://roo.ai)
[![Perplexity API](https://img.shields.io/badge/Perplexity-API%20(Tiered)-blue)](https://perplexity.ai)
[![Uses Claude 3.7 Sonnet](https://img.shields.io/badge/Uses-Claude%203.7%20Sonnet-orange)](https://www.anthropic.com/news/claude-3-5-sonnet)
[![Ontology-Guided (SAPPO)](https://img.shields.io/badge/Ontology-Guided%20(SAPPO)-purple)](.)
[![SPARC Methodology](https://img.shields.io/badge/Methodology-SPARC-orange)](.)
[![cline MCP Installer](https://img.shields.io/badge/cline-MCP%20Installer-orange)](https://cline.tools)

## 🌌 What is This? (The Evolved SPARC-SAPPO Framework Explained)

Welcome to the refined SPARC-SAPPO Agentic Development Framework, a highly structured system for AI-assisted software engineering built on Roo Code. This framework leverages **meticulous planning, ontological guidance, a robust Targeted TDD cycle, and strategic AI research** to deliver high-quality, cost-effective results using Anthropic's Claude 3.7 Sonnet. Inspired by [Rueven Cohen's original SPARC/Boomerang](https://gist.github.com/ruvnet/a206de8d484e710499398e4c39fa6299) concepts, this evolution emphasizes Micro-Tasking, Research Driven Development, and is backed by my custom-made [Software Architecture Problem Prediction Ontology](https://github.com/ChrisRoyse/Coding-Agent-Ontology)(SAPPO).

**Key Pillars:**

1.  **SPARC Principles:** Core symbolic guidelines (Clarity, Extensibility, Testing, Collaboration) embedded within agent instructions.
2.  **SAPPO Ontology:** A custom ontology (`:Problem`, `:Solution`, `:Context`, `:ArchitecturalPattern`, `:TechnologyVersion`) explicitly used by agents to structure tasks, anticipate issues, and document decisions.
3.  **Micro-Task Orchestration & "Boomerang" TDD Cycle:** A central `⚡️ SAPPO Orchestrator` breaks down plans into single micro-tasks. Crucially, it manages an immediate **Code -> Test -> Fix -> Re-Test** cycle for every implementation unit, driven by explicit PASS/FAIL reporting from the Tester.
4.  **Tiered Research-Driven Development (RDD):** Specialist agents strategically use Perplexity MCP tools (`search`, `get_documentation`, etc.) based on defined tiers (**MUST/SHOULD/MAY/DO NOT USE**), optimizing API usage and ensuring research is applied only when truly necessary.
5.  **Targeted Test-Driven Development (TDD):** A dedicated `🎯 Tester` (`@tester-core`) employs a **precise two-part strategy within the *immediate* TDD cycle:**
    *   **Core Logic Testing:** Focused unit tests verifying the internal correctness of the *newly implemented code*, including specific checks for `:RecursiveAlgorithm` patterns (base cases, steps, edge cases targeting `:LogicError` or `:StackOverflowError`).
    *   **Contextual Integration Testing:** Using `:Context` provided by the Orchestrator (e.g., feature, interacting components), the tester writes a *small number* of focused tests verifying only the **most critical, direct interactions** of the new code with its immediate collaborators. This catches integration issues like `:InterfaceMismatch` early.
6.  **Unified LLM, Dual-Mode Strategy (Claude 3.7 Sonnet):** Utilizes **Anthropic's Claude 3.7 Sonnet (~200k token context window)** with distinct temperature settings:
    *   **🧠 Thinking Mode (Temp ~0.7):** For planning, design, architecture, complex reasoning.
    *   **🛠️ Instruct Mode (Temp ~0.25):** For precise code, test generation, debugging following instructions.

**The Core Idea:** Provide a **detailed plan**. The `Orchestrator` (Thinking Mode) delegates **one micro-task**, framed with SAPPO. The Specialist (e.g., `Coder` - Instruct Mode) executes, using **Tiered RDD** for targeted research. The `Tester` (`@tester-core` - Instruct Mode) then *immediately* applies the **Targeted Testing Strategy** (Core Logic + Contextual Integration based on Orchestrator-provided context). Based on **PASS/FAIL**, the Orchestrator either initiates a fix micro-task (Coder/Debugger -> Tester) or proceeds with the plan. Broader regression testing is handled by the `Integrator` later. This **methodology drastically reduces the need for massive context windows**, making development **robust, fast, AND cost-effective**. We prioritize structure and *focused* testing over excessive context, proving that ~200k tokens, used wisely, is highly effective and economical.

## 📺 Quick Start & Methodology Video Guide:

[![Watch the Setup & Best Practices Guide](https://img.youtube.com/vi/X0qIr-dEViU/maxresdefault.jpg)](https://youtu.be/X0qIr-dEViU)

👆 **Click the image above for a walkthrough!** (Note: This video demonstrates the previous "Dual Testing" strategy. While setup remains similar, the testing methodology has evolved to the "Targeted Testing Strategy" described here for faster, more focused feedback in the immediate loop. Key principles of planning and micro-tasking remain.) This README reflects the **current** Targeted Testing approach.

## 🧠🛠️ Unified LLM, Dual-Mode Strategy (Claude 3.7 Sonnet @ ~200k Context)

Leveraging **Anthropic's Claude 3.7 Sonnet** (~200k context) with role-based temperature control:

1.  **🧠 Thinking Mode (Temperature: ~0.7)**
    *   **Model:** Claude 3.7 Sonnet
    *   **Purpose:** Planning, design, architecture, specs, documentation, complex reasoning.
    *   **Agents:** Orchestrator, Spec Writer, Architect, Docs Writer, Ask Guide, Security Reviewer (uses edit).

2.  **🛠️ Instruct Mode (Temperature: ~0.25)**
    *   **Model:** Claude 3.7 Sonnet
    *   **Purpose:** Precise code/test generation, debugging, integration, operations following strict guidance.
    *   **Agents:** Coder, Tester, Debugger, Integrator, Optimizer, DevOps.

**Why Claude 3.7 Sonnet & the ~200k Window Strategy (Cost-Efficiency by Design):**

*   **Peak Capability, Optimized Cost:** Claude 3.7 Sonnet offers leading performance within a generous yet manageable ~200k context.
*   **Methodology Trumps Raw Context:** This framework **intentionally avoids multi-million token dependency.** Our **rigorous Targeted TDD cycle** acts as the *immediate quality gate*. Combined with **micro-tasking**, **focused RDD**, and *later* **comprehensive integration tests** by `@integrator`, vast context becomes **methodologically unnecessary and economically wasteful for the core loop.**
*   **The Targeted TDD Advantage:** Core Logic testing ensures unit correctness. Contextual Integration testing validates *key interactions* early, guided by Orchestrator context. The LLM doesn't *need* to reread everything constantly in the fastest loop; the targeted tests confirm the unit works and fits its immediate purpose, while `@integrator` verifies broader system health later.
*   **Dramatic Cost Savings:** Extremely large context windows incur significantly higher, often quadratic, API costs (potentially **$0.30 to $2.00+ per call**). Our micro-tasking and *Targeted* TDD keep Instruct calls lean (often 50k-150k, focusing on the unit + immediate context), staying *well below* the 200k limit and **slashing LLM expenses** without sacrificing initial quality checks.
*   **Structure Over Size:** Success hinges on **your detailed plan** and the framework's structured execution (SAPPO, Targeted TDD Cycle), enabling Claude 3.7 Sonnet to excel within its efficient ~200k window. Rigor beats brute force.

## ✨ Key Features & Methodology

### 🏛️ SAPPO-Guided Micro-Tasking
-   **Ontology Mandate:** SAPPO terms (`:Problem`, `:Solution`, `:TechnologyVersion`, `:Context`, etc.) structure tasks and completion summaries.
-   **Granularity:** Orchestrator breaks plans into minimal, single logical units.
-   **Specialization:** Agents collaborate via the Orchestrator, using appropriate Claude 3.7 modes.

### 🔍 Tiered Research-Driven Development (RDD)
-   **Strategic Perplexity Use:** Specialist agents use MCP tools (`search`, `get_documentation`, etc.) based on **clear tiers**:
    *   **MUST USE:** For critical unknowns, unfamiliar APIs, complex errors, vulnerability checks.
    *   **SHOULD USE:** For best practices, specific technology/pattern nuances.
    *   **MAY USE:** For examples, broader context understanding.
    *   **DO NOT USE:** For basic knowledge, straightforward tasks.
-   **Optimized & Justified Research:** Avoids unnecessary API calls while ensuring accuracy when needed.

### ✅ Targeted Test-Driven Development (TDD)
-   **Immediate Testing Cycle ("Boomerang"):** `🎯 Tester` (`@tester-core`) runs immediately after `Coder` completion.
-   **Focused Validation (Targeted Strategy):**
    1.  **Core Logic Testing:** Unit tests verify the *implemented code's internal correctness*, including specific handling for patterns like `:RecursiveAlgorithm` (base/step/edge cases targeting relevant SAPPO `:Problem`s like `:LogicError`, `:StackOverflowError`).
    2.  **Contextual Integration Testing:** Orchestrator provides `:Context` (e.g., 'Part of Feature X', 'Consumed by Service Y'). Tester writes a *few critical tests* verifying **direct interactions** based on this context, preventing early integration `:Problem`s (`:InterfaceMismatch`, `:CompatibilityIssue`) related to the unit's role.
-   **PASS/FAIL Driven Workflow:** Tester's explicit PASS/FAIL result for the *targeted tests* dictates the Orchestrator's next step (initiate fix or proceed).
-   **Later Comprehensive Checks:** The `🔗 Integrator` agent runs broader, potentially system-wide tests *after* a unit has successfully passed its targeted TDD cycle and is ready for merge.
-   **Plan Integration:** Your plan should anticipate these targeted testing steps and provide necessary `:Context` hints for the Orchestrator to pass to the Tester.

### 📄 Detailed Planning is Paramount
-   **User Responsibility:** Success requires a **well-structured, phased plan**. The AI executes *your* strategy. Clearly defining expected interactions helps the Orchestrator provide good `:Context` for testing.
-   **Methodology > Model Size:** Good planning + strong TDD (Targeted loop + Comprehensive integration checks) are essential for quality and **cost-efficiency**, regardless of LLM context size.

### 🔄 The Workflow Loop (Featuring the Targeted Boomerang TDD Cycle)
1.  **You:** Provide a detailed plan to the `Orchestrator`, including hints about component interactions (:Context).
2.  **Orchestrator (Claude 3.7 Sonnet @ ~0.7):** Identifies next micro-task, frames with SAPPO, delegates (e.g., `new_task @coder Implement X... using :RecursiveAlgorithm... CONTEXT: Part of 'User Profile Update', sends data to :AuditService.` ).
3.  **Coder (Claude 3.7 Sonnet @ ~0.25):** Receives task, performs **Tiered RDD (if needed)**, implements the single unit.
4.  **Coder:** Reports `attempt_completion` (mentions pattern, SAPPO considerations, RDD usage). States **"Code complete, ready for immediate targeted testing via @tester-core. Returning control to Orchestrator."**
5.  **Orchestrator:** Immediately assigns testing task *with context*: `new_task @tester-core Apply TARGETED TESTING STRATEGY to X. CONTEXT: Part of 'User Profile Update', sends data to :AuditService. Test core logic (esp. recursion if any) AND context (interaction w/ :AuditService). Report PASS/FAIL.`
6.  **Tester (`@tester-core`, Claude 3.7 Sonnet @ ~0.25):** Writes/executes **Targeted Tests**: (1) Core Logic tests (unit tests, recursive checks). (2) Contextual Integration tests (mocks `:AuditService`, checks if `X` calls it correctly based on context).
7.  **Tester:** Reports `attempt_completion` with **explicit "Targeted testing complete. Result: PASS" or "Result: FAIL [details on Core/Contextual test failure...]"**, confirms strategy application.
8.  **Orchestrator (Analyzes Test Result):**
    *   **IF PASS:** Proceeds to the next step in your plan (e.g., documentation, pass to integrator).
    *   **IF FAIL:** Initiates fix cycle: assigns fix task to `@coder` or `@debugger` (`new_task @coder Fix :InterfaceMismatch in X identified by Contextual Integration test...`), awaits fix `attempt_completion`, then **loops back to Step 5** to re-assign testing to `@tester-core` *with the same context*.
9.  Cycle Repeats until the plan phase involving implementation/unit testing is complete. Later steps might involve `@integrator` for merging and broader tests.

## ✨ Why It's a Game Changer

-   🏛️ **Structured & Predictable:** SAPPO + Micro-tasking + Targeted TDD cycle create discipline.
-   💡 **Accurate & Efficient Research:** Tiered RDD ensures up-to-date info without waste.
-   ✅ **Robust & Fast Feedback:** Targeted TDD catches core logic and critical integration issues *immediately*. Comprehensive checks by `@integrator` ensure broader stability before release.
-   🧠 **Optimized AI Usage:** Leverages Claude 3.7 Sonnet's strengths via Thinking/Instruct modes within its efficient ~200k window.
-   💰 **MASSIVELY Cost-Effective:** Methodology (Micro-tasks + *Targeted* TDD loop) **makes >200k context unnecessary for the rapid iteration cycle**. Keeps API calls lean (often 50k-150k Instruct), **slashing LLM costs** versus huge context models. Avoid budget blowouts!
-   📈 **Superior Quality:** Leads to modular, rigorously unit-tested *and* integration-aware, secure, documented code.
-   🤝 **Clear Collaboration:** Explicit SAPPO terms, Targeted TDD cycle steps, Context passing, and PASS/FAIL reports improve traceability.

## 🛠️ The Core Components

1.  **SPARC-SAPPO Agent Army (.roomodes):** JSON definitions with SAPPO/Targeted TDD/RDD instructions, Thinking/Instruct roles, Tiered MCP rules. (*You are reading the description for V3 with Targeted TDD*).
2.  **SPARC Syntax:** Underlying symbolic principles. [See Overview](#-sparc-syntax-overview).
3.  **SAPPO Ontology:** Conceptual framework.
4.  **Perplexity Research Tools (MCP):** Integrated via `search`, `get_documentation`, etc., used according to tiers.
5.  **Unified LLM Engine (Claude 3.7 Sonnet):** Configured with two temperature profiles (~200k context limit).

## 🎬 See It In Action (Targeted Micro-Task & TDD Cycle Example)

**User Plan Snippet:** "Phase 3: Implement recursive file search for report generator. Step 3.1: Specify `findFilesRecursive`. Step 3.2: Code `findFilesRecursive`. CONTEXT: Consumed by :ReportGeneratorService, must handle '.txt' files only. Step 3.3: Apply Targeted TDD. Step 3.4: Document."

**▶️ Orchestrator (Claude @ 0.7):** "`new_task @spec-writer Specify `findFilesRecursive(dir, pattern)` using :RecursiveAlgorithm. Detail base case, recursive step. Target: `.txt` files. Potential :StackOverflowError :Problem. Define TDD anchors (Core Logic: base, recursion, edge cases like symlinks; Contextual Integration: check filter logic for `.txt`).`"

**(Later) 📝 Spec Writer (Claude @ 0.7):** "`attempt_completion` Spec written. Notes :RecursiveAlgorithm, targets `.txt` files, potential :StackOverflowError. Provides **TDD Anchors:** **Core Logic:** empty dir, nested `.txt` find, symlink loop avoidance. **Contextual Integration:** Ensure only `.txt` files are returned when called with various inputs. Used MCP `search` (SHOULD USE tier) for robust symlink loop detection patterns. Returning."

**▶️ Orchestrator:** "`new_task @coder Implement `findFilesRecursive` per spec... Use :NodeJS v20... Handle symlink loops (:LogicError). Add depth limit (:StackOverflowError mitigation). Ensure filter for `.txt` pattern passed in.`"

**(Later) 🧠 Coder (Claude @ 0.25):** "`attempt_completion` Implemented `findFilesRecursive`. Used :RecursiveAlgorithm, added depth limit, visited set for symlinks, respects input pattern (expects `.txt`). Used MCP `get_documentation` (MUST USE tier) for `fs.promises.readdir` `withFileTypes` option. Code complete, ready for immediate targeted testing via @tester-core. Returning."

**▶️ Orchestrator:** "`new_task @tester-core Apply TARGETED TESTING STRATEGY to `findFilesRecursive`. CONTEXT: Must return only '.txt' files for :ReportGeneratorService. TEST: (1) CORE LOGIC (base/step/edges/recursion). (2) CONTEXTUAL INTEGRATION (verify `.txt` filter works, interacts as expected by context). Report PASS/FAIL.`"

**(Later) 🎯 Tester (`@tester-core`, Claude @ 0.25):** "`attempt_completion` **Applied Targeted Testing Strategy.** Context: `.txt` filter for :ReportGeneratorService. **(1) Core Logic Testing:** Base case (empty dir) passed. Recursive step (nested file find) passed. Edge case (symlink loop) passed. **(2) Contextual Integration Testing:** Test with pattern `*.txt` correctly returned only .txt files. Test with other patterns returned empty list as expected per context. **Result: PASS**. All targeted tests passed. Returning control."
*(If FAIL: `... Result: FAIL. Contextual Integration test 'test_txt_filter_ignores_other_extensions' failed. Returned '.log' files unexpectedly. Suspected :LogicError in pattern filtering... Returning control.` The orchestrator would then trigger the fix cycle.)*

**▶️ Orchestrator:** "Implementation tested (Passed Targeted TDD cycle). Proceeding to documentation..."

## 🔧 Get Started (Join the Vibe!)

Ready for structured, Targeted TDD-powered, cost-effective AI development?

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
    *   **Why two profiles?** To easily switch between high-temp Thinking (Orchestrator, Architect, Spec Writer, etc.) and low-temp Instruct (Coder, Tester, Debugger, etc.) as required by the framework roles, optimizing Claude 3.7 Sonnet's performance within its ~200k context.
    *   **Manual Switching Required:** The `.roomodes` does NOT auto-assign profiles. **You MUST manually select the correct profile (`thinking` or `instruct`) in the Roo Code UI *before* invoking or allowing delegation to an agent.** Select `thinking` for Orchestrator interactions, switch to `instruct` when an Instruct agent (Coder, Tester) takes over, then switch back to `thinking` when control returns to Orchestrator. Diligence is key here.

3.  **Install SPARC-SAPPO RooModes:**
    *   Copy the entire JSON object from the `*.roomodes` file source representing the **Targeted Testing Strategy (V3)**.
    *   Go to Roo Code settings -> "Edit Global Modes".
    *   Paste the JSON, replacing existing content. Save.
    *   Reload Roo Code (`Roo Code: Reload Custom Modes` or restart VS Code).

### Start Developing!
1.  Open a Roo Code chat.
2.  **Manually select the `claude-3.7-sonnet-thinking` profile.**
3.  Select the `⚡️ SAPPO Orchestrator` mode.
4.  Provide your detailed, phased plan (mentioning testing needs, :Context hints for interaction, recursive parts).
5.  Observe the micro-tasking and **Targeted Boomerang TDD Cycle**.
6.  **Remember to manually switch profiles (Thinking <-> Instruct) based on which agent is active.** Keep Instruct context minimal, focused on the current micro-task + immediate context.
7.  Use `❓ Ask Guide` (Thinking profile) for help structuring plans or understanding the Targeted TDD/cost-efficiency rationale.

## <a name="sparc-syntax-overview"></a>🌌 SPARC Syntax Overview

The symbolic syntax (`Φ•Ω`, `Γ•Μ•Υ`, etc.) represents core principles encoded in agent instructions. Key concepts relevant to the Targeted TDD approach:

*   **Φ•Ω [Core•Flow]:** Workflow clarity, systematic extension, code quality (`§͟qual`), confirmation (`⊦confirm`).
*   **Γ•Μ•Υ [Context]:** Doc/context-driven action (`⊦⟨doc⟩ ⟨ctx⟩ → ⟨action⟩`), arch boundaries (`⊤⟨arch⟩`), tech management (`⊢{...} ⊥newΔ`). **Orchestrator passes necessary :Context for targeted testing.**
*   **Τ•Ρ [Tasks]:** Micro-tasks (`⊦⟨micro⟩`), **tiered RDD** for uncertainty (`‼️Ρ{pMCP tiers}→{search|...}✓findings`), self-verify (`⊗self{...}→⊦complete`).
*   **Κ•Σ [Code]:** Best practices (`⊢{bestPractice}`), conventions (`≡⟨conventions⟩`), modularity (`⊤⟨module⟩`), size limits (`⟨file⟩≤350Λ`), DRY (`¬⟨duplication⟩`).
*   **Χ [Refactor]:** Improve code based on specific triggers (`⋉{...}`), **verify via tests** (initially `@tester-core` for targeted checks, potentially `@integrator` later) (`⊨{⋈intact}⇒{⊦tester-core}`).
*   **Δ [Testing]:** **Test-driven** (`⊢⟨test→code⟩`), **targeted coverage** (`🎯⟨coverage:core+context⟩`), completion gated by **passing targeted tests** (`‼️✓⟨tests pass:targeted⟩→⊦complete`). Includes core recursive validation. **Later comprehensive testing via `@integrator`.**
*   **Β [Debug]:** SAPPO root cause (`⊙{⟨root⟩:SAPPO}`), precise logs (`⊢⟨log⟩`). Supports Targeted TDD cycle.
*   **Ξ [Security]:** Server-logic (`⊤{server-logic}`), validation/sanitization (`‼️⊤⟨validate⟩`), no hardcoded secrets (`¬⟨hardcode⟩`).
*   **Ψ•Ε [VCS•Env]:** Git usage (`⊤⟨git⟩`), env-agnostic code (`⟨code⟩→⟨agnostic⟩`).
*   **Λ [Docs]:** Accurate (`⊤⟨mirror-reality⟩`), including **Targeted Test strategy** explanation. Aids context recall.
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
-   [Software Architecture Problem Prediction Ontology (SAPPO)](https://github.com/ChrisRoyse/Coding-Agent-Ontology)
-   [cline MCP Installer](https://cline.tools)
-   [Requestly (Useful for API mocking/testing)](https://requestly.io/)
-   [MCP Standard](https://mcp.ai)

---
## 👤 Connect
- [🔗 LinkedIn - Christopher Royse](https://www.linkedin.com/in/christopher-royse-b624b596/)

---

Embrace structured, ontology-driven, **Targeted TDD-powered**, and **cost-effective** AI-accelerated development. Plan meticulously, execute precisely, test smartly!

---
