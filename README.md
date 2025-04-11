# 🚀 SPARC-Omega Vibe Coding: Knowledge-Guided AI + Perplexity + GitHub + Hyperbrowser!

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Roo Code Compatible](https://img.shields.io/badge/Roo%20Code-Compatible-brightgreen)](https://roo.ai)
[![Perplexity API](https://img.shields.io/badge/Perplexity-API-blue)](https://perplexity.ai)
[![GitHub Tools](https://img.shields.io/badge/GitHub-Tools-purple)](https://github.com)
[![Hyperbrowser Tools](https://img.shields.io/badge/Hyperbrowser-Tools-cyan)](https://github.com/hyperbrowserai/mcpglobal)
[![cline MCP Installer](https://img.shields.io/badge/cline-MCP%20Installer-orange)](https://cline.tools)

## 🎧 What is This? (The SPARC-Omega Vibe Explained)

Forget coding blind. This is **SPARC-Omega Vibe Coding** – a next-level framework for AI-driven development, **inspired by and extending the SPARC methodology and 'Boomerang Tasks' concept originally developed by Reuven Cohen for Roo Code**. I fuse Roo Code's multi-agent system with Perplexity's research, GitHub's repository management, and **Hyperbrowser's advanced web scraping and browser automation**. Crucially, the system uses **structured prompts to guide the AI's vast internal knowledge**, orchestrated by the **SPARC-Omega methodology**.

Here's the flow: You spark an idea. SPARC-Omega kicks in, using **guided prompts to leverage the AI's knowledge for proactive challenge anticipation**. It delegates tasks to a specialized crew of AI agents:

-   🌟 **SPARC-Omega Orchestrator**: Runs the show, integrating guided knowledge checks and coordinating MCP tools.
-   🔍 **Research Specialists**: Leverage Perplexity for cutting-edge info and Hyperbrowser (`scrape`, `crawl`, `extract`) for deep web data gathering.
-   🐙 **Git Managers**: Handle GitHub repos, branches, commits like pros.
-   🧠 **Coders & Architects**: Build modular solutions informed by guided knowledge checks, researching examples with Perplexity/Hyperbrowser.
-   🧪 **Testers**: Implement TDD, using guided prompts to target tests based on potential issues, and **Hyperbrowser Agents (`browser_use_agent`, `openai_...`, `claude_...`) for automated UI/E2E testing**.
-   🛡️ **Security Reviewers**: Audit code, focusing on common vulnerability patterns identified through guided prompts.
-   🚀 **DevOps**: Automate infrastructure and deployments, potentially using **Hyperbrowser Agents for complex console interactions** when APIs fall short.
-   ...and many more (Docs, Debugging, Integration, Optimization, Monitoring) – each enhanced with awareness of potential pitfalls via guided prompts and specific MCP tool access.

This isn't just autocomplete; it's **proactive, knowledge-guided, research-backed, automated full-lifecycle development** with agents that can *see, interact with, and extract data from the web* like never before.

## 🔄 NEW: SPARC-Omega Methodology & Guided Knowledge Integration

We've evolved beyond simple prediction. The system now operates on the **SPARC-Omega methodology**, **an enhancement of the original SPARC (Specification, Pseudocode, Architecture, Refinement, Completion) workflow and 'Boomerang Tasks' concept pioneered by Reuven Cohen**, integrated with **structured prompts that guide the AI's reasoning**:

### 🏛️ Proactive Guidance via Structured Prompts

Instead of relying on a formal ontology file, this framework uses targeted instructions within each agent's definition. Before coding, agents are prompted to:

-   **Identify Risk Patterns**: Leverage the LLM's internal knowledge to anticipate likely issues (e.g., potential security vulnerabilities, common compatibility problems, performance bottlenecks) based on the specific technologies and context of the task. Conceptual labels like `:Problem` or `:SecurityVulnerability` are used in prompts to focus the AI's attention.
-   **Focus on Best Practices**: Utilize prompts to guide the AI towards applying known best practices and common architectural patterns relevant to the task.
-   **Check Against Constraints**: Prompt the AI to consider potential constraints, such as platform incompatibilities or API changes, by accessing its internal knowledge base.

### ✨ SPARC-Omega Workflow

The enhanced SPARC flow uses this guided approach for robust development:

1.  **Specification**: Clarify goals, *using guiding concepts* in prompts to frame requirements and anticipate risks. Leverage Perplexity/Hyperbrowser for research.
2.  **Pseudocode**: Request high-level logic with TDD anchors, *informed by initial risk assessment prompts*.
3.  **Architecture**: Design extensible systems, *checking designs against known architectural patterns* identified via guided prompts. Use Perplexity/Hyperbrowser for architectural research.
4.  **Refinement**: Employ TDD (including **Hyperbrowser-powered UI tests**), debugging informed by knowledge of common issues, security reviews focused by vulnerability pattern prompts, and optimization flows.
5.  **Completion**: Integrate (*verifying against known compatibility factors*), document (*referencing key concepts*), monitor (*potentially using Hyperbrowser for synthetic checks*), and deploy.

This proactive, knowledge-guided approach dramatically improves code quality, security, and efficiency from the start by effectively leveraging the LLM's embedded knowledge.

## ✨ Why It's a Game Changer

Traditional AI coding tools operate in a vacuum. SPARC-Omega rewrites the rules:

-   🧠 **Proactive Risk Assessment**: Structured prompts guide the AI to leverage its internal knowledge and anticipate issues before they're coded.
-   🌐 **Full Web Interaction**: Hyperbrowser enables agents to scrape data, crawl sites, extract structured info, and **autonomously drive web browsers** for testing, research, or automation.
-   🐙 **Automated GitHub Workflow**: Seamlessly manage your entire GitHub presence programmatically.
-   💡 **Real-Time Research Power**: Perplexity keeps agents informed with the latest documentation, APIs, and best practices.
-   ✅ **Knowledge-Informed Quality**: Decisions leverage the LLM's vast knowledge base, guided by targeted prompts and supplemented by real-time research, leading to more robust solutions.
-   💻 **True Full Lifecycle Coverage**: From guided design and Hyperbrowser-driven testing to automated deployment and monitoring.
-   💸 **Cost-Effective Power**: Leverage potentially free models (like Gemini Flash/Pro via API when available) with efficient Perplexity/Hyperbrowser usage. GitHub MCP tools remain free.

## 🛠️ The Core Components

This framework integrates state-of-the-art AI capabilities:

### 1. The SPARC-Omega Multi-Agent Army (.roomodes) 🤖

A squad of specialized AI personas defined in the `.roomodes` file (included), each using guided prompts and assigned MCP tools:

-   🌟 **SPARC-Omega Orchestrator**: The maestro coordinating guided knowledge checks and tools.
-   📋 **Spec Writer (Omega)**: Uses guided prompts + Perplexity/Hyperbrowser (scrape, crawl, extract, *maybe* agents) for deep requirements gathering and risk identification.
-   🏗️ **Architect (Omega)**: Designs systems validated against known patterns + Perplexity/Hyperbrowser research.
-   🧠 **Coder (Omega)**: Writes code informed by risk prompts using GitHub + Perplexity/Hyperbrowser (scrape, extract).
-   🧪 **Tester (TDD, Omega)**: Writes tests targeted by risk prompts, executes **UI/E2E tests via Hyperbrowser Agents**.
-   🪲 **Debugger (Omega)**: Uses prompts to check known issues + Perplexity/Hyperbrowser (scrape, extract, *maybe* agents for reproduction).
-   🛡️ **Security Reviewer (Omega)**: Focuses audits using vulnerability pattern prompts + Perplexity/GitHub Search/Hyperbrowser (scrape, crawl).
-   📚 **Docs Writer (Omega)**: References key concepts + uses GitHub/Hyperbrowser (scrape, extract).
-   🔗 **Integrator (Omega)**: Verifies compatibility factors + uses GitHub, *maybe runs E2E tests via Hyperbrowser Agents*.
-   🚀 **DevOps (Omega)**: Uses platform knowledge prompts + GitHub/Perplexity/Hyperbrowser (scrape, *maybe agents for console automation*).
-   📈 **Monitor (Omega)**: Guided by performance issue prompts, *maybe sets up synthetic monitoring via Hyperbrowser Agents*.
-   🧹 **Optimizer (Omega)**: Guided by anti-pattern/performance prompts + uses GitHub/Perplexity/Hyperbrowser (scrape, extract).
-   ❓ **Ask (Omega Guide)**: Your guide to the SPARC-Omega system!

(Check the included `.roomodes` file for full details and instructions!)

### 2. Guided Knowledge Integration Framework 🏛️

**How it works:** This system does **not** load or query formal ontology files (like TTL). Instead, specific instructions and conceptual labels (e.g., `:Problem`, `:Solution`, `:SecurityVulnerability`) within each agent's `.roomodes` definition act as **structured prompts**. These prompts guide the underlying Large Language Model (LLM) to:
    a. Access relevant parts of its vast internal knowledge base (learned during training) about software pitfalls, patterns, technologies, and best practices.
    b. Structure its analysis and output around these concepts.
    c. Focus its external research using tools like Perplexity and Hyperbrowser.
It's a way to leverage the LLM's embedded knowledge proactively and consistently across the agent team.

### 3. Perplexity Research Power 💡

Integrated via MCP for real-time knowledge:

-   `search`, `get_documentation`, `find_apis`, `check_deprecated_code`, `chat_perplexity`.

### 4. GitHub Sidekick (MCP Tools) 🐙

Full programmatic control over your repositories:

-   Repo Ops (`create_repository`, `fork_repository`).
-   File Ops (`create_or_update_file`, `push_files`, `get_file_contents`).
-   Branching/Commits (`create_branch`, `list_commits`).
-   Issues/PRs (`create_issue`, `create_pull_request`).
-   Discovery (`search_code`, `search_repositories`).

### 5. Hyperbrowser Superpowers (MCP Tools) 🌐

Unlocks advanced web interaction via MCP (from `mcpglobal`):

-   **Data Extraction**:
    -   `scrape_webpage`: Get content from a single URL.
    -   `crawl_webpages`: Explore and collect data from multiple linked pages.
    -   `extract_structured_data`: Pull specific information using prompts/schemas.
-   **Browser Automation Agents**:
    -   `browser_use_agent`: Fast, cost-effective agent for *explicit, step-by-step* tasks.
    -   `openai_computer_use_agent`: General-purpose agent using OpenAI for standard web interactions.
    -   `claude_computer_use_agent`: Advanced agent using Claude for complex, nuanced tasks requiring sophisticated reasoning.
-   **Web Search**:
    -   `search_with_bing`: Perform web searches directly.

## 🎬 See It In Action (Usage Examples)

### Example 1: Guided Feature Planning with Web Research

**User**: "Let's spec out a feature to integrate Stripe payments into our Next.js app. Use Supabase for user data."

**🌟 SPARC-Omega Orchestrator**: "Vibing! 🚀 Let's plan this with foresight. Assigning to `spec-pseudocode-omega`. Task: Define requirements for Stripe integration in Next.js/Supabase context. *Use prompts to check internal knowledge for known compatibility issues or security vulnerability patterns* related to Stripe/Supabase auth. Use Perplexity (`search`, `get_documentation`) for latest Stripe API best practices and Hyperbrowser (`crawl_webpages`) on `stripe.com/docs` to gather detailed flow examples. Create modular pseudocode with TDD anchors. `attempt_completion`."

**(Later) 📋 Spec Writer (Omega)**: "Guided knowledge check flagged potential issues with handling webhook secrets securely (common vulnerability pattern) and ensuring transaction atomicity with Supabase (common integration problem). Researched via Perplexity & crawled Stripe docs using Hyperbrowser. Pseudocode includes secure webhook handling via env vars and database transaction logic. Ready! `attempt_completion`."

### Example 2: Automated UI Testing with Hyperbrowser Agent

**User**: "Okay, the login flow is coded. Let's add an E2E test to ensure users can log in via email."

**🌟 SPARC-Omega Orchestrator**: "Solid! 🧪 Assigning to `tdd-omega`. Task: Create and run an E2E test for the email login flow. *Use prompts to consider common login problem types* for edge cases (e.g., invalid password, non-existent user). Use Hyperbrowser's `openai_computer_use_agent` to execute the test steps against the staging URL [provide URL]. Steps: 1. Navigate to login page. 2. Find email input, enter 'test@example.com'. 3. Find password input, enter 'password123'. 4. Click login button. 5. Verify successful redirect to dashboard URL or presence of 'Welcome' text. Report results. `attempt_completion`."

**(Later) 🧪 Tester (TDD, Omega)**: "Prompts guided consideration of email case-insensitivity, added that step. Defined task for `openai_computer_use_agent`. Executing... Agent successfully navigated, entered credentials, clicked login, and verified dashboard access. Test passed! `attempt_completion`."

## 🔧 Get Started (Join the Vibe!)

Ready to code with foresight and automation?

### Prerequisites
-   VS Code with the Roo Code extension.
-   Perplexity API key.
-   GitHub Personal Access Token (scopes: repo, workflow, issues, etc.).
-   **Hyperbrowser API Key/Setup**: Access to Hyperbrowser tools (see [Hyperbrowser MCP Global Repo](https://github.com/hyperbrowserai/mcpglobal)).

### Easiest MCP Setup: Use cline!
1.  Install [cline](https://cline.tools).
2.  In cline, search for and install the MCP providers: "Perplexity AI", "GitHub", and "**Hyperbrowser**".
3.  Follow cline's prompts (it uses AI to set up the servers, likely asking for your API keys/tokens).
4.  Copy the MCP settings (URLs, headers/tokens) cline provides for each service.

### Configure Roo Code
1.  Open Roo Code settings in VS Code (Ctrl+Shift+P -> "Roo Code: Open Settings").
2.  Paste the Perplexity, GitHub, and **Hyperbrowser** MCP details copied from cline into the corresponding "Model Context Protocol (MCP) Settings" sections.

### Install the SPARC-Omega RooModes
1.  Copy the `.roomodes` file from this repository into the root directory of your project (or a parent directory).
2.  Roo Code will automatically detect and load the modes. (You can also save modes globally via Roo Code's UI/CLI if preferred).
    *   *Note*: The core logic and instructions, including the knowledge-guiding prompts and tool usage, are embedded within each mode definition in this `.roomodes` file.

### Start Vibing!
1.  Open a Roo Code chat in VS Code.
2.  Select an Omega mode (e.g., `🌟 SPARC-Omega Orchestrator`) from the mode selector.
3.  Give it a high-level objective and watch the knowledge-guided, tool-wielding AI agents collaborate!

## 🙏 Acknowledgements

The SPARC-Omega Vibe framework is deeply inspired by the foundational work of Reuven Cohen, particularly his development of the SPARC methodology (Specification, Pseudocode, Architecture, Refinement, Completion) and the 'Boomerang Tasks' concept within the Roo Code ecosystem. His insights into structuring AI-driven development workflows were instrumental in shaping this project.

For more background on the original concepts, please see his article:
- [🪃 Boomerang Tasks: Automating Code Development with Roo Code and SPARC Orchestration by Reuven Cohen](https://www.linkedin.com/pulse/boomerang-tasks-automating-code-development-roo-sparc-reuven-cohen-nr3zc/)

## 📜 License
Licensed under the MIT License—see the `LICENSE` file for details.

## 🔗 Related Resources
-   [Roo Code Docs](https://roo.ai/docs)
-   [Perplexity API Docs](https://perplexity.ai/api)
-   [GitHub API Docs](https://docs.github.com/en/rest)
-   [Hyperbrowser MCP Global Repo](https://github.com/hyperbrowserai/mcpglobal) (For Hyperbrowser tool details)
-   [MCP Standard](https://mcp.ai) (Underlying protocol)
-   [cline Setup](https://cline.tools) (Easiest MCP Server Setup)

---

Built with ❤️ by SPARC-Omega vibe coders. Let's automate the future, proactively!
