# 🚀 Unleash AI Vibe Coding: RooModes + Perplexity + GitHub Superpowers!

[![Watch the Demo!](https://img.youtube.com/vi/R86yXPuA7Qs/maxresdefault.jpg)](https://youtu.be/R86yXPuA7Qs)  
**(Click Above to See the Magic In Action!)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)  
[![Roo Code Compatible](https://img.shields.io/badge/Roo%20Code-Compatible-brightgreen.svg)](https://roocode.com/)  
[![Perplexity API](https://img.shields.io/badge/Perplexity-Integrated-blue.svg)](https://www.perplexity.ai/)  
[![GitHub Tools](https://img.shields.io/badge/GitHub%20MCP-Enabled-orange.svg)](https://github.com/features)  
[![cline MCP Installer](https://img.shields.io/badge/MCP%20Setup-Easy%20via%20cline-purple.svg)](https://microsoft.github.io/cline/)

## 🎧 What is This? (The Vibe Explained)

Say goodbye to blind coding and outdated practices! This repository delivers a **complete framework for AI-powered "vibe coding"**, blending Roo Code’s multi-agent boomerang system with Perplexity’s real-time research prowess and GitHub’s full repository toolkit via the Model Context Protocol (MCP). 

Here’s the vibe: You dream up an idea. You kick off some **deep research**—researching *how* to research, then diving into your concept. Feed a plan to your AI crew, and then... **just vibe**. Watch a squad of specialized agents take over:

- **Orchestrators** run the show.
- **Research Specialists** tap Perplexity for the latest best practices, APIs, and docs.
- **Git Managers** handle repos, branches, and commits on GitHub.
- **Coders**, **Architects**, **Testers**, **Reviewers**, **Documenters**, **DevOps** (shoutout to DevOps!) and more crush their tasks, all backed by real-time data and slick coding principles.

This isn’t just autocomplete. It’s **research-backed, automated, full-lifecycle development** powered by AI agents vibing together seamlessly. Boom shaka lockaka!

## ✨ Why It’s a Game Changer

Old-school AI coding tools lack context and fumble best practices. This system flips the script:

1. 🧠 **Never Code Blind Again:** Perplexity’s real-time research validates every move against current standards and examples—catch deprecated code *before* it’s written.
2. 🐙 **Automate Your Entire GitHub Workflow:** Programmatically manage repos, branches, issues, and PRs right from your AI flow.
3. ✅ **Evidence-Based Quality:** Code decisions are rooted in research, delivering secure, modern, and efficient solutions.
4. 💻 **Full Lifecycle Coverage:** Agents handle it all—research, architecture, coding, testing, docs, CI/CD, deployment, and monitoring.
5. 💸 **Cost-Effective:** Potentially free with models like Gemini 1.5 Flash/Pro (when available via API), with Perplexity API costs as low as $0.80 for a full day of heavy research. GitHub MCP tools? Free!

## 🛠️ The Core Components (Magic Sauce)

This framework fuses cutting-edge tools into one powerhouse:

### 1. The Multi-Agent Army (`.roomodes`) 🤖
A squad of specialized AI personas defined in the `.roomodes` file (included here):
- ⚡️ **SPARC Orchestrator:** The maestro, syncing Perplexity research with GitHub actions.
- 🔍 **Research Specialist:** Dives into Perplexity and GitHub for up-to-date insights.
- 🔄 **Git Manager:** Runs GitHub like a pro—repos, branches, commits.
- 🧐 **Code Reviewer:** Delivers research-backed code critiques.
- 🏗️ **Architect**, 🧠 **Coder**, 🧪 **Tester**, 🛡️ **Security Reviewer**, 📚 **Docs Writer**, 🔗 **Integrator**, 🚀 **CI/CD Engineer**, 📈 **Monitor**, 🧹 **Optimizer**, 🚀 **DevOps**—each a master of their craft.  
*(Check `.roomodes` for the full lineup!)*

### 2. Perplexity Research Power 💡
Tap Perplexity’s MCP tools right in your workflow:
- `chat_perplexity`: Keeps research context alive across tasks.
- `search`: Deep dives on any topic.
- `get_documentation`: Grabs the latest docs.
- `find_apis`: Uncovers integration options.
- `check_deprecated_code`: Keeps your code current.

### 3. GitHub Sidekick (MCP Tools) 🐙
Run GitHub without breaking a sweat:
- **Repo Ops:** `create_repository`, `fork_repository`
- **File Ops:** `create_or_update_file`, `push_files`, `get_file_contents`
- **Branching:** `create_branch`, `list_commits`
- **Issues/PRs:** `create_issue`, `update_issue`, `create_pull_request`, `get_pull_request_files`
- **Discovery:** `search_code`, `search_repositories`

### 4. The Secret Sauce: Syntaxed Coding Principles 🎯
Token-efficient coding rules using symbolic notation—shrinking ~7800 tokens of best practices to ~1100! Loaded into Roo Code’s "Custom Coding Instructions (All Modes)," these guide every agent without clogging the context window. When the bullseyes (⊕) drop, you’re golden!
```markdown
*Evidence-Based Simplicity*
↹ standards•solutions
⊕ clear•maintainable => validate
⊕ search => validate•simple
⊕ search_code => find•examples
⊕ evidence => minimize•complex

*Research-Driven Iteration*
↹ code•existing
⊕ search => best•practices
⊕ create_issue•update_issue => track
⊕ evidence•docs => justify•change
⊕ list_commits => understand•hist
```
*(Full principles in `symbolic_coding_principles.md`)*

## 🎬 See It In Action (Usage Examples)

### Example 1: Kickstarting a New Project Vibe
**User:** "Let’s build a Supabase-backed influencer marketing tracker with Next.js and TypeScript."  
**SPARC Orchestrator:** "Time to vibe! 🚀 I’ll orchestrate:  
1. Research Specialist hits Perplexity (`search`, `get_documentation`) for Supabase/Next.js patterns.  
2. Git Manager sets up the repo (`create_repository`) and branches (`create_branch`).  
3. Spec Writer drafts pseudocode (`spec-pseudocode`) from research.  
4. Coders (`code`) and Testers (`tdd`) build features, pushing to GitHub (`push_files`).  
Starting with research... [Perplexity running]... Got the latest! Repo ‘influencer-tracker’ is live. Let’s spec it out!"  

### Example 2: AI-Powered Code Review & Refactor
**User:** "Review this login function in `auth.ts`. Is it secure? Suggestions?"  
**Code Reviewer:** "On it! 🧐 I’ll analyze `auth.ts`, check Perplexity (`search`, `check_deprecated_code`) for OWASP standards, and GitHub (`search_code`) for patterns.  
[Research running...] Findings:  
1. Bcrypt hashing is solid, but salt rounds are low (OWASP update).  
2. Session tokens need httpOnly cookies (`get_documentation`).  
3. Spotted a better pattern in repo Xyz (`search_code`).  
Creating a PR (`create_pull_request`) on a new branch (`create_branch`) with fixes!"

## 🔧 Get Started (Easier Than You Think!)

Ready to vibe? Here’s the setup:

### Prerequisites
- VS Code with the [Roo Code extension](https://roocode.com/).
- [Perplexity API key](https://www.perplexity.ai/).
- [GitHub Personal Access Token](https://github.com/settings/tokens) (scopes: repo, workflow, issues, etc.).

### Easiest MCP Setup: Use [cline](https://microsoft.github.io/cline/)!
1. Install [cline](https://microsoft.github.io/cline/).
2. Search for "Perplexity AI" and "GitHub" MCP providers in cline.
3. Hit "Install" for each—cline’s AI sets up the servers (may prompt for API keys).
4. Copy the MCP settings (URLs, headers/tokens) from cline’s output.

### Configure Roo Code
1. Open Roo Code settings in VS Code.
2. Paste Perplexity and GitHub MCP details from cline into the MCP settings section.
3. Grab the `symbolic_coding_principles.md` content from this repo.
4. Paste it into "Custom Coding Instructions (All Modes)" in Roo Code settings.

### Install the RooModes
- Copy the `.roomodes` file from this repo to your project’s root.
- *Optional:* Save modes globally via Roo Code’s UI/CLI.

### Start Vibing!
1. Open a Roo Code chat in VS Code.
2. Pick a mode (e.g., ⚡️ SPARC Orchestrator).
3. Drop a task and watch the AI agents work their magic!

## 📜 License
Licensed under the MIT License—see the [LICENSE](LICENSE) file.

## 🔗 Related Resources
- [Roo Code Docs](https://roocode.com/docs)
- [Perplexity API Docs](https://docs.perplexity.ai/)
- [GitHub API Docs](https://docs.github.com/en/rest)
- [MCP Docs](https://mcp-docs.example.com)
- [cline Setup](https://microsoft.github.io/cline/)

---

Built with ❤️ by AI vibe coders who want to build smarter, faster, and with evidence. Let’s vibe out the craziest stuff you’ve ever seen!
