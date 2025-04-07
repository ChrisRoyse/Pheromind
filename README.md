# 🚀 Unleash AI Vibe Coding: RooModes + Perplexity + GitHub Superpowers!

[![Watch the Demo!](https://img.youtube.com/vi/R86yXPuA7Qs/maxresdefault.jpg)](https://youtu.be/R86yXPuA7Qs)  
(Click Above to See the Magic In Action!)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Roo Code Compatible](https://img.shields.io/badge/Roo%20Code-Compatible-brightgreen)](https://roo.ai)
[![Perplexity API](https://img.shields.io/badge/Perplexity-API-blue)](https://perplexity.ai)
[![GitHub Tools](https://img.shields.io/badge/GitHub-Tools-purple)](https://github.com)
[![cline MCP Installer](https://img.shields.io/badge/cline-MCP%20Installer-orange)](https://cline.tools)

## 🎧 What is This? (The Vibe Explained)

Say goodbye to blind coding and outdated practices! This repository delivers a complete framework for AI-powered "vibe coding", blending Roo Code's multi-agent boomerang system with Perplexity's real-time research prowess and GitHub's full repository toolkit via the Model Context Protocol (MCP).

Here's the vibe: You dream up an idea. You kick off some deep research—researching how to research, then diving into your concept. Feed a plan to your AI crew, and then... just vibe. Watch a squad of specialized agents take over:

- Orchestrators run the show.
- Research Specialists tap Perplexity for the latest best practices, APIs, and docs.
- Git Managers handle repos, branches, and commits on GitHub.
- Coders, Architects, Testers, Reviewers, Documenters, DevOps (shoutout to DevOps!) and more crush their tasks, all backed by real-time data and slick coding principles.

This isn't just autocomplete. It's research-backed, automated, full-lifecycle development powered by AI agents vibing together seamlessly. Boom shaka lockaka!

## 🔄 NEW: Predictive Research Methodology

I've made a significant upgrade to our core methodology! The AI coding assistants now operate on a Predictive Research Methodology:

### 🔮 Predict Problems Before They Happen

Before any major design or coding action, AI agents now:

- 🔍 **Research Potential Problems**: Use Perplexity AI (search, get_documentation) to investigate pitfalls, edge cases, security vulnerabilities, and best practices specific to the task.
- 💾 **Analyze Context**: Review existing codebase, history, and similar patterns using GitHub tools (search_code, list_commits).
- ❗ **Active Prediction**: Forecast potential issues based on research before generating solutions.

This approach significantly reduces issues downstream, resulting in cleaner code from the start. And the best part? The coding instructions are only 160 tokens!

## ✨ Why It's a Game Changer

Old-school AI coding tools lack context and fumble best practices. This system flips the script:

- 🧠 **Never Code Blind Again**: Perplexity's real-time research validates every move against current standards and examples—catch deprecated code before it's written.
- 🐙 **Automate Your Entire GitHub Workflow**: Programmatically manage repos, branches, issues, and PRs right from your AI flow.
- ✅ **Evidence-Based Quality**: Code decisions are rooted in research, delivering secure, modern, and efficient solutions.
- 💻 **Full Lifecycle Coverage**: Agents handle it all—research, architecture, coding, testing, docs, CI/CD, deployment, and monitoring.
- 💸 **Cost-Effective**: Potentially free with models like Gemini 1.5 Flash/Pro (when available via API), with Perplexity API costs as low as $0.80 for a full day of heavy research. GitHub MCP tools? Free!

## 🛠️ The Core Components

This framework fuses cutting-edge tools into one powerhouse:

### 1. The Multi-Agent Army (.roomodes) 🤖

A squad of specialized AI personas defined in the .roomodes file (included here):

- ⚡️ **SPARC Orchestrator**: The maestro, syncing Perplexity research with GitHub actions.
- 🔍 **Research Specialist**: Dives into Perplexity and GitHub for up-to-date insights.
- 🔄 **Git Manager**: Runs GitHub like a pro—repos, branches, commits.
- 🧐 **Code Reviewer**: Delivers research-backed code critiques.
- 🏗️ **Architect**, 🧠 **Coder**, 🧪 **Tester**, 🛡️ **Security Reviewer**, 📚 **Docs Writer**, 🔗 **Integrator**, 🚀 **CI/CD Engineer**, 📈 **Monitor**, 🧹 **Optimizer**, 🚀 **DevOps**—each a master of their craft.

(Check .roomodes for the full lineup!)

### 2. Perplexity Research Power 💡

Tap Perplexity's MCP tools right in your workflow:

- **chat_perplexity**: Keeps research context alive across tasks.
- **search**: Deep dives on any topic.
- **get_documentation**: Grabs the latest docs.
- **find_apis**: Uncovers integration options.
- **check_deprecated_code**: Keeps your code current.

### 3. GitHub Sidekick (MCP Tools) 🐙

Run GitHub without breaking a sweat:

- **Repo Ops**: create_repository, fork_repository
- **File Ops**: create_or_update_file, push_files, get_file_contents
- **Branching**: create_branch, list_commits
- **Issues/PRs**: create_issue, update_issue, create_pull_request, get_pull_request_files
- **Discovery**: search_code, search_repositories

### 4. Predictive Coding Principles 🎯

Token-efficient coding rules—shrinking complex best practices to just 160 tokens! Loaded into Roo Code's "Custom Coding Instructions (All Modes)," these guide every agent using our new Predictive Research Methodology:

```
*Predictive Research Methodology*
↹ predict•problems
⊕ search => pitfalls•vulnerabilities
⊕ search_code => errors•patterns
⊕ list_commits => history•context
⊕ predict => solve•document
```

## 🎬 See It In Action (Usage Examples)

### Example 1: Predictive Research in Action

**User**: "Let's build a Supabase-backed influencer marketing tracker with Next.js and TypeScript."

**SPARC Orchestrator**: "Time to vibe! 🚀 First, let's predict potential issues:

1. Research Specialist hits Perplexity (search) for Supabase/Next.js pitfalls.
2. Found: Auth token storage vulnerabilities, rate limiting concerns, pagination edge cases.
3. Git Manager checks (search_code) for similar implementations.
4. Architect documents predicted issues and mitigation strategies.
5. Now starting solution design with these insights...

Repo 'influencer-tracker' is live with initial architecture accounting for predicted issues!"

### Example 2: AI-Powered Predictive Code Review

**User**: "Review this login function in auth.ts. Is it secure? Suggestions?"

**Code Reviewer**: "On it! 🧐 Let me predict security issues first:

1. Researching OWASP auth vulnerabilities via Perplexity (search).
2. Checking similar auth patterns in the codebase (search_code).
3. Predicted issues: Missing rate limiting, potential for timing attacks, no CSRF protection.
4. Creating a PR (create_pull_request) with fixes for predicted vulnerabilities!
5. Added comprehensive tests to validate mitigations."

## 🔧 Get Started (Easier Than You Think!)

Ready to vibe? Here's the setup:

### Prerequisites
- VS Code with the Roo Code extension.
- Perplexity API key.
- GitHub Personal Access Token (scopes: repo, workflow, issues, etc.).

### Easiest MCP Setup: Use cline!
1. Install cline.
2. Search for "Perplexity AI" and "GitHub" MCP providers in cline.
3. Hit "Install" for each—cline's AI sets up the servers (may prompt for API keys).
4. Copy the MCP settings (URLs, headers/tokens) from cline's output.

### Configure Roo Code
1. Open Roo Code settings in VS Code.
2. Paste Perplexity and GitHub MCP details from cline into the MCP settings section.
3. Grab the predictive_coding_principles.md content from this repo.
4. Paste it into "Custom Coding Instructions (All Modes)" in Roo Code settings.

### Install the RooModes
1. Copy the .roomodes file from this repo to your project's root.
2. Optional: Save modes globally via Roo Code's UI/CLI.

### Start Vibing!
1. Open a Roo Code chat in VS Code.
2. Pick a mode (e.g., ⚡️ SPARC Orchestrator).
3. Drop a task and watch the AI agents predict problems and work their magic!

## 📜 License
Licensed under the MIT License—see the LICENSE file.

## 🔗 Related Resources
- [Roo Code Docs](https://roo.ai/docs)
- [Perplexity API Docs](https://perplexity.ai/api)
- [GitHub API Docs](https://docs.github.com/en/rest)
- [MCP Docs](https://mcp.ai/docs)
- [cline Setup](https://cline.tools)

Built with ❤️ by AI vibe coders who predict problems before they happen. Let's vibe out the craziest stuff you've ever seen!
