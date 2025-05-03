# 🚀 Zero-Code Blueprint for SPARC AI Development (Powered by Roo Code)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Roo Code Compatible](https://img.shields.io/badge/Roo%20Code-Compatible-brightgreen)](https://roo.ai)
[![Blueprint Driven](https://img.shields.io/badge/Input-Zero--Code%20Blueprint-blue)](./Zero_Code_User_Blueprint.pdf)
[![SPARC Methodology](https://img.shields.io/badge/Methodology-SPARC%20(Reuven%20Cohen)-orange)](.)
[![Uses AI Model (e.g., Claude 3.x)](https://img.shields.io/badge/Uses-AI%20Model-orange)](https://www.anthropic.com/)
[![MCP Enabled Agents](https://img.shields.io/badge/Agents-MCP%20Enabled-purple)](https://mcp.ai)

*Based on the powerful SPARC methodology and agent definitions pioneered by Reuven Cohen.*

## 🌌 What is This? (Bridging Vision & Code with AI)

Welcome! This repository showcases a revolutionary approach to software creation: enabling **anyone with an idea (a Visionary!)** to describe their desired program in plain English using the **Zero-Code User Blueprint**, and then having a sophisticated team of AI agents (SPARC, powered by Roo Code) automatically build it.

**Forget the technical jargon!** The core idea is simple:

1.  **You (The Visionary):** Fill out the `Zero_Code_User_Blueprint.pdf`. Describe *what* your program should do, *who* it's for, and *why* it needs to exist – just like explaining it to a human team.
2.  **SPARC (The AI Team):** The `sparc_agent_roomodes.json` defines a versatile team of AI specialists (like Architects, Coders, Testers, Researchers). Guided by the SPARC Orchestrator and your Blueprint, this AI team uses deep research, analysis, and code generation to bring your vision to life.

**The Goal:** To empower non-technical users to translate their real-world needs and ideas directly into working software, letting the AI handle the complex "how".

## ✨ Key Pillars & Methodology

1.  **Zero-Code User Blueprint:** A structured template (`.pdf` included) guiding users to provide clear, detailed descriptions of their project goals, features, users, and rules in simple language. This is the **single source of truth** for the user's vision.
2.  **SPARC Orchestration:** A master AI agent (`⚡️ SPARC Orchestrator`) interprets the Blueprint, breaks down the project into logical steps, and delegates tasks to specialized AI agents defined in the Roomodes.
3.  **Specialized AI Agent Team (Roomodes):** A suite of pre-configured Roo Code modes (`sparc_agent_roomodes.json`), each with a specific role (Specification Writing, Architecture, Coding, Testing, Debugging, Security, Documentation, **Deep Research**, **Database Admin (Supabase)**, **Web Crawling (Firecrawl)**, Deployment, etc.). These agents collaborate, using tools and research (via MCP integrations) as needed.
4.  **Deep Research Integration:** The `@deep-research` and `@fire-crawler` modes empower SPARC to automatically investigate existing solutions, technical possibilities, and gather necessary context based on the Blueprint, filling knowledge gaps.
5.  **Focus on Outcomes:** The process prioritizes understanding the user's *intent* and desired *outcomes* (as defined in the Blueprint's Success Criteria) over rigid technical pre-specifications.

## 🔄 The Workflow Loop (Vision to Reality)

1.  **You:** Download and meticulously fill out the `Zero_Code_User_Blueprint.pdf`. Focus on clarity and detail in plain English.
2.  **(In Roo Code)** **You:** Provide the completed Blueprint context (e.g., copy-paste content or reference the file) to the `⚡️ SPARC Orchestrator` mode.
3.  **SPARC Orchestrator:** Reads and analyzes the Blueprint.
4.  **Deep Research & Analysis:** Orchestrator likely delegates initial tasks:
    *   `new_task @deep-research Analyze Blueprint Section [X, Y, Z]. Research similar applications, potential challenges, and best practices mentioned in Section 9.`
    *   `new_task @fire-crawler Crawl websites mentioned in Section 9 [Similar Programs] to understand their features and structure.`
    *   `new_task @spec-pseudocode Translate Blueprint Sections [1-4] and research findings into formal requirements and high-level pseudocode.`
5.  **Architecture & Design:** `new_task @architect Design the system architecture based on the specification, considering platform choices (Section 6) and data needs (Section 4). Create diagrams.`
6.  **Phased Implementation & Testing (Iterative):**
    *   `new_task @code Implement feature [Core Action from Section 3] based on spec and architecture. Handle data [Information from Section 4].`
    *   (If Database needed) `new_task @supabase-admin Setup database schema for [Data from Section 4] based on architecture. Implement RLS policies.`
    *   `new_task @tdd Write and execute tests for feature [Core Action]. Verify against [Success Criteria from Section 8].`
    *   **If FAIL:** `new_task @debug Investigate test failure for [Feature].` -> Loop back.
7.  **Integration & Final Steps:** `new_task @integration Merge components.` -> `new_task @security-review Audit code.` -> `new_task @docs-writer Create user documentation based on Blueprint sections.` -> `new_task @devops Deploy application to [Platform from Section 6].`
8.  **Result:** SPARC presents the working program, aiming to meet the Definition of Done described in your Blueprint!

## ✨ Why This Approach?

*   👩‍💻 **Empowers Non-Technical Users:** Turns ideas into software without needing to code.
*   🗣️ **Clear Communication:** The Blueprint provides a structured way to express complex ideas simply.
*   ⚡ **Accelerated Development:** Leverages AI speed for research, coding, and testing.
*   🤖 **Handles Complexity:** Abstracts away difficult technical choices and implementation details.
*   🎯 **Focus on the Vision:** Keeps development aligned with the user's original goals and success criteria.
*   🧠 **Built-in Expertise:** Utilizes specialized AI agents for high-quality architecture, code, security, and more.

## 🛠️ The Core Components

1.  📄 **The Zero-Code User Blueprint (`Zero_Code_User_Blueprint.pdf`):** The structured questionnaire for capturing the user's vision. **[Download/View Blueprint](./Zero_Code_User_Blueprint.pdf)**
2.  🤖 **The SPARC Agent Roomodes (`sparc_agent_roomodes.json`):** The JSON configuration defining the AI specialist team for Roo Code. Contains roles like Orchestrator, Deep Research, Code, TDD, Supabase Admin, Fire Crawler, etc. **[View Roomodes](./sparc_agent_roomodes.json)**
3.  🧩 **Roo Code (Environment):** The VS Code extension that runs the SPARC agents.
4.  🧠 **AI Model (Engine):** The underlying large language model (e.g., Claude 3.x) that powers the agents' reasoning and generation.
5.  🔌 **MCP (Management Control Panel):** Enables agents like Deep Research (Perplexity), Supabase Admin, and Fire Crawler to interact securely with external tools and APIs.

## 🎬 How It Works: A Simple Example

**User fills out the Blueprint:**

*   **Project Title:** Simple Recipe Finder
*   **Section 1 (Elevator Pitch):** "An app to quickly find simple recipes based on ingredients I have at home."
*   **Section 3 (Core Actions):** "Search recipes by ingredient", "View recipe steps", "Save favorite recipes".
*   **Section 4 (Information):** "Recipe names, ingredients list, instructions, user favorites list".
*   **Section 8 (Success Criteria):** "1. When I search 'chicken, rice', I see recipes using both. 2. I can click a recipe and see clear steps. 3. I can click a 'Save' button and find it later in 'My Favorites'."

**▶️ SPARC Orchestrator (in Roo Code, after receiving Blueprint):**

1.  `Thinking... Analyzing Blueprint for 'Simple Recipe Finder'.`
2.  `Delegating Research: new_task @deep-research Analyze Blueprint. Research existing simple recipe apps (Section 9), common data structures for recipes (Section 4), and UI patterns (Section 5).`
3.  `Delegating Specification: new_task @spec-pseudocode Draft formal requirements based on Blueprint and research. Outline pseudocode for 'Search', 'View', 'Save' features (Section 3).`
4.  `Delegating Database Design: new_task @supabase-admin Design schema for recipes (name, ingredients, steps) and user favorites (user_id, recipe_id). Use info from Section 4.`
5.  *(...continues assigning tasks for Architecture, Coding, Testing based on the Blueprint specifications...)*
6.  `Result: Development proceeding based directly on user's vision described in the Blueprint.`

## 🔧 Get Started

Ready to turn your vision into reality without writing code?

### Prerequisites
1.  **VS Code** + **Roo Code extension** installed.
2.  **AI Model API Key** (e.g., Anthropic for Claude). Configured in Roo Code.
3.  **(Potentially) API Keys for MCP Tools:** If your project requires deep web research, database interaction, or web crawling, you might need keys for Perplexity AI, Supabase, or Firecrawl, respectively. Setup via **[cline](https://cline.tools)** or manually in Roo Code MCP settings.

### Configuration:

1.  **Install SPARC Roomodes:**
    *   Copy the entire JSON object from the `sparc_agent_roomodes.json` file in this repository.
    *   In VS Code, go to Roo Code settings -> "Edit Global Modes".
    *   Paste the JSON, replacing any existing content. Save.
    *   Reload Roo Code (`Roo Code: Reload Custom Modes` command or restart VS Code).

2.  **Configure AI Model:**
    *   Select your preferred AI model (e.g., Claude 3.5 Sonnet) in Roo Code's model settings.

3.  **(Optional) Configure MCP:**
    *   If using Deep Research, Supabase Admin, Fire Crawler, etc., configure their respective MCP connections in Roo Code settings, likely using URLs/Headers obtained from `cline`.

### Start Building!
1.  **Download** the `Zero_Code_User_Blueprint.pdf` from this repository.
2.  **Fill it out** completely and clearly in plain English. The more detail, the better!
3.  Open a Roo Code chat in VS Code.
4.  Select your configured AI Model profile.
5.  Select the `⚡️ SPARC Orchestrator` mode.
6.  **Provide the content** of your filled-out Blueprint to the Orchestrator. (You can copy-paste sections or the whole text). Clearly state: "Here is my completed Zero-Code Blueprint. Please begin the development process."
7.  Let the SPARC AI team take over! Observe as it asks clarifying questions (if needed, though the goal is minimal interaction), researches, designs, codes, and tests based *solely* on your Blueprint.
8.  Use the `❓ Ask` mode if you need guidance on how to interact with SPARC or formulate requests during the process (though ideally, the Blueprint is comprehensive).

## 📄 The Zero-Code User Blueprint

This PDF template is the heart of the user input process. It guides you through defining:

*   **Section 1: The Big Picture** (What & Why)
*   **Section 2: The Users** (Who is it for?)
*   **Section 3: The Features** (What can it DO?)
*   **Section 4: The Information** (What data does it handle?)
*   **Section 5: The Look & Feel** (General vibe)
*   **Section 6: The Platform** (Where will it be used?)
*   **Section 7: The Rules & Boundaries** (Must-dos and don'ts)
*   **Section 8: Success Criteria** (How do we know it's right?)
*   **Section 9: Inspirations & Comparisons** (Learning from others)
*   **Section 10: Future Dreams** (Optional nice-to-haves)

**[➡️ Download the Blueprint PDF here](./Zero_Code_User_Blueprint.pdf)**

## 🤖 The SPARC Agent Army (Roomodes)

The `sparc_agent_roomodes.json` file defines the roles, instructions, and capabilities of the AI agents that will build your project. It includes specialists like:

*   `⚡️ SPARC Orchestrator`: The project manager.
*   `🔍 Deep Research Mode`: Investigates and gathers knowledge.
*   `🔥 Fire Crawler`: Scrapes and analyzes web content.
*   `📋 Specification Writer`: Translates the Blueprint into formal specs.
*   `🏗️ Architect`: Designs the system structure.
*   `🧠 Auto-Coder`: Writes the code.
*   `🧪 Tester (TDD)`: Writes and runs tests.
*   `🔐 Supabase Admin`: Manages the database (if needed).
*   `🛡️ Security Reviewer`: Checks for vulnerabilities.
*   `📚 Documentation Writer`: Creates manuals.
*   `🚀 DevOps`: Handles deployment.
*   ...and others for debugging, integration, optimization.

**[➡️ View the Agent Definitions (JSON) here](./sparc_agent_roomodes.json)**

## 🙏 Acknowledgements

This approach is heavily inspired by and utilizes the **SPARC methodology and Roomode definitions pioneered by Reuven Cohen**. His work in structuring AI agent collaboration is foundational to this framework.

## 📜 License
MIT License - see `LICENSE` file.

## 🙏 Support Development

<div align="center">
  <p>Found this blueprint and agent setup valuable? Consider supporting its continued development and refinement.</p>
  <a href="https://paypal.me/ChrisRoyseAI" target="_blank"><img src="https://img.shields.io/badge/Support_via_PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white" alt="Support via PayPal" width="250"/></a>
  <p style="margin-top: 10px;">Your support helps offset API costs and allows for further exploration of AI-driven development.</p>
  <p>Thank you!</p>
</div>

## 🔗 Related Resources
-   [Roo Code Docs](https://roo.ai/docs)
-   [Reuven Cohen on LinkedIn](https://www.linkedin.com/in/reuvencohen/) (Follow for more on SPARC & AI)
-   [MCP Standard](https://mcp.ai)
-   [cline MCP Installer](https://cline.tools)
-   [Perplexity AI](https://perplexity.ai/), [Supabase](https://supabase.com/), [Firecrawl](https://firecrawl.dev/) (Tools potentially used by agents via MCP)

---
## 👤 Connect
- [🔗 LinkedIn - Christopher Royse](https://www.linkedin.com/in/christopher-royse-b624b596/)

---

Let's build the future, one Blueprint at a time!
