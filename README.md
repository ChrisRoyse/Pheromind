# 🚀 Zero-Code SPARC AI: Your Vision, Built by AI (Powered by Roo Code & Enhanced Tooling)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Roo Code Compatible](https://img.shields.io/badge/Roo%20Code-Compatible-brightgreen)](https://roo.ai)
[![Blueprint Driven](https://img.shields.io/badge/Input-Zero--Code%20Blueprint-blue)](./Zero_Code_User_Blueprint.pdf)
[![SPARC Methodology](https://img.shields.io/badge/Methodology-SPARC%20(Reuven%20Cohen)-orange)](.)
[![AI Models (e.g., Claude 3.x)](https://img.shields.io/badge/AI%20Models-Claude%203.x/GPT--4-orange)](.)
[![MCP Enabled Agents](https://img.shields.io/badge/Agents-MCP%20Enabled-purple)](.)
[![Video Demo Included](https://img.shields.io/badge/Demo-Video%20Context-informational)](.)

**Based on the powerful SPARC methodology and foundational agent definitions pioneered by Reuven Cohen.**

---

## 🌌 What is This? (From Your Vision to Working Software, Without Code)

Welcome! This repository demonstrates and provides the tools for a groundbreaking approach to software creation. It enables **anyone with an idea (we call you the Visionary!)** to describe their desired program in plain English using the **`Zero_Code_User_Blueprint.pdf`**, and then watch as a sophisticated team of AI agents, orchestrated by **SPARC** (and powered by the Roo Code VS Code extension), automatically builds it.

**The Problem:** Bringing a software idea to life often requires deep technical knowledge, creating a barrier for entrepreneurs, subject-matter experts, and creative thinkers.

**Our Solution:** We bridge this gap! This repository offers:

1. **A Structured Input:** The `Zero-Code_User_Blueprint.pdf` translates your vision into a format AI can understand, without you writing a single line of code.
2. **An Intelligent AI Workforce:** The `sparc_agent_roomodes.json` defines a versatile team of specialized AI agents (Architects, Coders, Testers, Researchers, Database Admins, Web Crawlers, etc.), ready to execute your blueprint using the robust **SPARC methodology**.
3. **Enhanced Tooling & Research:** This configuration integrates powerful **Deep Research** (using Perplexity) and **Web Crawling** (using Firecrawl) agents directly into the SPARC workflow. It also includes pre-researched documentation (like the Spark Report, Workflow, and "Uber Prompt" demonstrated in the included video context) to kickstart AI understanding and prompt generation for common development tasks.
4. **Streamlined SPARC Implementation:** This project bundles necessary SPARC modes (like Deep Research and Firecrawler) and provides clear documentation (`SPARC_Universal_Workflow.md`) on how to apply the methodology effectively within the Roo Code environment.

**The Goal:** To empower *you*, the Visionary, to transform your ideas into functional software by leveraging cutting-edge AI collaboration, making the powerful SPARC framework more accessible and even more potent through structured input and integrated research.

*The process and tools demonstrated here were showcased in the accompanying video (transcript context included or video linked).*

---

## ✨ Key Pillars & How It Works

This system rests on several key pillars:

1. **Zero-Code User Blueprint:** Your starting point. A detailed questionnaire (`.pdf` included) designed for non-technical users to articulate their project goals, target audience, desired features, essential rules, and success criteria in plain English. *This becomes the primary input for the AI team.*
2. **SPARC Methodology (by Reuven Cohen):** The core operational framework – **S**pecification, **P**seudocode, **A**rchitecture, **R**efinement, **C**ompletion. This structured approach ensures a logical flow from idea to deployment, managed by the Orchestrator.
3. **SPARC Orchestrator (⚡️ Mode):** The AI project manager. It interprets the Blueprint, consults the integrated research documents, breaks down the project using the SPARC workflow (`SPARC_Universal_Workflow.md`), and delegates tasks to specialized AI agents.
4. **Specialized AI Agent Team (Roomodes):** Defined in `sparc_agent_roomodes.json`, this is your AI development team. Each agent (mode) has a specific role, instructions, and access to tools (like coding, testing, security scanning, database management, research via MCP). We've included and integrated essential agents like Deep Research, Fire Crawler, and Supabase Admin.
5. **Integrated Deep Research & Context:** The `🔍 Deep Research` and `🔥 Fire Crawler` agents proactively gather external knowledge. Furthermore, the included documents (Spark Report, Workflow, Uber Prompt from the video demo) provide immediate, rich context to the AI, significantly enhancing its ability to plan and generate relevant prompts and code, especially for AI-assisted development tasks themselves.
6. **Outcome-Driven Development:** The focus is squarely on achieving the goals and `Success Criteria` you define in the Blueprint. The AI figures out the technical "how" based on your desired "what" and "why".

---

## 🔄 Conceptual Workflow: From Your Brain to AI-Built App
```
    A[You (Visionary)] -- Fills out --> B(Zero-Code Blueprint PDF);
    B -- Provides content to --> C{⚡️ SPARC Orchestrator (in Roo Code)};
    C -- Uses --> D[📄 SPARC Workflow Doc];
    C -- Consults --> E[📚 Enhanced Docs (Spark Report, Uber Prompt, etc.)];
    C -- Delegates Task 1 --> F 🔍 Deep Research;
    F -- Gathers Info --> C;
    C -- Delegates Task 2 --> G(📋 Specification Writer);
    G -- Creates Specs --> C;
    C -- Delegates Task 3 --> H(🏗️ Architect);
    H -- Designs System --> C;
    C -- Delegates Tasks (Iterative) --> I(🧠 Code / 🧪 TDD / 🔐 Supabase Admin / etc.);
    I -- Builds & Tests --> C;
    C -- Delegates Final Tasks --> J(🔗 Integrator / 🛡️ Security / 📚 Docs / 🚀 DevOps);
    J -- Finalizes & Deploys --> K{✅ Working Program!};
    K -- Matches --> L(🎯 Success Criteria from Blueprint);
```

---

## 🛠️ The Core Components in This Repository

* **📄 Zero_Code_User_Blueprint.pdf:** The essential questionnaire for capturing your vision. This is your primary interaction point. 
  ➡️ [Download/View Blueprint](./Uber Prompt SPARC.pdf)
  
* **🤖 sparc_agent_roomodes.json:** The JSON configuration defining the specialized AI agents for Roo Code. Includes the SPARC orchestrator and critical modes like Deep Research, Fire Crawler, Supabase Admin, and more, integrating the concepts from the video.
  ➡️ [View Agent Definitions (JSON)](./roomodes.json)
  
* **🧩 SPARC_Universal_Workflow.md:** A detailed guide outlining the step-by-step SPARC process leveraging these Roomodes and research capabilities, from conception to deployment and maintenance.
  ➡️ [Read the Workflow Guide](./SPARC Development Workflow.md)
  
* **📚 Enhanced Context Documents** (From Video Demo - Contained within this Repo or referenced):
  * **Spark Report:** Deep research findings on using Spark effectively with AI. (Example of Deep Research output)
  * **Spark Development Workflow:** A specific process document generated using AI. (Example artifact)
  * **"Uber Prompt":** A comprehensive starting prompt for AI program generation. (Example artifact)
  
  These demonstrate the power of using AI to generate documentation and context for subsequent AI tasks, as discussed in the video.
  
* **💡 Video Context (Implicit):** The transcript/summary/link related to the original video explaining the genesis of these tools and demonstrating their use.

---

## 🚀 Get Started: Build Your Idea!

Ready to bring your vision to life using AI? Follow these steps:

### Prerequisites

1. **Visual Studio Code:** The code editor. Install it from [code.visualstudio.com](https://code.visualstudio.com).
2. **Roo Code Extension:** Install this directly from the VS Code Marketplace. Search for "Roo Code".
3. **AI Model API Key:** You'll need an API key from a supported provider (e.g., Anthropic for Claude models, OpenAI for GPT models). Configure this within the Roo Code extension settings.
4. **(Optional but Recommended for Full Power) MCP Tooling Keys:** To enable the `🔍 Deep Research` (Perplexity AI), `🔥 Fire Crawler`, and `🔐 Supabase Admin` agents, you will likely need API keys for these services. The easiest way to manage these is often via cline (if available/applicable) or manual configuration in Roo Code's MCP settings. Check Roo Code documentation for details.

### Configuration

1. **Install SPARC Roomodes:**
   * Open the `sparc_agent_roomodes.json` file from this repository.
   * Copy the entire JSON content.
   * In VS Code, open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`).
   * Run the command: `Roo Code: Edit Global Modes`.
   * Paste the copied JSON into the `roomode.json` file that opens, completely replacing its previous content.
   * Save and close the file.
   * **Reload Roo Code:** Run the command `Roo Code: Reload Custom Modes` or simply restart VS Code.

2. **Configure AI Model:**
   * In Roo Code settings, select the AI model you have an API key for (e.g., Claude 3.5 Sonnet via Anthropic). Ensure the corresponding API key is entered.

3. **(Optional) Configure MCP Connections:**
   * Follow Roo Code's documentation to configure Management Control Panel (MCP) connections for Perplexity AI, Firecrawl, and Supabase if you intend to use those agents heavily. This usually involves providing API keys and potentially server endpoints via cline or the settings UI.

### Let's Build!

1. **Download & Complete the Blueprint:**
   * Download the `Zero_Code_User_Blueprint.pdf`.
   * Fill it out thoroughly and thoughtfully in plain English. Provide details, examples, and clear success criteria. The quality of your Blueprint directly impacts the quality of the AI's output.

2. **Start Roo Code Chat:**
   * Open VS Code.
   * Open a new Roo Code chat panel (usually via an icon in the activity bar or a command).

3. **Select Profile & Mode:**
   * Ensure your configured AI Model profile is active.
   * From the "Mode" dropdown in the Roo Code chat, select the `⚡️ SPARC Orchestrator` mode.

4. **Provide Your Blueprint:**
   * In the chat input, paste the complete text content of your filled-out Blueprint.
   * Precede it with a clear instruction, like:
   
   ```
   Hello SPARC! Here is my completed Zero-Code Blueprint. Please analyze it, perform any necessary research using the integrated tools and documents, and begin the development process following the SPARC methodology outlined in the workflow document. Build this vision for me.
   
   [--- PASTE YOUR ENTIRE FILLED BLUEPRINT TEXT HERE ---]
   ```

5. **Observe & Guide (Minimally):**
   * The SPARC Orchestrator will now begin analyzing, researching, and delegating tasks to the other AI agents. It will use the `SPARC_Universal_Workflow.md` as its guide.
   * Watch the process unfold in the chat. The goal is for the AI to proceed autonomously based on the Blueprint. It might ask clarifying questions if the Blueprint is ambiguous, but aim for completeness in your initial input.
   * If you need guidance during the process, you can switch to the `❓ Ask` mode for help on formulating requests or understanding SPARC.

6. **Receive Your Application:** The AI team will work through the SPARC phases, eventually aiming to present you with a functional application that meets the Success Criteria defined in your Blueprint!

---

## 🙏 Acknowledgements & Gratitude

This entire framework and workflow is built upon the pioneering work of **Reuven Cohen**.

* The **SPARC** (Specification, Pseudocode, Architecture, Refinement, Completion) methodology is his conceptual framework for structured AI software development.
* The foundational definitions and roles of the specialized AI agents (Roomodes) originate from his designs and implementations.

This repository aims to make Reuven's powerful SPARC vision more accessible and practical by providing:

* A clear Zero-Code entry point (the Blueprint) for non-technical users.
* Integrated Deep Research and Web Crawling capabilities within the SPARC flow.
* Pre-packaged documentation and examples (like the Spark Report/Workflow/Prompt) demonstrated in the video to enhance AI context.
* A consolidated and documented set of Roomodes for easy setup in Roo Code.

**Thank you, Reuven Cohen, for laying the groundwork for this exciting future of AI-driven development!**

Follow Reuven Cohen for more insights: 🔗 [Reuven Cohen on LinkedIn](https://www.linkedin.com/in/reuvencohen/)

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔗 Related & Helpful Resources

* [Roo Code Information (Official Docs/Blog)](https://roo.ai)
* [Reuven Cohen's SPARC Articles/Posts](https://www.linkedin.com/in/reuvencohen/) 
* [Perplexity AI](https://www.perplexity.ai/)
* [Firecrawl](https://firecrawl.dev/)
* [Supabase](https://supabase.com/)

---

## 👤 Connect With Me

🔗 [LinkedIn - Christopher Royse](https://www.linkedin.com/in/christopherroyse/)

---

**Let's build amazing things together! Provide your Blueprint and let the AI work its magic. ✨**
