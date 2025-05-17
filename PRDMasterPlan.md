**Product Requirements Document / Master Plan**

**CodeGraph: Ontology-Driven Code Knowledge Graph with Historical Analysis Capabilities**

---

## 1. Introduction & Vision

### 1.1. Project Title
CodeGraph: Ontology-Driven Code Knowledge Graph with Historical Analysis Capabilities

### 1.2. Executive Summary
CodeGraph is a system designed to automatically parse, understand, model, and **track the evolution of** complex, polyglot (multi-language) codebases as a comprehensive, versioned knowledge graph. It aims to function as a "Google Maps for code, through time," enabling development teams to rapidly discover code structures, analyze inter-component dependencies (including external libraries and intra-procedural control flow), assess the impact of changes, **and understand the historical evolution of their software**. By providing a queryable, ontology-driven, and near real-time representation of both the current and historical states of code, CodeGraph will significantly enhance code comprehension, accelerate development cycles, improve code quality, streamline developer onboarding, and lay the foundation for future AI/ML-driven code intelligence. The entire system is designed to be deployed and run efficiently within a Docker Desktop environment using Docker Compose, with careful consideration to avoid common port conflicts. Neo4j, when accessed from the host, will use ports `7921` (Bolt), `7922` (HTTP), and `7923` (HTTPS).

### 1.3. Problem Statement
Modern software development involves increasingly large, complex codebases that evolve rapidly. Understanding not only the current state but also the history of changes, dependencies, and control flow is crucial. Developers, architects, and QA engineers expend considerable time manually navigating code, deciphering its evolution, and managing dependencies. This manual effort results in:
*   **Slowed Development Velocity:** Significant time is lost in code discovery, understanding historical context, control flow, and impact analysis.
*   **Increased Risk of Bugs:** Misunderstanding historical changes, dependencies, or complex control flows can introduce errors or regressions.
*   **Difficult Onboarding & Knowledge Transfer:** New developers struggle to grasp not just the current system but also why it is structured the way it is, based on past decisions.
*   **Architectural Drift & Technical Debt Accumulation:** Without a clear view of how architecture and dependencies evolve, maintaining integrity and managing debt is challenging.
*   **Inefficient Refactoring & Debugging:** Identifying safe refactoring opportunities or the root cause of regressions is difficult without historical context.
*   **Cross-Language Blind Spots & Dependency Management Overheads:** Understanding interactions and managing third-party libraries over time is arduous.
Existing tools often provide partial solutions, lack deep control flow insights, offer limited build system awareness, do not adequately capture or expose code evolution, or are not easily deployable in a local, containerized environment.

### 1.4. Proposed Solution & Core Value Proposition
CodeGraph will address these problems by:
1.  **Parsing Multiple Languages, Build Systems, & Version Control History:** Ingesting and analyzing source code, common build system files, and **Git commit history** to extract declared external dependencies and track changes over time.
2.  **Building a Rich, Versioned Knowledge Graph:** Constructing an extensive graph database (Neo4j, running in Docker on non-standard ports for host access) where code entities, CFG elements, external libraries, and **commits** are nodes, and their relationships are edges, with mechanisms to represent changes across versions.
3.  **Ontology-Driven Modeling:** Defining a clear, extensible ontology for code elements, control flow constructs, dependency relationships, and **versioning concepts**.
4.  **Providing Query Capabilities for Current & Historical States:** Offering powerful API and CLI access to query the knowledge graph, enabling complex questions about current code structure, dependencies, control flow, impact, **and its evolution over specified commits or timeframes**.
5.  **Near Real-Time Updates & Historical Ingestion:** Monitoring configured codebases for new commits/changes and incrementally updating the knowledge graph, associating new states with commit information.
6.  **Foundation for AI/ML:** Structuring and storing versioned graph data in a manner that enables future development of AI/ML models for predictive analysis and anomaly detection.
7.  **Dockerized Deployment:** All components are containerized and orchestrated using Docker Compose. Neo4j will use host ports `7921` (Bolt), `7922` (HTTP), and `7923` (HTTPS).

**Core Value Proposition:** CodeGraph will empower development teams with unprecedented clarity and insight into their codebases, encompassing structure, control flow, external dependencies, **and their historical evolution**. It transforms how they interact with, understand, and evolve their software, all within their local Docker environments. This will lead to:
*   Drastically Reduced Time for Code Comprehension and **Historical Investigation**.
*   Improved Developer Productivity through better context and impact analysis.
*   Enhanced Code Quality & Reliability by understanding change propagation and identifying historical regression points.
*   Faster & Smoother Onboarding with access to project history and rationale.
*   Data-Driven Architectural, Refactoring, and Dependency Management Decisions, informed by evolutionary trends.
*   **Enabling Future AI/ML-Driven Insights** by systematically capturing versioned code data.
*   Simplified Local Deployment on Docker Desktop.

### 1.5. Goals & Objectives
The primary goal of CodeGraph (Version 1.0) is to provide a robust backend system capable of parsing multiple languages, their common build files, and Git commit history to construct an accurate, version-aware code knowledge graph including control flow and external dependencies. It will offer powerful query capabilities for both current and basic historical states via an API and CLI, all deployable via Docker Compose, and will capture data to enable future AI/ML features.

| ID  | Goal                                                                                             | Objective (SMART)                                                                                                                                                                                                                                                                                                                                                                                      | Metric                                                                                                                                                                  | Target (v1.0)                                                                                                                                       |
|-----|--------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| G1  | Establish core parsing (code, CFG, build files) and **version-aware graph construction**.        | **S:** Implement parsers for 3 initial key languages (e.g., Python, Java, JavaScript) capable of extracting core entities and basic control flow graph (CFG) elements. Implement parsers for 2-3 common build system files (e.g., `package.json`, `requirements.txt`, `pom.xml`). Enhance File Watcher to detect Git commits and extract metadata (hash, parent, author, timestamp). **M:** Successfully parse projects and their Git history, populating Neo4j (accessible on host Bolt port `7921`) with versioned code structures, CFGs, dependencies, and `Commit` nodes. **A:** Feasible with focused effort. **R:** Core to CodeGraph's enhanced value. **T:** Within 10 months.                                                                                                                                      | Languages, build systems, Git history depth supported; Graph accuracy for entities, CFGs, dependencies, and commit linkages.                                        | 3 languages, 2-3 build systems, basic Git commit tracking; 90% accuracy for entities, 80% for CFG/dependencies, 95% for commit metadata capture. |
| G2  | Enable effective code discovery, dependency, control flow, and **basic historical analysis**.    | **S:** Develop API/CLI endpoints for querying current relationships, dependencies, CFGs, and **listing commits or changes to key entities over recent history**. **M:** Users can answer predefined questions about current state and basic evolution. **A:** API/query development extended for versioning. **R:** Key user need. **T:** Within 11 months.                                                                                                                                                             | Query completion rate; User task success rate for scenarios including basic historical queries (e.g., "when did this function last change?").                                | 99% query success; Users can complete 10 key scenarios (including 2 new ones for basic history).                                                  |
| G3  | Ensure near real-time reflection of **committed code changes** in the versioned graph.           | **S:** File Watcher (Dockerized) detects new Git commits, triggering incremental parsing and graph updates, associating changes with commit data. **M:** Changes from new commits reflected in graph within X minutes. **A:** Complex incremental processing for versioned graph. **R:** Critical for usability. **T:** Within 12 months.                                                                                                                                                             | Graph update latency from commit to versioned graph update.                                                                                                             | < 5 minutes for typical commits (P95).                                                                                                              |
| G4  | Design for extensibility, maintainability, and **future AI/ML data needs**.                      | **S:** Modular architecture for parsers. Clear ontology evolution process. **Store versioned graph data in a structure conducive to future AI/ML analysis (e.g., sequences of changes, component metrics over time).** **M:** Documented processes and data schema for AI/ML readiness. **A:** Architectural priority. **R:** Future-proofing. **T:** Throughout development.                                                                                                                                                              | Time to integrate new parsers; Clarity of ontology/versioning; Documented data schema for AI/ML.                                                        | New parser integration documented; Versioning strategy clear; Data schema for AI/ML defined.                                                        |
| G5  | Deliver a stable and reliable backend platform on Docker Desktop.                                | **S:** Ensure Docker Compose stack is stable, data integrity for versioned graph. **M:** System uptime, data consistency. **A:** Standard DevOps/testing. **R:** Foundational. **T:** Continuous.                                                                                                                                                                                                                                                                                                      | API Uptime (during use); Zero critical data loss (current and historical).                                                                              | 99.9% uptime (during use); Zero critical data loss.                                                                                                 |

### 1.6. Scope
#### In Scope (Version 1.0):
*   **Core Parsing Engine:** Support for an initial set of 3-5 programming languages (e.g., Python, Java, JavaScript, TypeScript, Go). Focus will be on parsing syntactically correct code.
    *   Extraction of **Control Flow Graph (CFG) elements** (basic blocks, successor/branch relationships) for functions/methods in supported languages.
*   **Build System Integration (Basic):** Parsers for common build/dependency management files (e.g., `package.json` for Node.js, `requirements.txt`/`pyproject.toml` for Python, `pom.xml` for Maven Java, `build.gradle` for Gradle Java/Kotlin) to extract declared external library dependencies.
*   **Version Control Integration (Git - Basic):**
    *   File Watcher detects new commits in monitored Git repositories.
    *   Extraction of commit metadata: hash, parent hash(es), author name/email, committer name/email, author date, committer date, and full commit message.
    *   Association of parsed code/build file states with specific `Commit` nodes in the graph.
*   **Knowledge Graph Construction (Versioned):** Building a Neo4j graph (database name: `codegraph`) based on a defined ontology, including nodes for CFG elements, external dependencies, and `Commit` nodes. Entities and relationships will be linked to commits to represent their state at different versions (e.g., via properties indicating commit ranges or relationships to `Commit` nodes).
*   **Ontology Management:** A defined process for managing and evolving the code ontology, extended to include `Commit` entities and versioning relationships/properties.
*   **Global Unique IDs (GIDs) & Canonical IDs:** Implementation of robust GID and Canonical ID generation for all graph elements, ensuring conceptual entities can be tracked across versions.
*   **API & CLI:**
    *   Endpoints for configuring codebase monitoring (including Git repository specifics like branch to track and initial history import depth).
    *   Endpoints/commands for triggering scans (which will process commit history from the last known point or a specified range).
    *   Endpoints/commands for querying current state of code entities, relationships, **CFG paths**, and **declared external dependencies**.
    *   **Basic historical query endpoints:** e.g., list commits for a repository, view properties of an entity as of a specific commit (if directly versioned), list files changed in a commit.
    *   Basic API authentication and authorization.
*   **Real-time Monitoring & Incremental Updates (Commit-based):** The File Watcher service triggers updates based on new Git commits. For non-Git monitored paths, updates are based on file modification timestamps as a simpler version proxy.
*   **Handling Unresolved Dependencies & External Libraries:** Mechanism for representing internal code dependencies that span unparsed modules and for noting external library dependencies as declared in build files.
*   **Microservices Architecture:** Backend implemented as a set of communicating microservices, each running in a Docker container.
*   **Containerized Deployment:** All services, including Neo4j, PostgreSQL, and RabbitMQ, containerized using Docker, with Docker Compose for orchestration on Docker Desktop.
*   **Basic Logging and Monitoring:** For system health and troubleshooting within the Docker environment, accessible via Docker logs.
*   **Data Storage:**
    *   **Neo4j:** Running in Docker. Username: `neo4j`, Password: `test1234`, Database: `codegraph`. Connection for services: `bolt://codegraph-neo4j:7689` (Docker network alias). Host access for tools: `bolt://localhost:7921` (Bolt), HTTP on `http://localhost:7922`, and HTTPS on `https://localhost:7923`. Stores the versioned graph.
    *   **PostgreSQL:** Running in Docker. A dedicated database for CodeGraph metadata (e.g., `codegraph_metadata`) will be automatically created. Host access, if mapped, on a configurable port (e.g., `localhost:5433` if default `5432` is in use). Stores commit metadata details, configurations, job queues.
*   **Message Queue:** RabbitMQ, running in Docker, automatically created and configured by Docker Compose. Host access for management UI, if mapped, on a configurable port (e.g., `localhost:15673` if default `15672` is in use).
*   **File Watcher Service:** Runs in its own Docker container, enhanced for Git commit detection and metadata extraction, monitoring host paths via volume mounts.
*   **Supported Code Entities (Initial Focus):** Files, Modules/Packages, Functions/Methods, Classes/Interfaces/Structs, Variables (global, class members), Parameters, Return Types, **BasicBlocks**, **ExternalLibraries**, **Commits**.
*   **Supported Relationships (Initial Focus):** `IMPORTS`, `DEFINES_FUNCTION`, `DEFINES_CLASS`, `DEFINES_VARIABLE`, `CALLS_FUNCTION`, `INSTANTIATES_CLASS`, `INHERITS_FROM`, `IMPLEMENTS_INTERFACE`, `USES_TYPE`, `RETURNS_TYPE`, `HAS_PARAMETER`, **`FIRST_BLOCK`**, **`NEXT_BLOCK`**, **`BRANCHES_TO`**, **`CONTAINS_BLOCK`**, **`DECLARES_DEPENDENCY`**, **`HAS_COMMIT`** (linking a repository to its commits), **`PARENT_COMMIT`** (linking a commit to its parents), **`ENTITY_MODIFIED_IN_COMMIT`** (or a similar mechanism to link entity versions to commits).
*   **Data Capture for Future AI/ML:** The versioned graph structure and commit history (entity changes over commits, CFG metrics over time, dependency evolution) will provide the foundational dataset for future AI/ML tasks like predictive analysis of change impact or bug likelihood, and anomaly detection in code evolution patterns. The actual AI/ML models and complex predictive features are out of scope for v1.0; the focus is on capturing the necessary data.

#### Out of Scope (Version 1.0):
*   **Cloud Provider Services:** No direct integration with or reliance on cloud provider-specific services.
*   **Automated Kubernetes Deployment Scripts:** The primary focus is Docker Compose for Docker Desktop.
*   **Web-based User Interface (UI) for graph visualization/exploration.** (The API will be designed to support a future UI).
*   **Advanced AI-powered query suggestions, Natural Language Querying, fully implemented predictive models or complex anomaly detection algorithms.** (Only data foundation is in scope).
*   **IDE Integrations (Plugins).**
*   **Automated detection of complex anti-patterns or architectural violations** (beyond what can be achieved with direct graph queries on the v1.0 ontology and versioned data).
*   **Deep Semantic Analysis for Bug Detection (like static analyzers).**
*   **Full graph state reconstruction for any arbitrary past commit with full queryability as if it were the current state.** (v1.0 may offer properties of entities as of a commit, or list changes, but not a complete "time travel" query interface for the entire graph state).
*   **Detailed diffing of code entity content (e.g., line-by-line changes) between commits within CodeGraph.** (Focus is on linking entities to commits where they were changed and capturing their parsed state at that commit).
*   **Advanced Data Flow Analysis / Taint Tracking** (beyond what basic CFG structure enables directly).
*   **Support for all possible programming languages, all build systems and their complex configurations, or all version control systems (Git is the focus for historical analysis).**
*   **User-defined custom parsers through the UI/API.**
*   **Advanced security features like fine-grained access control on graph elements or parser sandboxing beyond basic container isolation and API key authentication.**
*   **Analysis of comments for semantic meaning or task linking.**
*   **Resolution of transitive external dependencies or checking for version conflicts between libraries.** Focus is on directly declared dependencies and their specified version strings as captured from build files.
*   **Execution of build scripts or compilation of code.** Analysis is static.
*   **Handling of extremely complex Git histories (e.g., octopus merges with many conflicting changes) with full fidelity in v1.0.** Initial support will focus on more common commit patterns along primary branches.

---

## 2. Target Audience & User Personas

### 2.1. Primary Users
*   **Software Developers (Mid-Level to Senior):** Developers actively working on coding, debugging, and refactoring tasks within medium to large, potentially polyglot, codebases. They need to quickly understand unfamiliar code, trace control flow, manage external library dependencies, **and understand the history of changes to specific components** using CodeGraph running on their Docker Desktop.
*   **Software Architects:** Responsible for designing, maintaining, and evolving the overall system architecture. They need a high-level view of component interactions, Control Flow Graphs for critical execution paths, an understanding of external library usage across the system, **and how these architectural elements and dependencies have evolved over time**, queryable through CodeGraph.
*   **Technical Leads:** Oversee development teams and projects. They need to understand code structure, control flow, dependency landscapes, **and commit history** for planning, delegation, risk assessment, root cause analysis of regressions, and ensuring code quality, leveraging CodeGraph's insights.

### 2.2. Secondary Users
*   **DevOps Engineers:** Interested in service dependencies, including understanding the footprint of third-party libraries **and how these dependencies change across software versions (commits)**, for local or on-premises deployment orchestration and for creating consistent development/testing environments.
*   **QA Engineers / Testers:** Use Control Flow Graph insights for designing test cases that achieve better path coverage and use dependency information and **change history between commits** for more targeted integration test planning and regression analysis.
*   **Security Analysts (Basic Use):** May use the graph to trace component connectivity, identify the usage of known vulnerable external libraries, **and understand how and when such libraries might have been introduced or updated over time by examining commit history**.
*   **Product Managers (Technical):** May use the system to gain a high-level understanding of feature implementation complexity, including reliance on external components, the intricacy of core logic paths, **and the evolution of features by tracking related code changes across commits**.

### 2.3. User Goals & Motivations (User Stories)

**Persona 1: Sarah, Mid-Level Software Developer**
*   **Goal:** Understand a new microservice she needs to contribute to, including its logic flow, dependencies, and recent evolution.
*   **Motivation:** Get up to speed quickly to deliver her first feature in the new service. Avoid breaking existing functionality, introducing problematic dependencies, or conflicting with recent changes.
*   **User Stories:**
    *   "As Sarah, a developer new to `ServiceX`, I want to quickly identify its main modules, key classes/functions, its primary external library dependencies (e.g., from `package.json`), view the control flow of critical functions, **and see the last few commits that modified these areas** using CodeGraph on my Docker Desktop (connecting to Neo4j on host Bolt port `7921`), so that I can understand its current scope, logic, recent history, and how it fits into the larger system."
    *   "As Sarah, when debugging a complex issue or a regression in `function_A`, I want to trace its control flow graph, see which external libraries it might interact with (based on imports and declared dependencies), **and review the commit history where `function_A` was changed**, via CodeGraph, so I can pinpoint the source of the problem more effectively."
    *   "As Sarah, before refactoring `class_B`, I want to find all usages of `class_B`, understand which functions within it have complex control flows by examining their CFGs, see what external dependencies might be affected, **and check the recent commit history for `class_B` to avoid merge conflicts or redundant work**, so I can assess the scope, risk, and timing of the refactoring effort."

**Persona 2: David, Software Architect**
*   **Goal:** Ensure a new microservice design adheres to architectural principles, manages dependencies effectively, doesn't introduce unwanted coupling or performance bottlenecks, **and track architectural evolution over time**.
*   **Motivation:** Maintain a clean, scalable, maintainable, secure, and evolving system architecture.
*   **User Stories:**
    *   "As David, an architect, I want to query the relationships between `ServiceA` and `ServiceB`, understand their declared external dependencies from their respective build files, review the CFGs of their primary API handling functions, **and see how these dependencies and critical functions have changed over the past six months** using CodeGraph, so that I can enforce architectural boundaries, ensure performance, identify shared library risks, and track architectural drift."
    *   "As David, I want to identify all services that declare a dependency on any version of `LogLibraryX` by querying CodeGraph, **and also see when each service first introduced or last updated this dependency by looking at commit data**, so that I can coordinate a system-wide upgrade, assess vulnerability impact over time, or plan for library deprecation."
    *   "As David, I want to analyze the external libraries used by our front-end applications (parsed from `package.json`) **and track the introduction of new major dependencies over time** using CodeGraph, to ensure we are not accumulating excessive dependencies that could affect load times or increase attack surface."

**Persona 3: Maria, Technical Lead**
*   **Goal:** Assess the risk and effort associated with a proposed major feature, manage library vulnerabilities proactively, ensure code quality, **and leverage historical data for team insights**.
*   **Motivation:** Plan sprints effectively, communicate potential challenges, maintain a healthy codebase, and improve team processes.
*   **User Stories:**
    *   "As Maria, a tech lead, when a critical vulnerability is announced in `CommonUtilityLib`, I want to quickly query CodeGraph to see which of our projects declare this library as a dependency in their build files, **and also identify the specific commits where potentially vulnerable versions were introduced or updated**, so I can prioritize patching efforts and understand the window of exposure."
    *   "As Maria, when reviewing a complex algorithm implemented in `function_C` during a code review, I want to examine its Control Flow Graph in CodeGraph to ensure all edge cases are handled and the logic is sound. **If the function was recently modified, I'd also like to see what changed from its previous version via commit history.**"
    *   "As Maria, I want CodeGraph to capture commit data and associate it with code changes so that in the future, our team can build tools or run analyses to predict which areas of the code are becoming more complex or error-prone based on their change history (churn), developer contributions, and structural metrics over time."
    *   "As Maria, during a post-mortem for an incident, I want to use CodeGraph to review the sequence of commits deployed to production around the time of the incident, examining the changes in code, CFGs, and dependencies, to help understand if any recent modifications contributed to the issue."

**Persona 4: Tom, DevOps Engineer (focusing on local/on-prem setups)**
*   **Goal:** Understand service communication paths, all software dependencies, **and how these have changed with recent commits**, for setting up local Docker Compose environments that accurately mirror potential production setups and for managing build artifacts.
*   **Motivation:** Ensure secure, reliable, and reproducible inter-service communication and builds in all environments, and to understand the impact of deploying new versions.
*   **User Stories:**
    *   "As Tom, a DevOps engineer, I want to list all upstream and downstream service dependencies for `PaymentService`, including its declared external software libraries, **and see if any of these dependencies changed in the latest set of commits scheduled for deployment**, using CodeGraph. This helps me accurately configure Docker networks, environment variables, ensure all necessary build artifacts are available, and anticipate potential integration issues for local testing and development."

---
## 3. System Architecture & Design

### 3.1. High-Level Architecture Diagram
*(Textual Description of Diagram)*

The CodeGraph system is a microservices-based, event-driven architecture, fully containerized for deployment via Docker Compose on Docker Desktop. Exposed ports for host access are carefully chosen to minimize conflicts with common developer tools. The architecture includes components for parsing source code, Control Flow Graphs (CFGs), build system files, and for integrating with Git version control history to build a versioned knowledge graph.

1.  **API Gateway (Docker Container):** Single entry point for all external API requests (CLI, future UI, external tools). Routes requests to appropriate backend services. Handles authentication and rate limiting. Exposes a port on `localhost` (e.g., `localhost:8181`, configurable).
    *   *Interacts with: All user-facing services, User/Auth Service (internally via Docker network).*
2.  **User & Config Service (Docker Container, using PostgreSQL):** Manages user accounts (if any beyond API keys), API keys, codebase configurations (repo URLs, paths, credentials for private repos, paths to build files, branch to track, initial history import depth), and parser configurations.
    *   *Interacts with: API Gateway, Orchestration Service (internally via Docker network).*
3.  **Orchestration Service (Docker Container):** Central coordinator for parsing tasks. Receives requests to add/scan codebases (including historical scans based on commit ranges). Dispatches parsing jobs for source code (to LPS) and build files (to BFPS), associating tasks with specific commit metadata. Manages the queue of parsing tasks on RabbitMQ.
    *   *Interacts with: API Gateway, User & Config Service, File Watcher Service, Language Parser Services, Build File Parser Services, Ingestion Worker, RabbitMQ (internally via Docker network).*
4.  **File Watcher Service (Docker Container - Enhanced for Git):** Monitors configured codebases. For Git repositories, detects new commits, extracts metadata (hash, parent(s), author, committer, dates, message), and list of changed files. Publishes events containing this commit metadata to RabbitMQ. For non-Git local paths, uses file modification timestamps as a simpler version proxy.
    *   *Interacts with: User & Config Service (for repo details, last processed commit), RabbitMQ (internally via Docker network), Git CLI.*
5.  **Language Parser Services (LPS - one Docker container type per language or group):**
    *   Each LPS is responsible for parsing code of its specific language(s) for a given commit, extracting entities, relationships, and **Control Flow Graph (CFG) elements (BasicBlocks, branches)**.
    *   Receives parsing tasks (including commit context) from the Orchestration Service via RabbitMQ. Outputs structured data (including commit context) in a standardized intermediate JSON format. Stateless and scalable.
    *   *Interacts with: RabbitMQ (consumes tasks, publishes results) (internally via Docker network).*
6.  **Build File Parser Services (BFPS - Docker Containers or modules):**
    *   Responsible for parsing specific build system files (e.g., `package.json`, `pom.xml`) for a given commit.
    *   Extracts declared **external library dependencies** (name, version string, ecosystem).
    *   Receives parsing tasks (including commit context) via RabbitMQ. Outputs structured data (including commit context) in a standardized intermediate JSON format.
    *   *Interacts with: RabbitMQ (consumes tasks, publishes results) (internally via Docker network).*
7.  **ID Generation Service (Docker Container):** Responsible for generating globally unique IDs (GIDs) and assisting in the creation/validation of canonical IDs for all entities, ensuring conceptual entities can be tracked across versions.
    *   *Interacts with: Ingestion Worker (primarily) (internally via Docker network).*
8.  **Ingestion Worker (Docker Container(s) - Enhanced for Versioning):**
    *   Consumes the standardized JSON output (with commit context) from both LPS and BFPS via RabbitMQ.
    *   Creates/updates `Commit` nodes in Neo4j.
    *   Validates data against the Ontology. Resolves GIDs/CIDs. Transforms data into Neo4j graph structures, **associating parsed entities/relationships with `Commit` nodes or updating versioning information to reflect the state at that commit.**
    *   Writes data to Neo4j and potentially updates/invalidates caches.
    *   *Interacts with: RabbitMQ, ID Generation Service, Ontology Service, Neo4j, PostgreSQL (internally via Docker network).*
9.  **Ontology Service (Docker Container, backed by PostgreSQL or config files):**
    *   Provides the master definition of the code ontology, including definitions for CFG elements, external libraries, `Commit` nodes, and versioning relationships/properties.
    *   *Interacts with: Ingestion Worker, API Service (internally via Docker network).*
10. **Graph Query Service (Docker Container, API for Neo4j - Enhanced for History):**
    *   Exposes an internal API for querying the Neo4j database.
    *   Translates user-friendly API queries (including those for CFGs, dependencies, and **basic historical states/commit history**) into optimized Cypher queries that navigate the versioned graph.
    *   *Interacts with: API Gateway, Neo4j, Ontology Service (internally via Docker network).*
11. **Neo4j Database (Docker Container):** The core knowledge graph storage. Stores all code entities, relationships, CFG structures, external dependency information, **and `Commit` nodes, effectively creating a versioned graph** in the `codegraph` database.
    *   **Internal Connection (Docker Network):** `bolt://codegraph-neo4j:7689`
    *   **Host Access (Port Mapping):** `bolt://localhost:7921`, `http://localhost:7922`, `https://localhost:7923`
    *   **Credentials:** `neo4j`/`test1234`. Data persisted via Docker volume.
12. **PostgreSQL Database (Docker Container):** Stores relational data: user configurations, API keys, parsing job queue state, ontology definitions, **detailed commit metadata logs if not fully in Neo4j**, and potentially aggregated data for future AI/ML. A specific database (e.g., `codegraph_metadata`) is auto-created.
    *   **Internal Connection (Docker Network):** `codegraph-postgres:5432`
    *   **Host Access (Port Mapping, example):** `localhost:5433`. Data persisted via Docker volume.
13. **Message Queue (RabbitMQ Docker Container):** Facilitates asynchronous communication.
    *   **Internal Connection (Docker Network):** `codegraph-rabbitmq:5672`
    *   **Host Access (Management UI, example):** `localhost:15673`.

*(Diagrammatically: A set of Docker containers interconnected on a Docker network defined in `docker-compose.yml`. The File Watcher now has a stronger interaction with Git. The Ingestion Worker and Graph Query Service are enhanced to handle versioned data linked to Commit nodes. Data stores (Neo4j, PostgreSQL) hold current and historical/commit-related information. API Gateway, Neo4j, PostgreSQL, and RabbitMQ Management UI expose carefully chosen, configurable ports to the host for external access or management. The File Watcher service accesses host file system paths via Docker volume mounts.)*

**Architectural Style:** Microservices, Event-Driven, fully containerized for Docker Desktop deployment using Docker Compose, with conflict-aware port mapping for host-exposed services, and **extended capabilities for Version Control Integration (Git), Historical Data Capture, Control Flow Graph analysis, and build file analysis.**

### 3.2. Component Breakdown & Responsibilities

1.  **API Gateway (e.g., Kong, Traefik, custom Node.js/Python in Docker)**
    *   **Input:** HTTP(S) requests from clients (CLI, future UI).
    *   **Output:** HTTP(S) responses. Proxied requests to backend services.
    *   **Core Logic:** Request routing, authentication (API key validation), rate limiting, SSL termination (if configured), request/response transformation (if needed), basic metrics collection.
    *   **Key Technologies:** Nginx + Lua, Kong, Traefik, Express Gateway, or chosen web framework.
    *   **Communication:** HTTP(S) externally. HTTP, gRPC internally to backend services over Docker network.
    *   **Docker:** Runs as a container, port mapped to host (e.g., `8181:80`).

2.  **User & Config Service (e.g., Python/FastAPI + SQLAlchemy in Docker)**
    *   **Input:** CRUD requests for users (admin only for v1), API keys, codebase configurations (repo URLs, paths, credentials for private repos, paths to build files, branch to track, initial history import depth, scan frequency, language hints).
    *   **Output:** Confirmation messages, requested data (JSON).
    *   **Core Logic:** Data validation, storage and retrieval from its PostgreSQL container. Secure storage of credentials for accessing private repositories. Tracks last processed commit per repository to enable incremental historical scans.
    *   **Key Technologies:** Python/FastAPI or Node.js/Express, PostgreSQL driver.
    *   **Communication:** RESTful HTTP API (internal, via API Gateway for external admin actions).
    *   **Docker:** Runs as a container, connects to PostgreSQL container via Docker network.

3.  **Orchestration Service (e.g., Python/Celery or Go in Docker)**
    *   **Input:** Requests to add/scan/re-scan codebases (from API Gateway), file change events and **new commit events** (from RabbitMQ via File Watcher).
    *   **Output:** Parsing tasks (associated with specific commit metadata) dispatched to RabbitMQ for Language Parser Services (LPS) and Build File Parser Services (BFPS). Status updates (potentially to PostgreSQL or a status tracking system).
    *   **Core Logic:** Manages lifecycle of a codebase scan (source code, build files, **commit history**). Breaks down "scan repository history" or "scan new commit" tasks into file-level parsing tasks for appropriate parsers, ensuring commit context (hash, date, changed files) is passed along. Prioritizes tasks. Monitors progress. Handles retries for transient parser failures.
    *   **Key Technologies:** Python/Celery, Go, RabbitMQ client.
    *   **Communication:** REST/gRPC from API Gateway, RabbitMQ for tasks and events (internal).
    *   **Docker:** Runs as a container, connects to RabbitMQ and other services.

4.  **File Watcher Service (e.g., Python with `watchdog` and GitPython in Docker - Enhanced for Git)**
    *   **Input:** Configuration of codebases/build files to watch (from User & Config Service), last known processed commit for Git repos.
    *   **Output:** Standardized file change events (path, change type, file_type) OR **new commit events** (commit_hash, parent_hashes, author_name, author_email, author_date, committer_name, committer_email, committer_date, message, changed_files_list) published to RabbitMQ.
    *   **Core Logic:**
        *   For Git repositories: Periodically polls configured remote repositories using `git fetch` and then inspects the log (e.g., `git log <last_processed_commit_hash>..HEAD --name-status`) to detect new commits since the last known processed commit. Extracts commit metadata (hash, parent(s), author name/email, committer name/email, author date, committer date, full message) and the list of files changed (added, modified, deleted, renamed) in each new commit.
        *   For non-Git local paths (mounted volumes): Continues to use OS-level file system event notifications, associating changes with current timestamp as a basic version proxy.
    *   **Key Technologies:** `watchdog` (Python for local paths), GitPython library or direct Git CLI execution (Git CLI must be installed in the container for Git operations).
    *   **Communication:** Reads from User & Config Service (for repository configurations, last processed commit). Publishes to RabbitMQ (internal).
    *   **Docker:** Runs in its own container. Host directories to be monitored are mounted as volumes. Needs Git credentials (e.g., via mounted SSH keys or token in environment variable) if accessing private remote repositories for fetching.

5.  **Language Parser Services (LPS - e.g., Python/tree-sitter in Docker)**
    *   **Input:** Task from RabbitMQ (e.g., { "file_path": "/mnt/watched_code/projectA/src/main.py", "language": "python", "repo_id": "xyz", **"commit_hash": "abc123efg", "commit_date": "..."** }). Source code content (either the content itself, or a path to the file which the LPS must checkout or access at the specified `commit_hash`).
    *   **Output:** Standardized JSON representing parsed entities (including **BasicBlocks** for CFG) and their relationships for that file, **including the associated commit_hash**, published to RabbitMQ.
    *   **Core Logic:** Selects appropriate parsing library. If given a file path and commit hash, the LPS might need to use Git CLI to checkout the specific version of the file before parsing. Parses code, extracts entities/relationships, CFG elements, generates CIDs, transforms to common JSON. Stateless.
    *   **Key Technologies (Examples):** Python `ast`/`LibCST`/`tree-sitter` (with CFG extraction logic), Java `JavaParser`/`Eclipse JDT`/`tree-sitter` (with CFG extraction logic), JS/TS `TypeScript Compiler API`/`Babel Parser`/`tree-sitter` (with CFG extraction logic), Go `go/parser` (with CFG extraction logic). Git CLI might be needed within the container.
    *   **Communication:** Consumes from RabbitMQ, Publishes to RabbitMQ (internal).
    *   **Docker:** One or more container types. Must have access to code (via shared Docker volumes and Git CLI for version checkout, or by receiving full file content in messages).

6.  **Build File Parser Services (BFPS - e.g., Python scripts/modules in Docker)**
    *   **Input:** Task from RabbitMQ (e.g., { "file_path": "/mnt/watched_code/projectA/package.json", "build_system": "npm", "repo_id": "xyz", **"commit_hash": "abc123efg"** }). Build file content (as of the given commit).
    *   **Output:** Standardized JSON representing declared external dependencies (library name, version string, ecosystem), **including the associated commit_hash**, published to RabbitMQ.
    *   **Core Logic:** Parses build file (as of given commit), extracts library names/versions.
    *   **Key Technologies:** Standard library parsers (JSON, XML), specific libraries for build files. Git CLI might be needed to get file content at specific commit.
    *   **Communication:** Consumes from RabbitMQ, Publishes to RabbitMQ (internal).
    *   **Docker:** Separate lightweight containers or integrated as modules within Orchestration Service or Ingestion Worker.

7.  **ID Generation Service (e.g., Python/FastAPI in Docker)**
    *   **Input:** Request for GID (optionally with entity type, canonical ID parts). Request to validate/finalize canonical ID for code entities, CFG elements, external libraries, and `Commit` nodes.
    *   **Output:** Globally Unique ID. Validated canonical ID.
    *   **Core Logic:** Generates unique, sortable, collision-resistant GIDs. Implements canonical ID construction/validation for all entity types, ensuring CIDs are consistent for conceptual entities across different versions.
    *   **Key Technologies:** UUID libraries.
    *   **Communication:** Internal REST/gRPC API.
    *   **Docker:** Runs as a container.

8.  **Ingestion Worker (e.g., Python/Pika for RabbitMQ in Docker - Enhanced for Versioning)**
    *   **Input:** Standardized JSON parser output (from LPS & BFPS) including `commit_hash`, via RabbitMQ.
    *   **Output:** Data written to Neo4j (versioned entities, `Commit` nodes). Updates to PostgreSQL.
    *   **Core Logic:**
        *   Consumes messages. Creates/updates a `Commit` node in Neo4j (identified by `commitHash`). Links to parent `Commit` nodes using `PARENT_COMMIT` relationships.
        *   Validates incoming data against Ontology. Finalizes GIDs/CIDs.
        *   For each parsed entity from a commit:
            *   Identifies the conceptual entity using its CID.
            *   Updates the entity's versioning information in Neo4j. This involves associating the entity's state (its properties and relationships at that commit) with the current `Commit` node. This could be achieved by:
                1.  Creating new, version-specific nodes for entities (e.g., `Function_v1_gid`, `Function_v2_gid`) that are linked to both the conceptual entity (via CID) and the `Commit` node.
                2.  Or, (simpler for v1.0) updating existing conceptual entity nodes (identified by CID) with temporal properties (e.g., `validFromCommitGid`, `validToCommitGid`, `lastModifiedInCommitGid`) or by linking them to the `Commit` node via a relationship like `ENTITY_STATE_IN_COMMIT {properties_map}`. The exact strategy for representing entity versions needs careful design to balance query performance and storage. This PRD leans towards property-based versioning or specific relationships on conceptual entities for v1.0.
            *   Handles ADDED, MODIFIED, DELETED states based on commit information (if available from File Watcher/diff) by setting appropriate versioning properties or creating/terminating versioned relationships.
        *   Writes to Neo4j transactionally. Manages pending relationships (which also need to be version-aware).
    *   **Key Technologies:** RabbitMQ client, Neo4j driver (connects to `bolt://codegraph-neo4j:7689`, user: `neo4j`, pass: `test1234`, db: `codegraph`), PostgreSQL driver.
    *   **Communication:** Consumes from RabbitMQ. Writes to Neo4j & PostgreSQL. Calls ID Generation Service & Ontology Service (internal).
    *   **Docker:** Runs as a container.

9.  **Ontology Service (e.g., Python/FastAPI in Docker)**
    *   **Input/Output:** Ontology definition requests/responses (including `Commit`, versioning properties/relationships like `PARENT_COMMIT`, `ENTITY_MODIFIED_IN_COMMIT`).
    *   **Core Logic:** Serves current CodeGraph ontology. Manages versioning of the ontology itself.
    *   **Key Technologies:** Python/FastAPI, PostgreSQL driver or file access.
    *   **Communication:** Internal REST/gRPC API.
    *   **Docker:** Runs as a container.

10. **Graph Query Service (e.g., Python/FastAPI + Neo4j driver in Docker - Enhanced for History)**
    *   **Input:** High-level query requests from API Gateway (current state, CFG, dependencies, **basic historical queries**).
    *   **Output:** Query results in JSON format.
    *   **Core Logic:** Translates abstract queries into efficient Cypher queries for Neo4j that navigate the versioned graph structure (e.g., filtering by commit properties, traversing `PARENT_COMMIT` or `ENTITY_MODIFIED_IN_COMMIT` relationships, or querying entities based on their versioning properties like `lastModifiedInCommitGid`).
    *   **Key Technologies:** Python/FastAPI, Neo4j driver.
    *   **Communication:** Internal REST/gRPC API. Queries Neo4j (db: `codegraph` via `bolt://codegraph-neo4j:7689`).
    *   **Docker:** Runs as a container.

11. **Neo4j Database (Official Neo4j Docker Image)**
    *   **Configuration:** `NEO4J_AUTH=neo4j/test1234`. Docker Compose maps host port `7921` to container port `7689` (Bolt), host port `7922` to container port `7474` (HTTP), and host port `7923` to container port `7473` (HTTPS, assuming an internal HTTPS port like `7473` or similar standard if enabled). `NEO4J_dbms_default__database=codegraph`. Data persisted in a named Docker volume (e.g., `codegraph_neo4j_data`). Stores `Commit` nodes and versioned representations of code elements.
    *   **Environment Variables for Neo4j container might include:**
        *   `NEO4J_dbms_connector_bolt_advertised__address=localhost:7921`
        *   `NEO4J_dbms_connector_bolt_listen__address=0.0.0.0:7689`
        *   `NEO4J_dbms_connector_http_advertised__address=localhost:7922`
        *   `NEO4J_dbms_connector_http_listen__address=0.0.0.0:7474` (container internal HTTP port)
        *   `NEO4J_dbms_connector_https_advertised__address=localhost:7923`
        *   `NEO4J_dbms_connector_https_listen__address=0.0.0.0:7473` (container internal HTTPS port, e.g., `7473`)
        *   `NEO4J_dbms_default__database=codegraph`

12. **PostgreSQL Database (Official PostgreSQL Docker Image)**
    *   **Configuration:** Host port e.g., `5433`. `codegraph_metadata` DB auto-created. Stores configurations, job states, **and potentially detailed commit logs or pre-aggregated historical metrics for AI/ML if Neo4j becomes too slow for certain raw history queries.** Data via Docker volume (e.g., `codegraph_postgres_data`).

13. **Message Queue (Official RabbitMQ Docker Image)**
    *   **Configuration:** Host Management UI port e.g., `15673`. Persistence via Docker volume (e.g., `codegraph_rabbitmq_data`).

### 3.3. Data Model & Ontology

#### 3.3.1. Detailed Ontology Definition
The CodeGraph Ontology defines the types of entities (nodes) and relationships recognized in code, including Control Flow Graph elements, External Library Dependencies, and Version Control (Commit) information.

**Node Labels & Properties:**

*   **`File`**: Represents a source code file or a build system file.
    *   `gid`: String (Global Unique ID, Primary Key for this instance/version of the file state)
    *   `canonicalId`: String (e.g., `repo_id::file_path` - stable identifier for the conceptual file across versions)
    *   `path`: String (Full path within the repository/project at the time of this version)
    *   `name`: String (File name, e.g., `UserService.java`, `package.json`)
    *   `language`: String (e.g., "Python", "Java", "JSON", "XML", "Gradle") - indicates parser to use.
    *   `loc`: Integer (Lines of Code - for source files, at this version)
    *   `checksum`: String (SHA256 hash of content at this version)
    *   `parsedAt`: DateTime (When this version was parsed)
    *   `repoGid`: String (GID of the Repository node it belongs to)
    *   `fileType`: String ("SourceCode", "BuildFile", "Configuration", "Other")
    *   `createdInCommitGid`: String (GID of the `Commit` where this file path first appeared or this version of content was created)
    *   `lastModifiedInCommitGid`: String (GID of the `Commit` where this version of the file's content was established)
    *   `deletedInCommitGid`: String (Optional, GID of the `Commit` where this file path was deleted)
*   **`Repository`**: Represents a codebase repository.
    *   `gid`: String (Global Unique ID, Primary Key)
    *   `canonicalId`: String (e.g., `git_url` or unique local project identifier)
    *   `url`: String (e.g., Git URL or unique local project identifier)
    *   `name`: String (Repository name)
    *   `lastScannedCommitHash`: String (The hash of the last commit processed for this repository by CodeGraph)
    *   `description`: String (Optional)
*   **`Module`**: Logical grouping of code, potentially defined by directory structure or build system configuration.
    *   `gid`: String (Primary Key for this version of the module state)
    *   `canonicalId`: String (e.g., `repo_id::module_path_or_name`)
    *   `name`: String (e.g., `com.example.utils`, `my_python_module`)
    *   `type`: String ("Package", "Namespace", "Module", "ProjectModule")
    *   `filePathHint`: String (Path to the defining file or directory, at this version)
    *   (Versioning properties like `createdInCommitGid`, `lastModifiedInCommitGid` apply if module definitions change)
*   **`Structure`**: Abstract parent label for classes, interfaces, structs, etc.
    *   `gid`: String (Primary Key for this version of the structure state)
    *   `canonicalId`: String (e.g., `repo_id::file_path::class_name` or `fully_qualified_class_name`)
    *   `name`: String (Short name, e.g., `MyClass`)
    *   `qualifiedName`: String (Fully qualified name, e.g., `com.example.MyClass`)
    *   `startLine`: Integer (at this version)
    *   `endLine`: Integer (at this version)
    *   `accessModifier`: String (optional, at this version)
    *   `isAbstract`: Boolean (optional, at this version)
    *   `isFinal`: Boolean (optional, at this version)
    *   (Versioning properties like `createdInCommitGid`, `lastModifiedInCommitGid` apply)
*   **`Class`**: Inherits from `Structure`. (All properties of `Structure`, versioned)
*   **`Interface`**: Inherits from `Structure`. (All properties of `Structure`, versioned)
*   **`Function`**: Represents a function, method, constructor.
    *   `gid`: String (Primary Key for this version of the function state)
    *   `canonicalId`: String (e.g., `repo_id::file_path::[class_name#]function_name(param_types)`)
    *   `name`: String (Short name)
    *   `qualifiedName`: String
    *   `signature`: String (at this version)
    *   `returnType`: String (at this version)
    *   `startLine`: Integer (at this version)
    *   `endLine`: Integer (at this version)
    *   `cyclomaticComplexity`: Integer (Optional, at this version)
    *   `accessModifier`: String (at this version)
    *   `isStatic`: Boolean (at this version)
    *   `isConstructor`: Boolean (at this version)
    *   `isAsync`: Boolean (at this version)
    *   (Versioning properties like `createdInCommitGid`, `lastModifiedInCommitGid` apply)
*   **`BasicBlock`**: Represents a basic block within a function's CFG.
    *   `gid`: String (Primary Key for this version of the basic block state)
    *   `canonicalId`: String (e.g., `function_cid_at_version::block_index_or_hash`) - needs careful definition for stability if function internals change.
    *   `indexInFunction`: Integer (A sequential index or unique identifier within the parent function, at this version)
    *   `startLine`: Integer (at this version)
    *   `endLine`: Integer (at this version)
    *   `instructionCount`: Integer (Optional, at this version)
    *   (Versioning properties like `createdInCommitGid`, `lastModifiedInCommitGid` apply, tied to parent function's version)
*   **`Variable`**: Global, class member, constant. (Properties as previously defined, versioned state)
*   **`Parameter`**: Function/method parameter. (Properties as previously defined, versioned state)
*   **`APIRoute`**: Exposed API endpoint. (Properties as previously defined, versioned state)
*   **`Service`**: Conceptual microservice. (Properties as previously defined, versioned state)
*   **`ExternalLibrary`**: Declared external library dependency.
    *   `gid`: String (Primary Key - represents the library itself, not a specific declaration instance)
    *   `canonicalId`: String (e.g., `ecosystem::library_name` like `npm::lodash`. Indexed.)
    *   `name`: String (e.g., `lodash`, `commons-lang3`. Indexed.)
    *   `ecosystem`: String (e.g., "npm", "maven", "pypi", "gradle". Indexed.)
    *   (Note: `versionDeclared` is now a property on the `DECLARES_DEPENDENCY` relationship, as a project can declare different versions over time or in different build files).
*   **`Commit`**: Represents a commit in a version control system (primarily Git).
    *   `gid`: String (Global Unique ID, Primary Key)
    *   `commitHash`: String (Unique identifier of the commit, e.g., SHA-1 for Git. Indexed.)
    *   `shortHash`: String (Shortened commit hash)
    *   `authorName`: String
    *   `authorEmail`: String
    *   `authorDate`: DateTime (Timestamp of when the commit was authored)
    *   `committerName`: String
    *   `committerEmail`: String
    *   `commitDate`: DateTime (Timestamp of when the commit was applied/committed. Indexed.)
    *   `message`: String (Full commit message)
    *   `summary`: String (Short summary of commit message, typically the first line)
    *   `repositoryGid`: String (GID of the Repository this commit belongs to)

**Relationship Types & Properties:**
(Relationships between code entities like `CALLS`, `INHERITS_FROM`, `NEXT_BLOCK` now represent the state of that relationship *as of the commit(s)* associated with the connected source/target node versions. This is achieved by ensuring the GIDs of the source/target nodes are those representing the state at a particular commit.)

*   **`PARENT_COMMIT`**: From a `Commit` node to its parent `Commit` node(s).
    *   `isMergeParent`: Boolean (Optional, true if this parent is part of a merge commit)
*   **`MODIFIED_FILE_IN_COMMIT`**: From a `Commit` node to a `File` node (the GID of the File node represents its state in/after this commit).
    *   `changeType`: String ("ADDED", "MODIFIED", "DELETED", "RENAMED", "COPIED", "TYPE_CHANGED")
    *   `oldPath`: String (If renamed or copied)
    *   `linesAdded`: Integer (Optional, from diffstat if available)
    *   `linesDeleted`: Integer (Optional, from diffstat if available)
*   **`DECLARES_DEPENDENCY`**: From a `File` (representing a build file state at a specific commit, identified by its GID) to an `ExternalLibrary` node (representing the conceptual library).
    *   `versionDeclaredRaw`: String (The exact version string from the build file at that commit, e.g., "^1.2.3")
    *   `scope`: String (Optional, e.g., "compile", "test", "runtime", "devDependency" - from build file at that commit)
    *   `commitGid`: String (GID of the `Commit` in which this dependency declaration is active)
*   **`CONTAINS`**, **`IMPORTS`**, **`DEFINES_FUNCTION`**, **`DEFINES_STRUCTURE`**, **`DEFINES_VARIABLE`**, **`HAS_PARAMETER`**, **`RETURNS_TYPE`**, **`CALLS`**, **`INSTANTIATES`**, **`INHERITS_FROM`**, **`IMPLEMENTS`**, **`USES_TYPE`**, **`ACCESSES_VARIABLE`**, **`EXPOSES_API`**, **`HANDLED_BY`**, **`CALLS_API`**, **`PART_OF_REPO`**, **`CONTAINS_BLOCK`**, **`FIRST_BLOCK`**, **`NEXT_BLOCK`**, **`BRANCHES_TO`**: These relationships connect specific GIDs of entities, where each GID represents the state of that entity as of a particular commit (defined by its `createdInCommitGid` or `lastModifiedInCommitGid` properties).

#### 3.3.2. Neo4j Graph Schema
The extended ontology maps to Neo4j:
*   Node Labels: `File`, `Repository`, `Module`, `Structure`, `Class`, `Interface`, `Function`, `BasicBlock`, `Variable`, `Parameter`, `APIRoute`, `Service`, `ExternalLibrary`, `Commit`.
*   Relationships: As defined above. Versioning is primarily handled by properties on entity nodes (e.g., `createdInCommitGid`, `lastModifiedInCommitGid`) and by ensuring relationships connect the GIDs of entities that co-existed or were related within the context of specific commits. The `DECLARES_DEPENDENCY` relationship will also carry a `commitGid` property.
*   **Internal Connection (Docker Network):** `bolt://codegraph-neo4j:7689`.
*   **Host Access (Port Mapping):** `bolt://localhost:7921`, `http://localhost:7922`, `https://localhost:7923`.
*   **Credentials:** `neo4j`/`test1234`. **Database:** `codegraph`.
*   **Indexes:** On `Commit.commitHash`, `Commit.commitDate`. On GIDs and CIDs for all major entity types. On versioning properties like `createdInCommitGid`, `lastModifiedInCommitGid` if used extensively for filtering. On `ExternalLibrary.canonicalId`.

#### 3.3.3. Global Unique ID (GID) and Canonical ID Strategy
*   **GID:** Unique for each distinct node instance in the graph. If an entity (e.g., a Function) is modified in a new commit, the node representing its state *in that new commit* will have a distinct GID. This means a conceptual entity will have multiple GID-identified nodes over its lifetime, each representing a version.
*   **CID:** Remains the stable identifier for the *conceptual* entity across all its versions/commits. This is critical for tracking an entity's history. E.g., function `com.example.MyClass.myMethod(String)` is the CID. This CID would be a property on all GID-identified version nodes of that function.
    *   `BasicBlock` CIDs will be scoped by the CID of their parent function and an index/identifier stable within that function's version.
    *   `ExternalLibrary` CIDs are `ecosystem::library_name`.

#### 3.3.4. Data Flow Diagrams (Textual Description)
**1. Initial Codebase Scan & History Ingestion (Neo4j on Host Bolt Port 7921):**
User configures Git repo. Orchestration Service triggers File Watcher.
File Watcher -> Fetches Git log from last known commit (or full history if new). For each commit:
    File Watcher -> Extracts commit metadata (hash, parent, author, date, message) and list of changed files (path, change type).
    File Watcher -> RabbitMQ (Event: New Commit Detected {commit_metadata, changed_files_list})
Orchestration Service <- RabbitMQ (Consumes Commit Event)
Orchestration Service -> For each changed file in the commit:
    Orchestration Service -> Retrieves file content *as of that commit* (e.g., using Git CLI).
    Orchestration Service -> RabbitMQ (Task: Parse `file_content_at_commit` for Language Y / Build System Z {commit_metadata, original_file_path})
Language/Build File Parser Services <- RabbitMQ (Consume Task)
Parser Services -> Parse file content. Generate JSON with entities, CFGs, dependencies, including the `commit_hash`.
Parser Services -> RabbitMQ (Publish Parsed Data {commit_hash, parsed_content, original_file_path})
Ingestion Worker <- RabbitMQ (Consumes Parsed Data)
Ingestion Worker -> Creates/updates `Commit` node for `commit_hash`. Links to parent `Commit`(s).
Ingestion Worker -> For each parsed entity:
    Ingestion Worker -> Creates a new GID-identified node for this version of the entity (carrying its conceptual CID). Sets `createdInCommitGid` to current `commit_hash`. If this entity (by CID) existed in a parent commit, its previous GID-version might be marked as `deletedInCommitGid` (or an equivalent mechanism).
    Ingestion Worker -> Creates relationships between these new GID-versioned entity nodes, reflecting their state in the current commit.
    Ingestion Worker -> Creates `MODIFIED_FILE_IN_COMMIT` relationship from `Commit` to the GID of the File node representing its state in this commit.
Ingestion Worker -> PostgreSQL (Store detailed commit log or processing status).

**2. Incremental Update (New Commit):** Same as above, but File Watcher starts from the latest commit it knows about.

**3. User Query (Historical):**
User (API/CLI) -> API Gateway (e.g., GET `/v1/entities/cid/{entity_cid}/history`)
API Gateway -> Graph Query Service
Graph Query Service -> Constructs Cypher query using `Commit` nodes and entity versioning. E.g., `MATCH (conceptual_entity {canonicalId: "{entity_cid}"}) <-[:IS_VERSION_OF]- (version_node) -[:STATE_IN_COMMIT]-> (c:Commit) RETURN c, version_node.properties ORDER BY c.commitDate DESC`. (Actual query depends on chosen versioning model).
Graph Query Service -> Neo4j (Executes Cypher).
(Response flow as previously detailed).

### 3.4. Technology Stack
*   **Backend Services (general):** Python (FastAPI, Flask) and/or Node.js (Express.js, NestJS). Go. Dockerized.
*   **Language Parsers (specific):** Python `ast`/`LibCST`/`tree-sitter`; Java `JavaParser`/`tree-sitter`; JS/TS `TypeScript Compiler API`/`tree-sitter`; Go `go/parser`. All with CFG extraction logic.
*   **Build File Parsers:** Python (`json`, `xml.etree.ElementTree`, `toml`, etc.).
*   **Version Control Tooling:** Git CLI (must be installed in File Watcher, Orchestrator, and potentially Parser service containers if they checkout specific versions).
*   **Graph Database:** Neo4j (Official Docker Image). Host Bolt: `7921`, Host HTTP: `7922`, Host HTTPS: `7923`.
*   **Relational Database:** PostgreSQL (Official Docker Image). Host Port (example): `5433`.
*   **Message Queue:** RabbitMQ (Official Docker Image). Host Management UI Port (example): `15673`.
*   **API Gateway:** Kong, Traefik, or custom (Docker). Host Port (example): `8181`.
*   **Containerization & Orchestration:** Docker, Docker Compose.
*   **Caching (Optional):** Redis (Official Docker Image). Host Port (example): `6380`.
*   **Monitoring & Logging (Local):** Standard Docker logging drivers. Optional Prometheus, Grafana, ELK (Dockerized).
*   **Operating System for File Watcher Container:** Linux-based Docker image with Git CLI installed.

### 3.5. API Design
The API is RESTful, using JSON. Accessed via API Gateway (e.g., `localhost:8181`). Extended for historical data access and to reflect commit-centric operations.

#### Key Endpoints (Version 1.0):

**Repositories & Scanning:**
*   `POST /v1/repositories`: Configure a new repository for CodeGraph to track.
    *   Request Body: `{ "url": "git@github.com:org/repo.git", "name": "MyRepo", "branch_to_track": "main", "initial_history_depth_commits": 1000, "credentials": { "type": "ssh_key_path", "value": "/path/to/id_rsa_in_watcher_container" }, "buildFilePaths": ["pom.xml", "submodule/package.json"], "scanFrequencyMinutes": 5, "languages": ["java", "javascript"] }`
    *   Response: `201 Created`, Repository object.
*   `GET /v1/repositories`: List all configured repositories.
*   `GET /v1/repositories/{repo_gid}`: Get details of a specific repository.
*   `PUT /v1/repositories/{repo_gid}`: Update configuration of a repository.
*   `DELETE /v1/repositories/{repo_gid}`: Remove a repository from CodeGraph.
*   `POST /v1/repositories/{repo_gid}/scan`: Trigger a scan to process new commits since the last scan. For a new repository, it processes history based on `initial_history_depth_commits` or from a specific tag/commit if provided.
    *   Optional Request Body: `{ "fromCommit": "hash_or_tag", "toCommit": "hash_or_tag_or_HEAD", "forceReProcess": false }`
    *   Response: `202 Accepted` (scan job queued), includes a job ID.
*   `GET /v1/repositories/{repo_gid}/scan_status`: Get the status of the latest scan or a specific scan job ID.

**Code Entities & Relationships (Querying - Extended for History):**
*   `GET /v1/entities/{gid}`: Get details of a specific entity GID (which represents a state of a conceptual entity at a particular version/commit).
    *   Response: Entity object with its properties and associated `commitGid`.
*   `GET /v1/entities`: Search for entities. By default, returns the latest version of entities matching criteria.
    *   Query Params: `type=<EntityType>`, `name=<EntityName>`, `canonicalId=<CID>`, `repoGid=<RepoGID>`, `limit=100`, `offset=0`.
    *   Response: Paginated list of latest version entity GIDs and their summary.
*   `GET /v1/functions/{function_gid}/callers`: Get callers of this specific function version (GID).
*   `GET /v1/functions/{function_gid}/callees`: Get callees of this specific function version (GID).
*   `GET /v1/functions/{function_gid}/cfg`: Get CFG for this specific function version (GID).
*   `GET /v1/repositories/{repo_gid}/dependencies`: List latest declared dependencies for a repository.
*   `GET /v1/libraries`: Search latest known external libraries.
*   `GET /v1/libraries/{library_gid}/dependents`: List repositories/modules using the latest version of this library.

**Commits & History (New Section):**
*   `GET /v1/repositories/{repo_gid}/commits`: List commits for a repository, paginated.
    *   Query Params: `branch=<name>` (if branch info is tracked with commits), `filePath=<path_changed_in_commit>`, `authorEmail=<email>`, `sinceDate=<YYYY-MM-DD>`, `untilDate=<YYYY-MM-DD>`, `limit`, `offset`.
    *   Response: Array of `Commit` objects (metadata: hash, author, date, summary).
*   `GET /v1/commits/{commit_hash}`: Get details of a specific commit, including a list of files changed (name, type of change like ADDED, MODIFIED, DELETED).
*   `GET /v1/commits/{commit_hash}/entities`: List entities (GIDs or CIDs with summary) that were created, modified, or deleted in this commit.
*   `GET /v1/entities/cid/{entity_cid}/history`: Get the commit history for a conceptual entity (identified by its Canonical ID).
    *   Response: List of relevant `Commit` objects (hash, author, date, summary) where this conceptual entity was created, modified, or deleted, and the GID of the entity version in that commit.
*   `GET /v1/entities/cid/{entity_cid}/as_of_commit/{commit_hash}`: (Stretch Goal for v1.0 due to query complexity) Get the properties/state of a conceptual entity as they were recorded for a specific `Commit`. Requires querying the specific GID-version of the entity linked to this commit.

**Ontology Endpoints:**
*   `GET /v1/ontology/node_labels`: List all defined node labels in the CodeGraph ontology.
*   `GET /v1/ontology/relationship_types`: List all defined relationship types.
*   `GET /v1/ontology/node_labels/{label_name}`: Get properties and description for a specific node label.
*   `GET /v1/ontology/relationship_types/{type_name}`: Get properties and description for a specific relationship type.

**AI/ML Data Foundation (Placeholder Endpoints - Data Collection Focus for v1.0):**
*   These endpoints are conceptual for v1.0, indicating the type of data being made available for future AI/ML. They might not perform complex analytics themselves but provide access to the raw historical data.
*   `GET /v1/analytics/repository/{repo_gid}/change_metrics_raw`: (Conceptual) Provides raw data like file paths, commit dates, and author for files changed within a repository, which can be used to calculate churn or other metrics externally.
*   `GET /v1/analytics/function/cid/{entity_cid}/version_data`: (Conceptual) Provides a list of GIDs and associated commit GIDs for all known versions of a function, allowing external tools to retrieve each version's properties (like CFG complexity) for trend analysis.

#### Request/Response Formats:
*   JSON for all request and response bodies.
*   Standard HTTP status codes (200 OK, 201 Created, 202 Accepted, 204 No Content, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 500 Internal Server Error).
*   Consistent JSON error format: `{ "error": { "code": "ERROR_CODE_STRING", "message": "Detailed error message.", "details": { ... } } }`.
*   Pagination for list endpoints: Use query parameters like `limit` and `offset` (or `page` and `pageSize`). Responses include pagination info (e.g., `totalItems`, `limit`, `offset`, `nextLink`, `prevLink`).

#### Authentication/Authorization Strategy:
*   **API Keys:** Primary method for authenticating client applications (CLI, external tools). Keys are passed in the `Authorization` header (e.g., `Authorization: Bearer <api_key>`). Keys are generated and managed via the User & Config Service.
*   **Internal Service-to-Service:** Communication within the Docker network is considered trusted for v1.0. Mutual TLS (mTLS) or short-lived JWT tokens are future considerations for enhanced internal security.
*   **Authorization:** Basic role-based access control (RBAC) for v1.0. For example, an "admin" role for managing repositories and users (if any), and a "read" or "query" role for accessing graph data. More granular permissions are future considerations.

#### Versioning Strategy:
*   URI Path Versioning (e.g., `/v1/...`, `/v2/...`). This is simple, clear, and widely understood for API evolution.

---

## 4. Functional Requirements

**FR-001: Configure Codebase Monitoring (with History)**
*   **Feature Name:** Codebase Configuration for Historical Analysis
*   **Description:** The system shall allow a user (via API/CLI) to specify a Git repository to be monitored by CodeGraph. Configuration includes repository URL, branch to track, depth of initial historical import (e.g., last N commits, from specific tag, full history if feasible within performance constraints), access credentials (e.g., SSH key path accessible to File Watcher container, PAT), paths to relevant build system files, and languages to prioritize. For non-Git local paths, basic file modification timestamp-based versioning will be used (historical queries will be limited).
*   **User Story:** "As a Tech Lead, I want to add my team's main Git repository to CodeGraph, specifying the 'main' branch, an initial import of the last 500 commits, and locations of `pom.xml` files, so the system can build a versioned knowledge graph."
*   **Acceptance Criteria:**
    *   User can successfully add a Git repository via API, providing URL, branch, initial history depth, credentials, and build file paths.
    *   User can successfully add a local directory path (for simpler, non-Git versioning) via API.
    *   The system securely stores access credentials.
    *   All configured repositories and their settings can be listed and updated via API.
    *   User can remove a repository from CodeGraph monitoring.

**FR-002: Manual Codebase Scan (with History Processing)**
*   **Feature Name:** Manual Scan Trigger for Commit History
*   **Description:** The system shall allow a user (via API/CLI) to initiate a scan to process Git commit history (from the last known processed commit or a specified range/depth) for a configured repository. This includes parsing changes to source code (for entities and CFGs) and associated build system files (for external dependencies) for each relevant commit.
*   **User Story:** "As a Developer, after configuring a repository, I want to trigger an initial scan to process its recent commit history, so the versioned knowledge graph is populated and I can start querying past states."
*   **Acceptance Criteria:**
    *   User can trigger a scan for a configured Git repository via an API call, optionally specifying a commit range or depth.
    *   The system queues the scan job and returns a job ID.
    *   User can query the status of an ongoing or completed scan.
    *   The scan processes commits based on configuration (new since last scan, or specified range/depth).
    *   The scan includes parsing code (entities, CFGs) and build files for each processed commit, associating the parsed state with that commit.

**FR-003: Commit-Based Codebase Monitoring and Incremental Versioned Update**
*   **Feature Name:** Commit-Based Codebase Monitoring and Incremental Versioned Update
*   **Description:** The File Watcher service shall monitor configured Git repositories for new commits on the tracked branch. Upon detecting new commits, it shall extract commit metadata (hash, parent(s), author, date, message, changed files) and trigger incremental parsing of only the affected files (code and build files) for each new commit. The Ingestion Worker will then update the versioned knowledge graph, creating new `Commit` nodes and associating the parsed states of entities, CFGs, and dependencies with these respective `Commit` nodes.
*   **User Story:** "As a Developer, I want CodeGraph to automatically detect new commits pushed to my monitored Git repository, extract all relevant commit information, parse the code and build file changes introduced in those commits, and update the versioned graph within minutes, so I always have access to the latest state and its history."
*   **Acceptance Criteria:**
    *   System detects new commits in monitored Git repositories on the configured branch.
    *   Commit metadata (hash, parent(s), author name/email, author date, committer name/email, committer date, full message, summary) is extracted and stored as `Commit` nodes in Neo4j.
    *   `PARENT_COMMIT` relationships are correctly created between `Commit` nodes.
    *   Only files indicated as changed in a commit (or all files if it's an initial commit for a version being processed) are re-parsed for that commit's context.
    *   Parsed entities, CFGs, and dependencies are linked to the relevant `Commit` node, reflecting their state in that version (e.g., via `lastModifiedInCommitGid` properties on entity nodes, or by creating new version-specific entity nodes linked to the commit).
    *   The system correctly handles changes along the configured primary branch. (Handling of complex merge/rebase histories might be simplified in v1.0, focusing on a linearized view if necessary).

**FR-004: Version-Aware Multi-Language Code Parsing and CFG Extraction**
*   **Feature Name:** Version-Aware Multi-Language Code Parsing and Control Flow Graph (CFG) Extraction
*   **Description:** The system shall parse source code from multiple programming languages. For each supported language, it will identify predefined code entities, their relationships, and extract basic Control Flow Graph (CFG) elements (BasicBlocks and their successor/branch relationships). The parsing process is aware of the specific commit context (e.g., by checking out the code at that commit or receiving content specific to that commit from the Orchestrator), ensuring that the extracted entities and CFGs reflect the state of the code *at that commit*.
*   **User Story:** "As an Architect, I want CodeGraph to parse our Python backend services and generate CFGs for key business logic functions *as they existed in commit 'abc123efg'*, so I can analyze their historical complexity and execution paths."
*   **Acceptance Criteria:**
    *   System correctly parses syntactically valid Python (v3.x) files from a given commit's version and extracts entities/relationships/CFGs.
    *   System correctly parses syntactically valid Java (v8/11+) files from a given commit's version and extracts entities/relationships/CFGs.
    *   System correctly parses syntactically valid JavaScript (ES6+) files from a given commit's version and extracts entities/relationships/CFGs.
    *   The system correctly identifies basic blocks within functions/methods for supported languages as they exist in the specified commit.
    *   The system correctly identifies sequential `NEXT_BLOCK` relationships between basic blocks for that version.
    *   The system correctly identifies `BRANCHES_TO` relationships for conditional and unconditional jumps between basic blocks for that version, capturing branch conditions where feasible.
    *   A `FIRST_BLOCK` relationship is established from a function (version) to its entry block (version).
    *   `CONTAINS_BLOCK` relationships link function versions to all their basic block versions.
    *   Parser output is transformed into the standardized intermediate JSON format, including CFG elements and the associated commit context.
    *   Parsers generate necessary information for Canonical ID creation for all entities including BasicBlocks, ensuring conceptual linkage across versions.
    *   Failed parsing of a single file (for a specific commit) does not halt parsing of other files; errors are logged with commit context.

**FR-005: Versioned Knowledge Graph Construction**
*   **Feature Name:** Versioned Knowledge Graph Construction
*   **Description:** The system shall take commit metadata and the output from language/build file parsers (which includes data for a specific commit) and construct/update a **versioned** knowledge graph in the Neo4j `codegraph` database (internally connected via Bolt port `7689`, host accessible on port `7921`). This includes creating/linking `Commit` nodes, and representing code entities, CFGs, and dependencies in a way that their state can be related to specific commits (e.g., using temporal properties on entities or creating version-specific entity nodes linked to commits).
*   **User Story:** "As a System (CodeGraph Ingestion Worker), upon receiving parsed data for a Java method (including its CFG) from commit 'abc123efg', and parsed dependency data from its `pom.xml` at the same commit, I will create/update corresponding nodes and relationships in Neo4j, ensuring all these elements are correctly associated with the 'abc123efg' `Commit` node, and that this state is distinguishable from states at other commits."
*   **Acceptance Criteria:**
    *   `Commit` nodes are created in Neo4j with correct metadata and `PARENT_COMMIT` links.
    *   Code entities (Functions, Classes, etc.), CFG elements (BasicBlocks), and ExternalLibraries are associated with the `Commit` node in which their state is being recorded. This association is achieved through:
        *   Relationships like `MODIFIED_FILE_IN_COMMIT` (from `Commit` to the GID of the `File` node representing its state in this commit).
        *   Properties on entity nodes such as `createdInCommitGid` (for the GID of the node representing the entity's first appearance or this specific version's creation) and `lastModifiedInCommitGid` (for the GID of the node representing this specific version's state).
        *   If an entity is deleted, its last version node might have a `deletedInCommitGid` property set.
    *   The graph structure allows for querying the state of elements as of a particular commit (to the extent supported by v1.0 API for basic historical queries).
    *   Idempotency is maintained for processing the same commit's data multiple times (no duplicate `Commit` nodes or entity versions for the same commit).
    *   The system handles unresolved ("pending") relationships, ensuring they are also contextually tied to the correct commit version.
    *   When a file is re-parsed for a given commit (e.g., due to a forced re-scan), existing versioned data for that file at that commit is correctly updated or replaced.

**FR-006: Entity & Relationship Query (Current & Basic Historical State)**
*   **Feature Name:** Current and Basic Historical State Query via API/CLI
*   **Description:** The system shall provide API/CLI endpoints to query for specific code entities by ID or properties (defaulting to the latest known version/state), traverse relationships, and also perform basic historical queries such as listing commits affecting an entity or retrieving an entity's state as recorded for a specific commit.
*   **User Story:** "As a Developer, I want to retrieve the current definition of function `X` (its latest version), and also be able to see a list of commits where this function (by its conceptual ID) was previously modified, along with the GIDs of its state in those commits."
*   **Acceptance Criteria:**
    *   User can query the current state (latest version) of entities (File, Function, Class, BasicBlock, ExternalLibrary, etc.) by GID (of the latest version) or CID.
    *   User can search for current state entities by type and properties.
    *   User can retrieve direct callers/callees, members, inheritance/implementation relationships for the current version of entities.
    *   User can retrieve a list of `Commit` GIDs/hashes where a conceptual entity (identified by its CID) was created, modified, or deleted.
    *   User can retrieve the properties of a specific GID-identified entity version (which is tied to a commit).
    *   API responses are in JSON. Queries are performant as per NFRs.

**FR-007: Impact Analysis Query (Current State)**
*   **Feature Name:** Current State Impact Analysis Query
*   **Description:** The system shall allow users to trace dependencies beyond direct relationships for the *current* version of the code. Historical impact analysis is out of scope for v1.0.
*   **User Story:** "As a Developer, if I change the current version of Python function `Y`, I want to find all other current Python functions that might be affected by querying CodeGraph."
*   **Acceptance Criteria:**
    *   User can query for N-depth callers/callees of the current version of a function.
    *   User can query for all current functions/methods that use the current version of a specific class/type.
    *   Query depth is configurable. Results indicate dependency path for current versions.

**FR-008: Cross-Language Dependency Identification (Current State)**
*   **Feature Name:** Current State Cross-Language API Dependency Identification
*   **Description:** For the *current* version of services, identify potential cross-language API calls.
*   **User Story:** "As an Architect, I want to see if our current Python `OrderService` calls APIs from our current Java `InventoryService`."
*   **Acceptance Criteria:**
    *   System can identify `APIRoute` nodes (current version).
    *   System can link `APIRoute` nodes to their handler `Function`s (current version).
    *   (Stretch) System can identify potential outbound API calls from a `Function` (current version) and attempt to link them to known `APIRoute`s (current version).

**FR-009: Ontology Management (Internal - Extended for Versioning)**
*   **Feature Name:** Ontology Definition and Access (including Versioning Concepts)
*   **Description:** The system shall use a defined ontology for all code entities, relationships, CFG elements, external library dependencies, **`Commit` nodes, and versioning constructs (properties and relationships)**. The Ontology Service will provide programmatic access to these definitions for other CodeGraph services.
*   **User Story:** "As a CodeGraph Developer working on the Ingestion Worker, I need to programmatically access the definition of a `Commit` node, its `PARENT_COMMIT` relationship, and properties like `createdInCommitGid` for `Function` nodes from the Ontology Service, so I can correctly build the versioned graph."
*   **Acceptance Criteria:**
    *   The CodeGraph ontology (including `Commit` nodes, `PARENT_COMMIT` relationships, and versioning properties like `createdInCommitGid`, `lastModifiedInCommitGid` for entities) is formally defined and stored.
    *   The Ontology Service provides an internal API to retrieve these ontology definitions.
    *   The Ingestion Worker uses the Ontology Service for validation of versioned data.
    *   A documented process exists for CodeGraph developers to update/evolve the ontology, including versioning aspects.

**FR-010: Secure API Access**
*   **Feature Name:** API Authentication
*   **Description:** All CodeGraph API endpoints must be secured. Clients (CLI, scripts, future UI) must authenticate using API keys.
*   **User Story:** "As an Administrator of CodeGraph, I want to ensure that only authorized users and systems can access the CodeGraph API, so that our codebase information (current and historical) is protected."
*   **Acceptance Criteria:**
    *   API requests to CodeGraph without a valid API key are rejected with a 401 Unauthorized status.
    *   API requests with an invalid, expired, or revoked API key are rejected.
    *   A mechanism exists for generating, managing, and securely storing API keys (handled by User & Config Service).

**FR-011: Control Flow Graph Querying (Current State)**
*   **Feature Name:** Current State Control Flow Graph Querying
*   **Description:** The system shall provide API/CLI endpoints to query the extracted CFG elements for the *current* (latest known) version of functions/methods. Querying CFGs of arbitrary past versions is a more advanced historical query.
*   **User Story:** "As a Developer, I want to retrieve the CFG for the latest version of `function_X` via the CodeGraph API, so I can understand its current internal logic."
*   **Acceptance Criteria:**
    *   User can retrieve all `BasicBlock` nodes (latest version) associated with the latest version of a given `Function` (identified by GID of latest version or CID).
    *   User can retrieve the `FIRST_BLOCK` for the latest version of a given `Function`.
    *   User can traverse `NEXT_BLOCK` and `BRANCHES_TO` relationships between `BasicBlock`s of the latest function version.
    *   API responses for CFG queries are in a clear, structured JSON format.

**FR-012: Build System Dependency Ingestion and Querying (Current State)**
*   **Feature Name:** Current State Build System Dependency Ingestion and Querying
*   **Description:** The system shall parse common build system files to identify *currently* declared external library dependencies (i.e., from the latest processed commit of the build file) and represent them in the knowledge graph. It shall provide API/CLI endpoints to query these currently declared dependencies.
*   **User Story:** "As a Tech Lead, I want to query CodeGraph to list all projects that *currently* declare a direct dependency on 'library-foo', so I can assess its present usage."
*   **Acceptance Criteria:**
    *   The system successfully parses common build files (package.json, requirements.txt/pyproject.toml, pom.xml, build.gradle) from the latest commit context.
    *   Extracted dependencies are created as `ExternalLibrary` nodes, linked via `DECLARES_DEPENDENCY` (carrying version and commit context) to the `File` node of the build file (latest version).
    *   User can query for all `ExternalLibrary` nodes currently associated with a repository or module.
    *   User can search for repositories/modules that currently depend on a specific `ExternalLibrary`.

**FR-013: Commit Metadata Ingestion and Querying**
*   **Feature Name:** Git Commit Metadata Ingestion and Basic Querying
*   **Description:** The system shall ingest metadata for each processed Git commit (hash, parent(s), author, committer, dates, message) and store it as `Commit` nodes in the knowledge graph, allowing basic queries on commit history.
*   **User Story:** "As a Developer, I want to list the last 10 commits for a repository 'RepoA', showing commit hash, author, date, and summary message, using the CodeGraph API, so I can get an overview of recent activity."
*   **Acceptance Criteria:**
    *   `Commit` nodes are created in Neo4j with properties: `commitHash`, `shortHash`, `authorName`, `authorEmail`, `authorDate`, `committerName`, `committerEmail`, `commitDate`, `message`, `summary`, `repositoryGid`.
    *   `PARENT_COMMIT` relationships correctly link `Commit` nodes to their parent(s).
    *   API endpoint exists to list commits for a repository with filtering options (e.g., by branch (if tracked with commit), author email, date range).
    *   API endpoint exists to retrieve details (metadata and list of changed file paths with change type) for a specific commit hash.

**FR-014: Basic Historical Entity State Querying**
*   **Feature Name:** Basic Historical Entity State Querying
*   **Description:** The system shall allow querying for basic information about a code entity (e.g., a function) as it existed in specific past commits, or list commits where its conceptual version changed.
*   **User Story:** "As a Developer, I want to see the commit history for a specific function (identified by its Canonical ID) to understand when it was last modified, by whom, and what its GID was in that commit, so I can trace its evolution."
*   **Acceptance Criteria:**
    *   API endpoint allows retrieving a list of `Commit` GIDs/hashes where a conceptual entity (identified by its CID) was modified (i.e., a new version of it was created/its state changed).
    *   For each such commit, the API response includes the GID of the entity node representing its state in that commit.
    *   (Stretch for v1.0) API endpoint allows retrieving key properties of an entity (e.g., function signature, start/end lines for a specific entity GID which is tied to a commit) as they were recorded for that version. Full AST/CFG reconstruction for an arbitrary past version is out of scope for v1.0.

**FR-015: Data Structuring for Future AI/ML Analytics**
*   **Feature Name:** Data Structuring for Future AI/ML Analytics
*   **Description:** The versioned graph data, including commit history, entity changes over time (which GID represents which conceptual entity at which commit), CFG metrics (like complexity if stored), and dependency evolution, shall be structured and stored in a way that facilitates future extraction and processing for AI/ML model training (e.g., for predicting change impact, bug likelihood, or detecting anomalies). This is a design principle for data modeling.
*   **User Story:** "As a CodeGraph System Architect, I want the historical data, commit linkages, and versioned entity states to be queryable and exportable in a format that data scientists can later use to build predictive models, even if CodeGraph v1.0 doesn't build those models itself. The schema should support this future need."
*   **Acceptance Criteria:**
    *   The Neo4j graph schema (nodes, relationships, properties for commits and versioned entities) is documented with future AI/ML use cases in mind (e.g., ability to extract sequences of changes for a given entity CID).
    *   Key metrics that could be derived from the versioned graph (e.g., churn per file/function by counting commit modifications, complexity change of a function's CFG over commits, dependency addition/removal frequency per project) are identifiable and extractable from the stored data.
    *   (No specific AI/ML features or complex data aggregation/analytics are built in v1.0, but the data foundation is laid by capturing versioned states and commit links).

---

## 5. Non-Functional Requirements (NFRs)

**5.1. Performance**
*   **NFR-001 (Incremental Update Latency - Commit Based):** For a typical new Git commit (e.g., modifying a few files, average complexity), the system running on an adequately resourced Docker Desktop host should detect the commit, parse affected files (source code for entities & CFGs, and any relevant build files), and update the versioned knowledge graph within 5 minutes (P95).
*   **NFR-002 (Initial History Scan Throughput):** For the initial scan of a repository's Git history, the system should aim to process at least 1,000 commits per hour, assuming commits of average size and complexity, on an adequately resourced host. This includes parsing all changed files within those commits and updating the graph. Performance will be highly dependent on commit content, repository size, and host resources.
*   **NFR-003 (API Query Response Time - Current State Queries):** Common API queries for the *current* state of entities, CFGs, and dependencies (e.g., get direct callers/callees, get entity by GID, list direct dependencies for a project, list basic blocks for a small function) should respond within 750ms (P95) for a moderately sized graph.
*   **NFR-004 (API Query Response Time - Basic Historical Queries):** Basic historical queries (e.g., list commits for a file, get last modified commit for a function's conceptual ID, retrieve metadata for a specific commit) should respond within 10 seconds (P90). Complex historical graph traversals or full state reconstruction for past commits are not a v1.0 performance focus.
*   **NFR-005 (File Watcher Git Detection Latency):** New commits in monitored Git repositories should be detected by the File Watcher service within 2 minutes of being pushed to the remote (assuming a configurable polling interval).

**5.2. Scalability**
*   **NFR-006 (Codebase & History Size):** The system (v1.0 running on Docker Desktop) should be able to handle and provide reasonable performance for repositories with up to 50,000 commits and a current version codebase size of up to 10 million LOC (across all monitored repositories). Neo4j and PostgreSQL storage will grow significantly with history; Docker volumes must accommodate this. Clear documentation on storage estimation guidelines will be provided.
*   **NFR-007 (Number of Repositories):** Support for managing configurations for at least 100 monitored repositories within the User & Config Service.
*   **NFR-008 (Concurrent API Users/Queries):** The API Gateway and backend query services, running on Docker Desktop, should support at least 20-50 concurrent requests without significant degradation in performance. Actual concurrency will be limited by host machine resources.
*   **NFR-009 (Language, Build System, VC System Extensibility):** The architecture must allow for adding new language parsers (including their CFG extraction capabilities) and new build file parsers. For v1.0, Git is the only version control system supported for historical analysis.
*   **NFR-010 (Ontology Scalability):** The CodeGraph ontology model, including versioning concepts, should be extensible to accommodate new entity types, relationship types, and properties as support for new languages, deeper analysis features, or more build systems are added, and to support evolving AI/ML data requirements.

**5.3. Reliability & Availability**
*   **NFR-011 (System Uptime):** Core API services (API Gateway, Graph Query Service) should be available whenever the Docker Compose stack for CodeGraph is running and healthy. Aim for high reliability during active use.
*   **NFR-012 (Fault Tolerance - Parsers):** Failure of a single language parser or build file parser container instance, or failure to parse a single malformed file (for a specific commit), should not affect other parser instances or the processing of other files/commits. Errors should be logged with commit context, and the system should attempt to continue. The Orchestration Service should manage retries for transient parser failures.
*   **NFR-013 (Fault Tolerance - Services):** Individual microservice containers should be designed to be stateless where possible. Docker Compose will be configured with restart policies (e.g., `restart: unless-stopped`) to automatically restart failed containers.
*   **NFR-014 (Data Persistence - Pending Relationships):** The mechanism for handling "pending relationships" (which now also need commit context) must ensure that these are durably stored (e.g., in PostgreSQL) until they can be resolved or are explicitly deemed unresolvable.
*   **NFR-015 (Message Queue Reliability):** Messages in RabbitMQ (including commit events and parsing tasks with commit context) should be configured for persistence (durable queues and persistent messages). The RabbitMQ container should use a Docker volume for its data. Dead-letter queues (DLQs) should be configured.

**5.4. Maintainability & Extensibility**
*   **NFR-016 (Modular Design):** Services (Docker containers) should be independently deployable (within Docker Compose) and testable. Clear interfaces (APIs, message schemas for commit data, parsed code/build data) between services.
*   **NFR-017 (Code Quality):** Code for each service should follow established coding standards, be well-documented (APIs, complex logic for CFG extraction, build file parsing, versioned graph ingestion), and have good unit/integration test coverage (>80% for critical components).
*   **NFR-018 (Ease of Adding New Parsers & Historical Processors):** A documented process and clear extension points should exist for adding a new language parser (including CFG extraction and handling commit context) or a new build file parser. Enhancements to historical data processing logic should be manageable.
*   **NFR-019 (Ontology Evolution for Versioning):** The system must support schema evolution for the CodeGraph ontology, particularly for versioning aspects. A documented process for managing ontology changes and migrating existing versioned data (if necessary) must be in place.

**5.5. Security**
*   **NFR-020 (Secure API):** All API Gateway endpoints protected by API key authentication. HTTPS if deployed with a reverse proxy.
*   **NFR-021 (Protection of Codebase Data & History):** Sensitive config (private repo keys for Git access) encrypted at rest in PostgreSQL. Graph primarily stores structure/metadata/commit info, not raw code diffs unless explicitly chosen for a feature (which is not in v1.0).
*   **NFR-022 (Secure Inter-Service Communication):** Docker network provides isolation. mTLS is a future consideration.
*   **NFR-023 (Dependency Isolation for Parsers):** Language and build file parsers run in isolated Docker containers. Resource limits configurable in Docker Compose.
*   **NFR-024 (Credential Management for Git):** Secure storage and handling of Git credentials (e.g., SSH keys mounted securely to File Watcher, tokens passed as environment variables from `.env` files). Credentials encrypted at rest by User & Config Service.
*   **NFR-025 (Least Privilege):** Service accounts for databases/RabbitMQ with minimum necessary permissions. Containers run with non-root users where possible. File Watcher's Git access should be read-only for fetching history.

**5.6. Usability (Developer Experience for API/CLI)**
*   **NFR-026 (API Discoverability & Documentation):** OpenAPI (Swagger) specification provided, accessible, with clear examples for all endpoints including new CFG, dependency, and **historical/commit-based queries**. Documentation must explain how to interpret versioned data.
*   **NFR-027 (CLI Ergonomics):** Intuitive CLI with clear commands for current state and historical queries. Help messages, consistent parameters, JSON output option. Configurable API endpoint/key.
*   **NFR-028 (Error Reporting):** Clear, actionable API/CLI errors with context, especially for historical queries or Git processing issues. Consistent JSON error format.
*   **NFR-029 (Feedback on Long Operations):** Immediate feedback (job ID) for long operations (scans, historical imports) and status polling. Progress indication for historical scans should show commit processing progress.

**5.7. Data Integrity**
*   **NFR-030 (GID Uniqueness):** GIDs must be globally unique for every versioned instance of an entity.
*   **NFR-031 (Canonical ID Stability):** CIDs must be stable and consistently identify conceptual entities across all their historical versions.
*   **NFR-032 (Ontology Adherence for Versioned Data):** All data in Neo4j (including `Commit` nodes, versioned entities, CFGs, dependencies) must conform to the CodeGraph ontology. Ingestion validates data.
*   **NFR-033 (No Data Loss during Incremental Updates of History):** Incremental updates (processing new commits) should not cause loss or corruption of previously ingested historical data.
*   **NFR-034 (Transactional Updates for Versioned Graph):** Neo4j updates for each commit (creating `Commit` node, linking entities, etc.) performed transactionally to ensure graph consistency.

---

## 6. User Interface (UI) / User Experience (UX) Considerations

While a full Web-based User Interface (UI) for graph visualization and exploration is out of scope for Version 1.0 of CodeGraph, the Developer Experience (DX) for the API and any accompanying Command Line Interface (CLI) is paramount. The API design should, however, keep future UI needs in mind, providing endpoints that can efficiently feed data for visualization of code structures, Control Flow Graphs, dependency relationships, **and commit histories or evolutionary timelines of code entities.**

### 6.1. API Developer Experience
*   **Clarity and Consistency:** API endpoints, request/response structures, parameter names, and error codes will be consistent and predictable across the entire API surface, including historical data endpoints. RESTful best practices will be followed.
*   **Comprehensive Documentation:** An OpenAPI (Swagger) specification will be provided and maintained. This documentation will be easily accessible and include:
    *   Detailed descriptions of all endpoints, parameters (including those for historical queries like commit hashes or date ranges), and authentication methods.
    *   Example requests and responses for each endpoint, illustrating how to query both current and basic historical data.
    *   Clear explanations of all possible HTTP status codes and error response formats.
    *   Information on rate limits, if implemented.
    *   Guidance on how to interpret versioned data and use CIDs vs GIDs for historical tracking.
*   **Useful Error Messages:** Error responses will be specific, provide context about what went wrong (e.g., "commit hash not found", "historical data not yet processed for this range"), and suggest potential fixes or next steps where possible.
*   **Client Libraries (Future Consideration):** Consideration will be given to auto-generating basic client libraries for popular programming languages from the OpenAPI specification in future iterations to simplify API integration, including historical queries.
*   **Authentication:** API key authentication will be straightforward to implement on the client-side.
*   **Rate Limiting Feedback:** If implemented, clear HTTP 429 responses with `Retry-After` headers will guide client behavior.
*   **Idempotency:** Endpoints for resource creation/update will support idempotency where appropriate.

### 6.2. CLI Design Principles
If a CLI is provided as a primary means of interaction with CodeGraph:
*   **Command Structure:** Standard CLI conventions (e.g., `codegraph <noun> <verb> [options] [args]`). Clear and consistent naming for commands and options, including those for historical queries (e.g., `codegraph log <repo_name>`, `codegraph entity history <entity_cid>`).
*   **Helpful Output:** Default output human-readable and informative. Option for structured JSON output (`--output json`). For historical data, output should clearly indicate commit context.
*   **Interactivity (Optional):** For complex commands or configurations, consider interactive prompts.
*   **Configuration:** Easy CLI configuration for API endpoint URL and API key.
*   **Verbosity Control:** Flags like `-v`, `-vv`, `--quiet`.
*   **Error Handling:** Clear error messages, non-zero exit codes on failure.
*   **Tab Completion (Future Consideration):** Shell auto-completion.
*   **Progress Indication:** For long-running commands (e.g., initial repository history scan trigger), provide progress indication (e.g., commits processed / total commits to process).

### 6.3. (Optional) Web UI Guiding Principles (for future consideration)
Should a Web UI be developed:
*   **Primary Goal:** Intuitive visualization of code structures, Control Flow Graphs, dependency graphs, **and the evolution of these elements over time (e.g., commit timelines, visual diffs of graph structures between versions)**. Interactive exploration of both current and historical states.
*   **Style:** Modern, clean, minimalist, focusing on information clarity and performance.
*   **Key Features (Conceptual):** Interactive graph rendering, search/filtering (with time/commit dimension), entity detail views (showing current and past versions), saved queries, ability to construct common queries without Cypher, visualization of CFG paths, mapping of external library usage, **and a timeline view for repositories/entities showing commits and significant changes.**
*   **Inspiration (Appearance & Functionality):** Tools like Neo4j Bloom, Kiali, Sourcegraph's UI, Gource (for visualizing history).
*   **Performance:** UI must remain responsive with large datasets and historical queries.

---

## 7. Deployment & Operations

### 7.1. Deployment Strategy
*   **Containerization:** All CodeGraph microservices (including File Watcher, Language Parsers, Build File Parsers), Neo4j, PostgreSQL, and RabbitMQ will be packaged as Docker containers.
*   **Local Development & Deployment:** Docker Compose will be the primary tool using a `docker-compose.yml` file.
    *   Neo4j container configured for host access on Bolt port `7921`, HTTP port `7922`, and HTTPS port `7923` (mapped from its internal container ports).
    *   PostgreSQL container maps to host port e.g., `5433`.
    *   RabbitMQ Management UI maps to host port e.g., `15673`.
    *   API Gateway maps to host port e.g., `8181`.
    *   Persistent data for Neo4j (versioned graph), PostgreSQL (configs, commit logs), and RabbitMQ (if enabled) via named Docker volumes.
*   **Environment Configuration:** Via `docker-compose.yml` and `.env` files (gitignored, containing secrets like Git tokens).
*   **CI/CD Pipeline (Conceptual for CodeGraph Development):** Automated builds, unit/integration tests, Docker image creation to a registry. End-users pull images and run `docker-compose up -d`.

### 7.2. Configuration Management
*   **Service Configuration:** Loaded from environment variables (via Docker Compose) and/or mounted config files.
    *   **Neo4j:** `NEO4J_AUTH="neo4j/test1234"`. Container-internal Bolt port `7689` mapped to host `7921`. Container-internal HTTP port `7474` mapped to host `7922`. Container-internal HTTPS port (e.g., `7473`) mapped to host `7923`. `NEO4J_dbms_default__database=codegraph`. Sufficient memory allocation for historical data.
    *   **PostgreSQL:** Entrypoint/init script creates `codegraph_metadata` DB and app user.
    *   **RabbitMQ:** Standard configuration via environment variables.
*   **Application Configuration (User-facing):** Stored in User & Config Service (PostgreSQL), e.g., repository URLs, branch to track, initial history depth, build file paths.

### 7.3. Monitoring & Logging requirements
*   **Logging:** Structured logs (JSON) to `stdout`/`stderr` from all services, including commit hashes in relevant log entries for traceability. Accessed via `docker-compose logs <service_name>`. Optional local ELK/Loki stack.
*   **Monitoring (Metrics):** Services expose `/metrics` (Prometheus format). Metrics to include queue lengths for commit processing, parsing rates per commit, historical ingestion backlog size. Optional local Prometheus/Grafana stack.
*   **Alerting:** Primarily for user-driven local troubleshooting.

### 7.4. Backup and Recovery Strategy
*   **Neo4j (Docker Volume):** `neo4j-admin dump --database=codegraph` executed against container. This will now include all historical commit data and versioned entities, potentially resulting in large dump files. Document procedure and storage considerations. Restore via `neo4j-admin load`.
*   **PostgreSQL (Docker Volume):** `pg_dump -d codegraph_metadata` (includes configurations, potentially detailed commit logs). Restore via `psql`. Document procedure.
*   **RabbitMQ (Docker Volume, if persistence enabled):** Definitions export/import. Volume backup for persistent messages.
*   **Configuration Data:** `docker-compose.yml` and `.env` files version controlled (with `.env` gitignored and managed securely by the user).
*   **RTO/RPO:** Dependent on user's backup practices for Docker volumes (which will be larger due to history) and CodeGraph config. System will provide tools/docs for backup.

---

## 8. Success Metrics & KPIs

*   **M1: Code Comprehension & Historical Investigation Time Reduction:**
    *   **KPI:** Average time for a developer to answer predefined questions about current code structure, CFGs, dependencies, AND **basic historical queries (e.g., when a function changed, by whom, what files changed in commit X)** using CodeGraph vs. manual methods.
    *   **Target (v1.0):** At least 50% reduction in time for 10 selected common comprehension/historical tasks.
*   **M2: New Developer Onboarding Time:**
    *   **KPI:** Time for a new developer to make their first meaningful contribution or confidently answer questions about architecture, key control flows, library usage, **and the recent evolution of components they are working on**.
    *   **Target (v1.0):** Qualitative feedback indicating significantly faster ramp-up.
*   **M3: Dependency & Commit Linkage Accuracy:**
    *   **KPI:** Percentage of declared external libraries and Git commits (including parent links and changed files metadata) correctly identified and linked to code entities in the graph.
    *   **Target (v1.0):** >95% for commit metadata capture and linkage; >85% for declared external libraries from supported build files.
*   **M3.1: CFG Element Accuracy:**
    *   **KPI:** Percentage of basic blocks and key conditional/unconditional branches correctly identified in a benchmark set of functions across different versions.
    *   **Target (v1.0):** >80% accuracy for CFG elements in supported languages.
*   **M4: Query Success & Performance:**
    *   **KPI 1:** API query success rate (>99.9%).
    *   **KPI 2:** Adherence to API response time NFRs (NFR-003 for current state, NFR-004 for basic historical).
*   **M5: Graph Freshness (Commit-Based):**
    *   **KPI:** Average latency from a Git commit push to the corresponding versioned update being reflected and queryable in the CodeGraph knowledge graph (NFR-001 target: < 5 minutes P95).
*   **M6: System Adoption & Usage (Post-Launch):**
    *   **KPIs:** Active API users, repositories configured, API query volume (distinguishing current vs. historical queries).
    *   **Target (v1.0):** Steady growth post-launch, with evidence of users utilizing historical query features.
*   **M7: Coverage of Supported Languages, Build Systems, & Versioning:**
    *   **KPI:** Percentage of key elements (entities, CFGs, dependencies, commit links, versioned states) correctly parsed and represented for supported languages/build systems on benchmark projects with known histories.
    *   **Target (v1.0):** >90% for core code entities (latest version); >80% for CFG elements (latest version) and declared dependencies (latest version); >90% for commit metadata and linkage.
*   **M8: User Satisfaction (Qualitative):**
    *   **KPI:** Feedback from users (NPS, surveys) on value, ease of use, performance, **and usefulness of historical insights**.
    *   **Target (v1.0):** Predominantly positive feedback, with specific positive mentions of historical analysis capabilities.
*   **M9: AI/ML Data Readiness:**
    *   **KPI:** Completeness, accuracy, and queryability of versioned data (commits, entity changes over commits, CFG metrics over time, dependency evolution) needed for defined future AI/ML use cases (e.g., change impact prediction, bug likelihood).
    *   **Measurement:** Audit of stored data against data requirements for 2-3 example AI/ML scenarios by a data scientist or architect.
    *   **Target (v1.0):** Core data elements for these scenarios are captured accurately, linked to commits, and retrievable via API/Cypher in a structured manner.

---

## 9. Risks, Assumptions, and Dependencies

### 9.1. Key Risks & Mitigation Strategies

| Risk ID | Risk Description                                                                                                | Likelihood | Impact | Mitigation Strategy                                                                                                                                                                                                                                                                                                                         |
|---------|-----------------------------------------------------------------------------------------------------------------|------------|--------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| R01     | **Complexity of Parsing Some Languages/Constructs:** Accurately parsing all nuances of multiple languages and their dynamic features can be very complex, leading to incomplete or incorrect graph data. | High       | High   | - Prioritize core, static constructs first for each language. <br>- Leverage mature, well-tested parsing libraries. <br>- Iterative approach: Start with a subset of features and expand. <br>- Implement thorough testing with diverse code samples. <br>- Clearly document parsing limitations. |
| R02     | **Performance Bottlenecks in Graph DB (Neo4j on Docker Desktop):** Large, dense graphs (especially with CFG elements and extensive commit history) can lead to slow query performance or ingestion times, constrained by Docker Desktop host resources. | High     | High   | - Optimize graph model for versioned data and common historical/current queries. <br>- Create appropriate indexes in Neo4j (on commit hashes, dates, CIDs, versioning properties). <br>- Profile and optimize Cypher queries. <br>- Ensure Docker Desktop has sufficient resources; document recommendations. <br>- Use batched writes for Ingestion Worker.          |
| R03     | **Scalability of Incremental Updates (Commit-based):** Efficiently identifying changes from new commits and applying them to a large, versioned graph without re-processing unchanged history can be challenging. | Medium     | High   | - Design fine-grained change detection based on Git diffs per commit. <br>- Optimize identification of existing conceptual entities (via CIDs) to link new versions. <br>- Use transactional updates. <br>- Benchmark incremental commit processing performance.                                                                                             |
| R04     | **Ontology Evolution Management (for Versioned Data):** Changing the CodeGraph ontology, especially versioning strategies, after historical data is ingested can be extremely complex and require costly data migrations. | Medium     | High   | - Design initial ontology and versioning model carefully with extensibility in mind. <br>- Version the ontology itself. <br>- Develop strategies for schema migration (aim to minimize breaking changes for v1.0). <br>- Prioritize additive changes to the ontology. |
| R05     | **Accuracy of Canonical ID Generation:** Ensuring CIDs are truly canonical and stable across all versions and refactors is critical for historical tracking. | Medium     | Medium | - Define robust CID generation rules per language and entity type. <br>- Extensive testing of CID stability with refactoring scenarios across commit histories. <br>- Document CID strategy.                                                                                                      |
| R06     | **Dependency on External Parser Libraries:** Bugs or limitations in third-party parser libraries can impact CodeGraph. | Medium     | Medium | - Choose well-maintained, widely used parser libraries. <br>- Abstract parser interactions. <br>- Vet new versions before upgrading. <br>- Consider contributing fixes or forking.                                                                                                                                              |
| R07     | **Handling Very Large Files or Repositories on Docker Desktop**: Extremely large files/repositories or very long commit histories could strain host resources. | Medium     | Medium | - Implement configurable limits on initial history import depth/file size. <br>- Optimize Git operations performed by File Watcher. <br>- Document performance based on host resources and history size.                                                                                                                             |
| R08     | **Security of Handling Source Code & Git Credentials**: Accessing user's source code and Git credentials requires robust security. | Medium     | High   | - Strict API authentication. <br>- Secure storage/handling of Git credentials (e.g., using mounted SSH keys for File Watcher, PATs passed as secure environment variables). <br>- Isolated Docker environments. <br>- Remind users host system security is crucial. <br>- CodeGraph minimizes storage of raw code.       |
| R09     | **Complexity/Accuracy of CFG Extraction:** Generating accurate CFGs for diverse language constructs can be complex. | High       | Medium | - Start with common control flow statements. <br>- Leverage compiler theories/libraries for CFG logic. <br>- Iteratively refine CFG detail. <br>- Document CFG analysis scope and limitations. |
| R10     | **Diversity & Complexity of Build Systems/Files:** Parsing all variants of build files accurately is challenging. | High       | Medium | - Focus on declarative dependency sections of common configurations. <br>- Avoid executing build scripts (static analysis only). <br>- Document supported build file constructs. <br>- Allow users to specify primary dependency file paths. |
| R11     | **Scalability of Storing Full History:** Storing detailed graph states for every commit for many large repositories can lead to massive data volumes, straining Neo4j/PostgreSQL on Docker Desktop. | High       | High   | - For v1.0, focus on efficient storage of commit metadata and linking changes to commits, potentially by versioning properties on conceptual entities rather than creating full entity duplicates per commit if feasible. <br>- Implement configurable history depth for initial import. <br>- Explore Neo4j data modeling techniques for temporal data that minimize redundancy (e.g., valid time slices). <br>- Clearly document storage implications and provide guidance on pruning old history (future feature). |
| R12     | **Performance of Historical Queries:** Complex queries across many commits or large version histories can be slow if not carefully designed and indexed. | Medium     | High   | - Optimize Cypher queries for historical traversals (e.g., using commit dates, parent links). <br>- Ensure appropriate Neo4j indexing on commit hashes, commit dates, and entity CIDs/versioning properties. <br>- For v1.0, limit the scope of historical queries to simpler ones (e.g., history of one entity, changes in one commit) rather than full graph state comparisons across distant commits. <br>- Consider pre-aggregating some historical metrics if needed (future). |
| R13     | **Complexity of Git History Processing:** Handling complex Git histories (merges, rebases, orphaned commits, very large commits) robustly can be challenging for the File Watcher and Ingestion Worker. | Medium     | Medium | - For v1.0, focus on processing commits along a single primary branch (e.g., main/master). <br>- Clearly define how merge commits are handled (e.g., process changes introduced by the merge, link to multiple parents; complex diffing of merge vs parents is out of scope for v1.0). <br>- Robust error handling for unexpected Git log outputs or repository states. <br>- Allow users to trigger re-processing of history for a repository if issues are found. |
| R14     | **Defining "Change" for AI/ML Data:** Determining what constitutes a meaningful "change event" for entities to feed into future AI/ML models requires careful definition and consistent capture. | Medium     | Medium | - Start with simple change indicators based on the versioned graph (e.g., entity properties changed between its GID-version linked to commit N and its GID-version linked to commit N-1, new CFG blocks, dependency version string change). <br>- Ensure the raw data (e.g., entity state per commit, commit metadata) is captured, allowing flexibility for future AI/ML feature engineering. <br>- Document the captured change indicators and how they relate to the versioned graph. |

### 9.2. Assumptions Made
*   **A01 (Trusted Codebases):** The system assumes it is parsing code from trusted sources provided by the user. Users are responsible for the security of the codebases they choose to analyze.
*   **A02 (Syntactically Correct Code & Well-Formed Build Files):** Parsers will primarily target syntactically correct code according to the specifications of the supported languages and well-formed build files for supported formats. Graceful logging of errors for malformed files is expected.
*   **A03 (Availability of Parsing Libraries & Git CLI):** Suitable open-source libraries/grammars exist for target languages (including basic CFG analysis support) and build file formats. Git CLI is assumed to be installable and usable within relevant Docker containers.
*   **A04 (Resource Availability on Docker Desktop Host):** The host machine running Docker Desktop has sufficient CPU cores, RAM, and disk I/O performance for all CodeGraph containers (services, Neo4j, PostgreSQL, RabbitMQ) to operate effectively for the targeted codebase sizes and historical depths. Resource recommendations will be documented.
*   **A05 (Git as Primary SCM for History):** While local file system paths (via volume mounts) are supported for monitoring current state (with basic timestamp versioning), rich historical analysis and versioning are primarily targeted at Git-based repositories.
*   **A06 (Network Access for Git):** CodeGraph containers (specifically File Watcher, Orchestrator, or Parsers if they clone/fetch directly) need network access from the Docker environment to fetch remote Git repositories if configured.
*   **A07 (English Language Identifiers):** Initial focus for any NLP-like features (future) or complex name analysis assumes English-based identifiers in source code. Ontology terms and system messages will be in English.
*   **A08 (Docker Environment):** The primary deployment and execution target for CodeGraph v1.0 is Docker Desktop (on Windows, macOS, or Linux) using Docker Compose for orchestration.
*   **A09 (Localhost Accessibility & Port Configuration):** Services that need to be accessed from the host machine (e.g., API Gateway on `localhost:8181`, Neo4j Browser via HTTP on `localhost:7922` and HTTPS on `localhost:7923`, Neo4j Bolt on `localhost:7921`, PostgreSQL client on e.g., `localhost:5433`, RabbitMQ Management UI on e.g., `localhost:15673`) will have their ports correctly mapped in `docker-compose.yml` to `localhost` using non-conflicting port numbers. Inter-service communication within the Docker environment will use Docker network aliases and internal container ports.
*   **A10 (Automatic Database/Queue Creation):** Setup scripts or Docker entrypoints for PostgreSQL and RabbitMQ containers (or an initialization container in the Docker Compose setup) will handle the creation/initialization of necessary databases (e.g., `codegraph_metadata` for PostgreSQL), users, and queues if they don't already exist on volume-persisted data. Neo4j will use the `codegraph` database.
*   **A11 (Git Repository Integrity):** Assumed that the Git repositories being processed are well-formed and not corrupted. The system will rely on standard Git CLI operations.
*   **A12 (Reasonable Commit Sizes & Frequency):** Assumed that individual commits and the frequency of commits are within reasonable bounds that allow the system to keep up with near real-time processing. Extremely large commits or very high-frequency commit storms might introduce processing delays.
*   **A13 (Stable Internet Connection for Remote Repos):** For monitoring remote Git repositories, a stable internet connection is assumed for the File Watcher service to perform `git fetch` operations.

### 9.3. External Dependencies
*   **E01 (Source Code Repositories & Git Access):** Availability and accessibility of configured Git repositories (e.g., network connectivity to `github.com`, valid credentials for private repos) or local file systems (which must be correctly mounted as Docker volumes).
*   **E02 (Third-Party Parser Libraries & Grammars):** Functionality, maintenance, licensing, and compatibility of chosen parser libraries and grammars for code (including CFG extraction capabilities) and build file formats.
*   **E03 (Neo4j Database Instance):** Requires a running Neo4j instance, configured as specified (username `neo4j`, password `test1234`, database `codegraph`). Connection for CodeGraph services: `bolt://codegraph-neo4j:7689`. Host access: `bolt://localhost:7921` (Bolt), `http://localhost:7922` (HTTP), and `https://localhost:7923` (HTTPS). This will be provided by a Docker container managed by Docker Compose.
*   **E04 (PostgreSQL Database Instance):** Requires a running PostgreSQL instance. Host access (e.g., `localhost:5433`). Internal connection for CodeGraph services (e.g., `codegraph-postgres:5432`). The CodeGraph application database (`codegraph_metadata`) within this instance will be automatically created. This will be provided by a Docker container managed by Docker Compose.
*   **E05 (Message Queue Instance):** Requires a running RabbitMQ instance. Host access for Management UI (e.g., `localhost:15673`). Internal connection for CodeGraph services (e.g., `codegraph-rabbitmq:5672`). This will be provided by a Docker container managed by Docker Compose.
*   **E06 (Cloud Provider Services):** **EXPLICITLY NONE.** The system is designed for Docker Desktop and does not rely on cloud-specific services for its core functionality.
*   **E07 (Operating System for File Watcher & Parser Containers):** Containers will typically be Linux-based. The host OS for Docker Desktop can be Windows, macOS, or Linux, and must support Docker volume mounting and allow containers to execute Git CLI commands.
*   **E08 (Docker Desktop Software):** The system relies on a functional installation of Docker Desktop (or a compatible Docker environment with Docker Compose V2 support) on the user's machine for execution.
*   **E09 (Git Command Line Interface):** The Git CLI must be installed and accessible within the Docker containers that perform Git operations (primarily File Watcher, potentially Orchestrator or Parser services).

---

## 10. Future Considerations & Roadmap

With the integration of basic CFG analysis, build system dependency tracking, and foundational historical data capture in v1.0, the future roadmap can build upon this significantly richer foundation.

**Phase 1.x (Enhancements to v1.0 capabilities):**
*   Expand support for more build system file variants and configurations (e.g., more complex Gradle configurations, other package managers like NuGet, Cargo, Go Modules).
*   Increase the depth and accuracy of CFG analysis (e.g., better handling of exceptions, more complex loop structures, inter-procedural CFG hints by linking call sites to target function CFGs).
*   Improve heuristics for linking external library nodes to actual source code if that source code is also parsed by CodeGraph (e.g., for monorepos or local library development).
*   Performance optimizations for storing and querying very large historical graphs and complex CFGs.
*   Support for more programming languages and their specific CFG/dependency paradigms.
*   **More sophisticated historical queries:** e.g., "show diff of function X's properties or CFG structure between commit A and commit B," "show all functions that called function Y when its conceptual version was Z."
*   **Basic AI/ML-driven insights (prototypes):** Based on the collected historical data, prototype simple predictive models (e.g., "files changed frequently together," "functions with high churn and complexity") or basic anomaly detection (e.g., "unusually large commit affecting critical files," "sudden spike in new dependencies").

**Phase 2 (Web UI, IDE Integrations, Deeper Analysis & AI/ML):**
*   **Web UI:** Development of an interactive web-based user interface for graph visualization (code structures, CFGs, dependency graphs, **and commit timelines/evolutionary changes**). Features would include advanced search, intuitive exploration, saved queries, and dashboards.
*   **IDE Integrations:** Creation of plugins for popular IDEs (e.g., VS Code, JetBrains IDEs) to display CodeGraph insights directly within the development environment (e.g., find usages, show callers/callees, navigate CFGs, view library dependency information, **and provide historical context/blame-like features linked to CodeGraph data**).
*   **Advanced Static Analysis & AI/ML:**
    *   Full-fledged Data Flow Analysis (DFA) building upon CFG capabilities (e.g., variable liveness analysis, reaching definitions, use-def chains).
    *   Basic Taint Tracking for identifying potential security vulnerabilities related to data flow.
    *   Mature **predictive models** for change impact, bug likelihood (based on historical churn, complexity, dependencies), refactoring suggestions.
    *   Advanced **anomaly detection** in code evolution, CFG structures, or dependency patterns.
*   **Automated Pattern Detection:** Allow users to define custom code patterns (or use pre-built ones for common issues) and detect architectural anti-patterns, potential security vulnerabilities (e.g., using known vulnerable library versions identified in v1.0, or risky data flows), or opportunities like dead code identification, leveraging both current and historical graph data.
*   **Refactoring Assistance:** Provide enhanced insights to aid large-scale refactoring, such as more accurately identifying all affected components of a proposed change using CFG, dependency data, and historical change impact.

**Phase 3 (Advanced Customization, Ecosystem Platform):**
*   **Historical Analysis & Graph Versioning (Advanced):** Full graph state time-travel queries allowing complex analysis of the graph as it existed at any arbitrary past commit. Semantic diffing of code structures between versions.
*   **Custom Parsers/Ontology Extensions (Advanced):** Allow users or organizations to define custom entity/relationship types within the CodeGraph ontology or integrate proprietary language/build system parsers into their CodeGraph instance with more ease.
*   **Integration with CI/CD (Advanced):** More intelligent checks in the Continuous Integration (CI) pipeline based on historical trends and predictive models (e.g., "this PR has a high predicted risk of introducing bugs," "this change significantly deviates from common evolution patterns for this module").
*   **CodeGraph as a Platform:** APIs for external tools to contribute to and consume the versioned knowledge graph, fostering an ecosystem of code intelligence applications.
*   **Support for other Version Control Systems:** Extending historical analysis beyond Git to systems like Mercurial or Perforce, if demand exists.

**Long-Term Vision:**
*   CodeGraph as the central, indispensable "nervous system" for understanding all code within an organization or for individual developers managing multiple projects. Its strength will lie in its comprehensive view, combining structural analysis, control flow understanding, dependency tracking, and a deep historical perspective.
*   Enabling automated code migration, modernization, and even generation tasks based on deep graph understanding and learned patterns from code evolution.
*   Becoming a platform for a wide range of advanced code analytics, software engineering intelligence, and developer productivity tools, potentially with a marketplace for plugins or specialized analyzers.
*   Flexible deployment options, from local Docker Desktop for individuals to scalable on-premises server deployments (e.g., using Kubernetes) for teams and enterprises, maintaining a consistent core feature set and data model.

---

## 11. Glossary of Terms

This glossary defines key terms used within the CodeGraph Product Requirements Document for universal understanding.

*   **API (Application Programming Interface):** A set of rules and protocols that allows different software components or services to communicate and exchange information with each other. In CodeGraph, this primarily refers to the RESTful API for interacting with the system.
*   **AST (Abstract Syntax Tree):** A tree representation of the syntactic structure of source code. Each node in the tree denotes a construct occurring in the code. Parsers generate ASTs as an intermediate step.
*   **Basic Block:** In Control Flow Graphs, a straight-line piece of code without any jumps in or out, except at the beginning for entry and at the end for exit/branching. A node in CodeGraph's CFG representation.
*   **Build File Parser Service (BFPS):** A CodeGraph microservice or module responsible for parsing build system files (like `package.json`, `pom.xml`) to extract declared external dependencies.
*   **Build System Integration:** The capability of CodeGraph to parse build system files to extract information, primarily declared external dependencies and potentially module structures.
*   **Canonical ID (CID):** A stable, unique identifier for a conceptual code element (like a specific function, class, basic block, or external library), designed to remain consistent across versions and minor refactorings. Used for tracking entities over time.
*   **CGQL (CodeGraph Query Language):** (Future) A placeholder for an envisioned domain-specific query language for CodeGraph, designed to be simpler for users than raw Cypher for common code analysis tasks.
*   **CLI (Command Line Interface):** A text-based interface used for interacting with the CodeGraph system, allowing users to execute commands to configure, scan, and query codebases.
*   **Code Entity:** A distinct structural element in source code (e.g., file, module, package, class, interface, function, method, variable, parameter, basic block) or a representation of an external component (e.g., external library) or a version control concept (e.g., commit). Represented as a node in the CodeGraph knowledge graph.
*   **Code Relationship:** A connection or interaction between two code entities, such as a function calling another function, a class inheriting from another class, a basic block branching to another, a project declaring a dependency on a library, or a commit having a parent commit. Represented as an edge (relationship) in the CodeGraph knowledge graph.
*   **Commit (Version Control):** A snapshot of changes to a repository at a specific point in time, typically identified by a unique hash (e.g., SHA-1 in Git). Represented as a `Commit` node in CodeGraph.
*   **Control Flow Graph (CFG):** A representation, using graph notation, of all paths that might be traversed through a program (typically a function or method) during its execution. CodeGraph v1.0 aims to represent intra-procedural CFGs, consisting of basic blocks and the control flow transitions between them.
*   **Cypher:** Neo4j's declarative graph query language, used to retrieve and manipulate data stored in the Neo4j graph database.
*   **Docker:** A platform for developing, shipping, and running applications in containers. CodeGraph and all its components are designed to run in Docker containers.
*   **Docker Compose:** A tool for defining and running multi-container Docker applications. CodeGraph uses Docker Compose for local deployment and orchestration.
*   **Event-Driven Architecture:** A software architecture pattern where services communicate by producing and consuming events, often via a message queue. This promotes loose coupling and scalability.
*   **ExternalLibrary:** A CodeGraph node representing a declared third-party library or package dependency identified from a build system file.
*   **File Watcher:** A CodeGraph service responsible for monitoring configured file system paths (via Docker volume mounts) and Git repositories for changes (including new commits) to trigger incremental parsing.
*   **GID (Global Unique ID):** A system-wide unique identifier assigned by CodeGraph to every distinct instance of a node (e.g., a specific version of a function, a specific commit) or relationship in the knowledge graph. Typically a UUID.
*   **Git:** A distributed version control system. CodeGraph v1.0 focuses on Git for historical analysis and version tracking.
*   **Graph Database:** A database that uses graph structures (nodes, edges, and properties) to represent and store data. Neo4j is the graph database used by CodeGraph.
*   **Historical Analysis:** The capability of CodeGraph to query and analyze the state of code, its structure, CFGs, and its dependencies as they existed in past commits or versions recorded in the version control system.
*   **Incremental Update:** The process of updating the CodeGraph knowledge graph by processing only changes from new commits or modified files, rather than re-processing the entire codebase or history from scratch.
*   **Ingestion Worker:** A CodeGraph service responsible for consuming parsed data (from code, build files, including commit context) from language and build file parsers, validating it against the ontology, transforming it, and writing it to the versioned Neo4j graph database.
*   **Knowledge Graph:** A graph-based representation of information and its relationships for a specific domain. In CodeGraph, this is a model of codebases, their components, their internal control flow, their external dependencies, their interconnections, and their evolution over time.
*   **LOC (Lines of Code):** A metric often used to measure the size of a software program by counting the number of lines in the text of the program's source code.
*   **LPS (Language Parser Service):** A CodeGraph microservice dedicated to parsing source code of a specific programming language (or a group of related languages) for a given commit and extracting entities, relationships, and Control Flow Graph elements.
*   **Microservices:** An architectural style where an application is composed of small, independent, and loosely coupled services that communicate over well-defined APIs (often HTTP or message queues).
*   **Neo4j:** A popular, native graph database system used by CodeGraph to store and query the code knowledge graph. CodeGraph's Neo4j instance runs in Docker, accessible from the host on Bolt port `7921`, HTTP port `7922`, and HTTPS port `7923`.
*   **Ontology:** A formal definition of the types, properties, and interrelationships of entities that exist for a particular domain. In CodeGraph, it defines the allowed node labels (e.g., `Function`, `BasicBlock`, `ExternalLibrary`, `Commit`), relationship types (e.g., `CALLS`, `BRANCHES_TO`, `DECLARES_DEPENDENCY`, `PARENT_COMMIT`), and their properties for representing code constructs, control flow, dependencies, and versioning information.
*   **Parser:** A software component that analyzes source code (a sequence of tokens) or build files to determine its grammatical structure with respect to a given formal grammar or format, typically producing an Abstract Syntax Tree (AST) or an internal structured representation.
*   **Polyglot:** Consisting of or using multiple programming languages. CodeGraph is designed to handle polyglot codebases.
*   **PostgreSQL:** A powerful, open-source object-relational database system. CodeGraph uses PostgreSQL (running in Docker, e.g., on host port `5433`) to store relational metadata such as user configurations, API keys, job queue states, detailed commit logs, and ontology definitions.
*   **PRD (Product Requirements Document):** This document, which outlines the vision, features, requirements, and plan for CodeGraph.
*   **RabbitMQ:** An open-source message broker software that implements the Advanced Message Queuing Protocol (AMQP). CodeGraph uses RabbitMQ (running in Docker, e.g., management UI on host port `15673`) for asynchronous communication between its microservices.
*   **Real-time (Near Real-time):** Refers to the system's ability to process and reflect changes (e.g., in source code, build files, or new commits) very shortly after they occur, making the knowledge graph almost immediately up-to-date with the latest versioned information.
*   **RESTful API:** An Application Programming Interface that adheres to the design principles of Representational State Transfer (REST), typically using HTTP methods (GET, POST, PUT, DELETE) and JSON for data exchange.
*   **UUID (Universally Unique Identifier):** A 128-bit number used to identify information in computer systems. Often used for GIDs.
*   **Versioned Knowledge Graph:** A knowledge graph that not only represents the current state of entities and relationships but also captures their evolution over time, typically by associating states with versions or commits from a version control system.


*** RECURSIVE TESTS MUST BE SET UP EVERY PLACE WHERE IT IS APPLICABLE TO ENSURE THIS SYSTEM IS SOLID ***

This is using Neo4j version 5.26.6 with APOC version 5.26.6 and Graph Data Science Library version 2.13.4