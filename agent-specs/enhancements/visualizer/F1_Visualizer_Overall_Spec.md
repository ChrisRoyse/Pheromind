# Feature Specification: F1 - Visual Pheromone & Documentation Landscape Tool

**Document ID:** `agent-specs/enhancements/visualizer/F1_Visualizer_Overall_Spec.md`
**Parent Plan:** [`README_Enhancements_Implementation_Plan.md`](../README_Enhancements_Implementation_Plan.md)
**Version:** 1.0
**Date:** 2025-05-15

## 1. Introduction & Goals

This document specifies the requirements for the "Visual Pheromone & Documentation Landscape Tool." The primary goal is to create a standalone UI application that runs alongside the Pheromind agents, providing a real-time or near real-time visual representation of the `.pheromone` file's signals and `documentationRegistry`.

This tool will help users:
* Understand the swarm's current state and activity.
* Visualize signal evolution and relationships.
* Easily navigate and inspect signals and documented artifacts.
* Identify patterns or anomalies in swarm behavior.
* Improve debugging and monitoring of Pheromind operations.

## 2. User Stories

* As a Pheromind user/developer, I want to see a live stream of signals as they are added to the `.pheromone` file so that I can monitor agent activity in real-time.
* As a Pheromind user, I want to view the details of any signal (full JSON) to understand its specific content.
* As a Pheromind user, I want to filter signals by type, target, or category to focus on specific aspects of the project.
* As a Pheromind user, I want to see a visual representation of how signals relate to project targets (e.g., modules, features) to understand influence patterns.
* As a Pheromind user, I want to easily browse and search the `documentationRegistry` to quickly find links to important project documents.
* As a Pheromind user, I want to see basic statistics about the signals (e.g., count by type) to get an overview of the swarm's state.

## 3. Chosen Technical Approach

* **Type:** Local Web Application.
* **Frontend:** Single Page Application (SPA) using **React with TypeScript**. Styling with **Tailwind CSS**.
* **Backend:** Lightweight **Node.js server using Express.js**.
    * Purpose: To reliably watch the local `.pheromone` file for changes and push updates to the frontend via **WebSockets** (e.g., using `socket.io` or `ws` library). This avoids potential complexities and security restrictions of direct browser file system watching for continuous real-time updates.
* **File Watching:** The Node.js backend will use `chokidar` to monitor the `.pheromone` file.
* **Visualization Libraries (Frontend):**
    * **Vis.js (Network, Timeline components):** For signal network graph and timeline views.
    * **Recharts or Chart.js:** For statistical charts (e.g., signal distribution).
    * Custom React components for list/table views.

## 4. High-Level Architecture

+-------------------------+      Reads      +-----------------+| Pheromind Agents        | ------------> | .pheromone file || (Roo Code Environment)  |      Writes     | (JSON)          |+-------------------------+                 +--------+--------+|| (File System Watch)v+----------------------------------------------------+| Visualizer Backend (Node.js + Express.js)          ||----------------------------------------------------|| - Chokidar: Watches .pheromone                     || - WebSocket Server (e.g., socket.io):              ||   - Reads & parses .pheromone on change            ||   - Pushes updates to connected clients            || - API Endpoint (optional): for initial load        |+------------------------+---------------------------+|| (WebSocket Connection)v+----------------------------------------------------+| Visualizer Frontend (React SPA in Browser)         ||----------------------------------------------------|| - WebSocket Client: Receives data updates          || - State Management (e.g., React Context/Zustand)   || - Components:                                      ||   - Dashboard                                      ||   - Signal Timeline View                           ||   - Signal Network View (Vis.js)                   ||   - Documentation Registry Explorer                ||   - Signal Detail Modal                            ||   - Charts (Recharts/Chart.js)                     |+----------------------------------------------------+
## 5. Data Flow

1.  Pheromind agents (specifically the Scribe) update the `.pheromone` file.
2.  The Visualizer Backend (Node.js server) running locally detects changes to `.pheromone` via `chokidar`.
3.  Upon detection, the backend reads the entire `.pheromone` file, parses the JSON content.
4.  The backend processes this data (if necessary) and emits an event (e.g., `pheromone_updated`) with the new data (signals array and documentationRegistry object) over a WebSocket connection to all connected frontend clients.
5.  The Visualizer Frontend (React app) receives the new data via its WebSocket client.
6.  The frontend updates its internal state.
7.  React components re-render to display the latest signals and documentation registry information.
8.  For initial load, the frontend might request the full `.pheromone` content via WebSocket or a dedicated HTTP GET endpoint on the backend.

## 6. Core Features & Modules

* **Backend Module (`visualizer-backend`):**
    * File watcher for `.pheromone`.
    * WebSocket server for real-time updates.
    * JSON parsing and basic validation of `.pheromone` content before broadcasting.
    * Configuration for `.pheromone` file path (e.g., via command-line argument or environment variable).
* **Frontend Module (`visualizer-frontend`):**
    * **Dashboard View:** Overview stats, entry point to other views.
    * **Signal Timeline/Stream View:** Chronological display of signals.
    * **Signal Network View:** Graph visualization of signals and targets.
    * **Documentation Registry Explorer:** Table/list view of documented artifacts.
    * **Signal Detail View:** Modal displaying full JSON of a selected signal.
    * **State Management:** To hold and manage the `.pheromone` data.
    * **WebSocket Client:** To connect to the backend and receive updates.

## 7. Non-Functional Requirements

* **Performance:** The UI should update smoothly with new signals. Large `.pheromone` files (up to the Scribe's pruning limit) should be handled efficiently. Graph visualizations should remain interactive.
* **Usability:** Intuitive navigation, clear information display.
* **Real-time (Near):** Updates should appear in the UI within a few seconds of the `.pheromone` file changing.
* **Error Handling:** Gracefully handle cases like invalid `.pheromone` JSON, backend connection issues. Display informative messages to the user.
* **Configurability (Basic):** The backend should allow configuration of the `.pheromone` file path.

## 8. Future Considerations (Out of Scope for v1)

* Historical data analysis / replaying signal history.
* Direct interaction/editing of `.pheromone` (explicitly out of scope for this visualizer).
* Advanced analytical queries on signal data.
* User accounts or settings persistence if deployed as a shared tool (v1 is a local tool).

## 9. Detailed Specifications

* **Frontend UI/UX Details:** See [`F1_Visualizer_Frontend_Spec.md`](./F1_Visualizer_Frontend_Spec.md)
* **Backend API & Logic:** See [`F1_Visualizer_Backend_Spec.md`](./F1_Visualizer_Backend_Spec.md)
