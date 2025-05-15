# Feature Specification: F1 - Visualizer Backend

**Document ID:** `agent-specs/enhancements/visualizer/F1_Visualizer_Backend_Spec.md`
**Parent Spec:** [`F1_Visualizer_Overall_Spec.md`](./F1_Visualizer_Overall_Spec.md)
**Version:** 1.0
**Date:** 2025-05-15

## 1. Introduction

This document specifies the backend requirements for the "Visual Pheromone & Documentation Landscape Tool." The backend will be a lightweight Node.js server using Express.js. Its primary responsibilities are to watch the local `.pheromone` file for changes and push updates to connected frontend clients via WebSockets.

## 2. Core Technologies

* **Runtime:** Node.js (LTS version, e.g., v18 or v20)
* **Framework:** Express.js
* **File Watching:** `chokidar`
* **WebSockets:** `socket.io` (recommended for ease of use and features like auto-reconnection) or `ws` (more lightweight).
* **Language:** JavaScript (with JSDoc for type hinting) or TypeScript (preferred for better type safety, transpile to JS for execution).

## 3. Server Setup & Configuration

* **Entry Point:** `server.js` or `index.js`.
* **Configuration:**
    * `PHEROMONE_FILE_PATH`: Path to the `.pheromone` file. Configurable via environment variable (e.g., `process.env.PHEROMONE_FILE_PATH`) or command-line argument. Default to `./.pheromone`.
    * `PORT`: Port for the server to listen on. Configurable via environment variable (e.g., `process.env.PORT`). Default to a suitable port like `3001` or `8080`.
* **Dependencies (`package.json`):**
    * `express`
    * `chokidar`
    * `socket.io` (or `ws`)
    * (If TypeScript) `typescript`, `ts-node`, `@types/node`, `@types/express`, etc.

## 4. Core Logic

### 4.1. File Watching (`fileWatcher.js`)

* Use `chokidar` to monitor the configured `PHEROMONE_FILE_PATH`.
* Watch for `add` (for initial creation) and `change` events on the file.
* **Debouncing/Throttling (Important):** Implement a short debounce (e.g., 200-500ms) for file change events. The Scribe might write to the file rapidly or in multiple small chunks. We only want to process and broadcast after the file has stabilized.
* When a debounced change is detected:
    1.  Read the content of the `.pheromone` file asynchronously (`fs.readFile`).
    2.  Parse the content as JSON.
        * Handle potential parsing errors gracefully (log the error, perhaps notify clients of an invalid file state, but don't crash the server).
    3.  If parsing is successful, pass the parsed data (signals array and documentationRegistry object) to the WebSocket module for broadcasting.

### 4.2. WebSocket Communication (`websocketManager.js`)

* Initialize `socket.io` server, attaching it to the HTTP server created by Express.
* **Connection Handling:**
    * On `connection` event from a new client:
        * Log the connection.
        * Immediately attempt to send the current state of the `.pheromone` file to this new client (see "Initial Data Load"). This ensures new clients get data without waiting for the next file change.
* **Broadcasting Updates:**
    * Provide a function (e.g., `broadcastPheromoneUpdate(data)`) that takes the parsed `.pheromone` data.
    * This function will emit an event (e.g., `pheromone_data_update`) with the data to all connected clients: `io.emit('pheromone_data_update', { signals: data.signals, documentationRegistry: data.documentationRegistry, filePath: configuredPheromonePath, lastModified: fileStats.mtime });`
* **Disconnection Handling:**
    * Log client disconnections.

### 4.3. Initial Data Load

* When a new client connects, or if a client sends a specific "request_initial_data" event:
    1.  Read the current `.pheromone` file (asynchronously).
    2.  Parse it.
    3.  Get file stats (e.g., `fs.stat` for last modified time).
    4.  Emit the data directly to that specific client socket: `socket.emit('pheromone_data_update', { signals: parsedData.signals, documentationRegistry: parsedData.documentationRegistry, filePath: configuredPheromonePath, lastModified: fileStats.mtime });`
    5.  Handle errors (file not found, parse error) by emitting an appropriate error event to the client.

## 5. API Endpoints (Express.js - `routes.js`)

* **`GET /api/pheromone/current` (Optional - for initial load if not solely relying on WebSocket for it):**
    * Reads, parses, and returns the current content of the `.pheromone` file as JSON.
    * Includes `filePath` and `lastModified` timestamp in the response.
    * Handles errors (file not found, parse error) with appropriate HTTP status codes (e.g., 404, 500).
* **`GET /api/status` (Optional - for health check):**
    * Returns a simple status message (e.g., `{ status: "running", watchingFile: "/path/to/.pheromone" }`).

## 6. Error Handling & Logging

* Implement robust error handling for file operations (read, watch), JSON parsing, and WebSocket communication.
* Use a simple console logger (e.g., `console.log`, `console.error`) for events:
    * Server start, port, watched file path.
    * Client connections/disconnections.
    * File change detections.
    * Errors during file processing or broadcasting.
    * Successful broadcasts.
* If `.pheromone` file is not found at startup, log an error and continue running (it might be created later). The watcher should pick it up when it appears.

## 7. Startup Script (`package.json` scripts)

* `"start"`: `node server.js` (or `ts-node src/server.ts` if using TypeScript, then build for production).
* `"dev"`: `nodemon server.js` (or equivalent for TypeScript with `ts-node-dev`) for development with auto-restarts.

## 8. Security Considerations (Minimal for Local Tool)

* Since this is intended as a local development tool run by the user, complex security measures are not a primary concern for v1.
* Avoid exposing the server to the public internet unless explicitly intended and secured.
* No sensitive data other than the `.pheromone` content itself is handled.
