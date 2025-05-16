# Pheromind Enhancements Suite

This directory contains the tools developed as part of the Pheromind Enhancements Suite, which aims to significantly elevate the Pheromind framework's usability, observability, and intelligence.

## Features

### F1: Visual Pheromone & Documentation Landscape Tool

A tool for visualizing the `.pheromone` file's signals and documentation registry in real-time.

- **Location**: [`visualizer/`](./visualizer/)
- **Components**:
  - **Backend**: Node.js server with file watching and WebSocket communication
  - **Frontend**: React SPA with dashboard, timeline, network, and documentation views

### F2: Advanced `.swarmConfig` Tuning & Validation UI

A tool for editing, validating, and managing `.swarmConfig` files.

- **Location**: [`swarmconfig_ui/`](./swarmconfig_ui/)
- **Components**:
  - **Frontend**: React SPA with JSON editor and schema validation

### F3: Self-adaptive `interpretationLogic` for Scribe (Phase 1)

Enhanced logging capabilities for the Pheromind Scribe to record detailed information about its interpretation process.

- **Location**: [`adaptive_scribe/`](./adaptive_scribe/)
- **Components**:
  - **Logging**: Utilities for detailed JSONL logging of the Scribe's interpretation process

## Setup and Usage

Each tool has its own README file with specific setup and usage instructions:

- [F1: Visual Pheromone & Documentation Landscape Tool](./visualizer/README.md)
- [F2: Advanced `.swarmConfig` Tuning & Validation UI](./swarmconfig_ui/frontend/README.md)
- [F3: Self-adaptive `interpretationLogic` for Scribe](./adaptive_scribe/README.md)

## Development

### Prerequisites

- Node.js LTS
- npm or yarn

### Common Commands

#### F1: Visual Pheromone & Documentation Landscape Tool

```bash
# Backend
cd tools/visualizer/backend
npm install
npm run dev

# Frontend
cd tools/visualizer/frontend
npm install
npm start
```

#### F2: Advanced `.swarmConfig` Tuning & Validation UI

```bash
cd tools/swarmconfig_ui/frontend
npm install
npm start
```

#### F3: Self-adaptive `interpretationLogic` for Scribe

This feature requires integration with the Pheromind Scribe. See the [README](./adaptive_scribe/README.md) for details.

## Architecture

The tools are designed to work together with the Pheromind framework:

- **F1 (Visualizer)** watches the `.pheromone` file and displays its contents in real-time
- **F2 (SwarmConfig UI)** allows editing and validation of the `.swarmConfig` file
- **F3 (Adaptive Scribe)** enhances the Scribe with logging capabilities

## Future Development

This is the initial implementation of the Pheromind Enhancements Suite. Future phases will include:

- **F3 Phase 2**: Analysis & Suggestion Engine for the Scribe
- **F3 Phase 3**: Human-in-the-Loop Review & Integration UI for the Scribe

## License

This project is part of the Pheromind framework and follows its licensing terms.