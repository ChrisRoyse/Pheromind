# Pheromind Enhancements Suite

This directory contains the tools developed as part of the Pheromind Enhancements Suite, which aims to significantly elevate the Pheromind framework's usability, observability, and intelligence.

## Available Tools

### F1: Visual Pheromone & Documentation Landscape Tool

A tool for visualizing the `.pheromone` file's signals and documentation registry in real-time.

- **Location**: [`visualizer/`](./visualizer/)
- **Components**:
  - **Backend**: Node.js server with file watching and WebSocket communication
  - **Frontend**: React SPA with dashboard, timeline, network, and documentation views
- **Key Features**:
  - Real-time updates via WebSockets
  - Dashboard with statistics and charts
  - Signal Timeline view for chronological display of signals
  - Signal Network view for visualizing relationships between signals
  - Documentation Registry Explorer for browsing documented artifacts

### F2: Advanced `.swarmConfig` Tuning & Validation UI

A tool for editing, validating, and managing `.swarmConfig` files.

- **Location**: [`swarmconfig_ui/`](./swarmconfig_ui/)
- **Components**:
  - **Frontend**: React SPA with JSON editor and schema validation
- **Key Features**:
  - Load `.swarmConfig` files via browser file input
  - Edit `.swarmConfig` content as raw JSON
  - Validate against JSON Schema
  - Clear error reporting with paths to problematic elements
  - Save modified `.swarmConfig` files

### F3: Self-adaptive `interpretationLogic` for Scribe (Phase 1)

Enhanced logging capabilities for the Pheromind Scribe to record detailed information about its interpretation process.

- **Location**: [`adaptive_scribe/`](./adaptive_scribe/)
- **Components**:
  - **Logging**: Utilities for detailed JSONL logging of the Scribe's interpretation process
- **Key Features**:
  - Detailed JSONL logging of the Scribe's interpretation process
  - Confidence scoring for matched patterns and rules
  - Tracking of unmatched segments
  - Log rotation and management
  - Configurable logging options

## Comprehensive Guide: Monitoring and Optimizing a Pheromone Process

This guide explains how to use the Pheromind Enhancements Suite tools together to effectively monitor and optimize your pheromone process.

### Understanding the Pheromone Process

The pheromone process in Pheromind involves:

1. **Signal Generation**: Task orchestrators create natural language summaries of completed work
2. **Interpretation**: The Pheromone Scribe interprets these summaries using rules defined in `.swarmConfig`
3. **State Management**: The Scribe updates the `.pheromone` file with new signals and documentation entries
4. **Orchestration**: Higher-level orchestrators use this state to determine next steps

The Enhancements Suite provides tools to observe, analyze, and improve each step of this process.

### Setup Workflow

Follow these steps to set up the complete monitoring and optimization environment:

1. **Start the Visualizer**:
   ```bash
   # Terminal 1: Start the backend
   cd tools/visualizer/backend
   npm install
   cp .env.example .env
   # Edit .env to point to your .pheromone file if needed
   npm run dev

   # Terminal 2: Start the frontend
   cd tools/visualizer/frontend
   npm install
   npm start
   # Access the visualizer at http://localhost:3000
   ```

2. **Launch the SwarmConfig UI**:
   ```bash
   # Terminal 3: Start the SwarmConfig UI
   cd tools/swarmconfig_ui/frontend
   npm install
   npm start
   # Access the UI at http://localhost:3001
   ```

3. **Integrate Adaptive Scribe Logging**:
   ```javascript
   // In your Pheromind Scribe implementation:
   const { ScribeLogger, createLogEntry } = require('./tools/adaptive_scribe/logging');
   
   const logger = new ScribeLogger({
     logDir: './logs/scribe',
     logFileName: 'interpretation_log',
     enabled: true
   });
   
   // Use in your interpretation logic
   // See tools/adaptive_scribe/README.md for details
   ```

### Practical Workflows

#### Workflow 1: Monitoring Signal Flow in Real-time

**Use Case**: Observe how signals are being generated and how the pheromone state evolves during active development.

1. Start the Visualizer backend and frontend as described above
2. Open the Visualizer in your browser
3. Navigate to the Dashboard view for an overview of signal activity
4. Switch to the Timeline view to see signals in chronological order
5. Use the Network view to understand relationships between signals
6. Check the Documentation Explorer to see what artifacts are being tracked

**Example**: During a complex refactoring task, monitor the Timeline view to ensure that each step is properly recorded as signals in the `.pheromone` file, and use the Documentation Explorer to verify that all modified files are being tracked in the documentation registry.

#### Workflow 2: Optimizing Scribe Interpretation Rules

**Use Case**: Improve how the Scribe interprets natural language summaries to generate more accurate signals.

1. Enable Adaptive Scribe logging in your Pheromind implementation
2. Run your AI swarm on a task and generate some signals
3. Analyze the logs in `./logs/scribe/` to identify:
   - Low confidence matches
   - Unmatched segments of summaries
   - Patterns that are frequently triggered
4. Launch the SwarmConfig UI
5. Load your current `.swarmConfig` file
6. Modify the `interpretationLogic` section based on your analysis:
   - Add or refine document patterns to better capture file references
   - Update signal rules to more accurately interpret summaries
   - Adjust priorities to ensure the most specific rules are applied first
7. Validate your changes against the schema
8. Save the updated `.swarmConfig` file
9. Test the changes by running another task and monitoring the results in the Visualizer

**Example**: If you notice that code review summaries are not being properly categorized, examine the Adaptive Scribe logs to identify the unmatched segments, then add new signal rules in the SwarmConfig UI that specifically target phrases like "code review completed" or "review findings".

#### Workflow 3: Debugging Signal Issues

**Use Case**: Troubleshoot when expected signals are not appearing or are incorrectly categorized.

1. Check the Visualizer's Timeline view to confirm the signal is missing or incorrect
2. Review the Adaptive Scribe logs to understand how the summary was interpreted:
   - Was the summary matched by any rules?
   - What was the confidence score?
   - Were there unmatched segments?
3. Use the SwarmConfig UI to examine the current rules
4. Make targeted adjustments to the rules
5. Test the changes with similar summaries
6. Monitor the results in the Visualizer

**Example**: If a task completion signal is missing, check the logs to see if the summary contained unusual phrasing that didn't match existing rules. Add a new rule in the SwarmConfig UI that captures this phrasing, then test it with a similar summary to verify it works.

### Advanced Optimization Techniques

#### Technique 1: Confidence Score Analysis

Use the confidence scores in the Adaptive Scribe logs to identify interpretation rules that need improvement:

1. Extract logs with low confidence scores (e.g., below 0.7)
2. Group them by rule or pattern
3. Identify common characteristics in the summaries that lead to low confidence
4. Refine the rules to better match these cases

#### Technique 2: Pattern Refinement Cycle

Implement a continuous improvement cycle for your interpretation patterns:

1. Monitor unmatched segments in the Adaptive Scribe logs
2. Create new patterns to capture these segments
3. Test the patterns with historical summaries
4. Refine based on results
5. Implement in your `.swarmConfig`
6. Monitor effectiveness in the Visualizer

#### Technique 3: Documentation Registry Optimization

Improve how documents are tracked in the documentation registry:

1. Use the Documentation Explorer in the Visualizer to identify missing or incorrectly categorized documents
2. Analyze the document patterns in your `.swarmConfig`
3. Update patterns to better capture document references
4. Test with sample summaries
5. Monitor improvements in the Documentation Explorer

### Troubleshooting

#### Visualizer Issues

- **No data appears**: Ensure the backend is pointing to the correct `.pheromone` file path in the `.env` file
- **Stale data**: Try refreshing the browser or restarting the backend
- **WebSocket connection errors**: Check that ports are not blocked by firewalls

#### SwarmConfig UI Issues

- **Validation errors**: Carefully review the error messages, which include paths to the problematic elements
- **File loading issues**: Ensure the file is valid JSON before attempting to load it
- **Changes not taking effect**: Remember to save the file and update it in your Pheromind implementation

#### Adaptive Scribe Logging Issues

- **No logs generated**: Verify that logging is enabled and the log directory is writable
- **Incomplete log entries**: Check that all required fields are being populated in the log entry
- **Performance issues**: Consider adjusting log rotation settings for large projects

## Best Practices

1. **Run all tools simultaneously** during active development for comprehensive monitoring
2. **Review logs regularly** to identify patterns that need improvement
3. **Make incremental changes** to your `.swarmConfig` file and test after each change
4. **Document your interpretation rules** to help team members understand the logic
5. **Back up your `.swarmConfig` file** before making significant changes
6. **Use version control** to track changes to your configuration over time
7. **Correlate signals with project milestones** to ensure critical events are being captured

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

This integrated architecture creates a feedback loop:
1. The Scribe interprets summaries using rules from `.swarmConfig`
2. The Adaptive Scribe logs the interpretation process
3. You analyze these logs to identify improvement opportunities
4. You update the rules using the SwarmConfig UI
5. You monitor the effects of your changes in the Visualizer

## Future Development

This is the initial implementation of the Pheromind Enhancements Suite. Future phases will include:

- **F3 Phase 2**: Analysis & Suggestion Engine for the Scribe
- **F3 Phase 3**: Human-in-the-Loop Review & Integration UI for the Scribe

## License

This project is part of the Pheromind framework and follows its licensing terms.