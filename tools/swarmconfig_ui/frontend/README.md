# Pheromind SwarmConfig UI

This is a web application for editing, validating, and managing `.swarmConfig` files for the Pheromind framework. It provides a user-friendly interface for tuning the Scribe's `interpretationLogic` and other swarm parameters.

## Features

- Load `.swarmConfig` files via browser file input
- Edit `.swarmConfig` content as raw JSON
- Validate against JSON Schema
- Clear error reporting with paths to problematic elements
- Save modified `.swarmConfig` files

## Technologies Used

- React 18+
- TypeScript
- Tailwind CSS
- JSONEditor for raw JSON editing
- Ajv for JSON Schema validation

## Setup

1. Install dependencies:
   ```
   npm install
   ```

2. Start the development server:
   ```
   npm start
   ```

3. Build for production:
   ```
   npm run build
   ```

## Project Structure

- `public/`: Static assets and HTML template
- `src/`: Source code
  - `components/`: Reusable UI components
    - `Header.js`: Application header
    - `RawEditor.js`: JSON editor component
    - `ValidationResults.js`: Displays validation results
    - `FileOperations.js`: Handles file loading and saving
  - `schema/`: JSON Schema definitions
    - `swarmConfigSchema.js`: Schema for `.swarmConfig` files
  - `utils/`: Utility functions
    - `validation.js`: Functions for validating against JSON Schema
  - `App.js`: Main application component
  - `index.js`: Entry point

## JSON Schema

The application includes a JSON Schema for `.swarmConfig` files, which defines the structure and validation rules for:

- `pheromoneDynamics`: Controls how signals evolve over time
- `scribeSettings`: Configuration for the Pheromone Scribe
  - `interpretationLogic`: Rules for interpreting natural language summaries
    - `documentPatterns`: Patterns for identifying document references
    - `signalRules`: Rules for generating signals
- `generalSettings`: General configuration options

## Usage

1. Click "Load .swarmConfig" to select a file from your local system
2. Edit the JSON content in the editor
3. Click "Validate" to check the configuration against the schema
4. Fix any validation errors
5. Click "Save .swarmConfig" to download the modified file

## Browser Support

The application is designed to work with modern browsers (Chrome, Firefox, Edge, Safari).