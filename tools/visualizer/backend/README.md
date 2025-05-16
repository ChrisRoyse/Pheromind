# Pheromind Visualizer Backend

This is the backend server for the Visual Pheromone & Documentation Landscape Tool. It watches the `.pheromone` file for changes and pushes updates to connected frontend clients via WebSockets.

## Features

- File watching using Chokidar
- WebSocket communication using Socket.io
- RESTful API endpoints
- Configuration via environment variables

## Setup

1. Install dependencies:
   ```
   npm install
   ```

2. Create a `.env` file based on the `.env.example` template:
   ```
   cp .env.example .env
   ```

3. Modify the `.env` file to configure the server:
   - `PORT`: The port the server will listen on (default: 3001)
   - `PHEROMONE_FILE_PATH`: The path to the `.pheromone` file to watch (default: `./.pheromone`)

## Running the Server

### Development Mode

```
npm run dev
```

This will start the server with nodemon, which will automatically restart the server when changes are detected.

### Production Mode

```
npm start
```

## API Endpoints

### GET /api/status

Returns the current status of the server.

**Response:**
```json
{
  "status": "running",
  "watchingFile": "/path/to/.pheromone",
  "serverTime": "2025-05-15T22:16:35.000Z"
}
```

### GET /api/pheromone/current

Returns the current content of the `.pheromone` file.

**Response:**
```json
{
  "signals": [...],
  "documentationRegistry": {...},
  "filePath": "/path/to/.pheromone",
  "lastModified": "2025-05-15T22:16:35.000Z"
}
```

### GET /api/pheromone/config

Returns the current configuration for the pheromone file watcher.

**Response:**
```json
{
  "pheromoneFilePath": "/path/to/.pheromone"
}
```

## WebSocket Events

### Client to Server

- `request_initial_data`: Request the initial data from the server

### Server to Client

- `pheromone_data_update`: Sent when the `.pheromone` file changes

## Project Structure

- `server.js`: Main entry point
- `fileWatcher.js`: Watches the `.pheromone` file for changes
- `websocketManager.js`: Manages WebSocket connections and broadcasts
- `routes.js`: Defines API endpoints

## Testing

```
npm test