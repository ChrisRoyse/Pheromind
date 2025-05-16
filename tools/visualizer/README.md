# Visual Pheromone & Documentation Landscape Tool

This tool provides a real-time visualization of the `.pheromone` file's signals and documentation registry. It consists of a Node.js backend that watches the `.pheromone` file for changes and a React frontend that displays the data in various views.

## Features

- Real-time updates via WebSockets
- Dashboard with statistics and charts
- Signal Timeline view for chronological display of signals
- Signal Network view for visualizing relationships between signals
- Documentation Registry Explorer for browsing documented artifacts
- Filtering and sorting capabilities

## Components

### Backend

The backend is a Node.js server that:
- Watches the `.pheromone` file for changes using Chokidar
- Parses the JSON content
- Broadcasts updates to connected clients via Socket.io
- Provides API endpoints for initial data load

**Location**: [`backend/`](./backend/)

### Frontend

The frontend is a React Single Page Application that:
- Connects to the backend via WebSockets
- Displays the `.pheromone` data in various views
- Provides filtering and sorting capabilities
- Visualizes signal relationships using Vis.js

**Location**: [`frontend/`](./frontend/)

## Setup and Usage

### Backend

1. Navigate to the backend directory:
   ```bash
   cd tools/visualizer/backend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file based on the `.env.example` template:
   ```bash
   cp .env.example .env
   ```

4. Modify the `.env` file to configure the server:
   - `PORT`: The port the server will listen on (default: 3001)
   - `PHEROMONE_FILE_PATH`: The path to the `.pheromone` file to watch (default: `./.pheromone`)

5. Start the server:
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

### Frontend

1. Navigate to the frontend directory:
   ```bash
   cd tools/visualizer/frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure the backend URL (optional):
   Create a `.env` file in the root directory with:
   ```
   REACT_APP_BACKEND_URL=http://localhost:3001
   ```

4. Start the development server:
   ```bash
   npm start
   ```

5. Build for production:
   ```bash
   npm run build
   ```

## Architecture

```
+-------------------------+      Reads      +-----------------+
| Pheromind Agents        | ------------> | .pheromone file |
| (Roo Code Environment)  |      Writes     | (JSON)          |
+-------------------------+                 +--------+--------+
                                                     |
                                                     | (File System Watch)
                                                     v
+----------------------------------------------------+
| Visualizer Backend (Node.js + Express.js)          |
|----------------------------------------------------+
| - Chokidar: Watches .pheromone                     |
| - WebSocket Server (socket.io):                    |
|   - Reads & parses .pheromone on change            |
|   - Pushes updates to connected clients            |
| - API Endpoint: for initial load                   |
+------------------------+---------------------------+
                         |
                         | (WebSocket Connection)
                         v
+----------------------------------------------------+
| Visualizer Frontend (React SPA in Browser)         |
|----------------------------------------------------+
| - WebSocket Client: Receives data updates          |
| - State Management (React Context)                 |
| - Components:                                      |
|   - Dashboard                                      |
|   - Signal Timeline View                           |
|   - Signal Network View (Vis.js)                   |
|   - Documentation Registry Explorer                |
|   - Signal Detail Modal                            |
|   - Charts (Recharts/Chart.js)                     |
+----------------------------------------------------+
```

## Development

### Backend

The backend is built with:
- Node.js
- Express.js
- Socket.io
- Chokidar

See the [backend README](./backend/README.md) for more details.

### Frontend

The frontend is built with:
- React
- TypeScript
- Tailwind CSS
- Socket.io Client
- Vis.js
- Chart.js

See the [frontend README](./frontend/README.md) for more details.