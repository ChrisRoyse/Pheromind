# Pheromind Visualizer Frontend

This is the frontend application for the Visual Pheromone & Documentation Landscape Tool. It provides a user interface for visualizing the `.pheromone` file's signals and documentation registry.

## Features

- Dashboard with statistics and charts
- Signal Timeline view for chronological display of signals
- Signal Network view for visualizing relationships between signals
- Documentation Registry Explorer for browsing documented artifacts
- Real-time updates via WebSockets

## Technologies Used

- React 18+
- TypeScript
- Tailwind CSS
- Socket.io Client
- Vis.js for network visualization
- Chart.js for data visualization
- React Router for navigation

## Setup

1. Install dependencies:
   ```
   npm install
   ```

2. Configure the backend URL (optional):
   Create a `.env` file in the root directory with:
   ```
   REACT_APP_BACKEND_URL=http://localhost:3001
   ```

3. Start the development server:
   ```
   npm start
   ```

## Project Structure

- `public/`: Static assets and HTML template
- `src/`: Source code
  - `components/`: Reusable UI components
    - `layout/`: Layout components (Header, Sidebar)
    - `signals/`: Signal-related components (SignalCard, SignalDetailModal)
  - `contexts/`: React contexts for state management
    - `PheromoneDataContext.js`: Context for managing pheromone data
  - `views/`: Page components
    - `DashboardView.js`: Overview with statistics and charts
    - `SignalTimelineView.js`: Chronological display of signals
    - `SignalNetworkView.js`: Network visualization of signals
    - `DocumentationExplorerView.js`: Table view of documentation registry
  - `App.js`: Main application component
  - `index.js`: Entry point

## Available Scripts

- `npm start`: Runs the app in development mode
- `npm test`: Launches the test runner
- `npm run build`: Builds the app for production
- `npm run eject`: Ejects from Create React App

## Connection to Backend

The frontend connects to the backend via WebSockets to receive real-time updates when the `.pheromone` file changes. Make sure the backend server is running before starting the frontend.

## Browser Support

The application is designed to work with modern browsers (Chrome, Firefox, Edge, Safari).