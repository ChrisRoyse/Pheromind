/**
 * Main server file for the Visual Pheromone & Documentation Landscape Tool backend
 */
require('dotenv').config();
const express = require('express');
const http = require('http');
const cors = require('cors');
const fileWatcher = require('./fileWatcher');
const websocketManager = require('./websocketManager');
const routes = require('./routes');

// Configuration
const PORT = process.env.PORT || 3001;
const PHEROMONE_FILE_PATH = process.env.PHEROMONE_FILE_PATH || './.pheromone';

// Initialize Express app
const app = express();
app.use(cors());
app.use(express.json());

// Set up routes
app.use('/api', routes);

// Create HTTP server
const server = http.createServer(app);

// Initialize WebSocket server
const io = websocketManager.initialize(server);

// Start file watcher
fileWatcher.initialize(PHEROMONE_FILE_PATH, (data) => {
  websocketManager.broadcastPheromoneUpdate(data);
});

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Watching .pheromone file at: ${PHEROMONE_FILE_PATH}`);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('Shutting down server...');
  fileWatcher.close();
  server.close(() => {
    console.log('Server shut down');
    process.exit(0);
  });
});

module.exports = server; // Export for testing