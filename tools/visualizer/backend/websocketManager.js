/**
 * WebSocket manager module for real-time communication with the frontend
 */
const socketIo = require('socket.io');

let io = null;

/**
 * Initialize the WebSocket server
 * @param {object} server - HTTP server instance
 * @returns {object} - Socket.io instance
 */
function initialize(server) {
  io = socketIo(server, {
    cors: {
      origin: '*', // In production, this should be restricted
      methods: ['GET', 'POST']
    }
  });
  
  io.on('connection', (socket) => {
    console.log(`Client connected: ${socket.id}`);
    
    // Handle initial data request
    socket.on('request_initial_data', () => {
      console.log(`Client ${socket.id} requested initial data`);
      // The actual data will be sent by the caller when available
    });
    
    // Handle disconnection
    socket.on('disconnect', () => {
      console.log(`Client disconnected: ${socket.id}`);
    });
  });
  
  return io;
}

/**
 * Broadcast pheromone data update to all connected clients
 * @param {object} data - The pheromone data to broadcast
 */
function broadcastPheromoneUpdate(data) {
  if (!io) {
    console.error('Socket.io not initialized');
    return;
  }
  
  console.log('Broadcasting pheromone update to all clients');
  io.emit('pheromone_data_update', data);
}

/**
 * Send pheromone data to a specific client
 * @param {string} socketId - The socket ID of the client
 * @param {object} data - The pheromone data to send
 */
function sendPheromoneDataToClient(socketId, data) {
  if (!io) {
    console.error('Socket.io not initialized');
    return;
  }
  
  const socket = io.sockets.sockets.get(socketId);
  if (socket) {
    console.log(`Sending pheromone data to client: ${socketId}`);
    socket.emit('pheromone_data_update', data);
  } else {
    console.error(`Socket ${socketId} not found`);
  }
}

module.exports = {
  initialize,
  broadcastPheromoneUpdate,
  sendPheromoneDataToClient
};