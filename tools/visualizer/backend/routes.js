/**
 * API routes for the Visual Pheromone & Documentation Landscape Tool backend
 */
const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

// Configuration
const PHEROMONE_FILE_PATH = process.env.PHEROMONE_FILE_PATH || './.pheromone';

/**
 * GET /api/status
 * Returns the server status and configuration
 */
router.get('/status', (req, res) => {
  res.json({
    status: 'running',
    watchingFile: PHEROMONE_FILE_PATH,
    serverTime: new Date().toISOString()
  });
});

/**
 * GET /api/pheromone/current
 * Returns the current content of the .pheromone file
 */
router.get('/pheromone/current', (req, res) => {
  const absolutePath = path.resolve(PHEROMONE_FILE_PATH);
  
  fs.readFile(absolutePath, 'utf8', (err, data) => {
    if (err) {
      if (err.code === 'ENOENT') {
        return res.status(404).json({ 
          error: 'File not found',
          message: `The .pheromone file was not found at ${absolutePath}`
        });
      }
      
      return res.status(500).json({ 
        error: 'Server error',
        message: `Error reading .pheromone file: ${err.message}`
      });
    }
    
    try {
      const parsedData = JSON.parse(data);
      const stats = fs.statSync(absolutePath);
      
      res.json({
        signals: parsedData.signals || [],
        documentationRegistry: parsedData.documentationRegistry || {},
        filePath: absolutePath,
        lastModified: stats.mtime
      });
    } catch (parseError) {
      res.status(500).json({ 
        error: 'Parse error',
        message: `Error parsing .pheromone file: ${parseError.message}`
      });
    }
  });
});

/**
 * GET /api/pheromone/config
 * Returns the current configuration for the pheromone file watcher
 */
router.get('/pheromone/config', (req, res) => {
  res.json({
    pheromoneFilePath: PHEROMONE_FILE_PATH
  });
});

module.exports = router;