/**
 * File watcher module for monitoring the .pheromone file
 */
const fs = require('fs');
const chokidar = require('chokidar');
const path = require('path');

let watcher = null;

/**
 * Initialize the file watcher
 * @param {string} filePath - Path to the .pheromone file
 * @param {function} onChangeCallback - Callback function to execute when file changes
 */
function initialize(filePath, onChangeCallback) {
  const absolutePath = path.resolve(filePath);
  
  console.log(`Setting up watcher for: ${absolutePath}`);
  
  // Create a debounced version of the file processing function
  // This prevents multiple rapid updates from causing excessive processing
  let debounceTimer = null;
  const debouncedProcessFile = (path) => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      processFile(path, onChangeCallback);
    }, 300); // 300ms debounce time
  };
  
  // Initialize watcher
  watcher = chokidar.watch(absolutePath, {
    persistent: true,
    awaitWriteFinish: {
      stabilityThreshold: 300,
      pollInterval: 100
    }
  });
  
  // Set up event handlers
  watcher
    .on('add', path => {
      console.log(`File ${path} has been added`);
      debouncedProcessFile(path);
    })
    .on('change', path => {
      console.log(`File ${path} has been changed`);
      debouncedProcessFile(path);
    })
    .on('error', error => {
      console.error(`Watcher error: ${error}`);
    });
    
  // Check if file exists initially
  if (fs.existsSync(absolutePath)) {
    console.log(`File ${absolutePath} exists, processing initial content`);
    processFile(absolutePath, onChangeCallback);
  } else {
    console.log(`File ${absolutePath} does not exist yet, waiting for creation`);
  }
  
  return watcher;
}

/**
 * Process the .pheromone file
 * @param {string} filePath - Path to the .pheromone file
 * @param {function} callback - Callback function to execute with the parsed data
 */
function processFile(filePath, callback) {
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      console.error(`Error reading file: ${err}`);
      return;
    }
    
    try {
      const parsedData = JSON.parse(data);
      const stats = fs.statSync(filePath);
      
      callback({
        signals: parsedData.signals || [],
        documentationRegistry: parsedData.documentationRegistry || {},
        filePath: filePath,
        lastModified: stats.mtime
      });
    } catch (parseError) {
      console.error(`Error parsing JSON: ${parseError}`);
    }
  });
}

/**
 * Close the file watcher
 */
function close() {
  if (watcher) {
    watcher.close();
    console.log('File watcher closed');
  }
}

module.exports = {
  initialize,
  close
};