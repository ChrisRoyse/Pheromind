/**
 * Logger utility for the Adaptive Scribe
 */
const fs = require('fs');
const path = require('path');

/**
 * Logger class for Scribe interpretation logging
 */
class ScribeLogger {
  /**
   * Create a new ScribeLogger
   * @param {Object} options - Logger options
   * @param {string} options.logDir - Directory to store log files
   * @param {string} options.logFileName - Base name for log files
   * @param {boolean} options.enabled - Whether logging is enabled
   * @param {number} options.maxLogSize - Maximum size of log file in bytes before rotation
   * @param {number} options.maxLogFiles - Maximum number of log files to keep
   */
  constructor(options = {}) {
    this.options = {
      logDir: options.logDir || './logs',
      logFileName: options.logFileName || 'scribe_interpretation',
      enabled: options.enabled !== undefined ? options.enabled : true,
      maxLogSize: options.maxLogSize || 10 * 1024 * 1024, // 10 MB
      maxLogFiles: options.maxLogFiles || 5
    };
    
    // Create log directory if it doesn't exist
    if (!fs.existsSync(this.options.logDir)) {
      fs.mkdirSync(this.options.logDir, { recursive: true });
    }
    
    this.currentLogFile = this.getCurrentLogFilePath();
  }
  
  /**
   * Get the current log file path
   * @returns {string} - Path to the current log file
   */
  getCurrentLogFilePath() {
    return path.join(this.options.logDir, `${this.options.logFileName}.jsonl`);
  }
  
  /**
   * Check if the current log file needs rotation
   * @returns {boolean} - True if rotation is needed
   */
  needsRotation() {
    if (!fs.existsSync(this.currentLogFile)) {
      return false;
    }
    
    const stats = fs.statSync(this.currentLogFile);
    return stats.size >= this.options.maxLogSize;
  }
  
  /**
   * Rotate log files
   */
  rotateLogFiles() {
    // Check if the current log file exists
    if (!fs.existsSync(this.currentLogFile)) {
      return;
    }
    
    // Shift existing log files
    for (let i = this.options.maxLogFiles - 1; i > 0; i--) {
      const oldFile = path.join(this.options.logDir, `${this.options.logFileName}.${i}.jsonl`);
      const newFile = path.join(this.options.logDir, `${this.options.logFileName}.${i + 1}.jsonl`);
      
      if (fs.existsSync(oldFile)) {
        if (i + 1 <= this.options.maxLogFiles) {
          // Shift file to next number
          if (fs.existsSync(newFile)) {
            fs.unlinkSync(newFile);
          }
          fs.renameSync(oldFile, newFile);
        } else {
          // Delete file if it exceeds maxLogFiles
          fs.unlinkSync(oldFile);
        }
      }
    }
    
    // Rename current log file to .1
    const newFile = path.join(this.options.logDir, `${this.options.logFileName}.1.jsonl`);
    if (fs.existsSync(newFile)) {
      fs.unlinkSync(newFile);
    }
    fs.renameSync(this.currentLogFile, newFile);
  }
  
  /**
   * Log an interpretation entry
   * @param {Object} entry - The log entry to write
   */
  logInterpretation(entry) {
    if (!this.options.enabled) {
      return;
    }
    
    // Check if rotation is needed
    if (this.needsRotation()) {
      this.rotateLogFiles();
    }
    
    // Add timestamp if not present
    if (!entry.timestamp) {
      entry.timestamp = new Date().toISOString();
    }
    
    // Write entry to log file
    const logLine = JSON.stringify(entry) + '\n';
    fs.appendFileSync(this.currentLogFile, logLine, 'utf8');
  }
  
  /**
   * Enable logging
   */
  enable() {
    this.options.enabled = true;
  }
  
  /**
   * Disable logging
   */
  disable() {
    this.options.enabled = false;
  }
  
  /**
   * Update logger options
   * @param {Object} options - New options
   */
  updateOptions(options) {
    this.options = { ...this.options, ...options };
    this.currentLogFile = this.getCurrentLogFilePath();
  }
}

module.exports = ScribeLogger;