import React, { useRef } from 'react';

const FileOperations = ({ onFileLoad, onSave, onValidate, fileName }) => {
  const fileInputRef = useRef(null);
  
  // Handle file selection
  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = (event) => {
      onFileLoad(event.target.result, file.name);
    };
    reader.onerror = (error) => {
      console.error('Error reading file:', error);
      alert('Error reading file');
    };
    reader.readAsText(file);
    
    // Reset file input
    e.target.value = null;
  };
  
  // Trigger file input click
  const handleLoadClick = () => {
    fileInputRef.current.click();
  };
  
  return (
    <div className="mb-6">
      <div className="flex flex-wrap gap-4 mb-2">
        <div>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept=".swarmConfig,.json"
            className="file-input"
          />
          <button 
            onClick={handleLoadClick}
            className="file-input-label"
          >
            Load .swarmConfig
          </button>
        </div>
        
        <button 
          onClick={onValidate}
          className="button"
          disabled={!fileName}
        >
          Validate
        </button>
        
        <button 
          onClick={onSave}
          className="button button-secondary"
          disabled={!fileName}
        >
          Save .swarmConfig
        </button>
      </div>
      
      {fileName && (
        <div className="text-sm text-gray-600">
          Current file: <span className="font-medium">{fileName}</span>
        </div>
      )}
    </div>
  );
};

export default FileOperations;