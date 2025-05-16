import React from 'react';
import { usePheromoneData } from '../../contexts/PheromoneDataContext';

const Header = ({ connectionStatus }) => {
  const { pheromoneData } = usePheromoneData();
  
  // Format the last modified timestamp
  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A';
    
    const date = new Date(timestamp);
    return date.toLocaleString();
  };
  
  // Get status indicator class
  const getStatusIndicatorClass = () => {
    switch (connectionStatus) {
      case 'connected':
        return 'status-connected';
      case 'disconnected':
        return 'status-disconnected';
      case 'error':
        return 'status-error';
      default:
        return 'status-disconnected';
    }
  };
  
  return (
    <header className="bg-gray-800 text-white p-4">
      <div className="container mx-auto flex justify-between items-center">
        <div className="flex items-center">
          <h1 className="text-xl font-bold mr-4">Pheromind Visualizer</h1>
          <div className="flex items-center text-sm">
            <span className={`status-indicator ${getStatusIndicatorClass()}`}></span>
            <span>{connectionStatus}</span>
          </div>
        </div>
        
        <div className="flex items-center text-sm">
          <div className="mr-4">
            <span className="font-semibold">File: </span>
            <span>{pheromoneData.filePath || 'N/A'}</span>
          </div>
          <div>
            <span className="font-semibold">Last Updated: </span>
            <span>{formatTimestamp(pheromoneData.lastModified)}</span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;