import React from 'react';
import { usePheromoneData } from '../../contexts/PheromoneDataContext';
import { Card, Title, Text, Badge } from '@tremor/react';

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
    <header className="bg-tremor-background dark:bg-tremor-background-dark border-b border-tremor-border shadow-sm">
      <Card className="rounded-none shadow-none bg-transparent py-3 px-6 flex flex-row items-center justify-between">
        <div className="flex items-center gap-4">
          <Title className="text-xl font-bold tracking-wide">Pheromind Visualizer</Title>
          <div className="flex items-center gap-2">
            <Badge className={`w-3 h-3 rounded-full ${getStatusIndicatorClass() === 'status-connected' ? 'bg-green-500' : getStatusIndicatorClass() === 'status-error' ? 'bg-red-500' : 'bg-gray-400'}`} />
            <Text className="text-sm">{connectionStatus}</Text>
          </div>
        </div>
        <div className="flex items-center gap-6 text-tremor-content">
          <Text className="text-sm"><span className="font-semibold">File:</span> {pheromoneData.filePath || 'N/A'}</Text>
          <Text className="text-sm"><span className="font-semibold">Last Updated:</span> {formatTimestamp(pheromoneData.lastModified)}</Text>
        </div>
      </Card>
    </header>
  );
};

export default Header;