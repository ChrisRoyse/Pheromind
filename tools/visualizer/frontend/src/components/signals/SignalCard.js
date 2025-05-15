import React, { useState } from 'react';
import SignalDetailModal from './SignalDetailModal';

const SignalCard = ({ signal }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [showModal, setShowModal] = useState(false);
  
  // Format timestamp
  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A';
    
    const date = new Date(timestamp);
    return date.toLocaleString();
  };
  
  // Calculate strength indicator width
  const getStrengthWidth = () => {
    if (!signal.strength) return '0%';
    
    // Assuming strength is between 0 and 1
    return `${Math.min(100, signal.strength * 100)}%`;
  };
  
  // Get color based on signal type
  const getTypeColor = () => {
    switch (signal.signalType) {
      case 'task_completed':
        return 'border-green-500';
      case 'task_started':
        return 'border-blue-500';
      case 'task_failed':
        return 'border-red-500';
      case 'document_created':
        return 'border-purple-500';
      case 'document_updated':
        return 'border-yellow-500';
      default:
        return 'border-gray-500';
    }
  };
  
  // Truncate message for display
  const truncateMessage = (message, maxLength = 150) => {
    if (!message) return '';
    if (message.length <= maxLength) return message;
    
    return `${message.substring(0, maxLength)}...`;
  };
  
  return (
    <>
      <div className={`signal-card ${getTypeColor()} border-l-4`}>
        <div className="flex justify-between items-start">
          <div>
            <div className="font-semibold">{signal.id}</div>
            <div className="text-sm text-gray-600">
              <span className="font-medium">Type: </span>
              <span>{signal.signalType}</span>
            </div>
            <div className="text-sm text-gray-600">
              <span className="font-medium">Target: </span>
              <span>{signal.target || 'N/A'}</span>
            </div>
            {signal.category && (
              <div className="text-sm text-gray-600">
                <span className="font-medium">Category: </span>
                <span>{signal.category}</span>
              </div>
            )}
          </div>
          <div className="text-sm text-gray-500">
            {formatTimestamp(signal.timestamp_created)}
          </div>
        </div>
        
        {signal.strength !== undefined && (
          <div className="mt-2">
            <div className="text-xs text-gray-600 mb-1">Strength: {signal.strength}</div>
            <div className="bg-gray-200 rounded-full h-2 w-full">
              <div 
                className="bg-blue-500 rounded-full h-2" 
                style={{ width: getStrengthWidth() }}
              ></div>
            </div>
          </div>
        )}
        
        <div className="mt-3">
          <div className="text-sm text-gray-700">
            {isExpanded ? signal.message : truncateMessage(signal.message)}
          </div>
          {signal.message && signal.message.length > 150 && (
            <button 
              className="text-blue-500 text-sm mt-1"
              onClick={() => setIsExpanded(!isExpanded)}
            >
              {isExpanded ? 'Show Less' : 'Show More'}
            </button>
          )}
        </div>
        
        <div className="mt-3 flex justify-end">
          <button 
            className="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600"
            onClick={() => setShowModal(true)}
          >
            View Details
          </button>
        </div>
      </div>
      
      {showModal && (
        <SignalDetailModal 
          signal={signal} 
          onClose={() => setShowModal(false)} 
        />
      )}
    </>
  );
};

export default SignalCard;