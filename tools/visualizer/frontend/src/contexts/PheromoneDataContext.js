import React, { createContext, useState, useContext, useEffect } from 'react';
import { io } from 'socket.io-client';

// Create context
const PheromoneDataContext = createContext();

// Custom hook for using the context
export const usePheromoneData = () => useContext(PheromoneDataContext);

export const PheromoneDataProvider = ({ children }) => {
  // State
  const [pheromoneData, setPheromoneData] = useState({
    signals: [],
    documentationRegistry: {},
    filePath: '',
    lastModified: null
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [socket, setSocket] = useState(null);

  // Fetch initial pheromone state from backend REST API, then connect websocket
  useEffect(() => {
    let didCancel = false;
    const fetchInitialData = async () => {
      setLoading(true);
      setError(null);
      try {
        const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:3001';
        const res = await fetch(`${backendUrl}/api/pheromone/current`);
        if (!res.ok) {
          throw new Error(`HTTP error! status: ${res.status}`);
        }
        const data = await res.json();
        if (!didCancel) {
          setPheromoneData(data);
          setLoading(false);
        }
      } catch (err) {
        if (!didCancel) {
          setError('Failed to fetch initial pheromone state');
          setLoading(false);
        }
      } finally {
        // Always connect the websocket after fetch attempt (success or error)
        if (!didCancel) {
          const socketInstance = io(process.env.REACT_APP_BACKEND_URL || 'http://localhost:3001');
          setSocket(socketInstance);
        }
      }
    };
    fetchInitialData();
    return () => {
      didCancel = true;
    };
  }, []);

  // Set up socket event listeners
  useEffect(() => {
    if (!socket) return;

    // Handle pheromone data updates
    socket.on('pheromone_data_update', (data) => {
      console.log('Received pheromone data update:', data);
      setPheromoneData(data);
      setLoading(false);
    });

    // Handle connection errors
    socket.on('connect_error', (err) => {
      console.error('Socket connection error:', err);
      setError('Failed to connect to the server');
      setLoading(false);
    });

    // Request initial data when connected
    socket.on('connect', () => {
      console.log('Connected to server, requesting initial data');
      socket.emit('request_initial_data');
    });

    // Handle disconnection
    socket.on('disconnect', () => {
      console.log('Disconnected from server');
      setError('Disconnected from server');
    });

    // Clean up listeners on unmount
    return () => {
      socket.off('pheromone_data_update');
      socket.off('connect_error');
      socket.off('connect');
      socket.off('disconnect');
    };
  }, [socket]);

  // Filter signals by type, target, or category
  const filterSignals = (filters = {}) => {
    const { type, target, category, searchText } = filters;
    
    return pheromoneData.signals.filter(signal => {
      // Apply type filter
      if (type && signal.signalType !== type) {
        return false;
      }
      
      // Apply target filter
      if (target && signal.target !== target) {
        return false;
      }
      
      // Apply category filter
      if (category && signal.category !== category) {
        return false;
      }
      
      // Apply text search
      if (searchText && !signal.message.toLowerCase().includes(searchText.toLowerCase())) {
        return false;
      }
      
      return true;
    });
  };

  // Get unique values for filters
  const getUniqueSignalTypes = () => {
    return [...new Set(pheromoneData.signals.map(signal => signal.signalType))];
  };

  const getUniqueTargets = () => {
    return [...new Set(pheromoneData.signals.map(signal => signal.target))];
  };

  const getUniqueCategories = () => {
    return [...new Set(pheromoneData.signals.map(signal => signal.category))];
  };

  // Filter documentation registry entries
  const filterDocumentation = (filters = {}) => {
    const { type, searchText } = filters;
    const registry = pheromoneData.documentationRegistry;
    
    return Object.keys(registry)
      .filter(key => {
        const entry = registry[key];
        
        // Apply type filter
        if (type && entry.type !== type) {
          return false;
        }
        
        // Apply text search (in description or file path)
        if (searchText) {
          const searchLower = searchText.toLowerCase();
          const descriptionMatch = entry.description && entry.description.toLowerCase().includes(searchLower);
          const pathMatch = key.toLowerCase().includes(searchLower);
          
          if (!descriptionMatch && !pathMatch) {
            return false;
          }
        }
        
        return true;
      })
      .reduce((filtered, key) => {
        filtered[key] = registry[key];
        return filtered;
      }, {});
  };

  // Get unique document types
  const getUniqueDocumentTypes = () => {
    const registry = pheromoneData.documentationRegistry;
    return [...new Set(Object.values(registry).map(entry => entry.type))];
  };

  // Context value
  const value = {
    pheromoneData,
    loading,
    error,
    filterSignals,
    getUniqueSignalTypes,
    getUniqueTargets,
    getUniqueCategories,
    filterDocumentation,
    getUniqueDocumentTypes
  };

  return (
    <PheromoneDataContext.Provider value={value}>
      {children}
    </PheromoneDataContext.Provider>
  );
};