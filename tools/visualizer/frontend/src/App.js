import React, { useState, useEffect } from 'react';
import { Routes, Route, Link } from 'react-router-dom';
import { io } from 'socket.io-client';
import './App.css';

// Context
import { PheromoneDataProvider } from './contexts/PheromoneDataContext';

// Components
import Header from './components/layout/Header';
import Sidebar from './components/layout/Sidebar';

// Views
import DashboardView from './views/DashboardView';
import SignalTimelineView from './views/SignalTimelineView';
import SignalNetworkView from './views/SignalNetworkView';
import DocumentationExplorerView from './views/DocumentationExplorerView';

function App() {
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  
  useEffect(() => {
    // Initialize socket connection
    const socket = io(process.env.REACT_APP_BACKEND_URL || 'http://localhost:3001');
    
    socket.on('connect', () => {
      console.log('Connected to server');
      setConnectionStatus('connected');
      
      // Request initial data
      socket.emit('request_initial_data');
    });
    
    socket.on('disconnect', () => {
      console.log('Disconnected from server');
      setConnectionStatus('disconnected');
    });
    
    socket.on('connect_error', (error) => {
      console.error('Connection error:', error);
      setConnectionStatus('error');
    });
    
    // Clean up on unmount
    return () => {
      socket.disconnect();
    };
  }, []);
  
  return (
    <PheromoneDataProvider>
      <div className="app">
        <Header connectionStatus={connectionStatus} />
        <div className="app-content">
          <Sidebar />
          <main className="main-content">
            <Routes>
              <Route path="/" element={<DashboardView />} />
              <Route path="/timeline" element={<SignalTimelineView />} />
              <Route path="/network" element={<SignalNetworkView />} />
              <Route path="/documentation" element={<DocumentationExplorerView />} />
            </Routes>
          </main>
        </div>
      </div>
    </PheromoneDataProvider>
  );
}

export default App;