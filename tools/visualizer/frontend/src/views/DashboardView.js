import React from 'react';
import { usePheromoneData } from '../contexts/PheromoneDataContext';
import { Pie, Bar } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title } from 'chart.js';

// Register ChartJS components
ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title);

const DashboardView = () => {
  const { pheromoneData, loading, error, getUniqueSignalTypes, getUniqueDocumentTypes } = usePheromoneData();
  
  // Generate random colors for charts
  const generateColors = (count) => {
    const colors = [];
    for (let i = 0; i < count; i++) {
      const r = Math.floor(Math.random() * 200);
      const g = Math.floor(Math.random() * 200);
      const b = Math.floor(Math.random() * 200);
      colors.push(`rgba(${r}, ${g}, ${b}, 0.6)`);
    }
    return colors;
  };
  
  // Prepare signal type distribution data
  const prepareSignalTypeData = () => {
    const types = getUniqueSignalTypes();
    const counts = types.map(type => {
      return pheromoneData.signals.filter(signal => signal.signalType === type).length;
    });
    
    const backgroundColor = generateColors(types.length);
    
    return {
      labels: types,
      datasets: [
        {
          data: counts,
          backgroundColor,
          borderColor: backgroundColor.map(color => color.replace('0.6', '1')),
          borderWidth: 1,
        },
      ],
    };
  };
  
  // Prepare document type distribution data
  const prepareDocumentTypeData = () => {
    const types = getUniqueDocumentTypes();
    const counts = types.map(type => {
      return Object.values(pheromoneData.documentationRegistry)
        .filter(doc => doc.type === type).length;
    });
    
    const backgroundColor = generateColors(types.length);
    
    return {
      labels: types,
      datasets: [
        {
          data: counts,
          backgroundColor,
          borderColor: backgroundColor.map(color => color.replace('0.6', '1')),
          borderWidth: 1,
        },
      ],
    };
  };
  
  // Get recent signals
  const getRecentSignals = (count = 5) => {
    if (!pheromoneData.signals || pheromoneData.signals.length === 0) {
      return [];
    }
    
    // Sort by timestamp (newest first) and take the first 'count' items
    return [...pheromoneData.signals]
      .sort((a, b) => new Date(b.timestamp_created) - new Date(a.timestamp_created))
      .slice(0, count);
  };
  
  // Format timestamp
  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A';
    
    const date = new Date(timestamp);
    return date.toLocaleString();
  };
  
  // Render loading state
  if (loading) {
    return (
      <div className="p-4">
        <h2 className="text-2xl font-bold mb-4">Dashboard</h2>
        <div className="text-center py-8">Loading...</div>
      </div>
    );
  }
  
  // Render error state
  if (error) {
    return (
      <div className="p-4">
        <h2 className="text-2xl font-bold mb-4">Dashboard</h2>
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          <p>{error}</p>
        </div>
      </div>
    );
  }
  
  // Get signal and document counts
  const signalCount = pheromoneData.signals ? pheromoneData.signals.length : 0;
  const documentCount = pheromoneData.documentationRegistry 
    ? Object.keys(pheromoneData.documentationRegistry).length 
    : 0;
  
  // Get recent signals
  const recentSignals = getRecentSignals();
  
  return (
    <div className="p-4">
      <h2 className="text-2xl font-bold mb-4">Dashboard</h2>
      
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        <div className="bg-white p-4 rounded shadow">
          <h3 className="text-lg font-semibold mb-2">Signals</h3>
          <p className="text-3xl font-bold">{signalCount}</p>
        </div>
        <div className="bg-white p-4 rounded shadow">
          <h3 className="text-lg font-semibold mb-2">Documentation Entries</h3>
          <p className="text-3xl font-bold">{documentCount}</p>
        </div>
      </div>
      
      {/* Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {signalCount > 0 && (
          <div className="bg-white p-4 rounded shadow">
            <h3 className="text-lg font-semibold mb-4">Signal Types Distribution</h3>
            <div className="h-64">
              <Pie data={prepareSignalTypeData()} options={{ maintainAspectRatio: false }} />
            </div>
          </div>
        )}
        
        {documentCount > 0 && (
          <div className="bg-white p-4 rounded shadow">
            <h3 className="text-lg font-semibold mb-4">Document Types Distribution</h3>
            <div className="h-64">
              <Pie data={prepareDocumentTypeData()} options={{ maintainAspectRatio: false }} />
            </div>
          </div>
        )}
      </div>
      
      {/* Recent Signals */}
      <div className="bg-white p-4 rounded shadow">
        <h3 className="text-lg font-semibold mb-4">Recent Signals</h3>
        
        {recentSignals.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead>
                <tr className="bg-gray-100">
                  <th className="px-4 py-2 text-left">ID</th>
                  <th className="px-4 py-2 text-left">Type</th>
                  <th className="px-4 py-2 text-left">Target</th>
                  <th className="px-4 py-2 text-left">Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {recentSignals.map((signal, index) => (
                  <tr key={index} className={index % 2 === 0 ? 'bg-gray-50' : 'bg-white'}>
                    <td className="px-4 py-2">{signal.id}</td>
                    <td className="px-4 py-2">{signal.signalType}</td>
                    <td className="px-4 py-2">{signal.target || 'N/A'}</td>
                    <td className="px-4 py-2">{formatTimestamp(signal.timestamp_created)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-gray-500">No signals available</p>
        )}
      </div>
    </div>
  );
};

export default DashboardView;