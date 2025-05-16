import React from 'react';
import { usePheromoneData } from '../contexts/PheromoneDataContext';
import { Card, Title, Text, Metric, DonutChart, Table, TableHead, TableRow, TableHeaderCell, TableBody, TableCell } from '@tremor/react';

const DashboardView = () => {
  const { pheromoneData, loading, error, getUniqueSignalTypes, getUniqueDocumentTypes } = usePheromoneData();
  
  // Tremor supported color names for DonutChart
  const tremorColors = [
    "blue", "cyan", "amber", "rose", "emerald", "violet", "fuchsia", "lime", "indigo", "teal"
  ];

  // Prepare signal type distribution data for Tremor DonutChart
  const prepareSignalTypeData = () => {
    const types = getUniqueSignalTypes();
    return types.map((type) => ({
      name: type,
      value: pheromoneData.signals.filter(signal => signal.signalType === type).length,
    }));
  };
  // Prepare document type distribution data for Tremor DonutChart
  const prepareDocumentTypeData = () => {
    const types = getUniqueDocumentTypes();
    return types.map((type) => ({
      name: type,
      value: Object.values(pheromoneData.documentationRegistry).filter(doc => doc.type === type).length,
    }));
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
    <div className="p-6 bg-tremor-background min-h-screen">
      <Title className="text-2xl mb-6">Dashboard</Title>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <Card>
          <Text>Signals</Text>
          <Metric>{signalCount}</Metric>
        </Card>
        <Card>
          <Text>Documentation Entries</Text>
          <Metric>{documentCount}</Metric>
        </Card>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        {signalCount > 0 && (
          <Card>
            <Title className="mb-4">Signal Types Distribution</Title>
            <DonutChart
              data={prepareSignalTypeData()}
              category="value"
              index="name"
              colors={tremorColors}
              className={`w-full h-64${prepareSignalTypeData().length === 1 ? ' single-slice' : ''}`}
            />
          </Card>
        )}
        {documentCount > 0 && (
          <Card>
            <Title className="mb-4">Document Types Distribution</Title>
            <DonutChart
              data={prepareDocumentTypeData()}
              category="value"
              index="name"
              colors={tremorColors}
              className={`w-full h-64${prepareDocumentTypeData().length === 1 ? ' single-slice' : ''}`}
            />
          </Card>
        )}
      </div>
      <Card>
        <Title className="mb-4">Recent Signals</Title>
        {recentSignals.length > 0 ? (
          <Table>
            <TableHead>
              <TableRow>
                <TableHeaderCell>ID</TableHeaderCell>
                <TableHeaderCell>Type</TableHeaderCell>
                <TableHeaderCell>Target</TableHeaderCell>
                <TableHeaderCell>Timestamp</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {recentSignals.map((signal, index) => (
                <TableRow key={index}>
                  <TableCell>{signal.id}</TableCell>
                  <TableCell>{signal.signalType}</TableCell>
                  <TableCell>{signal.target || 'N/A'}</TableCell>
                  <TableCell>{formatTimestamp(signal.timestamp_created)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Text>No signals available</Text>
        )}
      </Card>
    </div>
  );
};

export default DashboardView;