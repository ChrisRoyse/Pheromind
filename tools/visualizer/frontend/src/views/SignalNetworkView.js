import React, { useEffect, useRef, useState } from 'react';
import { usePheromoneData } from '../contexts/PheromoneDataContext';
import { Network } from 'vis-network/standalone';

const SignalNetworkView = () => {
  const { pheromoneData, loading, error } = usePheromoneData();
  const networkRef = useRef(null);
  const containerRef = useRef(null);
  const [groupBy, setGroupBy] = useState('target'); // 'target', 'signalType', or 'category'
  
  // Create and update network visualization
  useEffect(() => {
    if (loading || error || !pheromoneData.signals || pheromoneData.signals.length === 0) {
      return;
    }
    
    // Clean up previous network
    if (networkRef.current) {
      networkRef.current.destroy();
      networkRef.current = null;
    }
    
    // Prepare nodes and edges
    const { nodes, edges } = prepareNetworkData();
    
    // Create network
    const container = containerRef.current;
    const data = { nodes, edges };
    const options = {
      nodes: {
        shape: 'dot',
        size: 16,
        font: {
          size: 12,
          face: 'Tahoma'
        },
        borderWidth: 2
      },
      edges: {
        width: 1,
        smooth: {
          type: 'continuous'
        }
      },
      physics: {
        stabilization: true,
        barnesHut: {
          gravitationalConstant: -80,
          springConstant: 0.001,
          springLength: 200
        }
      },
      groups: generateGroups()
    };
    
    networkRef.current = new Network(container, data, options);
    
    // Add click event
    networkRef.current.on('click', function(params) {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0];
        const node = nodes.get(nodeId);
        
        if (node) {
          alert(`Selected: ${node.label}\nType: ${node.type}\nConnections: ${node.connections}`);
        }
      }
    });
    
  }, [pheromoneData.signals, groupBy, loading, error]);
  
  // Prepare network data based on groupBy selection
  const prepareNetworkData = () => {
    const nodes = [];
    const edges = [];
    const nodeMap = new Map();
    
    // Create nodes based on groupBy
    if (groupBy === 'target') {
      // Group by target
      const targets = new Map();
      
      pheromoneData.signals.forEach(signal => {
        const target = signal.target || 'unknown';
        
        if (!targets.has(target)) {
          targets.set(target, {
            id: target,
            label: target,
            group: target,
            type: 'target',
            connections: 0
          });
        }
        
        // Increment connections count
        const targetNode = targets.get(target);
        targetNode.connections++;
      });
      
      // Add target nodes
      targets.forEach(node => {
        nodes.push(node);
        nodeMap.set(node.id, node);
      });
      
      // Create edges between targets based on signal relationships
      const targetConnections = new Map();
      
      pheromoneData.signals.forEach(signal => {
        if (!signal.target) return;
        
        // Look for other signals that might be related
        pheromoneData.signals.forEach(otherSignal => {
          if (signal === otherSignal || !otherSignal.target) return;
          
          // Check if signals are related (e.g., same category or type)
          if (signal.category && signal.category === otherSignal.category) {
            const key = [signal.target, otherSignal.target].sort().join('-');
            
            if (!targetConnections.has(key)) {
              targetConnections.set(key, {
                from: signal.target,
                to: otherSignal.target,
                value: 1
              });
            } else {
              const connection = targetConnections.get(key);
              connection.value++;
            }
          }
        });
      });
      
      // Add edges
      targetConnections.forEach(edge => {
        edges.push(edge);
      });
    } else if (groupBy === 'signalType') {
      // Group by signal type
      const types = new Map();
      
      pheromoneData.signals.forEach(signal => {
        const type = signal.signalType || 'unknown';
        
        if (!types.has(type)) {
          types.set(type, {
            id: type,
            label: type,
            group: type,
            type: 'signalType',
            connections: 0
          });
        }
        
        // Increment connections count
        const typeNode = types.get(type);
        typeNode.connections++;
      });
      
      // Add type nodes
      types.forEach(node => {
        nodes.push(node);
        nodeMap.set(node.id, node);
      });
      
      // Create edges between types based on signal relationships
      const typeConnections = new Map();
      
      pheromoneData.signals.forEach(signal => {
        if (!signal.signalType) return;
        
        // Look for other signals that might be related
        pheromoneData.signals.forEach(otherSignal => {
          if (signal === otherSignal || !otherSignal.signalType) return;
          
          // Check if signals are related (e.g., same target)
          if (signal.target && signal.target === otherSignal.target) {
            const key = [signal.signalType, otherSignal.signalType].sort().join('-');
            
            if (!typeConnections.has(key)) {
              typeConnections.set(key, {
                from: signal.signalType,
                to: otherSignal.signalType,
                value: 1
              });
            } else {
              const connection = typeConnections.get(key);
              connection.value++;
            }
          }
        });
      });
      
      // Add edges
      typeConnections.forEach(edge => {
        edges.push(edge);
      });
    } else if (groupBy === 'category') {
      // Group by category
      const categories = new Map();
      
      pheromoneData.signals.forEach(signal => {
        const category = signal.category || 'unknown';
        
        if (!categories.has(category)) {
          categories.set(category, {
            id: category,
            label: category,
            group: category,
            type: 'category',
            connections: 0
          });
        }
        
        // Increment connections count
        const categoryNode = categories.get(category);
        categoryNode.connections++;
      });
      
      // Add category nodes
      categories.forEach(node => {
        nodes.push(node);
        nodeMap.set(node.id, node);
      });
      
      // Create edges between categories based on signal relationships
      const categoryConnections = new Map();
      
      pheromoneData.signals.forEach(signal => {
        if (!signal.category) return;
        
        // Look for other signals that might be related
        pheromoneData.signals.forEach(otherSignal => {
          if (signal === otherSignal || !otherSignal.category) return;
          
          // Check if signals are related (e.g., same target)
          if (signal.target && signal.target === otherSignal.target) {
            const key = [signal.category, otherSignal.category].sort().join('-');
            
            if (!categoryConnections.has(key)) {
              categoryConnections.set(key, {
                from: signal.category,
                to: otherSignal.category,
                value: 1
              });
            } else {
              const connection = categoryConnections.get(key);
              connection.value++;
            }
          }
        });
      });
      
      // Add edges
      categoryConnections.forEach(edge => {
        edges.push(edge);
      });
    }
    
    return {
      nodes: {
        add: nodes
      },
      edges: {
        add: edges
      }
    };
  };
  
  // Generate color groups
  const generateGroups = () => {
    const groups = {};
    const uniqueValues = new Set();
    
    // Collect unique values based on groupBy
    pheromoneData.signals.forEach(signal => {
      if (groupBy === 'target') {
        uniqueValues.add(signal.target || 'unknown');
      } else if (groupBy === 'signalType') {
        uniqueValues.add(signal.signalType || 'unknown');
      } else if (groupBy === 'category') {
        uniqueValues.add(signal.category || 'unknown');
      }
    });
    
    // Generate a color for each unique value
    Array.from(uniqueValues).forEach(value => {
      const r = Math.floor(Math.random() * 200);
      const g = Math.floor(Math.random() * 200);
      const b = Math.floor(Math.random() * 200);
      
      groups[value] = {
        color: {
          background: `rgba(${r}, ${g}, ${b}, 0.6)`,
          border: `rgba(${r}, ${g}, ${b}, 1)`,
          highlight: {
            background: `rgba(${r}, ${g}, ${b}, 0.8)`,
            border: `rgba(${r}, ${g}, ${b}, 1)`
          }
        }
      };
    });
    
    return groups;
  };
  
  // Handle group by change
  const handleGroupByChange = (e) => {
    setGroupBy(e.target.value);
  };
  
  // Render loading state
  if (loading) {
    return (
      <div className="p-4">
        <h2 className="text-2xl font-bold mb-4">Signal Network</h2>
        <div className="text-center py-8">Loading...</div>
      </div>
    );
  }
  
  // Render error state
  if (error) {
    return (
      <div className="p-4">
        <h2 className="text-2xl font-bold mb-4">Signal Network</h2>
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          <p>{error}</p>
        </div>
      </div>
    );
  }
  
  // Render empty state
  if (!pheromoneData.signals || pheromoneData.signals.length === 0) {
    return (
      <div className="p-4">
        <h2 className="text-2xl font-bold mb-4">Signal Network</h2>
        <div className="bg-gray-100 p-4 rounded text-center">
          <p className="text-gray-500">No signals available to visualize</p>
        </div>
      </div>
    );
  }
  
  return (
    <div className="p-4">
      <h2 className="text-2xl font-bold mb-4">Signal Network</h2>
      
      {/* Controls */}
      <div className="bg-white p-4 rounded shadow mb-6">
        <div className="flex items-center">
          <label className="mr-2 font-medium">Group By:</label>
          <select
            value={groupBy}
            onChange={handleGroupByChange}
            className="border border-gray-300 rounded px-3 py-2"
          >
            <option value="target">Target</option>
            <option value="signalType">Signal Type</option>
            <option value="category">Category</option>
          </select>
        </div>
      </div>
      
      {/* Network Visualization */}
      <div className="bg-white p-4 rounded shadow">
        <div ref={containerRef} className="network-container"></div>
      </div>
    </div>
  );
};

export default SignalNetworkView;