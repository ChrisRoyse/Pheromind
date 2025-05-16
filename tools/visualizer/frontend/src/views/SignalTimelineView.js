import React, { useState, useEffect } from 'react';
import { usePheromoneData } from '../contexts/PheromoneDataContext';
import SignalCard from '../components/signals/SignalCard';

const SignalTimelineView = () => {
  const { 
    pheromoneData, 
    loading, 
    error, 
    filterSignals, 
    getUniqueSignalTypes, 
    getUniqueTargets, 
    getUniqueCategories 
  } = usePheromoneData();
  
  // Filter state
  const [filters, setFilters] = useState({
    type: '',
    target: '',
    category: '',
    searchText: ''
  });
  
  // Sorting state
  const [sortBy, setSortBy] = useState('timestamp_desc'); // Default: newest first
  
  // Filtered and sorted signals
  const [displayedSignals, setDisplayedSignals] = useState([]);
  
  // Update displayed signals when data, filters, or sorting changes
  useEffect(() => {
    if (!pheromoneData.signals) return;
    
    // Apply filters
    let filtered = filterSignals(filters);
    
    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
      switch (sortBy) {
        case 'timestamp_asc':
          return new Date(a.timestamp_created) - new Date(b.timestamp_created);
        case 'timestamp_desc':
          return new Date(b.timestamp_created) - new Date(a.timestamp_created);
        case 'strength_asc':
          return (a.strength || 0) - (b.strength || 0);
        case 'strength_desc':
          return (b.strength || 0) - (a.strength || 0);
        default:
          return 0;
      }
    });
    
    setDisplayedSignals(filtered);
  }, [pheromoneData.signals, filters, sortBy, filterSignals]);
  
  // Handle filter changes
  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters(prev => ({ ...prev, [name]: value }));
  };
  
  // Handle sort changes
  const handleSortChange = (e) => {
    setSortBy(e.target.value);
  };
  
  // Clear all filters
  const clearFilters = () => {
    setFilters({
      type: '',
      target: '',
      category: '',
      searchText: ''
    });
  };
  
  // Get unique values for filter dropdowns
  const signalTypes = getUniqueSignalTypes();
  const targets = getUniqueTargets();
  const categories = getUniqueCategories();
  
  // Render loading state
  if (loading) {
    return (
      <div className="p-4">
        <h2 className="text-2xl font-bold mb-4">Signal Timeline</h2>
        <div className="text-center py-8">Loading...</div>
      </div>
    );
  }
  
  // Render error state
  if (error) {
    return (
      <div className="p-4">
        <h2 className="text-2xl font-bold mb-4">Signal Timeline</h2>
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          <p>{error}</p>
        </div>
      </div>
    );
  }
  
  return (
    <div className="p-4">
      <h2 className="text-2xl font-bold mb-4">Signal Timeline</h2>
      
      {/* Filters and Sorting */}
      <div className="bg-white p-4 rounded shadow mb-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          {/* Signal Type Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Signal Type</label>
            <select
              name="type"
              value={filters.type}
              onChange={handleFilterChange}
              className="w-full border border-gray-300 rounded px-3 py-2"
            >
              <option value="">All Types</option>
              {signalTypes.map((type, index) => (
                <option key={index} value={type}>{type}</option>
              ))}
            </select>
          </div>
          
          {/* Target Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Target</label>
            <select
              name="target"
              value={filters.target}
              onChange={handleFilterChange}
              className="w-full border border-gray-300 rounded px-3 py-2"
            >
              <option value="">All Targets</option>
              {targets.map((target, index) => (
                <option key={index} value={target}>{target}</option>
              ))}
            </select>
          </div>
          
          {/* Category Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Category</label>
            <select
              name="category"
              value={filters.category}
              onChange={handleFilterChange}
              className="w-full border border-gray-300 rounded px-3 py-2"
            >
              <option value="">All Categories</option>
              {categories.map((category, index) => (
                <option key={index} value={category}>{category}</option>
              ))}
            </select>
          </div>
          
          {/* Search Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Search</label>
            <input
              type="text"
              name="searchText"
              value={filters.searchText}
              onChange={handleFilterChange}
              placeholder="Search in message..."
              className="w-full border border-gray-300 rounded px-3 py-2"
            />
          </div>
          
          {/* Sort By */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Sort By</label>
            <select
              value={sortBy}
              onChange={handleSortChange}
              className="w-full border border-gray-300 rounded px-3 py-2"
            >
              <option value="timestamp_desc">Newest First</option>
              <option value="timestamp_asc">Oldest First</option>
              <option value="strength_desc">Strength (High to Low)</option>
              <option value="strength_asc">Strength (Low to High)</option>
            </select>
          </div>
        </div>
        
        {/* Clear Filters Button */}
        <div className="mt-4 flex justify-end">
          <button
            onClick={clearFilters}
            className="bg-gray-200 text-gray-700 px-4 py-2 rounded hover:bg-gray-300"
          >
            Clear Filters
          </button>
        </div>
      </div>
      
      {/* Signal Count */}
      <div className="mb-4">
        <p className="text-gray-600">
          Showing {displayedSignals.length} of {pheromoneData.signals ? pheromoneData.signals.length : 0} signals
        </p>
      </div>
      
      {/* Signal List */}
      <div className="space-y-4">
        {displayedSignals.length > 0 ? (
          displayedSignals.map((signal, index) => (
            <SignalCard key={index} signal={signal} />
          ))
        ) : (
          <div className="bg-gray-100 p-4 rounded text-center">
            <p className="text-gray-500">No signals match the current filters</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default SignalTimelineView;