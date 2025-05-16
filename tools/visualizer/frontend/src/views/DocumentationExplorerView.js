import React, { useState, useEffect } from 'react';
import { usePheromoneData } from '../contexts/PheromoneDataContext';

const DocumentationExplorerView = () => {
  const { 
    pheromoneData, 
    loading, 
    error, 
    filterDocumentation, 
    getUniqueDocumentTypes 
  } = usePheromoneData();
  
  // Filter state
  const [filters, setFilters] = useState({
    type: '',
    searchText: ''
  });
  
  // Sorting state
  const [sortBy, setSortBy] = useState('path_asc'); // Default: path (A-Z)
  
  // Filtered and sorted documentation entries
  const [displayedDocuments, setDisplayedDocuments] = useState([]);
  
  // Update displayed documents when data, filters, or sorting changes
  useEffect(() => {
    if (!pheromoneData.documentationRegistry) return;
    
    // Apply filters
    const filteredRegistry = filterDocumentation(filters);
    
    // Convert to array for sorting
    const documentsArray = Object.entries(filteredRegistry).map(([path, metadata]) => ({
      path,
      ...metadata
    }));
    
    // Apply sorting
    documentsArray.sort((a, b) => {
      switch (sortBy) {
        case 'path_asc':
          return a.path.localeCompare(b.path);
        case 'path_desc':
          return b.path.localeCompare(a.path);
        case 'type_asc':
          return (a.type || '').localeCompare(b.type || '');
        case 'type_desc':
          return (b.type || '').localeCompare(a.type || '');
        case 'date_asc':
          return new Date(a.timestamp || 0) - new Date(b.timestamp || 0);
        case 'date_desc':
          return new Date(b.timestamp || 0) - new Date(a.timestamp || 0);
        default:
          return 0;
      }
    });
    
    setDisplayedDocuments(documentsArray);
  }, [pheromoneData.documentationRegistry, filters, sortBy, filterDocumentation]);
  
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
      searchText: ''
    });
  };
  
  // Format timestamp
  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A';
    
    const date = new Date(timestamp);
    return date.toLocaleString();
  };
  
  // Get unique document types for filter dropdown
  const documentTypes = getUniqueDocumentTypes();
  
  // Render loading state
  if (loading) {
    return (
      <div className="p-4">
        <h2 className="text-2xl font-bold mb-4">Documentation Registry</h2>
        <div className="text-center py-8">Loading...</div>
      </div>
    );
  }
  
  // Render error state
  if (error) {
    return (
      <div className="p-4">
        <h2 className="text-2xl font-bold mb-4">Documentation Registry</h2>
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          <p>{error}</p>
        </div>
      </div>
    );
  }
  
  return (
    <div className="p-4">
      <h2 className="text-2xl font-bold mb-4">Documentation Registry</h2>
      
      {/* Filters and Sorting */}
      <div className="bg-white p-4 rounded shadow mb-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Document Type Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Document Type</label>
            <select
              name="type"
              value={filters.type}
              onChange={handleFilterChange}
              className="w-full border border-gray-300 rounded px-3 py-2"
            >
              <option value="">All Types</option>
              {documentTypes.map((type, index) => (
                <option key={index} value={type}>{type}</option>
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
              placeholder="Search in path or description..."
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
              <option value="path_asc">Path (A-Z)</option>
              <option value="path_desc">Path (Z-A)</option>
              <option value="type_asc">Type (A-Z)</option>
              <option value="type_desc">Type (Z-A)</option>
              <option value="date_desc">Date (Newest First)</option>
              <option value="date_asc">Date (Oldest First)</option>
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
      
      {/* Document Count */}
      <div className="mb-4">
        <p className="text-gray-600">
          Showing {displayedDocuments.length} of {
            pheromoneData.documentationRegistry 
              ? Object.keys(pheromoneData.documentationRegistry).length 
              : 0
          } documents
        </p>
      </div>
      
      {/* Documents Table */}
      <div className="bg-white rounded shadow overflow-hidden">
        {displayedDocuments.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="docs-table">
              <thead>
                <tr>
                  <th>File Path</th>
                  <th>Description</th>
                  <th>Type</th>
                  <th>Last Updated</th>
                  <th>Generated By</th>
                </tr>
              </thead>
              <tbody>
                {displayedDocuments.map((doc, index) => (
                  <tr key={index}>
                    <td className="font-medium text-blue-600 hover:underline cursor-pointer">
                      {doc.path}
                    </td>
                    <td>{doc.description || 'N/A'}</td>
                    <td>{doc.type || 'N/A'}</td>
                    <td>{formatTimestamp(doc.timestamp)}</td>
                    <td>{doc.generated_by || 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-4 text-center">
            <p className="text-gray-500">No documentation entries match the current filters</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default DocumentationExplorerView;