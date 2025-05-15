import React from 'react';
import { NavLink } from 'react-router-dom';
import { usePheromoneData } from '../../contexts/PheromoneDataContext';

const Sidebar = () => {
  const { pheromoneData } = usePheromoneData();
  
  // Count signals
  const signalCount = pheromoneData.signals ? pheromoneData.signals.length : 0;
  
  // Count documentation entries
  const documentationCount = pheromoneData.documentationRegistry 
    ? Object.keys(pheromoneData.documentationRegistry).length 
    : 0;
  
  return (
    <aside className="bg-gray-100 w-64 p-4 h-full">
      <nav>
        <ul className="space-y-2">
          <li>
            <NavLink 
              to="/" 
              className={({ isActive }) => 
                `block p-2 rounded ${isActive ? 'bg-blue-500 text-white' : 'hover:bg-gray-200'}`
              }
              end
            >
              Dashboard
            </NavLink>
          </li>
          <li>
            <NavLink 
              to="/timeline" 
              className={({ isActive }) => 
                `block p-2 rounded ${isActive ? 'bg-blue-500 text-white' : 'hover:bg-gray-200'}`
              }
            >
              Signal Timeline
              <span className="ml-2 bg-gray-200 text-gray-700 px-2 py-1 rounded-full text-xs">
                {signalCount}
              </span>
            </NavLink>
          </li>
          <li>
            <NavLink 
              to="/network" 
              className={({ isActive }) => 
                `block p-2 rounded ${isActive ? 'bg-blue-500 text-white' : 'hover:bg-gray-200'}`
              }
            >
              Signal Network
            </NavLink>
          </li>
          <li>
            <NavLink 
              to="/documentation" 
              className={({ isActive }) => 
                `block p-2 rounded ${isActive ? 'bg-blue-500 text-white' : 'hover:bg-gray-200'}`
              }
            >
              Documentation Registry
              <span className="ml-2 bg-gray-200 text-gray-700 px-2 py-1 rounded-full text-xs">
                {documentationCount}
              </span>
            </NavLink>
          </li>
        </ul>
      </nav>
      
      <div className="mt-8 text-sm text-gray-600">
        <h3 className="font-semibold mb-2">Quick Stats</h3>
        <div className="space-y-1">
          <div>
            <span className="font-medium">Signals: </span>
            <span>{signalCount}</span>
          </div>
          <div>
            <span className="font-medium">Documents: </span>
            <span>{documentationCount}</span>
          </div>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;