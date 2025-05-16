import React from 'react';
import { NavLink } from 'react-router-dom';
import { usePheromoneData } from '../../contexts/PheromoneDataContext';
import { Card, Title, Text, Badge } from '@tremor/react';

const Sidebar = () => {
  const { pheromoneData } = usePheromoneData();
  const signalCount = pheromoneData.signals ? pheromoneData.signals.length : 0;
  const documentationCount = pheromoneData.documentationRegistry 
    ? Object.keys(pheromoneData.documentationRegistry).length 
    : 0;

  return (
    <aside className="h-full min-h-screen bg-tremor-background dark:bg-tremor-background-dark border-r border-tremor-border p-0">
      <Card className="rounded-none shadow-none h-full flex flex-col justify-between bg-transparent">
        <nav>
          <Title className="mb-6 mt-2 text-lg tracking-wide">Navigation</Title>
          <ul className="flex flex-col gap-2">
            <li>
              <NavLink to="/" end className={({ isActive }) => `flex items-center px-3 py-2 rounded transition ${isActive ? 'bg-tremor-brand text-white' : 'hover:bg-tremor-muted'}`}>Dashboard</NavLink>
            </li>
            <li>
              <NavLink to="/timeline" className={({ isActive }) => `flex items-center px-3 py-2 rounded transition ${isActive ? 'bg-tremor-brand text-white' : 'hover:bg-tremor-muted'}`}>
                Signal Timeline
                <Badge className="ml-2" color="gray">{signalCount}</Badge>
              </NavLink>
            </li>
            <li>
              <NavLink to="/network" className={({ isActive }) => `flex items-center px-3 py-2 rounded transition ${isActive ? 'bg-tremor-brand text-white' : 'hover:bg-tremor-muted'}`}>Signal Network</NavLink>
            </li>
            <li>
              <NavLink to="/documentation" className={({ isActive }) => `flex items-center px-3 py-2 rounded transition ${isActive ? 'bg-tremor-brand text-white' : 'hover:bg-tremor-muted'}`}>
                Documentation Registry
                <Badge className="ml-2" color="gray">{documentationCount}</Badge>
              </NavLink>
            </li>
          </ul>
        </nav>
        <div className="mt-8 mb-2">
          <Title className="text-base mb-2">Quick Stats</Title>
          <div className="flex flex-col gap-1 text-tremor-content">
            <Text>Signals: <span className="font-semibold">{signalCount}</span></Text>
            <Text>Documents: <span className="font-semibold">{documentationCount}</span></Text>
          </div>
        </div>
      </Card>
    </aside>
  );
};

export default Sidebar;