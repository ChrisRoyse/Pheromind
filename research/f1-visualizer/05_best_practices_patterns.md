# Best Practices and Patterns: F1 - Visual Pheromone & Documentation Landscape Tool

## 1. Introduction

This document outlines recommended best practices and design patterns for implementing the Visual Pheromone & Documentation Landscape Tool. Following these guidelines will help ensure a maintainable, scalable, and high-quality implementation.

## 2. Architecture Patterns

### 2.1 Clean Architecture

#### Description:
Organize the codebase into layers with clear separation of concerns and dependencies pointing inward.

#### Implementation:

```
/src
  /core                 # Domain models and business logic
    /models             # Core data models (Signal, Document, etc.)
    /services           # Core business logic
  /infrastructure       # External systems integration
    /file-watcher       # File system watching
    /websocket          # WebSocket communication
  /ui                   # User interface components
    /components         # Reusable UI components
    /views              # Page/screen components
    /hooks              # Custom React hooks
  /utils                # Utility functions
```

#### Benefits:
- Clear separation of concerns
- Easier testing of individual components
- More maintainable and adaptable codebase
- Reduced coupling between components

### 2.2 Flux/Redux Pattern for State Management

#### Description:
Use a unidirectional data flow pattern for state management, whether with Redux, Zustand, or a custom implementation using React Context.

#### Implementation:

```javascript
// Example with React Context and useReducer
const initialState = {
  signals: [],
  documentationRegistry: {},
  selectedSignalId: null,
  filters: { signalType: null, target: null },
  connectionStatus: 'disconnected'
};

function reducer(state, action) {
  switch (action.type) {
    case 'SET_PHEROMONE_DATA':
      return {
        ...state,
        signals: action.payload.signals,
        documentationRegistry: action.payload.documentationRegistry
      };
    case 'SELECT_SIGNAL':
      return {
        ...state,
        selectedSignalId: action.payload
      };
    case 'SET_FILTER':
      return {
        ...state,
        filters: {
          ...state.filters,
          [action.payload.filterType]: action.payload.value
        }
      };
    case 'SET_CONNECTION_STATUS':
      return {
        ...state,
        connectionStatus: action.payload
      };
    default:
      return state;
  }
}

// In a provider component
const [state, dispatch] = useReducer(reducer, initialState);

// Usage in components
dispatch({ type: 'SELECT_SIGNAL', payload: signalId });
### 2.3 Container/Presentational Pattern

#### Description:
Separate components into "containers" (connected to state/data sources) and "presentational" components (pure rendering based on props).

#### Implementation:

```jsx
// Presentational component
const SignalCard = ({ signal, onSelect }) => (
  <div className="signal-card" onClick={() => onSelect(signal.id)}>
    <div className="signal-header">
      <span className="signal-type">{signal.signalType}</span>
      <span className="signal-strength">{signal.strength}</span>
    </div>
    <div className="signal-target">{signal.target}</div>
    <div className="signal-message">{signal.message}</div>
  </div>
);

// Container component
const SignalListContainer = () => {
  const { signals, selectedSignalId, filters } = useAppState();
  const dispatch = useAppDispatch();
  
  // Filter signals based on current filters
  const filteredSignals = useMemo(() => {
    return signals.filter(signal => {
      if (filters.signalType && signal.signalType !== filters.signalType) {
        return false;
      }
      if (filters.target && signal.target !== filters.target) {
        return false;
      }
      return true;
    });
  }, [signals, filters]);
  
  const handleSelectSignal = (signalId) => {
    dispatch({ type: 'SELECT_SIGNAL', payload: signalId });
  };
  
  return (
    <div className="signal-list">
      {filteredSignals.map(signal => (
        <SignalCard
          key={signal.id}
          signal={signal}
          isSelected={signal.id === selectedSignalId}
          onSelect={handleSelectSignal}
        />
      ))}
    </div>
  );
};
```

#### Benefits:
- Better separation of concerns
- More reusable UI components
- Easier testing of presentational components
- Clearer component responsibilities

## 3. Backend Best Practices

### 3.1 Dependency Injection

#### Description:
Use dependency injection to provide services and configurations to components, making them more testable and configurable.

#### Implementation:

```javascript
// Define service interfaces
class FileWatcherService {
  constructor(config) {
    this.config = config;
  }
  
  // Methods...
}

class WebSocketService {
  constructor(server, config) {
    this.server = server;
    this.config = config;
  }
  
  // Methods...
}

// Application composition
function createApp(config) {
  const app = express();
  const server = http.createServer(app);
  
  const fileWatcher = new FileWatcherService(config.fileWatcher);
  const webSocketService = new WebSocketService(server, config.webSocket);
  
  // Wire up services
  fileWatcher.on('change', (data) => {
    webSocketService.broadcast('pheromone_update', data);
  });
  
  return { app, server, fileWatcher, webSocketService };
}

// Usage
const app = createApp(config);
app.server.listen(config.port);
```

#### Benefits:
- Easier testing through mocking dependencies
- More flexible configuration
- Clearer component responsibilities
- Easier to extend or replace components
```

#### Benefits:
- Predictable state updates
- Centralized state management
- Easier debugging
- Clear data flow
### 3.2 Event-Driven Architecture

#### Description:
Use an event-driven approach for communication between backend components.

#### Implementation:

```javascript
// Event emitter
const eventBus = new EventEmitter();

// File watcher service
class FileWatcherService {
  constructor(eventBus, config) {
    this.eventBus = eventBus;
    this.config = config;
    this.watcher = null;
  }
  
  start() {
    this.watcher = chokidar.watch(this.config.filePath, this.config.options);
    
    this.watcher.on('change', async (path) => {
      try {
        const content = await fs.promises.readFile(path, 'utf8');
        const data = JSON.parse(content);
        this.eventBus.emit('pheromone:updated', { path, data });
      } catch (error) {
        this.eventBus.emit('pheromone:error', { path, error });
      }
    });
    
    this.watcher.on('error', (error) => {
      this.eventBus.emit('pheromone:watcher:error', { error });
    });
  }
  
  stop() {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
  }
}

// WebSocket service
class WebSocketService {
  constructor(eventBus, server, config) {
    this.eventBus = eventBus;
    this.io = socketIo(server, config);
    
    // Listen to events
    this.eventBus.on('pheromone:updated', (data) => {
      this.io.emit('pheromone_update', data);
    });
    
    this.eventBus.on('pheromone:error', (data) => {
      this.io.emit('pheromone_error', data);
    });
    
    // Handle socket connections
    this.io.on('connection', (socket) => {
      this.eventBus.emit('client:connected', { socketId: socket.id });
      
      socket.on('request_initial_data', () => {
        this.eventBus.emit('client:requested:initial_data', { socketId: socket.id });
      });
      
      socket.on('disconnect', () => {
        this.eventBus.emit('client:disconnected', { socketId: socket.id });
      });
    });
  }
}
```

#### Benefits:
- Loose coupling between components
- Easier to add new features or listeners
- More maintainable code
- Better testability

### 3.3 Error Handling Strategy

#### Description:
Implement a comprehensive error handling strategy for the backend.

#### Implementation:

```javascript
// Centralized error handler
function errorHandler(err, req, res, next) {
  // Log error
  console.error('API Error:', err);
  
  // Determine status code
  const statusCode = err.statusCode || 500;
  
  // Send error response
  res.status(statusCode).json({
    error: {
      message: err.message,
      code: err.code || 'INTERNAL_ERROR',
      ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
    }
  });
}

// Custom error classes
class AppError extends Error {
  constructor(message, statusCode, code) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

class FileNotFoundError extends AppError {
  constructor(filePath) {
    super(`File not found: ${filePath}`, 404, 'FILE_NOT_FOUND');
    this.filePath = filePath;
  }
}

class InvalidJsonError extends AppError {
  constructor(filePath, parseError) {
    super(`Invalid JSON in file: ${filePath}`, 400, 'INVALID_JSON');
    this.filePath = filePath;
    this.parseError = parseError;
  }
}

// Usage in routes/controllers
app.get('/api/pheromone/current', async (req, res, next) => {
  try {
    const filePath = config.pheromoneFilePath;
    
    try {
      await fs.promises.access(filePath, fs.constants.R_OK);
    } catch (error) {
      throw new FileNotFoundError(filePath);
    }
    
    try {
      const content = await fs.promises.readFile(filePath, 'utf8');
      const data = JSON.parse(content);
      res.json(data);
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new InvalidJsonError(filePath, error);
      }
      throw error;
    }
  } catch (error) {
    next(error);
  }
});

// Register error handler
app.use(errorHandler);
```

#### Benefits:
- Consistent error responses
- Better error tracking and debugging
- Improved user experience with meaningful error messages
- Separation of error handling from business logic
## 4. Frontend Best Practices

### 4.1 Custom React Hooks

#### Description:
Create custom hooks to encapsulate and reuse logic across components.

#### Implementation:

```javascript
// WebSocket connection hook
function useWebSocket(url) {
  const [socket, setSocket] = useState(null);
  const [status, setStatus] = useState('disconnected');
  const [error, setError] = useState(null);
  
  useEffect(() => {
    const newSocket = io(url);
    
    newSocket.on('connect', () => {
      setStatus('connected');
      setError(null);
    });
    
    newSocket.on('disconnect', () => {
      setStatus('disconnected');
    });
    
    newSocket.on('connect_error', (err) => {
      setStatus('error');
      setError(err);
    });
    
    setSocket(newSocket);
    
    return () => {
      newSocket.disconnect();
    };
  }, [url]);
  
  return { socket, status, error };
}

// Pheromone data hook
function usePheromoneData(socket) {
  const [data, setData] = useState({ signals: [], documentationRegistry: {} });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    if (!socket) return;
    
    // Request initial data
    socket.emit('request_initial_data');
    
    // Listen for updates
    socket.on('pheromone_update', (newData) => {
      setData(newData.data);
      setLoading(false);
      setError(null);
    });
    
    socket.on('pheromone_error', (err) => {
      setError(err);
      setLoading(false);
    });
    
    return () => {
      socket.off('pheromone_update');
      socket.off('pheromone_error');
    };
  }, [socket]);
  
  return { data, loading, error };
}

// Usage in components
function SignalDashboard() {
  const { socket, status } = useWebSocket('http://localhost:3001');
  const { data, loading, error } = usePheromoneData(socket);
  
  if (loading) return <LoadingSpinner />;
  if (error) return <ErrorMessage error={error} />;
  
  return (
    <div>
      <ConnectionStatus status={status} />
      <SignalList signals={data.signals} />
      <DocumentRegistry registry={data.documentationRegistry} />
    </div>
  );
}
```

#### Benefits:
- Reusable logic across components
- Cleaner component code
- Better separation of concerns
- Easier testing

### 4.2 Memoization Strategy

#### Description:
Use memoization strategically to optimize rendering performance.

#### Implementation:

```javascript
// Memoized component
const SignalCard = React.memo(({ signal, onSelect }) => {
  // Component implementation
});

// Memoized derived data
function SignalListView({ signals, filter }) {
  // Memoize filtered signals
  const filteredSignals = useMemo(() => {
    return signals.filter(signal => {
      if (filter.type && signal.signalType !== filter.type) return false;
      if (filter.target && signal.target !== filter.target) return false;
      return true;
    });
  }, [signals, filter.type, filter.target]);
  
  // Memoize signal type counts for statistics
  const signalTypeCounts = useMemo(() => {
    return signals.reduce((counts, signal) => {
      const type = signal.signalType;
      counts[type] = (counts[type] || 0) + 1;
      return counts;
    }, {});
### 4.3 Component Composition

#### Description:
Use component composition to build complex UIs from smaller, focused components.

#### Implementation:

```jsx
// Small, focused components
const SignalIcon = ({ type }) => {
  const iconMap = {
    task_completed: <CheckIcon />,
    dependency_identified: <LinkIcon />,
    // Other types...
  };
  
  return iconMap[type] || <DefaultIcon />;
};

const SignalStrengthIndicator = ({ strength }) => {
  return (
    <div className="strength-bar">
      <div 
        className="strength-fill" 
        style={{ width: `${strength * 100}%` }} 
      />
    </div>
  );
};

const TimeAgo = ({ timestamp }) => {
  const timeAgo = formatTimeAgo(timestamp);
  return <span title={new Date(timestamp).toLocaleString()}>{timeAgo}</span>;
};

// Composed component
const SignalCard = ({ signal, onSelect }) => {
  return (
    <div className="signal-card" onClick={() => onSelect(signal.id)}>
      <div className="signal-header">
        <SignalIcon type={signal.signalType} />
        <span className="signal-type">{signal.signalType}</span>
        <SignalStrengthIndicator strength={signal.strength} />
      </div>
      <div className="signal-target">{signal.target}</div>
      <div className="signal-message">{signal.message}</div>
      <div className="signal-footer">
        <TimeAgo timestamp={signal.timestamp_created} />
      </div>
    </div>
  );
};
```

#### Benefits:
- More maintainable and testable code
- Better reusability of components
- Clearer component responsibilities
- Easier to understand and modify UI

## 5. Testing Best Practices

### 5.1 Testing Pyramid

#### Description:
Follow the testing pyramid approach with more unit tests, fewer integration tests, and even fewer end-to-end tests.

#### Implementation:

```
/tests
  /unit                 # Unit tests
    /models             # Tests for domain models
    /services           # Tests for services
    /utils              # Tests for utility functions
  /integration          # Integration tests
    /api                # API endpoint tests
    /websocket          # WebSocket communication tests
  /e2e                  # End-to-end tests
```

#### Unit Test Example:

```javascript
// Unit test for a utility function
describe('signalUtils', () => {
  describe('filterSignalsByType', () => {
    it('should return signals of the specified type', () => {
      const signals = [
        { id: '1', signalType: 'task_completed' },
        { id: '2', signalType: 'dependency_identified' },
        { id: '3', signalType: 'task_completed' }
      ];
      
      const result = filterSignalsByType(signals, 'task_completed');
      
      expect(result).toHaveLength(2);
      expect(result[0].id).toBe('1');
      expect(result[1].id).toBe('3');
    });
    
    it('should return empty array if no signals match', () => {
      const signals = [
        { id: '1', signalType: 'task_completed' },
        { id: '2', signalType: 'dependency_identified' }
      ];
      
      const result = filterSignalsByType(signals, 'unknown_type');
      
      expect(result).toHaveLength(0);
    });
  });
});
```

#### Benefits:
- Faster feedback from unit tests
- Better test coverage
- More maintainable test suite
- Clearer isolation of issues

### 5.2 Component Testing Strategy

#### Description:
Use a combination of unit tests for logic and snapshot tests for UI components.

#### Implementation:

```jsx
// Component test with React Testing Library
import { render, screen, fireEvent } from '@testing-library/react';
import SignalCard from './SignalCard';

describe('SignalCard', () => {
  const mockSignal = {
    id: '123',
    signalType: 'task_completed',
    target: 'feature-x',
    strength: 0.8,
    message: 'Task completed successfully',
    timestamp_created: '2025-05-15T12:00:00Z'
  };
  
  it('renders signal information correctly', () => {
    render(<SignalCard signal={mockSignal} />);
    
    expect(screen.getByText('task_completed')).toBeInTheDocument();
    expect(screen.getByText('feature-x')).toBeInTheDocument();
    expect(screen.getByText('Task completed successfully')).toBeInTheDocument();
  });
  
  it('calls onSelect when clicked', () => {
    const handleSelect = jest.fn();
    render(<SignalCard signal={mockSignal} onSelect={handleSelect} />);
    
    fireEvent.click(screen.getByText('Task completed successfully'));
    
    expect(handleSelect).toHaveBeenCalledWith('123');
  });
  
  it('matches snapshot', () => {
    const { container } = render(<SignalCard signal={mockSignal} />);
    expect(container).toMatchSnapshot();
  });
});
```

#### Benefits:
- Verifies both behavior and appearance
- Catches unintended UI changes
- Tests components in isolation
- Focuses on user interactions

## 6. Documentation Best Practices

### 6.1 Code Documentation

#### Description:
Use consistent code documentation with JSDoc comments.

#### Implementation:

```javascript
/**
 * Filters signals by the specified signal type.
 * 
 * @param {Array<Object>} signals - The array of signal objects to filter.
 * @param {string} signalType - The signal type to filter by.
 * @returns {Array<Object>} A new array containing only signals of the specified type.
 */
function filterSignalsByType(signals, signalType) {
  return signals.filter(signal => signal.signalType === signalType);
}

/**
 * Component that displays a signal in a card format.
 * 
 * @param {Object} props - The component props.
 * @param {Object} props.signal - The signal object to display.
 * @param {Function} props.onSelect - Callback function when the card is selected.
 * @returns {JSX.Element} The rendered component.
 */
function SignalCard({ signal, onSelect }) {
  // Implementation...
}
```

#### Benefits:
- Better code understanding
- IDE autocompletion and type hints
- Easier maintenance
- Better onboarding for new developers

## 7. Conclusion

The Visual Pheromone & Documentation Landscape Tool should be implemented following these best practices to ensure a maintainable, scalable, and high-quality application. Key recommendations include:

1. **Architecture**: Use clean architecture with clear separation of concerns.
2. **State Management**: Implement unidirectional data flow with React Context or similar.
3. **Component Design**: Separate container and presentational components, use composition.
4. **Backend**: Use dependency injection and event-driven architecture.
5. **Frontend**: Leverage custom hooks, memoization, and component composition.
6. **Testing**: Follow the testing pyramid with appropriate test types.
7. **Documentation**: Maintain comprehensive code and architecture documentation.

By following these patterns and practices, the development team can create a robust, performant, and maintainable tool that meets the requirements and provides a good user experience.
  }, [signals]);
  
  // Memoize callback
  const handleSelectSignal = useCallback((signalId) => {
    // Handle selection
  }, [/* dependencies */]);
  
  return (
    <>
      <SignalStatistics counts={signalTypeCounts} />
      <div className="signal-list">
        {filteredSignals.map(signal => (
          <SignalCard
            key={signal.id}
            signal={signal}
            onSelect={handleSelectSignal}
          />
        ))}
      </div>
    </>
  );
}
```

#### Benefits:
- Reduced unnecessary re-renders
- Better performance with large datasets
- Clearer code with explicit dependencies