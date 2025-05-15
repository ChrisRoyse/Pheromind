import React, { useState } from 'react';
import { Tab, Tabs, TabList, TabPanel } from 'react-tabs';
import './App.css';

// Components
import Header from './components/Header';
import RawEditor from './components/RawEditor';
import ValidationResults from './components/ValidationResults';
import FileOperations from './components/FileOperations';

// Schema
import swarmConfigSchema from './schema/swarmConfigSchema';

// Utils
import { validateSwarmConfig } from './utils/validation';

function App() {
  // State
  const [swarmConfig, setSwarmConfig] = useState(null);
  const [fileName, setFileName] = useState('');
  const [validationResults, setValidationResults] = useState({
    valid: false,
    errors: [],
    performed: false
  });
  
  // Handle file load
  const handleFileLoad = (content, name) => {
    try {
      const parsedContent = JSON.parse(content);
      setSwarmConfig(parsedContent);
      setFileName(name);
      setValidationResults({
        valid: false,
        errors: [],
        performed: false
      });
    } catch (error) {
      alert(`Error parsing JSON: ${error.message}`);
    }
  };
  
  // Handle JSON change in editor
  const handleJsonChange = (json) => {
    setSwarmConfig(json);
    // Reset validation when content changes
    setValidationResults({
      valid: false,
      errors: [],
      performed: false
    });
  };
  
  // Handle validation
  const handleValidate = () => {
    if (!swarmConfig) {
      alert('Please load a .swarmConfig file first');
      return;
    }
    
    const results = validateSwarmConfig(swarmConfig, swarmConfigSchema);
    setValidationResults({
      valid: results.valid,
      errors: results.errors,
      performed: true
    });
  };
  
  // Handle save
  const handleSave = () => {
    if (!swarmConfig) {
      alert('Please load a .swarmConfig file first');
      return;
    }
    
    // Create a blob with the JSON content
    const blob = new Blob(
      [JSON.stringify(swarmConfig, null, 2)], 
      { type: 'application/json' }
    );
    
    // Create a download link
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName || '.swarmConfig';
    
    // Trigger download
    document.body.appendChild(link);
    link.click();
    
    // Clean up
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };
  
  return (
    <div className="app">
      <Header />
      
      <main className="app-content">
        <FileOperations 
          onFileLoad={handleFileLoad} 
          onSave={handleSave} 
          onValidate={handleValidate}
          fileName={fileName}
        />
        
        {validationResults.performed && (
          <ValidationResults 
            valid={validationResults.valid} 
            errors={validationResults.errors} 
          />
        )}
        
        <Tabs>
          <TabList>
            <Tab>Raw JSON Editor</Tab>
          </TabList>
          
          <TabPanel>
            <RawEditor 
              json={swarmConfig} 
              onChange={handleJsonChange} 
              schema={swarmConfigSchema}
            />
          </TabPanel>
        </Tabs>
      </main>
    </div>
  );
}

export default App;