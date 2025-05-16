import React, { useRef, useEffect } from 'react';
import { JsonEditor as Editor } from 'jsoneditor-react';
import 'jsoneditor-react/es/editor.min.css';

const RawEditor = ({ json, onChange, schema }) => {
  const editorRef = useRef(null);
  
  // Update editor content when json prop changes
  useEffect(() => {
    if (editorRef.current && json !== editorRef.current.jsonEditor.get()) {
      editorRef.current.jsonEditor.update(json);
    }
  }, [json]);
  
  // Handle editor initialization
  const handleEditorRef = (instance) => {
    editorRef.current = instance;
  };
  
  return (
    <div className="jsoneditor-container">
      {json ? (
        <Editor
          ref={handleEditorRef}
          value={json}
          onChange={onChange}
          schema={schema}
          mode="tree"
          navigationBar={true}
          mainMenuBar={true}
          statusBar={true}
          search={true}
          allowedModes={['tree', 'code', 'text']}
        />
      ) : (
        <div className="bg-gray-100 p-4 rounded text-center h-full flex items-center justify-center">
          <p className="text-gray-500">
            Please load a .swarmConfig file to start editing
          </p>
        </div>
      )}
    </div>
  );
};

export default RawEditor;