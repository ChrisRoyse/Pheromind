import React from 'react';

const SignalDetailModal = ({ signal, onClose }) => {
  // Format JSON for display
  const formatJson = (json) => {
    return JSON.stringify(json, null, 2);
  };
  
  // Copy JSON to clipboard
  const copyToClipboard = () => {
    navigator.clipboard.writeText(formatJson(signal))
      .then(() => {
        alert('Signal JSON copied to clipboard');
      })
      .catch(err => {
        console.error('Failed to copy: ', err);
      });
  };
  
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-bold">Signal Details</h2>
          <button 
            className="text-gray-500 hover:text-gray-700"
            onClick={onClose}
          >
            ✕
          </button>
        </div>
        
        <div className="mb-4">
          <button 
            className="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600"
            onClick={copyToClipboard}
          >
            Copy JSON
          </button>
        </div>
        
        <pre className="bg-gray-100 p-4 rounded overflow-auto max-h-96 text-sm">
          {formatJson(signal)}
        </pre>
      </div>
    </div>
  );
};

export default SignalDetailModal;