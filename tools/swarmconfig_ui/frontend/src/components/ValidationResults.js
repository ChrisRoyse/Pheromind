import React from 'react';

const ValidationResults = ({ valid, errors }) => {
  return (
    <div className={`validation-results ${valid ? 'validation-success' : 'validation-error'}`}>
      {valid ? (
        <div className="flex items-center">
          <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
          </svg>
          <span className="font-medium">Validation successful! The .swarmConfig is valid.</span>
        </div>
      ) : (
        <div>
          <div className="flex items-center">
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
            <span className="font-medium">Validation failed! The .swarmConfig has errors:</span>
          </div>
          
          <ul className="error-list">
            {errors.map((error, index) => (
              <li key={index}>
                <strong>Path:</strong> <span className="error-path">{error.instancePath || '(root)'}</span>
                <br />
                <strong>Message:</strong> {error.message}
                {error.params && (
                  <div className="text-sm mt-1">
                    <strong>Details:</strong> {JSON.stringify(error.params)}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default ValidationResults;