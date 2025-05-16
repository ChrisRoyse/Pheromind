import Ajv from 'ajv';

/**
 * Validates a swarmConfig object against the provided JSON schema
 * @param {Object} swarmConfig - The swarmConfig object to validate
 * @param {Object} schema - The JSON schema to validate against
 * @returns {Object} - Validation results with valid flag and errors array
 */
export const validateSwarmConfig = (swarmConfig, schema) => {
  // Create Ajv instance
  const ajv = new Ajv({
    allErrors: true, // Return all errors, not just the first one
    verbose: true    // Include detailed information in errors
  });
  
  // Compile schema
  const validate = ajv.compile(schema);
  
  // Validate swarmConfig
  const valid = validate(swarmConfig);
  
  // Return validation results
  return {
    valid,
    errors: validate.errors || []
  };
};

/**
 * Formats validation errors for display
 * @param {Array} errors - Array of validation errors from Ajv
 * @returns {Array} - Formatted errors with path and message
 */
export const formatValidationErrors = (errors) => {
  if (!errors || errors.length === 0) {
    return [];
  }
  
  return errors.map(error => {
    return {
      path: error.instancePath || '(root)',
      message: error.message,
      params: error.params
    };
  });
};