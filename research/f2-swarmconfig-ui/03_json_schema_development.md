# JSON Schema Development: F2 - Advanced `.swarmConfig` Tuning & Validation UI

## 1. Introduction

This document outlines the approach for developing a comprehensive JSON Schema for the `.swarmConfig` file. The JSON Schema is a critical component of the Advanced `.swarmConfig` Tuning & Validation UI, as it will be used to validate the configuration file and provide meaningful feedback to users. It will also serve as documentation for the structure and constraints of the `.swarmConfig` file.

## 2. JSON Schema Overview

### 2.1 What is JSON Schema?

JSON Schema is a vocabulary that allows you to annotate and validate JSON documents. It provides a contract for what JSON data is required for a given application and how to interact with it. JSON Schema is used to:

- Validate that a JSON document conforms to a specified structure
- Provide clear, human- and machine-readable documentation
- Provide complete structural validation for automated testing
- Serve as a basis for generating forms and other UI elements

### 2.2 JSON Schema Versions

Several versions (drafts) of JSON Schema exist. For this project, we recommend using **JSON Schema Draft 2020-12** or at minimum **Draft-07**, as these are widely supported by validation libraries like Ajv and provide the features needed for validating `.swarmConfig` files.

## 3. `.swarmConfig` Structure Analysis

Based on the project specifications, the `.swarmConfig` file appears to have the following high-level structure:

```json
{
  "pheromoneDynamics": {
    "evaporationRate": number,
    "amplificationRules": [...]
  },
  "scribeSettings": {
    "defaultSignalStrength": number,
    "signalTypes": [...],
    "categories": [...],
    "interpretationLogic": {
      "documentPatterns": [...],
      "signalRules": [...]
    }
  },
  "generalSettings": {
    // Various general settings
  }
}
```

The most complex parts of this structure are the `interpretationLogic.documentPatterns` and `interpretationLogic.signalRules` arrays, which contain the rules for interpreting natural language summaries.

## 4. Schema Development Approach

### 4.1 Incremental Development

We recommend an incremental approach to developing the JSON Schema:

1. **Basic Structure**: Define the top-level structure and required properties
2. **Simple Properties**: Add validation for simple properties (strings, numbers, booleans)
3. **Arrays and Objects**: Define schemas for arrays and nested objects
4. **Complex Validation**: Add more complex validation rules (dependencies, conditional validation)
5. **Documentation**: Add descriptions, examples, and other documentation

### 4.2 Schema Organization

The schema should be organized in a modular way to improve maintainability:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://pheromind.dev/schemas/swarmConfig.schema.json",
  "title": "SwarmConfig",
  "description": "Configuration for the Pheromind swarm",
  "type": "object",
  "required": ["pheromoneDynamics", "scribeSettings", "generalSettings"],
  "properties": {
    "pheromoneDynamics": { "$ref": "#/definitions/pheromoneDynamics" },
    "scribeSettings": { "$ref": "#/definitions/scribeSettings" },
    "generalSettings": { "$ref": "#/definitions/generalSettings" }
  },
  "definitions": {
    "pheromoneDynamics": { /* Schema for pheromoneDynamics */ },
    "scribeSettings": { /* Schema for scribeSettings */ },
    "generalSettings": { /* Schema for generalSettings */ },
    "documentPattern": { /* Schema for a single documentPattern */ },
    "signalRule": { /* Schema for a single signalRule */ }
    // Additional definitions as needed
  }
}
```

This approach allows for reuse of common definitions and keeps the schema organized and maintainable.

## 5. Schema for Key Components

### 5.1 Document Patterns

Based on the project specifications, `documentPatterns` are used to extract document references from natural language summaries. A schema for a document pattern might look like:

```json
{
  "type": "object",
  "required": ["pattern", "docType"],
  "properties": {
    "pattern": {
      "type": "string",
      "description": "Regular expression pattern to match document references in summaries"
    },
    "docType": {
      "type": "string",
      "description": "Type of document to be extracted"
    },
    "captureGroups": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Names of capture groups in the pattern"
    },
    "descriptionTemplate": {
      "type": "string",
      "description": "Template for generating document descriptions using captured groups"
    }
  }
}
```

### 5.2 Signal Rules

Signal rules appear to be more complex, with different properties based on the `conditionType`. A schema for signal rules might use conditional validation:

```json
{
  "type": "object",
  "required": ["conditionType", "generatesSignal"],
  "properties": {
    "conditionType": {
      "type": "string",
      "enum": ["handoff_reason_code_match", "summary_keywords", "pattern_match"],
      "description": "Type of condition that triggers this rule"
    },
    "value": {
      "type": "string",
      "description": "Value to match for handoff_reason_code_match condition type"
    },
    "keywords": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Keywords to match for summary_keywords condition type"
    },
    "pattern": {
      "type": "string",
      "description": "Regular expression pattern for pattern_match condition type"
    },
    "generatesSignal": {
      "$ref": "#/definitions/signalGeneration"
    },
    "updatesDocumentation": {
      "type": "boolean",
      "description": "Whether this rule updates documentation"
    }
  },
  "allOf": [
    {
      "if": {
        "properties": { "conditionType": { "const": "handoff_reason_code_match" } }
      },
      "then": {
        "required": ["value"]
      }
    },
    {
      "if": {
        "properties": { "conditionType": { "const": "summary_keywords" } }
      },
      "then": {
        "required": ["keywords"]
      }
    },
    {
      "if": {
        "properties": { "conditionType": { "const": "pattern_match" } }
      },
      "then": {
        "required": ["pattern"]
      }
    }
  ]
}
```

### 5.3 Signal Generation

The `generatesSignal` property of signal rules appears to define how a signal is generated. A schema for this might look like:

```json
{
  "type": "object",
  "required": ["signalType"],
  "properties": {
    "signalType": {
      "type": "string",
      "description": "Type of signal to generate"
    },
    "signalTypeTemplate": {
      "type": "string",
      "description": "Template for generating signal type using captured groups"
    },
    "category": {
      "type": "string",
      "description": "Category of the signal"
    },
    "messageTemplate": {
      "type": "string",
      "description": "Template for generating signal message using captured groups"
    },
    "dataFromPattern": {
      "type": "object",
      "additionalProperties": {
        "type": "string"
      },
      "description": "Mapping of data fields to capture group names"
    }
  },
  "oneOf": [
    { "required": ["signalType"] },
    { "required": ["signalTypeTemplate"] }
  ]
}
```

## 6. Advanced Schema Features

### 6.1 Conditional Validation

JSON Schema supports conditional validation through keywords like `if`, `then`, `else`, `allOf`, `anyOf`, and `oneOf`. These can be used to implement complex validation rules, such as requiring different properties based on the value of another property.

For example, the signal rules schema uses conditional validation to require different properties based on the `conditionType`:

```json
"allOf": [
  {
    "if": {
      "properties": { "conditionType": { "const": "handoff_reason_code_match" } }
    },
    "then": {
      "required": ["value"]
    }
  },
  // Other conditions...
]
```

### 6.2 Custom Formats

JSON Schema allows defining custom formats for string validation. This can be useful for validating regular expressions, templates, and other string formats specific to the `.swarmConfig` file.

For example, we could define a custom format for regular expression patterns:

```json
"pattern": {
  "type": "string",
  "format": "regex",
  "description": "Regular expression pattern"
}
```

The validation library (e.g., Ajv) would need to be configured to support this custom format.

### 6.3 Default Values

JSON Schema allows specifying default values for properties. This can be useful for providing sensible defaults for optional properties:

```json
"defaultSignalStrength": {
  "type": "number",
  "minimum": 0,
  "maximum": 1,
  "default": 0.5,
  "description": "Default strength for signals"
}
```

## 7. Schema Documentation

### 7.1 Property Descriptions

Each property in the schema should have a clear description that explains its purpose and any constraints:

```json
"evaporationRate": {
  "type": "number",
  "minimum": 0,
  "maximum": 1,
  "description": "Rate at which signal strength decreases over time (0-1)"
}
```

### 7.2 Examples

Examples help users understand how to use the schema correctly. They can be added at various levels:

```json
"documentPattern": {
  "type": "object",
  "required": ["pattern", "docType"],
  "properties": { /* ... */ },
  "examples": [
    {
      "pattern": "Document saved to ['\"]?(?<filePath>[^'\"]+)['\"]?",
      "docType": "implementation_plan",
      "captureGroups": ["filePath"],
      "descriptionTemplate": "Implementation plan at ${filePath}"
    }
  ]
}
```

### 7.3 Enumeration Descriptions

For properties with enumerated values, each value should be documented:

```json
"conditionType": {
  "type": "string",
  "enum": ["handoff_reason_code_match", "summary_keywords", "pattern_match"],
  "description": "Type of condition that triggers this rule",
  "enumDescriptions": {
    "handoff_reason_code_match": "Matches the handoff_reason_code from the orchestrator",
    "summary_keywords": "Matches keywords in the summary text",
    "pattern_match": "Matches a regular expression pattern in the summary text"
  }
}
```

## 8. Schema Validation and Testing

### 8.1 Validation Approach

The JSON Schema should be validated against existing `.swarmConfig` files to ensure it correctly represents the expected structure. This validation should be done both manually and automatically:

1. **Manual Validation**: Review the schema against known valid `.swarmConfig` files to ensure it captures all required properties and constraints.
2. **Automated Validation**: Write tests that validate known valid and invalid `.swarmConfig` files against the schema.

### 8.2 Test Cases

Test cases should cover a range of scenarios:

- **Valid Configurations**: Various valid `.swarmConfig` files with different combinations of properties.
- **Missing Required Properties**: Configurations missing required properties at various levels.
- **Invalid Property Types**: Properties with incorrect types (e.g., string instead of number).
- **Out-of-Range Values**: Numeric properties with values outside the allowed range.
- **Invalid Combinations**: Combinations of properties that violate conditional validation rules.

### 8.3 Schema Evolution

As the `.swarmConfig` format evolves, the schema will need to be updated. A versioning strategy should be established:

1. **Schema Versioning**: Include a version number in the schema.
2. **Backward Compatibility**: Ensure new versions of the schema validate old `.swarmConfig` files.
3. **Migration Path**: Provide guidance for migrating from old to new formats.

## 9. Implementation in the UI

### 9.1 Client-Side Validation

The JSON Schema will be used for client-side validation in the UI:

```javascript
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import schema from './swarmConfig.schema.json';

const ajv = new Ajv({ allErrors: true });
addFormats(ajv);

// Add custom formats if needed
ajv.addFormat('regex', {
  type: 'string',
  validate: (str) => {
    try {
      new RegExp(str);
      return true;
    } catch (e) {
      return false;
    }
  }
});

const validate = ajv.compile(schema);

function validateConfig(config) {
  const valid = validate(config);
  if (!valid) {
    return {
      valid: false,
      errors: validate.errors
    };
  }
  return { valid: true };
}
```

### 9.2 Error Reporting

Validation errors should be reported in a user-friendly way:

```javascript
function formatValidationErrors(errors) {
  return errors.map(error => {
    const path = error.instancePath || '';
    const property = error.params.missingProperty || '';
    const fullPath = path + (property ? `/${property}` : '');
    
    switch (error.keyword) {
      case 'required':
        return `Missing required property: ${fullPath}`;
      case 'type':
        return `Invalid type at ${fullPath}: expected ${error.params.type}`;
      case 'enum':
        return `Invalid value at ${fullPath}: must be one of ${error.params.allowedValues.join(', ')}`;
      // Handle other error types...
      default:
        return `Validation error at ${fullPath}: ${error.message}`;
    }
  });
}
```

### 9.3 Form Generation

The JSON Schema can also be used to generate form elements for editing the `.swarmConfig` file:

```javascript
function generateFormForSchema(schema, path = '') {
  if (schema.type === 'object') {
    return Object.entries(schema.properties).map(([key, prop]) => {
      const fieldPath = path ? `${path}.${key}` : key;
      return generateFormField(key, prop, fieldPath, schema.required?.includes(key));
    });
  }
  // Handle other schema types...
}

function generateFormField(key, schema, path, required) {
  switch (schema.type) {
    case 'string':
      if (schema.enum) {
        return <SelectField name={path} label={key} options={schema.enum} required={required} />;
      }
      return <TextField name={path} label={key} required={required} />;
    case 'number':
      return <NumberField name={path} label={key} min={schema.minimum} max={schema.maximum} required={required} />;
    case 'boolean':
      return <Checkbox name={path} label={key} />;
    case 'array':
      return <ArrayField name={path} label={key} itemSchema={schema.items} required={required} />;
    case 'object':
      return <ObjectField name={path} label={key} schema={schema} required={required} />;
    default:
      return null;
  }
}
```

## 10. Conclusion

Developing a comprehensive JSON Schema for the `.swarmConfig` file is a critical component of the Advanced `.swarmConfig` Tuning & Validation UI. The schema will serve multiple purposes:

1. **Validation**: Ensuring that the configuration file conforms to the expected structure and constraints.
2. **Documentation**: Providing clear documentation of the configuration format.
3. **UI Generation**: Potentially driving the generation of form elements for editing the configuration.

By following the approach outlined in this document, we can develop a robust, well-documented schema that meets these needs and provides a solid foundation for the UI.

The schema development should be an iterative process, starting with the basic structure and gradually adding more detailed validation rules and documentation. Regular testing against real `.swarmConfig` files will ensure that the schema accurately represents the expected format.