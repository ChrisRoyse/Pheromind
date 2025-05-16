/**
 * JSON Schema for .swarmConfig file
 */
const swarmConfigSchema = {
  type: "object",
  required: ["pheromoneDynamics", "scribeSettings", "generalSettings"],
  properties: {
    pheromoneDynamics: {
      type: "object",
      required: ["evaporationRate"],
      properties: {
        evaporationRate: {
          type: "number",
          minimum: 0,
          maximum: 1,
          description: "Rate at which signals evaporate over time (0-1)"
        },
        amplificationRules: {
          type: "array",
          items: {
            type: "object",
            required: ["condition", "amplificationFactor"],
            properties: {
              condition: {
                type: "string",
                description: "Condition for signal amplification"
              },
              amplificationFactor: {
                type: "number",
                minimum: 1,
                description: "Factor by which to amplify signal strength"
              }
            }
          }
        }
      }
    },
    scribeSettings: {
      type: "object",
      required: ["defaultSignalStrength", "interpretationLogic"],
      properties: {
        defaultSignalStrength: {
          type: "number",
          minimum: 0,
          maximum: 1,
          description: "Default strength for new signals (0-1)"
        },
        signalTypes: {
          type: "array",
          items: {
            type: "string"
          },
          description: "List of valid signal types"
        },
        categories: {
          type: "array",
          items: {
            type: "string"
          },
          description: "List of valid categories"
        },
        interpretationLogic: {
          type: "object",
          required: ["documentPatterns", "signalRules"],
          properties: {
            documentPatterns: {
              type: "array",
              items: {
                type: "object",
                required: ["pattern", "type"],
                properties: {
                  pattern: {
                    type: "string",
                    description: "Regex pattern to match document paths"
                  },
                  type: {
                    type: "string",
                    description: "Type of document to assign when pattern matches"
                  },
                  priority: {
                    type: "integer",
                    minimum: 0,
                    description: "Priority of this pattern (higher numbers take precedence)"
                  }
                }
              }
            },
            signalRules: {
              type: "array",
              items: {
                type: "object",
                required: ["conditionType", "signalType"],
                properties: {
                  conditionType: {
                    type: "string",
                    enum: ["contains", "regex", "handoff_reason"],
                    description: "Type of condition for this rule"
                  },
                  condition: {
                    type: "string",
                    description: "The condition to match (text or regex pattern)"
                  },
                  signalType: {
                    type: "string",
                    description: "Type of signal to generate when condition matches"
                  },
                  target: {
                    type: "string",
                    description: "Target to assign to the signal"
                  },
                  category: {
                    type: "string",
                    description: "Category to assign to the signal"
                  },
                  strength: {
                    type: "number",
                    minimum: 0,
                    maximum: 1,
                    description: "Strength to assign to the signal (0-1)"
                  },
                  priority: {
                    type: "integer",
                    minimum: 0,
                    description: "Priority of this rule (higher numbers take precedence)"
                  }
                }
              }
            }
          }
        }
      }
    },
    generalSettings: {
      type: "object",
      properties: {
        projectName: {
          type: "string",
          description: "Name of the project"
        },
        version: {
          type: "string",
          description: "Version of the configuration"
        },
        description: {
          type: "string",
          description: "Description of the configuration"
        }
      }
    }
  }
};

export default swarmConfigSchema;