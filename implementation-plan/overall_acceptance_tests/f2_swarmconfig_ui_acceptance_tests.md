# F2: Advanced `.swarmConfig` Tuning & Validation UI - Acceptance Tests

This document defines the high-level acceptance tests for the Advanced `.swarmConfig` Tuning & Validation UI (F2) of the Pheromind Enhancements Suite. These tests represent the ultimate success criteria for this feature, focusing on end-to-end functionality and user experience.

## 1. File Operations Tests

### Test F2-FILE-01: Loading `.swarmConfig` Files

**Objective**: Verify that the application can load `.swarmConfig` files from the local file system.

**Preconditions**:
- Application is running in a browser
- Valid `.swarmConfig` file is available on the local file system

**Test Steps**:
1. Open the application in a browser
2. Click the "Load .swarmConfig" button
3. Select a valid `.swarmConfig` file using the browser's file dialog
4. Observe the application's response

**Expected Results**:
- File dialog opens and allows selection of a file
- Selected file is read and parsed correctly
- File content is displayed in the raw JSON editor
- No errors occur during loading

**Acceptance Criteria**:
- Valid `.swarmConfig` files can be loaded successfully
- File content is displayed correctly and completely
- UI provides feedback during the loading process

### Test F2-FILE-02: Saving `.swarmConfig` Files

**Objective**: Verify that the application can save modified `.swarmConfig` files to the local file system.

**Preconditions**:
- Application is running with a loaded `.swarmConfig` file
- Changes have been made to the file content

**Test Steps**:
1. Click the "Save/Download .swarmConfig" button
2. Observe the browser's download behavior
3. Examine the downloaded file

**Expected Results**:
- Browser initiates a download of the file
- Downloaded file contains the modified content
- File is properly formatted as valid JSON

**Acceptance Criteria**:
- Modified content is saved correctly
- Downloaded file is valid JSON
- File name is appropriate (e.g., ".swarmConfig")

### Test F2-FILE-03: Error Handling for File Operations

**Objective**: Verify that the application handles file operation errors gracefully.

**Preconditions**:
- Application is running in a browser

**Test Steps**:
1. Attempt to load an invalid file (e.g., non-JSON file, empty file)
2. Attempt to load a file that is too large (if applicable)
3. Attempt to save when no file is loaded

**Expected Results**:
- Application displays appropriate error messages
- Application remains stable and usable
- No data loss occurs

**Acceptance Criteria**:
- All error conditions are handled gracefully
- Error messages are clear and helpful
- Application recovers from errors without requiring a refresh

## 2. JSON Editing Tests

### Test F2-EDIT-01: Raw JSON Editing

**Objective**: Verify that the application provides a functional raw JSON editor.

**Preconditions**:
- Application is running with a loaded `.swarmConfig` file

**Test Steps**:
1. Make various edits to the JSON content in the raw editor:
   - Add a new property
   - Modify an existing property
   - Delete a property
2. Observe the editor behavior and application response

**Expected Results**:
- Editor provides syntax highlighting
- Editor allows all types of edits
- Changes are reflected in the application's internal state
- Syntax errors are highlighted or indicated

**Acceptance Criteria**:
- All edits are possible and preserved
- Editor provides a good user experience (highlighting, indentation, etc.)
- Editor handles large JSON documents without performance issues

### Test F2-EDIT-02: JSON Syntax Validation

**Objective**: Verify that the application validates JSON syntax and provides feedback.

**Preconditions**:
- Application is running with a loaded `.swarmConfig` file

**Test Steps**:
1. Introduce a syntax error in the JSON (e.g., missing comma, unbalanced brackets)
2. Observe the application's response
3. Correct the error
4. Observe the application's response

**Expected Results**:
- Application detects the syntax error
- Error is highlighted or indicated in the editor
- Clear error message is displayed
- When error is corrected, error indication is removed

**Acceptance Criteria**:
- All syntax errors are detected and reported
- Error messages are clear and helpful
- Error locations are accurately indicated
- UI recovers when errors are corrected

## 3. Schema Validation Tests

### Test F2-SCHEMA-01: JSON Schema Validation

**Objective**: Verify that the application validates `.swarmConfig` files against the defined JSON Schema.

**Preconditions**:
- Application is running with a loaded `.swarmConfig` file

**Test Steps**:
1. Click the "Validate" button (if available) or trigger validation
2. Observe the validation results for a valid file
3. Modify the file to violate the schema (e.g., wrong property type, missing required property)
4. Trigger validation again
5. Observe the validation results for an invalid file

**Expected Results**:
- Valid files pass validation with a success message
- Invalid files fail validation with specific error messages
- Error messages indicate the location and nature of the schema violations
- Validation is performed against the complete schema

**Acceptance Criteria**:
- Schema validation correctly identifies valid and invalid files
- Error messages are clear, specific, and helpful
- Validation covers all aspects of the schema
- UI clearly indicates validation status

### Test F2-SCHEMA-02: Validation of Complex Schema Rules

**Objective**: Verify that the application correctly validates complex schema rules, such as conditional properties and dependencies.

**Preconditions**:
- Application is running with a loaded `.swarmConfig` file

**Test Steps**:
1. Modify the file to test complex schema rules:
   - Conditional properties based on `conditionType` in signal rules
   - Required properties based on other property values
   - Pattern properties (regex patterns)
2. Trigger validation
3. Observe the validation results

**Expected Results**:
- Complex schema rules are correctly evaluated
- Violations of complex rules are detected and reported
- Error messages accurately describe the complex rule violations

**Acceptance Criteria**:
- All complex schema rules are correctly validated
- Error messages for complex rules are understandable
- Validation is thorough and accurate

## 4. UI Functionality Tests

### Test F2-UI-01: UI Layout and Navigation

**Objective**: Verify that the application provides an intuitive and functional user interface.

**Preconditions**:
- Application is running in a browser

**Test Steps**:
1. Observe the initial layout and organization of the UI
2. Navigate between different sections or tabs (if applicable)
3. Resize the browser window to test responsiveness

**Expected Results**:
- UI is well-organized and intuitive
- Navigation between sections is clear and functional
- UI adapts appropriately to different window sizes

**Acceptance Criteria**:
- UI follows good design practices
- Navigation is intuitive and consistent
- UI is usable on different screen sizes

### Test F2-UI-02: Validation Result Display

**Objective**: Verify that validation results are displayed clearly and helpfully.

**Preconditions**:
- Application is running with a loaded `.swarmConfig` file that has validation errors

**Test Steps**:
1. Trigger validation
2. Observe the display of validation errors
3. Navigate to or select an error from the error list (if applicable)
4. Observe any highlighting or navigation to the error location

**Expected Results**:
- Validation errors are displayed in a clear, organized manner
- Error messages are specific and helpful
- UI provides a way to navigate to or highlight error locations
- Error display does not obscure the editor or other important UI elements

**Acceptance Criteria**:
- Error display is clear and helpful
- Error navigation (if implemented) works correctly
- Error display is well-integrated with the rest of the UI

## 5. Performance Tests

### Test F2-PERF-01: Large File Handling

**Objective**: Verify that the application can handle large `.swarmConfig` files efficiently.

**Preconditions**:
- Application is running in a browser
- Large `.swarmConfig` file is available (e.g., with many rules and patterns)

**Test Steps**:
1. Load the large `.swarmConfig` file
2. Edit various parts of the file
3. Validate the file
4. Save the file

**Expected Results**:
- File loads without excessive delay
- Editing remains responsive
- Validation completes in a reasonable time
- Saving works correctly for large files

**Acceptance Criteria**:
- Application handles reasonably large files without performance issues
- UI remains responsive with large files
- No memory-related issues occur with large files

### Test F2-PERF-02: Validation Performance

**Objective**: Verify that schema validation performs efficiently, even with complex schemas and large files.

**Preconditions**:
- Application is running with a loaded large `.swarmConfig` file

**Test Steps**:
1. Trigger validation
2. Observe the validation time and application responsiveness during validation
3. Make changes that affect many validation rules
4. Trigger validation again

**Expected Results**:
- Validation completes in a reasonable time
- UI remains responsive during validation
- Validation time scales reasonably with file size and complexity

**Acceptance Criteria**:
- Validation is efficient and does not cause UI freezing
- Validation time is reasonable for typical file sizes
- Application provides feedback during lengthy validations

## 6. Browser Compatibility Tests

### Test F2-COMPAT-01: Cross-Browser Compatibility

**Objective**: Verify that the application works correctly across different modern browsers.

**Preconditions**:
- Application is deployed and accessible

**Test Steps**:
1. Open the application in different browsers (Chrome, Firefox, Edge, Safari)
2. Perform basic operations in each browser:
   - Load a file
   - Edit the file
   - Validate the file
   - Save the file

**Expected Results**:
- Application functions correctly in all tested browsers
- UI appears consistent across browsers
- No browser-specific errors or issues occur

**Acceptance Criteria**:
- Application works in all major modern browsers
- User experience is consistent across browsers
- No critical functionality is browser-dependent

## 7. JSON Schema Tests

### Test F2-SCHEMA-03: Schema Completeness

**Objective**: Verify that the JSON Schema for `.swarmConfig` is complete and accurately represents the expected structure.

**Preconditions**:
- Application is running with the JSON Schema loaded

**Test Steps**:
1. Review the schema definition for completeness
2. Test validation against various valid `.swarmConfig` files with different features
3. Verify that all required sections are defined:
   - `pheromoneDynamics`
   - `scribeSettings`
   - `interpretationLogic` (including `documentPatterns` and `signalRules`)
   - `generalSettings`

**Expected Results**:
- Schema includes all required sections and properties
- Valid files with different features all pass validation
- Schema accurately represents the expected structure

**Acceptance Criteria**:
- Schema is complete and accurate
- Schema handles all valid variations of `.swarmConfig` files
- Schema documentation (if available) is clear and helpful