Core Template Structure
Task Plan Header
text
PROJECT: [Project Name]
PRD SOURCE: [Path to PRD file]
TOTAL ESTIMATED TOKENS: [X]/128,000
CREATED: [Date]
LAST UPDATED: [Date]
CONTEXT BUDGET ALLOCATION:
- Task Instructions: [X]% ([X] tokens)
- Code Context: [X]% ([X] tokens)  
- Documentation: [X]% ([X] tokens)
- Dependencies: [X]% ([X] tokens)
- Output Buffer: [X]% ([X] tokens)
Token Management Framework
Priority-Based Token Allocation:

Task Definition & Instructions (25% - ~32k tokens)

Core task requirements

Acceptance criteria

Implementation guidelines

Essential Code Context (40% - ~51k tokens)

Relevant source files

API definitions

Configuration files

Dependency Information (15% - ~19k tokens)

Related tasks

External dependencies

Interface requirements

Documentation Context (10% - ~13k tokens)

Relevant documentation

Code comments

Architecture notes

Output Buffer (10% - ~13k tokens)

Reserved for AI response

Error handling

Iterations

Task Definition Template
text
TASK ID: T-[XXX]
TITLE: [Concise task title]
ESTIMATED TOKENS: [X]/128,000
DEPENDENCIES: [List of task IDs this depends on]
BLOCKS: [List of task IDs this blocks]
PRIORITY: [High/Medium/Low]
COMPLEXITY: [Simple/Moderate/Complex]
ESTIMATED TIME: [X hours]

## CONTEXT MANAGEMENT STRATEGY
Token Budget Breakdown:
- Instructions: [X] tokens
- Code Context: [X] tokens
- Dependencies: [X] tokens
- Output: [X] tokens
- Buffer: [X] tokens

Context Prioritization:
1. [Most critical context elements]
2. [Secondary context elements]
3. [Optional context elements]

Token Overflow Strategy:
- If exceeding budget: [Specific truncation rules]
- Critical context to preserve: [List]
- Context that can be summarized: [List]
- Context that can be omitted: [List]

## TASK SPECIFICATION
### Objective
[Clear, specific objective in 1-2 sentences]

### Acceptance Criteria
- [ ] [Specific, testable criterion 1]
- [ ] [Specific, testable criterion 2]
- [ ] [Specific, testable criterion 3]

### Context Required
#### Code Files (Token Budget: [X])
- File: [path/to/file.ext] - [estimated tokens] - [why needed]
- File: [path/to/file.ext] - [estimated tokens] - [why needed]

#### Documentation (Token Budget: [X])
- Doc: docs/goodcodeguide.md - [estimated tokens] - Comprehensive code quality standards (readability, SOLID, DRY/KISS/YAGNI, function/file sizes, complexity metrics)
- Doc: docs/goodtestsguide.md - [estimated tokens] - Complete testing standards (FIRST principles, testing pyramid, test types, quality metrics)
- Doc: docs/restructure.md - [estimated tokens] - Architecture guardrails and restructuring patterns
- Doc: [additional docs] - [estimated tokens] - [specific sections needed]

#### Dependencies (Token Budget: [X])
- Must complete: [Task IDs]
- Interfaces from: [Task IDs]
- Data from: [Task IDs]

### Implementation Guidelines

#### Core Code Quality Standards
Embed guardrails for every task based on proven quality principles:

**Readability and Maintainability:**
- Enforce meaningful naming conventions that clearly describe purpose without requiring comments
- Apply consistent formatting and indentation following established style guides
- Write self-documenting code where structure and naming tell the story
- Avoid deep nesting (max 3-4 levels) to maintain comprehension
- Separate intention from implementation through well-named functions

**Design Principles (SOLID + Supporting Patterns):**
- **Single Responsibility Principle**: Each function/class/module has only one reason to change
- **Open-Closed Principle**: Open for extension, closed for modification
- **Liskov Substitution**: Subtypes must be substitutable for base types
- **Interface Segregation**: Many specific interfaces over one general-purpose
- **Dependency Inversion**: Depend on abstractions, not concretions
- **DRY**: Eliminate code duplication through abstraction and reuse
- **KISS**: Favor simple solutions over complex ones
- **YAGNI**: Don't build features until they're actually needed

**Size and Complexity Constraints:**
- **Functions**: Target 20-50 lines (industry consensus), flag >50 lines for review
  - Martin Fowler approach: Consider refactoring any function >6 lines
  - Complex algorithms exception: May extend to 100-200 lines with justification
- **Files**: Keep under 500 lines with 2-10 cohesive functions
  - Average successful project files: 20-50 lines (Uncle Bob's analysis)
  - Refactor proactively to minimize cognitive load
- **Cyclomatic Complexity**:
  - Maintain ≤10 for normal code (considered maintainable)
  - 11-20: Requires documented refactor plan
  - >20: Block unless mitigation approved
  - >50: Considered untestable, must be refactored

**Performance and Optimization:**
- Profile before optimizing - use benchmarking to identify actual bottlenecks
- Choose appropriate data structures based on usage patterns
- Avoid premature optimization - focus on algorithms first
- Implement smart caching for frequently used data
- Document performance requirements and constraints

**Security Requirements:**
- **Input Validation**: Validate all data from untrusted sources
- **Output Encoding**: Properly encode all output to prevent injection
- **Least Privilege**: Grant minimum necessary permissions
- **Secure Frameworks**: Use libraries with built-in security features
- **AI Code Review**: Require human-in-the-loop for AI-generated code
- Never log or expose secrets and keys

**Error Handling Excellence:**
- Provide informative, actionable error messages
- Avoid silent failures - log or handle every exception
- Distinguish recoverable from unrecoverable errors
- Implement graceful degradation where possible
- Define error handling architecture (centralized vs distributed)

### Testing Strategy Blueprint

#### FIRST Principles Foundation
Every test must satisfy the FIRST framework:
- **Fast**: Unit tests in milliseconds, integration tests in seconds-minutes
- **Independent**: Standalone execution without order dependencies
- **Repeatable**: Consistent results across environments (eliminate flaky tests)
- **Self-Validating**: Unambiguous pass/fail with proper assertions
- **Timely**: Written with or before code (shift-left approach)

#### Testing Pyramid Distribution
**Optimal layer distribution for balanced coverage:**
- **Unit Tests (70-80%)**:
  - Foundation with numerous fast, isolated tests
  - Target 80-90% code coverage for critical paths
  - Use AAA pattern (Arrange-Act-Assert)
  - Proper mock/stub/spy usage for isolation
  - Single responsibility per test
- **Integration Tests (15-20%)**:
  - Validate component interactions and data flow
  - Test actual database interactions
  - Contract verification for APIs
  - Use test doubles for unreliable dependencies
- **E2E Tests (5-10%)**:
  - Minimal suite covering critical user journeys
  - Focus on essential business functions
  - Cross-browser/platform compatibility
  - Robust selectors to reduce brittleness

#### Quality Standards by Test Type

**Unit Test Excellence:**
- Isolation without external dependencies
- Millisecond execution time
- Clear naming describing functionality
- Deterministic test data
- High code coverage without targeting 100%

**Integration Test Quality:**
- Proper dependency management
- Contract and schema validation
- Realistic test environments mirroring production
- Data flow validation between components
- Backward compatibility verification

**E2E Test Requirements:**
- Real user scenario simulation
- Critical path prioritization
- Clear test data management
- Minimal maintenance overhead
- Stable element identifiers

**API Contract Testing:**
- Clear request/response specifications
- All endpoint and method coverage
- Error handling validation
- Consumer-provider alignment
- Schema validation

#### Test Data Management
- **Data Masking**: Protect sensitive information while maintaining realism
- **Synthetic Generation**: Create realistic scenarios when production data unavailable
- **Version Control**: Track and manage test data versions
- **Automated Refresh**: Keep test data current and relevant
- **Environment Consistency**: Ensure uniform data across environments
- **Subset Sampling**: Use representative samples for efficiency

#### CI/CD Integration
- **Automated Builds**: Self-testing builds with validation
- **Fast Feedback**: Quick execution for frequent commits
- **Quality Gates**: Automated checks preventing poor code advancement
- **Pipeline Stages**: Map appropriate tests to each stage
- **Failure Management**: Immediate attention to broken builds
- **Comprehensive Suites**: Multiple test types at appropriate stages

#### Quality Metrics and Tracking
**Product Metrics:**
- Defect density (bugs per unit)
- Test coverage (code and requirements)
- Defect removal efficiency
- Mean time to detect issues

**Process Metrics:**
- Test case effectiveness
- Automation coverage percentage
- Test execution progress
- Cost of quality and ROI

**Performance Testing:**
- Response time metrics (average, peak, minimum)
- Throughput (requests/second, data transfer)
- Error rates under load
- Resource utilization (CPU, memory, network)
- Endurance and recovery testing

#### Security Testing Requirements
- Comprehensive vulnerability scanning
- Threat modeling against realistic scenarios
- Compliance verification
- False positive management
- Vulnerability discovery rate tracking

#### Accessibility Testing
- WCAG Level AA conformance
- POUR principles compliance
- Automated and manual testing combination
- Assistive technology compatibility
- User feedback integration

#### Documentation and Traceability
- Clear test objectives and rationale
- Requirements traceability matrix
- Regular documentation updates
- Risk-based testing approach
- Demo artifacts and evidence collection

### Token Management Rules
#### Context Inclusion Strategy:
1. Always include: [List of mandatory context]
2. Include if space allows: [List of helpful context]
3. Exclude: [List of unnecessary context]

#### Context Compression Techniques:
- Summarize: [What can be summarized vs. included verbatim]
- Reference: [What can be referenced by ID/path vs. included]
- Abstract: [What can be described vs. copied]

#### Overflow Handling:
If token limit approached:
1. First remove: [Least critical context]
2. Then compress: [Context that can be summarized]
3. Finally truncate: [Context that can be partially included]

### Quality Assurance Checklist

#### Code Quality Verification
- [ ] **Readability**: Meaningful naming, consistent formatting, self-documenting structure
- [ ] **Nesting**: Maximum 3-4 levels of nesting, refactored for clarity
- [ ] **Function Size**: 20-50 lines standard, >50 lines flagged with justification
- [ ] **File Size**: <500 lines with 2-10 cohesive functions
- [ ] **Cyclomatic Complexity**: ≤10 standard, 11-20 with refactor plan, >20 blocked
- [ ] **Design Principles**: SOLID, DRY, KISS, YAGNI properly applied
- [ ] **Dependencies**: Proper abstraction and dependency inversion implemented
- [ ] **Code Duplication**: Eliminated through appropriate abstractions

#### Testing Verification
- [ ] **FIRST Compliance**: All tests are Fast, Independent, Repeatable, Self-validating, Timely
- [ ] **Testing Pyramid**: 70-80% unit, 15-20% integration, 5-10% E2E distribution
- [ ] **Coverage Targets**: 80-90% for critical paths, risk-based coverage strategy
- [ ] **Test Isolation**: Proper mocking and dependency management
- [ ] **Contract Testing**: API contracts validated with schema verification
- [ ] **E2E Scope**: Limited to critical user journeys with stable selectors
- [ ] **Flaky Test Mitigation**: All non-deterministic tests eliminated or fixed
- [ ] **Test Data Strategy**: Masking, synthetic generation, version control defined
- [ ] **CI Integration**: Tests mapped to appropriate pipeline stages with quality gates

#### Security & Performance
- [ ] **Input Validation**: All untrusted data sources validated
- [ ] **Output Encoding**: Proper encoding prevents injection attacks
- [ ] **Least Privilege**: Minimum necessary permissions granted
- [ ] **Secrets Management**: No exposed or logged secrets/keys
- [ ] **AI Code Review**: Human-in-the-loop validation for AI-generated code
- [ ] **Performance Profiling**: Benchmarking before optimization
- [ ] **Caching Strategy**: Smart caching for frequently used data
- [ ] **Data Structure Choice**: Appropriate structures for usage patterns

#### Error Handling & Observability
- [ ] **Error Messages**: Informative and actionable for users/developers
- [ ] **No Silent Failures**: Every exception logged or handled
- [ ] **Error Classification**: Recoverable vs unrecoverable errors distinguished
- [ ] **Graceful Degradation**: Fallback functionality where appropriate
- [ ] **Telemetry**: Comprehensive logging and monitoring implemented
- [ ] **Audit Trails**: Critical operations tracked for compliance

#### Documentation & Maintenance
- [ ] **Code Documentation**: Clear comments for complex logic
- [ ] **API Documentation**: Complete interface specifications
- [ ] **Architecture Docs**: System design and component relationships documented
- [ ] **Test Documentation**: Clear objectives and traceability to requirements
- [ ] **Runbooks**: Operational procedures documented
- [ ] **Version Control**: Proper commit messages and change tracking
- [ ] **Knowledge Transfer**: Sufficient documentation for team onboarding

### Output Specification
Expected deliverables:
- [ ] [Specific file/component 1]
- [ ] [Specific file/component 2]
- [ ] [Tests for implementation]
- [ ] [Documentation updates]

Token allocation for response:
- Code: [X] tokens
- Tests: [X] tokens  
- Documentation: [X] tokens
- Explanations: [X] tokens
Dependency Management System
Dependency Types
text
DEPENDENCY_TYPE: 
- SEQUENTIAL: Task B cannot start until Task A completes
- PARALLEL: Tasks can run simultaneously
- RESOURCE: Tasks share common resources/files
- INTERFACE: Task B needs outputs from Task A
- KNOWLEDGE: Task B needs knowledge gained from Task A

DEPENDENCY_RELATIONSHIP:
- BLOCKS: [Task IDs this task blocks]
- BLOCKED_BY: [Task IDs blocking this task]
- SHARES_RESOURCES: [Task IDs sharing resources]
- PROVIDES_INTERFACE: [What this task provides to others]
- REQUIRES_INTERFACE: [What this task needs from others]
Critical Path Analysis
text
CRITICAL_PATH_ANALYSIS:
- Is on critical path: [Yes/No]
- Slack time: [X hours]
- Impact of delay: [Description]
- Mitigation strategies: [List]
Context Engineering Framework
Context Window Strategy for 128k Tokens
text
CONTEXT_WINDOW_MANAGEMENT:
Total Budget: 128,000 tokens

Reserved Allocations:
- System Instructions: 2,000 tokens (1.5%)
- Task Definition: 8,000 tokens (6.25%)
- Critical Dependencies: 12,000 tokens (9.4%)
- Core Code Context: 50,000 tokens (39%)
- Documentation: 15,000 tokens (11.7%)
- Test Context: 10,000 tokens (7.8%)
- Output Buffer: 20,000 tokens (15.6%)
- Safety Buffer: 11,000 tokens (8.6%)

Dynamic Allocation Rules:
1. If task is simple: Reduce code context, increase output buffer
2. If task is complex: Increase code context, reduce documentation
3. If dependencies are heavy: Increase dependency allocation
4. Always preserve minimum output buffer of 15,000 tokens
Context Prioritization Matrix
text
CONTEXT_PRIORITY_MATRIX:
Priority 1 (Always Include):
- Task definition and acceptance criteria
- Direct code files being modified
- Immediate dependencies
- Critical error handling patterns

Priority 2 (Include if Space):
- Related code files for reference
- Comprehensive documentation
- Extended dependencies
- Design patterns and examples

Priority 3 (Include Only if Extra Space):
- Historical context
- Peripheral documentation  
- Nice-to-have examples
- Tangential code files

Priority 4 (Omit if Necessary):
- Deprecated patterns
- Unrelated code
- Verbose comments
- Redundant documentation
Task Breakdown Rules
Microtask Principles
text
MICROTASK_CRITERIA:
- Single responsibility: One clear objective
- Token bounded: Must fit within 128k limit with buffer
- Time bounded: 2-6 hours of work maximum
- Testable: Clear success/failure criteria
- Independent: Minimal external dependencies
- Atomic: Complete unit of work

BREAKDOWN_STRATEGY:
1. Identify core functionality
2. Separate interface design from implementation  
3. Split complex algorithms into discrete steps
4. Isolate testing and documentation tasks
5. Create separate tasks for integration points
Task Sizing Guidelines
text
TASK_COMPLEXITY_LEVELS:

SIMPLE (20k-40k tokens):
- Single file modifications
- Straightforward implementations
- Minimal dependencies
- Clear patterns to follow

MODERATE (40k-80k tokens):
- Multi-file changes
- New component creation
- Some external dependencies
- Requires design decisions

COMPLEX (80k-120k tokens):
- System-wide changes
- New architecture components
- Heavy dependencies
- Research/exploration needed

NEVER EXCEED 120k tokens for task definition
Reserve minimum 8k tokens for response buffer
Implementation Workflow
Phase 1: Analysis and Planning
Parse PRD into high-level objectives

Identify major components and interfaces

Create dependency graph

Estimate token requirements per task

Validate 128k compliance for each task

Phase 2: Task Creation
Apply task template to each component

Define context management strategy

Establish dependency relationships

Validate token budgets

Create execution order

Phase 3: Validation and Optimization
Check for token budget violations

Optimize context inclusion strategies

Validate dependency completeness

Test critical path analysis

Refine task boundaries

Ensure all types are defined, request, response, database, component types etc.

Quality Control Framework
Token Budget Validation
text
VALIDATION_CHECKLIST:
- [ ] Total context < 120k tokens (leaving 8k buffer)
- [ ] Critical context always included
- [ ] Context prioritization defined
- [ ] Overflow strategy specified
- [ ] Dependencies properly allocated tokens
- [ ] Output buffer reserved
- [ ] Compression strategies defined
Dependency Validation
text
DEPENDENCY_CHECKLIST:
- [ ] All dependencies identified
- [ ] Dependency types specified
- [ ] Critical path calculated
- [ ] Resource conflicts resolved
- [ ] Interface requirements defined
- [ ] Execution order validated

## Code Architecture Requirements
### Architecture Definition
text
ARCHITECTURE_SPECIFICATION:
- System Organization: [High-level system structure and component relationships]
- Module Layout: [Directory structure and file organization patterns]
- Design Patterns: [Architectural patterns to follow (MVC, Hexagonal, etc.)]
- Component Hierarchy: [How components are layered and interact]
- Data Flow: [How data moves through the system]
- Interface Design: [API boundaries and communication protocols]

LAYOUT_STRUCTURE:
- Package/Module Organization:
  - Core modules: [Purpose and boundaries]
  - Feature modules: [Grouping and isolation strategies]
  - Shared modules: [Common utilities and services]
  - Configuration: [Settings and environment management]
- File Naming Conventions: [Consistent naming patterns]
- Import/Export Patterns: [How modules expose and consume functionality]
- Directory Structure: [Physical organization of code files]

### Architecture Documentation Requirements
text
ARCHITECTURE_DOCUMENTATION:
- [ ] System architecture diagram or description
- [ ] Component interaction flow
- [ ] Directory structure rationale
- [ ] Module responsibility boundaries
- [ ] Integration patterns and interfaces
- [ ] Scalability and extensibility considerations
- [ ] Technology stack justification

IMPLEMENTATION_GUIDELINES:
- Separation of Concerns: [How different responsibilities are isolated]
- Dependency Management: [How dependencies flow through the system]
- Error Handling Architecture: [Centralized vs distributed error handling]
- Testing Architecture: [Unit, integration, and system test organization]
- Configuration Management: [How settings and environment variables are handled]
- Logging and Monitoring: [Observability architecture]

### Architecture Validation Checklist
text
ARCHITECTURE_CHECKLIST:
- [ ] System organization clearly defined
- [ ] Module boundaries and responsibilities specified
- [ ] Directory structure follows established patterns
- [ ] Component interfaces well-defined
- [ ] Data flow architecture documented
- [ ] Technology choices justified
- [ ] Scalability considerations addressed
- [ ] Testing strategy aligns with architecture
- [ ] Error handling patterns consistent
- [ ] Configuration management strategy defined