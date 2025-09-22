# AI Coding Agent - Architectural Decision Record Template

## ADR Metadata
- **ADR ID**: ADR-[AUTO-GENERATED-NUMBER]
- **Agent ID**: [AGENT_IDENTIFIER]  
- **Task ID**: [TASK_REFERENCE_ID]
- **Date**: [TIMESTAMP]
- **Duration**: [TASK_EXECUTION_TIME]
- **Status**: [Proposed | Accepted | Implemented | Superseded | Deprecated]
- **AI Model/Version**: [MODEL_USED]
- **Confidence Level**: [High | Medium | Low] - Agent's confidence in this decision

## Executive Summary
**One-sentence decision summary**: [Brief statement of what was decided and why]

## Context & Problem Statement
### Problem Description
[Detailed description of the problem or requirement that triggered this architectural decision]

### Constraints & Requirements
- **Functional Requirements**: [What the system must do]
- **Non-Functional Requirements**: [Performance, security, scalability, etc.]
- **Technical Constraints**: [Existing technology stack, budget, timeline]
- **Business Constraints**: [Organizational, regulatory, compliance requirements]

### Triggering Event
[What specific event, request, or discovery prompted this architectural decision]

## Decision Drivers & Criteria
### Primary Decision Factors
1. [Factor 1 - e.g., Performance requirements]
2. [Factor 2 - e.g., Maintainability]  
3. [Factor 3 - e.g., Cost considerations]
4. [Factor 4 - e.g., Security requirements]

### Evaluation Criteria & Weights
| Criteria | Weight (1-10) | Description |
|----------|---------------|-------------|
| [Criteria 1] | [Weight] | [Brief description] |
| [Criteria 2] | [Weight] | [Brief description] |
| [Criteria 3] | [Weight] | [Brief description] |

## Options Considered
### Option 1: [Name/Description]
- **Description**: [Detailed description of this option]
- **Pros**:
  - [Pro 1]
  - [Pro 2]
  - [Pro 3]
- **Cons**:
  - [Con 1]
  - [Con 2]  
  - [Con 3]
- **Cost/Effort**: [Implementation complexity and resource requirements]
- **Risk Level**: [Low | Medium | High]

### Option 2: [Name/Description]
- **Description**: [Detailed description of this option]
- **Pros**:
  - [Pro 1]
  - [Pro 2]
- **Cons**:
  - [Con 1]
  - [Con 2]
- **Cost/Effort**: [Implementation complexity and resource requirements]
- **Risk Level**: [Low | Medium | High]

### Option 3: [Name/Description]
[Continue for additional options...]

## Decision
### Chosen Option
**Selected**: [Name of chosen option]

### Rationale
[Detailed explanation of why this option was selected over alternatives. Include:]
- Key factors that led to this decision
- How this option best meets the decision criteria
- Trade-offs accepted with this choice
- Specific benefits that outweighed the drawbacks

### Decision Matrix
| Option | [Criteria 1] Score | [Criteria 2] Score | [Criteria 3] Score | Weighted Total |
|--------|-------------------|-------------------|-------------------|----------------|
| Option 1 | [Score] | [Score] | [Score] | [Total] |
| Option 2 | [Score] | [Score] | [Score] | [Total] |
| **Selected Option** | **[Score]** | **[Score]** | **[Score]** | **[Total]** |

## Implementation Details
### Technical Approach
[Specific technical details about how the decision will be implemented]

### Dependencies
- [Dependency 1]
- [Dependency 2]
- [Dependency 3]

### Integration Points
[How this decision affects or integrates with existing systems/components]

### Configuration/Setup Required
[Any configuration changes, setup steps, or environmental modifications needed]

## Architecture & Design Impact
### System Architecture Changes
**Current Architecture State**: [Description of existing system architecture]

**Proposed Architecture Changes**: [How this decision modifies the system architecture]

**Architecture Patterns Affected**:
- [Pattern 1]: [How it's impacted - Enhanced/Modified/Replaced/Deprecated]
- [Pattern 2]: [How it's impacted]
- [Pattern 3]: [How it's impacted]

### Code Organization & Structure
**Module Layout Changes**:
- **New Modules**: [List of new modules/packages to be created]
- **Modified Modules**: [Existing modules that will be changed]
- **Deprecated Modules**: [Modules that will be phased out]

**Directory Structure Impact**:
```
[Before/After directory structure or description of changes]
```

**File Organization Guidelines**:
- **Naming Conventions**: [Any new or modified naming patterns]
- **Import/Export Patterns**: [How modules will expose and consume functionality]
- **Dependency Structure**: [How dependencies will flow through the system]

### Component Design
**New Components**:
| Component | Purpose | Interfaces | Dependencies |
|-----------|---------|------------|--------------|
| [Component 1] | [Purpose] | [APIs/Interfaces] | [Dependencies] |
| [Component 2] | [Purpose] | [APIs/Interfaces] | [Dependencies] |

**Modified Components**:
| Component | Changes | Impact | Migration Path |
|-----------|---------|--------|----------------|
| [Component 1] | [Changes] | [Impact] | [Migration steps] |
| [Component 2] | [Changes] | [Impact] | [Migration steps] |

### Data Flow & Integration
**Data Flow Changes**: [How data movement through the system is affected]

**API/Interface Changes**:
- **New Interfaces**: [List of new APIs or interfaces]
- **Modified Interfaces**: [Changes to existing interfaces]
- **Deprecated Interfaces**: [Interfaces being phased out]

**Integration Patterns**: [How this decision affects system integration patterns]

### Architecture Quality Attributes
**Impact on Quality Attributes**:
| Attribute | Current State | Target State | Implementation Strategy |
|-----------|---------------|--------------|------------------------|
| Performance | [Current] | [Target] | [How to achieve] |
| Scalability | [Current] | [Target] | [How to achieve] |
| Maintainability | [Current] | [Target] | [How to achieve] |
| Testability | [Current] | [Target] | [How to achieve] |
| Security | [Current] | [Target] | [How to achieve] |
| Reliability | [Current] | [Target] | [How to achieve] |

### Technology Stack Impact
**Technology Choices**:
- **New Technologies**: [Technologies being introduced]
- **Technology Changes**: [Modifications to existing tech stack]
- **Technology Retirement**: [Technologies being phased out]

**Justification for Technology Decisions**:
[Rationale for technology choices made as part of this architectural decision]

### Architecture Compliance
**Design Principles Adherence**:
- [ ] Single Responsibility Principle maintained
- [ ] Separation of Concerns preserved
- [ ] Dependency Inversion followed
- [ ] Interface Segregation maintained
- [ ] Open/Closed Principle respected

**Architecture Standards Compliance**:
- [ ] Coding standards followed
- [ ] Documentation standards met
- [ ] Testing architecture aligned
- [ ] Security architecture compliant
- [ ] Performance requirements addressed

## Consequences & Impact Analysis
### Positive Consequences
- [Positive outcome 1]
- [Positive outcome 2]
- [Positive outcome 3]

### Negative Consequences/Risks
- [Risk/negative outcome 1] - *Mitigation*: [How to address this]
- [Risk/negative outcome 2] - *Mitigation*: [How to address this]
- [Risk/negative outcome 3] - *Mitigation*: [How to address this]

### Impact Assessment
| Area | Impact Level | Description |
|------|-------------|-------------|
| Performance | [High/Medium/Low/None] | [Description of performance impact] |
| Security | [High/Medium/Low/None] | [Description of security implications] |
| Maintainability | [High/Medium/Low/None] | [Description of maintenance impact] |
| Scalability | [High/Medium/Low/None] | [Description of scaling implications] |
| Cost | [High/Medium/Low/None] | [Description of cost implications] |
| Team Productivity | [High/Medium/Low/None] | [Description of team impact] |

## Validation & Monitoring
### Success Metrics
[How will we measure if this decision was successful]
- **Metric 1**: [Target value] - [Measurement method]
- **Metric 2**: [Target value] - [Measurement method]  
- **Metric 3**: [Target value] - [Measurement method]

### Monitoring Plan
[How will ongoing monitoring be implemented]
- **Monitoring Tools**: [Tools that will track the decision's impact]
- **Review Schedule**: [When and how often this decision will be reviewed]
- **Key Indicators**: [What signs would suggest this decision needs revision]

### Rollback Plan
[What steps would be taken if this decision needs to be reversed]

## Agent Reasoning Chain
### Decision-Making Process
[Step-by-step breakdown of how the AI agent arrived at this decision]
1. **Analysis Phase**: [What was analyzed first]
2. **Option Generation**: [How alternatives were identified]
3. **Evaluation Phase**: [How options were compared]
4. **Selection Logic**: [Final decision logic]

### Tools & Resources Used
- [Tool/API 1]: [Purpose and outcome]
- [Tool/API 2]: [Purpose and outcome]
- [Resource/Documentation]: [How it informed the decision]

### Knowledge Sources Consulted
[What information sources the agent used to make this decision]
- [Source 1]: [Relevance and key insights]
- [Source 2]: [Relevance and key insights]

## Follow-up Actions
### Immediate Next Steps
- [ ] [Action item 1]
- [ ] [Action item 2]
- [ ] [Action item 3]

### Future Considerations
[Items to consider in future related decisions]
- [Future consideration 1]
- [Future consideration 2]

### Related ADRs
[References to other ADRs that relate to this decision]
- [ADR-XXX]: [Brief description of relationship]
- [ADR-YYY]: [Brief description of relationship]

## Approval & Review
### Stakeholders Consulted
[If applicable, any stakeholders or systems consulted during decision-making]

### Human Review Required
[Yes/No - Does this decision require human approval before implementation?]

### Review Status
- **Technical Review**: [Pending | Approved | Requires Changes]
- **Security Review**: [Pending | Approved | Requires Changes | N/A]
- **Architecture Review**: [Pending | Approved | Requires Changes]

---

## Agent Completion Metadata
- **Total Processing Time**: [Time to complete analysis and documentation]
- **Tokens Used**: [If applicable]
- **Error Count**: [Number of errors encountered during processing]
- **Research Iterations**: [How many analysis cycles were performed]
- **Confidence Score**: [Agent's confidence in decision quality - 0-100%]

---

*This ADR was automatically generated by [AGENT_NAME] on [TIMESTAMP]*
*Last updated: [UPDATE_TIMESTAMP]*