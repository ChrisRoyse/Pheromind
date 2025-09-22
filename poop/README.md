# Source Secure 🛡️

Advanced local secret scanner and security analyzer for source code. Detects API keys, credentials, and sensitive information in your codebase without sending data to external services.

## Features

### 🔍 480+ Secret Detectors

- **Cloud Providers**: AWS, Google Cloud, Azure, DigitalOcean, Heroku
- **Version Control**: GitHub, GitLab, Bitbucket tokens
- **Payment Services**: Stripe, PayPal, Square, Braintree
- **Communication**: Slack, Discord, Twilio, SendGrid
- **Databases**: PostgreSQL, MySQL, MongoDB, Redis connection strings
- **AI Services**: OpenAI, Anthropic, Hugging Face API keys
- **Cryptocurrency**: Wallet keys and seeds
- **And many more...**

### 🧠 Advanced Detection Methods

- **Entropy Analysis**: Detects high-entropy strings that could be secrets
- **Base64 Decoding**: Finds secrets hidden in encoded strings
- **Multi-line Detection**: Catches private keys, certificates, and JSON credentials
- **Context Validation**: Reduces false positives with intelligent pattern matching
- **Git History Scanning**: Finds secrets in past commits
- **Ollama AI Integration**: Optional local LLM for advanced detection

### 🎯 Security Features

- **Severity Levels**: CRITICAL, HIGH, MEDIUM, LOW
- **Remediation Suggestions**: Specific guidance for each type of secret
- **100% Local**: No data sent to external services
- **Pre-commit Hook Support**: Prevent secrets from being committed
- **CI/CD Integration**: Exit codes for automation

## Installation

### Global Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/source-secure.git
cd source-secure

# Install globally using npm link
npm link

# Or install globally from directory
npm install -g .
```

### Local Installation

```bash
npm install source-secure
```

### As a Git Pre-commit Hook

```bash
# Copy to your global git hooks
cp source-secure.js ~/.git-hooks/
cp scan-secrets.js ~/.git-hooks/

# Configure git to use global hooks
git config --global core.hooksPath ~/.git-hooks
```

## Usage

### Command Line

```bash
# Basic scan of current directory
source-secure

# Short alias
ss-scan

# Scan specific directory
source-secure /path/to/project

# Verbose output with remediation suggestions
source-secure --verbose

# Scan git history (last 100 commits)
source-secure --history

# Use AI detection with Ollama (requires Ollama installed)
source-secure --ai --verbose

# Combine multiple flags
source-secure /path/to/project --history --verbose
```

### NPM Scripts

Add to your `package.json`:

```json
{
  "scripts": {
    "security-scan": "source-secure",
    "security-scan:verbose": "source-secure --verbose",
    "security-scan:history": "source-secure --history",
    "security-scan:ai": "source-secure --ai --verbose"
  }
}
```

### Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/sh
source-secure . || exit 1
```

## Configuration

### Ignore Patterns

The scanner automatically ignores:

- `node_modules/`
- `.git/`
- `dist/`
- `build/`
- Binary files
- Lock files

### Supported File Types

- JavaScript/TypeScript (`.js`, `.jsx`, `.ts`, `.tsx`)
- Python (`.py`)
- Configuration files (`.json`, `.yml`, `.yaml`, `.xml`)
- Environment files (`.env`, `.env.*`)
- Shell scripts (`.sh`, `.bash`)
- Properties files (`.properties`, `.conf`, `.config`)

## Output Examples

### Standard Output

```
🔍 Scanning: /home/user/my-project

⚠️  Found 3 potential secret(s):

🚨 CRITICAL: 1 finding(s)
⚠️  HIGH: 2 finding(s)

Use --verbose flag for detailed findings and remediation steps
```

### Verbose Output

```
📄 src/config.js
   Line 42: AWS Access Key ID
   Match: AKIAIOSFODNN7EXAMPLE_FAKE
   🚨 IMMEDIATE ACTION REQUIRED: Revoke this credential immediately
   💡 Use AWS Secrets Manager or IAM roles instead of hardcoded credentials
```

## Exit Codes

- `0`: No secrets found
- `1`: Secrets found (CRITICAL or HIGH severity)

## Advanced Features

### Entropy Detection

Detects high-entropy strings that don't match known patterns but could be secrets:

```javascript
// This would be detected as a high-entropy string
const suspicious = "zX9kP2mN5qR8wT3yB6vC1aS4dF7gH0jK";
```

### Base64 Detection

Automatically decodes and scans base64-encoded content:

```javascript
// Encoded API key would be detected
const encoded = "QUl6YVN5QUdHb0hJVmhpbGtFSEJYVXppUGhlNTlEM1BqSkV3RTBZ";
```

### Multi-line Secrets

Detects certificates, private keys, and multi-line JSON credentials:

```javascript
const privateKey = `-----BEGIN PRIVATE KEY-----
[KEY CONTENT REDACTED]
-----END PRIVATE KEY-----`;
```

## Integration with CI/CD

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
      - run: npm install -g source-secure
      - run: source-secure --verbose
```

### GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - npm install -g source-secure
    - source-secure --verbose
```

### Jenkins

```groovy
stage('Security Scan') {
    steps {
        sh 'npm install -g source-secure'
        sh 'source-secure --verbose'
    }
}
```

## Ollama AI Integration

For enhanced detection using local AI:

1. Install Ollama: https://ollama.ai
2. Pull a model: `ollama pull llama2`
3. Run scan with AI: `source-secure --ai --verbose`

The AI helps detect:

- Context-specific secrets
- Custom credential patterns
- Business logic vulnerabilities

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details

## Security

If you discover a security vulnerability, please email security@example.com

## Comparison with Other Tools

| Feature            | Source Secure | GitGuardian | TruffleHog | Gitleaks |
| ------------------ | ------------- | ----------- | ---------- | -------- |
| 480+ Detectors     | ✅            | ✅          | ❌         | ❌       |
| Entropy Detection  | ✅            | ✅          | ✅         | ❌       |
| Base64 Decoding    | ✅            | ✅          | ❌         | ❌       |
| Local AI Support   | ✅            | ❌          | ❌         | ❌       |
| 100% Local         | ✅            | ❌          | ✅         | ✅       |
| Free & Open Source | ✅            | ❌          | ✅         | ✅       |

## Acknowledgments

Inspired by GitGuardian, TruffleHog, and the open-source security community.
