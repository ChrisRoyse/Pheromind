# Source Secure Configuration Guide

This guide explains how to customize Source Secure's scanning behavior by modifying the configuration constants in the source files.

## Table of Contents

- [File Type Configuration (SCAN_EXTENSIONS)](#file-type-configuration-scan_extensions)
- [Ignore Patterns (IGNORE_PATTERNS)](#ignore-patterns-ignore_patterns)
- [API Key Patterns (API_KEY_PATTERNS)](#api-key-patterns-api_key_patterns)
- [Scanning All Files](#scanning-all-files)
- [Compressed Files Support](#compressed-files-support)

## File Type Configuration (SCAN_EXTENSIONS)

### Location

- **File**: `scan-secrets.js` (line ~56)
- **File**: `source-secure.js` (line ~447)

### Current Default Configuration

```javascript
const SCAN_EXTENSIONS = [
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".json",
  ".env",
  ".config",
  ".html",
  ".htm",
  ".xml",
  ".py",
  ".rb",
  ".php",
  ".java",
  ".yml",
  ".yaml",
  ".toml",
  ".sh",
  ".bash",
  ".zsh",
  ".md",
  ".txt",
];
```

### How to Customize

#### Scan All Files (_._)

To scan ALL file types regardless of extension:

```javascript
// Option 1: Empty array means scan everything
const SCAN_EXTENSIONS = [];

// Option 2: Explicitly include all by checking differently
// Modify the shouldScanFile function:
function shouldScanFile(filePath) {
  if (shouldSkipPath(filePath)) return false;

  // Remove extension check to scan all files
  return true; // This will scan *.*
}
```

#### Add Specific Extensions

```javascript
const SCAN_EXTENSIONS = [
  // Existing extensions...
  ".go", // Go files
  ".rs", // Rust files
  ".swift", // Swift files
  ".kt", // Kotlin files
  ".scala", // Scala files
  ".c",
  ".cpp", // C/C++ files
  ".cs", // C# files
  ".m",
  ".mm", // Objective-C files
  ".sql", // SQL files
  ".properties", // Properties files
  ".ini", // INI configuration files
  ".pem",
  ".key",
  ".crt", // Certificate files
  ".tfvars", // Terraform variables
  // Add any other extensions you need
];
```

#### Scan Only Specific File Types

```javascript
// Example: Only scan JavaScript and environment files
const SCAN_EXTENSIONS = [
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".env",
  ".env.local",
  ".env.production",
];
```

## Ignore Patterns (IGNORE_PATTERNS)

### Location

- **File**: `scan-secrets.js` (line ~48)
- **File**: `source-secure.js` (line ~438 in walk function)

### Current Default Configuration

```javascript
const IGNORE_PATTERNS = [
  "node_modules",
  ".git",
  ".env.example",
  "*.lock",
  "*.log",
  "package-lock.json",
  "yarn.lock",
  "dist",
  "build",
  ".next",
  "scan-secrets.js", // Don't scan this file itself
];
```

### How to Customize

#### Add More Directories to Ignore

```javascript
const IGNORE_PATTERNS = [
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "coverage", // Test coverage
  "vendor", // PHP vendor directory
  "venv", // Python virtual environment
  "__pycache__", // Python cache
  ".pytest_cache", // Pytest cache
  "target", // Rust/Java build directory
  ".gradle", // Gradle cache
  ".idea", // IntelliJ IDEA
  ".vscode", // VS Code settings
  "*.min.js", // Minified files
  "*.map", // Source map files
  "*.chunk.*", // Webpack chunks
  "public/assets", // Compiled assets
  // Add your patterns here
];
```

#### Ignore Nothing (Scan Everything)

```javascript
const IGNORE_PATTERNS = [];
```

#### Custom Pattern Matching

```javascript
function shouldSkipPath(filePath) {
  const basename = path.basename(filePath);
  const dirname = path.dirname(filePath);

  // Custom logic examples:

  // Skip all test files
  if (basename.includes(".test.") || basename.includes(".spec.")) {
    return true;
  }

  // Skip files larger than 10MB
  const stats = fs.statSync(filePath);
  if (stats.size > 10 * 1024 * 1024) {
    return true;
  }

  // Skip specific directories by full path
  if (filePath.includes("/temp/") || filePath.includes("/tmp/")) {
    return true;
  }

  // Apply standard ignore patterns
  for (const pattern of IGNORE_PATTERNS) {
    if (pattern.includes("*")) {
      const regex = new RegExp(pattern.replace("*", ".*"));
      if (regex.test(basename)) return true;
    } else {
      if (filePath.includes(pattern)) return true;
    }
  }
  return false;
}
```

## API Key Patterns (API_KEY_PATTERNS)

### Location

- **File**: `scan-secrets.js` (lines 11-47)
- **File**: `source-secure.js` (lines 11-96)

### Structure

```javascript
const API_KEY_PATTERNS = [
    {
        name: 'Pattern Name',           // Display name
        pattern: /regex_pattern/flags,  // Regular expression
        severity: 'CRITICAL',           // CRITICAL, HIGH, MEDIUM, or LOW
        context: /optional_context/i    // Optional context validation
    }
];
```

### Adding Custom Patterns

#### Add Company-Specific API Keys

```javascript
const API_KEY_PATTERNS = [
  // Existing patterns...

  // Add your custom patterns:
  {
    name: "MyCompany API Key",
    pattern: /MYCO_[A-Z0-9]{32}/g,
    severity: "HIGH",
  },
  {
    name: "Internal Service Token",
    pattern: /svc_token_[a-zA-Z0-9]{40}/g,
    severity: "CRITICAL",
  },
  {
    name: "Database Password",
    pattern: /db_password["']\s*[:=]\s*["']([^"']{8,})/gi,
    severity: "CRITICAL",
    context: /database|mysql|postgres/i,
  },
];
```

#### Modify Severity Levels

```javascript
// Change AWS keys from CRITICAL to HIGH
{ name: 'AWS Access Key ID', pattern: /AKIA[A-Z0-9]{16}/g, severity: 'HIGH' },

// Change generic passwords from HIGH to CRITICAL
{ name: 'Generic Password', pattern: /password["']\s*[:=]\s*["']([^"']{8,})/gi, severity: 'CRITICAL' },
```

#### Add Context Validation

Context validation helps reduce false positives:

```javascript
{
    name: 'API Key',
    pattern: /[a-f0-9]{32}/g,
    severity: 'MEDIUM',
    context: /api[_-]?key|apikey|api_secret/i  // Only flag if near these words
}
```

#### Remove Patterns (Reduce False Positives)

Comment out or remove patterns that cause too many false positives:

```javascript
const API_KEY_PATTERNS = [
  // Commented out to reduce false positives
  // { name: 'Generic Token', pattern: /token[_\s-]?['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{32,})['\"]?/gi, severity: 'MEDIUM' },

  // Keep only specific patterns
  {
    name: "AWS Access Key ID",
    pattern: /AKIA[A-Z0-9]{16}/g,
    severity: "CRITICAL",
  },
  {
    name: "GitHub Token",
    pattern: /ghp_[0-9a-zA-Z]{36}/g,
    severity: "CRITICAL",
  },
];
```

## Scanning All Files

To configure Source Secure to scan ALL files (_._):

### Method 1: Modify SCAN_EXTENSIONS

```javascript
// In both scan-secrets.js and source-secure.js
const SCAN_EXTENSIONS = []; // Empty array = scan all

// Then modify shouldScanFile function:
function shouldScanFile(filePath) {
  if (shouldSkipPath(filePath)) return false;

  const ext = path.extname(filePath).toLowerCase();

  // If SCAN_EXTENSIONS is empty, scan all files
  if (SCAN_EXTENSIONS.length === 0) return true;

  // Otherwise check against the list
  return SCAN_EXTENSIONS.includes(ext) || ext === "";
}
```

### Method 2: Direct Modification

Simply change the condition in the scanning logic:

```javascript
// In the walk function, change this line:
if (['.js', '.py', '.json', '.env', '.yml', '.yaml', '.xml', '.config', '.conf', '.properties', '.sh', '.bash'].includes(ext) || ext === '') {

// To this (scans everything):
if (true) {  // Scan all files
```

## Compressed Files Support

### Adding Archive Scanning (Future Feature)

To add support for scanning compressed files (.zip, .7z, .rar, .tar.gz, etc.), you would need to:

1. **Install Dependencies**:

```bash
npm install node-7z  # For 7z, rar, zip support
npm install tar      # For tar, tar.gz support
npm install unzipper # Alternative for zip files
```

2. **Add Archive Detection**:

```javascript
const ARCHIVE_EXTENSIONS = [
  ".zip",
  ".7z",
  ".rar",
  ".tar",
  ".tar.gz",
  ".tgz",
  ".tar.bz2",
  ".tbz2",
  ".tar.xz",
  ".txz",
  ".jar",
  ".war",
  ".ear", // Java archives
  ".deb",
  ".rpm", // Package files
  ".iso",
  ".dmg", // Disk images
];

function isArchive(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return ARCHIVE_EXTENSIONS.includes(ext);
}
```

3. **Extract and Scan Function**:

```javascript
async function scanArchive(archivePath) {
  const tempDir = path.join(os.tmpdir(), "source-secure-" + Date.now());

  try {
    // Extract archive to temp directory
    await extractArchive(archivePath, tempDir);

    // Scan extracted contents
    const findings = await scanDirectory(tempDir);

    // Clean up
    fs.rmSync(tempDir, { recursive: true, force: true });

    return findings;
  } catch (error) {
    console.error(`Failed to scan archive ${archivePath}:`, error);
    return [];
  }
}
```

4. **Integration in Main Scanner**:

```javascript
// In the walk function
if (stats.isFile()) {
  if (isArchive(fullPath)) {
    // Scan archive contents
    const archiveFindings = await scanArchive(fullPath);
    findings.push(...archiveFindings);
  } else if (shouldScanFile(fullPath)) {
    // Regular file scanning
    const fileFindings = await scanFile(fullPath, flags.ai);
    findings.push(...fileFindings);
  }
}
```

### Current Workaround

Until archive support is built-in, you can:

1. **Extract manually and scan**:

```bash
# Extract archive
unzip archive.zip -d ./extracted/

# Scan extracted contents
source-secure ./extracted/
```

2. **Use a shell script**:

```bash
#!/bin/bash
# scan-archive.sh

ARCHIVE=$1
TEMP_DIR=$(mktemp -d)

# Extract based on extension
case "$ARCHIVE" in
    *.zip) unzip -q "$ARCHIVE" -d "$TEMP_DIR" ;;
    *.tar.gz|*.tgz) tar -xzf "$ARCHIVE" -C "$TEMP_DIR" ;;
    *.7z) 7z x "$ARCHIVE" -o"$TEMP_DIR" ;;
    *.rar) unrar x "$ARCHIVE" "$TEMP_DIR" ;;
esac

# Scan extracted contents
source-secure "$TEMP_DIR" --verbose

# Cleanup
rm -rf "$TEMP_DIR"
```

## Performance Optimization

### For Large Codebases

If scanning is slow, you can optimize by:

1. **Limiting file size**:

```javascript
function shouldScanFile(filePath) {
  const stats = fs.statSync(filePath);

  // Skip files larger than 5MB
  if (stats.size > 5 * 1024 * 1024) {
    console.log(`Skipping large file: ${filePath}`);
    return false;
  }

  // Continue with normal checks...
}
```

2. **Parallel scanning** (already implemented in source-secure.js):

```javascript
// Files are scanned in parallel using Promise.all
const allFindings = await Promise.all(scanPromises);
```

3. **Skip binary files**:

```javascript
const BINARY_EXTENSIONS = [
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".ico",
  ".mp3",
  ".mp4",
  ".avi",
  ".mov",
  ".pdf",
  ".doc",
  ".docx",
  ".xls",
  ".xlsx",
  ".ttf",
  ".woff",
  ".woff2",
  ".eot",
];

function shouldScanFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();

  // Skip binary files
  if (BINARY_EXTENSIONS.includes(ext)) {
    return false;
  }

  // Continue with normal checks...
}
```

## Examples

### Example 1: Web Development Focus

```javascript
// Only scan web-related files
const SCAN_EXTENSIONS = [
  ".js",
  ".jsx",
  ".ts",
  ".tsx", // JavaScript
  ".html",
  ".htm",
  ".css",
  ".scss",
  ".sass", // Frontend
  ".json",
  ".xml", // Data files
  ".env",
  ".env.local",
  ".env.production", // Environment
  ".yml",
  ".yaml", // Configuration
];

const IGNORE_PATTERNS = [
  "node_modules",
  "dist",
  "build",
  ".next",
  "*.min.js",
  "*.bundle.js",
  "public/vendor",
];
```

### Example 2: Python Project

```javascript
const SCAN_EXTENSIONS = [
  ".py", // Python files
  ".pyw", // Python GUI files
  ".pyx", // Cython files
  ".ipynb", // Jupyter notebooks
  ".ini",
  ".cfg",
  ".conf", // Config files
  ".env",
  ".flaskenv", // Environment files
  ".yml",
  ".yaml",
  ".toml", // Common config formats
  ".txt",
  ".md",
  ".rst", // Documentation
];

const IGNORE_PATTERNS = [
  "__pycache__",
  "*.pyc",
  "venv",
  "env",
  ".env",
  "virtualenv",
  ".pytest_cache",
  ".mypy_cache",
  "dist",
  "build",
  "*.egg-info",
  ".tox",
];
```

### Example 3: High Security Mode

```javascript
// Scan everything, ignore nothing
const SCAN_EXTENSIONS = []; // Empty = scan all

const IGNORE_PATTERNS = [
  ".git", // Only skip git directory
];

// Add more aggressive patterns
const API_KEY_PATTERNS = [
  // ... existing patterns ...

  // Add patterns for any long string
  {
    name: "Suspicious Long String",
    pattern: /[a-zA-Z0-9_-]{40,}/g,
    severity: "LOW",
  },

  // Flag any base64 encoded content
  {
    name: "Base64 Content",
    pattern: /[A-Za-z0-9+/]{50,}={0,2}/g,
    severity: "LOW",
  },
];
```

## Saving Your Configuration

After modifying the configuration:

1. **Save the files**
2. **Test your configuration**:

```bash
source-secure . --verbose
```

3. **Commit your changes** (if tracking in git):

```bash
git add -A
git commit -m "Updated scanner configuration for project needs"
```

4. **Re-install globally** if needed:

```bash
npm link
```

## Configuration Best Practices

1. **Start with defaults** and adjust based on false positives/negatives
2. **Document your changes** in comments
3. **Test thoroughly** after configuration changes
4. **Keep security/performance balance** - scanning everything may be slow
5. **Use context validation** to reduce false positives
6. **Regular updates** - Add new patterns as new services emerge

## Need Help?

If you need assistance with configuration:

1. Check the examples above
2. Review the source code comments
3. Test with `--verbose` flag for detailed output
4. Submit an issue on the repository with your use case
