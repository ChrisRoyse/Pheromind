#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// API Key patterns to detect
const API_KEY_PATTERNS = [
    // Google API Keys
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g },

    // AWS Keys
    { name: 'AWS Access Key ID', pattern: /AKIA[0-9A-Z]{16}/g },
    { name: 'AWS Secret Key', pattern: /[0-9a-zA-Z/+=]{40}/g, context: /aws_secret|aws_secret_access_key/i },

    // GitHub Tokens
    { name: 'GitHub Personal Access Token', pattern: /ghp_[0-9a-zA-Z]{36}/g },
    { name: 'GitHub OAuth Access Token', pattern: /gho_[0-9a-zA-Z]{36}/g },
    { name: 'GitHub App Token', pattern: /ghs_[0-9a-zA-Z]{36}/g },
    { name: 'GitHub Refresh Token', pattern: /ghr_[0-9a-zA-Z]{36}/g },

    // API Keys with common prefixes
    { name: 'Stripe API Key', pattern: /sk_live_[0-9a-zA-Z]{24}/g },
    { name: 'Stripe Test Key', pattern: /sk_test_[0-9a-zA-Z]{24}/g },
    { name: 'Stripe Publishable Key', pattern: /pk_live_[0-9a-zA-Z]{24}/g },
    { name: 'Stripe Test Publishable Key', pattern: /pk_test_[0-9a-zA-Z]{24}/g },

    // OpenAI
    { name: 'OpenAI API Key', pattern: /sk-[0-9a-zA-Z]{48}/g },

    // Slack
    { name: 'Slack Token', pattern: /xox[baprs]-[0-9a-zA-Z-]+/g },

    // Generic patterns for common key formats
    { name: 'Generic API Key', pattern: /['\"]api[_-]?key['\"]\s*[:=]\s*['\"]([^'\"]{20,})['\"](?![^>]*>)/gi },
    { name: 'Generic Secret', pattern: /['\"]secret['\"]\s*[:=]\s*['\"]([^'\"]{20,})['\"](?![^>]*>)/gi },
    { name: 'Generic Token', pattern: /['\"]token['\"]\s*[:=]\s*['\"]([^'\"]{20,})['\"](?![^>]*>)/gi },
    { name: 'Generic Password', pattern: /['\"]password['\"]\s*[:=]\s*['\"]([^'\"]{8,})['\"](?![^>]*>)/gi },

    // Bearer tokens
    { name: 'Bearer Token', pattern: /Bearer\s+[a-zA-Z0-9_-]{20,}/g },

    // Private keys
    { name: 'RSA Private Key', pattern: /-----BEGIN RSA PRIVATE KEY-----/g },
    { name: 'SSH Private Key', pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g },
    { name: 'PGP Private Key', pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g },
];

// Files and directories to skip
const IGNORE_PATTERNS = [
    'node_modules',
    '.git',
    '.env.example',
    '*.lock',
    '*.log',
    'package-lock.json',
    'yarn.lock',
    'dist',
    'build',
    '.next',
    'scan-secrets.js' // Don't scan this file
];

// File extensions to scan
const SCAN_EXTENSIONS = [
    '.js', '.jsx', '.ts', '.tsx',
    '.json', '.env', '.config',
    '.html', '.htm', '.xml',
    '.py', '.rb', '.php', '.java',
    '.yml', '.yaml', '.toml',
    '.sh', '.bash', '.zsh',
    '.md', '.txt'
];

function shouldSkipPath(filePath) {
    const basename = path.basename(filePath);
    const dirname = path.dirname(filePath);

    for (const pattern of IGNORE_PATTERNS) {
        if (pattern.includes('*')) {
            const regex = new RegExp(pattern.replace('*', '.*'));
            if (regex.test(basename)) return true;
        } else {
            if (filePath.includes(pattern)) return true;
        }
    }
    return false;
}

function shouldScanFile(filePath) {
    if (shouldSkipPath(filePath)) return false;

    const ext = path.extname(filePath).toLowerCase();
    return SCAN_EXTENSIONS.includes(ext) || ext === '';
}

function scanFile(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        const findings = [];

        for (const detector of API_KEY_PATTERNS) {
            const matches = content.matchAll(detector.pattern);

            for (const match of matches) {
                // If this pattern requires context, check for it
                if (detector.context) {
                    const contextStart = Math.max(0, match.index - 50);
                    const contextEnd = Math.min(content.length, match.index + match[0].length + 50);
                    const context = content.substring(contextStart, contextEnd);

                    if (!detector.context.test(context)) {
                        continue;
                    }
                }

                // Get line number
                const lines = content.substring(0, match.index).split('\n');
                const lineNumber = lines.length;

                // Get the line content
                const lineStart = content.lastIndexOf('\n', match.index) + 1;
                const lineEnd = content.indexOf('\n', match.index);
                const line = content.substring(lineStart, lineEnd !== -1 ? lineEnd : content.length);

                findings.push({
                    type: detector.name,
                    file: filePath,
                    line: lineNumber,
                    match: match[0].substring(0, 50) + (match[0].length > 50 ? '...' : ''),
                    content: line.trim().substring(0, 100) + (line.length > 100 ? '...' : '')
                });
            }
        }

        return findings;
    } catch (error) {
        if (error.code !== 'EISDIR') {
            console.error(`Error reading ${filePath}: ${error.message}`);
        }
        return [];
    }
}

function scanDirectory(dir) {
    const findings = [];

    function walk(currentPath) {
        if (shouldSkipPath(currentPath)) return;

        try {
            const stats = fs.statSync(currentPath);

            if (stats.isDirectory()) {
                const items = fs.readdirSync(currentPath);
                for (const item of items) {
                    walk(path.join(currentPath, item));
                }
            } else if (stats.isFile() && shouldScanFile(currentPath)) {
                const fileFindings = scanFile(currentPath);
                findings.push(...fileFindings);
            }
        } catch (error) {
            // Skip files we can't read
        }
    }

    walk(dir);
    return findings;
}

function main() {
    const args = process.argv.slice(2);
    const targetPath = args[0] || '.';

    console.log(`\n🔍 Scanning for API keys and secrets in: ${path.resolve(targetPath)}\n`);

    const startTime = Date.now();
    const findings = scanDirectory(targetPath);
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);

    if (findings.length === 0) {
        console.log(`✅ No potential API keys or secrets found! (scanned in ${duration}s)\n`);
        process.exit(0);
    } else {
        console.log(`⚠️  Found ${findings.length} potential API key(s) or secret(s):\n`);

        // Group by file
        const byFile = {};
        for (const finding of findings) {
            if (!byFile[finding.file]) {
                byFile[finding.file] = [];
            }
            byFile[finding.file].push(finding);
        }

        // Display findings
        for (const [file, items] of Object.entries(byFile)) {
            console.log(`📄 ${file}`);
            for (const item of items) {
                console.log(`   Line ${item.line}: ${item.type}`);
                console.log(`   > ${item.content}\n`);
            }
        }

        console.log(`\n⚠️  Please review these findings and ensure no sensitive data is committed.`);
        console.log(`Scan completed in ${duration}s\n`);

        // Exit with error code to fail pre-commit hook
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = { scanDirectory, scanFile };
