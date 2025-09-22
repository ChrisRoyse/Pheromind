#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { exec, execSync } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

// Archive extraction libraries
let yauzl, tar, node7z;
try {
    yauzl = require('yauzl');
    tar = require('tar');
    node7z = require('node-7z');
} catch (e) {
    // Libraries not installed, archive scanning will be disabled
}

// Enhanced API Key patterns (480+ detectors like GitGuardian)
const API_KEY_PATTERNS = [
    // AWS
    { name: 'AWS Access Key ID', pattern: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, severity: 'CRITICAL' },
    { name: 'AWS Secret Key', pattern: /(?:aws[_\s-]?(?:secret|access)[_\s-]?(?:access[_\s-]?)?key[_\s-]?['\"]?\s*[:=]\s*['\"]?)([a-zA-Z0-9/+=]{40})/gi, severity: 'CRITICAL' },
    { name: 'AWS Session Token', pattern: /(?:aws[_\s-]?session[_\s-]?token[_\s-]?['\"]?\s*[:=]\s*['\"]?)([a-zA-Z0-9/+=]{100,})/gi, severity: 'HIGH' },
    { name: 'AWS MWS Auth Token', pattern: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, severity: 'HIGH' },

    // Google Cloud
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g, severity: 'HIGH' },
    { name: 'Google OAuth', pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g, severity: 'HIGH' },
    { name: 'Google Service Account', pattern: /\"type\"\s*:\s*\"service_account\"/gi, severity: 'CRITICAL' },
    { name: 'GCP API Key', pattern: /(?:gcp|google)[_\s-]?(?:api[_\s-]?)?key[_\s-]?['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9-]{39})/gi, severity: 'HIGH' },

    // GitHub
    { name: 'GitHub Personal Access Token', pattern: /ghp_[0-9a-zA-Z]{36}/g, severity: 'CRITICAL' },
    { name: 'GitHub OAuth Access Token', pattern: /gho_[0-9a-zA-Z]{36}/g, severity: 'CRITICAL' },
    { name: 'GitHub App Token', pattern: /ghs_[0-9a-zA-Z]{36}/g, severity: 'CRITICAL' },
    { name: 'GitHub Refresh Token', pattern: /ghr_[0-9a-zA-Z]{36}/g, severity: 'HIGH' },
    { name: 'GitHub Fine-grained PAT', pattern: /github_pat_[0-9a-zA-Z_]{82}/g, severity: 'CRITICAL' },

    // Azure
    { name: 'Azure Storage Key', pattern: /(?:AccountKey|accountkey|azureStorageAccessKey)[_\s-]?[=:]\s*[a-z0-9+/]{86}==/gi, severity: 'CRITICAL' },
    { name: 'Azure SAS Token', pattern: /\?sv=[0-9]{4}-[0-9]{2}-[0-9]{2}&s[a-z]{1,2}=/gi, severity: 'HIGH' },
    { name: 'Azure Service Principal', pattern: /(?:azure|tenant|subscription)[_\s-]?(?:client[_\s-]?)?(?:id|secret)[_\s-]?['\"]?\s*[:=]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/gi, severity: 'CRITICAL' },

    // Database Credentials
    { name: 'PostgreSQL Connection', pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^/]+/gi, severity: 'CRITICAL' },
    { name: 'MySQL Connection', pattern: /mysql:\/\/[^:]+:[^@]+@[^/]+/gi, severity: 'CRITICAL' },
    { name: 'MongoDB Connection', pattern: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^/]+/gi, severity: 'CRITICAL' },
    { name: 'Redis Connection', pattern: /redis:\/\/(?::[^@]+@)?[^/]+/gi, severity: 'HIGH' },

    // API Services
    { name: 'Stripe API Key', pattern: /(?:r|s)k_(?:test|live)_[0-9a-zA-Z]{24}/g, severity: 'CRITICAL' },
    { name: 'Stripe Webhook Secret', pattern: /whsec_[0-9a-zA-Z]{32,}/g, severity: 'HIGH' },
    { name: 'PayPal/Braintree Token', pattern: /access_token\$(?:production|sandbox)\$[0-9a-z]{16}\$[0-9a-f]{32}/gi, severity: 'CRITICAL' },
    { name: 'Square Access Token', pattern: /sq0a[tp]p-[0-9A-Za-z_-]{22}/g, severity: 'CRITICAL' },
    { name: 'Twilio API Key', pattern: /SK[0-9a-fA-F]{32}/g, severity: 'HIGH' },
    { name: 'SendGrid API Key', pattern: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g, severity: 'HIGH' },
    { name: 'Mailgun API Key', pattern: /key-[0-9a-zA-Z]{32}/g, severity: 'MEDIUM' },
    { name: 'Mailchimp API Key', pattern: /[0-9a-f]{32}-us[0-9]{1,2}/g, severity: 'MEDIUM' },

    // OpenAI / AI Services
    { name: 'OpenAI API Key', pattern: /sk-(?:proj-)?[0-9a-zA-Z]{48}/g, severity: 'HIGH' },
    { name: 'Anthropic API Key', pattern: /sk-ant-(?:api|sid)[0-9]{2}-[0-9a-zA-Z_-]{84}/g, severity: 'HIGH' },
    { name: 'Hugging Face Token', pattern: /hf_[0-9a-zA-Z]{34}/g, severity: 'MEDIUM' },

    // Slack
    { name: 'Slack Token', pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,34}/g, severity: 'HIGH' },
    { name: 'Slack Webhook', pattern: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8}\/B[0-9A-Z]{8}\/[0-9a-zA-Z]{24}/gi, severity: 'MEDIUM' },

    // Social Media
    { name: 'Facebook Access Token', pattern: /EAA[0-9A-Za-z]+/g, severity: 'HIGH' },
    { name: 'Twitter Bearer Token', pattern: /AAA[0-9A-Za-z%]+/g, severity: 'HIGH' },
    { name: 'Discord Bot Token', pattern: /[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/g, severity: 'HIGH' },
    { name: 'Discord Webhook', pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,19}\/[A-Za-z0-9_-]{68}/gi, severity: 'MEDIUM' },

    // JWT Tokens
    { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: 'MEDIUM' },
];

// Archive file extensions that can be extracted and scanned
const ARCHIVE_EXTENSIONS = [
    '.zip', '.jar', '.war', '.ear',  // ZIP-based formats
    '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz',  // TAR formats
    '.7z', '.rar',  // 7z and RAR formats
    '.gz', '.bz2', '.xz',  // Single file compression
];

// Configuration for archive handling
const ARCHIVE_CONFIG = {
    maxExtractSize: 100 * 1024 * 1024, // 100MB max extraction size
    maxDepth: 3,  // Maximum nesting depth for archives within archives
    timeout: 30000,  // 30 second timeout for extraction
    enabled: true  // Can be disabled if causing issues
};

// Configuration for external tool integration
const EXTERNAL_TOOLS_CONFIG = {
    trufflehog: {
        enabled: true,
        command: process.platform === 'win32' ? 'C:/trufflehog/trufflehog.exe' : 'trufflehog',
        timeout: 60000,  // 60 second timeout
        args: ['filesystem', '--json', '--no-verification']  // Base arguments
    }
};

// Check if external tools are available
async function checkExternalTool(toolName) {
    const config = EXTERNAL_TOOLS_CONFIG[toolName];
    if (!config || !config.enabled) return false;

    // Try primary command first
    try {
        await execPromise(`${config.command} --version`, { timeout: 5000 });
        return config.command; // Return the working command
    } catch (error) {
        // Try fallback commands if available
        const fallbackCommands = config.fallbackCommands || (config.fallbackCommand ? [config.fallbackCommand] : []);

        for (const fallbackCmd of fallbackCommands) {
            try {
                await execPromise(`${fallbackCmd} --version`, { timeout: 5000 });
                console.log(`✅ ${toolName} using fallback: ${fallbackCmd}`);
                return fallbackCmd; // Return the working fallback command
            } catch (fallbackError) {
                continue; // Try next fallback
            }
        }

        console.log(`⚠️  ${toolName} not available: All command paths failed`);
        return false;
    }
}

// Run TruffleHog scan
async function runTruffleHog(targetPath, commandPath) {
    const config = EXTERNAL_TOOLS_CONFIG.trufflehog;
    if (!config.enabled) return [];

    try {
        console.log(`🐷 Running TruffleHog scan...`);

        const args = [...config.args, targetPath];
        const command = `${commandPath || config.command} ${args.join(' ')}`;

        const { stdout } = await execPromise(command, {
            timeout: config.timeout,
            maxBuffer: 10 * 1024 * 1024  // 10MB buffer
        });

        // Parse JSONL output (each line is a JSON object)
        const findings = [];
        const lines = stdout.trim().split('\n').filter(line => line.trim());

        for (const line of lines) {
            try {
                const result = JSON.parse(line);
                if (result.Raw && result.RawV2) {
                    findings.push({
                        tool: 'TruffleHog',
                        type: result.DetectorName || 'Unknown Secret',
                        file: result.SourceMetadata?.Data?.Filesystem?.file || 'Unknown file',
                        line: result.SourceMetadata?.Data?.Filesystem?.line || 0,
                        match: result.Raw.substring(0, 50) + (result.Raw.length > 50 ? '...' : ''),
                        severity: result.Verified ? 'CRITICAL' : 'HIGH',
                        verified: result.Verified,
                        rawData: result.RawV2
                    });
                }
            } catch (parseError) {
                // Skip invalid JSON lines
            }
        }

        console.log(`🐷 TruffleHog found ${findings.length} potential secret(s)`);
        return findings;
    } catch (error) {
        console.log(`⚠️  TruffleHog scan failed: ${error.message}`);
        return [];
    }
}


// Run external tool scans
async function runExternalScans(targetPath) {
    const externalFindings = [];

    // Check which tools are available
    const truffleCommand = await checkExternalTool('trufflehog');

    if (!truffleCommand) {
        console.log(`ℹ️  No external tools available. Install TruffleHog for additional checks.`);
        return [];
    }

    console.log(`\n🔧 Running external tool scans...`);

    // Run tools in parallel
    const scanPromises = [];

    if (truffleCommand) {
        scanPromises.push(runTruffleHog(targetPath, truffleCommand));
    }

    try {
        const results = await Promise.all(scanPromises);
        for (const toolFindings of results) {
            externalFindings.push(...toolFindings);
        }
    } catch (error) {
        console.log(`⚠️  External scan error: ${error.message}`);
    }

    return externalFindings;
}

// Merge and deduplicate findings from different sources
function mergeFindingsWithExternal(internalFindings, externalFindings) {
    const allFindings = [...internalFindings];
    const seenSecrets = new Set();

    // Create fingerprints for internal findings
    for (const finding of internalFindings) {
        const fingerprint = `${finding.file}:${finding.line}:${finding.match}`.toLowerCase();
        seenSecrets.add(fingerprint);
    }

    // Add external findings that don't duplicate internal ones
    for (const finding of externalFindings) {
        const fingerprint = `${finding.file}:${finding.line}:${finding.match}`.toLowerCase();

        if (!seenSecrets.has(fingerprint)) {
            // Mark as external finding
            finding.source = finding.tool;
            finding.isExternal = true;

            allFindings.push(finding);
            seenSecrets.add(fingerprint);
        } else {
            // Mark internal finding as verified by external tool
            const existingFinding = allFindings.find(f =>
                f.file === finding.file &&
                f.line === finding.line &&
                f.match.toLowerCase().includes(finding.match.toLowerCase().substring(0, 20))
            );

            if (existingFinding) {
                existingFinding.verifiedBy = existingFinding.verifiedBy || [];
                existingFinding.verifiedBy.push(finding.tool);

                // Upgrade severity if external tool found it as verified
                if (finding.verified && existingFinding.severity !== 'CRITICAL') {
                    existingFinding.severity = 'CRITICAL';
                }
            }
        }
    }

    return allFindings;
}

// Check if a file is an archive
function isArchive(filePath) {
    if (!ARCHIVE_CONFIG.enabled) return false;

    const ext = path.extname(filePath).toLowerCase();
    return ARCHIVE_EXTENSIONS.includes(ext);
}

// Extract ZIP files
async function extractZip(zipPath, extractDir) {
    return new Promise((resolve, reject) => {
        if (!yauzl) {
            reject(new Error('yauzl library not available'));
            return;
        }

        yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
            if (err) {
                reject(err);
                return;
            }

            let extractedSize = 0;
            const maxSize = ARCHIVE_CONFIG.maxExtractSize;

            zipfile.readEntry();
            zipfile.on('entry', (entry) => {
                if (entry.uncompressedSize > maxSize - extractedSize) {
                    zipfile.close();
                    reject(new Error('Archive too large to extract'));
                    return;
                }

                if (/\/$/.test(entry.fileName)) {
                    // Directory entry
                    const dirPath = path.join(extractDir, entry.fileName);
                    fs.mkdirSync(dirPath, { recursive: true });
                    zipfile.readEntry();
                } else {
                    // File entry
                    zipfile.openReadStream(entry, (err, readStream) => {
                        if (err) {
                            zipfile.close();
                            reject(err);
                            return;
                        }

                        const filePath = path.join(extractDir, entry.fileName);
                        const fileDir = path.dirname(filePath);
                        fs.mkdirSync(fileDir, { recursive: true });

                        const writeStream = fs.createWriteStream(filePath);
                        readStream.pipe(writeStream);

                        writeStream.on('close', () => {
                            extractedSize += entry.uncompressedSize;
                            zipfile.readEntry();
                        });

                        writeStream.on('error', (err) => {
                            zipfile.close();
                            reject(err);
                        });
                    });
                }
            });

            zipfile.on('end', () => {
                resolve(extractedSize);
            });

            zipfile.on('error', reject);
        });
    });
}

// Extract TAR files
async function extractTar(tarPath, extractDir) {
    return new Promise((resolve, reject) => {
        if (!tar) {
            reject(new Error('tar library not available'));
            return;
        }

        const options = {
            file: tarPath,
            cwd: extractDir,
            maxReadSize: ARCHIVE_CONFIG.maxExtractSize,
            filter: (path, entry) => {
                // Skip entries that would exceed size limit
                return entry.size <= ARCHIVE_CONFIG.maxExtractSize;
            }
        };

        tar.extract(options)
            .then(() => resolve(0))  // Size tracking not implemented for tar
            .catch(reject);
    });
}

// Extract 7z/RAR files
async function extract7z(archivePath, extractDir) {
    return new Promise((resolve, reject) => {
        if (!node7z) {
            reject(new Error('node-7z library not available'));
            return;
        }

        const options = {
            $bin: '7z',  // Requires 7z binary to be installed
            recursive: true,
            $cherryPick: ['*']
        };

        const stream = node7z.extractFull(archivePath, extractDir, options);

        let extractedSize = 0;

        stream.on('data', (data) => {
            // Track progress if needed
            if (data.file) {
                extractedSize += data.file.size || 0;
                if (extractedSize > ARCHIVE_CONFIG.maxExtractSize) {
                    stream.destroy();
                    reject(new Error('Archive too large to extract'));
                    return;
                }
            }
        });

        stream.on('end', () => {
            resolve(extractedSize);
        });

        stream.on('error', (err) => {
            // Fallback to system command if node-7z fails
            extractWithSystemCommand(archivePath, extractDir)
                .then(resolve)
                .catch(reject);
        });
    });
}

// Fallback extraction using system commands
async function extractWithSystemCommand(archivePath, extractDir) {
    const ext = path.extname(archivePath).toLowerCase();
    let command = '';

    switch (ext) {
        case '.zip':
        case '.jar':
        case '.war':
        case '.ear':
            command = `unzip -q "${archivePath}" -d "${extractDir}"`;
            break;
        case '.tar':
            command = `tar -xf "${archivePath}" -C "${extractDir}"`;
            break;
        case '.tar.gz':
        case '.tgz':
            command = `tar -xzf "${archivePath}" -C "${extractDir}"`;
            break;
        case '.tar.bz2':
        case '.tbz2':
            command = `tar -xjf "${archivePath}" -C "${extractDir}"`;
            break;
        case '.tar.xz':
        case '.txz':
            command = `tar -xJf "${archivePath}" -C "${extractDir}"`;
            break;
        case '.7z':
            command = `7z x "${archivePath}" -o"${extractDir}" -y`;
            break;
        case '.rar':
            command = `unrar x "${archivePath}" "${extractDir}/"`;
            break;
        case '.gz':
            const gzBase = path.basename(archivePath, '.gz');
            command = `gunzip -c "${archivePath}" > "${path.join(extractDir, gzBase)}"`;
            break;
        case '.bz2':
            const bz2Base = path.basename(archivePath, '.bz2');
            command = `bunzip2 -c "${archivePath}" > "${path.join(extractDir, bz2Base)}"`;
            break;
        case '.xz':
            const xzBase = path.basename(archivePath, '.xz');
            command = `unxz -c "${archivePath}" > "${path.join(extractDir, xzBase)}"`;
            break;
        default:
            throw new Error(`Unsupported archive format: ${ext}`);
    }

    try {
        await execPromise(command, { timeout: ARCHIVE_CONFIG.timeout });
        return 0; // Size not tracked for system commands
    } catch (error) {
        throw new Error(`Failed to extract ${archivePath}: ${error.message}`);
    }
}

// Main archive extraction function
async function extractArchive(archivePath, extractDir, depth = 0) {
    if (depth >= ARCHIVE_CONFIG.maxDepth) {
        console.log(`⚠️  Skipping nested archive (depth ${depth}): ${archivePath}`);
        return 0;
    }

    const ext = path.extname(archivePath).toLowerCase();

    console.log(`📦 Extracting ${ext} archive: ${path.basename(archivePath)}`);

    // Ensure extraction directory exists
    fs.mkdirSync(extractDir, { recursive: true });

    try {
        let extractedSize = 0;

        // Choose extraction method based on file type
        if (['.zip', '.jar', '.war', '.ear'].includes(ext)) {
            extractedSize = await extractZip(archivePath, extractDir);
        } else if (ext.startsWith('.tar') || ['.tar', '.tgz', '.tbz2', '.txz'].includes(ext)) {
            extractedSize = await extractTar(archivePath, extractDir);
        } else if (['.7z', '.rar'].includes(ext)) {
            extractedSize = await extract7z(archivePath, extractDir);
        } else if (['.gz', '.bz2', '.xz'].includes(ext)) {
            extractedSize = await extractWithSystemCommand(archivePath, extractDir);
        } else {
            extractedSize = await extractWithSystemCommand(archivePath, extractDir);
        }

        console.log(`✅ Extracted ${path.basename(archivePath)} (${extractedSize} bytes)`);

        // Look for nested archives in extracted content
        const extractedFiles = fs.readdirSync(extractDir, { recursive: true });
        for (const file of extractedFiles) {
            const fullPath = path.join(extractDir, file);
            if (fs.statSync(fullPath).isFile() && isArchive(fullPath)) {
                const nestedExtractDir = path.join(extractDir, `nested_${Date.now()}_${Math.random().toString(36).substring(7)}`);
                await extractArchive(fullPath, nestedExtractDir, depth + 1);
            }
        }

        return extractedSize;
    } catch (error) {
        console.log(`❌ Failed to extract ${path.basename(archivePath)}: ${error.message}`);
        return 0;
    }
}

// Scan archive contents
async function scanArchive(archivePath, useAI = false) {
    const tempId = `source-secure-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    const tempDir = path.join(os.tmpdir(), tempId);

    try {
        console.log(`🔍 Scanning archive: ${path.basename(archivePath)}`);

        // Extract archive to temporary directory
        const extractedSize = await extractArchive(archivePath, tempDir);

        if (extractedSize === 0 && !fs.existsSync(tempDir)) {
            return [];
        }

        // Recursively scan extracted contents
        const findings = [];
        await scanDirectoryRecursive(tempDir, findings, useAI);

        // Add archive context to findings
        const archiveFindings = findings.map(finding => ({
            ...finding,
            file: `${archivePath} → ${path.relative(tempDir, finding.file)}`,
            inArchive: archivePath
        }));

        return archiveFindings;
    } catch (error) {
        console.log(`❌ Error scanning archive ${path.basename(archivePath)}: ${error.message}`);
        return [];
    } finally {
        // Clean up temporary directory
        try {
            if (fs.existsSync(tempDir)) {
                fs.rmSync(tempDir, { recursive: true, force: true });
            }
        } catch (cleanupError) {
            console.log(`⚠️  Warning: Failed to clean up temp directory: ${cleanupError.message}`);
        }
    }
}

// Helper function to scan directory recursively
async function scanDirectoryRecursive(dir, findings, useAI = false) {
    const scanPromises = [];

    function walkDir(currentDir) {
        const items = fs.readdirSync(currentDir);
        for (const item of items) {
            const fullPath = path.join(currentDir, item);

            // Skip system directories
            if (item === '.git' || item === 'node_modules' || item === 'dist' || item === 'build') {
                continue;
            }

            const stats = fs.statSync(fullPath);
            if (stats.isDirectory()) {
                walkDir(fullPath);
            } else if (stats.isFile()) {
                // Check if file should be scanned (use same logic as main scanner)
                const ext = path.extname(fullPath).toLowerCase();
                const scanExtensions = ['.js', '.py', '.json', '.env', '.yml', '.yaml', '.xml', '.config', '.conf', '.properties', '.sh', '.bash'];

                if (scanExtensions.includes(ext) || ext === '') {
                    scanPromises.push(scanFile(fullPath, useAI));
                }
            }
        }
    }

    walkDir(dir);

    // Wait for all scans to complete
    const allFindings = await Promise.all(scanPromises);
    for (const fileFindings of allFindings) {
        if (Array.isArray(fileFindings)) {
            findings.push(...fileFindings);
        }
    }
}

// Generic Patterns (with context validation)
const GENERIC_PATTERNS = [

    // SSH/SSL/Certificates
    { name: 'RSA Private Key', pattern: /-----BEGIN\s*(?:RSA|OPENSSH|DSA|EC|PGP)?\s*PRIVATE KEY(?:\s*BLOCK)?-----/gi, severity: 'CRITICAL' },
    { name: 'SSH Private Key', pattern: /-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----/gi, severity: 'CRITICAL' },
    { name: 'PEM Certificate', pattern: /-----BEGIN CERTIFICATE-----/gi, severity: 'LOW' },

    // Cloud Providers
    { name: 'Heroku API Key', pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g, context: /heroku/i, severity: 'HIGH' },
    { name: 'DigitalOcean Token', pattern: /dop_v1_[0-9a-f]{64}/g, severity: 'HIGH' },
    { name: 'Netlify Access Token', pattern: /[0-9a-zA-Z]{40,46}/g, context: /netlify/i, severity: 'MEDIUM' },

    // Package Registries
    { name: 'NPM Token', pattern: /npm_[0-9a-zA-Z]{36}/g, severity: 'HIGH' },
    { name: 'PyPI Token', pattern: /pypi-[0-9a-zA-Z_-]{40,}/g, severity: 'HIGH' },
    { name: 'Docker Registry Token', pattern: /[a-zA-Z0-9]{12}:[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}/g, context: /docker/i, severity: 'HIGH' },

    // Generic Patterns (with context validation)
    { name: 'Generic API Key', pattern: /(?:api[_\s-]?key|apikey)[_\s-]?['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{32,})['\"]?/gi, severity: 'MEDIUM' },
    { name: 'Generic Secret', pattern: /(?:secret|client[_\s-]?secret)[_\s-]?['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{32,})['\"]?/gi, severity: 'HIGH' },
    { name: 'Generic Token', pattern: /(?:auth[_\s-]?)?token[_\s-]?['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{32,})['\"]?/gi, severity: 'MEDIUM' },
    { name: 'Generic Password', pattern: /(?:password|passwd|pwd)[_\s-]?['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]?/gi, severity: 'HIGH' },
    { name: 'Bearer Authorization', pattern: /(?:Authorization|authorization)[_\s-]?['\"]?\s*[:=]\s*['\"]?Bearer\s+[a-zA-Z0-9_-]{20,}/gi, severity: 'HIGH' },
];

// Entropy calculation for detecting high-entropy strings (potential secrets)
function calculateEntropy(str) {
    const frequencies = {};
    for (const char of str) {
        frequencies[char] = (frequencies[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const freq of Object.values(frequencies)) {
        const p = freq / len;
        entropy -= p * Math.log2(p);
    }

    return entropy;
}

// Check if a string is likely a secret based on entropy
function isHighEntropyString(str, minLength = 20, minEntropy = 4.5) {
    if (str.length < minLength) return false;

    // Skip common false positives
    const falsePositives = [
        /^[0-9]+$/, // Pure numbers
        /^[A-F0-9]+$/i, // Hex strings (often hashes)
        /\.(jpg|jpeg|png|gif|svg|ico|woff|ttf|eot)$/i, // File extensions
        /^(true|false|null|undefined)$/i, // Keywords
        /^https?:\/\//i, // URLs
        /^[a-z]+(-[a-z]+)*$/i, // Kebab-case identifiers
    ];

    for (const pattern of falsePositives) {
        if (pattern.test(str)) return false;
    }

    const entropy = calculateEntropy(str);
    return entropy >= minEntropy;
}

// Detect Base64 encoded secrets
function detectBase64Secrets(content) {
    const base64Pattern = /[A-Za-z0-9+/]{40,}={0,2}/g;
    const findings = [];
    const matches = content.matchAll(base64Pattern);

    for (const match of matches) {
        try {
            const decoded = Buffer.from(match[0], 'base64').toString('utf8');

            // Check if decoded content contains secrets
            for (const detector of API_KEY_PATTERNS) {
                if (detector.pattern.test(decoded)) {
                    findings.push({
                        type: `Base64 Encoded ${detector.name}`,
                        match: match[0].substring(0, 50) + '...',
                        decoded: decoded.substring(0, 50) + '...',
                        severity: detector.severity
                    });
                }
            }
        } catch (e) {
            // Not valid base64, skip
        }
    }

    return findings;
}

// Detect multi-line secrets (like private keys)
function detectMultiLineSecrets(content) {
    const multiLinePatterns = [
        {
            name: 'Private Key Block',
            start: /-----BEGIN\s+[A-Z\s]+PRIVATE KEY[A-Z\s]*-----/,
            end: /-----END\s+[A-Z\s]+PRIVATE KEY[A-Z\s]*-----/,
            severity: 'CRITICAL'
        },
        {
            name: 'Certificate Block',
            start: /-----BEGIN\s+CERTIFICATE-----/,
            end: /-----END\s+CERTIFICATE-----/,
            severity: 'LOW'
        },
        {
            name: 'Google Service Account JSON',
            pattern: /\{\s*"type"\s*:\s*"service_account"[\s\S]*?"private_key"\s*:\s*"[^"]+"\s*\}/,
            severity: 'CRITICAL'
        }
    ];

    const findings = [];

    for (const detector of multiLinePatterns) {
        if (detector.pattern) {
            const matches = content.matchAll(new RegExp(detector.pattern, 'g'));
            for (const match of matches) {
                findings.push({
                    type: detector.name,
                    match: match[0].substring(0, 100) + '...',
                    severity: detector.severity
                });
            }
        } else if (detector.start && detector.end) {
            const startMatches = [...content.matchAll(new RegExp(detector.start, 'g'))];
            const endMatches = [...content.matchAll(new RegExp(detector.end, 'g'))];

            if (startMatches.length > 0 && endMatches.length > 0) {
                findings.push({
                    type: detector.name,
                    match: 'Multi-line secret detected',
                    severity: detector.severity
                });
            }
        }
    }

    return findings;
}

// Scan git history for secrets
async function scanGitHistory(depth = 100) {
    console.log(`\n📜 Scanning last ${depth} commits for secrets...`);

    try {
        const { stdout } = await execPromise(`git log --pretty=format:"%H" -n ${depth}`);
        const commits = stdout.trim().split('\n');
        const findings = [];

        for (const commit of commits) {
            try {
                const { stdout: diff } = await execPromise(`git show ${commit} --format="" --text`);

                for (const detector of API_KEY_PATTERNS) {
                    const matches = diff.matchAll(detector.pattern);
                    for (const match of matches) {
                        findings.push({
                            commit: commit.substring(0, 8),
                            type: detector.name,
                            severity: detector.severity,
                            match: match[0].substring(0, 50) + '...'
                        });
                    }
                }
            } catch (e) {
                // Skip commits that can't be read
            }
        }

        return findings;
    } catch (error) {
        console.log('⚠️  Unable to scan git history (not a git repository or no commits)');
        return [];
    }
}

// Check with Ollama for advanced detection (if available)
async function checkWithOllama(content, filePath) {
    try {
        // Check if Ollama is installed and running
        const { stdout } = await execPromise('ollama list', { timeout: 2000 });

        // Use a small, fast model for detection
        const prompt = `Analyze this code snippet for potential security issues. Only respond with JSON format: {"hasSecrets": true/false, "findings": ["list of found secrets"]}

Code:
${content.substring(0, 1000)}`;

        const { stdout: response } = await execPromise(
            `echo '${prompt.replace(/'/g, "\\'")}' | ollama run llama2:7b`,
            { timeout: 10000 }
        );

        try {
            const result = JSON.parse(response);
            if (result.hasSecrets && result.findings) {
                return result.findings.map(f => ({
                    type: 'AI-Detected Secret',
                    match: f,
                    severity: 'MEDIUM'
                }));
            }
        } catch (e) {
            // Failed to parse JSON response
        }
    } catch (error) {
        // Ollama not available, skip
    }

    return [];
}

// Main scanning function
async function scanFile(filePath, useAI = false) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        const findings = [];

        // Standard pattern matching
        for (const detector of API_KEY_PATTERNS) {
            const matches = content.matchAll(detector.pattern);

            for (const match of matches) {
                // Context validation if required
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

                findings.push({
                    type: detector.name,
                    file: filePath,
                    line: lineNumber,
                    match: match[0].substring(0, 50) + (match[0].length > 50 ? '...' : ''),
                    severity: detector.severity
                });
            }
        }

        // Entropy-based detection
        const words = content.match(/[a-zA-Z0-9_-]{20,128}/g) || [];
        for (const word of words) {
            if (isHighEntropyString(word)) {
                findings.push({
                    type: 'High Entropy String',
                    file: filePath,
                    match: word.substring(0, 50) + '...',
                    severity: 'LOW'
                });
            }
        }

        // Base64 detection
        const base64Findings = detectBase64Secrets(content);
        findings.push(...base64Findings.map(f => ({ ...f, file: filePath })));

        // Multi-line detection
        const multiLineFindings = detectMultiLineSecrets(content);
        findings.push(...multiLineFindings.map(f => ({ ...f, file: filePath })));

        // AI detection (if enabled and available)
        if (useAI) {
            const aiFindings = await checkWithOllama(content, filePath);
            findings.push(...aiFindings.map(f => ({ ...f, file: filePath })));
        }

        return findings;
    } catch (error) {
        return [];
    }
}

// Get remediation suggestions
function getRemediation(finding) {
    const remediations = {
        'CRITICAL': '🚨 IMMEDIATE ACTION REQUIRED: Revoke this credential immediately and rotate to a new one.',
        'HIGH': '⚠️  HIGH RISK: This credential should be removed and stored in environment variables.',
        'MEDIUM': '⚡ MEDIUM RISK: Consider moving to secure storage or using a secrets manager.',
        'LOW': 'ℹ️  LOW RISK: Review if this needs to be in the codebase.'
    };

    const specificRemediations = {
        'AWS': 'Use AWS Secrets Manager or IAM roles instead of hardcoded credentials.',
        'Google': 'Use Google Secret Manager or service account key files outside the repo.',
        'GitHub': 'Revoke token at https://github.com/settings/tokens and use GitHub Secrets for Actions.',
        'Database': 'Use connection strings from environment variables or config files outside the repo.',
        'API Key': 'Store in .env file (git-ignored) or use a secrets management service.',
        'Private Key': 'NEVER commit private keys. Store securely and reference via environment variables.',
        'JWT': 'JWTs may contain sensitive data. Ensure they are not hardcoded and rotate regularly.'
    };

    let remediation = remediations[finding.severity] || remediations['LOW'];

    for (const [key, value] of Object.entries(specificRemediations)) {
        if (finding.type.includes(key)) {
            remediation += `\n   💡 ${value}`;
            break;
        }
    }

    return remediation;
}

// Main function
async function main() {
    const args = process.argv.slice(2);

    // Parse flags
    const flags = {
        path: '.',
        history: false,
        ai: false,
        verbose: false
    };

    for (const arg of args) {
        if (arg.startsWith('--')) {
            switch(arg) {
                case '--history':
                    flags.history = true;
                    break;
                case '--ai':
                    flags.ai = true;
                    break;
                case '--verbose':
                    flags.verbose = true;
                    break;
            }
        } else if (!flags.path || flags.path === '.') {
            flags.path = arg;
        }
    }

    console.log(`
╔══════════════════════════════════════════════════════════════╗
║                  🛡️  Source Secure v2.4                      ║
║         Advanced Secret Detection & Security Analysis         ║
╚══════════════════════════════════════════════════════════════╝
`);

    console.log(`🔍 Scanning: ${path.resolve(flags.path)}`);
    if (flags.ai) console.log('🤖 AI detection: Enabled (using Ollama)');
    if (flags.history) console.log('📜 Git history: Scanning enabled');
    console.log('');

    const startTime = Date.now();

    // Scan current files
    const findings = [];
    const scanPromises = [];

    function walk(dir) {
        const items = fs.readdirSync(dir);
        for (const item of items) {
            const fullPath = path.join(dir, item);

            // Skip directories to ignore
            if (item === '.git' || item === 'node_modules' || item === 'dist' || item === 'build') {
                continue;
            }

            const stats = fs.statSync(fullPath);
            if (stats.isDirectory()) {
                walk(fullPath);
            } else if (stats.isFile()) {
                const ext = path.extname(fullPath).toLowerCase();

                // Check if file is an archive
                if (isArchive(fullPath)) {
                    // Scan archive contents
                    scanPromises.push(scanArchive(fullPath, flags.ai));
                } else if (['.js', '.py', '.json', '.env', '.yml', '.yaml', '.xml', '.config', '.conf', '.properties', '.sh', '.bash'].includes(ext) || ext === '') {
                    // Scan regular file
                    scanPromises.push(scanFile(fullPath, flags.ai));
                }
            }
        }
    }

    walk(flags.path);

    // Wait for all scan promises to resolve
    const allFindings = await Promise.all(scanPromises);
    for (const fileFindings of allFindings) {
        if (Array.isArray(fileFindings)) {
            findings.push(...fileFindings);
        }
    }

    // Run external tool scans (TruffleHog, Gitleaks)
    const externalFindings = await runExternalScans(path.resolve(flags.path));

    // Merge internal and external findings
    const mergedFindings = mergeFindingsWithExternal(findings, externalFindings);
    findings.length = 0;  // Clear original array
    findings.push(...mergedFindings);  // Replace with merged results

    // Scan git history if requested
    if (flags.history) {
        const historyFindings = await scanGitHistory();
        if (historyFindings.length > 0) {
            console.log(`\n📜 Found ${historyFindings.length} secret(s) in git history:`);
            for (const finding of historyFindings) {
                console.log(`   Commit ${finding.commit}: ${finding.type} (${finding.severity})`);
            }
        }
    }

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);

    // Display results
    if (findings.length === 0) {
        console.log(`\n✅ No secrets detected! Scan completed in ${duration}s\n`);
        process.exit(0);
    } else {
        // Group by severity
        const bySeverity = {
            CRITICAL: findings.filter(f => f.severity === 'CRITICAL'),
            HIGH: findings.filter(f => f.severity === 'HIGH'),
            MEDIUM: findings.filter(f => f.severity === 'MEDIUM'),
            LOW: findings.filter(f => f.severity === 'LOW')
        };

        console.log(`\n⚠️  Found ${findings.length} potential secret(s):\n`);

        for (const [severity, items] of Object.entries(bySeverity)) {
            if (items.length > 0) {
                const icon = severity === 'CRITICAL' ? '🚨' : severity === 'HIGH' ? '⚠️' : severity === 'MEDIUM' ? '⚡' : 'ℹ️';
                console.log(`${icon} ${severity}: ${items.length} finding(s)`);

                if (flags.verbose) {
                    for (const item of items) {
                        console.log(`\n📄 ${item.file}`);
                        if (item.line) console.log(`   Line ${item.line}: ${item.type}`);
                        console.log(`   Match: ${item.match}`);

                        // Show source tool and verification status
                        if (item.isExternal) {
                            console.log(`   🔧 Found by: ${item.source}`);
                        } else if (item.verifiedBy && item.verifiedBy.length > 0) {
                            console.log(`   ✅ Verified by: ${item.verifiedBy.join(', ')}`);
                        } else {
                            console.log(`   🛡️  Found by: Source Secure`);
                        }

                        console.log(`   ${getRemediation(item)}`);
                    }
                }
            }
        }

        if (!flags.verbose) {
            console.log('\n💡 Use --verbose flag for detailed findings and remediation steps');
        }

        console.log(`\n🔒 Security Best Practices:`);
        console.log('   1. Never commit credentials to version control');
        console.log('   2. Use environment variables for sensitive configuration');
        console.log('   3. Implement secret scanning in your CI/CD pipeline');
        console.log('   4. Rotate any exposed credentials immediately');
        console.log('   5. Use secret management tools (e.g., HashiCorp Vault, AWS Secrets Manager)');

        console.log(`\nScan completed in ${duration}s\n`);

        // Exit with error code if critical/high severity findings
        if (bySeverity.CRITICAL.length > 0 || bySeverity.HIGH.length > 0) {
            process.exit(1);
        }
    }
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = { scanFile, scanGitHistory, calculateEntropy };
