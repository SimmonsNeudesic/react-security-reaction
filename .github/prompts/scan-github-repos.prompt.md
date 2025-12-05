---
title: Scan GitHub Repositories for Security Vulnerabilities
description: Scans accessible GitHub repositories for CVE-2025-66478 vulnerability and generates a comprehensive security report including Dependabot status
parameters:
  - name: owner
    description: GitHub owner/org to scan (defaults to current authenticated user)
    default: ""
  - name: filter-language
    description: Filter repos by primary language (e.g., TypeScript, JavaScript)
    default: ""
  - name: include-forks
    description: Include forked repositories in the scan
    default: "FALSE"
  - name: output-format
    description: Report output format (markdown, csv, json)
    default: "markdown"
  - name: report-path
    description: Path to save the report file
    default: "github-security-scan-report.md"
  - name: limit
    description: Maximum number of repos to scan (0 = all)
    default: "0"
  - name: workers
    description: Number of parallel workers for scanning
    default: "5"
---

# GitHub Repository Security Scanner

This prompt scans your accessible GitHub repositories to identify:
1. **CVE-2025-66478 Vulnerability** - Critical RCE in React Server Components
2. **Dependabot Status** - Whether repos have Dependabot enabled/configured
3. **Security Settings** - Overall security posture of each repository

**Configuration:**
- Owner/Org: `{{owner}}` (blank = current user's repos)
- Language Filter: `{{filter-language}}`
- Include Forks: `{{include-forks}}`
- Output Format: `{{output-format}}`
- Report Path: `{{report-path}}`
- Limit: `{{limit}}` repos (0 = all)
- Workers: `{{workers}}` parallel threads

---

## Execution Method

**This prompt uses a Python script for efficient scanning at scale.**

The script `scripts/scan-github-repos.py` handles:
- Parallel scanning of hundreds of repositories
- Git Trees API for reliable package.json discovery (no indexing delays)
- In-memory base64 decoding and JSON parsing
- Comprehensive vulnerability pattern matching
- Multiple output formats (markdown, CSV, JSON)

### Prerequisites

1. **GitHub CLI (gh)** must be installed and authenticated:
   ```bash
   gh auth login
   gh auth status  # Verify authentication
   ```

2. **Python 3.8+** must be available

3. **For organization scanning with SSO:** Ensure your token is authorized:
   ```bash
   gh auth refresh -s read:org
   ```

---

## Run the Scanner

Execute the Python script with the configured parameters:

```bash
python scripts/scan-github-repos.py \
  --owner "{{owner}}" \
  --format "{{output-format}}" \
  --output "{{report-path}}" \
  --limit {{limit}} \
  --workers {{workers}}
```

**Add optional flags as needed:**
- `--language "{{filter-language}}"` — Filter by language
- `--include-forks` — Include forked repositories
- `--quiet` — Suppress progress output

### Example Commands

```bash
# Scan your own repositories
python scripts/scan-github-repos.py

# Scan an organization (e.g., neudesic)
python scripts/scan-github-repos.py --owner neudesic

# Scan with limits for large orgs
python scripts/scan-github-repos.py --owner neudesic --limit 100 --workers 10

# Generate CSV report
python scripts/scan-github-repos.py --owner neudesic --format csv --output audit.csv

# Filter to TypeScript projects only  
python scripts/scan-github-repos.py --owner neudesic --language TypeScript
```

---

## What the Script Does

### Phase 1: Repository Discovery
- Lists all repositories for the specified owner/org
- Filters by language and fork status
- Applies limit if specified

### Phase 2: Security Configuration Audit
For each repository:
- Fetches security settings (Dependabot, secret scanning)
- Checks for `.github/dependabot.yml` configuration file
- Classifies Dependabot status as: Configured / Partial / Not Configured

### Phase 3: Vulnerability Scanning
For repositories with JavaScript/TypeScript:
- Uses Git Trees API (`recursive=1`) to find ALL `package.json` files
- Decodes and parses each package.json in-memory
- Checks for vulnerable versions of:
  - `next` (15.0.0-15.0.4, 15.1.0-15.1.8, etc.)
  - `react` (19.0.0, 19.1.0, 19.1.1, 19.2.0)
  - `react-server-dom-*` packages

### Phase 4: Report Generation
Generates comprehensive report with:
- Executive summary with counts
- Detailed vulnerability findings with remediation commands
- Dependabot status matrix for all repos
- Prioritized recommendations

---

## Output

The script exits with:
- **Exit code 0**: No vulnerabilities found
- **Exit code 1**: Error during scanning
- **Exit code 2**: Vulnerabilities found (review report)

### Sample Output

```
🔐 Authenticated as: SimmonsNeudesic
📂 Scanning: neudesic
📋 Listing repositories...
   Found 523 repositories
🔍 Scanning for vulnerabilities (using 10 workers)...
   [1/523] neudesic/project-alpha ✅
   [2/523] neudesic/project-beta 🚨 VULNERABLE
   ...

✅ Scan complete!
📊 Results:
   • Repositories scanned: 523
   • Vulnerable: 3 ⚠️
   • Dependabot enabled: 127/523
📁 Report saved to: github-security-scan-report.md
```

---

## Agent Instructions

When this prompt is invoked:

1. **DO NOT** manually iterate through repositories or make individual API calls
2. **DO** run the Python script with appropriate parameters
3. **DO** verify the script exists at `scripts/scan-github-repos.py`
4. **DO** present the summary output and offer to display report contents
5. **DO** suggest next steps based on findings

If the script is not found, instruct the user to ensure they have the `react-security-reaction` repository cloned and are running from its root directory.

---

## Troubleshooting

### "Could not get authenticated user"
```bash
gh auth login
```

### "403 Forbidden" on organization repos
```bash
gh auth refresh -h github.com -s read:org
# For SSO-protected orgs, authorize the token in GitHub settings
```

### Rate limiting
- Reduce `--workers` to 2-3
- Add `--limit` to scan fewer repos
- Wait and retry

### Script not found
Ensure you're running from the repository root:
```bash
cd /path/to/react-security-reaction
python scripts/scan-github-repos.py --help
```
