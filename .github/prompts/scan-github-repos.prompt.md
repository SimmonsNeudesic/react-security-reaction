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

## Agent Execution Constraints (IMPORTANT)

- Use only the GitHub MCP tools and the GitHub CLI (`gh`) described in this prompt.
- Do NOT create, write, or modify any PowerShell, Bash, or other helper scripts as a local or repository file during prompt execution. This does not prevent you from generating the final report file specified by `{{report-path}}`.
- Process fetched file contents in-memory and return structured results (JSON/markdown/csv) as the prompt output rather than emitting new files on disk.
- If you need to demonstrate decoding or parsing, show a one-line example (PowerShell or POSIX) for a human operator to run manually — do not execute or generate helper scripts as part of the agent run.
- If `gh` is not available in the execution environment, prefer MCP tools (e.g., `mcp_github_search_code`) and describe required `gh` commands for operators instead of creating files.

The remainder of this prompt assumes the agent will follow these constraints strictly.

---

## PHASE 1: Discover Repositories

### Step 1.1: Get Current User Context

First, identify the authenticated GitHub user to understand the scope of accessible repositories:

```
Use the GitHub MCP tool to get the current user info (mcp_github_get_me or equivalent).
Store the login name for later use.
```

### Step 1.2: List Accessible Repositories

Gather all repositories the user can access:

**If `{{owner}}` is specified:**
- Use GitHub CLI: `gh api --paginate /users/{{owner}}/repos` or `gh api --paginate /orgs/{{owner}}/repos`

**If `{{owner}}` is blank (default):**
- Use GitHub CLI: `gh api --paginate /user/repos`

**Apply filters:**
- If `{{filter-language}}` is set, filter to only repos with that primary language
- If `{{include-forks}}` is FALSE, exclude repos where `fork: true`

**For each repository, collect:**
- `full_name` (owner/repo)
- `name`
- `private` (true/false)
- `language`
- `default_branch`
- `html_url`

---

## PHASE 2: Security Configuration Audit

For each repository discovered in Phase 1, gather security configuration:

### Step 2.1: Check Security & Analysis Settings

Use GitHub CLI to get security settings:
```powershell
gh api /repos/{owner}/{repo} --jq '{
  name: .name,
  full_name: .full_name,
  private: .private,
  language: .language,
  security_and_analysis: .security_and_analysis
}'
```

**Extract for each repo:**
- `dependabot_security_updates.status` (enabled/disabled/null)
- `secret_scanning.status`
- `secret_scanning_push_protection.status`

### Step 2.2: Check for Dependabot Configuration File

Check if `.github/dependabot.yml` exists:
```powershell
gh api /repos/{owner}/{repo}/contents/.github/dependabot.yml --jq '.name' 2>&1
```

**Classification:**
- **Configured**: File exists AND `security_and_analysis.dependabot_security_updates.status` = "enabled"
- **Partial**: File exists but security updates disabled, OR no file but security updates enabled
- **Not Configured**: No file AND security updates disabled/null

---

## PHASE 3: Vulnerability Scanning

For repositories that could contain vulnerable packages (JavaScript/TypeScript projects):

### Step 3.1: Find package.json Files

**Primary method (REQUIRED):** Use the Git Trees API with recursive traversal to reliably find all `package.json` files in the repository. This method works immediately for all files (unlike code search which has indexing delays):

```bash
gh api /repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1 --jq '.tree[] | select(.path | endswith("package.json")) | .path'
```

This returns paths like:
- `package.json` (root)
- `vulnerable-app/package.json` (subdirectory)
- `packages/frontend/package.json` (monorepo)

**Fallback method (optional):** If the git trees API fails, try code search (note: recently pushed files may not be indexed):
```bash
gh api '/search/code?q=filename:package.json+repo:{owner}/{repo}' --jq '.items[].path'
```

**IMPORTANT:** Do NOT skip subdirectories. Many projects store applications in subfolders (e.g., `apps/`, `packages/`, `src/`, or named folders like `vulnerable-app/`). The git trees recursive method captures ALL package.json files regardless of depth.

### Step 3.2: Analyze Each package.json

For each package.json found, decode and extract versions. Agents must NOT write helper scripts or temporary files to disk. Use in-memory decoding and parsing. Example one-liners shown for human operators only:

PowerShell (in-memory decode example — for human operator):
```powershell
$encoded = (gh api /repos/{owner}/{repo}/contents/{path-to-package.json} --jq '.content')
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(($encoded -replace '\s','')))
$pkg = $decoded | ConvertFrom-Json
```

POSIX shell (human-run one-liner):
```bash
gh api /repos/{owner}/{repo}/contents/{path-to-package.json} --jq '.content' | base64 --decode | jq .
```

Agents should parse `package.json` content in-memory using available tools and return the parsed dependency versions as structured data in the prompt output.

**Extract relevant dependencies:**
- `next` (dependencies or devDependencies)
- `react`
- `react-dom`
- `react-server-dom-webpack`
- `react-server-dom-parcel`
- `react-server-dom-turbopack`

### Step 3.3: Vulnerability Pattern Matching

Check extracted versions against vulnerable patterns:

**Vulnerable Next.js Versions:**
| Pattern | Vulnerable Range | Patched Version |
|---------|-----------------|-----------------|
| `^15.0.[0-4]` | 15.0.0 - 15.0.4 | 15.0.5 |
| `^15.1.[0-8]` | 15.1.0 - 15.1.8 | 15.1.9 |
| `^15.2.[0-5]` | 15.2.0 - 15.2.5 | 15.2.6 |
| `^15.3.[0-5]` | 15.3.0 - 15.3.5 | 15.3.6 |
| `^15.4.[0-7]` | 15.4.0 - 15.4.7 | 15.4.8 |
| `^15.5.[0-6]` | 15.5.0 - 15.5.6 | 15.5.7 |
| `^16.0.[0-6]` | 16.0.0 - 16.0.6 | 16.0.7 |
| `14.3.0-canary.*` | All canary builds | 14.x stable |

**Vulnerable React Versions:**
- `19.0.0` (patched: 19.0.1)
- `19.1.0`, `19.1.1` (patched: 19.1.2)
- `19.2.0` (patched: 19.2.1)

**Safe (Not Vulnerable):**
- React 18.x (all versions)
- Next.js 13.x (all versions)
- Next.js 14.x stable (before canary builds)
- Projects using only client-side React

---

## PHASE 4: Generate Report

### Report Structure

Create a comprehensive markdown report with the following sections:

#### Executive Summary
```markdown
# GitHub Repository Security Scan Report

**Scan Date:** [Current Date]
**Scanned By:** [GitHub Username]
**Owner/Org:** {{owner}} or [Username]
**Total Repositories Scanned:** [count]

## Summary

| Metric | Count |
|--------|-------|
| Total Repos | [n] |
| Vulnerable (CVE-2025-66478) | [n] |
| Potentially At Risk | [n] |
| Safe / Not Applicable | [n] |
| Dependabot Enabled | [n] |
| Dependabot Configured | [n] |
| No Security Config | [n] |
```

#### Vulnerability Findings
```markdown
## 🚨 Critical Vulnerabilities Detected

### [Repo Name 1]
- **Repository:** [owner/repo](url)
- **Visibility:** Public/Private
- **CVE:** CVE-2025-66478 / CVE-2025-55182
- **CVSS:** 10.0 (Critical)
- **Affected Package:** next@15.2.0
- **Location:** `eCommApp/package.json`
- **Remediation:** `npm install next@15.2.6`

### [Repo Name 2]
...
```

#### Dependabot Status Matrix
```markdown
## Dependabot Configuration Status

| Repository | Visibility | Config File | Security Updates | Status |
|------------|------------|-------------|------------------|--------|
| repo-name-1 | Public | ✅ Yes | ✅ Enabled | ✅ Configured |
| repo-name-2 | Private | ❌ No | ❌ Disabled | ⚠️ Not Configured |
| repo-name-3 | Public | ✅ Yes | ❌ Disabled | ⚠️ Partial |
```

#### Security Recommendations
```markdown
## Recommendations

### Immediate Actions (Critical)
1. Repositories with CVE-2025-66478 vulnerability require immediate patching
2. [List specific repos and commands]

### High Priority
1. Enable Dependabot for repos without security scanning
2. Add `.github/dependabot.yml` to repos missing configuration

### General Recommendations
1. Enable secret scanning on all repositories
2. Enable push protection for secrets
3. Consider enabling GitHub Advanced Security for private repos
```

---

## PHASE 5: Save and Present Results

### Step 5.1: Save Report

Save the generated report to `{{report-path}}`:
- If `{{output-format}}` is "markdown": Save as .md file
- If `{{output-format}}` is "csv": Generate CSV with columns for each metric
- If `{{output-format}}` is "json": Generate structured JSON output

### Step 5.2: Summary Output

Present a concise summary to the user:

```
✅ GitHub Security Scan Complete

📊 Results Summary:
   • Repositories Scanned: [n]
   • Vulnerable: [n] ⚠️
   • Dependabot Enabled: [n]/[total]

📁 Full report saved to: {{report-path}}

⚡ Next Steps:
   1. Review vulnerable repositories immediately
   2. Run /check-react-vulnerability-cve-2025-66478 on affected repos
   3. Enable Dependabot on unprotected repositories
```

---

## Execution Notes

### MCP Tools Available
This prompt can leverage the following GitHub MCP tools:
- `mcp_github_search_repositories` - Search for repos by criteria
- `mcp_github_search_code` - Search for code patterns across repos
- GitHub CLI (`gh`) - For API calls not available via MCP

### Permissions Required
- `repo` scope for private repository access
- `read:org` scope for organization repository listing
- Repository admin access to view some security settings

### Limitations
- Cannot access repos in organizations where you don't have membership
- Private repos in other accounts require explicit collaboration
- Some security settings only visible to admins
- GitHub code search has rate limits

### Error Handling
- If a repo cannot be accessed, log it and continue
- If package.json decode fails, mark as "Unable to scan"
- If API rate limited, pause and retry with exponential backoff

---

## Example Usage

### Scan your own repositories
```
/scan-github-repos
```

### Scan a specific organization
```
/scan-github-repos owner=neudesic
```

### Scan only TypeScript projects
```
/scan-github-repos filter-language=TypeScript
```

### Generate CSV report
```
/scan-github-repos output-format=csv report-path=security-audit.csv
```
