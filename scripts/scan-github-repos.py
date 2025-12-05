#!/usr/bin/env python3
"""
GitHub Repository Security Scanner for CVE-2025-66478

Scans accessible GitHub repositories for:
1. CVE-2025-66478 vulnerability in React Server Components
2. Dependabot configuration status
3. Security settings (secret scanning, push protection)

Usage:
    python scan-github-repos.py [options]

Examples:
    python scan-github-repos.py                           # Scan your repos
    python scan-github-repos.py --owner neudesic          # Scan an org
    python scan-github-repos.py --owner neudesic --limit 100
    python scan-github-repos.py --format csv --output report.csv

Requirements:
    - GitHub CLI (gh) installed and authenticated
    - Python 3.8+
    - No additional packages required (uses stdlib only)
"""

import argparse
import base64
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


# =============================================================================
# Vulnerability Patterns
# =============================================================================

VULNERABLE_NEXT_PATTERNS = [
    (r"^15\.0\.[0-4]$", "15.0.5"),      # 15.0.0-15.0.4 → 15.0.5
    (r"^15\.1\.[0-8]$", "15.1.9"),      # 15.1.0-15.1.8 → 15.1.9
    (r"^15\.2\.[0-5]$", "15.2.6"),      # 15.2.0-15.2.5 → 15.2.6
    (r"^15\.3\.[0-5]$", "15.3.6"),      # 15.3.0-15.3.5 → 15.3.6
    (r"^15\.4\.[0-7]$", "15.4.8"),      # 15.4.0-15.4.7 → 15.4.8
    (r"^15\.5\.[0-6]$", "15.5.7"),      # 15.5.0-15.5.6 → 15.5.7
    (r"^16\.0\.[0-6]$", "16.0.7"),      # 16.0.0-16.0.6 → 16.0.7
    (r"^14\.3\.0-canary", "14.2.x"),    # canary builds
]

VULNERABLE_REACT_VERSIONS = {
    "19.0.0": "19.0.1",
    "19.1.0": "19.1.2",
    "19.1.1": "19.1.2",
    "19.2.0": "19.2.1",
}

VULNERABLE_RSC_PACKAGES = [
    "react-server-dom-webpack",
    "react-server-dom-parcel",
    "react-server-dom-turbopack",
]


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Vulnerability:
    package: str
    version: str
    patched_version: str
    location: str  # path to package.json
    cve: str = "CVE-2025-66478"
    cvss: float = 10.0


@dataclass
class RepoSecurityStatus:
    full_name: str
    name: str
    html_url: str
    private: bool
    language: Optional[str]
    default_branch: str
    fork: bool
    # Security settings
    dependabot_security_updates: Optional[str] = None  # enabled/disabled/null
    dependabot_config_exists: bool = False
    secret_scanning: Optional[str] = None
    secret_scanning_push_protection: Optional[str] = None
    # Vulnerability findings
    vulnerabilities: list = field(default_factory=list)
    package_json_paths: list = field(default_factory=list)
    scan_error: Optional[str] = None

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def dependabot_status(self) -> str:
        if self.dependabot_config_exists and self.dependabot_security_updates == "enabled":
            return "Configured"
        elif self.dependabot_config_exists or self.dependabot_security_updates == "enabled":
            return "Partial"
        else:
            return "Not Configured"


# =============================================================================
# GitHub CLI Helpers
# =============================================================================

def run_gh_api(endpoint: str, jq_filter: Optional[str] = None) -> tuple[bool, str]:
    """Run a gh api command and return (success, output)."""
    cmd = ["gh", "api", endpoint]
    if jq_filter:
        cmd.extend(["--jq", jq_filter])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            return False, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except FileNotFoundError:
        return False, "GitHub CLI (gh) not found. Please install it."


def run_gh_api_paginate(endpoint: str, jq_filter: Optional[str] = None) -> tuple[bool, str]:
    """Run a paginated gh api command."""
    cmd = ["gh", "api", "--paginate", endpoint]
    if jq_filter:
        cmd.extend(["--jq", jq_filter])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            return False, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "Timeout during pagination"
    except FileNotFoundError:
        return False, "GitHub CLI (gh) not found"


# =============================================================================
# Repository Discovery
# =============================================================================

def get_current_user() -> Optional[str]:
    """Get the authenticated GitHub username."""
    success, output = run_gh_api("/user", ".login")
    return output if success else None


def list_repositories(owner: Optional[str], include_forks: bool, language_filter: Optional[str], limit: int) -> list[dict]:
    """List repositories for a user or organization."""
    if owner:
        # Try org first, fall back to user
        success, output = run_gh_api_paginate(
            f"/orgs/{owner}/repos",
            f'[.[] | {{full_name, name, html_url, private, language, default_branch, fork}}]'
        )
        if not success:
            success, output = run_gh_api_paginate(
                f"/users/{owner}/repos",
                f'[.[] | {{full_name, name, html_url, private, language, default_branch, fork}}]'
            )
    else:
        success, output = run_gh_api_paginate(
            "/user/repos",
            '[.[] | {full_name, name, html_url, private, language, default_branch, fork}]'
        )
    
    if not success:
        print(f"Error listing repos: {output}", file=sys.stderr)
        return []
    
    # Parse JSON (paginated output is multiple JSON arrays)
    repos = []
    for line in output.split('\n'):
        line = line.strip()
        if line and line.startswith('['):
            try:
                repos.extend(json.loads(line))
            except json.JSONDecodeError:
                pass
    
    # Apply filters
    if not include_forks:
        repos = [r for r in repos if not r.get('fork', False)]
    
    if language_filter:
        repos = [r for r in repos if r.get('language', '').lower() == language_filter.lower()]
    
    # Apply limit
    if limit > 0:
        repos = repos[:limit]
    
    return repos


# =============================================================================
# Security Scanning
# =============================================================================

def get_repo_security_settings(repo_full_name: str) -> dict:
    """Get security settings for a repository."""
    success, output = run_gh_api(
        f"/repos/{repo_full_name}",
        '{security_and_analysis}'
    )
    
    if not success:
        return {}
    
    try:
        data = json.loads(output)
        sa = data.get('security_and_analysis') or {}
        return {
            'dependabot_security_updates': sa.get('dependabot_security_updates', {}).get('status'),
            'secret_scanning': sa.get('secret_scanning', {}).get('status'),
            'secret_scanning_push_protection': sa.get('secret_scanning_push_protection', {}).get('status'),
        }
    except json.JSONDecodeError:
        return {}


def check_dependabot_config(repo_full_name: str) -> bool:
    """Check if .github/dependabot.yml exists."""
    success, _ = run_gh_api(f"/repos/{repo_full_name}/contents/.github/dependabot.yml", ".name")
    return success


def find_package_json_files(repo_full_name: str, default_branch: str) -> list[str]:
    """Find all package.json files in a repository using git trees API."""
    success, output = run_gh_api(
        f"/repos/{repo_full_name}/git/trees/{default_branch}?recursive=1",
        '[.tree[] | select(.path | endswith("package.json")) | .path]'
    )
    
    if not success:
        return []
    
    try:
        paths = json.loads(output)
        # Filter out node_modules
        return [p for p in paths if 'node_modules' not in p]
    except json.JSONDecodeError:
        return []


def get_package_json_content(repo_full_name: str, path: str) -> Optional[dict]:
    """Fetch and decode a package.json file."""
    success, output = run_gh_api(f"/repos/{repo_full_name}/contents/{path}", ".content")
    
    if not success:
        return None
    
    try:
        # Decode base64
        decoded = base64.b64decode(output.replace('\n', '').replace(' ', '')).decode('utf-8')
        return json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return None


def extract_version(version_spec: str) -> Optional[str]:
    """Extract actual version from npm version specifier (^1.2.3 -> 1.2.3)."""
    if not version_spec:
        return None
    # Remove ^, ~, >=, etc.
    match = re.search(r'(\d+\.\d+\.\d+(?:-[\w.]+)?)', version_spec)
    return match.group(1) if match else None


def check_vulnerability(package: str, version: str) -> Optional[tuple[str, str]]:
    """Check if a package version is vulnerable. Returns (patched_version, cve) or None."""
    if not version:
        return None
    
    actual_version = extract_version(version)
    if not actual_version:
        return None
    
    # Check Next.js
    if package == "next":
        for pattern, patched in VULNERABLE_NEXT_PATTERNS:
            if re.match(pattern, actual_version):
                return patched, "CVE-2025-66478"
    
    # Check React
    if package == "react":
        if actual_version in VULNERABLE_REACT_VERSIONS:
            return VULNERABLE_REACT_VERSIONS[actual_version], "CVE-2025-55182"
    
    # Check RSC packages
    if package in VULNERABLE_RSC_PACKAGES:
        if actual_version in VULNERABLE_REACT_VERSIONS:
            return VULNERABLE_REACT_VERSIONS[actual_version], "CVE-2025-55182"
    
    return None


def scan_package_json(repo_full_name: str, path: str, content: dict) -> list[Vulnerability]:
    """Scan a package.json for vulnerable dependencies."""
    vulnerabilities = []
    
    # Check both dependencies and devDependencies
    all_deps = {}
    all_deps.update(content.get('dependencies', {}))
    all_deps.update(content.get('devDependencies', {}))
    
    packages_to_check = ['next', 'react', 'react-dom'] + VULNERABLE_RSC_PACKAGES
    
    for pkg in packages_to_check:
        if pkg in all_deps:
            result = check_vulnerability(pkg, all_deps[pkg])
            if result:
                patched, cve = result
                vulnerabilities.append(Vulnerability(
                    package=pkg,
                    version=extract_version(all_deps[pkg]) or all_deps[pkg],
                    patched_version=patched,
                    location=path,
                    cve=cve,
                ))
    
    return vulnerabilities


def scan_repository(repo: dict) -> RepoSecurityStatus:
    """Scan a single repository for security issues."""
    full_name = repo['full_name']
    default_branch = repo.get('default_branch', 'main')
    
    status = RepoSecurityStatus(
        full_name=full_name,
        name=repo['name'],
        html_url=repo['html_url'],
        private=repo.get('private', False),
        language=repo.get('language'),
        default_branch=default_branch,
        fork=repo.get('fork', False),
    )
    
    try:
        # Get security settings
        settings = get_repo_security_settings(full_name)
        status.dependabot_security_updates = settings.get('dependabot_security_updates')
        status.secret_scanning = settings.get('secret_scanning')
        status.secret_scanning_push_protection = settings.get('secret_scanning_push_protection')
        
        # Check dependabot config
        status.dependabot_config_exists = check_dependabot_config(full_name)
        
        # Find and scan package.json files
        package_paths = find_package_json_files(full_name, default_branch)
        status.package_json_paths = package_paths
        
        for path in package_paths:
            content = get_package_json_content(full_name, path)
            if content:
                vulns = scan_package_json(full_name, path, content)
                status.vulnerabilities.extend(vulns)
    
    except Exception as e:
        status.scan_error = str(e)
    
    return status


# =============================================================================
# Report Generation
# =============================================================================

def generate_markdown_report(results: list[RepoSecurityStatus], owner: str, scan_user: str) -> str:
    """Generate a Markdown security report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    vulnerable_repos = [r for r in results if r.is_vulnerable]
    dependabot_enabled = sum(1 for r in results if r.dependabot_security_updates == "enabled")
    dependabot_configured = sum(1 for r in results if r.dependabot_status == "Configured")
    with_package_json = sum(1 for r in results if r.package_json_paths)
    
    report = f"""# GitHub Repository Security Scan Report

**Scan Date:** {now}
**Scanned By:** {scan_user}
**Owner/Org:** {owner or scan_user}
**Total Repositories Scanned:** {len(results)}

## Summary

| Metric | Count |
|--------|-------|
| Total Repos | {len(results)} |
| Repos with package.json | {with_package_json} |
| Vulnerable (CVE-2025-66478) | {len(vulnerable_repos)} |
| Dependabot Security Updates Enabled | {dependabot_enabled} |
| Dependabot Fully Configured | {dependabot_configured} |

---

"""

    # Vulnerability findings
    if vulnerable_repos:
        report += "## 🚨 Critical Vulnerabilities Detected\n\n"
        for repo in vulnerable_repos:
            report += f"### {repo.name}\n"
            report += f"- **Repository:** [{repo.full_name}]({repo.html_url})\n"
            report += f"- **Visibility:** {'Private' if repo.private else 'Public'}\n"
            for vuln in repo.vulnerabilities:
                report += f"- **CVE:** {vuln.cve}\n"
                report += f"- **CVSS:** {vuln.cvss} (Critical)\n"
                report += f"- **Affected Package:** {vuln.package}@{vuln.version}\n"
                report += f"- **Location:** `{vuln.location}`\n"
                report += f"- **Remediation:** `npm install {vuln.package}@{vuln.patched_version}`\n"
            report += "\n"
    else:
        report += "## ✅ No Critical Vulnerabilities Detected\n\n"
        report += "No repositories were found with CVE-2025-66478 vulnerable packages.\n\n"

    # Dependabot status matrix
    report += "---\n\n## Dependabot Configuration Status\n\n"
    report += "| Repository | Visibility | Language | Config File | Security Updates | Status |\n"
    report += "|------------|------------|----------|-------------|------------------|--------|\n"
    
    for repo in sorted(results, key=lambda r: r.full_name):
        visibility = "Private" if repo.private else "Public"
        lang = repo.language or "-"
        config = "✅ Yes" if repo.dependabot_config_exists else "❌ No"
        security = "✅ Enabled" if repo.dependabot_security_updates == "enabled" else "❌ Disabled"
        status_icon = {
            "Configured": "✅ Configured",
            "Partial": "⚠️ Partial",
            "Not Configured": "❌ Not Configured"
        }.get(repo.dependabot_status, "❓ Unknown")
        
        report += f"| {repo.name} | {visibility} | {lang} | {config} | {security} | {status_icon} |\n"

    # Recommendations
    report += "\n---\n\n## Recommendations\n\n"
    
    if vulnerable_repos:
        report += "### 🚨 Immediate Actions (Critical)\n\n"
        for repo in vulnerable_repos:
            for vuln in repo.vulnerabilities:
                report += f"1. **{repo.full_name}**: `npm install {vuln.package}@{vuln.patched_version}`\n"
        report += "\n"
    
    no_dependabot = [r for r in results if r.dependabot_status == "Not Configured"]
    if no_dependabot:
        report += "### ⚠️ High Priority - Enable Dependabot\n\n"
        report += "The following repositories do not have Dependabot configured:\n\n"
        for repo in no_dependabot[:20]:  # Limit to 20
            report += f"- [{repo.name}]({repo.html_url})\n"
        if len(no_dependabot) > 20:
            report += f"- ... and {len(no_dependabot) - 20} more\n"
        report += "\n"

    report += "### General Recommendations\n\n"
    report += "1. Enable Dependabot security updates organization-wide\n"
    report += "2. Enable secret scanning on all repositories\n"
    report += "3. Enable push protection for secrets\n"
    report += "4. Run `npm audit` in CI pipelines\n"

    report += f"\n---\n\n*Report generated by scan-github-repos.py on {now}*\n"
    
    return report


def generate_csv_report(results: list[RepoSecurityStatus]) -> str:
    """Generate a CSV security report."""
    lines = ["Repository,Visibility,Language,Vulnerable,Vulnerabilities,Dependabot Config,Dependabot Updates,Status"]
    
    for repo in results:
        vuln_str = "; ".join(f"{v.package}@{v.version}" for v in repo.vulnerabilities) if repo.vulnerabilities else ""
        lines.append(",".join([
            repo.full_name,
            "Private" if repo.private else "Public",
            repo.language or "",
            "Yes" if repo.is_vulnerable else "No",
            f'"{vuln_str}"',
            "Yes" if repo.dependabot_config_exists else "No",
            repo.dependabot_security_updates or "unknown",
            repo.dependabot_status,
        ]))
    
    return "\n".join(lines)


def generate_json_report(results: list[RepoSecurityStatus]) -> str:
    """Generate a JSON security report."""
    data = {
        "scan_date": datetime.now().isoformat(),
        "total_repos": len(results),
        "vulnerable_count": sum(1 for r in results if r.is_vulnerable),
        "repositories": []
    }
    
    for repo in results:
        data["repositories"].append({
            "full_name": repo.full_name,
            "html_url": repo.html_url,
            "private": repo.private,
            "language": repo.language,
            "is_vulnerable": repo.is_vulnerable,
            "vulnerabilities": [
                {
                    "package": v.package,
                    "version": v.version,
                    "patched_version": v.patched_version,
                    "location": v.location,
                    "cve": v.cve,
                }
                for v in repo.vulnerabilities
            ],
            "dependabot_config_exists": repo.dependabot_config_exists,
            "dependabot_security_updates": repo.dependabot_security_updates,
            "dependabot_status": repo.dependabot_status,
        })
    
    return json.dumps(data, indent=2)


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Scan GitHub repositories for CVE-2025-66478 and security configuration"
    )
    parser.add_argument("--owner", "-o", help="GitHub owner/org to scan (default: your repos)")
    parser.add_argument("--language", "-l", help="Filter by primary language")
    parser.add_argument("--include-forks", action="store_true", help="Include forked repos")
    parser.add_argument("--limit", type=int, default=0, help="Max repos to scan (0 = all)")
    parser.add_argument("--format", "-f", choices=["markdown", "csv", "json"], default="markdown")
    parser.add_argument("--output", "-O", default="github-security-scan-report.md", help="Output file path")
    parser.add_argument("--workers", "-w", type=int, default=5, help="Parallel workers (default: 5)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")
    
    args = parser.parse_args()
    
    # Get current user
    user = get_current_user()
    if not user:
        print("Error: Could not get authenticated user. Run 'gh auth login' first.", file=sys.stderr)
        sys.exit(1)
    
    if not args.quiet:
        print(f"🔐 Authenticated as: {user}")
        print(f"📂 Scanning: {args.owner or user}")
    
    # List repositories
    if not args.quiet:
        print("📋 Listing repositories...")
    
    repos = list_repositories(args.owner, args.include_forks, args.language, args.limit)
    
    if not repos:
        print("No repositories found.", file=sys.stderr)
        sys.exit(1)
    
    if not args.quiet:
        print(f"   Found {len(repos)} repositories")
        print(f"🔍 Scanning for vulnerabilities (using {args.workers} workers)...")
    
    # Scan repositories in parallel
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(scan_repository, repo): repo for repo in repos}
        
        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)
            
            if not args.quiet:
                status = "🚨 VULNERABLE" if result.is_vulnerable else "✅"
                print(f"   [{i}/{len(repos)}] {result.full_name} {status}")
    
    # Generate report
    if args.format == "markdown":
        report = generate_markdown_report(results, args.owner, user)
        ext = ".md"
    elif args.format == "csv":
        report = generate_csv_report(results)
        ext = ".csv"
    else:
        report = generate_json_report(results)
        ext = ".json"
    
    # Ensure correct extension
    output_path = args.output
    if not output_path.endswith(ext):
        output_path = Path(output_path).stem + ext
    
    # Write report
    Path(output_path).write_text(report, encoding="utf-8")
    
    # Summary
    vulnerable_count = sum(1 for r in results if r.is_vulnerable)
    
    print(f"\n✅ Scan complete!")
    print(f"📊 Results:")
    print(f"   • Repositories scanned: {len(results)}")
    print(f"   • Vulnerable: {vulnerable_count} {'⚠️' if vulnerable_count else ''}")
    print(f"   • Dependabot enabled: {sum(1 for r in results if r.dependabot_security_updates == 'enabled')}/{len(results)}")
    print(f"📁 Report saved to: {output_path}")
    
    if vulnerable_count:
        print(f"\n⚠️  {vulnerable_count} vulnerable repositories found! Review the report for remediation steps.")
        sys.exit(2)  # Exit code 2 = vulnerabilities found


if __name__ == "__main__":
    main()
