# React Security Reaction: CVE-2025-66478 Response Kit

A comprehensive toolkit for detecting, communicating, and remediating the critical React Server Components vulnerability (CVE-2025-66478 / CVE-2025-55182).

## 🚨 Vulnerability Overview

| Attribute | Details |
|-----------|---------|
| **CVE IDs** | CVE-2025-66478 (Next.js), CVE-2025-55182 (React) |
| **CVSS Score** | 10.0 (Critical) |
| **Attack Type** | Unauthenticated Remote Code Execution |
| **Weakness** | CWE-502: Deserialization of Untrusted Data |
| **Disclosure Date** | December 3, 2025 |

## 📁 Repository Contents

```
react-security-reaction/
├── .github/
│   ├── copilot-instructions.md    # AI-assisted security detection
│   ├── dependabot.yml              # Automated dependency updates
│   ├── prompts/
│   │   ├── check-react-vulnerability-cve-2025-66478.prompt.md  # Local scan prompt
│   │   └── scan-github-repos.prompt.md                         # GitHub scanner prompt
│   ├── instructions/
│   │   └── react-vulnerability-cve-2025-66478.instructions.md  # Security rules
│   └── workflows/
│       ├── security-scan.yml       # Daily CVE scanning workflow
│       └── pr-security-gate.yml    # Block vulnerable PRs
├── docs/
│   ├── CONSULTANT_SECURITY_PLAYBOOK.md  # Complete remediation guide
│   └── AGENTIC_APPROACHES.md            # Automation strategies
├── vulnerable-app/                  # Test application (DO NOT DEPLOY)
│   ├── package.json                # Intentionally vulnerable deps
│   └── src/                        # Sample RSC implementation
├── scripts/
│   └── scan-repos.ps1              # Bulk repository scanner
└── README.md                       # This file
```

## 🚀 Quick Start

### For Individual Developers

1. **Copy the Copilot instructions** to your repository:
   ```bash
   cp .github/copilot-instructions.md /path/to/your/repo/.github/
   ```

2. **Enable Dependabot** by copying the config:
   ```bash
   cp .github/dependabot.yml /path/to/your/repo/.github/
   ```

3. **Add security workflows**:
   ```bash
   cp .github/workflows/* /path/to/your/repo/.github/workflows/
   ```

### For Teams / Organizations

1. **Distribute the Consultant Playbook** (`docs/CONSULTANT_SECURITY_PLAYBOOK.md`)
2. **Review the Agentic Approaches** (`docs/AGENTIC_APPROACHES.md`)
3. **Set up organization-wide templates** from this repository

## 🔍 Detection Methods

### Method 1: GitHub Copilot (Passive)

With `.github/copilot-instructions.md` in place, Copilot will automatically:
- Check for vulnerable packages when you work in the repository
- Alert you before writing code if vulnerabilities are detected
- Provide remediation commands

### Method 2: CI/CD Workflows (Active)

The included workflows will:
- Run daily scans for CVE-2025-66478
- Block PRs that introduce vulnerable packages
- Generate security reports in GitHub Actions summaries

### Method 3: Manual Script (Local Repos)

```powershell
# Run the bulk scanner on local repositories
.\scripts\scan-repos.ps1 -Path "C:\Code" -OutputReport "security-report.md"
```

### Method 4: GitHub Repository Scanner (Remote Repos)

Use the Copilot prompt to scan GitHub repos without cloning:

```bash
# Open the prompt file in VS Code and run it, or use the slash command:
/scan-github-repos

# Scan a specific organization
/scan-github-repos owner=neudesic

# Filter by language
/scan-github-repos filter-language=TypeScript
```

This method uses GitHub MCP tools and CLI to:
- Enumerate all accessible repositories
- Check for vulnerable package versions remotely
- Audit Dependabot and security settings
- Generate comprehensive reports

## 🛠️ Remediation

### Upgrade Commands

```bash
# Next.js (choose your version line)
npm install next@15.0.5   # 15.0.x
npm install next@15.1.9   # 15.1.x
npm install next@15.2.6   # 15.2.x
npm install next@15.3.6   # 15.3.x
npm install next@15.4.8   # 15.4.x
npm install next@15.5.7   # 15.5.x
npm install next@16.0.7   # 16.0.x

# For canary users
npm install next@14       # Downgrade to stable

# React packages directly
npm install react@latest react-dom@latest react-server-dom-webpack@latest
```

## 🧪 Testing the Detection

The `vulnerable-app/` directory contains an intentionally vulnerable application:

```bash
cd vulnerable-app
npm install
npm run security:check  # Should report vulnerabilities
```

⚠️ **WARNING**: Do not deploy the vulnerable-app to any environment!

## 📚 Resources

### Official Advisories
- [React Security Blog Post](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Next.js CVE Advisory](https://nextjs.org/blog/CVE-2025-66478)
- [GitHub Advisory GHSA-9qr9-h5gf-34mp](https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp)

### Background
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CVE-2025-55182](https://www.cve.org/CVERecord?id=CVE-2025-55182)

## 🤖 Agentic Approaches

See `docs/AGENTIC_APPROACHES.md` for detailed strategies on:
- Scaling security detection across hundreds of repositories
- MCP Server integration for CVSS monitoring
- GitHub Copilot coding agent automation
- Dependabot and GHAS optimization

## 📄 License

MIT - Use freely for security purposes.

---

*Created by Neudesic Security Response Team - December 2025*
