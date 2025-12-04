# Agentic Approaches to Security Vulnerability Response

## Executive Summary

This document outlines strategies for leveraging automation and AI-assisted tooling to respond to security vulnerabilities like CVE-2025-66478 at scale across a large consultancy with hundreds of repositories spanning internal projects and client engagements.

---

## The Challenge

### Scale Issues
- Hundreds of repositories across Neudesic org
- Many client GitHub organizations with varying access levels
- No single developer has visibility across all attack surfaces
- Diverse tech stacks and framework versions
- Different deployment environments and timelines

### Key Insight
> "No one agent or developer will have access to see/analyze everything"

This means our approach must be **distributed** and **empowering**, giving every consultant the tools to "see something, say something" in the repositories they do have access to.

---

## Approach 1: Copilot Instructions (Passive Detection)

### What It Is
A `.github/copilot-instructions.md` file that programs GitHub Copilot to automatically check for security vulnerabilities when developers work in a repository.

### How It Works
1. Developer opens a repository in VS Code with Copilot
2. Copilot reads the instructions file automatically
3. Before generating any code, Copilot checks package.json
4. If vulnerable versions detected, Copilot **stops and alerts**
5. Developer is provided remediation steps

### Strengths
- Zero additional tooling required
- Works in any repository where it's deployed
- Educates developers about the vulnerability
- Provides immediate, contextual guidance

### Limitations
- Only active when developer is working in VS Code
- Requires instructions file to be present
- Depends on developer using Copilot

### Deployment Strategy
```bash
# Create a reusable template
# Developers can add to any repository they access

# Option 1: Direct copy
curl -o .github/copilot-instructions.md https://raw.githubusercontent.com/neudesic/react-security-reaction/main/.github/copilot-instructions.md

# Option 2: GitHub template repository
# Set up react-security-reaction as a template
# Developers can use "Use this template" for new projects
```

### Scaling via Organization Defaults
GitHub allows organization-level default community health files. Consider:
1. Create `neudesic/.github` repository
2. Add `copilot-instructions.md` as organization default
3. All repos in org inherit unless they have their own

---

## Approach 2: GitHub Actions Workflows (Active Scanning)

### What It Is
CI/CD workflows that automatically scan for vulnerabilities on every push, PR, and on a daily schedule.

### Workflow Types

#### 1. Security Scan Workflow (`security-scan.yml`)
- Runs on push to main branches
- Runs on daily schedule
- Checks for vulnerable package versions
- Runs `npm audit`
- Performs CodeQL analysis
- Outputs results to GitHub Actions summary

#### 2. PR Security Gate (`pr-security-gate.yml`)
- Blocks PRs that introduce vulnerable packages
- Adds automated comments explaining the issue
- Provides remediation commands directly in PR

### Strengths
- Catches vulnerabilities automatically
- Works even if developer doesn't use Copilot
- Creates audit trail in GitHub
- Can be made required for merging

### Deployment Strategy
```yaml
# Add to repository settings
# Settings > Branches > Branch protection rules
# Require status checks: security-gate
```

### Scaling via Repository Rulesets
GitHub Organization admins can:
1. Create organization-level rulesets
2. Require specific workflows across all repos
3. Enforce branch protection organization-wide

---

## Approach 3: Dependabot Integration (Automated Updates)

### What It Is
GitHub's built-in dependency update tool that automatically creates PRs when security vulnerabilities are detected.

### Configuration
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    groups:
      security-updates:
        update-types: ["security"]
```

### Strengths
- Native GitHub integration
- Automatic PR creation
- Security advisories from GitHub Advisory Database
- Minimal configuration

### Limitations
- Only alerts, doesn't force action
- Can create PR noise if not configured properly
- Developers must still review and merge

### Dave's Note on Avoiding Wheel Reinvention
> "Dependabot and GHAS are things so we should avoid reinventing any wheels"

**Action Items:**
1. Audit current Dependabot adoption across Neudesic repos
2. Create standard `dependabot.yml` configuration
3. Enable Dependabot alerts organization-wide
4. Configure Dependabot security updates (auto-PR for security)

---

## Approach 4: GitHub Advanced Security (GHAS)

### What It Is
GitHub's enterprise security suite including:
- Code scanning (CodeQL)
- Secret scanning
- Dependency review
- Security overview dashboard

### Key Features for This Vulnerability

#### Dependency Review
Automatically analyzes dependencies in PRs and blocks merges if vulnerabilities detected.

#### Security Overview Dashboard
Organization-level view of:
- All security alerts across repos
- Trends over time
- Compliance status

### Enterprise Considerations
- GHAS requires GitHub Enterprise or public repos
- Additional licensing cost for private repos
- Significant value for organization-wide visibility

### Recommendation
If Neudesic has GHAS:
1. Enable dependency review on all repos
2. Set up organization security policies
3. Use security overview for CVE-2025-66478 tracking

---

## Approach 5: MCP Server for CVSS Publications (Future-Looking)

### Dave's Vision
> "MCP Server for CVSS publications for awareness, that might be interesting to drive SRE activities around security patching"

### Concept
Create a Model Context Protocol (MCP) server that:
1. Monitors CVE/NVD databases for new publications
2. Filters for relevant technologies (React, Next.js, Node.js, etc.)
3. Alerts developers/SRE teams when relevant CVEs are published
4. Provides context-aware remediation guidance

### Implementation Outline
```typescript
// mcp-cvss-monitor/src/server.ts
import { Server } from "@modelcontextprotocol/sdk/server";

const server = new Server({
  name: "cvss-monitor",
  version: "1.0.0"
});

// Tool: Check for new CVEs affecting a technology
server.tool("check_cves", {
  description: "Check for CVEs affecting specified technologies",
  parameters: {
    technologies: ["react", "next.js", "node"],
    severity: "critical",
    days: 30
  },
  handler: async (params) => {
    // Query NVD API
    // Filter by technology
    // Return relevant CVEs with remediation guidance
  }
});

// Tool: Get remediation guidance for a specific CVE
server.tool("get_remediation", {
  description: "Get remediation steps for a specific CVE",
  parameters: {
    cveId: "CVE-2025-66478"
  },
  handler: async (params) => {
    // Return structured remediation guidance
  }
});
```

### Integration Points
- Slack notifications for new critical CVEs
- GitHub Issues auto-creation for affected repos
- Azure DevOps work item creation
- Email digests for security team

### Status
This is a future enhancement. Focus first on approaches 1-4.

---

## Approach 6: GitHub Copilot Coding Agent

### What It Is
GitHub Copilot's agent mode that can work autonomously on issues.

### Use Case for Security Response
1. Create an issue: "Remediate CVE-2025-66478"
2. Assign to Copilot coding agent
3. Agent analyzes repository, identifies vulnerable packages
4. Agent creates PR with updated dependencies
5. Agent runs tests to verify fix

### Prompt Template
```markdown
## Issue: Remediate CVE-2025-66478

### Description
Scan this repository for packages affected by CVE-2025-66478 / CVE-2025-55182 and upgrade them to patched versions.

### Acceptance Criteria
- [ ] Identify all vulnerable packages
- [ ] Update to patched versions per the advisory
- [ ] Ensure application builds successfully
- [ ] Run existing tests
- [ ] Document changes in PR description

### References
- https://nextjs.org/blog/CVE-2025-66478
- https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
```

### Scaling with Issue Templates
Create `.github/ISSUE_TEMPLATE/security-remediation.yml`:
```yaml
name: Security Remediation
description: Request Copilot agent to remediate a CVE
labels: ["security", "copilot-agent"]
body:
  - type: input
    id: cve
    attributes:
      label: CVE ID
      placeholder: CVE-2025-66478
  - type: textarea
    id: context
    attributes:
      label: Additional Context
```

---

## Approach 7: Bulk Repository Scanner (PowerShell)

### What It Is
A script that scans multiple local repositories for vulnerable packages.

### Use Case
Consultants can run this against all repos they have cloned locally.

### Implementation
```powershell
# scripts/scan-repos.ps1
param(
    [string]$Path = ".",
    [string]$OutputReport = "security-scan-report.md"
)

$vulnerableRepos = @()

Get-ChildItem -Path $Path -Recurse -Filter "package.json" | 
    Where-Object { $_.FullName -notmatch "node_modules" } |
    ForEach-Object {
        $content = Get-Content $_.FullName -Raw | ConvertFrom-Json
        
        $nextVersion = $content.dependencies.next
        $reactVersion = $content.dependencies.react
        
        $isVulnerable = $false
        $vulnerabilities = @()
        
        if ($nextVersion -match "^15\.(0\.[0-4]|1\.[0-8]|2\.[0-5]|3\.[0-5]|4\.[0-7]|5\.[0-6])") {
            $isVulnerable = $true
            $vulnerabilities += "Next.js $nextVersion (CVE-2025-66478)"
        }
        
        if ($reactVersion -match "^19\.(0\.0|1\.[01]|2\.0)$") {
            $isVulnerable = $true
            $vulnerabilities += "React $reactVersion (CVE-2025-55182)"
        }
        
        if ($isVulnerable) {
            $vulnerableRepos += [PSCustomObject]@{
                Path = $_.DirectoryName
                Vulnerabilities = $vulnerabilities -join ", "
            }
        }
    }

# Generate report
$report = @"
# Security Scan Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

## Vulnerable Repositories Found: $($vulnerableRepos.Count)

"@

foreach ($repo in $vulnerableRepos) {
    $report += @"

### $($repo.Path)
- **Issues**: $($repo.Vulnerabilities)
- **Action**: Update packages per CVE advisories

"@
}

$report | Out-File -FilePath $OutputReport
Write-Host "Report generated: $OutputReport"
Write-Host "Found $($vulnerableRepos.Count) vulnerable repositories"
```

---

## Implementation Roadmap

### Phase 1: Immediate (This Week)
1. ✅ Create `.github/copilot-instructions.md` template
2. ✅ Create GitHub Actions workflows
3. ✅ Create consultant playbook
4. ✅ Create test vulnerable application
5. [ ] Distribute to team leads

### Phase 2: Short-term (Next 2 Weeks)
1. [ ] Audit Dependabot adoption across Neudesic repos
2. [ ] Enable Dependabot security updates org-wide
3. [ ] Create organization-level repository ruleset
4. [ ] Deploy to high-priority internal projects

### Phase 3: Medium-term (Next Month)
1. [ ] Create client-facing security advisory template
2. [ ] Develop MCP server prototype for CVSS monitoring
3. [ ] Integrate with Azure DevOps for client projects
4. [ ] Create training materials for consultants

### Phase 4: Long-term (Ongoing)
1. [ ] Establish security response playbook as standard practice
2. [ ] Build reusable automation for future CVEs
3. [ ] Create Neudesic security response SLA
4. [ ] Integrate with SRE monitoring and alerting

---

## Success Metrics

### Quantitative
- Number of repositories scanned
- Number of vulnerabilities detected
- Time to remediation (mean, median)
- PR merge rate for security updates

### Qualitative
- Developer awareness of vulnerability
- Ease of remediation process
- Client satisfaction with response time
- Reduction in security-related incidents

---

## Key Stakeholders

| Role | Responsibility |
|------|---------------|
| **Dave Jensen** | Executive sponsor, strategic direction |
| **Michael Simmons** | Technical lead, tooling development |
| **Aiden Y** | Security automation, long-term strategy |
| **Practice Leads** | Distribution within practices |
| **Consultants** | Execution on client projects |

---

## Conclusion

The combination of:
1. **Copilot Instructions** (passive, educational)
2. **GitHub Actions** (active, blocking)
3. **Dependabot** (automated updates)
4. **GHAS** (enterprise visibility)
5. **MCP Server** (future proactive monitoring)
6. **Copilot Coding Agent** (automated remediation)

...creates a defense-in-depth approach that scales to individual consultants while providing organizational visibility where possible.

The key insight is that **we don't need one system to see everything**. We need to **empower everyone to see what they can see** and provide them the tools to act immediately.

---

*Document Version: 1.0*  
*Last Updated: December 4, 2025*  
*Author: Michael Simmons, Neudesic*
