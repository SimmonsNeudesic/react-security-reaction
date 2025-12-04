<#
.SYNOPSIS
    Scans repositories for CVE-2025-66478 vulnerability in React Server Components.

.DESCRIPTION
    This script recursively searches through directories for package.json files
    and checks if they contain vulnerable versions of Next.js, React, or related
    RSC packages affected by CVE-2025-66478 / CVE-2025-55182.

.PARAMETER Path
    The root path to scan for repositories. Defaults to current directory.

.PARAMETER OutputReport
    Path to output the Markdown report. Defaults to "security-scan-report.md".

.PARAMETER Quiet
    Suppress console output, only generate report.

.EXAMPLE
    .\scan-repos.ps1 -Path "C:\Code" -OutputReport "report.md"

.EXAMPLE
    .\scan-repos.ps1 -Path "." -Quiet

.NOTES
    Author: Neudesic Security Response Team
    Date: December 2025
    CVE: CVE-2025-66478, CVE-2025-55182
#>

param(
    [Parameter(Position = 0)]
    [string]$Path = ".",
    
    [Parameter(Position = 1)]
    [string]$OutputReport = "security-scan-report.md",
    
    [switch]$Quiet
)

# Vulnerable version patterns
$vulnerablePatterns = @{
    # Next.js vulnerable versions (15.x before patches, 16.x before 16.0.7)
    "next" = @(
        "^15\.0\.[0-4]",           # 15.0.0 - 15.0.4 (patched: 15.0.5)
        "^15\.1\.[0-8]",           # 15.1.0 - 15.1.8 (patched: 15.1.9)
        "^15\.2\.[0-5]",           # 15.2.0 - 15.2.5 (patched: 15.2.6)
        "^15\.3\.[0-5]",           # 15.3.0 - 15.3.5 (patched: 15.3.6)
        "^15\.4\.[0-7]",           # 15.4.0 - 15.4.7 (patched: 15.4.8)
        "^15\.5\.[0-6]",           # 15.5.0 - 15.5.6 (patched: 15.5.7)
        "^16\.0\.[0-6]",           # 16.0.0 - 16.0.6 (patched: 16.0.7)
        "^14\.3\.0-canary"         # 14.3.0-canary.77+
    )
    
    # React vulnerable versions
    "react" = @(
        "^19\.0\.0$",
        "^19\.1\.0$",
        "^19\.1\.1$",
        "^19\.2\.0$"
    )
    
    # RSC packages vulnerable versions
    "react-server-dom-webpack" = @(
        "^19\.0\.0$",
        "^19\.1\.0$",
        "^19\.1\.1$",
        "^19\.2\.0$"
    )
    
    "react-server-dom-parcel" = @(
        "^19\.0\.0$",
        "^19\.1\.0$",
        "^19\.1\.1$",
        "^19\.2\.0$"
    )
    
    "react-server-dom-turbopack" = @(
        "^19\.0\.0$",
        "^19\.1\.0$",
        "^19\.1\.1$",
        "^19\.2\.0$"
    )
}

# Remediation guidance
$remediationCommands = @{
    "next" = @{
        "15.0" = "npm install next@15.0.5"
        "15.1" = "npm install next@15.1.9"
        "15.2" = "npm install next@15.2.6"
        "15.3" = "npm install next@15.3.6"
        "15.4" = "npm install next@15.4.8"
        "15.5" = "npm install next@15.5.7"
        "16.0" = "npm install next@16.0.7"
        "14.3" = "npm install next@14 (downgrade to stable)"
    }
    "react" = "npm install react@latest react-dom@latest"
    "react-server-dom-webpack" = "npm install react-server-dom-webpack@latest"
    "react-server-dom-parcel" = "npm install react-server-dom-parcel@latest"
    "react-server-dom-turbopack" = "npm install react-server-dom-turbopack@latest"
}

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    if (-not $Quiet) {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Test-VulnerableVersion {
    param(
        [string]$Package,
        [string]$Version
    )
    
    if (-not $vulnerablePatterns.ContainsKey($Package)) {
        return $false
    }
    
    # Clean version string (remove ^, ~, etc.)
    $cleanVersion = $Version -replace '[\^~>=<]', ''
    
    foreach ($pattern in $vulnerablePatterns[$Package]) {
        if ($cleanVersion -match $pattern) {
            return $true
        }
    }
    
    return $false
}

function Get-RemediationCommand {
    param(
        [string]$Package,
        [string]$Version
    )
    
    if ($Package -eq "next") {
        # Extract major.minor version
        $cleanVersion = $Version -replace '[\^~>=<]', ''
        if ($cleanVersion -match "^(\d+\.\d+)") {
            $majorMinor = $Matches[1]
            if ($remediationCommands["next"].ContainsKey($majorMinor)) {
                return $remediationCommands["next"][$majorMinor]
            }
        }
        return "npm install next@latest"
    }
    
    if ($remediationCommands.ContainsKey($Package)) {
        return $remediationCommands[$Package]
    }
    
    return "npm install $Package@latest"
}

# Main scanning logic
Write-Log "======================================" "Cyan"
Write-Log "CVE-2025-66478 Repository Scanner" "Cyan"
Write-Log "======================================" "Cyan"
Write-Log ""
Write-Log "Scanning path: $Path" "Yellow"
Write-Log ""

$vulnerableRepos = @()
$totalScanned = 0
$startTime = Get-Date

# Find all package.json files
$packageFiles = Get-ChildItem -Path $Path -Recurse -Filter "package.json" -ErrorAction SilentlyContinue | 
    Where-Object { $_.FullName -notmatch "node_modules" }

Write-Log "Found $($packageFiles.Count) package.json files to scan" "Yellow"
Write-Log ""

foreach ($file in $packageFiles) {
    $totalScanned++
    $repoVulnerabilities = @()
    
    try {
        $content = Get-Content $file.FullName -Raw | ConvertFrom-Json
        
        # Check dependencies and devDependencies
        $allDeps = @{}
        
        if ($content.dependencies) {
            $content.dependencies.PSObject.Properties | ForEach-Object {
                $allDeps[$_.Name] = $_.Value
            }
        }
        
        if ($content.devDependencies) {
            $content.devDependencies.PSObject.Properties | ForEach-Object {
                if (-not $allDeps.ContainsKey($_.Name)) {
                    $allDeps[$_.Name] = $_.Value
                }
            }
        }
        
        # Check each potentially vulnerable package
        foreach ($package in $vulnerablePatterns.Keys) {
            if ($allDeps.ContainsKey($package)) {
                $version = $allDeps[$package]
                
                if (Test-VulnerableVersion -Package $package -Version $version) {
                    $repoVulnerabilities += [PSCustomObject]@{
                        Package = $package
                        Version = $version
                        Remediation = Get-RemediationCommand -Package $package -Version $version
                    }
                }
            }
        }
        
        if ($repoVulnerabilities.Count -gt 0) {
            $vulnerableRepos += [PSCustomObject]@{
                Path = $file.DirectoryName
                PackageJson = $file.FullName
                ProjectName = if ($content.name) { $content.name } else { Split-Path $file.DirectoryName -Leaf }
                Vulnerabilities = $repoVulnerabilities
            }
            
            Write-Log "❌ VULNERABLE: $($file.DirectoryName)" "Red"
            foreach ($vuln in $repoVulnerabilities) {
                Write-Log "   - $($vuln.Package)@$($vuln.Version)" "Red"
            }
        } else {
            Write-Log "✅ Safe: $($file.DirectoryName)" "Green"
        }
    }
    catch {
        Write-Log "⚠️  Error reading: $($file.FullName) - $_" "Yellow"
    }
}

$endTime = Get-Date
$duration = $endTime - $startTime

# Generate report
$report = @"
# CVE-2025-66478 Security Scan Report

## Scan Summary

| Metric | Value |
|--------|-------|
| **Scan Date** | $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") |
| **Root Path** | ``$Path`` |
| **Total Projects Scanned** | $totalScanned |
| **Vulnerable Projects Found** | $($vulnerableRepos.Count) |
| **Scan Duration** | $($duration.TotalSeconds.ToString("F2")) seconds |

## CVE Information

| Attribute | Details |
|-----------|---------|
| **CVE IDs** | CVE-2025-66478 (Next.js), CVE-2025-55182 (React) |
| **CVSS Score** | 10.0 (Critical) |
| **Attack Type** | Unauthenticated Remote Code Execution |
| **CWE** | CWE-502: Deserialization of Untrusted Data |

---

"@

if ($vulnerableRepos.Count -eq 0) {
    $report += @"
## ✅ No Vulnerable Projects Found

All scanned projects are using safe versions of the affected packages.

"@
} else {
    $report += @"
## ⚠️ Vulnerable Projects ($($vulnerableRepos.Count) found)

The following projects require immediate attention:

"@

    $index = 1
    foreach ($repo in $vulnerableRepos) {
        $report += @"

### $index. $($repo.ProjectName)

**Path:** ``$($repo.Path)``

| Package | Current Version | Remediation |
|---------|-----------------|-------------|
"@
        foreach ($vuln in $repo.Vulnerabilities) {
            $report += "| $($vuln.Package) | $($vuln.Version) | ``$($vuln.Remediation)`` |`n"
        }
        
        $report += @"

**Quick Fix:**
``````bash
cd "$($repo.Path)"
"@
        foreach ($vuln in $repo.Vulnerabilities) {
            $report += "`n$($vuln.Remediation)"
        }
        $report += @"

npm audit
``````

"@
        $index++
    }
}

$report += @"
---

## Next Steps

1. **Immediate**: Address all vulnerable projects listed above
2. **Verify**: Run ``npm audit`` after updates to confirm fixes
3. **Test**: Ensure applications build and function correctly
4. **Deploy**: Push updates through your normal deployment process

## References

- [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Next.js CVE Advisory](https://nextjs.org/blog/CVE-2025-66478)
- [GitHub Advisory GHSA-9qr9-h5gf-34mp](https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp)

---

*Report generated by Neudesic Security Scanner*
"@

# Write report to file
$report | Out-File -FilePath $OutputReport -Encoding utf8

# Summary output
Write-Log ""
Write-Log "======================================" "Cyan"
Write-Log "Scan Complete" "Cyan"
Write-Log "======================================" "Cyan"
Write-Log ""
Write-Log "Total projects scanned: $totalScanned" "White"

if ($vulnerableRepos.Count -gt 0) {
    Write-Log "Vulnerable projects: $($vulnerableRepos.Count)" "Red"
    Write-Log ""
    Write-Log "⚠️  ACTION REQUIRED: Review and remediate vulnerable projects!" "Red"
} else {
    Write-Log "Vulnerable projects: 0" "Green"
    Write-Log ""
    Write-Log "✅ No vulnerable projects detected!" "Green"
}

Write-Log ""
Write-Log "Report saved to: $OutputReport" "Yellow"

# Return results for pipeline usage
return [PSCustomObject]@{
    TotalScanned = $totalScanned
    VulnerableCount = $vulnerableRepos.Count
    VulnerableProjects = $vulnerableRepos
    ReportPath = $OutputReport
}
