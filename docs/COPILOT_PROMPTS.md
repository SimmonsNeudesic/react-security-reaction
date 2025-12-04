# Reusable Copilot Prompts for Security Response

## CVE-2025-66478 Detection Prompts

These prompts can be used with GitHub Copilot Chat in VS Code or GitHub.com to assess and remediate the React Server Components vulnerability.

---

## Prompt 1: Initial Repository Assessment

Copy and paste this prompt into Copilot Chat when opening a new repository:

```
Analyze this repository for the CVE-2025-66478 / CVE-2025-55182 vulnerability.

Perform these checks:
1. Read package.json and identify Next.js, React, and react-server-dom-* package versions
2. Determine if the application uses React Server Components (look for 'use server' directives, async server components, server-only imports)
3. Check if any package versions match vulnerable patterns:
   - Next.js 15.x before 15.0.5/15.1.9/15.2.6/15.3.6/15.4.8/15.5.7
   - Next.js 16.x before 16.0.7
   - Next.js 14.3.0-canary.77+
   - React 19.0.0, 19.1.0, 19.1.1, 19.2.0
   - react-server-dom-webpack/parcel/turbopack 19.0.0-19.2.0

Report:
- Current package versions found
- Whether the app uses React Server Components
- Vulnerability status (VULNERABLE / SAFE / UNABLE TO DETERMINE)
- Specific remediation commands if vulnerable
```

---

## Prompt 2: Generate Upgrade Plan

Use this after confirming a repository is vulnerable:

```
This repository uses [PACKAGE]@[VERSION] which is vulnerable to CVE-2025-66478.

Generate a complete upgrade plan:

1. Target Version: What is the minimum safe version I should upgrade to?

2. Breaking Changes: Review the changelog between [CURRENT] and [TARGET] versions. List any breaking changes I need to address.

3. Code Changes: Search the codebase for patterns that might be affected by the upgrade:
   - Deprecated APIs
   - Changed behavior
   - New required configurations

4. Step-by-Step Instructions:
   - Exact npm/yarn commands to run
   - Configuration changes needed
   - Files that need modification

5. Verification Steps:
   - How to verify the vulnerability is patched
   - Tests to run
   - Manual checks to perform

6. Rollback Plan: If the upgrade fails, what are the rollback steps?
```

---

## Prompt 3: Automated Remediation (for Copilot Agent)

Use this prompt when creating an issue for Copilot coding agent:

```
## Task: Remediate CVE-2025-66478 Security Vulnerability

### Context
CVE-2025-66478 is a CVSS 10.0 critical vulnerability in React Server Components that allows unauthenticated remote code execution.

### Your Task
1. Scan this repository for vulnerable package versions
2. Update all affected packages to patched versions:
   - Next.js: upgrade within the current minor version to patched release
   - React: upgrade to 19.0.1, 19.1.2, or 19.2.1+
   - react-server-dom-*: upgrade to latest

3. Ensure the application still builds:
   - Run npm install
   - Run npm run build
   - Fix any build errors

4. Run existing tests if available:
   - Run npm test
   - Document any test failures

5. Create a PR with:
   - Clear title: "Security: Remediate CVE-2025-66478"
   - Description listing all package updates
   - Summary of any code changes required
   - Verification that build passes

### Constraints
- Do not change application functionality
- Maintain backward compatibility where possible
- Document all changes clearly
```

---

## Prompt 4: Security Audit Summary

Use this to generate a summary report for stakeholders:

```
Generate a security audit summary for this repository regarding CVE-2025-66478.

Include:

1. Executive Summary (2-3 sentences for non-technical stakeholders)

2. Technical Details:
   - Affected packages and versions found
   - Whether RSC features are in use
   - Attack surface assessment

3. Risk Assessment:
   - Current exposure level
   - Potential impact if exploited
   - Urgency rating

4. Remediation Status:
   - Changes already made (if any)
   - Remaining work
   - Estimated effort

5. Recommendations:
   - Immediate actions
   - Follow-up actions
   - Preventive measures

Format the output as a Markdown document suitable for sharing with project managers and clients.
```

---

## Prompt 5: Client Communication Draft

Use this to generate client-facing communication:

```
Draft a professional email/message for a client regarding CVE-2025-66478.

Context:
- We manage/developed their application
- The application uses [FRAMEWORK] version [VERSION]
- Current status: [VULNERABLE/PATCHED/IN PROGRESS]

The message should:
1. Clearly explain the situation without causing panic
2. Assure them we are on top of it
3. Explain what we're doing to address it
4. Provide timeline if applicable
5. Offer to discuss further if they have questions

Tone: Professional, reassuring, action-oriented
Length: 3-4 paragraphs
```

---

## Prompt 6: Post-Remediation Verification

Use this after applying fixes:

```
Verify that CVE-2025-66478 has been properly remediated in this repository.

Perform these checks:

1. Package Verification:
   - Run: npm list next react react-dom react-server-dom-webpack
   - Confirm all versions are at or above patched releases

2. Security Audit:
   - Run: npm audit
   - Report any remaining vulnerabilities

3. Build Verification:
   - Confirm npm run build succeeds
   - Check for any new warnings

4. Functionality Check:
   - List any Server Actions/Functions in the codebase
   - Confirm they're still syntactically correct

5. Summary:
   - Confirmation that vulnerability is remediated
   - Any remaining issues or concerns
   - Recommendations for ongoing security

Format as a verification report suitable for documentation.
```

---

## Usage Tips

1. **Context Matters**: Always make sure Copilot has access to the repository files, especially `package.json` and `package-lock.json`.

2. **Iterative Approach**: Start with Prompt 1 for assessment, then move to more specific prompts based on findings.

3. **Documentation**: Save Copilot's responses as part of your security documentation.

4. **Verification**: Always manually verify Copilot's findings against the official CVE advisories.

5. **Customization**: Modify these prompts to include project-specific details like deployment environments, client names, or internal processes.

---

*Prompts developed by Neudesic Security Response Team - December 2025*
