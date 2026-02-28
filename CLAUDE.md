# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Three PowerShell 7 (`pwsh`) scripts for security auditing Microsoft 365 / Entra ID environments. No build step, no tests — just run them.

| Script | Purpose |
|--------|---------|
| `Get-PrivilegedActivityReport.ps1` | Main audit script — generates HTML + CSV reports |
| `Get-CASessionPolicy.ps1` | Point-in-time CA session / token lifetime audit |
| `convert-for-sharepoint.ps1` | Post-processor: converts `<details>` elements to static HTML |

## Running the Scripts

```powershell
# Default 24-hour window
pwsh ./Get-PrivilegedActivityReport.ps1

# Custom range
pwsh ./Get-PrivilegedActivityReport.ps1 -DaysBack 7

# Force browser re-auth (bypass .auth_cache.json)
pwsh ./Get-PrivilegedActivityReport.ps1 -ForceReauth

# CA session audit (no time range — point-in-time)
pwsh ./Get-CASessionPolicy.ps1

# SharePoint conversion
pwsh ./convert-for-sharepoint.ps1 -InputFile report.html -OutputFile report_sharepoint.html
```

Modules auto-install on first run. Output files land in `$PSScriptRoot` (the script directory).

## Architecture: Get-PrivilegedActivityReport.ps1

### Connection Order (critical — do not change)

```
Connect-MgGraph  →  Get-EntraIDAuditLogs + Get-PrivilegedRoleAssignments  (Graph data fetched immediately — tokens expire ~30 min)
Connect-ExchangeOnline  →  can take 20+ min on first run
Connect-IPPSSession
Build-PrivilegedUserSet  (uses $roleAssignments + Exchange role groups)
Get-UnifiedAuditLogActivities
Get-SuspiciousEmailDeletions -PrivilegedUsers $privilegedUserSet
Export-Reports / Generate-HtmlReport
```

Graph data **must** be fetched immediately after `Connect-MgGraph`. Connecting Exchange first causes Graph tokens to expire before data collection.

### Data Sources

| Function | Source | Notes |
|----------|--------|-------|
| `Get-EntraIDAuditLogs` | Microsoft Graph | Filters to `$entraAuditCategories` — no per-operation filtering |
| `Get-PrivilegedRoleAssignments` | Microsoft Graph | Active + PIM Eligible; deduplicates if a user has both |
| `Build-PrivilegedUserSet` | `$roleAssignments` + Exchange `Get-RoleGroupMember` | Builds `[hashtable]` UPN→roles used to filter email deletions |
| `Get-UnifiedAuditLogActivities` | Exchange + IPPS | Two sub-paths: policy state snapshots (`Get-SecurityComplianceActivities`) + targeted UAL batch queries (`$targetedOperations`) |
| `Get-SuspiciousEmailDeletions` | Exchange UAL | SoftDelete/HardDelete where actor ≠ owner AND actor is in `$privilegedUserSet` |

### Key Filtering Configuration (top of script)

- **`$excludedActors`** — exact-match list of system/service accounts to suppress
- **`$excludedActorPatterns`** — regex patterns (GUIDs, `NT SERVICE\*`, `S-1-5-18`, etc.)
- **`$entraAuditCategories`** — controls which Entra audit categories are included (`RoleManagement`, `Policy`, `ApplicationManagement`, `DirectoryManagement`, `ResourceManagement`)
- **`$targetedOperations`** — UAL operations queried server-side in batches of 10; adding a wildcard here breaks performance — use exact operation names only

### UAL Dual-Source Strategy

`Get-UnifiedAuditLogActivities` runs **both** sources every time:
1. `Get-SecurityComplianceActivities` — policy state snapshots via direct cmdlets (no actor info)
2. `Search-UnifiedAuditLog` targeted batch queries — provides actor, IP, timestamp; the only path that captures TABL changes

When both return data for the same object, the UAL event wins (has more detail).

### Suspicious Email Deletion Filtering

Only surfaced when actor is in `$privilegedUserSet` (built by `Build-PrivilegedUserSet`). Privileged = holds one of these Entra roles OR Exchange role group memberships:
- **Entra**: Global Administrator, Exchange Administrator, Privileged Role Administrator, Compliance Administrator, Security Administrator, Application Administrator
- **Exchange groups**: ApplicationImpersonation, Organization Management, eDiscovery Manager, Records Management, Compliance Management

Non-privileged delegate access (e.g., EA deleting from exec's mailbox) is intentionally skipped.

### HTML Report Generation

`Generate-HtmlReport` builds a self-contained HTML string (inline CSS + JS). The operations detail section groups events by `Operation` name, renders them as collapsible `<details>` rows. `convert-for-sharepoint.ps1` post-processes this file via regex to replace the JS-driven expand/collapse with static `<details>`/`<summary>` HTML5 elements.

### Credential Cache

Both scripts share `.auth_cache.json` in `$PSScriptRoot`. Format: `{ UserPrincipalName, CachedAt/ExpiresAt }`. The two scripts use slightly different field names (`CachedAt` in the activity report, `ExpiresAt` in the CA script) — be aware of this if refactoring.

## Extending the Script

- **New excluded actor**: add to `$excludedActors` (exact) or `$excludedActorPatterns` (regex)
- **New UAL operation to monitor**: add exact operation name to `$targetedOperations` inside `Get-UnifiedAuditLogActivities` — no wildcards
- **New Entra ID audit category**: add to `$entraAuditCategories` — captures all operations in that category
- **Expand privileged user definition**: modify `$sensitiveRoles` list or `$exoGroups` list inside `Build-PrivilegedUserSet`

## Known Platform Constraints

- **TABL retrieval**: `Get-TenantAllowBlockListItems` is broken in pwsh on macOS — changes are captured via UAL instead
- **`Search-UnifiedAuditLog`**: slow on macOS (~12 min for 1-day targeted queries); not available until after `Connect-ExchangeOnline`
- **`Connect-MgGraph`**: does not support `-LoginHint`; cached UPN is display-only
