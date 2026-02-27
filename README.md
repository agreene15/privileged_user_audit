# privileged_user_audit

PowerShell scripts for security auditing of Microsoft 365 / Entra ID environments.

| Script | Purpose |
|--------|---------|
| `Get-PrivilegedActivityReport.ps1` | Generates a security risk report: privilege escalation, policy changes, app permission grants, federation/trust changes, eDiscovery activity, and email deletions by privileged accounts |
| `Get-CASessionPolicy.ps1` | Audits Conditional Access session controls, token lifetime policies, and MFA re-auth configuration |
| `convert-for-sharepoint.ps1` | Converts the HTML report's `<details>` elements to static HTML for SharePoint compatibility |

---

## Requirements

### License
- Microsoft 365 E3 or E5

### Roles (minimum)
- **Global Reader** + **Security Administrator** for most data
- **eDiscovery Administrator** (Purview) to include eDiscovery case data
- **Compliance Administrator** to read UAL audit events

### PowerShell
- PowerShell 7+ (`pwsh`) — install from [https://aka.ms/powershell](https://aka.ms/powershell)

### Modules (auto-installed on first run)
- `Microsoft.Graph.Authentication`
- `Microsoft.Graph.Reports`
- `Microsoft.Graph.Identity.DirectoryManagement`
- `Microsoft.Graph.Identity.Governance`
- `ExchangeOnlineManagement`

---

## Installation

```powershell
# Clone the repository
git clone https://github.com/YOUR_USERNAME/privileged_user_audit.git
cd privileged_user_audit

# Modules install automatically on first run — no manual steps required
```

---

## Usage

### Privileged Activity Report

```powershell
# Default: last 24 hours
pwsh ./Get-PrivilegedActivityReport.ps1

# Custom time range (e.g., last 7 days)
pwsh ./Get-PrivilegedActivityReport.ps1 -DaysBack 7

# Include Azure subscription activity logs
pwsh ./Get-PrivilegedActivityReport.ps1 -DaysBack 30 -IncludeAzure

# Force re-authentication (bypass cached token)
pwsh ./Get-PrivilegedActivityReport.ps1 -ForceReauth
```

On first run, a browser window will open for interactive authentication. Your UPN is cached locally in `.auth_cache.json` (gitignored) for up to 7 days to speed up subsequent runs.

**Output files** (written to the script directory):
| File | Contents |
|------|---------|
| `PrivilegedActivity_Report_*.html` | Full HTML report with expandable sections |
| `SecurityRisk_Activities_*.csv` | Entra ID high-risk activities |
| `UnifiedAuditLog_*.csv` | UAL audit events |
| `SuspiciousEmailDeletions_*.csv` | Cross-mailbox deletions by privileged accounts |
| `PrivilegedRoles_*.csv` | Current privileged role assignments (Active + PIM Eligible) |
| `PrivilegedActivity_Combined_*.csv` | All activities combined |

### CA Session Policy Audit

Point-in-time audit of Conditional Access session controls and token lifetime policies.

```powershell
pwsh ./Get-CASessionPolicy.ps1

# Force re-authentication
pwsh ./Get-CASessionPolicy.ps1 -ForceReauth
```

**What it reports:**
- CA policies enforcing sign-in frequency / periodic MFA re-auth
- Persistent browser session settings (`always` / `never`)
- Continuous Access Evaluation (CAE) mode overrides
- Enabled policies with no session controls
- Token Lifetime Policies (custom access/refresh token durations)
- Token Issuance Policies (SAML)
- Activity-Based Timeout Policies (Azure portal idle timeout)

### SharePoint-Compatible Report

The default HTML report uses `<details>` elements for collapsible sections, which SharePoint strips. Convert it for SharePoint:

```powershell
pwsh ./convert-for-sharepoint.ps1 -InputFile PrivilegedActivity_Report_<timestamp>.html -OutputFile report_sharepoint.html
```

---

## What the Report Covers

### Monitored Activity Categories

| Category | Examples |
|----------|---------|
| Privilege Escalation | Role assignments, PIM changes, group ownership, site collection admins |
| Conditional Access & Auth | Policy changes, authentication method updates |
| Exchange Mail Flow | Transport rules, connectors, journal rules |
| Defender for Office 365 | Safe Links, Safe Attachments, Anti-Phish, quarantine policies |
| Tenant Allow/Block List | Sender/URL/FileHash allow or block entries |
| eDiscovery & Compliance | Search creation, case activity, holds |
| Suspicious Email Deletions | SoftDelete/HardDelete by privileged accounts accessing other mailboxes |
| Retention | Retention policy changes |
| Application Permissions | OAuth consents, app role assignments, service principal credentials |
| Entra ID Security | Named locations, cross-tenant access, identity protection |
| Intune | Compliance policies, configuration profiles, app protection policies |
| Federation / Trust | Domain authentication, federation settings |
| Partner Access | GDAP, DAP, delegated admin relationships |
| Audit Configuration | AdminAuditLogConfig, OrganizationConfig changes |

### Deliberately Excluded (noise reduction)
- DLP policies
- SharePoint/OneDrive sharing events
- Teams policy changes
- Normal email deletions (user deleting from their own mailbox)
- Automated retention deletions (SYSTEM / S-1-5-18)
- Non-privileged delegate access deletions (e.g., EA deleting from exec's mailbox)

---

## Suspicious Email Deletion Filtering

The report surfaces email deletions only when the actor is a **privileged account** accessing another user's mailbox. Regular delegate access (e.g., an EA with delegate access) is filtered out as non-suspicious.

Privileged accounts are defined as holders of:
- **Entra ID roles**: Global Administrator, Exchange Administrator, Privileged Role Administrator, Compliance Administrator, Security Administrator, Application Administrator
- **Exchange role groups**: ApplicationImpersonation, Organization Management, eDiscovery Manager, Records Management, Compliance Management

---

## Verify Audit Prerequisites

```powershell
Get-OrganizationConfig | Select AuditDisabled              # Should be False
Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled  # Should be True
```

---

## Known Limitations

- **Tenant Allow/Block List**: Full retrieval requires Windows PowerShell 5.1; UAL captures changes on all platforms
- **Search-UnifiedAuditLog on macOS**: Available via Exchange Online connection but can be slow; use [Microsoft Purview Audit](https://compliance.microsoft.com) for ad-hoc searches
- **Exchange connection**: Can take 20+ minutes on first run; subsequent runs use cached MSAL tokens
- **PIM eligible roles**: Requires Azure AD Premium P2 / Entra ID Governance license

---

## License

MIT
