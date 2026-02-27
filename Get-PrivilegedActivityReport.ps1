<#
.SYNOPSIS
    Security risk report for policy changes and privilege escalation in Microsoft 365/Azure/Entra ID.

.DESCRIPTION
    This script collects HIGH-RISK security activities only:
    - Privilege escalation (role assignments, PIM activations)
    - Policy changes (Conditional Access, authentication policies)
    - Application permission grants (OAuth consents, app roles)
    - Federation/trust changes
    - eDiscovery and compliance searches

    EXCLUDES routine operations:
    - Password resets, user updates, license changes
    - System/service account activities (Substrate Management, etc.)
    - Day-to-day IT support operations

    Requires: E3/E5 license, Global Reader + Security Admin (minimum)

.PARAMETER DaysBack
    Number of days to look back for activities. Default is 1 (last 24 hours).

.PARAMETER OutputPath
    Directory to save reports. Default is current directory.

.PARAMETER IncludeAzure
    Include Azure subscription activity logs. Requires Az module and appropriate permissions.

.EXAMPLE
    .\Get-PrivilegedActivityReport.ps1

.EXAMPLE
    .\Get-PrivilegedActivityReport.ps1 -DaysBack 7 -OutputPath "C:\Reports"
#>

[CmdletBinding()]
param(
    [int]$DaysBack = 1,
    [string]$OutputPath = $PSScriptRoot,
    [switch]$IncludeAzure,
    [switch]$ForceReauth
)

# Credential cache file path
$credCachePath = Join-Path $PSScriptRoot ".auth_cache.json"

#region Configuration
$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$startDate = (Get-Date).AddDays(-$DaysBack)
$endDate = Get-Date

# System/Service accounts to EXCLUDE from reports (noise reduction)
$excludedActors = @(
    "Substrate Management",
    "Microsoft Substrate Management",
    "FA StrongAuthServer",
    "Microsoft Exchange",
    "Microsoft App Access Panel",
    "Microsoft Azure AD",
    "Azure AD",
    "Microsoft Graph",
    "Microsoft Office",
    "Microsoft Teams",
    "Microsoft SharePoint",
    "Microsoft Power Platform",
    "Microsoft Intune",
    "Microsoft Cloud App Security",
    "Microsoft Defender",
    "Microsoft 365",
    "ObjectId_intune",
    "Managed Identity",
    "Azure Resource Manager",
    "AAD Request Verification Service",
    "Microsoft Password Reset Service",
    "Windows Azure Active Directory",
    "Azure Portal",
    "Microsoft Azure Signup Portal",
    "Microsoft Approval Management",
    "Microsoft.Azure.SyncFabric",
    "Microsoft Azure AD Connect",
    "Microsoft Dynamics",
    "ServiceNow",
    "PIM",
    "System",
    "threatintel",
    "ThreatIntel",
    "Managed Service Identity",
    "Check audit log",
    "Power Virtual Agents Service"
)

# Patterns to exclude (regex)
$excludedActorPatterns = @(
    "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",  # GUIDs (service principals)
    "^Microsoft\s",
    "^Azure\s",
    "^Windows\sAzure",
    "Sync_.*",
    ".*_intune.*",
    "^On-Premises Directory Synchronization",
    "^ServicePrincipal_.*",
    "^[0-9a-f]{8}-0000-0000-[0-9a-f]{4}-[0-9a-f]{12}$",  # Common system GUIDs
    "^0000000[0-9a-f]-.*",  # System app GUIDs starting with 0000000
    "^NT SERVICE\\\\",  # Windows service accounts
    "^NT AUTHORITY\\\\",  # Windows system accounts
    "^S-1-5-18$",  # Local SYSTEM account (automated retention policies)
    "MSExchangeServiceHost"  # Exchange internal service
)

# HIGH-RISK operations only - Policy changes and Privilege escalation
$privilegedOperations = @(
    # === PRIVILEGE ESCALATION ===
    "Add member to role*",
    "Remove member from role*",
    "Add eligible member to role*",
    "Add-RoleGroupMember",
    "Remove-RoleGroupMember",
    "New-RoleGroup",
    "Set-RoleGroup",
    "Remove-RoleGroup",
    "New-ManagementRoleAssignment",
    "Remove-ManagementRoleAssignment",
    "Add owner to group*",
    "SiteCollectionAdminAdded",
    "SiteCollectionAdminRemoved",

    # === CONDITIONAL ACCESS & AUTH POLICIES ===
    # Note: Set/New/Remove-ConditionalAccessPolicy removed - Exchange syncs these internally
    # Real CA changes are captured in Entra ID audit logs with human actors
    "Add policy*",
    "Update policy*",
    "Delete policy*",
    "New-AuthenticationPolicy",
    "Set-AuthenticationPolicy",
    "Remove-AuthenticationPolicy",
    "Set-AuthenticationMethodsPolicy",
    "Update authentication method*",

    # === EXCHANGE MAIL FLOW (data exfil risk) ===
    "New-TransportRule",
    "Set-TransportRule",
    "Remove-TransportRule",
    "Enable-TransportRule",
    "Disable-TransportRule",
    "New-InboundConnector",
    "Set-InboundConnector",
    "Remove-InboundConnector",
    "New-OutboundConnector",
    "Set-OutboundConnector",
    "Remove-OutboundConnector",
    "New-JournalRule",
    "Set-JournalRule",
    "Remove-JournalRule",
    "Set-RemoteDomain",
    "New-RemoteDomain",
    "Set-AcceptedDomain",
    "New-AcceptedDomain",
    "Set-MailboxAuditBypassAssociation",

    # === TENANT ALLOW/BLOCK LIST (TABL) ===
    "New-TenantAllowBlockListItems",
    "Set-TenantAllowBlockListItems",
    "Remove-TenantAllowBlockListItems",
    "TenantAllowBlockList*",

    # === DEFENDER FOR OFFICE 365 ===
    "New-SafeLinksPolicy",
    "Set-SafeLinksPolicy",
    "Remove-SafeLinksPolicy",
    "New-SafeAttachmentPolicy",
    "Set-SafeAttachmentPolicy",
    "Remove-SafeAttachmentPolicy",
    "New-AntiPhishPolicy",
    "Set-AntiPhishPolicy",
    "Remove-AntiPhishPolicy",
    "Set-AtpPolicyForO365",
    "New-QuarantinePolicy",
    "Set-QuarantinePolicy",
    "Remove-QuarantinePolicy",
    "Set-HostedContentFilterPolicy",
    "New-HostedContentFilterPolicy",
    "Set-MalwareFilterPolicy",
    "New-MalwareFilterPolicy",

    # === DEFENDER FOR ENDPOINT ===
    "Add Indicator*",
    "Update Indicator*",
    "Delete Indicator*",
    "Create exclusion*",
    "Update exclusion*",
    "Delete exclusion*",
    "Update device group*",
    "Create device group*",
    "Delete device group*",
    "Update automation*",
    "Create security policy*",
    "Update security policy*",
    "Delete security policy*",
    "AttackSurfaceReduction*",
    "EndpointDetection*",

    # === EDISCOVERY & COMPLIANCE (data exfil risk) ===
    "New-ComplianceSearch",
    "Set-ComplianceSearch",
    "Start-ComplianceSearch",
    "New-ComplianceSearchAction",
    "SearchStarted",
    "SearchExported",
    "CaseAdded",
    "CaseMemberAdded",
    "CaseUpdated",
    "HoldCreated",
    "HoldUpdated",
    "HoldRemoved",
    "New-eDiscoveryCase*",
    "Add-eDiscoveryCaseAdmin*",
    "Update-eDiscoveryCase*",

    # === EMAIL DELETION (data destruction risk) ===
    "SoftDelete",
    "HardDelete",

    # === RETENTION POLICIES ===
    "New-RetentionPolicy",
    "Set-RetentionPolicy",
    "Remove-RetentionPolicy",
    "New-RetentionCompliancePolicy",
    "Set-RetentionCompliancePolicy",
    "Remove-RetentionCompliancePolicy",

    # === INSIDER RISK ===
    "New-InsiderRiskPolicy",
    "Set-InsiderRiskPolicy",
    "Remove-InsiderRiskPolicy",
    "InsiderRisk*",

    # === AUDIT LOG CONFIGURATION ===
    "Set-AdminAuditLogConfig",
    "Set-OrganizationConfig",
    "Set-UnifiedAuditLogConfig*",

    # === APPLICATION PERMISSIONS (backdoor risk) ===
    "Add app role assignment*",
    "Add OAuth2PermissionGrant*",
    "Consent to application*",
    "Add delegated permission grant*",
    "Add application*",
    "Update application*",
    "Add service principal credentials*",
    "Update service principal*",

    # === ENTRA ID SECURITY ===
    "Disable Strong Authentication*",
    "Update named location*",
    "Add named location*",
    "Delete named location*",
    "Update cross-tenant access*",
    "Add cross-tenant access*",
    "Delete cross-tenant access*",
    "Update external identities*",
    "Update identity protection*",
    "Update authentication strength*",
    "Update token lifetime*",

    # === INTUNE / ENDPOINT MANAGER ===
    "Create compliance policy*",
    "Update compliance policy*",
    "Delete compliance policy*",
    "Create configuration profile*",
    "Update configuration profile*",
    "Delete configuration profile*",
    "Create app protection policy*",
    "Update app protection policy*",
    "Delete app protection policy*",
    "Update enrollment restriction*",

    # === FEDERATION / TRUST / DOMAIN ===
    "Set federation settings*",
    "Set domain authentication*",
    "Add unverified domain*",
    "Verify domain*",
    "Update domain*",
    "Set-MsolDomainAuthentication",
    "Set-MsolDomainFederationSettings",

    # === PARTNER / DELEGATED ACCESS ===
    "Add partner*",
    "Update partner*",
    "Remove partner*",
    "Add delegated admin*",
    "Update delegated admin*",
    "Remove delegated admin*",
    "Gdap*",
    "Dap*"
)

# High-risk Entra ID audit categories
$entraAuditCategories = @(
    "RoleManagement",
    "Policy",
    "ApplicationManagement",
    "DirectoryManagement",
    "ResourceManagement"
)

# High-risk operation keywords for Entra ID filtering
$riskyOperationKeywords = @(
    # Role & Permissions
    "role",
    "permission",
    "consent",
    "eligible member",
    "app role",
    "oauth",
    "delegated",

    # Policies
    "policy",
    "conditional access",

    # Credentials & Auth
    "credential",
    "certificate",
    "secret",
    "key credential",
    "authentication",
    "federation",

    # Security Config
    "named location",
    "cross-tenant",
    "external identit",
    "identity protection",
    "authentication strength",
    "token lifetime",

    # Mail Flow
    "transport rule",
    "connector",
    "journal",
    "remote domain",
    "mail flow",

    # Defender
    "safe link",
    "safe attachment",
    "anti-phish",
    "allow block list",
    "quarantine",
    "malware filter",
    "content filter",
    "indicator",
    "exclusion",
    "attack surface",

    # Compliance
    "ediscovery",
    "compliance search",
    "hold",
    "retention",
    "insider risk",
    "audit log",

    # Email Deletion
    "softdelete",
    "harddelete",

    # Partner/Trust
    "partner",
    "delegated admin",
    "gdap",
    "domain"
)

# Helper function to check if actor should be excluded
function Test-ExcludedActor {
    param([string]$Actor)

    if ([string]::IsNullOrWhiteSpace($Actor)) { return $false }

    # Check exact matches
    foreach ($excluded in $excludedActors) {
        if ($Actor -eq $excluded -or $Actor -like "*$excluded*") {
            return $true
        }
    }

    # Check patterns
    foreach ($pattern in $excludedActorPatterns) {
        if ($Actor -match $pattern) {
            return $true
        }
    }

    return $false
}

# Helper function to check if operation is high-risk
function Test-RiskyOperation {
    param([string]$Operation)

    if ([string]::IsNullOrWhiteSpace($Operation)) { return $false }

    $opLower = $Operation.ToLower()
    foreach ($keyword in $riskyOperationKeywords) {
        if ($opLower -match $keyword) {
            return $true
        }
    }
    return $false
}
#endregion

#region Functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $logMessage = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage }
    }
}

function Get-CachedCredentials {
    if ($ForceReauth) {
        Write-Log "Force re-authentication requested, ignoring cache" "INFO"
        return $null
    }

    if (Test-Path $credCachePath) {
        try {
            $cache = Get-Content $credCachePath -Raw | ConvertFrom-Json
            # Check if cache is less than 7 days old
            $cacheAge = (Get-Date) - [DateTime]::Parse($cache.CachedAt)
            if ($cacheAge.TotalDays -lt 7) {
                Write-Log "Using cached credentials for $($cache.UserPrincipalName)" "INFO"
                return $cache
            } else {
                Write-Log "Credential cache expired, will re-authenticate" "INFO"
            }
        }
        catch {
            Write-Log "Failed to read credential cache: $_" "WARN"
        }
    }
    return $null
}

function Save-CredentialCache {
    param([string]$UserPrincipalName)

    $cache = @{
        UserPrincipalName = $UserPrincipalName
        CachedAt = (Get-Date).ToString("o")
    }

    try {
        $cache | ConvertTo-Json | Set-Content $credCachePath -Force
        Write-Log "Saved credential cache for $UserPrincipalName" "SUCCESS"
    }
    catch {
        Write-Log "Failed to save credential cache: $_" "WARN"
    }
}

function Test-ModuleInstalled {
    param([string]$ModuleName)
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Log "Module '$ModuleName' not found. Installing..." "WARN"
        Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module $ModuleName -Force
}

function Connect-Services {
    Write-Log "Connecting to Microsoft services..."

    # Connect to Microsoft Graph
    Write-Log "Connecting to Microsoft Graph..."
    try {
        $graphScopes = @(
            "AuditLog.Read.All",
            "Directory.Read.All",
            "SecurityEvents.Read.All"
        )
        Connect-MgGraph -Scopes $graphScopes -NoWelcome
        Write-Log "Connected to Microsoft Graph" "SUCCESS"
    }
    catch {
        Write-Log "Failed to connect to Microsoft Graph: $_" "ERROR"
        throw
    }

    # Connect to Exchange Online (includes Security & Compliance)
    Write-Log "Connecting to Exchange Online..."
    try {
        Connect-ExchangeOnline -ShowBanner:$false
        Write-Log "Connected to Exchange Online" "SUCCESS"
    }
    catch {
        Write-Log "Failed to connect to Exchange Online: $_" "ERROR"
        throw
    }

    # Connect to Security & Compliance Center
    Write-Log "Connecting to Security & Compliance Center..."
    try {
        Connect-IPPSSession -ShowBanner:$false
        Write-Log "Connected to Security & Compliance Center" "SUCCESS"
    }
    catch {
        Write-Log "Failed to connect to Security & Compliance: $_" "WARN"
    }

    # Optionally connect to Azure
    if ($IncludeAzure) {
        Write-Log "Connecting to Azure..."
        try {
            Connect-AzAccount
            Write-Log "Connected to Azure" "SUCCESS"
        }
        catch {
            Write-Log "Failed to connect to Azure: $_" "WARN"
        }
    }
}

# Operations to explicitly EXCLUDE (noise)
$excludedOperations = @(
    "Activate PIM role",
    "User activated PIM role",
    "Add eligible member to role in PIM",
    "PIM activation",
    "PIM requested",
    "Activate eligible role",
    # Read-only/query operations - not changes, not actionable
    "Validate password",
    "Validate Password",
    "Get Identity Providers",
    "Get identity providers",
    "Read identity providers",
    "Get a signed-in user",
    "Get user",
    "Get group",
    "Get service principal",
    "Get application",
    "List users",
    "List groups"
)

function Test-ExcludedOperation {
    param([string]$Operation)
    if ([string]::IsNullOrWhiteSpace($Operation)) { return $false }
    foreach ($excluded in $excludedOperations) {
        if ($Operation -like "*$excluded*") { return $true }
    }
    return $false
}

function Get-EntraIDAuditLogs {
    Write-Log "Fetching Entra ID audit logs (policy changes & privilege escalation only)..."
    $allLogs = @()
    $skippedSystem = 0
    $skippedRoutine = 0
    $skippedPIM = 0

    try {
        $filter = "activityDateTime ge $($startDate.ToString('yyyy-MM-ddTHH:mm:ssZ'))"

        $auditLogs = Get-MgAuditLogDirectoryAudit -Filter $filter -All

        foreach ($log in $auditLogs) {
            # Get the actor
            $actor = $log.InitiatedBy.User.UserPrincipalName ?? $log.InitiatedBy.App.DisplayName ?? "System"

            # Skip system/service accounts
            if (Test-ExcludedActor -Actor $actor) {
                $skippedSystem++
                continue
            }

            # Skip PIM activation events (the actions taken while elevated are captured separately)
            if (Test-ExcludedOperation -Operation $log.ActivityDisplayName) {
                $skippedPIM++
                continue
            }

            # Include if it's a risky category (Policy, RoleManagement, ApplicationManagement, etc.)
            $isRiskyCategory = $entraAuditCategories -contains $log.Category

            if (-not $isRiskyCategory) {
                $skippedRoutine++
                continue
            }

            $targetResources = ($log.TargetResources | ForEach-Object {
                "$($_.Type): $($_.DisplayName)"
            }) -join "; "

            # Extract modified properties to show what actually changed
            $modifiedProps = @()
            $isPermissionGrantOp = $log.ActivityDisplayName -match "delegated permission grant|OAuth2PermissionGrant|Consent to application|app role assignment"
            foreach ($target in $log.TargetResources) {
                if ($target.ModifiedProperties) {
                    foreach ($prop in $target.ModifiedProperties) {
                        $propName = $prop.DisplayName
                        $newVal = $prop.NewValue
                        $oldVal = $prop.OldValue
                        # Truncate long values but keep useful info
                        if ($newVal -and $newVal.Length -gt 200) {
                            $newVal = $newVal.Substring(0, 200) + "..."
                        }
                        if ($propName -and ($newVal -or $oldVal)) {
                            $modifiedProps += [PSCustomObject]@{ Key = $propName; Value = $newVal; OldValue = $oldVal }
                        }
                    }
                }
            }

            $detailsStr = if ($modifiedProps.Count -gt 0) {
                if ($isPermissionGrantOp) {
                    # Store as structured JSON for richer HTML rendering
                    $modifiedProps | ConvertTo-Json -Compress
                } else {
                    ($modifiedProps | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "
                }
            } else {
                $log.AdditionalDetails | ConvertTo-Json -Compress
            }

            $allLogs += [PSCustomObject]@{
                Timestamp       = $log.ActivityDateTime
                Source          = "EntraID"
                Operation       = $log.ActivityDisplayName
                Category        = $log.Category
                Result          = $log.Result
                InitiatedBy     = $actor
                TargetResources = $targetResources
                IPAddress       = $log.InitiatedBy.User.IpAddress
                Details         = $detailsStr
                CorrelationId   = $log.CorrelationId
            }
        }
        Write-Log "Retrieved $($allLogs.Count) high-risk activities (filtered out $skippedSystem system + $skippedRoutine routine + $skippedPIM PIM activations)" "SUCCESS"
    }
    catch {
        Write-Log "Error fetching Entra ID audit logs: $_" "ERROR"
    }

    return $allLogs
}

function Get-SecurityComplianceActivities {
    Write-Log "Fetching Security & Compliance activities..."
    $allActivities = @()

    # Get eDiscovery cases (shows recent cases that may indicate data exfil risk)
    # Requires eDiscovery Administrator role in Purview
    $ediscoveryCaseCount = 0
    try {
        Write-Log "Checking eDiscovery cases..." "INFO"

        $cases = Get-ComplianceCase -ErrorAction Stop

        foreach ($case in $cases) {
            if ($case.CreatedDateTime -ge $startDate -or $case.LastModifiedDateTime -ge $startDate) {
                $ediscoveryCaseCount++
                $allActivities += [PSCustomObject]@{
                    Timestamp       = $case.LastModifiedDateTime ?? $case.CreatedDateTime
                    Source          = "eDiscovery"
                    Operation       = "eDiscovery Case: $($case.Status)"
                    Category        = "Compliance"
                    Result          = $case.Status
                    InitiatedBy     = $case.CreatedBy ?? "Unknown"
                    TargetResources = $case.Name
                    IPAddress       = ""
                    Details         = "CaseType: $($case.CaseType); Status: $($case.Status)"
                    CorrelationId   = $case.Identity
                }
            }
        }
        if ($ediscoveryCaseCount -gt 0) {
            Write-Log "Found $ediscoveryCaseCount eDiscovery cases" "SUCCESS"
        }
    }
    catch {
        Write-Log "eDiscovery requires 'eDiscovery Administrator' role in Purview" "WARN"
    }

    # Get Retention Policies
    try {
        Write-Log "Checking retention policies..." "INFO"
        $retentionPolicies = Get-RetentionCompliancePolicy -ErrorAction SilentlyContinue

        foreach ($policy in $retentionPolicies) {
            if ($policy.WhenCreatedUTC -ge $startDate -or $policy.WhenChangedUTC -ge $startDate) {
                $allActivities += [PSCustomObject]@{
                    Timestamp       = $policy.WhenChangedUTC ?? $policy.WhenCreatedUTC
                    Source          = "Retention"
                    Operation       = "Retention Policy Modified"
                    Category        = "Compliance"
                    Result          = $policy.Enabled ? "Enabled" : "Disabled"
                    InitiatedBy     = $policy.LastModifiedBy ?? "Unknown"
                    TargetResources = $policy.Name
                    IPAddress       = ""
                    Details         = "Mode: $($policy.Mode)"
                    CorrelationId   = $policy.Guid
                }
            }
        }
    }
    catch {
        Write-Log "Could not fetch retention policies: $_" "WARN"
    }

    # Get Transport Rules (mail flow rules)
    try {
        Write-Log "Checking transport rules..." "INFO"
        $transportRules = Get-TransportRule -ErrorAction SilentlyContinue

        foreach ($rule in $transportRules) {
            if ($rule.WhenChanged -ge $startDate) {
                $allActivities += [PSCustomObject]@{
                    Timestamp       = $rule.WhenChanged
                    Source          = "Exchange"
                    Operation       = "Transport Rule: $($rule.State)"
                    Category        = "MailFlow"
                    Result          = $rule.State
                    InitiatedBy     = "(actor unavailable — search Purview Audit for '$($rule.Name)')"
                    TargetResources = $rule.Name
                    IPAddress       = ""
                    Details         = "Priority: $($rule.Priority); Mode: $($rule.Mode)"
                    CorrelationId   = $rule.Guid
                }
            }
        }
    }
    catch {
        Write-Log "Could not fetch transport rules: $_" "WARN"
    }

    # Get Connectors
    try {
        Write-Log "Checking mail connectors..." "INFO"
        $inboundConnectors = Get-InboundConnector -ErrorAction SilentlyContinue
        $outboundConnectors = Get-OutboundConnector -ErrorAction SilentlyContinue

        foreach ($connector in $inboundConnectors) {
            if ($connector.WhenChanged -ge $startDate) {
                $allActivities += [PSCustomObject]@{
                    Timestamp       = $connector.WhenChanged
                    Source          = "Exchange"
                    Operation       = "Inbound Connector: $($connector.Enabled)"
                    Category        = "MailFlow"
                    Result          = if ($connector.Enabled) { "Enabled" } else { "Disabled" }
                    InitiatedBy     = "(actor unavailable — search Purview Audit for '$($connector.Name)')"
                    TargetResources = $connector.Name
                    IPAddress       = ""
                    Details         = "SenderDomains: $($connector.SenderDomains -join ', ')"
                    CorrelationId   = $connector.Guid
                }
            }
        }

        foreach ($connector in $outboundConnectors) {
            if ($connector.WhenChanged -ge $startDate) {
                $allActivities += [PSCustomObject]@{
                    Timestamp       = $connector.WhenChanged
                    Source          = "Exchange"
                    Operation       = "Outbound Connector: $($connector.Enabled)"
                    Category        = "MailFlow"
                    Result          = if ($connector.Enabled) { "Enabled" } else { "Disabled" }
                    InitiatedBy     = "(actor unavailable — search Purview Audit for '$($connector.Name)')"
                    TargetResources = $connector.Name
                    IPAddress       = ""
                    Details         = "SmartHosts: $($connector.SmartHosts -join ', ')"
                    CorrelationId   = $connector.Guid
                }
            }
        }
    }
    catch {
        Write-Log "Could not fetch connectors: $_" "WARN"
    }

    # Get Tenant Allow/Block List items
    try {
        Write-Log "Checking Tenant Allow/Block List..." "INFO"
        $tablItems = @()

        # TABL cmdlet has issues in PowerShell Core - try each list type separately with error handling
        foreach ($listType in @("Sender", "Url", "FileHash")) {
            try {
                # Try with -Allow parameter first (sometimes works better in pwsh)
                $allowItems = Get-TenantAllowBlockListItems -ListType $listType -Allow -ErrorAction Stop
                $tablItems += $allowItems
            }
            catch {
                # If that fails, try without the filter
                try {
                    $items = Get-TenantAllowBlockListItems -ListType $listType -ErrorAction Stop
                    $tablItems += $items
                }
                catch {
                    # Known PowerShell Core bug - skip silently
                }
            }

            try {
                $blockItems = Get-TenantAllowBlockListItems -ListType $listType -Block -ErrorAction Stop
                $tablItems += $blockItems
            }
            catch {
                # Known PowerShell Core bug - skip silently
            }
        }

        if ($tablItems.Count -eq 0) {
            # If still no results, try using Invoke-Command with the EXO session
            try {
                $exoSession = Get-ConnectionInformation | Where-Object { $_.Name -like "*ExchangeOnline*" } | Select-Object -First 1
                if ($exoSession) {
                    Write-Log "Trying alternative TABL retrieval method..." "INFO"
                    $tablItems = Invoke-Command -Session (Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" } | Select-Object -First 1) -ScriptBlock {
                        $results = @()
                        foreach ($type in @("Sender", "Url", "FileHash")) {
                            try {
                                $results += Get-TenantAllowBlockListItems -ListType $type -ErrorAction SilentlyContinue
                            } catch {}
                        }
                        $results
                    } -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-Log "TABL retrieval requires Windows PowerShell 5.1 (known pwsh limitation)" "WARN"
            }
        }

        $tablCount = 0
        foreach ($item in $tablItems) {
            if ($null -ne $item -and $null -ne $item.LastModifiedDateTime -and $item.LastModifiedDateTime -ge $startDate) {
                $tablCount++
                $allActivities += [PSCustomObject]@{
                    Timestamp       = $item.LastModifiedDateTime
                    Source          = "TABL"
                    Operation       = "Allow/Block List: $($item.Action) $($item.ListType)"
                    Category        = "DefenderO365"
                    Result          = $item.Action
                    InitiatedBy     = $item.LastModifiedBy ?? "Unknown"
                    TargetResources = $item.Value
                    IPAddress       = ""
                    Details         = "ListType: $($item.ListType); Action: $($item.Action); Notes: $($item.Notes)"
                    CorrelationId   = $item.Identity
                }
            }
        }
        if ($tablCount -gt 0) {
            Write-Log "Found $tablCount TABL entries modified in date range" "SUCCESS"
        }
    }
    catch {
        Write-Log "TABL check skipped (PowerShell Core limitation): $_" "WARN"
    }

    # Get Safe Links Policies
    try {
        Write-Log "Checking Safe Links policies..." "INFO"
        $safeLinks = Get-SafeLinksPolicy -ErrorAction SilentlyContinue

        foreach ($policy in $safeLinks) {
            if ($policy.WhenChanged -ge $startDate) {
                $allActivities += [PSCustomObject]@{
                    Timestamp       = $policy.WhenChanged
                    Source          = "DefenderO365"
                    Operation       = "Safe Links Policy Modified"
                    Category        = "DefenderO365"
                    Result          = if ($policy.IsEnabled) { "Enabled" } else { "Disabled" }
                    InitiatedBy     = "(actor unavailable — search Purview Audit for '$($policy.Name)')"
                    TargetResources = $policy.Name
                    IPAddress       = ""
                    Details         = "ScanUrls: $($policy.ScanUrls); EnableForInternalSenders: $($policy.EnableForInternalSenders)"
                    CorrelationId   = $policy.Guid
                }
            }
        }
    }
    catch {
        Write-Log "Could not fetch Safe Links policies: $_" "WARN"
    }

    # Get Safe Attachment Policies
    try {
        Write-Log "Checking Safe Attachments policies..." "INFO"
        $safeAttach = Get-SafeAttachmentPolicy -ErrorAction SilentlyContinue

        foreach ($policy in $safeAttach) {
            if ($policy.WhenChanged -ge $startDate) {
                $allActivities += [PSCustomObject]@{
                    Timestamp       = $policy.WhenChanged
                    Source          = "DefenderO365"
                    Operation       = "Safe Attachment Policy Modified"
                    Category        = "DefenderO365"
                    Result          = if ($policy.Enable) { "Enabled" } else { "Disabled" }
                    InitiatedBy     = "(actor unavailable — search Purview Audit for '$($policy.Name)')"
                    TargetResources = $policy.Name
                    IPAddress       = ""
                    Details         = "Action: $($policy.Action); Redirect: $($policy.Redirect)"
                    CorrelationId   = $policy.Guid
                }
            }
        }
    }
    catch {
        Write-Log "Could not fetch Safe Attachment policies: $_" "WARN"
    }

    # Get Anti-Phishing Policies
    try {
        Write-Log "Checking Anti-Phishing policies..." "INFO"
        $antiPhish = Get-AntiPhishPolicy -ErrorAction SilentlyContinue

        foreach ($policy in $antiPhish) {
            if ($policy.WhenChanged -ge $startDate) {
                $allActivities += [PSCustomObject]@{
                    Timestamp       = $policy.WhenChanged
                    Source          = "DefenderO365"
                    Operation       = "Anti-Phish Policy Modified"
                    Category        = "DefenderO365"
                    Result          = if ($policy.Enabled) { "Enabled" } else { "Disabled" }
                    InitiatedBy     = "(actor unavailable — search Purview Audit for '$($policy.Name)')"
                    TargetResources = $policy.Name
                    IPAddress       = ""
                    Details         = "PhishThreshold: $($policy.PhishThresholdLevel); EnableSpoofIntelligence: $($policy.EnableSpoofIntelligence)"
                    CorrelationId   = $policy.Guid
                }
            }
        }
    }
    catch {
        Write-Log "Could not fetch Anti-Phishing policies: $_" "WARN"
    }

    if ($allActivities.Count -gt 0) {
        Write-Log "Retrieved $($allActivities.Count) Security & Compliance activities" "SUCCESS"
    }
    else {
        Write-Log "No Security & Compliance policy changes found in time range" "INFO"
    }

    return $allActivities
}

function Get-UnifiedAuditLogActivities {
    Write-Log "Fetching Unified Audit Log activities..."
    $allActivities = @()

    try {
        # Check if Search-UnifiedAuditLog is available (requires Windows PowerShell or proper module import)
        $cmdletAvailable = Get-Command -Name Search-UnifiedAuditLog -ErrorAction SilentlyContinue

        if (-not $cmdletAvailable) {
            Write-Log "Search-UnifiedAuditLog not available in pwsh. Checking policy configurations directly..." "INFO"

            # Get Security & Compliance activities by checking current policy states
            $allActivities = Get-SecurityComplianceActivities

            return $allActivities
        }

        # Always run the policy state snapshot first (transport rules, connectors, Defender policies, etc.)
        # This covers things UAL doesn't track well (current state) and runs fast
        Write-Log "Fetching current policy states (transport rules, connectors, Defender policies)..." "INFO"
        $policyStateActivities = Get-SecurityComplianceActivities
        if ($policyStateActivities.Count -gt 0) {
            $allActivities += $policyStateActivities
            Write-Log "Added $($policyStateActivities.Count) policy state activities" "INFO"
        }

        # OPTIMIZED: Query specific operations directly instead of scanning everything
        # Group operations for targeted queries (Search-UnifiedAuditLog -Operations doesn't support wildcards)
        # This runs on ALL platforms (including macOS/pwsh) to capture audit events with actor/timestamp
        # TABL changes are ONLY available via this path (Get-TenantAllowBlockListItems broken in pwsh)
        $targetedOperations = @(
            # Role/Permission changes
            "Add-RoleGroupMember",
            "Remove-RoleGroupMember",
            "New-RoleGroup",
            "Set-RoleGroup",
            "Remove-RoleGroup",
            "New-ManagementRoleAssignment",
            "Remove-ManagementRoleAssignment",
            # Transport rules & Mail flow
            "New-TransportRule",
            "Set-TransportRule",
            "Remove-TransportRule",
            "Enable-TransportRule",
            "Disable-TransportRule",
            "New-JournalRule",
            "Set-JournalRule",
            "Remove-JournalRule",
            # Connectors
            "New-InboundConnector",
            "Set-InboundConnector",
            "Remove-InboundConnector",
            "New-OutboundConnector",
            "Set-OutboundConnector",
            "Remove-OutboundConnector",
            # Defender for Office 365 policies
            "New-SafeLinksPolicy",
            "Set-SafeLinksPolicy",
            "Remove-SafeLinksPolicy",
            "New-SafeAttachmentPolicy",
            "Set-SafeAttachmentPolicy",
            "Remove-SafeAttachmentPolicy",
            "New-AntiPhishPolicy",
            "Set-AntiPhishPolicy",
            "Remove-AntiPhishPolicy",
            "Set-AtpPolicyForO365",
            "New-QuarantinePolicy",
            "Set-QuarantinePolicy",
            "Set-HostedContentFilterPolicy",
            "New-HostedContentFilterPolicy",
            "Set-MalwareFilterPolicy",
            "New-MalwareFilterPolicy",
            # Tenant Allow/Block List
            "New-TenantAllowBlockListItems",
            "Set-TenantAllowBlockListItems",
            "Remove-TenantAllowBlockListItems",
            # eDiscovery & Compliance
            "New-ComplianceSearch",
            "Set-ComplianceSearch",
            "Start-ComplianceSearch",
            "New-ComplianceSearchAction",
            "SearchStarted",
            "SearchExported",
            "CaseAdded",
            "CaseMemberAdded",
            "HoldCreated",
            "HoldUpdated",
            "HoldRemoved",
            # Retention
            "New-RetentionPolicy",
            "Set-RetentionPolicy",
            "Remove-RetentionPolicy",
            "New-RetentionCompliancePolicy",
            "Set-RetentionCompliancePolicy",
            # Audit config
            "Set-AdminAuditLogConfig",
            "Set-OrganizationConfig",
            # Authentication policies
            "New-AuthenticationPolicy",
            "Set-AuthenticationPolicy",
            "Remove-AuthenticationPolicy"
        )

        $totalResults = 0

        # Query in batches of operations (API limit considerations)
        $batchSize = 10
        for ($i = 0; $i -lt $targetedOperations.Count; $i += $batchSize) {
            $opBatch = $targetedOperations[$i..([Math]::Min($i + $batchSize - 1, $targetedOperations.Count - 1))]
            $opString = $opBatch -join ","

            Write-Log "Querying UAL for operations batch $([Math]::Floor($i/$batchSize) + 1)..." "INFO"

            $sessionId = [Guid]::NewGuid().ToString()
            do {
                $results = Search-UnifiedAuditLog `
                    -StartDate $startDate `
                    -EndDate $endDate `
                    -Operations $opBatch `
                    -SessionId $sessionId `
                    -SessionCommand ReturnLargeSet `
                    -ResultSize 5000

                if ($results) {
                    $totalResults += $results.Count

                    foreach ($result in $results) {
                        # Skip excluded actors
                        if (Test-ExcludedActor -Actor $result.UserIds) {
                            continue
                        }

                        $auditData = $result.AuditData | ConvertFrom-Json

                        $allActivities += [PSCustomObject]@{
                            Timestamp       = $result.CreationDate
                            Source          = "UnifiedAuditLog"
                            Operation       = $result.Operations
                            RecordType      = $result.RecordType
                            Result          = $auditData.ResultStatus ?? "Success"
                            InitiatedBy     = $result.UserIds
                            TargetResources = $auditData.ObjectId ?? $auditData.Target ?? ""
                            IPAddress       = $auditData.ClientIP ?? $auditData.ActorIpAddress
                            Details         = $result.AuditData
                            Workload        = $auditData.Workload
                        }
                    }
                }
            } while ($results -and $results.Count -eq 5000)
        }

        $ualCount = $allActivities.Count - $policyStateActivities.Count
        Write-Log "Retrieved $ualCount UAL audit events (queried $totalResults targeted records) + $($policyStateActivities.Count) policy state snapshots = $($allActivities.Count) total" "SUCCESS"

        # Deduplicate: if a UAL audit event exists for the same target as a policy state snapshot,
        # drop the snapshot (UAL version has actor + precise timestamp; snapshot has neither)
        if ($ualCount -gt 0 -and $policyStateActivities.Count -gt 0) {
            $ualTargets = $allActivities |
                Where-Object { $_.Source -eq "UnifiedAuditLog" } |
                ForEach-Object { $_.TargetResources } |
                Where-Object { $_ } |
                Sort-Object -Unique

            $dedupedActivities = $allActivities | Where-Object {
                # Keep all UAL events unconditionally
                if ($_.Source -eq "UnifiedAuditLog") { return $true }
                # For policy snapshots, drop if a UAL event covers the same target object
                $snapshotTarget = $_.TargetResources
                $coveredByUAL = $ualTargets | Where-Object { $snapshotTarget -and $_ -and ($snapshotTarget -like "*$_*" -or $_ -like "*$snapshotTarget*") }
                return (-not $coveredByUAL)
            }

            $dropped = $allActivities.Count - $dedupedActivities.Count
            if ($dropped -gt 0) {
                Write-Log "Removed $dropped policy state snapshot(s) superseded by UAL audit events (UAL has actor info)" "INFO"
            }
            $allActivities = $dedupedActivities
        }
    }
    catch {
        Write-Log "Error fetching Unified Audit Log: $_" "ERROR"
    }

    return $allActivities
}

function Get-SuspiciousEmailDeletions {
    param([hashtable]$PrivilegedUsers = @{})

    Write-Log "Fetching suspicious email deletions..."
    $suspiciousDeletions = @()
    $skippedSystem = 0
    $skippedSelfDelete = 0
    $skippedNonPrivileged = 0

    try {
        $cmdletAvailable = Get-Command -Name Search-UnifiedAuditLog -ErrorAction SilentlyContinue
        if (-not $cmdletAvailable) {
            Write-Log "Search-UnifiedAuditLog not available in pwsh. Cannot fetch suspicious email deletions." "WARN"
            return @()
        }

        $operations = @("SoftDelete", "HardDelete")
        $sessionId = [Guid]::NewGuid().ToString()

        do {
            $results = Search-UnifiedAuditLog `
                -StartDate $startDate `
                -EndDate $endDate `
                -Operations $operations `
                -SessionId $sessionId `
                -SessionCommand ReturnLargeSet `
                -ResultSize 5000

            if ($results) {
                foreach ($result in $results) {
                    $auditData = $result.AuditData | ConvertFrom-Json

                    # Skip system accounts (S-1-5-18 is SYSTEM account for automated retention policies)
                    if ($auditData.Actor -eq "S-1-5-18" -or (Test-ExcludedActor -Actor $result.UserIds)) {
                        $skippedSystem++
                        continue
                    }

                    # Skip if the actor is the mailbox owner (normal user deletion)
                    if ($auditData.MailboxOwnerUPN -and ($auditData.Actor -eq $auditData.MailboxOwnerUPN -or $result.UserIds -eq $auditData.MailboxOwnerUPN)) {
                        $skippedSelfDelete++
                        continue
                    }

                    # Skip non-privileged actors — delegate access is not a security concern
                    if ($PrivilegedUsers.Count -gt 0 -and -not $PrivilegedUsers.ContainsKey($result.UserIds.ToLower())) {
                        $skippedNonPrivileged++
                        continue
                    }

                    $actorRoles = if ($PrivilegedUsers.Count -gt 0) {
                        ($PrivilegedUsers[$result.UserIds.ToLower()] -join ", ")
                    } else { "" }

                    $suspiciousDeletions += [PSCustomObject]@{
                        Timestamp       = $result.CreationDate
                        Source          = "UnifiedAuditLog"
                        Operation       = $result.Operations
                        RecordType      = $result.RecordType
                        Result          = $auditData.ResultStatus ?? "Success"
                        InitiatedBy     = $result.UserIds
                        MailboxOwnerUPN = $auditData.MailboxOwnerUPN
                        ActorRoles      = $actorRoles
                        TargetResources = $auditData.ObjectId ?? $auditData.Target ?? ""
                        IPAddress       = $auditData.ClientIP ?? $auditData.ActorIpAddress
                        Details         = $result.AuditData # Keep raw data for HTML report parsing
                        Workload        = $auditData.Workload
                    }
                }
            }
        } while ($results -and $results.Count -eq 5000)

        Write-Log "Retrieved $($suspiciousDeletions.Count) suspicious email deletions (filtered out $skippedSystem system + $skippedSelfDelete self-deletions + $skippedNonPrivileged non-privileged delegate access)" "SUCCESS"
    }
    catch {
        Write-Log "Error fetching suspicious email deletions: $_" "WARN"
    }

    return $suspiciousDeletions
}

function Get-AzureActivityLogs {
    if (-not $IncludeAzure) { return @() }

    Write-Log "Fetching Azure Activity Logs..."
    $allActivities = @()

    try {
        $subscriptions = Get-AzSubscription

        foreach ($sub in $subscriptions) {
            Set-AzContext -Subscription $sub.Id | Out-Null
            Write-Log "Scanning subscription: $($sub.Name)"

            $logs = Get-AzActivityLog `
                -StartTime $startDate `
                -EndTime $endDate `
                -MaxRecord 1000

            foreach ($log in $logs) {
                # Filter for privileged/administrative operations
                if ($log.Authorization.Action -match "write|delete|action" -or
                    $log.OperationName.Value -match "roleAssignments|roleDefinitions|policyAssignments|locks") {

                    $allActivities += [PSCustomObject]@{
                        Timestamp       = $log.EventTimestamp
                        Source          = "AzureActivity"
                        Operation       = $log.OperationName.Value
                        Category        = $log.Category.Value
                        Result          = $log.Status.Value
                        InitiatedBy     = $log.Caller
                        TargetResources = $log.ResourceId
                        IPAddress       = $log.HttpRequest.ClientIpAddress
                        Subscription    = $sub.Name
                        Details         = $log.Properties | ConvertTo-Json -Compress
                    }
                }
            }
        }
        Write-Log "Retrieved $($allActivities.Count) Azure privileged activities" "SUCCESS"
    }
    catch {
        Write-Log "Error fetching Azure Activity Logs: $_" "ERROR"
    }

    return $allActivities
}

function Get-SignInRiskEvents {
    Write-Log "Fetching risky sign-ins (human users only)..."
    $riskySignIns = @()
    $skippedSystem = 0

    try {
        # Get risky sign-ins
        $signIns = Get-MgAuditLogSignIn -Filter "riskLevelDuringSignIn ne 'none' and createdDateTime ge $($startDate.ToString('yyyy-MM-ddTHH:mm:ssZ'))" -All

        foreach ($signIn in $signIns) {
            # Skip system/service accounts
            if (Test-ExcludedActor -Actor $signIn.UserPrincipalName) {
                $skippedSystem++
                continue
            }
            if (Test-ExcludedActor -Actor $signIn.AppDisplayName) {
                $skippedSystem++
                continue
            }

            $riskySignIns += [PSCustomObject]@{
                Timestamp        = $signIn.CreatedDateTime
                Source           = "RiskySignIn"
                User             = $signIn.UserPrincipalName
                RiskLevel        = $signIn.RiskLevelDuringSignIn
                RiskState        = $signIn.RiskState
                RiskDetail       = $signIn.RiskDetail
                IPAddress        = $signIn.IpAddress
                Location         = "$($signIn.Location.City), $($signIn.Location.CountryOrRegion)"
                AppDisplayName   = $signIn.AppDisplayName
                DeviceDetail     = $signIn.DeviceDetail.DisplayName
                ConditionalAccess = ($signIn.AppliedConditionalAccessPolicies | Where-Object { $_.Result -ne 'notApplied' } | ForEach-Object { $_.DisplayName }) -join "; "
            }
        }
        Write-Log "Retrieved $($riskySignIns.Count) risky sign-in events (filtered out $skippedSystem system accounts)" "SUCCESS"
    }
    catch {
        Write-Log "Error fetching risky sign-ins: $_" "WARN"
    }

    return $riskySignIns
}

function Get-PrivilegedRoleAssignments {
    Write-Log "Fetching current privileged role assignments (human users only)..."
    $roleAssignments = @()
    $skippedSystem = 0

    # High-risk roles to focus on
    $highRiskRoles = @(
        "Global Administrator",
        "Privileged Role Administrator",
        "Privileged Authentication Administrator",
        "Security Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "User Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Authentication Administrator",
        "Conditional Access Administrator",
        "Compliance Administrator",
        "Intune Administrator",
        "Azure AD Joined Device Local Administrator",
        "Helpdesk Administrator",
        "Password Administrator",
        "Groups Administrator",
        "License Administrator"
    )

    # Get role definitions for name lookup
    $roleDefinitions = @{}
    try {
        $roleDefs = Get-MgRoleManagementDirectoryRoleDefinition -All
        foreach ($rd in $roleDefs) {
            $roleDefinitions[$rd.Id] = $rd.DisplayName
        }
    }
    catch {
        Write-Log "Could not fetch role definitions: $_" "WARN"
    }

    try {
        # Get ACTIVE role assignments (currently assigned)
        Write-Log "Fetching active role assignments..."
        $roles = Get-MgDirectoryRole -All

        foreach ($role in $roles) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All

            foreach ($member in $members) {
                $memberType = $member.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
                $memberDetails = Get-MgDirectoryObject -DirectoryObjectId $member.Id
                $memberName = $memberDetails.AdditionalProperties.displayName
                $memberUPN = $memberDetails.AdditionalProperties.userPrincipalName

                # Skip service principals and system accounts
                if ($memberType -eq "servicePrincipal") {
                    $skippedSystem++
                    continue
                }

                if (Test-ExcludedActor -Actor $memberName) {
                    $skippedSystem++
                    continue
                }

                if (Test-ExcludedActor -Actor $memberUPN) {
                    $skippedSystem++
                    continue
                }

                # Determine if this is a high-risk role
                $isHighRisk = $highRiskRoles -contains $role.DisplayName

                $roleAssignments += [PSCustomObject]@{
                    RoleName        = $role.DisplayName
                    RoleId          = $role.Id
                    MemberId        = $member.Id
                    MemberType      = $memberType
                    MemberName      = $memberName
                    MemberUPN       = $memberUPN
                    IsHighRisk      = $isHighRisk
                    AssignmentType  = "Active"
                }
            }
        }
        $activeCount = $roleAssignments.Count
        Write-Log "Retrieved $activeCount active role assignments" "SUCCESS"
    }
    catch {
        Write-Log "Error fetching active role assignments: $_" "WARN"
    }

    # Get PIM ELIGIBLE role assignments
    try {
        Write-Log "Fetching PIM eligible role assignments..."
        $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All

        foreach ($eligible in $eligibleAssignments) {
            $principalId = $eligible.PrincipalId
            $roleDefId = $eligible.RoleDefinitionId
            $roleName = $roleDefinitions[$roleDefId] ?? "Unknown Role"

            # Get principal details
            try {
                $principal = Get-MgDirectoryObject -DirectoryObjectId $principalId
                $principalType = $principal.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
                $principalName = $principal.AdditionalProperties.displayName
                $principalUPN = $principal.AdditionalProperties.userPrincipalName

                # Skip service principals and system accounts
                if ($principalType -eq "servicePrincipal") {
                    $skippedSystem++
                    continue
                }

                if (Test-ExcludedActor -Actor $principalName) {
                    $skippedSystem++
                    continue
                }

                if (Test-ExcludedActor -Actor $principalUPN) {
                    $skippedSystem++
                    continue
                }

                # Check if already in list as active (avoid duplicates)
                $alreadyActive = $roleAssignments | Where-Object {
                    $_.MemberUPN -eq $principalUPN -and $_.RoleName -eq $roleName -and $_.AssignmentType -eq "Active"
                }
                if ($alreadyActive) {
                    continue
                }

                $isHighRisk = $highRiskRoles -contains $roleName

                $roleAssignments += [PSCustomObject]@{
                    RoleName        = $roleName
                    RoleId          = $roleDefId
                    MemberId        = $principalId
                    MemberType      = $principalType
                    MemberName      = $principalName
                    MemberUPN       = $principalUPN
                    IsHighRisk      = $isHighRisk
                    AssignmentType  = "PIM Eligible"
                }
            }
            catch {
                # Skip if we can't resolve the principal
                continue
            }
        }
        $eligibleCount = $roleAssignments.Count - $activeCount
        Write-Log "Retrieved $eligibleCount PIM eligible role assignments" "SUCCESS"
    }
    catch {
        Write-Log "Error fetching PIM eligible assignments (may require PIM license): $_" "WARN"
    }

    Write-Log "Total: $($roleAssignments.Count) role assignments (filtered out $skippedSystem system accounts)" "SUCCESS"
    return $roleAssignments
}

function Build-PrivilegedUserSet {
    param([array]$RoleAssignments)

    $privilegedUsers = @{}

    # Entra ID roles that warrant elevated scrutiny for email deletions
    $sensitiveRoles = @(
        "Global Administrator",
        "Exchange Administrator",
        "Privileged Role Administrator",
        "Compliance Administrator",
        "Security Administrator",
        "Application Administrator"
    )

    # From Entra ID role assignments (already fetched)
    foreach ($ra in $RoleAssignments) {
        if ($ra.MemberUPN -and ($sensitiveRoles -contains $ra.RoleName)) {
            $upn = $ra.MemberUPN.ToLower()
            if (-not $privilegedUsers.ContainsKey($upn)) { $privilegedUsers[$upn] = @() }
            $privilegedUsers[$upn] += $ra.RoleName
        }
    }

    # From Exchange role groups (AppImpersonation etc.)
    $exoGroups = @("ApplicationImpersonation", "Organization Management",
                   "eDiscovery Manager", "Records Management", "Compliance Management")
    foreach ($group in $exoGroups) {
        try {
            $members = Get-RoleGroupMember -Identity $group -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                $upn = ($m.WindowsEmailAddress ?? $m.PrimarySmtpAddress)?.ToLower()
                if ($upn) {
                    if (-not $privilegedUsers.ContainsKey($upn)) { $privilegedUsers[$upn] = @() }
                    $privilegedUsers[$upn] += "Exchange:$group"
                }
            }
        }
        catch { Write-Log "Could not query role group '$group': $_" "WARN" }
    }

    Write-Log "Privileged user set: $($privilegedUsers.Count) unique users" "SUCCESS"
    return $privilegedUsers
}

function Export-Reports {
    param(
        [array]$EntraLogs,
        [array]$UALLogs,
        [array]$AzureLogs,
        [array]$RoleAssignments,
        [array]$SuspiciousDeletions
    )

    Write-Log "Exporting reports..."

    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Export individual CSVs
    if ($EntraLogs.Count -gt 0) {
        $entraPath = Join-Path $OutputPath "SecurityRisk_Activities_$timestamp.csv"
        $EntraLogs | Export-Csv -Path $entraPath -NoTypeInformation
        Write-Log "Exported high-risk activities to: $entraPath"
    }

    if ($UALLogs.Count -gt 0) {
        $ualPath = Join-Path $OutputPath "UnifiedAuditLog_$timestamp.csv"
        $UALLogs | Export-Csv -Path $ualPath -NoTypeInformation
        Write-Log "Exported UAL logs to: $ualPath"
    }

    if ($AzureLogs.Count -gt 0) {
        $azurePath = Join-Path $OutputPath "AzureActivity_$timestamp.csv"
        $AzureLogs | Export-Csv -Path $azurePath -NoTypeInformation
        Write-Log "Exported Azure logs to: $azurePath"
    }

    if ($RoleAssignments.Count -gt 0) {
        $rolesPath = Join-Path $OutputPath "PrivilegedRoles_$timestamp.csv"
        $RoleAssignments | Export-Csv -Path $rolesPath -NoTypeInformation
        Write-Log "Exported role assignments to: $rolesPath"
    }

    if ($SuspiciousDeletions.Count -gt 0) {
        $deletionsPath = Join-Path $OutputPath "SuspiciousEmailDeletions_$timestamp.csv"
        $SuspiciousDeletions | Export-Csv -Path $deletionsPath -NoTypeInformation
        Write-Log "Exported suspicious email deletions to: $deletionsPath"
    }

    # Create combined summary report
    $allActivities = @()
    $allActivities += $EntraLogs
    $allActivities += $UALLogs
    $allActivities += $AzureLogs
    $allActivities += $SuspiciousDeletions

    if ($allActivities.Count -gt 0) {
        $combinedPath = Join-Path $OutputPath "PrivilegedActivity_Combined_$timestamp.csv"
        $allActivities | Sort-Object Timestamp -Descending | Export-Csv -Path $combinedPath -NoTypeInformation
        Write-Log "Exported combined report to: $combinedPath"
    }

    # Generate HTML Summary Report
    $htmlReport = Generate-HtmlReport -EntraLogs $EntraLogs -UALLogs $UALLogs -AzureLogs $AzureLogs -RoleAssignments $RoleAssignments -SuspiciousDeletions $SuspiciousDeletions
    $htmlPath = Join-Path $OutputPath "PrivilegedActivity_Report_$timestamp.html"
    $htmlReport | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Log "Exported HTML report to: $htmlPath" "SUCCESS"

    return $htmlPath
}

function Generate-HtmlReport {
    param(
        [array]$EntraLogs,
        [array]$UALLogs,
        [array]$AzureLogs,
        [array]$RoleAssignments,
        [array]$SuspiciousDeletions
    )

    $totalActivities = $EntraLogs.Count + $UALLogs.Count + $AzureLogs.Count + $SuspiciousDeletions.Count
    $allLogs = @()
    $allLogs += $EntraLogs
    $allLogs += $UALLogs
    $allLogs += $SuspiciousDeletions # Add suspicious deletions to overall logs for top actors and operations

    # Get top actors
    $allActors = @()
    $allActors += $EntraLogs | Select-Object -ExpandProperty InitiatedBy
    $allActors += $UALLogs | Select-Object -ExpandProperty InitiatedBy
    $allActors += $SuspiciousDeletions | Select-Object -ExpandProperty InitiatedBy # Include actors from deletions
    $topActors = $allActors | Group-Object | Sort-Object Count -Descending | Select-Object -First 10

    # Get operation breakdown with details
    $opsGrouped = $allLogs | Group-Object -Property Operation | Sort-Object Count -Descending

    # Count high-risk role holders
    $highRiskRoleCount = ($RoleAssignments | Where-Object { $_.IsHighRisk -eq $true }).Count

    # Build suspicious deletions table
    $suspiciousDeletionsHtml = ""
    if ($SuspiciousDeletions.Count -gt 0) {
        $deletionRows = $SuspiciousDeletions | Sort-Object Timestamp -Descending | ForEach-Object {
            $auditData = $_.Details | ConvertFrom-Json # Assuming Details is JSON string from UAL
            $itemCount = ($auditData.AffectedItems | Measure-Object).Count
            # Check if AffectedItems exists and is an array/list, otherwise default to 1 for a single deletion event
            if ($null -eq $auditData.AffectedItems) {
                $itemCount = 1
            } elseif ($auditData.AffectedItems -is [System.Array]) {
                $itemCount = $auditData.AffectedItems.Count
            } else {
                $itemCount = 1 # Fallback for single item or unexpected format
            }

            "<tr><td style='white-space:nowrap'>$($_.Timestamp)</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.Operation))</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.InitiatedBy))</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.MailboxOwnerUPN))</td><td>$itemCount</td><td>$($_.IPAddress)</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.ActorRoles))</td></tr>"
        }
        $suspiciousDeletionsHtml = $deletionRows -join "`n"
    }

    # Build the operations detail sections
    $opsDetailHtml = ""
    $opIndex = 0
    foreach ($opGroup in $opsGrouped) {
        $opIndex++
        $opName = $opGroup.Name
        $opCount = $opGroup.Count
        $opDetails = $opGroup.Group | Sort-Object Timestamp -Descending

        $detailRows = ""
        foreach ($detail in $opDetails) {
            $targetDisplay = if ($detail.TargetResources -and $detail.TargetResources.Length -gt 100) {
                [System.Web.HttpUtility]::HtmlEncode($detail.TargetResources.Substring(0,100)) + "..."
            } else {
                [System.Web.HttpUtility]::HtmlEncode($detail.TargetResources)
            }
            # Format details for display - show key info
            $detailsDisplay = ""
            if ($detail.Details) {
                # Special-case: delegated permission grant operations - parse for app name and scopes
                $opNameLower = $detail.Operation.ToLower()
                if ($opNameLower -match "delegated permission grant" -or $opNameLower -match "oauth2permissiongrant" -or $opNameLower -match "consent to application" -or $opNameLower -match "app role assignment") {
                    try {
                        $jsonDetails = $detail.Details | ConvertFrom-Json
                        $parts = @()

                        # Extract app name from TargetResources (e.g. "ServicePrincipal: MyApp; Application: MyApp")
                        $appName = ""
                        if ($detail.TargetResources) {
                            $targets = $detail.TargetResources -split "; "
                            foreach ($t in $targets) {
                                if ($t -match "^(ServicePrincipal|Application):\s*(.+)$") {
                                    $appName = $Matches[2].Trim()
                                    break
                                }
                            }
                        }
                        if ($appName) { $parts += "<strong>App:</strong> $([System.Web.HttpUtility]::HtmlEncode($appName))" }

                        # Structured format: array of {Key, Value, OldValue} from ModifiedProperties
                        if ($jsonDetails -is [System.Array]) {
                            foreach ($entry in $jsonDetails) {
                                $key = $entry.Key
                                $val = $entry.Value
                                if (-not $val -or $val -eq '""' -or $val -eq "[]") { continue }

                                # Clean up JSON-encoded string values (remove surrounding quotes)
                                $val = $val -replace '^"(.*)"$', '$1'

                                switch -Regex ($key) {
                                    "Scope" {
                                        # Scope is space-delimited permissions list
                                        $scopeClean = $val -replace '[\[\]"]', '' -replace ',', ' '
                                        $parts += "<strong>Permissions:</strong> $([System.Web.HttpUtility]::HtmlEncode($scopeClean))"
                                    }
                                    "ConsentType" {
                                        $consentLabel = if ($val -match "AllPrincipals") { "$val (admin consent — applies to ALL users)" } else { $val }
                                        $parts += "<strong>Consent Type:</strong> $([System.Web.HttpUtility]::HtmlEncode($consentLabel))"
                                    }
                                    "PrincipalId" {
                                        if ($val -and $val -ne '""') {
                                            $parts += "<strong>Granted To User ID:</strong> $([System.Web.HttpUtility]::HtmlEncode($val))"
                                        }
                                    }
                                    "AppId|ClientId" {
                                        $parts += "<strong>App ID:</strong> $([System.Web.HttpUtility]::HtmlEncode($val))"
                                    }
                                    "AppRole|RoleId|Role" {
                                        $parts += "<strong>App Role:</strong> $([System.Web.HttpUtility]::HtmlEncode($val))"
                                    }
                                }
                            }
                        }

                        # If we got nothing useful, fall back to raw
                        if ($parts.Count -le 1) {
                            $detailsDisplay = [System.Web.HttpUtility]::HtmlEncode($detail.Details)
                        } else {
                            $detailsDisplay = $parts -join "<br/>"
                        }
                    } catch {
                        $detailsDisplay = [System.Web.HttpUtility]::HtmlEncode($detail.Details)
                    }
                } else {
                    # Standard detail parsing for all other operations
                    try {
                        $jsonDetails = $detail.Details | ConvertFrom-Json
                        if ($jsonDetails.OperationProperties) {
                            $detailsDisplay = ($jsonDetails.OperationProperties | ForEach-Object { "$($_.Name): $($_.Value)" }) -join "; "
                        } elseif ($jsonDetails.Parameters) {
                            $detailsDisplay = ($jsonDetails.Parameters | ForEach-Object { "$($_.Name): $($_.Value)" }) -join "; "
                        } else {
                            $detailsDisplay = $detail.Details
                        }
                    } catch {
                        $detailsDisplay = $detail.Details
                    }
                    $detailsDisplay = [System.Web.HttpUtility]::HtmlEncode($detailsDisplay)
                    $detailsDisplay = $detailsDisplay -replace "; ", ";<br/>"
                }
            }
            $detailRows += "<tr><td style='white-space:nowrap'>$($detail.Timestamp)</td><td>$([System.Web.HttpUtility]::HtmlEncode($detail.InitiatedBy))</td><td>$targetDisplay</td><td style='font-size:11px;max-width:500px;word-wrap:break-word'>$detailsDisplay</td><td>$($detail.Result)</td></tr>`n"
        }

        $opsDetailHtml += @"
        <details class="op-section">
            <summary class="op-summary">
                <span class="op-name">$([System.Web.HttpUtility]::HtmlEncode($opName))</span>
                <span class="badge badge-count">$opCount</span>
            </summary>
            <table class="detail-table">
                <tr><th>Time</th><th>Performed By</th><th>Target</th><th>Details</th><th>Result</th></tr>
                $detailRows
            </table>
        </details>
"@
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Risk Report - Policy Changes & Privilege Escalation - $timestamp</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #c50f1f; border-bottom: 3px solid #c50f1f; padding-bottom: 10px; }
        h2 { color: #323130; margin-top: 30px; }
        .subtitle { color: #605e5c; font-size: 14px; margin-top: -10px; margin-bottom: 20px; }
        .summary-cards { display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 200px; }
        .card h3 { margin: 0 0 10px 0; color: #605e5c; font-size: 14px; }
        .card .value { font-size: 32px; font-weight: bold; color: #0078d4; }
        .card.warning .value { color: #d83b01; }
        .card.critical .value { color: #c50f1f; }
        table { width: 100%; border-collapse: collapse; background: white; margin: 10px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background: #0078d4; color: white; padding: 12px; text-align: left; }
        td { padding: 10px 12px; border-bottom: 1px solid #edebe9; }
        tr:hover { background: #f3f2f1; }
        tr.high-risk { background: #fdf3f4; }
        tr.high-risk:hover { background: #fce8e9; }
        .risk-high { color: #a80000; font-weight: bold; }
        .risk-medium { color: #d83b01; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .badge-critical { background: #c50f1f; color: white; }
        .badge-warning { background: #f7630c; color: white; }
        .badge-count { background: #0078d4; color: white; font-size: 13px; padding: 4px 10px; }
        .timestamp { color: #605e5c; font-size: 12px; }
        .section { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .filter-note { background: #eff6fc; border-left: 4px solid #0078d4; padding: 10px 15px; margin: 10px 0; font-size: 13px; }

        /* Expandable operations using HTML5 details/summary */
        .op-section { background: white; margin: 5px 0; border: 1px solid #e1e1e1; border-radius: 4px; }
        .op-summary { padding: 12px 15px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; background: #f5f5f5; }
        .op-summary:hover { background: #e6f2ff; }
        .op-name { font-weight: 500; }
        details[open] .op-summary { background: #e1e1e1; }
        .detail-table { margin: 0; box-shadow: none; border: none; border-top: 1px solid #e1e1e1; width: 100%; }
        .detail-table th { background: #605e5c; font-size: 12px; padding: 8px 12px; }
        .detail-table td { font-size: 13px; padding: 8px 12px; border-bottom: 1px solid #edebe9; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Risk Report</h1>
        <p class="subtitle">Policy Changes & Privilege Escalation Activity (System accounts excluded)</p>
        <p class="timestamp">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Period: $($startDate.ToString("yyyy-MM-dd HH:mm")) to $($endDate.ToString("yyyy-MM-dd HH:mm"))</p>

        <div class="filter-note">
            This report shows only high-risk activities: role assignments, policy changes, application permissions, and privilege escalation.
            Routine operations (password resets, user updates, license changes) and system account activities are excluded.
        </div>

        <div class="summary-cards">
            <div class="card $(if($totalActivities -gt 0){'critical'})">
                <h3>High-Risk Activities</h3>
                <div class="value">$totalActivities</div>
            </div>
            <div class="card">
                <h3>Policy/Role Changes</h3>
                <div class="value">$($EntraLogs.Count)</div>
            </div>
            <div class="card">
                <h3>Privileged Users</h3>
                <div class="value">$($RoleAssignments.Count)</div>
            </div>
            <div class="card $(if($highRiskRoleCount -gt 10){'warning'})">
                <h3>Global/Security Admins</h3>
                <div class="value">$highRiskRoleCount</div>
            </div>
        </div>

        <div class="section">
            <h2>Users Making High-Risk Changes</h2>
            <table>
                <tr><th>User</th><th>Risk Activity Count</th></tr>
                $($topActors | ForEach-Object { "<tr><td>$($_.Name)</td><td>$($_.Count)</td></tr>" })
            </table>
        </div>

        $(if ($SuspiciousDeletions.Count -gt 0) {@"
        <div class="section">
            <h2>Suspicious Email Deletions</h2>
            <p style="color:#605e5c;font-size:13px;margin-bottom:15px;">Privileged account accessing another user's mailbox (excludes SYSTEM/automated retention and non-privileged delegate access)</p>
            <table>
                <tr><th>Time</th><th>Operation</th><th>Performed By</th><th>Mailbox Owner</th><th>Items</th><th>IP Address</th><th>Actor Role</th></tr>
                $suspiciousDeletionsHtml
            </table>
        </div>
"@})

        <div class="section">
            <h2>High-Risk Operations Performed</h2>
            <p style="color:#605e5c;font-size:13px;margin-bottom:15px;">Click any operation to expand/collapse details</p>
            $opsDetailHtml
        </div>

        <div class="section">
            <h2>Current Privileged Role Assignments (Human Users Only)</h2>
            <table>
                <tr><th>Role</th><th>Risk</th><th>Assignment</th><th>Member</th><th>UPN</th></tr>
                $($RoleAssignments | Sort-Object @{Expression={$_.IsHighRisk}; Descending=$true}, @{Expression={$_.AssignmentType}}, RoleName | ForEach-Object {
                    $rowClass = if($_.IsHighRisk){'high-risk'}else{''}
                    $riskBadge = if($_.IsHighRisk){'<span class="badge badge-critical">HIGH</span>'}else{'<span class="badge badge-warning">ELEVATED</span>'}
                    $assignBadge = if($_.AssignmentType -eq 'Active'){'<span class="badge" style="background:#107c10;color:white">Active</span>'}else{'<span class="badge" style="background:#5c2d91;color:white">PIM Eligible</span>'}
                    "<tr class='$rowClass'><td>$($_.RoleName)</td><td>$riskBadge</td><td>$assignBadge</td><td>$($_.MemberName)</td><td>$($_.MemberUPN)</td></tr>"
                })
            </table>
        </div>
    </div>
</body>
</html>
"@

    return $html
}

function Disconnect-Services {
    Write-Log "Disconnecting from services..."

    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    if ($IncludeAzure) {
        try { Disconnect-AzAccount -ErrorAction SilentlyContinue } catch {}
    }

    Write-Log "Disconnected from all services" "SUCCESS"
}
#endregion

#region Main Execution
try {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "  Security Risk Report Generator" -ForegroundColor Cyan
    Write-Host "  Policy Changes & Privilege Escalation" -ForegroundColor Cyan
    Write-Host "  Period: Last $DaysBack day(s)" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""

    # Check and install required modules
    Write-Log "Checking required PowerShell modules..."
    Test-ModuleInstalled "Microsoft.Graph.Authentication"
    Test-ModuleInstalled "Microsoft.Graph.Reports"
    Test-ModuleInstalled "Microsoft.Graph.Identity.DirectoryManagement"
    Test-ModuleInstalled "Microsoft.Graph.Identity.Governance"
    Test-ModuleInstalled "ExchangeOnlineManagement"
    if ($IncludeAzure) {
        Test-ModuleInstalled "Az.Accounts"
        Test-ModuleInstalled "Az.Monitor"
    }

    # Load cached credentials
    $cachedCreds = Get-CachedCredentials
    $userUPN = $cachedCreds?.UserPrincipalName

    # Connect to Graph FIRST and fetch Graph-dependent data immediately
    # (Exchange connection takes 20+ min and Graph tokens expire)
    Write-Log "Connecting to Microsoft Graph..."
    try {
        $graphScopes = @(
            "AuditLog.Read.All",
            "Directory.Read.All",
            "SecurityEvents.Read.All"
        )
        # Use cached UPN if available for silent auth attempt
        if ($userUPN -and -not $ForceReauth) {
            Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop
        } else {
            Connect-MgGraph -Scopes $graphScopes -NoWelcome
        }
        Write-Log "Connected to Microsoft Graph" "SUCCESS"

        # Get and cache the current user's UPN if not already cached
        if (-not $userUPN) {
            try {
                $context = Get-MgContext
                $userUPN = $context.Account
                if ($userUPN) {
                    Save-CredentialCache -UserPrincipalName $userUPN
                }
            } catch {
                Write-Log "Could not determine user UPN for caching" "WARN"
            }
        }
    }
    catch {
        Write-Log "Failed to connect to Microsoft Graph: $_" "ERROR"
        throw
    }

    # Fetch Graph-dependent data IMMEDIATELY before token expires
    $entraLogs = Get-EntraIDAuditLogs
    $roleAssignments = Get-PrivilegedRoleAssignments

    # Now connect to Exchange (slow) and Compliance
    Write-Log "Connecting to Exchange Online..."
    try {
        # Use cached UPN for faster connection if available
        if ($userUPN -and -not $ForceReauth) {
            Connect-ExchangeOnline -UserPrincipalName $userUPN -ShowBanner:$false
        } else {
            Connect-ExchangeOnline -ShowBanner:$false
        }
        Write-Log "Connected to Exchange Online" "SUCCESS"
    }
    catch {
        Write-Log "Failed to connect to Exchange Online: $_" "ERROR"
        throw
    }

    Write-Log "Connecting to Security & Compliance Center..."
    try {
        if ($userUPN -and -not $ForceReauth) {
            Connect-IPPSSession -UserPrincipalName $userUPN -ShowBanner:$false
        } else {
            Connect-IPPSSession -ShowBanner:$false
        }
        Write-Log "Connected to Security & Compliance Center" "SUCCESS"
    }
    catch {
        Write-Log "Failed to connect to Security & Compliance: $_" "WARN"
    }

    # Build privileged user set (Entra roles + Exchange role groups)
    $privilegedUserSet = Build-PrivilegedUserSet -RoleAssignments $roleAssignments

    # Fetch Exchange-dependent data
    $ualLogs = Get-UnifiedAuditLogActivities
    $azureLogs = Get-AzureActivityLogs
    $suspiciousDeletions = Get-SuspiciousEmailDeletions -PrivilegedUsers $privilegedUserSet

    # Export reports
    $reportPath = Export-Reports `
        -EntraLogs $entraLogs `
        -UALLogs $ualLogs `
        -AzureLogs $azureLogs `
        -RoleAssignments $roleAssignments `
        -SuspiciousDeletions $suspiciousDeletions

    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "  Report generation complete!" -ForegroundColor Green
    Write-Host "  HTML Report: $reportPath" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host ""

    # Open HTML report
    if ($IsWindows -or $env:OS -match "Windows") {
        Start-Process $reportPath
    }
    elseif ($IsMacOS) {
        & open $reportPath
    }
}
catch {
    Write-Log "Script execution failed: $_" "ERROR"
    Write-Log $_.ScriptStackTrace "ERROR"
    throw
}
finally {
    Disconnect-Services
}
#endregion
