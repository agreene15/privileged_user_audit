<#
.SYNOPSIS
    Checks Conditional Access policies for session lifetime and MFA re-auth settings.

.DESCRIPTION
    Connects to Microsoft Graph and reports on:
    - Sign-in frequency (re-auth intervals) configured in CA policies
    - Persistent browser session settings
    - Policies with no session controls (potentially unlimited sessions)
    - Primary Refresh Token (PRT) / token lifetime context

    Requires: Global Reader role (minimum)

.PARAMETER ForceReauth
    Bypass cached credentials and force a new browser login.

.EXAMPLE
    pwsh ./Get-CASessionPolicy.ps1

.EXAMPLE
    pwsh ./Get-CASessionPolicy.ps1 -ForceReauth
#>

[CmdletBinding()]
param(
    [switch]$ForceReauth
)

$ErrorActionPreference = "Stop"
$credCachePath = Join-Path $PSScriptRoot ".auth_cache.json"

#region Helpers

function Write-Header {
    param([string]$Title)
    $line = "=" * 70
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "--- $Title ---" -ForegroundColor Yellow
}

function Get-CachedUpn {
    if (Test-Path $credCachePath) {
        try {
            $cache = Get-Content $credCachePath -Raw | ConvertFrom-Json
            $expires = [datetime]$cache.ExpiresAt
            if ($expires -gt (Get-Date)) {
                return $cache.UserPrincipalName
            }
        } catch { }
    }
    return $null
}

function Save-CachedUpn {
    param([string]$Upn)
    @{
        UserPrincipalName = $Upn
        ExpiresAt         = (Get-Date).AddDays(7).ToString("o")
    } | ConvertTo-Json | Set-Content $credCachePath
}

function ConvertFrom-TokenLifetimePolicyDefinition {
    param([string[]]$Definition)
    if (-not $Definition -or $Definition.Count -eq 0) { return $null }
    try {
        $outer = $Definition[0] | ConvertFrom-Json -ErrorAction Stop
        if ($outer.PSObject.Properties.Name -contains 'TokenLifetimePolicy') {
            return $outer.TokenLifetimePolicy
        }
        return $outer
    } catch { return $null }
}

function Format-TokenLifetimeValue {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return "(not set — uses Microsoft default)" }
    if ($Value -eq "until-revoked") { return "Until explicitly revoked (no maximum age)" }
    try {
        $ts = [System.TimeSpan]::Parse($Value)
        $parts = @()
        if ($ts.Days -gt 0)    { $parts += "$($ts.Days) day(s)" }
        if ($ts.Hours -gt 0)   { $parts += "$($ts.Hours) hour(s)" }
        if ($ts.Minutes -gt 0) { $parts += "$($ts.Minutes) min" }
        if ($parts.Count -eq 0) { $parts += "0 min" }
        return ($parts -join " ")
    } catch { return $Value }
}

#endregion

#region Graph Connection

Write-Header "CA Session Policy Checker"
Write-Host "Checking Conditional Access session controls..." -ForegroundColor Gray

# Ensure module
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "Installing Microsoft.Graph.Authentication..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
}
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.SignIns)) {
    Write-Host "Installing Microsoft.Graph.Identity.SignIns..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop

$cachedUpn = if (-not $ForceReauth) { Get-CachedUpn } else { $null }

if ($cachedUpn) {
    Write-Host "Using cached identity: $cachedUpn" -ForegroundColor Gray
}

Connect-MgGraph -Scopes @("Policy.Read.All", "Directory.Read.All") -NoWelcome

# Cache UPN after login
$context = Get-MgContext
if ($context.Account) {
    Save-CachedUpn -Upn $context.Account
    Write-Host "Connected as: $($context.Account)" -ForegroundColor Green
}

#endregion

#region Fetch CA Policies

Write-Section "Fetching Conditional Access Policies"

$policies = Get-MgIdentityConditionalAccessPolicy -All
Write-Host "Found $($policies.Count) total CA policies." -ForegroundColor Gray

#endregion

#region Analyze Session Controls

$results = @()

foreach ($policy in $policies) {
    $state   = $policy.State           # enabled / disabled / enabledForReportingButNotEnforced
    $session = $policy.SessionControls

    $signinFreqEnabled   = $false
    $signinFreqValue     = $null
    $signinFreqUnit      = $null
    $signinFreqType      = $null       # "timeBased" or "everyTime"
    $persistentSession   = $null
    $caeMode             = $null

    if ($session) {
        # Sign-in frequency
        $sif = $session.SignInFrequency
        if ($sif -and $sif.IsEnabled) {
            $signinFreqEnabled = $true
            $signinFreqType    = $sif.FrequencyInterval   # "timeBased" | "everyTime"
            $signinFreqValue   = $sif.Value
            $signinFreqUnit    = $sif.Type                # "hours" | "days"
        }

        # Persistent browser session
        $pbs = $session.PersistentBrowser
        if ($pbs -and $pbs.IsEnabled) {
            $persistentSession = $pbs.Mode   # "always" | "never"
        }

        # Continuous Access Evaluation
        $cae = $session.ContinuousAccessEvaluation
        if ($cae) {
            $caeMode = $cae.Mode   # "strictLocation" | "disabled" | ""
        }
    }

    $results += [PSCustomObject]@{
        PolicyName           = $policy.DisplayName
        State                = $state
        SignInFreqEnabled    = $signinFreqEnabled
        FrequencyInterval    = $signinFreqType
        FrequencyValue       = $signinFreqValue
        FrequencyUnit        = $signinFreqUnit
        PersistentBrowser    = $persistentSession
        CAEMode              = $caeMode
        HasSessionControls   = ($signinFreqEnabled -or $persistentSession -or $caeMode)
    }
}

#endregion

#region Report

Write-Header "Results"

# --- Policies WITH sign-in frequency enforcement ---
Write-Section "Policies Enforcing Sign-In Frequency (re-auth required)"
$withFreq = $results | Where-Object { $_.SignInFreqEnabled -and $_.State -eq "enabled" }
if ($withFreq) {
    foreach ($p in $withFreq) {
        $freq = if ($p.FrequencyInterval -eq "everyTime") {
            "Every sign-in (always prompt MFA)"
        } elseif ($p.FrequencyValue) {
            "$($p.FrequencyValue) $($p.FrequencyUnit)"
        } else {
            "Configured (check portal)"
        }
        Write-Host "  [ENFORCED] $($p.PolicyName)" -ForegroundColor Green
        Write-Host "             Re-auth every: $freq" -ForegroundColor White
    }
} else {
    Write-Host "  None — no enabled policies enforce periodic re-authentication." -ForegroundColor Red
}

# --- Policies with persistent browser session ---
Write-Section "Persistent Browser Session Settings"
$withPBS = $results | Where-Object { $_.PersistentSession -and $_.State -eq "enabled" }
if ($withPBS) {
    foreach ($p in $withPBS) {
        $color = if ($p.PersistentSession -eq "always") { "Red" } else { "Green" }
        Write-Host "  $($p.PolicyName)" -ForegroundColor $color
        Write-Host "  Mode: $($p.PersistentSession)" -ForegroundColor $color
    }
} else {
    Write-Host "  No enabled policies explicitly set persistent browser session." -ForegroundColor Yellow
    Write-Host "  (Default behavior: browser decides — often persists on managed devices)" -ForegroundColor Gray
}

# --- CAE ---
Write-Section "Continuous Access Evaluation (CAE)"
$withCAE = $results | Where-Object { $_.CAEMode -and $_.State -eq "enabled" }
if ($withCAE) {
    foreach ($p in $withCAE) {
        Write-Host "  $($p.PolicyName)  Mode: $($p.CAEMode)" -ForegroundColor Cyan
    }
} else {
    Write-Host "  No enabled policies explicitly configure CAE." -ForegroundColor Yellow
    Write-Host "  (CAE is on by default for supported apps — revokes tokens on risk events)" -ForegroundColor Gray
}

# --- Enabled policies with NO session controls (the silent culprit) ---
Write-Section "Enabled Policies With NO Session Controls (potential unlimited sessions)"
$noSession = $results | Where-Object { $_.State -eq "enabled" -and -not $_.HasSessionControls }
if ($noSession) {
    foreach ($p in $noSession) {
        Write-Host "  [NO SESSION CTRL] $($p.PolicyName)" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "  These policies authenticate users but rely on default token/refresh lifetimes." -ForegroundColor Yellow
    Write-Host "  On Entra-joined/Intune-compliant devices, a PRT (Primary Refresh Token)" -ForegroundColor Yellow
    Write-Host "  satisfies MFA claims silently for up to 14 days (rolling)." -ForegroundColor Yellow
} else {
    Write-Host "  All enabled policies have session controls configured." -ForegroundColor Green
}

# --- Disabled/report-only policies with frequency set (informational) ---
Write-Section "Report-Only / Disabled Policies With Session Controls (not enforced)"
$reportOnly = $results | Where-Object {
    $_.HasSessionControls -and $_.State -ne "enabled"
}
if ($reportOnly) {
    foreach ($p in $reportOnly) {
        Write-Host "  [$($p.State.ToUpper())] $($p.PolicyName)" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  None." -ForegroundColor Gray
}

#endregion

#region Token Lifetime Policies

# State variables read later by the dynamic Summary section
$hasCustomTokenPolicy  = $false
$orgDefaultTokenPolicy = $null

Write-Header "Token Lifetime Policies"

# --- 1. Token Lifetime Policies (refresh + access token lifetimes) ---
Write-Section "Token Lifetime Policies"
try {
    $tlPolicies = Get-MgPolicyTokenLifetimePolicy -All -ErrorAction Stop
} catch {
    Write-Host "  ERROR querying token lifetime policies: $_" -ForegroundColor Red
    $tlPolicies = @()
}

if (-not $tlPolicies -or $tlPolicies.Count -eq 0) {
    Write-Host "  No custom token lifetime policies configured." -ForegroundColor Green
    Write-Host "  Microsoft Entra ID defaults apply:" -ForegroundColor Gray
    Write-Host "    Access Token:                      1 hour" -ForegroundColor Gray
    Write-Host "    Refresh Token (non-persistent):    24 hours" -ForegroundColor Gray
    Write-Host "    Refresh Token (persistent):        90 days (rolling)" -ForegroundColor Gray
    Write-Host "    Primary Refresh Token (PRT):       14 days (rolling, managed devices)" -ForegroundColor Gray
    Write-Host "    Max single-factor refresh token:   Until-revoked" -ForegroundColor Gray
    Write-Host "    Max MFA refresh token:             Until-revoked" -ForegroundColor Gray
} else {
    $hasCustomTokenPolicy = $true
    Write-Host "  Found $($tlPolicies.Count) custom token lifetime policy/policies:" -ForegroundColor Yellow

    foreach ($tlp in $tlPolicies) {
        Write-Host ""
        $badge      = if ($tlp.IsOrganizationDefault) { "[ORG DEFAULT]" } else { "[SCOPED]" }
        $badgeColor = if ($tlp.IsOrganizationDefault) { "Cyan" } else { "Yellow" }
        Write-Host "  $badge $($tlp.DisplayName)" -ForegroundColor $badgeColor
        Write-Host "  Policy ID:  $($tlp.Id)" -ForegroundColor Gray

        $parsed = ConvertFrom-TokenLifetimePolicyDefinition -Definition $tlp.Definition
        if ($parsed) {
            if ($tlp.IsOrganizationDefault) { $orgDefaultTokenPolicy = $parsed }
            Write-Host "    Access Token Lifetime:              $(Format-TokenLifetimeValue $parsed.AccessTokenLifetime)" -ForegroundColor White
            Write-Host "    Max Inactive Time (sliding window): $(Format-TokenLifetimeValue $parsed.MaxInactiveTime)" -ForegroundColor White
            Write-Host "    Max Age (single-factor):            $(Format-TokenLifetimeValue $parsed.MaxAgeSingleFactor)" -ForegroundColor White
            Write-Host "    Max Age (MFA):                      $(Format-TokenLifetimeValue $parsed.MaxAgeMultiFactor)" -ForegroundColor White
            Write-Host "    Max Session Age (single-factor):    $(Format-TokenLifetimeValue $parsed.MaxAgeSessionSingleFactor)" -ForegroundColor White
            Write-Host "    Max Session Age (MFA):              $(Format-TokenLifetimeValue $parsed.MaxAgeSessionMultiFactor)" -ForegroundColor White
        } else {
            Write-Host "    (Could not parse Definition field — raw value below)" -ForegroundColor DarkYellow
            Write-Host "    $($tlp.Definition -join '; ')" -ForegroundColor Gray
        }

        # What apps/service principals this policy is assigned to
        try {
            $appTargets = Get-MgPolicyTokenLifetimePolicyApplyTo `
                -TokenLifetimePolicyId $tlp.Id `
                -All `
                -Property @('id', 'displayName') `
                -ErrorAction Stop
        } catch {
            $appTargets = $null
            Write-Host "  Applies to: (could not retrieve — check Directory.Read.All scope)" -ForegroundColor DarkGray
        }

        if ($null -ne $appTargets) {
            if (-not $appTargets -or $appTargets.Count -eq 0) {
                if ($tlp.IsOrganizationDefault) {
                    Write-Host "  Applies to: Org default (all apps without a more-specific policy)" -ForegroundColor Gray
                } else {
                    Write-Host "  Applies to: (none — policy is defined but not assigned to any app)" -ForegroundColor DarkGray
                    Write-Host "              This policy is INACTIVE and has no effect." -ForegroundColor DarkGray
                }
            } else {
                Write-Host "  Applies to:" -ForegroundColor Gray
                foreach ($target in $appTargets) {
                    $name = if ($target.DisplayName) { $target.DisplayName } else { "(no display name)" }
                    Write-Host "    - $name  [$($target.Id)]" -ForegroundColor White
                }
            }
        }
    }
}

# --- 2. Token Issuance Policies (SAML token format, less common) ---
Write-Section "Token Issuance Policies (SAML)"
try {
    $tiPolicies = Get-MgPolicyTokenIssuancePolicy -All -ErrorAction Stop
} catch {
    Write-Host "  ERROR querying token issuance policies: $_" -ForegroundColor Red
    $tiPolicies = @()
}

if (-not $tiPolicies -or $tiPolicies.Count -eq 0) {
    Write-Host "  None found. (Expected — these only appear in SAML federation scenarios)" -ForegroundColor Gray
} else {
    Write-Host "  Found $($tiPolicies.Count) token issuance policy/policies:" -ForegroundColor Yellow
    foreach ($tip in $tiPolicies) {
        Write-Host "  $($tip.DisplayName)  [ID: $($tip.Id)]" -ForegroundColor White
        Write-Host "    IsOrganizationDefault: $($tip.IsOrganizationDefault)" -ForegroundColor Gray
    }
}

# --- 3. Activity-Based Timeout Policies (Azure portal idle session timeout) ---
Write-Section "Activity-Based Timeout Policies (Azure Portal idle timeout)"
try {
    $abtPolicies = Get-MgPolicyActivityBasedTimeoutPolicy -All -ErrorAction Stop
} catch {
    Write-Host "  ERROR querying activity-based timeout policies: $_" -ForegroundColor Red
    $abtPolicies = @()
}

if (-not $abtPolicies -or $abtPolicies.Count -eq 0) {
    Write-Host "  None configured. Azure portal sessions use browser/default timeouts." -ForegroundColor Gray
} else {
    Write-Host "  Found $($abtPolicies.Count) activity-based timeout policy/policies:" -ForegroundColor Yellow
    foreach ($abtp in $abtPolicies) {
        Write-Host "  $($abtp.DisplayName)  [ID: $($abtp.Id)]" -ForegroundColor White
        $parsedAbt = ConvertFrom-TokenLifetimePolicyDefinition -Definition $abtp.Definition
        if ($parsedAbt) {
            $idleTimeout = if ($parsedAbt.PSObject.Properties.Name -contains 'WebSessionIdleTimeout') {
                Format-TokenLifetimeValue $parsedAbt.WebSessionIdleTimeout
            } else {
                ($parsedAbt | ConvertTo-Json -Compress)
            }
            Write-Host "    Web session idle timeout: $idleTimeout" -ForegroundColor White
        }
        Write-Host "    IsOrganizationDefault: $($abtp.IsOrganizationDefault)" -ForegroundColor Gray
    }
}

#endregion

#region Summary

Write-Header "Summary & What It Means For You"

if ($hasCustomTokenPolicy -and $orgDefaultTokenPolicy) {
    Write-Host ""
    Write-Host "  CUSTOM ORG-DEFAULT token lifetime policy IS active." -ForegroundColor Yellow
    Write-Host "  The following values OVERRIDE Microsoft's built-in defaults:" -ForegroundColor White
    Write-Host ""
    Write-Host "    Access Token Lifetime:    $(Format-TokenLifetimeValue $orgDefaultTokenPolicy.AccessTokenLifetime)" -ForegroundColor White
    Write-Host "    Max Inactive Time:        $(Format-TokenLifetimeValue $orgDefaultTokenPolicy.MaxInactiveTime)" -ForegroundColor White
    Write-Host "    Max Age (single-factor):  $(Format-TokenLifetimeValue $orgDefaultTokenPolicy.MaxAgeSingleFactor)" -ForegroundColor White
    Write-Host "    Max Age (MFA):            $(Format-TokenLifetimeValue $orgDefaultTokenPolicy.MaxAgeMultiFactor)" -ForegroundColor White
    Write-Host ""
    Write-Host "  NOTE: PRT (Primary Refresh Token) on managed/Entra-joined devices is NOT" -ForegroundColor Yellow
    Write-Host "  controlled by Token Lifetime Policy — it uses a separate 14-day rolling" -ForegroundColor Yellow
    Write-Host "  window regardless of any policy above." -ForegroundColor Yellow
} elseif ($hasCustomTokenPolicy) {
    Write-Host ""
    Write-Host "  Custom token lifetime policies exist but NONE is set as org default." -ForegroundColor Yellow
    Write-Host "  Scoped policies apply only to their explicitly assigned applications." -ForegroundColor Yellow
    Write-Host "  All other apps still use Microsoft defaults:" -ForegroundColor Gray
    Write-Host "    Access Token:                    1 hour" -ForegroundColor Gray
    Write-Host "    Refresh Token (non-persistent):  24 hours" -ForegroundColor Gray
    Write-Host "    Refresh Token (persistent):      90 days (rolling)" -ForegroundColor Gray
    Write-Host "    Primary Refresh Token (PRT):     14 days (rolling, managed devices)" -ForegroundColor Gray
} else {
    Write-Host @"

  No custom token lifetime policies — Microsoft Entra ID defaults apply:

    Access Token:                      1 hour
    Refresh Token (non-persistent):    24 hours
    Refresh Token (persistent):        90 days (rolling)
    Primary Refresh Token (PRT):       14 days (rolling) on managed devices
      └─ PRT silently satisfies MFA — this is why you are never re-prompted

"@ -ForegroundColor White
}

Write-Host @"

  RECOMMENDATION to enforce periodic MFA re-auth:
    Entra ID → Protection → Conditional Access → [your policy]
    → Session → Sign-in frequency → e.g. "1 day" or "8 hours"

  For stricter control, also set:
    Persistent browser session → "Never persistent"

"@ -ForegroundColor White

#endregion

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
Write-Host "Done." -ForegroundColor Green
