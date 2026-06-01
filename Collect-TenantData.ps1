<#
.SYNOPSIS
    Single-file Microsoft Entra ID configuration collector for the Entra ID
    Security Assessment. Collects read-only tenant data and writes a JSON
    snapshot that the assessor evaluates offline.

.DESCRIPTION
    Self-contained collector. A single .ps1 file the customer (or consultant)
    runs to produce tenant-data.json for offline evaluation. The script:

      * Validates PowerShell 7+.
      * Verifies / installs the required Microsoft Graph PowerShell modules
        (with consent on first run).
      * Prompts the operator about emergency-access (break-glass) accounts.
      * Connects to Microsoft Graph and gathers configuration data only.
      * Writes tenant-data.json (and optional tenant-data-raw.json) to the
        chosen output folder.

    No tenant configuration is modified. Only delegated, read-only Microsoft
    Graph scopes are requested.

.PARAMETER OutputPath
    Directory for the snapshot. Defaults to .\snapshot beside this script.

.PARAMETER TenantId
    Optional tenant id (use when your account is guest in multiple tenants).

.PARAMETER UseDeviceCode
    Use device-code flow (useful from a headless session or jump box).

.PARAMETER BreakGlassAccounts
    Optional list of break-glass / emergency-access account UPNs or object ids.
    Microsoft strongly recommends every tenant maintains at least two — see
    https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access

.PARAMETER SkipBreakGlassValidation
    Set when emergency-access accounts cannot be disclosed at collection time.
    The report will show a 'Skipped' banner instead of a 'Not provided' banner.

.PARAMETER SkipModuleInstall
    Skip the auto-install step. Use if your environment manages module
    installation centrally; the script will fail fast if anything is missing.

.PARAMETER SkipConnect
    Skip Connect-MgGraph (assume the caller already established a session).

.PARAMETER NonInteractive
    Skip all interactive prompts. Required for unattended / automation runs.

.EXAMPLE
    .\Collect-TenantData.ps1

.EXAMPLE
    .\Collect-TenantData.ps1 -BreakGlassAccounts 'bg1@contoso.com','bg2@contoso.com'

.EXAMPLE
    .\Collect-TenantData.ps1 -SkipBreakGlassValidation -UseDeviceCode

.NOTES
    Required Microsoft Graph scopes (delegated, read-only):
      Policy.Read.All
      Policy.Read.ConditionalAccess
      IdentityRiskyUser.Read.All
      Directory.Read.All
      Application.Read.All
      RoleManagement.Read.Directory
      AuditLog.Read.All
      Reports.Read.All
      CrossTenantInformation.ReadBasic.All
      UserAuthenticationMethod.Read.All   (only when -BreakGlassAccounts is used)

    Account requirements:
      The signed-in user needs Global Reader or Security Reader (or higher).
      No write permissions are required or used.

    What is collected:
      Tenant metadata and verified domains; Conditional Access policies;
      named locations; Identity Protection (sign-in / user-risk) policies;
      authentication-methods policy and authentication strengths; cross-tenant
      access defaults; service principals, app role assignments, OAuth2 grants;
      directory role definitions, role assignments, PIM-eligible assignments;
      application registrations and credential metadata (NO secret values);
      risky-user summary (counts); auth-method registration summary (counts);
      guest summary (counts); per-account break-glass compliance snapshot
      (only when -BreakGlassAccounts is supplied).

    What is NOT collected:
      User content (mail, files, chats), sign-in logs, audit logs, secrets,
      certificates, password material.

    Troubleshooting:
      * "PowerShell 7 or later is required" — install from https://aka.ms/powershell
        and start the script with pwsh (not Windows PowerShell).
      * "Install-Module" fails with "Untrusted repository" — run
        Set-PSRepository PSGallery -InstallationPolicy Trusted (one-off) and retry.
      * "Insufficient privileges to complete the operation" — the signed-in
        account lacks Global Reader (or equivalent). Re-run with a more
        privileged read-only account.
      * Browser sign-in does not appear — re-run with -UseDeviceCode.
      * Warnings about specific scopes — the collector tolerates missing scopes
        by emitting a warning and continuing; the corresponding section in the
        report will be marked as "not collected". Ask your administrator to
        grant the scope and re-run if it is critical.

    Returning the snapshot:
      When the script finishes it prints the path to tenant-data.json — return
      that file to your assessor via the channel you agreed (secure email,
      OneDrive link, Teams, etc.). Both output files are plain JSON; you may
      inspect them in a text editor before sending.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'snapshot'),
    [string]$TenantId,
    [switch]$UseDeviceCode,
    [string[]]$BreakGlassAccounts,
    [switch]$SkipBreakGlassValidation,
    [switch]$SkipModuleInstall,
    [switch]$SkipConnect,
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "PowerShell 7 or later is required. Detected version $($PSVersionTable.PSVersion). Download from https://aka.ms/powershell."
}

if ($BreakGlassAccounts -and $SkipBreakGlassValidation) {
    throw 'Use either -BreakGlassAccounts or -SkipBreakGlassValidation, not both.'
}

# --- Module check -----------------------------------------------------------

$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Applications'
)

$missing = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
if ($missing) {
    if ($SkipModuleInstall) {
        throw "Required modules are missing: $($missing -join ', '). Install with 'Install-Module Microsoft.Graph -Scope CurrentUser' and re-run."
    }
    Write-Host ''
    Write-Host 'The following Microsoft Graph modules are required and missing:' -ForegroundColor Yellow
    $missing | ForEach-Object { Write-Host "  - $_" }
    Write-Host ''

    if ($NonInteractive) {
        throw "Required modules missing and -NonInteractive set. Install Microsoft.Graph for the current user and re-run."
    }

    $response = Read-Host 'Install them now for the current user? [Y/n]'
    if ($response -in @('', 'Y', 'y')) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
    } else {
        throw 'Cannot continue without the required modules.'
    }
}

# --- Break-glass prompt -----------------------------------------------------

if (-not $BreakGlassAccounts -and -not $SkipBreakGlassValidation -and -not $NonInteractive) {
    Write-Host ''
    Write-Host 'Break-glass / emergency-access accounts have not been supplied.' -ForegroundColor Yellow
    Write-Host 'Reference: https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access'
    Write-Host ''
    Write-Host 'Options:'
    Write-Host '  1) Provide the UPNs (or object ids) of your break-glass accounts now'
    Write-Host '  2) Skip break-glass validation (the report will show a Skipped banner)'
    Write-Host '  3) Continue without making a decision (report will show Not provided)'
    $choice = Read-Host 'Choose [1/2/3] (default 3)'
    switch ($choice) {
        '1' {
            $entries = Read-Host 'Enter UPNs separated by commas'
            $list = @($entries -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($list.Count -gt 0) { $BreakGlassAccounts = $list }
        }
        '2' {
            $SkipBreakGlassValidation = [switch]$true
        }
        default { }
    }
}

# --- Run --------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path

Write-Host ''
Write-Host '== Collecting tenant data ==' -ForegroundColor Cyan

$ErrorActionPreference = 'Stop'
# NOTE: strict mode is intentionally kept at v1.0. This collector tolerates
# missing properties on Microsoft Graph responses (optional fields, partial
# data when scopes are not granted), which is incompatible with v2+/Latest
# strict-mode enforcement of "property must exist".
Set-StrictMode -Version 1.0

$script:CollectorVersion = '1.2.0'
$script:Warnings       = New-Object System.Collections.Generic.List[string]
$script:RawData        = [ordered]@{}
$script:GrantedScopes  = @()
$script:VerifiedDomains = @{}

#region Helpers --------------------------------------------------------------

function Write-Section([string]$Name) {
    Write-Host ''
    Write-Host "==> $Name" -ForegroundColor Cyan
}

function Add-Warning([string]$Message) {
    Write-Warning $Message
    $script:Warnings.Add($Message) | Out-Null
}

function Invoke-MgGraphRequestAllPages {
    <#
    Generic paginated GET over the v1.0 (or beta) Graph endpoint using
    Invoke-MgGraphRequest. Returns the concatenated 'value' arrays.
    Optional -Headers lets callers send advanced-query headers such as
    ConsistencyLevel: eventual (required by /servicePrincipals tag filters).
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers,
        [int]$MaxPages = 1000
    )
    $results = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $page = 0
    while ($next -and $page -lt $MaxPages) {
        try {
            $reqArgs = @{ Method = 'GET'; Uri = $next; ErrorAction = 'Stop' }
            if ($Headers -and $Headers.Count -gt 0) { $reqArgs['Headers'] = $Headers }
            $resp = Invoke-MgGraphRequest @reqArgs
        } catch {
            Add-Warning "Graph GET '$next' failed: $($_.Exception.Message)"
            break
        }

        $isDict = $resp -is [System.Collections.IDictionary]
        $hasValue = $isDict -and $resp.Contains('value')
        $hasNext  = $isDict -and $resp.Contains('@odata.nextLink')

        if ($hasValue) {
            $results.AddRange([object[]]$resp['value'])
        } else {
            # single-object response (no 'value' wrapper)
            $results.Add($resp) | Out-Null
            break
        }

        $next = if ($hasNext) { [string]$resp['@odata.nextLink'] } else { $null }
        $page++
    }
    return ,$results.ToArray()
}

function ConvertTo-Iso8601 {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    try {
        $dt = [datetime]::Parse([string]$Value, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
        return $dt.ToUniversalTime().ToString('o')
    } catch {
        return [string]$Value
    }
}

function Get-CredentialEnvelope {
    <#
        Normalizes either a passwordCredentials or keyCredentials entry to the
        shape required by normalized-schema.json. Note: $Entry holds Graph
        credential metadata only (keyId, dates) - no actual secret material.
        Tolerant of both IDictionary (the shape Invoke-MgGraphRequest returns)
        and PSCustomObject - direct member access works for both under
        StrictMode v1.0; absent fields evaluate to $null.
    #>
    param(
        [Parameter(Mandatory)][object]$Entry,
        [Parameter(Mandatory)][ValidateSet('secret','certificate')][string]$Type
    )

    $start  = $Entry.startDateTime
    $expiry = $Entry.endDateTime

    $startDt  = $null
    $expiryDt = $null
    if ($start)  { try { $startDt  = [datetime]::Parse([string]$start) }  catch {} }
    if ($expiry) { try { $expiryDt = [datetime]::Parse([string]$expiry) } catch {} }

    $now = [datetime]::UtcNow
    $isExpired = $false
    $daysUntilExpiry = $null
    $lifetimeDays = $null
    if ($expiryDt) {
        $isExpired = $expiryDt -lt $now
        $daysUntilExpiry = [int][math]::Floor(($expiryDt - $now).TotalDays)
    }
    if ($startDt -and $expiryDt) {
        $lifetimeDays = [int][math]::Floor(($expiryDt - $startDt).TotalDays)
    }

    [ordered]@{
        keyId           = $Entry.keyId
        type            = $Type
        displayName     = $Entry.displayName
        startDate       = ConvertTo-Iso8601 $startDt
        expiryDate      = ConvertTo-Iso8601 $expiryDt
        isExpired       = [bool]$isExpired
        daysUntilExpiry = $daysUntilExpiry
        lifetimeDays    = $lifetimeDays
    }
}

#endregion

#region Connect -------------------------------------------------------------

function Connect-Graph {
    if ($SkipConnect) {
        Write-Host 'Skipping Connect-MgGraph (caller-managed session).' -ForegroundColor Yellow
        return
    }

    $requiredScopes = @(
        'Policy.Read.All',
        'Policy.Read.ConditionalAccess',
        'IdentityRiskyUser.Read.All',
        'Directory.Read.All',
        'Application.Read.All',
        'RoleManagement.Read.Directory',
        'AuditLog.Read.All',
        'Reports.Read.All',
        'CrossTenantInformation.ReadBasic.All'
    )
    if ($BreakGlassAccounts) {
        $requiredScopes += 'UserAuthenticationMethod.Read.All'
    }

    Write-Section 'Connecting to Microsoft Graph'
    $connectArgs = @{ Scopes = $requiredScopes; NoWelcome = $true }
    if ($TenantId)      { $connectArgs['TenantId']  = $TenantId }
    if ($UseDeviceCode) { $connectArgs['UseDeviceCode'] = $true }

    Connect-MgGraph @connectArgs | Out-Null

    $ctx = Get-MgContext
    if (-not $ctx) { throw 'Connect-MgGraph did not produce a context.' }
    Write-Host ("Connected as {0} to tenant {1}" -f $ctx.Account, $ctx.TenantId)

    $script:GrantedScopes = @($ctx.Scopes)
    foreach ($s in $requiredScopes) {
        if ($script:GrantedScopes -notcontains $s) {
            Add-Warning "Required scope '$s' was not granted. Some data may be missing."
        }
    }
}

#endregion

#region Collectors ----------------------------------------------------------

function Get-TenantMetadata {
    Write-Section 'Tenant metadata'
    try {
        $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization'
        $first = ($org.value | Select-Object -First 1)
        $script:RawData.organization = $org

        # Capture verified domains for cloud-only / federated determination
        $script:VerifiedDomains = @{}
        foreach ($d in @($first.verifiedDomains)) {
            $name = [string]$d.name
            if ($name) {
                $script:VerifiedDomains[$name.ToLowerInvariant()] = [pscustomobject]@{
                    name        = $name
                    isInitial   = [bool]$d.isInitial
                    isDefault   = [bool]$d.isDefault
                    isFederated = ($d.type -eq 'Federated')
                }
            }
        }

        return [ordered]@{
            tenantId            = $first.id
            tenantDisplayName   = $first.displayName
            collectedAt         = (Get-Date).ToUniversalTime().ToString('o')
            collectorVersion    = $script:CollectorVersion
            scopesGranted       = $script:GrantedScopes
        }
    } catch {
        Add-Warning "Failed to read /organization: $($_.Exception.Message)"
        $script:VerifiedDomains = @{}
        return [ordered]@{
            tenantId          = (Get-MgContext).TenantId
            tenantDisplayName = $null
            collectedAt       = (Get-Date).ToUniversalTime().ToString('o')
            collectorVersion  = $script:CollectorVersion
            scopesGranted     = $script:GrantedScopes
        }
    }
}

function Get-ConditionalAccessPolicies {
    Write-Section 'Conditional Access policies'
    $raw = Invoke-MgGraphRequestAllPages -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
    $script:RawData.conditionalAccessPolicies = $raw

    $out = foreach ($p in $raw) {
        $conditions = $p.conditions
        $u  = $conditions.users
        $a  = $conditions.applications
        $pl = $conditions.platforms
        $lo = $conditions.locations

        $sif = $null
        $pb  = $null
        $sss = $null
        if ($p.sessionControls) {
            if ($p.sessionControls.signInFrequency)     { $sif = $p.sessionControls.signInFrequency }
            if ($p.sessionControls.persistentBrowser)   { $pb  = $p.sessionControls.persistentBrowser }
            if ($p.sessionControls.secureSignInSession) { $sss = $p.sessionControls.secureSignInSession }
        }

        [ordered]@{
            id               = $p.id
            displayName      = $p.displayName
            state            = $p.state
            createdDateTime  = ConvertTo-Iso8601 $p.createdDateTime
            modifiedDateTime = ConvertTo-Iso8601 $p.modifiedDateTime
            conditions = [ordered]@{
                users = [ordered]@{
                    includeUsers  = @($u.includeUsers)
                    excludeUsers  = @($u.excludeUsers)
                    includeGroups = @($u.includeGroups)
                    excludeGroups = @($u.excludeGroups)
                    includeRoles  = @($u.includeRoles)
                    excludeRoles  = @($u.excludeRoles)
                }
                applications = [ordered]@{
                    includeApplications = @($a.includeApplications)
                    excludeApplications = @($a.excludeApplications)
                    userActions         = @($a.userActions)
                }
                clientAppTypes   = @($conditions.clientAppTypes)
                platforms = [ordered]@{
                    includePlatforms = @($pl.includePlatforms)
                    excludePlatforms = @($pl.excludePlatforms)
                }
                locations = [ordered]@{
                    includeLocations = @($lo.includeLocations)
                    excludeLocations = @($lo.excludeLocations)
                }
                userRiskLevels    = @($conditions.userRiskLevels)
                signInRiskLevels  = @($conditions.signInRiskLevels)
            }
            grantControls = if ($p.grantControls) {
                [ordered]@{
                    operator                = $p.grantControls.operator
                    builtInControls         = @($p.grantControls.builtInControls)
                    authenticationStrength  = if ($p.grantControls.authenticationStrength) {
                        [ordered]@{
                            id          = $p.grantControls.authenticationStrength.id
                            displayName = $p.grantControls.authenticationStrength.displayName
                        }
                    } else { $null }
                }
            } else { $null }
            sessionControls = if ($p.sessionControls) {
                [ordered]@{
                    signInFrequency = if ($sif) {
                        [ordered]@{
                            isEnabled         = [bool]$sif.isEnabled
                            type              = $sif.type
                            value             = $sif.value
                            frequencyInterval = $sif.frequencyInterval
                        }
                    } else { $null }
                    persistentBrowser = if ($pb) {
                        [ordered]@{
                            isEnabled = [bool]$pb.isEnabled
                            mode      = $pb.mode
                        }
                    } else { $null }
                    secureSignInSession = if ($sss) {
                        [ordered]@{
                            isEnabled = [bool]$sss.isEnabled
                        }
                    } else { $null }
                }
            } else { $null }
        }
    }
    return ,@($out)
}

function Get-IdentityProtectionPolicies {
    param([object[]]$CaPolicies)

    Write-Section 'Identity Protection policies (derived)'
    $derived = New-Object System.Collections.Generic.List[object]

    foreach ($p in $CaPolicies) {
        if (-not ($p.state -eq 'enabled' -or $p.state -eq 'enabledForReportingButNotEnforced')) { continue }
        $controls = @()
        if ($p.grantControls -and $p.grantControls.builtInControls) {
            $controls = @($p.grantControls.builtInControls)
        }

        if ($p.conditions.userRiskLevels.Count -gt 0) {
            $derived.Add([ordered]@{
                id          = $p.id
                displayName = $p.displayName
                policyType  = 'userRisk'
                state       = $p.state
                riskLevels  = @($p.conditions.userRiskLevels)
                controls    = $controls
                source      = 'conditionalAccess'
            }) | Out-Null
        }
        if ($p.conditions.signInRiskLevels.Count -gt 0) {
            $derived.Add([ordered]@{
                id          = $p.id
                displayName = $p.displayName
                policyType  = 'signInRisk'
                state       = $p.state
                riskLevels  = @($p.conditions.signInRiskLevels)
                controls    = $controls
                source      = 'conditionalAccess'
            }) | Out-Null
        }
    }

    # Legacy Identity Protection policies (best-effort - the legacy API is being retired)
    foreach ($endpoint in @(
        'https://graph.microsoft.com/beta/identityProtection/policies/userRiskPolicy',
        'https://graph.microsoft.com/beta/identityProtection/policies/signInRiskPolicy'
    )) {
        try {
            $legacy = Invoke-MgGraphRequest -Method GET -Uri $endpoint -ErrorAction Stop
            if ($legacy) {
                $type = if ($endpoint -like '*userRiskPolicy') { 'userRisk' } else { 'signInRisk' }
                $derived.Add([ordered]@{
                    id          = $legacy.id
                    displayName = "Legacy $type policy"
                    policyType  = $type
                    state       = if ($legacy.isEnabled) { 'enabled' } else { 'disabled' }
                    riskLevels  = @($legacy.riskLevel)
                    controls    = @()
                    source      = 'identityProtectionLegacy'
                }) | Out-Null
            }
        } catch {
            # Legacy endpoint may be retired - silently skip
        }
    }

    $script:RawData.identityProtectionPolicies = $derived
    return ,$derived.ToArray()
}

function Get-PolicyDuplicateGroups {
    <#
        Groups Conditional Access policies by a functional fingerprint that
        deliberately ignores `state` and `displayName` so we catch:
          - Two enabled policies with the same effective decision (true duplicate),
          - One enabled and one report-only/disabled policy with the same
            decision (drift / left-over draft),
          - Policy clones where only the name was changed.
        Returns one record per fingerprint group with count > 1.
    #>
    param([object[]]$CaPolicies)

    if (-not $CaPolicies -or $CaPolicies.Count -lt 2) { return ,@() }

    function ConvertTo-CanonArray {
        param($value)
        if ($null -eq $value) { return @() }
        $arr = @($value) | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { [string]$_ } | Sort-Object -Unique
        return ,$arr
    }

    function Get-PolicyFingerprintObject {
        param($policy)

        $u  = $policy.conditions.users
        $a  = $policy.conditions.applications
        $pl = $policy.conditions.platforms
        $lo = $policy.conditions.locations

        $gc = $policy.grantControls
        $sc = $policy.sessionControls

        $sif = $null; $pb = $null
        if ($sc) {
            if ($sc.signInFrequency)   { $sif = $sc.signInFrequency }
            if ($sc.persistentBrowser) { $pb  = $sc.persistentBrowser }
        }

        return [ordered]@{
            includeUsers         = ConvertTo-CanonArray $u.includeUsers
            excludeUsers         = ConvertTo-CanonArray $u.excludeUsers
            includeGroups        = ConvertTo-CanonArray $u.includeGroups
            excludeGroups        = ConvertTo-CanonArray $u.excludeGroups
            includeRoles         = ConvertTo-CanonArray $u.includeRoles
            excludeRoles         = ConvertTo-CanonArray $u.excludeRoles
            includeApps          = ConvertTo-CanonArray $a.includeApplications
            excludeApps          = ConvertTo-CanonArray $a.excludeApplications
            userActions          = ConvertTo-CanonArray $a.userActions
            clientAppTypes       = ConvertTo-CanonArray $policy.conditions.clientAppTypes
            includePlatforms     = ConvertTo-CanonArray $pl.includePlatforms
            excludePlatforms     = ConvertTo-CanonArray $pl.excludePlatforms
            includeLocations     = ConvertTo-CanonArray $lo.includeLocations
            excludeLocations     = ConvertTo-CanonArray $lo.excludeLocations
            userRiskLevels       = ConvertTo-CanonArray $policy.conditions.userRiskLevels
            signInRiskLevels     = ConvertTo-CanonArray $policy.conditions.signInRiskLevels
            grantOperator        = if ($gc) { [string]$gc.operator } else { '' }
            grantBuiltIn         = if ($gc) { ConvertTo-CanonArray $gc.builtInControls } else { @() }
            grantAuthStrengthId  = if ($gc -and $gc.authenticationStrength) { [string]$gc.authenticationStrength.id } else { '' }
            sifEnabled           = if ($sif) { [bool]$sif.isEnabled } else { $false }
            sifType              = if ($sif) { [string]$sif.type } else { '' }
            sifValue             = if ($sif) { [string]$sif.value } else { '' }
            sifFrequency         = if ($sif) { [string]$sif.frequencyInterval } else { '' }
            pbEnabled            = if ($pb)  { [bool]$pb.isEnabled } else { $false }
            pbMode               = if ($pb)  { [string]$pb.mode } else { '' }
        }
    }

    function Get-ScopeSummary {
        param($fp)
        function Show-List { param($name, $arr) if (-not $arr -or $arr.Count -eq 0) { return $null }; if ($arr -contains 'All') { return "$name=All" } else { return ("{0}={1}" -f $name, $arr.Count) } }
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($pair in @(
            @{ n='IncUsers';  v=$fp.includeUsers  },
            @{ n='ExcUsers';  v=$fp.excludeUsers  },
            @{ n='IncGroups'; v=$fp.includeGroups },
            @{ n='ExcGroups'; v=$fp.excludeGroups },
            @{ n='IncRoles';  v=$fp.includeRoles  },
            @{ n='ExcRoles';  v=$fp.excludeRoles  },
            @{ n='IncApps';   v=$fp.includeApps   },
            @{ n='ExcApps';   v=$fp.excludeApps   },
            @{ n='Actions';   v=$fp.userActions   },
            @{ n='Clients';   v=$fp.clientAppTypes},
            @{ n='Platforms'; v=$fp.includePlatforms },
            @{ n='Locations'; v=$fp.includeLocations },
            @{ n='UserRisk';  v=$fp.userRiskLevels },
            @{ n='SignInRisk';v=$fp.signInRiskLevels }
        )) {
            $s = Show-List -name $pair.n -arr $pair.v
            if ($s) { [void]$parts.Add($s) }
        }
        $ctl = New-Object System.Collections.Generic.List[string]
        if ($fp.grantBuiltIn -and $fp.grantBuiltIn.Count -gt 0) { [void]$ctl.Add( ($fp.grantBuiltIn -join '+') ) }
        if ($fp.grantAuthStrengthId) { [void]$ctl.Add("authStrength=$($fp.grantAuthStrengthId.Substring(0,[Math]::Min(8,$fp.grantAuthStrengthId.Length)))…") }
        if ($fp.grantOperator) { [void]$ctl.Add("op=$($fp.grantOperator)") }
        if ($fp.sifEnabled) { [void]$ctl.Add("SIF=$($fp.sifValue)$($fp.sifType)") }
        if ($fp.pbEnabled)  { [void]$ctl.Add("PB=$($fp.pbMode)") }
        if ($ctl.Count -gt 0) { [void]$parts.Add(("Controls[{0}]" -f ($ctl -join ','))) }

        if ($parts.Count -eq 0) { return '(no conditions or controls)' }
        return ($parts -join '; ')
    }

    # Hash an object deterministically (JSON-canonical) → short fingerprint.
    function Get-Fingerprint {
        param($obj)
        $json = $obj | ConvertTo-Json -Depth 8 -Compress
        $sha  = [System.Security.Cryptography.SHA1]::Create()
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($json)
            $hash  = $sha.ComputeHash($bytes)
            $hex   = -join ($hash | ForEach-Object { $_.ToString('x2') })
            return $hex.Substring(0, 12)
        }
        finally { $sha.Dispose() }
    }

    $byFp = @{}
    foreach ($p in $CaPolicies) {
        $fpObj = Get-PolicyFingerprintObject -policy $p
        $fp    = Get-Fingerprint -obj $fpObj
        if (-not $byFp.ContainsKey($fp)) {
            $byFp[$fp] = [ordered]@{
                fingerprint = $fp
                policies    = New-Object System.Collections.Generic.List[object]
                fpObj       = $fpObj
            }
        }
        [void]$byFp[$fp].policies.Add([ordered]@{
            id          = [string]$p.id
            displayName = [string]$p.displayName
            state       = [string]$p.state
        })
    }

    $groups = New-Object System.Collections.Generic.List[object]
    foreach ($key in $byFp.Keys) {
        $grp = $byFp[$key]
        if ($grp.policies.Count -lt 2) { continue }

        $enabledCount    = @($grp.policies | Where-Object { $_.state -eq 'enabled' }).Count
        $reportOnlyCount = @($grp.policies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count
        $disabledCount   = @($grp.policies | Where-Object { $_.state -eq 'disabled' }).Count

        $policyList = ($grp.policies | ForEach-Object { "[{0}] {1}" -f $_.state, $_.displayName }) -join ' | '

        # Severity hint for the rule pack — used in evidence only.
        $severityHint = if ($enabledCount -ge 2) { 'enforced-duplicate' }
                        elseif ($enabledCount -ge 1 -and ($reportOnlyCount + $disabledCount) -ge 1) { 'drift' }
                        else { 'inactive-clones' }

        [void]$groups.Add([ordered]@{
            fingerprint      = $grp.fingerprint
            policyCount      = $grp.policies.Count
            enabledCount     = $enabledCount
            reportOnlyCount  = $reportOnlyCount
            disabledCount    = $disabledCount
            scopeSummary     = Get-ScopeSummary -fp $grp.fpObj
            policyList       = $policyList
            duplicateKind    = $severityHint
            policies         = $grp.policies.ToArray()
        })
    }

    # Sort: enforced duplicates first, then drift, then clones; within each, larger groups first.
    $kindRank = @{ 'enforced-duplicate' = 0; 'drift' = 1; 'inactive-clones' = 2 }
    $sorted = $groups | Sort-Object `
        @{ Expression = { $kindRank[$_.duplicateKind] } }, `
        @{ Expression = { -$_.policyCount } }, `
        'scopeSummary'

    return ,@($sorted)
}

function Get-TenantBaselineCoverage {
    <#
        Precomputes boolean coverage flags for Microsoft-recommended CA
        baselines that cannot be expressed as a pure declarative rule because
        they need cross-collection joins (e.g. "an admin-scoped policy must
        use an authentication strength classified as phishing-resistant"
        joins conditionalAccessPolicies × authenticationStrengths).
        Rules read these as simple `equals: true` / `equals: false` checks.
    #>
    param(
        [object[]]$CaPolicies,
        [object[]]$AuthStrengths
    )

    # Strength id → isPhishingResistant lookup, sourced from the already-
    # decorated $AuthStrengths collection.
    $prStrengthIds = @{}
    foreach ($s in @($AuthStrengths)) {
        if (-not $s -or -not $s.id) { continue }
        if ([bool]$s.isPhishingResistant) {
            $prStrengthIds[[string]$s.id] = $true
        }
    }

    $adminPrmfaCovered = $false
    foreach ($p in @($CaPolicies)) {
        if ([string]$p.state -ne 'enabled') { continue }
        if (-not $p.conditions -or -not $p.conditions.users) { continue }
        $roles = @($p.conditions.users.includeRoles)
        if ($roles.Count -eq 0) { continue }
        $gc = $p.grantControls
        if (-not $gc -or -not $gc.authenticationStrength -or -not $gc.authenticationStrength.id) { continue }
        $sid = [string]$gc.authenticationStrength.id
        if ($prStrengthIds.ContainsKey($sid)) {
            $adminPrmfaCovered = $true
            break
        }
    }

    return [ordered]@{
        adminPrmfaCovered = [bool]$adminPrmfaCovered
    }
}

function Get-AuthenticationMethodsPolicy {
    Write-Section 'Authentication methods policy'
    try {
        $policy = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy?$expand=authenticationMethodConfigurations'
        $script:RawData.authenticationMethodsPolicy = $policy

        # Surface tenant-level metadata used by AUTH-009 (per-user MFA migration).
        # Stashed in module scope to avoid changing the function's array return
        # shape; Main picks it up after the call.
        $regCampaignState = $null
        if ($policy.registrationEnforcement -and $policy.registrationEnforcement.authenticationMethodsRegistrationCampaign) {
            $regCampaignState = [string]$policy.registrationEnforcement.authenticationMethodsRegistrationCampaign.state
        }
        $script:AuthMethodsPolicyMeta = [ordered]@{
            policyMigrationState           = [string]$policy.policyMigrationState
            registrationCampaignState      = $regCampaignState
            reportSuspiciousActivityState  = if ($policy.reportSuspiciousActivitySettings) {
                [string]$policy.reportSuspiciousActivitySettings.state
            } else { $null }
        }

        $out = foreach ($cfg in @($policy.authenticationMethodConfigurations)) {
            [ordered]@{
                id              = $cfg.id
                state           = $cfg.state
                includeTargets  = @($cfg.includeTargets)
                excludeTargets  = @($cfg.excludeTargets)
                rawConfig       = $cfg
            }
        }
        return ,@($out)
    } catch {
        Add-Warning "Failed to read authenticationMethodsPolicy: $($_.Exception.Message)"
        $script:AuthMethodsPolicyMeta = [ordered]@{
            policyMigrationState          = $null
            registrationCampaignState     = $null
            reportSuspiciousActivityState = $null
        }
        return ,@()
    }
}

function Get-AuthorizationPolicy {
    <#
        Tenant-level authorization policy (single object at /policies/authorizationPolicy).
        Drives APP-001..005 (consent + invites + self-service capabilities).
        Classifies the user-consent setting from
        defaultUserRolePermissions.permissionGrantPoliciesAssigned because the
        actual policy IDs are semantically meaningful (Microsoft uses specific
        well-known IDs for the built-in consent tiers).
    #>
    Write-Section 'Tenant authorization policy'
    try {
        $p = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
        $script:RawData.authorizationPolicy = $p

        $perms = $null
        $assignedConsentPolicies = @()
        if ($p.defaultUserRolePermissions) {
            $perms = $p.defaultUserRolePermissions
            $assignedConsentPolicies = @($perms.permissionGrantPoliciesAssigned)
        }

        # Classify the user-consent state.
        #   disabled                          = empty (user consent off)
        #   verifiedPublisherLowImpactOnly    = '...microsoft-user-default-low'   (RECOMMENDED)
        #   allowAllApps                      = '...microsoft-user-default-legacy' (RISKY)
        #   custom                            = anything else (admin-defined policy)
        $userConsentState = if ($assignedConsentPolicies.Count -eq 0) {
            'disabled'
        }
        elseif ($assignedConsentPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy') {
            'allowAllApps'
        }
        elseif ($assignedConsentPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-low') {
            'verifiedPublisherLowImpactOnly'
        }
        else {
            'custom'
        }

        return [ordered]@{
            allowInvitesFrom                = [string]$p.allowInvitesFrom
            allowedToUseSSPR                = if ($null -ne $p.allowedToUseSSPR) { [bool]$p.allowedToUseSSPR } else { $null }
            allowedEmailVerifiedUsersToJoinOrganization = if ($null -ne $p.allowEmailVerifiedUsersToJoinOrganization) { [bool]$p.allowEmailVerifiedUsersToJoinOrganization } else { $null }
            blockMsolPowerShell             = if ($null -ne $p.blockMsolPowerShell) { [bool]$p.blockMsolPowerShell } else { $null }
            allowedToCreateApps             = if ($perms) { [bool]$perms.allowedToCreateApps } else { $null }
            allowedToCreateSecurityGroups   = if ($perms) { [bool]$perms.allowedToCreateSecurityGroups } else { $null }
            allowedToCreateTenants          = if ($perms) { [bool]$perms.allowedToCreateTenants } else { $null }
            allowedToReadBitlockerKeysForOwnedDevice = if ($perms) { [bool]$perms.allowedToReadBitlockerKeysForOwnedDevice } else { $null }
            permissionGrantPoliciesAssigned = $assignedConsentPolicies
            userConsentState                = $userConsentState
        }
    } catch {
        Add-Warning "Failed to read authorizationPolicy: $($_.Exception.Message)"
        return $null
    }
}

function Get-AdminConsentRequestPolicy {
    <#
        Tenant's admin-consent-request workflow: when users hit consent prompts
        for apps they cannot self-consent to, this routes a structured request
        to designated reviewers. Disabled-by-default in most tenants.
    #>
    Write-Section 'Admin consent request policy'
    try {
        $p = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy'
        $script:RawData.adminConsentRequestPolicy = $p

        return [ordered]@{
            isEnabled               = if ($null -ne $p.isEnabled) { [bool]$p.isEnabled } else { $false }
            notifyReviewers         = if ($null -ne $p.notifyReviewers) { [bool]$p.notifyReviewers } else { $false }
            remindersEnabled        = if ($null -ne $p.remindersEnabled) { [bool]$p.remindersEnabled } else { $false }
            requestDurationInDays   = if ($null -ne $p.requestDurationInDays) { [int]$p.requestDurationInDays } else { $null }
            reviewerCount           = @($p.reviewers).Count
            unavailable             = $false
        }
    } catch {
        Add-Warning "Failed to read adminConsentRequestPolicy: $($_.Exception.Message). This policy requires an Entra ID P1 or P2 licence."
        return [ordered]@{
            isEnabled             = $false
            notifyReviewers       = $false
            remindersEnabled      = $false
            requestDurationInDays = $null
            reviewerCount         = 0
            unavailable           = $true
        }
    }
}

function Get-PimRoleSettings {
    <#
        PIM role-management policy settings for privileged roles.
        Each Entra role has a roleManagementPolicy that controls activation
        requirements (MFA, justification, approval, max duration, notifications).
        Drives ADMIN-021..025.

        We only emit entries for canonically-privileged roles (per
        $RoleDefinitionLookup) to keep the snapshot focused and avoid noisy
        findings on Directory Reader / Message Center Reader / etc.
    #>
    param([hashtable]$RoleDefinitionLookup)

    Write-Section 'PIM role policy settings'
    try {
        $uri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$expand=policy(`$expand=rules)"
        $raw = Invoke-MgGraphRequestAllPages -Uri $uri
        $script:RawData.roleManagementPolicyAssignments = $raw
    } catch {
        Add-Warning "Failed to read PIM role management policies: $($_.Exception.Message). Verify Entra ID P2 licence + RoleManagement.Read.Directory scope."
        return ,@()
    }

    $out = @()
    foreach ($a in @($raw)) {
        if (-not $a -or -not $a.roleDefinitionId) { continue }
        $roleId = [string]$a.roleDefinitionId
        $roleInfo = $RoleDefinitionLookup[$roleId]
        if (-not $roleInfo) { continue }
        # Only privileged roles — see GetCanonicalPrivilegedTemplateIds in
        # Get-RoleDefinitionLookup.
        if (-not [bool]$roleInfo.isPrivileged) { continue }

        $rules = @()
        if ($a.policy -and $a.policy.rules) { $rules = @($a.policy.rules) }

        $enableRule  = $rules | Where-Object { [string]$_.id -eq 'Enablement_EndUser_Assignment'  } | Select-Object -First 1
        $expireRule  = $rules | Where-Object { [string]$_.id -eq 'Expiration_EndUser_Assignment'  } | Select-Object -First 1
        $approveRule = $rules | Where-Object { [string]$_.id -eq 'Approval_EndUser_Assignment'    } | Select-Object -First 1
        $notifAdmin  = $rules | Where-Object { [string]$_.id -eq 'Notification_Admin_EndUser_Assignment' } | Select-Object -First 1

        $enabled = @()
        if ($enableRule -and $enableRule.enabledRules) { $enabled = @($enableRule.enabledRules) }

        $mfaRequired           = ($enabled -contains 'MultiFactorAuthentication')
        $justificationRequired = ($enabled -contains 'Justification')
        $ticketingRequired     = ($enabled -contains 'Ticketing')

        $maxDurationIso = $null
        $maxDurationHours = $null
        if ($expireRule -and $expireRule.maximumDuration) {
            $maxDurationIso = [string]$expireRule.maximumDuration
            try {
                $maxDurationHours = [int]([System.Xml.XmlConvert]::ToTimeSpan($maxDurationIso)).TotalHours
            } catch {
                # Leave hours null if the ISO-8601 value is non-standard.
            }
        }

        $approvalRequired = $false
        if ($approveRule -and $approveRule.setting) {
            $approvalRequired = [bool]$approveRule.setting.isApprovalRequired
        }

        # 'notifyAdminsOnActivation' is true iff the Notification_Admin_EndUser_Assignment
        # rule exists AND has at least one recipient configured (notificationRecipients
        # array on the rule). The default-shipped rule has Microsoft's role-owner
        # recipient set but customers often clear it.
        $notifyAdminsOnActivation = $false
        if ($notifAdmin) {
            $recipients = @()
            if ($notifAdmin.notificationRecipients) { $recipients = @($notifAdmin.notificationRecipients) }
            # Default recipient is empty array → notifications are still sent to
            # the role owner unless explicitly disabled via isDefaultRecipientsEnabled.
            $defaultEnabled = $true
            if ($null -ne $notifAdmin.isDefaultRecipientsEnabled) {
                $defaultEnabled = [bool]$notifAdmin.isDefaultRecipientsEnabled
            }
            $notifyAdminsOnActivation = ($defaultEnabled -or ($recipients.Count -gt 0))
        }

        $out += [ordered]@{
            roleId                          = $roleId
            roleDisplayName                 = [string]$roleInfo.displayName
            roleTemplateId                  = [string]$roleInfo.templateId
            isPrivileged                    = [bool]$roleInfo.isPrivileged
            activationMfaRequired           = [bool]$mfaRequired
            activationJustificationRequired = [bool]$justificationRequired
            activationTicketingRequired     = [bool]$ticketingRequired
            activationApprovalRequired      = [bool]$approvalRequired
            activationMaxDurationIso        = $maxDurationIso
            activationMaxDurationHours      = $maxDurationHours
            notifyAdminsOnActivation        = [bool]$notifyAdminsOnActivation
        }
    }
    return ,@($out)
}

# Microsoft's built-in PRMFA strength accepts ONLY these methods.
# Used by Get-AuthenticationStrengths and Get-TenantBaselineCoverage.
$script:PhishResistantMethods = @('fido2','windowsHelloForBusiness','x509CertificateMultiFactor')

function Test-AuthStrengthPhishingResistant {
    # Returns $true iff every allowedCombination of $strength is composed
    # entirely of phishing-resistant method tokens.
    param($strength)
    if (-not $strength) { return $false }
    $combos = @($strength.allowedCombinations)
    if ($combos.Count -eq 0) { return $false }
    foreach ($combo in $combos) {
        $tokens = @(([string]$combo).Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($tokens.Count -eq 0) { return $false }
        foreach ($t in $tokens) {
            if ($script:PhishResistantMethods -notcontains $t) { return $false }
        }
    }
    return $true
}

function Get-AuthenticationStrengths {
    Write-Section 'Authentication strengths'
    try {
        $raw = Invoke-MgGraphRequestAllPages -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies'
        $script:RawData.authenticationStrengthPolicies = $raw

        $out = foreach ($s in $raw) {
            [ordered]@{
                id                    = $s.id
                displayName           = $s.displayName
                policyType            = $s.policyType
                requirementsSatisfied = $s.requirementsSatisfied
                allowedCombinations   = @($s.allowedCombinations)
                isPhishingResistant   = [bool](Test-AuthStrengthPhishingResistant -strength $s)
            }
        }
        return ,@($out)
    } catch {
        Add-Warning "Failed to read authenticationStrengthPolicies: $($_.Exception.Message)"
        return ,@()
    }
}

#endregion

#region Extended collectors (v1.1) ------------------------------------------

function Resolve-Principals {
    <#
        Batch-resolves principalIds (users / groups / service principals) via
        /directoryObjects/getByIds. Returns a hashtable:
            principalId -> [pscustomobject] {
                type, displayName, userPrincipalName, userType,
                isGuest, isCloudOnly, accountEnabled
            }
    #>
    param([string[]]$PrincipalIds)

    $lookup = @{}
    if (-not $PrincipalIds -or $PrincipalIds.Count -eq 0) { return $lookup }

    $unique = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]($PrincipalIds | Where-Object { $_ } | Sort-Object -Unique),
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $ids = @($unique)
    if ($ids.Count -eq 0) { return $lookup }

    $batchSize = 900   # /getByIds caps at 1000
    for ($i = 0; $i -lt $ids.Count; $i += $batchSize) {
        $end = [math]::Min($i + $batchSize - 1, $ids.Count - 1)
        $batch = @($ids[$i..$end])
        $body  = @{
            ids   = $batch
            types = @('user','group','servicePrincipal')
        } | ConvertTo-Json -Depth 4

        try {
            $resp = Invoke-MgGraphRequest -Method POST `
                -Uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' `
                -Body $body -ContentType 'application/json' -ErrorAction Stop
        } catch {
            Add-Warning "directoryObjects/getByIds failed: $($_.Exception.Message)"
            continue
        }

        foreach ($obj in @($resp.value)) {
            $odataType = [string]$obj.'@odata.type'
            $type = switch ($odataType) {
                '#microsoft.graph.user'             { 'user' }
                '#microsoft.graph.group'            { 'group' }
                '#microsoft.graph.servicePrincipal' { 'servicePrincipal' }
                default { 'unknown' }
            }
            $upn       = [string]$obj.userPrincipalName
            $userType  = [string]$obj.userType
            $isGuest   = $false
            if ($type -eq 'user') {
                $isGuest = ($userType -eq 'Guest') -or ($upn -and $upn -match '#EXT#')
            }
            $isCloudOnly = $null
            if ($upn) {
                $domain = ($upn -split '@')[-1].ToLowerInvariant()
                if ($script:VerifiedDomains.Count -gt 0 -and $script:VerifiedDomains.ContainsKey($domain)) {
                    $isCloudOnly = -not $script:VerifiedDomains[$domain].isFederated
                } elseif ($domain) {
                    # Domain not verified in this tenant: treat as external/guest
                    $isCloudOnly = $null
                }
            }
            $lookup[[string]$obj.id] = [pscustomobject]@{
                type              = $type
                displayName       = [string]$obj.displayName
                userPrincipalName = $upn
                userType          = $userType
                isGuest           = $isGuest
                isCloudOnly       = $isCloudOnly
                accountEnabled    = if ($null -ne $obj.accountEnabled) { [bool]$obj.accountEnabled } else { $null }
            }
        }
    }
    return $lookup
}

function Get-NamedLocations {
    Write-Section 'Conditional Access named locations'
    try {
        $raw = Invoke-MgGraphRequestAllPages -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations'
        $script:RawData.namedLocations = $raw

        $out = foreach ($n in $raw) {
            $odataType = [string]$n.'@odata.type'
            $type = switch ($odataType) {
                '#microsoft.graph.ipNamedLocation'      { 'ip' }
                '#microsoft.graph.countryNamedLocation' { 'country' }
                default { 'unknown' }
            }
            [ordered]@{
                id                                = [string]$n.id
                displayName                       = [string]$n.displayName
                type                              = $type
                isTrusted                         = if ($type -eq 'ip')      { [bool]$n.isTrusted } else { $null }
                ipRangeCount                      = if ($type -eq 'ip')      { @($n.ipRanges).Count } else { $null }
                countriesAndRegions               = if ($type -eq 'country') { @($n.countriesAndRegions) } else { @() }
                includeUnknownCountriesAndRegions = if ($type -eq 'country') { [bool]$n.includeUnknownCountriesAndRegions } else { $null }
            }
        }
        return ,@($out)
    } catch {
        Add-Warning "Failed to read namedLocations: $($_.Exception.Message)"
        return ,@()
    }
}

function Get-CrossTenantAccessDefaults {
    Write-Section 'Cross-tenant access policy (default)'
    try {
        $resp = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default' -ErrorAction Stop
        $script:RawData.crossTenantAccessDefaults = $resp

        $inboundTrust = $resp.inboundTrust
        $b2bColl      = $resp.b2bCollaborationInbound
        $b2bDcIn      = $resp.b2bDirectConnectInbound
        $b2bDcOut     = $resp.b2bDirectConnectOutbound

        $usersScope = $null
        $appsScope  = $null
        if ($b2bColl) {
            if ($b2bColl.usersAndGroups -and $b2bColl.usersAndGroups.accessType) { $usersScope = [string]$b2bColl.usersAndGroups.accessType }
            if ($b2bColl.applications   -and $b2bColl.applications.accessType)   { $appsScope  = [string]$b2bColl.applications.accessType }
        }

        return [ordered]@{
            inboundTrust = if ($inboundTrust) {
                [ordered]@{
                    isMfaAccepted                       = if ($null -ne $inboundTrust.isMfaAccepted)                       { [bool]$inboundTrust.isMfaAccepted }                       else { $null }
                    isCompliantDeviceAccepted           = if ($null -ne $inboundTrust.isCompliantDeviceAccepted)           { [bool]$inboundTrust.isCompliantDeviceAccepted }           else { $null }
                    isHybridAzureADJoinedDeviceAccepted = if ($null -ne $inboundTrust.isHybridAzureADJoinedDeviceAccepted) { [bool]$inboundTrust.isHybridAzureADJoinedDeviceAccepted } else { $null }
                }
            } else { $null }
            b2bCollaborationInbound = [ordered]@{
                usersAndGroupsScope = $usersScope
                applicationsScope   = $appsScope
            }
            b2bDirectConnectInbound  = if ($b2bDcIn  -and $b2bDcIn.usersAndGroups)  { [string]$b2bDcIn.usersAndGroups.accessType }  else { $null }
            b2bDirectConnectOutbound = if ($b2bDcOut -and $b2bDcOut.usersAndGroups) { [string]$b2bDcOut.usersAndGroups.accessType } else { $null }
        }
    } catch {
        Add-Warning "Failed to read crossTenantAccessPolicy/default: $($_.Exception.Message)"
        return $null
    }
}

function Get-RiskyUserSummary {
    Write-Section 'Risky users'
    try {
        $raw = Invoke-MgGraphRequestAllPages -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$top=500"
        $script:RawData.riskyUsers = $raw

        $total = @($raw).Count
        $byState = @{ atRisk = 0; confirmedCompromised = 0; remediated = 0; dismissed = 0; confirmedSafe = 0 }
        $byLevel = @{ high = 0; medium = 0; low = 0 }
        $sampleHigh = New-Object System.Collections.Generic.List[object]

        foreach ($u in $raw) {
            $state = [string]$u.riskState
            $level = [string]$u.riskLevel
            if ($byState.ContainsKey($state)) { $byState[$state]++ }
            if ($byLevel.ContainsKey($level)) { $byLevel[$level]++ }
            if ($level -eq 'high' -and $sampleHigh.Count -lt 25) {
                $sampleHigh.Add([ordered]@{
                    id                       = [string]$u.id
                    userPrincipalName        = [string]$u.userPrincipalName
                    userDisplayName          = [string]$u.userDisplayName
                    riskLevel                = $level
                    riskState                = $state
                    riskLastUpdatedDateTime  = ConvertTo-Iso8601 $u.riskLastUpdatedDateTime
                }) | Out-Null
            }
        }

        $atRiskCount = $byState.atRisk + $byState.confirmedCompromised

        return [ordered]@{
            totalRisky           = $total
            atRiskCount          = $atRiskCount
            confirmedCompromised = $byState.confirmedCompromised
            remediated           = $byState.remediated
            dismissed            = $byState.dismissed
            confirmedSafe        = $byState.confirmedSafe
            highRiskCount        = $byLevel.high
            mediumRiskCount      = $byLevel.medium
            lowRiskCount         = $byLevel.low
            sampleHighRisk       = $sampleHigh.ToArray()
        }
    } catch {
        Add-Warning "Failed to read riskyUsers: $($_.Exception.Message)"
        return $null
    }
}

function Get-UserRegistrationSummary {
    Write-Section 'User authentication-method registration'
    try {
        $raw = Invoke-MgGraphRequestAllPages -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?`$top=500"
        $script:RawData.userRegistrationDetails = @{ count = @($raw).Count; sample = @($raw | Select-Object -First 5) }

        $total          = 0
        $mfaCapable     = 0
        $mfaRegistered  = 0
        $passkeyReg     = 0
        $ssprCapable    = 0
        $ssprRegistered = 0

        foreach ($u in $raw) {
            # Skip non-member user types (guests / external) for capability stats
            if ([string]$u.userType -ne 'member') { continue }
            $total++
            if ([bool]$u.isMfaCapable)        { $mfaCapable++ }
            if ([bool]$u.isMfaRegistered)     { $mfaRegistered++ }
            if ([bool]$u.isPasskeyRegistered) { $passkeyReg++ }
            if ([bool]$u.isSsprCapable)       { $ssprCapable++ }
            if ([bool]$u.isSsprRegistered)    { $ssprRegistered++ }
        }

        $pct = { param($n,$d) if ($d -gt 0) { [math]::Round(($n/$d)*100, 2) } else { $null } }

        return [ordered]@{
            totalUsers                = $total
            mfaCapable                = $mfaCapable
            mfaRegistered             = $mfaRegistered
            passkeyRegistered         = $passkeyReg
            ssprCapable               = $ssprCapable
            ssprRegistered            = $ssprRegistered
            mfaRegisteredPercent      = & $pct $mfaRegistered $total
            mfaCapablePercent         = & $pct $mfaCapable    $total
            passkeyRegisteredPercent  = & $pct $passkeyReg    $total
        }
    } catch {
        Add-Warning "Failed to read authenticationMethods/userRegistrationDetails: $($_.Exception.Message)"
        return $null
    }
}

function Get-GuestSummary {
    Write-Section 'Guest users'
    try {
        $raw = Invoke-MgGraphRequestAllPages `
            -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName,displayName,userType,externalUserState&`$filter=userType eq 'Guest'&`$top=500"
        $script:RawData.guestUsers = @{ count = @($raw).Count }

        $total = @($raw).Count
        $accepted = 0
        $pending  = 0
        foreach ($g in $raw) {
            if ([string]$g.externalUserState -eq 'Accepted')          { $accepted++ }
            elseif ([string]$g.externalUserState -eq 'PendingAcceptance') { $pending++ }
        }
        return [ordered]@{
            totalGuests        = $total
            accepted           = $accepted
            pendingAcceptance  = $pending
        }
    } catch {
        Add-Warning "Failed to read guest users: $($_.Exception.Message)"
        return $null
    }
}

function Get-PimEligibleAssignments {
    <#
        Reads /roleManagement/directory/roleEligibilityScheduleInstances and
        normalizes per eligible role assignment. Principal enrichment is layered
        on later by the main flow once Resolve-Principals has run.
    #>
    param([hashtable]$RoleDefinitionLookup)

    Write-Section 'PIM eligible role assignments'
    try {
        $raw = Invoke-MgGraphRequestAllPages -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances'
        $script:RawData.pimEligibilityScheduleInstances = $raw

        $out = foreach ($i in $raw) {
            $def = $RoleDefinitionLookup[$i.roleDefinitionId]
            $end = $null
            try { if ($i.endDateTime) { $end = [datetime]::Parse([string]$i.endDateTime) } } catch {}
            [ordered]@{
                id                          = [string]$i.id
                principalId                 = [string]$i.principalId
                principalType               = $null   # filled by enrichment
                principalDisplayName        = $null
                principalUserPrincipalName  = $null
                principalIsGuest            = $null
                principalIsCloudOnly        = $null
                roleDefinitionId            = [string]$i.roleDefinitionId
                roleDisplayName             = if ($def) { [string]$def.displayName } else { [string]$i.roleDefinitionId }
                isPrivileged                = if ($def) { [bool]$def.isPrivileged } else { $null }
                startDateTime               = ConvertTo-Iso8601 $i.startDateTime
                endDateTime                 = ConvertTo-Iso8601 $end
                hasExpiry                   = [bool]$end
                memberType                  = [string]$i.memberType
                directoryScopeId            = [string]$i.directoryScopeId
            }
        }
        return ,@($out)
    } catch {
        Add-Warning "Failed to read roleEligibilityScheduleInstances: $($_.Exception.Message)"
        return ,@()
    }
}

function Add-PrincipalEnrichment {
    <#
        Mutates each ordered-dict assignment in -Assignments with principalType /
        principalDisplayName / principalUserPrincipalName / principalIsGuest /
        principalIsCloudOnly using -PrincipalLookup (Resolve-Principals output).
    #>
    param(
        [Parameter(Mandatory)][object[]]$Assignments,
        [Parameter(Mandatory)][hashtable]$PrincipalLookup
    )

    foreach ($a in $Assignments) {
        $principalKey = [string]$a.principalId
        if ($principalKey -and $PrincipalLookup.ContainsKey($principalKey)) {
            $p = $PrincipalLookup[$principalKey]
            $a.principalType              = $p.type
            $a.principalDisplayName       = $p.displayName
            $a.principalUserPrincipalName = $p.userPrincipalName
            $a.principalIsGuest           = $p.isGuest
            $a.principalIsCloudOnly       = $p.isCloudOnly
        } else {
            if (-not $a.principalType) { $a.principalType = 'unknown' }
        }
    }
}

function Get-EnrichedDirectoryRoleAssignments {
    <#
        Builds the flat directoryRoleAssignments array from $script:RawData.roleAssignments
        (already fetched by Get-DirectoryRoleAssignmentsForServicePrincipal) and the
        role-definition lookup. Principal enrichment is applied separately.
    #>
    param([hashtable]$RoleDefinitionLookup)

    $raw = @($script:RawData.roleAssignments)
    $out = foreach ($ra in $raw) {
        $def = $RoleDefinitionLookup[$ra.roleDefinitionId]
        [ordered]@{
            id                          = [string]$ra.id
            principalId                 = [string]$ra.principalId
            principalType               = $null
            principalDisplayName        = $null
            principalUserPrincipalName  = $null
            principalIsGuest            = $null
            principalIsCloudOnly        = $null
            roleDefinitionId            = [string]$ra.roleDefinitionId
            roleDisplayName             = if ($def) { [string]$def.displayName } else { [string]$ra.roleDefinitionId }
            isPrivileged                = if ($def) { [bool]$def.isPrivileged } else { $null }
            directoryScopeId            = [string]$ra.directoryScopeId
        }
    }
    return ,@($out)
}

function Get-BreakGlassDetails {
    <#
        Validates operator-supplied break-glass / emergency access accounts against
        the Microsoft Entra emergency access checklist:
          https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access

        Returns an [ordered] dictionary with two keys:
          config   = breakGlassConfig (status / skipReason / counts)
          accounts = array of per-account compliance snapshots
    #>
    param(
        [string[]]$Identifiers,
        [bool]$Skip,
        [object[]]$CaPolicies,
        [object[]]$RoleAssignments,
        [object[]]$PimEligible,
        [object[]]$AuthStrengths
    )

    $referenceUrl = 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access'

    if ($Skip) {
        Write-Section 'Break-glass validation (skipped by operator)'
        return [ordered]@{
            config = [ordered]@{
                status        = 'skipped'
                skipReason    = 'Operator explicitly skipped break-glass validation (-SkipBreakGlassValidation). Refer to the Microsoft Entra emergency access best-practice article.'
                providedCount = 0
                resolvedCount = 0
                referenceUrl  = $referenceUrl
            }
            accounts = @()
        }
    }

    if (-not $Identifiers -or $Identifiers.Count -eq 0) {
        Write-Section 'Break-glass validation (no accounts provided)'
        return [ordered]@{
            config = [ordered]@{
                status        = 'notProvided'
                skipReason    = 'No -BreakGlassAccounts list was supplied. Re-run with -BreakGlassAccounts (UPN or objectId per account) or -SkipBreakGlassValidation to record an explicit decision.'
                providedCount = 0
                resolvedCount = 0
                referenceUrl  = $referenceUrl
            }
            accounts = @()
        }
    }

    Write-Section 'Break-glass account validation'

    # Identify the initial *.onmicrosoft.com domain for cloud-only detection
    $initialDomain = $null
    foreach ($k in $script:VerifiedDomains.Keys) {
        if ($script:VerifiedDomains[$k].isInitial) {
            $initialDomain = $script:VerifiedDomains[$k].name.ToLowerInvariant()
            break
        }
    }

    # Pre-compute the set of enabled CA policies that enforce MFA (built-in 'mfa'
    # or any authenticationStrength). Report-only / disabled policies are ignored,
    # in line with MS guidance that report-only does not require exclusion.
    #
    # We also classify each enforced policy as either:
    #   - 'phishResistant' : the policy requires an authentication strength
    #     whose allowedCombinations contain ONLY phishing-resistant methods
    #     (fido2, windowsHelloForBusiness, x509CertificateMultiFactor).
    #   - 'weakMfa'        : anything else (builtIn 'mfa', or a strength that
    #     accepts at least one non-phishing-resistant combination such as
    #     password+SMS, password+push, TAP, etc).
    #
    # Modern Microsoft guidance (Entra emergency access doc, 2024+) is that
    # break-glass accounts should be EXCLUDED from weak-MFA / risk-based MFA
    # policies (those depend on MFA backend / risk engine availability), but
    # SHOULD be subject to phishing-resistant MFA — FIDO2 is offline-capable
    # and is the strongest control. Excluding break-glass from PRMFA policies
    # weakens posture rather than strengthening recoverability.

    $phishResistantMethods = @('fido2','windowsHelloForBusiness','x509CertificateMultiFactor')

    # Build a quick lookup: authStrength.id -> 'phishResistant'|'weakMfa'
    $strengthClassification = @{}
    foreach ($s in @($AuthStrengths)) {
        if (-not $s -or -not $s.id) { continue }
        $combos = @($s.allowedCombinations)
        $isPr = $true
        if ($combos.Count -eq 0) { $isPr = $false }
        foreach ($combo in $combos) {
            # A combination is a comma-separated list of method tokens (e.g.
            # "password,microsoftAuthenticatorPush"). The combination is
            # phishing-resistant only if every token in it is a PR method.
            $tokens = @(([string]$combo).Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $comboIsPr = ($tokens.Count -gt 0)
            foreach ($t in $tokens) {
                if ($phishResistantMethods -notcontains $t) { $comboIsPr = $false; break }
            }
            if (-not $comboIsPr) { $isPr = $false; break }
        }
        $strengthClassification[[string]$s.id] = if ($isPr) { 'phishResistant' } else { 'weakMfa' }
    }

    $enforcedMfaPolicies   = @()
    $enforcedWeakPolicies  = @()
    $enforcedPrPolicies    = @()
    foreach ($p in @($CaPolicies)) {
        if ([string]$p.state -ne 'enabled') { continue }
        $gc = $p.grantControls
        if (-not $gc) { continue }
        $built = @($gc.builtInControls)
        $strengthId = $null
        if ($gc.authenticationStrength -and $gc.authenticationStrength.id) {
            $strengthId = [string]$gc.authenticationStrength.id
        }
        if (-not ($built -contains 'mfa') -and -not $strengthId) { continue }

        $enforcedMfaPolicies += ,$p

        # Classify. A policy is PR only if it has an authStrength AND no weaker
        # control is being relied on. If 'mfa' built-in is also present, that
        # acts as a fallback (any MFA satisfies), so the policy is weak.
        $category = 'weakMfa'
        if ($strengthId -and -not ($built -contains 'mfa')) {
            $cls = $strengthClassification[$strengthId]
            if ($cls -eq 'phishResistant') { $category = 'phishResistant' }
        }
        if ($category -eq 'phishResistant') { $enforcedPrPolicies   += ,$p }
        else                                { $enforcedWeakPolicies += ,$p }
    }

    $accounts = New-Object System.Collections.Generic.List[object]
    $resolvedCount = 0

    foreach ($idf in $Identifiers) {
        $idf = [string]$idf
        if (-not $idf) { continue }

        $resolvedUser = $null
        $resolutionError = $null
        # Graph accepts either an objectId or a UPN on /users/{id}. The `signInActivity`
        # property returns 400 in tenants/contexts that don't expose it (e.g. lower
        # SKUs, certain CSP/MCAP demo tenants). Try with it first, then transparently
        # retry without it so the rest of the validation still runs. When the
        # fallback succeeds, lastSignInDateTime / daysSinceLastSignIn remain null
        # and the downstream sign-in-recency block is skipped.
        $selectWithActivity = 'id,userPrincipalName,displayName,userType,accountEnabled,onPremisesSyncEnabled,onPremisesImmutableId,signInActivity'
        $selectFallback     = 'id,userPrincipalName,displayName,userType,accountEnabled,onPremisesSyncEnabled,onPremisesImmutableId'
        $idfEscaped = [uri]::EscapeDataString($idf)
        try {
            $resolvedUser = Invoke-MgGraphRequest -Method GET `
                -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select={1}" -f $idfEscaped, $selectWithActivity) `
                -ErrorAction Stop
        } catch {
            $firstError = $_.Exception.Message
            $isBadRequest = $firstError -match 'BadRequest|Bad Request|\b400\b'
            if ($isBadRequest) {
                try {
                    $resolvedUser = Invoke-MgGraphRequest -Method GET `
                        -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select={1}" -f $idfEscaped, $selectFallback) `
                        -ErrorAction Stop
                    Add-Warning ("signInActivity unavailable for break-glass '{0}' (likely tenant SKU/licence); sign-in recency checks will be skipped." -f $idf)
                } catch {
                    $resolutionError = $_.Exception.Message
                    Add-Warning ("Break-glass account '{0}' could not be resolved: {1}" -f $idf, $resolutionError)
                }
            } else {
                $resolutionError = $firstError
                Add-Warning ("Break-glass account '{0}' could not be resolved: {1}" -f $idf, $resolutionError)
            }
        }

        if (-not $resolvedUser) {
            $accounts.Add([ordered]@{
                providedIdentifier               = $idf
                resolved                         = $false
                resolutionError                  = $resolutionError
                id                               = $null
                userPrincipalName                = $null
                displayName                      = $null
                domain                           = $null
                isOnInitialDomain                = $null
                isCloudOnly                      = $null
                onPremisesSyncEnabled            = $null
                accountEnabled                   = $null
                userType                         = $null
                isGlobalAdminActive              = $null
                isGlobalAdminEligible            = $null
                hasAnyPrivilegedRoleActive       = $null
                hasAnyPrivilegedRoleEligible     = $null
                activeRoleNames                  = @()
                eligibleRoleNames                = @()
                authenticationMethodTypes        = @()
                hasFido2                         = $null
                hasCertificateBased              = $null
                hasWindowsHelloForBusiness       = $null
                hasPhishingResistantMethod       = $null
                hasPassword                      = $null
                authMethodsAvailable             = $false
                enforcedMfaCaPolicyCount         = $enforcedMfaPolicies.Count
                excludedMfaCaPolicyCount         = 0
                excludedFromAllMfaCa             = $null
                nonExcludingMfaPolicies          = @()
                enforcedWeakMfaCaPolicyCount     = $enforcedWeakPolicies.Count
                excludedWeakMfaCaPolicyCount     = 0
                excludedFromAllWeakMfaCa         = $null
                nonExcludingWeakMfaPolicies      = @()
                enforcedPhishResistantCaPolicyCount = $enforcedPrPolicies.Count
                excludedPhishResistantCaPolicyCount = 0
                subjectToAnyPhishResistantCa     = $null
                applicablePhishResistantPolicies = @()
                lastSignInDateTime               = $null
                lastNonInteractiveSignInDateTime = $null
                daysSinceLastSignIn              = $null
            }) | Out-Null
            continue
        }

        $resolvedCount++
        $uid = [string]$resolvedUser.id
        $upn = [string]$resolvedUser.userPrincipalName

        # Domain & cloud-only determination
        $domain = $null
        if ($upn -and $upn.Contains('@')) { $domain = ($upn -split '@')[-1].ToLowerInvariant() }
        $isOnInitialDomain = $null
        if ($domain -and $initialDomain) { $isOnInitialDomain = ($domain -eq $initialDomain) }
        $isCloudOnly = $null
        $onPremSync = $resolvedUser.onPremisesSyncEnabled
        $onPremImmutable = $resolvedUser.onPremisesImmutableId
        if ($null -ne $onPremSync -or $null -ne $onPremImmutable) {
            # Either flag tells us the account is synced from on-prem AD
            $isCloudOnly = (-not [bool]$onPremSync) -and ([string]::IsNullOrEmpty([string]$onPremImmutable))
        } elseif ($domain -and $script:VerifiedDomains.ContainsKey($domain)) {
            $isCloudOnly = -not $script:VerifiedDomains[$domain].isFederated
        }

        # Role assignments — active (standing) and eligible (PIM)
        $activeRoles   = @($RoleAssignments | Where-Object { [string]$_.principalId -eq $uid })
        $eligibleRoles = @($PimEligible     | Where-Object { [string]$_.principalId -eq $uid })

        $activeRoleNames   = @($activeRoles   | ForEach-Object { [string]$_.roleDisplayName })
        $eligibleRoleNames = @($eligibleRoles | ForEach-Object { [string]$_.roleDisplayName })

        $isGaActive   = ($activeRoleNames   -contains 'Global Administrator')
        $isGaEligible = ($eligibleRoleNames -contains 'Global Administrator')

        $anyPrivilegedActive   = @($activeRoles   | Where-Object { [bool]$_.isPrivileged }).Count -gt 0
        $anyPrivilegedEligible = @($eligibleRoles | Where-Object { [bool]$_.isPrivileged }).Count -gt 0

        # Authentication methods
        $methodTypes = @()
        $hasFido2 = $null; $hasCba = $null; $hasWhfb = $null; $hasPassword = $null
        $authAvail = $false
        try {
            $methodsResp = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/users/$uid/authentication/methods" -ErrorAction Stop
            $authAvail = $true
            foreach ($m in @($methodsResp.value)) {
                $t = [string]$m.'@odata.type'
                if ($t) { $methodTypes += $t }
            }
            $hasFido2    = ($methodTypes -contains '#microsoft.graph.fido2AuthenticationMethod') -or `
                           ($methodTypes -contains '#microsoft.graph.passkeyAuthenticationMethod')
            $hasCba      = ($methodTypes -contains '#microsoft.graph.x509CertificateAuthenticationMethod')
            $hasWhfb     = ($methodTypes -contains '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod')
            $hasPassword = ($methodTypes -contains '#microsoft.graph.passwordAuthenticationMethod')
        } catch {
            Add-Warning ("Could not read authentication methods for break-glass '{0}': {1}" -f $upn, $_.Exception.Message)
        }
        $hasPhishingResistant = ($hasFido2 -eq $true) -or ($hasCba -eq $true) -or ($hasWhfb -eq $true)

        # CA exclusion analysis: an MFA-enforcing policy "covers" this user unless
        # the user (or a group the user is a member of, or a directory role the
        # user holds) is explicitly excluded. We approximate group exclusion via
        # excludeGroups containing the user's transitive group membership
        # (best-effort; if /transitiveMemberOf fails we fall back to direct
        # excludeUsers). Role-based exclusion compares CA excludeRoles (role
        # template IDs) against the user's active + PIM-eligible role
        # definitions; for built-in roles, roleDefinitionId == role template id.
        $userGroupIds = @()
        try {
            $tmRaw = Invoke-MgGraphRequestAllPages -Uri ("https://graph.microsoft.com/v1.0/users/{0}/transitiveMemberOf?`$select=id" -f $uid)
            $userGroupIds = @($tmRaw | ForEach-Object { [string]$_.id })
        } catch {
            Add-Warning ("Could not read transitiveMemberOf for break-glass '{0}': {1}" -f $upn, $_.Exception.Message)
        }

        # Combined active + eligible role definition IDs for role-based exclusion checks.
        $userRoleIds = @()
        $userRoleIds += @($activeRoles   | ForEach-Object { [string]$_.roleDefinitionId })
        $userRoleIds += @($eligibleRoles | ForEach-Object { [string]$_.roleDefinitionId })
        $userRoleIds = @($userRoleIds | Where-Object { $_ } | Sort-Object -Unique)

        $excludedCount = 0
        $nonExcluding  = New-Object System.Collections.Generic.List[string]
        $excludedWeakCount = 0
        $nonExcludingWeak = New-Object System.Collections.Generic.List[string]
        $excludedPrCount   = 0
        $applicablePr      = New-Object System.Collections.Generic.List[string]
        foreach ($p in $enforcedMfaPolicies) {
            $u = $p.conditions.users
            $exU = @($u.excludeUsers)
            $exG = @($u.excludeGroups)
            $exR = @($u.excludeRoles)
            $excluded = $false
            if ($exU -contains $uid) { $excluded = $true }
            if (-not $excluded) {
                foreach ($g in $exG) {
                    if ($userGroupIds -contains $g) { $excluded = $true; break }
                }
            }
            if (-not $excluded -and $exR.Count -gt 0 -and $userRoleIds.Count -gt 0) {
                foreach ($r in $exR) {
                    if ($userRoleIds -contains [string]$r) { $excluded = $true; break }
                }
            }
            if ($excluded) { $excludedCount++ }
            else           { $nonExcluding.Add([string]$p.displayName) | Out-Null }

            # Per-category bookkeeping. A policy is PR only if it carries an
            # authStrength id classified as phishing-resistant AND has no 'mfa'
            # builtIn that would let any weaker factor satisfy.
            $isPr = $false
            $gc = $p.grantControls
            if ($gc -and $gc.authenticationStrength -and $gc.authenticationStrength.id `
                -and -not (@($gc.builtInControls) -contains 'mfa')) {
                if ($strengthClassification[[string]$gc.authenticationStrength.id] -eq 'phishResistant') {
                    $isPr = $true
                }
            }
            if ($isPr) {
                if ($excluded) { $excludedPrCount++ }
                else           { $applicablePr.Add([string]$p.displayName) | Out-Null }
            } else {
                if ($excluded) { $excludedWeakCount++ }
                else           { $nonExcludingWeak.Add([string]$p.displayName) | Out-Null }
            }
        }
        $excludedFromAll = ($enforcedMfaPolicies.Count -gt 0) -and ($excludedCount -eq $enforcedMfaPolicies.Count)
        if ($enforcedMfaPolicies.Count -eq 0) { $excludedFromAll = $null }

        $excludedFromAllWeak = ($enforcedWeakPolicies.Count -gt 0) -and ($excludedWeakCount -eq $enforcedWeakPolicies.Count)
        if ($enforcedWeakPolicies.Count -eq 0) { $excludedFromAllWeak = $null }

        $subjectToAnyPr = $null
        if ($enforcedPrPolicies.Count -gt 0) {
            $subjectToAnyPr = ($applicablePr.Count -gt 0)
        }

        # Sign-in recency
        $lastSignIn = $null
        $lastNonInt = $null
        $daysSince  = $null
        if ($resolvedUser.signInActivity) {
            $lastSignIn = ConvertTo-Iso8601 $resolvedUser.signInActivity.lastSignInDateTime
            $lastNonInt = ConvertTo-Iso8601 $resolvedUser.signInActivity.lastNonInteractiveSignInDateTime
            try {
                $reference = if ($resolvedUser.signInActivity.lastSignInDateTime) { $resolvedUser.signInActivity.lastSignInDateTime } else { $resolvedUser.signInActivity.lastNonInteractiveSignInDateTime }
                if ($reference) {
                    $dt = [datetime]::Parse([string]$reference)
                    $daysSince = [int][math]::Floor(([datetime]::UtcNow - $dt.ToUniversalTime()).TotalDays)
                }
            } catch {}
        }

        $accounts.Add([ordered]@{
            providedIdentifier               = $idf
            resolved                         = $true
            resolutionError                  = $null
            id                               = $uid
            userPrincipalName                = $upn
            displayName                      = [string]$resolvedUser.displayName
            domain                           = $domain
            isOnInitialDomain                = $isOnInitialDomain
            isCloudOnly                      = $isCloudOnly
            onPremisesSyncEnabled            = if ($null -ne $onPremSync) { [bool]$onPremSync } else { $null }
            accountEnabled                   = if ($null -ne $resolvedUser.accountEnabled) { [bool]$resolvedUser.accountEnabled } else { $null }
            userType                         = [string]$resolvedUser.userType
            isGlobalAdminActive              = $isGaActive
            isGlobalAdminEligible            = $isGaEligible
            hasAnyPrivilegedRoleActive       = $anyPrivilegedActive
            hasAnyPrivilegedRoleEligible     = $anyPrivilegedEligible
            activeRoleNames                  = $activeRoleNames
            eligibleRoleNames                = $eligibleRoleNames
            authenticationMethodTypes        = $methodTypes
            hasFido2                         = $hasFido2
            hasCertificateBased              = $hasCba
            hasWindowsHelloForBusiness       = $hasWhfb
            hasPhishingResistantMethod       = $hasPhishingResistant
            hasPassword                      = $hasPassword
            authMethodsAvailable             = $authAvail
            enforcedMfaCaPolicyCount         = $enforcedMfaPolicies.Count
            excludedMfaCaPolicyCount         = $excludedCount
            excludedFromAllMfaCa             = $excludedFromAll
            nonExcludingMfaPolicies          = $nonExcluding.ToArray()
            enforcedWeakMfaCaPolicyCount     = $enforcedWeakPolicies.Count
            excludedWeakMfaCaPolicyCount     = $excludedWeakCount
            excludedFromAllWeakMfaCa         = $excludedFromAllWeak
            nonExcludingWeakMfaPolicies      = $nonExcludingWeak.ToArray()
            enforcedPhishResistantCaPolicyCount = $enforcedPrPolicies.Count
            excludedPhishResistantCaPolicyCount = $excludedPrCount
            subjectToAnyPhishResistantCa     = $subjectToAnyPr
            applicablePhishResistantPolicies = $applicablePr.ToArray()
            lastSignInDateTime               = $lastSignIn
            lastNonInteractiveSignInDateTime = $lastNonInt
            daysSinceLastSignIn              = $daysSince
        }) | Out-Null
    }

    return [ordered]@{
        config = [ordered]@{
            status        = 'defined'
            skipReason    = $null
            providedCount = @($Identifiers).Count
            resolvedCount = $resolvedCount
            referenceUrl  = $referenceUrl
        }
        accounts = $accounts.ToArray()
    }
}

#endregion

#region Collectors (workload identity continues) ----------------------------

function Get-DirectoryRoleAssignmentsForServicePrincipal {
    <#
        Returns a hashtable: spObjectId -> array of role assignment objects with display name.
        Sourced from /roleManagement/directory/roleAssignments and resolved against
        /roleManagement/directory/roleDefinitions.
    #>
    param([hashtable]$RoleDefinitionLookup)

    $raw = Invoke-MgGraphRequestAllPages -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'
    $script:RawData.roleAssignments = $raw

    $byPrincipal = @{}
    foreach ($ra in $raw) {
        $def = $RoleDefinitionLookup[$ra.roleDefinitionId]
        $entry = [ordered]@{
            id                  = $ra.id
            principalId         = $ra.principalId
            roleDefinitionId    = $ra.roleDefinitionId
            roleDisplayName     = if ($def) { $def.displayName } else { $ra.roleDefinitionId }
            isBuiltIn           = if ($def) { [bool]$def.isBuiltIn } else { $null }
            isPrivileged        = if ($def) { [bool]$def.isPrivileged } else { $null }
            directoryScopeId    = $ra.directoryScopeId
        }
        if (-not $byPrincipal.ContainsKey($ra.principalId)) {
            $byPrincipal[$ra.principalId] = New-Object System.Collections.Generic.List[object]
        }
        $byPrincipal[$ra.principalId].Add($entry) | Out-Null
    }
    return $byPrincipal
}

function Get-RoleDefinitionLookup {
    <#
        Microsoft Graph treats unifiedRoleDefinition.isPrivileged as an
        "advanced" property: it is either omitted entirely on the v1.0
        response or rejected as an invalid $select on some tenant editions
        (e.g. MCAP/CSP). We therefore:
          1. fetch role definitions without $select (always safe), and
          2. derive isPrivileged from the canonical Microsoft-published list
             of privileged Entra role template IDs, honouring the Graph value
             when present.
        Canonical list source:
        https://learn.microsoft.com/entra/identity/role-based-access-control/privileged-roles-permissions
    #>
    Write-Section 'Role definitions'
    $raw = Invoke-MgGraphRequestAllPages -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'
    $script:RawData.roleDefinitions = $raw

    # Microsoft's canonical privileged Entra role template IDs.
    $privilegedTemplateIds = @(
        '62e90394-69f5-4237-9190-012177145e10', # Global Administrator
        'e8611ab8-c189-46e8-94e1-60213ab1f814', # Privileged Role Administrator
        '194ae4cb-b126-40b2-bd5b-6091b380977d', # Security Administrator
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', # Privileged Authentication Administrator
        '29232cdf-9323-42fd-ade2-1d097af3e4de', # Exchange Administrator
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', # SharePoint Administrator
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', # Conditional Access Administrator
        '158c047a-c907-4556-b7ef-446551a6b5f7', # Cloud Application Administrator
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', # Application Administrator
        'fe930be7-5e62-47db-91af-98c3a49a38b1', # User Administrator
        '966707d0-3269-4727-9be2-8c3a10f19b9d', # Password Administrator
        '17315797-102d-40b4-93e0-432062caca18', # Compliance Administrator
        '3a2c62db-5318-420d-8d74-23affee5d9d5', # Intune Administrator
        '69091246-20e8-4a56-aa4d-066075b2a7a8', # Teams Administrator
        '7698a772-787b-4ac8-901f-60d6b08affd2', # Cloud Device Administrator
        '729827e3-9c14-49f7-bb1b-9608f156bbb8', # Helpdesk Administrator
        'a9ea8996-122f-4c74-9520-8edcd192826c', # Skype for Business Administrator
        'd29b2b05-8046-44ba-8758-1e26182fcf32', # Directory Synchronization Accounts
        '744ec460-397e-42ad-a462-8b3f9747a02c', # Knowledge Manager
        '8329153b-31d0-4727-b945-745eb3bc5f31', # Domain Name Administrator
        '11648597-926c-4cf3-9c36-bcebb0ba8dcc'  # Power Platform Administrator
    )

    $lookup = @{}
    foreach ($d in $raw) {
        $graphFlag = $d.isPrivileged
        $tid = if ($d.templateId) { [string]$d.templateId } else { [string]$d.id }
        $effective = if ($null -ne $graphFlag) {
            [bool]$graphFlag
        } else {
            $privilegedTemplateIds -contains $tid
        }
        $lookup[$d.id] = [pscustomobject]@{
            id           = $d.id
            templateId   = $tid
            displayName  = $d.displayName
            isBuiltIn    = $d.isBuiltIn
            isPrivileged = $effective
        }
    }
    return $lookup
}

function Get-ServicePrincipalsAndApps {
    param(
        [string]$TenantId
    )

    # Scope: match the Entra admin center's "Enterprise applications" -> "All applications"
    # default view. The portal filters service principals by the
    # 'WindowsAzureActiveDirectoryIntegratedApp' tag, which excludes Microsoft
    # first-party SPs, managed identities, and other system service principals.
    # The tags/any() filter is an advanced query, so we send $count=true and
    # ConsistencyLevel: eventual.
    Write-Section 'Service principals (Entra Enterprise Applications)'
    $spFilter = "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')"
    $spUri = 'https://graph.microsoft.com/v1.0/servicePrincipals' `
        + '?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,tags,signInAudience,passwordCredentials,keyCredentials' `
        + '&$top=200' `
        + '&$count=true' `
        + '&$filter=' + [uri]::EscapeDataString($spFilter)
    $spsRaw = Invoke-MgGraphRequestAllPages -Uri $spUri -Headers @{ ConsistencyLevel = 'eventual' }
    $script:RawData.servicePrincipals = $spsRaw

    Write-Section 'App role assignments (application permissions)'
    $appRoleAssignmentsBySp = @{}
    foreach ($sp in $spsRaw) {
        try {
            $assignments = Invoke-MgGraphRequestAllPages `
                -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments"
            $appRoleAssignmentsBySp[$sp.id] = $assignments
        } catch {
            Add-Warning "appRoleAssignments failed for $($sp.displayName): $($_.Exception.Message)"
            $appRoleAssignmentsBySp[$sp.id] = @()
        }
    }
    $script:RawData.appRoleAssignmentsBySp = $appRoleAssignmentsBySp

    Write-Section 'OAuth2 permission grants (delegated)'
    $oauth2Grants = Invoke-MgGraphRequestAllPages -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=200'
    $script:RawData.oauth2PermissionGrants = $oauth2Grants
    $grantsBySp = @{}
    foreach ($g in $oauth2Grants) {
        if (-not $grantsBySp.ContainsKey($g.clientId)) {
            $grantsBySp[$g.clientId] = New-Object System.Collections.Generic.List[object]
        }
        $grantsBySp[$g.clientId].Add($g) | Out-Null
    }

    Write-Section 'Resolving app-role IDs to permission names'
    # Build a lookup of resource SP -> { appRoleId -> value, scopeName -> value }.
    # Resolved lazily; the cache is keyed by both the SP objectId and appId so
    # call sites that hand us either form share a single Graph round-trip.
    # - appRoleAssignment.resourceId      -> SP objectId   -> /servicePrincipals/{id}
    # - oauth2PermissionGrant.resourceId  -> SP objectId   -> /servicePrincipals/{id}
    # - requiredResourceAccess.resourceAppId -> SP appId   -> /servicePrincipals(appId='{appId}')
    $resourceSpCache = @{}
    function Resolve-ResourceSp([string]$resourceId, [switch]$ByAppId) {
        if (-not $resourceId) { return $null }
        if ($resourceSpCache.ContainsKey($resourceId)) { return $resourceSpCache[$resourceId] }
        $uri = if ($ByAppId) {
            "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$resourceId')`?`$select=id,appId,displayName,appRoles,oauth2PermissionScopes"
        } else {
            "https://graph.microsoft.com/v1.0/servicePrincipals/$resourceId`?`$select=id,appId,displayName,appRoles,oauth2PermissionScopes"
        }
        try {
            $rsp = Invoke-MgGraphRequest -Method GET -Uri $uri
            $appRoleMap = @{}
            foreach ($ar in @($rsp.appRoles)) { $appRoleMap[[string]$ar.id] = $ar.value }
            $scopeMap = @{}
            foreach ($sc in @($rsp.oauth2PermissionScopes)) { $scopeMap[[string]$sc.id] = $sc.value }
            $entry = [pscustomobject]@{
                id           = $rsp.id
                appId        = $rsp.appId
                displayName  = $rsp.displayName
                appRoles     = $appRoleMap
                scopes       = $scopeMap
            }
            # Dual-key the cache so subsequent lookups by either form are free.
            if ($rsp.id)    { $resourceSpCache[[string]$rsp.id]    = $entry }
            if ($rsp.appId) { $resourceSpCache[[string]$rsp.appId] = $entry }
            $resourceSpCache[$resourceId] = $entry
            return $entry
        } catch {
            $kind = if ($ByAppId) { 'appId' } else { 'objectId' }
            Add-Warning "Could not resolve resource SP ($kind=$resourceId): $($_.Exception.Message)"
            $resourceSpCache[$resourceId] = $null
            return $null
        }
    }

    Write-Section 'Role definitions and assignments'
    $roleDefinitionLookup = Get-RoleDefinitionLookup
    $rolesByPrincipal = Get-DirectoryRoleAssignmentsForServicePrincipal -RoleDefinitionLookup $roleDefinitionLookup

    Write-Section 'Applications (registrations)'
    $appsRaw = Invoke-MgGraphRequestAllPages `
        -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,signInAudience,publisherDomain,requiredResourceAccess,passwordCredentials,keyCredentials&$top=200'
    $script:RawData.applications = $appsRaw

    # ---- Normalize service principals ----
    $servicePrincipals = foreach ($sp in $spsRaw) {
        $permissions = New-Object System.Collections.Generic.List[object]

        foreach ($ara in $appRoleAssignmentsBySp[$sp.id]) {
            $resourceSp = Resolve-ResourceSp $ara.resourceId
            $value = if ($resourceSp -and $resourceSp.appRoles.ContainsKey([string]$ara.appRoleId)) {
                $resourceSp.appRoles[[string]$ara.appRoleId]
            } else { [string]$ara.appRoleId }

            $permissions.Add([ordered]@{
                value               = $value
                permissionType      = 'application'
                resourceAppId       = if ($resourceSp) { $resourceSp.appId } else { $null }
                resourceDisplayName = if ($resourceSp) { $resourceSp.displayName } else { $ara.resourceDisplayName }
                consentType         = $null
                principalId         = $null
            }) | Out-Null
        }

        foreach ($g in $grantsBySp[$sp.id]) {
            $resourceSp = Resolve-ResourceSp $g.resourceId
            foreach ($scopeName in (@($g.scope -split ' ') | Where-Object { $_ })) {
                $permissions.Add([ordered]@{
                    value               = $scopeName
                    permissionType      = 'delegated'
                    resourceAppId       = if ($resourceSp) { $resourceSp.appId } else { $null }
                    resourceDisplayName = if ($resourceSp) { $resourceSp.displayName } else { $null }
                    consentType         = $g.consentType
                    principalId         = $g.principalId
                }) | Out-Null
            }
        }

        $roles = @()
        if ($rolesByPrincipal.ContainsKey($sp.id)) {
            $roles = foreach ($r in $rolesByPrincipal[$sp.id]) {
                [ordered]@{
                    roleDefinitionId = $r.roleDefinitionId
                    displayName      = $r.roleDisplayName
                    isBuiltIn        = $r.isBuiltIn
                    isPrivileged     = $r.isPrivileged
                    directoryScopeId = $r.directoryScopeId
                }
            }
        }

        $credentials = New-Object System.Collections.Generic.List[object]
        foreach ($pc in @($sp.passwordCredentials)) { $credentials.Add((Get-CredentialEnvelope -Entry $pc -Type 'secret')) | Out-Null }
        foreach ($kc in @($sp.keyCredentials))      { $credentials.Add((Get-CredentialEnvelope -Entry $kc -Type 'certificate')) | Out-Null }

        $homeSame = $null
        if ($sp.appOwnerOrganizationId -and $TenantId) {
            $homeSame = ([string]$sp.appOwnerOrganizationId -eq [string]$TenantId)
        }

        [ordered]@{
            id                       = $sp.id
            appId                    = $sp.appId
            displayName              = $sp.displayName
            servicePrincipalType     = $sp.servicePrincipalType
            accountEnabled           = $sp.accountEnabled
            appOwnerOrganizationId   = $sp.appOwnerOrganizationId
            homeTenantSameAsTenant   = $homeSame
            tags                     = @($sp.tags)
            permissions              = $permissions.ToArray()
            roles                    = @($roles)
            credentials              = $credentials.ToArray()
            signInAudience           = $sp.signInAudience
        }
    }

    # ---- Normalize applications ----
    $applications = foreach ($a in $appsRaw) {
        $reqPerms = New-Object System.Collections.Generic.List[object]
        foreach ($rra in @($a.requiredResourceAccess)) {
            # requiredResourceAccess.resourceAppId is an *appId*, not the SP objectId.
            $resourceSp = Resolve-ResourceSp $rra.resourceAppId -ByAppId
            foreach ($ra in @($rra.resourceAccess)) {
                $pt = if ($ra.type -eq 'Role') { 'application' } else { 'delegated' }
                $value = if ($resourceSp) {
                    if ($pt -eq 'application' -and $resourceSp.appRoles.ContainsKey([string]$ra.id)) { $resourceSp.appRoles[[string]$ra.id] }
                    elseif ($pt -eq 'delegated' -and $resourceSp.scopes.ContainsKey([string]$ra.id)) { $resourceSp.scopes[[string]$ra.id] }
                    else { [string]$ra.id }
                } else { [string]$ra.id }

                $reqPerms.Add([ordered]@{
                    value          = $value
                    permissionType = $pt
                    resourceAppId  = $rra.resourceAppId
                }) | Out-Null
            }
        }
        $creds = New-Object System.Collections.Generic.List[object]
        foreach ($pc in @($a.passwordCredentials)) { $creds.Add((Get-CredentialEnvelope -Entry $pc -Type 'secret')) | Out-Null }
        foreach ($kc in @($a.keyCredentials))      { $creds.Add((Get-CredentialEnvelope -Entry $kc -Type 'certificate')) | Out-Null }

        [ordered]@{
            id                   = $a.id
            appId                = $a.appId
            displayName          = $a.displayName
            signInAudience       = $a.signInAudience
            publisherDomain      = $a.publisherDomain
            requestedPermissions = $reqPerms.ToArray()
            credentials          = $creds.ToArray()
        }
    }

    # ---- Flat role assignments output ----
    $directoryRoleAssignments = foreach ($ra in $script:RawData.roleAssignments) {
        $def = $roleDefinitionLookup[$ra.roleDefinitionId]
        $spMatch = $servicePrincipals | Where-Object { $_.id -eq $ra.principalId } | Select-Object -First 1
        [ordered]@{
            id                    = $ra.id
            principalId           = $ra.principalId
            principalType         = if ($spMatch) { 'servicePrincipal' } else { 'unknown' }
            principalDisplayName  = if ($spMatch) { $spMatch.displayName } else { $null }
            roleDefinitionId      = $ra.roleDefinitionId
            roleDisplayName       = if ($def) { $def.displayName } else { $ra.roleDefinitionId }
            isPrivileged          = if ($def) { [bool]$def.isPrivileged } else { $null }
            directoryScopeId      = $ra.directoryScopeId
        }
    }

    return [ordered]@{
        servicePrincipals        = @($servicePrincipals)
        applications             = @($applications)
        directoryRoleAssignments = @($directoryRoleAssignments)
    }
}

#endregion

#region Main ----------------------------------------------------------------

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path

try {
    Connect-Graph

    $metadata     = Get-TenantMetadata
    $caPolicies   = Get-ConditionalAccessPolicies
    $idpPolicies  = Get-IdentityProtectionPolicies -CaPolicies $caPolicies
    $duplicateGroups = Get-PolicyDuplicateGroups   -CaPolicies $caPolicies
    $authMethods       = Get-AuthenticationMethodsPolicy
    $authMethodsMeta   = $script:AuthMethodsPolicyMeta
    $authStrengths = Get-AuthenticationStrengths
    $baselineCoverage = Get-TenantBaselineCoverage -CaPolicies $caPolicies -AuthStrengths $authStrengths
    $namedLocs    = Get-NamedLocations
    $crossTenant  = Get-CrossTenantAccessDefaults
    $authzPolicy        = Get-AuthorizationPolicy
    $adminConsentPolicy = Get-AdminConsentRequestPolicy
    $workload     = Get-ServicePrincipalsAndApps -TenantId $metadata.tenantId

    # Resolve role-definition lookup once for PIM + role-assignment enrichment.
    # (Get-ServicePrincipalsAndApps has already cached raw assignments and definitions.)
    $roleDefLookup = Get-RoleDefinitionLookup

    # Build enriched directoryRoleAssignments (all principal types, not just SPs).
    $directoryRoleAssignments = Get-EnrichedDirectoryRoleAssignments -RoleDefinitionLookup $roleDefLookup
    $pimEligible              = Get-PimEligibleAssignments         -RoleDefinitionLookup $roleDefLookup
    $pimRoleSettings          = Get-PimRoleSettings                -RoleDefinitionLookup $roleDefLookup

    # Resolve principal info for every principalId across both lists in one batch.
    $allPrincipalIds = @()
    $allPrincipalIds += @($directoryRoleAssignments | ForEach-Object { $_.principalId })
    $allPrincipalIds += @($pimEligible              | ForEach-Object { $_.principalId })
    $principalLookup = Resolve-Principals -PrincipalIds $allPrincipalIds

    Add-PrincipalEnrichment -Assignments $directoryRoleAssignments -PrincipalLookup $principalLookup
    Add-PrincipalEnrichment -Assignments $pimEligible              -PrincipalLookup $principalLookup

    $riskyUserSummary        = Get-RiskyUserSummary
    $userRegistrationSummary = Get-UserRegistrationSummary
    $guestSummary            = Get-GuestSummary

    $breakGlass = Get-BreakGlassDetails `
        -Identifiers      $BreakGlassAccounts `
        -Skip             $SkipBreakGlassValidation.IsPresent `
        -CaPolicies       $caPolicies `
        -RoleAssignments  $directoryRoleAssignments `
        -PimEligible      $pimEligible `
        -AuthStrengths    $authStrengths

    $snapshot = [ordered]@{
        metadata                  = $metadata
        conditionalAccessPolicies = @($caPolicies)
        identityProtectionPolicies= @($idpPolicies)
        policyDuplicateGroups     = @($duplicateGroups)
        authenticationMethods     = @($authMethods)
        authenticationMethodsPolicyMeta = $authMethodsMeta
        authenticationStrengths   = @($authStrengths)
        namedLocations            = @($namedLocs)
        tenantBaselineCoverage    = $baselineCoverage
        crossTenantAccessDefaults = $crossTenant
        authorizationPolicy       = $authzPolicy
        adminConsentRequestPolicy = $adminConsentPolicy
        pimRoleSettings           = @($pimRoleSettings)
        servicePrincipals         = $workload.servicePrincipals
        applications              = $workload.applications
        directoryRoleAssignments  = @($directoryRoleAssignments)
        pimEligibleAssignments    = @($pimEligible)
        riskyUserSummary          = $riskyUserSummary
        userRegistrationSummary   = $userRegistrationSummary
        guestSummary              = $guestSummary
        breakGlassConfig          = $breakGlass.config
        breakGlassAccounts        = @($breakGlass.accounts)
        collectionWarnings        = $script:Warnings.ToArray()
    }

    $normalizedPath = Join-Path $OutputPath 'tenant-data.json'
    $rawPath        = Join-Path $OutputPath 'tenant-data-raw.json'

    $snapshot      | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $normalizedPath -Encoding UTF8
    $script:RawData| ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $rawPath -Encoding UTF8

    Write-Host ''
    Write-Host "Normalized snapshot : $normalizedPath" -ForegroundColor Green
    Write-Host "Raw snapshot        : $rawPath"        -ForegroundColor Green
    $warnColor = if ($script:Warnings.Count) { 'Yellow' } else { 'Green' }
    Write-Host ("Warnings           : {0}" -f $script:Warnings.Count) -ForegroundColor $warnColor
}
catch {
    Write-Host ''
    Write-Host '==================== COLLECTOR FAILURE ====================' -ForegroundColor Red
    Write-Host ("Message : {0}" -f $_.Exception.Message) -ForegroundColor Red
    if ($_.Exception.InnerException) {
        Write-Host ("Inner   : {0}" -f $_.Exception.InnerException.Message) -ForegroundColor Red
    }
    if ($_.InvocationInfo) {
        Write-Host ("Location: {0}" -f $_.InvocationInfo.PositionMessage) -ForegroundColor Yellow
    }
    if ($_.ScriptStackTrace) {
        Write-Host 'Script stack trace:' -ForegroundColor DarkGray
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }
    Write-Host '===========================================================' -ForegroundColor Red
    throw
}

#endregion

$snapshotFile = Join-Path $OutputPath 'tenant-data.json'
$rawFile      = Join-Path $OutputPath 'tenant-data-raw.json'

Write-Host ''
Write-Host '== Done ==' -ForegroundColor Green
Write-Host ''
Write-Host 'Please send the following file back to your assessor:' -ForegroundColor Yellow
Write-Host "    $snapshotFile"
Write-Host ''
if (Test-Path -LiteralPath $rawFile) {
    Write-Host 'Optional companion file (raw Graph responses, useful for triage):'
    Write-Host "    $rawFile"
    Write-Host ''
}
Write-Host 'Both files are plain JSON. You can open them in a text editor to confirm'
Write-Host 'there is nothing your organisation considers sensitive before sending.'
Write-Host ''
Write-Host 'No tenant configuration was modified by this script.' -ForegroundColor Green

