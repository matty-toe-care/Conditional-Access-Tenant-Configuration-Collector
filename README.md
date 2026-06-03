# Conditional-Access-Tenant-Configuration-Collector

`Collect-TenantData.ps1` is a single-file, read-only Microsoft Graph data
collector. Run it against your Entra ID (Azure AD) tenant to produce a JSON
snapshot. **No tenant
configuration is modified.**

This script is intentionally self-contained — you only need this file (and
PowerShell 7) to run it. There is no installer, no DLL, no helper script.

---

## What it collects

Configuration data only:

- Tenant metadata and verified domains
- Conditional Access policies, named locations, cross-tenant access defaults
- Identity Protection (sign-in / user risk) policies
- Authentication methods policy, registration campaign state, migration state
- Authentication strengths (including a phishing-resistant classification)
- Tenant authorization policy (user / admin consent, self-service settings)
- Admin consent request workflow policy
- Service principals (Enterprise Applications), app role assignments,
  OAuth2 delegated grants, credential **metadata** (key IDs, expiry — never
  secret values)
- Application registrations and their credential metadata
- Directory role definitions and assignments, PIM-eligible assignments,
  PIM role-policy settings for privileged roles
- Risky-user counts, MFA / passkey registration counts, guest counts
- Per-account break-glass compliance snapshot (only if you opt in)

## What it does NOT collect

- User content (mail, files, chats, calendar)
- Sign-in logs or audit logs
- Secrets, certificates, passwords, or any credential material
- Personal data beyond the UPNs / display names of accounts that are
  directly relevant to a finding (privileged role holders, break-glass
  accounts, a small sample of risky users)

You can open the output JSON in any text editor to review.

---

## Prerequisites

| Requirement | Detail |
|-------------|--------|
| OS          | Windows, macOS, or Linux |
| PowerShell  | 7.0 or later — install from <https://aka.ms/powershell> |
| Modules     | Microsoft Graph PowerShell SDK (auto-installed on first run if missing) |
| Account     | Signed-in user needs **Global Reader** or **Security Reader** (or higher) |
| Network     | Outbound HTTPS to `graph.microsoft.com` and `login.microsoftonline.com` |

### Required Microsoft Graph scopes (all delegated, all read-only)

- `Policy.Read.All`
- `Policy.Read.ConditionalAccess`
- `IdentityRiskyUser.Read.All`
- `Directory.Read.All`
- `Application.Read.All`
- `RoleManagement.Read.Directory`
- `AuditLog.Read.All`
- `Reports.Read.All`
- `CrossTenantInformation.ReadBasic.All`
- `UserAuthenticationMethod.Read.All` *(only when `-BreakGlassAccounts` is used)*

The first time you run the collector your browser will show a Microsoft
consent screen listing these scopes. If your tenant requires admin consent
for new scope grants, ask your Entra admin to approve them once for the
"Microsoft Graph Command Line Tools" enterprise application.

If any individual scope is not granted, the collector emits a warning and
continues — the corresponding section of the report will be marked
"not collected".

---

## Quick start

```powershell
# Default: interactive sign-in, snapshot written to .\snapshot\
.\Collect-TenantData.ps1

# Provide break-glass / emergency-access accounts for validation (recommended)
.\Collect-TenantData.ps1 -BreakGlassAccounts 'bg1@contoso.onmicrosoft.com','bg2@contoso.onmicrosoft.com'

# Choose a specific tenant (you are a guest in several)
.\Collect-TenantData.ps1 -TenantId 00000000-0000-0000-0000-000000000000

# Headless / jump-box: use device-code sign-in instead of the browser pop-up
.\Collect-TenantData.ps1 -UseDeviceCode

# Write the snapshot somewhere specific
.\Collect-TenantData.ps1 -OutputPath 'C:\Assessments\contoso'
```

Get full help any time:

```powershell
Get-Help .\Collect-TenantData.ps1 -Full
```

---

## Parameters

| Parameter | Purpose |
|-----------|---------|
| `-OutputPath <path>` | Directory for the snapshot. Defaults to `.\snapshot` beside the script. |
| `-TenantId <guid>` | Target a specific tenant. Useful if your account is a guest in multiple tenants. |
| `-UseDeviceCode` | Use device-code sign-in (headless sessions, jump boxes). |
| `-BreakGlassAccounts <upn[,upn]>` | UPNs (or object IDs) of your emergency-access accounts. Triggers per-account compliance validation. |
| `-SkipBreakGlassValidation` | Record an explicit decision to skip break-glass validation. The report shows a `Skipped` banner instead of `Not provided`. |
| `-SkipModuleInstall` | Skip the auto-install step. Use when your environment manages module installation centrally. |
| `-SkipConnect` | Skip `Connect-MgGraph`. Use when the caller has already established a session. |
| `-NonInteractive` | Suppress all interactive prompts. Required for unattended / automation runs. |

`-BreakGlassAccounts` and `-SkipBreakGlassValidation` are mutually exclusive.

---

## Break-glass (emergency-access) accounts

[Microsoft strongly recommends](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)
every tenant maintains at least **two** dedicated break-glass accounts. The
collector cannot auto-discover these because they look identical to other
privileged accounts — you must name them explicitly.

When you pass `-BreakGlassAccounts`, each account is scored against the
Microsoft checklist:

- Cloud-only (created on the initial `*.onmicrosoft.com` domain — not synced
  or federated)
- Phishing-resistant credential registered (FIDO2 / Certificate-Based Auth /
  Windows Hello for Business)
- Permanent active Global Administrator (not PIM-eligible)
- Excluded from weak-MFA Conditional Access policies that depend on the
  same MFA / risk backend the account is meant to recover from
- Subject to **at least one** phishing-resistant MFA policy (FIDO2 is
  offline-capable; excluding break-glass from PRMFA weakens posture)
- Exercised within the last 90 days

If you cannot share account identifiers at collection time, pass
`-SkipBreakGlassValidation`. This is recorded as an explicit decision in the
report (a `Skipped` banner plus an informational finding `ADMIN-009`), which
is preferable to a silent `Not provided`.

If you run the script with neither switch and accept the default at the
interactive prompt, the report shows a `Not provided` banner and finding
`ADMIN-007`.

---

## Output files

After a successful run the collector writes two files to the output
directory (default `.\snapshot\`):

| File | Purpose |
|------|---------|
| `tenant-data.json`     | The **normalized snapshot** |
| `tenant-data-raw.json` | Optional companion: raw per-endpoint Graph responses, useful for triage. |

Both files are plain JSON. Inspect them in a text editor before sharing if
you want to confirm there is nothing your organisation considers sensitive.

---

## Troubleshooting

| Symptom | Resolution |
|---------|------------|
| `PowerShell 7 or later is required` | Install from <https://aka.ms/powershell> and start the script with `pwsh` (not Windows PowerShell `powershell.exe`). |
| `Install-Module` fails with `Untrusted repository` | One-off: `Set-PSRepository PSGallery -InstallationPolicy Trusted` then retry. |
| `Insufficient privileges to complete the operation` | The signed-in account lacks Global Reader (or equivalent). Re-run with a more privileged read-only account. |
| Browser sign-in pop-up does not appear | Re-run with `-UseDeviceCode` and follow the on-screen instructions. |
| Warnings about specific scopes not granted | The corresponding section of the report will be marked "not collected". Ask your admin to grant the missing scope and re-run if it is material. |
| `signInActivity` warnings on break-glass validation | Some tenant SKUs / contexts do not expose sign-in activity. The collector retries automatically without that field; the "exercised within 90 days" check is skipped for affected accounts. |
| `adminConsentRequestPolicy` warning about an Entra ID P1 / P2 licence | The endpoint is licence-gated. The collector records the policy as `unavailable=true` so the rule that depends on it does not raise a false positive. |
| `roleManagementPolicyAssignments` warning | PIM role-policy collection requires Entra ID P2 plus `RoleManagement.Read.Directory`. Findings in the PIM hygiene category will be omitted on tenants without P2. |
| The script takes several minutes on a large tenant | Service-principal enumeration is `O(n)` per app — this is expected on tenants with many Enterprise Applications and is unrelated to errors. |

---

## Privacy and trust notes

- The script connects to Microsoft Graph over HTTPS using your interactive
  Microsoft account. No credentials are stored.
- Only the scopes listed above are requested. They are all **read-only**.
- The Microsoft.Graph PowerShell modules are open source and published by
  Microsoft. The collector does not download any other code at runtime.
- The output JSON is written only to the path you specified — nothing is
  uploaded anywhere by the script itself.

---

## Version

Collector script version is exposed as `metadata.collectorVersion` in the
snapshot. Current: **1.2.0**.
