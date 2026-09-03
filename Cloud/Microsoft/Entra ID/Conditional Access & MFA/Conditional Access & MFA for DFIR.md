# Conditional Access & MFA for DFIR

On a case, CA and MFA answer two questions: **should this sign-in have been stopped, and why wasn't it?** You'll use them to explain how the attacker got in despite "we have MFA," and to close the gap.

New to the service? Read **What is Conditional Access & MFA** first. This note is the *how*.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [The "How Did They Beat MFA?" Checklist](#the-how-did-they-beat-mfa-checklist)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Where |
|--------|--------------|-------|
| **Sign-in logs → CA tab** | Per-sign-in: which policies applied and their result | Entra portal / `SigninLogs` |
| **Audit logs** | CA policy create/update/delete; MFA method changes | Entra portal / `AuditLogs` |
| **CA policy config** | The current policies (assignments, controls, exclusions, state) | Entra → Conditional Access / Graph |
| **MFA registration** | Which methods each user has registered | Entra → Authentication methods |

## Collect It

**Snapshot every CA policy (assignments, controls, state, exclusions):**

```powershell
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State, `
  @{n='IncludeUsers';e={$_.Conditions.Users.IncludeUsers}}, `
  @{n='ExcludeUsers';e={$_.Conditions.Users.ExcludeUsers}}, `
  @{n='GrantControls';e={$_.GrantControls.BuiltInControls}}
```

> **Console:** Entra ID → Protection → **Conditional Access** → export/screenshot each policy's state + exclusions.

**Pull CA policy *changes* in the window (defense evasion):**

```powershell
Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Update conditional access policy' or activityDisplayName eq 'Delete conditional access policy'"
```

**See how CA evaluated the suspect sign-in:**

```kql
SigninLogs
| where UserPrincipalName == "alice@contoso.com"
| mv-expand pol = ConditionalAccessPolicies
| project TimeGenerated, IPAddress, PolicyName=pol.displayName, Result=pol.result, AuthRequirement=AuthenticationRequirement
```

## Investigate on the Platform

The flow:

| Step | Do this |
|------|---------|
| 1. Read the sign-in's CA result | `success` / `failure` / `notApplied` — and *which* policies matched |
| 2. If `notApplied` | Find the gap: excluded user/group? legacy auth? unscoped app? |
| 3. If MFA "satisfied by token" | Suspect **token replay** (AiTM) — pivot to non-interactive sign-ins |
| 4. Check for policy changes | Did the attacker weaken/disable a CA policy in the window? |
| 5. Check MFA method changes | Did they register a new MFA method (persistence)? |

## The "How Did They Beat MFA?" Checklist

Work top to bottom — one of these almost always explains it:

| # | Question | If yes → |
|---|----------|----------|
| 1 | **Legacy auth?** (`ClientAppUsed` = IMAP/POP/SMTP/"Other clients") | MFA never applied → block legacy auth |
| 2 | **Token replay?** (MFA "satisfied by claim in token", new device, non-interactive) | AiTM → **Token Theft** playbook |
| 3 | **User excluded** from the MFA policy? | Fix the exclusion |
| 4 | **Policy Off / Report-only?** | Enforce it |
| 5 | **Trusted-location skip?** (signed in from a "trusted" IP) | Review named locations |
| 6 | **Service principal?** (app-only, no user) | Most CA doesn't apply → workload-ID policies |
| 7 | **MFA fatigue?** (many push prompts then an approve) | Enable number matching |
| 8 | **New MFA method registered** by the attacker? | Persistence → remove it, re-register |

## Hunt at Scale

**Sensitive sign-ins where CA didn't apply:**

```kql
SigninLogs
| where ConditionalAccessStatus == "notApplied"
| where AppDisplayName in ("Azure Portal","Microsoft Graph","Office 365 Exchange Online")
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ClientAppUsed
```

**Single-factor success on privileged access:**

```kql
SigninLogs
| where AuthenticationRequirement == "singleFactorAuthentication"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress
```

**MFA method registrations (possible attacker persistence):**

```kql
AuditLogs
| where OperationName has_any ("Register security info","Add authentication method","User registered security info")
| project TimeGenerated, InitiatedBy, TargetResources
```

## Respond

| Goal | Action |
|------|--------|
| Re-enable a disabled/weakened policy | Restore the CA policy to its enforced state |
| Remove attacker MFA persistence | Delete the rogue MFA method; require re-registration |
| Block the source | Add a named-location / IP block; block risky sign-ins |
| Cut the session | Revoke refresh tokens (`Revoke-MgUserSignInSession`) + CAE |
| Close the exclusion | Remove the compromised account from any policy exclusion |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Block legacy authentication** everywhere | Kills the #1 MFA bypass |
| **Require MFA** for all users; **phishing-resistant** for admins | Stops replay + password-only |
| **Enable number matching** on push | Stops MFA fatigue |
| **Minimize exclusions**; review break-glass accounts | No quiet bypass groups |
| **Require compliant/hybrid-joined device** for admins | Blocks stolen tokens on unknown devices |
| **Turn on CAE + short sign-in frequency** for sensitive apps | Shrinks stolen-token lifetime |
| **Alert on CA policy changes** (audit log) | Catch defense evasion |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `conditionalAccessStatus = notApplied` on admin/Graph access | Coverage gap the attacker used |
| `singleFactorAuthentication` success on privileged access | MFA not enforced where it matters |
| MFA "satisfied by claim in token" from a new device | Token replay (AiTM) |
| `Update/Delete conditional access policy` in the window | Defense evasion |
| New MFA method registered from a new IP | Attacker MFA persistence |
| Legacy-auth success | MFA bypassed entirely |
| A compromised account sitting in a policy **exclusion** | Deliberate/accidental bypass |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What CA/MFA are + how to read them | **Conditional Access & MFA → What is** |
| The sign-in CA evaluated | **Entra → Sign-in Logs** |
| CA policy change events | **Entra → Audit Logs** |
| Token replay that beats MFA | **Entra → Playbooks → Token Theft and AiTM** |
| Risk signals feeding CA | **Entra → Identity Protection** |

## Resources

- Conditional Access — https://learn.microsoft.com/entra/identity/conditional-access/overview
- Sign-in log CA details — https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-in-log-activity-details
- Number matching — https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-number-match
- MITRE ATT&CK: Modify Authentication Process (T1556) — https://attack.mitre.org/techniques/T1556/
