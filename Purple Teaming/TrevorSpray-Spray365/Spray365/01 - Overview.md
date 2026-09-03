# Spray365 — Overview

> 🔴 **Red Flag Principle:** Spray365's default behavior — in *both* its `generate normal` and `generate audit` modes — randomly assigns **a different legitimate Microsoft first-party `client_id` and a different resource `endpoint`** to every single credential attempt, drawn from a built-in catalog of ~45 client IDs and ~12 resource endpoints lifted directly from `AADInternals`' own token-acquisition source. A single spray run against one tenant can therefore appear in Entra ID Sign-in Logs as authentication traffic from dozens of *different, individually legitimate-looking* `AppDisplayName` values (Teams, Azure CLI, OneDrive, Skype, `aadsync`, and more) — hunting on any single `AppId` will miss most of the run. Hunt on the **shared authentication pattern** (MSAL ROPC via ` login.microsoftonline.com/organizations`, ID token endpoint `/oauth2/v2.0/token`), not on any one application identity.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

- [`MarkoH17/Spray365`](https://github.com/MarkoH17/Spray365), authored by **Mark Hedrick**, licensed **MIT**. Repo created 2021-11-04. **Correcting the task brief's assumed attribution: this is not an Optiv project** — Optiv's actual O365-spray tool is a separate, differently-architected tool called `Go365` (Go, not Python); Spray365 is an independent MarkoH17 project. The README credits **[@__TexasRanger](https://twitter.com/__TexasRanger)** and **SecurityRiskAdvisors' `msspray`** ([github.com/SecurityRiskAdvisors/msspray](https://github.com/SecurityRiskAdvisors/msspray)) as direct inspiration for the tool's approach.
- **Verified live against the GitHub API: the repository is archived** (`"archived": true`), last pushed 2025-06-24, with 381 stars. The most recent tagged release is `0.2.2-beta` (2022-07-14), though the in-source `version` string in `spray365.py` reads `0.2.3` — an unreleased bump that never shipped as a tagged GitHub Release. This is the defining fact distinguishing it from its bundled sibling: **Spray365 is dormant/unmaintained as of this build**, where `../TrevorSpray/` is actively developed.
- **No MITRE ATT&CK Software (S-number) entry, and — verified directly against the live [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) technique page's full Procedure Examples table — no procedure-example citation at all.** Same finding as `../TrevorSpray/`; neither tool in this bundle has any MITRE ATT&CK presence whatsoever.
- Its client_id/endpoint catalog (`modules/core/constants.py`) carries a source comment crediting **[`Gerenios/AADInternals`](https://github.com/Gerenios/AADInternals)'s `AccessToken_utils.ps1`** as the origin of both lookup tables — a direct, source-verified lineage tying this tool to `../../AADInternals/`, already built in this repo.

## How It Works

### The two-step "execution plan" architecture

Unlike `../TrevorSpray/`'s single-invocation model, Spray365 splits spraying into two deliberate steps, both exposed as subcommands of `spray365.py`:

```
STEP 1 — spray365.py generate {normal|audit} ...
    │  builds a list of Credential objects (domain, username, password,
    │  client_id, endpoint, user_agent, delay, initial_delay) and writes
    │  them as a JSON array to an operator-named .s365 file
    ▼
STEP 2 — spray365.py spray -ep plan.s365 ...
    │  reads the .s365 file back in, and for each Credential calls MSAL's
    │  PublicClientApplication.acquire_token_by_username_password() — a
    │  genuine OAuth2 Resource Owner Password Credentials (ROPC) grant
    │  against https://login.microsoftonline.com/organizations
    ▼
STEP 3 (optional) — spray365.py review results.json
       parses the exported spray365_results_<timestamp>.json and buckets
       every attempt into valid / invalid / partial-success (MFA/CA-blocked)
```

Because Step 2 only needs the `.s365` file, an execution plan produced by a *different* tool (any JSON matching the `Credential` schema) can be sprayed with Spray365 — the README calls this out explicitly as a supported workflow for building custom pipelines.

### `generate normal` — one credential per user×password, randomized identity per attempt

`modules/generate/modes/normal.py`, verified directly against source: for each `(username, password)` pair (or `user:pass` pairs from `--passwords_in_userfile`), a `Credential` is built with a **`random.choice()`-selected `client_id` and `endpoint`** from the full built-in catalogs (unless `-cID`/`-eID` pins specific ones) — this randomization happens **by default**, not only in audit mode. Credentials are then either:
- **Grouped by password** (default) — every user is tried with password 1, then every user with password 2, etc. (the standard "spray" shape), or
- **Shuffled** (`-S/--shuffle_auth_order`) — see below.

### `generate audit` — full cartesian product, built for Conditional Access fingerprinting

`modules/generate/modes/audit.py`: instead of one credential per user×password, this mode builds the **complete cross-product** of `users × passwords × client_ids × endpoint_ids × user_agents` — verified directly in `helpers.get_credential_products()`, which uses `itertools.product()` across all five dimensions. The tool's own console warning is explicit: *"Audit-mode execution plans contain permutations of all possible usernames, passwords, user-agents, aad_clients, and aad_endpoints."* With the full ~45×12 client/endpoint catalog, a single-user, single-password audit plan already produces **540 individual authentication attempts** — this mode is designed to answer "does *any* combination of application identity and resource endpoint bypass this tenant's Conditional Access policy for this one known-good credential," not to spray a large user population.

### The shuffle algorithm — an actual optimization search, not a simple `random.shuffle()`

`modules/generate/helpers.get_shuffled_credentials()`: when `-S/--shuffle_auth_order` is set, the tool doesn't just randomize order once — it generates **`-SO/--shuffle_optimization_attempts` (default 10) independent candidate execution plans**, computes each one's total estimated runtime via `get_spray_runtime()` (sum of every credential's `delay`+`initial_delay`), and **keeps the fastest one**. Each candidate plan groups credentials per-user, shuffles per-user ordering, then interleaves users randomly per "round" — and `_insert_random_initial_delays()` inserts extra per-credential delay wherever needed to guarantee `-mD/--min_loop_delay` seconds have elapsed since that same user's last attempt, even across the randomized ordering. This is a genuine scheduling-optimization step, not cosmetic randomization.

### The spray phase — real MSAL, real error-code table

`modules/spray/helpers.authenticate_credential()` builds an `msal.PublicClientApplication` per credential and calls `acquire_token_by_username_password(scopes=["<endpoint>/.default"])` — this is Microsoft's **own official MSAL library** performing a standard ROPC token acquisition, not a hand-built HTTP request the way `../TrevorSpray/`'s `msol` module works. The returned MSAL `error_codes` are matched against a fixed classification table:

| Error code(s) | Classification | Meaning |
|---|---|---|
| `7000218`, `700016`, `65001` | **Complete success** | Valid credential, token actually issued (note: MSAL treats these specific "consent required"/app-not-found-on-this-tenant codes as evidence the *password itself* was correct even though no usable token came back) |
| `50053`, `50055`, `50057`, `50158`, `50076`, `53003` | **Partial success** | Valid credential, blocked by lockout / expired password / disabled account / Conditional Access / MFA |
| `50034` | Invalid — user not found | |
| any other code | Invalid | |

`review` later buckets results using exactly this same three-way split, plus a `--show_valid_aad_access` flag that lists **which specific endpoint/client_id combinations succeeded** for each valid credential — directly surfacing which application-identity-and-resource pairing evades that tenant's Conditional Access, the actual point of the `audit` mode.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Core auth protocol | OAuth2 Resource Owner Password Credentials (ROPC) grant via Microsoft's official **MSAL** Python library (`PublicClientApplication.acquire_token_by_username_password`) |
| Target endpoint | `https://login.microsoftonline.com/organizations` (multi-tenant authority; not tenant-specific) |
| Client-identity evasion | Random selection per attempt from ~45 real Microsoft first-party `client_id`s and ~12 resource `endpoint_id`s (source: `AADInternals`) |
| Scheduling evasion | Execution-plan-based delay/jitter/shuffle, computed and validated *before* any traffic is sent |
| Result classification | MSAL `error_codes` (same underlying AADSTS taxonomy as `../TrevorSpray/`'s hand-parsed error strings, but consumed through MSAL's own structured response) |
| Traffic routing | Optional single HTTP/HTTPS `--proxy` (e.g. Burp); **no built-in IP-rotation mechanism of its own** — unlike `../TrevorSpray/`, IP diversity requires chaining an external proxy/VPN layer |

## Command-Line Switches — Quick Reference

Verified directly against `modules/generate/options.py`, `modules/generate/modes/normal.py`, `modules/generate/modes/audit.py`, `modules/spray/spray.py`, and `modules/review/review.py`.

### `spray365.py generate normal` — build a standard execution plan

| Switch | Plain-English meaning |
|---|---|
| `-ep, --execution_plan <file>` | **Required.** Output path for the generated `.s365` plan |
| `-d, --domain <domain>` | **Required.** Target O365/Azure AD domain |
| `-u, --user_file <file>` | **Required.** File of usernames (one per line, no domain) |
| `-p, --password <pw>` | A single password to spray (mutually exclusive with the two below) |
| `-pf, --password_file <file>` | File of passwords to spray |
| `--passwords_in_userfile` | Treat `-u`'s file as `username:password` pairs instead of usernames alone |
| `--delay <sec>` | Delay between attempts (default **30**) |
| `-mD, --min_loop_delay <sec>` | Minimum enforced time between two attempts for the *same* user, honored even when `-S` reorders things (default 0) |
| `-cID, --aad_client <id,id,...>` | Pin specific client ID(s) instead of random selection from the full catalog |
| `-eID, --aad_endpoint <id,id,...>` | Pin specific endpoint ID(s) instead of random selection |
| `-cUA, --custom_user_agent <string>` | Use one fixed custom User-Agent for every attempt |
| `-rUA, --random_user_agent` | Randomize User-Agent per attempt (default **True**) |
| `-S, --shuffle_auth_order` | Enable the optimization-search shuffle described above |
| `-SO, --shuffle_optimization_attempts <n>` | Candidate plans to generate and pick the fastest from (default 10) |

### `spray365.py generate audit` — build a full cross-product plan

Same `general_options`/`user_options`/`password_options`/`shuffle_options` as `normal`, **minus** `-cID`/`-eID`/user-agent pinning — `audit` always uses the *entire* client/endpoint/user-agent catalog, since the point is testing every combination.

### `spray365.py spray` — execute a plan

| Switch | Plain-English meaning |
|---|---|
| `-ep, --execution_plan <file>` | **Required.** Path to a previously generated `.s365` plan |
| `-l, --lockout <n>` | Abort after this many observed lockouts (AADSTS `50053`); `0` disables the check entirely (default **5**) |
| `-R, --resume_index <n>` | Resume spraying starting at this position in the plan (1-indexed) |
| `-i, --ignore_success` | Keep spraying a user's remaining passwords even after a valid credential is already found for them (default off — normally the tool skips remaining attempts for a user once a hit lands) |
| `-x, --proxy <url>` | Route all HTTP/HTTPS traffic through this proxy |
| `-k, --insecure` | Disable TLS certificate verification (e.g. to intercept via a self-signed Burp CA) |

### `spray365.py review` — analyze results

| Argument/Switch | Plain-English meaning |
|---|---|
| `RESULTS` (positional) | **Required.** Path to a `spray365_results_*.json` file |
| `--show_invalid_creds` | Also print every failed (non-existent-user-excluded) attempt |
| `--show_invalid_users` | Also print every confirmed-nonexistent username |
| `--show_valid_aad_access` | Print, per valid credential, exactly which `endpoint`/`client_id` combinations succeeded — the Conditional-Access-gap-mapping output |

## Quick Use-Case List

- Baseline generate-then-spray workflow: `generate normal` a plan, then `spray` it, against a standard O365/Azure AD tenant
- Resuming a spray from an exact position (`-R`) after a network interruption, without re-attempting everything from the start
- Pinning a single, specific `client_id`/`endpoint` pair (`-cID`/`-eID`) to target one known application/resource rather than randomizing across the whole catalog
- `audit` mode against **one already-known-valid credential** to fingerprint exactly which application-identity/resource combinations bypass the tenant's Conditional Access policies — a CA-gap-mapping use case distinct from population-wide spraying
- `--shuffle_auth_order` (with `-mD` set) to spread per-user attempt timing unpredictably and complicate lockout/timing-based correlation
- Proxying every request through Burp Suite (`-x http://127.0.0.1:8080 -k`) for manual inspection or replay of individual MSAL token requests
- `--ignore_success` to deliberately continue testing every remaining password for a user even after a hit — useful for password-reuse/weak-policy auditing rather than "first hit and stop" operational spraying
- Tuning the lockout threshold (`-l`) up or down depending on how aggressively the operator is willing to risk triggering Smart Lockout
- `review --show_valid_aad_access` to turn a completed spray/audit run into a concrete list of exploitable client-ID/endpoint combinations for a findings write-up
- `review --show_invalid_creds`/`--show_invalid_users` for a full post-mortem accounting of exactly what was attempted, useful for engagement documentation and deconfliction
- Building a custom `.s365` file with an external script/tool (matching the `Credential` JSON schema) and spraying it with Spray365's `spray` subcommand alone, bypassing `generate` entirely
- Chained workflow: feeding a valid credential and its confirmed-working `endpoint`/`client_id` pair (from `review --show_valid_aad_access`) into `../../AADInternals/` for endpoint-specific token acquisition, or testing the same password against on-prem AD via `../../NetExec/`/`../../Impacket/` in a hybrid-identity tenant

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Python | 3.9 minimum, 3.10 recommended (per README) |
| Install | `git clone https://github.com/MarkoH17/Spray365` then `pip3 install -r requirements.txt -U` — no PyPI package; the repo is archived but still clonable |
| Target domain | Required for every `generate` mode |
| Username list | Required for every `generate` mode |
| Password(s) | Required — single password, file, or `username:password` pairs via `--passwords_in_userfile` |
| Known-good credential (for `audit` mode) | Audit mode is only useful against a credential already confirmed valid — it's a CA-gap-mapping tool, not a discovery tool |
| No built-in IP rotation | Unlike `../TrevorSpray/`, achieving source-IP diversity requires chaining `-x/--proxy` to an external rotating-proxy service — not a capability Spray365 provides natively |
