# Transparency, Consent, and Control (TCC)

TCC is macOS's **privacy gatekeeper** (since **Mojave 10.14**, expanded every release), managed by the **`tccd`** daemon. It mediates app access to protected resources — camera, microphone, screen recording, **Full Disk Access**, **Accessibility**, **Automation**, contacts, calendars, photos, etc. — and records every **allow/deny** decision in SQLite. For DFIR, TCC is a goldmine: it reveals **which app got access to what, who authorized it, and WHEN** — i.e. a spyware/RAT's capabilities and the moment it was approved.

## Contents
- [Quick Triage](#quick-triage)
- [The Two Databases](#the-two-databases)
- [Reading TCC (live vs dead-box)](#reading-tcc-live-vs-dead-box)
- [`access` Table — Key Columns](#access-table--key-columns)
- [Decoding `auth_value` and `auth_reason`](#decoding-auth_value-and-auth_reason)
- [Key Services (`kTCCService…`)](#key-services-ktccservice)
- [Forensic Interpretation](#forensic-interpretation)
- [`tccutil` & Anti-Forensics](#tccutil--anti-forensics)
- [Unified Log Corroboration](#unified-log-corroboration)
- [Red Flags](#red-flags)

---

## Quick Triage

```bash
SYS="/Library/Application Support/com.apple.TCC/TCC.db"

USR="$HOME/Library/Application Support/com.apple.TCC/TCC.db"   # iterate /Users/*/... for all users on a dead-box

# --- Schema first (columns vary) ---
sqlite3 "$SYS" "PRAGMA table_info(access);"

# --- FULL DISK ACCESS holders (system DB) — highest-value grant ---
sqlite3 "$SYS" "SELECT client, auth_value, datetime(last_modified,'unixepoch') \
  FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;"

# --- Dump everything (both DBs) ---
sqlite3 "$SYS" "SELECT * FROM access;"

sqlite3 "$USR" "SELECT * FROM access;"

# --- List apps + service + status (INCLUDING denials/not-determined) ---
sqlite3 "$USR" "SELECT client, service, auth_value, datetime(last_modified,'unixepoch') FROM access;"

# --- All ALLOWED grants, newest first (user DB) ---
sqlite3 "$USR" "SELECT service, client, auth_reason, datetime(last_modified,'unixepoch') AS when \
  FROM access WHERE auth_value=2 ORDER BY last_modified DESC;"

# --- Per-service (the standard checks): Microphone / Camera / Screen Recording ---
sqlite3 "$USR" "SELECT client, auth_value, datetime(last_modified,'unixepoch') FROM access WHERE service='kTCCServiceMicrophone'   AND auth_value=2;"

sqlite3 "$USR" "SELECT client, auth_value, datetime(last_modified,'unixepoch') FROM access WHERE service='kTCCServiceCamera'       AND auth_value=2;"

sqlite3 "$USR" "SELECT client, auth_value, datetime(last_modified,'unixepoch') FROM access WHERE service='kTCCServiceScreenCapture' AND auth_value=2;"

# (swap in kTCCServiceAccessibility, kTCCServiceListenEvent, kTCCServiceAppleEvents, etc. — see §4)

# --- High-risk surveillance/keylogging capabilities granted (all at once) ---
sqlite3 "$USR" "SELECT service, client, datetime(last_modified,'unixepoch') FROM access \
  WHERE auth_value=2 AND service IN \
  ('kTCCServiceMicrophone','kTCCServiceCamera','kTCCServiceScreenCapture', \
   'kTCCServiceAccessibility','kTCCServiceListenEvent','kTCCServicePostEvent','kTCCServiceAppleEvents');"

# --- Suspicious CLIENTS: granted by absolute path (unbundled binaries) ---
sqlite3 "$USR" "SELECT service, client, datetime(last_modified,'unixepoch') \
  FROM access WHERE client_type=1 AND auth_value=2;"

# --- Automation: who controls whom ---
sqlite3 "$USR" "SELECT client, indirect_object_identifier, datetime(last_modified,'unixepoch') \
  FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"

# --- MDM-forced permissions ---
plutil -p "/Library/Application Support/com.apple.TCC/MDMOverrides.plist" 2>/dev/null

# --- Sweep every user's TCC.db on a mounted image ---
for db in /Users/*/Library/Application\ Support/com.apple.TCC/TCC.db; do
  echo "== $db =="; sqlite3 "$db" "SELECT service,client,auth_value,datetime(last_modified,'unixepoch') FROM access WHERE auth_value=2;"

done
```

---

## The Two Databases

| Scope | Path | Holds |
|---|---|---|
| 🔴 **System** (machine-wide, root) | `/Library/Application Support/com.apple.TCC/TCC.db` | **Full Disk Access** (`kTCCServiceSystemPolicyAllFiles`) and other system-wide policy grants |
| 🔴 **User** (per-user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Camera, mic, screen recording, Accessibility, Automation, contacts, calendar, photos… for that user |
| MDM overrides | `/Library/Application Support/com.apple.TCC/MDMOverrides.plist` | Permissions force-granted by an MDM profile (not user-driven) |

> Both DBs are **SIP-protected** (`restricted`) and owned by `tccd`. **Live:** your terminal/tool needs **Full Disk Access** to read them. **Dead-box:** read the file directly off the mounted image.

---

## Reading TCC (live vs dead-box)

```bash
# 0) Live: grant Full Disk Access to Terminal/your tool first
#    (System Settings ▸ Privacy & Security ▸ Full Disk Access)

# 1) ALWAYS inspect the schema first — columns vary by macOS version
sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" "PRAGMA table_info(access);"

sqlite3 ~/"Library/Application Support/com.apple.TCC/TCC.db" "PRAGMA table_info(access);"

# 2) Dump everything
sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" "SELECT * FROM access;"        # system

sqlite3 ~/"Library/Application Support/com.apple.TCC/TCC.db" "SELECT * FROM access;"        # user
```

> The lesson's tip is right: **run `PRAGMA table_info(access)` first** — older builds use a `timestamp`/`allowed` column; newer use `last_modified`/`auth_value`. Adjust your `SELECT` to the columns that actually exist.

---

## `access` Table — Key Columns

| Column | Meaning | DFIR use |
|---|---|---|
| 🔴 `service` | The protected resource (`kTCCService…`, §4) | What capability was granted |
| 🔴 `client` | App **bundle ID** or **absolute path** | Which app; a path in `/tmp`/odd location = suspicious |
| `client_type` | `0` = bundle ID, `1` = absolute path | Path-type clients (unbundled binaries) are notable |
| 🔴 `auth_value` | Allowed / denied / etc. (§3) | `2` = **Allowed** |
| `auth_reason` | *Why* it was set (§3) | User consent vs MDM vs system policy |
| `last_modified` | **Unix epoch** of last change | 🔴 **When** access was granted/changed — timeline anchor |
| `csreq` | Binary **code-signing requirement** for the client | Validates the app's identity; mismatch = impersonation |
| `indirect_object_identifier` | For **Automation**: the *target* app being controlled | App-to-app control (AppleEvents) mapping |
| `pid` / `boot_uuid` | Process/boot context | Session correlation |
| `allowed` *(older schema)* | `1`=allow, `0`=deny | Pre-Big Sur equivalent of `auth_value` |

```bash
# Decode the epoch inline
sqlite3 "$DB" "SELECT service, client, auth_value, datetime(last_modified,'unixepoch') FROM access ORDER BY last_modified DESC;"
```

---

## Decoding `auth_value` and `auth_reason`

**`auth_value`** — ⚠️ values **vary by macOS version**; confirm against your data (the lesson stresses this). **The one constant: `2` = Allowed.**

| Value | Modern (Big Sur 11+) | Note |
|---|---|---|
| `0` | Denied *(some docs/older: "Not Determined")* | 0/1 meaning differs by version |
| `1` | Unknown *(some: "Denied")* | verify in-data |
| 🔴 `2` | **Allowed** | reliable across versions |
| `3` | Limited (e.g. selected Photos) | partial grant |

> Pre-Big Sur schema uses an **`allowed`** column instead: `1` = allowed, `0` = denied (note the *flipped* sense of "1" vs modern).

**`auth_reason`** — how the decision was made (helps separate user action from policy):

| Value | Reason | Value | Reason |
|---|---|---|---|
| 2 | User Consent (prompt) | 7 | Override Policy |
| 3 | User Set (Settings) | 8 | Missing usage-string |
| 4 | System Set | 9 | Prompt Timeout |
| 5 | Service Policy | 11 | Entitled |
| 6 | **MDM Policy** | 12 | App-Type Policy |

> 🔴 `auth_reason = 2/3` = a human clicked "Allow"; `6` = pushed by MDM. A sensitive grant with reason `2` ties consent to a user session/time.

---

## Key Services (`kTCCService…`)

The high-risk ones for spyware/RAT capability are flagged.

| Service | Capability | Risk |
|---|---|---|
| 🔴 `kTCCServiceSystemPolicyAllFiles` | **Full Disk Access** — read all user data, other apps' data, TCC.db itself | Total data exposure |
| 🔴 `kTCCServiceAccessibility` | Control the computer — synthesize clicks/keys, read UI | Keylogging, automation, TCC-prompt clicking |
| 🔴 `kTCCServiceScreenCapture` | **Screen Recording** | Visual surveillance |
| 🔴 `kTCCServicePostEvent` / `kTCCServiceListenEvent` | Send / **monitor keystrokes** (Input Monitoring) | Keylogging |
| 🔴 `kTCCServiceAppleEvents` | **Automation** — control other apps (`indirect_object`) | Pivot into Mail/Finder/browsers |
| 🔴 `kTCCServiceMicrophone` / `kTCCServiceCamera` | Mic / camera | Audio/video surveillance |
| `kTCCServiceSystemPolicyDesktopFolder` / `…DocumentsFolder` / `…DownloadsFolder` | Protected user folders | Targeted data access |
| `kTCCServiceSystemPolicyRemovableVolumes` / `…NetworkVolumes` | External / network volumes | Data on removable/network media |
| `kTCCServiceAddressBook` / `kTCCServiceCalendar` / `kTCCServiceReminders` | Contacts / calendar / reminders | PII collection |
| `kTCCServicePhotos` / `kTCCServiceMediaLibrary` | Photos / media | PII collection |
| `kTCCServiceLocation` | Location | Tracking |
| `kTCCServiceDeveloperTool` | Run un-notarized code / debug | Defense bypass |

---

## Forensic Interpretation

| Observation | Meaning |
|---|---|
| Non-Apple app with FDA + Accessibility + Screen Recording + Mic/Camera | 🔴 Full **spyware/RAT** capability profile |
| `client` is an **absolute path** (not a bundle ID) in `/tmp`, `/Users/Shared`, `/private/var` | Unbundled implant binary granted access |
| `last_modified` clusters around a known intrusion time | Malware authorized at that moment — timeline anchor |
| `auth_reason = 6` (MDM) for a suspicious grant | Pushed silently via a (rogue?) profile — check `MDMOverrides.plist` |
| `csreq` doesn't match the on-disk binary's signature | App was swapped/impersonated after the grant |
| `kTCCServiceAppleEvents` with `indirect_object` = Finder/Mail/Browser | App-to-app control / data pivot |

---

## `tccutil` & Anti-Forensics

| Action | Command / artifact |
|---|---|
| Reset (clear) decisions for a service | `tccutil reset Camera [bundleid]` |
| Reset everything | `tccutil reset All` |
| 🔴 Direct DB write (self-grant) | Possible only with **FDA** or **SIP disabled** — attacker adds an `Allowed` row to bypass prompts |
| 🔴 Pre-approved DB swap | Dropping a prepared `TCC.db` to inherit grants |

> 🔴 A suddenly **empty** or recently **reset** TCC.db, or grants whose `last_modified` predates the app's install, suggests tampering. TCC-bypass CVEs historically let apps write TCC.db directly — corroborate grants with the **unified log** (§7), which records the original prompts/decisions independently.

---

## Unified Log Corroboration

`tccd` logs every request/decision — useful even if the DB was reset.

```bash
log show --predicate 'subsystem == "com.apple.TCC"' --info --last 7d

log show --predicate 'process == "tccd"' --info --last 7d

# Grants/denials mentioning a service or client
log show --predicate 'process == "tccd" AND eventMessage CONTAINS[c] "kTCCServiceScreenCapture"' --info --last 30d
```

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Non-Apple binary with **Full Disk Access** | Total data exposure / exfil capability |
| Same client holding Accessibility + Screen Recording + Mic/Camera + Input Monitoring | Spyware/RAT profile |
| `client` granted by **absolute path** in `/tmp`, `/Users/Shared`, `/private/var` | Unbundled implant |
| Grant `last_modified` aligned to intrusion window | Malware authorization timeline |
| `auth_reason = 6` (MDM) for unexpected grants + entries in `MDMOverrides.plist` | Silent policy-pushed access (rogue profile) |
| `csreq` mismatch vs the on-disk binary | App impersonation after grant |
| TCC.db recently **reset/empty**, or `tccutil reset` in history/logs | Anti-forensic clearing |
| Automation (`kTCCServiceAppleEvents`) targeting Mail/Finder/browsers | App-to-app data pivot |
