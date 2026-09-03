# LaZagne — Hands-On Use Cases

## Contents
- [Full Sweep, Written to Disk](#full-sweep-written-to-disk)
- [Category-Scoped Browser Credential Pull](#category-scoped-browser-credential-pull)
- [Single-Software Targeted Pull](#single-software-targeted-pull)
- [SAM/NTLM Hash Extraction](#samntlm-hash-extraction)
- [LSA Secrets Extraction](#lsa-secrets-extraction)
- [Domain Cached-Credential (MSCache/DCC2) Extraction](#domain-cached-credential-mscachedcc2-extraction)
- [DPAPI Hash Extraction for Offline Cracking](#dpapi-hash-extraction-for-offline-cracking)
- [Unlocking DPAPI Material With a Known Password](#unlocking-dpapi-material-with-a-known-password)
- [WiFi Pre-Shared Key Recovery](#wifi-pre-shared-key-recovery)
- [Windows Credential Manager Dump](#windows-credential-manager-dump)
- [Windows Vault and Credentials-File DPAPI Blobs](#windows-vault-and-credentials-file-dpapi-blobs)
- [Autologon Registry Credential Check](#autologon-registry-credential-check)
- [Sysadmin Tooling Sweep — Lateral-Movement Credential Harvesting](#sysadmin-tooling-sweep--lateral-movement-credential-harvesting)
- [Git for Windows Credential Harvesting](#git-for-windows-credential-harvesting)
- [Multi-User Harvest on a Shared Host](#multi-user-harvest-on-a-shared-host)
- [Non-Admin, Current-Session-Only Run](#non-admin-current-session-only-run)
- [JSON Output for Downstream Tooling](#json-output-for-downstream-tooling)
- [Chained Workflow — Recovered Credentials Into Lateral Movement or Cracking](#chained-workflow--recovered-credentials-into-lateral-movement-or-cracking)

---

## Full Sweep, Written to Disk

The default "run everything" invocation — every category, both output formats:

```
laZagne.exe all -oA
```

Produces `credentials_<DDMMYYYY_HHMMSS>.txt` and `.json` in the current directory. This is the shape seen in the large majority of real-world incident reports — an operator drops the standalone `.exe`, runs `all`, and exfiltrates the resulting file rather than screen-scraping console output.

**MITRE ATT&CK:** T1555 (Credentials from Password Stores), T1003.002/.004/.005 (OS Credential Dumping: SAM / LSA Secrets / Cached Domain Credentials — only actually executed if run elevated), T1005 (Data from Local System).

## Category-Scoped Browser Credential Pull

```
laZagne.exe browsers -oN
```

Runs every registered browser module (30+ Chromium/Gecko variants) without needing admin rights — browser credential stores are almost always decryptable inside the operator's own current session via `CryptUnprotectData`.

**MITRE ATT&CK:** T1555.003 (Credentials from Web Browsers).

## Single-Software Targeted Pull

Narrow a category to one specific application using its per-module flag — useful for a quiet, minimal-footprint pull when the operator already knows what's installed:

```
laZagne.exe browsers -firefox
laZagne.exe chats -skype
laZagne.exe mails -outlook
```

**MITRE ATT&CK:** T1555.003 (browsers), T1552.001 (Credentials In Files — most chat/mail clients store config in a flat file or SQLite DB).

## SAM/NTLM Hash Extraction

```
laZagne.exe windows -hashdump
```

Requires local admin. Triggers `save_hives()` for all three hives even though only SAM/SYSTEM are strictly needed by `dump_file_hashes()` — `save_hives()` saves every hive up front regardless of which specific `windows` module was requested, so this single-module invocation still produces all three `reg.exe save` child processes described in `01`. Output is standard SAM RID/NT-hash pairs, directly usable with `hashcat -m 1000` or pass-the-hash tooling.

**MITRE ATT&CK:** T1003.002 (OS Credential Dumping: Security Account Manager).

## LSA Secrets Extraction

```
laZagne.exe windows -lsa_secrets
```

Requires local admin (`system_module=True`). Recovers service-account passwords, cached `DPAPI_SYSTEM` key material (which the `wifi` module's SYSTEM-DPAPI path depends on), and — on systems where Autologon is both enabled and running a build old enough that it wasn't forced into LSA-Secrets storage — the Autologon password itself, per an explicit comment in `autologon.py`: *"Password are stored in cleartext on old system (< 2008 R2 and < Win7). If enabled on recent system, the password should be visible on the lsa secrets dump."*

**MITRE ATT&CK:** T1003.004 (OS Credential Dumping: LSA Secrets).

## Domain Cached-Credential (MSCache/DCC2) Extraction

```
laZagne.exe windows -mscache
```

Note the flag is `-mscache`, not `-cachedump`, despite the source file being named `cachedump.py` — the module registers itself with `ModuleInfo.__init__(self, 'mscache', 'windows', system_module=True)`. Requires admin; useful on a domain-joined laptop/workstation where a domain user has logged in without connectivity to a DC recently enough to have a cached logon verifier.

**MITRE ATT&CK:** T1003.005 (OS Credential Dumping: Cached Domain Credentials).

## DPAPI Hash Extraction for Offline Cracking

When LaZagne can't decrypt a DPAPI masterkey directly (no live session as that user, no known password), the DPAPI module code path can still produce a crackable hash string in hashcat/John's native `$DPAPImk$...` format rather than nothing. There's no dedicated CLI flag that forces hash-only output — this happens automatically as a side effect of an otherwise-failed decryption attempt against a discovered masterkey file, surfaced in verbose output:

```
laZagne.exe windows -oA -vv
```

Feed any `$DPAPImk$1*...` or `$DPAPImk$2*...` strings recovered this way into:

```
hashcat -m 15300 dpapi_hashes.txt wordlist.txt   # v1, local/domain context
hashcat -m 15900 dpapi_hashes.txt wordlist.txt   # v2, AD domain context
```

**MITRE ATT&CK:** T1555 (Credentials from Password Stores) — this use case is the recon/collection half; the actual cracking is out of scope for this tool (see this repo's `Hashcat/`).

## Unlocking DPAPI Material With a Known Password

If the operator already has a Windows user's plaintext password from another source (password spray, phishing, a prior hashcat crack), supply it directly to unlock that user's DPAPI-protected material without needing a live session or admin-driven impersonation:

```
laZagne.exe windows -password 'Summer2026!' -vaultfiles -credfiles
```

**MITRE ATT&CK:** T1555.004 (Windows Credential Manager), T1552.001 (Credentials In Files).

## WiFi Pre-Shared Key Recovery

```
laZagne.exe wifi -oN
```

As admin, this prefers the SYSTEM-DPAPI path (silent, no subprocess). As a non-admin user, it falls back to shelling out `netsh.exe wlan show profile "<SSID>" key=clear` per saved profile and parsing the "key content" line from its stdout — verified directly in `wifi.py`. Both paths recover the same pre-shared key; only the evidence trail differs (see `03`/`05`).

**MITRE ATT&CK:** T1552.001 (Credentials In Files — the WLAN profile XML itself), T1016 (System Network Configuration Discovery, for the profile enumeration step).

## Windows Credential Manager Dump

```
laZagne.exe windows -credman
```

No admin required (`only_from_current_user=True`) — calls `CredEnumerate`/`CredFree` directly against the current session's Credential Manager store. Recovers `CRED_TYPE_GENERIC` and `CRED_TYPE_DOMAIN_VISIBLE_PASSWORD` entries under 200 bytes.

**MITRE ATT&CK:** T1555.004 (Windows Credential Manager).

## Windows Vault and Credentials-File DPAPI Blobs

```
laZagne.exe windows -vault -credfiles -vaultfiles
```

`-vault` reads the Windows Vault via its native enumeration API; `-credfiles` and `-vaultfiles` decrypt the raw DPAPI-protected files under `%APPDATA%\Microsoft\Credentials\` and `%LOCALAPPDATA%\Microsoft\Vault\` directly. All three depend on `constant.user_dpapi` already being unlocked for the target user (current session, prior `-password`, or a Phase 3 impersonation having succeeded) — none will return results on their own if that precondition isn't met.

**MITRE ATT&CK:** T1555.004 (Windows Credential Manager), T1552.001 (Credentials In Files).

## Autologon Registry Credential Check

```
laZagne.exe windows -autologon
```

Requires admin (registry read against `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`). Recovers `DefaultUserName`/`DefaultPassword`/`AltDefaultPassword` values when `AutoAdminLogon=1` — a low-effort, high-value check that's often skipped because it feels "too easy" to be worth running deliberately.

**MITRE ATT&CK:** T1552.002 (Credentials in Registry).

## Sysadmin Tooling Sweep — Lateral-Movement Credential Harvesting

```
laZagne.exe sysadmin -oA
```

Covers a genuinely lateral-movement-relevant set of clients in one pass: WinSCP, PuTTY Connection Manager, mRemoteNG, RDPManager, VNC, FileZilla (client and server), OpenSSH for Windows, OpenVPN, CyberDuck, CoreFTP, Apache Directory Studio, Rclone's own `rclone.conf` (see this repo's `Rclone/` for what that credential subsequently unlocks), unattended-install answer files, and WSL. This is frequently the highest-value single category on an administrator's or sysadmin's workstation specifically — it's the credential set most likely to already point at other hosts.

**MITRE ATT&CK:** T1552.001 (Credentials In Files), T1552.004 (Private Keys — SSH/PuTTY key material where stored unencrypted or with a recoverable passphrase-protection path).

## Git for Windows Credential Harvesting

```
laZagne.exe git -oN
```

Recovers credentials stored by Git for Windows's own credential storage (plaintext `.git-credentials` or the Windows Credential Manager–backed helper, depending on configuration) — a common source of a personal or service-account token/PAT with source-repository access.

**MITRE ATT&CK:** T1552.001 (Credentials In Files), T1552.004 (Private Keys, where an SSH deploy key rather than a token is in play).

## Multi-User Harvest on a Shared Host

The single most consequential use case for how much this tool recovers per run — no special flag needed, this is simply what an elevated `all` run does automatically per `01`'s Phase 3/Phase 4 breakdown:

```
laZagne.exe all -oA
```

On a shared workstation, jump box, or Terminal Server host with several distinct users' processes running or profile directories present, this single elevated invocation: (1) runs the admin-only `windows` modules against the machine itself, (2) enumerates every running process's owning SID and impersonates each distinct user found to re-run the full per-user module set as them, then (3) walks every remaining `C:\Users\*` profile directory that wasn't already covered by impersonation, decrypting any DPAPI material for those users where a password/hash was separately recovered. One run, one output file, potentially every user who has ever used the box.

**MITRE ATT&CK:** T1134.001 (Access Token Manipulation: Token Impersonation/Theft), T1555, T1003.002/.004/.005.

## Non-Admin, Current-Session-Only Run

```
laZagne.exe all -oA
```

(Same command — the privilege check is internal, not a flag.) Run from a non-elevated foothold, this silently skips every `system_module=True` module and the entire Phase 3/4 impersonation-and-filesystem-walk logic, returning only what the operator's own current session can already decrypt: browsers, chat clients, mail clients, Credential Manager, and any DPAPI blob the operator's own live session can unlock. A legitimate, common early-foothold use case — worth calling out explicitly because the *identical command line* produces a dramatically different evidence footprint depending on privilege level (see `05`'s Hunting Priority table).

**MITRE ATT&CK:** T1555.003, T1555.004.

## JSON Output for Downstream Tooling

```
laZagne.exe all -oJ -output C:\Users\Public\out
```

`-oJ` structures output as `[{"User": "...", "Passwords": [["category", [["key: value"], ...]]]}, ...]` — parseable directly by a follow-on script or ingestion into a C2's own loot store, rather than the human-readable `-oN` text format.

**MITRE ATT&CK:** T1555, T1005.

## Chained Workflow — Recovered Credentials Into Lateral Movement or Cracking

A representative end-to-end chain, tying LaZagne's output into other tools already covered in this repo:

```
# 1. Harvest broadly from an elevated foothold
laZagne.exe all -oA

# 2a. A recovered RDP/VNC/WinSCP credential from the sysadmin category
#     feeds directly into lateral movement — e.g. PsExec/psexec.py against
#     the host that credential was scoped to (see ../PsExec/ and
#     ../Impacket/psexec/)

# 2b. A recovered $DPAPImk$ hash with no matching plaintext feeds hashcat
hashcat -m 15300 dpapi_hashes.txt rockyou.txt

# 2c. A cracked/recovered Windows password from step 2b can be fed straight
#     back into a second LaZagne pass to unlock that same user's remaining
#     DPAPI-protected material without needing admin-driven impersonation
laZagne.exe windows -password '<cracked_password>' -vaultfiles -credfiles
```

**MITRE ATT&CK:** T1555, T1021 (Remote Services — for whichever lateral-movement tool consumes the recovered credential; see the destination tool's own page for its specific sub-technique).
