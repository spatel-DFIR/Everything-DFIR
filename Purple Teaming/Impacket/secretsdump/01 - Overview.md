# Impacket — secretsdump.py — Overview

> 🔴 **Red Flag Principle:** `secretsdump.py` isn't one technique, it's three, and each leaves a fundamentally different footprint. The two that touch a network at all: (1) a **`IDL_DRSGetNCChanges`** RPC call against a Domain Controller's DRSUAPI endpoint from a source that **isn't one of the domain's actual DC computer accounts** — the exact same MS-DRSR signal covered in depth in `Mimikatz/lsadump (DCSync)/01 - Overview.md`, since `-just-dc` mode **is** DCSync, just from a different client; and (2) an **existing `RemoteRegistry` service being started (or re-enabled) on a host that isn't a server that normally runs it**, immediately followed by `winreg` RPC calls that **save the `SAM`/`SECURITY` hive to a randomly-named temp file** under `%SystemRoot%\Temp\` before reading it back over SMB. The third mode — offline hive-file parsing — touches the target network **not at all**, which is itself the detection-relevant fact for that path.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`secretsdump.py` lives in the same [`fortra/impacket`](https://github.com/fortra/impacket) `examples/` folder as `psexec.py`/`wmiexec.py`, under the same project lineage — originally CORE Security (Core Impact team), acquired by HelpSystems and rebranded **Fortra**. Its source header credits the same author line as the rest of the SMB-exec family: **Alberto Solino (`beto`, `@agsolino`)**, with the DRSUAPI/NTDS extraction path specifically crediting additional contributors (`Dirk-jan Mollema` is credited elsewhere in the codebase for `dementor.py`-style DRSUAPI research feeding into this tool's NTDS support; the file's own header lists `Benjamin Delpy` and others as reference for the crypto routines it reimplements — verify current header text against a live checkout, since attribution comments have been extended over the years as more extraction paths were added).

Where `psexec.py`/`wmiexec.py` are about **code execution**, `secretsdump.py` is Impacket's **credential-extraction Swiss Army knife** — its own CLI description states its purpose plainly: *"Performs various techniques to dump secrets from the remote machine without executing any agent there."* That last clause is the important one: unlike `psexec.py`, this tool's default remote paths **drop no agent/service binary of its own** on the target. It reuses **existing, already-installed Windows components** (the Remote Registry service, the DRSUAPI replication interface) rather than pushing new code — which is also exactly why its evidence trail looks nothing like `psexec.py`'s (see `04 - Target Evidence.md`).

## How It Works

`secretsdump.py` implements **three structurally different extraction paths**, selected by which arguments are supplied. Get the mode right before reading evidence sections — a `-just-dc` run and a plain no-flags run against the same host leave almost no overlapping artifacts.

### Path 1 — Remote SAM + LSA Secrets + Cached Domain Credentials, via Remote Registry

This is the **default** behavior whenever a live network target is given without `-just-dc`/`-just-dc-ntlm` and without `-use-vss`/`-use-remoteSSWMI`. It reimplements the classic `pwdump`/`fgdump`-era technique — decrypt the local SAM database, the LSA Secrets store, and cached domain-logon hashes (MSCache/DCC2) using the machine's boot key — but does it **entirely over SMB/RPC**, with no local agent.

```
Attacker (secretsdump.py)                              Target (10.10.10.5)
──────────────────────────                              ────────────────────
1. SMB Session Setup (TCP 445) ────────────────────────▶ Authenticate (NTLM or Kerberos)

2. DCE/RPC bind to \PIPE\svcctl (MS-SCMR) ─────────────▶ OpenSCManagerW / OpenServiceW("RemoteRegistry")
     └─ Query service status:                              If stopped: hRStartServiceW()
          if disabled (Start=4), first re-enable it         If disabled: hRChangeServiceConfigW(Start=3)
          to demand-start (3), THEN start it                  then start it — service state is later restored

3. DCE/RPC bind to \PIPE\winreg (MS-RRP) ──────────────▶ RemoteRegistry service now accepting winreg RPC

4. hOpenLocalMachine() → hBaseRegOpenKey() on
   SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data} ▶ Reads each subkey's Class-name field (not its data)
     → concatenate + fixed 16-byte permutation ──────────▶ derives the local boot key ("syskey")
   (identical algorithm to mimikatz's lsadump::sam —
    see Mimikatz/sekurlsa.../lsadump (DCSync)/01 for the
    shared boot-key math, not re-derived here)

5. hBaseRegCreateKey(SAM) → hBaseRegSaveKey() ─────────▶ SAM hive written to a NEW file:
   hBaseRegCreateKey(SECURITY) → hBaseRegSaveKey()          %SystemRoot%\Temp\<8-random-letters>.tmp
   (each hive gets its own random 8-letter temp file)        (one per hive requested)

6. SMB read of \\10.10.10.5\ADMIN$\Temp\<random>.tmp ──▶ Attacker downloads the saved hive copy

7. Decrypt locally using the boot key: LM/NTLM hashes
   from SAM, service-account/LSA secrets and MSCache2
   (DCC2) cached-logon hashes from SECURITY — entirely
   on the attacker's own machine

8. Service state restored (stopped/disabled if it was
   originally that way) — RemoteRegistry is NOT left
   running if it wasn't already; the saved-hive temp
   files are deleted from the target
```

Key mechanics, verified directly against `impacket/examples/secretsdump.py`'s `RemoteOperations` class:

- The **RemoteRegistry service is never newly created** — `secretsdump.py` opens the **existing** `RemoteRegistry` service via SCM (`\PIPE\svcctl`), checks its current status, and starts it only if it was stopped (re-enabling it first if its start type was disabled). This is a materially different footprint from `psexec.py`, which always creates a brand-new service — there is **no Event ID 7045** for this path, because nothing new is installed.
- Boot-key derivation reads four registry values under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\` — subkeys named **`JD`, `Skew1`, `GBG`, `Data`** — pulling each one's key **Class** field (not its data) and reassembling them through a fixed permutation table. This is byte-for-byte the same technique Mimikatz's `lsadump::sam`/`secrets`/`cache` uses locally (see `Mimikatz/lsadump (DCSync)/01 - Overview.md`'s "sam/secrets/cache" section for the shared crypto detail) — the difference is **how** the registry gets read, not the math once it's read.
- The actual hive extraction uses **`BaseRegSaveKey`** (MS-RRP) to write a **complete copy of the live `SAM`/`SECURITY` hive** to a new file at a path relative to the RemoteRegistry service process's working directory — resolving to **`%SystemRoot%\Temp\<8-random-ASCII-letters>.tmp`** — then reads that file back over a plain SMB file read against `ADMIN$`. This is a genuine, if short-lived, **filesystem artifact on the target** distinct from anything psexec/wmiexec leave (see `04 - Target Evidence.md`).
- Cached domain credentials decrypt to the format **`domain/username:$DCC2$<iterationcount>#username#<hash>`** (MSCache2/DCC2) — this is the exact format the tool's source produces, and it's the same hash format `hashcat`/`john` expect for mode 2100.
- `-skip-sam`/`-skip-security` selectively disable the SAM or SECURITY leg of this path without affecting the other, or NTDS extraction if also requested in the same run.

### Path 2 — Full NTDS.dit Extraction via DRSUAPI (the DCSync-equivalent path)

Triggered by **`-just-dc`**, **`-just-dc-ntlm`**, or **`-just-dc-user <username>`** (or by default against a DC target when no mode flag narrows the run) — and, by far, this tool's headline capability. `secretsdump.py`'s DRSUAPI mode speaks **the exact same MS-DRSR protocol** as Mimikatz's `lsadump::dcsync`: it binds to the target's `drsuapi` RPC interface and calls **`IDL_DRSGetNCChanges`**, asking the Domain Controller to replicate account objects to it as if it were a peer DC. **The protocol mechanics, the authorization model (`DS-Replication-Get-Changes`/`DS-Replication-Get-Changes-All` extended rights), the target-side Event 4662 signal, and the "any tool that speaks MS-DRSR looks identical on the wire" caveat are all covered in depth in `Mimikatz/lsadump (DCSync)/01 - Overview.md` and `04 - Target Evidence.md` — cross-linked here rather than re-derived.** What follows is what's specific to `secretsdump.py`'s own implementation:

- **`-just-dc`** pulls full NTDS.dit data (NTLM hashes **and** Kerberos keys) for every account. **`-just-dc-ntlm`** pulls NTLM hashes only — meaningfully faster on a large domain since it skips requesting/decoding the Kerberos-key-bearing `supplementalCredentials` blob. **`-just-dc-user <username>`** narrows to one account (implies `-just-dc`), and **`-ldapfilter <filter>`** narrows to accounts matching an LDAP filter (also implies `-just-dc`) — both are the single-object-pull equivalent of Mimikatz's `/user:`/`/guid:`, versus a full unfiltered run being the equivalent of `/all`.
- **`-history`** additionally dumps password history for both the SAM and NTDS legs, and LSA secrets' `OldVal`.
- **`-pwd-last-set`** annotates each account with its `pwdLastSet` attribute in the console output (not written to `-outputfile` data). **`-user-status`** annotates whether the account is disabled.
- **`-skip-user`** excludes one account, a comma-separated list, or a text file of account names from the pull — the inverse of `-just-dc-user`.
- **`-trust-keys`** additionally dumps trusted-domain-object (TDO) secrets and derives the inter-realm Kerberos AES/RC4 keys for each trust direction — the DRSUAPI-path equivalent of Mimikatz's `lsadump::trust`. **`-just-trust-keys`** does *only* this, skipping every regular account secret — useful for a narrowly-scoped cross-trust attack without touching the rest of the domain's credential material.
- **`-resumefile <path>`** — **DRSUAPI-only.** A full-domain NTDS pull against a large AD can take a long time and is vulnerable to a dropped connection; this flag checkpoints the replication cursor (USN watermark) to a local file so a re-run picks up where it left off rather than restarting the entire replication cycle. This has no equivalent in Mimikatz's `dcsync`.
- **`-use-vss`** — **verified still present in current source.** Switches NTDS acquisition away from DRSUAPI entirely, to the **older, noisier, pre-DCSync method**: remotely invoking `vssadmin` (via `-exec-method`, below) to create or reuse a Volume Shadow Copy of the drive holding `ntds.dit`, then copying the file out of the shadow snapshot to `%SYSTEMROOT%\Temp\<8-random>.tmp` and reading it back over SMB, exactly like Path 1's hive retrieval. This is the method every NTDS-dumping tool used **before** DCSync existed, and it requires **remote code execution rights** on the DC (a shell, effectively) rather than just replication permissions — `-exec-method {smbexec,wmiexec,mmcexec}` (default `smbexec`) selects which of Impacket's own exec techniques drives the `vssadmin` commands. This is meaningfully more invasive and detectable than DRSUAPI mode (see `04 - Target Evidence.md`), and exists mainly as a fallback when DRSUAPI access is blocked but local admin/code-exec on the DC is available.
- **`-use-remoteSSWMI`** — a variant of the VSS approach that creates the shadow copy via **DCOM/WMI's `Win32_ShadowCopy.Create()`** method instead of spawning `vssadmin.exe` at all, then downloads `SAM`/`SYSTEM`/`SECURITY` from the snapshot and parses them **locally** rather than live over winreg. `-use-remoteSSWMI-NTDS` (only valid combined with `-use-remoteSSWMI`) additionally pulls `ntds.dit` the same way when the target is a DC. `-remoteSSWMI-remote-volume` (default `C:\`) and `-remoteSSWMI-local-path` (default `.`) control where the snapshot is taken and where files land locally. This path trades a `vssadmin.exe` process launch for WMI method-invocation traffic — a different, not necessarily quieter, footprint.
- **`-use-keylist`** — a narrower, RODC-focused alternative to both DRSUAPI and VSS: the **Kerb-Key-List** method, which derives account keys via a crafted Kerberos TGS request against a **Read-Only Domain Controller** rather than a full replication call, using `-rodcNo`/`-rodcKey` (the RODC's krbtgt account number and AES key). This is a specialized technique for RODC-scoped credential recovery, not a general-purpose DRSUAPI replacement.

### Path 3 — Offline / Local Mode (no network at all)

Set the `target` positional to the literal string **`LOCAL`** with no username, or simply pass one or more of **`-sam`**, **`-security`**, **`-system`**, **`-ntds`** pointing at already-exfiltrated files, and `secretsdump.py` never opens a network connection. Internally this routes through a dedicated `LocalOperations` class that parses the raw `SYSTEM` hive file **offline** to derive the boot key — the identical `JD`/`Skew1`/`GBG`/`Data` class-value/permutation-table algorithm as Path 1, just reading a file instead of RPC-querying a live registry — then decrypts whichever of `-sam`/`-security`/`-ntds` were supplied using that key.

- **`-system`** is **required** for every offline decryption (SAM, SECURITY, and NTDS all need the boot key derived from it) — it must be a real binary `REGF`-format hive file; a text `.reg` export lacks the metadata needed to compute the boot key. **`-bootkey`** lets an operator supply an already-known boot key directly, skipping SYSTEM-hive parsing entirely.
- **`-sam`**, **`-security`**, **`-ntds`** each point at a standalone hive/database file copy — any subset can be supplied depending on what was exfiltrated.
- **This mode generates zero target-side network evidence of its own.** The `secretsdump.py` invocation itself only ever touches the local filesystem of the machine it's run on — see `04 - Target Evidence.md` for why the real evidence trail for this path lives entirely in **how** those hive/`ntds.dit` files were originally copied off the target (a Volume Shadow Copy, a backup, `ntdsutil ifm`, a stolen disk image), which is a **different tool's** artifact story, not this one's.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Transport | SMB (TCP 445) for Paths 1/2's registry and file-read legs; RPC endpoint mapper (TCP 135) → dynamic high port for DRSUAPI (Path 2 default) |
| Authentication | NTLM (password or pass-the-hash) or Kerberos (ticket, AES key, keytab) |
| Remote registry access | MS-RRP (Windows Remote Registry Protocol) over `\PIPE\winreg` — `BaseRegOpenKey`/`BaseRegSaveKey`/`BaseRegQueryInfoKey` |
| Service control | MS-SCMR (Service Control Manager Remote Protocol) over `\PIPE\svcctl` — used to check/start the **existing** `RemoteRegistry` service (Path 1), and by `-use-vss`'s `smbexec`-style exec method |
| Directory replication | **MS-DRSR** — `drsuapi` RPC interface, `IDL_DRSBind`/`IDL_DRSGetNCChanges` — the DCSync-equivalent core of Path 2's default mode. See `Mimikatz/lsadump (DCSync)/01 - Overview.md` for full protocol depth |
| Volume Shadow Copy (fallback) | `vssadmin.exe` (via a remote exec method) or DCOM/WMI `Win32_ShadowCopy` — Path 2's `-use-vss`/`-use-remoteSSWMI` |
| Kerberos ticket-based (RODC) | Kerb-Key-List method — `-use-keylist` |
| Local file parsing | Raw `REGF` hive-file and ESE-database (`ntds.dit`) parsing — Path 3, no protocol at all |
| Credential material recovered | Local SAM LM/NTLM hashes + history; LSA Secrets; MSCache2/DCC2 cached domain logons; full-domain NTLM hashes + Kerberos keys (AES/RC4) + supplemental credentials from NTDS.dit; trust-key material |

## Command-Line Switches — Quick Reference

Verified against the current argparse block in `examples/secretsdump.py` in [fortra/impacket](https://github.com/fortra/impacket).

**Positional**

| Argument | Meaning |
|---|---|
| `target` | `[[domain/]username[:password]@]<targetName or address>` **or the literal string `LOCAL`** to parse local files instead of touching a network target |

**General / Mode Selection**

| Switch | Plain-English meaning |
|---|---|
| `-system <hive>` | Local `SYSTEM` hive file to parse (binary `REGF` only — a text `.reg` export lacks the metadata to compute the boot key) |
| `-bootkey <hex>` | Supply an already-known boot key directly instead of deriving it from `-system` |
| `-security <hive>` | Local `SECURITY` hive file to parse |
| `-sam <hive>` | Local `SAM` hive file to parse |
| `-ntds <file>` | Local `NTDS.DIT` file to parse |
| `-resumefile <path>` | Resume/checkpoint file for a large NTDS.DIT dump — **DRSUAPI approach only** |
| `-skip-sam` | Don't parse the SAM hive on the remote system |
| `-skip-security` | Don't parse the SECURITY hive on the remote system |
| `-outputfile <base>` | Base filename for saved output — extensions `.sam`/`.secrets`/`.cached`/`.ntds` (+`.ntds.kerberos`/`.ntds.cleartext`) are appended automatically |
| `-use-vss` | Use the older `vssadmin`/NTDSUTIL-style Volume Shadow Copy method for NTDS instead of the default DRSUAPI approach |
| `-rodcNo <int>` | Number of the RODC krbtgt account — **Kerb-Key-List approach only** |
| `-rodcKey <hex>` | AES key of the Read-Only Domain Controller — **Kerb-Key-List approach only** |
| `-use-keylist` | Use the Kerb-Key-List method instead of the default DRSUAPI approach |
| `-exec-method {smbexec,wmiexec,mmcexec}` | Which Impacket remote-exec technique drives the `vssadmin` commands under `-use-vss`. **Default: `smbexec`** |
| `-use-remoteSSWMI` | Remotely create a Shadow Snapshot **via WMI** (`Win32_ShadowCopy`, no `vssadmin.exe` process) and download SAM/SYSTEM/SECURITY from it, then parse locally |
| `-use-remoteSSWMI-NTDS` | Also dump NTDS.DIT when using `-use-remoteSSWMI` (only works combined with it; use against a DC) |
| `-remoteSSWMI-remote-volume` | Remote volume to snapshot. **Default: `C:\`** |
| `-remoteSSWMI-local-path` | Local path to download the snapshotted files to. **Default: `.`** (current directory) |
| `-ts` | Prefix output lines with a timestamp |
| `-debug` | Verbose debug output |

**Display / NTDS Options**

| Switch | Plain-English meaning |
|---|---|
| `-just-dc-user <username>` | Extract NTDS.DIT data for only the named user. **DRSUAPI approach only.** Implies `-just-dc` |
| `-ldapfilter <filter>` | Extract NTDS.DIT data only for accounts matching an LDAP filter. **DRSUAPI approach only.** Implies `-just-dc` |
| `-just-dc` | Extract only NTDS.DIT data (NTLM hashes **and** Kerberos keys) — skips SAM/LSA-secrets/cached-creds entirely |
| `-just-dc-ntlm` | Extract only NTDS.DIT data, **NTLM hashes only** — skips Kerberos-key extraction for speed |
| `-trust-keys` | Also dump trusted-domain-object (TDO) secrets and derive inter-realm Kerberos keys (AES + RC4) per trust direction |
| `-just-trust-keys` | Like `-trust-keys` but dump **only** the trust keys, skipping every regular account secret |
| `-skip-user <user(s)>` | Do **not** extract NTDS.DIT data for the named user — comma-separated list or a text file, one user per line |
| `-pwd-last-set` | Show the `pwdLastSet` attribute for each NTDS.DIT account in console output (not written to `-outputfile` data) |
| `-user-status` | Display whether each account is disabled |
| `-history` | Dump password history (NTDS and SAM hashes) and LSA secrets' `OldVal` |

**Authentication**

| Switch | Plain-English meaning |
|---|---|
| `-hashes LMHASH:NTHASH` | Authenticate via NTLM hash — pass-the-hash |
| `-no-pass` | Don't prompt for a password — pairs with `-k` or `-hashes` |
| `-k` | Kerberos authentication, reading from `KRB5CCNAME` ccache if available |
| `-aesKey <hex>` | Kerberos AES key (128 or 256-bit) authentication |
| `-keytab <path>` | Read Kerberos keys from a keytab file |

**Connection**

| Switch | Plain-English meaning |
|---|---|
| `-dc-ip <ip>` | IP of a Domain Controller — needed for Kerberos if DNS won't resolve one from the target's domain part |
| `-target-ip <ip>` | Force a specific IP for the connection, useful when the target is a NetBIOS name that won't resolve |

## Quick Use-Case List

- Remote SAM dump — local account hashes off a standalone or domain-joined host
- Remote LSA Secrets extraction — service-account/scheduled-task stored credentials
- Remote cached domain credentials (MSCache2/DCC2) — offline-crackable domain-logon hashes
- Full DRSUAPI/DCSync-style NTDS.dit pull (`-just-dc`) — every domain account's NTLM + Kerberos key material in one operation
- NTLM-only fast full-domain pull (`-just-dc-ntlm`) — skips Kerberos-key decoding for speed at scale
- Single-user targeted DRSUAPI pull (`-just-dc-user`) — one high-value account (e.g. `krbtgt`), minimal footprint
- LDAP-filtered targeted pull (`-ldapfilter`) — a defined subset of accounts (e.g. all members of a privileged group already resolved to a filter)
- Trust-key extraction (`-trust-keys`/`-just-trust-keys`) — inter-domain/inter-forest Kerberos key material for cross-trust attacks
- Legacy VSS-based NTDS pull (`-use-vss`) — fallback when replication rights aren't available but code-exec on the DC is
- WMI-based remote shadow-snapshot pull (`-use-remoteSSWMI`) — VSS acquisition without spawning `vssadmin.exe`
- Kerb-Key-List pull against an RODC (`-use-keylist`) — narrow, RODC-scoped credential recovery
- Offline hive/`ntds.dit` parsing (`LOCAL` target / `-sam`/`-security`/`-system`/`-ntds`) — zero-network analysis of already-exfiltrated files
- Resuming an interrupted large NTDS dump (`-resumefile`) — checkpointed re-run against a big domain
- Chained immediately after `psexec.py`/`wmiexec.py` for the initial admin foothold, then `secretsdump.py` for the payoff

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Credential material | Cleartext password, NTLM hash, Kerberos ticket, AES key, or keytab — same options as `psexec.py`/`wmiexec.py` |
| **For Path 1 (remote SAM/LSA/cache):** local administrator on the target | Needed to open the `RemoteRegistry` service via SCM and to read/save `HKLM\SAM`/`HKLM\SECURITY` — the same admin-equivalent bar as `psexec.py`, but no code execution occurs |
| **For Path 2 (DRSUAPI/`-just-dc`):** `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` on the domain naming context | **Not** local admin on any specific machine — a principal holding these AD extended rights (default: Domain Admins, Enterprise Admins, DC computer accounts, or a delegated account like Azure AD Connect's sync account) can run this from anywhere with DRSUAPI reachability. See `Mimikatz/lsadump (DCSync)/01 - Overview.md`'s Prerequisites table for the full framing of this rights model — it applies identically here |
| **For Path 2 (`-use-vss`/`-use-remoteSSWMI` fallback):** local admin / code-exec rights on the DC itself | A materially higher bar than DRSUAPI mode — this path exists specifically for when replication rights aren't available but interactive-equivalent access to the DC is |
| **For Path 3 (offline):** copies of the relevant hive/database files already exfiltrated | No live access to the source machine needed at parse time — see `01 - Overview.md`'s Path 3 for how those files typically get pulled originally (VSS, backup, `ntdsutil ifm`, disk image) |
| Network reachability | TCP 445 (SMB) for Paths 1/2's registry legs; RPC endpoint mapper TCP 135 + dynamic high port for DRSUAPI — routinely blocked between untrusted segments and DCs in a well-segmented environment |
