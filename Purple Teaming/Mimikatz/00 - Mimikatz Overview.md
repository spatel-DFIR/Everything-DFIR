# Mimikatz — Overview

The root page for the `Mimikatz/` tool folder. Mimikatz is a **multi-sub-module tool** (§2 of `PLANNING.md`) — this page covers what the tool is, how to stand it up, and the mechanics shared across every sub-module underneath it. Sub-module folders (`sekurlsa (Credential Dumping)/`, `lsadump (DCSync)/`, `kerberos (Golden-Silver Ticket)/`) each carry their own 5-file deep dive; this page doesn't repeat that depth.

## Contents
- [What Mimikatz Is](#what-mimikatz-is)
- [Install & Setup](#install--setup)
- [Module (`::`) Command Structure](#module--command-structure)
- [Shared Mechanics Across Sub-Modules](#shared-mechanics-across-sub-modules)
- [Sub-Module Table of Contents](#sub-module-table-of-contents)

---

## What Mimikatz Is

Mimikatz was created by **Benjamin Delpy (`@gentilkiwi`)**, starting around 2007. In the project's own words, on its official repository [`github.com/gentilkiwi/mimikatz`](https://github.com/gentilkiwi/mimikatz): *"`mimikatz` is a tool I've made to learn `C` and make somes experiments with Windows security."* It is licensed under **CC BY 4.0** (per the repo's README — [creativecommons.org/licenses/by/4.0](https://creativecommons.org/licenses/by/4.0/)), and Delpy remains its sole primary author and maintainer; Vincent Le Toux is credited as co-author of the DCSync/DCShadow functionality that lives in the `lsadump` module.

**Origin story:** Delpy built the tool as a personal C-learning project and a set of experiments against Windows authentication internals. The single most consequential of those experiments was proving that the **WDigest** authentication provider held **plaintext user passwords in `lsass.exe`'s memory** — a design choice Microsoft had made for HTTP Digest authentication compatibility. Delpy reported this to Microsoft in 2011; Microsoft's initial response was that this did not constitute a vulnerability requiring an urgent fix, since an attacker would already need significant access to the host to read LSASS memory in the first place. Delpy shipped the capability publicly anyway — mimikatz's first public release (referred to by the project as "return of mimikatz," May 2011) began dumping cleartext credentials from the TsPkg provider, and WDigest cleartext extraction followed shortly after as the tool's signature capability. Microsoft eventually responded with **KB2871997** (2014), which — among other hardening changes — let WDigest plaintext credential caching be **disabled by default** on Windows 8.1/Server 2012 R2 and later, and made the same toggle available via registry key on backported earlier OSes (Windows 7/Server 2008 R2 and up). This registry toggle (`UseLogonCredential`) and its forensic implications are covered in depth in `sekurlsa (Credential Dumping)/`.

The tool has been in continuous, active development since — its live-memory-reading logic is pattern-matched per Windows build (the current source carries signatures as recent as Windows 11 24H2), meaning Delpy has to update mimikatz for every new Windows release that changes LSASS's internal memory layout. It's commonly built as **mimikatz 2.0** (the version banner introduced with the 2014 rewrite) even though development has continued well past that nominal version number.

## Install & Setup

| Step | Notes |
|---|---|
| Prebuilt release | Download from the official [Releases page](https://github.com/gentilkiwi/mimikatz/releases) — ships `mimikatz.exe`/`mimikatz.dll` for both Win32 and x64, no build environment needed. This is also the version most heavily fingerprinted by AV/EDR (see below) |
| Build from source | Visual Studio (2010/2012/2013 per the README, newer VS versions also build it) opening `mimikatz.sln`. The `mimikatz driver` (`mimidrv.sys`, used for kernel-level operations like removing LSA Protection — see `sekurlsa (Credential Dumping)/`) additionally requires the Windows Driver Kit 7.1, but is **optional for main operations** per the project's own README |
| Architecture match | `mimikatz.exe`/`.dll` **must match the bitness of the process it's reading** — a 32-bit (WOW64) mimikatz cannot read a 64-bit `lsass.exe`'s memory; the source explicitly checks `IsWow64Process` and errors out (`"mimikatz(win32) cannot access x64 process"`) rather than silently failing. Always run the x64 build against a 64-bit target OS |
| `privilege::debug` | Enables `SeDebugPrivilege` in the current process's token. This privilege is present-but-disabled by default even for local administrators; without it, mimikatz cannot open the handles it needs against `lsass.exe` or other protected processes. Run this first, in nearly every session |
| `token::elevate` | Impersonates a SYSTEM-level token (typically duplicated from `winlogon.exe` or another SYSTEM process) when the current context is administrator-but-not-SYSTEM. Needed for some operations (e.g. reading another user's DPAPI material, some `lsadump` actions) that require the SYSTEM security context specifically, not just admin rights |

## Module (`::`) Command Structure

Every mimikatz command takes the shape **`module::command [/arg:value ...]`** — the module groups related functionality, and `::` separates it from the specific command. This is the vocabulary every sub-module page in this folder builds on:

| Module | Purpose |
|---|---|
| `sekurlsa` | Extract credentials (plaintext, hashes, Kerberos tickets) directly from `lsass.exe` memory — the tool's flagship capability. See `sekurlsa (Credential Dumping)/` |
| `lsadump` | Offline/remote credential extraction — local SAM (`lsadump::sam`), LSA secrets (`lsadump::secrets`), cached domain logons (`lsadump::cache`), and the DCSync replication attack (`lsadump::dcsync`). See `lsadump (DCSync)/` |
| `kerberos` | List, export, and inject Kerberos tickets (`kerberos::list`, `kerberos::ptt`), and forge Golden/Silver tickets (`kerberos::golden`). See `kerberos (Golden-Silver Ticket)/` |
| `crypto` | Enumerate and export CryptoAPI/CNG certificates and keys |
| `vault` | Read Windows Credential Manager / Vault-stored credentials |
| `privilege` | Enable Windows privileges in the current token (`privilege::debug` above is the most common) |
| `token` | Manipulate/impersonate Windows access tokens (`token::elevate`, `token::revert`) |
| `event` | Manipulate the Windows Event Log service (e.g. clear/patch logging — relevant to anti-forensics, out of scope for the sub-modules built here) |
| `ts` | Terminal Services / RDP session manipulation |

## Shared Mechanics Across Sub-Modules

### How mimikatz gets loaded onto/into a target

| Method | Mechanics | Disk footprint |
|---|---|---|
| **Dropped binary** | `mimikatz.exe` (or `mimilib.dll`/`mimidrv.sys` as needed) copied to disk and executed directly, interactively or via a remote-execution chain | Full — the executable lands on disk and is trivially scanned by any on-access AV/EDR |
| **Reflective load via PowerShell** | `Invoke-Mimikatz` (originally a PowerSploit script, widely mirrored/forked since) embeds mimikatz's DLL as a Base64 blob inside a `.ps1` script and reflectively loads it directly into the PowerShell process's memory — the DLL is mapped and executed without ever being written to disk as a standalone file | None for the mimikatz binary itself — only the `.ps1` script (if dropped rather than piped/`IEX`'d) leaves a file artifact |
| **In-memory via a C2 agent** | Meterpreter's `kiwi` extension (a reimplementation of mimikatz's core `sekurlsa`/credential-extraction routines built as a Meterpreter extension DLL) and Cobalt Strike's Beacon `mimikatz`/`execute-assembly` commands both load the credential-extraction logic reflectively into an already-running, already-trusted process's memory — see `Metasploit/Meterpreter/01 - Overview.md` and `Metasploit/Meterpreter/02 - Hands-On Use Cases.md` ("Credential Harvesting via Kiwi") for the Meterpreter side of this in depth | None — the credential-theft logic never exists as a separate file on the target at any point |

### Why the stock binary is universally flagged

The default, unmodified `mimikatz.exe`/`mimikatz.dll` from the official releases carries what is effectively **near-100% static-signature detection** across mainstream AV/EDR products — it has been public, unchanged in its core form, and a top-tier detection priority for over a decade. This is precisely *why* the reflective/in-memory loading methods above are the default operational choice for real engagements and real intrusions alike: dropping `mimikatz.exe` to disk in anything resembling its stock form is expected to trigger an immediate alert on any host with a functioning endpoint product, whereas reflective loading skips the on-disk file-scan trigger entirely. This is not an absolute bypass — modern EDR increasingly hooks in-memory behavior (AMSI, ETW, LSASS-access telemetry) independent of whether a file ever touched disk, which is exactly what the Detection & Hunting sections in each sub-module below are built around — but it explains the strong default preference for never dropping the binary if it can be avoided.

## Sub-Module Table of Contents

| Sub-Module | Status | What It Covers |
|---|---|---|
| `sekurlsa (Credential Dumping)/` | ✅ Built — see `sekurlsa (Credential Dumping)/01 - Overview.md` | Live and offline (minidump) extraction of plaintext passwords, hashes, and Kerberos material from `lsass.exe` memory; pass-the-hash |
| `lsadump (DCSync)/` | ✅ Built — see `lsadump (DCSync)/01 - Overview.md` | Local SAM/LSA-secrets/cached-credential dumping (`sam`, `secrets`, `cache`), trust-key extraction (`trust`), legacy Netlogon hash retrieval (`netsync`), and the DCSync domain-replication credential-theft technique (`dcsync`) via MS-DRSR's `IDL_DRSGetNCChanges` |
| `kerberos (Golden-Silver Ticket)/` | ✅ Built — see `kerberos (Golden-Silver Ticket)/01 - Overview.md` | Golden/Silver ticket forgery via `kerberos::golden`, pass-the-ticket (`ptt`), ticket-cache listing/purging (`list`, `purge`), TGT/TGS retrieval (`tgt`, `ask`), and MIT/Heimdal ccache interop (`ptc`, `clist`) |

All three sub-modules share this page's `module::command` vocabulary, the `privilege::debug`/`token::elevate` prerequisites, and the loading-method taxonomy above — none of them re-derive it.
