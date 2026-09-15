# Impacket — Overview

The root page for the `Impacket/` tool folder. Impacket is not one tool but a **Python library plus a collection of `examples/` scripts built on it** — this page covers what the library is, how to install it, the mechanics and CLI conventions shared across every sub-tool beneath it (especially the commonly-confused psexec/wmiexec/smbexec trio), and a table of contents into the 7 sub-tool folders that carry the actual operational depth. This page intentionally stays shallow; go to a sub-tool's own `01 - Overview.md` for its Red Flag Principle, verified command reference, and full evidence chain.

## Contents
- [What Impacket Is](#what-impacket-is)
- [Install & Setup](#install--setup)
- [Library Structure — `examples/` vs. the Importable Library](#library-structure--examples-vs-the-importable-library)
- [Shared Mechanics Across Sub-Tools](#shared-mechanics-across-sub-tools)
- [Sub-Tool Table of Contents](#sub-tool-table-of-contents)

---

## What Impacket Is

Impacket's own [`fortra/impacket`](https://github.com/fortra/impacket) README states its lineage plainly, and it's worth quoting rather than paraphrasing: *"Impacket was originally created by [SecureAuth](https://www.secureauth.com/labs/open-source-tools/impacket), and now maintained by Fortra's Core Security."* The fuller chain behind that one-line summary, cross-checked against the project's own `setup.py` (`author="SecureAuth Corporation"`, `maintainer="Fortra"`) and public reporting on the two acquisitions involved: the tool traces back to **CORE Security Technologies** in the early-to-mid 2000s (the CORE IMPACT team, home of longtime lead author Alberto Solino — `beto`/`@agsolino` — credited in nearly every `examples/` script's header), CORE Security's assets were folded into **SecureAuth** via the 2015 Courion/Core Security merger, **HelpSystems acquired the Core Security business unit from SecureAuth in February 2019**, and HelpSystems **rebranded to Fortra in 2022**. The live README's "originally created by SecureAuth" framing is the maintainer's own present-day simplification of that chain — this repo's other Impacket sub-tool pages describe the origin as "CORE Security," which is the more historically precise starting point and not in conflict with Fortra's own framing, just a layer further back.

The project is licensed under **a modified Apache Software License** (per the repo's `LICENSE` file — "Apache" and "Apache Software Foundation" swapped for "Impacket" and "Fortra," otherwise the standard Apache 1.1 terms) — open source, not a paid product. Impacket's own README states its purpose as *"a collection of Python classes for working with network protocols... focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself"* — the `examples/` scripts this repo's sub-tool folders each cover are, in the README's own words, provided *"as examples of what can be done within the context of this library."* That framing matters operationally: every sub-tool below is a thin CLI wrapper around shared, reusable protocol code, not a standalone binary — which is also why a single library-level bug fix or protocol quirk (Kerberos etype negotiation, DCE/RPC fragmentation, PAC parsing) routinely shows up identically across several unrelated-looking sub-tools at once.

**When each of this folder's 7 covered sub-tools actually entered the toolkit** (verified directly against the project's own `ChangeLog.md` — a useful timeline for judging how long a given technique has been "in the wild" via Impacket specifically, independent of when the underlying Windows/Kerberos behavior itself was first documented):

| Script | First appeared |
|---|---|
| `psexec.py` | v0.9.9 (July 2012) |
| `smbexec.py` | v0.9.10 (March 2013) |
| `secretsdump.py` | v0.9.11 (February 2014) |
| `wmiexec.py` | v0.9.12 (July 2014) |
| `GetUserSPNs.py` | v0.9.15 (June 2016) — same release as `ntlmrelayx.py` |
| `ntlmrelayx.py` | v0.9.15 (June 2016) — generalized successor to the now-removed `smbrelayx.py` (SMB-only relay, first added v0.9.10) |
| `ticketer.py` | v0.9.17 (May 2018) — Silver Ticket support (`-spn`) landed after the initial Golden-only release, per the file's own `ToDo` comment |

## Install & Setup

| Step | Command / Notes |
|---|---|
| Install (recommended) | `python3 -m pipx install impacket` — the README explicitly recommends `pipx` over `pip` for system-wide installs, to keep Impacket's dependency set isolated |
| Install from source (unreleased/master) | Clone the repo, then `python3 -m pipx install .` from the unpacked directory — pulls in-development fixes not yet in a tagged release |
| Docker | `docker build -t "impacket:latest" .` then `docker run -it --rm "impacket:latest"` |
| Supported Python | 3.9 – 3.13 per the current `master` branch's classifiers |
| Current versions (verified against the live repo) | Latest stable **v0.13.1**; development branch **v0.14.0-dev** on `master` |
| Where the scripts land | `setup.py`'s `scripts=glob.glob('examples/*.py')` installs every `examples/*.py` file directly onto `PATH` as a runnable command (`psexec.py`, `wmiexec.py`, etc.) — no separate packaging step per script |

Impacket ships **no GUI and no persistent daemon of its own** (`ntlmrelayx.py`'s listening servers and `smbserver.py` are the closest things to a long-running service, and both are invoked per-session, not installed) — every sub-tool is a one-shot Python process an operator runs from a terminal.

## Library Structure — `examples/` vs. the Importable Library

Confirmed directly from `setup.py`'s `packages=[...]` declaration: the installable library is **`impacket`** plus subpackages **`impacket.dcerpc`**, **`impacket.dcerpc.v5`** (+ **`.dcom`**), **`impacket.krb5`**, **`impacket.ldap`**, **`impacket.mssql`**, and **`impacket.examples`** (+ its own **`.ntlmrelayx`** subtree — `clients`, `servers`, `servers.socksplugins`, `utils`, `attacks`, `attacks.httpattacks`). This produces a real, source-verified structural distinction that matters when reading this repo's other Impacket pages:

- **Top-level `examples/<tool>.py`** (e.g. `examples/secretsdump.py`) — the CLI script: `argparse` setup, credential prompting, console output formatting. This is what actually lands on `PATH` after install.
- **`impacket/examples/<tool>.py`** (e.g. `impacket/examples/secretsdump.py`) — a **separate file with the same name**, living inside the installed `impacket.examples` package, holding the reusable classes the CLI script actually calls (`RemoteOperations`, `SAMHashes`, `LSASecrets`, `NTDSHashes` for secretsdump's case). Other tools **import these classes directly** rather than shelling out to the CLI script — `Impacket/secretsdump/01 - Overview.md` documents this split for its own module, and `Impacket/ntlmrelayx/01 - Overview.md` confirms the concrete payoff: `ntlmrelayx.py`'s `dcsyncattack.py` attack module **imports `impacket/examples/secretsdump.py`'s own `NTDSHashes` class** rather than reimplementing DRSUAPI parsing, meaning a relayed DCSync pull and a directly-authenticated `secretsdump.py -just-dc` pull produce byte-identical output because they run through literally the same code.
- **`impacket.dcerpc.v5`** carries the actual MSRPC interface implementations every exec-over-RPC sub-tool depends on — `scmr.py` (MS-SCMR, used by `psexec.py`/`smbexec.py`/secretsdump's Remote Registry leg), `drsuapi.py` (MS-DRSR, used by `secretsdump.py`'s DCSync path), `dcom/wmi.py` (used by `wmiexec.py`).
- **`impacket.krb5`** carries the shared Kerberos protocol implementation — AS-REQ/TGS-REQ construction, PAC structures, etype negotiation — that `ticketer.py`, `GetUserSPNs.py`, and every other tool's `-k`/`-aesKey` authentication path all build on. This is why an etype-negotiation quirk documented in `GetUserSPNs/01 - Overview.md` (the RC4-preference bias in `getKerberosTGS()`) is a property of this shared library function, not something reimplemented per-script.
- **`impacket.ldap`** backs `GetUserSPNs.py`'s SPN enumeration and `ntlmrelayx.py`'s `ldapattack.py` module.

## Shared Mechanics Across Sub-Tools

Everything below applies across multiple sub-tools in this folder — it's the common vocabulary the sub-tool pages build on rather than re-explain.

### Common authentication flags

Verified per-tool against each sub-tool's own already-built switches table. Five flags recur across the credential-based tools, with two structural outliers:

| Flag | Meaning | psexec | wmiexec | smbexec | secretsdump | GetUserSPNs | ticketer | ntlmrelayx |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `-hashes LMHASH:NTHASH` | NTLM pass-the-hash | ✅ | ✅ | ✅ | ✅ | ✅ | ✅* | — |
| `-no-pass` | Skip password prompt, pair with `-k`/`-hashes` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — |
| `-k` | Kerberos auth via `KRB5CCNAME` ccache | ✅ | ✅ | ✅ | ✅ | ✅ | — | — |
| `-aesKey` | Kerberos AES128/256 key auth | ✅ | ✅ | ✅ | ✅ | ✅ | ✅† | — |
| `-keytab` | Read Kerberos keys from a keytab file | ✅ | ✅ | ✅ | ✅ | — | ✅† | — |
| `-dc-ip` | Explicit DC IP for Kerberos resolution | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |

\* `ticketer.py`'s `-hashes` authenticates the **template-fetching** identity for `-request`/`-impersonate` only — plain offline Golden/Silver forging never authenticates to anything. † `ticketer.py`'s `-aesKey`/`-keytab` are **signing key material for the forged ticket itself** (krbtgt's or a service account's key), a semantically different use of the same flag name from the other six tools' "authenticate me as this identity" usage — don't conflate the two when reading its switches table.

**`ntlmrelayx.py` is the one true outlier**: it holds none of the operator's own credentials at all — it relays a *victim's* live NTLM handshake — so the standard credential flags don't apply to the tool itself. Its few credential-shaped flags (`-auth-smb`/`-hashes-smb`, `-machine-account`/`-machine-hashes`) are scoped to specific attack-module transport legs, not the relay engine's core identity.

### The `psexec` / `wmiexec` / `smbexec` trio — verified deltas

These three are Impacket's "get an interactive/one-shot Windows shell over SMB" siblings and are commonly confused for each other. Read each sub-tool's own `01 - Overview.md` for full mechanics — this table is the fast disambiguation reference, verified against all three tools' source-derived overview pages already built in this repo:

| | `psexec.py` | `wmiexec.py` | `smbexec.py` |
|---|---|---|---|
| Execution primitive | MS-SCMR — creates & starts a **real service** running a dropped RemCom-derived binary | DCOM/WMI — `Win32_Process.Create()` | MS-SCMR — creates & starts a **disposable service** whose "binary" is `%COMSPEC%` itself |
| File dropped on target | **Yes** — 8-random-char RemCom-derived `.exe` on the admin share | **No** (default config) | **No** — command text is embedded directly in the service's `ImagePath`, never uploaded |
| Service created | **Once per session** | **Never** | **Once per command typed** — including one to prime the shell prompt before the operator types anything |
| Execution context | **SYSTEM** (service context) | **Authenticating user's own token** (impersonation) | **SYSTEM** (service context, same as psexec) |
| Default output-relay share | `ADMIN$` | `ADMIN$` | **`C$`** — not `ADMIN$`, a real, easily-missed difference |
| Positional `command` argument | Yes (default `cmd.exe`) | Yes (default: empty → interactive shell) | **None at all** — always drops into the semi-interactive shell; one-shot use requires piping stdin |
| Strongest built-in OPSEC flag | `-file` (swap the dropped binary to defeat hash-based detection) | `-silentcommand` (skips both the SMB output channel and the `cmd.exe` wrapper — direct `WmiPrvSE.exe` child) | **None** — the tool's own source comment calls it *"certainly not a stealthy way"* and warns Windows will kill long-running commands since the "service" never calls `StartServiceCtrlDispatcher()` |
| Primary event-log tell | One Event 7045 per session | **No 7045 at all** — hunt `WmiPrvSE.exe`'s child-process tree instead | A **burst** of 7045s sharing one `ServiceName`, one per command, seconds apart |

The one-line disambiguation: **one 7045 → psexec; a burst of 7045s → smbexec; zero 7045s but an unexplained `WmiPrvSE.exe` child → wmiexec.**

### The Kerberos / credential-material cluster

`secretsdump.py`, `ticketer.py`, and `GetUserSPNs.py` all revolve around Kerberos and credential material, but at three different stages of the same attack lifecycle rather than doing the same thing three ways:

```
secretsdump.py  ─── extracts real key material (SAM/LSA/NTDS.dit/DCSync,
                     including krbtgt's own NTLM/AES key via -just-dc-user krbtgt)
                              │
                              ▼
   ticketer.py  ─── forges Kerberos tickets FROM that key material
                     (Golden from krbtgt, Silver from a service/computer
                     account key recovered the same way)
                              │
                              ▼
GetUserSPNs.py  ─── a DIFFERENT extraction path — abuses ordinary Kerberos
                     TGS-REQ behavior to pull crackable service-account
                     hashes with ZERO privileged access, feeding Hashcat/
                     rather than feeding ticketer.py
```

`secretsdump.py -just-dc-user krbtgt` → `ticketer.py` is the direct, already-cross-linked chain (`Impacket/ticketer/01 - Overview.md`'s Quick Use-Case List names it explicitly). `GetUserSPNs.py` is structurally independent of the other two — it needs no elevated rights at all, just any valid domain credential — and its output chains into `Hashcat/` for offline cracking rather than into `ticketer.py`. `secretsdump.py`'s DRSUAPI mode is also the exact same MS-DRSR mechanic as `Mimikatz/lsadump (DCSync)/`'s `lsadump::dcsync` — both tools speak the identical protocol, which is why the DCSync detection guidance in that Mimikatz page applies verbatim to `secretsdump.py -just-dc` and to `ntlmrelayx.py`'s `dcsyncattack.py` module.

### How the 7 sub-tools typically chain together

```
Responder/ (LLMNR poisoning)  ──┐
Coercion (PetitPotam/etc.)    ──┼──▶  ntlmrelayx.py  ──▶  captured/relayed creds or a direct DCSync
Organic misconfigured auth    ──┘            │
                                              ▼
                                    secretsdump.py  ──▶  SAM/LSA/NTDS hashes, krbtgt key
                                              │
                     ┌────────────────────────┼────────────────────────┐
                     ▼                        ▼                        ▼
              psexec.py /              ticketer.py               GetUserSPNs.py
              wmiexec.py /            (forge Golden/Silver        (Kerberoast weak
              smbexec.py               from recovered keys)       service accounts)
              (shell via
               harvested creds)                                        │
                                                                         ▼
                                                                   Hashcat/ (crack
                                                                   offline)
```

Not every engagement runs the whole chain, and any sub-tool can be the entry point on its own (e.g. `GetUserSPNs.py` needs no prior foothold beyond a single valid domain credential) — this is the realistic *shape* of how they compose, not a mandatory sequence.

## Sub-Tool Table of Contents

| Sub-Tool | Covers |
|---|---|
| [`psexec/`](psexec/01%20-%20Overview.md) | RemCom-derived service binary dropped on the target, always SYSTEM. The trio's "classic" member — one Event 7045 per session, `-file` is the flag that breaks hash-based detection. |
| [`wmiexec/`](wmiexec/01%20-%20Overview.md) | DCOM/WMI `Win32_Process.Create()`, no service, no dropped binary, runs as the authenticating user. Zero-7045 sibling — hunt `WmiPrvSE.exe`'s child-process tree instead; `-silentcommand` is the strongest OPSEC flag in the trio. |
| [`smbexec/`](smbexec/01%20-%20Overview.md) | `cmd.exe`/`%COMSPEC%` itself as the service binary, recreated once **per command typed**. The noisiest of the trio by the author's own admission — a burst of same-named 7045s is the tell, default output share is `C$` not `ADMIN$`. |
| [`secretsdump/`](secretsdump/01%20-%20Overview.md) | Three structurally distinct credential-extraction paths — Remote Registry SAM/LSA/cache, DRSUAPI/DCSync-equivalent NTDS.dit pull, and fully offline hive parsing. The tool most other sub-tools and even `ntlmrelayx.py`'s DCSync module reuse code from directly. |
| [`ticketer/`](ticketer/01%20-%20Overview.md) | Offline Golden/Silver Kerberos ticket forging from recovered key material — plus `-request`/`-impersonate` Diamond/Sapphire modes that, unlike plain forging, generate real DC-logged Kerberos traffic at creation time. |
| [`GetUserSPNs (Kerberoasting)/`](GetUserSPNs%20%28Kerberoasting%29/01%20-%20Overview.md) | Kerberoasting — abuses ordinary TGS-REQ issuance to pull crackable service-account ticket hashes with no elevated privilege required at all. One-requester-many-SPNs plus an RC4 etype bias is the detection signature. |
| [`ntlmrelayx/`](ntlmrelayx/01%20-%20Overview.md) | Real-time NTLM relay across SMB/HTTP/LDAP/MSSQL/IMAP/RPC/WinRM — never cracks or sees a password, just forwards a live challenge-response before the victim's client times out. Lives or dies on whether the target enforces SMB signing / LDAP signing+channel binding. |

Every sub-tool page shares this page's authentication-flag vocabulary and the `examples/` vs. importable-library distinction above — none of them re-derive it.
