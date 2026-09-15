# Veil-Evasion — Overview

> 🔴 **Red Flag Principle:** Veil is a Python-based AV-evasion payload generator whose last functional code release (**3.1.14**) shipped **2020-04-22**, and whose GitHub repository has since been **archived** (confirmed live via the GitHub API — `"archived": true`, last push `2023-10-09`). This is not a currently-evolving evasion engine; it is a frozen ~2013-2020-era toolset. The single most important detection fact for a 2026 analyst is therefore **temporal, not technical**: every obfuscation trick Veil ships (AES/RC4/DES source encryption, letter/base64 substitution, PyInstaller/Py2Exe packing) has had five-plus years for AV/EDR vendors to build durable signature and behavioral coverage against it. Treat any Veil-generated artifact you find in 2026 as something a modern endpoint product should already catch — if it didn't, that's itself the more interesting finding (a badly-lagging AV/EDR deployment, or heavy operator hand-modification of the stock templates).

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified live against the official repository, [`Veil-Framework/Veil`](https://github.com/Veil-Framework/Veil), its `README.md`/`CHANGELOG`, the GitHub API (repo metadata + contributors), and the legacy [`Veil-Framework/Veil-Evasion`](https://github.com/Veil-Framework/Veil-Evasion) repository:

- **Two-repository lineage — read this carefully before citing a source.** What's commonly called "Veil-Evasion" today was originally its own standalone tool/repository (`Veil-Framework/Veil-Evasion`), a sibling to other original Veil-Framework tools (Veil-Catapult, Veil-Ordnance, Veil-Pillage). **That legacy repo is archived**, and its own GitHub description states plainly: *"Veil Evasion is no longer supported, use Veil 3.0!"* (1,839 stars, last push `2021-09-24`). At **Veil 3.0** (initial release per `CHANGELOG`, dated 2017-03-07), the project consolidated Veil-Evasion and Veil-Ordnance into a single unified `Veil-Framework/Veil` repository, where "Evasion" is now one of two internal tools (`Evasion` and `Ordnance`) selected via `-t/--tool`. This document covers the **current, unified `Veil` repo's Evasion tool** — the direct successor to the original standalone Veil-Evasion — and notes the older repo only where the distinction matters for source attribution.
- **Author/maintainer:** the README states plainly, *"Veil is current under support by @ChrisTruncer"* (Chris Truncer). Confirmed independently via the GitHub API's contributors endpoint — `ChrisTruncer` holds 158 commits against the repo, more than double the next-highest contributor (`g0tmi1k`, 66, largely install/setup-script work).
- **License:** GNU GPLv3, per the `LICENSE` file and README.
- **Current maintenance state — archived, not actively developed.** Confirmed directly via the GitHub API on the current `Veil-Framework/Veil` repo: `"archived": true`, `"pushed_at": "2023-10-09T13:57:20Z"`, 4,225 stars. The `CHANGELOG`'s most recent functional entry is **`3.1.14`** (2020-04-22, a superficial fix). No functional code change has landed in over five years as of this writing (2026). **State this plainly to any reader: Veil is an abandoned, historical tool**, not a maintained project.
- **The project's own website is not a reliable current source.** `veil-framework.com` (linked from the repo) now presents itself as a generic "cybersecurity education and tooling knowledge hub" and, in a fetch performed for this page, inaccurately listed PowerShell/AD tooling (PowerView) as a "component" of Veil — PowerView has no relationship to this project (it's a `PowerSploit`/`Empire` module, already documented in this repo's own `PowerSploit/` folder). Treat the domain as unreliable for current facts about this tool; **GitHub is the authoritative source of record**, which is what this page is verified against throughout.
- **Purpose, in the project's own words:** *"Veil is a tool designed to generate metasploit payloads that bypass common anti-virus solutions."*

## How It Works

Veil is a menu-driven Python 3 console (`Veil.py`), structurally similar in UX to `msfconsole` — a `Veil>` prompt lists loaded "tools," `use`/`info`/`options` navigate them, and each tool has its own sub-menu. It wraps **two independent internal tools**, selected via `-t/--tool` or the interactive `use` command:

| Tool | Purpose |
|---|---|
| **Evasion** | The payload-generation engine this page covers — turns a language template + a payload (often msfvenom-sourced shellcode) into a compiled, obfuscated artifact |
| **Ordnance** | A standalone raw-shellcode generator/encoder, independent of msfvenom — produces bind/reverse shellcode plus its own encoder chain (`--list-encoders`, `-e/--encoder`), for cases where Evasion's payloads need custom shellcode Ordnance itself supplies via `--msfvenom`-equivalent internal generation |

### The payload-generation pipeline

```
Operator                                          Veil (Evasion tool)
────────                                          ────────────────────
1. `use Evasion`  →  `list`  →  `use <N|path>`     Loads one of 10 language
   e.g. `use python/shellcode_inject/aes_encrypt.py` template directories:
                                                    autoit, c, cs, go, lua,
                                                    native, perl, powershell,
                                                    python, ruby

2. `set LHOST <ip>` / `set LPORT <port>`           Every payload module falls
   (+ any payload-specific options)                 into one of two families:

                                                    ┌─ meterpreter/  — purpose-
                                                    │  built rev_tcp/rev_https
                                                    │  stager, hand-written per
                                                    │  language
                                                    └─ shellcode_inject/ — a
                                                       generic wrapper that
                                                       VirtualAlloc(RWX)+
                                                       CreateThread()-executes
                                                       ANY msfvenom-supplied
                                                       raw shellcode
                                                       (`--msfvenom`, default
                                                       windows/meterpreter/
                                                       reverse_tcp)

3. `generate` (or `run`)                           Applies the selected
                                                    auxiliary obfuscation
                                                    module (below), then
                                                    hands off to a compiler
                                                    wrapper

4. Compiled artifact + auto-written .rc handler    Writes to
                                                    /var/lib/veil/output/
                                                    {source,compiled,
                                                    handlers}/ (see
                                                    `03 - Source Evidence.md`)
```

**Obfuscation layer — independent of msfvenom's own encoders.** Every language directory has an `auxiliary/` module set applied at generation time: `aes_encrypt`, `arc_encrypt` (RC4), `des_encrypt`, `base64_substitution`, `letter_substitution`, `flat` (no encoding), `pidinject`, `stallion`, and **Pyherion** (a Python-source encrypter, referenced in the `CHANGELOG`). These are Veil's own from-scratch obfuscation code — **not** msfvenom's `-e` encoder chain (e.g. `shikata_ga_nai`); Veil calls out to msfvenom only for raw *shellcode generation*, never for encoding. See `Metasploit/Encoders and Evasion/` for the msfvenom-side encoder mechanics this tool deliberately does not use. Critically, in every one of Veil's "encryption" modules, the decryption key is a **literal string embedded directly in the generated source/binary** — this is obfuscation to evade static signature matching, not real key-management; any static or dynamic analyst who recovers the sample recovers the key trivially in the same pass.

**Compilation/wrapping stage** (`tools/evasion/payloads/auxiliary/`): `pyinstaller_wrapper.py` compiles Python payload source into a Windows PE via PyInstaller (Veil's default `--compiler`); `macro_converter.py` wraps a payload as an Office VBA macro; `coldwar_wrapper.py` provides an alternate wrapping path. Output is a compiled PE32 (Python via PyInstaller/Py2Exe, or native compilation for C/C#/Go/native), a raw interpreted script (PowerShell/Python/Perl/Ruby/Lua source), or a VBA macro — plus, when `LHOST`/`RHOST` are set, an **auto-generated Metasploit resource (`.rc`) file** that stands up the matching `multi/handler` listener with one `msfconsole -r` invocation.

**Built-in anti-sandbox environmental keying.** Several payload modules (notably Ruby) expose `SLEEP`, `USERNAME`, `DOMAIN`, and `HOSTNAME` options — source-verified in `tool.py`'s payload-generation flow, which explicitly warns *"If using SLEEP check with Ruby, you must also provide an additional check (like HOSTNAME)!"* when only `SLEEP` is set. Setting these gates payload execution on matching environmental conditions before running — a deliberate, source-confirmed sandbox/analysis-evasion primitive, not an accidental side effect.

**Built-in operator OPSEC self-check (`checkvt`).** The Evasion menu's `checkvt` command reads every hash ever written to `/var/lib/veil/output/hashes.txt` and shells out to a bundled Ruby script (`vt-notify.rb`) that queries each hash against VirusTotal — letting an operator confirm before deployment whether a generated payload is already flagged. This is a genuine, source-verified network egress point *from the operator's own host*, covered further in `03 - Source Evidence.md`.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Obfuscated Files or Information | AES/RC4/DES source/shellcode encryption, base64/letter substitution, embedded-key "encryption" (key recoverable on recovery of the sample) |
| Software Packing | PyInstaller/Py2Exe compilation of Python payloads into a single PE; native compilation for C/C#/Go/AutoIt |
| Process/shellcode execution | In-process `VirtualAlloc`(RWX) + `CreateThread()` (or the language-native equivalent) to run injected shellcode — the mechanic shared by every `shellcode_inject/*` payload regardless of source language |
| Command and Scripting Interpreter | PowerShell, Python, Perl, Ruby, Lua payload families run as interpreted script rather than compiled PE |
| Phishing delivery vector | `macro_converter.py` wraps a payload as an Office VBA macro for maldoc delivery |
| Metasploit payload/handler protocol | Shellcode generated via `--msfvenom` inherits whatever meterpreter/stager protocol was requested (commonly `windows/meterpreter/reverse_tcp`/`reverse_https`) — the network callback is msfvenom's protocol, not a Veil-original one; see `Metasploit/msfvenom/` and `Metasploit/Meterpreter/` |
| Anti-analysis/sandbox evasion | `SLEEP`/`USERNAME`/`DOMAIN`/`HOSTNAME` environmental-keying payload options (Ruby payloads, confirmed in source) |
| OSINT/detection self-check | `checkvt` — outbound query to VirusTotal from the operator's own host |

## Command-Line Switches — Quick Reference

Verified live against [`Veil-Framework/Veil`](https://github.com/Veil-Framework/Veil)'s `Veil.py` (top-level `argparse` definitions) and `tools/evasion/tool.py`'s interactive menu-command dispatch — every flag/command below is source-confirmed, not guessed.

**Top-level invocation (`Veil.py`, non-interactive/CLI mode):**

| Switch | Plain-English meaning |
|---|---|
| `-t, --tool TOOL` | Select `Evasion` or `Ordnance` and skip the interactive main menu |
| `--list-tools` | Print the two available internal tools and exit |
| `--list-payloads` | List every payload module available for the selected tool |
| `-p PAYLOAD` | The specific payload module to generate (e.g. `python/shellcode_inject/aes_encrypt.py`) |
| `-o OUTPUT-NAME` | Base filename for the generated source/compiled artifact (default `payload`) |
| `-c OPTION=value [...]` | Set one or more payload-module options (e.g. `LHOST=`, `LPORT=`) non-interactively |
| `--ip / --domain IP` | Callback address baked into the payload |
| `--port PORT` | Callback port baked into the payload (**default `8675`** if not overridden — a weak but real default-config signal) |
| `--msfoptions OPTION=value [...]` | Pass-through options for the underlying Metasploit payload |
| `--msfvenom PAYLOAD` | Which Metasploit payload string to request shellcode for (default `windows/meterpreter/reverse_tcp`) — the direct, source-confirmed evidence that Evasion calls out to msfvenom for shellcode |
| `--compiler pyinstaller` | Compiler to use for Python payloads (PyInstaller is the only value the current source wires up) |
| `--clean` | Delete everything under the output directories |
| `--ordnance-payload PAYLOAD` | (Ordnance tool) bind_tcp/rev_tcp/etc. shellcode type to generate |
| `--list-encoders` | (Ordnance tool) list Ordnance's own shellcode encoders |
| `-e, --encoder ENCODER` | (Ordnance tool) apply a named encoder to the generated shellcode |
| `-b, --bad-chars \x00\x0a..` | (Ordnance tool) characters the encoded shellcode must avoid |
| `--print-stats` | (Ordnance tool) print size/stat info about the encoded shellcode |
| `--update` | Git-pull the framework to the latest commit |
| `--setup` / `--config` | Re-run install setup / regenerate `/etc/veil/settings.py` |
| `--version` | Print version banner and exit |

**Interactive menu commands** (three nested menus — Main → Evasion → per-payload options):

| Menu | Command | Meaning |
|---|---|---|
| Main (`Veil>:`) | `list` | List loaded tools (Evasion, Ordnance) |
| Main | `use <tool>` | Enter a tool's own menu |
| Main | `info <tool>` | Print a tool's description |
| Main | `options` | Show current framework configuration |
| Main | `update` / `config` / `setup` | Framework maintenance commands |
| Main | `exit` / `quit` | Quit Veil |
| Evasion (`Veil/Evasion>:`) | `list` | List loaded payload modules |
| Evasion | `use <N\|path>` | Select a payload module by number or full path |
| Evasion | `info <N\|path>` | Print a payload module's description/options |
| Evasion | `checkvt` | Hash every generated payload in `hashes.txt` and query VirusTotal for each |
| Evasion | `clean` | Delete generated payload artifacts |
| Payload options (`[<path>>>]:`) | `set KEY VALUE` | Set a payload option (`LHOST`, `LPORT`, `RHOST`, `SLEEP`, `USERNAME`, `DOMAIN`, `HOSTNAME`, etc. — varies per module) |
| Payload options | `options` / `help` | Reprint the current option table |
| Payload options | `generate` / `run` | Build the payload — writes source, compiles, and writes the `.rc` handler |
| Payload options | `back` / `main` / `menu` | Return to the parent menu |

## Quick Use-Case List

- Interactive, menu-driven single-payload generation walking `use` → `set` → `generate` (the default, documented workflow)
- Fully non-interactive CLI generation for scripting/automation (`Veil.py -t Evasion -p ... -o ... --ip ... --port ...`)
- Mass/batch generation of many payload-language variants from one callback (a phishing-campaign or red-team-engagement pattern — same LHOST/LPORT across a dozen differently-obfuscated artifacts to see which one survives a target's AV)
- Selecting a purpose-built `meterpreter/rev_tcp` or `meterpreter/rev_https` stager in a specific language (evading a target environment's known-good/known-bad language allowlist)
- Wrapping arbitrary msfvenom-generated shellcode via the generic `shellcode_inject` family, independent of the meterpreter-specific templates
- Applying a source/shellcode obfuscation module (AES, RC4, DES, base64/letter substitution, Pyherion) to change a payload's static signature
- Compiling a Python payload to a standalone Windows PE via the PyInstaller wrapper
- Wrapping a generated payload as an Office VBA macro (`macro_converter`) for a maldoc phishing delivery chain
- Auto-generating and launching the matching Metasploit `.rc` handler resource script from the same `LHOST`/`LPORT` values used at generation time
- Setting environmental-keying options (`SLEEP`/`USERNAME`/`DOMAIN`/`HOSTNAME`) to gate execution against sandbox/analysis environments
- Running the standalone Ordnance tool for raw bind/reverse shellcode plus its own encoder chain, independent of the Evasion tool and msfvenom entirely
- Operator OPSEC self-check via `checkvt` before deploying a generated payload
- A chained workflow: Veil-generated payload delivered via phishing → executed on a target → caught by a Metasploit `multi/handler` (or any Metasploit-payload-compatible C2) using the auto-written `.rc` file
- Historical/legacy-engagement analysis: recognizing a Veil-generated artifact recovered from an old incident or malware-repository sample, and reasoning about what a 2013-2020-era build looked like versus a currently-evolving toolset

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Linux operator host | Officially supported: Debian 8+, Kali Rolling 2018.1+; likely-compatible per README: Arch, Manjaro, BlackArch, Fedora 22+, Ubuntu 15.10+, and others. No native Windows/macOS operator support. |
| Install | `apt install veil` + `/usr/share/veil/config/setup.sh` on Kali, or a manual git clone + `config/setup.sh` — setup pulls in per-language toolchains (PyInstaller, Go, Wine for Ruby/Windows cross-compilation) |
| Metasploit Framework present | Required for any `meterpreter/*` payload or `--msfvenom`-driven `shellcode_inject/*` payload — `METASPLOIT_PATH`/`MSFVENOM_PATH` are configured at setup time |
| Network reachability, deployment side | Whatever protocol the requested Metasploit payload uses (commonly TCP to `LHOST:LPORT`, default port `8675` if unset) must be reachable from the eventual target back to the operator's listener |
| Windows/cross-compile toolchain, per language | PyInstaller for Python; Wine + a bundled Ruby/OCRA toolchain for Ruby; Go toolchain for Go; native `mingw`-class compilers for C/C#/native payloads — all installed by `config/setup.sh` |
| No elevation required to generate | Payload *generation* runs entirely on the operator's own Linux host with operator-level privileges; target-side execution/elevation requirements are whatever the delivered artifact itself demands, unrelated to Veil |
