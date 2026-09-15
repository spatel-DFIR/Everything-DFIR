# Veil-Evasion — Target Evidence

What executing a Veil-generated payload leaves on the **target/destination** host.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Process Tree](#process-tree)
- [Event Logs](#event-logs)
- [Sysmon](#sysmon)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint-Security-Product Signature Behavior](#endpoint-security-product-signature-behavior)
- [Memory Artifacts](#memory-artifacts)
- [Building a Timeline](#building-a-timeline)

---

## Filesystem

- **The delivered artifact itself** — a compiled PE (Python via PyInstaller/Py2Exe, or native C/C#/Go/AutoIt compilation), an interpreted script (PowerShell/Python/Perl/Ruby/Lua source, often written to disk as a `.ps1`/`.py` before execution, or piped directly to an interpreter without ever touching disk), or an Office document carrying a `macro_converter`-wrapped VBA macro. Filename/path are entirely operator-chosen (`-o OUTPUT-NAME`) — there is no fixed default drop location the way a signed system tool has.
- **PyInstaller onefile self-extraction — the single strongest disk artifact for Python-language payloads.** A PyInstaller onefile binary, at every execution, unpacks its bundled Python interpreter and every imported module into a randomly-named `%TEMP%\_MEI<random-digits>\` directory (Windows) before running — this is standard, well-documented PyInstaller runtime behavior, not something Veil adds or can suppress. That directory is normally cleaned up on a graceful exit but **survives a crash, a kill, or an abnormal termination** — meaning an unexpectedly-terminated Veil/PyInstaller payload frequently leaves its own fully-unpacked Python source/bytecode sitting in `%TEMP%` for a responder to recover directly, no dynamic analysis required.
- **VBA macro path:** if delivered via `macro_converter`, the payload lives embedded inside the Office document itself (extractable via `oletools`/`olevba`) rather than as a separate dropped file until the macro's own `AutoOpen`/`Document_Open` logic writes/executes it.

## Registry

Veil-generated payloads carry **no persistence mechanism of their own** — the tool's scope ends at "execute this shellcode/script once," not "survive reboot." Any registry Run key, scheduled task, or service entry found alongside a Veil-sourced payload is evidence of a **separate, subsequent operator action** (a distinct persistence tool/technique), not something to attribute to Veil itself. Treat persistence artifacts as a lead pointing to a different tool in this repo (`LOLBins/schtasks/`, `PowerSploit/PowerUp/`, `GhostPack/`, etc.), not as part of Veil's own footprint.

## Process Tree

```
winword.exe / excel.exe                    explorer.exe
        │  (macro AutoOpen)                        │  (direct EXE execution)
        ▼                                            ▼
powershell.exe -enc <base64>              <payload>.exe (PyInstaller-bundled,
   (or cmd.exe wrapper, per                 or native-compiled)
    payload template)                              │
        │                                            │  (PyInstaller onefile only)
        ▼                                    %TEMP%\_MEI<random>\ self-extraction
   VirtualAlloc(RWX) + CreateThread()               │
   in the SAME process — Veil's                     ▼
   shellcode_inject templates execute       VirtualAlloc(RWX) + CreateThread()
   in-process, they do not spawn a          in the SAME process
   separate injection target by default
```

**Same-process execution is the norm, not an outlier.** Every `shellcode_inject`/`meterpreter` payload template runs its shellcode inside its own process via `VirtualAlloc`+`CreateThread` (or the language-native equivalent) — it does not, by default, inject into a separate legitimate process. This means classic cross-process-injection telemetry (Sysmon Event 8 `CreateRemoteThread` against a *different* target image) generally will **not** fire for a stock Veil payload; the more relevant signal is same-process RWX memory allocation followed by thread creation, which requires EDR API-hooking/behavioral telemetry rather than default Sysmon configuration to see reliably.

## Event Logs

| Event ID | Source | What it shows |
|---|---|---|
| 4688 | Security (Process Creation) | The dropped payload's process creation — requires "Audit Process Creation" enabled (non-default) and ideally command-line auditing for full visibility |
| 1116 / 1117 | Microsoft-Windows-Windows Defender/Operational | Malware detected (1116) / action taken (1117) — see Endpoint-Security-Product Signature Behavior below for why this is the single most likely event to actually fire against a stock Veil payload in 2026 |
| 4103 / 4104 | Microsoft-Windows-PowerShell/Operational | Module/Script Block Logging — relevant only for `powershell`-language payloads; both are **off by default** (see `LOLBins/powershell/01 - Overview.md` for the full default-logging-posture finding, cross-linked rather than re-derived here) |

## Sysmon

| Event ID | Field of interest | What it shows |
|---|---|---|
| 1 (Process Creation) | `Image`, `CommandLine`, `ParentImage`, `Hashes` | The dropped artifact's own execution — `ParentImage` of `winword.exe`/`excel.exe` for macro-delivered payloads is the strongest single structural tell here |
| 7 (Image Load) | `ImageLoaded` | PyInstaller-bundled Python payloads load `python3X.dll`/the bundled interpreter runtime — an unexpected Python-interpreter DLL load inside a process with an unrelated-sounding name (`quarterly_report.exe`) is a strong anomaly signal |
| 11 (File Create) | `TargetFilename` | The `%TEMP%\_MEI<random>\` PyInstaller self-extraction tree, if the process crashes/is killed before cleanup; the dropped payload file itself |
| 3 (Network Connection) | `DestinationIp`, `DestinationPort` | The resulting meterpreter/Metasploit-payload callback — inherits whatever protocol `--msfvenom` requested (commonly `reverse_tcp`/`reverse_https`); see `Metasploit/Meterpreter/04 - Target Evidence.md` for the callback protocol's own detailed signature, not re-derived here |
| 8 (CreateRemoteThread) | — | **Will generally NOT fire** for stock Veil payloads — same-process execution is the default, see Process Tree above |

## Network-Layer Evidence

The callback traffic itself is msfvenom/Metasploit's payload protocol, not a Veil-original one — Veil only determines *how the shellcode got onto the target and into memory*, not what it does once it calls home. Apply `Metasploit/Meterpreter/04 - Target Evidence.md` and `Metasploit/msfvenom/04 - Target Evidence.md`'s network-layer coverage directly (JA3/JARM where TLS is involved, staged-payload's characteristic small-request/large-response pattern, etc.) rather than re-deriving it here. The one Veil-specific note: **default callback port is `8675`** if the operator ran `Veil.py` without an explicit `--port` — a weak, easily-changed, but real default-configuration signal worth including in a first-pass port-based sweep.

## Endpoint-Security-Product Signature Behavior

**This is the key detection fact for a 2026 analyst, and it deserves to be stated plainly rather than hedged:** Veil's underlying obfuscation techniques (AES/RC4/DES source encryption with an embedded key, base64/letter substitution, PyInstaller/Py2Exe packing) have not meaningfully changed since the tool's last functional release in April 2020. Independent research on PyInstaller specifically confirms the packed-binary format is now **highly detectable via entropy-based unpacking-identification tooling** (published benchmarks cite 99%+ recall for tools like Bintropy and PyPEiD against PyInstaller-packed samples) — meaning the compiled-output half of a Veil payload's evasion story is largely defeated by static entropy analysis alone, independent of any behavioral/signature detection. Combined with five-plus years of AV/EDR vendors building both static-signature and behavioral coverage against known Veil output patterns, **a modern, up-to-date endpoint product should be expected to flag a stock (non-hand-modified) Veil-generated payload** — if one doesn't, that itself is the more notable finding (a stale AV/EDR deployment, or an operator who materially hand-altered the generated template beyond what Veil's own obfuscation modules produce).

## Memory Artifacts

- Post-execution, the decrypted/decoded shellcode sits in the process's own RWX-allocated memory region — recoverable via standard memory-forensics shellcode-scanning (Volatility's `malfind`-class plugins looking for RWX regions with no backing file, or PE/shellcode signature scanning within them).
- Because every one of Veil's "encryption" modules embeds its decryption key as a literal string in the generated artifact, **the key itself is recoverable from the same memory region or from static analysis of the artifact on disk** — there is no separate key-management layer to defeat.
- PyInstaller's `_MEI*` extraction (Filesystem section, above) means a live memory capture during execution can also be correlated directly against the fully-unpacked interpreter/module tree sitting on disk at the same moment.

## Building a Timeline

1. **Delivery timestamp** — document creation/modification time (macro path) or file-write time (direct EXE) from filesystem metadata / Sysmon Event 11.
2. **Execution timestamp** — Sysmon Event 1 process creation for the payload itself; note `ParentImage` for delivery-vector confirmation (Office app vs. direct execution).
3. **PyInstaller self-extraction timestamp** (Python payloads only) — Sysmon Event 11 for the `_MEI*` directory creation, effectively simultaneous with process start.
4. **Network callback timestamp** — Sysmon Event 3 first outbound connection; correlate against the source-side `hashes.txt` write time (`03 - Source Evidence.md`) to establish build-to-detonation latency for the campaign.
5. **AV/EDR detection timestamp**, if any — Event 1116/1117 or an EDR platform's own alert log; given the Endpoint-Security-Product Signature Behavior note above, the gap (or absence) between execution and detection is itself informative about the target's endpoint-product currency.

**Distinguishing from a legitimate PyInstaller-built application:** legitimate PyInstaller-packaged Python software exists and is not inherently suspicious — the anomaly is context, not the packing technique alone. A PyInstaller `_MEI*` self-extraction tied to a process with an innocuous-sounding name, no corresponding installed-application record (no matching entry in `Add/Remove Programs`, no digital signature, no vendor-consistent file metadata), and a subsequent outbound connection matching a Metasploit payload protocol shape is the combination that separates a Veil-sourced artifact from routine legitimate Python-application packaging.
