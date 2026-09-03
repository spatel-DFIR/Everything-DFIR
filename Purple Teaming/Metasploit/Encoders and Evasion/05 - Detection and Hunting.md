# Metasploit — Encoders and Evasion — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

Encoders expose real operator choices that change the file's static shape (`-e`, `-i`, `-b` auto-selection); evasion modules expose module-specific options (`FILENAME`, payload choice) but not a generic "evasion strength" dial. Rank hunts by what survives those choices, strongest first:

| Rank | Signal | Survives encoder choice? | Survives `-i` iteration count? | Survives which evasion module? |
|---|---|---|---|---|
| 1 (strongest) | Behavioral EDR detection of the **decoded, running payload** (API-call sequence, RWX memory transition, injection/reflective-load behavior) | ✅ Yes — identical regardless of encoding | ✅ Yes | ✅ Yes for behavior-based detection generally; **not** for an evasion module's specific anti-emulation trick, which targets the sandbox/emulation stage, not live EDR |
| 2 | Structural/entropy injection signature (`../msfvenom/01 - Overview.md`'s red-flag: high-entropy injected region inside a normal-entropy template) | ✅ Yes | ✅ Yes | ✅ Yes for template-injection-based modules; **not applicable** to modules that don't use the template-injection model (verify per module before relying on this) |
| 3 | Decoder-stub structural/statistical match (e.g. YARA targeting `shikata_ga_nai`'s GetPC-stub-plus-additive-feedback shape) | ❌ **No** — only matches the specific encoder family the rule targets; a different encoder produces a differently-shaped stub | Partially — matches once per stub layer, so a multi-iteration file still matches, just doesn't need to | N/A (encoder-specific signal, not evasion-module) |
| 4 | Static AV signature on the raw/decoded payload | ✅ Survives encoder choice for products with behavioral unpacking; ❌ **No** for products relying purely on static byte matching against the *encoded* form | Partial — depends on product's unpacking depth | Partial — RC4-encrypted shellcode (`windows_defender_exe`-style) specifically defeats pure static byte matching |
| 5 (weakest) | Raw file hash / IOC match against a known-bad list | ❌ **No** — any change to `-e`, `-i`, template, or `FILENAME`-driven rebuild produces a different hash even though behavior is identical | ❌ No | ❌ No |

**Build hunts on ranks 1-2 as primary detections.** Behavioral EDR telemetry on the decoded, running payload and the structural entropy/injection signature both survive every encoding or evasion-module choice an operator can make, because neither depends on the specific bytes of the decoder stub or ciphertext — they depend on what the payload template structurally looks like and what it does once running. Treat ranks 3-5 as valuable enrichment (attribution, campaign correlation, confirming a specific encoder/module was used) once a candidate file is already flagged, not as sole detection logic — this mirrors the general caution `../msfvenom/05 - Detection and Hunting.md` and `../Meterpreter/05 - Detection and Hunting.md` already apply to hash- and signature-based hunting for this Framework.

## Hunting on Source

Applies to the operator/attacking host — see `03 - Source Evidence.md` for full artifact detail.

```bash
# Shell history — the encoder/iteration/bad-char flags directly reveal operator intent
grep -iE "msfvenom.*-e |msfvenom.*--encoder|msfvenom.*-i [0-9]" ~/.bash_history ~/.zsh_history 2>/dev/null

# msfconsole history — catches interactive use that never touches shell history
grep -iE "use encoder/|use evasion/|generate -f" ~/.msf4/history 2>/dev/null

# Local generated-file artifacts — evasion modules default here
ls -la ~/.msf4/local/ 2>/dev/null

# OS-level audit — survives history clearing
ausearch -x msfvenom 2>/dev/null
ausearch -x msfconsole 2>/dev/null
ausearch -x ruby 2>/dev/null

# Process snapshot, if caught live
ps aux | grep -iE "msfvenom|msfconsole"
```
A `-b` (bad-character) flag without an accompanying `-e` in history is a soft signal the encoding was exploit-development-driven rather than evasion-driven (per `02 - Hands-On Use Cases.md`'s tagging distinction) — worth noting in a report rather than assuming every encoder invocation was an AV-evasion attempt.

## Hunting on Target

PowerShell-first for the file-structure and stub-signature layers; the behavioral layer is inherited from `../Meterpreter/05 - Detection and Hunting.md` and not repeated here.

```powershell
# Entropy scan across a suspect binary's sections — a sharp jump between a
# low-entropy template region and a high-entropy injected/encoded region is
# the strongest surviving static signal (Hunting Priority rank 2)
# (requires a PE-section-aware entropy tool; conceptually:)
$bytes = [System.IO.File]::ReadAllBytes("C:\suspect.exe")
# ... compute Shannon entropy per N-byte window, plot/inspect for a sharp
# discontinuity rather than a smooth, uniformly-mid-entropy file

# Files written under a default evasion-module-style random name pattern —
# weak on its own, useful as an enrichment filter alongside other signals
Get-ChildItem -Path C:\Users\*\Downloads,C:\Users\*\AppData\Local\Temp -Include *.exe -Recurse -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^[a-zA-Z0-9]{8,16}\.exe$' }
```
```bash
# YARA — decoder-stub structural rules (community rulesets, e.g. the
# well-established shikata_ga_nai-family signatures) target the GetPC-stub /
# additive-feedback-XOR shape rather than a literal byte string, which is
# why they survive the polymorphic mutation per module while still being
# encoder-family-specific (Hunting Priority rank 3)
yara -r shikata_ga_nai_family.yar /path/to/suspect/files/
```
There is deliberately no single Event ID table on this page — encoders and evasion modules don't independently generate event-log/Sysmon signal beyond whatever the **delivered, wrapped payload** produces once executed. Pivot to `../Meterpreter/05 - Detection and Hunting.md`'s Hunting on Target (or `../msfvenom/05 - Detection and Hunting.md` for a non-Meterpreter payload) for the full event-ID-level hunt once a candidate encoded/evasive file has been identified via the static signals above.

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with EDR/endpoint-agent query access, or
# adapt to your platform's fleet-query tool (Velociraptor, osquery, etc.)
# Combine two independently-strong, encoding-agnostic signals:
#   1. Structural entropy anomaly (per-binary, computationally heavier —
#      run against a narrowed candidate set from step 2 where possible)
#   2. Recently-created, unsigned, randomly-named executables in user-
#      writable paths — a broad but cheap first-pass filter
Get-ChildItem -Path C:\Users\*\Downloads,C:\Users\*\AppData\Local\Temp,C:\ProgramData -Include *.exe,*.dll -Recurse -ErrorAction SilentlyContinue |
  Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) } |
  ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.FullName
    if ($sig.Status -ne 'Valid') {
      [PSCustomObject]@{ Path = $_.FullName; Created = $_.CreationTime; SignatureStatus = $sig.Status }
    }
  } | Export-Csv -Path .\unsigned_recent_binaries.csv -NoTypeInformation
```
Every result needs the entropy/structural check (or a full behavioral EDR review) before being treated as a confirmed finding — unsigned, recently-created, randomly-named binaries have plenty of legitimate causes (installers, update packages, developer tooling); this sweep is a candidate-narrowing filter, not a detection on its own.

## Remediation

**Capture evidence first** — preserve the suspect file itself (both for hash/structural analysis and as evidence of the specific encoder/evasion module used, which can aid attribution/campaign correlation), and snapshot process memory if the payload is confirmed running, before killing anything — same principle applied throughout this Metasploit sub-tool series (e.g. `../RPC and Daemon (msfrpcd-msfd)/05 - Detection and Hunting.md`'s Remediation section).

```powershell
# Isolate and terminate the running payload process, once confirmed
Stop-Process -Id <PID> -Force

# Preserve the dropped file for analysis before removal
Copy-Item "C:\suspect.exe" -Destination "\\forensics-share\case123\suspect.exe"
Remove-Item "C:\suspect.exe" -Force
```
Because encoding/evasion-module use doesn't change the underlying payload's behavior, remediation for the *payload itself* is identical to whatever `../Meterpreter/05 - Detection and Hunting.md` or `../msfvenom/05 - Detection and Hunting.md` prescribes for that specific payload family — the encoder/evasion angle mainly changes *how the file was found*, not what to do once it has been. If an evasion module's technique (e.g. AppLocker-bypass proxy execution via a signed binary) is confirmed in use, treat the underlying policy gap — not just this one file — as the thing needing remediation: an AppLocker/software-restriction-policy rule set that permits `RegAsm.exe`/`RegSvcs.exe`/`InstallUtil.exe`/`MSBuild.exe`/`PresentationHost.exe` to run unconstrained content will keep being exploitable by the next evasion module in that same family regardless of how this specific file is handled.
