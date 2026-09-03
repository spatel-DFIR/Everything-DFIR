# Metasploit — Encoders and Evasion — Overview

> 🔴 **Red Flag Principle:** An **encoder** and an **evasion module** solve two structurally different problems, and conflating them leads to bad threat models on both sides of the table. An encoder (`x86/shikata_ga_nai` and its siblings) only ever changes the **byte pattern of an already-generated payload** — it wraps raw shellcode in a decoder stub and mutates that stub's instruction encoding, nothing else. It does not change what the payload does at runtime, does not touch the delivery mechanism, and — critically for a defender — **the decoder-stub shape itself is a signature**: `shikata_ga_nai`'s GetPC-stub-plus-XOR-additive-feedback pattern is old enough and common enough that mainstream AV/EDR products signature the stub, not just the raw payload underneath it. An **evasion module** (`evasion/windows/*`, `evasion/linux/*`) is a different, newer (2018+) module class entirely — a purpose-built generator combining a specific technique (RC4-encrypted shellcode, AppLocker-bypass proxy execution, process herpaderping) into one output file. If you remember one thing: **"encoded" is not "evasive."** Encoding defeats naive static-signature matching only; it has zero effect on behavioral/EDR detection, and by the current threat landscape even the static layer increasingly catches it.

> ⚠️ **Scope note for this page:** Per the current build pass, this folder concentrates its research and depth on **msfvenom's encoders** — `x86/shikata_ga_nai` and the full set enumerated by `msfvenom -l encoders`. The **`evasion/` module class** gets only the high-level treatment below (what it is, how it structurally differs from encoders, 2-3 named examples) deliberately — **a deeper per-module dive into `evasion/windows/*` and `evasion/linux/*` internals is planned as a follow-up pass and is intentionally NOT done here.** Anywhere this page or its siblings (`02`-`05`) touch evasion modules, treat the coverage as a pointer/overview, not the finished depth the encoder half received.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line / Console Reference](#command-line--console-reference)
- [Verified Encoder Inventory](#verified-encoder-inventory)
- [Evasion Modules — Brief Coverage (Deep Dive Deferred)](#evasion-modules--brief-coverage-deep-dive-deferred)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Metasploit's **encoder** module type is one of the Framework's original module classes, dating to the early 2000s alongside `payload` and `nop` modules — its job has never changed: take a buffer of shellcode and re-emit functionally identical bytes in a different encoding, primarily to strip bad characters an exploit's delivery path can't tolerate (nulls, newlines, etc.) and secondarily to vary the payload's static signature. `x86/shikata_ga_nai` — Japanese for "it cannot be helped" — was written by Metasploit contributor **spoonm** and has shipped as the Framework's flagship "Excellent"-ranked encoder for essentially the tool's entire public history; it is verified directly against Rapid7's own module database entry ([`rapid7.com/db/modules/encoder/x86/shikata_ga_nai`](https://www.rapid7.com/db/modules/encoder/x86/shikata_ga_nai/)), which describes it as *"a polymorphic XOR additive feedback encoder. The decoder stub is generated based on dynamic instruction substitution and dynamic block ordering."* Before June 2015, encoding was invoked through the standalone `msfencode` utility (paired with `msfpayload` for generation); both were folded into the single `msfvenom` CLI — full history of that consolidation lives in `../msfvenom/01 - Overview.md`'s History section and isn't re-derived here.

The **evasion** module type is much newer and a genuinely separate addition to the Framework's module taxonomy, not a rename or extension of encoders. Rapid7 introduced it on **October 9, 2018**, announced in the blog post *"Metasploit's First Antivirus Evasion Modules"* ([`rapid7.com/blog/post/2018/10/09/introducing-metasploits-first-evasion-module`](https://www.rapid7.com/blog/post/2018/10/09/introducing-metasploits-first-evasion-module/)) — Rapid7's own framing is that it gives "Framework users the ability to generate evasive payloads without having to install external tools," and provides a structured place for the team's own AV-evasion research (custom compilers, anti-emulation tricks, encryption of the embedded shellcode) to live as a first-class, reusable module rather than one-off scripts. Both module classes live in the same [`rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework) repository as the rest of the Framework — `modules/encoders/` and `modules/evasion/` respectively — same maintainer, license, and versioning as covered in `../00 - Metasploit Overview.md`.

## How It Works

### Encoders

```
Raw payload bytes (from a payload module or -p stdin)
        │
        ▼
┌───────────────────────────────────────────────────┐
│ Encoder module .encode()                          │
│                                                     │
│ 1. Generate a decoder stub — the bit of machine    │
│    code that will run FIRST on the target and      │
│    reverses the encoding at runtime before          │
│    jumping into the real payload                   │
│ 2. For shikata_ga_nai specifically: apply dynamic   │
│    instruction substitution (same logical           │
│    operation, different opcode choices each pass)  │
│    and dynamic block ordering (reshuffle the        │
│    stub's internal blocks) — this is what makes it  │
│    "polymorphic": two encodes of the SAME payload    │
│    produce DIFFERENT bytes                          │
│ 3. XOR the payload body against a computed key,      │
│    additive-feedback style (each byte's key value   │
│    depends on the previous byte) — the actual        │
│    obfuscation of the payload body itself            │
│ 4. Prepend the decoder stub to the XORed body        │
└───────────────────────────────────────────────────┘
        │
        ▼
Output: [decoder stub][encoded payload body]
   — same BEHAVIOR as the original payload once the
     stub decodes it at runtime, DIFFERENT BYTES on
     disk/in the buffer than the unencoded original
```

The critical mechanical point for a defender: encoding is **reversible obfuscation of the payload's static representation only**. Nothing about the decoder-stub-plus-XOR-body construction changes what API calls the payload makes, what network connection it opens, or how it behaves once running — it only changes what the bytes look like *before* that stub executes. `-i <count>` (msfvenom's iteration flag) re-runs this whole process multiple times, layering stub-on-stub-on-stub; per Rapid7's own documentation this does **not** meaningfully improve evasion (see `../msfvenom/01 - Overview.md`'s Command-Line Switches table) — it mainly grows the file and adds CPU-decode overhead on the target at execution time.

### Evasion Modules

Structurally, an evasion module is closer to a **format/generator module married to a specific, hand-engineered technique** than to the generic mutation-engine model above. Rapid7's own framing: *"An evasion module functions similarly to a file format exploit in Metasploit in that the output of both is a file. An evasion module is different in that it does not start a payload handler automatically."* Concretely, for `evasion/windows/windows_defender_exe`:

```
msfconsole operator workflow                    What the module actually does
─────────────────────────────                    ──────────────────────────────
use evasion/windows/windows_defender_exe   ───▶  Loads the module (search/use/set/run
                                                    mechanics identical to any other
                                                    msfconsole module — see
                                                    ../msfconsole/02 - Hands-On Use
                                                    Cases.md's Baseline Module Workflow,
                                                    not re-derived here)
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST/LPORT
set FILENAME <name>                       ───▶  Optional — controls the output
                                                    filename; a random name is used
                                                    if unset
exploit / run                              ───▶  1. Generates the raw payload (same
                                                    payload-module machinery msfvenom
                                                    uses)
                                                  2. RC4-encrypts the shellcode buffer
                                                    specifically to defeat static
                                                    scanning (documented technique,
                                                    per Rapid7's module docs)
                                                  3. Compiles it into an executable
                                                    with a module-specific custom
                                                    compiler/template, tuned to also
                                                    include an anti-emulation check
                                                    exploiting weaknesses in the AV
                                                    engine's runtime scanner
                                                  4. Writes the finished file to the
                                                    operator's local Metasploit
                                                    directory (~/.msf4/local/) —
                                                    NOT to the target; like msfvenom,
                                                    evasion modules generate locally
                                                    and delivery is a separate step
```

Each evasion module bundles its **own, distinct technique** — there is no shared "evasion engine" the way `shikata_ga_nai`'s polymorphic mutation logic is one engine reused conceptually across encoder-class thinking. That per-module bespoke-technique structure is the core structural difference from encoders, and it's the reason a deep dive here means reading each module's individual mechanics rather than one shared engine — exactly the work explicitly deferred to the follow-up pass noted at the top of this page.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Encoder generation | Pure local module invocation — same `Msf::PayloadGenerator`/module-tree mechanics as `../msfvenom/01 - Overview.md`; no network I/O |
| Encoder mutation mechanic | Decoder-stub generation + payload-body transform (XOR-additive-feedback for `shikata_ga_nai`; other encoders use different transforms — alphanumeric mapping, bit rotation, context-derived keys — see [Verified Encoder Inventory](#verified-encoder-inventory)) |
| Evasion generation | Module-specific: payload generation + a bespoke technique (shellcode encryption, custom compilation, anti-emulation, signed-binary proxy execution, process herpaderping) per module — no single shared mechanism |
| Delivered payload's own protocol | Whatever the wrapped payload module implements post-execution — fully covered in `../Meterpreter/01 - Overview.md` for Meterpreter-family payloads, not re-derived here |

## Command-Line / Console Reference

Encoders are reachable two ways — from `msfvenom` directly (covered in depth in `../msfvenom/01 - Overview.md`'s switches table; not repeated here) or by loading an `encoder/` module inside `msfconsole` like any other module. Evasion modules are **msfconsole-only** — there is no `msfvenom` flag that invokes an `evasion/` module, since evasion modules are their own module type with their own generation logic, not something msfvenom's `Msf::PayloadGenerator` pipeline wraps.

| Context | Command | Plain-English meaning |
|---|---|---|
| msfvenom | `-e <encoder>` | Select an encoder by name (e.g. `x86/shikata_ga_nai`) — full flag table in `../msfvenom/01 - Overview.md` |
| msfvenom | `-l encoders` | Enumerate every encoder registered in the current Framework install |
| msfconsole | `use encoder/x86/shikata_ga_nai` | Load an encoder module directly, same `use`/`set`/`run` pattern as any other module (see `../msfconsole/02 - Hands-On Use Cases.md`'s Baseline Module Workflow) |
| msfconsole | `set PAYLOAD <payload>` then `generate -f <format> -o <path>` | Inside an encoder module context, generate the encoded payload to a file — the msfconsole-native equivalent of an msfvenom `-e` invocation |
| msfconsole | `search type:evasion` | Enumerate evasion modules currently registered |
| msfconsole | `use evasion/windows/<name>` | Load an evasion module by path |
| msfconsole | `set FILENAME <name>` | Evasion-module-specific option (present on most `evasion/windows/*` modules) — controls the output filename; random if unset |
| msfconsole | `exploit` / `run` | Generate the evasive file — written to `~/.msf4/local/` by default, not to the target |

## Verified Encoder Inventory

Verified directly against the encoder file listing in [`rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework)'s `modules/encoders/` tree (GitHub repository contents, checked this pass) — this is the authoritative, current module set, not a copied cheat-sheet list. Ranks for `x86/shikata_ga_nai` (Excellent), `x86/countdown` (Normal), and `x86/alpha_mixed` (Low) were individually spot-checked against their Rapid7 database pages and are cited with confidence. The remaining ranks below reflect the standard, long-published `msfvenom -l encoders` output as documented across the Metasploit ecosystem — **treat them as a reasonable baseline, not individually re-verified this pass**, and confirm with `msfvenom -l encoders` or `info <encoder>` before citing a specific rank as fact in a report. A handful of newer additions to the module tree have no well-established public rank record at all; those are flagged explicitly rather than guessed.

**x86 encoders** (target/exploit-buffer architecture — the large majority of real-world msfvenom encoder usage):

| Encoder | Rank | Notes |
|---|---|---|
| `x86/shikata_ga_nai` | **Excellent** ✅ verified | Polymorphic XOR-additive-feedback, dynamic instruction substitution + block ordering — the default "just works" choice, and the most heavily signatured by exactly the same token |
| `x86/countdown` | Normal ✅ verified | Single-byte XOR keyed on payload length |
| `x86/alpha_mixed` | Low ✅ verified | SkyLined's Alpha2 mixed-case alphanumeric encoder — output is alphanumeric text, for injection contexts that only tolerate printable characters |
| `x86/alpha_upper` | Low | Alpha2 uppercase-only variant of the above |
| `x86/nonalpha` | Low | Avoids alphabetic bytes entirely |
| `x86/nonupper` | Low | Avoids uppercase bytes entirely |
| `x86/unicode_mixed` | Manual | Unicode-safe mixed-case encoding — for contexts that mangle payloads through a Unicode up-conversion (e.g. certain Windows API string handling) |
| `x86/unicode_upper` | Manual | Unicode-safe uppercase-only variant |
| `x86/call4_dword_xor` | Normal | GetPC-via-`call`-instruction XOR encoder |
| `x86/fnstenv_mov` | Normal | GetPC-via-`fnstenv` XOR encoder (an older FPU-instruction-based position-independence trick) |
| `x86/jmp_call_additive` | Normal | Additive-feedback XOR using a jmp/call GetPC stub |
| `x86/xor_dynamic` | Normal | Dynamic-key XOR, simpler engine than `shikata_ga_nai` |
| `x86/add_sub` | Manual | Add/subtract-based obfuscation rather than XOR |
| `x86/opt_sub` | Manual | Optimized subtract-based variant |
| `x86/single_static_bit` | Manual | Single-static-bit encoding scheme |
| `x86/context_cpuid` | Manual | Derives part of its decode key from the `cpuid` instruction's runtime output (context-keyed, complicates static emulation) |
| `x86/context_stat` | Manual | Derives key material from a `stat()` syscall's runtime result |
| `x86/context_time` | Manual | Derives key material from the current time |
| `x86/avoid_utf8_tolower` | Manual | Avoids bytes a UTF8-lowercasing transform would mangle |
| `x86/avoid_underscore_tolower` | Manual | Avoids bytes an underscore/lowercase transform would mangle |
| `x86/bloxor` | Not verified this pass | Present in the current module tree; no established public rank record found in this session's lookups — confirm locally |
| `x86/bmp_polyglot` | Not verified this pass | Bitmap-polyglot-style encoder; newer addition, confirm locally |
| `x86/service` | Not verified this pass | Newer addition; confirm locally |
| `x86/xor_poly` | Not verified this pass | Newer addition distinct from `xor_dynamic`; confirm locally |

**x64 encoders** (smaller set — 64-bit shellcode has historically had fewer bad-character/positional constraints driving encoder development):

| Encoder | Rank | Notes |
|---|---|---|
| `x64/xor_dynamic` | Normal | Dynamic-key XOR, 64-bit counterpart to the x86 version |
| `x64/xor_context` | Normal | Context-keyed XOR, 64-bit |
| `x64/zutto_dekiru` | Manual | `shikata_ga_nai`'s 64-bit sibling in spirit (polymorphic-style engine); rank per current listing, not individually re-verified this pass |
| `x64/xor` | Not verified this pass | Newer/simpler addition; confirm locally |

**Other-architecture encoder families** exist in the same `modules/encoders/` tree — `cmd/` (shell-command-context encoders), `generic/` (the `none` passthrough encoder plus a couple of generic transforms), `mipsbe/`, `mipsle/`, `php/`, `ppc/`, `riscv32le/`, `riscv64le/`, `ruby/`, `sparc/` — confirmed present via the same directory listing but **intentionally not deep-dived here**, consistent with this page's msfvenom/x86-x64-focused scope; they follow the same encode-a-buffer-behind-a-decoder-stub model described above, just for non-Windows/x86 target architectures.

## Evasion Modules — Brief Coverage (Deep Dive Deferred)

**What the module class is:** a Metasploit module type (`modules/evasion/`) introduced October 2018 that generates a file combining a payload with a specific, hand-engineered AV/EDR-evasion technique — output is always a locally-generated file (default `~/.msf4/local/`), never a network operation, and unlike `exploit` modules an evasion module never auto-starts a listener.

**How it structurally differs from encoders** (see [How It Works](#how-it-works) above for the full comparison): encoders are one generic, reusable **mutation engine** (`shikata_ga_nai`'s polymorphic transform) applied uniformly to any payload's bytes. Evasion modules are **individually engineered per-technique generators** — each module in `modules/evasion/windows/` or `modules/evasion/linux/` does something structurally different from its siblings, not a shared engine with parameters.

**Three named examples**, verified present in the current [`modules/evasion/windows/`](https://github.com/rapid7/metasploit-framework/tree/master/modules/evasion/windows) tree via this pass's directory-listing check:

- **`evasion/windows/windows_defender_exe`** — RC4-encrypts the embedded shellcode, compiles through a custom (non-default) compiler chain, and includes an anti-emulation check aimed at weaknesses in AV runtime scanning engines — per Rapid7's own module documentation.
- **`evasion/windows/applocker_evasion_regasm_regsvcs`** (one of five `applocker_evasion_*` modules, alongside `_install_util`, `_msbuild`, `_presentationhost`, `_workflow_compiler`) — generates output designed to run via a Microsoft-signed binary (`RegAsm.exe`/`RegSvcs.exe`) that AppLocker/software-restriction policies typically allow by default, a signed-binary-proxy-execution pattern (MITRE **T1218.009**) rather than a byte-obfuscation technique.
- **`evasion/windows/process_herpaderping`** — generates an executable using the process herpaderping technique (write payload to disk, map it into a process, then modify/overwrite the on-disk file before the mapped image is fully validated) to present a different file to disk-scanning AV than what actually executes.

**Deliberately not covered in this pass:** per-module internals (exact RC4 key handling, the specific anti-emulation checks, the herpaderping timing mechanics), the full `evasion/linux/` tree (confirmed to exist — `aarch64/`, `x64/`, `x86/` subfolders — but not enumerated), and a worked hands-on example beyond the single illustrative command in `02 - Hands-On Use Cases.md`. Extend this section first when this folder gets its follow-up pass.

## Quick Use-Case List

- Enumerating available encoders before building anything (`msfvenom -l encoders`, or `search type:encoder` in msfconsole)
- Basic `shikata_ga_nai` single-pass encoding for static-signature obfuscation of a generated payload
- Multiple-iteration encoding (`-i <count>`) — and knowing why it doesn't meaningfully help
- Alphanumeric-only encoding (`x86/alpha_mixed`/`alpha_upper`) for injection contexts that only tolerate printable characters
- Bad-character-driven automatic encoder selection (`-b`) for exploit-development shellcode — mechanics covered in `../msfvenom/02 - Hands-On Use Cases.md`, referenced here from the encoder-selection angle
- Context-keyed encoders (`x86/context_cpuid`/`context_stat`/`context_time`) for complicating static emulation specifically
- x64 payload encoding (`x64/zutto_dekiru`, `x64/xor_dynamic`) for 64-bit targets
- Chained multi-encoder pipelines (different encoder per pass) — mechanics in `../msfvenom/02 - Hands-On Use Cases.md`, revisited here for *why* an operator would pick different encoders per link in the chain
- Loading an encoder module directly inside msfconsole (`use encoder/...`, `generate`) instead of via the msfvenom CLI
- Generating an evasive Windows executable via `evasion/windows/windows_defender_exe` (brief coverage — see above)
- Generating an AppLocker-bypass payload via one of the `evasion/windows/applocker_evasion_*` modules (brief coverage — see above)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`, with the encoder half receiving full depth and the evasion half kept to one or two illustrative examples consistent with this page's stated scope.

## Prerequisites

| Requirement | Notes |
|---|---|
| Metasploit Framework installed | Encoders and evasion modules are both part of the core Framework install — no separate download, see `../00 - Metasploit Overview.md` |
| No target reachability required to *generate* | Both module types generate entirely locally — same as msfvenom, see `../msfvenom/01 - Overview.md`'s Prerequisites |
| Compatible architecture/platform | An encoder must match the payload's architecture (`x86` encoder for an `x86` payload, etc.) or generation fails outright — same constraint msfvenom enforces |
| A delivery mechanism, separately | Neither an encoder nor an evasion module delivers anything to a target — that's a separate step (manual transfer, a LOLBin, a phishing payload, etc.) |
| A matching listener, for reverse payloads | Same as any other payload — a `multi/handler` (or equivalent) must be reachable at the configured callback address once the generated file executes |
