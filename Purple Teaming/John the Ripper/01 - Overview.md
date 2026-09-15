# John the Ripper — Overview

> 🔴 **Red Flag Principle:** John the Ripper is an offline, single-process-focused password-hash cracker that **never touches the network** — it reads hashes from a file, performs cryptographic operations locally, and reports matches. Every execution is a completely local, forensically-auditable process with no authentication attempts or network probes of any kind. The signature is **local resource consumption (CPU, disk I/O, memory)** and the pot file (`john.pot`), not any network activity or target-host event.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`openwall/john`](https://github.com/openwall/john):

- **Primary author:** Alexander Peslyak (Solar Designer), founded the Openwall Project in 1998. John the Ripper's original development began in 1996; Openwall hosts the continued open-source maintenance.
- **License:** GPL v2+ (verified against LICENSE file in the repo). The project is community-driven with the "jumbo" branch containing contributions from dozens of developers.
- **Origin/Purpose:** Designed as a fast password cracker for detecting weak Unix passwords, particularly crypt(3)-based hashes. The tool has evolved to support hundreds of hash types across multiple platforms (Unix/Linux, macOS, Windows, DOS, BeOS, OpenVMS).
- **Current Status:** The bleeding-edge "jumbo" version (linked from the official GitHub) is actively maintained with regular commits, community contributions, and continuous CI testing. The classic "core" version (v1.9.0 stable) exists for minimalist deployments. Latest jumbo version tracked at `bleeding-jumbo` branch.
- **Key distinction:** Unlike Hashcat (GPU-focused, closed-source commercial roots), John the Ripper is purely CPU-focused (though recent jumbo builds support OpenCL for some formats), open-source-first, and designed for deep-dictionary and rule-based attacks over pure brute-force speed.
- **Installation:** Available via package manager (`apt install john`, `brew install john`) or built from source via `./configure && make`. Pre-built binaries available on GitHub releases.

## How It Works

John the Ripper is fundamentally a **state-machine password-candidate generator** driving a **format-specific hash validator**. Unlike network-based tools (Hydra, Spray365), it performs zero authentication attempts and never leaves the attacking host.

```
                    John the Ripper lifecycle
   ┌────────────────────────────────────────────────────────┐
   │  1. Read input hash file(s)                             │
   │     - Auto-detect format (DES, MD5, bcrypt, SHA-512...) │
   │     - Or use --format=explicit                          │
   │     - Load into in-memory hash table                    │
   │                                                          │
   │  2. Select cracking mode:                               │
   │     a) Single crack (login/GECOS data mangling)         │
   │     b) Wordlist (dictionary + optional rules)           │
   │     c) Incremental (brute-force with charset/grammar)  │
   │     d) Mask (structured password templates)             │
   │     e) Markov (statistical probability chains)          │
   │     f) External (custom C code generation)              │
   │     g) Loopback (pot file as wordlist + rules)          │
   │                                                          │
   │  3. Generate candidate passwords                        │
   │     - Feed each candidate to format's validator         │
   │     - Hash-table lookup (O(1) per candidate)            │
   │     - On match: record in john.pot, continue            │
   │                                                          │
   │  4. Optionally resume                                   │
   │     - Session saved to john.rec (binary checkpoint)     │
   │     - Auto-saved every 10 minutes + on clean exit       │
   │     - Recovery via --restore or --session=NAME          │
   └────────────────────────────────────────────────────────┘
```

**Critical mechanics for forensics:**

1. **The pot file (`john.pot`, default location `$JOHN/john.pot`)** — a plain-text file, one cracked password per line, in format `hash:password`. Every match is immediately appended; the file survives reboot and is never re-cracked on subsequent runs (integrity checked via hash comparison). This is the operator's **sole persistent record** of what was cracked across all sessions.

2. **Session state (`john.rec`, binary format)** — when interrupted (Ctrl-C), John writes a binary session file containing the mode, wordlist position, rule index, or incremental-mode position. Resume via `--restore` or `--session=NAME` picks up exactly where it left off. Auto-saved every 10 minutes for crash recovery; deleted on successful completion.

3. **Format auto-detection** — John can identify most common formats on-the-fly (crypt(3) variants, MD5, bcrypt, SHA-512, Windows NT hashes, Kerberos, etc.) without explicit `--format=` specification. Custom/uncommon formats require manual specification; the `--list=formats` option shows all compiled-in formats.

4. **Rules engine** — the real productivity lever. A rule file (loaded from `john.conf` sections like `[List.Rules:Wordlist]` or via `--rules=SECTION`) modifies each wordlist entry before hashing. Common rules: `T` (toggle case), `l` (lowercase all), `u` (uppercase all), `c` (capitalize first), `$` + character (append), `^` + character (prepend). Rules can be stacked with `--rules-stack`.

5. **Single crack mode** — scans the input for login/GECOS/home-directory names and mangles them with built-in rules; unusually fast for initially-populated passwd files. Automatically re-tests every cracked password against all other hashes.

6. **No network, no cleanup** — John leaves behind only the pot file and (optionally) session files. No temporary files, no network traces, no service registration. The attacking host's filesystem is the only artifact source.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Hash types supported | 300+ (core + jumbo): DES, MD5, bcrypt, scrypt, Argon2, SHA-1, SHA-256, SHA-512, crypt(3) variants, Windows LM/NT, Kerberos 5, PBKDF2, AES, RSA, DSA, ECDSA, PDF, ZIP, RAR, Office (DOCX, XLSX), KeePass, 1Password, and many more |
| Attack modes | Single crack, Wordlist (+rules), Incremental, Mask, Markov, External, Loopback, Regex, Subsets |
| Transport/Network | None — completely offline, all operations on local files |
| Character encoding | UTF-8, other encodings via `--encoding` |
| Session persistence | Binary `john.rec` checkpoint file (attacking host only); text `john.pot` password results |
| Parallelization | Single-process (not multi-threaded by default in core) — use `john-omp` or `--fork=N` (jumbo) for multi-CPU. Note: `--fork` parallelizes across CPU cores but all processes share one session file, requiring careful coordination |

**Format auto-detection (without `--format=`):**

John uses the `valid()` function, hash structure, and salt/iteration-count patterns to identify formats on-the-fly. For example:
- `$1$...$` prefix → MD5-crypt
- `$2a$...$` or `$2b$...$` → bcrypt
- `$5$...$` → SHA-256-crypt
- `$6$...$` → SHA-512-crypt
- `aad3...` (32 hex chars) → could be MD5, but depends on context; John tries multiple in order of likelihood

If auto-detection fails or you want to force a specific format (for optimization or certainty), use `--format=FORMAT`. The `--list=formats` option shows all available formats for the compiled binary.

## Command-Line Switches — Quick Reference

Verified live against the official `openwall/john` source and the help text (`john -h`, `john -?`).

| Switch | Plain-English meaning |
|---|---|
| `--wordlist=FILE` or `-w FILE` | Use FILE as a wordlist (one candidate per line). Requires `--rules` to enable mangling, otherwise tries passwords as-is. |
| `--rules[=SECTION]` or `-r [SECTION]` | Enable word mangling rules from config section `[List.Rules:SECTION]`, default is `[List.Rules:Wordlist]`. Can also pass inline rules: `--rules=:$1$2` to append "12" to each word. |
| `--incremental[=MODE]` or `-i [MODE]` | Brute-force mode using character set MODE. Pre-defined modes: `ASCII` (95 chars), `LowerNum` (36 chars), `Lower` (26 chars), `Digits` (10 chars), etc. Requires `.chr` charset file for length statistics. |
| `--mask=MASK` | Structured password template, e.g., `pass?d?d` tries "pass00" through "pass99". Modes: `?a`=all, `?l`=lower, `?u`=upper, `?d`=digit, `?s`=symbol, `?w`=word-char. Can stack with other modes (hybrid). |
| `--markov[=LEVEL]` | Markov-mode brute-force using statistical character-pair frequencies from `$JOHN/john.pot`. LEVEL 0–300 controls aggressiveness; higher = slower but more likely passwords. |
| `--external=MODE` or `-e MODE` | Use custom C code from `[List.External:MODE]` in config to generate candidate passwords. Powerful but slow. |
| `--single` or `-s` | "Single crack" mode using login/GECOS names as candidates. Fastest mode for typical /etc/passwd files. |
| `--loopback[=FILE]` | Use `.pot` file as wordlist (extract password part only, suppress duplicates). Re-apply rules to previously-cracked passwords for further mangling. |
| `--format=FORMAT` | Force hash format (e.g., `md5crypt`, `bcrypt`, `sha512crypt`, `nt` for Windows NT). Use `--list=formats` to see all available formats. |
| `--session=NAME` | Name the session; John writes `NAME.rec` for resume and `NAME.log` for logging. Allows parallel runs with separate session tracking. |
| `--restore[=NAME]` | Resume a previous session from `NAME.rec` or `$JOHN/john.rec`. Continue from exact stopping point. |
| `--pot=FILE` | Override default pot file path (`$JOHN/john.pot`). John never re-cracks hashes found in the pot file, checking by hash comparison. |
| `--show[=left]` | Print cracked passwords (from pot) for given hash files. `--show=left` prints uncracked hashes instead. |
| `--test[=TIME]` | Run self-tests and benchmarks for all formats (or `--format=` specific). Good for baseline performance assessment. |
| `--fork=N` | (Jumbo only) Run N parallel processes on the same session. All processes share `john.rec` state file; not suitable for distributed setups. |
| `--max-length=N` | Reject candidate passwords longer than N characters (not truncate, unlike some tools). |
| `--min-length=N` | Reject candidate passwords shorter than N characters. |
| `--skip-self-tests` | Skip format self-tests on startup (speeds up very short attacks). |
| `--list=encodings` | List supported character encodings for `--encoding`. |
| `--encoding=NAME` | Use encoding NAME (e.g., `UTF-8`, `cp1252`) for candidate generation. Useful for international password cracking. |
| `--rules-skip-nop` | Skip no-op rules (optimization for rerunning with rules after a wordlist-only pass). |
| `--config=FILE` | Use alternate config file instead of `john.conf`. |
| `--save-memory` or `--mem-saving-level=N` | Reduce memory usage (useful for hash formats with large per-hash state, e.g., bcrypt). Slows down performance. |
| `--verbose` or `-v` | Print candidate passwords as they're tried (very verbose, slows down cracking). |
| `--log-stderr` | Log output to stderr instead of file. |

**Special switches for format discovery:**
- `--list=formats` — show all compiled-in formats (hundreds in jumbo)
- `--list=rules` — show all rule sections in config
- `--list=external` — show all external-mode functions in config
- `--show=formats` — parse input file and show detected formats/hash types

## Quick Use-Case List

1. **Single-crack baseline on /etc/passwd** — fastest for initially-populated shadow files; uses login/GECOS mangling
2. **Wordlist + best64 rules** — de facto standard: dictionary attack with 64 best-performing rules
3. **Incremental mode (ASCII)** — full brute-force when other modes exhaust (slow, thorough)
4. **Mask mode for known patterns** — e.g., `Password?d?d?d` when you know users add 3 digits
5. **Hybrid mask + wordlist** — e.g., wordlist as base, then append 2 digits via mask (`?w?d?d`)
6. **Rules stacking (rules + rules-stack)** — apply two rule sets sequentially for deeper mangling
7. **Format-specific optimization** — e.g., `--format=md5crypt --fork=4` on multicore for faster MD5-crypt
8. **Markov-mode attack** — probabilistic keyspace exploration, good for middle-ground keyspace sizes
9. **External-mode custom generator** — hand-rolled password logic (e.g., "all 4-letter words + 2-digit suffix")
10. **Loopback attack** — re-apply rules to previously-cracked pot-file passwords for iterative refinement
11. **Credential-format chaining** — crack online-obtained hashes (e.g., from `Hashcat/`), then test same passwords against different hash types
12. **Distributed multi-session cracking** — run multiple `--session=NAME1/2/3` instances in parallel on same machine; combine results via loopback

## Prerequisites

- **Hash input file** — one hash per line; format auto-detected or specified via `--format=`. Can be multiple files (John merges them).
- **Wordlist** (for wordlist mode) — plain-text file, one candidate per line. Public wordlists: `rockyou.txt`, CrackStation wordlist, SecLists, custom wordlists per organization.
- **Rules config** (optional, for wordlist mode) — included in default `john.conf`; can use `--rules=` inline or load custom sections.
- **Charset file** (for incremental mode) — `.chr` files bundled with John (e.g., `ASCII.chr`, `LowerNum.chr`). Can generate custom charset from pot file via `--make-charset=FILE`.
- **CPU availability** — single-process by default (use `john-omp` executable or `--fork=N` for multi-core). No GPU acceleration in core builds; jumbo builds support OpenCL on some formats.
- **Disk space** — pot file can grow large (one line per cracked hash); session file is binary and small (~MB). Large wordlist files (500 MB+ common).
- **No authentication required** — completely offline, all operations local.
