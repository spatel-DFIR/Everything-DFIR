# Hashcat — Overview

> 🔴 **Red Flag Principle:** Hashcat runs **entirely offline, on the operator's own compute, against hash material that was already exfiltrated by some other tool** — it never touches the target host, sends it a single packet, or opens a session against it. There is no "hashcat traffic" to catch on the wire and no hashcat-specific event log entry to hunt for on the victim. The single most distinctive fact about this tool, forensically, is therefore **where the evidence isn't**: `04 - Target Evidence.md` in this folder is deliberately thin, because the real evidentiary weight of a hashcat-cracked credential sits entirely in the tool that captured the hash in the first place (`Mimikatz/`, `Responder/`, Impacket's `secretsdump.py`/`GetUserSPNs.py`) and in whatever the operator does *after* cracking — reusing a recovered password against a real target, which lands back in standard authentication logs.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Hashcat was originally written by **Jens "atom" Steube**, first released in **2009** as a CPU-only password recovery tool, built partly as a way to explore then-emerging GPGPU (general-purpose GPU) computing. Two GPU-accelerated forks followed on a separate, **closed-source** codebase — `oclHashcat` (AMD/OpenCL) and `cudaHashcat` (NVIDIA/CUDA) — while the original CPU tool continued in parallel.

Verified against the project's own [`docs/changes.txt`](https://github.com/hashcat/hashcat/blob/master/docs/changes.txt) and public reporting at the time:

- **December 2015** — Steube released the source for both hashcat and oclHashcat under the **MIT license**, ending years as closed-source freeware (reported by [SecurityWeek](https://www.securityweek.com/password-cracking-tool-hashcat-goes-open-source/) and [Kaspersky Securelist](https://securelist.com/stepping-out-of-the-dark-hashcat-went-opensource/72993/)).
- **v3.00** — the CPU-only `hashcat` and the GPU-only `oclHashcat`/`cudaHashcat` branches were **merged into a single unified `hashcat` codebase** with OpenCL as the common backend. The old CPU-only tool was renamed `hashcat-legacy` and no longer receives feature development.
- **v6.2.0** — added attack-mode **9, Association Attack** (aka "Context Attack"), for attacking hashes that carry an associated per-hash "hint" (see [How It Works](#how-it-works)).
- **v7.0.0** — added HIP backend support for AMD GPUs and a Metal backend for Apple Silicon/macOS, plus the "Assimilation Bridge" (an embedded interpreter framework letting hash-mode plugins call out to external languages, e.g. Python, for hash types that don't map cleanly onto GPU kernels), alongside 80+ new hash modes.
- **v7.1.2** — current stable release verified against at the time of writing; this note's flag syntax, hash-mode numbers, and default paths are checked against the `master` branch and the current stable tag as of this writing, not against memory or older cheat sheets.

Canonical upstream repository: [`github.com/hashcat/hashcat`](https://github.com/hashcat/hashcat), MIT-licensed, project lead Jens Steube ([`@jsteube`](https://github.com/jsteube)). Primary documentation lives at the separate [hashcat wiki](https://hashcat.net/wiki/).

**Correction worth flagging explicitly:** many older cheat sheets and blog posts reference `rules/best64.rule` as hashcat's canonical "quick win" rule file. Verified against the current `rules/` directory in the official repo, **that file no longer exists under that name** — it was renamed/expanded to **`rules/best66.rule`**. Scripts or muscle-memory commands that hardcode `best64.rule` will fail against a current hashcat checkout.

## How It Works

Hashcat is a **candidate-generation-and-comparison engine**, not a protocol tool. At its core it does three things in a loop, accelerated across whatever compute backend is available:

1. **Generate password candidates** according to the chosen **attack mode** (`-a`) — straight from a wordlist, mask-based brute force, a combination of wordlists, or hybrid variants (see [Techniques/Protocols Used](#techniques--protocols-used)).
2. **Run each candidate through the target hash algorithm's kernel** — a hand-optimized implementation of the specific algorithm (NTLM/MD4, NetNTLMv2/HMAC-MD5, Kerberos RC4-HMAC, bcrypt, etc.) selected by `-m`, compiled to run on the backend device (GPU via OpenCL/CUDA/HIP/Metal, or CPU).
3. **Compare the computed hash against the target hash list.** A match is written to the **potfile** (and optionally `-o`'s outfile) and the candidate is removed from further consideration for that hash.

```
┌─────────────────┐      ┌──────────────────┐      ┌───────────────────┐
│ Attack-mode      │      │ Hash-mode kernel  │      │ Target hash list   │
│ candidate         │────▶│ (algorithm-        │────▶│ (loaded once,       │
│ generator          │      │ specific compute)  │      │ compared per         │
│ (-a 0/1/3/6/7/9)   │      │ (-m NNNN)          │      │ candidate)           │
└─────────────────┘      └──────────────────┘      └─────────┬─────────┘
                                                                       │ match
                                                                       ▼
                                                     ┌───────────────────┐
                                                     │ hashcat.potfile    │
                                                     │ (+ -o outfile,      │
                                                     │   console output)   │
                                                     └───────────────────┘
```

**Attack modes** (`-a`) determine *how* candidates are generated, not what's being cracked:

- **`-a 0` Straight** — candidates come one-for-one from a wordlist (optionally transformed by `-r` rules).
- **`-a 1` Combination** — every word from wordlist A concatenated with every word from wordlist B.
- **`-a 3` Brute-force/Mask** — candidates generated from a **mask** (a per-position character-class template, e.g. `?u?l?l?l?l?l?d?d`) rather than a wordlist at all.
- **`-a 6` Hybrid Wordlist + Mask** — each wordlist word with a mask-generated suffix appended (`word` + `?d?d?d?d`).
- **`-a 7` Hybrid Mask + Wordlist** — a mask-generated prefix followed by each wordlist word (`?d?d?d?d` + `word`).
- **`-a 9` Association** — added in v6.2.0; each hash in the list carries an associated per-hash "hint" (e.g. a username or salt-adjacent context string) and hashcat tries candidates against *only* the hash(es) tied to that hint rather than the whole candidate stream against every hash — used by hash-mode plugins that model this relationship (e.g. cracking a hash where the username itself is a strong candidate seed).

**Hash-mode plugins** (`modules/` in the source tree, selected by `-m`) are what make hashcat generic across 300+ algorithms — each is a small C module (or, since v7.0, an Assimilation Bridge script) that defines the algorithm's parsing rules, salt handling, and the actual compute kernel. This is why hash-mode **numbers must be exact** — `-m 1000` and `-m 5600` are unrelated algorithms that happen to both originate from Windows authentication, and guessing a nearby number silently targets the wrong algorithm.

**Rule engines** (`-r`) apply a small mangling language (append/prepend/case-toggle/leetspeak/etc., one rule per line in a `.rule` file) to every wordlist candidate before it's hashed — this is how a 14M-word list like `rockyou.txt` becomes billions of realistic candidates without hashcat having to store them all in memory at once; rules are expanded and discarded on the fly per-candidate.

**Session/restore state**: every run writes a `.restore` checkpoint file (named after `--session`, default session name `hashcat`) periodically during execution, letting a killed or paused run resume from roughly where it left off with `--restore` rather than restarting the keyspace from zero — critical for mask/brute-force jobs that can run for days.

## Techniques / Protocols Used

Hashcat isn't network-protocol-driven the way most tools in this repo are — its "protocol" surface is the compute backend and the hash-algorithm implementations it ships.

| Layer | Detail |
|---|---|
| Compute backends | OpenCL (cross-vendor), CUDA (NVIDIA-specific, generally faster on NVIDIA hardware when available), HIP (AMD, added v7.0), Metal (Apple Silicon/macOS, added v7.0), and plain CPU fallback |
| Hash-mode plugin architecture | `modules/` — one plugin per algorithm/mode number, defining parsing, salting, and the GPU/CPU kernel; 300+ shipped as of the current release, with the "Assimilation Bridge" (v7.0+) allowing plugins to shell out to an embedded interpreter for algorithms that don't map cleanly to GPU kernels |
| Attack-mode candidate generators | Straight (`-a 0`), Combination (`-a 1`), Brute-force/Mask (`-a 3`), Hybrid Wordlist+Mask (`-a 6`), Hybrid Mask+Wordlist (`-a 7`), Association (`-a 9`) |
| Rule engine | A dedicated mangling mini-language (`-r`, `.rule` files) — case toggling, char insertion/deletion, leetspeak substitution, reversal, duplication, and 30+ other primitives, stackable up to 31 functions per rule line |
| Mask/keyspace definition | Built-in charsets `?l ?u ?d ?s ?a ?h ?H ?b`, user-defined custom charsets (`-1`/`-2`/`-3`/`-4`), `.hcmask` files for scripting multiple masks with per-mask custom charsets |
| Distributed cracking | `--brain` server/client mode (deduplicates candidates already tried across a fleet of hashcat clients working the same job), or manual keyspace splitting via `-s`/`-l` (skip/limit) across independently-launched instances |
| Credential material it consumes | Any of 300+ supported hash types — this repo's cross-links focus on **NTLM** (`-m 1000`), **NetNTLMv1/v2** (`-m 5500`/`-m 5600`), and **Kerberos 5 RC4-HMAC (etype 23) TGS-REP/AS-REP** (`-m 13100`/`-m 18200`), since those are what `Mimikatz/`, `Responder/`, and Impacket's `secretsdump.py`/`GetUserSPNs.py` in this repo actually produce |

## Command-Line Switches — Quick Reference

Verified against the official [`hashcat/hashcat`](https://github.com/hashcat/hashcat) repository's `--help` output and the [hashcat.net wiki](https://hashcat.net/wiki/doku.php?id=hashcat) as of v7.1.2. This is not exhaustive (hashcat has 150+ flags) — it covers everything referenced in `02 - Hands-On Use Cases.md`.

**Core — required for every run**

| Switch | Plain-English meaning |
|---|---|
| `-m, --hash-type=NUM` | Which algorithm the target hash list uses (e.g. `1000` = NTLM). **Must be exact** — see [How It Works](#how-it-works) |
| `-a, --attack-mode=NUM` | How candidates are generated (`0` Straight is the default if omitted) |
| *(positional)* | Hash file (or single hash string) as the first positional argument, followed by wordlist(s)/mask(s) as needed by the attack mode |

**Wordlist & rules**

| Switch | Plain-English meaning |
|---|---|
| `-r, --rules-file=FILE` | Apply every rule in a `.rule` file to every wordlist candidate (repeatable — combine multiple rule files) |
| `-j, --rule-left=RULE` | Apply a single inline rule to the left wordlist (used with `-a 1` combination attacks) |
| `-k, --rule-right=RULE` | Same, for the right wordlist |
| `-g, --generate-rules=NUM` | Generate NUM random rules on the fly instead of reading a `.rule` file |

**Mask / brute-force**

| Switch | Plain-English meaning |
|---|---|
| `-1, -2, -3, -4` (`--custom-charset1`–`4`) | Define a custom charset referenced as `?1`–`?4` in a mask |
| `-i, --increment` | Try every mask length from the minimum up to the mask's full length, instead of only the exact length specified |
| `--increment-min=NUM` / `--increment-max=NUM` | Bound the increment range |
| `--hex-charset` | Treat a custom charset definition as hex-encoded bytes rather than literal characters |

**Session, restore, and output**

| Switch | Plain-English meaning |
|---|---|
| `--session=NAME` | Name this run for restore/status purposes (default `hashcat`) |
| `--restore` | Resume a previous run from its `.restore` checkpoint file, matched by `--session` name |
| `--restore-file-path=FILE` | Explicit path to a `.restore` file, overriding the default session-name-derived location |
| `--restore-disable` | Don't write a `.restore` checkpoint at all (useful for short, disposable runs; means an interrupted run can't resume) |
| `-o, --outfile=FILE` | Write cracked `hash:plaintext` pairs to a file as they're found, in addition to the potfile |
| `--outfile-format=NUM` | Controls which fields (hash, plain, hex-plain, crack-position, etc.) get written to the outfile |
| `--potfile-path=FILE` | Use a non-default potfile location |
| `--potfile-disable` | Don't read/write a potfile for this run at all |
| `--show` | Don't crack — just compare the given hash list against the potfile and print already-cracked matches |
| `--left` | Inverse of `--show` — print hashes from the list that are **not** in the potfile (i.e. still uncracked) |
| `--username` | Strip a leading `username:` field from each line of the hash file before parsing (needed for formats like secretsdump's pwdump output that prefix the hash with an account name) |
| `--remove` | Delete each hash from the input hash file once it's cracked |
| `--stdout` | Don't hash or compare at all — just print generated candidates to stdout (used to feed candidates into another tool, or to sanity-check a mask/rule combination before committing GPU time to it) |

**Performance / device selection**

| Switch | Plain-English meaning |
|---|---|
| `-b, --benchmark` | Run hashcat's built-in benchmark for the default set of common hash modes |
| `--benchmark-all` | Benchmark **every** supported hash mode, not just the common subset |
| `-O, --optimized-kernel-enable` | Use faster, optimized compute kernels — trade-off is a **lower maximum supported password length** (varies by algorithm, commonly 27-55 chars) since the optimized kernels use fixed-size register allocations |
| `-w, --workload-profile=NUM` | `1`=Low, `2`=Default, `3`=High, `4`=Nightmare — how aggressively hashcat claims the GPU (higher = faster cracking, less usable desktop simultaneously) |
| `-d, --backend-devices=STR` | Comma-separated list of backend device IDs to use (for multi-GPU rigs, or to exclude a device) |
| `-s, --skip=NUM` / `-l, --limit=NUM` | Skip the first NUM candidates / stop after NUM candidates — the manual mechanism for splitting one keyspace across multiple independently-launched hashcat instances (distributed cracking without `--brain`) |

**Misc**

| Switch | Plain-English meaning |
|---|---|
| `--status` | Enable automatic periodic status-screen updates during a run (useful when output is piped/logged rather than watched interactively) |
| `--status-timer=NUM` | Seconds between status updates |
| `--logfile-disable` | Disable hashcat's own logfile for this run |
| `--hex-salt` / `--hex-wordlist` | Treat the salt field / wordlist entries as hex-encoded rather than literal |

## Quick Use-Case List

- Straight/dictionary attack against a wordlist (`-a 0`)
- Rule-based attack layering mangling rules onto a wordlist (`-r`)
- Combinator attack concatenating two wordlists (`-a 1`)
- Brute-force/mask attack with no wordlist at all (`-a 3`)
- Hybrid wordlist+mask and mask+wordlist attacks (`-a 6`/`-a 7`)
- Association attack for hint-tied hash types (`-a 9`)
- Cracking NTLM hashes pulled from `Impacket/secretsdump/` or `Mimikatz/lsadump (DCSync)/` output
- Cracking captured NetNTLMv2 hashes from `Responder/`-poisoned segments
- Cracking Kerberoasted TGS-REP tickets (`-m 13100`) — planned cross-link: `Impacket/GetUserSPNs (Kerberoasting)/`
- Cracking AS-REP-roasted tickets from accounts without Kerberos pre-auth (`-m 18200`)
- Password-policy-aware mask cracking using `.hcmask` files scoped to a known complexity policy
- Benchmarking hardware before committing to a long-running job (`-b`)
- Session management and resuming an interrupted multi-day job (`--session`/`--restore`)
- Distributed/multi-GPU cracking, either via `--brain` server/client or manual `-s`/`-l` keyspace splitting
- Filtering a hash list into cracked vs. still-uncracked subsets (`--show`/`--left`)
- Chained workflow: capture (Responder/Mimikatz/secretsdump) → crack (hashcat) → reuse the recovered credential in a separate lateral-movement tool

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Compute hardware | A GPU is not strictly required (CPU-only cracking works) but is the entire point of using hashcat over a slower CPU-only cracker — practical throughput for anything beyond trivial wordlists assumes a discrete GPU with current OpenCL/CUDA/HIP/Metal drivers installed |
| Already-captured hash material | Hashcat cracks hashes, it does not obtain them — every use case here assumes the hash was already dumped/captured by a separate tool (`Mimikatz/`, `Responder/`, `secretsdump.py`, `GetUserSPNs.py`, etc.) |
| Correct hash-mode number | The operator must know (or correctly identify via `--identify` or manual inspection of the hash's format) which `-m` value matches the captured material — an incorrect mode either errors out immediately (format mismatch) or, worse, silently cracks nothing while burning compute time |
| Wordlists/rules/masks appropriate to the target | Cracking success is bounded by candidate quality, not just GPU speed — a well-chosen rule set (e.g. `best66.rule`) or a mask scoped to a known password policy dramatically outperforms brute-forcing the full keyspace blind |
| For distributed/multi-GPU cracking | Either multiple GPUs in one host (`-d`) or multiple hosts coordinated via `--brain` server/client or manually via `-s`/`-l` keyspace splitting |
| Privileges | No special privileges required beyond normal user access to the GPU device — unlike most tools in this repo, hashcat does not need administrator/root on the machine it runs on (device access permissions aside) |
