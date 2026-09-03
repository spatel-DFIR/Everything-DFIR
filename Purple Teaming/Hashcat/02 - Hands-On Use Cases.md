# Hashcat — Hands-On Use Cases

Every scenario below assumes the hash material was already captured by a separate tool — hashcat's job starts once a hash file exists on the operator's own machine. **MITRE ATT&CK T1110.002 (Brute Force: Password Cracking)** applies to every cracking scenario in this file as the baseline technique; scenario-specific additional IDs are called out where the *source* of the hash material carries its own technique (Kerberoasting, AS-REP Roasting) distinct from the cracking step itself.

## Contents
- [Straight/Dictionary Attack](#straightdictionary-attack)
- [Rule-Based Attack Against a Wordlist](#rule-based-attack-against-a-wordlist)
- [Combinator Attack](#combinator-attack)
- [Brute-Force/Mask Attack](#brute-forcemask-attack)
- [Hybrid Wordlist + Mask and Mask + Wordlist Attacks](#hybrid-wordlist--mask-and-mask--wordlist-attacks)
- [Association Attack](#association-attack)
- [Cracking NTLM Hashes from secretsdump/DCSync Output](#cracking-ntlm-hashes-from-secretsdumpdcsync-output)
- [Cracking NetNTLMv2 Hashes Captured by Responder](#cracking-netntlmv2-hashes-captured-by-responder)
- [Cracking Kerberoasted TGS-REP Tickets](#cracking-kerberoasted-tgs-rep-tickets)
- [Cracking AS-REP-Roasted Tickets](#cracking-as-rep-roasted-tickets)
- [Password-Policy-Aware Mask Cracking with .hcmask Files](#password-policy-aware-mask-cracking-with-hcmask-files)
- [Benchmarking Hardware](#benchmarking-hardware)
- [Session Management and Restore/Resume](#session-management-and-restoreresume)
- [Distributed / Multi-GPU Cracking](#distributed--multi-gpu-cracking)
- [Filtering Cracked vs. Uncracked Hashes](#filtering-cracked-vs-uncracked-hashes)
- [Chained Workflow — Capture to Crack to Reuse](#chained-workflow--capture-to-crack-to-reuse)

---

## Straight/Dictionary Attack

**MITRE ATT&CK:** T1110.002

```bash
hashcat -m 1000 -a 0 ntlm_hashes.txt rockyou.txt
```

The baseline case — every candidate comes one-for-one from `rockyou.txt` (or any wordlist), hashed with the NTLM (`-m 1000`) kernel and compared against every hash in `ntlm_hashes.txt`. `-a 0` is the default attack mode if `-a` is omitted entirely. This is the first thing to try against any hash list before reaching for anything more expensive — it's fast and catches every password that's simply a real word/name/known-breach password with no modification.

## Rule-Based Attack Against a Wordlist

**MITRE ATT&CK:** T1110.002

```bash
hashcat -m 1000 -a 0 ntlm_hashes.txt rockyou.txt -r rules/best66.rule
```

`-r` layers hashcat's mangling mini-language on top of every wordlist word before hashing — case toggling, digit/symbol appending, leetspeak substitution, truncation, and more, all defined declaratively in a `.rule` file. `rules/best66.rule` ships with the tool (verified against the current `rules/` directory — see the correction in `01 - Overview.md`'s History: older guides reference a `best64.rule` that no longer exists under that name). This single flag is usually the highest-value addition to any dictionary attack, since real-world password policies push users toward exactly the kind of small mutations (`Summer2024!` from `summer`) that a rule file systematically generates.

## Combinator Attack

**MITRE ATT&CK:** T1110.002

```bash
hashcat -m 1000 -a 1 ntlm_hashes.txt wordlist1.txt wordlist2.txt
```

`-a 1` concatenates every word from `wordlist1.txt` with every word from `wordlist2.txt` (no separator by default) — e.g. `wordlist1` containing months and `wordlist2` containing years produces `january2024`, `february2024`, etc. `-j`/`-k` can apply a single inline rule to the left/right wordlist respectively (e.g. `-j c` to capitalize the left word) without needing a full rule file.

## Brute-Force/Mask Attack

**MITRE ATT&CK:** T1110.002

```bash
# Fixed 8-character mask: uppercase, 5 lowercase, 2 digits
hashcat -m 1000 -a 3 ntlm_hashes.txt ?u?l?l?l?l?l?d?d

# Same, but try every length from 1 up to the mask's length
hashcat -m 1000 -a 3 -i ntlm_hashes.txt ?a?a?a?a?a?a?a?a
```

`-a 3` abandons wordlists entirely and generates candidates directly from a **mask** — a per-position template using built-in charsets (`?l` lowercase, `?u` uppercase, `?d` digit, `?s` special, `?a` = all four combined, `?h`/`?H` hex, `?b` all byte values). `-i`/`--increment` (with optional `--increment-min`/`--increment-max`) tries every mask length up to the full mask rather than only the exact length given — useful when password length isn't known but an upper bound is assumed. This is the most GPU-time-expensive attack mode; it's a last resort after dictionary/rule/combinator approaches have been exhausted, or a first resort when the operator has independent knowledge of a password policy (see [Password-Policy-Aware Mask Cracking](#password-policy-aware-mask-cracking-with-hcmask-files)).

## Hybrid Wordlist + Mask and Mask + Wordlist Attacks

**MITRE ATT&CK:** T1110.002

```bash
# -a 6: wordlist word, then a 4-digit mask suffix (word2024, word0000...word9999)
hashcat -m 1000 -a 6 ntlm_hashes.txt wordlist.txt ?d?d?d?d

# -a 7: a 4-digit mask prefix, then a wordlist word
hashcat -m 1000 -a 7 ntlm_hashes.txt ?d?d?d?d wordlist.txt
```

Splits the difference between dictionary and mask attacks — a realistic base word from a wordlist combined with a bounded brute-forced prefix or suffix (commonly a year, a short PIN, or a symbol+digit tail matching a password-policy requirement). `-a 6` appends the mask; `-a 7` prepends it. Far cheaper than a full mask attack over the same total length, since the wordlist supplies the "realistic" portion of the password and only the small mask segment gets brute-forced.

## Association Attack

**MITRE ATT&CK:** T1110.002

```bash
hashcat -m 22000 -a 9 wpa_hashes_with_essid_hints.hc22000
```

`-a 9`, added in hashcat v6.2.0, is for hash types whose plugin models a per-hash "hint" — a piece of context tied to one specific hash rather than the whole candidate stream (e.g. an SSID/ESSID embedded in a WPA capture, or a username embedded alongside a hash format that supports it). Candidates are tried only against the hash(es) carrying the matching hint rather than blindly against the entire hash list, which both improves accuracy and avoids false positives that a context-blind attack mode could produce. Not every hash mode supports association-attack semantics — check the specific mode's plugin documentation before assuming `-a 9` is available for it.

## Cracking NTLM Hashes from secretsdump/DCSync Output

**MITRE ATT&CK:** T1110.002 — cracking; the hash itself originates from **T1003.006** (OS Credential Dumping: DCSync) or **T1003.002** (Security Account Manager) depending on source

```bash
# secretsdump.py / DCSync output is pwdump-format:
# username:RID:LMhash:NThash:::
# hashcat -m 1000 wants only the NT hash column — either pre-strip it,
# or pass --username to have hashcat discard everything before the last field
hashcat -m 1000 --username ntlm_dump.txt rockyou.txt -r rules/best66.rule
```

Planned cross-link: `Impacket/secretsdump/` (not yet built in this repo — DCSync/SAM/LSA-secrets dumping mechanics live there once written). Today, cross-link to `Mimikatz/lsadump (DCSync)/` for how this hash material is actually obtained on the target side — that folder's `04 - Target Evidence.md` is where the *acquisition* of this hash is forensically visible, not here. `--username` matters here specifically because pwdump-format output prefixes each hash line with an account name that `-m 1000` doesn't otherwise expect.

## Cracking NetNTLMv2 Hashes Captured by Responder

**MITRE ATT&CK:** T1110.002 — cracking; the hash itself originates from **T1557.001** (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay)

```bash
hashcat -m 5600 logs/SMB-NTLMv2-Client-10.10.10.44.txt rockyou.txt -r rules/best66.rule
```

Directly chains off `Responder/02 - Hands-On Use Cases.md`'s "Cracking Captured Hashes Offline" scenario — this is the same command, documented here in full since Responder's own page only summarizes it. NetNTLMv2 is challenge-salted per capture session (`Responder.conf`'s `Challenge = Random` default), so unlike a raw NTLM hash, **rainbow tables don't apply** — every NetNTLMv2 hash must be cracked independently against the wordlist/rule combination, which is meaningfully slower than `-m 1000`.

## Cracking Kerberoasted TGS-REP Tickets

**MITRE ATT&CK:** T1110.002 — cracking; the hash itself originates from **T1558.003** (Steal or Forge Kerberos Tickets: Kerberoasting)

```bash
hashcat -m 13100 kerberoast_tgs.txt rockyou.txt -r rules/best66.rule
```

Mode `13100` is **Kerberos 5, etype 23, TGS-REP** — the RC4-HMAC-encrypted portion of a service ticket requested for any account with a Service Principal Name (SPN) set, crackable offline because the ticket is encrypted with a key derived from the service account's own password. See `Impacket/GetUserSPNs (Kerberoasting)/02 - Hands-On Use Cases.md` for requesting the tickets in the first place; this page only covers cracking a `$krb5tgs$23$...`-formatted ticket once obtained. AES-encrypted tickets (etype 17/18, hashcat modes `19600`/`19700`) are also possible where the target account enforces `msDS-SupportedEncryptionTypes` = AES-only — verified against `Impacket/GetUserSPNs (Kerberoasting)/01 - Overview.md`, not yet documented in this file's own mode table. Service accounts are disproportionately valuable Kerberoast targets because they're frequently configured with old, never-rotated, weak passwords and elevated privileges.

## Cracking AS-REP-Roasted Tickets

**MITRE ATT&CK:** T1110.002 — cracking; the hash itself originates from **T1558.004** (Steal or Forge Kerberos Tickets: AS-REP Roasting)

```bash
hashcat -m 18200 asrep_hashes.txt rockyou.txt -r rules/best66.rule
```

Mode `18200` is **Kerberos 5, etype 23, AS-REP** — obtainable, without any prior credentials, against any account that has **Kerberos pre-authentication disabled** (`DONT_REQ_PREAUTH` `userAccountControl` flag). Impacket's `GetNPUsers.py` is the common tool for requesting these tickets against a domain's unauthenticated accounts; no dedicated folder for it exists yet in this repo's Impacket tree, so cross-link is deferred until it's built. Distinct from Kerberoasting in that it targets a specific, often-misconfigured account property rather than every SPN-bearing account, and requires zero authentication to trigger.

## Password-Policy-Aware Mask Cracking with .hcmask Files

**MITRE ATT&CK:** T1110.002

```bash
# Ships with hashcat — every permutation of an 8-char password containing
# exactly 1 uppercase, 1 lowercase, 5 digits, and 1 special character,
# i.e. a common Windows complexity-policy shape
hashcat -m 1000 -a 3 ntlm_hashes.txt masks/8char-1l-1u-1d-1s-compliant.hcmask
```

`.hcmask` files (one mask per line, optionally with per-mask custom charsets) let an operator encode independent knowledge of a target's password policy directly into the keyspace searched, instead of guessing a single fixed mask or brute-forcing blind. `masks/8char-1l-1u-1d-1s-compliant.hcmask` ships in the official repo's `masks/` directory and enumerates every character-class-position permutation that satisfies an 8-character/4-class complexity requirement — exactly the shape many enterprise password policies mandate, which makes this file disproportionately effective against organizations that only enforce complexity, not length or dictionary-word exclusion.

## Benchmarking Hardware

**MITRE ATT&CK:** Not applicable — operational/planning step, not an attack technique

```bash
hashcat -b
hashcat -b -m 1000       # benchmark one specific mode only
hashcat --benchmark-all  # benchmark every supported hash mode
```

Run before committing to a long job — reports hashes/second per algorithm on the current hardware/backend configuration, letting an operator estimate realistic runtime for a mask attack's full keyspace before spending days of GPU time on it. Also useful as a smoke test that OpenCL/CUDA/HIP/Metal drivers are correctly detecting all installed compute devices.

## Session Management and Restore/Resume

**MITRE ATT&CK:** Not applicable — operational step

```bash
# Start a long-running job under a named session
hashcat -m 1000 -a 3 -i --session corp_ntlm_20260802 ntlm_hashes.txt ?a?a?a?a?a?a?a?a

# ...interrupted (Ctrl+C, reboot, VPN drop) — resume exactly where it left off
hashcat --session corp_ntlm_20260802 --restore
```

Every run periodically writes a `.restore` checkpoint file (see `03 - Source Evidence.md` for its default location) named after `--session`. `--restore-disable` skips writing this file entirely for short, disposable jobs where resumability isn't worth the I/O overhead; `--restore-file-path` points at a non-default restore-file location if needed. For a multi-day mask/brute-force job against a large keyspace, session naming discipline (one session per hash list/attack combination) is what makes resuming after any interruption practical.

## Distributed / Multi-GPU Cracking

**MITRE ATT&CK:** T1110.002 — same technique, scaled

```bash
# Single host, multiple GPUs — hashcat auto-splits the keyspace across
# all detected devices unless -d restricts it
hashcat -m 1000 -a 3 ntlm_hashes.txt ?a?a?a?a?a?a?a?a -d 1,2,3,4

# Manual keyspace split across independently-launched instances on
# separate hosts (no shared state) — host A takes the first half:
hashcat -m 1000 -a 3 ntlm_hashes.txt ?a?a?a?a?a?a?a?a -s 0 -l 50000000000

# Host B takes the second half:
hashcat -m 1000 -a 3 ntlm_hashes.txt ?a?a?a?a?a?a?a?a -s 50000000000 -l 50000000000

# Or: hashcat's own brain server/client mode, which deduplicates candidates
# already tried across every connected client automatically
hashcat --brain-server
hashcat -m 1000 -a 0 ntlm_hashes.txt rockyou.txt --brain-client
```

Single-host multi-GPU scaling is automatic (`-d` only needed to *restrict* which devices participate). True multi-host distribution requires either manual `-s`/`-l` keyspace splitting (simple, no coordination, but no protection against overlapping work if the split is miscalculated) or `--brain-server`/`--brain-client`, which coordinates candidate distribution across every connected client so none of them waste time on candidates another client has already tried.

## Filtering Cracked vs. Uncracked Hashes

**MITRE ATT&CK:** Not applicable — triage step

```bash
# What's already cracked, from a prior session's potfile
hashcat -m 1000 --show ntlm_hashes.txt

# What's still uncracked — feed straight into a follow-up attack
hashcat -m 1000 --left ntlm_hashes.txt > still_uncracked.txt
hashcat -m 1000 -a 3 -i still_uncracked.txt ?a?a?a?a?a?a?a?a?a
```

`--show`/`--left` never touch the GPU — they only compare the given hash list against the existing potfile. This is the standard way to triage a large hash dump after a fast dictionary/rule pass: pull out what's already cracked for immediate use, and narrow the remaining, harder set before committing to an expensive mask attack against only the hashes that actually need it.

## Chained Workflow — Capture to Crack to Reuse

**MITRE ATT&CK:** T1557.001 (capture) → T1110.002 (crack) → T1078 (Valid Accounts, on reuse)

```bash
# 1. Capture — Responder poisons the segment, captures a NetNTLMv2 hash
#    (see Purple Teaming/Responder/02 - Hands-On Use Cases.md)
sudo python3 Responder.py -I eth0 -v
# -> logs/SMB-NTLMv2-Client-10.10.10.44.txt

# 2. Crack — offline, on the operator's own machine, no target contact
hashcat -m 5600 logs/SMB-NTLMv2-Client-10.10.10.44.txt rockyou.txt -r rules/best66.rule
hashcat -m 5600 --show logs/SMB-NTLMv2-Client-10.10.10.44.txt

# 3. Reuse — the recovered plaintext goes back against a real target,
#    which is where target-side evidence for this whole chain actually starts
psexec.py 'CORP/jsmith:<recovered-password>@10.10.10.20'
```

This is the canonical reason hashcat's own evidentiary footprint on the *target* is essentially nil (see `04 - Target Evidence.md`) while still mattering enormously to an investigation: it's the silent middle link in a three-step chain where step 1 and step 3 are both loud and well-instrumented. An analyst who only looks at target-side logs sees a poisoning burst (step 1) and, hours or days later, a successful authentication from a previously-unseen credential (step 3) — the gap between them is where hashcat ran, invisibly, on infrastructure the blue team most likely never has visibility into.
