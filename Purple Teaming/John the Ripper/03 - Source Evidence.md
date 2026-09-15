# John the Ripper — Source Evidence

## Overview

John the Ripper is an **entirely offline, local-computation tool** — it reads hashes, computes locally, and records results. The attacking host is the only artifact source; the target never sees the attack coming. All evidence lives on the attacker's machine.

---

## Pot File (`john.pot`)

**Location:** `$JOHN/john.pot` (default); overridable via `--pot=FILE`

**What it is:** Plain-text file, one cracked password per line, format `hash:password`. Immediately appended on each match; never truncated; survives between sessions. This is the **authoritative log of every password successfully cracked** across all John sessions on this host.

**Format:**
```
$1$abcd1234$xyz...:password1
$1$efgh5678$xyz...:password2
$6$salt...$xyz...:mySecretPassword
```

**How it's written:**
- Appended immediately on match (not buffered)
- Mode `0644` by default (readable by any user running john)
- If pot file is corrupted or unreadable, John warns and starts fresh
- When restarted, John checks every hash against the pot before attempting (hash-based comparison, not string match)

**Forensic value:**
- **Direct password evidence** — every line is a plaintext password the operator obtained
- **Timeline** — file modification time (`mtime`) reflects the cracking session's end time; creation time (`crtime` on APFS/NTFS) reflects when cracking started
- **Format diversity** — if pot contains bcrypt, MD5-crypt, NT hashes, etc., indicates multi-format attack or multi-target cracking
- **Volume** — pot file size and line count indicate attack scale (1000 lines = 1000 hashes cracked)

**Evasion resistance:**
- Renaming or deleting the pot file before forensic collection is the only evasion; John will create a new one on next run
- Pot file integrity: if operator modifies or truncates it, John's next run will skip already-cracked hashes from pot (prevents re-cracking) so modifications are forensically detectable
- No automated cleanup; pot persists by design

---

## Session File (`john.rec`, binary)

**Location:** `john.rec` (default); or `NAME.rec` if `--session=NAME` used

**What it is:** Binary checkpoint file written every ~10 minutes and on graceful exit (Ctrl-C). Encodes:
- Current cracking mode (single, wordlist, incremental, etc.)
- Wordlist file offset (byte position in wordlist)
- Rule index (if rules enabled)
- Incremental-mode state (current password length, character index)
- Hash table state (which hashes already matched)
- Session parameters (format, salt, hash list)

**How it's written:**
- Binary format (not human-readable)
- Mode `0600` (owner-read/write only) if created by john
- Overwritten every 10 minutes (`SAVE_STATE_INTERVAL 300` in source) and on clean exit
- Designed for resume via `john --restore` or `john --restore=NAME`

**Forensic value:**
- **Attack mode recovery** — parsing the binary session file reveals which cracking mode was active (wordlist offset → how far through rockyou.txt, incremental state → charset and password length)
- **Active session indicator** — presence of recent `john.rec` (within last 10 minutes) indicates a running or recently-interrupted John session
- **Resumable state** — indicates the operator expected to resume this attack later (not a one-time, quick run)
- **Parallelization detection** — multiple `NAME1.rec`, `NAME2.rec` files in same directory suggest parallel sessions

**Limitations:**
- Binary format requires John's own parsing (`john --status=NAME` reads it, but raw parsing is difficult without reverse-engineering)
- If deleted/corrupted, next `john --restore` fails gracefully (John starts over)
- No timestamp embedded; rely on filesystem modification time

**Evasion resistance:**
- Operator deletes `john.rec` after finishing → no resumable state, but pot file still remains
- Session file is transient by design; critical evidence is in pot file, not session file

---

## Wordlist Files

**Location:** Usually in `/usr/share/wordlists/`, `/opt/wordlists/`, or operator's custom directory

**Common paths:**
- `/usr/share/wordlists/rockyou.txt` (or rockyou.txt.gz — 14+ million words)
- `/usr/share/wordlists/john.lst` (included with John installations)
- `~/.john/wordlists/` (operator's custom wordlists)
- `/opt/cracking/rockyou_modified.txt` (curated/modified versions)

**Forensic value:**
- **Wordlist presence** — finding rockyou.txt or other public wordlists on the attacking host confirms password cracking is in scope
- **Custom wordlists** — operator-compiled wordlist (e.g., company names, historical passwords) reveals targeting or campaign specifics
- **Size/modification** — large custom wordlist (100 MB+) indicates serious long-term campaign; recent mtime suggests ongoing attack
- **Integration in rules** — wordlist combined with specific rule sections (best64, all, KoreLogic) indicates attack sophistication

**Evasion resistance:**
- Wordlist files are typically public (rockyou.txt is freely available); presence alone is not incriminating, but combined with pot file is highly suspect
- Custom wordlists are more distinctive; keeping them after a run is the main artifact

---

## Rules Configuration Section

**Location:** In `john.conf` configuration file (or inline via `--rules=:rule;rule;...`)

**What it contains:**
```
[List.Rules:best64]
# John's built-in rules (case toggling, appending digits, etc.)
l
u
c
r
...
$1$2$3$4
```

**Forensic value:**
- **Rules enablement indicator** — presence of `--rules` in shell history or config confirms wordlist enhancement
- **Custom rules** — operator-written `[List.External:MODE]` sections reveal custom password-generation logic
- **Stacking detection** — `--rules-stack` in command line indicates iterative, sophisticated attack (not one-pass wordlist)

**Evasion resistance:**
- John's built-in rules are immutable (compiled into the binary)
- Custom rules can be deleted from john.conf
- Shell history is the better source of evidence here (see below)

---

## Shell/Command History

**Locations:**
- `~/.bash_history` (Bash)
- `~/.zsh_history` (Zsh)
- `~/.ksh_history` (Korn shell)
- `~/.sh_history` (older shells)
- `/var/log/auth.log` or `/var/log/secure` (if root commands are logged)

**Evidence:**
```bash
john /path/to/shadow
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 /path/to/hashes
john --session=megarun --incremental=ASCII /huge/hashfile
john --restore=megarun
john --show /path/to/hashes > cracked_passwords.txt
john --loopback --rules=all /path/to/hashes
```

**Forensic value:**
- **Attack timeline** — command timestamps (if logged) or mtime of history file
- **Attack parameters** — hash file paths, wordlists, modes reveal targeting and sophistication
- **Session persistence** — use of named sessions (`--session=NAME`) indicates planned long-term attack
- **Result exfiltration** — `john --show > file.txt` reveals operator extracted results

**Evasion resistance:**
- History can be cleared or disabled (`unset HISTFILE`, `history -c`)
- Manual commands without history logging possible (but unusual)
- Reliable artifact if not explicitly cleared

---

## Process List / Memory Footprint

**Running John process:**
```bash
ps aux | grep john
# abc     12345  45.2 12.3 2148908 1024576 ?    Sl   10:30 john --wordlist=rockyou.txt --rules=best64 /large/hashfile
```

**Forensic value:**
- **Active session detection** — presence of running `john` process confirms ongoing cracking
- **Command-line reconstruction** — full command-line visible in `/proc/[PID]/cmdline`
- **Resource usage** — high CPU (45.2%) and memory (12.3%, 1 GB) typical for John (varies by format)
- **Hash format inference** — very high memory (3+ GB) suggests bcrypt/scrypt (slower, memory-intensive formats); lower memory (100–500 MB) suggests MD5 or SHA-based hashes

**Limitations:**
- Evidence disappears on process termination
- Only useful during active cracking or within a very recent timeframe

---

## Disk I/O Artifacts

**Files John creates or modifies:**
- `john.pot` (appended continuously)
- `john.rec` or `NAME.rec` (written every 10 minutes)
- `john.log` (optional, if logging enabled; appends with `--log-stderr`)
- Temporary charset files (`.chr`) if using `--make-charset`

**Filesystem timeline:**
- `john.pot` mtime advances every few seconds to minutes (as matches accumulate)
- `john.rec` mtime advances every ~10 minutes (checkpoint interval)
- If pot file is very new (mtime within last hour) and large (1000+ lines), indicates recent, active cracking

**Forensic value:**
- **Cluster timeline** — pot file older than session file suggests attack completed and no longer running
- **Deleted file recovery** — unallocated clusters may contain older pot-file versions (forensic carving)

---

## Log File (Optional, `john.log` or `NAME.log`)

**Created if:** Logging is enabled (default in some builds, or via `--log-stderr`)

**Contents:**
```
Loaded hashes (sha512crypt) [SHA-512 crypt 256/256 AVX2] (cost 1:5000 rounds) 100 different salts, only 75 unique salts
Saved state: sha512crypt, version 2, cost 1 5000 rounds
Saved state: sha512crypt, version 2, cost 1 5000 rounds
Saving progress file, 49 passwords left
SHA-512 crypt: 51 group 1, 49 group 2  (cost 1:5000 rounds)
alice / password123
bob / MyPassword!
...
```

**Forensic value:**
- **Cracked password listing** — plaintext passwords directly logged
- **Timestamp precision** — exact cracking time
- **Hash-type confirmation** — log shows which formats were loaded and cracked

**Evasion resistance:**
- Logging can be disabled or log file deleted after session

---

## Network Connections

**Expected:** None. John is completely offline and makes zero network connections.

**Absence of network evidence is itself suspicious** — if a tool is being used for password cracking, network connection absence is expected (unlike network-based tools like Hydra or Spray365, which must probe targets).

---

## Performance/Benchmark Artifacts

**If `--test` is run:**
```bash
john --test
```

Output goes to stdout (or log file if logging enabled):
```
Benchmarking: md5crypt [MD5 crypt 256/256 AVX2]... (8 xops) DONE
Many salts:  100,000 c/s real, 100,000 c/s virtual
Only salts:  200,000 c/s real, 200,000 c/s virtual
...
```

**Forensic value:**
- **Baseline performance testing** — indicates operator establishing expected throughput for their cracking environment
- **Format optimization** — `--test --format=bcrypt` shows operator profiling bcrypt performance
- **System capabilities discovery** — operator determining CPU/GPU capabilities before large-scale attack

---

## Extracted Hashes (Source Files)

**Typical hash sources the operator must have obtained before using John:**

| Source | Tool/Method | Evidence | Example |
|---|---|---|---|
| Unix shadow file | Local access or `Impacket/secretsdump` | `/etc/shadow` copy, often named `shadow`, `shadow.bak`, `passwd`, `shadow-copy` | `$6$salt$xyz...` |
| Windows SAM | `Impacket/secretsdump`, registry dump | SAM hive dump or plaintext hash file from secretsdump output, often named `SAM`, `sam.bak`, `user_hashes.txt` | `Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::` |
| Domain hashes | `Impacket/secretsdump`, tool output | NTDS.dit dump or DRSUAPI results, often named `domain_hashes.txt`, `DC_hashes.txt` | `user:1103:aad3b435...` |
| Kerberos | `Impacket/GetUserSPNs` or traffic capture | Kerberoast hashes, often named `kerberos_hashes.txt`, `spn.txt` | `$krb5tgs$23$*...` |
| Web app databases | SQL injection, application backup | Database dumps (MySQL, PostgreSQL, MongoDB), often bcrypt/PBKDF2 | `alice:$2b$12$...` |
| Cloud credentials | API breach, configuration file | API keys, password hashes from AWS/Azure/GCP leaks | varies |

**Forensic value:**
- **Hash-source location** — finding `/tmp/domain_hashes.txt` or `/opt/cracking/secretsdump_output.txt` reveals tool chain
- **Hash format diversity** — operator with both NTLM and bcrypt hashes indicates multi-target compromise (Windows + web app)
- **File naming conventions** — operator's naming reveals targeting scope (e.g., `customer_database_hashes.txt` → targeted customer database)

---

## Cryptocurrency/Cloud Evidence

**Unlikely for CPU-based John, but possible:**

- No cloud GPU rental artifacts expected (John is CPU-focused; Hashcat uses cloud GPUs)
- No blockchain evidence (no funds transfers for commercial Hashcat cloud services)

---

## Correlating Source to Target Timeline

**Attack sequence reconstruction:**

1. **Target compromise/reconnaissance** — operator obtains hash file from target (via `Impacket/secretsdump/`, local access, breach, etc.)
2. **Transfer to attacking host** — hash file appears on attacker's filesystem (often in `/tmp/`, `/opt/cracking/`, or user home directory)
3. **John cracking begins** — `john.rec` created, pot file initiated
4. **Pot file grows** — passwords accumulate over minutes/hours/days
5. **Session paused or completed** — `john.rec` mtime stops advancing; operator may run `john --show` to extract results
6. **Cleanup (or not)** — operator optionally deletes pot file, session file, or wordlists; shell history cleared; hash-source file removed

**Timeline correlation:**
- Hash file mtime vs. pot file ctime: time elapsed between compromise and cracking start
- Pot file mtime progression: cracking session duration and any gaps
- `john.rec` vs. pot file: if rec is much newer than pot, indicates idle session (could be resumed)
- Shell history vs. command timestamps: confirm user ran John at claimed times

---

## Summary: Source-Side Forensic Priority

1. **`john.pot`** — Most critical artifact, plaintext cracked passwords
2. **Shell history** — Command-line parameters, cracking modes, targeting info
3. **Hash-source files** — Shows what was cracked, targeting scope
4. **`john.rec` or `NAME.rec`** — Session state, attack parallelization
5. **Wordlist files** — Custom wordlists reveal organization targeting
6. **Log files** (`john.log`) — Timestamped cracking timeline
7. **Filesystem timeline** — mtime analysis, deleted-file recovery
