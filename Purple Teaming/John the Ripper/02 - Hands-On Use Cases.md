# John the Ripper — Hands-On Use Cases

## Single-Crack Mode on Unix /etc/passwd

**MITRE ATT&CK:** T1110.004 (Credential Stuffing), T1555 (Credentials from Password Managers)

When you've obtained a shadow file (`/etc/shadow` or `/etc/passwd`) with user account metadata (login names, GECOS/full-name fields, home directories), single-crack mode is the fastest starting point. It mangles the user's own data — names, reversed names, capitalization variants — before trying wordlist or brute-force.

```bash
# Simplest form: auto-detects crypt(3) hashes
john /path/to/shadow

# With progress output
john --verbose /path/to/shadow

# View results at any time in a separate shell
john --show /path/to/shadow

# Resume an interrupted session
john --restore
```

**What happens:**
1. John reads the shadow file, identifies crypt(3)-based hashes (DES, MD5-crypt, SHA-512-crypt, etc.)
2. Extracts login names (`root`, `alice`, etc.), GECOS fields (`Alice Smith`, `root`), home paths (`/home/alice`, etc.)
3. Mangles each with built-in rules (lowercase, capitalize, reverse, prepend/append digits, toggle case)
4. Each mangled candidate is hashed and compared against the shadow file
5. On match, immediately written to `john.pot` and printed to terminal
6. Single-crack mode re-tests every cracked password against ALL loaded hashes (catches users with identical passwords)

**Performance:** Single-crack typically cracks 20–80% of users on a typical system (weak password choices, password=username variants) in 10–60 seconds.

---

## Wordlist Mode with Best64 Rules

**MITRE ATT&CK:** T1110.004 (Credential Stuffing)

Dictionary attack: try every word in a wordlist, then apply mangling rules to each. Best64 is a curated set of 64 rules with high success rates across leaked password datasets.

```bash
# Wordlist mode with best64 rules (standard attack)
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 /path/to/hashes

# Custom wordlist
john --wordlist=/opt/custom-wordlist.txt --rules=best64 /path/to/hashes

# Different rule set
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=all /path/to/hashes

# Disable rules (try passwords verbatim)
john --wordlist=/usr/share/wordlists/rockyou.txt /path/to/hashes

# Loopback: reapply rules to previously-cracked passwords
john --loopback --rules=best64 /path/to/hashes
```

**What the rules do (sample best64 rules):**
- `T` — toggle case of all characters
- `l` — lowercase all
- `u` — uppercase all
- `c` — capitalize (first letter uppercase, rest lowercase)
- `C` — invert capitalize (first lowercase, rest uppercase)
- `$1$2$3` — append "123" to each word
- `^3^2^1` — prepend "321" to each word
- `Az"[0-9][0-9]"` — append two random digits
- `>8` — reject candidates longer than 8 characters (before hashing)

**Example wordlist entry and resulting candidates:**
```
Input word: "password"
Rules:
  T  → "PASSWORD"
  l  → "password" (no-op)
  c  → "Password"
  $1 → "password1"
  $1$! → "password1!"
  ^! → "!password"
```

**Performance:** On `rockyou.txt` (14 million words) with best64 rules: ~30–60 minutes on modern CPU for typical MD5-crypt, longer for bcrypt/scrypt (slower hash functions).

---

## Incremental Mode (Full Brute-Force)

**MITRE ATT&CK:** T1110 (Brute Force)

When wordlist and single-crack exhaust without success. Generates all possible character combinations up to a maximum length, prioritizing more likely passwords first (via trigraph-frequency statistics).

```bash
# ASCII (95 printable chars: a-z, A-Z, 0-9, symbols)
john --incremental=ASCII /path/to/hashes

# Lowercase + digits only (36 chars)
john --incremental=LowerNum /path/to/hashes

# Lowercase only (26 chars)
john --incremental=Lower /path/to/hashes

# Digits only (10 chars) — good for PIN-like hashes
john --incremental=Digits /path/to/hashes

# Custom charset file
john --incremental=LowerNum --config=/opt/custom.conf /path/to/hashes

# Generate custom charset from your cracked pot file, then use it
john --make-charset=/opt/custom.chr /path/to/hashes
john --incremental=custom.chr /path/to/hashes
```

**Charset files needed:**
Each `.chr` file encodes trigraph probabilities for each password length. Pre-defined includes:
- `ASCII.chr` — all printable ASCII
- `LowerNum.chr` — a-z + 0-9
- `Lower.chr` — a-z only
- `Upper.chr` — A-Z only
- `Digits.chr` — 0-9 only
- `LowerSpace.chr` — a-z + space

**Performance:** Incremental is **very slow** — expect days to weeks for full 8–10 character passwords on modern CPU. Typically used as a last-resort after wordlist + rules exhaust, or with aggressive timeout limits (`--max-run-time=3600` for 1-hour limit).

---

## Mask Mode (Structured Templates)

**MITRE ATT&CK:** T1110.004 (Credential Stuffing)

When you know the password structure (e.g., "starts with capital letter, then lowercase, ends with 2 digits"), masks let you skip impossible keyspace and focus on plausible candidates.

```bash
# Append 2 digits to every candidate (typical "password + date" pattern)
john --wordlist=/usr/share/wordlists/rockyou.txt --mask=?w?d?d /path/to/hashes

# Literal prefix + digits
john --mask=Pass?d?d?d /path/to/hashes  # "Pass000" to "Pass999"

# Capital letter + lowercase + 2 digits
john --mask=?u?l?l?d?d /path/to/hashes

# Multiple positions (all permutations)
john --mask=?u?l?l?l?d /path/to/hashes

# Hybrid: wordlist base + mask suffix
john --wordlist=/usr/share/wordlists/rockyou.txt --mask=?d?d /path/to/hashes

# Mask character codes:
# ?a = all (upper + lower + digit + symbol)
# ?l = lowercase
# ?u = uppercase
# ?d = digit
# ?s = symbol
# ?w = word char (letter or digit, no symbol)
```

**Performance:** Mask mode on GPU (in some jumbo builds) is **very fast** — millions of candidates/second. On CPU-only, still faster than incremental because the keyspace is smaller.

---

## Credential Stuffing with Known Breaches

**MITRE ATT&CK:** T1110.004 (Credential Stuffing)

When you have a list of login:password pairs from a data breach or social engineering, validate them against hashes.

```bash
# Prepare breach file: one "login:password" per line (format: username:plaintext)
cat > breach.txt << 'EOF'
alice:Passw0rd!
bob:MyPassword123
charlie:welcome
EOF

# Convert to John format (--pot-format):
john --loopback=breach.txt --format=bcrypt /path/to/bcrypt_hashes

# Or directly try known passwords against hashes (manual check):
# - Hash each password from breach.txt
# - Compare against your target hashes
# Simpler approach: use john --wordlist=breach_passwords.txt --rules=none
```

**More direct approach with wordlist:**
```bash
# Extract just passwords from breach file
cut -d: -f2 breach.txt > breach_passwords.txt

# Try against hashes (no rules, verbatim)
john --wordlist=breach_passwords.txt /path/to/hashes
```

**Performance:** Instant — a few million hashes/second on CPU, limited by wordlist size.

---

## Multi-Hash Attack with Format Specification

**MITRE ATT&CK:** T1110.004 (Credential Stuffing)

When your hash file contains mixed formats or John's auto-detection fails.

```bash
# Specify format explicitly (e.g., MD5-crypt on Linux, NT on Windows)
john --format=md5crypt --wordlist=/usr/share/wordlists/rockyou.txt /etc/shadow

# Windows NT hashes (from SAM dump or Impacket secretsdump)
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt samhashes.txt

# Kerberos 5 AS-REQ pre-auth (from Kerberoasting or captured traffic)
john --format=krb5asrep /path/to/asrep_hashes

# Bcrypt (common in web apps)
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt bcrypt_hashes.txt

# List all available formats
john --list=formats | head -50
```

**Performance:** Format-specific optimization can make 10–100x difference. For example, MD5-crypt optimized vs. generic: ~1 million vs. 100k hashes/second.

---

## Resumable Session with Named Checkpoints

**MITRE ATT&CK:** T1110.004 (Credential Stuffing)

Large cracks over multiple days/weeks. Name sessions so you can run multiple parallel attacks without collisions.

```bash
# Start a new named session (saves to "bigrun.rec" and "bigrun.log")
john --session=bigrun --wordlist=/usr/share/wordlists/rockyou.txt --rules=all /large/hash/file

# While running in one terminal, check status in another
john --status=bigrun
# Output: [bigrun] bigrun: running (1234 words/sec, 567890 words, ETA: 3d 12h)

# Interrupt session (Ctrl-C) — state automatically saved to bigrun.rec

# Resume later
john --restore=bigrun

# After session completes, view results
john --show /large/hash/file
```

**Log file:** John automatically logs all cracks + progress to `bigrun.log`:
```
Loaded hashes (md5crypt) [MD5 crypt 256/256 AVX2] (cost 1:500)
Opened attempt log file bigrun.log
bigrun: starting (wordlist)
bigrun: loaded 1,000,000 hashes (1,000,000 unique IDs, MD5, salted)
bigrun: alice / P@ssw0rd
bigrun: bob / Summer2024
...
```

**Performance:** Multi-day attacks are normal; typical recovery time from a crash: seconds (resume from binary `.rec` file).

---

## Markov Mode Attack

**MITRE ATT&CK:** T1110 (Brute Force)

Statistical attack: uses character-pair frequencies from previously-cracked passwords (your pot file) to generate plausible candidates in likelihood order.

```bash
# Markov mode level 200 (medium aggressiveness)
john --markov=200 /path/to/hashes

# Markov level 100 (conservative, faster)
john --markov=100 /path/to/hashes

# Markov level 300 (aggressive, slower, more likely)
john --markov=300 /path/to/hashes

# Generate the Markov database first from your pot file
john --markov=200 --pot=/opt/my.pot /path/to/hashes

# Combine with other constraints (e.g., min/max length)
john --markov=200 --min-length=6 --max-length=12 /path/to/hashes
```

**How it works:**
1. Analyzes your `john.pot` file for character-pair frequencies (e.g., "th" is common, "xq" is rare)
2. Generates candidate passwords in order of statistical likelihood
3. Good for "middle ground" between pure brute-force and limited wordlist

**Performance:** ~100k–1M candidates/second (CPU-dependent), targeting keyspace of plausible passwords.

---

## Rules Stacking (Applied Sequentially)

**MITRE ATT&CK:** T1110.004 (Credential Stuffing)

Apply two rule sets in sequence for deeper transformations.

```bash
# Best64 rules, then ShiftToggle rules (case-shift variants)
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 --rules-stack=ShiftToggle /path/to/hashes

# Wordlist rules (best64), then advanced mangling (all)
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 --rules-stack=all /path/to/hashes

# Single mode + rules-stack (re-apply rules to single-crack results)
john --single --rules-stack=best64 /path/to/shadow

# Hybrid mask + rules
john --mask=?d?d?d --rules=all /path/to/hashes
```

**Important:** Stacking two rule sets can produce **millions of candidates per wordlist entry** (rules × rules), massively increasing run time. Use sparingly.

**Performance:** Best64 + ShiftToggle on 1 million-word list: ~1–3 hours (depends on hash type).

---

## External Mode with Custom C Code

**MITRE ATT&CK:** T1110 (Brute Force)

Write custom candidate-generation logic in a C-like language embedded in `john.conf`.

```bash
# Example: external mode in john.conf [List.External:custom_gen]
# This generates passwords like "user123", "user124", ..., "user999"

john --external=custom_gen /path/to/hashes
```

**Example john.conf section:**
```
[List.External:custom_gen]
void generate(int count) {
    int i;
    for (i = 0; i < 900; i++) {
        sprintf(word, "user%d", 100 + i);
        if (ext_filter(word) == -1) continue;
        out_generate(word);
    }
}
```

**Use cases:**
- Organization-specific password patterns (e.g., all passwords start with company name)
- Temporal patterns (passwords include year or month)
- Technical wordlist generation (e.g., port numbers, HTTP method names)

**Performance:** Highly variable; external mode can be slower than built-in modes due to C interpreter overhead, but allows fine-grained control.

---

## Distributed Multi-Session Attack on Large Hash File

**MITRE ATT&CK:** T1110.004 (Credential Stuffing)

Crack a very large hash file (millions of hashes) by running multiple independent sessions in parallel on the same machine.

```bash
# Terminal 1: Session A
john --session=attack_a --wordlist=/usr/share/wordlists/rockyou.txt /huge/hashfile

# Terminal 2: Session B (simultaneous, different rules)
john --session=attack_b --wordlist=/usr/share/wordlists/rockyou.txt --rules=all /huge/hashfile

# Terminal 3: Session C (incremental, lower priority)
john --session=attack_c --incremental=LowerNum /huge/hashfile

# Monitor status
john --status=attack_a
john --status=attack_b
john --status=attack_c

# All three write to the same $JOHN/john.pot, so results accumulate
# View combined results
john --show /huge/hashfile
```

**Important caveat:** All sessions share the same pot file (`$JOHN/john.pot` by default). Hashes already cracked by session A are skipped in sessions B/C (John checks the pot before trying each hash). This is fine, but **do not** use `--fork=N` at the same time as parallel `--session` — that would cause resource contention and duplicate work.

**Performance:** Linear scaling with number of parallel sessions (e.g., 3 sessions ≈ 3× total throughput).

---

## Format Auto-Detection vs. Explicit Specification

**MITRE ATT&CK:** T1110.004 (Credential Stuffing)

John can identify most common hash formats automatically, but explicit `--format=` is faster and more reliable.

```bash
# Auto-detect (default, one-size-fits-all)
john /path/to/hashes

# Explicit format (faster, avoids scanning all formats)
john --format=md5crypt /path/to/hashes

# When auto-detection fails (rare), specify format
# Example: You have NTLM hashes (Windows NT) but John tries MD5 first
john --format=nt samhashes.txt

# Discover format of input file
john --show=types /path/to/hashes
# Output: md5crypt (MD5 crypt)

# List all formats and find the one you need
john --list=formats | grep -i bcrypt
# Output: bcrypt (Blowfish-based crypt(3) password hashing)
```

**Performance:** Auto-detection scans hashes against 20–50 format validators; explicit `--format=` skips straight to one. Speedup: ~10–100× faster startup (but cracking speed is identical once started).

---

## Generating Custom Charset for Incremental Mode

**MITRE ATT&CK:** T1110 (Brute Force)

Build a custom `.chr` file based on real cracked passwords in your pot file, then use it for incremental mode.

```bash
# Your pot file has 10,000 cracked passwords
# Analyze character frequencies
john --make-charset=/opt/mycharset.chr /path/to/your/hashes

# John reads from its default pot file, analyzes character distributions
# Writes mycharset.chr with trigraph frequencies for lengths 1–13

# Now use this custom charset for incremental mode
john --incremental=mycharset.chr /new/hashfile

# Or restrict to specific hashes for charset (e.g., only from a subset)
john --make-charset=/opt/subset.chr --users=alice,bob /path/to/shadow
```

**What john.pot must contain:**
Plain-text format: `hash:password` or (after `--show`) just the password. Each line is analyzed for character frequencies.

**Performance:** Charset generation is instant (<1 second for large pot files); incremental mode using custom charset runs normally but is tuned to your specific password distribution.
