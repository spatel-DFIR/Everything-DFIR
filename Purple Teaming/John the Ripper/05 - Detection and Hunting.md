# John the Ripper — Detection and Hunting

Since John the Ripper is **completely offline**, this section focuses on hunting the **attacking host's artifacts** — the pot file, session files, wordlists, and command history that reveal the cracking activity.

---

## Hunting Priority Table

| Artifact | Evasion Resistance | Details | Rank |
|---|---|---|---|
| `john.pot` (pot file) | ★★★★★ Undefeatable | Plain-text cracked passwords; immediate forensic gold. Operator must delete or rename to evade. Deleted files recoverable via carving. | #1 |
| Shell history (`.bash_history`, `.zsh_history`) | ★★★★☆ High | Command-line parameters (hash file path, wordlist, mode) visible. Can be cleared, but typical ops don't bother. | #2 |
| Hash-source file (local copy) | ★★★★☆ High | `/tmp/shadow`, `/opt/cracking/domain_hashes.txt` — proves operator had hash access. Mtime vs. pot-file ctime reveals timeline. | #3 |
| Session files (`john.rec`, `NAME.rec`) | ★★★★☆ High | Binary checkpoint files; presence indicates interrupted session, intent to resume. Mtime reveals recent activity. | #4 |
| Wordlist files | ★★★☆☆ Moderate | Public wordlists (rockyou.txt) common; custom wordlists more distinctive. Presence + pot file = high confidence. | #5 |
| Process artifacts (Sysmon logs if captured) | ★★★☆☆ Moderate | Active-session detection if compromised host monitored; rare. | #6 |
| Log files (`john.log`) | ★★☆☆☆ Low | Optional; can be disabled or deleted. Lower fidelity than pot file. | #7 |
| Filesystem timeline (mtime analysis) | ★★☆☆☆ Low | Indicates recent cracking; easily manipulated via touch, but rare in practice. | #8 |

**Key insight:** The pot file is the smoking gun. Everything else is supplementary corroboration.

---

## Hunting on Source (Attacking Host)

### High-Priority Hunt: Find Pot Files

**Goal:** Locate `john.pot` and any renamed/alternate pot files.

**Commands:**

```bash
# Most direct: find all pot files in standard locations
find ~/.john -name "*.pot" 2>/dev/null
find ~/ -name "*john*.pot" 2>/dev/null
find /opt -name "*.pot" 2>/dev/null
find /tmp -name "*.pot" 2>/dev/null

# Broader search: any "pot" files (not just john.pot)
find / -name "*.pot" -type f 2>/dev/null

# Search by content: any file containing "hash:password" pattern
grep -r "^\$[0-9]\$.*:.*" / 2>/dev/null | head -20

# Even broader: files with hash-like patterns (MD5/SHA/bcrypt/NT hashes)
find / -type f -size +1k -exec grep -l "^\$[0-9]\$\|^\$2[aby]\$\|^[a-f0-9]\{32\}" {} \; 2>/dev/null

# Check in user home directories (most common location)
for user in $(cut -d: -f1 /etc/passwd); do
    find /home/$user -name "*.pot" 2>/dev/null
done

# Check current working directories of recent processes (if forensic image)
ls -la ~/.john/
ls -la ~/.config/john/
ls -la /root/.john/  # if root ran john
```

**Pot file indicators:**
- Size > 0 bytes (each cracked password is one line)
- Recent mtime (last modified within hours/days)
- Plain-text format: `hash:plaintext` per line
- Multiple hash types indicate multi-target cracking

**On Windows (if john was installed):**
```powershell
# Default John homedir on Windows
Get-ChildItem "$env:APPDATA\John*" -Recurse -Filter "*.pot"

# User profiles
Get-ChildItem "C:\Users\*\AppData\Roaming\John*" -Recurse -Filter "*.pot"

# Common alternate paths
Get-ChildItem "C:\cracking\*", "C:\tools\john\*" -Recurse -Filter "*.pot"

# Search by content
Get-ChildItem -Recurse -Filter "*.pot" | Select-String "\$[0-9]\$.*:.*"
```

---

### Hunt Session Files and Checkpoints

**Goal:** Detect active or recent cracking sessions.

**Commands:**

```bash
# Find session recovery files
find ~/ -name "john.rec" 2>/dev/null
find ~/ -name "*.rec" -type f 2>/dev/null  # NAME.rec for named sessions
find /tmp -name "*.rec" 2>/dev/null

# Check modification time (recent = active/recent attack)
ls -la ~/.john/john.rec
stat ~/.john/john.rec  # shows all timestamps (ctime, mtime, atime)

# Find multiple session files (indicates parallelization)
ls -la ~/*.rec  # attack_a.rec, attack_b.rec, etc.

# Check for running john process and its associated session
ps aux | grep john
lsof -p $(pgrep john)  # files open by john process (if running)
```

**Session file indicators:**
- Binary file, typically 1–100 MB
- Recently modified (within 10 minutes if actively cracking)
- Multiple `.rec` files suggest parallel sessions

---

### Hunt Shell History

**Goal:** Recover command-line invocations of John and hash-file operations.

**Commands:**

```bash
# Bash history
cat ~/.bash_history | grep john

# Zsh history
cat ~/.zsh_history | grep john

# Current shell session history
history | grep john

# Search for any password cracking commands
grep -E "john|hashcat|hydra|--wordlist|--incremental" ~/.bash_history
grep -E "john|hashcat|hydra|--wordlist|--incremental" ~/.zsh_history

# Show full context (before/after lines)
grep -B 2 -A 2 "john" ~/.bash_history

# Find references to hash files
grep -E "shadow|hashes\.txt|domain.*hash|secretsdump|GetUserSPNs" ~/.bash_history

# Recover deleted history file (forensic)
strings ~/.bash_history.* 2>/dev/null | grep john  # if history rotation happened
```

**History indicators:**
- Commands like `john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 /path/to/hashes`
- Named sessions: `john --session=bigrun --wordlist=...`
- Resume commands: `john --restore` or `john --restore=bigrun`
- Results extraction: `john --show`

**On Windows (PowerShell history):**
```powershell
# PowerShell history
(Get-PSReadlineOption).HistorySavePath  # location of history file
Get-Content $PROFILE | grep john
Get-Content (Get-PSReadlineOption).HistorySavePath | Select-String john
```

---

### Hunt Wordlist Files

**Goal:** Locate public and custom wordlists used for cracking.

**Commands:**

```bash
# Common wordlist locations
ls -la /usr/share/wordlists/
ls -la /opt/wordlists/
ls -la ~/.wordlists/
ls -la /tmp/wordlists/

# Find rockyou.txt specifically (most common)
find / -name "rockyou.txt*" 2>/dev/null

# Find large text files that are likely wordlists (1 word per line)
find /opt /home /tmp -type f -name "*.txt" -size +10M 2>/dev/null

# Custom wordlists (often named suggestively)
find / -name "*wordlist*" -o -name "*passwords*" -o -name "*dict*" 2>/dev/null | grep -v "^/proc\|^/sys"

# Check modification time of wordlists (recent = recently added for cracking campaign)
find /opt -type f -name "*.txt" -newermt "2024-01-01" 2>/dev/null
```

**Wordlist indicators:**
- rockyou.txt presence (14 MB, 14M lines)
- Custom wordlists with organization-specific terms (e.g., company names, product names)
- Modification time aligned with pot-file creation (uploaded right before cracking started)

---

### Hunt for Hash-Source Files

**Goal:** Find copies of dumped hashes on the attacking host.

**Commands:**

```bash
# Direct hash-file patterns
find / -type f -exec grep -l "^\$6\$.*:.*\|^Administrator:[0-9]*:" {} \; 2>/dev/null | head -10

# Common naming patterns
find /tmp /opt /home -name "*shadow*" -o -name "*hashes*" -o -name "*domain*hash*" 2>/dev/null
find / -name "secretsdump_output.txt" -o -name "DC_hashes.txt" 2>/dev/null

# Search for files with hash-like lines
find /home /opt /tmp -type f -size +1k -exec bash -c 'head -1 "$1" | grep -q "^\$[0-9]\$\|^[a-f0-9]\{32\}" && echo "$1"' _ {} \;

# Check for Impacket secretsdump output (format: username:RID:HASH:HASH:comment:...)
grep -r "Administrator:[0-9]*:" / 2>/dev/null | head -5
```

**Hash-file indicators:**
- File contains Unix shadow (`$1$`, `$6$`) or Windows NT (`$NT$`) hashes
- Filenames suggest tool output (`secretsdump_output.txt`, `DC_hashes.txt`)
- Mtime before pot-file ctime (hash dump occurred first, then cracking)

---

### Hunt John Configuration

**Goal:** Find custom rules, external modes, or config modifications.

**Commands:**

```bash
# Find john.conf
find / -name "john.conf" 2>/dev/null

# Check default location
cat ~/.john/john.conf 2>/dev/null || cat /etc/john/john.conf 2>/dev/null

# Look for custom rule sections
grep -A 10 "\[List.Rules:" ~/.john/john.conf 2>/dev/null

# Look for external mode definitions
grep -A 20 "\[List.External:" ~/.john/john.conf 2>/dev/null

# Check for modified rule configurations
diff /etc/john/john.conf ~/.john/john.conf 2>/dev/null
```

**Config indicators:**
- Custom `[List.External:MODE]` sections with C code indicate sophisticated password generation
- Modified rule sections indicate targeted attacks
- Recent mtime on john.conf indicates pre-attack setup

---

### Memory Forensics (if system compromised while John running)

**Goal:** Recover pot-file contents or running John state from memory.

**Commands (on memory dump):**

```bash
# Volatility plugin (if available)
volatility -f memory.dump linux.pstree | grep john
volatility -f memory.dump linux.memmap -p $(pgrep john)

# Strings search for cracked passwords in memory
strings memory.dump | grep -E "^.{8,}$" | sort -u | head -100  # potential passwords

# Search for john.pot content in memory
strings memory.dump | grep "^\$[0-9]\$.*:" | head -20

# Search for wordlist content (loaded into memory during cracking)
strings memory.dump | grep -E "^(password|john|admin|welcome|letmein)" | sort | uniq -c | sort -rn | head -20
```

**Memory indicators:**
- John process address space contains open pot-file content
- Wordlist content loaded and cached
- Hash table (in-memory loaded hashes) visible as structured data

---

## Hunting on Target

### Target-Side: None (Direct)

**Since John never touches the target, there is no direct target-side evidence.**

However, hunt for **evidence of the hash-dump tool that fed John**:

| Dump Method | Hunt Command | Evidence |
|---|---|---|
| `Impacket/secretsdump` via DRSUAPI | `grep "4662" /var/log/auth.log` or `Get-EventLog Security -Filter @{EventID=4662}` (Windows) | LDAP Directory Service Access event 4662 |
| `Impacket/secretsdump` via RemoteRegistry | `Get-EventLog Security -Filter @{EventID=4633}` (Windows) | Registry access event 4633/4658 |
| VSS + NTDS.dit copy | `wevtutil qe System /q:"*[System[Provider[@Name='VSS'] and EventID=8192]]"` (Windows) | Volume Shadow Copy creation |
| Mimikatz lsadump (DCSync) | `Get-EventLog Security -Filter @{EventID=4662}` (same as secretsdump) | DRSUAPI events |

---

## Hunt Strategy: From Pot File to Attack Reconstruction

**Scenario:** You've acquired a host and found a pot file. Here's a playbook to reconstruct the full attack:

### Step 1: Validate and Analyze Pot File

```bash
# Count lines (cracked passwords)
wc -l john.pot

# Sample first/last entries
head -5 john.pot
tail -5 john.pot

# Extract just passwords (right side of colon)
cut -d: -f2 john.pot > cracked_passwords.txt
wc -l cracked_passwords.txt  # how many passwords cracked

# Identify hash types
cut -d: -f1 john.pot | head -10  # look at hash prefixes
```

### Step 2: Correlate with Shell History

```bash
# Find the john command that created this pot
grep -n "john" ~/.bash_history | tail -20

# Reconstruct the attack parameters
# Example history: john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 /tmp/shadow
# Now you know:
#   - Wordlist: rockyou.txt (public, not targeted)
#   - Rules: best64 (standard, high-confidence rules)
#   - Hash source: /tmp/shadow (obtained from where?)
```

### Step 3: Timeline Correlation

```bash
# Compare timestamps
stat john.pot
stat /tmp/shadow  # hash source file
stat john.rec

# Interpretation:
# - shadow mtime (when hashes obtained): 2024-01-15 10:30
# - john.pot ctime (cracking started): 2024-01-15 10:35 (5 min later)
# - john.pot mtime (last password cracked): 2024-01-16 08:45 (23 hours later)
# → Attack ran for ~23 hours
```

### Step 4: Threat Assessment

```bash
# High-value passwords cracked?
grep -E "^(root|admin|domain.*admin)" john.pot

# Credential diversity
grep "^Administrator:\|^root:" john.pot

# Success rate (how many hashes were there originally?)
# Compare pot-file line count to original hash file line count
# High success rate (>50%) suggests weak passwords or targeted password guessing
```

---

## Deception / Evasion-Resistant Signals

| Signal | Evasion | Residual Evidence |
|---|---|---|
| Pot file deleted | Operator deletes after session | Unallocated clusters recoverable via carving; mtime metadata on containing directory |
| History cleared | `history -c`, `unset HISTFILE` | Previous `.bash_history` rotations (if system logs rotation); memory forensics |
| Session files deleted | Operator cleans up `.rec` files | Unallocated clusters; pot file remains |
| Wordlist files removed | Operator deletes `/opt/wordlists/` | Unallocated clusters; shell history may reference filenames |
| John binary removed | Operator deletes john executable | Shell history proves it ran; unallocated clusters; Sysmon logs (if captured during run) |

**Bottom line:** Deleting pot file is the operator's only effective evasion; everything else is forensically recoverable or leaves corroborating evidence.

---

## Automated Hunting Rules

### Splunk Query (for endpoint monitoring)

```spl
index=endpoint process=john OR process=john.exe
| stats count by host, process, command_line
| where count > 0
```

### Sysmon Event Detection (Windows)

```xml
<RuleGroup name="John Detection" groupRelation="or">
    <ProcessCreate onmatch="include">
        <Image condition="contains">john</Image>
        <CommandLine condition="contains any">--wordlist|--incremental|--format|--session</CommandLine>
    </ProcessCreate>
    <FileCreate onmatch="include">
        <TargetFilename condition="contains any">john.pot|john.rec|.john\john.rec</TargetFilename>
    </FileCreate>
</RuleGroup>
```

### Auditd Rules (Linux)

```bash
# Monitor for john execution
-a exit,always -F exe=/usr/bin/john -F perm=x -F auid>=1000 -k john_execution

# Monitor for pot file access
-a exit,always -F path=*john.pot -F perm=wa -F auid>=1000 -k john_pot_modification

# Monitor for wordlist access in common directories
-a exit,always -F dir=/usr/share/wordlists -F perm=r -F auid>=1000 -k wordlist_access
```

### YARA Signature (for pot-file content)

```yara
rule John_Pot_File {
    strings:
        $s1 = /\$[0-9]\$[^\$:]{8,}\$[^\$:]+:[^\n]{4,}/  // Hash:password pattern
        $s2 = /$1$[a-z0-9./]{8}\$[a-z0-9./]{22}:/      // MD5-crypt:password
        $s3 = /$6$[a-z0-9./]{16}\$[a-z0-9./]{86}:/     // SHA-512-crypt:password
    condition:
        uint32(0) != 0x7f454c46 and uint32(0) != 0x4d5a90 and (any of ($s*))
}
```

---

## Summary: Hunting Priority

1. **Find john.pot** → Smoking-gun evidence of password cracking; impossible to fully erase
2. **Correlate timeline** → pot-file mtime + hash-source mtime = attack window
3. **Review shell history** → identifies hash source, wordlist, and attack mode
4. **Hunt hash-source file** → proves operator had hash access; links to dump technique (Impacket, Mimikatz, etc.)
5. **Detect subsequent usage** → if cracked passwords were used, hunt for post-compromise activity (SSH/RDP logins, lateral movement)

**Confidence levels:**
- Pot file alone: **95% confident** password cracking occurred
- Pot file + shell history: **99% confident** scope and timeline
- Pot file + hash source + shell history: **100% case closure** (attackers, methods, timing all known)
