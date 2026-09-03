# Hashcat — Detection and Hunting

Because `04 - Target Evidence.md` is legitimately near-empty, this file inverts the usual Source/Target split used elsewhere in this repo: **Hunting on Source** below is where nearly all of the actionable hunting for hashcat itself lives; **Hunting on Target** is largely a redirect to the acquisition-tool pages that actually carry the target-side signal, plus the one genuine target-side tell (credential-reuse timing).

## Contents
- [Hunting Priority — Which Signal Survives Which OPSEC Choice](#hunting-priority--which-signal-survives-which-opsec-choice)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which OPSEC Choice

Hashcat exposes several flags that directly remove or reduce artifacts (`--potfile-disable`, `--restore-disable`, `--logfile-disable`, custom `--potfile-path`/`--restore-file-path`, a renamed binary). Rank hunts by what survives that scoping, strongest first:

| Rank | Signal | Survives `--potfile-disable`? | Survives `--restore-disable`? | Survives clearing shell history? | Survives renaming the binary? |
|---|---|---|---|---|---|
| 1 (strongest) | GPU driver-level utilization/telemetry showing sustained heavy compute with no legitimate corresponding workload | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes — this is process-behavior, not filename-based |
| 2 | `auditd` execve records (where syscall auditing is enabled) | ✅ Yes | ✅ Yes | ✅ Yes | ⚠️ Partial — execve still logs the binary path/name, so a renamed binary changes the search string but not whether the event exists |
| 3 | Input hash files fingerprinted by content (`$krb5tgs$`, `$krb5asrep$`, NetNTLMv2 structure, etc.) present anywhere on disk | ✅ Yes — content-based, not tool-output-based | ✅ Yes | ✅ Yes | ✅ Yes |
| 4 | Potfile / outfile content (recovered plaintexts) | ❌ **No** — this is exactly what `--potfile-disable` removes | N/A | ✅ Yes if not disabled | N/A |
| 5 | `.restore` session files | N/A | ❌ **No** — removed entirely by `--restore-disable` | ✅ Yes if not disabled | N/A |
| 6 (weakest) | Shell history (`~/.bash_history`, `~/.zsh_history`) showing the invocation line | ✅ Yes (independent of hashcat's own flags) | ✅ Yes | ❌ **No** — trivially cleared, the most operator-controllable artifact in this list |

**Build hunts on rank 1-3 as primary — GPU telemetry anomalies and content-based hash-file fingerprinting survive every hashcat-specific OPSEC flag, because neither depends on hashcat choosing to write anything at all.** Treat potfile/restore-file/shell-history evidence (ranks 4-6) as high-value **when present** but not something to rely on as a sole detection.

## Hunting on Source

```bash
# 1. Process and GPU device check — hashcat's own process name if unrenamed,
#    plus GPU utilization independent of process name
ps aux | grep -i hashcat
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv

# 2. Potfile / restore-file discovery — default profile locations first
find ~/.local/share/hashcat -maxdepth 1 -type f 2>/dev/null   # Linux
find / -iname "*.potfile" -o -iname "*.restore" 2>/dev/null    # broader sweep, any location

# 3. CONTENT-based hash-file fingerprinting — the strongest hunt in this file,
#    survives every OPSEC flag hashcat exposes because it doesn't depend on
#    hashcat's own output at all, only on files matching known hash formats
#    existing somewhere on disk
grep -rlE '\$krb5tgs\$23\$|\$krb5asrep\$23\$' / --include="*.txt" 2>/dev/null
grep -rlE '^[a-zA-Z0-9_.\$-]+::[A-Za-z0-9_.-]*:[0-9a-f]{16}:[0-9a-f]{32}:' / --include="*.txt" 2>/dev/null  # NetNTLMv2 shape

# 4. Installed copies / git checkouts, to pin the version in use
find / -iname "hashcat" -type f 2>/dev/null
git -C <path-to-checkout> log -1 --format='%H %cd' 2>/dev/null

# 5. Shell history — weakest signal (rank 6), but cheap to check
grep -iE "hashcat (-m|--hash-type)" ~/.bash_history ~/.zsh_history 2>/dev/null

# 6. auditd execve — survives a shell-history wipe
ausearch -x hashcat 2>/dev/null
```

## Hunting on Target

There is no hashcat-specific target-side hunt (see `04 - Target Evidence.md`). What actually applies here:

1. **Hunt the acquisition tool, not hashcat** — every hash type hashcat cracks has its own hunting page already built or planned in this repo:
   - `Mimikatz/lsadump (DCSync)/05 - Detection and Hunting.md` for DCSync-sourced NTLM hashes.
   - `Responder/05 - Detection and Hunting.md` for NetNTLMv2 captures (its own Hunting Priority table ranks Security 4625/Sysmon 3 as the strongest, protocol-agnostic signal — the same rank-1 logic applied there to poisoning applies here to cracking: hunt the behavior that can't be turned off, not the tool-specific flag that can).
   - Kerberoasting/AS-REP-roasting hunting will live in the planned `Impacket/GetUserSPNs (Kerberoasting)/05 - Detection and Hunting.md` once built — in the interim, filter Event 4769 for RC4 (etype `0x17`) service-ticket requests against accounts capable of AES, and Event 4768 for TGT requests against accounts with `DONT_REQ_PREAUTH` set.

2. **Hunt for credential-reuse timing** — the one genuine indirect target-side signal:

```powershell
# A previously-unseen or previously-failing credential succeeding for the
# first time is the practical tell that a cracking cycle just completed
# somewhere off-network. Compare 4625 (failure) and 4624 (success) for the
# SAME account within a tight window, days apart, with nothing in between
# that would otherwise explain a password change (no 4723/4724 password-
# reset event for that account in the same window).
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} |
  Where-Object { $_.Properties[5].Value -eq 'jsmith' } |
  Sort-Object TimeCreated |
  Select-Object TimeCreated, Id, @{n='SourceIP';e={$_.Properties[18].Value}}
```

## Fleet-Wide Sweep

Two distinct sweep scenarios apply, depending on the "compromised host repurposed as a cracking rig" nuance raised in `03 - Source Evidence.md`:

```powershell
# Scenario A: hunting for hashcat RUNNING somewhere inside the managed estate
# (relevant only if the operator is using a compromised host as compute,
# not a fully external rig the blue team has no visibility into at all)
$targets = Get-Content .\hosts.txt

Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-Process | Where-Object { $_.ProcessName -match 'hashcat' }
  Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -ErrorAction SilentlyContinue |
    Where-Object { $_.UtilizationPercentage -gt 80 }
} -ErrorAction SilentlyContinue

# Scenario B: the far more common real-world case — sweep for the credential-
# reuse tell (above) across every host, since that's the signal that exists
# regardless of where hashcat itself actually ran
$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 500 -ErrorAction SilentlyContinue
} -ErrorAction SilentlyContinue
$results | Group-Object { $_.Properties[5].Value } | Where-Object Count -gt 0 |
  Select-Object Name, Count
```

EDR/process-creation telemetry (not native Windows event logs) is the realistic way to catch Scenario A at fleet scale — filter process-creation events for `hashcat.exe`/`hashcat.bin` by name (trivially evaded by a rename) or, more durably, for sustained anomalous GPU utilization on hosts with no legitimate GPU-compute workload.

## Remediation

**Capture evidence first** — if a cracking rig (external or a compromised internal host) is identified live, image it before shutting it down; potfile/restore-file/GPU-telemetry evidence is exactly the kind of thing an operator's own cleanup script or a simple `--potfile-disable`-by-default habit can make disappear once they know they're caught.

The actual fix is **not** a detection rule against hashcat itself — hashcat cannot be prevented from running on infrastructure the defender doesn't control. Remediation here means denying it useful hash material and reusable credentials in the first place:

- **Password length and complexity that defeats mask enumeration** — a policy that only enforces character-class complexity at a fixed short length (e.g. 8 characters) is exactly what files like `masks/8char-1l-1u-1d-1s-compliant.hcmask` are built to exhaust; length is the single strongest lever against brute-force/mask attacks specifically.
- **Kerberos**: enforce AES-only ticket encryption (`msDS-SupportedEncryptionTypes`) on service accounts to remove the RC4/etype-23 material that makes Kerberoasting/AS-REP roasting cheaply crackable at all; use Group Managed Service Accounts (gMSA) with their long, randomly-rotated passwords instead of human-chosen service-account passwords.
- **NTLM/NetNTLM exposure**: the underlying remediation belongs to the *capture* tool's own page (`Responder/05 - Detection and Hunting.md`'s Remediation section covers disabling LLMNR/NBT-NS/WPAD; `Mimikatz/lsadump (DCSync)/05 - Detection and Hunting.md` covers restricting DCSync-capable replication rights) — hashcat's remediation is downstream of denying the capture, not a separate control.
- **Credential-reuse detection as a compensating control** — since hashcat itself can't be blocked, the practical detection posture (this file's Hunting on Target section) is watching for a previously-failing or previously-unseen credential succeeding, which is the one place this entire attack chain is forced back into visibility.
