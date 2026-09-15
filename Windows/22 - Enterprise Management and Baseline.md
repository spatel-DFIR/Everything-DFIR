# Enterprise Management and Baseline

This note covers **baselining** — the discipline of knowing what "normal" looks like for a given environment, fleet-wide, so that a deviation is a measurable finding rather than a hunch. Note 01 gave you "Know Normal" at the single-host process-tree level; note 20 forward-referenced this note as the fleet-scale prerequisite anomaly-based hunting depends on. This is that note.

> 📁 **Group Policy Object (GPO) forensics — fundamentals, storage/replication, content deep dive, DC-side and domain-joined-host investigation, and abuse/hunting/detection — now has its own standalone folder: [`GPO/`](<GPO/00 - GPO Fundamentals and Architecture.md>).** GPO remains one of the primary mechanisms an organization uses to *establish and enforce* the baseline this note discusses (security settings, software deployment, logging configuration all typically flow through it, per [`GPO/00`](<GPO/00 - GPO Fundamentals and Architecture.md#what-gpo-is--centralized-configuration-and-its-forensic-duality>)'s forensic-duality framing), and a GPO that has been quietly modified is one of the most consequential ways a baseline can silently drift out from under an investigation — but the GPO mechanics themselves, previously covered in this note, now live entirely in that folder.

> 🔴 **A host's Autoruns/persistence-mechanism inventory deviating significantly from the established fleet baseline, with no legitimate change-management explanation, is the core anomaly-based-hunting signal this note exists to enable.** Note 20 named this explicitly: hypothesis-driven and IOC-based hunting each have a bounded starting point, but anomaly-based/baseline-deviation hunting has the steepest prerequisite of the three — you cannot hunt for deviation from normal without first having established what normal **is**.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [What "Baseline" Means in This Module](#what-baseline-means-in-this-module)
- [Practical Baselining Techniques and Sources](#practical-baselining-techniques-and-sources)
- [Baseline Drift and Post-Incident Restoration](#baseline-drift-and-post-incident-restoration)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, estate-wide baselining triage — `Invoke-Command`/CIM for fleet comparison against a known-good reference. No third-party tooling required. (For GPO-specific hunt commands, see [`GPO/05 - GPO Abuse, Hunting and Detection`](<GPO/05 - GPO Abuse, Hunting and Detection.md>).)

```powershell
# Cross-host software inventory diff against a known-good reference - the Compare-Object baselining sweep this note is built on
$golden = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName
$suspect = Invoke-Command -ComputerName SuspectHost -ScriptBlock { Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName }
Compare-Object -ReferenceObject $golden -DifferenceObject $suspect
```

## What "Baseline" Means in This Module

A baseline is an established record of what *normal* looks like for a given environment — normal process trees, normal service and scheduled-task inventory, normal network connections, normal user login patterns and hours — that anomaly-based threat hunting depends on for comparison. Note 20 named this explicitly: *hypothesis-driven* and *IOC-based* hunting each have a bounded starting point (a specific technique, a specific known indicator), but *anomaly-based / baseline-deviation* hunting has the steepest prerequisite of the three — you cannot hunt for deviation from normal without first having established what normal **is**.

Note 01's "Know Normal" process-tree material is the single-host version of this: the dozen legitimate system processes, their expected paths, parents, instance counts, and sessions, built so that an unexpected `svchost.exe` parent or an out-of-place instance count jumps out as a measurable deviation rather than a vague feeling. This note is the **fleet-wide extension** of the same idea. Without a baseline, "this looks weird" is analyst intuition. With a baseline, it's a measurable deviation — the difference between a hunch and a finding you can defend in a report.

## Practical Baselining Techniques and Sources

| Source | What it establishes | Notes |
|---|---|---|
| **Autoruns / `autorunsc.exe` fleet snapshots** | A persistence-mechanism baseline — what autostart entries, services, scheduled tasks, and other launch points are *expected* across known-good machines, or on the same machine over time | Note 16 (Live Response and Volatile Data) already covers `autorunsc.exe` for live collection; this note's use of it is the same tool pointed at baseline-building rather than single-host triage — snapshot a representative sample of known-good hosts (or the same fleet before an incident) and diff against it later |
| **Golden image / reference-build comparison** | What software, services, and scheduled tasks *should* be present on a given host role, based on the organization's known-good deployment image | Comparing a suspect host's actual inventory against the golden image directly surfaces additions the attacker made that a generic "is this process legitimate" check might miss, because it's specific to *this organization's* build rather than a generic Windows baseline |
| **Software inventory / enterprise-management platforms** | Fleet-wide "what SHOULD be installed" ground truth, generated and maintained continuously rather than snapshotted ad hoc | SCCM (Microsoft Configuration Manager) and Intune are the most common examples in Microsoft-centric environments; treat the category generically where the specific platform in a given environment isn't confirmed — the forensic value is the same regardless of which product is in use: a queryable record of intended fleet state to diff a suspect host against |
| **Network baseline** | Normal outbound-connection patterns and destinations for a given host role, so an unusual C2-adjacent connection stands out | Cross-reference note 12 (Lateral Movement) for what abnormal internal connections look like, and note 16 for the live network-collection commands used to capture a host's current connection state for comparison |

The common thread across all four: each one only has value **before** an incident, or against a **known-good reference point** established independently of the host under investigation. A baseline built *from* a potentially-compromised host proves nothing — the golden image, the fleet-wide Autoruns snapshot, and the inventory-management platform's record all need to originate from a trusted source of truth.

### PowerShell

installed-software inventory via the Uninstall registry keys (avoids the slow, WMI-repair-triggering `Win32_Product` class):

```powershell
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object DisplayName
```

diff a hunt list of hosts' installed software against a known-good golden-image reference, one host at a time:

```powershell
$golden = Invoke-Command -ComputerName GoldenImageHost -ScriptBlock {
    Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName
}
foreach ($computerName in Get-Content C:\hunt\hosts.txt) {
    $target = Invoke-Command -ComputerName $computerName -ScriptBlock {
        Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName
    }
    Compare-Object -ReferenceObject $golden -DifferenceObject $target |
        Select-Object @{N='Host';E={$computerName}}, InputObject, SideIndicator
}
```

## Baseline Drift and Post-Incident Restoration

Once an incident is contained and remediated, the environment needs to return to its established baseline — and this note's baseline concept is literally what note 20's IR-lifecycle **Recovery** stage is recovering *to*. Note 21 (Remediation and Containment) already owns the mechanics of removing individual attacker artifacts (disable-and-document persistence mechanisms, credential resets) — this note's contribution is the complementary "return to known-good configuration" angle:

- **GPO re-application** — a targeted `gpupdate /force` re-pushes the organization's actual, current policy baseline to a remediated host, confirming a host that may have had local settings tampered with is back in line with domain policy — full mechanics (including confirming it actually landed) now live in [`GPO/04 - Domain-Joined Host GPO Investigation`](<GPO/04 - Domain-Joined Host GPO Investigation.md#forcing-a-refresh>).
- **Reimaging against the golden image** — for a host where the scope or depth of compromise makes surgical remediation unreliable, rebuilding against the same golden-image reference used for baselining (above) is the highest-confidence way back to known-good state.
where full reimaging isn't warranted, diffing the host's current Autoruns/software/service inventory against its fleet or golden-image baseline (per the previous section) identifies exactly what needs reverting, rather than guessing.

Baseline drift isn't only an attacker phenomenon — legitimate configuration changes, missed patches, or an admin's one-off local change all cause a host's real state to diverge from the documented baseline over time, independent of any incident. That's part of why note 21's Verification of Successful Remediation step (re-running detection techniques, re-diffing Autoruns) matters: it confirms the host has actually returned to baseline, not just that the specific artifact originally found is gone.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| A host's Autoruns/persistence-mechanism inventory deviating significantly from the established fleet baseline with no legitimate explanation | The core anomaly-based-hunting signal this note exists to enable — a deviation with no documented change-management record behind it |

## Tooling

| Tool | Use |
|---|---|
| **Autoruns / `autorunsc.exe`** (Sysinternals) | Persistence-mechanism fleet baselining and post-incident diff-checking — cross-reference note 16 (live collection) and note 21 (post-remediation verification) |
| **SCCM / Intune, or generic enterprise-management-platform inventory tooling** | Source of fleet-wide "what SHOULD be installed" ground truth — named generically since the specific platform varies by environment |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Single-host "Know Normal" process-tree baseline — the foundation this note's fleet-wide baselining builds on | **Windows OS Fundamentals & Versions (01)** |
| GPO fundamentals through abuse/hunting — GPO as the mechanism that establishes and enforces this note's baseline, and as an attacker's mass-deployment target | **[GPO/ folder](<GPO/00 - GPO Fundamentals and Architecture.md>)**, starting at 00 |
| Full event-log taxonomy | **Event Log Analysis (11)** |
| Live-host Autoruns collection mechanics this note's baselining leans on | **Live Response and Volatile Data (16)** |
| The explicit forward-reference this note fulfills — baselining as the prerequisite anomaly-based hunting depends on at fleet scale | **Threat Hunting Methodology and Intelligence (20)** |
| Post-incident remediation mechanics (disable-and-document, credential resets) that this note's baseline-restoration angle complements | **Remediation and Containment (21)** |

## Resources

- SANS FOR508 poster/index — used as a coverage-checklist only for the baselining content this note synthesizes; no verbatim reproduction
