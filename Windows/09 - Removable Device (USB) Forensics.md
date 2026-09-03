# Removable Device (USB) Forensics

Every USB device Windows has ever seen leaves a footprint spread across half a dozen independent locations — device-enumeration keys in the `SYSTEM` hive, driver-install logs, per-user shell keys, and (on Win10+) a dedicated event log that finally gives genuine connect/disconnect history rather than just "first and last." No single artifact here answers the whole investigative question. The value is in stacking them: one key tells you a device existed, a different key tells you what drive letter it got, a third tells you which user was logged in, and a fourth (if audit policy was ever turned on) tells you what the user actually did with it.

This note treats "USB forensics" as shorthand for **removable-device forensics generally** — not every device Windows enumerates as external is the classic USB mass-storage drive, and treating them all as if they were is the single most common miss in this artifact family (see the taxonomy below, especially UASP).

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Device Class Taxonomy](#device-class-taxonomy)
- [USBSTOR Identification Fields and the Linkage Chain](#usbstor-identification-fields-and-the-linkage-chain)
- [Devices Without a Real Serial Number](#devices-without-a-real-serial-number)
- [Volume Name and Drive-Letter Mapping](#volume-name-and-drive-letter-mapping)
- [Volume Serial Number (VSN)](#volume-serial-number-vsn)
- [Connection Timestamps](#connection-timestamps)
- [DeviceMigration Keys](#devicemigration-keys)
- [User Attribution](#user-attribution)
- [Event-Log Auditing of Actual File Interaction](#event-log-auditing-of-actual-file-interaction)
- [Device-Lifecycle Summary Table](#device-lifecycle-summary-table)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against the registry, `setupapi.dev.log`, and the Security/System event logs before any parser (RECmd/USB Detective) comes out — no third-party modules required.

```powershell
# Every USBSTOR device ever connected - vendor/product from the key name, serial number, and FriendlyName in one pass
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' | ForEach-Object {
    $device = $_.PSChildName
    Get-ChildItem $_.PSPath | Select-Object @{N='Device';E={$device}}, @{N='SerialNumber';E={$_.PSChildName}},
        @{N='FriendlyName';E={(Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).FriendlyName}}
}

# USB installation entries in setupapi.dev.log - timestamps are the host's LOCAL time zone, not UTC (see Connection Timestamps)
Select-String -Path 'C:\Windows\inf\setupapi.dev.log' -Pattern 'Device Install.*USBSTOR|VID_.*PID_' -Context 0,3

# Security-log events tied to removable-storage access/recognition (4663/4656/6416) - empty result means audit policy
# was never turned on, not "nothing happened" - confirm object-access auditing before reading absence as evidence
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663,4656,6416} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, @{N='Detail';E={ ($_.Message -split "`n" | Select-String 'Object Name|Device Description') -join ' | ' }}

# PnP driver-install events (20001/20003) outside 07:00-19:00 local - a fresh mass-storage device installed after hours
Get-WinEvent -FilterHashtable @{LogName='System'; Id=20001,20003} -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated.Hour -lt 7 -or $_.TimeCreated.Hour -ge 19 } |
    Select-Object TimeCreated, Id, Message

# Bursts of 3+ PnP device-install events inside any single hour - possible mass-storage staging ahead of exfil
Get-WinEvent -FilterHashtable @{LogName='System'; Id=20001,20003} -ErrorAction SilentlyContinue |
    Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH') } | Where-Object Count -ge 3 | Select-Object Name, Count
```

## Device Class Taxonomy

Windows enumerates every device it sees under a USB **class driver**, and which class a device belongs to determines which registry branch holds its history. All of these live in the `SYSTEM` hive (see Registry Forensics Fundamentals, note 04, for hive-loading and `CurrentControlSet` resolution mechanics — everything below is nested under whichever `ControlSetNNN` resolves as current).

| Class | What it covers | Registry home | Notes |
|---|---|---|---|
| **MSC** (Mass Storage Class) | The classic USB flash drive / external HDD — the device most people mean by "a USB stick" | `SYSTEM\CurrentControlSet\Enum\USBSTOR` | The primary focus of most of this note |
| **UASP** (USB Attached SCSI Protocol) | A faster, modern mass-storage transport used by many current external SSDs and some flash drives — same physical use case as MSC, different protocol stack | `SYSTEM\CurrentControlSet\Enum\SCSI` (not USBSTOR) | 🔴 **The single biggest miss in this artifact family.** An analyst who only checks `USBSTOR` will not see a UASP device at all — it never enumerates there. If USBSTOR looks unremarkable or empty on a host you expect had external storage attached, check the SCSI branch for UASP devices before concluding "no removable storage was used." |
| **HID** (Human Interface Device) | Keyboards, mice, and — forensically significant — **potential hardware keyloggers** disguised as an innocuous HID device | `SYSTEM\CurrentControlSet\Enum\HID` | A HID entry with an unfamiliar vendor string, or one that appeared once during a suspected physical-access window, is worth treating as a hardware-implant lead, not routine peripheral noise |
| **MTP** (Media Transfer Protocol) | Phones, digital cameras, tablets, some SD-card readers — connects via Windows Portable Devices rather than presenting as a mountable disk volume | `SOFTWARE\Microsoft\Windows Portable Devices\Devices` (registry) plus its own enumeration branch, distinct from USBSTOR | Because MTP devices don't register as USBSTOR mass-storage entries, an MTP-based phone transfer can be entirely invisible to an analyst who only pulls USBSTOR — check Windows Portable Devices separately whenever mobile-device data transfer is in scope |

## USBSTOR Identification Fields and the Linkage Chain

A USBSTOR device key's name and subkeys carry the device's identifying fields:

| Field | Where | Meaning |
|---|---|---|
| **VID** (Vendor ID) | Encoded in the USBSTOR device-instance key name | Identifies the manufacturer |
| **PID** (Product ID) | Encoded in the USBSTOR device-instance key name | Identifies the specific product line/model |
| **iSerialNumber** | The last path segment under the device-instance key | The device's reported serial number — see the placeholder-value caveat below. The FOR500 personal index also flags this field as functioning as an **alternate SCSI serial number / registry ID** in some contexts, worth cross-checking against the SCSI branch rather than assuming USBSTOR's copy is the only place it appears |
| **ParentIdPrefix** | A subkey/value under the USBSTOR device-instance key | The **link key** — see below |

`ParentIdPrefix` is the mechanism that ties a USBSTOR entry to the rest of the device's footprint elsewhere in the registry and in Win10+ event logs. Walk the chain in order:

```
SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_<vendor>&Prod_<product>\<iSerialNumber>
        │
        │  ParentIdPrefix value recorded here
        ▼
SYSTEM\CurrentControlSet\Enum\SCSI\Ven_<vendor>_Prod_<product>\<ParentIdPrefix>...
        │
        │  Device Parameters\Partmgr\DiskId
        ▼
SCSI\<ParentIdPrefix>\Device Parameters\Partmgr\DiskId
        │
        │  DiskId value matches the corresponding VBR/volume data
        ▼
Microsoft-Windows-Partition/Diagnostic.evtx — Event ID 1006 entries for that disk
        (and, separately, the Windows Portable Devices key for the same device instance)
```

Practically: if you only have a USBSTOR entry, `ParentIdPrefix` is what lets you pivot into the SCSI branch (where UASP devices already live natively, and where the same physical device's `DiskId` sits), and `DiskId` is what lets you pivot again into the Partition/Diagnostic event log for genuine connect/disconnect history (see Connection Timestamps below). Skipping this chain and reading USBSTOR in isolation is how analysts miss the richer timeline sitting one or two pivots away.

### PowerShell

To walk the full USBSTOR tree and pull every value on each device-instance key, the native equivalent of browsing it in Registry Explorer:

```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' | ForEach-Object {
    Get-ChildItem $_.PSPath | Get-ItemProperty
}
```

To decode VID/PID out of the device key name, flag a synthesized (placeholder) serial by the `&`-as-second-character tell, and surface `ParentIdPrefix` for the SCSI pivot:

```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' | ForEach-Object {
    if ($_.PSChildName -match 'Ven_(?<VID>[^&]+).*Prod_(?<PID>[^&]+)') {
        $vid = $Matches.VID; $prodId = $Matches.PID
        Get-ChildItem $_.PSPath | ForEach-Object {
            $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                VID            = $vid
                PID            = $prodId
                SerialNumber   = $_.PSChildName
                IsSynthesized  = $_.PSChildName.Length -ge 2 -and $_.PSChildName[1] -eq '&'
                ParentIdPrefix = $props.ParentIdPrefix
                FriendlyName   = $props.FriendlyName
            }
        }
    }
}
```

To sweep an entire estate for a specific device serial number of interest (e.g. a USB known to be involved in an incident) and export for pivoting:

```powershell
$targetSerial = 'AA1234567890'
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    param($Serial)
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -eq $Serial } |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, PSChildName,
            @{N='FriendlyName';E={(Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).FriendlyName}}
} -ArgumentList $targetSerial | Export-Csv C:\hunt\usb_serial_sweep.csv -NoTypeInformation
```

## Devices Without a Real Serial Number

Not every USB device reports a genuine, unique hardware serial number to Windows — some cheaper or non-compliant devices simply don't have one to report. When that happens, Windows does not leave the serial-number field blank; it synthesizes a placeholder identifier for that device instance.

🔴 **The tell: an `&` as the second character of the "serial number" field.** A synthesized value in this shape (e.g. `7&2c1c5a3f&0`) is not a real device serial — it's a Windows-generated stand-in, built from other enumeration data, used because the hardware itself never supplied a proper serial. This is itself a diagnostic fact worth recording: it tells you the device's true hardware serial was unavailable or unreadable to Windows, which matters if you're later trying to match this device instance against a physical exhibit by serial number — a straightforward serial-to-serial match will fail, because there was never a real serial to match against in the first place.

## Volume Name and Drive-Letter Mapping

Three separate keys, each contributing a different piece of the "what drive letter, what volume name" picture:

| Key | Holds | Caveat |
|---|---|---|
| `SOFTWARE\Microsoft\Windows Portable Devices\Devices` | The device's friendly/assigned volume name (the label a user sees in Explorer) | Keyed by device identifiers shared with the USBSTOR/MTP enumeration above |
| `SYSTEM\MountedDevices` | Maps drive letters to a device's unique identifier/serial number | 🔴 **Only the LAST device mapped to a given drive letter is recoverable here.** If `E:\` has been assigned to five different USB drives over the device's lifetime, `MountedDevices` shows you the fifth one only — the four prior assignments are not directly available from this key alone. Historical drive-letter history has to come from elsewhere (Partition/Diagnostic 1006 events, setupapi logs, or Properties timestamp subkeys correlated against other host activity), not from `MountedDevices` itself |
| `SOFTWARE\Microsoft\Windows Search\VolumeInfoCache` (Win7+) | A supplementary volume-name/identifier cache, useful as a second source when cross-checking `MountedDevices`' last-known mapping | Introduced Win7+; don't expect it on XP |

## Volume Serial Number (VSN)

🔴 **The VSN is not the USB's hardware serial number — this is a common point of confusion, and the two must never be conflated in a finding.** The device's hardware serial (iSerialNumber, covered above) belongs to the physical USB device itself and is reported by the device firmware. The **VSN belongs to the filesystem/partition** written onto that device — it's generated when the volume is formatted, not when the hardware was manufactured. Reformat the same physical drive and it gets a new VSN while keeping the same hardware serial; the two numbers describe entirely different layers of the same device.

Nearly all filesystems carry a VSN. The one notable exception: **GPT-partitioned raw volumes do not have a VSN** — treat "no VSN found" on a GPT device as expected, not as a parsing failure.

**Where to find it:**

| Source | OS scope | Caveat |
|---|---|---|
| `SOFTWARE\Microsoft\WindowsNT\CurrentVersion\EMDMgmt` | Older, historically the primary registry source | Often **missing entirely on modern SSD-based external devices** — don't rely on this key alone on a recent host; treat its absence as inconclusive rather than "no VSN exists" |
| Volume Boot Record (VBR) data embedded in **Event ID 1006**, `Microsoft-Windows-Partition/Diagnostic.evtx` | Win10+ | The VSN is 4 bytes at a filesystem-dependent byte offset within the VBR data captured by the event — table below |

| Filesystem | VSN byte offset within VBR data |
|---|---|
| FAT | `0x43` |
| exFAT | `0x64` |
| NTFS | `0x48` |

> 🔴 **Why the VSN matters — the strongest device-to-file-access correlation technique in this entire artifact family.** LNK files and Jump List shell-item data (see File and Folder Opening (User Activity), note 07) embed the VSN of the volume a target file lived on at the time the shortcut was created or updated. That means an LNK pointing at `E:\confidential\report.docx` doesn't just tell you a file was opened from a removable drive — its embedded VSN can be matched against a specific USB device's own VSN (recovered via `EMDMgmt` or event ID 1006's VBR data), tying a specific file access on the host back to a specific physical device, **even after that device has been disconnected and is no longer available to examine.** This is the pivot that turns "a USB drive was plugged in at some point" and "this file was opened from a removable volume" into "this specific file was opened from this specific physical device" — treat any LNK/Jump List VSN as a lead worth running against every USB VSN you've recovered for the host.

## Connection Timestamps

Three independent sources, each with different coverage and a different gotcha:

| Source | What it gives you | Gotcha |
|---|---|---|
| **`setupapi.dev.log`** (Win7+) — `setupapi.log` on XP | First-install timestamp for the device, searchable by device serial number | 🔴 Logged in the host's **local time zone**, not UTC — a timeline built by naively treating this alongside UTC-normalized event-log timestamps will be off by the host's UTC offset unless you convert explicitly |
| **USBSTOR `Properties\{83da6326-97a6-4088-9453-a19231573b29}\####` numbered sub-values** | Per-device install/connection timestamps, stored as 64-bit FILETIME | `0064` = First Install; `0066` = Last Connected (Win8+); `0067` = Last Removal (Win8+) — the two "Last" values did not exist pre-Win8, so a Win7 host will show First Install only from this GUID subkey |
| **Event ID 1006**, `Microsoft-Windows-Partition/Diagnostic.evtx` (Win10+) | Logged for **every** connect and disconnect event, not just first/last — genuine historical connection-history reconstruction, matched to a device via the `DiskId` linkage described above | 🔴 This log is **cleared during major Windows feature updates** — a real data-loss gotcha. A Win10 host that has been through several feature updates since a USB device was last used may show a much shorter connection history than actually occurred; note the host's update history when this log looks thinner than expected |

Only event ID 1006 gives real connect/disconnect *history*. The other two sources are bookend timestamps (first install, last connect, last removal) — useful, but they cannot tell you how many times a device was plugged in between those bookends.

### PowerShell

To pull a device's install block straight out of `setupapi.dev.log` by serial number (remember: local time zone, not UTC):

```powershell
Select-String -Path 'C:\Windows\inf\setupapi.dev.log' -Pattern 'AA1234567890' -Context 5,5
```

To decode the `Properties\{83da6326-97a6-4088-9453-a19231573b29}` numbered sub-values (`0064`/`0066`/`0067`) as FILETIME to get First Install / Last Connected (Win8+) / Last Removal (Win8+) for one device instance:

```powershell
$propertiesKey = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler\AA1234567890\Properties\{83da6326-97a6-4088-9453-a19231573b29}'
'0064','0066','0067' | ForEach-Object {
    $sub = Get-ItemProperty -Path (Join-Path $propertiesKey $_) -ErrorAction SilentlyContinue
    if ($sub) {
        $ftBytes = $sub.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -First 1 -ExpandProperty Value
        [PSCustomObject]@{
            Property  = @{'0064'='First Install';'0066'='Last Connected';'0067'='Last Removal'}[$_]
            Timestamp = [DateTime]::FromFileTime([BitConverter]::ToInt64($ftBytes,0))
        }
    }
}
```

## DeviceMigration Keys

When a major Windows feature update runs, the live USBSTOR/SCSI enumeration tree gets cleaned up — old, superseded device-instance entries are removed to keep the active tree current. Rather than being destroyed outright, superseded entries are migrated into a dedicated `DeviceMigration` registry area first.

This is a genuinely useful fact rather than just trivia: a device that looks completely purged from the live USBSTOR tree post-upgrade may still be fully recoverable from `DeviceMigration`, which tracks VID/PID/iSerialNumber/DiskID/LastPresentDate for the superseded entries. Always check `DeviceMigration` before concluding a device's registry trail was destroyed by an OS upgrade — it frequently wasn't, it just moved.

## User Attribution

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` records, per user, the Volume GUIDs that user's Explorer session has mounted.

- If a specific device's Volume GUID (tied back to the device via `MountedDevices`/`VolumeInfoCache` above) appears in a given user's `MountPoints2`, that user's profile was logged in and actively interacting with Explorer while the device was present — this is the standard mechanism for answering "which user had this USB device."
- 🔴 `MountPoints2` is **USBSTOR-specific in its primary use case** — it will not reliably show devices that only ever appeared as network shares in all cases, though it can **occasionally contain network-share entries too**. Don't treat a missing device in `MountPoints2` as proof no user touched it if the device in question is network-share-adjacent rather than a straightforward USBSTOR mass-storage device.
- Resolving the `NTUSER.DAT` hive back to a specific SID/username uses the same SAM/`ProfileList` material covered in Users, Groups & Authentication (note 05) — cross-reference there for the SID-to-username mechanics this note assumes.

## Event-Log Auditing of Actual File Interaction

Everything above tells you a device was connected and which drive letter/user it was tied to. These event IDs are the only artifacts in this family that can answer **what the user actually did with the files on it** — and all of them are audit-policy-dependent.

| Event ID | Log | What it captures |
|---|---|---|
| **4663** | Security | An attempt to access a removable-storage object — the specific event used for BYOD/detailed-tracking scenarios. This is the one that answers "what files did they touch on the USB," not merely "was it plugged in" |
| **4656** | Security | A failed access attempt against a removable-storage object |
| **6416** | Security | A new external device was recognized by the system — connection-level, not file-level |
| **20001 / 20003** | System | Plug-and-play driver install events — a simpler, always-available signal that a device's driver was installed, independent of audit policy |

🔴 **4663, 4656, and 6416's removable-storage-specific detail depend on audit policy being explicitly enabled** (Audit Object Access / Audit PnP Activity with removable-storage auditing turned on) — **these are not logged by default.** Their absence on a host is the normal, expected state unless you've confirmed the relevant audit policy was active; don't read "no 4663 events" as "the user never touched the drive" without first checking whether object-access auditing was ever turned on. The PnP driver-install events (20001/20003) in `System.evtx` have no such dependency and are a reasonable fallback signal when detailed auditing was never enabled.

### PowerShell

To pull the raw events for the specific IDs this note documents, Security and System side by side:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663,4656,6416} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message
Get-WinEvent -FilterHashtable @{LogName='System'; Id=20001,20003} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message
```

To extract the object/device name from each 4663 event and check whether it matches a serial number already seen under USBSTOR on this host:

```powershell
$knownSerials = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' | ForEach-Object { Get-ChildItem $_.PSPath } |
    Select-Object -ExpandProperty PSChildName
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Message -match 'Object Name:\s*(\S+)') {
        $objectName = $Matches[1]
        [PSCustomObject]@{
            TimeCreated    = $_.TimeCreated
            ObjectName     = $objectName
            MatchesUSBSTOR = [bool]($knownSerials | Where-Object { $objectName -match [regex]::Escape($_) })
        }
    }
}
```

To sweep an entire estate's Security log for any of these event IDs referencing a specific device serial, and export for timeline pivoting:

```powershell
$targetSerial = 'AA1234567890'
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    param($Serial)
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663,4656,6416} -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match [regex]::Escape($Serial) } |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, TimeCreated, Id
} -ArgumentList $targetSerial | Export-Csv C:\hunt\usb_event_sweep.csv -NoTypeInformation
```

## Device-Lifecycle Summary Table

| Question | Artifact / Key / Event ID that answers it |
|---|---|
| Was this device ever connected to this host? | `SYSTEM\CurrentControlSet\Enum\USBSTOR` (MSC) or `\SCSI` (UASP) or `\HID` (HID) or Windows Portable Devices (MTP) |
| What drive letter did it get (most recently)? | `SYSTEM\MountedDevices` (last mapping only), cross-checked against `VolumeInfoCache` |
| What was the device's volume/friendly name? | `SOFTWARE\Microsoft\Windows Portable Devices\Devices` |
| Which user was logged in while it was present? | `NTUSER.DAT\...\MountPoints2` (per user), cross-referenced to SAM/`ProfileList` (note 05) |
| When was it first installed? | `setupapi.dev.log`/`setupapi.log`, or Properties `0064` (First Install) |
| When was it last connected / last removed? | Properties `0066`/`0067` (Win8+ only) |
| Exactly when did it connect/disconnect, every time? | Event ID 1006, `Microsoft-Windows-Partition/Diagnostic.evtx` (Win10+ only, and cleared by feature updates) |
| Did the device survive a Windows feature-update purge of the live enum tree? | `DeviceMigration` registry area |
| What VSN belongs to the volume, for LNK/Jump List correlation? | `EMDMgmt` (older/hedge) or VBR data inside event ID 1006 at the filesystem-specific offset |
| What files did the user actually touch on the device? | Event ID 4663 (Security, audit-policy-dependent) |
| Was there a failed access attempt? | Event ID 4656 (Security, audit-policy-dependent) |
| Was a driver installed for this device, regardless of audit policy? | Event ID 20001/20003 (System) |

## Tooling

| Tool | Use |
|---|---|
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Primary means of browsing/batch-parsing every registry key in this note — USBSTOR/SCSI/HID enumeration, the Properties GUID timestamp sub-values, `MountedDevices`, `MountPoints2`, `DeviceMigration`, and Windows Portable Devices — with the usual `CurrentControlSet` resolution and transaction-log replay handled automatically (see Registry Forensics Fundamentals, note 04) |
| **Windows Event Viewer** (built-in) or a dedicated event-log viewer | Reading `Microsoft-Windows-Partition/Diagnostic.evtx` (event ID 1006), `Security.evtx` (4663/4656/6416), and `System.evtx` (20001/20003) — hedge deliberately here: no single specialized third-party USB-event-log parser is confidently named for this pass; standard Event Viewer or your organization's log-aggregation tooling both work fine against these logs |
| **RegRipper** | Plugin-based fast triage — a dedicated USB-history plugin extracts USBSTOR/USB device history in one pass, useful before a deeper Registry Explorer session |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| USBSTOR looks empty or unremarkable, but external storage use is suspected | Check the `SCSI` branch for UASP devices — they never enumerate under USBSTOR at all |
| "Serial number" field with `&` as its second character | A Windows-synthesized placeholder, not the device's real hardware serial — the device itself never reported one |
| VSN and USB hardware serial number treated as the same fact in a report | They are different layers (filesystem vs. physical hardware) — conflating them undermines a device-to-file correlation argument |
| `MountedDevices` cited as complete drive-letter history for a given letter | It only preserves the last device mapped to that letter — prior assignments require other sources |
| Partition/Diagnostic 1006 history for a device is thinner than expected | Check whether the host has been through a major Windows feature update since — the log is cleared on those upgrades |
| Device missing from the live USBSTOR/SCSI tree after an OS upgrade, assumed purged | Check `DeviceMigration` first — superseded entries are often migrated there rather than destroyed |
| Absence of 4663/4656/6416 events cited as proof a user never touched a device's files | These require audit policy (Object Access / PnP Activity auditing) to be explicitly enabled — silent by default |
| LNK/Jump List entry pointing at a removable-volume path, with no attempt to match its embedded VSN against known USB VSNs on the host | Missed opportunity — this is the strongest device-to-file correlation technique in this artifact family, don't skip it |
| GPT-partitioned device reported as "missing a VSN" and treated as anomalous | Expected — GPT raw volumes don't carry a VSN at all |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Hive structure, `CurrentControlSet` resolution, transaction-log replay used to parse every registry key in this note | Registry Forensics Fundamentals (note 04) |
| Resolving a `MountPoints2`/SAM SID to an actual username | Users, Groups & Authentication (note 05) |
| Whether a deleted file arrived via a USB device in the first place | Deleted Items and File Existence (note 08) |
| Matching an LNK file's or Jump List's embedded VSN back to a specific physical device | File and Folder Opening (User Activity) (note 07) |
| Security/System event log fundamentals underlying 4663/4656/6416/20001/20003/1006 | Event Log Analysis (forward reference — not yet written) |

## Resources

- SANS FOR500 poster, "External Device/USB Usage" panel — coverage checklist for keys/fields/event IDs, rewritten in this note's own words
- SANS FOR500 course syllabus (public) — removable-device forensics coverage checklist
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
- RegRipper — https://github.com/keydet89/RegRipper3.0
- Microsoft Learn — Partition diagnostic events overview: https://learn.microsoft.com/windows-hardware/drivers/install/partition-diagnostic-events
