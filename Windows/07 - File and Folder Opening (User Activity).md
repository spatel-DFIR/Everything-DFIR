# File and Folder Opening (User Activity)

The "Evidence of Program Execution" family (note 06) answers "did this program run?" This note answers a related but distinct question: **did this specific user access this specific file or folder, and when?** The two questions overlap — opening a document often launches an application, and an application's Jump List can show both — but they are not the same claim, and the artifacts below are built and interpreted differently from the execution-evidence family.

Nearly everything here lives per-user, mostly in `NTUSER.DAT` (with one major exception — Shell Bags, which lives primarily in `USRCLASS.DAT`). See Registry Forensics Fundamentals (note 04) for hive-loading, `CurrentControlSet`-equivalent resolution, and transaction-log replay mechanics that apply to every registry key cited below.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Shell Bags](#shell-bags)
- [Recent Files & RecentDocs](#recent-files--recentdocs)
- [Open/Save MRU & Last Visited MRU](#opensave-mru--last-visited-mru)
- [User Typed Paths](#user-typed-paths)
- [WordWheelQuery](#wordwheelquery)
- [Shortcut (LNK) Files](#shortcut-lnk-files)
- [Office-Specific Tracking](#office-specific-tracking)
- [Internet Explorer file:///](#internet-explorer-file)
- [Jump Lists — the File-Access Angle](#jump-lists--the-file-access-angle)
- [Summary: Which Artifact Answers Which Question](#summary-which-artifact-answers-which-question)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native one-liners across this note's registry-based artifacts — no third-party modules required. Shell Bags' BagMRU/Bags binary structures and an LNK's embedded target metadata are **not** decoded here (see each section's own PowerShell → Interpret for the honest limits and the real parser to reach for).

```powershell
# RecentDocs - every rollup, per-extension, and Folder subkey with its current values in one pass
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' -Recurse |
    ForEach-Object { Get-ItemProperty -Path $_.PSPath }

# TypedPaths - paths manually typed into the Explorer address bar - prior-knowledge signal, not casual browsing
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths' -ErrorAction SilentlyContinue

# WordWheelQuery - terms typed into the Explorer search box - what the user was hunting for on their own machine
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery' -ErrorAction SilentlyContinue

# LNK files in the general Recent folder, newest-accessed first - each survives deletion of its target
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\*.lnk" | Sort-Object LastWriteTime -Descending |
    Select-Object Name, CreationTime, LastWriteTime

# Office File MRU across every installed Office version/app in one sweep
Get-ChildItem 'HKCU:\Software\Microsoft\Office' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -eq 'File MRU' } | ForEach-Object { Get-ItemProperty $_.PSPath }

# Shell Bags presence/scale check only - a count, not a decode of the BagMRU folder hierarchy (needs SBECmd)
Get-ChildItem 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU' -Recurse -ErrorAction SilentlyContinue |
    Measure-Object | Select-Object -ExpandProperty Count
```

## Shell Bags

Windows Explorer remembers how you like each folder displayed — icon size, sort order, whether you were in list view or detail view — so it can restore that view the next time you open the same folder. Storing "this folder's preferred view" per folder, per user, requires Explorer to keep a running record of every folder a user has ever browsed into, locally, over the network, or on removable media. That running record is **Shell Bags**, and it is one of the most valuable folder-access artifacts on a Windows host precisely because Explorer was never trying to build a forensic log — it was just trying to remember your view settings.

Shell Bags is really **two structures that work as a pair**:

| Structure | What it stores |
|---|---|
| **BagMRU** | The **folder hierarchy** itself — the tree of folders the user has navigated into, in the order navigated, including parent/child relationships |
| **Bags** | The **view-preference data** for each folder referenced in BagMRU — icon size, sort column, window position, and similar per-folder display settings |

Neither half is useful alone: BagMRU tells you *which folders existed and were browsed*, and Bags tells you *how each one was displayed* — but Bags entries are keyed to BagMRU's structure, so you read them together, not in isolation.

**Where it lives:**

| Location | Role |
|---|---|
| `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` | Primary folder-hierarchy data (Windows Vista and later) |
| `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags` | Primary view-preference data (Vista and later) |
| `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` | Residual/legacy folder-hierarchy data — pre-Vista primary location, and still populated in some cases on later OS versions (notably Desktop and network-share entries) |
| `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags` | Residual/legacy view-preference data, same caveat as above |

`USRCLASS.DAT` is the per-user classes hive (see Registry Forensics Fundamentals, note 04, for its location under `%USERPROFILE%\AppData\Local\Microsoft\Windows\`) — treat it as mandatory reading alongside `NTUSER.DAT` for this artifact; a Shell Bags analysis that only pulls `NTUSER.DAT` is an incomplete one on Vista and later.

🔴 **The single most valuable property of Shell Bags: it outlives the folder it describes.** Because BagMRU entries are added when a folder is first browsed and are not automatically purged when that folder is later deleted, renamed, moved, or overwritten, Shell Bags can prove a folder **existed and was accessed at some point in the past even though it does not exist on the system today**. This is genuinely powerful in cases involving anti-forensic cleanup, exfiltration staging directories that were deleted after use, or attacker tooling folders removed post-intrusion — Shell Bags may be the only artifact left attesting that the folder was ever there.

A subtlety worth flagging in the other direction: **copying a folder can create a new Shell Bags entry** for the copy's path, distinct from the entry for the original. Don't assume a Shell Bags entry for a given path means the user necessarily navigated to an original, long-standing directory — it may reflect a freshly-copied duplicate, which matters when you're trying to establish provenance of a specific folder instance.

### PowerShell

To confirm Shell Bags data exists in both hive locations before reaching for a real parser:

```powershell
Test-Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU'
Test-Path 'HKCU:\Software\Microsoft\Windows\Shell\BagMRU'
```

With the honest limit that this counts BagMRU subkeys as a rough proxy for "how many folders are tracked" but does **not** decode the MRUListEx ordering, the shell-item ID lists, or the paired Bags view-preference data — that decode requires ShellBagsExplorer/SBECmd (see Tooling):

```powershell
(Get-ChildItem 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU' -Recurse -ErrorAction SilentlyContinue |
    Measure-Object).Count
```

To sweep an estate for hosts where Shell Bags data is unexpectedly absent (possible profile wipe/cleanup), then hand the offline hive to SBECmd for the real decode:

```powershell
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    [PSCustomObject]@{
        ComputerName   = $env:COMPUTERNAME
        UsrClassBagMRU = Test-Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU'
    }
} | Export-Csv C:\hunt\shellbags_sweep.csv -NoTypeInformation

# Outer harness - SBECmd against an offline USRCLASS.DAT for the actual BagMRU/Bags decode
& 'C:\Tools\SBECmd.exe' -d "$env:LOCALAPPDATA\Microsoft\Windows\UsrClass.dat" --csv C:\hunt\shellbags_out
```

## Recent Files & RecentDocs

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` is Explorer's own general-purpose "what did this user recently open" log, independent of any specific application. It has three layers, all MRU-ordered:

| Subkey | Tracks | Depth |
|---|---|---|
| `RecentDocs` (root/rollup key) | Every file or folder opened, regardless of extension | Last ~150 items |
| `RecentDocs\.<ext>` (per-extension subkeys) | Files of that specific extension only (e.g. `.docx`, `.pdf`, `.xlsx`) | Last ~20 items per extension, each its own MRU list |
| `RecentDocs\Folder` | Folders opened (as distinct from files) | Last ~30 folders, same MRU logic |

**Interpretation mechanic that matters:** within any MRU-ordered subkey, the most-recently-accessed item sits at the head of the MRU order, and that subkey's own **last-write time** gives you a timestamp for "the most recent time a file of this type (or a folder) was opened" — even though individual entries inside the key don't each carry their own timestamp. That means the per-extension subkeys are frequently more useful than the rollup key: if you only care about `.pdf` activity, the `.pdf` subkey's last-write time tells you exactly when the user's most recent PDF was opened, without needing to wade through 150 mixed-extension rollup entries.

### PowerShell

To enumerate the rollup key's values plus the names of every per-extension and `Folder` subkey present:

```powershell
Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' | Select-Object -ExpandProperty Property
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' | Select-Object PSChildName
```

Since no built-in cmdlet exposes a registry key's own last-write time, this helper wraps the Win32 `RegQueryInfoKey` API via `Add-Type` (still native .NET/PowerShell, no third-party module) to recover it — this is the mechanic behind "the `.pdf` subkey's last-write time = most recent PDF opened" above:

```powershell
function Get-RegKeyLastWriteTime {
    param([Parameter(Mandatory)][string]$Path)
    Add-Type -Namespace Win32Reg -Name Advapi32 -MemberDefinition @'
[DllImport("advapi32.dll")]
public static extern int RegQueryInfoKey(Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
    System.Text.StringBuilder lpClass, ref uint lpcchClass, System.IntPtr lpReserved, out uint lpcSubKeys,
    System.IntPtr lpcbMaxSubKeyLen, System.IntPtr lpcbMaxClassLen, out uint lpcValues,
    System.IntPtr lpcbMaxValueNameLen, System.IntPtr lpcbMaxValueLen, System.IntPtr lpcbSecurityDescriptor,
    out long lpftLastWriteTime);
'@ -ErrorAction SilentlyContinue
    $key = Get-Item $Path
    $class = New-Object System.Text.StringBuilder 255
    [uint32]$classLen = 255; [uint32]$subKeys = 0; [uint32]$values = 0; [long]$lastWrite = 0
    [Win32Reg.Advapi32]::RegQueryInfoKey($key.Handle, $class, [ref]$classLen, [IntPtr]::Zero, [ref]$subKeys,
        [IntPtr]::Zero, [IntPtr]::Zero, [ref]$values, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$lastWrite) | Out-Null
    [DateTime]::FromFileTimeUtc($lastWrite)
}

# Every per-extension subkey, sorted by last-write time - answers "when was the most recent file of this
# type opened" without wading through the mixed-extension rollup key
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' |
    ForEach-Object { [PSCustomObject]@{ SubKey = $_.PSChildName; LastWrite = Get-RegKeyLastWriteTime $_.PSPath } } |
    Sort-Object LastWrite -Descending
```

To sweep an estate for a specific extension's activity count per host (swap `.pdf` for the extension you're chasing), export for pivoting:

```powershell
$results = Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf'
    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        EntryCount   = (Get-Item $key -ErrorAction SilentlyContinue).ValueCount
    }
}
$results | Export-Csv C:\hunt\recentdocs_pdf_sweep.csv -NoTypeInformation
```

## Open/Save MRU & Last Visited MRU

Both live under `ComDlg32` and both are populated by the same Windows-provided **common dialog box** — the "Open" or "Save As" window that appears inside a huge range of applications (Office, browsers, chat clients, PDF readers, and effectively anything that doesn't roll its own file picker).

| Artifact | Registry key | What it records |
|---|---|---|
| **Open/Save MRU** | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU` (Win7+) / `...\ComDlg32\OpenSaveMRU` (XP) | Files opened or saved through a common dialog box, organized into per-extension MRU lists (mirrors the RecentDocs per-extension pattern) |
| **Last Visited MRU** | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` (Win7+) / `...\ComDlg32\LastVisitedMRU` (XP) | The **last directory a specific application** used with a common dialog box |

Open/Save MRU tells you what files were touched. **Last Visited MRU tells you something arguably more interesting: which directory a specific application last interacted with.** Because the key is organized by the calling application rather than by file extension, it directly ties an app to a folder — and that pairing can surface directories the user would never have reached by casually browsing. An application's Last Visited MRU entry pointing at an unexpected staging folder, an unusual removable-media path, or a directory with no obvious business purpose is a lead worth chasing precisely because it's the *application*, not the user's normal Explorer habits, that put that directory there.

### PowerShell

To enumerate the per-extension (Open/Save) and per-application (Last Visited) subkey names on Win7+:

```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU' -ErrorAction SilentlyContinue |
    Select-Object PSChildName

Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU' -ErrorAction SilentlyContinue |
    Select-Object PSChildName
```

For Win7+ PidlMRU values are binary shell-item ID lists, not plain path strings. PowerShell can confirm which application/extension subkeys exist and rank them by last-write time (helper defined in Recent Files & RecentDocs → Interpret above), but decoding the embedded path out of the PIDL itself needs RECmd/Registry Explorer. XP-era `LastVisitedMRU`/`OpenSaveMRU`, by contrast, stored plain path strings and decode natively with no extra work:

```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU' -ErrorAction SilentlyContinue |
    ForEach-Object { [PSCustomObject]@{ Application = $_.PSChildName; LastWrite = Get-RegKeyLastWriteTime $_.PSPath } } |
    Sort-Object LastWrite -Descending

# XP-era equivalent - plain path strings, no PIDL to decode
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU' -ErrorAction SilentlyContinue
```

To sweep an estate for Last Visited MRU application entries not on a known-good allowlist (structure/naming only, not a target-path decode) — a triage lead for apps interacting with dialogs in unexpected ways:

```powershell
$allowlist = Get-Content C:\hunt\known_apps.txt
$remote = Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU' -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, PSChildName
}
$remote | Where-Object { $allowlist -notcontains $_.PSChildName } | Export-Csv C:\hunt\lastvisited_sweep.csv -NoTypeInformation
```

## User Typed Paths

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` records paths the user **manually typed** into the File Explorer address bar, as opposed to arriving at a folder by clicking through the folder hierarchy.

That distinction is the entire forensic value of this key. A folder that shows up in Shell Bags or RecentDocs only tells you the user *ended up* there — they could have arrived by clicking, by a shortcut, or by an application opening it for them. A path in `TypedPaths` means the user **already knew the exact path existed** before they navigated to it — they had to type it, character by character, rather than discover it. That's a materially stronger "prior knowledge" signal than "the folder was clicked into," and it applies just as well to UNC/network paths (`\\server\share\...`) as to local ones — a typed UNC path is strong evidence the user knew a specific network resource existed and how to reach it directly.

### PowerShell

The `TypedPaths` values (`url1`, `url2`, …) are plain path/UNC strings, fully native to read, no decode needed:

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths' -ErrorAction SilentlyContinue |
    Select-Object -Property * -ExcludeProperty PS*
```

To sweep an estate for typed UNC paths specifically — a typed UNC path is a stronger prior-knowledge signal than one reached by browsing, so flag shares outside expected business use:

```powershell
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    $props = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths' -ErrorAction SilentlyContinue
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Name -like 'url*' -and $_.Value -like '\\*' } |
            Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, Name, Value
    }
} | Export-Csv C:\hunt\typedpaths_unc_sweep.csv -NoTypeInformation
```

## WordWheelQuery

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` stores the terms a user has typed into the **File Explorer search box** (not a web search — this is local file search), stored as Unicode strings in MRU order.

This is one of the few artifacts in this note that answers "what was the user looking *for*" rather than "what did the user open." A search term of `password`, `confidential`, a specific project codename, or the exact filename of a sensitive document is direct evidence of intent — the user wasn't just browsing, they were hunting for something specific on their own machine. Treat WordWheelQuery as an intent artifact to pair with whatever the user subsequently opened (via RecentDocs, Open/Save MRU, or an LNK file) immediately afterward.

### PowerShell

Search-term values decode natively as Unicode strings; `MRUListEx` is a binary MRU-order index and is excluded here since the terms themselves matter more than their order for triage:

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery' -ErrorAction SilentlyContinue |
    Select-Object -Property * -ExcludeProperty PS*, MRUListEx
```

To sweep an estate for search terms matching a sensitive-term watchlist:

```powershell
$terms = 'password','confidential','ssn','secret'
$remote = Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    $props = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery' -ErrorAction SilentlyContinue
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' -and $_.Name -ne 'MRUListEx' } |
            Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, Name, Value
    }
}
$remote | Where-Object { $t = $_.Value; $terms | Where-Object { $t -match [regex]::Escape($_) } } |
    Export-Csv C:\hunt\wordwheelquery_hits.csv -NoTypeInformation
```

## Shortcut (LNK) Files

Windows automatically creates a `.lnk` shortcut file every time a user opens a file, folder, or device through Explorer or a shell-integrated common dialog — the user never asks for this, and in most cases never sees it happen.

**Where they live:**

| Location | Scope |
|---|---|
| `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\` | General-purpose LNK files, created by Explorer for any file/folder/device access |
| `%USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent\` | Office-specific LNK files, created alongside the general set when Office applications open documents |

Each LNK file carries **two independent layers of timestamp evidence**, and conflating them is the most common mistake with this artifact:

| Layer | What it tells you |
|---|---|
| **The LNK file's own creation/modification time** (its `$STANDARD_INFORMATION` metadata, same as any file on disk) | *First* time this specific file/folder was opened (LNK creation) and *most recent* time it was opened (LNK modification) — this describes the shortcut's own history |
| **The LNK's embedded target metadata** (shell-item data inside the LNK) | A snapshot of the **target file** at the moment the LNK was made/updated: the target's own modified/accessed/created timestamps, volume serial number, network share path if applicable, the target's original full path, and the originating system name |

🔴 **An LNK file survives the deletion of the file it points to.** Because the LNK is a separate file created by Windows shell integration, deleting, moving, or renaming the target — or removing the media it lived on entirely — does not delete or update the LNK. This means an LNK file can be the *only* surviving evidence describing a file that no longer exists anywhere on the system: its original full path, its size-adjacent metadata, and the volume or network share it came from, all preserved in a shortcut that outlived its target. This is one of the highest-value facts in this entire note — always check `Recent\` for LNK files referencing paths that no longer resolve to anything on the live system.

### PowerShell

Jump List file mechanics (a separate OLE/CFB container format) are covered in `06/Jump Lists.md`, not here — the commands below are LNK-specific.

Enumerate LNK files in both Recent locations, newest-modified (most recently opened target) first:

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\*.lnk", "$env:APPDATA\Microsoft\Office\Recent\*.lnk" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object FullName, CreationTime, LastWriteTime
```

PowerShell reads the LNK file's **own** creation/modified dates (first/last opened) natively; the gap between them approximates how long the shortcut has been in active use. The **embedded target shell-item metadata** (target timestamps, volume serial number, network path, originating system name) is a binary structure inside the `.lnk` and is **not** natively decodable — that layer requires LECmd (see Tooling):

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\*.lnk" |
    Select-Object Name, CreationTime, LastWriteTime, @{N='DaysBetweenFirstAndLastOpen';E={($_.LastWriteTime - $_.CreationTime).Days}}
```

Sweep an estate for the most recently touched LNK files per host, export for timeline pivoting, then hand the collected directory to LECmd for the real target-metadata decode:

```powershell
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\*.lnk" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 5 |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, Name, LastWriteTime
} | Export-Csv C:\hunt\lnk_sweep.csv -NoTypeInformation

# Outer harness - LECmd for the actual embedded-target-metadata decode (orphaned-target detection, etc.)
& 'C:\Tools\LECmd.exe' -d "$env:APPDATA\Microsoft\Windows\Recent" --csv C:\hunt\lnk_out
```

## Office-Specific Tracking

Microsoft Office maintains its own, richer parallel to the generic Explorer artifacts above — all under `NTUSER.DAT\Software\Microsoft\Office\<Version>\<AppName>\`, where `<Version>` is the Office build number (`12.0` = Office 2007, `14.0` = Office 2010, `15.0` = Office 2013, `16.0` = Office 2016/2019/Microsoft 365) and `<AppName>` is `Word`, `Excel`, `PowerPoint`, etc.

| Sub-artifact | Key (under the app's Office key) | What it adds beyond the generic equivalent |
|---|---|---|
| **Office Recent Files / File MRU** | `File MRU` | Unlike the generic `RecentDocs` key, this stores the document's **full path** directly against each MRU entry, plus a **last-opened timestamp** per entry — no reconstruction via key-last-write-time needed |
| **MS Word Reading Locations** | `Word\Reading Locations` (Word 2013+) | The **last read position** within a document, plus a **last-closed time**. Paired with File MRU's open time for the same document, the gap between the two can approximate a **session duration** — how long the user actually had that document open |
| **Office Trust Records** | `Security\Trusted Documents\TrustRecords` | Audits which macro-enabled or otherwise security-flagged documents the user **explicitly chose to trust** past a security warning — full path, the time trust was granted, and (per Microsoft's retention behavior) often years of accumulated history. Directly relevant to phishing/malicious-macro investigations: a Trust Record is evidence the user clicked past a warning specifically for that file |

**Office OAlerts** is a separate, event-log-based artifact rather than a registry key: Office applications log dialog warnings shown to the user — e.g. "do you want to save changes before closing?" — as **Event ID 300** in `OAlerts.evtx`. It's weak evidence on its own (a dialog being shown isn't proof of a deliberate action), but it is real, timestamped confirmation that the user was actively interacting with a specific file at a specific moment, and it's useful corroboration when File MRU and Reading Locations data for the same document line up with an OAlerts entry.

### PowerShell

Enumerate File MRU/Reading Locations subkeys across every installed Office version/app, plus Trust Records for a given app:

```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Office' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -in @('File MRU','Reading Locations') } |
    Select-Object PSChildName, PSParentPath

Get-Item 'HKCU:\Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords' -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Property
```

Each File MRU value string embeds the full path plus a bracketed last-opened-time token directly (unlike generic `RecentDocs`, no key-last-write-time workaround needed). This note doesn't document the exact bracket-token byte offsets, so the raw values below are read natively but split into path/timestamp only via RECmd (see Tooling) for a guaranteed-correct result:

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Office\16.0\Word\File MRU' -ErrorAction SilentlyContinue |
    Select-Object -Property * -ExcludeProperty PS*
```

Sweep Trust Records across every Office app/version on an estate, then correlate against OAlerts Event ID 300 for the same time window (full Event Log coverage in Event Log Analysis, note 11):

```powershell
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    Get-ChildItem 'HKCU:\Software\Microsoft\Office' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -eq 'TrustRecords' } |
        ForEach-Object {
            Get-ItemProperty $_.PSPath | Select-Object -Property * -ExcludeProperty PS* |
                ForEach-Object { [PSCustomObject]@{ ComputerName = $env:COMPUTERNAME; Document = $_ } }
        }
} | Export-Csv C:\hunt\trustrecords_sweep.csv -NoTypeInformation

Get-WinEvent -FilterHashtable @{ LogName = 'OAlerts'; Id = 300 } -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message
```

## Internet Explorer file:///

Internet Explorer's history database — `WebCacheV*.dat` on modern Windows (the WebCache ESE database; see Registry Forensics Fundamentals note 04's sibling coverage of ESE-based stores) — doesn't only record web URLs. It also records **local and network file accesses** in the form of `file:///C:/path/to/file.ext` entries, because the same underlying shell/URL-history engine handles both.

Two things make this artifact more durable and more ambiguous than it first appears:

- **It persists even where Internet Explorer itself has been removed.** The `WebCache` engine underlying this history is a shared Windows component, not IE-exclusive, so historical `file:///` entries can remain recoverable on systems where IE has since been uninstalled or superseded by Edge.
- **A `file:///` entry does not necessarily mean the file was opened inside a browser.** Other shell-integration paths can populate the same history store — this is corroborating evidence of file access, not proof of a specific application having been used to view the file. Treat it the way you'd treat ShimCache's "presence, not proof of a specific action" caveat (see `ShimCache (AppCompatCache).md`, note 06): valuable, but pair it with another artifact before asserting exactly how the file was accessed.

## Jump Lists — the File-Access Angle

Jump Lists are fully covered mechanically in `06 - Evidence of Program Execution/Jump Lists.md` (AppID naming, the OLE/CFB container structure, Automatic vs. Custom Destinations, JLECmd parsing) — this note does not re-derive any of that.

What belongs here is the interpretation angle: beyond confirming an application ran, each Jump List entry is a per-item record of a specific file or object that application opened, complete with its own timestamp data. That combination — **which application, which specific file, and when** — in a single artifact is unusual; most of the artifacts in this note give you two of those three facts at best (RecentDocs gives file + rough time but not the app; Last Visited MRU gives app + directory but not a specific file). When a Jump List entry and a RecentDocs/Office File MRU entry corroborate each other for the same file, that's about as strong a "this user opened this file with this application at this time" case as host-based artifacts get.

## Summary: Which Artifact Answers Which Question

| Artifact | Question it answers | Per-user? | Survives target deletion? |
|---|---|---|---|
| **Shell Bags** | Which folders (local/network/removable) has this user browsed, including folders that no longer exist? | Yes | Yes — this is its defining property |
| **RecentDocs** | What files/folders has this user opened recently, overall or by extension? | Yes | No — reflects current MRU state only |
| **Open/Save MRU** | What files has this user opened/saved via a common dialog box? | Yes | No |
| **Last Visited MRU** | Which directory did a specific application last interact with? | Yes | No |
| **User Typed Paths** | Did the user already know this exact path before navigating to it? | Yes | No |
| **WordWheelQuery** | What was the user searching for on their own machine? | Yes | No |
| **LNK Files** | When was this specific file first/last opened, and what did the target look like at that time? | Yes | **Yes — the LNK itself persists** |
| **Office File MRU / Reading Locations** | What Office document was opened, from what full path, for how long? | Yes | No |
| **Office Trust Records** | Did the user explicitly trust a macro-enabled/flagged document? | Yes | No |
| **Office OAlerts** | Was the user actively interacting with a specific file at a specific time? | Yes (event log, but user-session-scoped) | N/A (event log) |
| **IE file:///** | Was this local/network file accessed via a shell/browser-integrated path? | Yes | Yes — history entry can outlive the file |
| **Jump Lists** | Which app opened which specific file, and when? | Yes | Depends — entry persists until it ages out of the list |

## Tooling

| Tool | Use |
|---|---|
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Primary means of viewing/batch-parsing every registry-based artifact in this note — RecentDocs, ComDlg32 (Open/Save + Last Visited MRU), TypedPaths, WordWheelQuery, Office File MRU/Reading Locations/Trust Records, and Shell Bags' raw BagMRU/Bags structures |
| **ShellBagsExplorer** (Eric Zimmerman) | Purpose-built Shell Bags parser — reconstructs the BagMRU folder hierarchy paired with each folder's Bags view-preference data, across both `USRCLASS.DAT` and `NTUSER.DAT` |
| **LECmd** (Eric Zimmerman) | Primary LNK file parser — decodes both the LNK file's own timestamps and its embedded target metadata (target timestamps, volume serial number, network share info, original path, system name) |
| **JLECmd** (Eric Zimmerman) | Jump List parser — see `06/Jump Lists.md` for full coverage; relevant here for the file-access angle covered above |
| **RegRipper** | Plugin-based alternative for quick extraction of RecentDocs, ComDlg32, TypedPaths, and Office MRU keys, useful for rapid triage before a deeper Registry Explorer pass |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Shell Bags entry for a folder that no longer exists anywhere on the live filesystem | Shell Bags does not purge on deletion — this is direct evidence the folder existed and was browsed at some point, independent of its current absence; check for anti-forensic cleanup or exfiltration staging |
| Shell Bags entries for both an original folder and a same-named copy at a different path | Copying a folder creates a new Shell Bags entry — don't assume a single long-standing folder when the entry may reflect a fresh duplicate |
| LNK file in `Recent\` whose target path no longer resolves | The LNK survives deletion of its target — treat the LNK's embedded metadata as the last known snapshot of a file that is now gone, moved, or on unattached media |
| TypedPaths entry for a UNC/network path with no corresponding legitimate business reason | Strong evidence the user had prior knowledge of a specific network resource before typing it directly, rather than discovering it by browsing |
| WordWheelQuery entry containing a sensitive term (e.g. a password, project codename, or specific filename) | Evidence of deliberate intent — the user was hunting for something specific, not casually browsing |
| Office Trust Record for a macro-enabled document opened during a known phishing window | User explicitly clicked past a security warning to trust a flagged document — directly relevant to macro-malware delivery investigations |
| IE/WebCache `file:///` entry cited as proof the file was opened in a browser | Unsupported on its own — other shell-integration paths populate the same history store; corroborate with another artifact before asserting the access method |
| Last Visited MRU entry pointing an application at an unexpected or unusual directory | The application, not the user's normal Explorer habits, put that directory there — a lead worth chasing on its own |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Jump Lists mechanics (AppID, OLE/CFB structure, Automatic vs. Custom Destinations, JLECmd) | **Jump Lists** (`06 - Evidence of Program Execution/Jump Lists.md`) |
| Registry hive structure, `USRCLASS.DAT`/`NTUSER.DAT` loading, transaction-log replay used to acquire every key in this note | **Registry Forensics Fundamentals** (note 04) |
| Establishing that a file/folder existed on disk even after deletion, beyond what Shell Bags and LNK files alone show | **Deleted Items and File Existence** (note 08 — in progress alongside this note) |
| Attachment- and message-level file handling that overlaps with Office document tracking here | **Email Forensics** (forward reference — not yet written) |
| Full browser-history depth behind the IE `file:///` angle covered here | **Web Browser Forensics** (forward reference — not yet written) |

## Resources

- Eric Zimmerman's tools (Registry Explorer, RECmd, ShellBagsExplorer, LECmd, JLECmd) — https://ericzimmerman.github.io/
- RegRipper (community-maintained registry plugin framework) — https://github.com/keydet89/RegRipper3.0
- SANS FOR500 poster, "Windows Artifact Analysis: Evidence of… File and Folder Opening" panel — coverage checklist for path/key/interpretation facts, rewritten in this note's own words
- SANS FOR500 course syllabus (public) — file/folder-opening artifact coverage checklist
