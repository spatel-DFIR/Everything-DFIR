# Office Persistence Abuse (Test, Trusted Locations, Add-ins, Outlook)

Microsoft Office ships its own startup, extensibility, and trust model layered on top of Windows' own autostart mechanisms — and every piece of that model has been abused for persistence at some point. This note covers four related but distinct techniques that all abuse Office's *own* application-startup behavior rather than a generic Windows autostart location: the undocumented Office Test debugging hook, the legitimate add-in loading model (COM/VSTO/WLL), the Outlook Home Page rendering feature, and the Trusted Locations macro-security bypass. They're grouped together because an investigation into one of them almost always benefits from checking the others — an attacker who understands Office's registry footprint well enough to abuse one technique typically knows about the rest, and all four share the same practical constraint: they're scoped to a specific Office application, a specific installed version, and (with rare exceptions) the current user's own registry hive.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing this mechanism against Services, Scheduled Tasks, WMI Event Consumers, and DLL Hijacking.

> 🔴 **All four techniques are only as suspicious as what they load, or what they've disabled.** Add-ins, Trusted Locations, and even the Office Test key have legitimate uses in some environments (enterprise line-of-business add-ins, IT-managed network-share trusted paths, genuine Microsoft-internal debugging tooling that occasionally survives in an image). The finding is never "an add-in exists" or "a Trusted Location is configured," it's an add-in with no legitimate publisher pointing at an unsigned DLL, a Trusted Location aimed at a user-writable staging folder like `%TEMP%` or Downloads, an Office Test key that exists at all outside a genuine Microsoft development machine, or an Outlook Home Page pointing at a local file or unexpected remote URL instead of a normal folder view.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Office Test](#office-test)
- [Office Add-ins (COM, VSTO, WLL)](#office-add-ins-com-vsto-wll)
- [Outlook Home Page](#outlook-home-page)
- [Trusted Locations](#trusted-locations)
- [Scoping: Per-User, Per-Version](#scoping-per-user-per-version)
- [Event Log Evidence](#event-log-evidence)
- [Red Flags Specific to Office Persistence](#red-flags-specific-to-office-persistence)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

```powershell
# Office Test key - should not exist at all outside genuine Microsoft-internal debugging; flag its mere presence
Get-ItemProperty 'HKCU:\Software\Microsoft\Office test\Special\Perf' -ErrorAction SilentlyContinue
Get-ItemProperty 'HKLM:\Software\Microsoft\Office test\Special\Perf' -ErrorAction SilentlyContinue

# Every registered Office add-in across every installed app/version, with LoadBehavior decoded
Get-ChildItem 'HKCU:\Software\Microsoft\Office\*\*\Addins\*' -ErrorAction SilentlyContinue | ForEach-Object {
    $addin = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{ KeyPath = $_.PSPath; FriendlyName = $addin.FriendlyName; LoadBehavior = $addin.LoadBehavior; Description = $addin.Description }
}

# Add-ins with LoadBehavior indicating auto-load at startup (bit value 2 set: 3, 19, etc.) - the highest-priority subset to review first
Get-ChildItem 'HKCU:\Software\Microsoft\Office\*\*\Addins\*' -ErrorAction SilentlyContinue | Where-Object {
    ([int](Get-ItemProperty $_.PSPath).LoadBehavior -band 2) -eq 2
} | Select-Object PSChildName, @{N='LoadBehavior';E={(Get-ItemProperty $_.PSPath).LoadBehavior}}

# Every Trusted Location across all installed Office apps/versions, flagging paths outside Program Files
Get-ChildItem 'HKCU:\Software\Microsoft\Office\*\*\Security\Trusted Locations\Location*' -ErrorAction SilentlyContinue | ForEach-Object {
    $loc = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{ KeyPath = $_.PSPath; Path = $loc.Path; AllowSubFolders = $loc.AllowSubFolders; Suspicious = $loc.Path -notmatch '^[A-Za-z]:\\Program Files' }
}

# Outlook WebView (Home Page cache) entries across all folders/versions - local file or non-standard URL is the tell
Get-ChildItem 'HKCU:\Software\Microsoft\Office\*\Outlook\WebView\*' -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{ Folder = $_.PSChildName; URL = (Get-ItemProperty $_.PSPath -Name URL -ErrorAction SilentlyContinue).URL }
}

# All four techniques in one sweep, tagged by category, for fast triage
@(
    @{ Category='OfficeTest'; Path='HKCU:\Software\Microsoft\Office test\Special\Perf' }
) | ForEach-Object { if (Test-Path $_.Path) { [PSCustomObject]@{ Category = $_.Category; Value = (Get-ItemProperty $_.Path).'(default)' } } }
```

## Office Test

`HKCU\Software\Microsoft\Office test\Special\Perf` is an undocumented registry value, not created by any standard Office installation, that Microsoft's own Office binaries check on startup as an internal debugging/performance-testing hook. When present, the `(Default)` value names a DLL that Office loads and invokes automatically the next time **any** Office application starts — Word, Excel, Outlook, PowerPoint, whichever the user opens first after the key is planted.

Two properties make this an unusually clean persistence primitive compared to almost everything else in this family:

- **No macro security prompt, no Protected View warning, no user interaction at all.** Because the trigger is a registry-level hook evaluated at process startup rather than document content being opened, none of the macro-security UI an analyst would normally expect from "Office running attacker code" ever appears. The user just opens Word normally.
- **The key is not created by any legitimate Office installation or update.** Unlike Add-ins or Trusted Locations, which have obvious, common legitimate uses, `Office test\Special\Perf` existing at all — on a machine that isn't a genuine Microsoft internal development box — is itself close to a de facto indicator of abuse, which is why the Hunt Evil block above checks for bare existence rather than trying to distinguish "good" values from "bad" ones.

The same key also exists under `HKLM\Software\Microsoft\Office test\Special\Perf` for a machine-wide variant, which requires admin rights to write but then affects every user on the host who opens an Office application.

### PowerShell

Check both the HKCU and HKLM locations directly — this key's mere presence, not any particular value inside it, is the primary signal:

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Office test\Special\Perf' -ErrorAction SilentlyContinue
Get-ItemProperty 'HKLM:\Software\Microsoft\Office test\Special\Perf' -ErrorAction SilentlyContinue
```

If the key exists, verify the referenced DLL's Authenticode signature and location — a legitimate Microsoft-signed DLL in a Microsoft-owned path is a different finding than an unsigned DLL sitting in `%TEMP%` or `%APPDATA%`:

```powershell
$dll = (Get-ItemProperty 'HKCU:\Software\Microsoft\Office test\Special\Perf').'(default)'
if ($dll) { Get-AuthenticodeSignature $dll | Select-Object Path, Status, SignerCertificate }
```

## Office Add-ins (COM, VSTO, WLL)

Office supports several genuinely different add-in technologies, and each loads automatically when its corresponding host application starts:

| Add-in type | Registry footprint | Notes |
|---|---|---|
| COM add-in | `HKCU\Software\Microsoft\Office\<Version>\<App>\Addins\<ProgID>` (per-user) and `HKLM\Software\Microsoft\Office\<Version>\<App>\Addins\<ProgID>` (machine-wide, requires admin to write) | The general-purpose, most common add-in registration model — covers most third-party COM-based Office add-ins |
| VSTO add-in | Same `Addins\<ProgID>` structure, plus a `Manifest` value pointing at the `.vsto` deployment manifest | .NET-based add-ins built with Visual Studio Tools for Office; the manifest reference is the extra field worth pulling alongside `LoadBehavior` |
| WLL (Word add-in library) | Not registry-based — a `.wll` file (a renamed DLL) dropped directly into a Word startup folder, most commonly `%APPDATA%\Microsoft\Word\STARTUP\` | Loads purely by file presence in the startup folder — no `LoadBehavior` value to check at all, which makes this the variant most likely to be missed by a registry-only sweep |

The value that matters most across the registry-based variants is `LoadBehavior`, a DWORD bitmask under each add-in's key:

| `LoadBehavior` | Meaning |
|---|---|
| `0` | Not loaded automatically; may still be loaded manually or programmatically |
| `2` | Not loaded at startup — often the value an add-in falls back to after a crash disables it |
| `3` | **Loaded at startup, and currently loaded** — the standard "this add-in auto-runs" value, and the one worth checking first |
| `8` | Load on demand — not loaded automatically, loads only when explicitly invoked (e.g. a ribbon button) |
| `9` | Load-on-demand *and* currently connected — distinct from `3`; this add-in is not auto-loading at every startup, it loaded because something specifically requested it |
| `16` | Load once (first time only), then behave as load-on-demand thereafter |

`LoadBehavior = 3` is the value most directly analogous to an Auto-start service or a `LogonTrigger`ed scheduled task — it means Office loads this add-in unconditionally, every time the application starts, with no further user action required.

### PowerShell

Enumerate every registered add-in across every installed Office application and version in one pass, since the wildcard segments (`<Version>`, `<App>`) vary by what's actually installed on the host:

```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Office\*\*\Addins\*' -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ItemProperty $_.PSPath | Select-Object PSChildName, FriendlyName, LoadBehavior, Description, Manifest
}
```

Check the machine-wide location as well — an add-in registered there affects every user of that Office application on the host, and requires admin rights to have planted:

```powershell
Get-ChildItem 'HKLM:\Software\Microsoft\Office\*\*\Addins\*' -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ItemProperty $_.PSPath | Select-Object PSChildName, FriendlyName, LoadBehavior
}
```

Check Word's startup folder directly for `.wll` files, since this variant has no registry footprint at all and is invisible to the two queries above:

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Word\STARTUP" -Filter *.wll -ErrorAction SilentlyContinue
```

## Outlook Home Page

Outlook's "Home Page" feature lets a folder (most commonly the Inbox) display a rendered web page instead of the standard message list — a legitimate feature originally intended for things like an internal company portal shown when a user opens their mailbox. Historically (CVE-2017-11774 and the exploitation of it that followed), attackers abused this by pointing a folder's home page at a local HTML/script file or an attacker-controlled remote URL rather than a legitimate internal page; because Outlook renders the home page using Internet Explorer's rendering engine, a malicious page could execute code in that context, and — critically — the home page setting persists across Outlook restarts, giving the attacker re-execution on every subsequent Outlook launch without needing to re-establish access.

This is genuinely more MAPI-property-based than a single clean top-level registry key — the authoritative, persisted setting lives as a MAPI property on the folder itself (within the mailbox store, `PR_WLINK_ADDRESS_BOOK_EID`-adjacent folder-level web-view properties, most reliably read through Outlook's own object model rather than a raw registry query). That said, Outlook does cache the currently-configured URL per folder under the user's registry hive, at a version-scoped path worth checking as a fast, registry-only proxy:

```
HKCU\Software\Microsoft\Office\<Version>\Outlook\WebView\<FolderName>\URL
```

Treat this registry value as a useful, fast-to-query cache of the folder's current home-page URL rather than the sole source of truth — if the finding matters, corroborate it against the mailbox's own MAPI folder properties (via Outlook's object model, `MFCMAPI`, or equivalent) rather than relying on the registry cache alone, since the registry-cached value's own persistence/update semantics across profile changes are less rigorously documented than the underlying MAPI property.

### PowerShell

Pull the cached WebView URL for every folder/version present in the user's hive as a fast initial triage step:

```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Office\*\Outlook\WebView\*' -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{ Folder = $_.PSChildName; URL = (Get-ItemProperty $_.PSPath -Name URL -ErrorAction SilentlyContinue).URL }
}
```

Flag any URL referencing a local file path or an unfamiliar scheme rather than `https://` pointed at a known-legitimate internal or vendor domain:

```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Office\*\Outlook\WebView\*' -ErrorAction SilentlyContinue | ForEach-Object {
    $url = (Get-ItemProperty $_.PSPath -Name URL -ErrorAction SilentlyContinue).URL
    if ($url -match '^(file:|C:\\|\\\\)' -or $url -notmatch '^https?://') { [PSCustomObject]@{ Folder = $_.PSChildName; URL = $url } }
}
```

## Trusted Locations

A folder registered as a Trusted Location disables Office's macro-security warnings and Protected View entirely for any document opened from that folder — and, if `AllowSubFolders` is set, from any subfolder beneath it — regardless of the macro-security level otherwise configured. This is not code execution on its own; it's a bypass primitive that removes the one prompt standing between "user opens a macro-laden document" and "the macro runs silently."

```
HKCU\Software\Microsoft\Office\<Version>\<App>\Security\Trusted Locations\Location<N>\Path
HKCU\Software\Microsoft\Office\<Version>\<App>\Security\Trusted Locations\Location<N>\AllowSubFolders
```

| Value | Meaning |
|---|---|
| `Path` | The trusted folder itself — a trailing backslash is expected in the legitimate format Office writes |
| `AllowSubFolders` | DWORD; `0` (default/absent) = only the exact folder is trusted, `1` = every subfolder beneath it is trusted too |

An attacker-added Trusted Location pointing at a folder the attacker (or any low-privileged user) can write to — `%TEMP%`, a Downloads subfolder, a OneDrive sync folder — turns that folder into a macro-security-free drop zone: any document later placed there, by any delivery mechanism, opens with macros silently enabled. Combined with `AllowSubFolders = 1` pointed at a broad, commonly-written-to root like the user's entire Downloads folder, this becomes a standing bypass for every future malicious document rather than a one-time hijack.

### PowerShell

Enumerate every Trusted Location across every installed Office app/version and flag anything outside the expected, vendor-controlled `Program Files` locations that ship by default:

```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Office\*\*\Security\Trusted Locations\Location*' -ErrorAction SilentlyContinue | ForEach-Object {
    $loc = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{ App = $_.PSPath; Path = $loc.Path; AllowSubFolders = $loc.AllowSubFolders }
}
```

Specifically flag entries pointing into user-writable staging locations, since these are the ones that function as a practical macro-bypass drop zone rather than a legitimate, IT-managed network-share exception:

```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Office\*\*\Security\Trusted Locations\Location*' -ErrorAction SilentlyContinue | ForEach-Object {
    $loc = Get-ItemProperty $_.PSPath
    if ($loc.Path -match '\\(Temp|AppData|Downloads)\\') { [PSCustomObject]@{ App = $_.PSPath; Path = $loc.Path; AllowSubFolders = $loc.AllowSubFolders } }
}
```

## Scoping: Per-User, Per-Version

All four techniques are, with the narrow HKLM exceptions noted for Office Test and machine-wide add-ins, **per-user (`HKCU`-scoped) and per-installed-Office-version**. The version segment in each path above (`<Version>`, e.g. `16.0` for Office 2016/2019/365, `15.0` for Office 2013, `14.0` for Office 2010) means an investigation needs to enumerate whichever version(s) are actually installed on the host rather than assuming a single fixed path — a host that's been upgraded across Office versions over its lifetime, or one running side-by-side installs, can carry stale registrations under an older version's subtree that are worth checking even if that version is no longer the default. The wildcard-based queries throughout this note (`Office\*\*\Addins\*`, `Office\*\*\Security\Trusted Locations\Location*`) are written specifically to avoid hardcoding a single version and missing this.

## Event Log Evidence

None of the four techniques generates a dedicated Windows Event Log entry — all are registry-value writes and, for the WLL variant, an ordinary file drop, with no Office-specific or Windows-native event source tracking their creation.

| Log | Event ID | Meaning | Notes |
|---|---|---|---|
| Security log | 4657 | A registry value was modified | 🔴 Requires **"Audit Registry" (Object Access)** enabled *and* a SACL configured on the specific key — neither is default |
| Filesystem MACB on the referenced DLL / `.wll` / registry key last-write time | n/a | Creation/modification timestamps | See NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes and Registry Forensics Fundamentals (note 04) for pulling a key's own last-write time absent auditing |
| Prefetch / ShimCache / Amcache | n/a | Confirms an add-in DLL or Office-Test DLL actually loaded, and first/last-seen timing | See note 06 — an add-in or Office Test DLL loaded into `winword.exe`/`outlook.exe` leaves the same execution trail any loaded module would |

🔴 **As with the other HKCU-scoped, UI-adjacent mechanisms in this family, expect no log trail absent pre-configured registry auditing.** The registry value's own last-write time, the referenced DLL's filesystem timestamps, and process/module-load evidence (Prefetch, ShimCache, Amcache, or EDR process-injection telemetry showing the DLL loaded into the Office process) are the primary evidence sources here.

## Red Flags Specific to Office Persistence

- **`Office test\Special\Perf` exists at all.** This key is not created by any standard Office installation or update — its mere presence outside a genuine Microsoft-internal development machine is close to a de facto indicator of abuse, independent of what the referenced DLL turns out to be.
- **`LoadBehavior = 3` for an add-in with no legitimate publisher, no code signature, or a `FriendlyName`/`Description` that doesn't match any known vendor.** This is the "loads automatically, every time" configuration — the add-in equivalent of a service's `Start = 0x02`.
- **A `.wll` file in `%APPDATA%\Microsoft\Word\STARTUP\` with no corresponding registry `Addins` entry.** WLLs load by file presence alone, so this variant is invisible to a registry-only sweep — always check the startup folder directly rather than assuming a clean `Addins` registry enumeration is sufficient.
- **A Trusted Location pointed at `%TEMP%`, a Downloads subfolder, or any other user-writable staging directory.** This isn't code execution by itself, but it's a standing macro-security bypass — any document later placed in that folder opens with macros silently enabled, and `AllowSubFolders = 1` widens that to the entire directory tree beneath it.
- **An Outlook folder's WebView URL pointing at a local file path or an unfamiliar remote domain.** Legitimate home-page use is normally a stable, recognizable internal portal or vendor URL; a `file:` reference or a domain that doesn't match the organization's known infrastructure — especially on the Inbox, the folder most consistently opened — is the tell.
- **Any of these four findings present under an Office version the user's default/currently-configured version doesn't match.** A stale registration surviving under an older version subtree after an Office upgrade can still be relevant if that version binary is still present and launchable on the host — don't assume irrelevance just because it's not under the "current" version key.

## Tooling

| Tool | Use |
|---|---|
| **Direct registry query (`Get-ItemProperty`, Registry Editor)** | The primary tool for all four techniques — no specialized parser needed, all four live in plain registry values readable with the built-in cmdlets shown throughout this note |
| **Office's own COM Add-ins dialog (`File > Options > Add-ins`)** | Live, GUI-based view of registered add-ins and their current load state — useful for a quick visual cross-check against the registry enumeration, though it only reflects the currently-installed Office version's own view |
| **Trust Center (`File > Options > Trust Center > Trusted Locations`)** | Live, GUI-based view of configured Trusted Locations per application — same cross-check value as the Add-ins dialog |
| **`MFCMAPI`** | Direct inspection of a mailbox's MAPI folder properties, including the authoritative Outlook Home Page setting beyond what the registry cache reflects |
| **Autoruns** (Sysinternals) | Surfaces some Office add-in registrations as part of its broader autostart sweep, though coverage of Trusted Locations, Office Test, and the Outlook Home Page setting specifically is limited — treat this note's direct registry queries as the authoritative sweep for those three |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `NTUSER.DAT`'s `Software\Microsoft\Office` subtree from an acquired image rather than a live host — see Registry Forensics Fundamentals (note 04) |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `Office test\Special\Perf` exists (HKCU or HKLM) | Not created by any standard Office install — presence alone is close to a de facto indicator of abuse |
| Add-in with `LoadBehavior = 3` (or `19`), no legitimate publisher/signature | Auto-loads at every Office startup — the add-in equivalent of an Auto-start service |
| `.wll` file in `%APPDATA%\Microsoft\Word\STARTUP\` with no matching registry `Addins` entry | Loads by file presence alone — invisible to a registry-only sweep |
| Trusted Location `Path` inside `%TEMP%`, Downloads, or another user-writable staging folder | Standing macro-security bypass for any document later dropped there |
| Trusted Location `AllowSubFolders = 1` on a broad, commonly-written-to root | Widens the bypass to the entire directory tree beneath the trusted path |
| Outlook folder WebView `URL` pointing at a local file path or unfamiliar domain | Historically abused (CVE-2017-11774) for persistent code execution on Outlook startup, tied to a specific, frequently-opened folder |
| Registration present under a non-default/older installed Office version subtree | Stale but still-relevant if that version's binaries remain launchable on the host |
| No Security-log 4657 despite a suspicious value | Registry-object-access auditing is off by default for these keys — rely on the value's own last-write time and the referenced DLL's filesystem/Prefetch trail instead |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all five persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure, `NTUSER.DAT` offline access mechanics | Registry Forensics Fundamentals (note 04) |
| Another per-user, UI-adjacent hijack of a default Windows/application handler | File Association & Screensaver Hijacking (this family) |
| CLSID-based hijacking of Office's own COM-instantiated components | COM Hijacking (this family) |
| Confirming actual load/execution of an add-in or Office-Test DLL | ShimCache (AppCompatCache).md, Amcache.md, Prefetch.md (note 06) |
| Full registry-auditing/event-log mechanics (4657 and SACL configuration) | Event Log Analysis (note 11) |

## Resources

- MITRE ATT&CK T1137.002 (Office Application Startup: Office Test) — https://attack.mitre.org/techniques/T1137/002/
- MITRE ATT&CK T1137.006 (Office Application Startup: Add-ins) — https://attack.mitre.org/techniques/T1137/006/
- MITRE ATT&CK T1137.004 (Office Application Startup: Outlook Home Page) — https://attack.mitre.org/techniques/T1137/004/
- Microsoft, Registry entries for VSTO Add-ins — https://learn.microsoft.com/visualstudio/vsto/registry-entries-for-vsto-add-ins
- Microsoft, Designate Trusted Locations for Files in Office — https://learn.microsoft.com/deployoffice/security/designate-trusted-locations-for-files-in-office
- Mandiant, "Breaking the Rules: A Tough Outlook for Home Page Attacks" (CVE-2017-11774) — https://www.mandiant.com/resources/breaking-the-rules-tough-outlook-for-home-page-attacks
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
- Office Trusted Locations macro-security bypass: Unmapped — no confidently-known MITRE sub-technique ID exists for this specific mechanism; used rather than guessing one, per this repo's documented convention (see `Windows/Scripts/persistence/README.md`)
