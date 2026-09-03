# Browser Helper Objects & Shell Extensions

Both techniques in this note are COM-registration-based — the same underlying mechanism as full COM Hijacking (MITRE ATT&CK T1546.015), but scoped to two specific, well-known COM extension-point categories rather than the arbitrary CLSID-shadowing approach general COM hijacking uses. Where COM hijacking can target almost any CLSID a target application happens to reference, Browser Helper Objects and shell extensions each register into one narrow, purpose-built loading slot that Windows itself defines and consults automatically — no target-application CLSID reference needs to be found and shadowed at all, because the loading location already exists precisely for this purpose.

**Browser Helper Objects (BHOs)** are COM DLLs that Internet Explorer loads automatically into every new browser instance. 🔴 **Set the right expectation here before reading further: this is a legacy technique tied specifically to Internet Explorer, not to Edge's modern Chromium-based extension model.** On any host where IE has been fully retired — which describes most current, actively-managed Windows estates, since IE was formally retired as a product in 2022 and removed from the OS in later Windows 10/11 servicing — this technique has essentially nothing left to attach to. It remains genuinely relevant in two situations: legacy or regulated environments (certain government, healthcare, and industrial-control estates) that retain IE or Edge's IE-mode compatibility for a dependent line-of-business application, and historical or timeline-reconstruction analysis of an older compromise where IE was still the primary or a coexisting browser. This note covers BHOs at that level of expectation — not as equally current with the other techniques in this persistence family.

**Shell extensions** are a broader and still fully current category: COM objects that `explorer.exe` (and any other process hosting the shell namespace — an `Open`/`Save As` common dialog in a completely unrelated application counts) loads to handle a specific shell operation. Context-menu handlers, property-sheet handlers, icon handlers, and several other `shellex` handler types are each their own registered extension point, invoked when the relevant shell action actually occurs — most visibly, a right-click.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table.

> 🔴 **Both techniques are unmapped in MITRE ATT&CK as their own sub-techniques — this repo marks them `Unmapped` deliberately.** Both are legitimate instances of the general COM-hijacking mechanism (T1546.015) scoped to a specific, well-known extension point rather than an arbitrary hijacked CLSID — see COM Hijacking for the general mechanism. A finding here is suspicious the same way the rest of this family judges suspicion: not because a BHO or shell extension exists (both are entirely legitimate, routinely-used Windows/third-party functionality), but because a specific entry points at an unexpected, unsigned, or unaccountable DLL.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Browser Helper Objects](#browser-helper-objects)
- [Shell Extensions](#shell-extensions)
- [Red Flags Specific to BHOs & Shell Extensions](#red-flags-specific-to-bhos--shell-extensions)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native registry-and-CLSID-resolution triage — both techniques ultimately resolve to a DLL path via a CLSID lookup under `HKCR\CLSID\<CLSID>\InprocServer32`, which is the common final step worth building the habit of checking regardless of which registration point led you there.

```powershell
# Every registered BHO with its CLSID resolved to an actual DLL path and signature status
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects' -ErrorAction SilentlyContinue |
    ForEach-Object {
        $clsid = $_.PSChildName
        $dll = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
        $sig = if ($dll) { (Get-AuthenticodeSignature $dll -ErrorAction SilentlyContinue).Status } else { $null }
        [PSCustomObject]@{ CLSID = $clsid; DllPath = $dll; SignatureStatus = $sig }
    }

# Every CLSID on the Shell Extensions "Approved" list, resolved the same way - the broadly-scoped security control worth checking on its own
Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved' -ErrorAction SilentlyContinue |
    ForEach-Object { $_.GetValueNames() } | ForEach-Object {
        $clsid = $_
        $dll = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
        [PSCustomObject]@{ CLSID = $clsid; DllPath = $dll }
    }

# shellex handlers registered directly under a ProgID or file-type key - context-menu/property-sheet/icon handlers etc.
Get-ChildItem 'HKCR:\*\shellex' -ErrorAction SilentlyContinue | Get-ChildItem | ForEach-Object {
    $clsid = (Get-ItemProperty $_.PSPath).'(default)'
    [PSCustomObject]@{ HandlerType = $_.PSParentPath -replace '.*\\', ''; HandlerKey = $_.PSChildName; CLSID = $clsid }
}

# Per-user cached shell extensions - loaded at least once under this specific user profile, no admin rights required to write this
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached' -ErrorAction SilentlyContinue

# CLSIDs referenced by a BHO or shellex handler with no InprocServer32 DLL that actually resolves - broken registration or evasive load path
$bhoClsids = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects' -ErrorAction SilentlyContinue).PSChildName
$bhoClsids | ForEach-Object {
    $dll = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$_\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
    if (-not $dll -or -not (Test-Path $dll)) { [PSCustomObject]@{ CLSID = $_; DllPath = $dll; Resolves = $false } }
}
```

## Browser Helper Objects

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\<CLSID>
```

Each subkey under this key is named for a CLSID — not a friendly name, the CLSID itself is the subkey name — and its mere presence is the registration; there's no separate "enabled" flag to check beyond the key existing at all. When Internet Explorer (or legacy Edge running in IE-compatibility mode) starts, it enumerates every CLSID listed here and calls `CoCreateInstance` on each one, loading the corresponding COM object into the same process space as the browser itself — meaning a malicious BHO runs with the same privileges and network access as the browser session it's attached to, and a fresh instance loads with every new IE process, not just the first one on a given boot.

Resolving the actual payload from a BHO entry always requires the same second step: the CLSID subkey name only identifies *which* object to load — the DLL itself is found by following that CLSID over to the standard COM registration location, `HKCR\CLSID\<CLSID>\InprocServer32`, whose default value is the path to the actual DLL. This is the same CLSID-to-DLL resolution pattern used throughout Windows COM registration and, not coincidentally, throughout general COM Hijacking analysis — a BHO finding and a COM-hijacking finding often end at the exact same kind of artifact once you get past the registration point that led you there.

### PowerShell

Enumerate registered BHOs and resolve each one to its actual DLL in a single pass — the CLSID subkey name alone tells you almost nothing on its own:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects' -ErrorAction SilentlyContinue | ForEach-Object {
    $clsid = $_.PSChildName
    $dll = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
    [PSCustomObject]@{ CLSID = $clsid; DllPath = $dll }
}
```

Verify the Authenticode signature of every resolved BHO DLL — legitimate BHOs from established vendors (Adobe, Java, antivirus toolbars from the IE-toolbar era) are reliably signed; an unsigned or self-signed BHO DLL is a strong signal in an artifact category that has this little legitimate remaining population on a modern host:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects' -ErrorAction SilentlyContinue | ForEach-Object {
    $dll = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$($_.PSChildName)\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
    if ($dll -and (Test-Path $dll)) { Get-AuthenticodeSignature $dll | Select-Object Path, Status, SignerCertificate }
}
```

## Shell Extensions

```
HKCR\<ProgID or CLSID>\shellex\<HandlerType>\<CLSID>
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved
```

A shell extension registers into the `shellex` subkey of either a file-type ProgID (e.g. `.txt`'s ProgID) or a predefined shell object, under a subkey named for the specific handler type it implements — common handler types include context-menu handlers (`ContextMenuHandlers`), property-sheet handlers (`PropertySheetHandlers`), icon handlers (`IconHandler`), drag-and-drop handlers, and column-provider handlers, among others. Each one is loaded into whatever process hosts the shell namespace at the moment its associated operation occurs — `explorer.exe` for the everyday case, but equally any other application's `Open`/`Save As` common file-dialog, since those dialogs host the same shell namespace and will invoke the same registered handlers. A context-menu handler, specifically, loads and runs the moment a user right-clicks a matching file or object — a trigger an attacker doesn't have to predict the timing of, only rely on eventually happening.

The `Shell Extensions\Approved` key is a separate, broadly-scoped security control layered on top of the `shellex` registration itself: on OS/configuration combinations where the relevant enforcement setting is active, Explorer will refuse to load a shell extension whose CLSID isn't listed in `Approved`, regardless of whether it's otherwise correctly registered under a `shellex` subkey. That makes `Approved` worth checking as its own artifact in two directions — its *presence* for a given CLSID is corroborating evidence that a shell extension is actually loading (not just registered but inert), while its *absence entirely*, or evidence that the enforcement isn't active on that host/OS version, indicates the approval check isn't actually mitigating anything there, and `shellex` registration alone is sufficient for the extension to load.

A per-user record of shell extensions that have actually loaded at least once accumulates under:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached
```

This is a genuine execution-evidence artifact distinct from the registration keys above — it confirms the extension was actually invoked under that specific user profile, not merely registered somewhere on the system, and it requires no administrative privilege to populate (unlike the `HKLM`-rooted registration and approval keys), which is part of what makes shell-extension registration attractive to an attacker without local admin rights in the first place.

### PowerShell

Walk every `shellex` handler registered under the classes root, since handler types are scattered across many different ProgID/predefined-object keys rather than one central location:

```powershell
Get-ChildItem 'HKCR:\*\shellex' -ErrorAction SilentlyContinue | Get-ChildItem | ForEach-Object {
    [PSCustomObject]@{ HandlerType = $_.PSChildName; CLSID = (Get-ItemProperty $_.PSPath).'(default)' }
}
```

Cross-reference every CLSID found in `shellex` registrations against the `Approved` list, to see which extensions are relying on the approval control being unenforced, or which are properly approved but still worth resolving to a DLL and checking:

```powershell
$approved = (Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved' -ErrorAction SilentlyContinue).GetValueNames()
$clsid = '<CLSID-from-shellex-registration>'
if ($clsid -notin $approved) { Write-Output "$clsid is registered under shellex but NOT on the Approved list" }
```

Check per-user `Cached` entries to confirm a specific shell extension actually loaded under a given profile, which is stronger evidence than registration alone:

```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached' -ErrorAction SilentlyContinue
```

## Red Flags Specific to BHOs & Shell Extensions

- **Any BHO present at all on a host where Internet Explorer has been fully retired.** Given how legacy this mechanism is, a populated BHO key on a modern, IE-free host is itself worth questioning — either a genuinely stale artifact from an old install that was never cleaned up, or a live and currently underappreciated technique on that specific host.
- **An unsigned or self-signed DLL resolved from a BHO or shellex CLSID.** With so little legitimate BHO population remaining, and shellex handlers from reputable vendors (7-Zip, WinRAR, antivirus context-menu scanners) reliably signed, an unsigned resolution is a strong signal in both categories.
- **A `shellex` registration whose CLSID doesn't appear on the `Shell Extensions\Approved` list, on a host/OS configuration where that enforcement is expected to be active.** Either the extension is quietly failing to load (worth confirming via the `Cached` key) or the enforcement isn't actually active on that host — both are worth establishing rather than assuming.
- **A context-menu handler pointing at a DLL outside `Program Files`/`System32`**, mirroring the drop-and-persist pattern used throughout this family — a shell extension has no more legitimate reason to live in `%APPDATA%` or `%TEMP%` than a service or scheduled task does.
- **A `shellex`-registered CLSID with no corresponding `InprocServer32` DLL that actually resolves on disk**, or one where the referenced file is missing — either a broken/orphaned registration worth noting for baseline-hygiene purposes, or evidence the file was removed post-execution while the registry pointer survives.
- **Per-user `Shell Extensions\Cached` entries for a CLSID with no `HKLM`-level `Approved` listing and no `shellex` registration visible under `HKLM`**, since a non-admin user can write shell-extension registrations entirely within their own `HKCU` hive — worth specifically checking `HKCU\Software\Classes` for ProgID/shellex entries a standard user could have planted without ever touching `HKLM`.

## Tooling

| Tool | Use |
|---|---|
| `Get-ChildItem` / `Get-ItemProperty` (native PowerShell) | Direct enumeration of `Browser Helper Objects`, `shellex`, and `Shell Extensions\Approved`/`Cached` — no third-party tool required for the core hunt |
| **Autoruns** (Sysinternals) | Has a dedicated **Internet Explorer** tab for BHOs (with signature/VirusTotal cross-reference) and an **Explorer** tab that surfaces shell extensions and other Explorer-hosted add-ons — the fastest single-pass way to review both categories alongside every other autostart mechanism in this family |
| **ShellExView** (NirSoft) | Purpose-built shell-extension enumerator, listing every registered handler with type, associated file, and a one-click disable — useful as a dedicated cross-check against the Autoruns Explorer tab |
| `Get-AuthenticodeSignature` | Verifying code-signing status of any resolved BHO or shell-extension DLL |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of both `HKLM`-rooted registration keys and per-user `Cached`/`HKCU\Software\Classes` entries when working from an acquired image rather than a live host |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Any populated BHO entry on a host with IE fully retired | Legacy artifact population — worth investigating either as stale cruft or an underappreciated live technique |
| Unsigned/self-signed DLL resolved from a BHO or shellex CLSID | Both categories skew heavily toward signed vendor DLLs on a legitimate host |
| `shellex` CLSID absent from `Shell Extensions\Approved` where enforcement is expected | Extension may be silently failing to load, or the approval control isn't actually active on that host — establish which |
| Shell-extension DLL located outside `Program Files`/`System32` | Same drop-and-persist logic used throughout this family |
| `shellex`-registered CLSID with no resolvable `InprocServer32` DLL on disk | Broken/orphaned registration, or the file was removed post-execution while the registry pointer survives |
| `HKCU`-only shell-extension registration with no `HKLM` counterpart | Requires no administrative privilege — a non-admin foothold technique worth checking specifically under `HKCU\Software\Classes` |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all Persistence Mechanisms notes | Autostart (Run/RunOnce) Keys |
| The general, arbitrary-CLSID COM hijacking mechanism both techniques in this note are a scoped subset of | COM Hijacking |
| Registry hive access mechanics for `HKLM\SOFTWARE\Classes` and per-user `HKCU\Software\Classes` | Registry Forensics Fundamentals (note 04) |
| Search-order/DLL side-loading persistence, a related but mechanically distinct loader-level technique | DLL Hijacking |
| First/last-seen and hash identity of a resolved BHO or shell-extension DLL | ShimCache (AppCompatCache).md, Amcache.md (note 06) |
| Confirming actual execution/load of a shell-extension or BHO DLL beyond the `Cached` key | Prefetch.md (note 06) |

## Resources

- Browser Helper Objects — **Unmapped** (no dedicated MITRE ATT&CK sub-technique ID; a legacy, IE-specific instance of the general COM-hijacking mechanism)
- Shell Extensions — **Unmapped** (no dedicated MITRE ATT&CK sub-technique ID; a scoped instance of the general COM-hijacking mechanism, T1546.015)
- MITRE ATT&CK T1546.015 (Event Triggered Execution: Component Object Model Hijacking) — the general mechanism both techniques in this note are a scoped subset of; MITRE's own documentation for this technique cites the Shell Icon Overlay handler as one worked example — https://attack.mitre.org/techniques/T1546/015/
- Microsoft, The Basics of Browser Helper Objects — https://learn.microsoft.com/archive/blogs/askie/the-basics-of-browser-helper-objects
- Microsoft, Registering Shell Extension Handlers — https://learn.microsoft.com/windows/win32/shell/reg-shell-exts
- NirSoft, ShellExView — https://www.nirsoft.net/utils/shexview.html
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
