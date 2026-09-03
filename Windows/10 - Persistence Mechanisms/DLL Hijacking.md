# DLL Hijacking

Every mechanism earlier in this family — Run keys, services, scheduled tasks, WMI event subscriptions — has one thing in common: a dedicated place Windows stores "run this on this trigger." DLL hijacking doesn't. There is no `HKLM\...\DllHijack` key, no `System32\Tasks\` entry, no `root\subscription` object. The technique instead exploits a mechanism that already runs constantly and legitimately on every Windows host: the loader's own **DLL search order**. Plant a malicious DLL somewhere the loader will find it *before* the real one, give it the exact filename the target process is already going to ask for, and the next time that process launches — by whatever means, on whatever schedule, triggered by whatever mechanism already covered in this family or simply a user double-clicking an icon — Windows loads the attacker's code into a legitimate process for free.

That "by whatever means" clause is the reason this note closes out the Persistence Mechanisms family rather than standing fully independent of it: DLL hijacking on its own only re-executes when its host process is already going to launch anyway. It is frequently found **layered on top of** a Run key, a service, or a scheduled task that was already legitimately launching the target executable — the registry/task footprint you'd normally hunt belongs to the *launcher*, not to the hijack itself. See Where the Persistence Actually Comes From below.

This is the fifth and final note in the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing DLL Hijacking against Run Keys, Services, Scheduled Tasks, and WMI Event Consumers.

> 🔴 **DLL hijacking has no registry key or scheduler entry of its own to hunt.** Every red flag in this note lives on the filesystem (an out-of-place DLL) or in execution artifacts (a loaded-module record) — not in a config store. If your triage process is "check Run keys, check services, check tasks, check WMI, done," you will walk past this technique every time. It requires deliberately inspecting application directories and load events, not just enumerating known persistence locations.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [What It Is](#what-it-is)
- [The Windows DLL Search Order](#the-windows-dll-search-order)
- [SafeDllSearchMode](#safedllsearchmode)
- [The Sub-Techniques](#the-sub-techniques)
  - [Classic Search-Order Hijacking](#classic-search-order-hijacking)
  - [DLL Side-Loading](#dll-side-loading)
  - [Phantom DLL Hijacking](#phantom-dll-hijacking)
  - [DLL Redirection — `.local` Files and Manifests](#dll-redirection--local-files-and-manifests)
  - [Not the Same Thing: DLL Injection](#not-the-same-thing-dll-injection)
- [Where the Persistence Actually Comes From](#where-the-persistence-actually-comes-from)
- [How to Interpret It — Filesystem Evidence](#how-to-interpret-it--filesystem-evidence)
- [How to Interpret It — Execution Evidence](#how-to-interpret-it--execution-evidence)
- [Signature Verification: The Core Triage Move](#signature-verification-the-core-triage-move)
- [Red Flags Specific to DLL Hijacking](#red-flags-specific-to-dll-hijacking)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against currently-loaded modules and the filesystem — no third-party tool required. This only catches **static/currently-loaded** evidence (what a running process has loaded right now, and what's signed); it can't reconstruct an import table or prove a specific load was malicious rather than legitimate — for that depth, defer to Procmon's live search-order capture or a proper binary/import-table analysis tool, neither of which PowerShell replaces (see Tooling below).

```powershell
# Loaded modules for a running process, flagged if not sitting in System32/Program Files - the loader's own record of where it found each DLL
Get-Process -Name explorer | Select-Object -ExpandProperty Modules |
    Where-Object { $_.FileName -notmatch '^C:\\(Windows\\System32|Program Files)' } |
    Select-Object ModuleName, FileName

# Authenticode signature status for every module a process has loaded - the fastest way to spot the one unsigned DLL among dozens of signed ones
(Get-Process -Name explorer).Modules | ForEach-Object { Get-AuthenticodeSignature $_.FileName } |
    Select-Object Path, Status, SignerCertificate

# The KnownDLLs list - these always resolve straight to System32 regardless of search order, so anything on disk claiming to BE one of these from elsewhere is immediately suspect
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'

# DLLs sitting in user-writable directories that share a filename with a common system DLL - the phantom/side-load staging pattern
Get-ChildItem -Path $env:TEMP, $env:LOCALAPPDATA, "$env:USERPROFILE\Downloads" -Recurse -Filter *.dll -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in @('version.dll','dwmapi.dll','winmm.dll','wow64log.dll','uxtheme.dll') }

# Unsigned DLLs loaded into a high-value process - lsass, svchost, explorer are exactly the processes an attacker wants their planted DLL riding inside
# (reading another user's/SYSTEM's process modules, e.g. lsass, normally requires an elevated session)
foreach ($name in 'lsass','svchost','explorer') {
    Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
        $procId = $_.Id
        $_.Modules | ForEach-Object {
            $sig = Get-AuthenticodeSignature $_.FileName
            if ($sig.Status -ne 'Valid') { [PSCustomObject]@{ Process = $name; PID = $procId; Module = $_.FileName; SignatureStatus = $sig.Status } }
        }
    }
}
```

## What It Is

DLL hijacking (also called DLL search-order hijacking, DLL planting, or DLL side-loading depending on the exact variant) abuses the order in which the Windows loader looks for a DLL a process requests by name rather than by full path. If an attacker can get a malicious DLL with the right filename into a directory the loader checks *before* the legitimate copy, the loader hands the attacker's code to the requesting process instead — no exploit, no memory corruption, just Windows doing exactly what it was designed to do against a search order the attacker gamed.

## The Windows DLL Search Order

When a process (or a DLL it has already loaded) calls `LoadLibrary` with a bare filename rather than a fully-qualified path, and the DLL isn't already loaded and isn't satisfied by a **known DLL** redirect (a small, Microsoft-controlled list of core system DLLs — `kernel32.dll`, `ntdll.dll`, and similar — that always resolve straight to `System32` regardless of search order, specifically to close off this exact attack against the most critical system libraries), the loader walks a fixed sequence of locations:

| Order | Location | Notes |
|---|---|---|
| 1 | The directory the calling application was loaded from | The single highest-value location for classic search-order hijacking and side-loading — an attacker who can write here wins before the loader even looks anywhere else |
| 2 | The system directory (`%SystemRoot%\System32`) | Where the legitimate copy of most system DLLs actually lives — write access here normally requires admin/SYSTEM, which is why this row is rarely the attacker's insertion point and far more often the row the *legitimate* DLL is being hijacked away from |
| 3 | The 16-bit system directory (`%SystemRoot%\System`) | Legacy, effectively vestigial on modern 64-bit Windows — included for completeness and legacy-image work, not a realistic modern attack surface |
| 4 | The Windows directory (`%SystemRoot%`) | Less commonly abused in practice than row 1, but still checked before the current directory and `PATH` |
| 5 | The current working directory (CWD) | **Only checked here if SafeDllSearchMode is disabled** — see below; on a modern default configuration this row effectively moves to position 6/7 (after `PATH`), which is the entire point of SafeDllSearchMode |
| 6 | Directories listed in the `PATH` environment variable | Checked last on a default modern configuration — an attacker-controlled directory added to `PATH` (or an existing world-writable directory already on `PATH`) is a viable but comparatively rare insertion point compared to row 1 |

🔴 **Row 1 — the application's own directory — is where the overwhelming majority of real-world hijacking and side-loading happens.** It's the first place checked, it's frequently writable by a standard user (anywhere under `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`, or a user-profile "portable app" install), and it requires no privilege escalation or `PATH` manipulation at all — just the ability to drop a file next to an executable the attacker also controls or that a user will run.

## SafeDllSearchMode

**SafeDllSearchMode** moves the current working directory from its "naive" position (checked immediately after the application directory, ahead of the system directories) to *after* `PATH` in the search order — closing off a large class of hijacks where an attacker could get a victim to launch a legitimate, trusted executable from a directory the attacker controlled (e.g. a malicious DLL sitting in a Downloads folder alongside a copy of a real, trusted EXE the victim was tricked into running from there).

| | Behavior |
|---|---|
| **Pre-XP SP1 / early legacy** | CWD checked early (position 2, immediately after the application directory) — the more dangerous, naive order |
| **XP SP1 / Server 2003 onward — SafeDllSearchMode enabled by default** | CWD moved to after `PATH` — the search order shown in the table above; this is the behavior on every currently-supported Windows version |
| **Disabled via registry** | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode` (`REG_DWORD`), value `0` disables it, reverting to the naive pre-SP1 order | 🔴 **Finding this value explicitly set to `0` on a modern host is itself a red flag** — it's not a setting normal software or normal administration has any reason to touch, and disabling it meaningfully widens the DLL-hijacking attack surface on that host |

Because SafeDllSearchMode has been the default for two decades, its main forensic relevance today is (a) recognizing genuinely legacy/pre-SP1 images where the naive order applies, and (b) treating an explicit registry override to disable it as a standalone finding worth investigating on its own, independent of any specific hijack you're chasing.

## The Sub-Techniques

### Classic Search-Order Hijacking

The textbook case: a legitimate application calls `LoadLibrary("somelib.dll")` (a bare filename, no path) expecting to find the real copy in `System32` or wherever it normally resolves. The attacker drops a malicious DLL of the same name into a location checked *earlier* in the search order — almost always the application's own directory (row 1 above) — and the loader picks up the attacker's copy first, silently, with no error, no warning, and (from the application's perspective) apparently normal operation.

This requires write access to a location ahead of the legitimate DLL in the search order — the application directory is the practical target, since it's the row most often writable by a standard user and checked first regardless of `PATH`/CWD configuration.

### DLL Side-Loading

A close cousin of classic search-order hijacking, distinguished mainly by intent and packaging rather than mechanism: the attacker places a malicious DLL with the **exact expected filename** next to a **legitimate, often digitally-signed executable** — one the attacker also drops onto the host (frequently a copy of a real, signed vendor binary known to load a DLL from its own directory by name) or that already exists there. The signed EXE launches, asks for its expected DLL by name, finds the attacker's planted copy in the same directory, and loads it — all while the process that just executed malicious code is, by every code-signing and application-allowlisting check, a perfectly legitimate, trusted binary.

🔴 **This is prized specifically for defense evasion.** Application allowlisting, some AV heuristics, and analyst instinct alike tend to trust "a signed Microsoft/vendor EXE is running" far more than they scrutinize what that EXE loaded. Side-loading launders malicious code execution through a parent process that passes every surface-level legitimacy check — the finding isn't in the process name or its signature, it's in the unsigned or mismatched DLL sitting next to it.

### Phantom DLL Hijacking

A variant where the legitimate application looks for a DLL that **doesn't actually exist on a stock system** — a reference left over in the application's import table or an internal `LoadLibrary` call for a DLL that was deprecated, optional, platform-conditional, or simply never shipped in the installed configuration. On an unmodified system this lookup normally fails silently or no-ops; the application was written to tolerate its absence. An attacker who identifies such a phantom reference can supply a DLL of that exact name, and the loader — finding no legitimate copy anywhere in the search order to compete with — loads the attacker's version without ever displacing a real file.

Phantom hijacking is attractive precisely because there's no legitimate DLL being overwritten, replaced, or shadowed — nothing to diff against a "should be here" baseline, since nothing was ever supposed to be there in the first place. The tell is almost entirely behavioral/contextual: an unfamiliar DLL name, in an application directory, that doesn't correspond to any DLL the vendor actually ships in that product version.

### DLL Redirection — `.local` Files and Manifests

A legacy-but-real variant that doesn't rely on search-order timing at all, but on Windows' own DLL-redirection features:

- **`<app>.exe.local` folder/file redirection** — the mere presence of a file or folder named `<appname>.exe.local` next to an executable causes the loader to prefer DLLs found alongside the EXE (or inside that `.local` folder) over the normal search order and even over side-by-side (WinSxS) assemblies, for legacy compatibility reasons. An attacker who creates a `.local` marker and drops DLLs to match can redirect loading without touching the search order proper.
- **WinSxS / manifest-based redirection** — an application's embedded or external manifest can specify which versioned assembly/DLL set it should bind to; manipulating the manifest or planting a matching assembly in a location the manifest resolution checks achieves a similar redirection effect through the side-by-side assembly system rather than the classic search order.

Both are less commonly seen in current intrusions than rows 1–3 above (search-order, side-loading, phantom) but are real, documented techniques — worth checking for on older application installs or when a hijack investigation turns up no plausible search-order explanation but a `.local` file or unusual manifest is present in the same directory.

### Not the Same Thing: DLL Injection

**DLL hijacking is a load-time technique** — it works by manipulating what the loader finds when a process asks for a DLL by name during normal startup or runtime library loading. **DLL injection is a runtime technique** — forcibly loading a DLL into an already-running process from the outside (`CreateRemoteThread` + `LoadLibrary`, `SetWindowsHookEx`, reflective loading, and similar), with no dependence on search order or filenames at all. They are frequently confused because both end with "attacker code running inside a legitimate process," but the mechanism, evidence trail, and detection approach are different disciplines. Injection depth belongs in Memory Analysis (Processes, Injection, Rootkits) (note 17) — this note stays scoped to search-order/load-time abuse.

## Where the Persistence Actually Comes From

Because DLL hijacking has no trigger of its own, its "persistence" is entirely borrowed from whatever already causes the host process to launch:

| The DLL sits waiting for… | Which is covered in… |
|---|---|
| A user double-clicking a shortcut or Start Menu entry | Not itself a persistence mechanism — but see Shellbags/Recent Files (note 07) for evidence the app was launched this way |
| A Run/RunOnce key that already launches the legitimate app at logon | Autostart (Run/RunOnce) Keys |
| An Auto-start service whose `ImagePath` points at the legitimate host executable | Services |
| A scheduled task whose `<Actions><Exec>` launches the legitimate host executable | Scheduled Tasks |
| A WMI permanent-subscription consumer that launches the legitimate host executable | WMI Event Consumers |

🔴 **The "layered on top" pattern is a strong finding in its own right.** If a host shows a normal, expected persistence artifact (a Run key, a service, or a task pointing at a legitimate, signed application) **and** that application's own directory contains a newly-dropped, unsigned DLL, treat the two together as a single intrusion rather than two unrelated observations — the registry/task entry is legitimate and pre-existing, but it's now unwittingly re-arming the attacker's payload on every trigger. Removing only the DLL breaks the immediate execution; removing only the persistence entry doesn't remove the planted DLL, which will simply wait for the next legitimate launch (a user double-click, a reinstall, a future service start) to fire again.

This also means DLL hijacking's evidence trail is almost entirely **filesystem and execution-artifact based**, not registry-based — see the two sections below.

## How to Interpret It — Filesystem Evidence

| Signal | What it means |
|---|---|
| Unsigned or mis-signed DLL in a directory otherwise full of vendor-signed DLLs | The single strongest filesystem tell — see Signature Verification below |
| DLL creation/modification timestamp postdating the application's own install or last-update timestamp | A DLL created *after* the app was installed, sitting in the app's own folder, is inconsistent with a normal vendor deployment — see NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes for MACB caveats that apply to this comparison |
| Filename matching a well-known Windows system DLL, but the file is **not** in `System32` | A DLL named identically to a real system component but living in an application directory, a user-writable path, or anywhere outside `System32` is inherently suspicious — legitimate copies of true system DLLs live in `System32` (or WinSxS), not scattered around the filesystem |
| DLL with no corresponding entry in the vendor's known file manifest/installer package | Where a vendor manifest, installer log, or known-good hash set exists to check against, a DLL present on disk that the installer never placed is a strong signal |
| `<app>.exe.local` file/folder present alongside an executable that doesn't normally ship one | Possible `.local`-based redirection — see DLL Redirection above |

## How to Interpret It — Execution Evidence

Because there's no registry footprint, execution/loaded-module evidence carries proportionally more weight here than in any other note in this family.

| Source | What it can show | Caveats |
|---|---|---|
| **Sysmon Event ID 7 (ImageLoad)** | The single strongest detection source for this technique when deployed — logs every DLL load with the loading process, full DLL path, code-signing status, and hash | 🔴 **Requires explicit Sysmon configuration.** ImageLoad logging is extremely verbose (every DLL, every process, constantly) and is frequently excluded or heavily filtered in default/common Sysmon rule configs specifically because of that volume — do not assume Event ID 7 data exists for the window you're investigating just because Sysmon is present on the host; confirm the deployed config actually enables and doesn't over-filter ImageLoad events |
| **Prefetch** | The host executable's `.pf` file records referenced files/directories/volumes the process touched near launch, which in practice can include DLLs loaded during that startup window — see Prefetch.md (note 06) | Prefetch's referenced-files field reflects what was touched *at that specific run*, is subject to the same 128/1024-entry rolling cap and volatility as the rest of Prefetch, and is not a substitute for a purpose-built module-load log; treat it as corroboration, not a primary source |
| **Amcache** | Inventories the DLL itself as a file if/when it gets swept into `Root\File`/`InventoryApplicationFile` — giving you the SHA-1, path, and timestamps for the planted DLL, same as any other tracked binary | Amcache's per-build inconsistency (see Amcache.md, note 06) applies here too — don't assume every planted DLL will show up, and this is presence evidence, not proof the DLL was actually loaded by the target process |
| **ShimCache** | Presence evidence for the DLL if the compatibility subsystem evaluated it | Weakest signal in the set — no execution timestamp post-XP, and evaluation ≠ load; see ShimCache (AppCompatCache).md (note 06) |
| **Process Monitor (Procmon)** | Live, real-time capture of the actual search-order probing as it happens — the loader's `CreateFile`/`QueryOpen` operations against each candidate path in order, showing `PATH NOT FOUND` or `NAME NOT FOUND` results at the legitimate locations followed by a `SUCCESS` at an unexpected path | This is the **live-response signature of hijacking in progress** — running Procmon while relaunching the suspect executable and filtering on the DLL name will show you the exact search-order walk and exactly where it resolved; requires live access and a controlled relaunch, not useful for dead-box/retrospective analysis |

### PowerShell

Cross-reference a loaded DLL's actual path against where it should live, and decode the signature and publisher on each mismatch rather than just a pass/fail verdict:

```powershell
Get-Process -Name explorer | Select-Object -ExpandProperty Modules | ForEach-Object {
    $expected = $_.ModuleName -in @('kernel32.dll','ntdll.dll','user32.dll','advapi32.dll') -and $_.FileName -notmatch '^C:\\Windows\\System32\\'
    $sig = Get-AuthenticodeSignature $_.FileName
    [PSCustomObject]@{
        Module      = $_.ModuleName
        Path        = $_.FileName
        PathMismatch = $expected
        SignatureStatus = $sig.Status
        Publisher   = $sig.SignerCertificate.Subject
    }
} | Where-Object { $_.PathMismatch -or $_.SignatureStatus -ne 'Valid' }
```

Sweep an estate for a specific DLL name (such as one named in a threat-intel report) to find every host it's been sideloaded on, export for pivoting, and hash-compare each hit against a known-good baseline copy:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-ChildItem C:\ -Recurse -Filter 'version.dll' -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName'; E={ $env:COMPUTERNAME }}, FullName, LastWriteTime
} | Export-Csv C:\hunt\dll_sweep.csv -NoTypeInformation

$knownGoodHash = (Get-FileHash 'C:\hunt\baseline\version.dll' -Algorithm SHA256).Hash
Get-FileHash 'C:\Suspect\App\version.dll' -Algorithm SHA256 | Where-Object Hash -ne $knownGoodHash
```

## Signature Verification: The Core Triage Move

The fastest, highest-yield triage step for a suspected hijack is checking the digital signature of every DLL in the suspect application directory — a directory full of Microsoft- or vendor-signed DLLs with one unsigned (or differently-signed) file sitting among them is the classic tell, and it requires no knowledge of the specific application's normal DLL manifest to spot.

- **`sigcheck` (Sysinternals)** — the primary tool for this: point it at a directory and it reports signature status, signer, and (with `-h`) hashes for every file, in a form that's trivial to script/batch across many directories or many hosts.
- **PowerShell `Get-AuthenticodeSignature`** — the built-in, no-install equivalent; `Get-ChildItem *.dll | Get-AuthenticodeSignature` against a suspect directory gives the same unsigned/signed verdict per file and is often the faster option on a live-response engagement where installing Sysinternals tooling isn't practical.

Neither tool tells you *why* an unsigned DLL is there — a genuinely unsigned but legitimate third-party DLL is not unheard of — but an unsigned file sitting in a directory that is otherwise wall-to-wall Microsoft- or vendor-signed content is exactly the pattern worth escalating.

### PowerShell

The two native building blocks behind every check above enumerate the modules a live process has loaded and check any given DLL's signature — both are built-in, no Sysinternals staging required:

```powershell
Get-Process -Name notepad | Select-Object -ExpandProperty Modules | Select-Object ModuleName, FileName, FileVersion

Get-ChildItem 'C:\Program Files\SomeApp\*.dll' | Get-AuthenticodeSignature | Select-Object Path, Status, SignerCertificate
```

## Red Flags Specific to DLL Hijacking

- **Unsigned DLL in a directory of otherwise-signed vendor DLLs** — the primary, highest-confidence tell; see Signature Verification above.
- **DLL filename matching a known Windows system DLL but located outside `System32`.** Names like `version.dll`, `dwmapi.dll`, `winmm.dll`, `wow64log.dll`, and `uxtheme.dll` have documented histories as commonly-abused search-order/phantom targets because many applications reference them by bare filename without validating the resolved path — but the underlying pattern (a system-DLL-sounding name outside `System32`) matters more than memorizing any specific list, since the exact names in vogue shift over time.
- **DLL creation timestamp postdating the host application's installation date.** A DLL that appeared in the app's own folder well after the app itself was installed or last updated has no ordinary explanation.
- **A legitimate, signed EXE loading from an unusual working directory.** A vendor binary that normally runs from `Program Files` observed launching from a Downloads folder, a temp directory, or a user profile path is exactly the setup side-loading depends on.
- **Both a normal persistence artifact and a newly-dropped DLL present together.** The "layered on top" pattern described above — an existing, legitimate Run key/service/task pointing at an application whose own directory now also contains a suspicious DLL — is a stronger finding than either observation alone.
- **`SafeDllSearchMode` explicitly disabled (`0`) via registry on a modern host.** Not something normal software or administration has reason to touch; widens the attack surface deliberately.
- **A `.local` file/folder appearing next to an executable that never shipped one.** Possible manifest/redirection-based abuse — see DLL Redirection above.

## Tooling

| Tool | Use |
|---|---|
| **Sysinternals `sigcheck`** | Primary triage tool — batch signature/hash verification across a suspect application directory; the fastest way to spot the one unsigned DLL among a folder of signed ones |
| **PowerShell `Get-AuthenticodeSignature`** | Built-in equivalent to sigcheck for signature verification, no additional tooling required — useful when Sysinternals binaries aren't already staged on the host |
| **Sysmon (Event ID 7 — ImageLoad)** | The strongest native/near-native detection source for actual DLL loads, including path, signer, and hash — requires explicit configuration, since ImageLoad logging is verbose and frequently excluded by default in common Sysmon rule sets; confirm the deployed config before relying on it |
| **Process Monitor (Procmon)** | Live capture of the loader's actual search-order probing in real time — `PATH NOT FOUND`/`NAME NOT FOUND` at expected locations followed by `SUCCESS` at an unexpected one is the live-response signature of an active hijack; requires live access and a controlled relaunch |
| **Autoruns (Sysinternals)** | 🔴 **Does not directly enumerate DLL hijacking** the way it enumerates Run keys, services, scheduled tasks, or WMI subscriptions — there is no fixed config location for this technique for Autoruns to walk. It remains useful indirectly (its `AppInit_DLLs`, `Winlogon`, and known-DLL-adjacent entries are worth checking, and it's still the right tool for every *other* mechanism this DLL might be riding on top of), but treat this as a real coverage gap rather than assuming Autoruns will surface a hijacked DLL on its own |
| **PECmd (Eric Zimmerman)** | Parses Prefetch `.pf` files, including the referenced files/directories/volumes field that can surface a loaded DLL touched during a specific run — useful corroboration for "was this DLL present and touched near launch," though it's not a purpose-built module-load parser and shares Prefetch's general volatility/cap limitations (note 06) |
| **KAPE** | Triage collection of application directories, Prefetch, Amcache, and Sysmon event data at scale for offline sigcheck/Get-AuthenticodeSignature review — see Evidence Acquisition & Imaging (note 02) |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Unsigned DLL sitting among otherwise vendor-signed DLLs in an application directory | Primary, highest-confidence tell for this technique — run sigcheck/`Get-AuthenticodeSignature` across the directory |
| DLL filename matches a known Windows system DLL but lives outside `System32` | Consistent with search-order or phantom hijacking of a commonly-abused system DLL name |
| DLL creation timestamp postdates the host application's install/last-update date | No ordinary explanation for a new file appearing in an already-installed application's own folder |
| Legitimate signed EXE observed launching from an unusual working directory | Sets up the exact search-order conditions side-loading depends on |
| Existing Run key/service/task pointing at a legitimate app whose directory now also contains a suspicious DLL | The "layered on top" pattern — treat both findings as one intrusion, not two |
| `SafeDllSearchMode` registry value set to `0` on a modern host | Deliberately widens the search-order attack surface; not a normal configuration |
| `.local` file/folder next to an executable that never shipped one | Possible manifest/redirection-based DLL abuse |
| Sysmon present but Event ID 7 (ImageLoad) sparse or absent for the window in question | Likely a config gap, not an absence of activity — ImageLoad is commonly filtered out by default; don't conclude "no hijack" from its absence alone |
| Autoruns run and came back clean | Does not clear this technique — Autoruns has no dedicated DLL-hijacking enumeration; a clean Autoruns pass only clears the *other* mechanisms in this family |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all five persistence mechanisms | Autostart (Run/RunOnce) Keys |
| The Run key that may be re-launching the legitimate host process the hijacked DLL is riding on | Autostart (Run/RunOnce) Keys |
| The Auto-start service whose `ImagePath` may be the trigger re-arming this DLL on every boot | Services |
| The scheduled task whose action may be launching the legitimate host executable | Scheduled Tasks |
| The WMI permanent subscription whose consumer may be launching the legitimate host executable | WMI Event Consumers |
| Normal vs. abnormal process-tree/parent-child relationships, used to judge whether the host process itself looks legitimate | Windows OS Fundamentals & Versions (note 01) |
| Registry hive mechanics for `SafeDllSearchMode` and `AppInit_DLLs`-style adjacent keys | Registry Forensics Fundamentals (note 04) |
| MACB timestamp rules for comparing DLL creation time against application install time | NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes |
| Run-count and referenced-files evidence for the host executable's launches | Prefetch.md (note 06) |
| Presence evidence and last-modified timestamp for the DLL itself | ShimCache (AppCompatCache).md (note 06) |
| SHA-1 hash identity and cross-host matching for the planted DLL | Amcache.md (note 06) |
| Runtime DLL injection into an already-running process — the load-time/runtime distinction | Memory Analysis (Processes, Injection, Rootkits) (note 17) |
| Remote delivery of a side-loaded DLL/EXE pair as part of a lateral-movement push | Lateral Movement (note 12) |

## Resources

- SANS FOR508 poster — Malware Persistence panel, DLL search-order/side-loading coverage checklist, rewritten in this note's own words
- Microsoft, Dynamic-Link Library Search Order — https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-search-order
- Microsoft, SafeDllSearchMode registry value documentation — https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-search-order
- Sysinternals sigcheck — https://learn.microsoft.com/sysinternals/downloads/sigcheck
- Sysinternals Process Monitor (Procmon) — https://learn.microsoft.com/sysinternals/downloads/procmon
- Sysmon (Sysinternals) — https://learn.microsoft.com/sysinternals/downloads/sysmon
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (PECmd) — https://ericzimmerman.github.io/
- MITRE ATT&CK T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking) — https://attack.mitre.org/techniques/T1574/001/
- MITRE ATT&CK T1574.002 (Hijack Execution Flow: DLL Side-Loading) — https://attack.mitre.org/techniques/T1574/002/
- MITRE ATT&CK T1574.008 (Hijack Execution Flow: Path Interception by Search Order Hijacking) — https://attack.mitre.org/techniques/T1574/008/
