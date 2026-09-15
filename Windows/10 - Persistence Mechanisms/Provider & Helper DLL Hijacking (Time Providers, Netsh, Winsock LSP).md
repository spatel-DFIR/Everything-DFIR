# Provider & Helper DLL Hijacking (Time Providers, Netsh, Winsock LSP)

Windows exposes several subsystems that are explicitly designed to load third-party DLLs into a well-known process at a well-known moment — the Windows Time service loading a "time provider" at service start, `netsh.exe` loading a "helper" DLL every time it runs, and the Winsock catalog loading a "layered service provider" into every process that touches the network stack. All three follow the identical pattern this note is built around: register a DLL path in a specific registry location, and a legitimate, trusted Windows component loads and executes it automatically, with no scheduled task, no new service, and no unusual process name anywhere in the chain. This note covers all three together because they share that pattern even though they attach to three different subsystems, and an analyst checking one should routinely sweep the other two in the same pass.

The three techniques differ meaningfully in trigger frequency and blast radius, which matters for both attacker tradecraft and analyst prioritization: a Time Provider DLL loads once per `W32Time` service start (infrequent, but SYSTEM-adjacent and boot-persistent); a Netsh Helper DLL loads only when `netsh.exe` itself is invoked (rare on most hosts, but a real trigger whenever an admin, script, or VPN client runs it); and a Winsock LSP loads into essentially every process on the host that uses networking APIs (the broadest trigger surface of the three, and also the most operationally fragile — a broken LSP entry can silently break all networking on the host, which is itself a forensically useful tell).

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing provider/helper DLL hijacking against Run keys, Services, Scheduled Tasks, and WMI Event Consumers.

> 🔴 **A registered provider or helper DLL is only as suspicious as its path and its necessity.** Time Providers and Netsh Helpers both have small, well-known legitimate populations (a couple of built-in time providers; a handful of vendor-registered netsh helpers, most commonly VPN clients). Winsock LSPs are somewhat more variable host-to-host due to legitimate security software also using this mechanism, which makes path/signature verification — not name recognition alone — the primary filter for that one. The finding is never "an entry exists," it's "this DLL path is outside the expected location, unsigned, or has no plausible legitimate owner."

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Time Providers — Registry Structure](#time-providers--registry-structure)
- [Netsh Helper DLLs — Registry Structure](#netsh-helper-dlls--registry-structure)
- [Winsock LSP — Registry Structure](#winsock-lsp--registry-structure)
- [Event Log Evidence](#event-log-evidence)
- [Red Flags Specific to Provider & Helper DLL Hijacking](#red-flags-specific-to-provider--helper-dll-hijacking)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native registry-only triage across all three mechanisms in one pass — none has a dedicated PowerShell module, so these read the registry directly and, for Winsock, decode the LSP catalog.

```powershell
# Every registered W32Time provider with its DllName, enabled state, and whether the DLL is under System32
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders' | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    [PSCustomObject]@{ Provider = $_.PSChildName; DllName = $p.DllName; Enabled = $p.Enabled; UnderSystem32 = $p.DllName -match '^%systemroot%\\system32\\|^C:\\Windows\\System32\\' }
}

# Every registered Netsh helper DLL with its resolved path
Get-Item 'HKLM:\SOFTWARE\Microsoft\Netsh' -ErrorAction SilentlyContinue | ForEach-Object {
    (Get-ItemProperty $_.PSPath).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
        Select-Object Name, Value
}

# Winsock LSP catalog entries whose PackedCatalogItem doesn't resolve to a signed, System32-resident DLL
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\*' -ErrorAction SilentlyContinue |
    Select-Object PSChildName, PackedCatalogItem

# Time provider DLLs that fail Authenticode validation - the primary triage filter for this mechanism
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders' | ForEach-Object {
    $dll = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DllName -replace '%systemroot%', 'C:\Windows'
    if ($dll -and (Test-Path $dll)) {
        $sig = Get-AuthenticodeSignature $dll
        if ($sig.Status -ne 'Valid') { [PSCustomObject]@{ Provider = $_.PSChildName; Dll = $dll; SignatureStatus = $sig.Status } }
    }
}

# Netsh helper DLL paths pointing outside System32 - the drop-and-persist pattern for this specific trigger
Get-Item 'HKLM:\SOFTWARE\Microsoft\Netsh' -ErrorAction SilentlyContinue | ForEach-Object {
    (Get-ItemProperty $_.PSPath).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Value -notmatch '\\System32\\' } |
        Select-Object Name, Value
}

# netsh winsock reset (or LSP corruption) recently used - correlate against network-loss reports as a possible evidence-destruction event
Get-WinEvent -FilterHashtable @{LogName='System'} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Winsock' } | Select-Object TimeCreated, Id, Message
```

## Time Providers — Registry Structure

The Windows Time service (`W32Time`) loads one or more time-provider DLLs at service start to retrieve or output time synchronization data. Providers register under:

```
HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\<ProviderName>
```

| Value | Meaning | Forensic relevance |
|---|---|---|
| `DllName` | Path to the provider DLL, typically expressed as `%systemroot%\System32\<name>.dll` | 🔴 The value that matters — legitimate providers (`VMICTimeProvider` on Hyper-V guests, `NtpClient`, `NtpServer`) resolve into `System32`; anything else is the tell |
| `Enabled` | DWORD, `1` or `0` | Gates whether the provider actually loads regardless of its `DllName` — an entry with `Enabled = 0` is dormant but still worth noting if it was recently flipped |
| `InputProvider` / `OutputProvider` | DWORD flags | Distinguish whether the provider supplies time data inward, outward, or both — mostly relevant for understanding legitimate function, not a red flag on its own |

`W32Time` typically runs under the `LocalService` account rather than full `LocalSystem` — a meaningfully lower privilege ceiling than the Print Spooler or many other service-hosted mechanisms in this family, but administrative privilege is still required to register a new provider in the first place, and the service-relaunch persistence pattern (the DLL reloads automatically every time `W32Time` restarts, which happens on every boot by default) still applies in full.

### PowerShell

Enumerate every registered time provider and resolve `DllName`'s `%systemroot%` token to a real path for signature checking:

```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders' | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    $resolved = $p.DllName -replace '%systemroot%', $env:SystemRoot
    [PSCustomObject]@{ Provider = $_.PSChildName; DllName = $p.DllName; Resolved = $resolved; Enabled = $p.Enabled }
}
```

Cross-check each resolved DLL against a signature check and confirm the `W32Time` service's current running state, since a provider only loads while the service is actually running:

```powershell
Get-Service W32Time | Select-Object Status, StartType
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders' | ForEach-Object {
    $dll = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DllName -replace '%systemroot%', $env:SystemRoot
    if (Test-Path $dll) { Get-AuthenticodeSignature $dll | Select-Object Path, Status }
}
```

## Netsh Helper DLLs — Registry Structure

`netsh.exe` supports a helper-DLL extensibility model — third-party software (most commonly VPN clients and some network-management tools) registers a helper so `netsh` gains new subcommands relevant to that software. Every registered helper appears as a single value under one flat key, with no per-helper subkey structure:

```
HKLM\SOFTWARE\Microsoft\Netsh
```

| Value | Meaning | Forensic relevance |
|---|---|---|
| `<HelperName>` (value name is arbitrary/vendor-chosen) | Full path to the helper DLL | 🔴 The value's *data* is the path that matters — legitimate helpers resolve into `System32`; the value *name* itself is typically a vendor-chosen internal identifier rather than a human-friendly label, so don't rely on name recognition the way port-monitor names are usable |

Persistence via this mechanism is triggered only when `netsh.exe` itself runs — not at boot, not at logon, but whenever any process (an administrator running a network diagnostic command, a scheduled maintenance script, a VPN client's own connect routine, or an attacker directly invoking `netsh` to trigger their own planted helper) launches `netsh.exe`. That makes it a genuinely lower-frequency trigger than the other two mechanisms in this note, but not a theoretical one — `netsh` is common enough in routine administration and third-party software behavior that a planted helper will typically fire sooner or later without the attacker needing to do anything further.

### PowerShell

Enumerate every registered helper — the key holds a flat list of values, so this reads all of them directly rather than walking subkeys:

```powershell
Get-Item 'HKLM:\SOFTWARE\Microsoft\Netsh' | ForEach-Object {
    (Get-ItemProperty $_.PSPath).PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } |
        Select-Object Name, Value
}
```

Check each resolved DLL's signature and location, applying the same `System32` expectation used for the other two mechanisms in this note:

```powershell
Get-Item 'HKLM:\SOFTWARE\Microsoft\Netsh' | ForEach-Object {
    (Get-ItemProperty $_.PSPath).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        if (Test-Path $_.Value) { Get-AuthenticodeSignature $_.Value | Select-Object Path, Status }
    }
}
```

## Winsock LSP — Registry Structure

A Layered Service Provider inserts itself into the Winsock 2 protocol chain so it can intercept every socket operation a process on the host makes — legitimately used by some security software (content filtering, parental controls, older antivirus network shims) and historically abused by adware/spyware to intercept and redirect browser traffic. LSP entries live in the Winsock protocol catalog:

```
HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\
```

| Value | Meaning | Forensic relevance |
|---|---|---|
| `Catalog_Entries\<NNNN>` (numbered subkeys) | One subkey per registered LSP/base-protocol entry | The full catalog is a chain — entries reference each other by catalog ID, so the *order* and *completeness* of the chain matters, not just individual entries |
| `PackedCatalogItem` | Binary blob encoding the provider's GUID, path to its DLL, and protocol chain metadata | Requires parsing to extract the DLL path directly — most analysts pull this via `Get-NetAdapterBinding`/`netsh winsock show catalog` rather than decoding the binary blob by hand |

This is by a wide margin the broadest trigger surface of the three mechanisms in this note: an LSP loads into **every process on the host that uses the Windows Sockets API**, not just one service or one command invocation, giving an attacker code execution inside browsers, mail clients, and essentially anything that touches the network. That breadth comes with a well-documented operational risk that cuts both ways for detection — LSP chain corruption (a broken or missing entry, often left behind by malware removal or careless uninstallation of the software that registered it) can silently break *all* networking on the host, which means a host that suddenly loses network connectivity with no other explanation is itself worth checking for a recent LSP change. The standard, native remediation for a broken LSP chain is:

```
netsh winsock reset
```

🔴 **This command rebuilds the Winsock catalog from scratch and is evidence-destroying** — it removes the very entries an analyst would otherwise want to examine. If LSP hijacking is suspected, capture the catalog (`netsh winsock show catalog`, or an offline registry export of `Protocol_Catalog9`) before anyone runs a reset for "fix my internet" reasons, and treat a `netsh winsock reset` in a host's command history as a potential (if often innocent) evidence-destruction event worth asking about.

### PowerShell

Enumerate the live Winsock catalog via the native `netsh` command, which decodes `PackedCatalogItem` for you rather than requiring manual binary parsing:

```powershell
netsh winsock show catalog
```

Pull the raw catalog entry count and subkey names directly from the registry when working from an offline hive where `netsh` isn't available to run live:

```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries' -ErrorAction SilentlyContinue |
    Select-Object PSChildName
```

Check whether `netsh winsock reset` (or an equivalent LSP-clearing tool) appears in recent PowerShell/console history, as context for whether an apparent "clean" catalog is the result of remediation rather than an absence of compromise:

```powershell
Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue | Select-String 'winsock'
```

## Event Log Evidence

None of the three mechanisms in this note has a dedicated, always-on event ID. Evidence is again split between generic registry auditing and service-level operational logs.

| Source | Applies to | Event ID | Meaning | Notes |
|---|---|---|---|---|
| Security log | All three | 4657 | Registry value modified | 🔴 Requires **non-default auditing** with a SACL configured on the specific key — not enabled by default |
| System log | Time Providers | 7036 | `W32Time` service started/stopped | Bounds when a newly-registered provider DLL would first load |
| System log | Time Providers | 7040 (rare for this service) | Service start-type changed | Worth checking if `W32Time`'s own start type was altered as part of an attacker ensuring it runs |
| Process-creation auditing | Netsh Helper | Security 4688 (if command-line auditing enabled) | `netsh.exe` invocation | The only reliable way to know *when* a Netsh helper actually got a chance to load, since registration alone doesn't cause execution — `netsh.exe` has to run |
| System/Application log | Winsock LSP | Varies | Network-stack failures following catalog corruption | Not a dedicated LSP event, but application- or network-stack error events clustering after an LSP change are a practical corroborating signal |

Because none of these mechanisms logs its own trigger event by default, this note leans on registry-state review (unrecognized entries, out-of-place DLL paths, signature failures) as the primary detection method, corroborated by execution evidence for the DLL itself and, for Netsh specifically, by `netsh.exe` process-creation timing.

### PowerShell

Correlate `W32Time` service-restart events against each time provider's DLL file creation time, the same pattern used elsewhere in this family to bound when a planted DLL would first have loaded:

```powershell
$w32Restarts = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} -MaxEvents 50 |
    Where-Object { $_.Message -match 'Windows Time' }
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders' | ForEach-Object {
    $dll = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DllName -replace '%systemroot%', $env:SystemRoot
    if (Test-Path $dll) {
        [PSCustomObject]@{ Provider = $_.PSChildName; DllCreated = (Get-Item $dll).CreationTime; LastServiceRestart = ($w32Restarts | Select-Object -First 1).TimeCreated }
    }
}
```

## Red Flags Specific to Provider & Helper DLL Hijacking

- **Time provider `DllName` resolving outside `System32`.** Legitimate providers — `NtpClient`, `NtpServer`, `VMICTimeProvider` on Hyper-V guests — all resolve into `System32`; anything else has no legitimate explanation.
- **Netsh helper value pointing at a DLL outside `System32`, especially one with no plausible VPN/network-tooling vendor behind it.** Because the value *name* itself is often an opaque vendor identifier, path verification matters more here than name-pattern recognition.
- **An LSP entry in the Winsock catalog with no corresponding installed security/network software to explain it.** Legitimate LSPs are almost always tied to specific, identifiable software (content filters, older AV network shims, some VPN clients) — an entry with no explanation is worth chasing down.
- **A time-provider or netsh-helper DLL that fails Authenticode signature validation.** All three mechanisms load DLLs into trusted, broadly-present Windows components — an unsigned DLL riding along has no legitimate excuse.
- **A host reporting sudden, unexplained total loss of network connectivity, especially followed shortly by a `netsh winsock reset` in command history.** LSP chain corruption is a well-known side effect of both legitimate uninstalls gone wrong and deliberate malicious LSP registration — the reset itself is evidence-destroying, so a reset immediately following a connectivity complaint (rather than following an identified root cause) is worth a second look.
- **A Netsh helper DLL present in the registry with no corresponding `netsh.exe` process-creation event ever recorded.** Confirms the helper is registered but has not yet had a chance to fire — useful for triaging urgency (dormant but armed) versus confirmed execution.

## Tooling

| Tool | Use |
|---|---|
| **`reg query`** | Live enumeration of `W32Time\TimeProviders`, `SOFTWARE\Microsoft\Netsh`, and (indirectly) the Winsock catalog registry path — none of the three has a dedicated PowerShell module |
| **`netsh winsock show catalog`** | The native, purpose-built way to read the Winsock LSP catalog without manually parsing `PackedCatalogItem` binary data |
| **Autoruns** (Sysinternals) | Its "Winsock Providers" tab covers LSP entries directly, with code-signing and VirusTotal cross-reference; Time Providers and Netsh Helpers are not broken out as dedicated Autoruns tabs on all versions, so cross-check those manually against the registry paths above |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders`, `SOFTWARE\Microsoft\Netsh`, and `SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9` when working from acquired `SYSTEM`/`SOFTWARE` hives — see Registry Forensics Fundamentals (note 04) |
| `sigcheck` (Sysinternals) | Bulk signature verification across resolved DLL paths for all three mechanisms |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Time provider `DllName` outside `System32` | No legitimate provider resolves elsewhere |
| Netsh helper DLL outside `System32` | Same drop-and-persist logic, harder to spot by name alone since helper value names are often opaque vendor identifiers |
| Winsock LSP entry with no identifiable owning software | Legitimate LSPs are normally traceable to specific, installed security/network software |
| Any of the three DLLs fails Authenticode signature validation | These load into trusted, broadly-present Windows components with no legitimate reason to be unsigned |
| Sudden total network-connectivity loss followed by `netsh winsock reset` in command history | LSP corruption is a known side effect of malicious registration and of botched removal; the reset itself destroys the evidence it might otherwise explain |
| Netsh helper registered with no corresponding `netsh.exe` execution evidence | Dormant-but-armed persistence — hasn't fired yet, still worth remediating before it does |
| No Security 4657 coverage of any of these three registry paths | Not enabled by default — absence doesn't mean no registry change occurred; rely on registry-state review as the primary evidence source |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure and offline `SYSTEM`/`SOFTWARE` hive access mechanics | Registry Forensics Fundamentals (note 04) |
| Service-based persistence, including the `W32Time` service's own registry footprint | Services |
| Print-Spooler DLL-hijack mechanisms following the identical registration pattern against a different host process | Print Spooler Hijacking (Port Monitors & Print Processors) |
| Other DLL-search-order and DLL-hijack persistence with no service/task footprint of its own | DLL Hijacking |
| First/last-seen evidence and hash identity of a planted provider/helper/LSP DLL | ShimCache (AppCompatCache).md, Amcache.md (note 06) |
| Confirming actual loading/execution of a planted DLL | Prefetch.md (note 06) |

## Resources

- MITRE ATT&CK T1547.003 (Boot or Logon Autostart Execution: Time Providers) — https://attack.mitre.org/techniques/T1547/003/
- MITRE ATT&CK T1546.007 (Event Triggered Execution: Netsh Helper DLL) — https://attack.mitre.org/techniques/T1546/007/
- Winsock Layered Service Providers are **not currently mapped** to a MITRE ATT&CK technique — treated here as an unmapped-but-documented persistence primitive; see the [ired.team](https://www.ired.team/) and Malwarebytes Labs LSP writeups referenced below for community documentation in the absence of a formal ATT&CK entry
- Microsoft, Windows Time Service Tools and Settings (`W32Time`) — https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings
- Microsoft, Netsh Commands — https://learn.microsoft.com/windows-server/networking/technologies/netsh/netsh
- Microsoft, Winsock Layered Service Providers overview — https://learn.microsoft.com/windows/win32/winsock/layered-service-providers-2
- ired.team, Hijacking Time Providers (T1209) — https://www.ired.team/offensive-security/persistence/t1209-hijacking-time-providers
- ired.team, Netsh Helper DLL — https://www.ired.team/offensive-security/persistence/t1128-netsh-helper-dll
- Malwarebytes Labs, "Changes in the LSP stack" — https://www.malwarebytes.com/blog/news/2014/10/changes-in-the-lsp-stack
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
