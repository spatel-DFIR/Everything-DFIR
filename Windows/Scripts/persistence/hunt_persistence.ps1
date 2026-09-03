<#
.SYNOPSIS
    Read-only Windows persistence hunter covering 40+ MITRE ATT&CK TA0003 (Persistence)
    technique families, safe for live EDR RTR (Real-Time Response, e.g. CrowdStrike Falcon)
    sessions on production hosts.

.DESCRIPTION
    hunt_persistence.ps1  v1.0  author: Suvas Patel

    A single self-contained, console-only script that enumerates the full breadth of
    common Windows persistence locations (Run keys, services, scheduled tasks, WMI
    subscriptions, Winlogon/LSA/IFEO tamper, COM hijacking, Office trust abuse, and many
    more -- see the module catalog inside this script, $script:ModuleCatalog, for the
    authoritative, current list of every technique family it covers) and prints:

      1. A full, always-shown inventory of every finding, grouped by module.
      2. An evidence-weighted ANOMALY QUEUE of only the findings that scored NOTABLE or
         HIGH (see -MinSeverity), in the same "flag on evidence, enumerate everything
         else" style as this repo's other hunt_*.ps1 tools.
      3. An honest COVERAGE REPORT: which modules ran, which were skipped and why,
         which registry paths/files were inaccessible, and which user profiles have no
         loaded registry hive (so per-user checks for that profile were skipped).

    SAFETY CONTRACT (live RTR hosts)
    Strictly read-only. This script never calls a mutating cmdlet against anything --
    no New-Item/Set-Item/Remove-Item/New-ItemProperty/Set-ItemProperty/Clear-Item against
    any registry path, no file writes of any kind (no Out-File/Export-Csv/Export-Clixml/
    Set-Content/Add-Content), no service/process control, no "reg load"/"reg unload", no
    network calls. Output goes to the console only (Write-Output/Write-Host/Write-Warning/
    Write-Error) -- there is no CSV/JSON export, by deliberate permanent design decision,
    matching the other three tools in this repo (hunt_eventlogs.ps1, hunt_recyclebin.ps1,
    the LNK-files tool). Does not require elevation to run -- it detects elevation and
    degrades gracefully (warns, then lists inaccessible targets in the coverage report)
    rather than failing.

    OUT OF SCOPE (deliberate, not an oversight -- do not add these without reopening the
    design discussion)
      - Offline/non-loaded registry hive scanning via "reg load". Mounting another user's
        hive with reg load is a WRITE to the registry (it creates a live key) and carries
        real risk of leaving a hive mounted/orphaned if an RTR session drops mid-script,
        which can break that user's profile. Per-user checks are therefore limited to
        hives already loaded (HKEY_USERS) -- see Get-LoadedUserHives / Get-OnDiskProfiles
        and the coverage report's "profiles with no loaded hive" section.
      - WSL-internal persistence (cron, systemd units, shell rc files inside a WSL distro
        filesystem). Out of scope for a Windows registry/filesystem persistence hunter.
      - Kernel/driver rootkit-hook detection (SSDT/IDT hooks, inline hooks, etc.). Needs
        kernel-mode tooling this script deliberately does not attempt to be.
      - UEFI/firmware persistence (bootkits, SPI flash implants). Outside the reach of
        anything queryable from within a running OS via PowerShell.
      - Outlook Rules. These are stored inside the mailbox (server-side or .ost/.pst),
        not in the registry or a filesystem location this tool enumerates.
      - Office macro *content* analysis (VBA project decompilation/scanning). This tool
        looks at Office *trust configuration* (Trusted Locations, Office Test) as
        persistence surface, not macro payload content.
      - Generic filesystem DLL search-order-hijack scanning. There is no fixed,
        enumerable registry/filesystem location for this technique family -- it requires
        walking arbitrary application install directories, which is a different tool's
        job. See this repo's "Windows/10 - Persistence Mechanisms/DLL Hijacking.md" for
        the manual/targeted methodology.

.PARAMETER Modules
    Restrict the run to specific module tokens (see $script:ModuleCatalog in this script
    for the full list and what each one checks). If omitted, the default run is every
    Fast-tier module, plus every Deep-tier module if -Deep is also given. If -Modules is
    given explicitly, it is taken as the exact set to run regardless of tier -- naming a
    Deep-tier token here runs it even without -Deep, since the operator asked for it by
    name.

.PARAMETER Deep
    Also run Deep-tier modules (heavier/slower checks: full COM hijack sweep, full
    Authenticode re-verification pass, Office add-ins, Outlook, SYSVOL GPO, Winsock LSP,
    BITS jobs, credential providers, BHOs, shell extensions) in addition to the Fast-tier
    default. Ignored if -Modules is explicitly given (see above).

.PARAMETER Since
    Start of an optional incident window, e.g. '2026-07-28' or '2026-07-28 09:00:00'.
    Interpreted in the host's local time zone, converted to UTC internally. Wins over
    -Days if both are supplied. When no timeframe is requested at all (-Since/-Days/
    -Until all omitted), the window is left unset and the RECENCY evidence tag is never
    produced for this run.

.PARAMETER Days
    Lookback window in days from now, used to compute the incident window start.
    Default 1. Only takes effect if -Since, -Days, or -Until is explicitly supplied --
    passing none of the three leaves timeframe scoping off entirely (see -Since above).

.PARAMETER Until
    End of the incident window. Same format/time-zone rules as -Since. Defaults to now
    when a window was requested via -Since/-Days but -Until itself was not given.

.PARAMETER MinSeverity
    Filters the ANOMALY QUEUE section only (High | Notable | Low, default Low). The full
    inventory section always shows every finding regardless of this setting. 'Low' and
    'Notable' both surface NOTABLE-and-above findings (LOW-tier findings are inventory-
    only and are never queued); 'High' surfaces HIGH-tier findings only.

.PARAMETER InventoryOnly
    Print only the full inventory section; skip the ANOMALY QUEUE. Mutually exclusive
    with -AnomaliesOnly.

.PARAMETER AnomaliesOnly
    Print only the ANOMALY QUEUE section; skip the full inventory. Mutually exclusive
    with -InventoryOnly. The COVERAGE REPORT is always printed regardless of either flag.

.PARAMETER Help
    Print usage and exit immediately, before any other processing.

.EXAMPLE
    .\hunt_persistence.ps1
    Fast-tier default run: full inventory + anomaly queue + coverage report.

.EXAMPLE
    .\hunt_persistence.ps1 -Deep -MinSeverity High
    Full Fast + Deep tier sweep, anomaly queue restricted to HIGH-tier findings only.

.EXAMPLE
    .\hunt_persistence.ps1 -Modules RunKeys,Services,ScheduledTasks,WMI -Since '2026-07-25'
    Targeted rerun of four modules, scoped to an incident window starting 2026-07-25.

.EXAMPLE
    .\hunt_persistence.ps1 -InventoryOnly
    Full inventory only, no anomaly scoring output (coverage report still prints).

.NOTES
    Author : Suvas Patel
    Version: 1.0

    THIS FILE WAS BUILT IN SEQUENTIAL PASSES (A: scaffolding/shared helpers/scoring
    engine/rendering; B: 10 structurally-nontrivial core modules; C: 21 Fast-tier
    modules; D: 10 Deep-tier modules + final dispatch wiring). All 42 tokens in
    $script:ModuleCatalog now resolve to a real function -- see that catalog for the
    authoritative, current list of every technique family this tool covers, and the
    region comments (Pass B/C/D) throughout this file for which build pass wrote which
    functions.
#>

[CmdletBinding()]
param(
    [ValidateSet(
        'RunKeys', 'StartupFolders', 'ShellFolderRedir', 'Services', 'ServiceDll',
        'ScheduledTasks', 'WMI', 'Winlogon', 'LSAPackages', 'IFEO', 'AppInitCerts',
        'ActiveSetup', 'BootLogonScripts', 'PortMonitors', 'PrintProcessors',
        'TimeProviders', 'NetshHelpers', 'AppShim', 'PSProfiles', 'PSModulePath',
        'CommandProcessorAutoRun', 'EnvHijack', 'SafeBoot', 'TerminalServices',
        'NetworkProviderOrder', 'BootExecute', 'FileAssoc', 'Screensaver', 'OfficeTest',
        'OfficeTrustedLocations', 'KnownDlls', 'ComWatchlist',
        'ComFull', 'FullSignaturePass', 'OfficeAddins', 'Outlook', 'SysvolGpo',
        'WinsockLsp', 'BitsJobs', 'CredentialProviders', 'BHO', 'ShellExt'
    )]
    [string[]]$Modules,

    [switch]$Deep,

    [string]$Since,

    [int]$Days = 1,

    [string]$Until,

    [ValidateSet('High', 'Notable', 'Low')]
    [string]$MinSeverity = 'Low',

    [switch]$InventoryOnly,

    [switch]$AnomaliesOnly,

    [switch]$Help
)

# ===========================================================================
#  Constants
# ===========================================================================
$ScriptVersion = '1.0'
$ScriptAuthor  = 'Suvas Patel'
$ScriptName    = 'hunt_persistence.ps1'

# Tier thresholds shared by Add-Finding and the rendering functions.
$script:HighThreshold    = 6
$script:NotableThreshold = 3

# ---------------------------------------------------------------------------
# -Help : handled before anything else runs, per RTR requirement.
# ---------------------------------------------------------------------------
if ($Help) {
    @"
$ScriptName  v$ScriptVersion  author: $ScriptAuthor

Read-only Windows persistence hunter covering 40+ MITRE ATT&CK TA0003 (Persistence)
technique families. Safe for EDR RTR live sessions: read-only, console-only output,
no files written, no CSV/JSON export, no elevation required (degrades gracefully).

USAGE
  .\$ScriptName [-Modules <token[]>] [-Deep] [-Since <datetime>] [-Days <int>]
      [-Until <datetime>] [-MinSeverity High|Notable|Low] [-InventoryOnly]
      [-AnomaliesOnly] [-Help]

OUTPUT SECTIONS
  Full Inventory   Every finding from every module that ran, grouped by module.
                    Skipped (with a note) if -AnomaliesOnly is given.
  Anomaly Queue     Findings scored NOTABLE+ (or HIGH-only with -MinSeverity High).
                    Skipped (with a note) if -InventoryOnly is given.
  Coverage Report   Always printed: modules run/skipped, unreadable targets, user
                    profiles with no loaded hive, elevation status.

KEY PARAMETERS
  -Modules <token[]>   Restrict to specific module tokens. Default: all Fast-tier
                        modules (+ Deep-tier too if -Deep is also given). Naming a
                        Deep-tier token explicitly here runs it even without -Deep.
  -Deep                Also run Deep-tier (heavier) modules. Ignored if -Modules given.
  -Since <datetime>    Incident window start, e.g. '2026-07-28' or '2026-07-28 09:00:00'.
                        Wins over -Days. Enables the RECENCY evidence tag.
  -Days <int>          Lookback window in days (default 1). Ignored if -Since given.
                        No timeframe scoping happens at all unless -Since/-Days/-Until
                        is explicitly supplied.
  -Until <datetime>    End of window (default: now, once a window is requested).
  -MinSeverity         High | Notable | Low (default Low). Filters the anomaly queue
                        only -- the full inventory always shows everything.
  -InventoryOnly       Print inventory only.
  -AnomaliesOnly       Print anomaly queue only.

See the comment-based help (Get-Help -Full .\$ScriptName) for the full parameter
reference and the explicit OUT-OF-SCOPE list (reg load, WSL, kernel hooks, UEFI,
Outlook Rules, Office macro content, generic DLL search-order-hijack scanning).

All displayed timestamps are UTC.
"@ | Write-Output
    return
}

# ===========================================================================
#  Module catalog -- the key extension point for Pass B/C/D
# ===========================================================================
#
# One entry per technique family this tool covers. Pass B/C/D implement the
# function named in FunctionName; the dispatch loop at the bottom of this file
# calls it via "& $entry.FunctionName" if (and only if) Get-Command finds it,
# so this catalog is authoritative for both what gets run and what still needs
# to be built. Attack = MITRE ATT&CK sub-technique ID where confidently known,
# else the literal string 'Unmapped' -- do not guess.
#
$script:ModuleCatalog = @(
    # ---- Fast tier (32 tokens) --------------------------------------------
    [PSCustomObject]@{ Token = 'RunKeys';                 FunctionName = 'Get-RunKeyPersistence';                 Tier = 'Fast'; Attack = 'T1547.001'; DisplayName = 'Registry Run / RunOnce Keys' }
    [PSCustomObject]@{ Token = 'StartupFolders';           FunctionName = 'Get-StartupFolderPersistence';          Tier = 'Fast'; Attack = 'T1547.001'; DisplayName = 'Startup Folder Items (user & common)' }
    [PSCustomObject]@{ Token = 'ShellFolderRedir';         FunctionName = 'Get-ShellFolderRedirectionPersistence'; Tier = 'Fast'; Attack = 'T1547.001'; DisplayName = 'Shell Folder Redirection (User Shell Folders)' }
    [PSCustomObject]@{ Token = 'Services';                 FunctionName = 'Get-ServicePersistence';                Tier = 'Fast'; Attack = 'T1543.003'; DisplayName = 'Windows Services' }
    [PSCustomObject]@{ Token = 'ServiceDll';               FunctionName = 'Get-ServiceDllPersistence';             Tier = 'Fast'; Attack = 'T1543.003'; DisplayName = 'Service DLL Hijack (svchost-hosted services)' }
    [PSCustomObject]@{ Token = 'ScheduledTasks';           FunctionName = 'Get-ScheduledTaskPersistence';          Tier = 'Fast'; Attack = 'T1053.005'; DisplayName = 'Scheduled Tasks' }
    [PSCustomObject]@{ Token = 'WMI';                      FunctionName = 'Get-WmiEventSubscriptionPersistence';   Tier = 'Fast'; Attack = 'T1546.003'; DisplayName = 'WMI Event Subscriptions' }
    [PSCustomObject]@{ Token = 'Winlogon';                 FunctionName = 'Get-WinlogonHelperPersistence';         Tier = 'Fast'; Attack = 'T1547.004'; DisplayName = 'Winlogon Helper DLL / Shell / Userinit' }
    [PSCustomObject]@{ Token = 'LSAPackages';              FunctionName = 'Get-LsaPackagePersistence';             Tier = 'Fast'; Attack = 'T1547.005'; DisplayName = 'LSA Authentication/Notification/Security Packages' }
    [PSCustomObject]@{ Token = 'IFEO';                     FunctionName = 'Get-IfeoPersistence';                   Tier = 'Fast'; Attack = 'T1546.012'; DisplayName = 'Image File Execution Options Debugger Hijack' }
    [PSCustomObject]@{ Token = 'AppInitCerts';              FunctionName = 'Get-AppInitCertsPersistence';           Tier = 'Fast'; Attack = 'T1546.010'; DisplayName = 'AppInit_DLLs & Trust Provider/Certificate Hijack' }
    [PSCustomObject]@{ Token = 'ActiveSetup';              FunctionName = 'Get-ActiveSetupPersistence';            Tier = 'Fast'; Attack = 'T1547.014'; DisplayName = 'Active Setup StubPath' }
    [PSCustomObject]@{ Token = 'BootLogonScripts';         FunctionName = 'Get-BootLogonScriptPersistence';        Tier = 'Fast'; Attack = 'T1037.001'; DisplayName = 'Boot / Logon Scripts (Group Policy)' }
    [PSCustomObject]@{ Token = 'PortMonitors';             FunctionName = 'Get-PortMonitorPersistence';            Tier = 'Fast'; Attack = 'T1547.010'; DisplayName = 'Port Monitors' }
    [PSCustomObject]@{ Token = 'PrintProcessors';          FunctionName = 'Get-PrintProcessorPersistence';         Tier = 'Fast'; Attack = 'T1547.012'; DisplayName = 'Print Processors' }
    [PSCustomObject]@{ Token = 'TimeProviders';            FunctionName = 'Get-TimeProviderPersistence';           Tier = 'Fast'; Attack = 'T1547.003'; DisplayName = 'Time Providers' }
    [PSCustomObject]@{ Token = 'NetshHelpers';             FunctionName = 'Get-NetshHelperPersistence';            Tier = 'Fast'; Attack = 'T1546.007'; DisplayName = 'Netsh Helper DLLs' }
    [PSCustomObject]@{ Token = 'AppShim';                  FunctionName = 'Get-AppShimPersistence';                Tier = 'Fast'; Attack = 'T1546.011'; DisplayName = 'Application Shimming (Custom SDB)' }
    [PSCustomObject]@{ Token = 'PSProfiles';               FunctionName = 'Get-PSProfilePersistence';              Tier = 'Fast'; Attack = 'T1546.013'; DisplayName = 'PowerShell Profile Scripts' }
    [PSCustomObject]@{ Token = 'PSModulePath';             FunctionName = 'Get-PSModulePathPersistence';           Tier = 'Fast'; Attack = 'Unmapped';  DisplayName = 'PSModulePath Environment Hijack' }
    [PSCustomObject]@{ Token = 'CommandProcessorAutoRun';  FunctionName = 'Get-CommandProcessorAutoRunPersistence';Tier = 'Fast'; Attack = 'Unmapped';  DisplayName = 'cmd.exe AutoRun Registry Value' }
    [PSCustomObject]@{ Token = 'EnvHijack';                FunctionName = 'Get-EnvironmentVariableHijackPersistence'; Tier = 'Fast'; Attack = 'Unmapped'; DisplayName = 'Environment Variable Hijack (COR_PROFILER, windir, etc.)' }
    [PSCustomObject]@{ Token = 'SafeBoot';                 FunctionName = 'Get-SafeBootPersistence';               Tier = 'Fast'; Attack = 'Unmapped';  DisplayName = 'SafeBoot Minimal/Network Service Enablement' }
    [PSCustomObject]@{ Token = 'TerminalServices';         FunctionName = 'Get-TerminalServicesPersistence';       Tier = 'Fast'; Attack = 'Unmapped';  DisplayName = 'Terminal Services InitialProgram/Shell Hijack' }
    [PSCustomObject]@{ Token = 'NetworkProviderOrder';     FunctionName = 'Get-NetworkProviderPersistence';        Tier = 'Fast'; Attack = 'T1556.008'; DisplayName = 'Network Provider Order DLL Hijack' }
    [PSCustomObject]@{ Token = 'BootExecute';              FunctionName = 'Get-BootExecutePersistence';            Tier = 'Fast'; Attack = 'Unmapped';  DisplayName = 'Session Manager BootExecute Value' }
    [PSCustomObject]@{ Token = 'FileAssoc';                FunctionName = 'Get-FileAssociationPersistence';        Tier = 'Fast'; Attack = 'T1546.001'; DisplayName = 'Change Default File Association' }
    [PSCustomObject]@{ Token = 'Screensaver';              FunctionName = 'Get-ScreensaverPersistence';            Tier = 'Fast'; Attack = 'T1546.002'; DisplayName = 'Screensaver Hijack' }
    [PSCustomObject]@{ Token = 'OfficeTest';               FunctionName = 'Get-OfficeTestPersistence';             Tier = 'Fast'; Attack = 'T1137.002'; DisplayName = 'Office Test Registry Value' }
    [PSCustomObject]@{ Token = 'OfficeTrustedLocations';   FunctionName = 'Get-OfficeTrustedLocationPersistence';  Tier = 'Fast'; Attack = 'Unmapped';  DisplayName = 'Office Trusted Locations Macro Bypass' }
    [PSCustomObject]@{ Token = 'KnownDlls';                FunctionName = 'Get-KnownDllsPersistence';              Tier = 'Fast'; Attack = 'T1574.001'; DisplayName = 'KnownDLLs Registry Tampering' }
    [PSCustomObject]@{ Token = 'ComWatchlist';             FunctionName = 'Get-ComHijackWatchlistPersistence';     Tier = 'Fast'; Attack = 'T1546.015'; DisplayName = 'COM Hijacking (fast watchlist subset)' }

    # ---- Deep tier (10 tokens) ---------------------------------------------
    [PSCustomObject]@{ Token = 'ComFull';                  FunctionName = 'Get-ComHijackFullScanPersistence';      Tier = 'Deep'; Attack = 'T1546.015'; DisplayName = 'COM Hijacking (full CLSID/InprocServer32 sweep)' }
    [PSCustomObject]@{ Token = 'FullSignaturePass';        FunctionName = 'Get-FullSignatureSweepPersistence';     Tier = 'Deep'; Attack = 'Unmapped';  DisplayName = 'Full Authenticode Re-verification Pass' }
    [PSCustomObject]@{ Token = 'OfficeAddins';             FunctionName = 'Get-OfficeAddinPersistence';            Tier = 'Deep'; Attack = 'T1137.006'; DisplayName = 'Office Add-ins (WLL/VSTO/COM)' }
    [PSCustomObject]@{ Token = 'Outlook';                  FunctionName = 'Get-OutlookPersistence';                Tier = 'Deep'; Attack = 'T1137.004'; DisplayName = 'Outlook Home Page / Registry-Visible Config' }
    [PSCustomObject]@{ Token = 'SysvolGpo';                FunctionName = 'Get-SysvolGpoPersistence';              Tier = 'Deep'; Attack = 'T1037.003'; DisplayName = 'SYSVOL GPO Scripts/Preferences Tampering' }
    [PSCustomObject]@{ Token = 'WinsockLsp';               FunctionName = 'Get-WinsockLspPersistence';             Tier = 'Deep'; Attack = 'Unmapped';  DisplayName = 'Winsock Layered Service Provider (LSP) Hijack' }
    [PSCustomObject]@{ Token = 'BitsJobs';                 FunctionName = 'Get-BitsJobPersistence';                Tier = 'Deep'; Attack = 'T1197';     DisplayName = 'BITS Jobs' }
    [PSCustomObject]@{ Token = 'CredentialProviders';      FunctionName = 'Get-CredentialProviderPersistence';     Tier = 'Deep'; Attack = 'Unmapped';  DisplayName = 'Credential Provider / Password Filter DLL' }
    [PSCustomObject]@{ Token = 'BHO';                      FunctionName = 'Get-BhoPersistence';                    Tier = 'Deep'; Attack = 'T1176';     DisplayName = 'Browser Helper Objects (Internet Explorer, legacy)' }
    [PSCustomObject]@{ Token = 'ShellExt';                 FunctionName = 'Get-ShellExtensionPersistence';         Tier = 'Deep'; Attack = 'Unmapped';  DisplayName = 'Shell Extension Handlers (shellex CLSID)' }
)

# ===========================================================================
#  Evidence-scoring engine
# ===========================================================================
#
# THE FINDING SHAPE -- every module function (Pass B/C/D) produces its results
# by calling Add-Finding below, which builds and appends objects of exactly
# this shape to $script:AllFindings. Later passes and the rendering functions
# in this file all depend on this shape staying stable:
#
#   Module              string   Human-readable module name (e.g. 'Run Keys')
#   Token               string   Catalog token (e.g. 'RunKeys')
#   Technique           string   ATT&CK sub-technique ID, or 'Unmapped'
#   Location            string   Registry path or file path where this was found
#   ValueName           string   Registry value name, if applicable ($null otherwise)
#   RawValue            string   The raw string as found (unparsed command line, ImagePath, etc.)
#   ResolvedTarget      string   Best-effort resolved executable/DLL path (see Resolve-CommandLineTarget)
#   PathTrust           string   'Trusted' | 'Untrusted' | 'Other' | 'DoesNotExist' (see Test-PathTrust)
#   SignatureStatus     string   Valid | NotSigned | HashMismatch | UnknownError | NotTrusted | FileNotFound | Error
#   SignaturePublisher  string   Signer certificate subject, or $null
#   LastWriteUtc        datetime Last-write time (UTC) of the key/file, or $null
#   Score               int      Computed by Add-Finding from Evidence tag weights
#   Evidence            string[] Evidence tags present (see $script:EvidenceWeights)
#   Tier                string   'HIGH' | 'NOTABLE' | 'LOW'
#   IsAbsolute          bool     $true if Tier was forced via Add-Finding -Absolute, not scored
#
$script:AllFindings      = New-Object System.Collections.Generic.List[object]

# Targets (registry paths, files) a module function could not read. Same
# pattern as hunt_eventlogs.ps1's $UnreadableLogs -- append PSCustomObjects
# shaped @{ Target = <string>; Reason = <string> }, never drop a failure
# silently.
$script:UnreadableTargets = New-Object System.Collections.Generic.List[object]

# Evidence tag -> score weight. LOLBIN-DOWNLOADER-family tags (the literal
# 'LOLBIN-DOWNLOADER' tag, or any future sub-tag a module author prefixes with
# 'LOLBIN-DOWNLOADER', e.g. 'LOLBIN-DOWNLOADER-CERTUTIL') are capped at a
# combined contribution of 8 to Score even if several match at once -- see the
# scoring loop in Add-Finding.
$script:EvidenceWeights = @{
    'SIG-TAMPERED'                  = 6
    'SIG-UNSIGNED-TRUSTED-LOCATION' = 4
    'SIG-UNSIGNED-OTHER'            = 2
    'PATH-UNTRUSTED'                = 4
    'PATH-DANGLING'                 = 3
    'LOLBIN-ENCODED'                = 4
    'LOLBIN-HIDDEN'                 = 3
    'LOLBIN-DOWNLOADER'             = 4
    'LOLBIN-RAW-NETWORK-LITERAL'    = 3
    'RECENCY'                       = 2
}

# Timeframe window (UTC), resolved in the Main section below. Both remain
# $null -- a persistent "no incident window requested" state -- unless the
# operator explicitly supplied -Since, -Days, or -Until.
$script:WindowStart = $null
$script:WindowEnd   = $null

# Called by module functions (Pass B/C/D) before deciding whether to add the
# RECENCY evidence tag to a finding.
function Test-InWindow {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $TimeUtc
    )
    if (-not $script:WindowStart -or -not $script:WindowEnd) { return $false }
    if (-not $TimeUtc) { return $false }
    return ($TimeUtc -ge $script:WindowStart -and $TimeUtc -le $script:WindowEnd)
}

# Module functions call this to record a finding. Computes Score from the
# Evidence tags supplied (via $script:EvidenceWeights), derives Tier from
# Score, unless -Absolute is given to force Tier regardless of the numeric
# score -- for the small set of hard-absolute findings later passes will
# implement (IFEO accessibility hijack, Winlogon Shell/Userinit tamper,
# untrusted LSA package, modified BootExecute, SafeDllSearchMode disabled,
# populated Command Processor AutoRun, active AppInit, set COR_PROFILER,
# orphaned TaskCache entry, etc.) where the mere presence of the artifact is
# itself conclusive, independent of any weighted score.
function Add-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Token,
        [string]$Technique = 'Unmapped',
        [string]$Location,
        [string]$ValueName,
        [string]$RawValue,
        [string]$ResolvedTarget,
        [string]$PathTrust,
        [string]$SignatureStatus,
        [string]$SignaturePublisher,
        [AllowNull()]$LastWriteUtc,
        [string[]]$Evidence,
        [ValidateSet('HIGH', 'NOTABLE')]
        [string]$Absolute
    )

    if (-not $Evidence) { $Evidence = @() }

    $score = 0
    $downloaderContribution = 0
    foreach ($tag in $Evidence) {
        $weight = 0
        if ($script:EvidenceWeights.ContainsKey($tag)) {
            $weight = $script:EvidenceWeights[$tag]
        } elseif ($tag -like 'LOLBIN-DOWNLOADER*') {
            $weight = $script:EvidenceWeights['LOLBIN-DOWNLOADER']
        }

        if ($tag -like 'LOLBIN-DOWNLOADER*') {
            $downloaderContribution += $weight
        } else {
            $score += $weight
        }
    }
    if ($downloaderContribution -gt 8) { $downloaderContribution = 8 }
    $score += $downloaderContribution

    $isAbsolute = $false
    if ($Absolute) {
        $tier = $Absolute
        $isAbsolute = $true
    } elseif ($score -ge $script:HighThreshold) {
        $tier = 'HIGH'
    } elseif ($score -ge $script:NotableThreshold) {
        $tier = 'NOTABLE'
    } else {
        $tier = 'LOW'
    }

    $finding = [PSCustomObject]@{
        Module             = $Module
        Token              = $Token
        Technique          = $Technique
        Location           = $Location
        ValueName          = $ValueName
        RawValue           = $RawValue
        ResolvedTarget     = $ResolvedTarget
        PathTrust          = $PathTrust
        SignatureStatus    = $SignatureStatus
        SignaturePublisher = $SignaturePublisher
        LastWriteUtc       = $LastWriteUtc
        Score              = $score
        Evidence           = $Evidence
        Tier               = $tier
        IsAbsolute         = $isAbsolute
    }

    $script:AllFindings.Add($finding)
    return $finding
}

# ===========================================================================
#  Shared helper functions -- pure readers only
# ===========================================================================
#
# Every helper below must handle a missing/inaccessible/malformed target
# gracefully (try/catch, return a sentinel value) and must never throw
# uncaught -- a module function calling one of these should never need its
# own top-level try/catch just to survive a bad path.

# Trust verdict for a resolved filesystem path.
#   'Trusted'      System32/SysWOW64/Program Files/Program Files (x86)/WinSxS
#   'Untrusted'    TEMP, Local\Temp, a Downloads folder, ProgramData root
#                  (exactly "C:\ProgramData\<file>", not a vendor subfolder),
#                  a drive root, or a user profile root
#   'DoesNotExist' path does not resolve to a file on disk -- PATH-DANGLING
#                  evidence, not collapsed into 'Other'
#   'Other'        anything else (e.g. a custom install dir under a drive
#                  root's subfolder that isn't clearly trusted or untrusted)
function Test-PathTrust {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return 'Other' }

    $exists = $false
    try {
        $exists = Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction Stop
    } catch {
        $exists = $false
    }
    if (-not $exists) { return 'DoesNotExist' }

    $full = $Path
    try {
        $full = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    } catch {
        $full = $Path
    }

    $systemRoot      = $env:SystemRoot
    $programFiles    = $env:ProgramFiles
    $programFilesX86 = ${env:ProgramFiles(x86)}
    $temp            = $env:TEMP
    # The prompt's own convention for "the roaming-profile-relative local temp
    # folder" is %LOCALAPPDATA%\Temp (i.e. C:\Users\<user>\AppData\Local\Temp)
    # -- using $env:LOCALAPPDATA here rather than $env:APPDATA, since APPDATA
    # points at \Roaming, which has no \Temp subfolder in a stock profile.
    $localTemp       = $null
    if ($env:LOCALAPPDATA) { $localTemp = Join-Path $env:LOCALAPPDATA 'Temp' }
    $programData     = $env:ProgramData

    # ---- Trusted ----
    if ($systemRoot -and ($full -like (Join-Path $systemRoot 'System32\*'))) { return 'Trusted' }
    if ($systemRoot -and ($full -like (Join-Path $systemRoot 'SysWOW64\*'))) { return 'Trusted' }
    if ($programFiles -and ($full -like "$programFiles\*")) { return 'Trusted' }
    if ($programFilesX86 -and ($full -like "$programFilesX86\*")) { return 'Trusted' }
    if ($full -match '\\WinSxS\\') { return 'Trusted' }

    # ---- Untrusted ----
    if ($temp -and ($full -like "$temp\*")) { return 'Untrusted' }
    if ($localTemp -and ($full -like "$localTemp\*")) { return 'Untrusted' }
    if ($full -match '\\Downloads\\') { return 'Untrusted' }

    $parentDir = $null
    try { $parentDir = Split-Path -Path $full -Parent } catch { $parentDir = $null }

    if ($parentDir -and $programData -and ($parentDir.TrimEnd('\') -ieq $programData.TrimEnd('\'))) { return 'Untrusted' }
    if ($parentDir -and ($parentDir -match '^[A-Za-z]:\\$')) { return 'Untrusted' }
    if ($parentDir -and ($parentDir -match '^[A-Za-z]:\\Users\\[^\\]+$')) { return 'Untrusted' }

    return 'Other'
}

# Best-effort extraction of a testable executable/DLL file path from a raw
# command-line or ImagePath-style string.
#
# ASSUMPTIONS (documented, not exhaustive -- this is best-effort, not a full
# command-line parser):
#   - A leading double-quoted segment is treated as the full path; everything
#     after the closing quote is treated as arguments.
#   - Otherwise, tokens are scanned left to right for the first one ending in
#     a known executable/library extension (.exe/.dll/.com/.scr/.sys/.cpl);
#     everything up to and including that token is the path (handles unquoted
#     paths containing spaces reasonably, e.g. "C:\Program Files\foo\bar.exe
#     -x"), and if nothing matches, the first whitespace-delimited token is
#     used as a last resort.
#   - rundll32.exe/regsvr32.exe invocations: the DLL argument is treated as
#     the real target, since that is what actually executes attacker code,
#     not the LOLBin host binary itself.
#   - Does not handle nested quoting, environment variable expansion, or
#     every possible escaping edge case. A module function should treat a
#     $null/empty result as "could not resolve", not as evidence of anything.
function Resolve-CommandLineTarget {
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }

    $cl = $CommandLine.Trim()
    $target    = $null
    $remainder = ''

    if ($cl.StartsWith('"')) {
        $endQuote = $cl.IndexOf('"', 1)
        if ($endQuote -gt 0) {
            $target    = $cl.Substring(1, $endQuote - 1)
            $remainder = $cl.Substring($endQuote + 1).Trim()
        } else {
            $target    = $cl.Trim('"')
            $remainder = ''
        }
    } else {
        $knownExt = @('.exe', '.dll', '.com', '.scr', '.sys', '.cpl')
        $tokens = $cl -split '\s+'
        $found = $false
        for ($i = 0; $i -lt $tokens.Count; $i++) {
            $tokenLower = $tokens[$i].ToLowerInvariant()
            foreach ($ext in $knownExt) {
                if ($tokenLower.EndsWith($ext)) {
                    $target = ($tokens[0..$i] -join ' ')
                    if ($i + 1 -le $tokens.Count - 1) {
                        $remainder = ($tokens[($i + 1)..($tokens.Count - 1)] -join ' ')
                    } else {
                        $remainder = ''
                    }
                    $found = $true
                    break
                }
            }
            if ($found) { break }
        }
        if (-not $found) {
            $target = $tokens[0]
            if ($tokens.Count -gt 1) {
                $remainder = ($tokens[1..($tokens.Count - 1)] -join ' ')
            } else {
                $remainder = ''
            }
        }
    }

    $hostName = $null
    try { $hostName = [System.IO.Path]::GetFileName($target) } catch { $hostName = $null }

    if ($hostName -and ($hostName -ieq 'rundll32.exe' -or $hostName -ieq 'rundll32')) {
        if ($remainder) {
            $dllArg = ($remainder -split ',')[0].Trim()
            $dllArg = ($dllArg -split '\s+')[0]
            if ($dllArg) { return $dllArg }
        }
    }
    if ($hostName -and ($hostName -ieq 'regsvr32.exe' -or $hostName -ieq 'regsvr32')) {
        if ($remainder -match '([A-Za-z]:\\[^\s"]+\.dll|\\\\[^\s"]+\.dll)') {
            return $Matches[1]
        }
    }

    return $target
}

# Wraps Get-AuthenticodeSignature with a consistent, never-throws result.
function Get-AuthenticodeVerdict {
    param([string]$Path)

    $result = [PSCustomObject]@{
        Status    = 'Error'
        Publisher = $null
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $result.Status = 'FileNotFound'
        return $result
    }

    $exists = $false
    try {
        $exists = Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction Stop
    } catch {
        $exists = $false
    }
    if (-not $exists) {
        $result.Status = 'FileNotFound'
        return $result
    }

    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        switch ([string]$sig.Status) {
            'Valid'        { $result.Status = 'Valid' }
            'NotSigned'    { $result.Status = 'NotSigned' }
            'HashMismatch' { $result.Status = 'HashMismatch' }
            'NotTrusted'   { $result.Status = 'NotTrusted' }
            'UnknownError' { $result.Status = 'UnknownError' }
            default        { $result.Status = 'UnknownError' }
        }
        if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject) {
            $result.Publisher = $sig.SignerCertificate.Subject
        }
    } catch {
        $result.Status = 'Error'
    }

    return $result
}

# Regex-based LOLBin/suspicious command-line evidence tagging. Returns each
# matched tag once (no duplicates) as a string array; never throws.
function Get-CommandLineEvidence {
    param([string]$CommandLine)

    $tags = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $tags.ToArray() }

    $opts = [Text.RegularExpressions.RegexOptions]::IgnoreCase

    try {
        # LOLBIN-ENCODED: -enc / -EncodedCommand followed by a long base64-looking blob
        if ([Text.RegularExpressions.Regex]::IsMatch($CommandLine, '-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}', $opts)) {
            $tags.Add('LOLBIN-ENCODED')
        }

        # LOLBIN-HIDDEN: hidden window style combined with -NoProfile/-nop
        $hasHiddenWindow = [Text.RegularExpressions.Regex]::IsMatch($CommandLine, '(-windowstyle\s+hidden|-w\s+hidden)', $opts)
        $hasNoProfile    = [Text.RegularExpressions.Regex]::IsMatch($CommandLine, '(-noprofile|-nop\b)', $opts)
        if ($hasHiddenWindow -and $hasNoProfile) {
            $tags.Add('LOLBIN-HIDDEN')
        }

        # LOLBIN-DOWNLOADER family
        $downloaderPatterns = @(
            'rundll32[^"\r\n]*(https?://|\\\\)',
            'regsvr32[^"\r\n]*/i:https?://',
            'mshta[^"\r\n]*(https?://|vbscript:)',
            'certutil[^"\r\n]*(-urlcache|-decode)',
            'bitsadmin[^"\r\n]*/transfer',
            '(wscript|cscript)[^"\r\n]*(\\temp\\|\\appdata\\)'
        )
        foreach ($p in $downloaderPatterns) {
            if ([Text.RegularExpressions.Regex]::IsMatch($CommandLine, $p, $opts)) {
                if (-not $tags.Contains('LOLBIN-DOWNLOADER')) { $tags.Add('LOLBIN-DOWNLOADER') }
            }
        }

        # LOLBIN-RAW-NETWORK-LITERAL: bare IPv4 or http(s):// literal
        $hasIp  = [Text.RegularExpressions.Regex]::IsMatch($CommandLine, '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', $opts)
        $hasUrl = [Text.RegularExpressions.Regex]::IsMatch($CommandLine, 'https?://', $opts)
        if ($hasIp -or $hasUrl) {
            $tags.Add('LOLBIN-RAW-NETWORK-LITERAL')
        }
    } catch {
        # A regex engine failure here should never take down a module -- fall
        # through and return whatever tags were already found.
    }

    return $tags.ToArray()
}

# Microsoft.Win32.RegistryKey does not expose the key's own last-write time
# via any public property -- the only way to read it without mutating
# anything is the native RegQueryInfoKey Win32 API, called against the
# already-open handle. This is the same read-only technique registry-
# forensics tools (RECmd, Registry Explorer, etc.) rely on; it requires only
# KEY_QUERY_VALUE access (already implied by having the key open for
# reading) and performs no write of any kind.
Add-Type -Namespace Native -Name RegistryTime -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
public static extern int RegQueryInfoKey(
    Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
    System.Text.StringBuilder lpClass,
    ref uint lpcchClass,
    IntPtr lpReserved,
    ref uint lpcSubKeys,
    ref uint lpcbMaxSubKeyLen,
    ref uint lpcbMaxClassLen,
    ref uint lpcValues,
    ref uint lpcbMaxValueNameLen,
    ref uint lpcbMaxValueLen,
    ref uint lpcbSecurityDescriptor,
    out long lpftLastWriteTime);
'@ -ErrorAction SilentlyContinue

function Get-RegKeyLastWriteTimeUtc {
    param([Parameter(Mandatory = $true)][Microsoft.Win32.RegistryKey]$Key)

    try {
        $className       = New-Object System.Text.StringBuilder 1024
        $classLen        = [uint32]1024
        $subKeys         = [uint32]0
        $maxSubKeyLen    = [uint32]0
        $maxClassLen     = [uint32]0
        $values          = [uint32]0
        $maxValueNameLen = [uint32]0
        $maxValueLen     = [uint32]0
        $secDescriptor   = [uint32]0
        $lastWriteTime   = [long]0

        $rc = [Native.RegistryTime]::RegQueryInfoKey(
            $Key.Handle, $className, [ref]$classLen, [IntPtr]::Zero,
            [ref]$subKeys, [ref]$maxSubKeyLen, [ref]$maxClassLen,
            [ref]$values, [ref]$maxValueNameLen, [ref]$maxValueLen,
            [ref]$secDescriptor, [ref]$lastWriteTime)

        if ($rc -ne 0) { return $null }

        return [DateTime]::FromFileTimeUtc($lastWriteTime)
    } catch {
        return $null
    }
}

# Mounts HKU: (session-local read alias only -- not a disk/registry write)
# and enumerates loaded user hives, excluding "_Classes"-suffixed subkeys.
# Every SID is resolved to an account name where possible; on translation
# failure, the bare SID string is used instead of dropping the entry.
function Get-LoadedUserHives {
    $result = New-Object System.Collections.Generic.List[object]

    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        try {
            New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -Scope Script -ErrorAction Stop | Out-Null
        } catch {
            return $result
        }
    }

    $subKeys = $null
    try {
        $subKeys = Get-ChildItem -LiteralPath 'HKU:\' -ErrorAction Stop
    } catch {
        return $result
    }

    foreach ($k in $subKeys) {
        $sid = $k.PSChildName
        if ($sid -like '*_Classes') { continue }

        $accountName = $null
        try {
            $accountName = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $accountName = $sid
        }

        $result.Add([PSCustomObject]@{
            SID         = $sid
            AccountName = $accountName
            HivePath    = "HKU:\$sid"
        })
    }

    return $result
}

# Authoritative on-disk profile list (ProfileImagePath per SID from
# HKLM:\...\ProfileList), cross-referenced against Get-LoadedUserHives to set
# HiveLoaded. This is the basis of the coverage report's per-user honesty
# check: a profile found here with HiveLoaded = $false means registry-backed
# per-user checks were skipped for it, because mounting it via "reg load" is
# explicitly out of scope (see the OUT OF SCOPE note in the help block).
function Get-OnDiskProfiles {
    $result = New-Object System.Collections.Generic.List[object]

    $loadedHives  = Get-LoadedUserHives
    $loadedSidSet = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    foreach ($h in $loadedHives) { [void]$loadedSidSet.Add($h.SID) }

    $profileKeys = $null
    try {
        $profileKeys = Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop
    } catch {
        return $result
    }

    foreach ($pk in $profileKeys) {
        $sid = $pk.PSChildName
        $profilePath = $null
        try {
            $profilePath = (Get-ItemProperty -LiteralPath $pk.PSPath -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
        } catch {
            $profilePath = $null
        }

        $result.Add([PSCustomObject]@{
            SID         = $sid
            ProfilePath = $profilePath
            HiveLoaded  = $loadedSidSet.Contains($sid)
        })
    }

    return $result
}
# ===========================================================================
#  Core Persistence Modules (Pass B)
# ===========================================================================
#region Core Persistence Modules (Pass B)
#
# Ten structurally-nontrivial module functions (RunKeys, StartupFolders,
# Services, ServiceDll, ScheduledTasks, WMI, Winlogon, LSAPackages, IFEO,
# AppInitCerts, ActiveSetup). Every function below is read-only: only
# Get-Item/Get-ChildItem/Get-ItemProperty-style registry reads, Get-ChildItem
# filesystem reads, and Get-ScheduledTask/Get-CimInstance native readers.
# Every registry/filesystem/CIM call is wrapped in try/catch; failures other
# than "the target simply doesn't exist" are appended to
# $script:UnreadableTargets rather than thrown. Each function calls
# Add-Finding for every item it inspects, including zero-evidence inventory
# items (Evidence = @()), per the shared scoring engine's contract.

# ---------------------------------------------------------------------------
# Private helpers shared by several module functions below (not part of the
# Pass A shared-helpers region -- kept local to this region since they exist
# only to remove duplication across the ~10 functions that follow).
# ---------------------------------------------------------------------------

# Get-Item wrapper that treats "key not present" as the silent, expected case
# (most of the keys these modules probe are legitimately absent on most
# hosts -- e.g. WOW6432Node on a 32-bit OS, a per-user Shell override that
# almost no profile sets) while still recording genuine access failures
# (permissions, missing drive/provider) to the coverage report.
function Get-RegistryKeySafe {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        return Get-Item -LiteralPath $Path -ErrorAction Stop
    } catch {
        if ($_.CategoryInfo.Category -ne 'ObjectNotFound') {
            $script:UnreadableTargets.Add(@{ Target = $Path; Reason = $_.Exception.Message })
        }
        return $null
    }
}

# Builds the common Evidence tag set (PATH-*/SIG-*/LOLBIN-*/RECENCY) from
# already-computed PathTrust/SignatureStatus/command-line-evidence/last-write
# inputs. Only emits tags that exist in $script:EvidenceWeights (Pass A) --
# statuses with no defined tag (NotTrusted/UnknownError/FileNotFound/Error)
# are recorded on the finding's own SignatureStatus field but do not score.
function Get-StandardEvidenceTags {
    param(
        [AllowNull()][string]$PathTrust,
        [AllowNull()][string]$SignatureStatus,
        [string[]]$CommandLineTags,
        [AllowNull()]$LastWriteUtc
    )

    $tags = New-Object System.Collections.Generic.List[string]

    if ($PathTrust -eq 'Untrusted') {
        $tags.Add('PATH-UNTRUSTED')
    } elseif ($PathTrust -eq 'DoesNotExist') {
        $tags.Add('PATH-DANGLING')
    }

    switch ($SignatureStatus) {
        'HashMismatch' { $tags.Add('SIG-TAMPERED') }
        'NotSigned' {
            if ($PathTrust -eq 'Trusted') {
                $tags.Add('SIG-UNSIGNED-TRUSTED-LOCATION')
            } else {
                $tags.Add('SIG-UNSIGNED-OTHER')
            }
        }
        default { }
    }

    if ($CommandLineTags) {
        foreach ($t in $CommandLineTags) {
            if (-not $tags.Contains($t)) { $tags.Add($t) }
        }
    }

    if (Test-InWindow -TimeUtc $LastWriteUtc) { $tags.Add('RECENCY') }

    return $tags.ToArray()
}

# Full pipeline for a raw command-line-shaped value (Run key value, ImagePath,
# scheduled-task action, StubPath, Debugger, ...): resolve the executable
# target, expand any %ENVVAR% references Resolve-CommandLineTarget itself
# deliberately leaves unexpanded (see that function's own docstring), then
# run Test-PathTrust/Get-AuthenticodeVerdict/Get-CommandLineEvidence and call
# Add-Finding. -Absolute/-ExtraEvidence are optional pass-throughs for the
# handful of hard-absolute callers.
function Add-CommandLineFinding {
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Token,
        [string]$Technique = 'Unmapped',
        [string]$Location,
        [string]$ValueName,
        [string]$RawValue,
        [AllowNull()]$LastWriteUtc,
        [ValidateSet('HIGH', 'NOTABLE')][string]$Absolute,
        [string[]]$ExtraEvidence
    )

    $resolvedTarget = $null
    if ($RawValue) {
        $resolvedTarget = Resolve-CommandLineTarget -CommandLine $RawValue
        if ($resolvedTarget) {
            $resolvedTarget = [System.Environment]::ExpandEnvironmentVariables($resolvedTarget)
        }
    }

    $pathTrust = $null
    $sigStatus = $null
    $sigPublisher = $null
    if ($resolvedTarget) {
        $pathTrust = Test-PathTrust -Path $resolvedTarget
        $verdict = Get-AuthenticodeVerdict -Path $resolvedTarget
        $sigStatus = $verdict.Status
        $sigPublisher = $verdict.Publisher
    }

    $cleTags = Get-CommandLineEvidence -CommandLine $RawValue
    $evidence = Get-StandardEvidenceTags -PathTrust $pathTrust -SignatureStatus $sigStatus -CommandLineTags $cleTags -LastWriteUtc $LastWriteUtc
    if ($ExtraEvidence) {
        foreach ($e in $ExtraEvidence) {
            if ($evidence -notcontains $e) { $evidence += $e }
        }
    }

    $params = @{
        Module             = $Module
        Token              = $Token
        Technique          = $Technique
        Location           = $Location
        ValueName          = $ValueName
        RawValue           = $RawValue
        ResolvedTarget     = $resolvedTarget
        PathTrust          = $pathTrust
        SignatureStatus    = $sigStatus
        SignaturePublisher = $sigPublisher
        LastWriteUtc       = $LastWriteUtc
        Evidence           = $evidence
    }
    if ($Absolute) { $params['Absolute'] = $Absolute }

    return Add-Finding @params
}

# Same pipeline as Add-CommandLineFinding, but for callers that already know
# the exact target file (a Startup-folder item enumerated via Get-ChildItem,
# a ServiceDll/LSA-package/AppCertDLLs path) rather than a command line that
# needs parsing. No Get-CommandLineEvidence pass unless -ExtraCommandLineTags
# is supplied (there is no "command line" to scan for most of these).
function Add-FileTargetFinding {
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Token,
        [string]$Technique = 'Unmapped',
        [string]$Location,
        [string]$ValueName,
        [string]$RawValue,
        [string]$TargetPath,
        [AllowNull()]$LastWriteUtc,
        [ValidateSet('HIGH', 'NOTABLE')][string]$Absolute,
        [string[]]$ExtraEvidence,
        [string[]]$ExtraCommandLineTags
    )

    if ($TargetPath) {
        $TargetPath = [System.Environment]::ExpandEnvironmentVariables($TargetPath)
    }

    $pathTrust = $null
    $sigStatus = $null
    $sigPublisher = $null
    if ($TargetPath) {
        $pathTrust = Test-PathTrust -Path $TargetPath
        $verdict = Get-AuthenticodeVerdict -Path $TargetPath
        $sigStatus = $verdict.Status
        $sigPublisher = $verdict.Publisher
    }

    $cleTags = @()
    if ($ExtraCommandLineTags) { $cleTags = $ExtraCommandLineTags }
    $evidence = Get-StandardEvidenceTags -PathTrust $pathTrust -SignatureStatus $sigStatus -CommandLineTags $cleTags -LastWriteUtc $LastWriteUtc
    if ($ExtraEvidence) {
        foreach ($e in $ExtraEvidence) {
            if ($evidence -notcontains $e) { $evidence += $e }
        }
    }

    $params = @{
        Module             = $Module
        Token              = $Token
        Technique          = $Technique
        Location           = $Location
        ValueName          = $ValueName
        RawValue           = $RawValue
        ResolvedTarget     = $TargetPath
        PathTrust          = $pathTrust
        SignatureStatus    = $sigStatus
        SignaturePublisher = $sigPublisher
        LastWriteUtc       = $LastWriteUtc
        Evidence           = $evidence
    }
    if ($Absolute) { $params['Absolute'] = $Absolute }

    return Add-Finding @params
}

# Current-session HKCU plus every loaded hive from Get-LoadedUserHives, as a
# flat list of registry roots -- the "current hive AND every loaded hive"
# iteration pattern several modules below need (RunKeys, Winlogon, ActiveSetup).
function Get-HiveRootsForPerUserCheck {
    $roots = New-Object System.Collections.Generic.List[object]
    $roots.Add([PSCustomObject]@{ Root = 'HKCU:'; Label = 'HKCU (current session)' })
    foreach ($hive in (Get-LoadedUserHives)) {
        $roots.Add([PSCustomObject]@{ Root = $hive.HivePath; Label = $hive.AccountName })
    }
    return $roots
}

# ---------------------------------------------------------------------------
# 1. Registry Run / RunOnce Keys -- T1547.001
# ---------------------------------------------------------------------------

function Read-RunKeyPath {
    param([string]$Path)

    $key = Get-RegistryKeySafe -Path $Path
    if (-not $key) { return }

    $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $key
    foreach ($valueName in $key.GetValueNames()) {
        $raw = $null
        try { $raw = $key.GetValue($valueName) } catch { $raw = $null }
        if (-not $raw) { continue }

        Add-CommandLineFinding -Module 'Registry Run / RunOnce Keys' -Token 'RunKeys' -Technique 'T1547.001' `
            -Location $Path -ValueName $valueName -RawValue ([string]$raw) -LastWriteUtc $lastWrite
    }
}

function Get-RunKeyPersistence {
    $machineKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    foreach ($path in $machineKeys) { Read-RunKeyPath -Path $path }

    # Per-user: current HKCU session plus every loaded hive (HKU\<SID>).
    foreach ($h in (Get-HiveRootsForPerUserCheck)) {
        Read-RunKeyPath -Path "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Run"
        Read-RunKeyPath -Path "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        # Per-user GPO-pushed Run key -- the HKCU analog of the machine-wide
        # Policies\Explorer\Run key already checked above; a real, distinct
        # autostart surface (e.g. Autoruns' "Explorer" tab), not a duplicate.
        Read-RunKeyPath -Path "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"

        # Legacy NT\CurrentVersion\Windows Load/Run values -- rarely populated on
        # modern Windows, but a real (if low-confidence) Windows-NT-era autostart
        # mechanism; still worth a single, cheap per-hive check. Report if present.
        $legacyPath = "$($h.Root)\Software\Microsoft\Windows NT\CurrentVersion\Windows"
        $legacyKey = Get-RegistryKeySafe -Path $legacyPath
        if ($legacyKey) {
            $legacyLastWrite = Get-RegKeyLastWriteTimeUtc -Key $legacyKey
            foreach ($valueName in @('Load', 'Run')) {
                $raw = $null
                try { $raw = $legacyKey.GetValue($valueName) } catch { $raw = $null }
                if ($raw) {
                    Add-CommandLineFinding -Module 'Registry Run / RunOnce Keys' -Token 'RunKeys' -Technique 'T1547.001' `
                        -Location $legacyPath -ValueName $valueName -RawValue ([string]$raw) -LastWriteUtc $legacyLastWrite
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 2. Startup Folder Items (user & common) -- T1547.001
# ---------------------------------------------------------------------------

function Get-StartupFolderPersistence {
    $folders = New-Object System.Collections.Generic.List[object]

    if ($env:ProgramData) {
        $allUsersPath = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
        $folders.Add([PSCustomObject]@{ Path = $allUsersPath; Scope = 'All Users' })
    }

    # Filesystem-based per-user surfaces are swept regardless of hive-load state --
    # this is the whole point of using Get-OnDiskProfiles here instead of
    # Get-LoadedUserHives: a Startup folder is readable even for a profile with no
    # loaded registry hive.
    foreach ($profile in (Get-OnDiskProfiles)) {
        if (-not $profile.ProfilePath) { continue }
        $userPath = Join-Path $profile.ProfilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        $folders.Add([PSCustomObject]@{ Path = $userPath; Scope = $profile.SID })
    }

    foreach ($f in $folders) {
        $items = $null
        try {
            $items = Get-ChildItem -LiteralPath $f.Path -File -ErrorAction Stop
        } catch {
            if ($_.CategoryInfo.Category -ne 'ObjectNotFound') {
                $script:UnreadableTargets.Add(@{ Target = $f.Path; Reason = $_.Exception.Message })
            }
            continue
        }

        foreach ($item in $items) {
            # .lnk: full shortcut-target parsing (working directory, embedded args,
            # resolved target path) is out of scope here -- that's this repo's
            # hunt_lnk.ps1's job. Report the shortcut file's own path/name/write-time.
            #
            # Non-.lnk (.exe/.bat/.cmd/.ps1/.vbs/etc.) dropped straight in a Startup
            # folder: no command line to extract LOLBin evidence from without
            # reading file content, which is out of scope/too slow for RTR -- score
            # on path-trust/signature/recency only. A script sitting directly in an
            # all-users/per-user Startup folder has an inherently thin legitimate
            # baseline regardless of file type.
            Add-FileTargetFinding -Module 'Startup Folder Items (user & common)' -Token 'StartupFolders' -Technique 'T1547.001' `
                -Location $f.Path -ValueName $item.Name -RawValue $item.FullName -TargetPath $item.FullName `
                -LastWriteUtc $item.LastWriteTimeUtc
        }
    }
}

# ---------------------------------------------------------------------------
# 3. Windows Services + Service DLL Hijack (svchost-hosted) -- T1543.003
# ---------------------------------------------------------------------------

function Get-ServicePersistence {
    $servicesKey = Get-RegistryKeySafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services'
    if (-not $servicesKey) { return }

    foreach ($childName in $servicesKey.GetSubKeyNames()) {
        $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$childName"
        $svcKey = Get-RegistryKeySafe -Path $svcPath
        if (-not $svcKey) { continue }

        $imagePath = $svcKey.GetValue('ImagePath')
        if (-not $imagePath) { continue }   # driver/library-only keys with no ImagePath are not an executable-launch surface

        $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $svcKey

        # Start: 0=Boot 1=System 2=Auto are the live persistence candidates;
        # 3=Demand/4=Disabled are still reported (inventory-level, naturally lower
        # score baseline since scoring is evidence-driven, not Start-driven).
        Add-CommandLineFinding -Module 'Windows Services' -Token 'Services' -Technique 'T1543.003' `
            -Location $svcPath -ValueName 'ImagePath' -RawValue ([string]$imagePath) -LastWriteUtc $lastWrite
    }
}

function Get-ServiceDllPersistence {
    $servicesKey = Get-RegistryKeySafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services'
    if (-not $servicesKey) { return }

    foreach ($childName in $servicesKey.GetSubKeyNames()) {
        $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$childName"
        $svcKey = Get-RegistryKeySafe -Path $svcPath
        if (-not $svcKey) { continue }

        $imagePath = $svcKey.GetValue('ImagePath')
        if (-not $imagePath) { continue }
        if (([string]$imagePath) -notmatch 'svchost\.exe.*-k\s+\S+') { continue }

        $paramsPath = "$svcPath\Parameters"
        $paramsKey = Get-RegistryKeySafe -Path $paramsPath
        if (-not $paramsKey) { continue }   # svchost-hosted service with no Parameters subkey -- nothing to evaluate

        $serviceDll = $paramsKey.GetValue('ServiceDll')
        if (-not $serviceDll) { continue }

        # The real abuse surface: evaluate the DLL actually loaded into svchost.exe,
        # not svchost.exe itself, which is always a legitimate, trusted-location
        # binary and would tell an analyst nothing.
        $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $svcKey
        Add-FileTargetFinding -Module 'Service DLL Hijack (svchost-hosted services)' -Token 'ServiceDll' -Technique 'T1543.003' `
            -Location $paramsPath -ValueName 'ServiceDll' -RawValue ([string]$serviceDll) -TargetPath ([string]$serviceDll) -LastWriteUtc $lastWrite
    }
}

# ---------------------------------------------------------------------------
# 4. Scheduled Tasks -- T1053.005
# ---------------------------------------------------------------------------

function Get-ScheduledTaskPersistence {
    $tasks = $null
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
    } catch {
        # Task Scheduler service unavailable/locked down -- degrade to "module
        # unavailable" rather than crash the run.
        $script:UnreadableTargets.Add(@{ Target = 'Get-ScheduledTask (Task Scheduler service)'; Reason = $_.Exception.Message })
        return
    }

    $tasksRoot = Join-Path $env:SystemRoot 'System32\Tasks'
    $liveTaskPaths = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)

    foreach ($task in $tasks) {
        $taskFullPath = $task.TaskPath.TrimEnd('\') + '\' + $task.TaskName
        if (-not $taskFullPath.StartsWith('\')) { $taskFullPath = "\$taskFullPath" }
        [void]$liveTaskPaths.Add($taskFullPath)

        $execParts = New-Object System.Collections.Generic.List[string]
        foreach ($action in $task.Actions) {
            if ($action.Execute) {
                $line = $action.Execute
                if ($action.Arguments) { $line = "$line $($action.Arguments)" }
                $execParts.Add($line)
            }
        }
        $commandLine = ($execParts -join ' ; ')

        $lastWrite = $null
        try {
            $xmlPath = Join-Path $tasksRoot $taskFullPath.TrimStart('\')
            if (Test-Path -LiteralPath $xmlPath -PathType Leaf -ErrorAction Stop) {
                $lastWrite = (Get-Item -LiteralPath $xmlPath -ErrorAction Stop).LastWriteTimeUtc
            }
        } catch {
            # On-disk XML unreadable -- recency simply unavailable for this task, not fatal.
        }

        $runAs = $task.Principal.UserId
        $runLevel = $task.Principal.RunLevel
        $rawValue = $commandLine
        if ($runAs -or $runLevel) { $rawValue = "$commandLine  [RunAs=$runAs RunLevel=$runLevel]" }

        Add-CommandLineFinding -Module 'Scheduled Tasks' -Token 'ScheduledTasks' -Technique 'T1053.005' `
            -Location $taskFullPath -ValueName $task.TaskName -RawValue $rawValue -LastWriteUtc $lastWrite
    }

    # TASKCACHE-ORPHAN cross-reference: a TaskCache\Tasks GUID entry with no live
    # Get-ScheduledTask result and no on-disk XML (or vice versa: on-disk XML with
    # neither a TaskCache entry nor a live result) is a hard absolute per the
    # design -- a fully-consistent task leaves all three artifacts in sync.
    $taskCachePaths = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    $taskCacheKey = Get-RegistryKeySafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks'
    if ($taskCacheKey) {
        foreach ($guid in $taskCacheKey.GetSubKeyNames()) {
            $entryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$guid"
            $entryKey = Get-RegistryKeySafe -Path $entryPath
            if (-not $entryKey) { continue }

            $taskPathValue = $entryKey.GetValue('Path')
            if (-not $taskPathValue) { continue }
            [void]$taskCachePaths.Add($taskPathValue)

            $inLive = $liveTaskPaths.Contains($taskPathValue)
            $xmlOnDisk = $false
            try {
                $candidateXml = Join-Path $tasksRoot $taskPathValue.TrimStart('\')
                $xmlOnDisk = Test-Path -LiteralPath $candidateXml -PathType Leaf -ErrorAction Stop
            } catch {
                $xmlOnDisk = $false
            }

            if (-not $inLive -and -not $xmlOnDisk) {
                Add-Finding -Module 'Scheduled Tasks' -Token 'ScheduledTasks' -Technique 'T1053.005' `
                    -Location $entryPath -ValueName 'Path' -RawValue $taskPathValue `
                    -Absolute 'NOTABLE' -Evidence @('TASKCACHE-ORPHAN')
            }
        }
    }

    # Reverse direction: on-disk task XML with neither a TaskCache entry nor a live result.
    try {
        $xmlFiles = Get-ChildItem -LiteralPath $tasksRoot -File -Recurse -ErrorAction Stop
        foreach ($xf in $xmlFiles) {
            $relative = $xf.FullName.Substring($tasksRoot.Length)
            if (-not $relative.StartsWith('\')) { $relative = "\$relative" }
            if (-not $taskCachePaths.Contains($relative) -and -not $liveTaskPaths.Contains($relative)) {
                Add-Finding -Module 'Scheduled Tasks' -Token 'ScheduledTasks' -Technique 'T1053.005' `
                    -Location $xf.FullName -ValueName $xf.Name -RawValue $relative `
                    -Absolute 'NOTABLE' -Evidence @('TASKCACHE-ORPHAN')
            }
        }
    } catch {
        if ($_.CategoryInfo.Category -ne 'ObjectNotFound') {
            $script:UnreadableTargets.Add(@{ Target = $tasksRoot; Reason = $_.Exception.Message })
        }
    }
}

# ---------------------------------------------------------------------------
# 5. WMI Event Subscriptions -- T1546.003
# ---------------------------------------------------------------------------

function Get-WmiEventSubscriptionPersistence {
    $filters = $null
    try {
        $filters = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction Stop
    } catch {
        $script:UnreadableTargets.Add(@{ Target = 'root\subscription:__EventFilter'; Reason = $_.Exception.Message })
        return
    }
    if (-not $filters) { $filters = @() }

    $consumers = New-Object System.Collections.Generic.List[object]
    try {
        $base = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop
        if ($base) { $consumers.AddRange(@($base)) }
    } catch {
        # Base class query can fail even when concrete subclasses are queryable --
        # fall back to unioning the four standard concrete consumer classes.
        foreach ($className in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer', 'SMTPEventConsumer', 'LogFileEventConsumer')) {
            try {
                $c = Get-CimInstance -Namespace 'root\subscription' -ClassName $className -ErrorAction Stop
                if ($c) { $consumers.AddRange(@($c)) }
            } catch {
                $script:UnreadableTargets.Add(@{ Target = "root\subscription:$className"; Reason = $_.Exception.Message })
            }
        }
    }

    $bindings = @()
    try {
        $bindingResult = Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop
        if ($bindingResult) { $bindings = @($bindingResult) }
    } catch {
        $script:UnreadableTargets.Add(@{ Target = 'root\subscription:__FilterToConsumerBinding'; Reason = $_.Exception.Message })
    }

    $boundFilterNames = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    $boundConsumerNames = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)

    # Only a resolved, BOUND triad (filter+consumer+binding all present and
    # linked) is a queueable finding, per this repo's own WMI-note doctrine --
    # an orphaned filter or consumer alone is context, not evidence of activity.
    foreach ($binding in $bindings) {
        $filterName = ($binding.Filter -replace '.*Name="([^"]*)".*', '$1')
        $consumerName = ($binding.Consumer -replace '.*Name="([^"]*)".*', '$1')

        $filter = $filters | Where-Object { $_.Name -eq $filterName } | Select-Object -First 1
        $consumer = $consumers | Where-Object { $_.Name -eq $consumerName } | Select-Object -First 1

        if ($filter -and $consumer) {
            [void]$boundFilterNames.Add($filterName)
            [void]$boundConsumerNames.Add($consumerName)

            $actionText = $null
            if ($consumer.CommandLineTemplate) { $actionText = $consumer.CommandLineTemplate }
            elseif ($consumer.ScriptText) { $actionText = $consumer.ScriptText }

            $cleTags = @()
            if ($actionText) { $cleTags = Get-CommandLineEvidence -CommandLine $actionText }
            $evidence = Get-StandardEvidenceTags -PathTrust $null -SignatureStatus $null -CommandLineTags $cleTags -LastWriteUtc $null

            $rawValue = "Filter='$filterName' Query=[$($filter.Query)] | Consumer='$consumerName' ($($consumer.CimClass.CimClassName)) Action=[$actionText]"

            Add-Finding -Module 'WMI Event Subscriptions' -Token 'WMI' -Technique 'T1546.003' `
                -Location 'root\subscription' -ValueName $consumerName -RawValue $rawValue -Evidence $evidence
        }
    }

    # Orphaned halves -- inert per the doctrine above; still reported for
    # completeness/context, but inventory-only (Evidence = @()).
    foreach ($filter in $filters) {
        if (-not $boundFilterNames.Contains($filter.Name)) {
            Add-Finding -Module 'WMI Event Subscriptions' -Token 'WMI' -Technique 'T1546.003' `
                -Location 'root\subscription' -ValueName $filter.Name -RawValue $filter.Query -Evidence @()
        }
    }
    foreach ($consumer in $consumers) {
        if (-not $boundConsumerNames.Contains($consumer.Name)) {
            $orphanAction = $null
            if ($consumer.CommandLineTemplate) { $orphanAction = $consumer.CommandLineTemplate }
            elseif ($consumer.ScriptText) { $orphanAction = $consumer.ScriptText }
            Add-Finding -Module 'WMI Event Subscriptions' -Token 'WMI' -Technique 'T1546.003' `
                -Location 'root\subscription' -ValueName $consumer.Name -RawValue $orphanAction -Evidence @()
        }
    }
}

# ---------------------------------------------------------------------------
# 6. Winlogon Helper DLL / Shell / Userinit -- T1547.004
# ---------------------------------------------------------------------------

function Get-WinlogonHelperPersistence {
    $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $winlogonKey = Get-RegistryKeySafe -Path $winlogonPath
    if ($winlogonKey) {
        $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $winlogonKey

        $shell = $winlogonKey.GetValue('Shell')
        if ($shell) {
            # Stock value is exactly "explorer.exe", no path prefix -- a hard
            # absolute per the design if it's anything else.
            if (([string]$shell).Trim() -ine 'explorer.exe') {
                $shellTarget = Resolve-CommandLineTarget -CommandLine $shell
                if ($shellTarget) { $shellTarget = [System.Environment]::ExpandEnvironmentVariables($shellTarget) }
                Add-Finding -Module 'Winlogon Helper DLL / Shell / Userinit' -Token 'Winlogon' -Technique 'T1547.004' `
                    -Location $winlogonPath -ValueName 'Shell' -RawValue ([string]$shell) -ResolvedTarget $shellTarget `
                    -LastWriteUtc $lastWrite -Absolute 'HIGH' -Evidence @('WINLOGON-SHELL-TAMPER')
            } else {
                Add-Finding -Module 'Winlogon Helper DLL / Shell / Userinit' -Token 'Winlogon' -Technique 'T1547.004' `
                    -Location $winlogonPath -ValueName 'Shell' -RawValue ([string]$shell) -LastWriteUtc $lastWrite -Evidence @()
            }
        }

        $userinit = $winlogonKey.GetValue('Userinit')
        if ($userinit) {
            # Stock value is "%SystemRoot%\system32\userinit.exe," (trailing comma) --
            # compare on the expanded form, case-insensitive, so a literal or
            # %SystemRoot%-prefixed stock value both read as normal.
            $userinitExpanded = [System.Environment]::ExpandEnvironmentVariables([string]$userinit).TrimEnd()
            $stockValue = (Join-Path $env:SystemRoot 'system32\userinit.exe,').TrimEnd()
            if ($userinitExpanded -ine $stockValue) {
                Add-Finding -Module 'Winlogon Helper DLL / Shell / Userinit' -Token 'Winlogon' -Technique 'T1547.004' `
                    -Location $winlogonPath -ValueName 'Userinit' -RawValue ([string]$userinit) `
                    -LastWriteUtc $lastWrite -Absolute 'HIGH' -Evidence @('WINLOGON-USERINIT-CHAIN')
            } else {
                Add-Finding -Module 'Winlogon Helper DLL / Shell / Userinit' -Token 'Winlogon' -Technique 'T1547.004' `
                    -Location $winlogonPath -ValueName 'Userinit' -RawValue ([string]$userinit) -LastWriteUtc $lastWrite -Evidence @()
            }
        }

        foreach ($v in @('Taskman', 'VmApplet')) {
            $val = $winlogonKey.GetValue($v)
            if ($val) {
                Add-CommandLineFinding -Module 'Winlogon Helper DLL / Shell / Userinit' -Token 'Winlogon' -Technique 'T1547.004' `
                    -Location $winlogonPath -ValueName $v -RawValue ([string]$val) -LastWriteUtc $lastWrite
            }
        }
    }

    # Legacy notification-package DLLs.
    $notifyPath = "$winlogonPath\Notify"
    $notifyKey = Get-RegistryKeySafe -Path $notifyPath
    if ($notifyKey) {
        foreach ($subName in $notifyKey.GetSubKeyNames()) {
            $subPath = "$notifyPath\$subName"
            $subKey = Get-RegistryKeySafe -Path $subPath
            if (-not $subKey) { continue }
            $dll = $subKey.GetValue('DllName')
            if (-not $dll) { continue }
            $subLastWrite = Get-RegKeyLastWriteTimeUtc -Key $subKey
            Add-FileTargetFinding -Module 'Winlogon Helper DLL / Shell / Userinit' -Token 'Winlogon' -Technique 'T1547.004' `
                -Location $subPath -ValueName 'DllName' -RawValue ([string]$dll) -TargetPath ([string]$dll) -LastWriteUtc $subLastWrite
        }
    }

    # Per-user Shell override -- current HKCU session plus every loaded hive.
    # Absence is the normal case for most profiles; a populated value is the anomaly.
    foreach ($h in (Get-HiveRootsForPerUserCheck)) {
        $userWinlogonPath = "$($h.Root)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $userKey = Get-RegistryKeySafe -Path $userWinlogonPath
        if (-not $userKey) { continue }

        $userShell = $userKey.GetValue('Shell')
        if ($userShell) {
            $userLastWrite = Get-RegKeyLastWriteTimeUtc -Key $userKey
            $userShellTarget = Resolve-CommandLineTarget -CommandLine $userShell
            if ($userShellTarget) { $userShellTarget = [System.Environment]::ExpandEnvironmentVariables($userShellTarget) }
            Add-Finding -Module 'Winlogon Helper DLL / Shell / Userinit' -Token 'Winlogon' -Technique 'T1547.004' `
                -Location $userWinlogonPath -ValueName 'Shell' -RawValue ([string]$userShell) -ResolvedTarget $userShellTarget `
                -LastWriteUtc $userLastWrite -Absolute 'HIGH' -Evidence @('WINLOGON-SHELL-TAMPER')
        }
    }
}

# ---------------------------------------------------------------------------
# 7. LSA Authentication/Notification/Security Packages -- T1547.005
# ---------------------------------------------------------------------------

function Test-LsaPackageEntry {
    param(
        [string]$EntryName,
        [string]$ValueName,
        [string]$Location,
        [string[]]$Defaults,
        [AllowNull()]$LastWriteUtc
    )

    if (-not $EntryName) { return }

    $isDefault = $false
    foreach ($d in $Defaults) {
        if ($EntryName -ieq $d) { $isDefault = $true; break }
    }
    if ($isDefault) {
        # Named built-in package, not a file-path value -- no path-trust check needed.
        Add-Finding -Module 'LSA Authentication/Notification/Security Packages' -Token 'LSAPackages' -Technique 'T1547.005' `
            -Location $Location -ValueName $ValueName -RawValue $EntryName -LastWriteUtc $LastWriteUtc -Evidence @()
        return
    }

    # Non-default entry: LSA packages are named without full paths by convention --
    # resolve under System32. A non-default Notification Packages entry is also
    # where password-filter DLLs register (T1556.002, credential theft) -- flagged
    # here for analyst context only; T1556 scoring itself is out of scope.
    $dllName = $EntryName
    if ($dllName -notmatch '\.dll$') { $dllName = "$dllName.dll" }
    $resolvedPath = $null
    if ($env:SystemRoot) { $resolvedPath = Join-Path (Join-Path $env:SystemRoot 'System32') $dllName }

    $pathTrust = $null
    $verdict = [PSCustomObject]@{ Status = $null; Publisher = $null }
    if ($resolvedPath) {
        $pathTrust = Test-PathTrust -Path $resolvedPath
        $verdict = Get-AuthenticodeVerdict -Path $resolvedPath
    }

    $evidence = Get-StandardEvidenceTags -PathTrust $pathTrust -SignatureStatus $verdict.Status -CommandLineTags @() -LastWriteUtc $LastWriteUtc

    $failsTrust = ($pathTrust -eq 'Untrusted' -or $pathTrust -eq 'DoesNotExist' -or
                   $verdict.Status -eq 'NotSigned' -or $verdict.Status -eq 'HashMismatch' -or $verdict.Status -eq 'NotTrusted')

    $params = @{
        Module             = 'LSA Authentication/Notification/Security Packages'
        Token              = 'LSAPackages'
        Technique          = 'T1547.005'
        Location           = $Location
        ValueName          = $ValueName
        RawValue           = $EntryName
        ResolvedTarget     = $resolvedPath
        PathTrust          = $pathTrust
        SignatureStatus    = $verdict.Status
        SignaturePublisher = $verdict.Publisher
        LastWriteUtc       = $LastWriteUtc
        Evidence           = $evidence
    }
    if ($failsTrust) {
        if ($evidence -notcontains 'LSA-UNTRUSTED-PACKAGE') { $params['Evidence'] += 'LSA-UNTRUSTED-PACKAGE' }
        $params['Absolute'] = 'HIGH'
    }
    Add-Finding @params
}

function Get-LsaPackagePersistence {
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $lsaKey = Get-RegistryKeySafe -Path $lsaPath
    if (-not $lsaKey) { return }
    $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $lsaKey

    $authDefaults = @('msv1_0', 'kerberos', 'negotiate', 'schannel', 'wdigest', 'tspkg', 'pku2u')
    $authPackages = $lsaKey.GetValue('Authentication Packages')
    if ($authPackages) {
        foreach ($entry in $authPackages) {
            Test-LsaPackageEntry -EntryName $entry -ValueName 'Authentication Packages' -Location $lsaPath -Defaults $authDefaults -LastWriteUtc $lastWrite
        }
    }

    # Notification Packages and Security Packages have no single, universally-fixed
    # default set the way Authentication Packages does -- every entry here is
    # resolved and evaluated rather than assumed-safe against a skip-list; a
    # genuinely legitimate, signed, System32-resident package simply scores
    # LOW/zero through the normal path-trust/signature pipeline regardless.
    foreach ($valueName in @('Notification Packages', 'Security Packages')) {
        $entries = $lsaKey.GetValue($valueName)
        if (-not $entries) { continue }
        foreach ($entry in $entries) {
            Test-LsaPackageEntry -EntryName $entry -ValueName $valueName -Location $lsaPath -Defaults @() -LastWriteUtc $lastWrite
        }
    }

    # OSConfig\Security Packages -- the value actually consulted at boot on modern
    # Windows; the plain Lsa\Security Packages value above is legacy/back-compat.
    # Both are reported without asserting which one "wins" with false confidence.
    $osConfigPath = "$lsaPath\OSConfig"
    $osConfigKey = Get-RegistryKeySafe -Path $osConfigPath
    if ($osConfigKey) {
        $osLastWrite = Get-RegKeyLastWriteTimeUtc -Key $osConfigKey
        $osEntries = $osConfigKey.GetValue('Security Packages')
        if ($osEntries) {
            foreach ($entry in $osEntries) {
                Test-LsaPackageEntry -EntryName $entry -ValueName 'Security Packages' -Location $osConfigPath -Defaults @() -LastWriteUtc $osLastWrite
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 8. Image File Execution Options Debugger Hijack -- T1546.012 / T1546.008
# ---------------------------------------------------------------------------

function Get-IfeoPersistence {
    $accessibilityBinaries = @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe')

    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    )

    foreach ($root in $roots) {
        $rootKey = Get-RegistryKeySafe -Path $root
        if (-not $rootKey) { continue }

        foreach ($exeName in $rootKey.GetSubKeyNames()) {
            $subPath = "$root\$exeName"
            $subKey = Get-RegistryKeySafe -Path $subPath
            if (-not $subKey) { continue }
            $subLastWrite = Get-RegKeyLastWriteTimeUtc -Key $subKey

            $debugger = $subKey.GetValue('Debugger')
            if ($debugger) {
                $isAccessibilityTarget = $false
                foreach ($a in $accessibilityBinaries) {
                    if ($exeName -ieq $a) { $isAccessibilityTarget = $true; break }
                }

                if ($isAccessibilityTarget) {
                    $debuggerTarget = Resolve-CommandLineTarget -CommandLine $debugger
                    if ($debuggerTarget) { $debuggerTarget = [System.Environment]::ExpandEnvironmentVariables($debuggerTarget) }
                    Add-Finding -Module 'Image File Execution Options Debugger Hijack' -Token 'IFEO' -Technique 'T1546.008' `
                        -Location $subPath -ValueName 'Debugger' -RawValue ([string]$debugger) -ResolvedTarget $debuggerTarget `
                        -LastWriteUtc $subLastWrite -Absolute 'HIGH' -Evidence @('IFEO-ACCESSIBILITY-HIJACK')
                } else {
                    # Any other exe with a Debugger value: rare in legitimate use, so
                    # presence itself is worth at least inventory-level reporting even
                    # when the debugger target itself checks out clean.
                    Add-CommandLineFinding -Module 'Image File Execution Options Debugger Hijack' -Token 'IFEO' -Technique 'T1546.012' `
                        -Location $subPath -ValueName 'Debugger' -RawValue ([string]$debugger) -LastWriteUtc $subLastWrite
                }
            }

            # GlobalFlag 512 (0x200, FLG_MONITOR_SILENT_PROCESS_EXIT) paired with a
            # SilentProcessExit\<exeName> subkey's MonitorProcess -- report
            # MonitorProcess as the effective hijack target via the same pipeline.
            $globalFlag = $subKey.GetValue('GlobalFlag')
            if ($globalFlag -and (([int64]$globalFlag) -band 0x200)) {
                $silentPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$exeName"
                $silentKey = Get-RegistryKeySafe -Path $silentPath
                if ($silentKey) {
                    $monitorProcess = $silentKey.GetValue('MonitorProcess')
                    if ($monitorProcess) {
                        $silentLastWrite = Get-RegKeyLastWriteTimeUtc -Key $silentKey
                        Add-CommandLineFinding -Module 'Image File Execution Options Debugger Hijack' -Token 'IFEO' -Technique 'T1546.012' `
                            -Location $silentPath -ValueName 'MonitorProcess' -RawValue ([string]$monitorProcess) -LastWriteUtc $silentLastWrite
                    }
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 9. AppInit_DLLs & AppCertDLLs -- T1546.010 / T1546.009
# ---------------------------------------------------------------------------

function Get-AppInitCertsPersistence {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
    )

    foreach ($root in $roots) {
        $key = Get-RegistryKeySafe -Path $root
        if (-not $key) { continue }
        $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $key

        # RequireSignedAppInit_DLLs is read here for completeness (per the design
        # notes) but has no independent place in the fixed finding schema below --
        # it doesn't change AppInit_DLLs' own per-DLL Absolute-tier logic.
        $requireSigned = $key.GetValue('RequireSignedAppInit_DLLs')
        $null = $requireSigned

        $appInitDlls = $key.GetValue('AppInit_DLLs')
        $loadAppInit = $key.GetValue('LoadAppInit_DLLs')

        if ($appInitDlls -and ([string]$appInitDlls).Trim()) {
            $loadActive = ($loadAppInit -eq 1 -or $loadAppInit -eq '1')
            $dllList = ([string]$appInitDlls) -split '[\s,]+' | Where-Object { $_ }

            foreach ($dllPath in $dllList) {
                $expandedPath = [System.Environment]::ExpandEnvironmentVariables($dllPath)
                $pathTrust = Test-PathTrust -Path $expandedPath
                $verdict = Get-AuthenticodeVerdict -Path $expandedPath
                $evidence = Get-StandardEvidenceTags -PathTrust $pathTrust -SignatureStatus $verdict.Status -CommandLineTags @() -LastWriteUtc $lastWrite

                $untrusted = ($pathTrust -eq 'Untrusted' -or $pathTrust -eq 'DoesNotExist' -or
                              $verdict.Status -eq 'NotSigned' -or $verdict.Status -eq 'HashMismatch' -or $verdict.Status -eq 'NotTrusted')

                $params = @{
                    Module             = 'AppInit_DLLs & Trust Provider/Certificate Hijack'
                    Token              = 'AppInitCerts'
                    Technique          = 'T1546.010'
                    Location           = $root
                    ValueName          = 'AppInit_DLLs'
                    RawValue           = $dllPath
                    ResolvedTarget     = $expandedPath
                    PathTrust          = $pathTrust
                    SignatureStatus    = $verdict.Status
                    SignaturePublisher = $verdict.Publisher
                    LastWriteUtc       = $lastWrite
                    Evidence           = $evidence
                }

                if ($loadActive) {
                    # Hard absolute per the design: AppInit_DLLs populated AND
                    # LoadAppInit_DLLs=1 means it's actually active. NOTABLE baseline,
                    # escalated to HIGH if this specific DLL also fails path-trust/signature.
                    if ($evidence -notcontains 'APPINIT-ACTIVE') { $params['Evidence'] += 'APPINIT-ACTIVE' }
                    if ($untrusted) { $params['Absolute'] = 'HIGH' } else { $params['Absolute'] = 'NOTABLE' }
                } else {
                    # Populated but inactive (LoadAppInit_DLLs=0) -- not the hard
                    # absolute, since the DLL never actually loads; still scored normally.
                }

                Add-Finding @params
            }
        }
    }

    # AppCertDLLs -- not a hard absolute per the design's rubric, but presence is
    # inherently rare/interesting; same normal-scoring treatment as AppInit's
    # non-active path above.
    $appCertPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs'
    $appCertKey = Get-RegistryKeySafe -Path $appCertPath
    if ($appCertKey) {
        $acLastWrite = Get-RegKeyLastWriteTimeUtc -Key $appCertKey
        foreach ($valueName in $appCertKey.GetValueNames()) {
            $raw = $appCertKey.GetValue($valueName)
            if (-not $raw) { continue }
            Add-FileTargetFinding -Module 'AppInit_DLLs & Trust Provider/Certificate Hijack' -Token 'AppInitCerts' -Technique 'T1546.009' `
                -Location $appCertPath -ValueName $valueName -RawValue ([string]$raw) -TargetPath ([string]$raw) -LastWriteUtc $acLastWrite
        }
    }
}

# ---------------------------------------------------------------------------
# 10. Active Setup StubPath -- T1547.014
# ---------------------------------------------------------------------------

function Get-ActiveSetupPersistence {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components'
    )

    $hiveRoots = Get-HiveRootsForPerUserCheck

    foreach ($root in $roots) {
        $rootKey = Get-RegistryKeySafe -Path $root
        if (-not $rootKey) { continue }

        foreach ($guid in $rootKey.GetSubKeyNames()) {
            $compPath = "$root\$guid"
            $compKey = Get-RegistryKeySafe -Path $compPath
            if (-not $compKey) { continue }

            $stubPath = $compKey.GetValue('StubPath')
            if (-not $stubPath) { continue }

            $version = $compKey.GetValue('Version')
            $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $compKey

            # Cross-reference per-user status: if HKLM's Version is newer than a
            # given user's recorded version (or the user has no entry at all), that
            # StubPath WILL execute next logon for that user. ACTIVESETUP-PENDING-EXEC
            # is a descriptive, zero-weight tag purely for analyst context -- it has
            # no entry in $script:EvidenceWeights, so it never moves the score.
            $pending = $false
            foreach ($h in $hiveRoots) {
                $userCompPath = "$($h.Root)\Software\Microsoft\Active Setup\Installed Components\$guid"
                $userCompKey = Get-RegistryKeySafe -Path $userCompPath
                if (-not $userCompKey) {
                    $pending = $true
                    continue
                }
                $userVersion = $userCompKey.GetValue('Version')
                if ($version -and ($userVersion -ne $version)) { $pending = $true }
            }

            $extraEvidence = @()
            if ($pending) { $extraEvidence = @('ACTIVESETUP-PENDING-EXEC') }

            Add-CommandLineFinding -Module 'Active Setup StubPath' -Token 'ActiveSetup' -Technique 'T1547.014' `
                -Location $compPath -ValueName 'StubPath' -RawValue ([string]$stubPath) -LastWriteUtc $lastWrite -ExtraEvidence $extraEvidence
        }
    }
}

#endregion Core Persistence Modules (Pass B)

# ===========================================================================
#  Fast-Tier Modules (Pass C)
# ===========================================================================
#region Fast-Tier Modules (Pass C)
#
# Twenty-one module functions: the ~11 simplest single/few-value registry
# checks are driven off a shared table (Invoke-SimpleRegistryValueCheck +
# $script:SimpleValueChecks) to avoid writing ten nearly-identical 40-line
# functions; the remaining ~10 involve multiple locations, per-profile
# filesystem sweeps, or cross-referencing and are implemented directly.
# Same read-only contract as Pass B: only Get-Item/Get-ChildItem/
# Get-ItemProperty-style reads, every registry/filesystem call wrapped in
# try/catch, genuine access failures appended to $script:UnreadableTargets,
# and every module calls Add-Finding (via the shared Add-CommandLineFinding/
# Add-FileTargetFinding/Add-Finding pipeline) for everything it inspects.

# ---------------------------------------------------------------------------
# Private helpers local to this region.
# ---------------------------------------------------------------------------

# Test-PathTrust (Pass A) is deliberately file-only (Test-Path -PathType Leaf),
# since almost every other module resolves a single executable/DLL. A few
# Pass C modules (ShellFolderRedir, PSModulePath, OfficeTrustedLocations) need
# the same Trusted/Untrusted/Other/DoesNotExist verdict for a DIRECTORY
# instead -- this mirrors Test-PathTrust's own trusted/untrusted rules with
# -PathType Container rather than duplicating its logic ad hoc at each call
# site.
function Test-DirectoryPathTrust {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return 'Other' }

    $exists = $false
    try {
        $exists = Test-Path -LiteralPath $Path -PathType Container -ErrorAction Stop
    } catch {
        $exists = $false
    }
    if (-not $exists) { return 'DoesNotExist' }

    $full = $Path
    try {
        $full = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    } catch {
        $full = $Path
    }
    $full = $full.TrimEnd('\')

    $systemRoot      = $env:SystemRoot
    $programFiles    = $env:ProgramFiles
    $programFilesX86 = ${env:ProgramFiles(x86)}
    $temp            = $env:TEMP
    $localTemp       = $null
    if ($env:LOCALAPPDATA) { $localTemp = (Join-Path $env:LOCALAPPDATA 'Temp').TrimEnd('\') }
    $programData     = $env:ProgramData

    if ($systemRoot -and ($full -like (Join-Path $systemRoot 'System32\*'))) { return 'Trusted' }
    if ($programFiles -and ($full -like "$programFiles\*")) { return 'Trusted' }
    if ($programFilesX86 -and ($full -like "$programFilesX86\*")) { return 'Trusted' }
    if ($full -match '\\WinSxS\\') { return 'Trusted' }

    if ($temp -and ($full -ieq $temp.TrimEnd('\') -or $full -like "$($temp.TrimEnd('\'))\*")) { return 'Untrusted' }
    if ($localTemp -and ($full -ieq $localTemp -or $full -like "$localTemp\*")) { return 'Untrusted' }
    if ($full -match '\\Downloads(\\|$)') { return 'Untrusted' }
    if ($programData -and ($full -ieq $programData.TrimEnd('\'))) { return 'Untrusted' }
    if ($full -match '^[A-Za-z]:$') { return 'Untrusted' }
    if ($full -match '^[A-Za-z]:\\Users\\[^\\]+$') { return 'Untrusted' }

    return 'Other'
}

# A handful of the simple-table checks below (port monitors, time providers,
# print processors, netsh helpers) store a bare DLL FILE NAME with no path --
# Windows loads these from System32 by convention. Anything that already
# looks like a path (contains a slash) is left untouched for the normal
# Resolve/expand pipeline downstream.
function Resolve-BareDllName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $Name }
    if ($Name -notmatch '[\\/]') {
        if ($env:SystemRoot) { return (Join-Path (Join-Path $env:SystemRoot 'System32') $Name) }
    }
    return $Name
}

# ---------------------------------------------------------------------------
# Table-driven generic runner for the ~11 simplest single/few-value registry
# checks. Each $script:SimpleValueChecks entry describes WHERE to look
# (Hive/KeyPath) and HOW to interpret what's found (Mode):
#   'SubkeyValue' -- enumerate immediate subkeys of KeyPath; read ValueName
#                    from each subkey and evaluate it as a file target
#                    (PortMonitors, PrintProcessors, TimeProviders).
#   'AllValues'   -- read every value directly under KeyPath (no subkeys) and
#                    evaluate each as a file target (NetshHelpers).
#   'Custom'      -- hand the opened key straight to a Handler scriptblock
#                    (the "AbsoluteRule" hook) for entries whose logic is
#                    more than a single value read (hard-absolute rules,
#                    multi-value comparisons, cross-references). The
#                    scriptblock receives ($Key, $FullKeyPath, $LastWriteUtc,
#                    $HiveRootInfo) and is responsible for calling
#                    Add-Finding/Add-CommandLineFinding/Add-FileTargetFinding
#                    itself.
# Hive is 'HKLM' (fixed root), 'HKCU' (current session only), or
# 'PerUserHive' (current session + every loaded hive, via
# Get-HiveRootsForPerUserCheck).
function Invoke-SimpleRegistryValueCheck {
    param([Parameter(Mandatory = $true)][string]$Token)

    $entries = $script:SimpleValueChecks | Where-Object { $_.Token -eq $Token }

    foreach ($entry in $entries) {
        $roots = $null
        switch ($entry.Hive) {
            'HKLM'        { $roots = @([PSCustomObject]@{ Root = 'HKLM:'; Label = 'HKLM' }) }
            'HKCU'        { $roots = @([PSCustomObject]@{ Root = 'HKCU:'; Label = 'HKCU (current session)' }) }
            'PerUserHive' { $roots = Get-HiveRootsForPerUserCheck }
            default       { $roots = @([PSCustomObject]@{ Root = 'HKLM:'; Label = 'HKLM' }) }
        }

        foreach ($h in $roots) {
            $fullKeyPath = "$($h.Root)\$($entry.KeyPath)"
            $key = Get-RegistryKeySafe -Path $fullKeyPath
            if (-not $key) { continue }
            $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $key

            switch ($entry.Mode) {
                'SubkeyValue' {
                    foreach ($sub in $key.GetSubKeyNames()) {
                        $subPath = "$fullKeyPath\$sub"
                        $subKey = Get-RegistryKeySafe -Path $subPath
                        if (-not $subKey) { continue }
                        $val = $subKey.GetValue($entry.ValueName)
                        if (-not $val) { continue }
                        $subLastWrite = Get-RegKeyLastWriteTimeUtc -Key $subKey
                        $target = Resolve-BareDllName -Name ([string]$val)
                        Add-FileTargetFinding -Module $entry.Module -Token $entry.Token -Technique $entry.Attack `
                            -Location $subPath -ValueName $entry.ValueName -RawValue ([string]$val) -TargetPath $target -LastWriteUtc $subLastWrite
                    }
                }
                'AllValues' {
                    foreach ($valueName in $key.GetValueNames()) {
                        $val = $key.GetValue($valueName)
                        if (-not $val) { continue }
                        $target = Resolve-BareDllName -Name ([string]$val)
                        Add-FileTargetFinding -Module $entry.Module -Token $entry.Token -Technique $entry.Attack `
                            -Location $fullKeyPath -ValueName $valueName -RawValue ([string]$val) -TargetPath $target -LastWriteUtc $lastWrite
                    }
                }
                'Custom' {
                    & $entry.Handler $key $fullKeyPath $lastWrite $h
                }
            }
        }
    }
}

# ---- Custom-mode handlers (referenced by $script:SimpleValueChecks below) ----

# CommandProcessorAutoRun -- unmapped (T1059.003-adjacent). HARD ABSOLUTE per
# design: any non-empty AutoRun value is inherently notable, escalated to
# HIGH if it also trips any LOLBIN-* command-line pattern.
$script:Handler_CommandProcessorAutoRun = {
    param($Key, $KeyPath, $LastWrite, $HiveInfo)

    $raw = $Key.GetValue('AutoRun')
    if (-not $raw -or -not ([string]$raw).Trim()) { return }
    $rawStr = [string]$raw

    $cleTags = Get-CommandLineEvidence -CommandLine $rawStr
    $isLolbin = $false
    foreach ($t in $cleTags) { if ($t -like 'LOLBIN-*') { $isLolbin = $true; break } }

    $absolute = 'NOTABLE'
    if ($isLolbin) { $absolute = 'HIGH' }

    Add-CommandLineFinding -Module 'cmd.exe AutoRun Registry Value' -Token 'CommandProcessorAutoRun' -Technique 'Unmapped' `
        -Location $KeyPath -ValueName 'AutoRun' -RawValue $rawStr -LastWriteUtc $LastWrite `
        -Absolute $absolute -ExtraEvidence @('AUTORUN-POPULATED')
}

# SafeBoot -- Minimal/Network subkey names are service/driver names that also
# load in Safe Mode; inventory only (cross-reference against Services token is
# left to the analyst). AlternateShell's stock default is exactly "cmd.exe".
$script:Handler_SafeBootServiceList = {
    param($Key, $KeyPath, $LastWrite, $HiveInfo)

    foreach ($sub in $Key.GetSubKeyNames()) {
        Add-Finding -Module 'SafeBoot Minimal/Network Service Enablement' -Token 'SafeBoot' -Technique 'Unmapped' `
            -Location $KeyPath -ValueName $null -RawValue $sub -LastWriteUtc $LastWrite -Evidence @()
    }
}
$script:Handler_SafeBootAlternateShell = {
    param($Key, $KeyPath, $LastWrite, $HiveInfo)

    $val = $Key.GetValue('AlternateShell')
    if (-not $val) { return }
    $valStr = [string]$val

    if ($valStr.Trim() -ieq 'cmd.exe') {
        Add-Finding -Module 'SafeBoot Minimal/Network Service Enablement' -Token 'SafeBoot' -Technique 'Unmapped' `
            -Location $KeyPath -ValueName 'AlternateShell' -RawValue $valStr -LastWriteUtc $LastWrite -Evidence @()
    } else {
        # Not the stock default -- scored via the normal command-line pipeline
        # (path-trust/signature on whatever AlternateShell now points at)
        # rather than a hard absolute, since this is a single string value,
        # not an enumerable list.
        Add-CommandLineFinding -Module 'SafeBoot Minimal/Network Service Enablement' -Token 'SafeBoot' -Technique 'Unmapped' `
            -Location $KeyPath -ValueName 'AlternateShell' -RawValue $valStr -LastWriteUtc $LastWrite `
            -ExtraEvidence @('SAFEBOOT-ALTERNATESHELL-NONDEFAULT')
    }
}

# TerminalServices -- unmapped. Hijack condition is InitialProgram populated
# AND fInheritInitialProgram=0 (the RDP session ignores the client-requested
# shell and always launches InitialProgram instead).
$script:Handler_TerminalServices = {
    param($Key, $KeyPath, $LastWrite, $HiveInfo)

    $initialProgram = $Key.GetValue('InitialProgram')
    $inherit = $Key.GetValue('fInheritInitialProgram')
    if (-not $initialProgram -or -not ([string]$initialProgram).Trim()) { return }

    $inheritOff = ($inherit -eq 0 -or $inherit -eq '0')
    if ($inheritOff) {
        Add-CommandLineFinding -Module 'Terminal Services InitialProgram/Shell Hijack' -Token 'TerminalServices' -Technique 'Unmapped' `
            -Location $KeyPath -ValueName 'InitialProgram' -RawValue ([string]$initialProgram) -LastWriteUtc $LastWrite `
            -ExtraEvidence @('TS-INITIALPROGRAM-HIJACK')
    } else {
        # Populated but the client's own shell is still honored -- lower
        # signal, still worth normal-pipeline reporting.
        Add-CommandLineFinding -Module 'Terminal Services InitialProgram/Shell Hijack' -Token 'TerminalServices' -Technique 'Unmapped' `
            -Location $KeyPath -ValueName 'InitialProgram' -RawValue ([string]$initialProgram) -LastWriteUtc $LastWrite
    }
}

# NetworkProviderOrder -- unmapped. Cross-references each named provider in
# ProviderOrder against its own Services\<name>\NetworkProvider\ProviderPath.
$script:Handler_NetworkProviderOrder = {
    param($Key, $KeyPath, $LastWrite, $HiveInfo)

    $order = $Key.GetValue('ProviderOrder')
    if (-not $order) { return }
    $providers = ([string]$order) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    foreach ($p in $providers) {
        $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$p\NetworkProvider"
        $svcKey = Get-RegistryKeySafe -Path $svcPath
        $providerPath = $null
        if ($svcKey) { $providerPath = $svcKey.GetValue('ProviderPath') }

        if (-not $providerPath) {
            # A provider named in the order list with no resolvable
            # ProviderPath is a dangling reference -- reuse the existing
            # PATH-DANGLING weighted tag rather than inventing a new one.
            Add-Finding -Module 'Network Provider Order DLL Hijack' -Token 'NetworkProviderOrder' -Technique 'Unmapped' `
                -Location $KeyPath -ValueName 'ProviderOrder' -RawValue $p -PathTrust 'DoesNotExist' `
                -Evidence @('PATH-DANGLING') -LastWriteUtc $LastWrite
            continue
        }

        Add-FileTargetFinding -Module 'Network Provider Order DLL Hijack' -Token 'NetworkProviderOrder' -Technique 'Unmapped' `
            -Location $svcPath -ValueName 'ProviderPath' -RawValue ([string]$providerPath) -TargetPath ([string]$providerPath) -LastWriteUtc $LastWrite
    }
}

# BootExecute -- unmapped, near-zero legitimate baseline. Stock default is
# exactly "autocheck autochk *" (a single REG_MULTI_SZ line). HARD ABSOLUTE
# per design on any deviation. SetupExecute (normally empty/absent) is scored
# normally, not as an absolute -- rarer to have a hardcoded always-empty
# guarantee here.
$script:Handler_BootExecute = {
    param($Key, $KeyPath, $LastWrite, $HiveInfo)

    $bootExecute = $Key.GetValue('BootExecute')
    if ($bootExecute) {
        $bootExecuteArr = @($bootExecute)
        $stockDefault = @('autocheck autochk *')
        $isDefault = ($bootExecuteArr.Count -eq $stockDefault.Count)
        if ($isDefault) {
            for ($i = 0; $i -lt $bootExecuteArr.Count; $i++) {
                if (([string]$bootExecuteArr[$i]).Trim() -ne $stockDefault[$i]) { $isDefault = $false; break }
            }
        }
        $joined = ($bootExecuteArr -join ' | ')

        if (-not $isDefault) {
            Add-Finding -Module 'Session Manager BootExecute Value' -Token 'BootExecute' -Technique 'Unmapped' `
                -Location $KeyPath -ValueName 'BootExecute' -RawValue $joined -LastWriteUtc $LastWrite `
                -Absolute 'HIGH' -Evidence @('BOOTEXECUTE-MODIFIED')
        } else {
            Add-Finding -Module 'Session Manager BootExecute Value' -Token 'BootExecute' -Technique 'Unmapped' `
                -Location $KeyPath -ValueName 'BootExecute' -RawValue $joined -LastWriteUtc $LastWrite -Evidence @()
        }
    }

    $setupExecute = $Key.GetValue('SetupExecute')
    if ($setupExecute) {
        $setupJoined = (@($setupExecute) -join ' | ')
        Add-CommandLineFinding -Module 'Session Manager BootExecute Value' -Token 'BootExecute' -Technique 'Unmapped' `
            -Location $KeyPath -ValueName 'SetupExecute' -RawValue $setupJoined -LastWriteUtc $LastWrite
    }
}

# Screensaver -- T1546.002, per hive (current + loaded). SCRNSAVE.EXE only
# actually runs at lock/idle when ScreenSaveActive=1.
$script:Handler_Screensaver = {
    param($Key, $KeyPath, $LastWrite, $HiveInfo)

    $active   = $Key.GetValue('ScreenSaveActive')
    $timeout  = $Key.GetValue('ScreenSaveTimeOut')
    $scrnsave = $Key.GetValue('SCRNSAVE.EXE')

    if ($scrnsave) {
        $isActive = ($active -eq '1' -or $active -eq 1)
        if ($isActive) {
            Add-FileTargetFinding -Module 'Screensaver Hijack' -Token 'Screensaver' -Technique 'T1546.002' `
                -Location $KeyPath -ValueName 'SCRNSAVE.EXE' -RawValue ([string]$scrnsave) -TargetPath ([string]$scrnsave) -LastWriteUtc $LastWrite
        } else {
            Add-Finding -Module 'Screensaver Hijack' -Token 'Screensaver' -Technique 'T1546.002' `
                -Location $KeyPath -ValueName 'SCRNSAVE.EXE' -RawValue ([string]$scrnsave) -LastWriteUtc $LastWrite -Evidence @()
        }
    }
    if ($null -ne $timeout) {
        Add-Finding -Module 'Screensaver Hijack' -Token 'Screensaver' -Technique 'T1546.002' `
            -Location $KeyPath -ValueName 'ScreenSaveTimeOut' -RawValue ([string]$timeout) -LastWriteUtc $LastWrite -Evidence @()
    }
}

# KnownDlls -- KnownDLLs\* is read as context inventory only (no scoring; it
# helps an analyst judge other findings). SafeDllSearchMode=0 is a HARD
# ABSOLUTE per design (NOTABLE).
$script:Handler_KnownDllsList = {
    param($Key, $KeyPath, $LastWrite, $HiveInfo)

    foreach ($valueName in $Key.GetValueNames()) {
        $val = $Key.GetValue($valueName)
        if (-not $val) { continue }
        Add-Finding -Module 'KnownDLLs Registry Tampering' -Token 'KnownDlls' -Technique 'T1574.001' `
            -Location $KeyPath -ValueName $valueName -RawValue ([string]$val) -LastWriteUtc $LastWrite -Evidence @()
    }
}
$script:Handler_SafeDllSearchMode = {
    param($Key, $KeyPath, $LastWrite, $HiveInfo)

    $val = $Key.GetValue('SafeDllSearchMode')
    if ($null -eq $val) { return }

    if ($val -eq 0 -or $val -eq '0') {
        Add-Finding -Module 'KnownDLLs Registry Tampering' -Token 'KnownDlls' -Technique 'T1574.001' `
            -Location $KeyPath -ValueName 'SafeDllSearchMode' -RawValue ([string]$val) -LastWriteUtc $LastWrite `
            -Absolute 'NOTABLE' -Evidence @('SAFEDLLSEARCHMODE-DISABLED')
    } else {
        Add-Finding -Module 'KnownDLLs Registry Tampering' -Token 'KnownDlls' -Technique 'T1574.001' `
            -Location $KeyPath -ValueName 'SafeDllSearchMode' -RawValue ([string]$val) -LastWriteUtc $LastWrite -Evidence @()
    }
}

$script:SimpleValueChecks = @(
    [PSCustomObject]@{ Token = 'PortMonitors'; Module = 'Port Monitors'; Attack = 'T1547.010'; Hive = 'HKLM'; KeyPath = 'SYSTEM\CurrentControlSet\Control\Print\Monitors'; ValueName = 'Driver'; Mode = 'SubkeyValue' }

    [PSCustomObject]@{ Token = 'PrintProcessors'; Module = 'Print Processors'; Attack = 'T1547.012'; Hive = 'HKLM'; KeyPath = 'SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors'; ValueName = 'Driver'; Mode = 'SubkeyValue' }
    [PSCustomObject]@{ Token = 'PrintProcessors'; Module = 'Print Processors'; Attack = 'T1547.012'; Hive = 'HKLM'; KeyPath = 'SYSTEM\CurrentControlSet\Control\Print\Environments\Windows NT x86\Print Processors'; ValueName = 'Driver'; Mode = 'SubkeyValue' }

    [PSCustomObject]@{ Token = 'TimeProviders'; Module = 'Time Providers'; Attack = 'T1547.003'; Hive = 'HKLM'; KeyPath = 'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'; ValueName = 'DllName'; Mode = 'SubkeyValue' }

    [PSCustomObject]@{ Token = 'NetshHelpers'; Module = 'Netsh Helper DLLs'; Attack = 'T1546.007'; Hive = 'HKLM'; KeyPath = 'SOFTWARE\Microsoft\Netsh'; ValueName = $null; Mode = 'AllValues' }

    [PSCustomObject]@{ Token = 'CommandProcessorAutoRun'; Module = 'cmd.exe AutoRun Registry Value'; Attack = 'Unmapped'; Hive = 'HKLM'; KeyPath = 'SOFTWARE\Microsoft\Command Processor'; ValueName = $null; Mode = 'Custom'; Handler = $script:Handler_CommandProcessorAutoRun }
    [PSCustomObject]@{ Token = 'CommandProcessorAutoRun'; Module = 'cmd.exe AutoRun Registry Value'; Attack = 'Unmapped'; Hive = 'PerUserHive'; KeyPath = 'Software\Microsoft\Command Processor'; ValueName = $null; Mode = 'Custom'; Handler = $script:Handler_CommandProcessorAutoRun }

    [PSCustomObject]@{ Token = 'SafeBoot'; Module = 'SafeBoot Minimal/Network Service Enablement'; Attack = 'Unmapped'; Hive = 'HKLM'; KeyPath = 'SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal'; ValueName = $null; Mode = 'Custom'; Handler = $script:Handler_SafeBootServiceList }
    [PSCustomObject]@{ Token = 'SafeBoot'; Module = 'SafeBoot Minimal/Network Service Enablement'; Attack = 'Unmapped'; Hive = 'HKLM'; KeyPath = 'SYSTEM\CurrentControlSet\Control\SafeBoot\Network'; ValueName = $null; Mode = 'Custom'; Handler = $script:Handler_SafeBootServiceList }
    [PSCustomObject]@{ Token = 'SafeBoot'; Module = 'SafeBoot Minimal/Network Service Enablement'; Attack = 'Unmapped'; Hive = 'HKLM'; KeyPath = 'SYSTEM\CurrentControlSet\Control\SafeBoot'; ValueName = $null; Mode = 'Custom'; Handler = $script:Handler_SafeBootAlternateShell }

    [PSCustomObject]@{ Token = 'TerminalServices'; Module = 'Terminal Services InitialProgram/Shell Hijack'; Attack = 'Unmapped'; Hive = 'HKLM'; KeyPath = 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; ValueName = $null; Mode = 'Custom'; Handler = $script:Handler_TerminalServices }

    [PSCustomObject]@{ Token = 'NetworkProviderOrder'; Module = 'Network Provider Order DLL Hijack'; Attack = 'Unmapped'; Hive = 'HKLM'; KeyPath = 'SYSTEM\CurrentControlSet\Control\NetworkProvider\Order'; ValueName = $null; Mode = 'Custom'; Handler = $script:Handler_NetworkProviderOrder }

    [PSCustomObject]@{ Token = 'BootExecute'; Module = 'Session Manager BootExecute Value'; Attack = 'Unmapped'; Hive = 'HKLM'; KeyPath = 'SYSTEM\CurrentControlSet\Control\Session Manager'; ValueName = $null; Mode = 'Custom'; Handler = $script:Handler_BootExecute }

    [PSCustomObject]@{ Token = 'Screensaver'; Module = 'Screensaver Hijack'; Attack = 'T1546.002'; Hive = 'PerUserHive'; KeyPath = 'Control Panel\Desktop'; ValueName = $null; Mode = 'Custom'; Handler = $script:Handler_Screensaver }

    [PSCustomObject]@{ Token = 'KnownDlls'; Module = 'KnownDLLs Registry Tampering'; Attack = 'T1574.001'; Hive = 'HKLM'; KeyPath = 'SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'; ValueName = $null; Mode = 'Custom'; Handler = $script:Handler_KnownDllsList }
    [PSCustomObject]@{ Token = 'KnownDlls'; Module = 'KnownDLLs Registry Tampering'; Attack = 'T1574.001'; Hive = 'HKLM'; KeyPath = 'SYSTEM\CurrentControlSet\Control\Session Manager'; ValueName = $null; Mode = 'Custom'; Handler = $script:Handler_SafeDllSearchMode }
)

# ---- Catalog wrapper functions for the 11 table-driven tokens -------------
function Get-PortMonitorPersistence      { Invoke-SimpleRegistryValueCheck -Token 'PortMonitors' }
function Get-PrintProcessorPersistence   { Invoke-SimpleRegistryValueCheck -Token 'PrintProcessors' }
function Get-TimeProviderPersistence     { Invoke-SimpleRegistryValueCheck -Token 'TimeProviders' }
function Get-NetshHelperPersistence      { Invoke-SimpleRegistryValueCheck -Token 'NetshHelpers' }
function Get-CommandProcessorAutoRunPersistence { Invoke-SimpleRegistryValueCheck -Token 'CommandProcessorAutoRun' }
function Get-SafeBootPersistence         { Invoke-SimpleRegistryValueCheck -Token 'SafeBoot' }
function Get-TerminalServicesPersistence { Invoke-SimpleRegistryValueCheck -Token 'TerminalServices' }
function Get-NetworkProviderPersistence  { Invoke-SimpleRegistryValueCheck -Token 'NetworkProviderOrder' }
function Get-BootExecutePersistence      { Invoke-SimpleRegistryValueCheck -Token 'BootExecute' }
function Get-ScreensaverPersistence      { Invoke-SimpleRegistryValueCheck -Token 'Screensaver' }
function Get-KnownDllsPersistence        { Invoke-SimpleRegistryValueCheck -Token 'KnownDlls' }

# ---------------------------------------------------------------------------
# Bespoke modules (multiple locations / filesystem sweeps / cross-references
# -- not simple single-value table entries).
# ---------------------------------------------------------------------------

# Shell Folder Redirection -- T1547.001-adjacent. Per hive (current +
# loaded), compares the resolved Startup / Common Startup path against the
# stock expected path; a redirected path elsewhere is the finding.
function Get-ShellFolderRedirectionPersistence {
    $expectedCommonStartup = $null
    if ($env:ProgramData) { $expectedCommonStartup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp' }

    foreach ($h in (Get-HiveRootsForPerUserCheck)) {
        foreach ($subKeyName in @('Shell Folders', 'User Shell Folders')) {
            $path = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Explorer\$subKeyName"
            $key = Get-RegistryKeySafe -Path $path
            if (-not $key) { continue }
            $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $key

            foreach ($valueName in @('Startup', 'Common Startup')) {
                $raw = $key.GetValue($valueName)
                if (-not $raw) { continue }
                $expanded = [System.Environment]::ExpandEnvironmentVariables([string]$raw)

                $expected = $null
                if ($valueName -eq 'Common Startup') {
                    $expected = $expectedCommonStartup
                } elseif ($h.Root -eq 'HKCU:') {
                    if ($env:USERPROFILE) { $expected = Join-Path $env:USERPROFILE 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
                } else {
                    $sid = ($h.Root -replace '^HKU:\\', '')
                    $profileMatch = $script:OnDiskProfiles | Where-Object { $_.SID -eq $sid } | Select-Object -First 1
                    if ($profileMatch -and $profileMatch.ProfilePath) {
                        $expected = Join-Path $profileMatch.ProfilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
                    }
                }

                $isRedirected = $false
                if ($expected) {
                    $isRedirected = ($expanded.TrimEnd('\') -ine $expected.TrimEnd('\'))
                } else {
                    # No known-good comparison path for this hive -- fall back to a
                    # loose structural check instead of asserting a specific path.
                    $isRedirected = ($expanded -notmatch '\\Start Menu\\Programs\\Start[Uu]p$')
                }

                if ($isRedirected) {
                    $dirTrust = Test-DirectoryPathTrust -Path $expanded
                    $evidence = @('SHELLFOLDER-REDIRECTED')
                    if ($dirTrust -eq 'Untrusted') { $evidence += 'PATH-UNTRUSTED' }
                    elseif ($dirTrust -eq 'DoesNotExist') { $evidence += 'PATH-DANGLING' }
                    if (Test-InWindow -TimeUtc $lastWrite) { $evidence += 'RECENCY' }

                    Add-Finding -Module 'Shell Folder Redirection (User Shell Folders)' -Token 'ShellFolderRedir' -Technique 'T1547.001' `
                        -Location $path -ValueName $valueName -RawValue ([string]$raw) -ResolvedTarget $expanded -PathTrust $dirTrust `
                        -LastWriteUtc $lastWrite -Evidence $evidence
                } else {
                    Add-Finding -Module 'Shell Folder Redirection (User Shell Folders)' -Token 'ShellFolderRedir' -Technique 'T1547.001' `
                        -Location $path -ValueName $valueName -RawValue ([string]$raw) -LastWriteUtc $lastWrite -Evidence @()
                }
            }
        }
    }
}

# Boot / Logon Scripts (Group Policy). Legacy UserInitMprLogonScript (per hive)
# is tagged T1037.001 (its own distinct, local-only technique); the registry
# pointers to GPO script GUIDs and the LOCAL GPO cache on disk are the same
# GPO-distributed-script mechanism as SysvolGpo, so they are tagged T1037.003
# to match. Does NOT read SYSVOL over the network -- domain-joined hosts may
# have additional SYSVOL-sourced scripts not visible here; that's the
# -Deep-tier SysvolGpo token's job.
function Read-GpoScriptRegistryTree {
    param([string]$RootPath)

    # Real shape is ...\Scripts\<Startup|Shutdown|Logon|Logoff>\<seq>\<GUID>\<n>
    # with Script/Parameters values at the leaf. Best-effort walk (not a full
    # GPO parser): report every 'Script' value found at any depth up to 4.
    $stack = New-Object System.Collections.Generic.List[string]
    $stack.Add($RootPath)
    $depth = 0
    while ($stack.Count -gt 0 -and $depth -lt 4) {
        $next = New-Object System.Collections.Generic.List[string]
        foreach ($p in $stack) {
            $k = Get-RegistryKeySafe -Path $p
            if (-not $k) { continue }
            $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $k
            $script = $k.GetValue('Script')
            if ($script) {
                Add-CommandLineFinding -Module 'Boot / Logon Scripts (Group Policy)' -Token 'BootLogonScripts' -Technique 'T1037.003' `
                    -Location $p -ValueName 'Script' -RawValue ([string]$script) -LastWriteUtc $lastWrite
            }
            foreach ($sub in $k.GetSubKeyNames()) { $next.Add("$p\$sub") }
        }
        $stack = $next
        $depth++
    }
}

function Get-BootLogonScriptPersistence {
    foreach ($h in (Get-HiveRootsForPerUserCheck)) {
        $envPath = "$($h.Root)\Environment"
        $envKey = Get-RegistryKeySafe -Path $envPath
        if ($envKey) {
            $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $envKey
            $logonScript = $envKey.GetValue('UserInitMprLogonScript')
            if ($logonScript) {
                Add-CommandLineFinding -Module 'Boot / Logon Scripts (Group Policy)' -Token 'BootLogonScripts' -Technique 'T1037.001' `
                    -Location $envPath -ValueName 'UserInitMprLogonScript' -RawValue ([string]$logonScript) -LastWriteUtc $lastWrite
            }
        }

        foreach ($scope in @('Logon', 'Logoff')) {
            Read-GpoScriptRegistryTree -RootPath "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\$scope"
        }
    }

    foreach ($scope in @('Startup', 'Shutdown')) {
        Read-GpoScriptRegistryTree -RootPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\$scope"
    }

    # Local GPO cache -- report scripts.ini existence (contents not parsed --
    # out of scope, same reasoning as not reading Startup-folder script
    # content in Pass B) and enumerate any files under the Scripts subfolders.
    # $env:SystemRoot can be unset (non-Windows host, stripped environment) --
    # guarded the same way Resolve-BareDllName guards it above.
    if ($env:SystemRoot) {
        $gpBase = Join-Path $env:SystemRoot 'System32\GroupPolicy'
        foreach ($ini in @((Join-Path $gpBase 'Machine\Scripts\scripts.ini'), (Join-Path $gpBase 'User\Scripts\scripts.ini'))) {
            try {
                if (Test-Path -LiteralPath $ini -PathType Leaf -ErrorAction Stop) {
                    $item = Get-Item -LiteralPath $ini -ErrorAction Stop
                    Add-Finding -Module 'Boot / Logon Scripts (Group Policy)' -Token 'BootLogonScripts' -Technique 'T1037.003' `
                        -Location $ini -ValueName $null -RawValue $ini -LastWriteUtc $item.LastWriteTimeUtc -Evidence @()
                }
            } catch {
                $script:UnreadableTargets.Add(@{ Target = $ini; Reason = $_.Exception.Message })
            }
        }

        foreach ($base in @((Join-Path $gpBase 'Machine\Scripts'), (Join-Path $gpBase 'User\Scripts'))) {
            foreach ($sub in @('Startup', 'Shutdown', 'Logon', 'Logoff')) {
                $dir = Join-Path $base $sub
                try {
                    $files = Get-ChildItem -LiteralPath $dir -File -Recurse -ErrorAction Stop
                    foreach ($f in $files) {
                        Add-FileTargetFinding -Module 'Boot / Logon Scripts (Group Policy)' -Token 'BootLogonScripts' -Technique 'T1037.003' `
                            -Location $dir -ValueName $f.Name -RawValue $f.FullName -TargetPath $f.FullName -LastWriteUtc $f.LastWriteTimeUtc
                    }
                } catch {
                    if ($_.CategoryInfo.Category -ne 'ObjectNotFound') {
                        $script:UnreadableTargets.Add(@{ Target = $dir; Reason = $_.Exception.Message })
                    }
                }
            }
        }
    }
}

# Application Shimming (Custom SDB) -- T1546.011, inventory-only per design;
# does not parse .sdb internals.
function Get-AppShimPersistence {
    $roots = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom'; Label = 'Custom' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB'; Label = 'InstalledSDB' }
    )
    foreach ($r in $roots) {
        $key = Get-RegistryKeySafe -Path $r.Path
        if (-not $key) { continue }
        foreach ($sub in $key.GetSubKeyNames()) {
            $subPath = "$($r.Path)\$sub"
            $subKey = Get-RegistryKeySafe -Path $subPath
            if (-not $subKey) { continue }
            $subLastWrite = Get-RegKeyLastWriteTimeUtc -Key $subKey

            $valueNames = $subKey.GetValueNames()
            $descr = $null
            foreach ($candidate in @('DatabasePath', 'DatabaseDescription', '')) {
                if ($valueNames -contains $candidate) { $descr = $subKey.GetValue($candidate); break }
            }
            Add-Finding -Module 'Application Shimming (Custom SDB)' -Token 'AppShim' -Technique 'T1546.011' `
                -Location $subPath -ValueName $r.Label -RawValue ([string]$descr) -LastWriteUtc $subLastWrite -Evidence @()
        }
    }

    if ($env:SystemRoot) {
        foreach ($dir in @((Join-Path $env:SystemRoot 'AppPatch\Custom'), (Join-Path $env:SystemRoot 'AppPatch\Custom\Custom64'))) {
            try {
                $files = Get-ChildItem -LiteralPath $dir -Filter '*.sdb' -File -ErrorAction Stop
                foreach ($f in $files) {
                    Add-Finding -Module 'Application Shimming (Custom SDB)' -Token 'AppShim' -Technique 'T1546.011' `
                        -Location $dir -ValueName $f.Name -RawValue $f.FullName -LastWriteUtc $f.LastWriteTimeUtc -Evidence @()
                }
            } catch {
                if ($_.CategoryInfo.Category -ne 'ObjectNotFound') {
                    $script:UnreadableTargets.Add(@{ Target = $dir; Reason = $_.Exception.Message })
                }
            }
        }
    }
}

# PowerShell Profile Scripts -- T1546.013. File-existence + LastWriteTime
# only; script content is not read (same reasoning as Startup-folder items in
# Pass B). Mirrors Get-StartupFolderPersistence's Get-OnDiskProfiles pattern
# so profiles with no loaded hive are still covered on disk.
function Get-PSProfilePersistence {
    $candidates = New-Object System.Collections.Generic.List[object]

    if ($PSHOME) {
        $candidates.Add([PSCustomObject]@{ Path = (Join-Path $PSHOME 'profile.ps1'); Scope = 'All Users (AllHosts)' })
        $candidates.Add([PSCustomObject]@{ Path = (Join-Path $PSHOME 'Microsoft.PowerShell_profile.ps1'); Scope = 'All Users (PowerShell console)' })
    }

    foreach ($profile in (Get-OnDiskProfiles)) {
        if (-not $profile.ProfilePath) { continue }
        $docsBase = Join-Path $profile.ProfilePath 'Documents\WindowsPowerShell'
        $candidates.Add([PSCustomObject]@{ Path = (Join-Path $docsBase 'profile.ps1'); Scope = $profile.SID })
        $candidates.Add([PSCustomObject]@{ Path = (Join-Path $docsBase 'Microsoft.PowerShell_profile.ps1'); Scope = $profile.SID })

        if (-not $profile.HiveLoaded) {
            # Known-Folder/OneDrive redirection of Documents can't be resolved
            # without this user's hive loaded -- a redirected-Documents profile
            # could be missed here. Documented coverage gap, not a silent one.
            $script:UnreadableTargets.Add(@{ Target = $docsBase; Reason = 'Profile hive not loaded -- cannot resolve a possible OneDrive/Known-Folder Documents redirection for this profile; only the default Documents path was checked.' })
        }
    }

    foreach ($c in $candidates) {
        try {
            if (Test-Path -LiteralPath $c.Path -PathType Leaf -ErrorAction Stop) {
                $item = Get-Item -LiteralPath $c.Path -ErrorAction Stop
                $evidence = Get-StandardEvidenceTags -PathTrust $null -SignatureStatus $null -CommandLineTags @() -LastWriteUtc $item.LastWriteTimeUtc
                Add-Finding -Module 'PowerShell Profile Scripts' -Token 'PSProfiles' -Technique 'T1546.013' `
                    -Location $c.Path -ValueName $c.Scope -RawValue $c.Path -LastWriteUtc $item.LastWriteTimeUtc -Evidence $evidence
            }
        } catch {
            $script:UnreadableTargets.Add(@{ Target = $c.Path; Reason = $_.Exception.Message })
        }
    }
}

# PSModulePath Environment Hijack -- unmapped, T1574.007-adjacent. Flags any
# untrusted-path entry (a user-writable directory on the module autoload
# path) from the system value, every per-user value, and the live process value.
function Get-PSModulePathPersistence {
    $sources = New-Object System.Collections.Generic.List[object]

    $sysKey = Get-RegistryKeySafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    if ($sysKey) {
        $val = $sysKey.GetValue('PSModulePath')
        if ($val) {
            $sources.Add([PSCustomObject]@{ Value = [string]$val; Location = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'; LastWriteUtc = (Get-RegKeyLastWriteTimeUtc -Key $sysKey) })
        }
    }

    foreach ($h in (Get-HiveRootsForPerUserCheck)) {
        $envPath = "$($h.Root)\Environment"
        $envKey = Get-RegistryKeySafe -Path $envPath
        if ($envKey) {
            $val = $envKey.GetValue('PSModulePath')
            if ($val) {
                $sources.Add([PSCustomObject]@{ Value = [string]$val; Location = $envPath; LastWriteUtc = (Get-RegKeyLastWriteTimeUtc -Key $envKey) })
            }
        }
    }

    if ($env:PSModulePath) {
        $sources.Add([PSCustomObject]@{ Value = $env:PSModulePath; Location = '$env:PSModulePath (live process)'; LastWriteUtc = $null })
    }

    foreach ($src in $sources) {
        $dirs = $src.Value -split ';' | Where-Object { $_ }
        foreach ($dir in $dirs) {
            $expanded = [System.Environment]::ExpandEnvironmentVariables($dir)
            $trust = Test-DirectoryPathTrust -Path $expanded

            $evidence = @()
            if ($trust -eq 'Untrusted') { $evidence += 'PATH-UNTRUSTED' }
            if (Test-InWindow -TimeUtc $src.LastWriteUtc) { $evidence += 'RECENCY' }

            Add-Finding -Module 'PSModulePath Environment Hijack' -Token 'PSModulePath' -Technique 'Unmapped' `
                -Location $src.Location -ValueName 'PSModulePath' -RawValue $dir -ResolvedTarget $expanded -PathTrust $trust `
                -LastWriteUtc $src.LastWriteUtc -Evidence $evidence
        }
    }
}

# Environment Variable Hijack (COR_PROFILER family, DOTNET_STARTUP_HOOKS) --
# catalog Attack is 'Unmapped' for this token (COR_PROFILER itself maps to
# T1574.012, but DOTNET_STARTUP_HOOKS does not -- the catalog's single
# 'Unmapped' Attack value is used for every variable here per the catalog
# being authoritative). HARD ABSOLUTE per design: presence of any watched
# variable is NOTABLE, escalated to HIGH if the referenced profiler DLL /
# startup-hook assembly path fails path-trust or signature.
function Get-EnvironmentVariableHijackPersistence {
    $watchNames = @('COR_ENABLE_PROFILING', 'COR_PROFILER', 'COR_PROFILER_PATH', 'CORECLR_ENABLE_PROFILING', 'CORECLR_PROFILER', 'DOTNET_STARTUP_HOOKS')

    $sources = New-Object System.Collections.Generic.List[object]
    $sysKey = Get-RegistryKeySafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    if ($sysKey) {
        $sources.Add([PSCustomObject]@{ Key = $sysKey; Location = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'; LastWriteUtc = (Get-RegKeyLastWriteTimeUtc -Key $sysKey) })
    }
    foreach ($h in (Get-HiveRootsForPerUserCheck)) {
        $envPath = "$($h.Root)\Environment"
        $envKey = Get-RegistryKeySafe -Path $envPath
        if ($envKey) {
            $sources.Add([PSCustomObject]@{ Key = $envKey; Location = $envPath; LastWriteUtc = (Get-RegKeyLastWriteTimeUtc -Key $envKey) })
        }
    }

    foreach ($src in $sources) {
        foreach ($name in $watchNames) {
            $val = $src.Key.GetValue($name)
            if (-not $val -or -not ([string]$val).Trim()) { continue }
            $valStr = [string]$val

            # COR_PROFILER/CORECLR_PROFILER are CLSID GUIDs by convention, not
            # paths -- only *_PATH / DOTNET_STARTUP_HOOKS (or a value that
            # already looks like a filesystem path) are resolved as a target.
            $targetToCheck = $null
            if ($name -eq 'COR_PROFILER_PATH') {
                $targetToCheck = $valStr
            } elseif ($name -eq 'DOTNET_STARTUP_HOOKS') {
                $targetToCheck = ($valStr -split ';' | Select-Object -First 1)
            } elseif ($valStr -match '^[A-Za-z]:\\|^\\\\') {
                $targetToCheck = $valStr
            }

            $pathTrust = $null
            $sigStatus = $null
            $sigPublisher = $null
            $resolved = $null
            if ($targetToCheck) {
                $resolved = [System.Environment]::ExpandEnvironmentVariables($targetToCheck)
                $pathTrust = Test-PathTrust -Path $resolved
                $verdict = Get-AuthenticodeVerdict -Path $resolved
                $sigStatus = $verdict.Status
                $sigPublisher = $verdict.Publisher
            }

            $untrusted = ($pathTrust -eq 'Untrusted' -or $pathTrust -eq 'DoesNotExist' -or
                          $sigStatus -eq 'NotSigned' -or $sigStatus -eq 'HashMismatch' -or $sigStatus -eq 'NotTrusted')

            $evidence = Get-StandardEvidenceTags -PathTrust $pathTrust -SignatureStatus $sigStatus -CommandLineTags @() -LastWriteUtc $src.LastWriteUtc
            if ($evidence -notcontains 'DOTNET-PROFILER-SET') { $evidence += 'DOTNET-PROFILER-SET' }

            $absolute = 'NOTABLE'
            if ($targetToCheck -and $untrusted) { $absolute = 'HIGH' }

            Add-Finding -Module 'Environment Variable Hijack (COR_PROFILER, windir, etc.)' -Token 'EnvHijack' -Technique 'Unmapped' `
                -Location $src.Location -ValueName $name -RawValue $valStr -ResolvedTarget $resolved -PathTrust $pathTrust `
                -SignatureStatus $sigStatus -SignaturePublisher $sigPublisher -LastWriteUtc $src.LastWriteUtc `
                -Absolute $absolute -Evidence $evidence
        }
    }
}

# Change Default File Association -- T1546.001. NOTE: this token was not
# spelled out with exact registry paths in the Pass C build spec (unlike the
# other 20). Implemented against the well-documented, standard Windows 8+
# per-user override mechanism: FileExts\<ext>\UserChoice\ProgId, resolved to
# that ProgId's shell\open\command. Confidence: high on the mechanism itself,
# medium on the specific extension watchlist chosen below (kept small and
# limited to script/executable-adjacent extensions with a thin legitimate
# handler set, deliberately not the sprawling handler space of .txt/.html/
# .pdf/Office document extensions).
function Get-FileAssociationPersistence {
    $watchExtensions = @('.bat', '.cmd', '.js', '.vbs', '.wsf', '.hta', '.reg', '.ps1', '.scr', '.msc')

    foreach ($h in (Get-HiveRootsForPerUserCheck)) {
        foreach ($ext in $watchExtensions) {
            $userChoicePath = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext\UserChoice"
            $ucKey = Get-RegistryKeySafe -Path $userChoicePath
            if (-not $ucKey) { continue }
            $progId = $ucKey.GetValue('ProgId')
            if (-not $progId) { continue }
            $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $ucKey

            # Per-user Classes override first, then the machine-wide ProgId
            # registration. NOTE: per-user COM/ProgId class data for a
            # non-interactively-loaded hive technically lives in a separately
            # loaded HKU:\<SID>_Classes hive on real Windows, not under
            # HKU:\<SID>\Software\Classes -- this may return no data for some
            # loaded-but-non-interactive hives; a documented coverage caveat,
            # not a silent gap (see final report).
            $cmdPath = "$($h.Root)\Software\Classes\$progId\shell\open\command"
            $cmdKey = Get-RegistryKeySafe -Path $cmdPath
            if (-not $cmdKey) {
                $cmdPath = "HKLM:\SOFTWARE\Classes\$progId\shell\open\command"
                $cmdKey = Get-RegistryKeySafe -Path $cmdPath
            }
            if (-not $cmdKey) { continue }
            $cmd = $cmdKey.GetValue('')
            if (-not $cmd) { continue }

            Add-CommandLineFinding -Module 'Change Default File Association' -Token 'FileAssoc' -Technique 'T1546.001' `
                -Location $cmdPath -ValueName $ext -RawValue ([string]$cmd) -LastWriteUtc $lastWrite `
                -ExtraEvidence @('FILEASSOC-USERCHOICE-OVERRIDE')
        }
    }
}

# Office Test Registry Value -- T1137.002. Near-zero legitimate baseline in a
# normal enterprise environment; any populated default value is inherently
# rare/interesting, scored via the standard path-trust/signature pipeline.
function Get-OfficeTestPersistence {
    foreach ($h in (Get-HiveRootsForPerUserCheck)) {
        $path = "$($h.Root)\Software\Microsoft\Office test\Special\Perf"
        $key = Get-RegistryKeySafe -Path $path
        if (-not $key) { continue }
        $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $key
        $raw = $key.GetValue('')
        if (-not $raw) { continue }

        Add-FileTargetFinding -Module 'Office Test Registry Value' -Token 'OfficeTest' -Technique 'T1137.002' `
            -Location $path -ValueName '(Default)' -RawValue ([string]$raw) -TargetPath ([string]$raw) -LastWriteUtc $lastWrite `
            -ExtraEvidence @('OFFICETEST-POPULATED')
    }
}

# Office Trusted Locations Macro Bypass -- context for T1137.001 macro risk.
# Walks whatever Office version subkeys actually exist (no hardcoded version
# number) for the common app names, per hive (current + loaded).
function Get-OfficeTrustedLocationPersistence {
    $appNames = @('Word', 'Excel', 'PowerPoint', 'Access', 'Outlook')

    foreach ($h in (Get-HiveRootsForPerUserCheck)) {
        $officeRoot = "$($h.Root)\Software\Microsoft\Office"
        $officeKey = Get-RegistryKeySafe -Path $officeRoot
        if (-not $officeKey) { continue }

        foreach ($verName in $officeKey.GetSubKeyNames()) {
            foreach ($app in $appNames) {
                $tlRoot = "$officeRoot\$verName\$app\Security\Trusted Locations"
                $tlKey = Get-RegistryKeySafe -Path $tlRoot
                if (-not $tlKey) { continue }

                foreach ($locName in $tlKey.GetSubKeyNames()) {
                    if ($locName -notlike 'Location*') { continue }
                    $locPath = "$tlRoot\$locName"
                    $locKey = Get-RegistryKeySafe -Path $locPath
                    if (-not $locKey) { continue }
                    $locLastWrite = Get-RegKeyLastWriteTimeUtc -Key $locKey

                    $tlPath = $locKey.GetValue('Path')
                    if (-not $tlPath) { continue }
                    $allowSub = $locKey.GetValue('AllowSubFolders')
                    $expanded = [System.Environment]::ExpandEnvironmentVariables([string]$tlPath)

                    $dirTrust = Test-DirectoryPathTrust -Path $expanded
                    $isBroad = ($expanded -match '^[A-Za-z]:\\?$' -or $expanded -match '^[A-Za-z]:\\Users\\[^\\]+\\?$')
                    $subFoldersOn = ($allowSub -eq 1 -or $allowSub -eq '1')

                    $evidence = @()
                    if ($dirTrust -eq 'Untrusted') { $evidence += 'PATH-UNTRUSTED' }
                    if ($subFoldersOn -and $isBroad) { $evidence += 'OFFICE-TRUSTLOC-BROAD-SUBFOLDERS' }
                    if (Test-InWindow -TimeUtc $locLastWrite) { $evidence += 'RECENCY' }

                    Add-Finding -Module 'Office Trusted Locations Macro Bypass' -Token 'OfficeTrustedLocations' -Technique 'Unmapped' `
                        -Location $locPath -ValueName $app -RawValue ([string]$tlPath) -ResolvedTarget $expanded -PathTrust $dirTrust `
                        -LastWriteUtc $locLastWrite -Evidence $evidence
                }
            }
        }
    }
}

# COM Hijacking (fast watchlist subset) -- T1546.015. Best-effort,
# non-exhaustive starting set based on well-known, stable, publicly
# documented core Windows Shell namespace CLSIDs -- NOT a claim that any of
# these specific GUIDs have been observed abused by a named malware family.
# Operators should expand/verify this list for their environment; do NOT
# treat absence of a hit here as proof of no COM hijacking -- see the
# Deep-tier ComFull token (full CLSID sweep) for comprehensive coverage. This
# watchlist exists to validate the resolve -> trust -> signature detection
# pipeline cheaply on a handful of CLSIDs that should not normally be
# per-user-overridden on a clean host.
$script:ComHijackWatchlist = @(
    [PSCustomObject]@{ Clsid = '{20D04FE0-3AEA-1069-A2D8-08002B30309D}'; Name = 'My Computer / This PC' }
    [PSCustomObject]@{ Clsid = '{645FF040-5081-101B-9F08-00AA002F954E}'; Name = 'Recycle Bin' }
    [PSCustomObject]@{ Clsid = '{21EC2020-3AEA-1069-A2DD-08002B30309D}'; Name = 'Control Panel' }
    [PSCustomObject]@{ Clsid = '{208D2C60-3AEA-1069-A2D7-08002B30309D}'; Name = 'My Network Places / Network' }
    [PSCustomObject]@{ Clsid = '{871C5380-42A0-1069-A2EA-08002B30309D}'; Name = 'Internet Explorer / Internet shortcut handler' }
)

function Get-ComHijackWatchlistPersistence {
    foreach ($h in (Get-HiveRootsForPerUserCheck)) {
        foreach ($entry in $script:ComHijackWatchlist) {
            $path = "$($h.Root)\Software\Classes\CLSID\$($entry.Clsid)\InprocServer32"
            $key = Get-RegistryKeySafe -Path $path
            if (-not $key) { continue }
            $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $key
            $raw = $key.GetValue('')
            if (-not $raw) { continue }

            # A per-user InprocServer32 override existing at all for one of
            # these core shell CLSIDs is the anomaly -- these are not expected
            # to be user-overridden on a clean host, independent of the
            # resolved DLL's own trust/signature verdict.
            Add-FileTargetFinding -Module 'COM Hijacking (fast watchlist subset)' -Token 'ComWatchlist' -Technique 'T1546.015' `
                -Location $path -ValueName $entry.Name -RawValue ([string]$raw) -TargetPath ([string]$raw) -LastWriteUtc $lastWrite `
                -ExtraEvidence @('COM-WATCHLIST-CLSID-OVERRIDDEN')
        }
    }
}

#endregion Fast-Tier Modules (Pass C)

# ===========================================================================
#  Deep-Tier Modules (Pass D)
# ===========================================================================
#region Deep-Tier Modules (Pass D)
#
# Ten module functions covering the heavier/slower checks gated behind -Deep
# (or an explicit -Modules token name): the full unrestricted COM CLSID
# sweep, a full Authenticode re-verification pass, Office add-ins, Outlook,
# SYSVOL GPO, Winsock LSP, BITS jobs, credential providers, BHOs, and shell
# extensions. Same read-only contract as Pass B/C: only Get-Item/
# Get-ChildItem/Get-ItemProperty-style registry reads, Get-ChildItem
# filesystem reads, Get-ScheduledTask/Get-CimInstance/Get-BitsTransfer native
# readers, and one read-only `netsh ... show ...` shell-out -- every call
# wrapped in try/catch, genuine access failures appended to
# $script:UnreadableTargets, every module calling Add-Finding (via the shared
# Add-CommandLineFinding/Add-FileTargetFinding/Add-Finding pipeline) for
# everything it inspects.

# ---------------------------------------------------------------------------
# Private helpers local to this region.
# ---------------------------------------------------------------------------

# Resolves a CLSID GUID string to its InprocServer32/LocalServer32
# target under a given Classes hive root (e.g. 'HKLM:\SOFTWARE\Classes',
# 'HKCU:\Software\Classes', or a per-user 'HKU:\<SID>_Classes'). Follows one
# TreatAs redirect hop if present (TreatAs points to a different CLSID that
# should be treated as this one -- RedirectedFrom records the original CLSID
# so callers can note the chain). LocalServer32 values are command lines
# (exe path + optional args), not bare paths -- resolved through the same
# Resolve-CommandLineTarget used everywhere else in this file so both server
# types return a clean, ready-to-check TargetPath. Never throws; a $null
# .Path means "no resolvable server for this CLSID" (common and NOT itself
# evidence of anything -- most CLSIDs exist only for marshaling/interface
# identification and never had an InprocServer32/LocalServer32 to begin
# with). Reused by ComFull, OfficeAddins, CredentialProviders, BHO, and
# ShellExt -- the one shared CLSID-resolution helper for all five, instead of
# duplicating this lookup at each call site.
function Resolve-ClsidToDll {
    param(
        [Parameter(Mandatory = $true)][string]$Clsid,
        [Parameter(Mandatory = $true)][string]$ClassesRoot
    )

    $result = [PSCustomObject]@{
        Clsid          = $Clsid
        Path           = $null
        RawValue       = $null
        ServerType     = $null
        KeyPath        = $null
        LastWriteUtc   = $null
        RedirectedFrom = $null
    }

    $clsidPath = "$ClassesRoot\CLSID\$Clsid"
    $clsidKey = Get-RegistryKeySafe -Path $clsidPath
    if (-not $clsidKey) { return $result }

    $effectivePath = $clsidPath
    $treatAs = $clsidKey.GetValue('TreatAs')
    if ($treatAs -and ([string]$treatAs) -ne $Clsid) {
        $redirectedPath = "$ClassesRoot\CLSID\$treatAs"
        $redirectedKey = Get-RegistryKeySafe -Path $redirectedPath
        if ($redirectedKey) {
            $result.RedirectedFrom = $Clsid
            $effectivePath = $redirectedPath
        }
    }

    foreach ($serverType in @('InprocServer32', 'LocalServer32')) {
        $serverPath = "$effectivePath\$serverType"
        $serverKey = Get-RegistryKeySafe -Path $serverPath
        if (-not $serverKey) { continue }
        $raw = $serverKey.GetValue('')
        if (-not $raw) { continue }
        $rawStr = [string]$raw

        $target = $rawStr
        if ($serverType -eq 'LocalServer32') {
            $cmdTarget = Resolve-CommandLineTarget -CommandLine $rawStr
            if ($cmdTarget) { $target = $cmdTarget }
        }

        $result.RawValue     = $rawStr
        $result.Path         = [System.Environment]::ExpandEnvironmentVariables($target)
        $result.ServerType   = $serverType
        $result.KeyPath      = $serverPath
        $result.LastWriteUtc = Get-RegKeyLastWriteTimeUtc -Key $serverKey
        return $result
    }

    return $result
}

# Given a "current + loaded hive" root object from Get-HiveRootsForPerUserCheck
# (Root = 'HKCU:' or 'HKU:\<SID>'), returns the Classes hive root that
# actually holds that user's per-user COM/ProgID class registrations.
#
# CORRECTNESS NOTE: per-user COM class registrations for a loaded-but-not-
# interactive hive live in the SEPARATE HKU:\<SID>_Classes hive (backed by
# UsrClass.dat), NOT under HKU:\<SID>\Software\Classes (backed by
# NTUSER.DAT, which is typically sparse/empty for this data) -- Windows only
# merges these transparently into HKEY_CURRENT_USER for the interactively
# logged-on user viewing their own hive. This helper checks whether
# <SID>_Classes is separately loaded/mounted alongside <SID> and prefers it
# when present, falling back to Software\Classes under the plain hive only
# when it is not (documented, possibly-incomplete fallback, not a silent
# gap). Pass C's smaller ComWatchlist/FileAssoc modules documented this same
# gap without fixing it (see their own comments); Pass D's ComFull and
# OfficeAddins are the modules that actually apply this fix, since they are
# meant to be the comprehensive/authoritative sweeps.
function Get-ClassesRootForHive {
    param([Parameter(Mandatory = $true)]$HiveRootInfo)

    if ($HiveRootInfo.Root -eq 'HKCU:') {
        return [PSCustomObject]@{ ClassesRoot = 'HKCU:\Software\Classes'; SourceLabel = 'HKCU (current session)' }
    }

    $sid = ($HiveRootInfo.Root -replace '^HKU:\\', '')
    $classesHivePath = "HKU:\${sid}_Classes"
    $classesKey = Get-RegistryKeySafe -Path $classesHivePath
    if ($classesKey) {
        return [PSCustomObject]@{ ClassesRoot = $classesHivePath; SourceLabel = "$($HiveRootInfo.Label) (HKU:\<SID>_Classes -- UsrClass.dat, authoritative)" }
    }
    return [PSCustomObject]@{ ClassesRoot = "$($HiveRootInfo.Root)\Software\Classes"; SourceLabel = "$($HiveRootInfo.Label) (Software\Classes fallback -- _Classes hive not separately loaded, may be incomplete)" }
}

# ProgID -> CLSID lookup (the ProgID's own CLSID subkey default value),
# against a given Classes root. Used only by OfficeAddins.
function Resolve-ProgIdToClsid {
    param(
        [Parameter(Mandatory = $true)][string]$ProgId,
        [Parameter(Mandatory = $true)][string]$ClassesRoot
    )

    $path = "$ClassesRoot\$ProgId\CLSID"
    $key = Get-RegistryKeySafe -Path $path
    if (-not $key) { return $null }
    $val = $key.GetValue('')
    if (-not $val) { return $null }
    return [string]$val
}

# Shared enumeration pattern for "CLSID-named subkeys directly under a fixed
# registry key, resolve each via Resolve-ClsidToDll against a fixed Classes
# root" -- used by CredentialProviders and BHO (including its WOW6432Node
# mirror) to avoid writing the same ~15-line loop three times.
function Read-ClsidKeyListPersistence {
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Token,
        [string]$Technique = 'Unmapped',
        [string]$ClassesRoot = 'HKLM:\SOFTWARE\Classes',
        [switch]$ReadDisplayName
    )

    $rootKey = Get-RegistryKeySafe -Path $RootPath
    if (-not $rootKey) { return }

    foreach ($clsid in $rootKey.GetSubKeyNames()) {
        $subPath = "$RootPath\$clsid"
        $valueName = $clsid
        if ($ReadDisplayName) {
            $subKey = Get-RegistryKeySafe -Path $subPath
            if ($subKey) {
                $displayName = $subKey.GetValue('')
                if ($displayName) { $valueName = "$clsid ($displayName)" }
            }
        }

        $resolved = Resolve-ClsidToDll -Clsid $clsid -ClassesRoot $ClassesRoot
        if (-not $resolved.Path) {
            Add-Finding -Module $Module -Token $Token -Technique $Technique `
                -Location $subPath -ValueName $valueName -RawValue $clsid -PathTrust 'DoesNotExist' -Evidence @('PATH-DANGLING')
            continue
        }

        Add-FileTargetFinding -Module $Module -Token $Token -Technique $Technique `
            -Location $resolved.KeyPath -ValueName $valueName -RawValue $resolved.RawValue -TargetPath $resolved.Path -LastWriteUtc $resolved.LastWriteUtc
    }
}

# ---------------------------------------------------------------------------
# 1. COM Hijacking -- full CLSID/InprocServer32 sweep -- T1546.015
# ---------------------------------------------------------------------------

# The full, unrestricted counterpart to Pass C's curated ComWatchlist. Sweeps
# EVERY CLSID under HKCU:\Software\Classes\CLSID (current session) and, per
# loaded hive, the _Classes-hive-aware root from Get-ClassesRootForHive
# above. This produces a LOT of LOW-tier inventory (thousands of legitimate
# per-user CLSID registrations on a normal host) -- that is expected and
# correct: the doctrine here is "enumerate everything, flag on evidence," not
# a pre-filtered "smart" subset (see ComWatchlist for the cheap curated
# version). Does not sweep HKLM:\SOFTWARE\Classes\CLSID -- COM hijacking is a
# per-user-override technique (a user-writable HKCU/UsrClass.dat entry
# shadowing the machine-wide registration), so the machine-wide registration
# itself is not the abuse surface this module targets.
function Get-ComHijackFullScanPersistence {
    foreach ($h in (Get-HiveRootsForPerUserCheck)) {
        $classesInfo = Get-ClassesRootForHive -HiveRootInfo $h
        $clsidRoot = "$($classesInfo.ClassesRoot)\CLSID"
        $clsidRootKey = Get-RegistryKeySafe -Path $clsidRoot
        if (-not $clsidRootKey) { continue }

        foreach ($guid in $clsidRootKey.GetSubKeyNames()) {
            $resolved = Resolve-ClsidToDll -Clsid $guid -ClassesRoot $classesInfo.ClassesRoot
            if (-not $resolved.Path) { continue }

            $valueLabel = $resolved.ServerType
            if ($resolved.RedirectedFrom) {
                $valueLabel = "$($resolved.ServerType) (TreatAs redirect: $($resolved.RedirectedFrom) -> effective CLSID)"
            }

            Add-FileTargetFinding -Module 'COM Hijacking (full CLSID/InprocServer32 sweep)' -Token 'ComFull' -Technique 'T1546.015' `
                -Location $resolved.KeyPath -ValueName "$guid :: $valueLabel [source: $($classesInfo.SourceLabel)]" -RawValue $resolved.RawValue `
                -TargetPath $resolved.Path -LastWriteUtc $resolved.LastWriteUtc
        }
    }
}

# ---------------------------------------------------------------------------
# 2. Full Authenticode Re-verification Pass -- Unmapped (context-only token)
# ---------------------------------------------------------------------------

# Fast-tier's Get-ServicePersistence/Get-ScheduledTaskPersistence already run
# every resolved target through the standard Add-CommandLineFinding pipeline
# (which itself always calls Get-AuthenticodeVerdict) -- what Fast-tier does
# NOT do is independently re-derive and report the full signature-status
# DISTRIBUTION across the whole Services + Scheduled Tasks surface as a
# single completion artifact, nor individually re-flag HashMismatch/
# NotTrusted verdicts as their own dedicated absolute findings independent of
# whatever PathTrust-driven Tier the original finding already received. This
# module re-enumerates both surfaces from scratch (so it also works when
# invoked standalone via -Modules FullSignaturePass, without Services/
# ScheduledTasks having run first) and does exactly that.
function Get-FullSignatureSweepPersistence {
    $statusCounts = @{}
    $targets = New-Object System.Collections.Generic.List[object]

    $servicesKey = Get-RegistryKeySafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services'
    if ($servicesKey) {
        foreach ($childName in $servicesKey.GetSubKeyNames()) {
            $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$childName"
            $svcKey = Get-RegistryKeySafe -Path $svcPath
            if (-not $svcKey) { continue }
            $imagePath = $svcKey.GetValue('ImagePath')
            if (-not $imagePath) { continue }

            $resolved = Resolve-CommandLineTarget -CommandLine ([string]$imagePath)
            if ($resolved) { $resolved = [System.Environment]::ExpandEnvironmentVariables($resolved) }
            if (-not $resolved) { continue }

            $targets.Add([PSCustomObject]@{
                Location = $svcPath; ValueName = "$childName (ImagePath)"; RawValue = [string]$imagePath
                Target = $resolved; LastWriteUtc = (Get-RegKeyLastWriteTimeUtc -Key $svcKey); SourceModule = 'Services'
            })
        }
    }

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($task in $tasks) {
            $taskFullPath = $task.TaskPath.TrimEnd('\') + '\' + $task.TaskName
            if (-not $taskFullPath.StartsWith('\')) { $taskFullPath = "\$taskFullPath" }
            foreach ($action in $task.Actions) {
                if (-not $action.Execute) { continue }
                $line = $action.Execute
                if ($action.Arguments) { $line = "$line $($action.Arguments)" }

                $resolved = Resolve-CommandLineTarget -CommandLine $line
                if ($resolved) { $resolved = [System.Environment]::ExpandEnvironmentVariables($resolved) }
                if (-not $resolved) { continue }

                $targets.Add([PSCustomObject]@{
                    Location = $taskFullPath; ValueName = "$($task.TaskName) (Action)"; RawValue = $line
                    Target = $resolved; LastWriteUtc = $null; SourceModule = 'ScheduledTasks'
                })
            }
        }
    } catch {
        $script:UnreadableTargets.Add(@{ Target = 'Get-ScheduledTask (Task Scheduler service)'; Reason = $_.Exception.Message })
    }

    foreach ($t in $targets) {
        $verdict = Get-AuthenticodeVerdict -Path $t.Target
        $status = $verdict.Status
        if (-not $statusCounts.ContainsKey($status)) { $statusCounts[$status] = 0 }
        $statusCounts[$status]++

        $extraEvidence = @()
        $absolute = $null
        if ($status -eq 'HashMismatch') {
            $extraEvidence += 'FULLSIG-HASHMISMATCH-CONFIRMED'
            $absolute = 'HIGH'
        } elseif ($status -eq 'NotTrusted') {
            $extraEvidence += 'FULLSIG-NOTTRUSTED-CONFIRMED'
            $absolute = 'NOTABLE'
        }

        $params = @{
            Module = 'Full Authenticode Re-verification Pass'; Token = 'FullSignaturePass'; Technique = 'Unmapped'
            Location = $t.Location; ValueName = "$($t.ValueName) [source: $($t.SourceModule)]"
            RawValue = $t.RawValue; TargetPath = $t.Target; LastWriteUtc = $t.LastWriteUtc; ExtraEvidence = $extraEvidence
        }
        if ($absolute) { $params['Absolute'] = $absolute }
        Add-FileTargetFinding @params
    }

    $distribution = ($statusCounts.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
    if (-not $distribution) { $distribution = '(no resolvable binaries found across Services/ScheduledTasks)' }
    Add-Finding -Module 'Full Authenticode Re-verification Pass' -Token 'FullSignaturePass' -Technique 'Unmapped' `
        -Location '(summary)' -ValueName 'SignatureStatusDistribution (Services + ScheduledTasks)' -RawValue $distribution -Evidence @()
}

# ---------------------------------------------------------------------------
# 3. Office Add-ins (WLL/VSTO/COM) -- T1137.006
# ---------------------------------------------------------------------------

# Reads one App\Addins key (either shape below) and evaluates every ProgID
# subkey with a non-zero LoadBehavior.
function Read-OfficeAddinsAppKey {
    param(
        [Parameter(Mandatory = $true)][string]$AddinsPath,
        [Parameter(Mandatory = $true)][string]$ClassesRoot,
        [Parameter(Mandatory = $true)][string]$SourceLabel
    )

    $addinsKey = Get-RegistryKeySafe -Path $AddinsPath
    if (-not $addinsKey) { return }

    foreach ($progId in $addinsKey.GetSubKeyNames()) {
        $progIdPath = "$AddinsPath\$progId"
        $progIdKey = Get-RegistryKeySafe -Path $progIdPath
        if (-not $progIdKey) { continue }

        $loadBehavior = $progIdKey.GetValue('LoadBehavior')
        if ($null -eq $loadBehavior -or $loadBehavior -eq 0) { continue }
        $lastWrite = Get-RegKeyLastWriteTimeUtc -Key $progIdKey

        $clsid = Resolve-ProgIdToClsid -ProgId $progId -ClassesRoot $ClassesRoot
        $resolved = $null
        if ($clsid) { $resolved = Resolve-ClsidToDll -Clsid $clsid -ClassesRoot $ClassesRoot }

        # LoadBehavior=3 ("load at startup") is the common, higher-signal
        # bitmask value; any other non-zero value is still inventoried since
        # it is still worth an analyst's attention (e.g. 9 = load on demand +
        # first-time load, 2 = loaded but connected).
        $extraEvidence = @()
        if ($loadBehavior -eq 3) { $extraEvidence += 'OFFICEADDIN-LOADBEHAVIOR-3' }

        $valueLabel = "$progId LoadBehavior=$loadBehavior [$SourceLabel]"

        if ($resolved -and $resolved.Path) {
            Add-FileTargetFinding -Module 'Office Add-ins (WLL/VSTO/COM)' -Token 'OfficeAddins' -Technique 'T1137.006' `
                -Location $resolved.KeyPath -ValueName $valueLabel -RawValue $resolved.RawValue `
                -TargetPath $resolved.Path -LastWriteUtc $lastWrite -ExtraEvidence $extraEvidence
        } else {
            # Either no CLSID could be resolved for this ProgID, or the CLSID
            # has no InprocServer32/LocalServer32 -- a non-zero-LoadBehavior
            # add-in with an unresolvable target is a dangling registration
            # worth flagging, distinct from ComFull's silent skip (there,
            # most CLSIDs legitimately have no server at all; here, a
            # LoadBehavior entry implies one SHOULD exist). Both sub-cases are
            # "unresolvable target" per the comment above, so both get
            # PATH-DANGLING/DoesNotExist -- previously only the "CLSID
            # resolved but had no server" sub-case was tagged, silently
            # under-scoring the more severe "ProgID has no CLSID at all" case.
            if ($extraEvidence -notcontains 'PATH-DANGLING') { $extraEvidence += 'PATH-DANGLING' }
            $pathTrust = 'DoesNotExist'
            Add-Finding -Module 'Office Add-ins (WLL/VSTO/COM)' -Token 'OfficeAddins' -Technique 'T1137.006' `
                -Location $progIdPath -ValueName $valueLabel -RawValue $clsid -PathTrust $pathTrust `
                -LastWriteUtc $lastWrite -Evidence $extraEvidence
        }
    }
}

# Walks both real-world Office add-in registration shapes for one Office
# root + Classes root pair: version-specific (Office\<version>\<App>\Addins)
# and version-agnostic (Office\<App>\Addins). Mirrors
# Get-OfficeTrustedLocationPersistence's "walk whatever version subkeys
# actually exist" pattern rather than hardcoding a version number.
function Read-OfficeAddinTree {
    param(
        [Parameter(Mandatory = $true)][string]$OfficeRoot,
        [Parameter(Mandatory = $true)][string[]]$AppNames,
        [Parameter(Mandatory = $true)][string]$ClassesRoot,
        [Parameter(Mandatory = $true)][string]$SourceLabel
    )

    $officeKey = Get-RegistryKeySafe -Path $OfficeRoot
    if (-not $officeKey) { return }

    foreach ($app in $AppNames) {
        Read-OfficeAddinsAppKey -AddinsPath "$OfficeRoot\$app\Addins" -ClassesRoot $ClassesRoot -SourceLabel $SourceLabel
    }
    foreach ($verName in $officeKey.GetSubKeyNames()) {
        foreach ($app in $AppNames) {
            Read-OfficeAddinsAppKey -AddinsPath "$OfficeRoot\$verName\$app\Addins" -ClassesRoot $ClassesRoot -SourceLabel $SourceLabel
        }
    }
}

function Get-OfficeAddinPersistence {
    $appNames = @('Word', 'Excel', 'PowerPoint', 'Access', 'Outlook', 'Publisher', 'Visio', 'Project', 'OneNote')

    foreach ($h in (Get-HiveRootsForPerUserCheck)) {
        $classesInfo = Get-ClassesRootForHive -HiveRootInfo $h
        Read-OfficeAddinTree -OfficeRoot "$($h.Root)\Software\Microsoft\Office" -AppNames $appNames `
            -ClassesRoot $classesInfo.ClassesRoot -SourceLabel $classesInfo.SourceLabel
    }

    Read-OfficeAddinTree -OfficeRoot 'HKLM:\SOFTWARE\Microsoft\Office' -AppNames $appNames `
        -ClassesRoot 'HKLM:\SOFTWARE\Classes' -SourceLabel 'HKLM'
    Read-OfficeAddinTree -OfficeRoot 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office' -AppNames $appNames `
        -ClassesRoot 'HKLM:\SOFTWARE\Classes' -SourceLabel 'HKLM (WOW6432Node)'
}

# ---------------------------------------------------------------------------
# 4. Outlook Home Page / FormRegions -- T1137.004 / T1137.003
# ---------------------------------------------------------------------------

# CONFIDENCE NOTE (honest, not asserted certainty): the exact modern
# (Outlook 2016+/365) registry layout for Home Page and FormRegions
# persistence was not confidently verifiable while building this module.
# What's implemented below is a narrower, honestly-scoped best-effort rather
# than a claim of exhaustive/version-accurate coverage:
#   - Home Page: the historically-documented per-folder WebView shape
#     (...\Outlook\WebView\<FolderName>\URL). This enumerates whatever
#     WebView\* subkeys actually exist under each Office version found and
#     reports any URL value present, without asserting this is exhaustive
#     for every Outlook version/folder-naming scheme.
#   - FormRegions: enumerates whatever subkeys exist under
#     ...\Outlook\FormRegions and reports ALL of their values verbatim,
#     generically -- specific value names for this key (e.g. a manifest
#     location) are not asserted with confidence, so nothing is guessed;
#     every value name/data pair found is simply surfaced for the analyst.
# Catalog Attack for the Outlook token is the single value 'T1137.004'
# (Home Page); FormRegions findings are tagged with the more specific
# 'T1137.003' sub-technique per-finding, per this module's own build spec.
function Get-OutlookPersistence {
    foreach ($h in (Get-HiveRootsForPerUserCheck)) {
        $officeRoot = "$($h.Root)\Software\Microsoft\Office"
        $officeKey = Get-RegistryKeySafe -Path $officeRoot
        if (-not $officeKey) { continue }

        foreach ($verName in $officeKey.GetSubKeyNames()) {
            $webViewRoot = "$officeRoot\$verName\Outlook\WebView"
            $webViewKey = Get-RegistryKeySafe -Path $webViewRoot
            if ($webViewKey) {
                foreach ($folderName in $webViewKey.GetSubKeyNames()) {
                    $folderPath = "$webViewRoot\$folderName"
                    $folderKey = Get-RegistryKeySafe -Path $folderPath
                    if (-not $folderKey) { continue }
                    $url = $folderKey.GetValue('URL')
                    if (-not $url) { continue }
                    $folderLastWrite = Get-RegKeyLastWriteTimeUtc -Key $folderKey

                    Add-Finding -Module 'Outlook Home Page / Registry-Visible Config' -Token 'Outlook' -Technique 'T1137.004' `
                        -Location $folderPath -ValueName "WebView\$folderName\URL" -RawValue ([string]$url) `
                        -LastWriteUtc $folderLastWrite -Evidence @('OUTLOOK-WEBVIEW-HOMEPAGE-SET')
                }
            }

            $formRegionsRoot = "$officeRoot\$verName\Outlook\FormRegions"
            $formRegionsKey = Get-RegistryKeySafe -Path $formRegionsRoot
            if ($formRegionsKey) {
                foreach ($regionName in $formRegionsKey.GetSubKeyNames()) {
                    $regionPath = "$formRegionsRoot\$regionName"
                    $regionKey = Get-RegistryKeySafe -Path $regionPath
                    if (-not $regionKey) { continue }
                    $regionLastWrite = Get-RegKeyLastWriteTimeUtc -Key $regionKey

                    $valuePairs = New-Object System.Collections.Generic.List[string]
                    foreach ($vn in $regionKey.GetValueNames()) {
                        $vv = $regionKey.GetValue($vn)
                        if ($null -eq $vv) { continue }
                        $displayName = $vn
                        if (-not $displayName) { $displayName = '(Default)' }
                        $valuePairs.Add("$displayName=$vv")
                    }
                    $raw = ($valuePairs -join '; ')

                    Add-Finding -Module 'Outlook Home Page / Registry-Visible Config' -Token 'Outlook' -Technique 'T1137.003' `
                        -Location $regionPath -ValueName "FormRegions\$regionName" -RawValue $raw `
                        -LastWriteUtc $regionLastWrite -Evidence @('OUTLOOK-FORMREGION-REGISTERED')
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 5. SYSVOL GPO Scripts/Preferences Tampering -- T1037.003
#
# CORRECTION: this module's findings were previously tagged T1037.001, which
# is specifically the HKCU\Environment\UserInitMprLogonScript registry-value
# technique -- a different, local-only mechanism this module does not touch.
# What this module actually reads (SYSVOL\<domain>\Policies\{GUID}\Machine|
# User\Scripts\{Startup,Shutdown,Logon,Logoff} and scripts.ini) is GPO-
# assigned logon/startup scripts distributed via NETLOGON/SYSVOL, which is
# T1037.003 "Network Logon Script".
# ---------------------------------------------------------------------------

# The SYSVOL source-of-truth counterpart to Get-BootLogonScriptPersistence's
# local-GPO-cache check. Gated on domain-joined (re-queries
# Win32_ComputerSystem locally rather than assuming a script-scoped value
# from Write-HostTriage is present, since that function only prints to the
# console and does not stash its result). Degrades gracefully and quickly on
# a non-domain host, an unreachable DC, or access denied -- every filesystem
# call here is try/catch-wrapped and failures are logged to
# $script:UnreadableTargets rather than allowed to propagate; relies on
# Windows' own SMB/UNC connection-attempt timeout (not an infinite hang) to
# bound an unreachable-but-not-actively-refused path, no additional custom
# timeout machinery is layered on top, per the build spec's own
# "reasonably short IMPLICIT tolerance for failure" -- deliberately not
# "add artificial limits" on the actual GPO enumeration itself once SYSVOL
# is reachable, since that can legitimately be slow/large on a real domain.
function Get-SysvolGpoPersistence {
    $cs = $null
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    } catch {
        $script:UnreadableTargets.Add(@{ Target = 'Win32_ComputerSystem (domain-joined check for SysvolGpo)'; Reason = $_.Exception.Message })
        return
    }
    if (-not $cs -or -not $cs.PartOfDomain -or -not $cs.Domain) {
        # Not domain-joined (or couldn't confirm) -- SYSVOL is not applicable.
        # Correct, expected state on a workgroup host, not an error.
        return
    }

    $domain = $cs.Domain
    $sysvolPoliciesRoot = "\\$domain\SYSVOL\$domain\Policies"

    $policyFolders = $null
    try {
        $policyFolders = Get-ChildItem -LiteralPath $sysvolPoliciesRoot -Directory -ErrorAction Stop
    } catch {
        $script:UnreadableTargets.Add(@{ Target = $sysvolPoliciesRoot; Reason = $_.Exception.Message })
        return
    }

    foreach ($gpoFolder in $policyFolders) {
        $gpoGuid = $gpoFolder.Name

        foreach ($scopeInfo in @(
            [PSCustomObject]@{ ScriptsSub = 'Machine\Scripts'; SubDirs = @('Startup', 'Shutdown') }
            [PSCustomObject]@{ ScriptsSub = 'User\Scripts';    SubDirs = @('Logon', 'Logoff') }
        )) {
            $scriptsBase = Join-Path $gpoFolder.FullName $scopeInfo.ScriptsSub
            $iniPath = Join-Path $scriptsBase 'scripts.ini'
            try {
                if (Test-Path -LiteralPath $iniPath -PathType Leaf -ErrorAction Stop) {
                    $item = Get-Item -LiteralPath $iniPath -ErrorAction Stop
                    Add-Finding -Module 'SYSVOL GPO Scripts/Preferences Tampering' -Token 'SysvolGpo' -Technique 'T1037.003' `
                        -Location $iniPath -ValueName "GPO {$gpoGuid}" -RawValue $iniPath -LastWriteUtc $item.LastWriteTimeUtc -Evidence @()
                }
            } catch {
                $script:UnreadableTargets.Add(@{ Target = $iniPath; Reason = $_.Exception.Message })
            }

            foreach ($sub in $scopeInfo.SubDirs) {
                $dir = Join-Path $scriptsBase $sub
                try {
                    $files = Get-ChildItem -LiteralPath $dir -File -Recurse -ErrorAction Stop
                    foreach ($f in $files) {
                        Add-FileTargetFinding -Module 'SYSVOL GPO Scripts/Preferences Tampering' -Token 'SysvolGpo' -Technique 'T1037.003' `
                            -Location $dir -ValueName "GPO {$gpoGuid} :: $($f.Name)" -RawValue $f.FullName -TargetPath $f.FullName -LastWriteUtc $f.LastWriteTimeUtc
                    }
                } catch {
                    if ($_.CategoryInfo.Category -ne 'ObjectNotFound') {
                        $script:UnreadableTargets.Add(@{ Target = $dir; Reason = $_.Exception.Message })
                    }
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 6. Winsock Layered Service Provider (LSP) Hijack -- Unmapped
# ---------------------------------------------------------------------------

# `netsh winsock show catalog` is a query-only read verb (never reset/add/
# set/delete -- see this file's safety contract). Output format is not a
# stable, documented contract, so parsing is a defensive regex over any line
# containing a plausible DLL path rather than a strict fixed-column parser.
function Get-WinsockLspPersistence {
    $output = $null
    try {
        $output = & netsh.exe winsock show catalog 2>&1
    } catch {
        $script:UnreadableTargets.Add(@{ Target = 'netsh.exe winsock show catalog'; Reason = $_.Exception.Message })
        return
    }
    if (-not $output) {
        $script:UnreadableTargets.Add(@{ Target = 'netsh.exe winsock show catalog'; Reason = 'no output returned (netsh.exe likely unavailable on this host/OS)' })
        return
    }

    $outputText = ($output | Out-String)
    $dllPathPattern = '([A-Za-z]:\\[^\r\n]*?\.dll|%[A-Za-z0-9_]+%[^\r\n]*?\.dll)'
    $dllMatches = $null
    try {
        $dllMatches = [Text.RegularExpressions.Regex]::Matches($outputText, $dllPathPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    } catch {
        $dllMatches = $null
    }

    if (-not $dllMatches -or $dllMatches.Count -eq 0) {
        $script:UnreadableTargets.Add(@{ Target = 'netsh.exe winsock show catalog (parse)'; Reason = 'output returned but no Provider Path-shaped .dll entries were found by the parser' })
        Add-Finding -Module 'Winsock Layered Service Provider (LSP) Hijack' -Token 'WinsockLsp' -Technique 'Unmapped' `
            -Location 'netsh.exe winsock show catalog' -ValueName $null `
            -RawValue $outputText.Substring(0, [Math]::Min(500, $outputText.Length)) -Evidence @()
        return
    }

    $seen = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    $entryNum = 0
    foreach ($m in $dllMatches) {
        $entryNum++
        $rawPath = $m.Groups[1].Value.Trim()
        if (-not $seen.Add($rawPath)) { continue }
        $expanded = [System.Environment]::ExpandEnvironmentVariables($rawPath)

        Add-FileTargetFinding -Module 'Winsock Layered Service Provider (LSP) Hijack' -Token 'WinsockLsp' -Technique 'Unmapped' `
            -Location 'netsh.exe winsock show catalog' -ValueName "Provider Path (catalog entry #$entryNum)" -RawValue $rawPath -TargetPath $expanded
    }
}

# ---------------------------------------------------------------------------
# 7. BITS Jobs -- T1197
# ---------------------------------------------------------------------------

# Get-BitsTransfer is a read-only query cmdlet from the built-in (but
# optional-on-some-SKUs) BitsTransfer module. Both the module-import and the
# cmdlet call are try/catch-wrapped independently so either failure degrades
# to "module/feature unavailable" in the coverage report rather than a crash.
function Get-BitsJobPersistence {
    try {
        Import-Module BitsTransfer -ErrorAction Stop
    } catch {
        $script:UnreadableTargets.Add(@{ Target = 'BitsTransfer module'; Reason = "module unavailable -- $($_.Exception.Message)" })
        return
    }

    $jobs = $null
    try {
        $jobs = Get-BitsTransfer -AllUsers -ErrorAction Stop
    } catch {
        $script:UnreadableTargets.Add(@{ Target = 'Get-BitsTransfer -AllUsers'; Reason = $_.Exception.Message })
        return
    }
    if (-not $jobs) { return }

    foreach ($job in $jobs) {
        # Inventory the job itself regardless of NotifyCmdLine presence -- a
        # BITS job quietly downloading to a suspicious path is worth
        # surfacing even with no notify command configured. BITS jobs don't
        # expose a registry-key-style last-write time, so LastWriteUtc is
        # left $null rather than asserting a misleading value.
        Add-Finding -Module 'BITS Jobs' -Token 'BitsJobs' -Technique 'T1197' `
            -Location "BITS job $($job.JobId)" -ValueName $job.DisplayName `
            -RawValue "State=$($job.JobState) | Owner=$($job.OwnerAccount) | TransferType=$($job.TransferType)" -Evidence @()

        if ($job.PSObject.Properties.Match('NotifyCmdLine').Count -gt 0) {
            $notify = $job.NotifyCmdLine
            if ($notify -and ([string]$notify).Trim()) {
                Add-CommandLineFinding -Module 'BITS Jobs' -Token 'BitsJobs' -Technique 'T1197' `
                    -Location "BITS job $($job.JobId)" -ValueName 'NotifyCmdLine' -RawValue ([string]$notify) `
                    -ExtraEvidence @('BITS-NOTIFYCMDLINE-SET')
            }
        } else {
            # Documented limitation, not a silently-skipped check: some
            # PowerShell/BitsTransfer module versions don't expose
            # NotifyCmdLine as a property on the job object at all.
            $script:UnreadableTargets.Add(@{ Target = "BITS job $($job.JobId) NotifyCmdLine"; Reason = 'NotifyCmdLine property not exposed by Get-BitsTransfer on this PowerShell/module version' })
        }
    }
}

# ---------------------------------------------------------------------------
# 8. Credential Provider / Password Filter DLL -- Unmapped (T1556-adjacent)
# ---------------------------------------------------------------------------

function Get-CredentialProviderPersistence {
    Read-ClsidKeyListPersistence -RootPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers' `
        -Module 'Credential Provider / Password Filter DLL' -Token 'CredentialProviders' -Technique 'Unmapped' `
        -ClassesRoot 'HKLM:\SOFTWARE\Classes' -ReadDisplayName
}

# ---------------------------------------------------------------------------
# 9. Browser Helper Objects -- Unmapped (legacy, low modern prevalence -- IE
#    itself is EOL, but the registration point is still a real, checkable
#    location on any host that still has the key)
# ---------------------------------------------------------------------------

function Get-BhoPersistence {
    Read-ClsidKeyListPersistence -RootPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects' `
        -Module 'Browser Helper Objects (Internet Explorer, legacy)' -Token 'BHO' -Technique 'Unmapped' -ClassesRoot 'HKLM:\SOFTWARE\Classes'
    Read-ClsidKeyListPersistence -RootPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects' `
        -Module 'Browser Helper Objects (Internet Explorer, legacy)' -Token 'BHO' -Technique 'Unmapped' -ClassesRoot 'HKLM:\SOFTWARE\Classes'
}

# ---------------------------------------------------------------------------
# 10. Shell Extension Handlers (shellex CLSID) -- Unmapped
# ---------------------------------------------------------------------------

function Get-ShellExtensionPersistence {
    # ContextMenuHandlers -- HKLM:\SOFTWARE\Classes\<root>\shellex\ContextMenuHandlers\<HandlerName>
    # has (Default) = CLSID (a handler-name-keyed list, NOT CLSID-keyed, so
    # Read-ClsidKeyListPersistence's shape doesn't fit here -- walked
    # directly). SCOPING NOTE: HKLM:\SOFTWARE\Classes\* has one subkey per
    # registered ProgID/extension (thousands on a real host) -- rather than
    # walking all of them, this checks only the handful of well-known roots
    # context-menu handlers are conventionally registered against, per the
    # build spec's explicit scoping choice. This is a deliberately narrower
    # sweep than ComFull's unrestricted CLSID enumeration.
    $contextMenuRoots = @('*', 'Directory', 'Folder', 'AllFilesystemObjects')
    foreach ($root in $contextMenuRoots) {
        $handlersPath = "HKLM:\SOFTWARE\Classes\$root\shellex\ContextMenuHandlers"
        $handlersKey = Get-RegistryKeySafe -Path $handlersPath
        if (-not $handlersKey) { continue }

        foreach ($handlerName in $handlersKey.GetSubKeyNames()) {
            $handlerPath = "$handlersPath\$handlerName"
            $handlerKey = Get-RegistryKeySafe -Path $handlerPath
            if (-not $handlerKey) { continue }
            $clsid = $handlerKey.GetValue('')
            if (-not $clsid) { continue }
            $clsidStr = [string]$clsid

            $resolved = Resolve-ClsidToDll -Clsid $clsidStr -ClassesRoot 'HKLM:\SOFTWARE\Classes'
            if (-not $resolved.Path) {
                Add-Finding -Module 'Shell Extension Handlers (shellex CLSID)' -Token 'ShellExt' -Technique 'Unmapped' `
                    -Location $handlerPath -ValueName "ContextMenuHandlers\$handlerName [root=$root]" -RawValue $clsidStr `
                    -PathTrust 'DoesNotExist' -Evidence @('PATH-DANGLING')
                continue
            }
            Add-FileTargetFinding -Module 'Shell Extension Handlers (shellex CLSID)' -Token 'ShellExt' -Technique 'Unmapped' `
                -Location $resolved.KeyPath -ValueName "ContextMenuHandlers\$handlerName [root=$root]" -RawValue $resolved.RawValue `
                -TargetPath $resolved.Path -LastWriteUtc $resolved.LastWriteUtc
        }
    }

    # ShellIconOverlayIdentifiers -- same (Default)=CLSID shape, one fixed location.
    $overlayPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'
    $overlayKey = Get-RegistryKeySafe -Path $overlayPath
    if ($overlayKey) {
        foreach ($idName in $overlayKey.GetSubKeyNames()) {
            $idPath = "$overlayPath\$idName"
            $idKey = Get-RegistryKeySafe -Path $idPath
            if (-not $idKey) { continue }
            $clsid = $idKey.GetValue('')
            if (-not $clsid) { continue }
            $clsidStr = [string]$clsid

            $resolved = Resolve-ClsidToDll -Clsid $clsidStr -ClassesRoot 'HKLM:\SOFTWARE\Classes'
            if (-not $resolved.Path) {
                Add-Finding -Module 'Shell Extension Handlers (shellex CLSID)' -Token 'ShellExt' -Technique 'Unmapped' `
                    -Location $idPath -ValueName "ShellIconOverlayIdentifiers\$idName" -RawValue $clsidStr `
                    -PathTrust 'DoesNotExist' -Evidence @('PATH-DANGLING')
                continue
            }
            Add-FileTargetFinding -Module 'Shell Extension Handlers (shellex CLSID)' -Token 'ShellExt' -Technique 'Unmapped' `
                -Location $resolved.KeyPath -ValueName "ShellIconOverlayIdentifiers\$idName" -RawValue $resolved.RawValue `
                -TargetPath $resolved.Path -LastWriteUtc $resolved.LastWriteUtc
        }
    }

    # Shell Extensions\Approved -- CONTEXT ONLY. A flat VALUE list (value
    # NAME = CLSID, value DATA = friendly name), not a subkey list --
    # cross-reference material for an analyst, NOT an enforcement boundary:
    # a CLSID's absence from this list is NOT itself evidence of anything
    # (many legitimate shell extensions on modern Windows are never
    # "Approved"-listed at all; this mechanism is largely a legacy/back-compat
    # holdover). Reported with a zero-weight context tag, never scored.
    $approvedPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved'
    $approvedKey = Get-RegistryKeySafe -Path $approvedPath
    if ($approvedKey) {
        $approvedLastWrite = Get-RegKeyLastWriteTimeUtc -Key $approvedKey
        foreach ($clsidValueName in $approvedKey.GetValueNames()) {
            $friendlyName = $approvedKey.GetValue($clsidValueName)
            Add-Finding -Module 'Shell Extension Handlers (shellex CLSID)' -Token 'ShellExt' -Technique 'Unmapped' `
                -Location $approvedPath -ValueName $clsidValueName -RawValue ([string]$friendlyName) `
                -LastWriteUtc $approvedLastWrite -Evidence @('SHELLEXT-APPROVED-LIST-CONTEXT-ONLY')
        }
    }
}

#endregion Deep-Tier Modules (Pass D)


# ===========================================================================
#  Banner + host-triage preamble
# ===========================================================================

function Write-Banner {
    param(
        [bool]$IsElevated,
        [string]$CommandLine
    )

    $runTime  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
    $hostName = $env:COMPUTERNAME

    Write-Output ''
    Write-Output "$ScriptName  v$ScriptVersion    author: $ScriptAuthor"
    Write-Output "Ran at   : $runTime"
    Write-Output "Hostname : $hostName"
    Write-Output "Command  : $CommandLine"

    if (-not $IsElevated) {
        Write-Output ''
        Write-Output '!! WARNING: not running elevated. Other users'' registry hives, protected'
        Write-Output '!! service configuration, and some LSA-related keys typically require'
        Write-Output '!! Administrator to read. This run will note any inaccessible target in the'
        Write-Output '!! coverage report below rather than fail. Re-run elevated for full coverage.'
    }
    Write-Output ''
}

function Write-HostTriage {
    param([bool]$IsElevated)

    Write-Output '=== Host Triage ==='

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        Write-Output ("OS         : {0} (Build {1}, {2})" -f $os.Caption, $os.BuildNumber, $os.OSArchitecture)
    } catch {
        Write-Output "OS         : could not query Win32_OperatingSystem ($($_.Exception.Message))"
    }

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs.PartOfDomain) {
            Write-Output "Domain     : joined - $($cs.Domain)"
        } else {
            Write-Output "Domain     : workgroup - $($cs.Workgroup)"
        }
    } catch {
        Write-Output "Domain     : could not query Win32_ComputerSystem ($($_.Exception.Message))"
    }

    if ($IsElevated) {
        Write-Output 'Elevation  : running as Administrator'
    } else {
        Write-Output 'Elevation  : NOT elevated - some checks will be degraded (see coverage report)'
    }

    # An erroring or empty AntiVirusProduct query is NOT evidence of "no AV
    # installed" -- root\SecurityCenter2 is absent on Server SKUs and can be
    # unavailable for other reasons. Never collapse "could not determine"
    # into "none present".
    try {
        $av = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
        if ($av) {
            $names = ($av | ForEach-Object { $_.displayName }) -join ', '
            Write-Output "AV/EDR     : $names"
        } else {
            Write-Output 'AV/EDR     : not available (Server SKU or namespace absent) -- not evidence of no AV installed'
        }
    } catch {
        Write-Output 'AV/EDR     : not available (Server SKU or namespace absent) -- not evidence of no AV installed'
    }

    $sysmonSvc = $null
    try { $sysmonSvc = Get-Service -Name Sysmon, Sysmon64 -ErrorAction SilentlyContinue } catch { $sysmonSvc = $null }

    $sysmonLogPresent = $false
    try {
        $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue
        if ($logs | Where-Object { $_.LogName -eq 'Microsoft-Windows-Sysmon/Operational' }) { $sysmonLogPresent = $true }
    } catch {
        $sysmonLogPresent = $false
    }

    if ($sysmonSvc) {
        $svcNames = ($sysmonSvc | ForEach-Object { "$($_.Name) ($($_.Status))" }) -join ', '
        Write-Output "Sysmon     : service present - $svcNames"
    } elseif ($sysmonLogPresent) {
        Write-Output 'Sysmon     : service not found, but Sysmon operational log is present'
    } else {
        Write-Output 'Sysmon     : not detected (no service, no operational log)'
    }

    Write-Output ''
}

# ===========================================================================
#  Rendering scaffolding
# ===========================================================================

# Prints the always-shown full inventory: one compact line per finding,
# grouped and headed by Module. Skipped (with a note) if -AnomaliesOnly.
function Write-InventoryLine {
    Write-Output '=== Full Inventory ==='

    if ($AnomaliesOnly) {
        Write-Output '(skipped -- -AnomaliesOnly was given; see ANOMALY QUEUE below)'
        Write-Output ''
        return
    }

    if ($script:AllFindings.Count -eq 0) {
        Write-Output '(no findings recorded -- see coverage report for which modules ran)'
        Write-Output ''
        return
    }

    $grouped = $script:AllFindings | Group-Object -Property Module | Sort-Object Name
    foreach ($g in $grouped) {
        Write-Output "-- $($g.Name) --"
        foreach ($f in ($g.Group | Sort-Object Location)) {
            $target = $f.ResolvedTarget
            if (-not $target) { $target = $f.RawValue }
            $lastWrite = 'unknown'
            if ($f.LastWriteUtc) { $lastWrite = $f.LastWriteUtc.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' }
            Write-Output ("  {0} | {1} | {2} | {3} | {4}" -f $f.Location, $target, $f.PathTrust, $f.SignatureStatus, $lastWrite)
        }
    }
    Write-Output ''
}

# Prints full multi-line detail blocks for findings whose Tier meets or
# exceeds -MinSeverity, plus a tally by tier and by module. Skipped (with a
# note) if -InventoryOnly.
function Write-AnomalyQueue {
    Write-Output '=== Anomaly Queue ==='

    if ($InventoryOnly) {
        Write-Output '(skipped -- -InventoryOnly was given; see Full Inventory above)'
        Write-Output ''
        return
    }

    $rank = @{ 'LOW' = 1; 'NOTABLE' = 2; 'HIGH' = 3 }

    # LOW-tier findings are inventory-only and are never queued. 'Low' and
    # 'Notable' both surface NOTABLE-and-above; 'High' surfaces HIGH only.
    $minRank = 2
    if ($MinSeverity -eq 'High') { $minRank = 3 }

    $queued = $script:AllFindings |
        Where-Object { $rank[$_.Tier] -ge $minRank } |
        Sort-Object -Property @{ Expression = { $rank[$_.Tier] }; Descending = $true }, Module

    if (-not $queued -or ($queued | Measure-Object).Count -eq 0) {
        Write-Output '(no findings met the NOTABLE/HIGH evidence threshold at the current -MinSeverity)'
        Write-Output ''
        return
    }

    foreach ($f in $queued) {
        Write-Output '------------------------------------------------------------'
        Write-Output ("[{0}] {1} ({2})" -f $f.Tier, $f.Module, $f.Technique)
        Write-Output ("Location   : {0}" -f $f.Location)
        Write-Output ("ValueName  : {0}" -f $f.ValueName)
        Write-Output ("RawValue   : {0}" -f $f.RawValue)
        Write-Output ("Target     : {0}" -f $f.ResolvedTarget)
        Write-Output ("PathTrust  : {0}" -f $f.PathTrust)
        Write-Output ("Signature  : {0} ({1})" -f $f.SignatureStatus, $f.SignaturePublisher)
        $lastWrite = 'unknown'
        if ($f.LastWriteUtc) { $lastWrite = $f.LastWriteUtc.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' }
        Write-Output ("LastWrite  : {0}" -f $lastWrite)
        Write-Output ("Score      : {0}  (Absolute override: {1})" -f $f.Score, $f.IsAbsolute)
        Write-Output ("Evidence   : {0}" -f ($f.Evidence -join ', '))
        Write-Output ''
    }
    Write-Output '------------------------------------------------------------'
    Write-Output ''

    Write-Output 'Tally by tier:'
    foreach ($t in 'HIGH', 'NOTABLE', 'LOW') {
        $c = ($queued | Where-Object { $_.Tier -eq $t } | Measure-Object).Count
        Write-Output ("  {0} : {1}" -f $t, $c)
    }
    Write-Output ''

    Write-Output 'Tally by module:'
    $byModule = $queued | Group-Object -Property Module | Sort-Object Name
    foreach ($m in $byModule) {
        Write-Output ("  {0} : {1}" -f $m.Name, $m.Count)
    }
    Write-Output ''
}

# Always printed, regardless of -InventoryOnly/-AnomaliesOnly: which modules
# ran vs. were skipped and why, unreadable targets, per-user hive coverage,
# elevation recap.
function Write-CoverageReport {
    Write-Output '=== Coverage Report ==='

    $totalModules = $script:ModuleCatalog.Count
    $ranCount     = $script:ResolvedModules.Count
    $implementedCount = $ranCount - $script:NotYetImplemented.Count

    Write-Output ("Modules in catalog          : {0}" -f $totalModules)
    Write-Output ("Modules selected this run   : {0}" -f $ranCount)
    Write-Output ("  - implemented & executed  : {0}" -f $implementedCount)
    Write-Output ("  - not yet implemented     : {0}  (should always be 0 post-Pass-D; nonzero here means a catalog FunctionName/actual-function mismatch -- see source)" -f $script:NotYetImplemented.Count)
    foreach ($m in $script:NotYetImplemented) {
        Write-Output ("      - {0} ({1})" -f $m.Token, $m.FunctionName)
    }
    Write-Output ("Skipped by -Modules scope   : {0}" -f $script:SkippedByScope.Count)
    foreach ($m in $script:SkippedByScope) {
        Write-Output ("      - {0}" -f $m.Token)
    }
    Write-Output ("Skipped, deep-tier w/o -Deep: {0}" -f $script:SkippedDeepTier.Count)
    foreach ($m in $script:SkippedDeepTier) {
        Write-Output ("      - {0}" -f $m.Token)
    }

    Write-Output ''
    if ($script:IsElevated) {
        Write-Output 'Elevation                   : Administrator'
    } else {
        Write-Output 'Elevation                   : NOT elevated -- registry/service checks requiring privileged access were degraded'
    }

    Write-Output ''
    if ($script:UnreadableTargets.Count -gt 0) {
        Write-Output "Unreadable/inaccessible targets ($($script:UnreadableTargets.Count)):"
        foreach ($u in $script:UnreadableTargets) {
            Write-Output ("  {0} - {1}" -f $u.Target, $u.Reason)
        }
    } else {
        Write-Output 'Unreadable/inaccessible targets: none.'
    }

    Write-Output ''
    if ($script:OnDiskProfiles -and (($script:OnDiskProfiles | Measure-Object).Count -gt 0)) {
        $noHive = $script:OnDiskProfiles | Where-Object { -not $_.HiveLoaded }
        $noHiveCount = ($noHive | Measure-Object).Count
        if ($noHiveCount -gt 0) {
            Write-Output "Profiles with no loaded hive ($noHiveCount) -- registry-backed per-user checks skipped for these (reg load is explicitly out of scope):"
            foreach ($p in $noHive) {
                Write-Output ("  {0} ({1})" -f $p.ProfilePath, $p.SID)
            }
        } else {
            Write-Output 'All on-disk profiles have a loaded hive -- per-user registry coverage is complete.'
        }
    } else {
        Write-Output 'On-disk profile enumeration unavailable on this host/OS.'
    }
    Write-Output ''
}

# ===========================================================================
#  Main
# ===========================================================================

# --- -InventoryOnly / -AnomaliesOnly mutual exclusivity --------------------
if ($InventoryOnly -and $AnomaliesOnly) {
    Write-Error '-InventoryOnly and -AnomaliesOnly are mutually exclusive. Specify at most one.'
    return
}

# --- Elevation check (never hard-fails -- warn + degrade) ------------------
$script:IsElevated = $false
try {
    $currentIdentity   = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal  = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $script:IsElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $script:IsElevated = $false
}

# --- Effective command line (for the banner / a self-documenting transcript) --
$EffectiveCommandLine = $null
if ($MyInvocation.Line -and $MyInvocation.Line.Trim().Length -gt 0) {
    $EffectiveCommandLine = $MyInvocation.Line.Trim()
} else {
    $parts = @()
    foreach ($key in $PSBoundParameters.Keys) {
        $value = $PSBoundParameters[$key]
        if ($value -is [switch]) {
            if ($value.IsPresent) { $parts += "-$key" }
        } elseif ($value -is [array]) {
            $parts += "-$key " + (($value -join ','))
        } else {
            $parts += "-$key `"$value`""
        }
    }
    $EffectiveCommandLine = "$ScriptName " + ($parts -join ' ')
}

Write-Banner -IsElevated $script:IsElevated -CommandLine $EffectiveCommandLine
Write-HostTriage -IsElevated $script:IsElevated

# --- Resolve module scope ---------------------------------------------------
$script:ResolvedModules = New-Object System.Collections.Generic.List[object]
$script:SkippedByScope  = New-Object System.Collections.Generic.List[object]
$script:SkippedDeepTier = New-Object System.Collections.Generic.List[object]

if ($PSBoundParameters.ContainsKey('Modules') -and $Modules) {
    # Explicit -Modules is the exact set, regardless of tier -- naming a
    # Deep-tier token here runs it even without -Deep.
    foreach ($entry in $script:ModuleCatalog) {
        if ($Modules -contains $entry.Token) {
            $script:ResolvedModules.Add($entry)
        } else {
            $script:SkippedByScope.Add($entry)
        }
    }
} else {
    # Default: all Fast-tier modules, plus Deep-tier too if -Deep was given.
    foreach ($entry in $script:ModuleCatalog) {
        if ($entry.Tier -eq 'Fast') {
            $script:ResolvedModules.Add($entry)
        } elseif ($Deep) {
            $script:ResolvedModules.Add($entry)
        } else {
            $script:SkippedDeepTier.Add($entry)
        }
    }
}

Write-Output ("Modules selected: {0} of {1} in catalog." -f $script:ResolvedModules.Count, $script:ModuleCatalog.Count)
Write-Output ''

# --- Resolve timeframe -------------------------------------------------------
# Reuses the -Since-wins-over-Days pattern and -Until-defaults-to-now rule
# from hunt_eventlogs.ps1, but unlike that tool, timeframe scoping here is
# opt-in: $script:WindowStart/$script:WindowEnd stay $null (no incident
# window, RECENCY evidence never fires) unless -Since/-Days/-Until was
# explicitly supplied.
$TimeframeRequested = $PSBoundParameters.ContainsKey('Since') -or $PSBoundParameters.ContainsKey('Days') -or $PSBoundParameters.ContainsKey('Until')

if ($TimeframeRequested) {
    if ($PSBoundParameters.ContainsKey('Since')) {
        try {
            $script:WindowStart = (Get-Date -Date $Since -ErrorAction Stop).ToUniversalTime()
        } catch {
            Write-Error "Could not parse -Since value '$Since': $($_.Exception.Message)"
            return
        }
        if ($PSBoundParameters.ContainsKey('Days')) {
            Write-Output 'Note: both -Since and -Days were supplied; -Since wins, -Days is ignored.'
        }
    } else {
        $script:WindowStart = (Get-Date).AddDays(-$Days).ToUniversalTime()
    }

    if ($PSBoundParameters.ContainsKey('Until')) {
        try {
            $script:WindowEnd = (Get-Date -Date $Until -ErrorAction Stop).ToUniversalTime()
        } catch {
            Write-Error "Could not parse -Until value '$Until': $($_.Exception.Message)"
            return
        }
    } else {
        $script:WindowEnd = (Get-Date).ToUniversalTime()
    }

    if ($script:WindowEnd -lt $script:WindowStart) {
        Write-Error "Resolved -Until ($($script:WindowEnd)) is earlier than -Since/-Days start ($($script:WindowStart)). Check your timeframe."
        return
    }

    Write-Output ("Incident window: {0} UTC -> {1} UTC (enables RECENCY evidence)" -f $script:WindowStart.ToString('yyyy-MM-dd HH:mm:ss'), $script:WindowEnd.ToString('yyyy-MM-dd HH:mm:ss'))
} else {
    Write-Output 'No incident window requested (-Since/-Days/-Until not supplied) -- RECENCY evidence disabled for this run.'
}
Write-Output ''

# --- On-disk profile inventory (basis of the honest coverage report) -------
$script:OnDiskProfiles = Get-OnDiskProfiles

# --- Dispatch loop -----------------------------------------------------------
# All 42 $script:ModuleCatalog tokens resolve to a real function as of Pass D.
# $script:NotYetImplemented should therefore always be empty in normal
# operation; the Get-Command guard and this list are kept as defensive
# robustness (a future catalog edit that adds a token without a matching
# function, or a typo'd FunctionName, degrades gracefully via the coverage
# report instead of throwing) rather than as an expected mid-build state.
$script:NotYetImplemented = New-Object System.Collections.Generic.List[object]

foreach ($entry in $script:ResolvedModules) {
    if (Get-Command -Name $entry.FunctionName -ErrorAction SilentlyContinue) {
        # Every module function is documented/designed to degrade gracefully on
        # its own (try/catch around every registry/filesystem/CIM call) and
        # never throw -- this outer try/catch is defense-in-depth only, so a
        # single unforeseen bug in one module (a bad path, a null-deref, a
        # provider quirk on an unusual host) surfaces as one coverage-report
        # line rather than aborting the whole run and losing every other
        # module's already-collected findings.
        try {
            & $entry.FunctionName
        } catch {
            $script:UnreadableTargets.Add(@{ Target = "$($entry.FunctionName) (module: $($entry.Token))"; Reason = "Module threw an unhandled error and was aborted: $($_.Exception.Message)" })
        }
    } else {
        $script:NotYetImplemented.Add($entry)
    }
}

# --- Render -------------------------------------------------------------------
Write-InventoryLine
Write-AnomalyQueue
Write-CoverageReport
