<#
.SYNOPSIS
    Read-only Windows Event Log inventory and timeframe-correct keyword/regex hunter, safe for
    live EDR RTR (Real-Time Response) sessions.

.DESCRIPTION
    hunt_eventlogs.ps1  v1.0  author: Suvas Patel

    Two modes:

      Inventory (default, no keyword/pattern/level given)
        Lists every event log on the host that has RecordCount -gt 0 (or all logs with
        -IncludeEmptyLogs), and for each: LogName, RecordCount, oldest event time (UTC),
        newest event time (UTC). Logs that error (need elevation, disabled channel, etc.)
        are collected into a separate "unreadable logs" list at the end instead of being
        silently dropped.

      Search (auto-promoted when -Keywords, -Pattern, or -Level is supplied; also settable
      explicitly with -Mode Search)
        Runs a timeframe-scoped Get-WinEvent -FilterHashtable query per log (StartTime/EndTime
        applied BEFORE any event-count cap - see the "MaxEvents bugs" note below), then applies
        keyword substring matching (OR across -Keywords), a single -Pattern regex, and/or a
        -Level filter. If none of -Keywords/-Pattern is given but -Level/-LogName/a timeframe
        is, every in-scope event is still emitted, tagged "(scope filter only - no text match
        required)". Every match prints as a full, un-clipped block (never Format-Table -Wrap,
        which clips long Message text), followed by a tally: total matches, breakdown by log,
        breakdown by keyword/pattern, any -MaxEvents truncation, and the unreadable-logs list.

    THE MAXEVENTS BUGS THIS REWRITE FIXES
    Bug 1 (raw ordering): the original ad hoc script called `Get-WinEvent -LogName X
    -MaxEvents 500` and only AFTERWARDS filtered those 500 raw records by `-ge $StartDate`. On
    a busy log (Security, Defender/Operational) 500 raw records can span minutes, so matches
    earlier in the requested window were silently dropped. Fixed by putting StartTime/EndTime
    inside -FilterHashtable, evaluated by the event log provider before any count cap.

    Bug 2 (keyword starvation, found testing this rewrite): even with the timeframe applied
    first, capping RAW EVENT RETRIEVAL at -MaxEvents before keyword/pattern matching has the
    same silent-miss effect one level down - the newest N raw events in the window can easily
    contain zero mentions of the keyword while hundreds of matches sit further back in the same
    window, and the operator has no way to tell the difference from "genuinely no matches."
    Fixed by never capping retrieval when -Keywords/-Pattern is active: the full timeframe is
    always searched, and -MaxEvents instead caps how many MATCHES are shown per log (newest
    first), with an honest "N more matches exist" note in the summary if the cap was hit. A
    scope-only dump (no -Keywords/-Pattern) is unaffected - there every event in scope IS a
    "match," so capping retrieval and capping displayed results are the same thing.

    SAFETY CONTRACT (live RTR hosts)
    Read-only. Console output only - no files written, no temp files, no CSV/JSON export
    (explicitly out of scope for RTR safety). Single self-contained .ps1, no external modules,
    no dependencies beyond what ships with Windows PowerShell 5.1. Does not require elevation
    to run - it detects elevation and degrades gracefully (warns + lists inaccessible logs)
    rather than failing.

.PARAMETER Mode
    'Inventory' or 'Search'. If omitted, the script infers Search when -Keywords, -Pattern, or
    -Level is supplied, else Inventory.

.PARAMETER Keywords
    One or more substrings to match against each event's Message text (OR logic - any keyword
    matching is enough). Case-insensitive unless -CaseSensitive is given. Matching is done with
    a plain .Contains() check, not -like, so keywords containing *, ?, or [ are treated literally
    instead of as wildcards.

.PARAMETER Pattern
    A single .NET regular expression matched against each event's Message text via
    [Text.RegularExpressions.Regex]::IsMatch(). Case-insensitive unless -CaseSensitive is given.
    An invalid pattern prints one warning and is disabled for the run (it will not throw per event).

.PARAMETER CaseSensitive
    Makes both -Keywords and -Pattern matching case-sensitive.

.PARAMETER Level
    One or more of Critical, Error, Warning, Information, Verbose. Maps to the Windows event
    Level filter. Supplying this alone (with no -Keywords/-Pattern) auto-promotes to Search mode
    and still emits every event at that level in scope (scope-filter-only match).

.PARAMETER LogName
    Restrict which logs are searched/inventoried. Supports wildcards via -like, e.g.
    'Microsoft-Windows-*'. Does not, by itself, promote Inventory to Search.

.PARAMETER Since
    Start of the timeframe, e.g. '2026-07-28' or '2026-07-28 09:00:00'. Interpreted in the
    host's local time zone. Wins over -Days if both are supplied.

.PARAMETER Days
    Lookback window in days from now. Default 1 (matches the original script's default).
    Ignored if -Since is supplied.

.PARAMETER Until
    End of the timeframe. Same format/time-zone rules as -Since. Defaults to now.

.PARAMETER MaxEvents
    With no -Keywords/-Pattern (a scope-only dump): per-log cap on returned events, applied
    AFTER the timeframe filter. With -Keywords/-Pattern: per-log cap on MATCHES shown (newest
    first) - matching itself always runs over every event in the timeframe first, so a busy
    log can never silently starve the keyword search the way a raw-event cap would. A keyword/
    pattern search always shows at least the newest 50 matches per log regardless of a smaller
    -MaxEvents value, so an accidentally tiny cap can't hide real matches. If a log has more
    matches than the effective cap allows, the summary reports how many were left out.
    Default 500.

.PARAMETER IncludeEmptyLogs
    Include logs with RecordCount -eq 0 (Inventory) / search them anyway (Search). By default
    both modes skip logs with no records.

.PARAMETER Help
    Print usage and exit immediately, before any other processing.

.EXAMPLE
    .\hunt_eventlogs.ps1
    Inventory of every non-empty event log on the host (oldest/newest event time, record count).

.EXAMPLE
    .\hunt_eventlogs.ps1 -Keywords '.msi','powershell.exe' -Days 3
    Search the last 3 days across all logs for either substring in the Message text.

.EXAMPLE
    .\hunt_eventlogs.ps1 -Pattern '(?i)(-enc\b|-EncodedCommand|IEX\b|Invoke-Expression|DownloadString|DownloadFile)' -LogName 'Microsoft-Windows-PowerShell/Operational'
    Regex search restricted to the PowerShell operational log, default 1-day lookback. Matches
    are against Message body text, not EventID - a pattern like '\b4104\b' looks like it should
    find script-block-logging events but won't, since a 4104 event's Message is the script
    block's own content, not a mention of its own event ID.

.EXAMPLE
    .\hunt_eventlogs.ps1 -Level Error,Critical -Since '2026-07-27 08:00:00' -Until '2026-07-27 20:00:00' -LogName 'System'
    Scoped dump (no keyword needed) of every Error/Critical event in the System log within an
    explicit time window.

.NOTES
    Author : Suvas Patel
    Version: 1.0
#>

[CmdletBinding()]
param(
    [ValidateSet('Inventory', 'Search')]
    [string]$Mode,

    [string[]]$Keywords,

    [string]$Pattern,

    [switch]$CaseSensitive,

    [ValidateSet('Critical', 'Error', 'Warning', 'Information', 'Verbose')]
    [string[]]$Level,

    [string[]]$LogName,

    [string]$Since,

    [int]$Days = 1,

    [string]$Until,

    [int]$MaxEvents = 500,

    [switch]$IncludeEmptyLogs,

    [switch]$Help
)

$ScriptVersion = '1.0'
$ScriptAuthor  = 'Suvas Patel'
$ScriptName    = 'hunt_eventlogs.ps1'

# ---------------------------------------------------------------------------
# -Help : handled before anything else runs, per RTR requirement.
# ---------------------------------------------------------------------------
if ($Help) {
    @"
$ScriptName  v$ScriptVersion  author: $ScriptAuthor

Read-only Windows Event Log inventory + timeframe-correct keyword/regex hunter.
Safe for EDR RTR live sessions: read-only, console-only output, no files written,
no CSV/JSON export, no elevation required (degrades gracefully if not elevated).

USAGE
  .\$ScriptName [-Mode Inventory|Search] [-Keywords <string[]>] [-Pattern <regex>]
      [-CaseSensitive] [-Level <Critical|Error|Warning|Information|Verbose>[]]
      [-LogName <string[]>] [-Since <datetime>] [-Days <int>] [-Until <datetime>]
      [-MaxEvents <int>] [-IncludeEmptyLogs] [-Help]

MODES
  Inventory (default)  Lists every log with events: name, record count, oldest/newest event (UTC).
  Search               Auto-enabled by -Keywords / -Pattern / -Level, or forced with -Mode Search.
                        Timeframe-scoped per log, then keyword/regex/level filtered.

KEY PARAMETERS
  -Keywords <string[]>   Substring match against Message (OR logic, case-insensitive by default).
  -Pattern  <regex>      Single .NET regex match against Message.
  -CaseSensitive         Case-sensitive keyword/pattern matching.
  -Level    <string[]>   Critical | Error | Warning | Information | Verbose.
  -LogName  <string[]>   Restrict logs searched, wildcards via -like (e.g. 'Microsoft-Windows-*').
  -Since    <datetime>   Start of window, e.g. '2026-07-28' or '2026-07-28 09:00:00'. Wins over -Days.
  -Days     <int>        Lookback window in days (default 1). Ignored if -Since given.
  -Until    <datetime>   End of window (default: now).
  -MaxEvents <int>       Scope-only dump: per-log cap after the timeframe filter. Keyword/
                         pattern search: per-log cap on MATCHES shown (newest first, floor of
                         50 even if set lower) - the full timeframe is always searched first.
                         (default 500)
  -IncludeEmptyLogs      Include/search logs with RecordCount 0 (default: skipped).

EXAMPLES
  .\$ScriptName
  .\$ScriptName -Keywords '.msi','powershell.exe' -Days 3
  .\$ScriptName -Pattern '(?i)(-enc\b|-EncodedCommand|IEX\b|Invoke-Expression|DownloadString|DownloadFile)' -LogName 'Microsoft-Windows-PowerShell/Operational'
  .\$ScriptName -Level Error,Critical -Since '2026-07-27 08:00:00' -Until '2026-07-27 20:00:00' -LogName System

All displayed timestamps are UTC. See README.md in this folder for full documentation.
"@ | Write-Output
    return
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Console-width-aware table: never truncates (RTR/redirected hosts often misreport or fix
# their width), shrinks the widest column first, then wraps instead of clipping.
function Get-ConsoleWidth {
    $w = 0
    try { $w = $Host.UI.RawUI.WindowSize.Width } catch { }
    if (-not $w -or $w -lt 40) { $w = 120 }
    return [Math]::Min($w - 1, 200)
}

function Split-Cell {
    param([string]$Text, [int]$W)
    if ($null -eq $Text) { $Text = '' }
    if ($Text.Length -le $W) { return , @($Text) }
    $out = New-Object System.Collections.Generic.List[string]
    $rem = $Text
    while ($rem.Length -gt $W) {
        $slice = $rem.Substring(0, $W)
        $b = [Math]::Max($slice.LastIndexOf(' '), $slice.LastIndexOf('\'))
        if ($b -lt [int]($W * 0.5)) { $b = $W - 1 }
        $out.Add($rem.Substring(0, $b + 1).TrimEnd())
        $rem = $rem.Substring($b + 1).TrimStart()
    }
    if ($rem) { $out.Add($rem) }
    return , $out.ToArray()
}

function Write-WideTable {
    param([object[]]$Rows, [string[]]$Cols, [int]$Indent = 0)
    if (-not $Rows -or $Rows.Count -eq 0) { return }
    $pad = ' ' * $Indent
    $avail = (Get-ConsoleWidth) - $Indent
    $n = $Cols.Count
    $w = @()
    for ($i = 0; $i -lt $n; $i++) {
        $m = $Cols[$i].Length
        foreach ($r in $Rows) { $l = ([string]$r.($Cols[$i])).Length; if ($l -gt $m) { $m = $l } }
        $w += [Math]::Min($m, 70)
    }
    $total = ($w | Measure-Object -Sum).Sum + (2 * ($n - 1))
    while ($total -gt $avail) {
        $wide = 0
        for ($i = 1; $i -lt $n; $i++) { if ($w[$i] -gt $w[$wide]) { $wide = $i } }
        if ($w[$wide] -le 8) { break }
        $w[$wide]--; $total--
    }
    $hdr = @(); $rule = @()
    for ($i = 0; $i -lt $n; $i++) { $hdr += $Cols[$i].PadRight($w[$i]).Substring(0, $w[$i]); $rule += ('-' * $w[$i]) }
    Write-Output ($pad + ($hdr -join '  '))
    Write-Output ($pad + ($rule -join '  '))
    foreach ($r in $Rows) {
        $cells = @(); $h = 1
        for ($i = 0; $i -lt $n; $i++) {
            $c = Split-Cell ([string]$r.($Cols[$i])) $w[$i]
            $cells += , $c
            if ($c.Count -gt $h) { $h = $c.Count }
        }
        for ($line = 0; $line -lt $h; $line++) {
            $o = @()
            for ($i = 0; $i -lt $n; $i++) {
                $t = ''
                if ($line -lt $cells[$i].Count) { $t = $cells[$i][$line] }
                $o += $t.PadRight($w[$i])
            }
            Write-Output ($pad + (($o -join '  ').TrimEnd()))
        }
    }
}

function Get-CandidateLogs {
    param(
        [string[]]$NamePatterns,
        [bool]$IncludeEmpty
    )

    $result      = New-Object System.Collections.Generic.List[object]
    $unreadable  = New-Object System.Collections.Generic.List[object]

    $allLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue
    foreach ($log in $allLogs) {

        $recordCount = $null
        try {
            $recordCount = $log.RecordCount
        } catch {
            $unreadable.Add([PSCustomObject]@{
                LogName = $log.LogName
                Reason  = $_.Exception.Message
            })
            continue
        }

        if (-not $IncludeEmpty -and (-not $recordCount -or $recordCount -le 0)) {
            continue
        }

        if ($NamePatterns) {
            $matched = $false
            foreach ($p in $NamePatterns) {
                if ($log.LogName -like $p) { $matched = $true; break }
            }
            if (-not $matched) { continue }
        }

        $result.Add([PSCustomObject]@{
            LogName     = $log.LogName
            RecordCount = $recordCount
        })
    }

    return [PSCustomObject]@{
        Logs       = $result
        Unreadable = $unreadable
    }
}

function Write-Banner {
    param(
        [string]$EffectiveMode,
        [bool]$IsElevated,
        [string]$CommandLine
    )

    $runTime  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
    $hostName = $env:COMPUTERNAME

    Write-Output "$ScriptName  v$ScriptVersion    author: $ScriptAuthor"
    Write-Output "Ran at   : $runTime"
    Write-Output "Hostname : $hostName"
    Write-Output "Mode     : $EffectiveMode"
    Write-Output "Command  : $CommandLine"

    if (-not $IsElevated) {
        Write-Output ''
        Write-Output '!! WARNING: not running elevated. The Security log and some provider logs'
        Write-Output '!! (e.g. Microsoft-Windows-* channels requiring privileged read access) may be'
        Write-Output '!! inaccessible; they will appear in the unreadable-logs list below rather than'
        Write-Output '!! causing a failure. Re-run from an elevated PowerShell for full coverage.'
    }
    Write-Output ''
}

# ---------------------------------------------------------------------------
# Elevation check (never hard-fails on this - warn + degrade)
# ---------------------------------------------------------------------------

$IsElevated = $false
try {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $IsElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $IsElevated = $false
}

# ---------------------------------------------------------------------------
# Effective command line (for the banner, so a saved RTR transcript is
# self-documenting)
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Resolve effective mode
# ---------------------------------------------------------------------------

$EffectiveMode = 'Inventory'
if ($PSBoundParameters.ContainsKey('Mode')) {
    $EffectiveMode = $Mode
} elseif ($Keywords -or $Pattern -or $Level) {
    $EffectiveMode = 'Search'
}

Write-Banner -EffectiveMode $EffectiveMode -IsElevated $IsElevated -CommandLine $EffectiveCommandLine

if ($EffectiveMode -eq 'Inventory' -and ($Keywords -or $Pattern -or $Level)) {
    Write-Output 'Note: -Mode Inventory was explicitly forced; -Keywords/-Pattern/-Level are ignored in this mode.'
    Write-Output ''
}

# ---------------------------------------------------------------------------
# Resolve timeframe (Search mode only, but computed either way for the banner-
# adjacent messaging below)
# ---------------------------------------------------------------------------

$StartDate = $null
$EndDate   = $null

if ($EffectiveMode -eq 'Search') {

    if ($PSBoundParameters.ContainsKey('Since')) {
        try {
            $StartDate = Get-Date -Date $Since -ErrorAction Stop
        } catch {
            Write-Error "Could not parse -Since value '$Since': $($_.Exception.Message)"
            return
        }
        if ($PSBoundParameters.ContainsKey('Days')) {
            Write-Output "Note: both -Since and -Days were supplied; -Since wins, -Days is ignored."
        }
    } else {
        $StartDate = (Get-Date).AddDays(-$Days)
    }

    if ($PSBoundParameters.ContainsKey('Until')) {
        try {
            $EndDate = Get-Date -Date $Until -ErrorAction Stop
        } catch {
            Write-Error "Could not parse -Until value '$Until': $($_.Exception.Message)"
            return
        }
    } else {
        $EndDate = Get-Date
    }

    if ($EndDate -lt $StartDate) {
        Write-Error "Resolved -Until ($EndDate) is earlier than -Since/-Days start ($StartDate). Check your timeframe."
        return
    }

    $startDisplay = $StartDate.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $endDisplay   = $EndDate.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    Write-Output ("Timeframe: {0} UTC  ->  {1} UTC" -f $startDisplay, $endDisplay)
    Write-Output ''
}

# ---------------------------------------------------------------------------
# Level -> Windows event Level integer map
# ---------------------------------------------------------------------------

$LevelMap = @{
    'Critical'    = 1
    'Error'       = 2
    'Warning'     = 3
    'Information' = 4
    'Verbose'     = 5
}

$LevelInts = $null
if ($Level) {
    $LevelInts = @()
    foreach ($lvl in $Level) { $LevelInts += $LevelMap[$lvl] }
}

# ---------------------------------------------------------------------------
# Validate regex once (so a bad -Pattern prints one warning, not one per event)
# ---------------------------------------------------------------------------

$PatternValid = $false
if ($Pattern) {
    try {
        [Text.RegularExpressions.Regex]::IsMatch('validation-probe', $Pattern) | Out-Null
        $PatternValid = $true
    } catch {
        Write-Warning "Invalid -Pattern regex '$Pattern': $($_.Exception.Message). Pattern matching disabled for this run."
        $PatternValid = $false
    }
}

# ---------------------------------------------------------------------------
# Discover candidate logs
# ---------------------------------------------------------------------------

$discovery       = Get-CandidateLogs -NamePatterns $LogName -IncludeEmpty $IncludeEmptyLogs.IsPresent
$CandidateLogs   = $discovery.Logs
$UnreadableLogs  = New-Object System.Collections.Generic.List[object]
foreach ($u in $discovery.Unreadable) { $UnreadableLogs.Add($u) }

if ($CandidateLogs.Count -eq 0) {
    Write-Output 'No candidate event logs matched the current scope (-LogName / -IncludeEmptyLogs).'
    if ($UnreadableLogs.Count -gt 0) {
        Write-Output ''
        Write-Output "Unreadable logs ($($UnreadableLogs.Count)):"
        foreach ($u in $UnreadableLogs) {
            Write-Output ("  {0} - {1}" -f $u.LogName, $u.Reason)
        }
    }
    return
}

# ===========================================================================
# INVENTORY MODE
# ===========================================================================

if ($EffectiveMode -eq 'Inventory') {

    Write-Output "Inventorying $($CandidateLogs.Count) event log(s)..."
    Write-Output ''

    $inventoryRows = New-Object System.Collections.Generic.List[object]

    foreach ($log in $CandidateLogs) {

        if ($log.RecordCount -le 0) {
            $inventoryRows.Add([PSCustomObject]@{
                LogName     = $log.LogName
                RecordCount = 0
                OldestUTC   = '(no events)'
                NewestUTC   = '(no events)'
            })
            continue
        }

        try {
            $oldest = Get-WinEvent -LogName $log.LogName -Oldest -MaxEvents 1 -ErrorAction Stop
            $newest = Get-WinEvent -LogName $log.LogName -MaxEvents 1 -ErrorAction Stop

            $inventoryRows.Add([PSCustomObject]@{
                LogName     = $log.LogName
                RecordCount = $log.RecordCount
                OldestUTC   = $oldest.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
                NewestUTC   = $newest.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            })
        } catch {
            $UnreadableLogs.Add([PSCustomObject]@{
                LogName = $log.LogName
                Reason  = $_.Exception.Message
            })
        }
    }

    if ($inventoryRows.Count -gt 0) {
        $sortedInventory = $inventoryRows | Sort-Object LogName
        Write-WideTable -Rows $sortedInventory -Cols @('LogName', 'RecordCount', 'OldestUTC', 'NewestUTC')
    } else {
        Write-Output 'No readable logs to report.'
    }

    Write-Output ''
    if ($UnreadableLogs.Count -gt 0) {
        Write-Output "Unreadable logs ($($UnreadableLogs.Count)) - needs elevation, disabled channel, or a live query error:"
        foreach ($u in $UnreadableLogs) {
            Write-Output ("  {0} - {1}" -f $u.LogName, $u.Reason)
        }
    } else {
        Write-Output 'Unreadable logs: none.'
    }

    return
}

# ===========================================================================
# SEARCH MODE
# ===========================================================================

$ScopeOnly = (-not $Keywords) -and (-not ($Pattern -and $PatternValid))

# Keyword/pattern search always shows at least this many of the newest matches per log, even
# if the operator passed a smaller -MaxEvents - a tiny cap (e.g. -MaxEvents 10) on a busy log
# could otherwise display almost nothing despite hundreds of real matches existing in scope.
# Scope-only dumps are exempt: there -MaxEvents directly caps raw events returned, by design.
$MinMatchesShown = 50
$MatchDisplayCap = if ($ScopeOnly) { $MaxEvents } else { [Math]::Max($MaxEvents, $MinMatchesShown) }

$AllMatches      = New-Object System.Collections.Generic.List[object]
$CountsByLog     = @{}
$CountsByCriterion = @{}
$TruncatedLogs   = New-Object System.Collections.Generic.List[object]

foreach ($log in $CandidateLogs) {

    $filterHash = @{
        LogName   = $log.LogName
        StartTime = $StartDate
        EndTime   = $EndDate
    }
    if ($LevelInts) { $filterHash['Level'] = $LevelInts }

    $events = $null
    try {
        if ($ScopeOnly) {
            $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents $MaxEvents -ErrorAction Stop
        } else {
            # Keyword/pattern search: do NOT cap raw retrieval with -MaxEvents here. Capping
            # retrieval before text-matching would let -MaxEvents silently starve the keyword
            # search on a busy log - the newest N raw events could easily contain zero mentions
            # of the keyword even though hundreds exist earlier in the same requested window.
            # -MaxEvents is instead applied below as a cap on MATCHES shown, after the full
            # timeframe has been searched, with an honest count of anything left out.
            $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction Stop
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            # Not an error - just nothing in this log within the requested scope. Skip silently.
            continue
        } else {
            $UnreadableLogs.Add([PSCustomObject]@{
                LogName = $log.LogName
                Reason  = $_.Exception.Message
            })
            continue
        }
    }

    $logMatchTotal = 0

    foreach ($evt in $events) {

        $message = $evt.Message
        $matchedKeywords = @()
        $matchedPattern  = $false

        if ($Keywords -and $message) {
            foreach ($kw in $Keywords) {
                if ($CaseSensitive) {
                    if ($message.Contains($kw)) { $matchedKeywords += $kw }
                } else {
                    if ($message.ToLowerInvariant().Contains($kw.ToLowerInvariant())) { $matchedKeywords += $kw }
                }
            }
        }

        if ($Pattern -and $PatternValid -and $message) {
            $opts = [Text.RegularExpressions.RegexOptions]::None
            if (-not $CaseSensitive) { $opts = [Text.RegularExpressions.RegexOptions]::IgnoreCase }
            try {
                if ([Text.RegularExpressions.Regex]::IsMatch($message, $Pattern, $opts)) { $matchedPattern = $true }
            } catch {
                # Already validated once above; treat any surprise failure as a non-match.
                $matchedPattern = $false
            }
        }

        $isMatch = $false
        $matchReasonParts = @()

        if ($ScopeOnly) {
            $isMatch = $true
            $matchReasonParts += '(scope filter only - no text match required)'
        } else {
            if ($matchedKeywords.Count -gt 0) {
                $isMatch = $true
                foreach ($kw in $matchedKeywords) { $matchReasonParts += "keyword '$kw'" }
            }
            if ($matchedPattern) {
                $isMatch = $true
                $matchReasonParts += "regex '$Pattern'"
            }
        }

        if (-not $isMatch) { continue }

        $logMatchTotal++
        if (-not $ScopeOnly -and $logMatchTotal -gt $MatchDisplayCap) {
            # Keep scanning (cheap - already retrieved) so the truncation note below is an
            # honest count, but stop adding further matches to the displayed results.
            continue
        }

        $timeUtc = $evt.TimeCreated.ToUniversalTime()

        $AllMatches.Add([PSCustomObject]@{
            TimeUtc    = $timeUtc
            LogName    = $evt.LogName
            EventID    = $evt.Id
            Level      = $evt.LevelDisplayName
            Source     = $evt.ProviderName
            MatchedOn  = ($matchReasonParts -join ', ')
            Message    = $message
        })

        if (-not $CountsByLog.ContainsKey($evt.LogName)) { $CountsByLog[$evt.LogName] = 0 }
        $CountsByLog[$evt.LogName]++

        foreach ($part in $matchReasonParts) {
            if (-not $CountsByCriterion.ContainsKey($part)) { $CountsByCriterion[$part] = 0 }
            $CountsByCriterion[$part]++
        }
    }

    if (-not $ScopeOnly -and $logMatchTotal -gt $MatchDisplayCap) {
        $TruncatedLogs.Add([PSCustomObject]@{
            LogName = $log.LogName
            Shown   = $MatchDisplayCap
            Total   = $logMatchTotal
        })
    }
}

$SortedMatches = $AllMatches | Sort-Object -Property TimeUtc -Descending

Write-Output "Searched $($CandidateLogs.Count) log(s)."
if ($ScopeOnly) {
    if ($Pattern -and -not $PatternValid) {
        Write-Output 'No usable filter: the -Pattern regex was invalid and got disabled (see the warning above), and no -Keywords was given - emitting every event in scope (scope filter only), NOT a filtered search.'
    } else {
        Write-Output 'No -Keywords/-Pattern supplied - emitting every event in scope (scope filter only).'
    }
}
Write-Output ''

if ($SortedMatches.Count -eq 0) {
    Write-Output 'No matching events found.'
} else {
    foreach ($m in $SortedMatches) {
        Write-Output '------------------------------------------------------------'
        Write-Output ("Time     : {0} UTC" -f $m.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss'))
        Write-Output ("Log      : {0}" -f $m.LogName)
        Write-Output ("EventID  : {0}" -f $m.EventID)
        Write-Output ("Level    : {0}" -f $m.Level)
        Write-Output ("Source   : {0}" -f $m.Source)
        Write-Output ("Matched  : {0}" -f $m.MatchedOn)
        Write-Output 'Message  :'
        if ($m.Message) {
            Write-Output $m.Message
        } else {
            Write-Output '(no message text available for this event)'
        }
        Write-Output ''
    }
    Write-Output '------------------------------------------------------------'
}

Write-Output ''
Write-Output '=== Summary ==='
Write-Output "Total matches: $($SortedMatches.Count)"

if ($CountsByLog.Count -gt 0) {
    Write-Output ''
    Write-Output 'By log:'
    foreach ($key in ($CountsByLog.Keys | Sort-Object)) {
        Write-Output ("  {0} : {1}" -f $key, $CountsByLog[$key])
    }
}

if ($CountsByCriterion.Count -gt 0) {
    Write-Output ''
    Write-Output 'By keyword/pattern/scope:'
    foreach ($key in ($CountsByCriterion.Keys | Sort-Object)) {
        Write-Output ("  {0} : {1}" -f $key, $CountsByCriterion[$key])
    }
}

if ($TruncatedLogs.Count -gt 0) {
    Write-Output ''
    Write-Output "Truncated by -MaxEvents ($($TruncatedLogs.Count) log(s)) - more matches existed in the timeframe than shown:"
    foreach ($t in $TruncatedLogs) {
        Write-Output ("  {0} - showing newest {1} of {2} matches. Raise -MaxEvents or narrow -Since/-Until/-LogName to see the rest." -f $t.LogName, $t.Shown, $t.Total)
    }
}

Write-Output ''
if ($UnreadableLogs.Count -gt 0) {
    Write-Output "Unreadable logs ($($UnreadableLogs.Count)) - needs elevation, disabled channel, or a live query error:"
    foreach ($u in $UnreadableLogs) {
        Write-Output ("  {0} - {1}" -f $u.LogName, $u.Reason)
    }
} else {
    Write-Output 'Unreadable logs: none.'
}
