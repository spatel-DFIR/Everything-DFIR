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
        applied BEFORE -MaxEvents trims to the newest N — see the "MaxEvents bug" note below),
        then applies keyword substring matching (OR across -Keywords), a single -Pattern regex,
        and/or a -Level filter. If none of -Keywords/-Pattern is given but -Level/-LogName/a
        timeframe is, every in-scope event is still emitted, tagged "(scope filter only — no
        text match required)". Every match prints as a full, un-clipped block (never
        Format-Table -Wrap, which clips long Message text), followed by a tally: total matches,
        breakdown by log, breakdown by keyword/pattern, and the unreadable-logs list.

    THE BUG THIS REWRITE FIXES
    The original ad hoc script called `Get-WinEvent -LogName X -MaxEvents 500` and only
    AFTERWARDS filtered those 500 raw records by `-ge $StartDate`. On a busy log (Security,
    Defender/Operational) 500 raw records can span minutes, so matches earlier in the requested
    window were silently dropped with no indication to the operator that this happened. This
    script instead puts StartTime/EndTime inside -FilterHashtable, which is evaluated by the
    event log provider BEFORE -MaxEvents trims the result set — so -MaxEvents now correctly
    means "the most recent N events WITHIN the timeframe," not "the most recent N events,
    then hope they happen to be in the timeframe."

    SAFETY CONTRACT (live RTR hosts)
    Read-only. Console output only — no files written, no temp files, no CSV/JSON export
    (explicitly out of scope for RTR safety). Single self-contained .ps1, no external modules,
    no dependencies beyond what ships with Windows PowerShell 5.1. Does not require elevation
    to run — it detects elevation and degrades gracefully (warns + lists inaccessible logs)
    rather than failing.

.PARAMETER Mode
    'Inventory' or 'Search'. If omitted, the script infers Search when -Keywords, -Pattern, or
    -Level is supplied, else Inventory.

.PARAMETER Keywords
    One or more substrings to match against each event's Message text (OR logic — any keyword
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
    Per-log cap on returned events, applied AFTER the timeframe filter. Default 500.

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
    .\hunt_eventlogs.ps1 -Pattern '\b(4104|4103)\b' -LogName 'Microsoft-Windows-PowerShell/Operational'
    Regex search restricted to the PowerShell operational log, default 1-day lookback.

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
  -MaxEvents <int>       Per-log cap AFTER the timeframe filter (default 500).
  -IncludeEmptyLogs      Include/search logs with RecordCount 0 (default: skipped).

EXAMPLES
  .\$ScriptName
  .\$ScriptName -Keywords '.msi','powershell.exe' -Days 3
  .\$ScriptName -Pattern '\b(4104|4103)\b' -LogName 'Microsoft-Windows-PowerShell/Operational'
  .\$ScriptName -Level Error,Critical -Since '2026-07-27 08:00:00' -Until '2026-07-27 20:00:00' -LogName System

All displayed timestamps are UTC. See README.md in this folder for full documentation.
"@ | Write-Output
    return
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
# Elevation check (never hard-fails on this — warn + degrade)
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
        $inventoryRows | Sort-Object LogName | Format-Table -AutoSize
    } else {
        Write-Output 'No readable logs to report.'
    }

    Write-Output ''
    if ($UnreadableLogs.Count -gt 0) {
        Write-Output "Unreadable logs ($($UnreadableLogs.Count)) — needs elevation, disabled channel, or a live query error:"
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

$AllMatches      = New-Object System.Collections.Generic.List[object]
$CountsByLog     = @{}
$CountsByCriterion = @{}

foreach ($log in $CandidateLogs) {

    $filterHash = @{
        LogName   = $log.LogName
        StartTime = $StartDate
        EndTime   = $EndDate
    }
    if ($LevelInts) { $filterHash['Level'] = $LevelInts }

    $events = $null
    try {
        $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            # Not an error — just nothing in this log within the requested scope. Skip silently.
            continue
        } else {
            $UnreadableLogs.Add([PSCustomObject]@{
                LogName = $log.LogName
                Reason  = $_.Exception.Message
            })
            continue
        }
    }

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
            $matchReasonParts += '(scope filter only — no text match required)'
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
}

$SortedMatches = $AllMatches | Sort-Object -Property TimeUtc -Descending

Write-Output "Searched $($CandidateLogs.Count) log(s)."
if ($ScopeOnly) {
    Write-Output 'No -Keywords/-Pattern supplied — emitting every event in scope (scope filter only).'
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

Write-Output ''
if ($UnreadableLogs.Count -gt 0) {
    Write-Output "Unreadable logs ($($UnreadableLogs.Count)) — needs elevation, disabled channel, or a live query error:"
    foreach ($u in $UnreadableLogs) {
        Write-Output ("  {0} - {1}" -f $u.LogName, $u.Reason)
    }
} else {
    Write-Output 'Unreadable logs: none.'
}
