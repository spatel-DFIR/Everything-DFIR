<#
.SYNOPSIS
    Read-only Recycle Bin ($Recycle.Bin) triage for live Windows incident response.

.DESCRIPTION
    hunt_recyclebin.ps1 parses every SID folder under $Recycle.Bin on every fixed
    volume (or an analyst-supplied path, e.g. a mounted/offline image), recovers
    the Windows 10/11 ("version 2") $I metadata record for every deleted item,
    pairs it with its $R content counterpart when present, and prints a full,
    per-item enumeration of everything it finds -- deletion time (UTC), original
    path/size, current size/timestamps, and (opt-in) a SHA-256 hash of recovered
    content.

    On top of the enumeration it runs a small evidence-weighted anomaly engine
    (ORPHAN-I / ORPHAN-R / TIMESTAMP-ANOMALY / SUSPICIOUS-ORIGINAL-EXT /
    DELETION-CLUSTER) and prints a ranked ANOMALY QUEUE, using the same
    "flag on evidence, enumerate everything else" doctrine as the sibling
    hunt_persistence.sh / hunt_intrusion.sh tools.

    This tool is READ-ONLY. It never restores, deletes, empties, or otherwise
    modifies Recycle Bin contents -- it only reads $I/$R metadata and, when
    -Hash is given, computes hashes of already-recovered content. See the
    README for the full safety contract.

    Windows 7 / 8.0 ("version 1") $I files are explicitly out of scope -- they
    are detected and skipped with a one-line note and a tally entry, never
    guessed at or silently swallowed.

.PARAMETER Path
    One or more explicit $Recycle.Bin roots to scan, in addition to the
    default live-volume sweep. Accepts either a volume/mount root (e.g.
    "E:\" or "E:\mounted_image") or the $Recycle.Bin folder itself. Useful
    for a mounted/offline image path.

.PARAMETER IncludeRemovable
    Also probe removable (USB, DriveType=2) drives' $Recycle.Bin, in addition
    to the default fixed-drive (DriveType=3) sweep.

.PARAMETER Since
    Incident window start, 'yyyy-MM-dd' (UTC). Filters the item enumeration to
    items whose DeleteTime falls on/after this date, and gates DELETION-CLUSTER
    detection. Overrides -Days if both are given.

.PARAMETER Days
    Incident window: last N days (UTC, from now). Same effect as -Since.

.PARAMETER User
    Filter results to one owner. Matches (case-insensitive, substring) against
    the resolved "DOMAIN\user" account name.

.PARAMETER SID
    Filter results to one owner by exact SID folder name (e.g. S-1-5-21-...).

.PARAMETER Hash
    Opt-in: recursively SHA-256 hash recovered folder contents (and the
    recovered file itself, if the $R item is a single file). Off by default --
    the default pass walks folders for file count/size only, no hashing, so
    the fast pass stays fast. Alias: -Deep.

.PARAMETER MaxHashSizeMB
    Per-file cap (MB) when -Hash is enabled. Files above this size are skipped
    for hashing (noted individually) rather than hanging the run. Default 200.

.PARAMETER MinSeverity
    Filters the ANOMALY QUEUE section only (High | Notable | Low, default Low
    = show both HIGH and NOTABLE). The full per-item enumeration always shows
    every item regardless of this setting -- recovering the deleted-file
    timeline is this tool's core job, never hidden behind a severity filter.

.PARAMETER Help
    Show full help and exit.

.EXAMPLE
    .\hunt_recyclebin.ps1
    Fast default pass: all fixed volumes, no hashing.

.EXAMPLE
    .\hunt_recyclebin.ps1 -Hash -MaxHashSizeMB 100

.EXAMPLE
    .\hunt_recyclebin.ps1 -Since 2026-07-20 -MinSeverity High

.EXAMPLE
    .\hunt_recyclebin.ps1 -Path 'E:\mounted_image' -User jdoe

.NOTES
    Author  : Suvas Patel
    Version : 1.0
    Part of the Windows DFIR Field Reference -- see "Recycle.Bin Analysis.md".
#>

[CmdletBinding()]
param(
    [Parameter()][string[]]$Path,
    [Parameter()][switch]$IncludeRemovable,
    [Parameter()][string]$Since,
    [Parameter()][int]$Days,
    [Parameter()][string]$User,
    [Parameter()][string]$SID,
    [Parameter()][Alias('Deep')][switch]$Hash,
    [Parameter()][int]$MaxHashSizeMB = 200,
    [Parameter()][ValidateSet('High', 'Notable', 'Low')][string]$MinSeverity = 'Low',
    [Parameter()][switch]$Help
)

# ======================================================================
#  Constants
# ======================================================================
$ScriptVersion = '1.0'
$ScriptAuthor  = 'Suvas Patel'
$ScriptName    = 'hunt_recyclebin.ps1'

# Extensions worth flagging when the ORIGINAL (pre-delete) path also looks
# like a staging/execution location rather than an installed application.
$SuspiciousExtensions = @('ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'bat', 'cmd', 'hta', 'exe', 'dll', 'scr')

$HighThreshold    = 6
$NotableThreshold = 3

# ======================================================================
#  Help
# ======================================================================
if ($Help) {
    Get-Help -Full $PSCommandPath
    exit 0
}

# ======================================================================
#  Small helpers
# ======================================================================

function Resolve-SidOwner {
    param([Parameter(Mandatory)][string]$SidString)
    try {
        $account = (New-Object System.Security.Principal.SecurityIdentifier($SidString)).Translate([System.Security.Principal.NTAccount])
        return $account.Value
    } catch {
        return "Unknown User (SID: $SidString)"
    }
}

function Test-UserMatch {
    param([string]$OwnerName, [string]$Filter)
    if ([string]::IsNullOrEmpty($Filter)) { return $true }
    return ($OwnerName -like "*$Filter*")
}

# Parses a $I ("version 2", Windows 10/11) header from raw bytes.
# Returns a PSCustomObject with Status: 'OK' | 'Malformed' | 'LegacyVersion'.
function Get-IFileHeader {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $minHeaderLength = 28   # version(8) + filesize(8) + deletetime(8) + namelength(4)
    if ($Bytes.Length -lt $minHeaderLength) {
        return [PSCustomObject]@{
            Status = 'Malformed'
            Reason = "header truncated -- only $($Bytes.Length) byte(s), need at least $minHeaderLength"
        }
    }

    $version = [BitConverter]::ToInt64($Bytes, 0)
    if ($version -ne 2) {
        return [PSCustomObject]@{ Status = 'LegacyVersion'; Version = $version }
    }

    $fileSize      = [BitConverter]::ToInt64($Bytes, 8)
    $deleteTimeRaw = [BitConverter]::ToInt64($Bytes, 16)
    $nameLength    = [BitConverter]::ToInt32($Bytes, 24)

    if ($nameLength -lt 0) {
        return [PSCustomObject]@{ Status = 'Malformed'; Reason = "negative name-length field ($nameLength)" }
    }

    $nameByteCount  = $nameLength * 2
    $requiredLength = $minHeaderLength + $nameByteCount
    if ($Bytes.Length -lt $requiredLength) {
        return [PSCustomObject]@{
            Status = 'Malformed'
            Reason = "name field truncated -- need $requiredLength byte(s), have $($Bytes.Length)"
        }
    }

    $originalPath = ''
    if ($nameByteCount -gt 0) {
        try {
            $originalPath = [System.Text.Encoding]::Unicode.GetString($Bytes, $minHeaderLength, $nameByteCount).TrimEnd([char]0)
        } catch {
            return [PSCustomObject]@{ Status = 'Malformed'; Reason = "could not decode original-path field: $($_.Exception.Message)" }
        }
    }

    $deleteTimeUtc = $null
    try { $deleteTimeUtc = [DateTime]::FromFileTimeUtc($deleteTimeRaw) } catch { $deleteTimeUtc = $null }

    return [PSCustomObject]@{
        Status        = 'OK'
        Version       = $version
        FileSize      = $fileSize
        DeleteTimeUtc = $deleteTimeUtc
        OriginalPath  = $originalPath
    }
}

function Get-FileHashSafe {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][long]$SizeBytes, [Parameter(Mandatory)][long]$MaxBytes)
    if ($SizeBytes -gt $MaxBytes) {
        return "SKIPPED (size $([Math]::Round($SizeBytes / 1MB, 2)) MB exceeds -MaxHashSizeMB cap of $([Math]::Round($MaxBytes / 1MB, 0)) MB)"
    }
    try {
        $h = Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $h.Hash
    } catch {
        return "ERROR (could not hash: $($_.Exception.Message))"
    }
}

# Walks a recovered folder for file count/total size, and (opt-in) hashes.
function Get-RecoveredFolderStats {
    param([Parameter(Mandatory)][string]$FolderPath, [bool]$DoHash, [long]$MaxHashBytes)

    $result = [PSCustomObject]@{
        FileCount = 0
        TotalSize = [long]0
        Files     = New-Object System.Collections.Generic.List[object]
        WalkNote  = $null
    }

    $walkErrors = $null
    $items = Get-ChildItem -LiteralPath $FolderPath -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable walkErrors
    if ($walkErrors -and $walkErrors.Count -gt 0) {
        $result.WalkNote = "$($walkErrors.Count) item(s) inaccessible during recursive walk -- partial coverage"
    }

    foreach ($it in $items) {
        if ($it.PSIsContainer) { continue }
        $result.FileCount++
        $result.TotalSize += $it.Length
        if ($DoHash) {
            $hashVal = Get-FileHashSafe -FilePath $it.FullName -SizeBytes $it.Length -MaxBytes $MaxHashBytes
        } else {
            $hashVal = 'N/A (hashing disabled -- use -Hash to enable)'
        }
        $relPath = $it.FullName
        if ($relPath.Length -gt $FolderPath.Length) { $relPath = $relPath.Substring($FolderPath.Length).TrimStart('\') }
        $result.Files.Add([PSCustomObject]@{ RelativePath = $relPath; Size = $it.Length; Hash = $hashVal })
    }
    return $result
}

function Get-Tier {
    param([int]$Score)
    if ($Score -ge $HighThreshold) { return 'HIGH' }
    if ($Score -ge $NotableThreshold) { return 'NOTABLE' }
    return 'CLEAN'
}

function Format-Bytes {
    param($Bytes)
    if ($null -eq $Bytes) { return 'unknown' }
    return "{0:N0} bytes" -f $Bytes
}

function Format-Utc {
    param($DateTimeUtc)
    if ($null -eq $DateTimeUtc) { return 'unknown' }
    return $DateTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
}

# Builds the list of $Recycle.Bin roots to scan: default fixed-volume sweep
# (+ removable, if requested) plus any analyst-supplied -Path entries.
function Get-CandidateRoots {
    param([string[]]$ExplicitPaths, [bool]$IncludeRemovableDrives)

    $roots = @()
    $driveTypes = @(3)
    if ($IncludeRemovableDrives) { $driveTypes += 2 }

    try {
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop | Where-Object { $driveTypes -contains $_.DriveType }
        foreach ($d in $disks) {
            if ($d.DeviceID) {
                $candidate = Join-Path $d.DeviceID '$Recycle.Bin'
                if ($roots -notcontains $candidate) { $roots += $candidate }
            }
        }
    } catch {
        Write-Warning "Could not enumerate logical disks via Win32_LogicalDisk: $($_.Exception.Message)"
    }

    foreach ($p in $ExplicitPaths) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $trimmed = $p.TrimEnd('\')
        if ($trimmed -match '\$Recycle\.Bin$') {
            $candidate = $trimmed
        } else {
            $candidate = Join-Path $trimmed '$Recycle.Bin'
        }
        if ($roots -notcontains $candidate) { $roots += $candidate }
    }

    return $roots
}

# ======================================================================
#  Banner
# ======================================================================
$nowUtc = (Get-Date).ToUniversalTime()
$effectiveArgs = foreach ($k in $PSBoundParameters.Keys) {
    $v = $PSBoundParameters[$k]
    if ($v -is [switch]) {
        if ($v.IsPresent) { "-$k" }
    } else {
        "-$k `"$v`""
    }
}
$effectiveCommandLine = "$ScriptName " + ($effectiveArgs -join ' ')

Write-Host ''
Write-Host "$ScriptName  v$ScriptVersion    author: $ScriptAuthor"
Write-Host "Ran at   : $($nowUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Write-Host "Hostname : $env:COMPUTERNAME"
Write-Host "Command  : $effectiveCommandLine"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$IsElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsElevated) {
    Write-Host ''
    Write-Host '!! WARNING: not running elevated. Other users'' SID folders under $Recycle.Bin'
    Write-Host '!! typically require Administrator to read. This run will note any root or'
    Write-Host '!! SID folder it could not access rather than fail -- see INACCESSIBLE ROOTS below.'
}

# ======================================================================
#  Incident window (-Since / -Days)
# ======================================================================
$WindowSet = $false
$WindowCutoffUtc = $null
if ($Since) {
    try {
        $parsedSince = [DateTime]::ParseExact($Since, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
        $WindowCutoffUtc = [DateTime]::SpecifyKind($parsedSince, [DateTimeKind]::Utc)
        $WindowSet = $true
    } catch {
        Write-Warning "Could not parse -Since '$Since' as yyyy-MM-dd -- ignoring incident window."
    }
} elseif ($Days -gt 0) {
    $WindowCutoffUtc = $nowUtc.AddDays(-$Days)
    $WindowSet = $true
}
if ($WindowSet) {
    Write-Host "Incident window: DeleteTime >= $(Format-Utc $WindowCutoffUtc) (enables DELETION-CLUSTER detection)"
}

# ======================================================================
#  Tallies
# ======================================================================
$VolumesScanned          = New-Object System.Collections.Generic.List[object]
$InaccessibleRoots       = New-Object System.Collections.Generic.List[string]
$SkippedLegacyVersion    = New-Object System.Collections.Generic.List[object]
$MalformedHeaders        = New-Object System.Collections.Generic.List[object]
$UnreadableIFiles        = New-Object System.Collections.Generic.List[object]
$InaccessibleRFilesTOCTOU = New-Object System.Collections.Generic.List[object]

$AllRecords = New-Object System.Collections.Generic.List[object]

$MaxHashBytes = ([long]$MaxHashSizeMB) * 1MB

# ======================================================================
#  Scan
# ======================================================================
$roots = Get-CandidateRoots -ExplicitPaths $Path -IncludeRemovableDrives:([bool]$IncludeRemovable)

foreach ($root in $roots) {
    $present = Test-Path -LiteralPath $root
    $VolumesScanned.Add([PSCustomObject]@{ Root = $root; Present = $present })
    if (-not $present) { continue }

    $sidFolders = $null
    try {
        $sidFolders = Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop
    } catch {
        $InaccessibleRoots.Add("$root -- $($_.Exception.Message)")
        continue
    }

    foreach ($sidFolder in $sidFolders) {
        $ownerName = Resolve-SidOwner -SidString $sidFolder.Name

        if ($SID -and ($sidFolder.Name -ne $SID)) { continue }
        if ($User -and -not (Test-UserMatch -OwnerName $ownerName -Filter $User)) { continue }

        $allItems = $null
        try {
            $allItems = Get-ChildItem -LiteralPath $sidFolder.FullName -Force -ErrorAction Stop
        } catch {
            $InaccessibleRoots.Add("$($sidFolder.FullName) -- $($_.Exception.Message)")
            continue
        }

        $nameSet = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
        foreach ($n in $allItems) { [void]$nameSet.Add($n.Name) }

        $iItems = $allItems | Where-Object { $_.Name -like '$I*' }
        $rItems = $allItems | Where-Object { $_.Name -like '$R*' }

        # ---------------- $I items (paired or orphaned) ----------------
        foreach ($iItem in $iItems) {

            $bytes = $null
            try {
                $bytes = [System.IO.File]::ReadAllBytes($iItem.FullName)
            } catch {
                $UnreadableIFiles.Add([PSCustomObject]@{ Path = $iItem.FullName; Reason = $_.Exception.Message })
                continue
            }

            $parsed = Get-IFileHeader -Bytes $bytes

            if ($parsed.Status -eq 'LegacyVersion') {
                $SkippedLegacyVersion.Add([PSCustomObject]@{ Path = $iItem.FullName; Version = $parsed.Version })
                Write-Host "`$I version $($parsed.Version) not supported -- Windows 7/8.0 legacy format is out of scope for this tool -- skipped: $($iItem.FullName)"
                continue
            }
            if ($parsed.Status -eq 'Malformed') {
                $MalformedHeaders.Add([PSCustomObject]@{ Path = $iItem.FullName; Reason = $parsed.Reason })
                continue
            }

            # window filter -- drop items outside an active incident window
            if ($WindowSet) {
                if (-not $parsed.DeleteTimeUtc) { continue }
                if ($parsed.DeleteTimeUtc -lt $WindowCutoffUtc) { continue }
            }

            $rName = '$R' + $iItem.Name.Substring(2)
            $rExistedInInitialListing = $nameSet.Contains($rName)
            $rFullPath = Join-Path $sidFolder.FullName $rName

            $rItem = $null
            $rAccessNote = $null
            if ($rExistedInInitialListing) {
                try {
                    $rItem = Get-Item -LiteralPath $rFullPath -Force -ErrorAction Stop
                } catch {
                    $rAccessNote = "R file inaccessible/purged during scan: $($_.Exception.Message)"
                    $InaccessibleRFilesTOCTOU.Add([PSCustomObject]@{ Path = $rFullPath; Reason = $_.Exception.Message })
                }
            }

            $record = [PSCustomObject]@{
                RecordType        = 'Paired'
                Owner             = $ownerName
                SidString         = $sidFolder.Name
                RootPath          = $root
                IFilePath         = $iItem.FullName
                RFilePath         = $(if ($rExistedInInitialListing) { $rFullPath } else { $null })
                HasR              = $rExistedInInitialListing
                RAccessible       = ($null -ne $rItem)
                RFileAccessNote   = $rAccessNote
                DeleteTimeUtc     = $parsed.DeleteTimeUtc
                OriginalPath      = $parsed.OriginalPath
                OriginalSizeBytes = $parsed.FileSize
                IsFolder          = $false
                CurrentSizeBytes  = $null
                CurrentCreatedUtc = $null
                CurrentModifiedUtc = $null
                CurrentAccessedUtc = $null
                FolderStats       = $null
                FileHash          = $null
                Evidence          = New-Object System.Collections.Generic.List[string]
                Score             = 0
            }

            if ($rItem) {
                $record.CurrentCreatedUtc  = $rItem.CreationTimeUtc
                $record.CurrentModifiedUtc = $rItem.LastWriteTimeUtc
                $record.CurrentAccessedUtc = $rItem.LastAccessTimeUtc
                if ($rItem.PSIsContainer) {
                    $record.IsFolder = $true
                    $folderStats = Get-RecoveredFolderStats -FolderPath $rItem.FullName -DoHash ([bool]$Hash) -MaxHashBytes $MaxHashBytes
                    $record.FolderStats = $folderStats
                    $record.CurrentSizeBytes = $folderStats.TotalSize
                } else {
                    $record.CurrentSizeBytes = $rItem.Length
                    if ($Hash) {
                        $record.FileHash = Get-FileHashSafe -FilePath $rItem.FullName -SizeBytes $rItem.Length -MaxBytes $MaxHashBytes
                    } else {
                        $record.FileHash = 'N/A (hashing disabled -- use -Hash to enable)'
                    }
                }
            }

            # ---------------- evidence scoring ----------------
            if (-not $record.HasR) {
                $record.Evidence.Add('ORPHAN-I')
                $record.Score += 3
            }
            if ($record.RAccessible -and $record.DeleteTimeUtc -and ($record.CurrentCreatedUtc -or $record.CurrentModifiedUtc)) {
                if (($record.CurrentCreatedUtc -and $record.CurrentCreatedUtc -gt $record.DeleteTimeUtc) -or
                    ($record.CurrentModifiedUtc -and $record.CurrentModifiedUtc -gt $record.DeleteTimeUtc)) {
                    $record.Evidence.Add('TIMESTAMP-ANOMALY')
                    $record.Score += 4
                }
            }
            $ext = ''
            try { $ext = ([System.IO.Path]::GetExtension($record.OriginalPath)).TrimStart('.').ToLowerInvariant() } catch { $ext = '' }
            if ($ext -and ($SuspiciousExtensions -contains $ext)) {
                if ($record.OriginalPath -match '\\Temp\\' -or
                    $record.OriginalPath -match '\\Downloads\\' -or
                    $record.OriginalPath -match '^[A-Za-z]:\\[^\\]+$') {
                    $record.Evidence.Add('SUSPICIOUS-ORIGINAL-EXT')
                    $record.Score += 3
                }
            }

            $AllRecords.Add($record)
        }

        # ---------------- standalone $R items (no $I present at all) ----------------
        foreach ($rItemEntry in $rItems) {
            $iName = '$I' + $rItemEntry.Name.Substring(2)
            if ($nameSet.Contains($iName)) { continue }   # paired, already handled above

            $rItemLive = $null
            $rAccessNote = $null
            try {
                $rItemLive = Get-Item -LiteralPath $rItemEntry.FullName -Force -ErrorAction Stop
            } catch {
                $rAccessNote = "R file inaccessible/purged during scan: $($_.Exception.Message)"
                $InaccessibleRFilesTOCTOU.Add([PSCustomObject]@{ Path = $rItemEntry.FullName; Reason = $_.Exception.Message })
            }

            $record = [PSCustomObject]@{
                RecordType        = 'OrphanR'
                Owner             = $ownerName
                SidString         = $sidFolder.Name
                RootPath          = $root
                IFilePath         = $null
                RFilePath         = $rItemEntry.FullName
                HasR              = $true
                RAccessible       = ($null -ne $rItemLive)
                RFileAccessNote   = $rAccessNote
                DeleteTimeUtc     = $null
                OriginalPath      = $null
                OriginalSizeBytes = $null
                IsFolder          = $false
                CurrentSizeBytes  = $null
                CurrentCreatedUtc = $null
                CurrentModifiedUtc = $null
                CurrentAccessedUtc = $null
                FolderStats       = $null
                FileHash          = $null
                Evidence          = New-Object System.Collections.Generic.List[string]
                Score             = 0
            }

            if ($rItemLive) {
                $record.CurrentCreatedUtc  = $rItemLive.CreationTimeUtc
                $record.CurrentModifiedUtc = $rItemLive.LastWriteTimeUtc
                $record.CurrentAccessedUtc = $rItemLive.LastAccessTimeUtc
                if ($rItemLive.PSIsContainer) {
                    $record.IsFolder = $true
                    $folderStats = Get-RecoveredFolderStats -FolderPath $rItemLive.FullName -DoHash ([bool]$Hash) -MaxHashBytes $MaxHashBytes
                    $record.FolderStats = $folderStats
                    $record.CurrentSizeBytes = $folderStats.TotalSize
                } else {
                    $record.CurrentSizeBytes = $rItemLive.Length
                    if ($Hash) {
                        $record.FileHash = Get-FileHashSafe -FilePath $rItemLive.FullName -SizeBytes $rItemLive.Length -MaxBytes $MaxHashBytes
                    } else {
                        $record.FileHash = 'N/A (hashing disabled -- use -Hash to enable)'
                    }
                }
            }

            $record.Evidence.Add('ORPHAN-R')
            $record.Score += 3

            # Orphan-R items have no recorded DeleteTime, so they are never dropped by
            # an active incident window -- excluding them would hide exactly the kind
            # of evidence a window search is trying to surface (metadata destroyed).
            $AllRecords.Add($record)
        }
    }
}

# ======================================================================
#  DELETION-CLUSTER (only evaluated with an active incident window)
# ======================================================================
if ($WindowSet) {
    $clusterable = $AllRecords | Where-Object { $_.DeleteTimeUtc }
    $groups = $clusterable | Group-Object -Property {
        $bucketMinute = [int]([Math]::Floor($_.DeleteTimeUtc.Minute / 5) * 5)
        "{0}|{1}|{2:D2}" -f $_.SidString, $_.DeleteTimeUtc.ToString('yyyy-MM-dd HH'), $bucketMinute
    }
    foreach ($g in $groups) {
        if ($g.Count -ge 5) {
            foreach ($rec in $g.Group) {
                $rec.Evidence.Add('DELETION-CLUSTER')
                $rec.Score += 3
            }
        }
    }
}

# ======================================================================
#  Output: VOLUMES SCANNED
# ======================================================================
Write-Host ''
Write-Host '===== VOLUMES SCANNED ====='
foreach ($v in $VolumesScanned) {
    if ($v.Present) {
        Write-Host "  [present] $($v.Root)"
    } else {
        Write-Host "  [absent]  $($v.Root)  (no `$Recycle.Bin -- not an error)"
    }
}
if ($InaccessibleRoots.Count -gt 0) {
    Write-Host ''
    Write-Host "  INACCESSIBLE (needs elevation or was removed mid-scan):"
    foreach ($i in $InaccessibleRoots) { Write-Host "    $i" }
}

# ======================================================================
#  Output: per-item enumeration, grouped by owner
# ======================================================================
Write-Host ''
Write-Host '===== RECOVERED ITEMS (by owner) ====='

$byOwner = $AllRecords | Group-Object -Property Owner | Sort-Object Name

if ($byOwner.Count -eq 0) {
    Write-Host '  (no recoverable $I records found across scanned roots)'
}

$OverallOriginalSize = [long]0
$OverallCurrentSize  = [long]0
$OverallItemCount    = 0

foreach ($ownerGroup in $byOwner) {
    Write-Host ''
    Write-Host "-- $($ownerGroup.Name) ($($ownerGroup.Group[0].SidString)) --"

    $userOriginalSize = [long]0
    $userCurrentSize  = [long]0

    foreach ($rec in ($ownerGroup.Group | Sort-Object { $_.DeleteTimeUtc })) {
        $tier = Get-Tier -Score $rec.Score
        $tag = ''
        if ($tier -eq 'HIGH') { $tag = '[HIGH] ' }
        elseif ($tier -eq 'NOTABLE') { $tag = '[NOTABLE] ' }

        if ($rec.RecordType -eq 'Paired') {
            Write-Host ''
            Write-Host "${tag}Recycle Bin item: $($rec.IFilePath)"
            Write-Host "   Deleted (UTC) : $(Format-Utc $rec.DeleteTimeUtc)"
            Write-Host "   Original Path : $($rec.OriginalPath)"
            Write-Host "   Original Size : $(Format-Bytes $rec.OriginalSizeBytes)"
            Write-Host "   `$I File       : $($rec.IFilePath)"
            if ($rec.HasR) {
                Write-Host "   `$R File       : $($rec.RFilePath)"
                if ($rec.RAccessible) {
                    Write-Host "   Current Size  : $(Format-Bytes $rec.CurrentSizeBytes)$(if ($rec.IsFolder) { " (folder, $($rec.FolderStats.FileCount) file(s))" })"
                    Write-Host "   Current Times : Created $(Format-Utc $rec.CurrentCreatedUtc) | Modified $(Format-Utc $rec.CurrentModifiedUtc) | Accessed $(Format-Utc $rec.CurrentAccessedUtc)"
                    if ($rec.IsFolder) {
                        if ($rec.FolderStats.WalkNote) { Write-Host "   Folder Walk   : $($rec.FolderStats.WalkNote)" }
                        foreach ($f in $rec.FolderStats.Files) {
                            Write-Host "      - $($f.RelativePath)  ($(Format-Bytes $f.Size))  hash: $($f.Hash)"
                        }
                    } else {
                        Write-Host "   File Hash     : $($rec.FileHash)"
                    }
                } else {
                    Write-Host "   `$R Status     : $($rec.RFileAccessNote)"
                }
            } else {
                Write-Host "   `$R File       : (none found -- metadata survives, content is gone)"
            }
        } else {
            # OrphanR
            Write-Host ''
            Write-Host "${tag}Recycle Bin item (orphan `$R -- no `$I metadata record): $($rec.RFilePath)"
            Write-Host "   `$I File       : (none found -- content survives, metadata record is missing)"
            if ($rec.RAccessible) {
                Write-Host "   Current Size  : $(Format-Bytes $rec.CurrentSizeBytes)$(if ($rec.IsFolder) { " (folder, $($rec.FolderStats.FileCount) file(s))" })"
                Write-Host "   Current Times : Created $(Format-Utc $rec.CurrentCreatedUtc) | Modified $(Format-Utc $rec.CurrentModifiedUtc) | Accessed $(Format-Utc $rec.CurrentAccessedUtc)"
                if ($rec.IsFolder) {
                    if ($rec.FolderStats.WalkNote) { Write-Host "   Folder Walk   : $($rec.FolderStats.WalkNote)" }
                    foreach ($f in $rec.FolderStats.Files) {
                        Write-Host "      - $($f.RelativePath)  ($(Format-Bytes $f.Size))  hash: $($f.Hash)"
                    }
                } else {
                    Write-Host "   File Hash     : $($rec.FileHash)"
                }
            } else {
                Write-Host "   `$R Status     : $($rec.RFileAccessNote)"
            }
        }

        if ($rec.Evidence.Count -gt 0) {
            Write-Host "   Evidence      : $($rec.Evidence -join ', ')  (score $($rec.Score), tier $tier)"
        }

        if ($rec.OriginalSizeBytes) { $userOriginalSize += $rec.OriginalSizeBytes }
        if ($rec.CurrentSizeBytes)  { $userCurrentSize  += $rec.CurrentSizeBytes }
    }

    Write-Host ''
    Write-Host "   [$($ownerGroup.Name) summary] items: $($ownerGroup.Count) | original size: $(Format-Bytes $userOriginalSize) | current size: $(Format-Bytes $userCurrentSize)"

    $OverallOriginalSize += $userOriginalSize
    $OverallCurrentSize  += $userCurrentSize
    $OverallItemCount    += $ownerGroup.Count
}

# ======================================================================
#  Output: SUMMARY
# ======================================================================
Write-Host ''
Write-Host '===== SUMMARY ====='
Write-Host "  Total items recovered   : $OverallItemCount"
Write-Host "  Total original size     : $(Format-Bytes $OverallOriginalSize)"
Write-Host "  Total current size      : $(Format-Bytes $OverallCurrentSize)"
Write-Host "  Space still recoverable : $(Format-Bytes $OverallCurrentSize)  (bytes still on disk in existing `$R content -- freed only if the bin is emptied)"
Write-Host ''
Write-Host "  Coverage gaps (explicit -- not hidden):"
Write-Host "    Skipped (legacy `$I version, out of scope) : $($SkippedLegacyVersion.Count)"
foreach ($s in $SkippedLegacyVersion) { Write-Host "      - v$($s.Version): $($s.Path)" }
Write-Host "    Malformed/truncated `$I headers            : $($MalformedHeaders.Count)"
foreach ($m in $MalformedHeaders) { Write-Host "      - $($m.Path) -- $($m.Reason)" }
Write-Host "    Unreadable `$I files                        : $($UnreadableIFiles.Count)"
foreach ($u in $UnreadableIFiles) { Write-Host "      - $($u.Path) -- $($u.Reason)" }
Write-Host "    Inaccessible `$R files (TOCTOU / purged)     : $($InaccessibleRFilesTOCTOU.Count)"
foreach ($t in $InaccessibleRFilesTOCTOU) { Write-Host "      - $($t.Path) -- $($t.Reason)" }
Write-Host "    Inaccessible roots/SID folders (elevation) : $($InaccessibleRoots.Count)"
foreach ($r in $InaccessibleRoots) { Write-Host "      - $r" }

# ======================================================================
#  Output: ANOMALY QUEUE
# ======================================================================
Write-Host ''
Write-Host '===== ANOMALY QUEUE ====='

$queueMinRank = 2   # NOTABLE and up always eligible for the queue
if ($MinSeverity -eq 'High') { $queueMinRank = 3 }

$rankOf = @{ 'HIGH' = 3; 'NOTABLE' = 2; 'CLEAN' = 1 }
$queued = $AllRecords | ForEach-Object {
    $t = Get-Tier -Score $_.Score
    [PSCustomObject]@{ Record = $_; Tier = $t; Rank = $rankOf[$t] }
} | Where-Object { $_.Rank -ge 2 -and $_.Rank -ge $queueMinRank } | Sort-Object -Property Rank -Descending

if ($queued.Count -eq 0) {
    Write-Host '  (none -- no item met the NOTABLE/HIGH evidence threshold at the current -MinSeverity)'
} else {
    foreach ($q in $queued) {
        $rec = $q.Record
        $label = if ($rec.RecordType -eq 'Paired') { $rec.IFilePath } else { $rec.RFilePath }
        Write-Host ''
        Write-Host "[$($q.Tier)] $($rec.Owner): $label"
        Write-Host "   why: $($rec.Evidence -join ', ')  (score $($rec.Score))"
    }
    Write-Host ''
    $hiCount = ($queued | Where-Object { $_.Tier -eq 'HIGH' }).Count
    $noCount = ($queued | Where-Object { $_.Tier -eq 'NOTABLE' }).Count
    Write-Host "  $hiCount HIGH * $noCount NOTABLE"
}

Write-Host ''
