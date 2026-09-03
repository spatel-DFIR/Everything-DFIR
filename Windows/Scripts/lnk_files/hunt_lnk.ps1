<#
.SYNOPSIS
  Read-only sweep and forensic deep-dive of Windows .lnk (shortcut) files for DFIR triage.
.DESCRIPTION
  Evidence-weighted LNK triage tool. Full design doc, scoring table, MS-SHLLINK field
  reference, and changelog live in README.md alongside this script -- read that for detail.
  Sweep mode (default) scans %SystemDrive%\Users\*, the all-users Startup folder, every
  removable drive root, and any -Path roots; scores each .lnk into [HIGH]/[NOTABLE]/clean.
  Deep-dive mode (-Path <single .lnk>) prints full COM properties plus MS-SHLLINK binary
  forensic data COM never exposes (header timestamps, volume serial, tracker MachineID/MAC/
  Droid GUIDs, MFT entry/sequence, and other decoded ExtraDataBlocks).
  READ-ONLY. Never calls the shortcut's .Save() or any COM write method. Console-only by default;
  -OutFile is the sole opt-in exception (CSV export). RTR-safe; no elevation required.
.PARAMETER Path
  A single .lnk file switches to deep-dive mode; directories/files add to the sweep scope.
.PARAMETER Since
  Incident window start (YYYY-MM-DD); feeds RECENT (+2, never alone).
.PARAMETER Days
  Incident window as "last N days" instead of -Since.
.PARAMETER MinSeverity
  high|notable|low (default low); high hides NOTABLE.
.PARAMETER Hash
  SHA-256 the resolved target of flagged items. Off by default.
.PARAMETER Detail
  Full per-item forensic detail + full clean-item list, vs. one summary line each by default.
  (Named -Detail not -Debug: PowerShell reserves -Debug as a built-in common parameter.)
.PARAMETER OutFile
  CSV export path (off by default), full forensic field set, one row per item.
.PARAMETER Help
  Show help and exit.
.EXAMPLE
  hunt_lnk.ps1
.EXAMPLE
  hunt_lnk.ps1 -Path 'D:\Badmark\2020-05-20.txt.lnk'
.EXAMPLE
  hunt_lnk.ps1 -OutFile C:\triage\lnk_findings.csv -Hash -Detail
.NOTES
  Script  : hunt_lnk.ps1   Version : 1.5   Author : Suvas Patel
  Safety  : Read-only, console-only by default (-OutFile is the sole write path). No
            elevation required; degrades gracefully with an access-denied summary.
#>
[CmdletBinding()]
param(
  [string[]]$Path,
  [string]$Since,
  [int]$Days,
  [ValidateSet('high', 'notable', 'low')]
  [string]$MinSeverity = 'low',
  [switch]$Hash,
  [switch]$Detail,
  [string]$OutFile,
  [switch]$Help
)
$Version = '1.5'
$Author  = 'Suvas Patel'
# Script-scoped: $PSBoundParameters inside a nested function is that function's own (empty) params.
$script:ScriptBoundParams = $PSBoundParameters
if ($Help) {
  try {
    Get-Help -Name $PSCommandPath -Full
  } catch {
    Write-Host "hunt_lnk.ps1 v$Version -- see the comment-based help at the top of the script, or README.md."
  }
  return
}
# LOLBins/script hosts abused as LNK targets; matched leaf-name-exact (not substring) below.
$LolBins = @(
  'cmd', 'cmd.exe', 'powershell', 'powershell_ise', 'pwsh', 'wscript', 'cscript', 'mshta',
  'rundll32', 'regsvr32', 'certutil', 'bitsadmin', 'forfiles', 'msiexec', 'msbuild',
  'installutil', 'regasm', 'regsvcs', 'cmstp', 'wmic'
)
# Encoded / obfuscated / download markers -> strong payload evidence on their own.
$strongRx = '(-enc\b|-EncodedCommand\b|FromBase64String|IEX\b|Invoke-Expression|DownloadString|DownloadFile|https?://)'
# Hidden-window flags only count as a payload marker when stacked with a URL or an encoded blob.
$hiddenRx    = '(-w\s+hidden|-windowstyle\s+hidden|-nop\b|-noprofile\b)'
$blobRx     = '[A-Za-z0-9+/]{40,}={0,2}'
# Doc/media extensions left in the LNK's own name -> Windows hides the real .lnk extension
# (Invoice.pdf.lnk displays as "Invoice.pdf" -- classic phishing tell).
$masqRx = '\.(txt|pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|zip|csv)$'
# Caps a multi-GB file renamed .lnk from being fully buffered into memory.
$maxSz = 5MB
# KNOWNFOLDERID -> friendly name (persistence-relevant folders only; unmapped prints raw GUID).
$kfm = @{
  'B97D20BB-F46A-4C97-BA10-5E3608430854' = 'Startup (per-user)'
  '82A5EA35-D9CD-47C5-9629-E15D2F714E47' = 'Startup (common/all-users)'
  'B4BFCC3A-DB2C-424C-B029-7FE99A87C641' = 'Desktop'
  'C4AA340D-F20F-4863-AFEF-F87EF2E6BA25' = 'Desktop (common/all-users)'
  '374DE290-123F-4565-9164-39C4925E467B' = 'Downloads'
  'FDD39AD0-238F-46AF-ADB4-6C85480369C7' = 'Documents'
  '3EB685DB-65F9-4CF6-A03A-E3EF65729F3D' = 'Roaming AppData'
  'F1B32785-6FBA-4FCF-9D55-7B8E7F157091' = 'Local AppData'
  '62AB5D82-FDC1-4DC3-A9DD-070D1D495D97' = 'ProgramData'
  '1AC14E77-02E7-4E5D-B744-2EB1AE5198B7' = 'System32'
  'F38BF404-1D43-42F2-9305-67DE0B28FC23' = 'Windows'
  '5E6C858F-0E22-4760-9AFE-EA3317B67173' = 'User Profile'
  '0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8' = 'Start Menu Programs (common/all-users)'
  '8983036C-27C0-404B-8F08-102D10DCFD74' = 'SendTo'
  'AE50C081-EBD2-438A-8655-8A092E34987A' = 'Recent Items'
}
# [Convert]::ToUInt32, not bare hex: >0x7FFFFFFF parses negative Int32, -eq vs UInt32 silently never matches (v1.3).
$Sigs = @{
  EnvironmentVariable = [Convert]::ToUInt32('A0000001', 16); Console = [Convert]::ToUInt32('A0000002', 16)
  Tracker = [Convert]::ToUInt32('A0000003', 16); ConsoleFE = [Convert]::ToUInt32('A0000004', 16)
  SpecialFolder = [Convert]::ToUInt32('A0000005', 16); Darwin = [Convert]::ToUInt32('A0000006', 16)
  IconEnvironment = [Convert]::ToUInt32('A0000007', 16); Shim = [Convert]::ToUInt32('A0000008', 16)
  PropertyStore = [Convert]::ToUInt32('A0000009', 16); KnownFolder = [Convert]::ToUInt32('A000000B', 16)
  VistaIDList = [Convert]::ToUInt32('A000000C', 16)
}
function Test-IsElevated {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}
function Get-EffectiveCommandLine {
  if ($script:ScriptBoundParams.Count -eq 0) { return '(no options -- default sweep)' }
  $parts = foreach ($kv in $script:ScriptBoundParams.GetEnumerator()) {
    $val = $kv.Value
    if ($val -is [switch]) {
      if ($val.IsPresent) { "-$($kv.Key)" }
    } elseif ($val -is [array]) {
      "-$($kv.Key) " + ($val -join ',')
    } else {
      "-$($kv.Key) $val"
    }
  }
  return ($parts -join ' ')
}
function Write-Banner {
  param([string]$Mode)
  Write-Host "hunt_lnk.ps1  v$Version    author: $Author
Ran at   : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC
Hostname : $env:COMPUTERNAME
Mode     : $Mode
Command  : hunt_lnk.ps1 $(Get-EffectiveCommandLine)"
  if (-not (Test-IsElevated)) {
    Write-Host "
!! WARNING: not running elevated. Some other users' profiles under $env:SystemDrive\Users may
!! be partially or fully inaccessible; those paths are skipped and counted as
!! access-denied below rather than silently reported clean.
!! Re-run from an elevated session for full coverage." -ForegroundColor Yellow
  }
}
function Get-ByteSlice {
  param([byte[]]$by, [int]$Start, [int]$Length)
  $slice = New-Object byte[] $Length
  [Array]::Copy($by, $Start, $slice, 0, $Length)
  return , $slice
}
function ConvertTo-LnkGuidString {
  param([byte[]]$by)
  try {
    return ([Guid]::new($by)).ToString().ToUpperInvariant()
  } catch {
    return 'N/A (parse error)'
  }
}
function Get-ShellItemFileReference {
  # 0xBEEF0004 block; Win7+ carries FILE_REFERENCE (entry/seq), offset 20, verified vs LECmd (v1.3).
  param([byte[]]$ib)
  $res = [ordered]@{
    Found        = $false
    ExtensionVer = $null
    MftEntry     = $null
    MftSequence  = $null
  }
  if ($null -eq $ib -or $ib.Length -lt 8) { return [pscustomobject]$res }
  $sgb = [byte[]](0x04, 0x00, 0xEF, 0xBE)  # 0xBEEF0004 little-endian
  for ($i = 0; $i -le ($ib.Length - 4); $i++) {
    if ($ib[$i] -eq $sgb[0] -and $ib[$i+1] -eq $sgb[1] -and
      $ib[$i+2] -eq $sgb[2] -and $ib[$i+3] -eq $sgb[3]) {
      $bst = $i - 4   # start of the 2-byte ExtensionSize field
      if ($bst -lt 0 -or ($bst + 4) -gt $ib.Length) { continue }
      $extSize = [BitConverter]::ToUInt16($ib, $bst)
      $extVer  = [BitConverter]::ToUInt16($ib, $bst + 2)
      if ($extSize -lt 8 -or ($bst + $extSize) -gt $ib.Length) { continue }
      $res.Found        = $true
      $res.ExtensionVer = $extVer
      # FILE_REFERENCE, Win7+ only, offset 20.
      $fro = $bst + 20
      if ($extVer -ge 7 -and ($fro + 8) -le $ib.Length -and ($fro + 8) -le ($bst + $extSize)) {
        $fileRef = [BitConverter]::ToUInt64($ib, $fro)
        $res.MftEntry    = $fileRef -band 0xFFFFFFFFFFFF
        $res.MftSequence = ($fileRef -shr 48) -band 0xFFFF
      }
      break
    }
  }
  return [pscustomobject]$res
}
function Get-DualStringBlockValue {
  # 260-byte ANSI + optional 520-byte Unicode, null-terminated. Prefers Unicode when present.
  param([byte[]]$by, [int]$dst, [int]$bnd)
  $value = 'N/A'
  if (($dst + 260) -le $by.Length -and ($dst + 260) -le $bnd) {
    $ansiBytes = Get-ByteSlice -by $by -Start $dst -Length 260
    $ansiStr = [System.Text.Encoding]::ASCII.GetString($ansiBytes).TrimEnd([char]0).Trim()
    if ($ansiStr) { $value = $ansiStr }
  }
  $us = $dst + 260
  if (($us + 520) -le $by.Length -and ($us + 520) -le $bnd) {
    $uBytes = Get-ByteSlice -by $by -Start $us -Length 520
    $uStr = [System.Text.Encoding]::Unicode.GetString($uBytes).TrimEnd([char]0).Trim()
    if ($uStr) { $value = $uStr }
  }
  return $value
}
function Convert-LnkFileTime {
  param([Int64]$ft)
  if ($ft -eq 0) { return 'N/A (unset)' }
  try {
    return ([DateTime]::FromFileTimeUtc($ft)).ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
  } catch {
    return 'N/A (invalid FILETIME)'
  }
}
function Get-WindowStyleLabel {
  param($Style)
  switch ($Style) {
    1 { 'Normal' }
    3 { 'Maximized' }
    7 { 'Minimized' }
    default { 'Unknown' }
  }
}
function Test-IsLolBin {
  param([string]$tp)
  if ([string]::IsNullOrWhiteSpace($tp)) { return $false }
  $leaf      = [System.IO.Path]::GetFileName($tp)
  $leafNoExt = [System.IO.Path]::GetFileNameWithoutExtension($tp)
  foreach ($b in $LolBins) {
    if ($leaf -ieq $b -or $leafNoExt -ieq $b -or $leaf -ieq "$b.exe") { return $true }
  }
  return $false
}
function Test-HasPayloadMarker {
  param([string]$args2)
  if ([string]::IsNullOrWhiteSpace($args2)) { return $false }
  if ($args2 -imatch $strongRx) { return $true }
  if ($args2 -imatch $hiddenRx) {
    if ($args2 -imatch 'https?://') { return $true }
    if ($args2 -imatch $blobRx) { return $true }
  }
  return $false
}
function Test-DoubleExtMasquerade {
  param([string]$LnkFileName)
  $nameNoLnk = $LnkFileName -replace '\.lnk$', ''
  return ($nameNoLnk -imatch $masqRx)
}
function Test-DanglingTarget {
  param([string]$tp)
  if ([string]::IsNullOrWhiteSpace($tp)) { return $false }
  if ($tp -notmatch '^[A-Za-z]:\\|^\\\\') { return $false }  # shell-namespace targets aren't paths
  if ($tp -match '^\\\\') { return $false }  # UNC not probed: dead \\host\share blocks for SMB timeout
  return (-not (Test-Path -LiteralPath $tp))
}
function Test-IconSpoof {
  param([string]$tp, [string]$IconLocation)
  if ([string]::IsNullOrWhiteSpace($IconLocation)) { return $false }
  if (-not (Test-IsLolBin -tp $tp)) { return $false }
  $iconFile = ($IconLocation -split ',')[0]
  if ([string]::IsNullOrWhiteSpace($iconFile)) { return $false }
  $iconLeaf   = [System.IO.Path]::GetFileName($iconFile)
  $targetLeaf = [System.IO.Path]::GetFileName($tp)
  if ([string]::IsNullOrWhiteSpace($iconLeaf) -or [string]::IsNullOrWhiteSpace($targetLeaf)) { return $false }
  return ($iconLeaf -ine $targetLeaf)
}
function Test-SuspiciousPath {
  param([string]$tp, [string]$WorkingDirectory)
  foreach ($p in @($tp, $WorkingDirectory)) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    if ($p -imatch '\\AppData\\Local\\Temp\\') { return $true }
    if ($p -imatch '\\Temp\\') { return $true }
    if ($p -imatch '\\Windows\\Temp\\') { return $true }
    if ($p -imatch '\\Users\\Public\\') { return $true }
    if ($p -imatch '\\\.[^\\]+(\\|$)') { return $true }  # hidden/dot-prefixed folder segment
    # dropped directly at a drive root or ProgramData root -- non-standard install location
    if ($p -imatch '^[A-Za-z]:\\[^\\]+\.(exe|dll|scr|bat|cmd|com|ps1|vbs|js)$') { return $true }
    if ($p -imatch '^[A-Za-z]:\\ProgramData\\[^\\]+\.(exe|dll|scr|bat|cmd|com|ps1|vbs|js)$') { return $true }
  }
  return $false
}
function Test-IsJunction {
  # Redirection junctions deny listing by OS design -- excluded from the access-denied tally.
  param([string]$Path)
  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    return [bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
  } catch {
    return $false
  }
}
function Get-LnkComProperties {
  # Shared WScript.Shell property shape so the field list can't drift; $null gives the all-null shape.
  param($sc)
  if ($null -eq $sc) {
    return [pscustomobject]@{
      TargetPath = $null; Arguments = $null; WorkingDirectory = $null
      Description = $null; Hotkey = $null; IconLocation = $null; WindowStyle = $null
    }
  }
  return [pscustomobject]@{
    TargetPath = $sc.TargetPath; Arguments = $sc.Arguments
    WorkingDirectory = $sc.WorkingDirectory; Description = $sc.Description
    Hotkey = $sc.Hotkey; IconLocation = $sc.IconLocation
    WindowStyle = $sc.WindowStyle
  }
}
function Get-TargetHash {
  param([string]$tp)
  if ([string]::IsNullOrWhiteSpace($tp)) { return $null }
  if (-not (Test-Path -LiteralPath $tp -PathType Leaf)) { return $null }
  try {
    return (Get-FileHash -LiteralPath $tp -Algorithm SHA256 -ErrorAction Stop).Hash
  } catch {
    return $null
  }
}
function Add-Evidence {
  param([ref]$Score, [System.Collections.Generic.List[string]]$Reasons, [int]$Weight, [string]$Reason)
  $Score.Value += $Weight
  if (-not $Reasons.Contains($Reason)) { $Reasons.Add($Reason) }
}
function Get-Tier {
  param([int]$Score)
  if ($Score -ge 5) { return 'HIGH' }
  if ($Score -ge 3) { return 'NOTABLE' }
  return 'LOW'
}
function Get-LnkFinding {
  param([Parameter(Mandatory)][string]$lkp, [Parameter(Mandatory)]$pr, [Parameter(Mandatory)][System.IO.FileInfo]$fi, $rtu)
  $scr   = 0
  $rs = New-Object System.Collections.Generic.List[string]
  $tgt = $pr.TargetPath
  $isLolBin   = Test-IsLolBin -tp $tgt
  if ($isLolBin) {
    if (Test-HasPayloadMarker -args2 $pr.Arguments) {
      Add-Evidence ([ref]$scr) $rs 5 'LOLBIN-PAYLOAD'
    } else {
      # Below NOTABLE alone -- stock cmd/powershell shortcuts are common; promotes only when stacked.
      Add-Evidence ([ref]$scr) $rs 2 'LOLBIN-TARGET'
    }
    if (Test-IconSpoof -tp $tgt -IconLocation $pr.IconLocation) {
      Add-Evidence ([ref]$scr) $rs 2 'ICON-SPOOF-SUSPECTED'
    }
  }
  if (Test-DoubleExtMasquerade -LnkFileName $fi.Name) {
    Add-Evidence ([ref]$scr) $rs 4 'DOUBLE-EXT-MASQUERADE'
  }
  if (Test-DanglingTarget -tp $tgt) {
    Add-Evidence ([ref]$scr) $rs 3 'DANGLING-TARGET'
  }
  if (Test-SuspiciousPath -tp $tgt -WorkingDirectory $pr.WorkingDirectory) {
    Add-Evidence ([ref]$scr) $rs 2 'SUSPICIOUS-PATH'
  }
  $isRecent = $false
  if ($rtu) {
    if ($fi.LastWriteTimeUtc -ge $rtu) {
      Add-Evidence ([ref]$scr) $rs 2 'RECENT'
      $isRecent = $true
    }
  }
  $lnkBase    = [System.IO.Path]::GetFileNameWithoutExtension($fi.Name)
  $tb = $null
  if ($tgt) { $tb = [System.IO.Path]::GetFileNameWithoutExtension($tgt) }
  $nameMismatch = ($tb) -and ($lnkBase -ine $tb)
  [pscustomobject]@{
    Score        = $scr
    Tier         = Get-Tier -Score $scr
    Reasons      = $rs
    NameMismatch = [bool]$nameMismatch
    IsLolBin     = $isLolBin
    IsRecent     = $isRecent
  }
}
# MS-SHLLINK parser; bounds-checked, never throws.
function Get-ShellLinkForensicData {
  param([Parameter(Mandatory)][string]$Path)
  $r = [ordered]@{
    HeaderValid = $false; HeaderSize = $null; FileAttributes = $null
    HeaderCreationTime = 'N/A'; HeaderAccessTime = 'N/A'; HeaderWriteTime = 'N/A'
    FileSize = $null; IconIndex = $null; ShowCommand = $null; HotKey = $null
    DriveSerialNumber = 'N/A'; MachineID = 'N/A'; MAC = 'N/A (no tracker block)'
    DroidVolumeID = 'N/A'; DroidFileID = 'N/A'
    DroidBirthVolumeID = 'N/A'; DroidBirthFileID = 'N/A'
    MftEntry = 'N/A'; MftSequence = 'N/A'; MftReferenceNote = $null
    EnvironmentVarTarget = 'N/A'; IconEnvironmentPath = 'N/A'; DarwinAppID = 'N/A'
    ShimLayer = 'N/A'; SpecialFolderID = 'N/A'
    KnownFolderID = 'N/A'; KnownFolderName = 'N/A'
    OtherExtraBlocks = New-Object System.Collections.Generic.List[string]
    ParseError = $null
  }
  try {
    $sizeCheck = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($sizeCheck.Length -gt $maxSz) {
      $r.ParseError = "File too large to parse ($($sizeCheck.Length) bytes, cap is $maxSz) -- skipped rather than buffered fully into memory"
      return [pscustomobject]$r
    }
  } catch {
    $r.ParseError = "Could not stat file: $($_.Exception.Message)"
    return [pscustomobject]$r
  }
  $b = $null
  try {
    $b = [System.IO.File]::ReadAllBytes($Path)
  } catch {
    $r.ParseError = "Could not read file: $($_.Exception.Message)"
    return [pscustomobject]$r
  }
  if ($null -eq $b -or $b.Length -lt 76) {
    $r.ParseError = "File too small to be a valid shell link ($($b.Length) bytes)"
    return [pscustomobject]$r
  }
  try {
    # ---- ShellLinkHeader (fixed 76 bytes @ offset 0) ----
    $hsz = [BitConverter]::ToUInt32($b, 0)
    $r.HeaderSize = $hsz
    if ($hsz -ne 76) {
      $r.ParseError = "Unexpected HeaderSize 0x$('{0:X}' -f $hsz) (expected 0x4C)"
      return [pscustomobject]$r
    }
    $r.HeaderValid = $true
    $lf = [BitConverter]::ToUInt32($b, 20)
    $r.FileAttributes = [BitConverter]::ToUInt32($b, 24)
    $hasIDL = [bool]($lf -band 0x1)
    $hasLinkInfo         = [bool]($lf -band 0x2)
    $hasName             = [bool]($lf -band 0x4)
    $hasRelativePath     = [bool]($lf -band 0x8)
    $hasWorkingDir       = [bool]($lf -band 0x10)
    $hasArguments        = [bool]($lf -band 0x20)
    $hasIconLocation     = [bool]($lf -band 0x40)
    $isUnicode           = [bool]($lf -band 0x80)
    $creationFt = [BitConverter]::ToInt64($b, 28)
    $accessFt   = [BitConverter]::ToInt64($b, 36)
    $writeFt    = [BitConverter]::ToInt64($b, 44)
    $r.HeaderCreationTime = Convert-LnkFileTime -ft $creationFt
    $r.HeaderAccessTime   = Convert-LnkFileTime -ft $accessFt
    $r.HeaderWriteTime    = Convert-LnkFileTime -ft $writeFt
    $r.FileSize    = [BitConverter]::ToUInt32($b, 52)
    $r.IconIndex   = [BitConverter]::ToInt32($b, 56)
    $r.ShowCommand = [BitConverter]::ToUInt32($b, 60)
    $r.HotKey      = [BitConverter]::ToUInt16($b, 64)
    $off = 76
    # Walk terminal item's MFT entry/seq (see Get-ShellItemFileReference).
    if ($hasIDL) {
      if (($off + 2) -gt $b.Length) {
        $r.ParseError = 'Truncated before LinkTargetIDList size field'
        return [pscustomobject]$r
      }
      $idListSize  = [BitConverter]::ToUInt16($b, $off)
      $ils = $off + 2
      $ile   = $ils + $idListSize
      if ($ile -gt $b.Length) {
        $r.ParseError = 'LinkTargetIDList size runs past end of file'
        return [pscustomobject]$r
      }
      $io  = $ils
      $li    = $null
      while (($io + 2) -le $ile) {
        $isz = [BitConverter]::ToUInt16($b, $io)
        if ($isz -eq 0) { break }  # terminal ID
        if ($isz -lt 2 -or ($io + $isz) -gt $ile) { break }
        $li = Get-ByteSlice -by $b -Start $io -Length $isz
        $io += $isz
      }
      if ($li) {
        $sr = Get-ShellItemFileReference -ib $li
        if ($sr.Found -and $null -ne $sr.MftEntry) {
          $r.MftEntry    = '0x{0:X}' -f $sr.MftEntry
          $r.MftSequence = '0x{0:X}' -f $sr.MftSequence
          $r.MftReferenceNote = 'verified vs LECmd on one host -- best-effort, cross-verify before evidentiary use'
        } elseif ($sr.Found) {
          $r.MftReferenceNote = "shell item ext block v$($sr.ExtensionVer), no FILE_REFERENCE (pre-Win7 format)"
        }
      }
      $off = $ile
    }
    # LinkInfo (only read for the volume serial number)
    if ($hasLinkInfo) {
      if (($off + 16) -gt $b.Length) {
        $r.ParseError = 'Truncated before LinkInfo header'
        return [pscustomobject]$r
      }
      $lis = $off
      $lisz  = [BitConverter]::ToUInt32($b, $lis)
      if ($lisz -lt 16 -or ($lis + $lisz) -gt $b.Length) {
        $r.ParseError = 'LinkInfo size out of bounds'
        return [pscustomobject]$r
      }
      $linkInfoFlags  = [BitConverter]::ToUInt32($b, $lis + 8)
      $volumeIdOffset = [BitConverter]::ToUInt32($b, $lis + 12)
      $hasVolumeIDAndPath = [bool]($linkInfoFlags -band 0x1)
      if ($hasVolumeIDAndPath) {
        $vo = $lis + $volumeIdOffset
        if (($vo + 12) -le $b.Length -and $vo -ge $lis) {
          $driveSerial = [BitConverter]::ToUInt32($b, $vo + 8)
          $hex = '{0:X8}' -f $driveSerial
          $r.DriveSerialNumber = $hex.Substring(0, 4) + '-' + $hex.Substring(4, 4)
        }
      }
      $off = $lis + $lisz
    }
    # StringData section (skipped past -- COM already gives us these reliably)
    $sf = @()
    if ($hasName)         { $sf += 'Description' }
    if ($hasRelativePath) { $sf += 'RelativePath' }
    if ($hasWorkingDir)   { $sf += 'WorkingDir' }
    if ($hasArguments)    { $sf += 'CommandLineArguments' }
    if ($hasIconLocation) { $sf += 'IconLocation' }
    foreach ($f in $sf) {
      if (($off + 2) -gt $b.Length) {
        $r.ParseError = "Truncated before StringData field '$f'"
        return [pscustomobject]$r
      }
      $count = [BitConverter]::ToUInt16($b, $off)
      $bpc = 1
      if ($isUnicode) { $bpc = 2 }
      $off += 2 + ($count * $bpc)
      if ($off -gt $b.Length) {
        $r.ParseError = "StringData field '$f' runs past end of file"
        return [pscustomobject]$r
      }
    }
    # Anything not decoded below is still named+sized in OtherExtraBlocks, never dropped.
    $kub = @{
      ($Sigs.Console)       = 'ConsoleDataBlock'
      ($Sigs.ConsoleFE)     = 'ConsoleFEDataBlock'
      ($Sigs.PropertyStore) = 'PropertyStoreDataBlock (may carry AppUserModelID)'
      ($Sigs.VistaIDList)   = 'VistaAndAboveIDListDataBlock'
    }
    while (($off + 8) -le $b.Length) {
      $bsz = [BitConverter]::ToUInt32($b, $off)
      if ($bsz -eq 0) { break }
      if ($bsz -lt 8 -or ($off + $bsz) -gt $b.Length) { break }
      $sig  = [BitConverter]::ToUInt32($b, $off + 4)
      $ds = $off + 8
      $be  = $off + $bsz
      if ($sig -eq $Sigs.Tracker) {
        # 88-byte payload; MAC uses DroidFileID's node field.
        if (($ds + 88) -le $b.Length) {
          $mib = Get-ByteSlice -by $b -Start ($ds + 8) -Length 16
          $mit  = [System.Text.Encoding]::ASCII.GetString($mib).TrimEnd([char]0).Trim()
          if ([string]::IsNullOrWhiteSpace($mit)) {
            $r.MachineID = 'N/A'
          } else {
            $r.MachineID = $mit
          }
          $dvib      = Get-ByteSlice -by $b -Start ($ds + 24) -Length 16
          $dfib        = Get-ByteSlice -by $b -Start ($ds + 40) -Length 16
          $dbvib = Get-ByteSlice -by $b -Start ($ds + 56) -Length 16
          $dbfib   = Get-ByteSlice -by $b -Start ($ds + 72) -Length 16
          $r.DroidVolumeID      = ConvertTo-LnkGuidString -by $dvib
          $r.DroidFileID        = ConvertTo-LnkGuidString -by $dfib
          $r.DroidBirthVolumeID = ConvertTo-LnkGuidString -by $dbvib
          $r.DroidBirthFileID   = ConvertTo-LnkGuidString -by $dbfib
          # Version nibble = top 4 bits of byte index 7 (file order) of the DroidFileID GUID.
          $versionNibble = ([int]$dfib[7] -band 0xF0) -shr 4
          if ($versionNibble -eq 1) {
            $macBytes = Get-ByteSlice -by $dfib -Start 10 -Length 6
            $r.MAC = ($macBytes | ForEach-Object { '{0:X2}' -f $_ }) -join ':'
          } else {
            $r.MAC = 'N/A (non-time-based GUID)'
          }
        }
      } elseif ($sig -eq $Sigs.EnvironmentVariable) {
        # Target path as originally written, env vars unexpanded -- can differ from COM's TargetPath.
        $r.EnvironmentVarTarget = Get-DualStringBlockValue -by $b -dst $ds -bnd $be
      } elseif ($sig -eq $Sigs.SpecialFolder) {
        # SpecialFolderID(4)+Offset(4); raw CSIDL, not mapped (superseded by KnownFolderDataBlock).
        if (($ds + 4) -le $b.Length -and ($ds + 4) -le $be) {
          $r.SpecialFolderID = [BitConverter]::ToUInt32($b, $ds)
        }
      } elseif ($sig -eq $Sigs.Darwin) {
        # App ID for MSI/Store-installed apps -- attributes the shortcut to a package.
        $r.DarwinAppID = Get-DualStringBlockValue -by $b -dst $ds -bnd $be
      } elseif ($sig -eq $Sigs.IconEnvironment) {
        $r.IconEnvironmentPath = Get-DualStringBlockValue -by $b -dst $ds -bnd $be
      } elseif ($sig -eq $Sigs.Shim) {
        # Shim layer name -- abused for persistence/evasion.
        if ($ds -lt $be) {
          $shimBytes = Get-ByteSlice -by $b -Start $ds -Length ($be - $ds)
          $shimStr = [System.Text.Encoding]::Unicode.GetString($shimBytes).TrimEnd([char]0).Trim()
          if ($shimStr) { $r.ShimLayer = $shimStr }
        }
      } elseif ($sig -eq $Sigs.KnownFolder) {
        # KnownFolderDataBlock: KnownFolderID GUID(16) + Offset(4).
        if (($ds + 16) -le $b.Length -and ($ds + 16) -le $be) {
          $kfGuidBytes = Get-ByteSlice -by $b -Start $ds -Length 16
          $kfGuid = ConvertTo-LnkGuidString -by $kfGuidBytes
          $r.KnownFolderID = $kfGuid
          if ($kfm.ContainsKey($kfGuid)) {
            $r.KnownFolderName = $kfm[$kfGuid]
          } else {
            $r.KnownFolderName = 'N/A (GUID not in local lookup table)'
          }
        }
      } elseif ($kub.ContainsKey($sig)) {
        $r.OtherExtraBlocks.Add("$($kub[$sig]) (0x$('{0:X8}' -f $sig), $bsz bytes) -- not decoded")
      } else {
        $r.OtherExtraBlocks.Add("Unrecognized block signature 0x$('{0:X8}' -f $sig), $bsz bytes")
      }
      $off += $bsz
    }
  } catch {
    $r.ParseError = "Parse exception: $($_.Exception.Message)"
  }
  return [pscustomobject]$r
}
function Write-LnkSummaryLine {
  param([Parameter(Mandatory)][string]$lkp, [Parameter(Mandatory)]$pr, [Parameter(Mandatory)]$fnd)
  $evidence = if ($fnd.Reasons.Count -gt 0) { $fnd.Reasons -join ', ' } else { '(none)' }
  Write-Host "   [$($fnd.Tier) $($fnd.Score)] $lkp -> $($pr.TargetPath)  ($evidence)"
}
function Write-LnkDetailBlock {
  param([Parameter(Mandatory)][string]$lkp, [Parameter(Mandatory)]$pr, $fnd, $fd,
    [Parameter(Mandatory)][System.IO.FileInfo]$fi, [string]$TargetHash, [switch]$FullDetail)
  Write-Host "   File             : $lkp"
  if ($pr.TargetPath)       { Write-Host "   Target           : $($pr.TargetPath)" }
  if ($pr.Arguments)        { Write-Host "   Arguments        : $($pr.Arguments)" }
  if ($pr.WorkingDirectory) { Write-Host "   WorkingDirectory : $($pr.WorkingDirectory)" }
  if ($pr.Description)      { Write-Host "   Description      : $($pr.Description)" }
  if ($pr.Hotkey)           { Write-Host "   Hotkey           : $($pr.Hotkey)" }
  if ($pr.IconLocation)     { Write-Host "   IconLocation     : $($pr.IconLocation)" }
  Write-Host "   WindowStyle      : $($pr.WindowStyle) ($(Get-WindowStyleLabel $pr.WindowStyle))"
  Write-Host "   LNK LastWriteTime (filesystem) : $($fi.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
  if ($fnd -and $fnd.NameMismatch) {
    Write-Host '   note             : LNK display name differs from target file name (context only, not scored)'
  }
  if ($fd) {
    Write-Host "   Header CreationTime : $($fd.HeaderCreationTime)
   Header AccessTime   : $($fd.HeaderAccessTime)
   Header WriteTime    : $($fd.HeaderWriteTime)
   DriveSerialNumber   : $($fd.DriveSerialNumber)
   MachineID (tracker) : $($fd.MachineID)
   MAC (tracker)       : $($fd.MAC)
   DroidVolumeID       : $($fd.DroidVolumeID)
   DroidFileID         : $($fd.DroidFileID)
   DroidBirthVolumeID  : $($fd.DroidBirthVolumeID)
   DroidBirthFileID    : $($fd.DroidBirthFileID)"
    if ($fd.MftEntry -ne 'N/A') {
      Write-Host "   MFT Entry/Sequence  : $($fd.MftEntry) / $($fd.MftSequence)"
    }
    if ($fd.MftReferenceNote) {
      Write-Host "   MFT ref note        : $($fd.MftReferenceNote)"
    }
    if ($fd.EnvironmentVarTarget -ne 'N/A') { Write-Host "   EnvVar target       : $($fd.EnvironmentVarTarget)" }
    if ($fd.IconEnvironmentPath -ne 'N/A')  { Write-Host "   Icon env path       : $($fd.IconEnvironmentPath)" }
    if ($fd.DarwinAppID -ne 'N/A')          { Write-Host "   Darwin/App ID       : $($fd.DarwinAppID)" }
    if ($fd.ShimLayer -ne 'N/A')            { Write-Host "   Shim layer          : $($fd.ShimLayer)" }
    if ($fd.SpecialFolderID -ne 'N/A')      { Write-Host "   SpecialFolder ID    : $($fd.SpecialFolderID)" }
    if ($fd.KnownFolderID -ne 'N/A') {
      Write-Host "   KnownFolder         : $($fd.KnownFolderName)  ($($fd.KnownFolderID))"
    }
    if ($fd.OtherExtraBlocks -and $fd.OtherExtraBlocks.Count -gt 0) {
      Write-Host "   Other ExtraData blocks (not fully decoded):"
      foreach ($b in $fd.OtherExtraBlocks) { Write-Host "     - $b" }
    }
    if ($FullDetail) {
      Write-Host "   Header HeaderSize   : $($fd.HeaderSize)
   Header FileAttributes (raw) : 0x$('{0:X}' -f $fd.FileAttributes)
   Header FileSize     : $($fd.FileSize)
   Header IconIndex    : $($fd.IconIndex)
   Header ShowCommand  : $($fd.ShowCommand)"
    }
    if ($fd.ParseError) {
      Write-Host "   ParseNote           : $($fd.ParseError)"
    }
  }
  if ($TargetHash) { Write-Host "   TargetSHA256     : $TargetHash" }
  if ($fnd) {
    Write-Host "   Score / Tier     : $($fnd.Score) / $($fnd.Tier)"
    Write-Host "   Evidence         : $(if ($fnd.Reasons.Count -gt 0) { $fnd.Reasons -join ', ' } else { '(none)' })"
  }
}
$ddMode = $false
$df = $null
if ($Path -and $Path.Count -eq 1) {
  $cnd = $Path[0]
  if ((Test-Path -LiteralPath $cnd -PathType Leaf) -and ($cnd -match '\.lnk$')) {
    $ddMode = $true
    $df = (Resolve-Path -LiteralPath $cnd).Path
  }
}
$rcu = $null
if ($Since) {
  try {
    $rcu = ([datetime]::Parse($Since)).ToUniversalTime()
  } catch {
    Write-Warning "Could not parse -Since '$Since' (expected YYYY-MM-DD); ignoring incident window."
  }
} elseif ($Days -gt 0) {
  $rcu = (Get-Date).ToUniversalTime().AddDays(-$Days)
}
if ($ddMode) {
  Write-Banner -Mode 'deep-dive'
  Write-Host "`n===== DEEP-DIVE: $df ====="
  $finf = $null
  try {
    $finf = Get-Item -LiteralPath $df -Force -ErrorAction Stop
  } catch {
    Write-Host "ERROR: could not stat '$df': $($_.Exception.Message)"
    return
  }
  # WSH may be disabled by policy -- degrade, don't crash: MS-SHLLINK data below is COM-independent.
  $ws = $null
  try {
    $ws = New-Object -ComObject WScript.Shell -ErrorAction Stop
  } catch {
    Write-Warning "WScript.Shell COM unavailable ($($_.Exception.Message)) -- shortcut properties unavailable; MS-SHLLINK data below unaffected."
  }
  $sco = $null
  $pv = Get-LnkComProperties -sc $null
  if ($ws) {
    try {
      $sco = $ws.CreateShortcut($df)
      $pv = Get-LnkComProperties -sc $sco
    } catch {
      Write-Host "ERROR: could not read shortcut properties via COM: $($_.Exception.Message)"
    } finally {
      if ($sco) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($sco) | Out-Null }
      [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ws) | Out-Null
      [GC]::Collect()
      [GC]::WaitForPendingFinalizers()
    }
  }
  $fnd2  = Get-LnkFinding -lkp $df -pr $pv -fi $finf -rtu $rcu
  $forensic = Get-ShellLinkForensicData -Path $df
  $hashVal  = $null
  if ($Hash) { $hashVal = Get-TargetHash -tp $pv.TargetPath }
  Write-Host ''
  Write-LnkDetailBlock -lkp $df -pr $pv -fnd $fnd2 -fd $forensic `
    -fi $finf -TargetHash $hashVal -FullDetail
  Write-Host "`n==== Verdict: [$($fnd2.Tier)]  (score $($fnd2.Score)) ===="
  return
}
Write-Banner -Mode 'sweep'
$jb = New-Object System.Collections.Generic.List[object]
$up = Join-Path $env:SystemDrive 'Users'
if (Test-Path -LiteralPath $up) {
  $jb.Add([pscustomobject]@{ Path = $up; Recurse = $true; IsFile = $false; Label = "$up (default)" })
}
$sp2 = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
if (Test-Path -LiteralPath $sp2) {
  $jb.Add([pscustomobject]@{ Path = $sp2; Recurse = $true; IsFile = $false; Label = 'All-users Startup (default)' })
}
try {
  $removableDrives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=2' -ErrorAction Stop
  foreach ($d in $removableDrives) {
    $root = "$($d.DeviceID)\"
    if (Test-Path -LiteralPath $root) {
      $jb.Add([pscustomobject]@{ Path = $root; Recurse = $false; IsFile = $false; Label = "removable drive root $root (default)" })
    }
  }
} catch {
  Write-Warning "Could not enumerate removable drives: $($_.Exception.Message)"
}
if ($Path) {
  foreach ($p in $Path) {
    if (Test-Path -LiteralPath $p -PathType Container) {
      $jb.Add([pscustomobject]@{ Path = $p; Recurse = $true; IsFile = $false; Label = "operator-specified: $p" })
    } elseif (Test-Path -LiteralPath $p -PathType Leaf) {
      $jb.Add([pscustomobject]@{ Path = $p; Recurse = $false; IsFile = $true; Label = "operator-specified file: $p" })
    } else {
      Write-Warning "Path not found, skipping: $p"
    }
  }
}
Write-Host "`n===== SCAN SCOPE ====="
foreach ($j in $jb) { Write-Host "   $($j.Label)" }
$fl          = New-Object System.Collections.Generic.List[string]
$dp = New-Object System.Collections.Generic.List[string]
foreach ($j in $jb) {
  if ($j.IsFile) {
    if ($j.Path -match '\.lnk$') { $fl.Add((Resolve-Path -LiteralPath $j.Path).Path) }
    continue
  }
  if (-not (Test-Path -LiteralPath $j.Path)) { continue }
  $localErr = $null
  $items = Get-ChildItem -LiteralPath $j.Path -Filter '*.lnk' -File -Force -Recurse:$j.Recurse `
    -ErrorAction SilentlyContinue -ErrorVariable localErr
  foreach ($i in $items) { $fl.Add($i.FullName) }
  foreach ($e in $localErr) {
    $deniedPath = [string]$e.TargetObject
    if (-not (Test-IsJunction -Path $deniedPath)) { $dp.Add($deniedPath) }
  }
}
$fl = @($fl | Select-Object -Unique)
Write-Host "`n===== SWEEP ($($fl.Count) .lnk files found) ====="
$high    = New-Object System.Collections.Generic.List[object]
$nt = New-Object System.Collections.Generic.List[object]
$cl   = New-Object System.Collections.Generic.List[object]
$ur   = New-Object System.Collections.Generic.List[string]
if ($fl.Count -gt 0) {
  # Degrade, don't crash: every candidate is counted, routed to $ur with a reason.
  $ws = $null
  try {
    $ws = New-Object -ComObject WScript.Shell -ErrorAction Stop
  } catch {
    Write-Warning "WScript.Shell COM unavailable ($($_.Exception.Message)) -- all $($fl.Count) candidates reported unreadable."
  }
  if ($ws) {
    try {
      foreach ($lp in $fl) {
        $finf = $null
        try {
          $finf = Get-Item -LiteralPath $lp -Force -ErrorAction Stop
        } catch {
          $ur.Add("$lp : $($_.Exception.Message)")
          continue
        }
        $sco = $null
        $pv    = $null
        try {
          $sco = $ws.CreateShortcut($lp)
          $pv = Get-LnkComProperties -sc $sco
        } catch {
          $ur.Add("$lp : $($_.Exception.Message)")
          continue
        } finally {
          if ($sco) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($sco) | Out-Null }
        }
        $fnd2 = Get-LnkFinding -lkp $lp -pr $pv -fi $finf -rtu $rcu
        $entry = [pscustomobject]@{ LnkPath = $lp; Props = $pv; FileInfo = $finf; Finding = $fnd2 }
        switch ($fnd2.Tier) {
          'HIGH'    { $high.Add($entry) }
          'NOTABLE' { $nt.Add($entry) }
          default   { $cl.Add($entry) }
        }
      }
    } finally {
      [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ws) | Out-Null
      [GC]::Collect()
      [GC]::WaitForPendingFinalizers()
    }
  } else {
    foreach ($lp in $fl) { $ur.Add("$lp : WScript.Shell COM unavailable") }
  }
}
Write-Host "`n===== ANOMALIES ====="
Write-Host "`n-- [HIGH] ($($high.Count)) --"
if ($high.Count -eq 0) {
  Write-Host '   (none)'
} else {
  foreach ($e in $high) {
    $fd = Get-ShellLinkForensicData -Path $e.LnkPath
    $hv = $null
    if ($Hash) { $hv = Get-TargetHash -tp $e.Props.TargetPath }
    Write-Host ''
    Write-LnkDetailBlock -lkp $e.LnkPath -pr $e.Props -fnd $e.Finding -fd $fd -fi $e.FileInfo -TargetHash $hv
  }
}
if ($MinSeverity -ne 'high') {
  Write-Host "`n-- [NOTABLE] ($($nt.Count)) --"
  if ($nt.Count -eq 0) {
    Write-Host '   (none)'
  } elseif ($Detail) {
    foreach ($e in $nt) {
      $fd = Get-ShellLinkForensicData -Path $e.LnkPath
      $hv = $null
      if ($Hash) { $hv = Get-TargetHash -tp $e.Props.TargetPath }
      Write-Host ''
      Write-LnkDetailBlock -lkp $e.LnkPath -pr $e.Props -fnd $e.Finding -fd $fd -fi $e.FileInfo -TargetHash $hv
    }
  } else {
    foreach ($e in $nt) { Write-LnkSummaryLine -lkp $e.LnkPath -pr $e.Props -fnd $e.Finding }
    Write-Host '   (re-run with -Detail for full MS-SHLLINK forensic data on these)'
  }
}
Write-Host "`n-- clean shortcuts, enumerated -- not scored as anomalies ($($cl.Count)) --"
if ($cl.Count -eq 0) {
  Write-Host '   (none found)'
} elseif ($Detail) {
  foreach ($e in $cl) {
    $mm = ''
    if ($e.Finding.NameMismatch) { $mm = '  [name-mismatch: context only, not scored]' }
    Write-Host "   $($e.LnkPath) -> $($e.Props.TargetPath)$mm"
  }
} else {
  Write-Host "   (re-run with -Detail to list all $($cl.Count) clean shortcuts)"
}
Write-Host "`n-- unreadable / parse failures ($($ur.Count)) --"
if ($ur.Count -eq 0) {
  Write-Host '   (none)'
} else {
  foreach ($u in $ur) { Write-Host "   $u" }
}
Write-Host "`n-- access-denied paths skipped ($($dp.Count)) --"
if ($dp.Count -eq 0) {
  Write-Host '   (none)'
} else {
  foreach ($a in $dp) { Write-Host "   $a" }
}
Write-Host "`n==== $($high.Count) HIGH  $($nt.Count) NOTABLE  $($cl.Count) clean  $($ur.Count) unreadable  $($dp.Count) access-denied ===="
Write-Host 'Triage order: work [HIGH] first, then [NOTABLE]. Clean items are enumerated for context, never scored as anomalies.'
if (-not (Test-IsElevated) -and $dp.Count -gt 0) {
  Write-Host 'Re-run elevated to resolve the access-denied paths above for full coverage.'
}
if ($OutFile) {
  Write-Host "`n-- writing CSV export to $OutFile --"
  $rows = New-Object System.Collections.Generic.List[object]
  $ai = New-Object System.Collections.Generic.List[object]
  $ai.AddRange($high); $ai.AddRange($nt); $ai.AddRange($cl)
  foreach ($e in $ai) {
    $fd = Get-ShellLinkForensicData -Path $e.LnkPath
    $hv = $null
    if ($Hash) { $hv = Get-TargetHash -tp $e.Props.TargetPath }
    $rows.Add([pscustomobject]@{
      LnkPath = $e.LnkPath; Tier = $e.Finding.Tier; Score = $e.Finding.Score
      Evidence = ($e.Finding.Reasons -join ';')
      TargetPath = $e.Props.TargetPath; Arguments = $e.Props.Arguments
      WorkingDirectory = $e.Props.WorkingDirectory; IconLocation = $e.Props.IconLocation
      LnkLastWriteTimeUtc = $e.FileInfo.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
      HeaderCreationTime = $fd.HeaderCreationTime; HeaderAccessTime = $fd.HeaderAccessTime
      HeaderWriteTime = $fd.HeaderWriteTime; DriveSerialNumber = $fd.DriveSerialNumber
      MachineID = $fd.MachineID; MAC = $fd.MAC
      DroidVolumeID = $fd.DroidVolumeID; DroidFileID = $fd.DroidFileID
      MftEntry = $fd.MftEntry; MftSequence = $fd.MftSequence
      EnvironmentVarTarget = $fd.EnvironmentVarTarget; IconEnvironmentPath = $fd.IconEnvironmentPath
      DarwinAppID = $fd.DarwinAppID; ShimLayer = $fd.ShimLayer
      KnownFolderName = $fd.KnownFolderName; KnownFolderID = $fd.KnownFolderID
      OtherExtraBlocks = ($fd.OtherExtraBlocks -join ' | ')
      TargetSHA256 = $hv
      ParseError           = $fd.ParseError
    })
  }
  try {
    $rows | Export-Csv -LiteralPath $OutFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    Write-Host "   wrote $($rows.Count) rows"
  } catch {
    Write-Warning "Could not write CSV to '$OutFile': $($_.Exception.Message)"
  }
}
