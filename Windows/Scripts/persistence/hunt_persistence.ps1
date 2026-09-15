<#
.SYNOPSIS
  Read-only sweep of Windows persistence mechanisms (MITRE ATT&CK TA0003) for DFIR triage.
.DESCRIPTION
  Enumerates 32 persistence technique families, resolves each referenced target to a real
  path, verifies path trust and Authenticode signature, and scores items with a weighted
  evidence model into HIGH / NOTABLE / clean. Module reference, evidence weights and the
  Absolute-vs-Scored table live in README.md alongside this script.

  READ-ONLY: every registry and WMI access is a read, no hive is loaded, nothing is written.
  RTR-safe: console only, no interactive prompts, wraps instead of truncating, and degrades
  without elevation with every unreadable target listed rather than silently skipped.
  Host-agnostic: no hardcoded user/host names or per-host allowlists. False-positive control
  comes from path trust, signature verification, or an OS-documented stock default.
.PARAMETER Quick
  Run the 25 Quick-tier modules. Default when no mode is given.
.PARAMETER Deep
  Quick tier plus the 7 Deep-tier modules (32 total). Slower: ComFull sweeps every per-user CLSID.
.PARAMETER Modules
  Run exactly the named tokens, any tier, case-insensitive. See -ListModules.
.PARAMETER ListModules
  Print the module catalog and exit.
.PARAMETER InventoryOnly
  Raw enumeration: no scoring or suppression. Verification still runs, so trust/signature
  columns are real. Cannot combine with -AnomaliesOnly or -MinSeverity.
.PARAMETER AnomaliesOnly
  Show only scored rows at or above -MinSeverity; modules with nothing flagged are skipped.
.PARAMETER MinSeverity
  High or Notable (default Notable).
.PARAMETER Since
  Display filter start (YYYY-MM-DD). Narrows what is shown; it does NOT change scoring. A
  real finding whose artifact predates the cutoff will not display -- this is a scope
  decision, not a noise filter. Items with no timestamp are always shown.
.PARAMETER Days
  Display filter as "last N days" instead of -Since.
.PARAMETER Until
  Display filter end (YYYY-MM-DD). Same caveat as -Since.
.PARAMETER Help
  Show help and exit.
.EXAMPLE
  hunt_persistence.ps1
.EXAMPLE
  hunt_persistence.ps1 -Deep -AnomaliesOnly -MinSeverity High
.EXAMPLE
  hunt_persistence.ps1 -Modules scheduledtasks,wmi -Verbose
.NOTES
  Script : hunt_persistence.ps1   Version : 2.0   Author : Suvas Patel
  Safety : Read-only, console-only, no elevation required (coverage report lists gaps).
#>
#Requires -Version 3.0
[CmdletBinding()]
param(
  [switch]$Quick,
  [switch]$Deep,
  [string[]]$Modules,
  [switch]$ListModules,
  [switch]$InventoryOnly,
  [switch]$AnomaliesOnly,
  [ValidateSet('High', 'Notable')][string]$MinSeverity = 'Notable',
  [string]$Since,
  [int]$Days,
  [string]$Until,
  [switch]$Help
)
$Version = '2.0'
$Author = 'Suvas Patel'
$script:BoundParams = $PSBoundParameters

# --- Technique-defined constants and OS-documented stock defaults (not host exclusions) ---
# IFEO Debugger on any of these is conclusive: they are reachable pre-authentication.
$AccessibilityBins = @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe')
$StockShell = 'explorer.exe'
$StockBootExecute = 'autocheck autochk *'
$StockAltShell = 'cmd.exe'
$LolBins = @('cmd', 'powershell', 'powershell_ise', 'pwsh', 'wscript', 'cscript', 'mshta', 'rundll32',
  'regsvr32', 'certutil', 'bitsadmin', 'forfiles', 'msiexec', 'msbuild', 'installutil', 'regasm',
  'regsvcs', 'cmstp', 'wmic', 'curl', 'schtasks')
# Word-bounded on both sides -- a bare IEX\b matches inside acpiex.sys and similar file names.
$StrongCmdRx = '(\B-enc\b|\B-EncodedCommand\b|\bFromBase64String\b|\bIEX\b|\bInvoke-Expression\b|\bDownloadString\b|\bDownloadFile\b|\bNet\.WebClient\b|\bInvoke-WebRequest\b|\bbitsadmin\b.*/transfer\b|\bcertutil\b.*-urlcache)'
$WeakCmdRx = '(\B-w\s+hidden\b|\B-windowstyle\s+hidden\b|\B-nop\b|\B-noprofile\b|\B-ep\s+bypass\b|\B-executionpolicy\s+bypass\b)'
# Real base64 comes in groups of 4 with 0-2 pad chars; a bare 40-char alphabet run is not.
$B64Rx = '(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])'
# Script/executable handlers only -- deliberately narrower than the document-handler space.
$WatchedExt = @('.bat', '.cmd', '.js', '.jse', '.vbs', '.vbe', '.wsf', '.hta', '.reg', '.ps1', '.scr', '.msc', '.lnk', '.txt')
$WatchedEnvVars = @('COR_ENABLE_PROFILING', 'COR_PROFILER', 'COR_PROFILER_PATH', 'COR_PROFILER_PATH_32', 'COR_PROFILER_PATH_64', 'windir')
# Documented-abused shell CLSIDs, non-exhaustive by design -- a per-user override is the finding.
$ComWatch = [ordered]@{
  '{A6BA00FE-40E8-477C-B713-C64A14F18ADB}' = 'Task Scheduler app-update COM handler'
  '{42AEDC87-2188-41FD-B9A3-0C966FEABEC1}' = 'MruPidlList'
  '{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}' = 'WBEM New Event Subsystem'
  '{3543619C-D563-43F7-95EA-4DA7E1CC396A}' = 'Shell Icon Overlay handler'
  '{BCDE0395-E52F-467C-8E3D-C4579291692E}' = 'MMDeviceEnumerator'
}
$StartTypes = @{ 0 = 'Boot'; 1 = 'System'; 2 = 'Auto'; 3 = 'Manual'; 4 = 'Disabled' }
$LoadBehavior = @{ 0 = 'not loaded'; 1 = 'loaded'; 2 = 'not auto-load'; 3 = 'auto-load at startup'; 8 = 'on demand'; 9 = 'on demand, connected'; 16 = 'load once' }

# Tier thresholds match the sibling tools in this repo (HIGH >= 5, NOTABLE >= 3).
$Weights = [ordered]@{
  'ENCODED-COMMAND' = 4; 'DOWNLOAD-CRADLE' = 4; 'SIGNATURE-INVALID' = 3; 'USER-WRITABLE-PATH' = 3
  'SUSPICIOUS-CONTENT' = 3; 'TARGET-MISSING' = 2; 'UNTRUSTED-PATH' = 2; 'UNSIGNED' = 2; 'LOLBIN' = 2
  'REGISTRATION-ORPHAN' = 2; 'PER-USER-OVERRIDE' = 2; 'HIDDEN' = 2; 'NON-DEFAULT-VALUE' = 2
  'REMOTE-URL' = 2; 'USER-WRITABLE-ARG' = 2; 'HANDLER-CHAIN' = 3; 'USERCHOICE-OVERRIDE' = 2; 'PRECEDES-SMB' = 1
  'OBFUSCATION-FLAGS' = 1; 'RECENCY' = 1
}
$Reasons = @{
  'ENCODED-COMMAND' = 'command line carries an encoded/base64 payload'
  'DOWNLOAD-CRADLE' = 'command line downloads and executes remote content'
  'SIGNATURE-INVALID' = 'target signature is invalid or its hash does not match'
  'USER-WRITABLE-PATH' = 'target sits in a user-writable location'
  'SUSPICIOUS-CONTENT' = 'file content contains download/execute or obfuscation patterns'
  'TARGET-MISSING' = 'registered target does not exist on disk'
  'UNTRUSTED-PATH' = 'target is outside Windows and Program Files'
  'UNSIGNED' = 'target binary is not Authenticode-signed'
  'LOLBIN' = 'entry launches an interpreter or living-off-the-land binary'
  'REGISTRATION-ORPHAN' = 'registration is inconsistent across the artifacts that should agree'
  'PER-USER-OVERRIDE' = 'a per-user override shadows the machine-wide definition'
  'HIDDEN' = 'entry is configured to stay out of the default UI view'
  'NON-DEFAULT-VALUE' = 'value deviates from the documented Windows default'
  'REMOTE-URL' = 'command line fetches from a remote URL'
  'USER-WRITABLE-ARG' = 'interpreter is handed a file from a user-writable location'
  'HANDLER-CHAIN' = 'command runs something extra and then chains to the real handler, so the hijack stays invisible'
  'USERCHOICE-OVERRIDE' = 'the handler Explorer actually uses for this user differs from the machine default'
  'PRECEDES-SMB' = 'network provider is ordered ahead of LanmanWorkstation, so it sees logon credentials first'
  'OBFUSCATION-FLAGS' = 'command line uses hidden-window / policy-bypass flags'
  'RECENCY' = 'artifact was written in the last 14 days'
}

# .NET exposes no registry key LastWriteTime; RegQueryInfoKey is the only route to it.
if (-not ('DfirReg' -as [type])) {
  Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class DfirReg {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  private static extern int RegOpenKeyEx(IntPtr k, string sub, int opt, int sam, out IntPtr res);
  [DllImport("advapi32.dll")] private static extern int RegCloseKey(IntPtr k);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  private static extern int RegQueryInfoKey(IntPtr k, StringBuilder c, IntPtr cc, IntPtr r, IntPtr sk,
    IntPtr msk, IntPtr mc, IntPtr v, IntPtr mvn, IntPtr mv, IntPtr sd, out long ft);
  public static long LastWrite(int root, string sub) {
    IntPtr h; if (RegOpenKeyEx(new IntPtr(root), sub, 0, 0x0001, out h) != 0) return 0;
    try { long ft; if (RegQueryInfoKey(h, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
      IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft) != 0) return 0; return ft; }
    finally { RegCloseKey(h); }
  }
}
'@ -ErrorAction SilentlyContinue
}
# Add-Type can fail under Constrained Language Mode/WDAC; cache success so Read-Key degrades
# (no LastWrite) instead of throwing on every call.
$script:HasDfirReg = [bool]('DfirReg' -as [type])
# Predefined handles as signed ints (0x8000000N overflows an Int32 literal).
$RegRoots = @{
  'HKCR' = @{ H = -2147483648; N = [Microsoft.Win32.Registry]::ClassesRoot }
  'HKCU' = @{ H = -2147483647; N = [Microsoft.Win32.Registry]::CurrentUser }
  'HKLM' = @{ H = -2147483646; N = [Microsoft.Win32.Registry]::LocalMachine }
  'HKU'  = @{ H = -2147483645; N = [Microsoft.Win32.Registry]::Users }
}

# --- Run state: every shared lookup is computed once and reused by every module ---
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Unreadable = New-Object System.Collections.Generic.List[object]
$script:Errors = New-Object System.Collections.Generic.List[object]
$script:SigCache = @{}
$script:SidNames = @{}
$script:NowUtc = (Get-Date).ToUniversalTime()
$script:RecencyCut = $script:NowUtc.AddDays(-14)

function Limit-Reason {
  # Caps a raw .NET exception so one gap can't dominate the coverage list.
  param([string]$Reason)
  $r = ($Reason -replace '\s+', ' ').Trim()
  if ($r.Length -gt 140) { $r = $r.Substring(0, 137) + '...' }
  return $r
}

function Add-Gap {
  param([string]$Target, [string]$Reason, [string]$Module = 'startup')
  $script:Unreadable.Add([pscustomobject]@{ Module = $Module; Target = $Target; Reason = (Limit-Reason $Reason) })
}

function Test-Elevated {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Read-Key {
  # Opens, reads everything, closes. Returns $null when absent; records access-denied so a
  # non-elevated run under-reports loudly rather than silently.
  param([ValidateSet('HKLM', 'HKCU', 'HKU', 'HKCR')][string]$Root, [AllowEmptyString()][string]$Sub, [string]$Module = '?')
  $info = $RegRoots[$Root]
  $key = $null
  try { $key = $info.N.OpenSubKey($Sub, $false) }
  catch [System.Security.SecurityException] { Add-Gap "$Root\$Sub" 'access denied (re-run elevated)' $Module; return $null }
  catch [System.UnauthorizedAccessException] { Add-Gap "$Root\$Sub" 'access denied (re-run elevated)' $Module; return $null }
  catch { Add-Gap "$Root\$Sub" $_.Exception.Message $Module; return $null }
  if (-not $key) { return $null }
  $vals = @{}; $subs = @()
  try {
    # DoNotExpandEnvironmentNames keeps REG_EXPAND_SZ raw so the operator sees what was
    # actually written; Resolve-Target does the expansion deliberately instead.
    foreach ($n in $key.GetValueNames()) { $vals[$n] = $key.GetValue($n, $null, 'DoNotExpandEnvironmentNames') }
    $subs = @($key.GetSubKeyNames())
  } catch { Add-Gap "$Root\$Sub" "partial read: $($_.Exception.Message)" $Module }
  finally { $key.Close() }
  $lw = $null
  if ($script:HasDfirReg) {
    $ft = [DfirReg]::LastWrite($info.H, $Sub)
    if ($ft -gt 0) { try { $lw = [datetime]::FromFileTimeUtc($ft) } catch { } }
  }
  [pscustomobject]@{ Path = "$Root\$Sub"; Values = $vals; Names = @($vals.Keys); Subs = $subs; LastWrite = $lw }
}

function Resolve-Target {
  # -Profile substitutes the OWNING profile's directory for %USERPROFILE%-family variables,
  # so a value read from another user's hive never resolves against the running account.
  param([string]$Raw, [string]$Profile)
  if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
  $p = $Raw.Trim().Trim('"').Trim()
  if (-not $p) { return $null }
  $p = $p -replace '^\\\\\?\\', '' -replace '^\\\?\?\\', ''          # NT / long-path prefixes
  $p = $p -replace '(?i)^\\SystemRoot\\', "$env:SystemRoot\"
  if ($p -imatch '^system32\\') { $p = Join-Path $env:SystemRoot $p }
  if ($Profile) {
    $p = $p -replace '(?i)%USERPROFILE%', $Profile
    $p = $p -replace '(?i)%APPDATA%', (Join-Path $Profile 'AppData\Roaming')
    $p = $p -replace '(?i)%LOCALAPPDATA%', (Join-Path $Profile 'AppData\Local')
    $p = $p -replace '(?i)%TEMP%|%TMP%', (Join-Path $Profile 'AppData\Local\Temp')
  }
  try { $p = [Environment]::ExpandEnvironmentVariables($p) } catch { }
  $p = $p.Trim()
  if (-not $p) { return $null }
  if ($p -match '^[A-Za-z]:\\' -or $p -match '^\\\\') { return $p }
  # Real CreateProcess search order (see README False-positive controls). SysWOW64 is NOT in
  # a 64-bit process's search order -- putting it earlier resolves bare "explorer.exe" wrong.
  $dirs = @((Join-Path $env:SystemRoot 'System32'), $env:SystemRoot)
  if ($env:Path) { $dirs += ($env:Path -split ';' | Where-Object { $_ }) }
  $dirs += (Join-Path $env:SystemRoot 'SysWOW64')   # last resort, for 32-bit registrations
  foreach ($d in $dirs) {
    try { $c = Join-Path $d $p; if (Test-Path -ErrorAction SilentlyContinue -LiteralPath $c -PathType Leaf) { return $c } } catch { }
  }
  return (Join-Path (Join-Path $env:SystemRoot 'System32') $p)
}

function Get-Trust {
  # Derived from where Windows itself installs code, never from a per-host allowlist.
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return 'Unknown' }
  $p = $Path.TrimEnd('\')
  # Checked first: these sit inside trusted roots in some cases (Windows\Temp) and must not
  # be classified as System because of it.
  foreach ($rx in @('\\AppData\\', '\\Temp\\', '\\Downloads\\', '\\Users\\Public\\', '\\PerfLogs\\')) {
    if ($p -imatch $rx) { return 'UserWritable' }
  }
  $sys = $env:SystemRoot.TrimEnd('\')
  if ($p -ieq $sys -or $p -like "$sys\*") { return 'System' }
  foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if ($pf -and $p -like "$($pf.TrimEnd('\'))\*") { return 'Program' }
  }
  if ($p -like "$(Join-Path $env:SystemDrive 'Users')\*") { return 'UserWritable' }
  return 'Untrusted'
}

# Signers of the OS itself, not a per-host allowlist -- see README False-positive controls.
$OsVendors = @('Microsoft Corporation', 'Intel Corporation')
# WHQL third-party driver attestation, never treated as an OS-vendor binary -- see README.
$WhqlPublisher = 'Microsoft Windows Hardware Compatibility Publisher'

function Get-SigInfo {
  # Cached by path: the same binary (svchost, rundll32) is referenced by dozens of entries and
  # signature verification is the most expensive operation in this tool.
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return [pscustomobject]@{ Label = 'n/a'; Org = ''; OsVendor = $false } }
  $k = $Path.ToLowerInvariant()
  if ($script:SigCache.ContainsKey($k)) { return $script:SigCache[$k] }
  $label = 'Missing'; $org = ''; $cn = ''
  if (Test-Path -ErrorAction SilentlyContinue -LiteralPath $Path -PathType Leaf) {
    try {
      $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
      if ($s.Status -eq 'Valid') {
        $subj = ''
        if ($s.SignerCertificate) { $subj = [string]$s.SignerCertificate.Subject }
        if ($subj -match 'O=(?:")?([^",]+)') { $org = $Matches[1].Trim() }
        if ($subj -match 'CN=(?:")?([^",]+)') { $cn = $Matches[1].Trim() }
        if ($cn -ieq $WhqlPublisher) { $label = 'WHQL 3rd-party' }
        elseif ($org) { $label = $org -replace '\s+(Corporation|Inc\.?|LLC|Ltd\.?|GmbH)$', '' }
        else { $label = 'signed' }
      } elseif ($s.Status -eq 'UnknownError') { $label = 'Unverifiable' } else { $label = [string]$s.Status }
    } catch { $label = 'Unverifiable' }
  }
  $osVendor = (($OsVendors -contains $org) -and ($cn -ine $WhqlPublisher))
  $info = [pscustomobject]@{ Label = $label; Org = $org; OsVendor = $osVendor }
  $script:SigCache[$k] = $info
  return $info
}

function Get-Signature {
  param([string]$Path)
  return (Get-SigInfo $Path).Label
}

function Test-OsVendorBinary {
  # "Benign Windows baseline": signed by an OS vendor AND sitting on an expected path.
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  if (-not (Get-SigInfo $Path).OsVendor) { return $false }
  return ((Get-Trust $Path) -in @('System', 'Program'))
}

function Get-CmdTarget {
  # Extracts the executable, or for rundll32 the DLL argument -- that is the code that
  # actually runs and the thing worth verifying.
  param([string]$Cmd)
  if ([string]::IsNullOrWhiteSpace($Cmd)) { return $null }
  $c = $Cmd.Trim()
  $exe = $null
  if ($c -match '^"([^"]+)"') {
    $exe = $Matches[1]
  } elseif ($c -imatch '^(.+?\.(?:exe|dll|com|bat|cmd|scr|ps1|vbs|js|sys|msc))(?:[\s,]|$)') {
    # Non-greedy to the FIRST extension: splitting unquoted "...\App\x.exe -flag" on
    # whitespace instead yields "C:\Program", a false missing target.
    $exe = $Matches[1]
  } else {
    $toks = @($c -split '\s+'); $exe = $toks[0]; $acc = ''
    foreach ($t in $toks) {
      if ($acc) { $acc = "$acc $t" } else { $acc = $t }
      if (Test-Path -LiteralPath $acc -ErrorAction SilentlyContinue) { $exe = $acc }
    }
  }
  if (-not $exe) { return $null }
  # Shell placeholders (%1, %*, %L, %V) mean "execute the file itself" -- no handler binary to
  # resolve; treating %1 as a path invents a false TARGET-MISSING.
  if ($exe -match '^%[\d\*LlVv]$') { return $null }
  $leaf = ''
  try { $leaf = [IO.Path]::GetFileNameWithoutExtension($exe) } catch { }
  if ($leaf -ieq 'rundll32') {
    $rest = $c.Substring([Math]::Min($c.Length, $c.IndexOf($exe) + $exe.Length)).Trim()
    foreach ($t in @($rest -split '\s+' | Where-Object { $_ })) {
      if ($t -match '^[/-]') { continue }        # skip /d and friends
      $dll = ($t -split ',')[0].Trim('"')
      if ($dll) { return $dll }
    }
  }
  return $exe
}

function Test-Base64Blob {
  # A genuine base64 blob almost always mixes in letters outside 0-9a-f; a 40+ char run
  # that is pure hex (a hash or a GUID chain, the two common coincidental matches) does
  # not, so require that signal before trusting the length/alphabet match alone.
  param([string]$Cmd)
  $m = [regex]::Match($Cmd, $B64Rx)
  if (-not $m.Success) { return $false }
  return ([regex]::Matches($m.Value, '[g-zG-Z+/]').Count -ge 3)
}

function Get-CmdEvidence {
  # Weak obfuscation flags promote to a strong tag only when stacked with a URL or an
  # encoded blob, so a stock "-NoProfile" launcher stays quiet.
  param([string]$Cmd)
  $t = @()
  if ([string]::IsNullOrWhiteSpace($Cmd)) { return $t }
  if ($Cmd -imatch $StrongCmdRx) {
    if ($Cmd -imatch '(DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|-urlcache|/transfer)') { $t += 'DOWNLOAD-CRADLE' }
    else { $t += 'ENCODED-COMMAND' }
  }
  if ($Cmd -imatch $WeakCmdRx) {
    if ($Cmd -imatch 'https?://' -or (Test-Base64Blob $Cmd)) { if ($t -notcontains 'ENCODED-COMMAND') { $t += 'ENCODED-COMMAND' } }
    else { $t += 'OBFUSCATION-FLAGS' }
  }
  # Run something, then chain to the legitimate handler ("cmd /c start evil.exe & notepad %1").
  # Keyed on the shell separator only -- a download whose output happens to be a second .exe is
  # a different thing and already scored by DOWNLOAD-CRADLE. Measured at zero on a clean host.
  if ($Cmd -imatch '(\s&{1,2}\s|\s\|\|?\s)') { $t += 'HANDLER-CHAIN' }
  return $t
}

function Get-ArgumentPaths {
  # Path-shaped tokens (quoted/drive-rooted/env-var-rooted/UNC) -- the resolved target alone
  # can't show what an interpreter was handed: "wscript.exe C:\...\x.vbs" resolves to wscript.exe.
  param([string]$Cmd)
  if ([string]::IsNullOrWhiteSpace($Cmd)) { return @() }
  $found = New-Object System.Collections.Generic.List[string]
  foreach ($rx in @('"([A-Za-z]:\\[^"]+)"', '(?<![:"\w])([A-Za-z]:\\[^\s",;]+)', '(%\w+%\\[^\s",;]+)', '(\\\\[^\s",;]+)')) {
    foreach ($mm in [regex]::Matches($Cmd, $rx)) {
      $v = $mm.Groups[1].Value.Trim().Trim('"')
      if ($v -and -not $found.Contains($v)) { $found.Add($v) }
    }
  }
  return $found.ToArray()
}

function Test-LolBin {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  try { return ($LolBins -contains ([IO.Path]::GetFileNameWithoutExtension($Path)).ToLowerInvariant()) } catch { return $false }
}

function Test-Content {
  # Bounded scan for download/execute patterns, capped so a huge file is never buffered. A
  # read failure or the size cap is logged as a gap, not returned as clean.
  param([string]$Path, [string]$Module = '?')
  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  try {
    if ((Get-Item -LiteralPath $Path -Force -ErrorAction Stop).Length -gt 512KB) {
      Add-Gap $Path 'content not scanned: file exceeds the 512KB cap' $Module
      return $false
    }
    return ([IO.File]::ReadAllText($Path) -imatch $StrongCmdRx)
  } catch { Add-Gap $Path "content unreadable: $($_.Exception.Message)" $Module; return $false }
}

function Resolve-Sid {
  # Cached SID -> account name for the whole run. Every module that has a SID in hand uses
  # this, so an operator never has to decode one by eye.
  param([string]$Sid, [string]$Profile)
  if ([string]::IsNullOrWhiteSpace($Sid)) { return '' }
  if ($script:SidNames.ContainsKey($Sid)) { return $script:SidNames[$Sid] }
  $name = $Sid
  if ($Sid -eq '.DEFAULT') {
    $name = '.DEFAULT (new-user template)'
  } else {
    try { $name = (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value }
    catch { if ($Profile) { $name = (Split-Path -Leaf $Profile) } }
  }
  $script:SidNames[$Sid] = $name
  return $name
}

function Resolve-Principal {
  # Task/service principals are stored as either a SID or an account name. Resolve only the
  # SID-shaped ones; leave "NT AUTHORITY\SYSTEM" and the like untouched.
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
  if ($Value -notmatch '^S-1-[0-9\-]+$') { return $Value }
  $name = Resolve-Sid $Value
  # A SID that will not translate is usually a deleted account -- say so rather than leaving
  # the operator to work out why this one row still shows a raw SID.
  if ($name -eq $Value) { return "$Value (unresolved SID - deleted account?)" }
  return $name
}

function Initialize-Hives {
  # Enumerated once. Per-user modules iterate this instead of reading HKCU, which only ever
  # reflects whoever is running the script.
  $list = New-Object System.Collections.Generic.List[object]
  $loaded = @()
  $u = Read-Key 'HKU' ''
  if ($u) { $loaded = @($u.Subs | Where-Object { $_ -notmatch '_Classes$' }) }
  $pl = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
  $plKey = Read-Key 'HKLM' $pl
  $seen = @{}
  if ($plKey) {
    foreach ($sid in $plKey.Subs) {
      $k = Read-Key 'HKLM' "$pl\$sid"
      $path = $null
      if ($k -and $k.Values.ContainsKey('ProfileImagePath')) { $path = Resolve-Target ([string]$k.Values['ProfileImagePath']) }
      $seen[$sid] = $true
      $list.Add([pscustomobject]@{ Sid = $sid; User = (Resolve-Sid $sid $path); Profile = $path; Loaded = ($loaded -contains $sid) })
    }
  }
  # A hive can be loaded with no ProfileList entry (service accounts, stale mounts).
  foreach ($sid in $loaded) {
    if ($seen.ContainsKey($sid)) { continue }
    $list.Add([pscustomobject]@{ Sid = $sid; User = (Resolve-Sid $sid $null); Profile = $null; Loaded = $true })
  }
  $script:Hives = $list
  $script:Loaded = @($list | Where-Object { $_.Loaded })
  # Filesystem-side modules use this so a profile with no loaded hive is still swept.
  $script:Profiles = @($list | Where-Object { $_.Profile -and (Test-Path -ErrorAction SilentlyContinue -LiteralPath $_.Profile) })
}

function Add-Finding {
  <#
    Two kinds of finding, split deliberately (see README):
      Absolute -- presence/deviation is conclusive; the score is irrelevant.
      Scored   -- needs corroborating weak signals to separate attacker-controlled from benign.
  #>
  param(
    [Parameter(Mandatory)][string]$Module,
    [Parameter(Mandatory)][AllowEmptyString()][string]$Item,
    [string]$Scope, [string]$Detail, [string]$Location, [string]$Extra,
    [string]$Command, [string]$Target, [string]$Profile,
    $LastWrite,
    [string[]]$Evidence = @(),
    # '' accepted so a caller can pass a conditional expression meaning "no absolute rule".
    [ValidateSet('High', 'Notable', '')][string]$Absolute,
    [switch]$VerboseOnly, [switch]$NoVerify, [switch]$NoCmdTarget
  )
  $tags = New-Object System.Collections.Generic.List[string]
  foreach ($e in $Evidence) { if ($e -and -not $tags.Contains($e)) { $tags.Add($e) } }
  $resolved = $null
  if ($Target) { $resolved = Resolve-Target $Target $Profile }
  elseif ($Command -and -not $NoCmdTarget) {
    $raw = Get-CmdTarget $Command
    if ($raw) { $resolved = Resolve-Target $raw $Profile }
  }
  $trust = 'n/a'; $sig = 'n/a'
  if ($resolved -and -not $NoVerify) {
    # Verification runs even under -InventoryOnly: only scoring is skipped, so the
    # trust/signature columns are real data rather than blanks.
    $trust = Get-Trust $resolved
    $sig = Get-Signature $resolved
    if ($trust -eq 'UserWritable') { $tags.Add('USER-WRITABLE-PATH') } elseif ($trust -eq 'Untrusted') { $tags.Add('UNTRUSTED-PATH') }
    if ($sig -eq 'Missing') { if (-not $tags.Contains('TARGET-MISSING')) { $tags.Add('TARGET-MISSING') } } elseif ($sig -eq 'NotSigned') { if (-not $tags.Contains('UNSIGNED')) { $tags.Add('UNSIGNED') } } elseif ($sig -eq 'HashMismatch') { if (-not $tags.Contains('SIGNATURE-INVALID')) { $tags.Add('SIGNATURE-INVALID') } }
    if (Test-LolBin $resolved) { $tags.Add('LOLBIN') }
  }
  if ($Command) {
    foreach ($t in (Get-CmdEvidence $Command)) { if (-not $tags.Contains($t)) { $tags.Add($t) } }
    # A persistence entry that reaches out to a remote URL. Measured at zero occurrences
    # across every command line on a clean host, so this needs no LOLBIN gate to stay quiet.
    if ($Command -imatch '\b(?:https?|ftp)://' -and -not $tags.Contains('REMOTE-URL')) { $tags.Add('REMOTE-URL') }
    # An interpreter handed a file from a user-writable location -- the drop-and-persist
    # pattern. Gated on LOLBIN so an ordinary app reading its own AppData config stays quiet;
    # the resolved target is skipped so rundll32's own DLL is not counted twice.
    if ($tags.Contains('LOLBIN')) {
      foreach ($a in (Get-ArgumentPaths $Command)) {
        $ap = Resolve-Target $a $Profile
        if (-not $ap -or ($resolved -and $ap -ieq $resolved)) { continue }
        if ((Get-Trust $ap) -eq 'UserWritable') {
          if (-not $tags.Contains('USER-WRITABLE-ARG')) { $tags.Add('USER-WRITABLE-ARG') }
          break
        }
      }
    }
  }
  # Fixed 14-day window, independent of -Since/-Days display narrowing; withheld for a
  # Microsoft-signed trusted-path target -- see README Time handling.
  if ($LastWrite -is [datetime] -and $LastWrite -ge $script:RecencyCut) {
    if (-not ($resolved -and -not $NoVerify -and (Test-OsVendorBinary $resolved))) { $tags.Add('RECENCY') }
  }
  # Windows baseline: OS-vendor binary on an expected path, computed for every module. Only
  # zero-evidence rows are suppressed on this -- see README False-positive controls.
  $baseline = ($resolved -and -not $NoVerify -and (Test-OsVendorBinary $resolved))
  $score = 0; $tier = 'LOW'
  if (-not $InventoryOnly) {
    foreach ($t in $tags) { if ($Weights.Contains($t)) { $score += $Weights[$t] } }
    if ($Absolute) { $tier = $Absolute.ToUpperInvariant() }
    elseif ($score -ge 5) { $tier = 'HIGH' } elseif ($score -ge 3) { $tier = 'NOTABLE' }
  }
  $script:Findings.Add([pscustomobject]@{
      Module = $Module; Item = $Item; Scope = $Scope; Detail = $Detail; Location = $Location
      Extra = $Extra; Command = $Command; Target = $resolved; Trust = $trust; Sig = $sig; LastWrite = $LastWrite
      Evidence = $tags.ToArray(); Score = $score; Tier = $tier; Absolute = [bool]$Absolute
      Quiet = [bool]$VerboseOnly; Routine = $baseline
    })
}

function Add-KeyValues {
  # Generic emitter: one finding per value in a key. Collapses the many "read a key, report
  # its values" modules into a few lines each.
  param(
    [string]$Module, [string]$Root, [string]$Sub, [string]$Scope, [string]$Profile,
    [string[]]$Only,            # restrict to these value names; omit for all
    [switch]$AsTarget,          # value data is a file path, not a command line
    [string]$Absolute, [string[]]$Evidence = @()
  )
  $k = Read-Key $Root $Sub $Module
  if (-not $k) { return }
  $names = $k.Names
  if ($Only) { $names = @($Only | Where-Object { $k.Values.ContainsKey($_) }) }
  foreach ($n in $names) {
    $d = [string]$k.Values[$n]
    if ([string]::IsNullOrWhiteSpace($d)) { continue }
    $p = @{ Module = $Module; Item = $n; Scope = $Scope; Detail = $d; Location = "$Root\$Sub"
      Profile = $Profile; LastWrite = $k.LastWrite; Evidence = $Evidence
    }
    if ($AsTarget) { $p.Target = $d } else { $p.Command = $d }
    if ($Absolute) { $p.Absolute = $Absolute }
    Add-Finding @p
  }
}

function Resolve-Clsid {
  # HKCU wins the HKCR merge, so the per-user registration is checked first -- that
  # precedence rule is the entire COM-hijack mechanism.
  param([string]$Clsid, [string]$Module)
  if ([string]::IsNullOrWhiteSpace($Clsid)) { return $null }
  $id = $Clsid.Trim(); if ($id -notmatch '^\{') { $id = '{' + $id.Trim('{}') + '}' }
  # ClassId can come from task XML, which an attacker controls; refuse anything that is not
  # GUID-shaped before splicing it into a registry Sub path.
  if ($id -notmatch '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$') { return $null }
  foreach ($h in $script:Loaded) {
    $k = Read-Key 'HKU' "$($h.Sid)\Software\Classes\CLSID\$id\InprocServer32" $Module
    if ($k -and $k.Values.ContainsKey('')) { return [string]$k.Values[''] }
  }
  foreach ($s in @("SOFTWARE\Classes\CLSID\$id\InprocServer32", "SOFTWARE\WOW6432Node\Classes\CLSID\$id\InprocServer32")) {
    $k = Read-Key 'HKLM' $s $Module
    if ($k -and $k.Values.ContainsKey('')) { return [string]$k.Values[''] }
  }
  return $null
}

function Test-ClsidOverride {
  param([string]$Clsid, [string]$Module)
  if ([string]::IsNullOrWhiteSpace($Clsid)) { return $false }
  $id = $Clsid.Trim(); if ($id -notmatch '^\{') { $id = '{' + $id.Trim('{}') + '}' }
  if ($id -notmatch '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$') { return $false }
  foreach ($h in $script:Loaded) {
    if (Read-Key 'HKU' "$($h.Sid)\Software\Classes\CLSID\$id\InprocServer32" $Module) { return $true }
  }
  return $false
}

# --- Rendering: widths derived from data and live console width; cells wrap, never truncate,
# --- because a truncated ImagePath is the one thing an analyst cannot afford to lose in RTR.
function Get-Width {
  $w = 0
  try { $w = $Host.UI.RawUI.WindowSize.Width } catch { }
  if (-not $w -or $w -lt 40) { $w = 120 }     # RTR and redirected hosts report 0
  return [Math]::Min($w - 1, 200)
}

function Split-Cell {
  param([string]$Text, [int]$W)
  if ($null -eq $Text) { $Text = '' }
  # Strips all C0 controls and DEL (not just CR/LF/TAB) -- an attacker-controlled value could
  # otherwise carry a terminal escape sequence into Write-Host.
  $Text = $Text -replace '[\x00-\x1F\x7F]+', ' '
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

function Write-Indented {
  # A label plus wrapped text, continuation lines aligned under the text, not the label.
  param([string]$Prefix, [string]$Text)
  $pad = ' ' * $Prefix.Length
  $lines = Split-Cell $Text ((Get-Width) - $Prefix.Length)
  Write-Host "$Prefix$($lines[0])"
  for ($i = 1; $i -lt $lines.Count; $i++) { Write-Host "$pad$($lines[$i])" }
}

function Write-Table {
  param([object[]]$Rows, [string[]]$Cols, [int]$Indent = 3)
  if (-not $Rows -or $Rows.Count -eq 0) { return }
  $pad = ' ' * $Indent
  $avail = (Get-Width) - $Indent
  $n = $Cols.Count
  $w = @()
  for ($i = 0; $i -lt $n; $i++) {
    $m = $Cols[$i].Length
    foreach ($r in $Rows) { $l = ([string]$r[$i]).Length; if ($l -gt $m) { $m = $l } }
    $w += [Math]::Min($m, 70)      # cap so one long command line cannot starve the rest
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
  Write-Host ($pad + ($hdr -join '  '))
  Write-Host ($pad + ($rule -join '  '))
  foreach ($r in $Rows) {
    $cells = @(); $h = 1
    for ($i = 0; $i -lt $n; $i++) {
      $c = Split-Cell ([string]$r[$i]) $w[$i]
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
      Write-Host ($pad + (($o -join '  ').TrimEnd()))
    }
  }
}

############################### MODULES -- Quick tier ###################################

function M-RunKeys {
  $m = 'RunKeys'
  $machine = @('Run', 'RunOnce', 'RunOnceEx', 'RunServices', 'RunServicesOnce', 'Policies\Explorer\Run')
  foreach ($s in $machine) {
    Add-KeyValues $m 'HKLM' "SOFTWARE\Microsoft\Windows\CurrentVersion\$s" 'machine'
    Add-KeyValues $m 'HKLM' "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\$s" 'machine (32-bit)'
  }
  foreach ($h in $script:Loaded) {
    foreach ($s in @('Run', 'RunOnce', 'RunOnceEx', 'Policies\Explorer\Run')) {
      Add-KeyValues $m 'HKU' "$($h.Sid)\Software\Microsoft\Windows\CurrentVersion\$s" $h.User $h.Profile
    }
  }
  # Per-user Run keys also exist for profiles whose hive is not mounted; those are covered by
  # the unloaded-hive report rather than silently missed.
  # Legacy Windows NT load/run values -- still honoured at logon, rarely checked.
  Add-KeyValues $m 'HKLM' 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'machine (legacy load/run)' -Only @('load', 'run') -Evidence @('NON-DEFAULT-VALUE')
  foreach ($h in $script:Loaded) {
    Add-KeyValues $m 'HKU' "$($h.Sid)\Software\Microsoft\Windows NT\CurrentVersion\Windows" "$($h.User) (legacy load/run)" $h.Profile -Only @('load', 'run') -Evidence @('NON-DEFAULT-VALUE')
  }
}

function M-StartupFolders {
  # Swept on disk per profile so a profile with no loaded hive is still covered.
  $m = 'StartupFolders'
  $dirs = @([pscustomobject]@{ P = (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'); U = 'All Users'; H = $null })
  foreach ($p in $script:Profiles) {
    $dirs += [pscustomobject]@{ P = (Join-Path $p.Profile 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'); U = $p.User; H = $p.Profile }
  }
  $shell = $null
  try { $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop } catch { Add-Gap 'WScript.Shell COM' 'unavailable; .lnk targets unresolved' $m }
  try {
    foreach ($d in $dirs) {
      if (-not (Test-Path -ErrorAction SilentlyContinue -LiteralPath $d.P)) { continue }
      $items = $null
      try { $items = Get-ChildItem -LiteralPath $d.P -File -Force -ErrorAction Stop } catch { Add-Gap $d.P $_.Exception.Message $m; continue }
      foreach ($f in $items) {
        if ($f.Name -ieq 'desktop.ini') { continue }
        $target = $f.FullName; $cmd = $null
        if ($shell -and $f.Extension -ieq '.lnk') {
          try {
            $sc = $shell.CreateShortcut($f.FullName)
            if ($sc.TargetPath) { $target = $sc.TargetPath }
            $cmd = (@($sc.TargetPath, $sc.Arguments) | Where-Object { $_ }) -join ' '
            [Runtime.InteropServices.Marshal]::ReleaseComObject($sc) | Out-Null
          } catch { Add-Gap $f.FullName "shortcut unreadable: $($_.Exception.Message)" $m }
        }
        Add-Finding -Module $m -Item $f.Name -Scope $d.U -Detail $target -Location $d.P -Target $target -Command $cmd -Profile $d.H -LastWrite $f.LastWriteTimeUtc
      }
    }
  } finally {
    if ($shell) { [Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null; [GC]::Collect() }
  }
}

function M-ShellFolderRedir {
  # A redirected Startup folder relocates the sweep above without touching any Run key.
  $m = 'ShellFolderRedir'
  # Compared by canonical suffix, not equality: .DEFAULT stores the value unexpanded and has
  # no ProfileList entry, so an equality check reports a stock value as redirected.
  $expected = @{
    'Startup'        = 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    'Common Startup' = 'Microsoft\Windows\Start Menu\Programs\Startup'
  }
  foreach ($h in $script:Loaded) {
    foreach ($s in @('User Shell Folders', 'Shell Folders')) {
      $k = Read-Key 'HKU' "$($h.Sid)\Software\Microsoft\Windows\CurrentVersion\Explorer\$s" $m
      if (-not $k) { continue }
      foreach ($n in @('Startup', 'Common Startup')) {
        if (-not $k.Values.ContainsKey($n)) { continue }
        $raw = ([string]$k.Values[$n]).TrimEnd('\')
        $res = Resolve-Target $raw $h.Profile
        $suffix = $expected[$n]
        $stock = ($raw -ilike "*$suffix") -or ($res -and $res.TrimEnd('\') -ilike "*$suffix")
        Add-Finding -Module $m -Item $n -Scope $h.User -Location "HKU\$($h.Sid)\...\Explorer\$s" -NoVerify `
          -Detail $(if ($stock) { "$raw (matches stock path)" } else { "$raw (expected to end with ...\$suffix)" }) `
          -LastWrite $k.LastWrite -Evidence $(if ($stock) { @() } else { @('NON-DEFAULT-VALUE') }) -VerboseOnly:$stock
      }
    }
  }
}

function M-Services {
  # svchost-hosted services are handled by ServiceDll instead: evaluating svchost.exe here
  # would say nothing about the code that actually runs.
  $m = 'Services'
  $root = 'SYSTEM\CurrentControlSet\Services'
  $all = Read-Key 'HKLM' $root $m
  if (-not $all) { return }
  foreach ($n in $all.Subs) {
    $s = Read-Key 'HKLM' "$root\$n" $m
    if (-not $s) { continue }
    $img = [string]$s.Values['ImagePath']
    if ([string]::IsNullOrWhiteSpace($img)) { continue }
    $exe = Get-CmdTarget $img
    if ($exe -and ([IO.Path]::GetFileName($exe)) -ieq 'svchost.exe') { continue }
    $start = 'unknown'
    if ($null -ne $s.Values['Start'] -and $StartTypes.ContainsKey([int]$s.Values['Start'])) { $start = $StartTypes[[int]$s.Values['Start']] }
    $acct = Resolve-Principal ([string]$s.Values['ObjectName']); if (-not $acct) { $acct = 'LocalSystem' }
    $disp = [string]$s.Values['DisplayName']
    Add-Finding -Module $m -Item $n -Scope "$start / $acct" -Detail $img -Location "HKLM\$root\$n" `
      -Command $img -Extra $(if ($disp) { "DisplayName: $disp" } else { $null }) -LastWrite $s.LastWrite
  }
}

function M-ServiceDll {
  # The process tree looks entirely normal here; Parameters\ServiceDll is the only place
  # svchost-hosted service abuse surfaces at all.
  $m = 'ServiceDll'
  $root = 'SYSTEM\CurrentControlSet\Services'
  $all = Read-Key 'HKLM' $root $m
  if (-not $all) { return }
  foreach ($n in $all.Subs) {
    $p = Read-Key 'HKLM' "$root\$n\Parameters" $m
    if (-not $p) { continue }
    $dll = [string]$p.Values['ServiceDll']
    if ([string]::IsNullOrWhiteSpace($dll)) { continue }
    $s = Read-Key 'HKLM' "$root\$n" $m
    $grp = ''
    if ($s -and ([string]$s.Values['ImagePath']) -match '-k\s+(\S+)') { $grp = $Matches[1] }
    Add-Finding -Module $m -Item $n -Scope $grp -Detail $dll -Location "HKLM\$root\$n\Parameters" `
      -Target $dll -LastWrite $p.LastWrite
  }
}

function M-ScheduledTasks {
  # Cross-references filesystem / TaskCache / live scheduler -- present in one but not the
  # others is an orphan, a finding in itself.
  $m = 'ScheduledTasks'
  $live = @{}; $info = @{}; $liveOk = $true
  try {
    $tasks = Get-ScheduledTask -ErrorAction Stop
    foreach ($t in $tasks) { $live[($t.TaskPath + $t.TaskName).ToLowerInvariant()] = $true }
    foreach ($i in ($tasks | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue)) {
      if ($i) { $info[($i.TaskPath + $i.TaskName).ToLowerInvariant()] = $i }
    }
  } catch { $liveOk = $false; Add-Gap 'Get-ScheduledTask' $_.Exception.Message $m }
  $cache = @{}
  $cRoot = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks'
  $cKey = Read-Key 'HKLM' $cRoot $m
  if ($cKey) {
    foreach ($g in $cKey.Subs) {
      $e = Read-Key 'HKLM' "$cRoot\$g" $m
      if ($e -and $e.Values.ContainsKey('Path')) { $cache[([string]$e.Values['Path']).ToLowerInvariant()] = $true }
    }
  }
  $onDisk = @{}
  foreach ($root in @((Join-Path $env:SystemRoot 'System32\Tasks'), (Join-Path $env:SystemRoot 'SysWOW64\Tasks'))) {
    if (-not (Test-Path -ErrorAction SilentlyContinue -LiteralPath $root)) { continue }
    $files = $null
    try { $files = Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction Stop } catch { Add-Gap $root $_.Exception.Message $m; continue }
    foreach ($f in $files) {
      $xml = $null
      try { $xml = [xml](Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop) } catch { Add-Gap $f.FullName "task XML unreadable: $($_.Exception.Message)" $m; continue }
      if (-not $xml.Task) { continue }
      $path = '\' + $f.FullName.Substring($root.Length).TrimStart('\')
      $onDisk[$path.ToLowerInvariant()] = $true
      $runAs = ''
      if ($xml.Task.Principals -and $xml.Task.Principals.Principal) {
        $pr = @($xml.Task.Principals.Principal)[0]
        # Task XML stores the principal as a SID as often as a name; show the name.
        $runAs = Resolve-Principal "$($pr.UserId)$($pr.GroupId)"
        if ($pr.RunLevel) { $runAs = "$runAs ($($pr.RunLevel))" }
      }
      $trg = @()
      if ($xml.Task.Triggers) { foreach ($t in $xml.Task.Triggers.ChildNodes) { $trg += $t.LocalName } }
      if ($trg.Count -eq 0) { $trg = @('none') }
      $ev = @()
      if ($xml.Task.Settings -and ([string]$xml.Task.Settings.Hidden -ieq 'true')) { $ev += 'HIDDEN' }
      # If Get-ScheduledTask failed, $live is empty and unreliable, not known-orphaned -- skip
      # that half rather than mass-tag every on-disk task.
      if (-not $cache.ContainsKey($path.ToLowerInvariant()) -or ($liveOk -and -not $live.ContainsKey($path.ToLowerInvariant()))) { $ev += 'REGISTRATION-ORPHAN' }
      $lastRun = ''
      $i = $info[$path.ToLowerInvariant()]
      # The scheduler reports a literal 1999-11-30 for "never run", in LOCAL time.
      if ($i -and $i.LastRunTime) { $lastRun = $(if ($i.LastRunTime.Year -gt 1999) { $i.LastRunTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') } else { 'never' }) }
      $actions = @()
      if ($xml.Task.Actions) { foreach ($a in $xml.Task.Actions.ChildNodes) { $actions += $a } }
      if ($actions.Count -eq 0) {
        Add-Finding -Module $m -Item $f.Name -Scope $runAs -Detail '(no action defined)' -Location $path `
          -Extra "triggers: $($trg -join ',')" -LastWrite $f.LastWriteTimeUtc -Evidence $ev
        continue
      }
      foreach ($a in $actions) {
        $cmd = $null; $target = $null; $noCmd = $false; $ev2 = @() + $ev
        if ($a.LocalName -eq 'Exec') {
          # Target is left for Add-Finding to derive from the full command line, arguments
          # included: that is what drills "rundll32.exe x.dll,Entry" down to x.dll.
          $cmd = (@([string]$a.Command, [string]$a.Arguments) | Where-Object { $_ }) -join ' '
        } elseif ($a.LocalName -eq 'ComHandler') {
          # A COM-handler action is only as trustworthy as the CLSID it resolves to, and a
          # per-user override hijacks the task without touching the task at all.
          $clsid = [string]$a.ClassId
          $cmd = "ComHandler $clsid"
          $target = Resolve-Clsid $clsid $m
          # Unresolvable CLSID has no file target; without this the literal word "ComHandler"
          # is treated as a binary name and reported as a missing System32 file.
          if (-not $target) { $noCmd = $true }
          if (Test-ClsidOverride $clsid $m) { $ev2 += 'PER-USER-OVERRIDE' }
        } else { $cmd = $a.LocalName; $noCmd = $true }
        # Detail is what actually executes -- the whole point of looking at a task. Triggers
        # and last-run time are context, so they move to -Verbose.
        $more = "triggers: $($trg -join ',')"
        if ($lastRun) { $more = "$more | last run: $lastRun" }
        Add-Finding -Module $m -Item $f.Name -Scope $runAs -Detail $cmd -Location $path -Extra $more `
          -Command $cmd -Target $target -NoCmdTarget:$noCmd -LastWrite $f.LastWriteTimeUtc -Evidence $ev2
      }
    }
  }
  foreach ($c in $cache.Keys) {
    if ($onDisk.ContainsKey($c)) { continue }
    Add-Finding -Module $m -Item (Split-Path -Leaf $c) -Scope 'unknown' -Location $c -NoVerify `
      -Detail 'TaskCache entry with no task XML on disk' -Evidence @('REGISTRATION-ORPHAN') -Absolute 'Notable'
  }
}

function M-WMI {
  # Only a BOUND filter+consumer+binding triad executes. Orphaned halves are inventory
  # context: flagging them buries the real ones under legitimate monitoring software.
  $m = 'WMI'
  $f = @(); $c = @(); $b = @()
  try {
    $f = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction Stop)
    $c = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop)
    $b = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop)
  } catch { Add-Gap 'root\subscription' $_.Exception.Message $m; return }
  $bound = @{}
  foreach ($bind in $b) {
    # CIM renders the reference as Name = "x" WITH spaces around the equals sign.
    $fn = ''; $cn = ''
    if ([string]$bind.Filter -match 'Name\s*=\s*"([^"]+)"') { $fn = $Matches[1] }
    if ([string]$bind.Consumer -match 'Name\s*=\s*"([^"]+)"') { $cn = $Matches[1] }
    $bound[$cn] = $true
    $flt = $f | Where-Object { $_.Name -eq $fn } | Select-Object -First 1
    $con = $c | Where-Object { $_.Name -eq $cn } | Select-Object -First 1
    $act = ''; $type = 'unknown'
    if ($con) {
      $type = $con.CimClass.CimClassName
      if ($con.CommandLineTemplate) { $act = [string]$con.CommandLineTemplate }
      elseif ($con.ScriptText) { $act = [string]$con.ScriptText }
      elseif ($con.FileName) { $act = [string]$con.FileName }
    }
    $ev = @()
    # An ActiveScript consumer keeps its payload inside the repository -- no file on disk to
    # verify, so the script text itself is the only thing left to judge.
    if ($type -eq 'ActiveScriptEventConsumer' -and $act -imatch $StrongCmdRx) { $ev += 'SUSPICIOUS-CONTENT' }
    Add-Finding -Module $m -Item "$fn -> $cn" -Scope "$type (bound)" -Location 'root\subscription' `
      -Detail "trigger: $(if ($flt) { [string]$flt.Query } else { 'filter not found' }) | action: $act" `
      -Command $(if ($type -eq 'CommandLineEventConsumer') { $act } else { $null }) `
      -Target $(if ($act -and $type -ne 'CommandLineEventConsumer' -and $type -ne 'ActiveScriptEventConsumer') { $act } else { $null }) -Evidence $ev
  }
  foreach ($con in $c) {
    if ($bound.ContainsKey([string]$con.Name)) { continue }
    $act = ''
    if ($con.CommandLineTemplate) { $act = [string]$con.CommandLineTemplate } elseif ($con.ScriptText) { $act = [string]$con.ScriptText }
    Add-Finding -Module $m -Item ([string]$con.Name) -Scope "$($con.CimClass.CimClassName) (no binding, inert)" `
      -Location 'root\subscription' -Detail "action: $act" -NoVerify -VerboseOnly
  }
}

function M-Winlogon {
  # Absolute rules only: legitimate variance here is effectively zero.
  $m = 'Winlogon'
  $sub = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  $k = Read-Key 'HKLM' $sub $m
  if ($k) {
    $sh = [string]$k.Values['Shell']
    if ($sh) {
      $stock = ($sh.Trim() -ieq $StockShell)
      Add-Finding -Module $m -Item 'Shell' -Scope 'machine' -Location "HKLM\$sub" -Command $sh -LastWrite $k.LastWrite `
        -Detail "configured: $sh | expected: $StockShell" -Absolute $(if ($stock) { '' } else { 'High' }) `
        -Evidence $(if ($stock) { @() } else { @('NON-DEFAULT-VALUE') }) -VerboseOnly:$stock
    }
    $ui = [string]$k.Values['Userinit']
    if ($ui) {
      # Userinit legitimately ends in a trailing comma. What matters is how many
      # comma-separated entries exist, not equality with the default string.
      $entries = @($ui -split ',' | Where-Object { $_.Trim() })
      $stock = ($entries.Count -le 1)
      Add-Finding -Module $m -Item 'Userinit' -Scope 'machine' -Location "HKLM\$sub" -Command $ui -LastWrite $k.LastWrite `
        -Detail "configured: $ui | expected: exactly one path plus trailing comma" `
        -Absolute $(if ($stock) { '' } else { 'High' }) -Evidence $(if ($stock) { @() } else { @('NON-DEFAULT-VALUE') }) -VerboseOnly:$stock
    }
  }
  # Notify was deprecated after Vista; nothing current legitimately registers here.
  $nk = Read-Key 'HKLM' "$sub\Notify" $m
  if ($nk) {
    foreach ($p in $nk.Subs) {
      $pk = Read-Key 'HKLM' "$sub\Notify\$p" $m
      if (-not $pk) { continue }
      Add-Finding -Module $m -Item $p -Scope 'machine (Notify package)' -Location "HKLM\$sub\Notify\$p" `
        -Target ([string]$pk.Values['DllName']) -Detail ([string]$pk.Values['DllName']) -LastWrite $pk.LastWrite `
        -Absolute 'Notable' -Evidence @('NON-DEFAULT-VALUE')
    }
  }
  # A per-user Shell override exists for almost no one by default and needs no elevation.
  foreach ($h in $script:Loaded) {
    $uk = Read-Key 'HKU' "$($h.Sid)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" $m
    if (-not $uk -or -not $uk.Values.ContainsKey('Shell')) { continue }
    Add-Finding -Module $m -Item 'Shell (per-user)' -Scope $h.User -Location "HKU\$($h.Sid)\...\Winlogon" `
      -Command ([string]$uk.Values['Shell']) -Detail ([string]$uk.Values['Shell']) -Profile $h.Profile `
      -LastWrite $uk.LastWrite -Absolute 'High' -Evidence @('PER-USER-OVERRIDE')
  }
}

function M-LSAPackages {
  # Every name resolved and verified individually -- no assumed-safe skip list, since password
  #-filter software legitimately populates Notification Packages, exactly where malice hides.
  $m = 'LSAPackages'
  $sub = 'SYSTEM\CurrentControlSet\Control\Lsa'
  $k = Read-Key 'HKLM' $sub $m
  if (-not $k) { return }
  foreach ($list in @('Authentication Packages', 'Notification Packages', 'Security Packages')) {
    if (-not $k.Values.ContainsKey($list)) { continue }
    foreach ($e in @($k.Values[$list])) {
      $n = [string]$e
      if ([string]::IsNullOrWhiteSpace($n) -or $n -ieq '""') { continue }
      $ev = @(); $res = $null
      # A path-shaped or malformed entry never resolves the normal System32 way -- catch it
      # before naive resolution turns a traversal string into a plausible-looking path.
      if ($n -match '[\\/:*?"<>|]') { $ev += 'NON-DEFAULT-VALUE'; $res = Resolve-Target $n }
      else { $res = Resolve-Target "$n.dll" }
      Add-Finding -Module $m -Item $n -Scope $list -Location "HKLM\$sub" -Target $res -Detail $res -LastWrite $k.LastWrite -Evidence $ev
    }
  }
  # OSConfig holds a second, boot-authoritative copy; tooling updating only one is odd.
  $oc = Read-Key 'HKLM' "$sub\OSConfig" $m
  if ($oc -and $oc.Values.ContainsKey('Security Packages') -and $k.Values.ContainsKey('Security Packages')) {
    $a = (@($k.Values['Security Packages']) | Sort-Object) -join ';'
    $b = (@($oc.Values['Security Packages']) | Sort-Object) -join ';'
    if ($a -ne $b) {
      Add-Finding -Module $m -Item 'Security Packages' -Scope 'OSConfig mirror out of sync' -Location "HKLM\$sub\OSConfig" `
        -Detail "primary: $a | OSConfig: $b" -NoVerify -LastWrite $oc.LastWrite -Absolute 'Notable' -Evidence @('NON-DEFAULT-VALUE')
    }
  }
}

function M-IFEO {
  # A Debugger on an accessibility binary is conclusive on presence alone -- scoring the
  # debugger's own trust would under-rate the highest-severity variant of this technique.
  $m = 'IFEO'
  foreach ($root in @('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
      'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
    $rk = Read-Key 'HKLM' $root $m
    if (-not $rk) { continue }
    foreach ($bin in $rk.Subs) {
      $k = Read-Key 'HKLM' "$root\$bin" $m
      if (-not $k) { continue }
      $acc = ($AccessibilityBins -contains $bin.ToLowerInvariant())
      $type = $(if ($acc) { 'ACCESSIBILITY (pre-auth reachable)' } else { 'application' })
      $dbg = [string]$k.Values['Debugger']
      if ($dbg) {
        Add-Finding -Module $m -Item $bin -Scope $type -Location "HKLM\$root\$bin" -Command $dbg `
          -Detail "Debugger = $dbg" -LastWrite $k.LastWrite -Absolute $(if ($acc) { 'High' } else { '' }) -Evidence @('NON-DEFAULT-VALUE')
      }
      # Silent Process Exit: the second, far less checked IFEO abuse path.
      $gf = $k.Values['GlobalFlag']
      if ($null -ne $gf) {
        $v = 0; try { $v = [int]$gf } catch { }
        if ($v -band 0x200) {
          $mon = $null
          $mk = Read-Key 'HKLM' "SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$bin" $m
          if ($mk) { $mon = [string]$mk.Values['MonitorProcess'] }
          Add-Finding -Module $m -Item $bin -Scope $type -Location "HKLM\...\SilentProcessExit\$bin" -Command $mon `
            -Detail ('SilentProcessExit GlobalFlag 0x{0:X} MonitorProcess = {1}' -f $v, $mon) -LastWrite $k.LastWrite `
            -Absolute 'Notable' -Evidence @('NON-DEFAULT-VALUE')
        }
      }
    }
  }
}

function M-AppInitCerts {
  # AppInit_DLLs is only live when LoadAppInit_DLLs = 1 -- the populated-vs-active
  # distinction is the central judgement for this key.
  $m = 'AppInitCerts'
  foreach ($v in @(@{ S = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; V = '64-bit' },
      @{ S = 'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'; V = '32-bit' })) {
    $k = Read-Key 'HKLM' $v.S $m
    if (-not $k) { continue }
    $list = [string]$k.Values['AppInit_DLLs']
    if ([string]::IsNullOrWhiteSpace($list)) { continue }
    $active = ($k.Values['LoadAppInit_DLLs'] -eq 1)
    foreach ($dll in @($list -split '[\s,;]+' | Where-Object { $_ })) {
      Add-Finding -Module $m -Item 'AppInit_DLLs' -Scope $v.V -Location "HKLM\$($v.S)" -Target $dll `
        -Detail "$dll | $(if ($active) { 'ACTIVE (LoadAppInit_DLLs=1)' } else { 'dormant (LoadAppInit_DLLs=0)' })" `
        -LastWrite $k.LastWrite -Absolute $(if ($active) { 'Notable' } else { '' }) -Evidence @('NON-DEFAULT-VALUE')
    }
  }
  # AppCertDLLs has no enable switch and no Secure Boot mitigation: populated means live.
  $sm = Read-Key 'HKLM' 'SYSTEM\CurrentControlSet\Control\Session Manager' $m
  if ($sm -and $sm.Values.ContainsKey('AppCertDLLs')) {
    foreach ($dll in @($sm.Values['AppCertDLLs'] | Where-Object { $_ })) {
      Add-Finding -Module $m -Item 'AppCertDLLs' -Scope 'machine' -Location 'HKLM\SYSTEM\...\Session Manager' `
        -Target ([string]$dll) -Detail ([string]$dll) -LastWrite $sm.LastWrite -Absolute 'Notable' -Evidence @('NON-DEFAULT-VALUE')
    }
  }
}

function M-ActiveSetup {
  # StubPath fires for every profile whose recorded HKCU version is stale. The version
  # delta is zero-weight context: it is normal after any legitimate component update.
  $m = 'ActiveSetup'
  foreach ($root in @('SOFTWARE\Microsoft\Active Setup\Installed Components',
      'SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components')) {
    $rk = Read-Key 'HKLM' $root $m
    if (-not $rk) { continue }
    foreach ($g in $rk.Subs) {
      $k = Read-Key 'HKLM' "$root\$g" $m
      if (-not $k) { continue }
      $stub = [string]$k.Values['StubPath']
      if ([string]::IsNullOrWhiteSpace($stub)) { continue }
      $ver = [string]$k.Values['Version']
      $name = [string]$k.Values['']
      if ([string]::IsNullOrWhiteSpace($name)) { $name = "(unnamed) $g" }
      $pending = @()
      foreach ($h in $script:Loaded) {
        $uk = Read-Key 'HKU' "$($h.Sid)\Software\Microsoft\Active Setup\Installed Components\$g" $m
        $uv = ''
        if ($uk) { $uv = [string]$uk.Values['Version'] }
        if ($uv -ne $ver) { $pending += $h.User }
      }
      $det = "v$ver IsInstalled=$([string]$k.Values['IsInstalled'])"
      if ($pending.Count -gt 0) { $det = "$det | pending for: $($pending -join ', ')" }
      Add-Finding -Module $m -Item $name -Scope $g -Location "HKLM\$root\$g" -Command $stub -Detail $det -LastWrite $k.LastWrite
    }
  }
}

function M-BootLogonScripts {
  # Best-effort registry + local GPO script cache walk, not a full GPO parser. Degrades to
  # nothing on a standalone host rather than erroring.
  $m = 'BootLogonScripts'
  foreach ($h in $script:Loaded) {
    Add-KeyValues $m 'HKU' "$($h.Sid)\Environment" $h.User $h.Profile -Only @('UserInitMprLogonScript') -Absolute 'Notable' -Evidence @('NON-DEFAULT-VALUE')
  }
  foreach ($kind in @('Startup', 'Shutdown')) {
    $base = "SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\$kind"
    $k = Read-Key 'HKLM' $base $m
    if (-not $k) { continue }
    foreach ($gpo in $k.Subs) {
      $gk = Read-Key 'HKLM' "$base\$gpo" $m
      if (-not $gk) { continue }
      foreach ($idx in $gk.Subs) {
        $s = Read-Key 'HKLM' "$base\$gpo\$idx" $m
        if (-not $s) { continue }
        $cmd = [string]$s.Values['Script']
        if (-not $cmd) { continue }
        Add-Finding -Module $m -Item (Split-Path -Leaf $cmd) -Scope "GPO $kind script" -Location "HKLM\$base\$gpo\$idx" `
          -Command ((@($cmd, [string]$s.Values['Parameters']) | Where-Object { $_ }) -join ' ') -Detail $cmd -LastWrite $s.LastWrite
      }
    }
  }
  foreach ($d in @(@{ P = 'System32\GroupPolicy\Machine\Scripts\Startup'; S = 'local GPO Startup' },
      @{ P = 'System32\GroupPolicy\Machine\Scripts\Shutdown'; S = 'local GPO Shutdown' },
      @{ P = 'System32\GroupPolicy\User\Scripts\Logon'; S = 'local GPO Logon' },
      @{ P = 'System32\GroupPolicy\User\Scripts\Logoff'; S = 'local GPO Logoff' })) {
    $dir = Join-Path $env:SystemRoot $d.P
    if (-not (Test-Path -ErrorAction SilentlyContinue -LiteralPath $dir)) { continue }
    try {
      foreach ($f in (Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction Stop)) {
        if ($f.Name -ieq 'scripts.ini') { continue }
        $ev = @()
        if (Test-Content $f.FullName $m) { $ev += 'SUSPICIOUS-CONTENT' }
        Add-Finding -Module $m -Item $f.Name -Scope $d.S -Location $dir -Target $f.FullName -Detail $f.FullName -LastWrite $f.LastWriteTimeUtc -Evidence $ev
      }
    } catch { Add-Gap $dir $_.Exception.Message $m }
  }
}

function M-NetshHelpers {
  # Helper value names are opaque vendor identifiers, so path/signature verification is the
  # only usable filter -- name recognition is not available here.
  foreach ($s in @('SOFTWARE\Microsoft\Netsh', 'SOFTWARE\WOW6432Node\Microsoft\Netsh')) {
    Add-KeyValues 'NetshHelpers' 'HKLM' $s 'machine' -AsTarget
  }
}

function M-PSProfiles {
  # None of these files exist on a stock install, so existence is a data point. Content is
  # scanned for the download/execute patterns the reference note names as the finding.
  $m = 'PSProfiles'
  $cand = New-Object System.Collections.Generic.List[object]
  $roots = @(@{ P = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0'); E = 'WinPS 5.1' },
    @{ P = (Join-Path $env:SystemRoot 'SysWOW64\WindowsPowerShell\v1.0'); E = 'WinPS 5.1 (32-bit)' })
  if ($env:ProgramFiles -and (Test-Path -ErrorAction SilentlyContinue -LiteralPath (Join-Path $env:ProgramFiles 'PowerShell'))) {
    try {
      foreach ($d in (Get-ChildItem -LiteralPath (Join-Path $env:ProgramFiles 'PowerShell') -Directory -ErrorAction Stop)) {
        $roots += @{ P = $d.FullName; E = "PowerShell $($d.Name)" }
      }
    } catch { Add-Gap (Join-Path $env:ProgramFiles 'PowerShell') $_.Exception.Message $m }
  }
  foreach ($r in $roots) {
    foreach ($f in @('profile.ps1', 'Microsoft.PowerShell_profile.ps1', 'Microsoft.PowerShellISE_profile.ps1')) {
      $cand.Add([pscustomobject]@{ P = (Join-Path $r.P $f); S = 'AllUsers'; E = $r.E })
    }
  }
  foreach ($p in $script:Profiles) {
    foreach ($e in @(@{ D = 'WindowsPowerShell'; E = 'WinPS 5.1' }, @{ D = 'PowerShell'; E = 'PowerShell 7+' })) {
      foreach ($f in @('profile.ps1', 'Microsoft.PowerShell_profile.ps1', 'Microsoft.PowerShellISE_profile.ps1')) {
        $cand.Add([pscustomobject]@{ P = (Join-Path $p.Profile "Documents\$($e.D)\$f"); S = $p.User; E = $e.E })
      }
    }
    # A OneDrive-redirected Documents folder moves these out from under the path above.
    foreach ($e in @('WindowsPowerShell', 'PowerShell')) {
      $rd = Join-Path $p.Profile "OneDrive\Documents\$e"
      if (-not (Test-Path -ErrorAction SilentlyContinue -LiteralPath $rd)) { continue }
      foreach ($f in @('profile.ps1', 'Microsoft.PowerShell_profile.ps1')) {
        $cand.Add([pscustomobject]@{ P = (Join-Path $rd $f); S = "$($p.User) (redirected)"; E = $e })
      }
    }
  }
  foreach ($c in $cand) {
    if (-not (Test-Path -ErrorAction SilentlyContinue -LiteralPath $c.P -PathType Leaf)) { continue }
    $i = $null
    try { $i = Get-Item -LiteralPath $c.P -Force -ErrorAction Stop } catch { Add-Gap $c.P $_.Exception.Message $m; continue }
    $ev = @('NON-DEFAULT-VALUE')
    if (Test-Content $c.P $m) { $ev += 'SUSPICIOUS-CONTENT' }
    # Verification is skipped: a per-user .ps1 is user-writable and unsigned by definition.
    # Existence is context; content is the finding.
    Add-Finding -Module $m -Item $i.Name -Scope "$($c.S) / $($c.E)" -Location (Split-Path -Parent $c.P) `
      -Target $c.P -Detail "$($i.Length) bytes" -NoVerify -LastWrite $i.LastWriteTimeUtc -Evidence $ev
  }
}

function M-CommandProcessorAutoRun {
  # Fires on essentially every new cmd.exe. Some enterprises genuinely use this for
  # environment setup, so a plain value is NOTABLE; a LOLBIN/encoded payload promotes it.
  $m = 'CommandProcessorAutoRun'
  Add-KeyValues $m 'HKLM' 'SOFTWARE\Microsoft\Command Processor' 'machine' -Only @('AutoRun') -Absolute 'Notable' -Evidence @('NON-DEFAULT-VALUE')
  foreach ($h in $script:Loaded) {
    Add-KeyValues $m 'HKU' "$($h.Sid)\Software\Microsoft\Command Processor" $h.User $h.Profile -Only @('AutoRun') -Absolute 'Notable' -Evidence @('NON-DEFAULT-VALUE')
  }
}

function M-EnvHijack {
  # Watched variables have no benign default population, so presence is the finding; APM
  # tooling is the one legitimate explanation, distinguished by verifying the referenced DLL.
  $m = 'EnvHijack'
  $scopes = @(@{ R = 'HKLM'; S = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'; L = 'machine'; P = $null })
  foreach ($h in $script:Loaded) { $scopes += @{ R = 'HKU'; S = "$($h.Sid)\Environment"; L = $h.User; P = $h.Profile } }
  foreach ($s in $scopes) {
    $k = Read-Key $s.R $s.S $m
    if (-not $k) { continue }
    foreach ($v in $WatchedEnvVars) {
      if (-not $k.Values.ContainsKey($v)) { continue }
      $d = [string]$k.Values[$v]
      if ([string]::IsNullOrWhiteSpace($d)) { continue }
      # windir exists on every host by design; only a value that is not the real Windows
      # directory is a finding.
      if ($v -ieq 'windir') {
        $r = Resolve-Target $d $s.P
        if ($r -and ($r.TrimEnd('\') -ieq $env:SystemRoot.TrimEnd('\'))) { continue }
      }
      Add-Finding -Module $m -Item $v -Scope $s.L -Location "$($s.R)\$($s.S)" -Detail $d -Profile $s.P `
        -Target $(if ($v -ieq 'windir' -or $v -imatch 'PATH$') { $d } else { $null }) `
        -LastWrite $k.LastWrite -Absolute 'Notable' -Evidence @('NON-DEFAULT-VALUE')
    }
    if (-not $k.Values.ContainsKey('Path')) { continue }
    $entries = @(([string]$k.Values['Path']) -split ';' | Where-Object { $_.Trim() })
    $sys32 = (Join-Path $env:SystemRoot 'System32').TrimEnd('\')
    $idx = -1
    for ($i = 0; $i -lt $entries.Count; $i++) {
      $r = Resolve-Target $entries[$i] $s.P
      if ($r -and ($r.TrimEnd('\') -ieq $sys32)) { $idx = $i; break }
    }
    # Only meaningful in the list that actually contains System32 (the machine PATH) -- the
    # per-user PATH is appended at logon, so every entry there would otherwise read as noise.
    if ($idx -lt 0) { continue }
    for ($i = 0; $i -lt $idx; $i++) {
      $dir = Resolve-Target $entries[$i] $s.P
      if (-not $dir) { continue }
      $t = Get-Trust $dir
      if ($t -eq 'System' -or $t -eq 'Program') { continue }
      Add-Finding -Module $m -Item "PATH ahead of System32: $dir" -Scope $s.L -Location "$($s.R)\$($s.S)" -NoVerify `
        -Detail "position $($i + 1) of $($entries.Count), trust: $t" -LastWrite $k.LastWrite -Evidence @('UNTRUSTED-PATH', 'NON-DEFAULT-VALUE')
    }
  }
}

function M-SafeBoot {
  # A SafeBoot entry defeats the analyst's own remediation step rather than hiding anything,
  # so the roster is inventory-only; AlternateShell is the scored check.
  $m = 'SafeBoot'
  $root = 'SYSTEM\CurrentControlSet\Control\SafeBoot'
  $k = Read-Key 'HKLM' $root $m
  if ($k -and $k.Values.ContainsKey('AlternateShell')) {
    $v = [string]$k.Values['AlternateShell']
    $stock = ($v.Trim() -ieq $StockAltShell)
    Add-Finding -Module $m -Item 'AlternateShell' -Scope 'Safe Mode shell' -Location "HKLM\$root" -Command $v `
      -Detail "configured: $v | expected: $StockAltShell" -LastWrite $k.LastWrite `
      -Absolute $(if ($stock) { '' } else { 'High' }) -Evidence $(if ($stock) { @() } else { @('NON-DEFAULT-VALUE') }) -VerboseOnly:$stock
  }
  foreach ($mode in @('Minimal', 'Network')) {
    $mk = Read-Key 'HKLM' "$root\$mode" $m
    if (-not $mk) { continue }
    foreach ($e in $mk.Subs) {
      $ek = Read-Key 'HKLM' "$root\$mode\$e" $m
      $kind = ''
      if ($ek -and $ek.Values.ContainsKey('')) { $kind = [string]$ek.Values[''] }
      $lw = $(if ($ek) { $ek.LastWrite } else { $null })
      # Only a "Service"-typed entry is expected to have a Services key -- "Driver Group" and
      # device setup classes never do, so demanding one there flagged most of a stock roster.
      $svc = Read-Key 'HKLM' "SYSTEM\CurrentControlSet\Services\$($e -replace '\..*$', '')" $m
      if ($kind -ieq 'Service' -and -not $svc) {
        Add-Finding -Module $m -Item $e -Scope "$mode ($kind)" -Location "HKLM\$root\$mode\$e" -NoVerify `
          -Detail 'no matching Services registration' -LastWrite $lw -Evidence @('REGISTRATION-ORPHAN')
        continue
      }
      # Resolve to the binary this entry permits in Safe Mode and verify it -- whose code runs
      # when an analyst boots to Safe Mode to remediate should be the OS vendor's.
      $img = ''
      if ($svc) { $img = [string]$svc.Values['ImagePath'] }
      if ($img) {
        Add-Finding -Module $m -Item $e -Scope "$mode ($kind)" -Location "HKLM\$root\$mode\$e" `
          -Command $img -Detail $img -LastWrite $lw
      } else {
        Add-Finding -Module $m -Item $e -Scope "$mode ($kind)" -Location "HKLM\$root\$mode\$e" -NoVerify `
          -Detail 'allowed to start in Safe Mode' -LastWrite $lw -VerboseOnly
      }
    }
  }
}

function M-NetworkProviderOrder {
  # Every name cross-referenced against its own ProviderPath -- no assumed-safe list. A
  # malicious provider early in the chain sees credentials via NPLogonNotify().
  $m = 'NetworkProviderOrder'
  $k = Read-Key 'HKLM' 'SYSTEM\CurrentControlSet\Control\NetworkProvider\Order' $m
  if (-not $k -or -not $k.Values.ContainsKey('ProviderOrder')) { return }
  $order = @(([string]$k.Values['ProviderOrder']) -split ',' | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
  # HwOrder is the parallel copy Windows keeps; the two normally agree. A provider present in
  # one but not the other is a half-finished change worth reconciling.
  $hw = Read-Key 'HKLM' 'SYSTEM\CurrentControlSet\Control\NetworkProvider\HwOrder' $m
  if ($hw -and $hw.Values.ContainsKey('ProviderOrder')) {
    $hwOrder = @(([string]$hw.Values['ProviderOrder']) -split ',' | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
    if (($order -join ',') -ne ($hwOrder -join ',')) {
      Add-Finding -Module $m -Item 'Order vs HwOrder' -Scope 'machine' -Location 'HKLM\SYSTEM\...\NetworkProvider' -NoVerify `
        -Detail "Order: $($order -join ',') | HwOrder: $($hwOrder -join ',')" -LastWrite $hw.LastWrite `
        -Absolute 'Notable' -Evidence @('REGISTRATION-ORPHAN')
    }
  }
  # Position relative to LanmanWorkstation decides who sees a credential first: every
  # provider ahead of SMB is offered the logon notification before it.
  $smbIndex = [Array]::FindIndex($order, [Predicate[string]] { param($x) $x -ieq 'LanmanWorkstation' })
  $seen = @{}
  for ($i = 0; $i -lt $order.Count; $i++) {
    $n = $order[$i]
    $seen[$n.ToLowerInvariant()] = $true
    $reg = Read-Key 'HKLM' "SYSTEM\CurrentControlSet\Services\$n\NetworkProvider" $m
    $path = $null; $ev = @()
    if ($reg -and $reg.Values.ContainsKey('ProviderPath')) { $path = [string]$reg.Values['ProviderPath'] }
    else { $ev += 'REGISTRATION-ORPHAN' }    # a name with nothing behind it is the setup half
    $pos = "position $($i + 1) of $($order.Count)"
    if ($smbIndex -ge 0 -and $i -lt $smbIndex) {
      $pos = "$pos, ahead of LanmanWorkstation"
      # Only a non-OS-vendor provider earns the tag -- Windows itself ships RDPNP/P9NP ahead
      # of LanmanWorkstation by default.
      $resolvedPath = Resolve-Target $path
      if (-not $resolvedPath -or -not (Test-OsVendorBinary $resolvedPath)) { $ev += 'PRECEDES-SMB' }
    }
    Add-Finding -Module $m -Item $n -Scope $pos -Location 'HKLM\SYSTEM\...\NetworkProvider\Order' `
      -Target $path -Detail $(if ($path) { $path } else { 'NO ProviderPath registration found' }) -LastWrite $k.LastWrite -Evidence $ev
  }
  # The other direction: a provider DLL registered under a service but absent from the order.
  # Staged rather than live, and invisible to a sweep that only walks ProviderOrder.
  $svcRoot = 'SYSTEM\CurrentControlSet\Services'
  $all = Read-Key 'HKLM' $svcRoot $m
  if (-not $all) { return }
  foreach ($svc in $all.Subs) {
    if ($seen.ContainsKey($svc.ToLowerInvariant())) { continue }
    $reg = Read-Key 'HKLM' "$svcRoot\$svc\NetworkProvider" $m
    if (-not $reg -or -not $reg.Values.ContainsKey('ProviderPath')) { continue }
    Add-Finding -Module $m -Item $svc -Scope 'registered but not in ProviderOrder' -Location "HKLM\$svcRoot\$svc\NetworkProvider" `
      -Target ([string]$reg.Values['ProviderPath']) -Detail ([string]$reg.Values['ProviderPath']) `
      -LastWrite $reg.LastWrite -Evidence @('REGISTRATION-ORPHAN')
  }
}

function M-BootExecute {
  # smss.exe runs these before anything else in user mode. The documented stock value is a
  # single string, so exact matching is valid here and nowhere else.
  $m = 'BootExecute'
  $k = Read-Key 'HKLM' 'SYSTEM\CurrentControlSet\Control\Session Manager' $m
  if (-not $k -or -not $k.Values.ContainsKey('BootExecute')) { return }
  $e = @($k.Values['BootExecute'] | Where-Object { $_ })
  $stock = (($e -join ';') -eq $StockBootExecute)
  Add-Finding -Module $m -Item 'BootExecute' -Scope 'machine' -Location 'HKLM\SYSTEM\...\Session Manager' -NoVerify `
    -Detail "configured: $($e -join ' | ') | expected: $StockBootExecute" -LastWrite $k.LastWrite `
    -Absolute $(if ($stock) { '' } else { 'High' }) -Evidence $(if ($stock) { @() } else { @('NON-DEFAULT-VALUE') }) -VerboseOnly:$stock
}

function M-FileAssoc {
  # HKCU wins the HKCR merge, so a per-user override is the finding regardless of the command.
  # The command is the Detail -- the ProgID indirection that produced it is context.
  $m = 'FileAssoc'
  $machineProg = @{}
  foreach ($ext in $WatchedExt) {
    $ek = Read-Key 'HKLM' "SOFTWARE\Classes\$ext" $m
    if (-not $ek) { continue }
    $prog = [string]$ek.Values['']
    if ([string]::IsNullOrWhiteSpace($prog)) { continue }
    $machineProg[$ext] = $prog
    $ck = Read-Key 'HKLM' "SOFTWARE\Classes\$prog\shell\open\command" $m
    if (-not $ck) { continue }
    $cmd = [string]$ck.Values['']
    if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
    Add-Finding -Module $m -Item $ext -Scope 'machine' -Location "HKLM\SOFTWARE\Classes\$prog\shell\open\command" `
      -Command $cmd -Detail $cmd -Extra "ProgID: $prog" -LastWrite $ck.LastWrite
  }
  foreach ($h in $script:Loaded) {
    foreach ($ext in $WatchedExt) {
      # UserChoice is what Explorer actually honours for a double-click, overriding Classes
      # entirely -- the Classes side alone can describe a handler that never runs.
      $uc = Read-Key 'HKU' "$($h.Sid)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext\UserChoice" $m
      $ucProg = ''
      if ($uc) { $ucProg = [string]$uc.Values['ProgId'] }
      $ek = Read-Key 'HKU' "$($h.Sid)\Software\Classes\$ext" $m
      $hkcuProg = ''
      if ($ek) { $hkcuProg = [string]$ek.Values[''] }
      if (-not $ucProg -and -not $hkcuProg) { continue }
      $prog = $(if ($ucProg) { $ucProg } else { $hkcuProg })
      $source = $(if ($ucProg) { 'UserChoice (Explorer-authoritative)' } else { 'HKCU Classes override' })
      # Per-user first, then machine-wide: HKCU wins the merge.
      $ck = Read-Key 'HKU' "$($h.Sid)\Software\Classes\$prog\shell\open\command" $m
      if (-not $ck) { $ck = Read-Key 'HKLM' "SOFTWARE\Classes\$prog\shell\open\command" $m }
      $cmd = ''
      if ($ck) { $cmd = [string]$ck.Values[''] }
      # A Classes override is always evidence. A UserChoice entry's mere presence is normal --
      # what's worth surfacing is one that DISAGREES with the machine default on a watched
      # script/executable extension. Weight 2: context alone, escalates when stacked with an
      # unsigned/missing/user-writable handler. Quiet only because $WatchedExt is narrow --
      # widening it into document/media/browser extensions would light this up on normal
      # Windows behaviour (measured on a clean host: 52 benign UserChoice divergences, none a
      # script or executable type).
      $ev = @()
      if ($hkcuProg) { $ev += 'PER-USER-OVERRIDE' }
      if ($ucProg -and $machineProg.ContainsKey($ext) -and $ucProg -ine $machineProg[$ext]) {
        $ev += 'USERCHOICE-OVERRIDE'
        $source = "$source, machine default is $($machineProg[$ext])"
      }
      Add-Finding -Module $m -Item $ext -Scope $h.User -Location "HKU\$($h.Sid)\...\$ext" `
        -Command $cmd -Detail $(if ($cmd) { $cmd } else { "(ProgID $prog has no open command)" }) `
        -Extra "ProgID: $prog | via $source" -Profile $h.Profile `
        -LastWrite $(if ($uc) { $uc.LastWrite } else { $ek.LastWrite }) -Evidence $ev
    }
  }
}

function M-Screensaver {
  # A .scr is a renamed PE. ScreenSaveActive gates whether the target ever fires, so a
  # dormant hijack is still displayed -- just not verified as a live trigger.
  $m = 'Screensaver'
  foreach ($h in $script:Loaded) {
    $k = Read-Key 'HKU' "$($h.Sid)\Control Panel\Desktop" $m
    if (-not $k -or -not $k.Values.ContainsKey('SCRNSAVE.EXE')) { continue }
    $scr = [string]$k.Values['SCRNSAVE.EXE']
    if ([string]::IsNullOrWhiteSpace($scr)) { continue }
    $active = ([string]$k.Values['ScreenSaveActive'] -eq '1')
    Add-Finding -Module $m -Item 'SCRNSAVE.EXE' -Scope $h.User -Location "HKU\$($h.Sid)\Control Panel\Desktop" `
      -Target $scr -Profile $h.Profile -NoVerify:(-not $active) -LastWrite $k.LastWrite `
      -Detail "$scr | $(if ($active) { "enabled, timeout $([string]$k.Values['ScreenSaveTimeOut'])s" } else { 'disabled (dormant)' })"
  }
}

function M-OfficeTest {
  # Not created by any Office installation or update -- presence alone is the finding.
  $m = 'OfficeTest'
  $sub = 'Software\Microsoft\Office test\Special\Perf'
  $k = Read-Key 'HKLM' $sub $m
  if ($k) {
    Add-Finding -Module $m -Item 'Office test\Special\Perf' -Scope 'machine' -Location "HKLM\$sub" `
      -Target ([string]$k.Values['']) -Detail ([string]$k.Values['']) -LastWrite $k.LastWrite -Absolute 'High' -Evidence @('NON-DEFAULT-VALUE')
  }
  foreach ($h in $script:Loaded) {
    $uk = Read-Key 'HKU' "$($h.Sid)\$sub" $m
    if (-not $uk) { continue }
    Add-Finding -Module $m -Item 'Office test\Special\Perf' -Scope $h.User -Location "HKU\$($h.Sid)\$sub" `
      -Target ([string]$uk.Values['']) -Detail ([string]$uk.Values['']) -Profile $h.Profile -LastWrite $uk.LastWrite `
      -Absolute 'High' -Evidence @('NON-DEFAULT-VALUE')
  }
}

function M-DllSearchOrder {
  # The roster carries no triage value without a same-build baseline to diff against, so it
  # is inventory-only; SafeDllSearchMode is the check that stands alone.
  $m = 'DllSearchOrder'
  $sm = Read-Key 'HKLM' 'SYSTEM\CurrentControlSet\Control\Session Manager' $m
  if ($sm) {
    $v = $sm.Values['SafeDllSearchMode']
    $off = ($null -ne $v -and [int]$v -eq 0)      # absent means enabled (the OS default)
    Add-Finding -Module $m -Item 'SafeDllSearchMode' -Scope 'machine' -Location 'HKLM\SYSTEM\...\Session Manager' -NoVerify `
      -Detail $(if ($off) { '0 - DISABLED (current directory searched before System32)' } else { 'enabled (1 or default)' }) `
      -LastWrite $sm.LastWrite -Absolute $(if ($off) { 'Notable' } else { '' }) `
      -Evidence $(if ($off) { @('NON-DEFAULT-VALUE') } else { @() }) -VerboseOnly:(-not $off)
  }
  $k = Read-Key 'HKLM' 'SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs' $m
  if (-not $k) { return }
  # DllDirectory is where every KnownDLL is mapped from -- repointing it redirects the whole
  # pre-mapped set at once. Absent means the documented default (System32 / SysWOW64).
  foreach ($dv in @(@{ N = 'DllDirectory'; E = (Join-Path $env:SystemRoot 'System32') },
      @{ N = 'DllDirectory32'; E = (Join-Path $env:SystemRoot 'SysWOW64') })) {
    if (-not $k.Values.ContainsKey($dv.N)) { continue }
    $val = Resolve-Target ([string]$k.Values[$dv.N])
    $stock = ($val -and $val.TrimEnd('\') -ieq $dv.E.TrimEnd('\'))
    Add-Finding -Module $m -Item $dv.N -Scope 'machine' -Location 'HKLM\SYSTEM\...\KnownDLLs' -NoVerify `
      -Detail "$([string]$k.Values[$dv.N]) | expected: $($dv.E)" -LastWrite $k.LastWrite `
      -Absolute $(if ($stock) { '' } else { 'High' }) `
      -Evidence $(if ($stock) { @() } else { @('NON-DEFAULT-VALUE') }) -VerboseOnly:$stock
  }
  $dir = Join-Path $env:SystemRoot 'System32'
  if ($k.Values.ContainsKey('DllDirectory')) {
    $d = Resolve-Target ([string]$k.Values['DllDirectory'])
    if ($d) { $dir = $d }
  }
  foreach ($n in $k.Names) {
    if ($n -imatch '^DllDirectory') { continue }
    $dll = [string]$k.Values[$n]
    if ([string]::IsNullOrWhiteSpace($dll)) { continue }
    # A roster entry is a bare file name resolved against DllDirectory. One carrying a path
    # separator is redirecting a pre-mapped DLL somewhere else entirely.
    if ($dll -match '[\\/]') {
      Add-Finding -Module $m -Item $n -Scope 'roster' -Location 'HKLM\SYSTEM\...\KnownDLLs' `
        -Target $dll -Detail "$dll (roster entries are bare file names, not paths)" `
        -LastWrite $k.LastWrite -Absolute 'High' -Evidence @('NON-DEFAULT-VALUE')
      continue
    }
    $full = Join-Path $dir $dll
    $exists = Test-Path -ErrorAction SilentlyContinue -LiteralPath $full -PathType Leaf
    # Architecture-specific entries legitimately have no file, so absence is inventory, not a
    # finding; one that exists but is not OS-vendor-signed is a replaced pre-mapped DLL.
    if (-not $exists) {
      Add-Finding -Module $m -Item $n -Scope 'roster' -Location 'HKLM\SYSTEM\...\KnownDLLs' -NoVerify `
        -Detail "$dll (not present; normal for another architecture's entries)" -LastWrite $k.LastWrite -VerboseOnly
      continue
    }
    $bad = -not (Get-SigInfo $full).OsVendor
    Add-Finding -Module $m -Item $n -Scope 'roster' -Location 'HKLM\SYSTEM\...\KnownDLLs' -Target $full `
      -Detail $dll -LastWrite $k.LastWrite -VerboseOnly:(-not $bad) `
      -Absolute $(if ($bad) { 'High' } else { '' }) -Evidence $(if ($bad) { @('NON-DEFAULT-VALUE') } else { @() })
  }
}

function M-ComWatchlist {
  # These CLSIDs have no normal HKCU counterpart, so a per-user override is the finding.
  $m = 'ComWatchlist'
  foreach ($clsid in $ComWatch.Keys) {
    foreach ($h in $script:Loaded) {
      $k = Read-Key 'HKU' "$($h.Sid)\Software\Classes\CLSID\$clsid\InprocServer32" $m
      if (-not $k) { continue }
      Add-Finding -Module $m -Item $clsid -Scope "$($h.User) | $($ComWatch[$clsid])" -Location "HKU\$($h.Sid)\...\CLSID\$clsid" `
        -Target ([string]$k.Values['']) -Detail ([string]$k.Values['']) -Profile $h.Profile -LastWrite $k.LastWrite `
        -Absolute 'High' -Evidence @('PER-USER-OVERRIDE')
    }
  }
}

################################ MODULES -- Deep tier ###################################

function M-ComFull {
  # HKLM excluded by design -- COM hijacking is a per-user-override technique; sweeping HKLM's
  # thousands of legitimate registrations is volume without signal. Slowest module in the tool.
  # Rows collapse per (user, target DLL) -- see README Deep tier reference for why.
  $m = 'ComFull'
  foreach ($h in $script:Loaded) {
    $root = "$($h.Sid)\Software\Classes\CLSID"
    $rk = Read-Key 'HKU' $root $m
    if (-not $rk) { continue }
    $byTarget = [ordered]@{}
    foreach ($clsid in $rk.Subs) {
      $k = Read-Key 'HKU' "$root\$clsid\InprocServer32" $m
      if (-not $k) { continue }
      $dll = [string]$k.Values['']
      if ([string]::IsNullOrWhiteSpace($dll)) { continue }
      # The precedence-override signature: an HKCU registration for a CLSID HKLM also
      # defines did not need to exist for the class to work.
      $shadow = $false
      foreach ($s in @("SOFTWARE\Classes\CLSID\$clsid", "SOFTWARE\WOW6432Node\Classes\CLSID\$clsid")) {
        if (Read-Key 'HKLM' $s $m) { $shadow = $true; break }
      }
      $key = $dll.ToLowerInvariant()
      if (-not $byTarget.Contains($key)) {
        $byTarget[$key] = [pscustomobject]@{ Dll = $dll; Count = 0; Clsids = @(); Shadow = $false; LastWrite = $k.LastWrite }
      }
      $e = $byTarget[$key]
      $e.Count++
      if ($e.Clsids.Count -lt 4) { $e.Clsids += $clsid }
      if ($shadow) { $e.Shadow = $true }
      if ($k.LastWrite -is [datetime] -and ($e.LastWrite -isnot [datetime] -or $k.LastWrite -gt $e.LastWrite)) { $e.LastWrite = $k.LastWrite }
    }
    foreach ($e in $byTarget.Values) {
      $leaf = $e.Dll
      try { $leaf = [IO.Path]::GetFileName($e.Dll.Trim('"')) } catch { }
      $which = ($e.Clsids -join ', ')
      if ($e.Count -gt $e.Clsids.Count) { $which = "$which, +$($e.Count - $e.Clsids.Count) more" }
      Add-Finding -Module $m -Item $leaf -Scope $h.User -Location "HKU\$root" -Target $e.Dll `
        -Detail "$($e.Count) CLSID(s) -> $($e.Dll)$(if ($e.Shadow) { ' | SHADOWS an HKLM class' } else { ' | HKCU-only class' })" `
        -Extra "CLSIDs: $which" -Profile $h.Profile -LastWrite $e.LastWrite `
        -Evidence $(if ($e.Shadow) { @('PER-USER-OVERRIDE') } else { @() })
    }
  }
}

function M-FullSignaturePass {
  # Re-derives signatures across service/task targets, independent of those modules' tiering.
  # Uses the shared cache, so running after Services/ScheduledTasks costs nothing extra.
  $m = 'FullSignaturePass'
  $targets = New-Object System.Collections.Generic.List[object]
  $root = 'SYSTEM\CurrentControlSet\Services'
  $all = Read-Key 'HKLM' $root $m
  if ($all) {
    foreach ($n in $all.Subs) {
      $s = Read-Key 'HKLM' "$root\$n" $m
      if ($s -and [string]$s.Values['ImagePath']) {
        $e = Get-CmdTarget ([string]$s.Values['ImagePath'])
        if ($e) { $targets.Add([pscustomobject]@{ Src = 'Service'; Item = $n; Raw = $e; LW = $s.LastWrite }) }
      }
      $p = Read-Key 'HKLM' "$root\$n\Parameters" $m
      if ($p -and [string]$p.Values['ServiceDll']) {
        $targets.Add([pscustomobject]@{ Src = 'ServiceDll'; Item = $n; Raw = [string]$p.Values['ServiceDll']; LW = $p.LastWrite })
      }
    }
  }
  $tr = Join-Path $env:SystemRoot 'System32\Tasks'
  if (Test-Path -ErrorAction SilentlyContinue -LiteralPath $tr) {
    try {
      foreach ($f in (Get-ChildItem -LiteralPath $tr -File -Recurse -Force -ErrorAction Stop)) {
        $xml = $null
        try { $xml = [xml](Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop) } catch { Add-Gap $f.FullName "task XML unreadable: $($_.Exception.Message)" $m; continue }
        if (-not $xml.Task -or -not $xml.Task.Actions) { continue }
        foreach ($a in $xml.Task.Actions.ChildNodes) {
          if ($a.LocalName -ne 'Exec' -or -not [string]$a.Command) { continue }
          # The task XML's own timestamp is wired through so these rows participate in
          # time-narrowing like every other module's do.
          $targets.Add([pscustomobject]@{ Src = 'ScheduledTask'; Item = $f.Name; Raw = [string]$a.Command; LW = $f.LastWriteTimeUtc })
        }
      }
    } catch { Add-Gap $tr $_.Exception.Message $m }
  }
  $census = @{}
  foreach ($t in $targets) {
    $r = Resolve-Target $t.Raw
    if (-not $r) { continue }
    $sig = Get-Signature $r
    $trust = Get-Trust $r
    if ($census.ContainsKey($sig)) { $census[$sig]++ } else { $census[$sig] = 1 }
    $abs = ''; $ev = @()
    if ($sig -eq 'HashMismatch') { $abs = 'High'; $ev += 'SIGNATURE-INVALID' }
    # Unsigned inside a Windows directory is a different claim than unsigned in Program Files.
    elseif ($sig -eq 'NotSigned' -and $trust -eq 'System') { $abs = 'Notable'; $ev += 'UNSIGNED' }
    if (-not $abs) { continue }
    Add-Finding -Module $m -Item $t.Item -Scope $t.Src -Location $t.Src -Target $r -Detail "$sig / $trust" -LastWrite $t.LW -Absolute $abs -Evidence $ev
  }
  Add-Finding -Module $m -Item 'signature census' -Scope "$($targets.Count) targets" -NoVerify -VerboseOnly `
    -Detail (($census.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')
}

function M-OfficeAddins {
  # Office versions walked dynamically: a host upgraded across versions can carry a
  # stale-but-launchable registration under an older version subtree.
  $m = 'OfficeAddins'
  $scopes = @(@{ R = 'HKLM'; B = 'SOFTWARE\Microsoft\Office'; L = 'machine'; P = $null },
    @{ R = 'HKLM'; B = 'SOFTWARE\WOW6432Node\Microsoft\Office'; L = 'machine (32-bit)'; P = $null })
  foreach ($h in $script:Loaded) { $scopes += @{ R = 'HKU'; B = "$($h.Sid)\Software\Microsoft\Office"; L = $h.User; P = $h.Profile; Sid = $h.Sid } }
  foreach ($s in $scopes) {
    $ok = Read-Key $s.R $s.B $m
    if (-not $ok) { continue }
    foreach ($ver in $ok.Subs) {
      $vk = Read-Key $s.R "$($s.B)\$ver" $m
      if (-not $vk) { continue }
      foreach ($app in $vk.Subs) {
        $ak = Read-Key $s.R "$($s.B)\$ver\$app\Addins" $m
        if (-not $ak) { continue }
        foreach ($prog in $ak.Subs) {
          $k = Read-Key $s.R "$($s.B)\$ver\$app\Addins\$prog" $m
          if (-not $k) { continue }
          $lb = $k.Values['LoadBehavior']; $lbl = 'unset'
          if ($null -ne $lb) {
            $i = 0; try { $i = [int]$lb } catch { }
            $lbl = $(if ($LoadBehavior.ContainsKey($i)) { "$i ($($LoadBehavior[$i]))" } else { "$i" })
          }
          # Resolve ProgID -> CLSID -> the DLL that actually loads.
          $pk = $null
          if ($s.Sid) { $pk = Read-Key 'HKU' "$($s.Sid)\Software\Classes\$prog\CLSID" $m }
          if (-not $pk) { $pk = Read-Key 'HKLM' "SOFTWARE\Classes\$prog\CLSID" $m }
          $dll = $null
          if ($pk) { $dll = Resolve-Clsid ([string]$pk.Values['']) $m }
          if (-not $dll -and $k.Values.ContainsKey('Manifest')) { $dll = [string]$k.Values['Manifest'] }
          Add-Finding -Module $m -Item "$prog $([string]$k.Values['FriendlyName'])".Trim() -Scope "$app $ver / $($s.L)" `
            -Location "$($s.R)\$($s.B)\$ver\$app\Addins\$prog" -Target $dll -Detail "LoadBehavior $lbl | $dll" `
            -Profile $s.P -LastWrite $k.LastWrite
        }
      }
    }
  }
  # WLL/XLA add-ins load by file presence alone -- a registry-only sweep of this technique
  # is incomplete by construction.
  foreach ($p in $script:Profiles) {
    foreach ($d in @('AppData\Roaming\Microsoft\Word\STARTUP', 'AppData\Roaming\Microsoft\Excel\XLSTART')) {
      $dir = Join-Path $p.Profile $d
      if (-not (Test-Path -ErrorAction SilentlyContinue -LiteralPath $dir)) { continue }
      try {
        foreach ($f in (Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction Stop)) {
          Add-Finding -Module $m -Item $f.Name -Scope "$($p.User) / startup folder" -Location $dir -Target $f.FullName `
            -Detail 'loads on file presence, no registry entry' -LastWrite $f.LastWriteTimeUtc -Evidence @('NON-DEFAULT-VALUE')
        }
      } catch { Add-Gap $dir $_.Exception.Message $m }
    }
  }
}

function M-SysvolGpo {
  # Gated on an actual domain-joined check so this is a clean no-op on a workgroup host.
  # An unreachable DC degrades into the coverage report, not an error.
  $m = 'SysvolGpo'
  $domain = $null
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if (-not $cs.PartOfDomain) { return }
    $domain = $cs.Domain
  } catch { Add-Gap 'Win32_ComputerSystem' $_.Exception.Message $m; return }
  if (-not $domain) { return }
  $root = "\\$domain\SYSVOL\$domain\Policies"
  if (-not (Test-Path -ErrorAction SilentlyContinue -LiteralPath $root)) { Add-Gap $root 'SYSVOL unreachable (no DC contact or access denied)' $m; return }
  $pol = $null
  try { $pol = Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop } catch { Add-Gap $root $_.Exception.Message $m; return }
  foreach ($p in $pol) {
    foreach ($scope in @('Machine', 'User')) {
      $dir = Join-Path $p.FullName "$scope\Scripts"
      if (-not (Test-Path -ErrorAction SilentlyContinue -LiteralPath $dir)) { continue }
      try {
        foreach ($f in (Get-ChildItem -LiteralPath $dir -File -Recurse -Force -ErrorAction Stop)) {
          $ev = @()
          if ($f.Extension -imatch '^\.(ps1|bat|cmd|vbs|js|wsf)$' -and (Test-Content $f.FullName $m)) { $ev += 'SUSPICIOUS-CONTENT' }
          Add-Finding -Module $m -Item $f.Name -Scope "$($p.Name) / $scope" -Location $dir -Target $f.FullName `
            -Detail $f.FullName -LastWrite $f.LastWriteTimeUtc -Evidence $ev
        }
      } catch { Add-Gap $dir $_.Exception.Message $m }
    }
  }
}

function M-BitsJobs {
  # NotifyCmdLine is the execution primitive; Get-BitsTransfer doesn't expose it, so BITS COM
  # supplies that one property. A job without it is inventory; with it, a triggered execution.
  $m = 'BitsJobs'
  $jobs = @()
  try { Import-Module BitsTransfer -ErrorAction Stop; $jobs = @(Get-BitsTransfer -AllUsers -ErrorAction Stop) }
  catch { Add-Gap 'Get-BitsTransfer -AllUsers' $_.Exception.Message $m }
  $notify = @{}
  $mgr = $null
  try {
    $mgr = New-Object -ComObject 'Microsoft.BackgroundIntelligentTransferManagement.5.1' -ErrorAction Stop
    foreach ($j in $mgr.EnumJobs(0)) { try { $notify[[string]$j.JobId] = [string]$j.NotifyCmdLine } catch { Add-Gap "BITS job $($j.JobId)" "NotifyCmdLine unreadable: $($_.Exception.Message)" $m } }
  } catch { Add-Gap 'BITS COM (NotifyCmdLine)' $_.Exception.Message $m }
  finally { if ($mgr) { [Runtime.InteropServices.Marshal]::ReleaseComObject($mgr) | Out-Null } }
  foreach ($j in $jobs) {
    $id = [string]$j.JobId
    $cmd = $null
    if ($notify.ContainsKey($id)) { $cmd = $notify[$id] }
    $created = $null
    if ($j.CreationTime) { try { $created = ([datetime]$j.CreationTime).ToUniversalTime() } catch { } }
    $ev = @()
    if ($cmd) { $ev += 'NON-DEFAULT-VALUE' }
    if ([string]$j.TransferType -ieq 'Upload') { $ev += 'NON-DEFAULT-VALUE' }
    Add-Finding -Module $m -Item ([string]$j.DisplayName) -Scope "$([string]$j.OwnerAccount) / $([string]$j.JobState) / $([string]$j.TransferType)" `
      -Location "JobId $id" -Command $cmd -Detail $(if ($cmd) { "NotifyCmdLine: $cmd" } else { 'no NotifyCmdLine' }) `
      -LastWrite $created -Evidence $ev -VerboseOnly:(-not $cmd)
  }
}

function M-CredentialProviders {
  # A malicious provider captures the plaintext credential at the UI layer, before anything
  # reaches the LSA. Every provider is resolved and verified; no assumed-safe list.
  $m = 'CredentialProviders'
  foreach ($root in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers',
      'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters')) {
    $rk = Read-Key 'HKLM' $root $m
    if (-not $rk) { continue }
    foreach ($clsid in $rk.Subs) {
      $k = Read-Key 'HKLM' "$root\$clsid" $m
      $name = ''
      if ($k) { $name = [string]$k.Values[''] }
      $dll = Resolve-Clsid $clsid $m
      $ev = @()
      if (Test-ClsidOverride $clsid $m) { $ev += 'PER-USER-OVERRIDE' }
      Add-Finding -Module $m -Item $(if ($name) { $name } else { '(unnamed)' }) -Scope $clsid -Location "HKLM\$root\$clsid" `
        -Target $dll -Detail $dll -LastWrite $(if ($k) { $k.LastWrite } else { $null }) -Evidence $ev
    }
  }
}

function M-ShellExt {
  # Limited to well-known handler roots -- ComFull covers the broad case. Approved is context
  # only, not an enforcement boundary on modern builds.
  $m = 'ShellExt'
  $approved = @{}
  $ak = Read-Key 'HKLM' 'SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved' $m
  if ($ak) { foreach ($n in $ak.Names) { $approved[$n.ToUpperInvariant()] = $true } }
  $roots = @(
    @{ R = 'HKLM'; S = 'SOFTWARE\Classes\*\shellex\ContextMenuHandlers'; T = 'ContextMenu (all files)'; L = 'machine'; P = $null }
    @{ R = 'HKLM'; S = 'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers'; T = 'ContextMenu (directory)'; L = 'machine'; P = $null }
    @{ R = 'HKLM'; S = 'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers'; T = 'ContextMenu (desktop)'; L = 'machine'; P = $null }
    @{ R = 'HKLM'; S = 'SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers'; T = 'ContextMenu (folder)'; L = 'machine'; P = $null }
    @{ R = 'HKLM'; S = 'SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers'; T = 'ContextMenu (fs objects)'; L = 'machine'; P = $null }
    @{ R = 'HKLM'; S = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'; T = 'IconOverlay'; L = 'machine'; P = $null }
  )
  foreach ($h in $script:Loaded) {
    $roots += @{ R = 'HKU'; S = "$($h.Sid)\Software\Classes\*\shellex\ContextMenuHandlers"; T = 'ContextMenu (all files)'; L = $h.User; P = $h.Profile }
    $roots += @{ R = 'HKU'; S = "$($h.Sid)\Software\Classes\Directory\shellex\ContextMenuHandlers"; T = 'ContextMenu (directory)'; L = $h.User; P = $h.Profile }
  }
  foreach ($r in $roots) {
    $rk = Read-Key $r.R $r.S $m
    if (-not $rk) { continue }
    foreach ($hnd in $rk.Subs) {
      $k = Read-Key $r.R "$($r.S)\$hnd" $m
      if (-not $k) { continue }
      $clsid = [string]$k.Values['']
      if ([string]::IsNullOrWhiteSpace($clsid)) { $clsid = $hnd }
      $dll = Resolve-Clsid $clsid $m
      Add-Finding -Module $m -Item $hnd -Scope "$($r.T) / $($r.L)" -Location "$($r.R)\$($r.S)\$hnd" -Target $dll `
        -Detail "$dll | approved: $(if ($approved.ContainsKey($clsid.ToUpperInvariant())) { 'listed' } else { 'not listed' })" `
        -Profile $r.P -LastWrite $k.LastWrite -Evidence $(if ($r.R -eq 'HKU') { @('PER-USER-OVERRIDE') } else { @() })
    }
  }
}

##################################### Catalog ###########################################
# Pipe-delimited, not nested arrays -- newline-separated array literals inside @() flatten and
# silently destroy the per-row grouping.
$Catalog = @(
  'RunKeys|Quick|T1547.001|Run/RunOnce keys, GPO Explorer\Run, WOW6432Node mirror, legacy load/run'
  'StartupFolders|Quick|T1547.001|Per-profile and all-users Startup folders, .lnk targets resolved'
  'ShellFolderRedir|Quick|T1547.001|Startup folder redirected away from the stock path'
  'Services|Quick|T1543.003|Service ImagePath, start type, run-as account'
  'ServiceDll|Quick|T1543.003|svchost-hosted services: Parameters\ServiceDll'
  'ScheduledTasks|Quick|T1053.005|Task XML actions/triggers/principal + TaskCache/live orphan check'
  'WMI|Quick|T1546.003|Permanent event subscriptions; bound filter+consumer+binding triads'
  'Winlogon|Quick|T1547.004|Shell, Userinit, Notify packages, per-user Shell override'
  'LSAPackages|Quick|T1547.005|Authentication/Notification/Security Packages + OSConfig mirror'
  'IFEO|Quick|T1546.012/.008|IFEO Debugger and SilentProcessExit monitors'
  'AppInitCerts|Quick|T1546.010/.009|AppInit_DLLs (populated vs active) and AppCertDLLs'
  'ActiveSetup|Quick|T1547.014|Installed Components StubPath and HKLM/HKCU version delta'
  'BootLogonScripts|Quick|T1037.001/.003|UserInitMprLogonScript and the local GPO script cache'
  'NetshHelpers|Quick|T1546.007|Registered netsh helper DLLs'
  'PSProfiles|Quick|T1546.013|Every PowerShell profile path per engine/profile, with content scan'
  'CommandProcessorAutoRun|Quick|Unmapped|cmd.exe AutoRun, machine and per-user'
  'EnvHijack|Quick|T1574.012/.007|COR_PROFILER family, windir tampering, PATH ahead of System32'
  'SafeBoot|Quick|Unmapped|SafeBoot Minimal/Network roster and AlternateShell'
  'NetworkProviderOrder|Quick|T1556.008|ProviderOrder cross-referenced against each ProviderPath'
  'BootExecute|Quick|Unmapped|Session Manager BootExecute vs the documented stock value'
  'FileAssoc|Quick|T1546.001|Script/executable handlers, per-user override precedence'
  'Screensaver|Quick|T1546.002|SCRNSAVE.EXE with the ScreenSaveActive live/dormant distinction'
  'OfficeTest|Quick|T1137.002|Office test\Special\Perf debugging hook'
  'DllSearchOrder|Quick|T1574.001|SafeDllSearchMode, DllDirectory and the KnownDLLs roster'
  'ComWatchlist|Quick|T1546.015|Per-user overrides of documented-abused shell CLSIDs'
  'ComFull|Deep|T1546.015|Full per-user CLSID InprocServer32 sweep (slowest module)'
  'FullSignaturePass|Deep|Unmapped|Signature census across services and scheduled tasks'
  'OfficeAddins|Deep|T1137.006|COM/VSTO add-ins across every Office version + WLL/XLA startup files'
  'SysvolGpo|Deep|T1037.003|SYSVOL GPO logon/startup scripts (domain-joined only)'
  'BitsJobs|Deep|T1197|BITS job queue and the NotifyCmdLine execution primitive'
  'CredentialProviders|Deep|Unmapped|Registered credential providers and provider filters'
  'ShellExt|Deep|Unmapped|Context-menu and icon-overlay shell extension handlers'
) | ForEach-Object {
  $f = $_ -split '\|', 4
  [pscustomobject]@{ Token = $f[0]; Tier = $f[1]; Mitre = $f[2]; Fn = "M-$($f[0])"; Desc = $f[3] }
}

function Get-CmdLine {
  if ($script:BoundParams.Count -eq 0) { return '(no options -- default Quick sweep)' }
  (($script:BoundParams.GetEnumerator() | ForEach-Object {
      $v = $_.Value
      if ($v -is [switch]) { if ($v.IsPresent) { "-$($_.Key)" } }
      elseif ($v -is [array]) { "-$($_.Key) " + ($v -join ',') }
      else { "-$($_.Key) $v" }
    }) -join ' ')
}

function Test-InWindow {
  # No timestamp = filter-exempt: "unknown" cannot be shown to fall outside the window.
  param($F)
  if (-not $script:WinStart -and -not $script:WinEnd) { return $true }
  if ($F.LastWrite -isnot [datetime]) { return $true }
  if ($script:WinStart -and $F.LastWrite -lt $script:WinStart) { return $false }
  if ($script:WinEnd -and $F.LastWrite -gt $script:WinEnd) { return $false }
  return $true
}

####################################### Main ############################################
if ($Help) {
  try { Get-Help -Name $PSCommandPath -Full } catch { Write-Host "hunt_persistence.ps1 v$Version -- see README.md." }
  return
}
if ($ListModules) {
  Write-Host "`nhunt_persistence.ps1 v$Version -- module catalog ($($Catalog.Count) modules)"
  Write-Table @($Catalog | ForEach-Object { , @($_.Token, $_.Tier, $_.Mitre, $_.Desc) }) @('Token', 'Tier', 'ATT&CK', 'Checks')
  Write-Host ''
  return
}
$modes = @($Quick, $Deep, [bool]$Modules) | Where-Object { $_ }
if ($modes.Count -gt 1) { Write-Host 'ERROR: -Quick, -Deep and -Modules are mutually exclusive. Pick one.' -ForegroundColor Red; return }
if ($InventoryOnly -and ($AnomaliesOnly -or $script:BoundParams.ContainsKey('MinSeverity'))) {
  Write-Host 'ERROR: -InventoryOnly cannot combine with -AnomaliesOnly or -MinSeverity.' -ForegroundColor Red
  Write-Host '       It disables scoring entirely, so there is no tier to filter on.' -ForegroundColor Red
  return
}
$selected = @(); $modeLabel = 'Quick'
if ($Modules) {
  $unknown = @(); $seen = @{}
  # Split on commas too: RTR's "powershell -File script.ps1 -Modules a,b" binds "a,b" as ONE
  # string, not an array.
  foreach ($t in ($Modules -split ',' | Where-Object { $_.Trim() })) {
    $hit = $Catalog | Where-Object { $_.Token -ieq $t.Trim() } | Select-Object -First 1
    if (-not $hit) { $unknown += $t; continue }
    # De-dupe by Token, not Select-Object -Unique -- it compares PSCustomObjects by ToString(),
    # identical for all of them, and silently collapses the selection to one.
    if ($seen.ContainsKey($hit.Token)) { continue }
    $seen[$hit.Token] = $true; $selected += $hit
  }
  if ($unknown.Count -gt 0) {
    Write-Host "ERROR: unknown module token(s): $($unknown -join ', '). Use -ListModules." -ForegroundColor Red
    return
  }
  if ($selected.Count -eq 0) {
    Write-Host 'ERROR: -Modules supplied no valid module token(s). Use -ListModules.' -ForegroundColor Red
    return
  }
  $modeLabel = 'Modules (explicit selection)'
} elseif ($Deep) {
  $selected = @($Catalog); $modeLabel = 'Deep (Quick + Deep tier)'
} else {
  $selected = @($Catalog | Where-Object { $_.Tier -eq 'Quick' })
}
$script:WinStart = $null; $script:WinEnd = $null
if ($Since) {
  try { $script:WinStart = ([datetime]::ParseExact($Since, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)).ToUniversalTime() }
  catch { Write-Host "ERROR: could not parse -Since '$Since' (expected YYYY-MM-DD)." -ForegroundColor Red; return }
} elseif ($Days -gt 0) { $script:WinStart = $script:NowUtc.AddDays(-$Days) }
elseif ($Days -lt 0) { Write-Host "ERROR: -Days must be positive (got $Days)." -ForegroundColor Red; return }
if ($Until) {
  try { $script:WinEnd = ([datetime]::ParseExact($Until, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)).ToUniversalTime() }
  catch { Write-Host "ERROR: could not parse -Until '$Until' (expected YYYY-MM-DD)." -ForegroundColor Red; return }
}
if ($script:WinStart -and $script:WinEnd -and $script:WinStart -gt $script:WinEnd) {
  Write-Host 'ERROR: the -Since/-Days window starts after -Until ends -- the window is empty.' -ForegroundColor Red
  return
}
$winLabel = 'all time (no display filter); RECENCY tagging fixed at 14 days'
if ($script:WinStart -or $script:WinEnd) {
  $a = $(if ($script:WinStart) { $script:WinStart.ToString('yyyy-MM-dd HH:mm') } else { 'earliest' })
  $b = $(if ($script:WinEnd) { $script:WinEnd.ToString('yyyy-MM-dd HH:mm') } else { 'now' })
  $winLabel = "$a -> $b UTC (display filter; hides items outside it, scored or not)"
}

$os = 'unknown'
try { $os = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption } catch { }
$elev = Test-Elevated
# WOW64 silently rewrites System32 and non-WOW6432Node registry access to the 32-bit view
# with no error -- the whole native-vs-32-bit model this script relies on would be wrong.
$wow64Mismatch = (-not [Environment]::Is64BitProcess) -and [Environment]::Is64BitOperatingSystem
Write-Host ''
Write-Host "hunt_persistence.ps1  v$Version    author: $Author"
Write-Host "Ran at    : $($script:NowUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Write-Host "Hostname  : $env:COMPUTERNAME"
Write-Host "User      : $env:USERDOMAIN\$env:USERNAME  (elevated: $(if ($elev) { 'yes' } else { 'NO' }))"
Write-Host "OS        : $os"
Write-Host "Mode      : $modeLabel  ($($selected.Count) modules)"
Write-Host "Window    : $winLabel"
Write-Host "Command   : hunt_persistence.ps1 $(Get-CmdLine)"
if (-not $elev) {
  Write-Host ''
  Write-Host '!! WARNING: not running as Administrator. Machine-wide keys, other users'' hives' -ForegroundColor Yellow
  Write-Host '!! and other profiles'' files may be unreadable. Every target that could not be' -ForegroundColor Yellow
  Write-Host '!! read is listed in the coverage report -- it is never reported clean. Re-run' -ForegroundColor Yellow
  Write-Host '!! from an elevated session for full coverage.' -ForegroundColor Yellow
}
if ($wow64Mismatch) {
  Write-Host ''
  Write-Host '!! WARNING: running as a 32-bit process on a 64-bit OS -- WOW64 redirects' -ForegroundColor Yellow
  Write-Host '!! System32 and non-WOW6432Node registry access to the 32-bit view without this' -ForegroundColor Yellow
  Write-Host '!! script''s knowledge, so native-view coverage cannot be guaranteed. Re-run' -ForegroundColor Yellow
  Write-Host '!! with 64-bit powershell.exe/pwsh.exe.' -ForegroundColor Yellow
}

try { Initialize-Hives } catch {
  Add-Gap 'Initialize-Hives' "hive enumeration failed: $($_.Exception.Message)" 'startup'
  $script:Hives = @(); $script:Loaded = @(); $script:Profiles = @()
}
foreach ($mod in $selected) {
  Write-Verbose "Running $($mod.Token)"
  try {
    # Out-Null at the dispatch site: a module that accidentally emits an object must never
    # leak it into the console between report sections.
    & $mod.Fn | Out-Null
  } catch {
    $script:Errors.Add([pscustomobject]@{ Module = $mod.Token; Reason = (Limit-Reason $_.Exception.Message) })
    Add-Gap "module $($mod.Token)" "module failed: $($_.Exception.Message)" $mod.Token
  }
}

# Wrapped so a rendering bug (or the hive-enumeration failure above) never loses findings
# already gathered -- the catch below dumps them flat instead of crashing with nothing shown.
try {
# --- Report ---
$rank = @{ 'LOW' = 0; 'NOTABLE' = 1; 'HIGH' = 2 }
$minRank = $(if ($MinSeverity -eq 'High') { 2 } else { 1 })
$verbose = ($VerbosePreference -ne 'SilentlyContinue')
# Tier is its own trailing column rather than an inline prefix, so it never eats into the
# item name and every row lines up under one place to scan.
$cols = @('Item', 'Scope', 'Modified', 'Detail')
if ($verbose) { $cols += @('More', 'Target', 'Trust', 'Signature', 'Score') }
$cols += 'Tag'
# Every tag rendered in the Tag column, counted, so the legend at the end describes exactly
# what fired in this run and nothing else.
$tagCounts = [ordered]@{}
# Modules whose rows share a registry key are printed grouped under that key's full path, so
# an analyst can review and remediate one key at a time.
$grouped = @('RunKeys')
$hiddenByTime = 0
Write-Host ''
Write-Host '================================ FINDINGS ================================'
foreach ($mod in $selected) {
  $rows = @($script:Findings | Where-Object { $_.Module -eq $mod.Token })
  $n = $rows.Count
  $rows = @($rows | Where-Object { Test-InWindow $_ })
  $hiddenByTime += ($n - $rows.Count)
  if (-not $InventoryOnly -and $AnomaliesOnly) { $rows = @($rows | Where-Object { $rank[$_.Tier] -ge $minRank }) }
  # Suppression never hides a row that scored -- only confirmed-clean, zero-evidence rows.
  # Quiet rows return under -Verbose or -InventoryOnly; Routine rows only under -InventoryOnly.
  $suppressed = @{}
  if (-not $verbose -and -not $InventoryOnly) {
    $before = $rows.Count
    $rows = @($rows | Where-Object { -not $_.Quiet -or $rank[$_.Tier] -ge 1 })
    if ($before - $rows.Count -gt 0) { $suppressed['confirmed-stock values and static rosters; re-run with -Verbose to include'] = $before - $rows.Count }
  }
  if (-not $InventoryOnly) {
    $before = $rows.Count
    # Zero evidence is the bar, not "below NOTABLE" -- any tag at all keeps a row visible even
    # at LOW, so trimming the Windows baseline can never become a false negative.
    $rows = @($rows | Where-Object { -not $_.Routine -or $_.Evidence.Count -gt 0 })
    if ($before - $rows.Count -gt 0) { $suppressed['Windows baseline: OS-vendor-signed binaries on expected paths; re-run with -InventoryOnly to include'] = $before - $rows.Count }
  }
  if ($rows.Count -eq 0) {
    if (-not $AnomaliesOnly) {
      Write-Host "`n-- $($mod.Token) [$($mod.Mitre)] -- nothing found"
      foreach ($k in $suppressed.Keys) { Write-Host "   [$($suppressed[$k]) row(s) suppressed -- $k]" }
    }
    continue
  }
  Write-Host "`n-- $($mod.Token) [$($mod.Mitre)] -- $($rows.Count) item(s)"
  $isGrouped = ($grouped -contains $mod.Token)
  foreach ($grp in @($rows | Group-Object { if ($isGrouped) { $_.Location } else { '' } })) {
    if ($isGrouped) {
      # Full registry path plus the account it belongs to, so the row below is actionable.
      $owner = @($grp.Group | ForEach-Object { $_.Scope } | Select-Object -Unique) -join ', '
      Write-Host ''
      Write-Indented '   ' $grp.Name
      if ($owner) { Write-Indented '   ' "user: $owner   ($($grp.Count) value(s))" }
    }
    # Inside a group the owning account is already in the header, so Scope would just repeat
    # it and cost width that the command line needs.
    $useCols = @($cols | Where-Object { -not ($isGrouped -and $_ -eq 'Scope') })
    $table = @()
    foreach ($r in $grp.Group) {
      $modified = $(if ($r.LastWrite -is [datetime]) { $r.LastWrite.ToString('yyyy-MM-dd HH:mm') } else { 'unknown' })
      $cells = @($r.Item)
      if (-not $isGrouped) { $cells += $r.Scope }
      $cells += @($modified, $r.Detail)
      if ($verbose) {
        $cells += @($r.Extra, $r.Target, $r.Trust, $r.Sig, $(if ($InventoryOnly) { '-' } else { [string]$r.Score }))
      }
      # Tier plus the evidence codes, in one column. This carries everything the separate
      # anomaly queue used to restate, which is why that section no longer exists.
      $tags = @()
      if (-not $InventoryOnly) {
        # A trailing * marks an Absolute-rule tier: presence/deviation alone was conclusive,
        # not evidence accumulation -- see the legend below.
        if ($rank[$r.Tier] -ge $minRank) { $tags += $(if ($r.Absolute) { "$($r.Tier)*" } else { $r.Tier }) }
        $tags += $r.Evidence
      }
      foreach ($t in $tags) { if ($tagCounts.Contains($t)) { $tagCounts[$t]++ } else { $tagCounts[$t] = 1 } }
      $cells += ($tags -join ',')
      $table += , $cells
    }
    Write-Table $table $useCols
  }
  foreach ($k in $suppressed.Keys) { Write-Host "   [$($suppressed[$k]) row(s) suppressed -- $k]" }
}
# Legend for the Tag column: every tag that actually appeared in this run, nothing else.
if ($tagCounts.Count -gt 0) {
  $tierMeaning = @{
    'HIGH'    = 'Score >=5 or an Absolute rule matched -- conclusive on its own. Work these first.'
    'NOTABLE' = 'Score 3-4 -- weak signals stacked, or a mechanism with documented legitimate uses.'
  }
  # Tiers first (plain, then the Absolute-marked variant), then evidence codes by frequency.
  $tierNames = @('HIGH', 'HIGH*', 'NOTABLE', 'NOTABLE*')
  $order = @($tierNames | Where-Object { $tagCounts.Contains($_) })
  $order += @($tagCounts.Keys | Where-Object { $tierNames -notcontains $_ } |
    Sort-Object { -$tagCounts[$_] })
  $tw = 0
  foreach ($t in $order) { if ($t.Length -gt $tw) { $tw = $t.Length } }
  Write-Host ''
  Write-Host '=============================== TAG LEGEND ==============================='
  foreach ($t in $order) {
    $base = $t.TrimEnd('*')
    $meaning = $tierMeaning[$base]
    if ($meaning -and $t.EndsWith('*')) { $meaning = "$meaning * = an Absolute rule fired (presence/deviation alone, not evidence accumulation)." }
    if (-not $meaning) { $meaning = $Reasons[$t] }
    if (-not $meaning) { $meaning = '(no description)' }
    if ($meaning.Length -gt 1) { $meaning = $meaning.Substring(0, 1).ToUpper() + $meaning.Substring(1) }
    Write-Indented ('   {0}  ' -f $t.PadRight($tw)) $meaning
  }
}

# One labelled block: everything an operator needs to judge coverage, as few lines as honest.
$unloaded = @($script:Hives | Where-Object { -not $_.Loaded })
$shown = @($script:Findings | Where-Object { Test-InWindow $_ })
Write-Host ''
Write-Host '================================ SUMMARY ================================='
if ($InventoryOnly) {
  Write-Indented '   Findings : ' "inventory only, no scoring -- $($script:Findings.Count) items, $($selected.Count) modules"
} else {
  $h = @($shown | Where-Object { $_.Tier -eq 'HIGH' }).Count
  $n = @($shown | Where-Object { $_.Tier -eq 'NOTABLE' }).Count
  Write-Indented '   Findings : ' "$h HIGH, $n NOTABLE of $($script:Findings.Count) items across $($selected.Count) modules"
}
if ($hiddenByTime -gt 0) {
  Write-Indented '   Window   : ' "$hiddenByTime item(s) hidden by the active time filter, scored ones included"
}
# Unreadable targets are never folded into a clean result -- they are the places this run
# could not speak for.
if ($script:Unreadable.Count -eq 0) {
  Write-Host '   Coverage : complete -- every target in scope was read'
} else {
  Write-Indented '   Coverage : ' "$($script:Unreadable.Count) target(s) unreadable, NOT reported clean$(if (-not $elev) { ' -- re-run elevated' })"
  foreach ($u in ($script:Unreadable | Sort-Object Module, Target)) {
    Write-Indented '              ' "$($u.Module): $($u.Target) -- $($u.Reason)"
  }
}
if ($script:Errors.Count -gt 0) {
  Write-Indented '   Failed   : ' "$($script:Errors.Count) module(s) skipped"
  foreach ($e in $script:Errors) { Write-Indented '              ' "$($e.Module): $($e.Reason)" }
}
# Loading a hive is a write, so this tool never does it -- an unloaded profile's registry
# surface is out of reach by design.
if ($unloaded.Count -gt 0) {
  Write-Indented '   Hives    : ' "$($unloaded.Count) profile(s) not loaded -- per-user registry skipped, on-disk artifacts swept"
  foreach ($u in $unloaded) {
    $f = 'NTUSER.DAT not found'
    if ($u.Profile) { $c = Join-Path $u.Profile 'NTUSER.DAT'; if (Test-Path -ErrorAction SilentlyContinue -LiteralPath $c) { $f = $c } }
    Write-Indented '              ' "$($u.User) -- $f"
  }
}
Write-Host ''
} catch {
  Write-Host ''
  Write-Host "!! WARNING: report rendering failed ($($_.Exception.Message))." -ForegroundColor Yellow
  Write-Host '!! Findings gathered before the failure are listed below, unformatted, rather than lost.' -ForegroundColor Yellow
  foreach ($f in $script:Findings) {
    Write-Host "$($f.Module) | $($f.Item) | $($f.Detail) | $($f.Tier) | $($f.Evidence -join ',')"
  }
}
