# WSL Registry & Configuration Deep-Dive

The **HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER registry hives** hold the master registry of installed WSL distros, their configuration, and interop settings — this note is a byte-level reference for reading those keys offline and detecting unauthorized distro installation or configuration tampering.

> 🔴 The Lxss registry keys are the **source of truth** for which distros exist, where they're stored, and how they're configured. An attacker using `wsl --import` to install a side-loaded rootfs into a hidden location, changing `DefaultUid` to 0 to run all commands as root, or disabling logging via `Flags` bits are all changes that leave registry artifacts — this note maps every bit and key.

## Contents

- [LXSS Registry Hierarchy](#lxss-registry-hierarchy)
- [HKCU Lxss Root Keys](#hkcu-lxss-root-keys)
- [Distro GUID Subkeys](#distro-guid-subkeys)
- [Flags Bit Interpretation](#flags-bit-interpretation)
- [State Values and Install Status](#state-values-and-install-status)
- [Global WSL Configuration](#global-wsl-configuration)
- [Detecting Unauthorized Distro Installation](#detecting-unauthorized-distro-installation)
- [Detecting Configuration Tampering](#detecting-configuration-tampering)
- [Registry Acquisition and Analysis](#registry-acquisition-and-analysis)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## LXSS Registry Hierarchy

```
HKEY_CURRENT_USER
  Software
    Microsoft
      Windows
        CurrentVersion
          Lxss                                 # 🔴 The WSL root hive for the current user
            DefaultDistribution   = REG_SZ     # GUID of the default distro (or empty if none)
            DefaultUID            = REG_DWORD  # (legacy; prefer per-distro DefaultUid)
            LxssUserPreferences   = REG_BINARY # User preference blob (rarely set)
            {DISTRO-GUID-1}       = (KEY)      # Subkey per installed distro
            {DISTRO-GUID-2}       = (KEY)      # ...

HKEY_LOCAL_MACHINE
  Software
    Microsoft
      Windows
        CurrentVersion
          Lxss                                 # 🔴 System-level WSL config (rarely used)
```

---

## HKCU Lxss Root Keys

| Key / Value | Type | Purpose | Forensic Significance |
|------------|------|---------|----------------------|
| `DefaultDistribution` | REG_SZ | GUID of the default distro; empty if no default set | Indicates which distro the user prefers (lightweight indicator of usage) |
| `DefaultUID` | REG_DWORD | (Legacy) default UID for all distros if not overridden per-distro | Only applies if per-distro `DefaultUid` is not set |
| `LxssUserPreferences` | REG_BINARY | Blob of user settings (encoding undocumented) | Rarely exploited; low forensic value |

---

## Distro GUID Subkeys

Each installed distro (via Microsoft Store or `wsl --import`) gets a subkey under `HKCU\...\Lxss\{GUID}`:

### Required/Common Keys

| Value | Type | Purpose | Red Flag If… |
|-------|------|---------|-------------|
| **DistributionName** | REG_SZ | Human-readable distro name (e.g., "Ubuntu-22.04") | Name doesn't match Windows Store naming convention (likely imported) |
| **Version** | REG_DWORD | WSL version: **1** (WSL1) or **2** (WSL2) | WSL1 is legacy; check for outdated/unsupported distro |
| **BasePath** | REG_SZ | **🔴 Filesystem path** to the distro's files or vhdx | In unusual location (temp, Downloads, C:\Users\...\AppData\Roaming\), suggests manual import or sideload |
| **PackageFamilyName** | REG_SZ | Windows Store package (e.g., `CanonicalGroupLimited.Ubuntu22.04LTS_<hash>`) | Missing or non-standard = manually imported (not from Store) |
| **DefaultUid** | REG_DWORD | Default Linux UID for this distro (0 = root, suspicious) | **🔴 DefaultUid=0**: everything runs as root by default |
| **DefaultGid** | REG_DWORD | Default Linux GID (usually 0 for root, expected) | Rarely tampered with |
| **State** | REG_DWORD | Install state (see **State Values**, below) | **1** = installed; **3** = registered but not installed = incomplete setup |
| **Flags** | REG_DWORD | Bitfield: interop, mount options, environment bits (see **Flags Bit Interpretation**) | 🔴 Check bits 0–3 for disabled interop or environment masking |
| **DistroId** | REG_SZ | Internal distro identifier (may differ from DistributionName) | Rarely set; usually matches DistributionName |
| **DistributionVersion** | REG_SZ | Distro version string (e.g., "22.04") | Unusually high or low version = outdated or pre-release |
| **KernelCommandLine** | REG_SZ | **🔴 Custom kernel boot args** (WSL2) | Present = custom kernel passed to Hyper-V; likely attacker-controlled |

### Optional/Advanced Keys

| Value | Type | Purpose |
|-------|------|---------|
| `Environment` | REG_SZ | Pre-set environment variables (rare) |
| `LxRunOffline*` | REG_SZ | LxRunOffline tool metadata (if distro was imported via LxRunOffline instead of native `wsl --import`) |

---

## Flags Bit Interpretation

The `Flags` REG_DWORD is a bitfield controlling WSL behavior. Each bit has a meaning:

```
Flags = (bit 0) | (bit 1) | (bit 2) | (bit 3) | ... (other bits typically 0)
```

| Bit | Value | Name / Meaning | Impact | Red Flag If Set = 0 |
|-----|-------|----------------|--------|-------------------|
| 0 | 0x0001 | **ENABLE_INTEROP** | Allow WSL to launch Windows .exe from inside Linux | 🔴 **Disabled (0)** = no interop; a policy to restrict cross-OS execution |
| 1 | 0x0002 | **APPEND_NT_PATH** | Add Windows `PATH` to WSL `$PATH` | Disabled = WSL doesn't see Windows commands; unusual but not necessarily malicious |
| 2 | 0x0004 | **ENABLE_DRIVE_MOUNTING** | Allow Windows drives to mount at `/mnt/c`, `/mnt/d` | 🔴 **Disabled (0)** = Linux can't access Windows filesystem; restricts lateral movement but also usability |
| 3 | 0x0008 | **ENABLE_METADATA_COMMANDS** | Use Windows-side utilities for extended attributes (e.g., chown) | Rarely set; low forensic value |

**Example:**
- `Flags = 0x0007` → bits 0, 1, 2 set → interop, append NT path, and drive mounting all enabled (standard)
- `Flags = 0x0001` → only interop enabled; drive mounting disabled → Windows filesystem not accessible from Linux (restrictive policy)
- `Flags = 0x0000` → **🔴 nothing enabled** → highly restrictive distro, used only in isolation

---

## State Values and Install Status

The `State` REG_DWORD indicates distro installation status:

| Value | Meaning | Forensic Interpretation |
|-------|---------|------------------------|
| **1** | Installed and ready | Distro is fully set up and operational |
| **2** | Installing | Distro is mid-installation (rare to see on a static image) |
| **3** | Registered but **not installed** | 🔴 Distro entry exists but vhdx/rootfs is missing; incomplete setup or attacker left a stub |

---

## Global WSL Configuration

Beyond the per-distro Lxss keys, two global config files control WSL2 settings:

### `.wslconfig` (Windows Side)

```
%USERPROFILE%\.wslconfig
```

**Not a registry file** — it's a plain-text config file in the user's home directory. Covers WSL2 memory, networking, swap:

```ini
[wsl2]
kernel=C:\Path\To\Custom\Kernel.img          # 🔴 Custom kernel = attacker-supplied
memory=4GB                                    # WSL2 VM memory limit
swap=2GB                                      # Disk swap for the VM
networkingMode=mirrored                       # Network mode (WSL2)
```

**Forensic Significance:** A custom `kernel=` path indicates an attacker-supplied WSL2 kernel, likely modified for persistence or evasion.

### `wsl.conf` (Linux Side, Inside Distro)

```
/etc/wsl.conf   (INSIDE the distro's ext4.vhdx)
```

**Not on the Windows registry** — it's a Linux config file at the root of the distro. Covers init, interop, mounts:

```ini
[boot]
command=/usr/bin/my_payload                  # 🔴 Runs as ROOT on every distro start
systemd=true                                  # Enable systemd (if false, minimal init)

[interop]
enabled=true                                  # Allow WSL to launch Windows .exe
appendWindowsPath=true                        # Prepend Windows PATH

[automount]
enabled=true                                  # Auto-mount Windows drives
```

**Forensic Significance:** `[boot] command=` is WSL-native persistence — executed as root every time the distro starts. A shell script or binary at that path is likely malicious. See [**WSL → 02 - Investigating Linux Inside WSL**](<02 - Investigating Linux Inside WSL.md>) for hunting `[boot] command=` inside the distro.

---

## Detecting Unauthorized Distro Installation

Attackers often use `wsl --import` or LxRunOffline to install a custom rootfs into an unexpected location:

### Telltale Signs in the Registry

1. **Non-Standard BasePath**
   - Store-installed distros: `%LOCALAPPDATA%\Packages\CanonicalGroupLimited.*` or `Microsoft.VirtualDesktopAdmin*`
   - **🔴 Suspicious paths:**
     - Temp folders: `C:\Users\<user>\AppData\Local\Temp\...`
     - Downloads: `C:\Users\<user>\Downloads\...`
     - Hidden folders: `C:\Users\<user>\AppData\Roaming\...`
     - User-writable paths outside standard locations

2. **Missing PackageFamilyName**
   - Store distros: always have a `PackageFamilyName`
   - **🔴 Missing PackageFamilyName** = manually imported via `wsl --import` or LxRunOffline

3. **Unusual DistributionName**
   - Standard names: `Ubuntu-22.04`, `Debian`, `openSUSE-Leap-15`, `Kali-Linux`
   - **🔴 Custom names:** `MyDistro`, `Payload`, `Extracted`

4. **DefaultUid = 0**
   - Normal: 1000 or higher (regular user)
   - **🔴 DefaultUid = 0**: everything runs as root by default (unusual, suspicious)

### Hunting Query (PowerShell)

```powershell
# List all WSL distros from the registry
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*' |
  Select-Object @{N='GUID';E={$_.PSChildName}}, DistributionName, Version, BasePath, DefaultUid, State |
  Where-Object {$_.GUID -ne '(Default)'}

# Red flags: print suspicious ones
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*' |
  Where-Object {
    $_.BasePath -match 'Temp|Downloads|Roaming' -or
    $_.DefaultUid -eq 0 -or
    $null -eq $_.PackageFamilyName
  } |
  Select-Object PSChildName, DistributionName, BasePath, DefaultUid
```

---

## Detecting Configuration Tampering

### Registry-Level Changes

Check for LastWrite times on Lxss keys to detect when distros were modified:

```powershell
# Get the LastWrite timestamp of the Lxss registry key
$key = Get-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
$key.GetValue('') # Returns LastWrite time
```

**Interpretation:**
- If `LastWrite` is older than the distro's creation (PackageFamilyName install date), distro config was unchanged.
- If `LastWrite` is recent and unexpected, distro config was tampered with (Flags, DefaultUid, or other values changed).

### Check Flags Bits

```powershell
# Get Flags for each distro
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*' -ErrorAction SilentlyContinue |
  Where-Object Flags -ne $null |
  Select-Object PSChildName, DistributionName, Flags, @{
    N='InteropEnabled'; E={[bool]($_.Flags -band 0x0001)}
  }, @{
    N='DrivesMounted'; E={[bool]($_.Flags -band 0x0004)}
  }
```

**Red flags:**
- `InteropEnabled=False` on a distro that should allow interop → policy or attacker restriction
- `DrivesMounted=False` → Windows filesystem not accessible (unusual, unless by design)
- `Flags=0` → all features disabled (highly restrictive, investigate why)

### Check wsl.conf inside the distro

The `[boot] command=` in `/etc/wsl.conf` (inside the Linux filesystem of the vhdx) is the most dangerous:

```bash
# After mounting the vhdx and chrooting into the distro:
cat /etc/wsl.conf | grep -A2 '\[boot\]'
```

**Red flags:**
- Any executable path in `[boot] command=` that you don't recognize
- Payload scripts (base64-encoded commands, curl, wget)
- References to `/mnt/c/...` (Windows-side access)

---

## Registry Acquisition and Analysis

### Offline Analysis (Forensic Imaging)

1. **Extract NTUSER.DAT** from the user's profile
2. **Use a registry parser** (e.g., Registry Recon, RegRipper, or PowerShell):

```powershell
# PowerShell: read offline registry hive (Administrator required)
$hive = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("System")
# For offline: use third-party tools or mount the hive temporarily

# Or use reg.exe to export
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss" /s > lxss_export.txt
```

3. **Parse with RegRipper**:

```bash
regrip.pl -r /path/to/NTUSER.DAT -p lxss
```

### Live Analysis (Active Host)

```powershell
# All Lxss keys
Get-ChildItem -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -Recurse

# Specific distro (if GUID known)
$guid = 'YOUR-GUID-HERE'
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\$guid"

# JSON export for downstream tools
Get-ChildItem -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -Recurse |
  ForEach-Object {
    Get-ItemProperty -Path $_.PSPath |
    ConvertTo-Json
  } > wsl_distros.json
```

---

## Correlate With

| To go deeper on… | Pivot to |
|------------------|----------|
| Registry hive structure and LastWrite mechanics | [**Windows → 04 - Registry Forensics Fundamentals**](<../Windows/04 - Registry Forensics Fundamentals.md>) — hive files, transaction logs, timeline reconstruction from registry |
| Offline registry parsing and artifact extraction | [**Windows → 04 - Registry Forensics Fundamentals**](<../Windows/04 - Registry Forensics Fundamentals.md>) → **"Reading Hives Offline"** section |
| Windows-host side vhdx location and launcher traces | [**WSL → 01 - WSL Artifacts on the Windows Host**](<01 - WSL Artifacts on the Windows Host.md>) — where the vhdx lives, event logs, Prefetch analysis |
| Inside-distro `/etc/wsl.conf` persistence | [**WSL → 02 - Investigating Linux Inside WSL**](<02 - Investigating Linux Inside WSL.md>) — `[boot] command=`, shell startup, systemd checks |
| Hunting for distro access and registry changes | [**WSL → 04 - WSL-Specific Hunting & Detection**](<04 - WSL-Specific Hunting & Detection.md>) — VHD access patterns, registry change events |
| Timeline correlation with NTFS timestamps | [**Windows → 18 - Timeline Analysis**](<../Windows/18 - Timeline Analysis.md>) — LNK, MFT, prefetch timeline correlation |

---

## Red Flags

| 🔴 Finding | Why it matters | Investigation Path |
|-----------|----------------|-------------------|
| Distro with `DefaultUid = 0` (root by default) | Everything runs as root; attacker escalation | Check for suspicious payloads inside the distro; see **WSL/02** |
| `BasePath` in Temp, Downloads, Roaming, or non-standard location | Manually imported; likely attacker-supplied distro | Examine the vhdx/rootfs; check for malware, persistence |
| Missing `PackageFamilyName` | Not from Microsoft Store; custom/imported | Who created it? When? What's the payload? |
| `Flags = 0x0000` (all features disabled) | Highly restrictive; investigate the purpose | Check event logs; is the distro even used? |
| Interop disabled (`Flags` bit 0 = 0) but distro is active | Deliberate isolation (may be intentional, or attacker restriction) | Cross-reference with Lxss usage logs; see Windows/11 event log |
| Distro registered but `State = 3` (not installed) | vhdx or rootfs missing or corrupted; incomplete setup | Look for backup/recovery artifacts, or deletion (anti-forensics) |
| Recent `LastWrite` on Lxss keys with no corresponding Windows event | Configuration tampered with offline or by attacker | Correlate with host timeline; check for unauthorized access |
| Custom `kernel=` in `.wslconfig` | Attacker-supplied WSL2 kernel | Extract and analyze the kernel binary; likely rootkit |
| WSL distro exists but not installed (`State=3`) and BasePath deleted | Attacker cleaned up traces | Check Windows event logs for distro removal; check NTFS deleted file recovery |

---

## Resources

- **Microsoft WSL registry documentation:** https://learn.microsoft.com/windows/wsl/
- **`.wslconfig` / `wsl.conf` reference:** https://learn.microsoft.com/windows/wsl/wsl-config
- **MITRE ATT&CK T1564.008 (Masquerading via WSL):** https://attack.mitre.org/techniques/T1564/008/
- **Registry Recon (open-source registry parser):** https://github.com/keydet89/RegRipper3.0
- **Volatility 3 registry module:** For memory-resident registry hives
