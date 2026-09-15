# Application Bundle (.app) Structure and Forensic Analysis

An `.app` file is **not a single executable** — it's a **directory bundle** containing an executable, libraries, resources, metadata, and code signatures. Many DFIR engineers treat `.app` files as black boxes, but understanding the internal structure reveals execution behavior, dependencies, entitlements, code-signing provenance, and signs of tampering. This note maps the bundle anatomy, explains what each directory contains forensically, and shows how to detect suspicious or malicious `.app` bundles.

> 🔴 **Directory bundles hide complexity**: an `.app` bundles together an executable, dynamically loaded libraries, plugins, frameworks, embedded resources — and Apple's code signature that certifies *who* built it, *when*, and *what capabilities* it requested. A malicious `.app` can masquerade as a legitimate one with a spoofed name, hidden executable, or unsigned code. Understanding the bundle structure is the difference between seeing "Finder.app" and finding the actual binary and its entitlements.

## Contents
- [Quick Triage](#quick-triage)
- [.app Bundle Directory Structure](#app-bundle-directory-structure)
- [Metadata and Forensic Artifacts](#metadata-and-forensic-artifacts)
- [Code Signatures and Notarization](#code-signatures-and-notarization)
- [Entitlements and Sandbox Analysis](#entitlements-and-sandbox-analysis)
- [Execution and Launch Evidence](#execution-and-launch-evidence)
- [Detecting Suspicious and Malicious .app Bundles](#detecting-suspicious-and-malicious-app-bundles)
- [Extracting and Analyzing .app Contents](#extracting-and-analyzing-app-contents)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Identify an app by name and get its bundle ID
APP="/Applications/Suspect.app"
BUNDLE_ID=$(mdls -name kMDItemCFBundleIdentifier "$APP" | grep -o '"[^"]*"' | tr -d '"')

# Verify code signature
codesign -dvvv "$APP" 2>&1 | head -20

# Check entitlements (what the app requests)
codesign -d --entitlements - "$APP" | plutil -p - | head -30

# Notarization status (Apple approval)
spctl -a -v -t install "$APP" 2>&1 | head -5
```

---

## .app Bundle Directory Structure

An `.app` bundle is a **standardized macOS directory package** with a predictable structure:

```
MyApp.app/
├── Contents/
│   ├── MacOS/                    # Executable binaries (main + helpers)
│   ├── Frameworks/               # Bundled libraries (.framework dirs)
│   ├── Plugins/                  # Loadable bundles (extensions)
│   ├── Resources/                # Images, sounds, localized strings, data files
│   ├── Info.plist                # 🔴 Metadata (version, bundle ID, executable name)
│   ├── PkgInfo                   # Package type (binary: "APPL")
│   ├── CodeResources             # Code signature (hashes of all files)
│   └── _CodeSignature/           # Cryptographic signature
└── _CodeSignature/               # Alternative code signature location
```

---

## Detailed Subdirectory Forensics

### Contents/MacOS/ — Executable and Helper Binaries

```bash
APP="/Applications/MyApp.app"
ls -la "$APP/Contents/MacOS/"

# Identify the main executable
EXEC=$(defaults read "$APP/Contents/Info" CFBundleExecutable)
file "$APP/Contents/MacOS/$EXEC"

# Check for hidden or non-standard executables
find "$APP/Contents/MacOS/" -type f ! -name "$EXEC" -exec file {} \;
```

| What's Here | Forensic Value |
|---|---|
| **Main executable** | 🔴 The actual binary that runs; verify signature, architecture (ARM64, x86_64) |
| **Helper executables** | Spawned subprocesses; check signatures separately |

**Forensic questions:**
- Are all binaries **signed and with matching signatures**?
- Are there **unexpected helper executables** that don't match the app's purpose?

### Contents/Frameworks/ — Bundled Libraries and Dependencies

```bash
ls -la "$APP/Contents/Frameworks/" | grep -i ".framework"

# Inspect a framework
FRAMEWORK="$APP/Contents/Frameworks/MyLibrary.framework"
codesign -dvvv "$FRAMEWORK" | head -10
```

| What's Here | Forensic Value |
|---|---|
| `.framework` directories | Bundled libraries; check if signed/notarized |
| **Unusual/custom frameworks** | 🔴 Likely backdoors or injection points |

### Contents/Plugins/ — Extensions and Loadable Bundles

```bash
find "$APP/Contents/Plugins/" -name "*.plugin" -o -name "*.bundle" | while read plugin; do
  codesign -d "$plugin"
done
```

| What's Here | Forensic Value |
|---|---|
| **Plugins** (`.plugin`, `.bundle`) | Loaded at app startup; sign independently |
| **App Extensions** | Gain access to files/data; check entitlements |

### Contents/Resources/ — Non-Executable Assets

```bash
# Find suspicious file types in Resources
find "$APP/Contents/Resources/" -type f -executable
```

| What's Here | Forensic Value |
|---|---|
| **Images, localization, config files** | Standard assets |
| **Embedded scripts or binaries** | 🔴 Highly suspicious; executables should be in MacOS/ |
| **Configuration files** | 🔴 Check for hardcoded C2 servers, API keys |

---

## Metadata and Forensic Artifacts

### Info.plist — The Bundle Identity

The **`Info.plist`** declares the app's identity, entitlements, and required frameworks.

```bash
APP="/Applications/MyApp.app"

# View key entries
defaults read "$APP/Contents/Info" CFBundleIdentifier        # e.g., com.apple.finder
defaults read "$APP/Contents/Info" CFBundleExecutable        # executable name
defaults read "$APP/Contents/Info" CFBundleVersion           # version
defaults read "$APP/Contents/Info" CFBundleShortVersionString # display version
```

| Info.plist Key | Forensic Value |
|---|---|
| **CFBundleIdentifier** | 🔴 Check if it's a typo-squat (e.g., `com.appple.finder`) |
| **CFBundleExecutable** | Name of the binary to run; verify it exists |
| **CFBundleVersion** | Check against vendor site (version mismatch = suspicious) |
| **NSHumanReadableCopyright** | May be blank or spoofed |
| **CFBundleURLSchemes** | Registered URL schemes; malware may register C2 handlers |
| **NSAppTransportSecurity** | HTTPS enforcement; disabled = unencrypted comms allowed |

**Forensic analysis:**
```bash
# Check for suspicious URLs in plist
defaults read "$APP/Contents/Info" 2>/dev/null | grep -i 'http\|url'

# Check for URL scheme registration
defaults read "$APP/Contents/Info" CFBundleURLSchemes 2>/dev/null
```

---

## Code Signatures and Notarization

### Verifying Code Signature

Every code-signed `.app` carries a **cryptographic signature** that certifies the developer and detects tampering.

```bash
APP="/Applications/MyApp.app"

# Verify signature (will error if invalid)
codesign -v "$APP"

# Detailed signature info
codesign -dvvv "$APP" 2>&1 | head -50
```

| Signature Property | Forensic Meaning |
|---|---|
| **✓ Valid signature** | App has not been modified since signing |
| **✗ Invalid signature** | App has been tampered with — **🔴 Red flag** |
| **Unsigned** | Apple Silicon Macs **reject unsigned apps** at launch |
| **Self-signed** | Developer signature, not Apple |
| **Developer ID** | Signed with valid Developer ID certificate (standard for notarized apps) |

### Notarization Status

Apple's **notarization** process scans apps for malware and issues an approval certificate.

```bash
# Check notarization status
spctl -a -v -t install "/Applications/MyApp.app"
# e.g., "accepted" (notarized) or "rejected" (failed)
```

| Notarization Status | Forensic Meaning |
|---|---|
| **Accepted** | ✓ Scanned by Apple, approved (low malware risk) |
| **Rejected** | ✗ Failed Apple's scan (malware detected) |
| **No ticket** | Offline or old app; requires manual inspection if recent |

---

## Entitlements and Sandbox Analysis

### Entitlements — Declared Capabilities

Entitlements define what **system resources an app is allowed to access** (file system, network, camera, microphone, etc.).

```bash
APP="/Applications/MyApp.app"

# Extract entitlements
codesign -d --entitlements - "$APP" | plutil -p - | head -50
```

| Entitlement | What It Allows | Forensic Red Flags |
|---|---|---|
| **com.apple.security.files.user-selected.read-write** | Full Disk Access | 🔴 Broad access; legitimate for editors, malware dropper targets |
| **com.apple.security.network.client** | Outbound network connections | Normal for networked apps; check for C2 URLs |
| **com.apple.security.device.usb** | USB device access | Suspicious on apps that don't need it |
| **com.apple.security.device.microphone** | Microphone recording | Check if app declares need for it |
| **com.apple.security.temporary-exception.\*** | Sandbox exceptions | 🔴 Circumvents sandbox; inspect why |

---

## Execution and Launch Evidence

### How .app Bundles Are Launched

```bash
# Method 1: User double-click (GUI)
# Finder calls LaunchServices, finds CFBundleExecutable, runs it

# Method 2: Command line
open -a MyApp.app

# Method 3: LaunchAgent/LaunchDaemon plist
# Specifies bundle path; launchd starts it at boot/login

# Method 5: URL scheme handler
# Opening a URL (e.g., slack://) launches the app
```

### Execution Evidence Preservation

When an `.app` runs, it leaves traces:

| Artifact | Where to Find |
|---|---|
| **knowledgeC.db / Biome** | Usage timeline |
| **Process list** | PID, parent, command line |
| **Crash reports** | `~/Library/Logs/DiagnosticMessages/` |
| **Unified logs** | Subsystem logs, launchd, sandbox |
| **TCC.db** | Permission grants to the app |

---

## Detecting Suspicious and Malicious .app Bundles

### Quick Suspicious .app Checklist

```bash
APP="/Applications/Suspect.app"

# 1. Check signature
codesign -v "$APP" || echo "🔴 INVALID SIGNATURE"

# 2. Check notarization
spctl -a -v -t install "$APP" | grep -i "accepted\|rejected"

# 3. Hunt for unsigned/suspicious executables in bundle
find "$APP/Contents" -type f -perm +111 -exec codesign -v {} \; 2>&1 | grep -i "invalid"

# 4. Check for hidden files
find "$APP" -name ".*" -not -path "*/.." -type f

# 5. Scan for hardcoded C2 servers
strings "$APP/Contents/MacOS/"* | grep -E '^https?://|\.onion'
```

### Structural Red Flags

| Red Flag | Concern |
|---|---|
| **Invalid/missing signature** | Tampered or malicious app |
| **Unsigned binaries in MacOS/, Plugins/, Frameworks/** | Malware injection point |
| **Executable in Contents/Resources/** | Violates bundle standards |
| **Embedded PE/ELF binaries** | Cross-platform malware dropper |
| **Hidden files or directories** | Obfuscation / anti-forensics |
| **Bundle ID typo-squats known app** | Masquerade / spoofing |

### Content Red Flags

```bash
# Look for suspicious API calls
nm "$APP/Contents/MacOS/"* 2>/dev/null | grep -i 'exec\|spawn\|fork\|dlopen'
```

---

## Extracting and Analyzing .app Contents

### Bundle Extraction and Preservation

```bash
# Copy the entire bundle (preserves extended attributes)
cp -Rp /Applications/Suspect.app /tmp/Suspect.app.extracted

# Or use ditto for forensic preservation
ditto -ck --sequesterRsrc /Applications/Suspect.app /tmp/Suspect.app.tar
```

### Forensic Deep Dive

```bash
APP="/Applications/Suspect.app"

# 1. Enumerate all files with metadata
find "$APP" -type f -exec ls -la {} \; > /tmp/app_manifest.txt

# 2. Hash all executables
find "$APP/Contents" -type f -perm +111 -exec sha256sum {} \; > /tmp/app_hashes.txt

# 3. Extract all strings from binaries
EXEC="$APP/Contents/MacOS/$(defaults read "$APP/Contents/Info" CFBundleExecutable)"
strings "$EXEC" | grep -E 'http|url|exec' > /tmp/app_strings.txt

# 4. Dependency analysis
otool -L "$EXEC"  # show dynamic library dependencies
```

---

## Red Flags

| 🔴 Finding | Likely Meaning |
|---|---|
| **Invalid code signature** | Tampered app or malware |
| **Unsigned binaries in MacOS/, Plugins/** | Backdoor injection point |
| **Executable code in Contents/Resources/** | Violates bundle standards; likely malicious |
| **Embedded PE/ELF executable** | Cross-platform malware dropper |
| **Bundle ID typo-squats known app** | Masquerade / spoofing |
| **Notarization rejected** | Failed Apple's malware scan |
| **Hidden files/directories** | Obfuscation; unusual for legitimate apps |
| **Hardcoded C2 URLs** in strings | Command-and-control communication |
| **App present on disk but not in receipts/Homebrew** | 🔴 Hand-dropped, likely malware |
| **Recent modification timestamps** | Possible tampering or unauthorized deployment |

---

## Resources

- Cross-ref: [Program Execution Evidence](<Program Execution Evidence.md>), [Application and Container Data](<Application and Container Data.md>), [Download Provenance and Quarantine](<Download Provenance and Quarantine.md>)
- Tools: `codesign`, `spctl`, `otool`, `nm`, `file`, `strings`
- MITRE ATT&CK: T1036 (Masquerading), T1574 (Hijacking Execution Flow), T1195 (Supply Chain Compromise)

