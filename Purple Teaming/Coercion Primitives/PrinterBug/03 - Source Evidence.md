# PrinterBug — Source Evidence

**Attacker-side artifacts from PrinterBug coercion.**

---

## Process

- **SpoolSample.exe** (.NET binary) or **python3 printerbug.py** (Python script).
- Short-lived (~2 seconds); terminates after RPC callback.
- No persistent child processes.

---

## Network

**Outbound RPC:**
```bash
ss -tnp
# TCP 192.168.1.99:50000 192.168.1.10:135  (Endpoint Mapper)
# TCP 192.168.1.99:50001 192.168.1.10:445  (RPRN RPC over SMB)
```

**Listening:** Responder / ntlmrelayx ports (separate processes).

---

## Logs

**SpoolSample output:**
```
[*] Targeting \\192.168.1.10
[+] Coercion attempt initiated
[+] Callback received from CORP\DC01$
```

**Responder logs:**
```
[+] NTLM capture from DC01$::CORP:...
```

---

## Shell History

```bash
grep -i "printerbug\|spoolsample" ~/.bash_history
```

---

**Next:** See `04 - Target Evidence.md`.
