# Metasploit — RPC and Daemon (msfrpcd / msfd) — Source Evidence

Two distinct hosts can carry "source"-side evidence here: the **daemon host** (running `msfrpcd`/`msfd`, i.e. the automation backend itself), and the **RPC client host** (wherever a script or `Msf::RPC::Client`/`pymetasploit3` call actually originates, which is very often a *different* box than the daemon — that's the whole point of the RPC model). Both are covered below. Everything specific to `~/.msf4/` directory contents, the Framework database, and resource scripts is shared ground with `../msfconsole/03 - Source Evidence.md` — that page is the canonical breakdown of the directory itself; this page adds what's specific to running the framework headless/remotely rather than interactively.

## Contents
- [Daemon Host: Process and Command-Line Exposure](#daemon-host-process-and-command-line-exposure)
- [Daemon Host: Persistence Artifacts](#daemon-host-persistence-artifacts)
- [Daemon Host: Listening Socket State](#daemon-host-listening-socket-state)
- [Daemon Host: Database and Token Records](#daemon-host-database-and-token-records)
- [RPC Client Host: Script and Shell Artifacts](#rpc-client-host-script-and-shell-artifacts)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Daemon Host: Process and Command-Line Exposure

```bash
ps aux | grep -iE "msfrpcd|msfd|msgrpc"
ps -eo pid,cmd | grep -iE "msfrpcd|msfd"
```
Unlike most tools in this module, `msfrpcd` and `msfd` are **long-lived server processes**, not one-shot invocations — a `ps` snapshot taken hours or days after startup still shows the original invocation, including any `-U`/`-P` credentials passed as literal CLI arguments (visible in `ps aux` output and `/proc/<pid>/cmdline` to any local user on a shared box, same exposure class documented for other tools in this module). The `MSF_RPC_USER`/`MSF_RPC_PASS` environment-variable path (see `02 - Hands-On Use Cases.md`'s systemd scenario) exists specifically to avoid this — but environment variables are still recoverable by anyone with sufficient privilege to read `/proc/<pid>/environ`:
```bash
sudo cat /proc/<pid>/environ | tr '\0' '\n' | grep -i MSF_RPC
```
An investigator finding `-U`/`-P` absent from `ps` output should specifically check for env-based credential supply before concluding none were used.

## Daemon Host: Persistence Artifacts

```bash
systemctl list-units --type=service | grep -i msf
cat /etc/systemd/system/msfrpcd.service 2>/dev/null
journalctl -u msfrpcd --no-pager
crontab -l 2>/dev/null | grep -iE "msfrpcd|msfd"
```
A `systemd` unit file (or cron entry, `rc.local` line, `init.d` script) referencing `msfrpcd`/`msfd` is durable, deliberate evidence that the daemon was meant to survive a reboot as an always-on backend — a materially different finding than a one-off `msfrpcd -f` run from an interactive shell. The unit file itself often carries the credentials or the `MSF_RPC_USER`/`MSF_RPC_PASS` values directly (see `02`'s systemd example), making it a higher-value artifact than shell history for reconstructing exactly how the service was configured.

## Daemon Host: Listening Socket State

```bash
ss -tlnp | grep -E ':55552|:55553|:55554'
ss -tnp  | grep -E ':55552|:55553|:55554'   # established connections = active RPC clients / msfd sessions right now
```
A key distinction from `../msfconsole/03 - Source Evidence.md`'s handler-socket coverage: `multi/handler` only listens while a job is active, but `msfrpcd`/`msfd` are **listening for the entire lifetime of the process** regardless of whether any client is currently connected — the socket being open is not, by itself, evidence of an active operation, only that the service is running. Established connections on these ports, by contrast, are direct evidence of an active RPC client or `msfd` console session at the moment of capture; correlate the remote IP against the RPC client host's own artifacts below.

## Daemon Host: Database and Token Records

If the Framework database is connected (not disabled via `-n`), permanent API tokens issued by `auth.token_add`/`auth.token_generate` are stored as rows in the `Mdm::ApiKey` table — queryable the same way `../msfconsole/03 - Source Evidence.md`'s Database Contents section covers `hosts`/`services`/`creds`/`loot`:
```
msf6 > irb
>> Mdm::ApiKey.all.map(&:token)
```
Every token in this table is a **standing, non-expiring credential** independent of the `-U`/`-P` username/password pair — an investigator who only rotates the RPC password without also auditing/revoking `Mdm::ApiKey` rows leaves every previously-issued permanent token still valid. `session.list`, `job.list`, and `db.hosts`/`db.services`/`db.creds` results are all backed by the exact same tables `../msfconsole/03 - Source Evidence.md` documents — RPC-driven activity lands in the identical database, indistinguishable from console-driven activity at the data layer (the distinguishing signal is the network/process evidence above and the client-side evidence below, not the database contents themselves).

## RPC Client Host: Script and Shell Artifacts

The box actually issuing `auth.login`/`module.execute`/`console.write` calls is frequently **not** the daemon host — it's wherever the operator's automation script, orchestration tool, or interactive Ruby/Python session runs. That host carries its own distinct evidence trail:

```bash
# The script itself — the RPC equivalent of a resource script: a deliberately
# authored, literal record of exactly what was called and in what order
find / -iname "*.py" -o -iname "*.rb" 2>/dev/null | \
  xargs grep -l "MsfRpcClient\|Msf::RPC::Client\|auth\.login\|module\.execute" 2>/dev/null

# Shell history for the invocation — a script run captures the whole chain in one line
grep -iE "msfrpc|pymetasploit" ~/.bash_history ~/.zsh_history ~/.python_history 2>/dev/null

# Installed client libraries — presence indicates RPC-driving capability exists
pip3 show pymetasploit3 2>/dev/null
gem list | grep -i msgpack
```
A recovered Python/Ruby script that imports `pymetasploit3`/`Msf::RPC::Client` and hard-codes a target host/port/credential is functionally identical in evidentiary value to a `.rc` resource script recovered from an operator box (`../msfconsole/03 - Source Evidence.md`'s Resource Scripts section) — it's the operator's own literal, ordered playbook, just written for the RPC surface instead of the console.

## OS-Level Audit Trail

```bash
ausearch -x msfrpcd 2>/dev/null
ausearch -x msfd 2>/dev/null
ausearch -x ruby 2>/dev/null       # both daemons run under the Ruby interpreter
```
If `auditd` syscall auditing is enabled on the daemon host, this is the artifact class most likely to survive process-argument obfuscation (env-var credentials), history deletion, or the daemon being torn down entirely before an investigator arrives — kernel-level execve records don't depend on anything the application layer chose to log.

## Memory Forensics

- A running `msfrpcd`/`msfd` process's memory can contain the plaintext `-U`/`-P` credentials (or, if env-var-supplied, the resolved environment block), every currently-valid session token (`service.tokens`), and — for `msfd` specifically — the full interactive console buffer of whatever any connected client has typed, since it's the same in-process `Msf::Ui::Console::Driver` state `../msfconsole/03 - Source Evidence.md` documents for local sessions.
- On the RPC **client** host, a captured process for a long-running automation script retains the token and credential values used to authenticate, the same Ruby/Python garbage-collection-timing exposure documented in `../msfconsole/03 - Source Evidence.md`'s Memory Forensics section — a full capture (`gcore`, VM snapshot) followed by a token-pattern search (`TEMP` + 28 alphanumeric characters is a distinctive, greppable format) is a viable recovery path even after the script itself has exited.

## Timeline Correlation Value

Anchor a timeline on: the daemon's own start time (`ss`/`ps` process start timestamp, or the `systemd`/cron persistence artifact's own timestamps) → the first established connection on the service port (`ss -tnp` at capture time, or a network-sensor record if the daemon host is monitored) → the corresponding `auth.login` event (recoverable from a packet capture only if `-S` was used or TLS was intercepted) → whatever module/session activity followed, which lands in the same database `sessions.opened_at`/`closed_at` columns `../msfconsole/03 - Source Evidence.md` uses for console-driven activity. Correlating the RPC client host's own script/shell-history timestamp against the daemon host's connection-accept timestamp is what ties a specific automation script, run from a specific controller box, to a specific daemon instance and — downstream — to whatever target-side activity resulted (`04 - Target Evidence.md`).
