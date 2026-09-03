# AdFind — Overview

> 🔴 **Red Flag Principle:** AdFind's entire value to an operator — precise, scriptable LDAP filters instead of clicking through `dsa.msc` — is exactly what makes it loud on the wire. Every meaningful invocation carries a **raw LDAP filter string or a named `-sc` shortcut** (`objectcategory=person`, `trustdmp`, `computers_pwdnotreqd`, …) as plaintext in its own command line, and the compiled binary's PE metadata still identifies it as `AdFind.exe` even when the file itself is renamed. **Command-line logging (Sysmon Event ID 1 / Security 4688) that captures the full argument string — matched against these known filter/shortcut fragments and the `OriginalFileName` PE field — is the single highest-yield detection surface for this tool**, ahead of anything the target domain controller itself logs.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

AdFind is authored and maintained by **Joe Richards**, a long-time Active Directory MVP, and distributed as freeware through his personal site, **[joeware.net](https://www.joeware.net/freetools/tools/adfind/index.htm)** — verified directly against the tool's official pages:

- **Canonical source:** [`joeware.net/freetools/tools/adfind/`](https://www.joeware.net/freetools/tools/adfind/index.htm) (overview) and [`joeware.net/freetools/tools/adfind/usage.htm`](https://www.joeware.net/freetools/tools/adfind/usage.htm) (full switch reference) — there is **no official GitHub or other public source-control repository**. This was checked directly, not assumed: a GitHub code/topic search turns up only unofficial third-party repos re-hosting compiled binaries or wrapper scripts (e.g. `Al1ex/AdFind`), never the project's own source. AdFind ships as a **compiled Win32 binary only** — the source is not publicly released, and the site directs anyone wanting to bundle it in a commercial product to contact the author directly for licensing rather than pointing at a repo. Treat joeware.net itself as the only authoritative reference for this note.
- **License:** Freeware, "as-is," no warranty. Not open source.
- **Purpose, in the author's own words:** a command-line AD/LDAP query tool built because existing options at the time (`ldapsearch`, `search.vbs`, Microsoft's own `dsquery`/`dsget`) were too limited for the kind of fast, scriptable, filter-driven queries an AD administrator actually needs day to day.
- **Versioning:** AdFind has shipped steady incremental releases for two decades — V01.31.00 (2006), V01.52.00 (2020), V01.55.00 (2021), and V01.62.00 (2023) are all independently documented on the author's blog; the current usage page (checked for this note) shows **V01.64.00cpp**. The `cpp` suffix in the version string is the author's own convention marking it as the native C++ build.
- **The author is well aware of, and has publicly commented on, AdFind's adoption by ransomware and other criminal operators.** A 2020 blog post titled *"9 out of 10 hackers prefer AdFind for AD Recon…"* is Joe Richards responding directly to a threat-intel report naming his tool: *"This isn't the first I have read about AdFind being used by bad actors, it won't be the last,"* adding that tools like his are attractive to attackers because *"they are fast and they work and don't require a huge infrastructure around them to function."* This is not a third party's inference about dual-use tooling — it's the author's own acknowledgment, and it's part of why AdFind shows up so consistently across ransomware-precursor reporting (see the Quick Use-Case List below).

## How It Works

**AdFind is a native LDAP client, not an ADSI/COM wrapper — this is a real, verified distinction worth getting right.** A common assumption (including early drafts of this note) is that AdFind rides ADSI, the same COM-based interface layer PowerView/PowerShell's `System.DirectoryServices` use. It doesn't. AdFind is built directly against **`wldap32.dll`**, the native Win32 LDAP client library — confirmed both by the executable's own import table and by the author's own blog posts benchmarking AdFind against a PowerShell/`S.DS.Protocols` equivalent (AdFind ran **4.5–6.25× faster** and used roughly a third of the CPU on the same 700k-object directory query). That performance gap is the whole reason AdFind exists and the whole reason it's an operator favorite for bulk enumeration: it talks the LDAP wire protocol directly instead of paying ADSI's COM marshaling overhead.

### The LDAP query model AdFind wraps

Every AD query, regardless of the tool making it, is fundamentally an **LDAP search request** with four required pieces — AdFind's entire command-line surface exists to let an operator set these four things quickly from a shell instead of a GUI:

| LDAP concept | AdFind switch | What it controls |
|---|---|---|
| **Bind (authentication)** | `-u`/`-up`, or nothing | Establishes the LDAP session's security context. With no `-u`/`-up`, AdFind binds using the calling process's current logon token (Kerberos/NTLM via SSPI, whatever the OS negotiates) — no credentials appear on the command line at all. `-simple`, `-ntlm`, `-digest` force a specific bind mechanism (`LDAP_AUTH_SIMPLE`/`_NTLM`/`_DIGEST`), still against the password supplied via `-up` |
| **Base DN (search root)** | `-b <DN>` | Where in the directory tree the search starts. AdFind also provides named shortcuts for the well-known naming contexts so the operator never has to type them out: `-default` (the domain partition), `-schema`, `-config`, `-subnets` (the Sites container's Subnets object), `-partitions` |
| **Filter** | `-f <RFC 2254 filter>` | The actual query logic — an LDAP filter string, e.g. `(objectcategory=person)` or a compound `(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=32))`. If omitted, defaults to `objectclass=*` (return everything under the base) |
| **Scope** | `-s base\|onelevel\|subtree` | How far the search descends from the base DN — a single object, its immediate children, or the entire subtree. AdFind defaults to subtree |

A bind, one search request carrying base+filter+scope, and a stream of result entries back — that's the entire protocol exchange. AdFind's real engineering is everything wrapped *around* that one request: dozens of named base-DN/filter shortcuts (the `-sc` mechanism, below), bitwise-filter syntax sugar (`-bit`, expanding `:AND:=`/`:OR:=` into the real OID-based matching rules `1.2.840.113556.1.4.803`/`.804`), and output formatting (`-csv`, `-list`, `-dn`, `-sl`) built specifically so a single invocation's output pipes cleanly into a spreadsheet or a second command — the combination is what makes bulk AD enumeration a one-liner instead of a script.

```
Operator host                                    Domain Controller / Global Catalog
──────────────                                   ───────────────────────────────────
AdFind.exe -b DC=corp,DC=local
           -f "(objectcategory=person)"
           sAMAccountName mail -csv
        │
        ├─ 1. Resolve target: -h host:port given?  ──▶  if not, DsGetDcName-style
        │      explicit, else "serverless" bind         serverless locate finds a
        │      via the current domain context            reachable DC automatically
        │
        ├─ 2. LDAP bind (wldap32 ldap_bind_s /       ──▶  DC authenticates the
        │      ldap_connect) — current token unless        session (Kerberos/NTLM
        │      -u/-up/-simple/-ntlm/-digest given          via SSPI, or simple bind)
        │
        ├─ 3. Single ldap_search_s/_ext_s call        ──▶  DC (or GC) evaluates the
        │      carrying base DN + filter + scope +          filter against its own
        │      requested attribute list                     copy of the directory
        │
        ◀── 4. Result entries streamed back, paged ───┘   (1000-object default page
        │      via LDAP paged-results control if            size unless -nopaging or
        │      -nopaging isn't set                           -ps overrides it)
        │
        └─ 5. OutputFormat() renders each entry per
               -csv/-list/-dn/-sl/plain — to console
               or a redirected file
```

### Global Catalog vs. domain controller targeting

`-gc` retargets the exact same bind/search mechanism at **port 3268** (LDAPS GC: 3269) instead of the standard **389** (LDAPS: 636). This isn't a different protocol — it's the same LDAP search, but serviced by a Global Catalog server's **partial, read-only, forest-wide replica** rather than a single domain's full read-write copy. The practical difference for an operator: a `-gc` query against one server returns matching objects **from every domain in the forest** in a single round trip, at the cost of only being able to filter/return attributes flagged for GC replication (most commonly queried attributes are, but not all — full-object detail on a hit typically still needs a follow-up non-GC query against that object's own domain). This is why `-gc` shows up specifically on cross-domain/forest-wide sweeps (e.g. `-sc trustdmp`, forest-wide user searches) while single-domain enumeration just uses the default DC bind.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Directory access protocol | LDAP (TCP 389, LDAPS 636) against a domain controller; LDAP/LDAPS Global Catalog (TCP 3268/3269) via `-gc` for forest-wide queries |
| Client implementation | Native Win32 LDAP client API (`wldap32.dll`) — **not** ADSI/COM, and not a managed `.NET DirectoryServices` client either. This is why AdFind is materially faster and lighter-footprint than script-based AD enumeration built on those higher-level layers |
| Authentication | Current logon-session token by default (Kerberos or NTLM via SSPI, whatever the OS negotiates with the target) when no explicit credentials are given; `-u`/`-up` for an alternate username/password pair with a selectable bind mechanism (`-simple`, `-ntlm`, `-digest`) |
| Server discovery | "Serverless" binding — if `-h` isn't given, AdFind lets the OS locate a reachable domain controller for the current domain context automatically, the same mechanism behind `nltest`/`echo %LOGONSERVER%` |
| Output | Console (default), or any text stream redirected to a file — CSV, tab-delimited, list-style, or raw labeled attribute dumps, chosen specifically for downstream parsing (Excel, `findstr`, a second script) rather than human browsing |

## Command-Line Switches — Quick Reference

Verified against the official switch reference at [joeware.net/freetools/tools/adfind/usage.htm](https://www.joeware.net/freetools/tools/adfind/usage.htm). AdFind has a very large total switch surface (well over a hundred, including dozens of `-sc` shortcuts); the table below covers the ones that matter for reading or writing a real command line — not an exhaustive reproduction of the built-in help.

| Switch | Plain-English meaning |
|---|---|
| `-h host:port` | Target a specific server/port instead of letting AdFind locate a DC automatically. Default port is 389 if omitted |
| `-gc` | Query the Global Catalog (port 3268) instead of a single domain's DC — forest-wide results, partial attribute set |
| `-ssl` / `-starttls` | Use LDAPS (encrypted) instead of plaintext LDAP |
| `-u <userdn>` | Alternate account to authenticate as — accepts `DOMAIN\user`, `user@domain.com` (UPN), or a full distinguished name |
| `-up <pwd>` | Password for `-u`. Accepts a cleartext string, a literal `*` to prompt interactively (keeps the password off the command line and out of history), or an `ENCPWD:xxx` value produced by `-encpwd` (a locally reversible obfuscation, **not** encryption of forensic strength) |
| `-encpwd <pwd>` | Utility mode: encodes a password into the `ENCPWD:xxx` form for reuse with `-up` — optional, purely to keep a literal password out of a saved script |
| `-simple` / `-ntlm` / `-digest` | Force a specific LDAP bind mechanism (Simple Bind / NTLM / Digest) against the `-u`/`-up` credential — note none of these switches accept an NTLM *hash*; AdFind always binds with a real (or `ENCPWD`-obfuscated) password, unlike pass-the-hash-capable tools such as Impacket's scripts |
| `-b <DN>` | Base DN to search from (RFC 2253 format) |
| `-default` / `-schema` / `-config` / `-subnets` / `-partitions` | Shortcuts that resolve and use the domain/schema/configuration/Subnets-container/Partitions-container naming context as the base DN, without the operator typing the full DN out |
| `-rb <relative DN>` | Relative base — combine with one of the shortcuts above, e.g. `-default -rb "cn=users"` |
| `-f <filter>` | RFC 2254 LDAP filter. Defaults to `objectclass=*` if omitted |
| `-bit` | Rewrites shorthand `:AND:=` / `:OR:=` / `:INCHAIN:=` / `:NEST:=` in a filter into the real LDAP matching-rule OIDs (`1.2.840.113556.1.4.803`/`.804`/`.1941`) — lets an operator write bitwise `userAccountControl` filters without memorizing OID strings |
| `-s base\|onelevel\|subtree` | Search scope. Defaults to subtree |
| `-sc <name>` | Run a named built-in shortcut query in one word instead of a full `-b`/`-f` filter — dozens exist (see Quick Use-Case List); common ones include `trustdmp` (domain trusts), `domainlist`, `dclist`, `dcmodes`, `adinfo`, `computers_pwdnotreqd`, `gpodmp` |
| `-dn` | Return distinguished names only |
| `-nodn` | Suppress the DN in output (attribute values only) |
| `-list` | Compact list-style output — no DN, no attribute labels |
| `-sl` | "Sorted list" — shortcut for `-sort` + `-list` combined |
| `-c` | Return only a count of matching objects, not the objects themselves |
| `-csv [delim]` | CSV-formatted output, optionally with a custom field delimiter |
| `-nopaging` / `-ps <size>` | Disable LDAP result paging, or set a custom page size (default page size is 1000 objects per round trip) |
| `-t <seconds>` | Query timeout (default 120 seconds) |
| `1.1` (as an attribute name) | LDAP's own convention for "return no attributes, DNs only" — a fast existence/count-style query with minimal data transferred |

## Quick Use-Case List

- Bulk domain-user enumeration (`-f "(objectcategory=person)"`)
- Bulk computer-object enumeration (`-f "(objectcategory=computer)"`)
- Domain/security-group enumeration and privileged-group membership mapping
- Domain trust enumeration for cross-domain/forest attack-path planning (`-sc trustdmp`)
- OU structure mapping to understand the target's administrative boundaries
- Subnet and site enumeration for network-topology awareness (`-subnets -f (objectCategory=subnet)`)
- GPO enumeration (`-sc gpodmp`)
- Finding accounts with weak Kerberos/authentication settings — password-not-required accounts (`-sc computers_pwdnotreqd` / the `PASSWD_NOTREQD` UAC bit), accounts with expired or never-expiring passwords
- SPN enumeration as a Kerberoasting precursor — overlaps in purpose with `setspn -Q` and Impacket's `GetUserSPNs.py`, though AdFind only *discovers* SPN-bearing accounts and takes no further action
- Domain controller / forest topology enumeration (`-sc dclist`, `-sc dcmodes`, `-sc fsmo`) to map replication and functional-level state
- One-liner `-sc` shortcut usage vs. hand-built `-b`/`-f` filters for anything the built-in shortcuts don't already cover
- Alternate-credential enumeration via `-u`/`-up` from a foothold that doesn't already hold a usable domain session
- Global Catalog (`-gc`) sweeps for forest-wide results in a single query, vs. default single-domain DC targeting
- CSV-formatted bulk exports (`-csv`) piped into a spreadsheet or a follow-on script for offline analysis
- The well-documented, near-universal role as an early **ransomware-precursor recon step** — output from an AdFind sweep routinely feeds the operator's next tool choice (BloodHound for attack-path graphing, Kerberoasting against a discovered SPN list, lateral movement toward a discovered low-hanging-fruit host)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Target environment | Any LDAP directory — Active Directory, ADAM/AD LDS, or other RFC-compliant LDAP servers. Every real-world use case in this repo targets AD |
| Network reachability | LDAP (389) or LDAPS (636) to a domain controller, or GC (3268/3269) for forest-wide queries — no other ports needed |
| Execution host | Any Windows host — AdFind does **not** require RSAT or any AD administrative tools to be installed; it's a self-contained static-ish binary carrying its own LDAP client code path, unlike tools such as `setspn.exe` that depend on an installed RSAT feature |
| Authentication | Either an existing authenticated session (current logon token — the common case when run from an already-compromised domain-joined host) or explicit `-u`/`-up` alternate credentials reachable over LDAP from wherever AdFind runs |
| Directory-side permissions | Any authenticated domain user can read the vast majority of AD's default-ACL'd attributes — no elevated privileges are required for most of the use cases above, which is exactly why this tool is so effective this early in an intrusion |
