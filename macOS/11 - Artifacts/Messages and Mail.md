# Messages and Mail

Apple **Messages** (iMessage/SMS) and **Mail** are high-value **communications** artifacts — content, contacts, attachments, and timing that support insider, harassment, BEC, and exfil-over-comms cases. Messages stores everything in a single SQLite **`chat.db`**; Mail keeps per-message `.emlx` files plus a SQLite **Envelope Index**. Both sit under the user's protected Library, so reading them **live needs Full Disk Access** (TCC).

> 🔴 `chat.db` is a goldmine: every iMessage/SMS with timestamps, the sender/recipient handles, and attachment paths. Mail's `.emlx` are full RFC-822 messages on disk. Both can show **data exfiltrated via chat/email** and who the user communicated with.

## Contents
- [Quick Triage](#quick-triage)
- [Messages chat.db](#messages-chatdb)
- [chat.db Schema](#chatdb-schema)
- [Useful chat.db Queries](#useful-chatdb-queries)
- [Message Attachments](#message-attachments)
- [Mail](#mail)
- [Access and TCC](#access-and-tcc)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Messages DB (copy out before querying; needs FDA live)
ls -la ~/Library/Messages/chat.db*

# Recent messages (text + timestamp)
sqlite3 ~/Library/Messages/chat.db "SELECT datetime(date/1000000000 + 978307200,'unixepoch'), is_from_me, text FROM message ORDER BY date DESC LIMIT 20;"

# Mail on disk
find ~/Library/Mail -name '*.emlx' 2>/dev/null | head
```

---

## Messages chat.db

| Path | Holds |
|---|---|
| 🔴 `~/Library/Messages/chat.db` | iMessage + SMS messages, handles, chats (SQLite) |
| `~/Library/Messages/chat.db-wal` / `-shm` | Write-ahead log — **copy these too** (uncommitted messages) |
| 🔴 `~/Library/Messages/Attachments/` | Sent/received files (images, docs) |
| `~/Library/Messages/chat.db.backup` | Occasional backup copy |

> Always copy `chat.db` **with** its `-wal`/`-shm` sidecars — recent messages may live only in the WAL.

---

## chat.db Schema

| Table | Holds |
|---|---|
| 🔴 `message` | The messages — `text`, `date`, `is_from_me`, `service`, `handle_id` |
| `handle` | Phone numbers / Apple IDs (`id`) |
| `chat` | Conversations (incl. group chats) |
| `chat_message_join` | Links messages ↔ chats |
| `attachment` | Attachment metadata (filename, path, mime) |
| `message_attachment_join` | Links messages ↔ attachments |

🔴 **Timestamps**: `date` is **nanoseconds since 2001-01-01** (Cocoa epoch) on modern macOS → `date/1000000000 + 978307200` for Unix. (Older DBs used plain seconds — if dates look wrong, drop the `/1000000000`.)

---

## Useful chat.db Queries

```sql
-- Messages with readable time + the other party
SELECT
  datetime(m.date/1000000000 + 978307200, 'unixepoch') AS Time,
  CASE m.is_from_me WHEN 1 THEN 'ME' ELSE h.id END AS Party,
  m.text
FROM message m
LEFT JOIN handle h ON m.handle_id = h.ROWID
ORDER BY m.date DESC
LIMIT 50;
```

```sql
-- All conversations with a specific number / Apple ID
SELECT datetime(m.date/1000000000 + 978307200,'unixepoch'), m.is_from_me, m.text
FROM message m JOIN handle h ON m.handle_id=h.ROWID
WHERE h.id LIKE '%5551234567%'
ORDER BY m.date;
```

```sql
-- Messages that carried attachments (potential exfil)
SELECT datetime(m.date/1000000000 + 978307200,'unixepoch'), a.filename, a.mime_type
FROM message m
JOIN message_attachment_join j ON m.ROWID=j.message_id
JOIN attachment a ON j.attachment_id=a.ROWID
ORDER BY m.date DESC;
```

---

## Message Attachments

```bash
# What was sent/received as files
ls -laR ~/Library/Messages/Attachments/ 2>/dev/null | head -50

# Find recent attachments
find ~/Library/Messages/Attachments -type f -mtime -30 2>/dev/null
```

🔴 The `Attachments/` tree holds the **actual files** exchanged — a path for **data exfiltration** (sending company files out) or ingress (receiving tooling). Attachments keep their own timestamps + may carry quarantine.

---

## Mail

| Path | Holds |
|---|---|
| 🔴 `~/Library/Mail/V*/` | Mailbox data (version dir: `V10`, `V9`, …) |
| `…/<account>/…/*.emlx` | Individual messages (RFC-822 + Apple metadata) |
| `…/MailData/Envelope Index` | 🔴 SQLite index of all mail (senders, subjects, dates) |
| `~/Library/Mail/V*/MailData/` | Accounts, signatures, rules |

```bash
# Find messages on disk
find ~/Library/Mail -name '*.emlx' 2>/dev/null

# Read one (.emlx = length line + raw RFC-822 + plist trailer)
cat "~/Library/Mail/V10/.../123.emlx" | head -40

# Query the Envelope Index (senders/subjects/dates)
sqlite3 ~/Library/Mail/V*/MailData/Envelope\ Index "SELECT * FROM messages LIMIT 20;" 2>/dev/null
```

🔴 Mail **rules** can auto-forward/delete (exfil or evidence destruction) — check `MailData` for suspicious rules.

---

## Access and TCC

🔴 These DBs are under the user's protected Library — **reading them live requires Full Disk Access** (TCC). On a dead-box image you read them directly.

```bash
# If blocked live, grant Terminal FDA (System Settings) or work from an image
sqlite3 ~/Library/Messages/chat.db ".tables" 2>&1   # 'unable to open' = needs FDA
```

> Copy DBs (with `-wal`/`-shm`) before querying; don't alter evidence. Parsers: **mac_apt** (`MESSAGES`/`IMESSAGE`), commercial suites.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Attachments of **company/sensitive files** sent out | Exfiltration over Messages |
| Conversations with unknown/external parties | Collusion / data handoff |
| Mail **auto-forward rule** to an external address | Exfil / BEC persistence |
| Mail rule auto-deleting messages | Evidence destruction |
| Messages/Mail **deleted** around an incident | Cover-up (check WAL / Trash / FSEvents) |
| Tooling/links received via chat | Ingress / social engineering |
| Comms at odd hours with sensitive content | Insider activity |

---

## Resources

- mac_apt (`MESSAGES` plugin): https://github.com/ydkhatri/mac_apt
- `man sqlite3` · Cross-ref: TCC (FDA), Program Execution Evidence, Cross-Artifact Correlation
