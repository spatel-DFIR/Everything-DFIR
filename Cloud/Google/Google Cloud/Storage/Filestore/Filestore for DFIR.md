# Filestore for DFIR

Filestore cases answer a narrower question than GCS cases: **not** "which files were read/written" (Google cannot tell you that — see below), but **when was the instance created/changed/snapshotted/deleted, by whom, and what can I recover from a snapshot or backup.**

New to it? Read **What is Filestore** first — especially the logging-gap section, before you're mid-incident.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [🔴 The Logging Gap — Read This First](#-the-logging-gap--read-this-first)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Snapshot-Based Acquisition](#snapshot-based-acquisition)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Default | Best for |
|--------|--------------|---------|----------|
| **Admin Activity (Cloud Audit Logs)** | Instance create/delete/patch, snapshot/backup create/delete/restore | ✅ On | Instance lifecycle timeline |
| **Data Access (Cloud Audit Logs)** | 🔴 **Does not exist for file I/O** — there is no `DATA_READ`/`DATA_WRITE` category to enable, unlike GCS | N/A | Nothing — see below |
| **VPC Flow Logs** | Connections to the NFS port (2049) on the Filestore instance's IP | Off by default (enable on the subnet) | Who connected, not what they did |
| **Host-side (mounting VM/pod)** | Filesystem timestamps, EDR file telemetry, application logs, shell history | Depends on the host | The *only* file-content-level evidence available |
| **Snapshots / Backups** | Point-in-time copies of the share | Manual/scheduled | Content diffing, recovery, offline acquisition |

## 🔴 The Logging Gap — Read This First

**There are no file-operation-level logs available via the Google API or Cloud Audit Logs for Filestore.** Instance lifecycle events (create/delete/patch/snapshot) are logged under `file.googleapis.com`. Individual file reads, writes, deletes, and renames on the mounted NFS share are **not logged anywhere on Google's side, at any tier, with any setting** — this is a structural gap (NFS is a network filesystem protocol, not a per-file API call), not a toggle you forgot to flip.

**Contrast with GCS:** Cloud Storage has an *optional* Data Access log category (`storage.objects.get/create/delete`) you can enable for exactly this kind of question. Filestore has no equivalent category to enable — the option simply doesn't exist. Don't spend investigation time looking for a "Filestore Data Access" toggle; there isn't one.

**What this means practically:** if the question is "did user X read/exfiltrate/delete file Y on the share," Filestore's own logs cannot answer it. You must build the answer from:

1. **The mounting compute instance(s)/pod(s)** — host filesystem metadata (mtime/ctime, watch for `noatime` suppressing atime), auditd rules on the NFS mount path, EDR file-access telemetry, application logs that reference the file path.
2. **Snapshots/backups** — diff two points in time to establish *that* content changed, even without knowing the exact operation or actor.
3. **VPC Flow Logs** — confirm *which hosts* connected to the NFS port during the window, narrowing which mounting VMs to pull host evidence from.
4. **IAM/network audit trail** — who had the ability to reach the share at all (firewall rules, VPC peering, IAM on hosts that had it mounted).

Document this limitation in your report early — it shapes the whole evidence-collection plan, not just a footnote.

## Collect It

**Step 1 — Instance lifecycle timeline.**

```bash
# All Filestore admin activity on an instance, last 30 days
gcloud logging read \
  'resource.type="fileshare" AND resource.labels.instance_name="<instance>" AND protoPayload.serviceName="file.googleapis.com"' \
  --freshness=30d --format=json

# Just the destructive/high-impact ops
gcloud logging read \
  'protoPayload.serviceName="file.googleapis.com" AND
   protoPayload.methodName=("google.cloud.filestore.v1.CloudFilestoreManager.DeleteInstance" OR
                             "google.cloud.filestore.v1.CloudFilestoreManager.DeleteBackup")' \
  --freshness=30d
```

> **Console:** Logs Explorer → filter `resource.type="fileshare"` (or `filestore_instance` depending on API version) → `protoPayload.serviceName="file.googleapis.com"`.

**Step 2 — Current instance state and reachability.**

```bash
# Instance details: network, tier, IP, current shares
gcloud filestore instances describe <instance> --zone=<zone>

# What networks/firewall rules can reach the NFS export
gcloud compute firewall-rules list --filter="allowed.ports:2049"
```

**Step 3 — Who could have mounted it (VPC Flow Logs, if enabled).**

```bash
gcloud logging read \
  'resource.type="gce_subnetwork" AND jsonPayload.connection.dest_port=2049 AND
   jsonPayload.connection.dest_ip="<filestore_instance_ip>"' \
  --freshness=30d
```

🔴 If Flow Logs weren't enabled on the subnet before the incident, this evidence doesn't exist retroactively — same lesson as the file-operation gap: know your logging posture ahead of time.

**Step 4 — Pull host-side evidence from every VM/pod that had the share mounted** (see **Correlate With**). This is where the actual file-level answer lives.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Scope the instance | Confirm which instance/share is in question; pull its full Admin Activity history |
| 2. Build the lifecycle timeline | Create → config/network changes → snapshots/backups → (delete, if any) |
| 3. Identify who could reach it | Firewall rules + VPC routing to port 2049; IAM on any host that mounted it |
| 4. Enumerate the mounting hosts | Every GCE VM / GKE pod (via PersistentVolumeClaim) that had the share mounted during the window |
| 5. Pivot to host evidence | For each mounting host: filesystem timestamps, EDR, application logs, shell history — this is where file-level answers come from |
| 6. Check for recovery points | Snapshots/backups that predate suspected tampering — diff or restore-and-compare |

## Snapshot-Based Acquisition

Given the logging gap, **snapshots and backups are the main forensic acquisition path** for Filestore — they're the only way to get at file-level content state without relying entirely on live host access.

```bash
# List existing snapshots/backups
gcloud filestore snapshots list --instance=<instance> --zone=<zone>
gcloud filestore backups list

# Take a forensic snapshot now (preserve current state before further changes)
gcloud filestore snapshots create <snap-name> --instance=<instance> --zone=<zone> \
  --description="DFIR acquisition $(date -u +%FT%TZ)"

# Restore a snapshot to a NEW instance for offline analysis (don't restore over the live share)
gcloud filestore instances create <analysis-instance> --zone=<zone> \
  --file-share=name="<share>",source-snapshot=<snap-name>
```

| Goal | Approach |
|------|----------|
| Preserve current state | Snapshot immediately, before any remediation touches the share |
| Establish "what changed" | Restore an earlier snapshot/backup to a separate analysis instance, mount both, diff with `rsync -avnc` or `diff -rq` |
| Full offline review | Mount the restored analysis instance read-only on an isolated VM; run file-integrity/EDR/YARA scans there instead of on production |
| Chain of custody | Note snapshot/backup timestamps and the `CreateSnapshot`/`CreateBackup` audit log entries as your provenance record |

🔴 Snapshots are instance-local and can be deleted along with the instance; **backups** are the durable, longer-retained option and survive instance deletion — if you expect a live incident might end in `DeleteInstance`, take a backup, not just a snapshot.

## Hunt at Scale

**BigQuery — Filestore lifecycle events across the org:**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS who,
       protopayload_auditlog.methodName AS action,
       resource.labels.instance_name AS instance
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.serviceName = 'file.googleapis.com'
  AND protopayload_auditlog.methodName IN (
    'google.cloud.filestore.v1.CloudFilestoreManager.DeleteInstance',
    'google.cloud.filestore.v1.CloudFilestoreManager.DeleteBackup')
ORDER BY timestamp DESC;
```

**Instances with no recent backup (recovery-gap hunt):**

```bash
for inst in $(gcloud filestore instances list --format='value(name)'); do
  echo "$inst: $(gcloud filestore backups list --filter="sourceInstance:$inst" --format='value(createTime)' | sort | tail -1)"
done
```

> **At the very end — SecOps UDM (optional):** land Filestore Admin Activity events (`file.googleapis.com`) to correlate instance lifecycle with identity/IP context across projects. It will never carry file-level detail — keep expectations aligned with the logging gap above.

## Respond

| Goal | Action |
|------|--------|
| Preserve evidence before remediating | Take a **backup** (not just a snapshot) of the live instance immediately |
| Cut off further access | Tighten the firewall rule / VPC routing to the NFS port; remove IAM from compromised identities |
| Contain a compromised mounting host | Isolate that VM/pod first — it's the actual source of file-level compromise, not the Filestore instance itself |
| Recover from tampering | Restore from the last-known-good snapshot/backup to a **new** instance; validate before cutting production over |
| Rotate | Any credentials/secrets that lived on the share |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| Enable **VPC Flow Logs** on the subnet hosting the Filestore instance | The only network-level "who connected" evidence you'll have, given the file-op logging gap |
| Restrict firewall rules to only the VMs/subnets that need NFS access | Shrinks the pool of hosts you'd need to pull host-evidence from |
| Schedule regular **backups** (not just ad hoc snapshots) | Durable recovery points that survive instance deletion |
| Deploy **auditd**/EDR with file-access rules on every mounting VM | This is where your file-level detection has to live, since Google can't provide it |
| Alert on `DeleteInstance` / `DeleteBackup` via a log-based metric | Catch destructive/anti-forensic actions in near-real-time |
| Document the logging gap in your incident-response runbook | So responders don't waste time hunting for a log source that doesn't exist |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `DeleteInstance` or `DeleteBackup` outside a change window | Destruction / anti-forensics — check if it preceded an incident report |
| Firewall rule opened to `0.0.0.0/0` (or overly broad CIDR) on port 2049 | NFS export reachable beyond intended hosts |
| A new, unexpected VM/pod appears in VPC Flow Logs connecting to the Filestore IP | Unauthorized mount |
| `UpdateInstance` changing network/authorized-network config | Could widen who can reach the share |
| No backups exist, or the last backup predates the suspected incident window | Recovery-point gap — snapshot immediately before anything else changes |
| Host-side evidence (EDR, auditd, timestamps) is the *only* place a finding shows up | Expected, given the logging gap — not itself suspicious, but confirm you actually pulled it |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The service + why the logging gap exists | **Filestore → What is Filestore** |
| The mounting compute instance's own evidence | **GCP → Compute Engine** |
| The mounting GKE workload's own evidence | **Container → GKE** |
| Network-level "who connected" | **GCP → VPC Flow Logs** |
| The object-storage contrast (Data Access logs that *do* exist) | **Cloud Storage → Cloud Storage for DFIR** |
| Audit log fundamentals | **GCP → Cloud Audit Logs** |

## Resources

- Filestore overview — https://cloud.google.com/filestore/docs/overview
- Filestore audit logging — https://cloud.google.com/filestore/docs/audit-logging
- Filestore backups — https://cloud.google.com/filestore/docs/backups
- Filestore snapshots — https://cloud.google.com/filestore/docs/snapshots
- MITRE ATT&CK: T1530 Data from Cloud Storage — https://attack.mitre.org/techniques/T1530/
