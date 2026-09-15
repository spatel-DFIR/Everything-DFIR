# Rclone — Target Evidence

Set expectations correctly before anything else, the same way `AdFind/04 - Target Evidence.md` does for its own thin-target tool: **rclone has no single "target" in the sense this repo's template usually means.** It doesn't execute on a remote host, doesn't create a service, and drops nothing to a destination the way a lateral-movement tool does. There are really **two different things** an analyst might mean by "target" for this tool, and they have completely different evidence shapes:

1. **The source file share being read from** — if the data being exfiltrated lives on a separate file server rather than the same host rclone runs on, that file server is a real, evidence-rich "target" in the traditional sense (it's a host other than the operator's own that gets touched).
2. **The destination cloud provider** — Mega, S3, Dropbox, etc. — which is almost always attacker-controlled infrastructure the victim organization has zero logging visibility into. This is the "target" a defender instinctively looks for evidence on, and it's usually the one with the least available.

This page covers both honestly rather than force-fitting rclone into a filesystem/registry/event-log template it doesn't produce artifacts for.

## Contents
- [Evidence on the Source File Share (if separate from the execution host)](#evidence-on-the-source-file-share-if-separate-from-the-execution-host)
- [Evidence at the Destination Cloud Provider](#evidence-at-the-destination-cloud-provider)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint/DLP Security Product Behavior](#endpointdlp-security-product-behavior)
- [Building a Timeline](#building-a-timeline)

---

## Evidence on the Source File Share (if separate from the execution host)

Where rclone reads from a network share (`\\fileserver\Shares\Finance` in `02`'s examples) rather than local disk on the same host it runs from, **that file server is a genuine target host** and generates real, standard Windows evidence — none of it rclone-specific, all of it already covered elsewhere in this repo, so it's cross-linked rather than re-derived:

| Evidence | Where it's covered |
|---|---|
| Object Access auditing (Security Event **4663** — an account was granted requested access to an object; **5145** — a network share object was checked for access) if file/share auditing is enabled | Not rclone-specific — standard Windows object-access auditing, covered in `Windows/11 - Event Log Analysis.md` |
| SMB session/tree-connect evidence on the file server (source IP, account used, share accessed) | `Windows/12 - Lateral Movement.md` |
| A large, unusual read volume against a share from a single source account/host in a short window | The core anomaly signal for this scenario — no dedicated rclone artifact, just an unusually large legitimate-looking read |

**Important caveat:** Windows does **not** enable object-access/file-share auditing by default — the same "assume it's off unless proven otherwise" caution `AdFind/04 - Target Evidence.md` gives Directory Service diagnostics applies here. Absent that non-default auditing, the file server itself may contribute nothing beyond ordinary SMB connection-level telemetry (source IP, account, timestamp), pushing the real evidentiary weight back onto `03 - Source Evidence.md`'s process/command-line record on the host that actually ran rclone.

## Evidence at the Destination Cloud Provider

This is the weakest link in the entire chain, and it's worth being direct about why: **in the overwhelming majority of documented cases (CISA's Akira and BlackSuit/Royal advisories, The DFIR Report's Sodinokibi case, MITRE S1040's Conti/DarkSide history), the destination account — the Mega.nz account, the S3 bucket, the FTP server — belongs to the attacker, not the victim organization.** A victim has no audit-log access to infrastructure they don't own or control. There is no equivalent here to querying a domain controller's own event log, because the "server" in this exchange isn't the victim's.

The one exception worth naming: if an operator instead abuses a cloud account or service the **victim organization itself already owns** (a compromised corporate OneDrive/Google Workspace/AWS account, rather than attacker-owned infrastructure), then that provider's own native logging becomes real, recoverable target-side evidence — AWS CloudTrail `PutObject`/`s3:PutObject` API call records, Azure Storage/Entra ID sign-in logs, Google Workspace admin audit logs. This is a materially different scenario from the "attacker's own Mega account" pattern documented across most public reporting reviewed for this note, and worth distinguishing explicitly in any real investigation rather than assuming one or the other.

## Network-Layer Evidence

The one class of "target-side" evidence that's reliably present **regardless** of who owns the destination account, because it's produced by the network path itself rather than the destination's own application logging:

| Source | What it shows |
|---|---|
| Firewall/proxy logs | Outbound connection to the destination provider's IP range/domain — visible even when the account behind it is unknown |
| TLS SNI (Server Name Indication, visible in cleartext during the TLS handshake on a network sensor even though the session payload itself is encrypted) | The destination hostname (`s3.amazonaws.com`, `webdav.pcloud.com`, a self-hosted `ftp1.example.com`, etc.) — the single most useful network-layer datum for this tool, since it survives full HTTPS/TLS encryption of the actual file content |
| Zeek `ssl.log`/`x509.log`, NetFlow, or an equivalent proxy/firewall connection log | Connection duration and volume — a large, sustained outbound transfer to a cloud-storage IP range from a host with no established legitimate reason to talk to it is a coarse but genuinely useful anomaly, especially at fleet scale (see `05 - Detection and Hunting.md`) |

The core limitation: connections to major cloud-storage providers (AWS, Google, Microsoft, Dropbox) are, by design, **indistinguishable at the IP/domain level from an enormous volume of entirely legitimate traffic** — allowlisting `*.amazonaws.com` or similar is not a viable detection strategy on its own. SNI/destination-domain evidence is corroborating context for a hunt already anchored on the source-side process/command-line signal in `03`, not a standalone detection mechanism.

## Endpoint/DLP Security Product Behavior

Where a **cloud access security broker (CASB)** or DLP product with network/proxy-level visibility is deployed, it may independently flag large uploads to a cloud-storage provider from a non-browser process — this is a real, additional signal in organizations that have that specific tooling, but it's not something every environment has, and it isn't rclone-specific (it would flag any large upload from an unrecognized process). Where no such product exists, there is no target-side endpoint-security angle distinct from what `03 - Source Evidence.md` already covers on the executing host itself.

## Building a Timeline

Given how little the destination side natively contributes, timeline-building for an rclone operation is, like AdFind's, fundamentally a **source-side exercise corroborated by network-layer metadata**: `[Sysmon 1 / Security 4688 process creation for rclone/a renamed equivalent on the source host, full command line]` → `[rclone.conf read timestamp, if a saved remote was used]` → `[outbound connection + TLS SNI to the destination provider, held open for the transfer's duration — source-side netstat/EDR, or firewall/proxy/Zeek logs]` → `[--log-file contents, if present, itemizing exactly what transferred]` → `[on the file-share host, if auditing was enabled and the source data lived on a separate server: 4663/5145 object-access events in the same window]`. In most real investigations, the first three are what's actually recoverable — the destination provider's own logs and the file-share host's object-access auditing are both bonuses that depend on non-default conditions (victim ownership of the destination account; auditing enabled on the file server), not something to build a detection strategy around. See `05 - Detection and Hunting.md`'s Hunting Priority table for how this evidence shape drives which signal to hunt on first.
