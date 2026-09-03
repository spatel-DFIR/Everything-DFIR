# SoftPerfect Network Scanner — Hands-On Use Cases

Every scenario below expands an entry from `01 - Overview.md`'s Quick Use-Case List, with a full command sequence (verified against the official [command-line manual](https://www.softperfect.com/products/networkscanner/manual/command-line.htm)) and its MITRE ATT&CK ID(s).

## Contents
- [Baseline Unauthenticated Sweep](#baseline-unauthenticated-sweep)
- [Authenticated Deep Scan via WMI/Remote Registry](#authenticated-deep-scan-via-wmiremote-registry)
- [SNMP Enumeration of Non-Windows Infrastructure](#snmp-enumeration-of-non-windows-infrastructure)
- [SSH Querying of Linux/Unix/Appliance Targets](#ssh-querying-of-linuxunixappliance-targets)
- [Silent Scheduled Sweep via Task Scheduler](#silent-scheduled-sweep-via-task-scheduler)
- [Continuous Background Monitoring](#continuous-background-monitoring)
- [Config-File-Driven Repeatable Scans](#config-file-driven-repeatable-scans)
- [Exporting Directly to a SQLite Database](#exporting-directly-to-a-sqlite-database)
- [Column-Filtered Export for a Minimal Target List](#column-filtered-export-for-a-minimal-target-list)
- [Fleet-Wide Wake-on-LAN Before a Mass Operation](#fleet-wide-wake-on-lan-before-a-mass-operation)
- [Renaming the Binary to Blend Into Administrative Activity](#renaming-the-binary-to-blend-into-administrative-activity)
- [Chained Workflow: Feeding Authenticated Findings into Lateral Movement](#chained-workflow-feeding-authenticated-findings-into-lateral-movement)

---

## Baseline Unauthenticated Sweep

**MITRE ATT&CK:** T1046 (Network Service Discovery), T1018 (Remote System Discovery)

```
netscan.exe /range:192.168.0.1-192.168.10.254
```

No credentials, no config file — an ICMP/ARP + port sweep identical in spirit to `Advanced IP Scanner/`'s default behavior, just with a genuinely documented CLI to drive it non-interactively from the first command.

## Authenticated Deep Scan via WMI/Remote Registry

**MITRE ATT&CK:** T1018, T1082 (System Information Discovery), T1069 (Permission Groups Discovery), T1552 (Unsecured Credentials — for what a WMI/registry pull can surface)

```
:: GUI: Options → Credential Manager → add a domain admin/local-admin
:: credential, then select it under the WMI/Registry scan-option tabs
:: before running the sweep
```

Once configured, every reachable Windows host in the range returns installed software, running services, local group membership, and remote-registry-exposed configuration data — this is the deep-enumeration capability `Advanced IP Scanner/` structurally lacks, and it requires a real, already-obtained privileged credential rather than nothing at all.

## SNMP Enumeration of Non-Windows Infrastructure

**MITRE ATT&CK:** T1046, T1018

```
:: GUI: enable the SNMP scan option, supply a community string
:: (default "public" is a common finding worth checking first)
```

Surfaces switches, printers, UPS units, and other SNMP-speaking infrastructure with no Windows agent to query at all — useful for mapping network topology beyond just Windows endpoints, and for finding devices still running a default/weak community string.

## SSH Querying of Linux/Unix/Appliance Targets

**MITRE ATT&CK:** T1018, T1082

```
:: GUI: supply SSH credentials via Credential Manager, enable the
:: SSH remote-query option for the target range
```

Extends the same authenticated-enumeration model to non-Windows hosts in a mixed environment — one tool, one credential store, covering both a Windows Active Directory estate and its Linux/appliance neighbors in the same sweep.

## Silent Scheduled Sweep via Task Scheduler

**MITRE ATT&CK:** T1046, T1053.005 (Scheduled Task/Job: Scheduled Task — for the persistence mechanism hosting the recurring scan, cross-linked to `LOLBins/schtasks/`)

```
netscan.exe /hide /auto:"C:\Windows\Temp\netscan_results.xml" /range:v4
```

No window ever appears; a scheduled task calling this line on a recurring basis gives an operator a standing, low-visibility recon capability that regenerates fresh results on its own schedule — pair with `LOLBins/schtasks/`'s own hunting guidance for the task-registration side of this chain.

## Continuous Background Monitoring

**MITRE ATT&CK:** T1046

```
netscan.exe /hide /live:"C:\Windows\Temp\netscan_live.xml"
```

Keeps the application resident and re-scans continuously, overwriting the export file after every round — closer to a standing situational-awareness feed than a one-shot recon action, useful for an operator wanting to notice new hosts appearing on a network over an extended dwell period.

## Config-File-Driven Repeatable Scans

**MITRE ATT&CK:** T1046, T1552 (for the credential material a config file may reference)

```
netscan.exe /hide /config:netscan.xml /mpass:secretpassword /range:192.168.1.0-192.168.1.254 /auto:"result.csv"
```

`/config` loads a pre-built scan profile (columns, enabled query types, credential references); `/mpass` supplies the master password non-interactively so the whole chain runs unattended even against an encrypted config — the automation-grade equivalent of a saved, reusable operator playbook.

## Exporting Directly to a SQLite Database

**MITRE ATT&CK:** T1046, T1560 (Archive Collected Data — loosely, for the structured-output angle)

```
netscan.exe /hide /auto:"C:\Windows\Temp\inventory.db" /range:all
```

A `.db` extension on `/auto`/`/live` writes a genuine SQLite database rather than a flat file — useful for an operator who wants to query/join scan results programmatically rather than parse XML/CSV, and a distinct forensic artifact type from the flat-file exports covered in `03 - Source Evidence.md`.

## Column-Filtered Export for a Minimal Target List

**MITRE ATT&CK:** T1046

```
netscan.exe /hide /auto:result.csv /cols:"Host Name;MAC Address;IP Address"
```

Strips the export down to exactly the fields needed for a handoff to another tool, rather than the full enumerated dataset — a smaller, more surgical target list, and a smaller forensic artifact to find later.

## Fleet-Wide Wake-on-LAN Before a Mass Operation

**MITRE ATT&CK:** T1018

```
netscan.exe /wolfile:mac_list.txt
```

Identical operational need to `Advanced IP Scanner/`'s Wake-on-LAN use case — bring sleeping endpoints online ahead of a scheduled mass action — but scriptable in one line against a pre-built MAC list rather than a GUI multi-select.

## Renaming the Binary to Blend Into Administrative Activity

**MITRE ATT&CK:** T1036.005 (Masquerading: Match Legitimate Name or Location)

```
copy netscan.exe C:\Intel.exe
C:\Intel.exe /hide /auto:"C:\Windows\Temp\results.xml" /range:all
```

Directly documented by CISA's Black Basta advisory — affiliates rename the binary to something innocuous (`Intel`, `Dell`) and drop it at the root of `C:\`, relying on a filename-only glance to pass unnoticed. Per `01 - Overview.md`'s red-flag callout, this defeats a filename-based hunt but not the PE's own `FileDescription`/`ProductName` metadata (`04 - Target Evidence.md`, `05 - Detection and Hunting.md`).

## Chained Workflow: Feeding Authenticated Findings into Lateral Movement

**MITRE ATT&CK:** T1046 → T1021/T1570 (Lateral Tool Transfer) downstream

```
:: Export the WMI/registry deep-scan results including local admin
:: group membership and running services, then hand the resulting
:: host list to a credential-based execution tool already in this repo
netscan.exe /hide /auto:"deep_scan.csv" /cols:"Host Name;IP Address;OS;Local Groups" /range:all
:: → feed deep_scan.csv into Impacket/wmiexec/ or Impacket/psexec/
:: using the same credential already validated by this scan's own
:: successful WMI/registry query
```

Because NetScan's authenticated query **already proved the credential works** against a given host (a successful WMI/registry pull is itself a validated-auth signal), this chain skips a separate credential-validation step other lateral-movement workflows would otherwise need.
