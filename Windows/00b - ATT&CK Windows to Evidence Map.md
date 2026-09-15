# ATT&CK Windows to Evidence Map

Reverse lookup: given a MITRE ATT&CK technique, which Windows note or artifact covers it. Verify IDs against the current Enterprise matrix — techniques and sub-technique numbering evolve.

## Contents

- [Initial Access](#initial-access)
- [Execution](#execution)
- [Persistence](#persistence)
- [Privilege Escalation](#privilege-escalation)
- [Defense Evasion](#defense-evasion)
- [Credential Access](#credential-access)
- [Discovery and Lateral Movement](#discovery-and-lateral-movement)
- [Collection and Exfiltration](#collection-and-exfiltration)
- [Command and Control](#command-and-control)
- [Impact](#impact)

## Initial Access

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Phishing: Spearphishing Attachment/Link | T1566.001/.002 | 15 - Email Forensics; Phishing and BEC Initial Access Playbook |
| Phishing: Spearphishing via Service | T1566.003 | Phishing and BEC Initial Access Playbook |
| Valid Accounts | T1078 | 05 - Users, Groups & Authentication (4624/4625, logon types); RDP Brute-Force and Foothold Playbook |
| External Remote Services (RDP) | T1133 | 12 - Lateral Movement (RDP section); RDP Brute-Force and Foothold Playbook |
| Exploit Public-Facing Application | T1190 | 11 - Event Log Analysis (Application/service logs); Windows Malware and Threat Landscape; 23/IIS - Web Server Forensics; 23/Microsoft Exchange Server Forensics (ProxyLogon/ProxyShell/ProxyNotShell-class pre-auth exploitation) |
| Drive-by Compromise | T1189 | 14/Chromium and Firefox (History, Downloads); Windows Malware and Threat Landscape |
| Replication Through Removable Media | T1091 | 09 - Removable Device (USB) Forensics |

## Execution

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Command/Scripting: PowerShell | T1059.001 | 11 - Event Log Analysis (PowerShell Operational, 4103/4104); 16 - Live Response and Volatile Data |
| Command/Scripting: Windows Command Shell | T1059.003 | 11 - Event Log Analysis (4688 Process Creation); 06/Prefetch; 06/ShimCache (AppCompatCache); 23/IIS - Web Server Forensics (`w3wp.exe → cmd.exe`); 23/SQL Server Forensics (`sqlservr.exe → cmd.exe` via `xp_cmdshell`) |
| Command/Scripting: Visual Basic | T1059.005 | 11 - Event Log Analysis (PowerShell/Office macro events); Phishing and BEC Initial Access Playbook |
| Command/Scripting: PowerShell | T1059.001 | 11 - Event Log Analysis (PowerShell Operational, 4103/4104); 16 - Live Response and Volatile Data; 23/IIS - Web Server Forensics (`w3wp.exe → powershell.exe`); 23/SCCM (Configuration Manager) Forensics (Run Scripts/CMPivot) |
| Windows Management Instrumentation | T1047 | 10/WMI Event Consumers; 12 - Lateral Movement (WMI/WMIC Remote Execution) |
| Software Deployment Tools | T1072 | 23/SCCM (Configuration Manager) Forensics (Application/Package deployment abuse — headline technique) |
| Scheduled Task/Job: Scheduled Task | T1053.005 | 10/Scheduled Tasks; 12 - Lateral Movement (Remote Scheduled Tasks); 23/SQL Server Forensics (SQL Server Agent Jobs — conceptual analog, no dedicated sub-technique) |
| Native API | T1106 | 17/Memory Analysis (Processes, Injection, Rootkits) |
| Shared Modules | T1129 | 10/DLL Hijacking; 06/Amcache (module load evidence) |
| System Services: Service Execution | T1569.002 | 10/Services; 11 - Event Log Analysis (Service Control Manager events) |
| User Execution | T1204 | 06/UserAssist; 06/Prefetch; 07 - File and Folder Opening (User Activity) |

## Persistence

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | 10/Autostart (Run-RunOnce) Keys |
| Create or Modify System Process: Windows Service | T1543.003 | 10/Services |
| Scheduled Task/Job: Scheduled Task | T1053.005 | 10/Scheduled Tasks |
| Event Triggered Execution: WMI Event Subscription | T1546.003 | 10/WMI Event Consumers |
| Hijack Execution Flow: DLL Search Order Hijacking | T1574.001 | 10/DLL Hijacking |
| Hijack Execution Flow: DLL Side-Loading | T1574.002 | 10/DLL Hijacking |
| Server Software Component: IIS/Web Shell | T1505.003 | 11 - Event Log Analysis (Application log); Windows Malware and Threat Landscape; 23/IIS - Web Server Forensics; 23/Microsoft Exchange Server Forensics (OWA/ECP web shells) |
| Server Software Component (mail transport agent — no dedicated sub-technique) | T1505 | 23/Microsoft Exchange Server Forensics (malicious Transport Agent registered into the message pipeline) |
| Server Software Component: SQL Stored Procedures | T1505.001 | 23/SQL Server Forensics (CLR assembly backdoors, startup stored procedures) |
| Account Manipulation | T1098 | 05 - Users, Groups & Authentication (Account Management events); 05b - Active Directory & Domain Forensic Artifacts; 23/SQL Server Forensics (addition to `sysadmin` role) |
| Account Manipulation: Additional Email Delegate Permissions | T1098.002 | 23/Microsoft Exchange Server Forensics (non-owner mailbox access via delegate/admin permission grants) |
| Create Account | T1136 | 05 - Users, Groups & Authentication (4720 and related Account Management events); 23/SQL Server Forensics (new SQL logins/database users) |
| Browser Extensions | T1176 | 14/Chromium (Chrome & Edge) (Extensions section) |

## Privilege Escalation

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Process Injection | T1055 | 17/Memory Analysis (Processes, Injection, Rootkits) — DLL injection, process hollowing, doppelgänging |
| Abuse Elevation Control Mechanism: Bypass UAC | T1548.002 | 04 - Registry Forensics Fundamentals (UAC keys); 11 - Event Log Analysis |
| Access Token Manipulation | T1134 | 17/Memory Analysis (Processes, Injection, Rootkits); 05 - Users, Groups & Authentication (4648 explicit credentials); 23/Kerberos Ticket Abuse Investigation (S4U2Self/S4U2Proxy delegation abuse in the live log sequence) |
| Scheduled Task/Job: Scheduled Task | T1053.005 | 10/Scheduled Tasks |
| Domain or Tenant Policy Modification: GPO | T1484.001 | GPO/05 - GPO Abuse, Hunting and Detection (full technique + consolidated hunt); GPO/00-04 for fundamentals through investigation workflow |

## Defense Evasion

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Indicator Removal: Clear Windows Event Logs | T1070.001 | 11 - Event Log Analysis (Log Clearing/Event 1102); 19 - Anti-Forensics and Evidence Destruction |
| Indicator Removal: File Deletion | T1070.004 | 08 - Deleted Items and File Existence; 19 - Anti-Forensics and Evidence Destruction |
| Indicator Removal: Timestomp | T1070.006 | NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes; 19 - Anti-Forensics and Evidence Destruction (Timestomping Detection) |
| Indicator Removal: File Deletion (Recycle Bin bypass) | T1070.004 | 08 - Deleted Items and File Existence (Recycle Bin); 19 - Anti-Forensics and Evidence Destruction (Recycle Bin Bypass) |
| Masquerading | T1036 | 06/Amcache; 06/ShimCache (AppCompatCache); 16 - Live Response and Volatile Data |
| Hijack Execution Flow: DLL Side-Loading | T1574.002 | 10/DLL Hijacking |
| Process Injection | T1055 | 17/Memory Analysis (Processes, Injection, Rootkits) |
| Rootkit | T1014 | 17/Memory Analysis (Rootkit Detection — pslist vs psscan, DKOM) |
| Obfuscated Files or Information | T1027 | 17/Memory Analysis (Malfind/YARA Scanning); 06/Amcache |
| Impair Defenses: Disable/Modify Tools | T1562.001 | 11 - Event Log Analysis (Audit Policy Change, 4719); 21 - Remediation and Containment |
| Modify Registry | T1112 | 04 - Registry Forensics Fundamentals |
| Subvert Trust Controls: Code Signing | T1553.002 | 06/Amcache; Windows Malware and Threat Landscape |
| File and Directory Permissions Modification | T1222 | NTFS/00 - NTFS Deep Dive Overview ($Secure); 19 - Anti-Forensics and Evidence Destruction |
| File and Directory Permissions Modification: Windows File and Directory Permissions Modification | T1222.001 | 23/File Server Forensics (4670 DACL-change hunt — widening effective access without a group-membership change) |
| Rogue Domain Controller | T1207 | 23/Domain Controller — Role-Specific Forensics (full depth — replication-topology/rogue-partner detection, `repadmin`) |

## Credential Access

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| OS Credential Dumping: LSASS Memory | T1003.001 | 17/Memory Analysis (Credential Theft From Memory — LSASS and Mimikatz) |
| OS Credential Dumping: NTDS | T1003.003 | 05b - Active Directory & Domain Forensic Artifacts; 23/Domain Controller — Role-Specific Forensics (host-side `ntdsutil`/VSS acquisition and theft mechanics — 05b owns offline extraction/interpretation once you have the file) |
| OS Credential Dumping: DCSync | T1003.006 | 05b - Active Directory & Domain Forensic Artifacts (DCSync / Replication Abuse) |
| OS Credential Dumping: SAM | T1003.002 | 05 - Users, Groups & Authentication (SAM Hive Account Structure) |
| Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | 05b - Active Directory & Domain Forensic Artifacts (Kerberos Abuse Techniques); 23/Kerberos Ticket Abuse Investigation (krbtgt-reset-boundary discontinuity hunt, lifetime-vs-policy check) |
| Steal or Forge Kerberos Tickets: Silver Ticket | T1558.002 | 05b - Active Directory & Domain Forensic Artifacts (Kerberos Abuse Techniques); 23/Kerberos Ticket Abuse Investigation (logon-without-a-paired-ticket-request gap-hunt — the DC-blind-spot workflow) |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | 05b - Active Directory & Domain Forensic Artifacts (Kerberos Abuse Techniques); 23/Kerberos Ticket Abuse Investigation (estate-wide RC4/distinct-SPN sweep) |
| Steal or Forge Kerberos Tickets: AS-REP Roasting | T1558.004 | 05b - Active Directory & Domain Forensic Artifacts (Kerberos Abuse Techniques); 23/Kerberos Ticket Abuse Investigation (technique comparison table) |
| Unsecured Credentials: Credentials in Files / GPP cpassword | T1552.001 / T1552.006 | 05b - Active Directory & Domain Forensic Artifacts (GPP cpassword Vulnerability) |
| Unsecured Credentials (Network Access Account / OSD task-sequence credentials) | T1552 | 23/SCCM (Configuration Manager) Forensics (NAA credential extraction; task-sequence variable credential exposure) |
| Credentials from Password Stores: Web Browsers | T1555.003 | 14/Chromium (Chrome & Edge) (Passwords & DPAPI); 14/Firefox |
| Forced Authentication | T1187 | 23/SQL Server Forensics (`xp_dirtree`/`xp_fileexist` against an attacker-controlled UNC path) |
| Brute Force | T1110 | 05 - Users, Groups & Authentication (4625 failure bursts); RDP Brute-Force and Foothold Playbook; 23/SQL Server Forensics (`sa`/SQL-authenticated login failure bursts) |
| Multi-Factor Authentication Interception/Request Generation | T1621 | 05 - Users, Groups & Authentication (Logon Types); Phishing and BEC Initial Access Playbook |

## Discovery and Lateral Movement

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Remote Services: Remote Desktop Protocol | T1021.001 | 12 - Lateral Movement (RDP); 05 - Users, Groups & Authentication (RDP Usage Tracking) |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | 12 - Lateral Movement (PsExec / SMB Admin Shares); 23/SCCM (Configuration Manager) Forensics (Client Push Installation Account); 23/File Server Forensics |
| Remote Services: Windows Remote Management | T1021.006 | 12 - Lateral Movement (PowerShell Remoting / WinRM); 11 - Event Log Analysis (WinRM/PowerShell Remoting operational logs) |
| Remote Services (SQL linked servers — no dedicated sub-technique) | T1021 | 23/SQL Server Forensics (`sys.servers`/`OPENQUERY` pivoting between SQL instances) |
| Exploitation of Remote Services | T1210 | 23/SQL Server Forensics (unauthenticated/vulnerability-based compromise of an exposed instance) |
| System Services: Service Execution (remote) | T1569.002 | 12 - Lateral Movement (Remote Services) |
| Use Alternate Authentication Material: Pass the Hash / Pass the Ticket | T1550.002/.003 | 12 - Lateral Movement (Pass-the-Hash / Pass-the-Ticket); 23/Kerberos Ticket Abuse Investigation (cross-host ticket-reuse detection workflow; theft mechanics owned by 17/Memory Analysis) |
| System Information/Network/Account Discovery | T1082/T1016/T1087 | 06/UserAssist; 16 - Live Response and Volatile Data |
| Network Share Discovery | T1135 | 12 - Lateral Movement (`net use` / Share Mapping / SMB Session Enumeration); 23/File Server Forensics |
| Remote System Discovery | T1018 | 16 - Live Response and Volatile Data; 11 - Event Log Analysis |
| File and Directory Discovery | T1083 | 07 - File and Folder Opening (User Activity); 08 - Deleted Items and File Existence (Windows Search Database); 23/File Server Forensics |

## Collection and Exfiltration

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Email Collection | T1114 | 15 - Email Forensics |
| Email Collection: Remote Email Collection | T1114.002 | 23/Microsoft Exchange Server Forensics (mailbox export abuse for bulk exfiltration) |
| Email Collection: Email Forwarding Rule | T1114.003 | 23/Microsoft Exchange Server Forensics (hidden/malicious inbox rules — BEC persistence) |
| Data from Local System | T1005 | 07 - File and Folder Opening (User Activity); 08 - Deleted Items and File Existence; 23/SQL Server Forensics (`bcp`/`OPENROWSET` mass export) |
| Data from Network Shared Drive | T1039 | 23/File Server Forensics (collection/staging directly from hosted shares) |
| Data from Cloud Storage | T1530 | 13/OneDrive, Google Drive for Desktop, Box Drive, Dropbox |
| Archive Collected Data | T1560 | 07 - File and Folder Opening (User Activity); 16 - Live Response and Volatile Data |
| Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002 | 13/OneDrive, Google Drive for Desktop, Box Drive, Dropbox |
| Exfiltration Over Alternative Protocol | T1048 | 23/File Server Forensics (bulk data movement off shares via SMB itself, outside the primary C2 channel) |
| Exfiltration Over C2 Channel | T1041 | 16 - Live Response and Volatile Data; 17/Memory Analysis (network connections from memory) |
| Automated Exfiltration | T1020 | 13/ cloud storage sync logs; 16 - Live Response and Volatile Data |

## Command and Control

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Application Layer Protocol: Web Protocols | T1071.001 | 23/IIS - Web Server Forensics (web shell C2/exfil blending into normal HTTP(S) traffic) |
| Ingress Tool Transfer | T1105 | 23/IIS - Web Server Forensics (web shell or follow-on tooling dropped/pulled via the compromised application) |

## Impact

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Data Encrypted for Impact | T1486 | Ransomware Playbook; 08 - Deleted Items and File Existence; 23/File Server Forensics (file-server-side detection query for the encryption stage) |
| Inhibit System Recovery | T1490 | 19 - Anti-Forensics and Evidence Destruction (Volume Shadow Copy Analysis — Shadow Copy Deletion); 23/File Server Forensics |
| Service Stop | T1489 | 10/Services; 11 - Event Log Analysis (Service Control Manager Events) |
| Data Destruction | T1485 | 19 - Anti-Forensics and Evidence Destruction (Secure-Delete / Wiping Tools) |
| Defacement | T1491 | 07 - File and Folder Opening (User Activity); Windows Malware and Threat Landscape |
