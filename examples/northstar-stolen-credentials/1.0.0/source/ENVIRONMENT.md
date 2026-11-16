# Northstar Health: environment briefing

Northstar Health, a fictional regional care provider.

The modeled inventory contains 5 user accounts and 9 internal endpoints/servers. Logical sensors and third-party infrastructure are separate from that host count.

Collection window: **2026-11-09 15:00–2026-11-09 23:00 UTC** (8 hours). Local window: 2026-11-09 09:00–2026-11-09 17:00 CST; timezone America/Chicago, UTC offset -0600. Emitted timestamps are UTC. A one-hour simulation warmup precedes collection.

Ordinary business hours are approximately 09:00–17:00 local time (09:00 CST corresponds to 15:00 UTC; 17:00 corresponds to 23:00 UTC). Individual staff schedules and server activity vary.

## User directory

| Account | Name | Work | Primary system |
|---|---|---|---|
| daniel.kim | Daniel Kim | IT operations | NSH-IT-01 |
| ethan.brooks | Ethan Brooks | IT operations | NSH-IT-02 |
| jordan.lee | Jordan Lee | Clinical coordination | NSH-CLIN-LNX-01 |
| maya.patel | Maya Patel | Clinical coordination | NSH-CLIN-01 |
| sofia.martinez | Sofia Martinez | Clinical coordination | NSH-CLIN-02 |

## Systems

| Host | Address | Operating system | Roles |
|---|---|---|---|
| NSH-CLIN-01 | 10.42.10.21 | Windows 11 | workstation |
| NSH-CLIN-02 | 10.42.10.22 | Windows 11 | workstation |
| NSH-CLIN-LNX-01 | 10.42.10.41 | Linux Ubuntu 24.04 | workstation |
| NSH-DC-01 | 10.42.20.10 | Windows Server 2022 | domain controller, dns server |
| NSH-FILE-01 | 10.42.20.20 | Windows Server 2022 | file server |
| NSH-IT-01 | 10.42.10.31 | Windows 11 | workstation |
| NSH-IT-02 | 10.42.10.32 | Windows 11 | workstation |
| NSH-MAIL-01 | 10.42.20.30 | Linux Ubuntu 24.04 | mail server |
| NSH-SAMBA-01 | 10.42.20.40 | Linux Ubuntu 24.04 | smb server |

## Network and collection

- clinical_lan: `10.42.10.0/24`, internal exposure.
- server_lan: `10.42.20.0/24`, internal exposure.
- northstar-core-span: network span, monitoring clinical_lan, server_lan; sources zeek.
- northstar-edge-fw: firewall tap, monitoring clinical_lan, server_lan; sources cisco_asa.

Selected source families: windows, zeek, ecar, syslog, cisco_asa. Source availability also depends on host platform, deployed facilities, routing and source policy.

The core SPAN covers the clinical and server networks. Windows file-server auditing and Linux Samba/syslog collection are host-local. Linux mounted-CIFS access has no universal per-file client syslog. Network Kerberos/NTLM protocol logs are not part of this source set.

## Mail

Accepted domains: northstarhealth.lab.
- primary: mail.northstarhealth.lab on NSH-MAIL-01; generic_smtp.

Message-artifact policy: storyline. IMAPS/OWA access remains encrypted. A mailbox session is not a per-message read receipt.

## Shared storage

- NSH-FILE-01.clinical_ops: `ClinicalOps`, standard server audit policy.
- NSH-SAMBA-01.clinical_archive: `ClinicalArchive`, high server audit policy.
- Mapping clinical_ops_drive: NSH-FILE-01.clinical_ops, presented as `H:`.
- Mapping clinical_archive_mapping: NSH-SAMBA-01.clinical_archive, presented as `I:`.
