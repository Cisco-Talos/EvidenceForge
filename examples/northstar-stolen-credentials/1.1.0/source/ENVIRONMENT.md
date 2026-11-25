# Northstar Health: environment briefing

Northstar Health, a fictional regional care provider.

The modeled inventory contains 7 user accounts and 11 workstations and servers. The network has two logical sensors.

Collection window: **2026-11-09 15:00–2026-11-09 23:00 UTC** (8 hours). Local window: 2026-11-09 09:00–2026-11-09 17:00 CST; timezone America/Chicago, UTC offset -0600. Emitted timestamps are UTC. A one-hour simulation warmup precedes collection.

Ordinary business hours are approximately 09:00–17:00 local time (09:00 CST corresponds to 15:00 UTC; 17:00 corresponds to 23:00 UTC). Individual staff schedules and server activity vary.

## User directory

| Account | Name | Work | Primary system |
|---|---|---|---|
| daniel.kim | Daniel Kim | IT operations | NSH-IT-01 |
| daniel.kim-admin | Daniel Kim | Infrastructure administration | NSH-ADMIN-01 |
| ethan.brooks | Ethan Brooks | IT operations | NSH-IT-02 |
| ethan.brooks-admin | Ethan Brooks | Infrastructure administration | NSH-ADMIN-01 |
| jordan.lee | Jordan Lee | Clinical coordination | NSH-CLIN-LNX-01 |
| maya.patel | Maya Patel | Clinical coordination | NSH-CLIN-01 |
| sofia.martinez | Sofia Martinez | Clinical coordination | NSH-CLIN-02 |

## Systems

| Host | Address | Operating system | Roles |
|---|---|---|---|
| NSH-ADMIN-01 | 10.42.60.21 | Windows 11 | privileged administration workstation |
| NSH-CLIN-01 | 10.42.10.21 | Windows 11 | workstation |
| NSH-CLIN-02 | 10.42.10.22 | Windows 11 | workstation |
| NSH-CLIN-LNX-01 | 10.42.10.41 | Linux Ubuntu 24.04 | workstation |
| NSH-DC-01 | 10.42.30.10 | Windows Server 2022 | domain controller, DNS server |
| NSH-FILE-01 | 10.42.20.20 | Windows Server 2022 | file server |
| NSH-IT-01 | 10.42.50.31 | Windows 11 | workstation |
| NSH-IT-02 | 10.42.50.32 | Windows 11 | workstation |
| NSH-MAIL-01 | 10.42.40.30 | Linux Ubuntu 24.04 | mailbox server |
| NSH-RELAY-01 | 10.42.70.25 | Linux Ubuntu 24.04 | SMTP relay |
| NSH-SAMBA-01 | 10.42.20.40 | Linux Ubuntu 24.04 | smb server |

## Network and collection

- `clinical_lan` (`10.42.10.0/24`) hosts clinical workstations.
- `storage_lan` (`10.42.20.0/24`) hosts the Windows file server and Samba archive server.
- `identity_lan` (`10.42.30.0/24`) hosts Active Directory and internal DNS.
- `mail_lan` (`10.42.40.0/24`) hosts internal mailboxes.
- `it_lan` (`10.42.50.0/24`) hosts IT staff workstations.
- `management_lan` (`10.42.60.0/24`) hosts the privileged administration workstation.
- `mail_dmz` (`10.42.70.0/24`) hosts the Internet-facing SMTP relay.

Selected source families: windows, zeek, ecar, syslog, cisco_asa. Source availability also depends on host platform, deployed facilities, routing and source policy.

The stateful firewall, NSH-EDGE-01, routes traffic between the seven segments and to the Internet. Its policy denies traffic by default and permits specific flows. Outbound HTTPS from the clinical and IT networks uses port address translation at `203.0.113.42`. Inbound SMTP reaches NSH-RELAY-01 through static NAT at `203.0.113.43`.

The `northstar-core-span` sensor provides Zeek coverage of all seven segments. The `northstar-edge-fw` tap provides Cisco ASA logs for traffic handled by NSH-EDGE-01. Windows file-server auditing and Linux Samba/syslog collection are host-local. Linux mounted-CIFS access has no universal per-file client syslog. Network Kerberos/NTLM protocol logs are not part of this source set.

## Mail

The modeled mail domain is `northstarhealth.lab`. Inbound SMTP flows through `mx.northstarhealth.lab` on NSH-RELAY-01 to `mail.northstarhealth.lab` on NSH-MAIL-01. Outbound mail uses the same relay.

Message-artifact policy: storyline. IMAPS/OWA access remains encrypted. A mailbox session is not a per-message read receipt.

## Shared storage

- NSH-FILE-01.clinical_ops: `ClinicalOps`, standard server audit policy.
- NSH-SAMBA-01.clinical_archive: `ClinicalArchive`, high server audit policy.
- Mapping clinical_ops_drive: NSH-FILE-01.clinical_ops, presented as `H:`.
- Mapping clinical_archive_mapping: NSH-SAMBA-01.clinical_archive, presented as `I:`.
