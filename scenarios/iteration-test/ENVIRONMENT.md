# Meridian Healthcare Solutions Environment Summary

## Overview

Meridian Healthcare Solutions is a mid-size healthcare IT company providing EHR
integration services from a corporate headquarters with an on-premises data center,
redundant Active Directory, mixed Windows and Linux workstations, a small DMZ, and
internal application, database, cross-platform file, proxy, mail, and monitoring
infrastructure.

This assessment variant provides bidirectional network visibility across the corporate,
server, DMZ, and database segments. It also includes a Samba research store and a
centralized Linux monitoring host so endpoint, storage, authentication, and network
evidence can be compared across platforms.

- **Timezone:** America/Chicago
- **All log timestamps are in UTC.**
- **Data window:** 2024-03-18T12:00:00Z to 2024-03-18T18:00:00Z
- **Approximate environment size:** 8 named users and 21 modeled systems/devices

## User Directory

| Username | Full Name | Email | Role | Department | Primary System |
|----------|-----------|-------|------|------------|----------------|
| aisha.johnson | Aisha Johnson | aisha.johnson@meridianhcs.com | Help Desk | IT Support | WS-AJOHNSON-01 |
| diego.ramirez | Diego Ramirez | diego.ramirez@meridianhcs.com | Accountant | Finance | WS-DRAMIREZ-01 |
| evelyn.brooks | Evelyn Brooks | evelyn.brooks@meridianhcs.com | Executive | Executives | WS-EBROOKS-01 |
| lina.nguyen | Lina Nguyen | lina.nguyen@meridianhcs.com | Software Engineer | Engineering | WS-LNGUYEN-01 |
| marcus.chen | Marcus Chen | marcus.chen@meridianhcs.com | System Administrator | IT Administration | WS-MCHEN-01 |
| omar.haddad | Omar Haddad | omar.haddad@meridianhcs.com | Data Analyst | Analytics | WS-OHADDAD-01 |
| priya.patel | Priya Patel | priya.patel@meridianhcs.com | Security Analyst | Security | WS-PPATEL-01 |
| sophia.martinez | Sophia Martinez | sophia.martinez@meridianhcs.com | Sales Representative | Sales | WS-SMARTINEZ-01 |

## Systems Inventory

| Hostname | IP Address | OS | Type | Services |
|----------|------------|----|------|----------|
| DC-01 | 10.10.2.10 | Windows Server 2022 | Domain controller | AD DS, DNS, Kerberos, LDAP, SMB, W32Time, DHCP |
| DC-02 | 10.10.2.11 | Windows Server 2022 | Domain controller | AD DS, DNS, Kerberos, LDAP, SMB, W32Time |
| FILE-SRV-01 | 10.10.2.20 | Windows Server 2019 | Server | SMB |
| FILE-LNX-01 | 10.10.2.21 | Ubuntu 22.04 | Server | Samba, SMB, SSH, syslog |
| MAIL-EDGE-01 | 10.10.2.25 | Ubuntu 22.04 | Server | SMTP, IMAPS, Postfix, Dovecot |
| MAIL-CLIN-01 | 10.10.2.26 | Ubuntu 22.04 | Server | SMTP, IMAPS, Postfix, Dovecot |
| MAIL-FIN-01 | 10.10.2.27 | Windows Server 2022 | Server | SMTP, OWA, IMAPS, Exchange |
| APP-INT-01 | 10.10.2.30 | Ubuntu 22.04 | Server | SSH, Gunicorn, CIFS, smbclient |
| LOG-MON-01 | 10.10.2.40 | Ubuntu 22.04 | Server | rsyslog, Elasticsearch, SSH, resolver |
| WEB-EXT-01 | 10.10.3.10 | Ubuntu 22.04 | Server | Apache, PHP-FPM, SSH |
| PROXY-01 | 10.10.3.20 | Ubuntu 22.04 | Server | Squid, SSH |
| DB-PROD-01 | 10.10.4.10 | CentOS 8 | Server | MySQL, SSH |
| WS-LNGUYEN-01 | 10.10.1.21 | Ubuntu 22.04 | Workstation | SSH, CIFS, smbclient |
| WS-OHADDAD-01 | 10.10.1.22 | Ubuntu 22.04 | Workstation | SSH, CIFS, smbclient |
| WS-MCHEN-01 | 10.10.1.31 | Windows 11 Enterprise | Workstation | DNS client, W32Time |
| WS-PPATEL-01 | 10.10.1.32 | Windows 11 Enterprise | Workstation | DNS client, W32Time |
| WS-EBROOKS-01 | 10.10.1.33 | Windows 10 Enterprise | Workstation | DNS client, W32Time |
| WS-DRAMIREZ-01 | 10.10.1.34 | Windows 10 Enterprise | Workstation | DNS client, W32Time |
| WS-AJOHNSON-01 | 10.10.1.35 | Windows 10 Enterprise | Workstation | DNS client, W32Time |
| WS-SMARTINEZ-01 | 10.10.1.36 | Windows 10 Enterprise | Workstation | DNS client, W32Time |
| LT-MRIVERA-02 | 10.10.1.99 | Ubuntu 22.04 | Workstation | DHCP client, SSH, CIFS, smbclient |

## File Storage

`FILE-SRV-01` uses an NTFS data volume mounted at `D:\` and a ReFS archive volume
mounted below `C:\Mounts\Archive\`. The generated collaboration and home-directory
shares, plus the explicit Finance share, use the data volume. The ClinicalExports
share uses the folder-mounted archive volume and requires SMB encryption.

`FILE-LNX-01` uses an XFS volume rooted at `/srv/samba` with high server auditing.
Its `ClinicalResearch` Samba share contains seeded study, runbook, and integration
metadata. Engineering and Analytics have persistent per-user CIFS mappings at
`/mnt/clinical-research`; the mobile synchronization path is an on-demand
`/mnt/mhsync` mapping that always authenticates as `svc_mhsync`.

| Share | Server path | Purpose | Access summary | Presentation |
|-------|-------------|---------|----------------|--------------|
| Finance | `D:\Departments\Finance` | Department working files | Finance modify; domain administrators administer; Sales denied | Persistent `F:` mapping for Finance on `WS-DRAMIREZ-01`, otherwise UNC |
| ClinicalExports | `C:\Mounts\Archive\Clinical\Exports` | Deidentified clinical exports and audit samples | Analytics modify; domain administrators administer | UNC; encrypted SMB |
| ClinicalResearch | `/srv/samba/ClinicalResearch` | Clinical studies and integration working files | Engineering, Analytics, and Security read; Engineering, Analytics, and `svc_mhsync` modify; domain administrators administer; Sales denied | CIFS mount or direct SMB |
| Collaboration | Generated under `D:\` | General team collaboration | Preset-derived effective access | UNC |
| Homes | Generated under `D:\` | User home directories | Preset-derived effective access | UNC |

Domain-controller SYSVOL and NETLOGON storage is generated deterministically for
both `DC-01` and `DC-02`. DHCP remains exclusive to `DC-01`. File catalogs are
metadata-only, seed-stable, and independent of the six-hour collection duration.

## Network Topology

| Segment | CIDR | Description |
|---------|------|-------------|
| corporate_lan | 10.10.1.0/24 | Corporate workstation network |
| server_vlan | 10.10.2.0/24 | Internal server VLAN |
| dmz | 10.10.3.0/24 | Internet-facing DMZ |
| database_vlan | 10.10.4.0/24 | Database VLAN with dedicated bidirectional SPAN collection |

Public CIDR: `203.14.220.0/28`

## Email Topology

Accepted mail domains are `meridianhcs.com` and `research.meridianhcs.com`.
Mailbox placement uses `MAIL-EDGE-01` by default, with engineering and analytics
mailboxes on `MAIL-CLIN-01`, and finance and executive mailboxes on `MAIL-FIN-01`.
Outbound mail can route through the edge server and smart-host relays; inbound
internet mail enters through `MAIL-EDGE-01`.

## Network Sensors

| Sensor | Type | Placement | Monitors | Direction | Formats |
|--------|------|-----------|----------|-----------|---------|
| zeek-core | Network | SPAN | corporate_lan, server_vlan | bidirectional | Zeek |
| zeek-dmz | Network | SPAN | dmz | bidirectional | Zeek |
| zeek-db | Network | SPAN | database_vlan | bidirectional | Zeek |
| snort-perimeter | IDS | TAP | dmz | bidirectional | Snort alerts |
| snort-core | IDS | SPAN | corporate_lan, server_vlan | bidirectional | Snort alerts |
| fw-perimeter | Firewall | TAP | corporate_lan, server_vlan, dmz | bidirectional | Cisco ASA |

## Available Data Sources

| Log Format | Description |
|------------|-------------|
| windows | Windows Security and Sysmon-style endpoint events |
| zeek | Zeek network logs, including SMTP, DNS, SSL, files, HTTP, and connections |
| ecar | Simulated endpoint detection and response telemetry |
| syslog | Linux system, SSH, mail, and service logs |
| bash_history | Linux user shell history |
| snort_alert | IDS alert records |
| cisco_asa | Firewall allow/deny and NAT records |
| web_access | Web server access logs |
| proxy_access | Explicit forward proxy access logs |
