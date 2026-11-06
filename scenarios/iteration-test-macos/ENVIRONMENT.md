# Meridian Healthcare Solutions — environment

This assessment variant retains the mixed enterprise environment and adds two locally managed macOS engineering workstations. There are 9 named users and 23 systems.

The collection window is November 2, 2026, 13:00–19:00 UTC (07:00–13:00 America/Chicago, CST), with two hours of warmup. The original Windows/Linux workload, six-hour duration and low baseline are preserved.

## Systems

| Host | IP | OS | Role |
| --- | --- | --- | --- |
| APP-INT-01 | 10.10.2.30 | Ubuntu 22.04 | server |
| DB-PROD-01 | 10.10.4.10 | CentOS 8 | server |
| DC-01 | 10.10.2.10 | Windows Server 2022 | domain_controller |
| DC-02 | 10.10.2.11 | Windows Server 2022 | domain_controller |
| FILE-LNX-01 | 10.10.2.21 | Ubuntu 22.04 | server |
| FILE-SRV-01 | 10.10.2.20 | Windows Server 2019 | server |
| LOG-MON-01 | 10.10.2.40 | Ubuntu 22.04 | server |
| LT-MRIVERA-02 | 10.10.1.99 | Ubuntu 22.04 | workstation |
| MAC-MROSS-01 | 10.10.1.41 | macOS 27 | workstation |
| MAC-MROSS-02 | 10.10.1.42 | macOS 27 | workstation |
| MAIL-CLIN-01 | 10.10.2.26 | Ubuntu 22.04 | server |
| MAIL-EDGE-01 | 10.10.2.25 | Ubuntu 22.04 | server |
| MAIL-FIN-01 | 10.10.2.27 | Windows Server 2022 | server |
| PROXY-01 | 10.10.3.20 | Ubuntu 22.04 | server |
| WEB-EXT-01 | 10.10.3.10 | Ubuntu 22.04 | server |
| WS-AJOHNSON-01 | 10.10.1.35 | Windows 10 Enterprise | workstation |
| WS-DRAMIREZ-01 | 10.10.1.34 | Windows 10 Enterprise | workstation |
| WS-EBROOKS-01 | 10.10.1.33 | Windows 10 Enterprise | workstation |
| WS-LNGUYEN-01 | 10.10.1.21 | Ubuntu 22.04 | workstation |
| WS-MCHEN-01 | 10.10.1.31 | Windows 11 Enterprise | workstation |
| WS-OHADDAD-01 | 10.10.1.22 | Ubuntu 22.04 | workstation |
| WS-PPATEL-01 | 10.10.1.32 | Windows 11 Enterprise | workstation |
| WS-SMARTINEZ-01 | 10.10.1.36 | Windows 10 Enterprise | workstation |

## People

| Account | Name | Primary system |
| --- | --- | --- |
| aisha.johnson | Aisha Johnson | WS-AJOHNSON-01 |
| diego.ramirez | Diego Ramirez | WS-DRAMIREZ-01 |
| evelyn.brooks | Evelyn Brooks | WS-EBROOKS-01 |
| lina.nguyen | Lina Nguyen | WS-LNGUYEN-01 |
| marcus.chen | Marcus Chen | WS-MCHEN-01 |
| maya.ross | Maya Ross | MAC-MROSS-01 |
| omar.haddad | Omar Haddad | WS-OHADDAD-01 |
| priya.patel | Priya Patel | WS-PPATEL-01 |
| sophia.martinez | Sophia Martinez | WS-SMARTINEZ-01 |

## Collection and normal operations

Corporate workstations use the corporate LAN; directory, file, mail, application and monitoring servers occupy the server VLAN. The DMZ hosts the EHR portal and explicit proxy. A separate database VLAN has its own SPAN. The existing Zeek, IDS and perimeter firewall placements are retained, with the Macs added to the corporate LAN.

The selected sources include Windows Security/Sysmon, eCAR, Linux syslog/Bash history, Zeek protocols, proxy/web records, Snort alerts, Cisco ASA, macOS Endpoint Security, Unified Log and zsh history. Native ES is the Mac process inventory. Unified Log represents selected native message families; an application start does not necessarily produce a ULF message. Native launchd ULF is outside the current collection model.

Maya Ross uses Apple Terminal on MAC-MROSS-01 and iTerm2 on MAC-MROSS-02. Her Mac accounts are local; their audit/session identifiers are separate from directory logon identifiers. Installed applications include Chrome and ordinary engineering collaboration tools. The original storage, mail, proxy and directory services remain available.

The original enterprise_standard observation profile and low baseline are retained. Source-specific collection and process coverage are recorded in each generated bundle. This environment briefing is excluded from blind reviewer inputs.

The engineering Macs have persistent, user-scoped SMB mounts for shared research,
collaboration and home storage under /Volumes. These mounts do not expand their
access to finance, administrative or domain-policy shares.
