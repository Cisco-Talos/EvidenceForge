# Meridian Healthcare Solutions — Environment Summary

## Overview

Meridian Healthcare Solutions is a mid-size healthcare IT company (~120 employees) providing EHR integration services. The corporate HQ includes an on-premises data center supporting development, operations, and client-facing services.

- **Timezone:** America/Chicago (Central Time, UTC-6)
- **All log timestamps are in UTC.** Business hours are approximately 14:00–00:00 UTC (8:00 AM – 6:00 PM Central).
- **Data window:** 2024-03-18T12:00:00Z to 2024-03-19T02:00:00Z (14 hours)
- **Approximate environment size:** 17 users, 24 systems/devices

## User Directory

| Username | Full Name | Email | Role | Department | Primary System |
|----------|-----------|-------|------|------------|----------------|
| angela.morrison | Angela Morrison | angela.morrison@meridianhcs.com | Sales Representative | Sales | WS-SALES-01 |
| brian.kowalski | Brian Kowalski | brian.kowalski@meridianhcs.com | Accountant | Finance | WS-FIN-01 |
| charles.whitfield | Charles Whitfield | charles.whitfield@meridianhcs.com | Chief Operating Officer | Executive | WS-EXEC-01 |
| derek.hamill | Derek Hamill | derek.hamill@meridianhcs.com | Legal Counsel | Legal | WS-LEGAL-01 |
| diana.reyes | Diana Reyes | diana.reyes@meridianhcs.com | Security Analyst | Security | WS-SEC-01 |
| emily.jacobs | Emily Jacobs | emily.jacobs@meridianhcs.com | Business Analyst | Business Operations | WS-ANALYST-01 |
| james.abara | James Abara | james.abara@meridianhcs.com | HR Specialist | Human Resources | WS-HR-01 |
| kevin.tran | Kevin Tran | kevin.tran@meridianhcs.com | Help Desk Technician | IT Operations | WS-HELP-01 |
| lisa.fernandez | Lisa Fernandez | lisa.fernandez@meridianhcs.com | Project Manager | Project Management | WS-PM-01 |
| marcus.chen | Marcus Chen | marcus.chen@meridianhcs.com | Software Engineer | Engineering | WS-DEV-01 |
| maria.santos | Maria Santos | maria.santos@meridianhcs.com | Receptionist | Front Desk | WS-FRONT-01 |
| nina.volkov | Nina Volkov | nina.volkov@meridianhcs.com | Marketing Coordinator | Marketing | WS-MKT-01 |
| priya.dasgupta | Priya Dasgupta | priya.dasgupta@meridianhcs.com | Data Analyst | Data Analytics | WS-DATA-01 |
| raj.subramanian | Raj Subramanian | raj.subramanian@meridianhcs.com | Software Engineer | Engineering | WS-DEV-03 |
| sarah.oconnell | Sarah O'Connell | sarah.oconnell@meridianhcs.com | Software Engineer | Engineering | WS-DEV-02 |
| tom.nakamura | Tom Nakamura | tom.nakamura@meridianhcs.com | System Administrator | IT Operations | WS-IT-01 |
| tyler.brooks | Tyler Brooks | tyler.brooks@meridianhcs.com | Engineering Intern | Engineering | WS-INTERN-01 |

**Service accounts:** svc_backup, svc_monitor, svc_sqlreader

## Systems Inventory

| Hostname | IP Address | OS | Type | Services |
|----------|------------|-----|------|----------|
| DC-01 | 10.10.2.10 | Windows Server 2022 | Domain Controller | Active Directory, DNS, DHCP |
| FILE-SRV-01 | 10.10.2.11 | Windows Server 2019 | File Server | SMB, DFS |
| WEB-EXT-01 | 10.10.3.10 | Ubuntu 22.04 | Web Server | Apache, PHP |
| PROXY-01 | 10.10.3.11 | Ubuntu 22.04 | Proxy Server | Squid |
| APP-INT-01 | 10.10.2.20 | Ubuntu 22.04 | Application Server | Tomcat, Java |
| DB-PROD-01 | 10.10.4.10 | CentOS 7 | Database Server | MySQL |
| LOG-SRV-01 | 10.10.2.21 | Ubuntu 22.04 | Log Server | Elasticsearch, Logstash |
| WS-DEV-01 | 10.10.1.10 | Windows 11 | Workstation | — |
| WS-DEV-02 | 10.10.1.11 | Windows 10 | Workstation | — |
| WS-DEV-03 | 10.10.1.12 | Ubuntu 22.04 | Workstation | — |
| WS-IT-01 | 10.10.1.20 | Windows 10 | Workstation | — |
| WS-SEC-01 | 10.10.1.21 | Ubuntu 22.04 | Workstation | — |
| WS-FIN-01 | 10.10.1.30 | Windows 10 | Workstation | — |
| WS-DATA-01 | 10.10.1.31 | Ubuntu 22.04 | Workstation | — |
| WS-EXEC-01 | 10.10.1.40 | Windows 11 | Workstation | — |
| WS-PM-01 | 10.10.1.41 | Windows 10 | Workstation | — |
| WS-HR-01 | 10.10.1.42 | Windows 10 | Workstation | — |
| WS-SALES-01 | 10.10.1.43 | Windows 10 | Workstation | — |
| WS-LEGAL-01 | 10.10.1.44 | Windows 10 | Workstation | — |
| WS-MKT-01 | 10.10.1.45 | Windows 10 | Workstation | — |
| WS-FRONT-01 | 10.10.1.46 | Windows 10 | Workstation | — |
| WS-HELP-01 | 10.10.1.47 | Windows 10 | Workstation | — |
| WS-ANALYST-01 | 10.10.1.48 | Windows 10 | Workstation | — |
| WS-INTERN-01 | 10.10.1.49 | Windows 10 | Workstation | — |

## Network Topology

### Subnets

| Segment | CIDR | Description |
|---------|------|-------------|
| corporate_lan | 10.10.1.0/24 | Corporate workstation network |
| server_vlan | 10.10.2.0/24 | Internal servers (DC, file server, app server, log server) |
| dmz | 10.10.3.0/24 | DMZ — web-facing services (web server, proxy) |
| database_vlan | 10.10.4.0/24 | Database segment |

### Network Sensors

| Sensor | Type | Placement | Monitors | Direction | Formats |
|--------|------|-----------|----------|-----------|---------|
| zeek-core | Network | SPAN | corporate_lan, server_vlan | Bidirectional | Zeek |
| zeek-dmz | Network | SPAN | dmz | Bidirectional | Zeek |
| snort-perimeter | IDS | TAP | dmz | Inbound | Snort Alert |
| fw-perimeter | Firewall | TAP | corporate_lan, server_vlan, dmz | Bidirectional | Cisco ASA |

- **zeek-core** monitors all traffic within and between the corporate workstation network and server VLAN via a SPAN port on the core switch.
- **zeek-dmz** monitors all traffic within the DMZ segment via a dedicated SPAN port.
- **snort-perimeter** monitors inbound traffic entering the DMZ from external sources via a network TAP.
- **fw-perimeter** is a Cisco ASA firewall monitoring traffic across the corporate LAN, server VLAN, and DMZ segments.

## Available Data Sources

| Log Format | Description |
|------------|-------------|
| Windows Security Events | Authentication, process execution, account management, Kerberos |
| Windows Sysmon | Process creation/termination, remote thread injection, process access, DNS queries |
| Zeek (13 log types) | conn, dns, http, ssl, files, x509, dhcp, ntp, weird, pe, ocsp, packet_filter, reporter |
| eCAR | EDR/XDR telemetry (PROCESS, FILE, FLOW, REGISTRY, MODULE, THREAD, USER_SESSION, SERVICE) |
| Syslog | Linux authentication and system logs |
| Bash History | Per-user timestamped command history |
| Snort Alert | IDS alerts in fast alert format |
| Cisco ASA | Firewall logs (built/teardown, deny, NAT translation) |
| Web Access | Apache/Nginx combined access log format |
| Proxy Access | Forward proxy access log (Squid W3C Extended format) |
