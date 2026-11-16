# Kestrel Ridge Engineering: environment briefing

Kestrel Ridge Engineering, a fictional four-person engineering group with managed Apple Silicon Macs and private Linux infrastructure.

The modeled inventory contains 4 user accounts and 6 internal endpoints/servers. Logical sensors and third-party infrastructure are separate from that host count.

Collection window: **2026-11-09 14:00–2026-11-09 22:00 UTC** (8 hours). Local window: 2026-11-09 09:00–2026-11-09 17:00 EST; timezone America/New_York, UTC offset -0500. Emitted timestamps are UTC. A one-hour simulation warmup precedes collection.

Ordinary business hours are approximately 09:00–17:00 local time (09:00 EST corresponds to 14:00 UTC; 17:00 corresponds to 22:00 UTC). Individual staff schedules and server activity vary.

## User directory

| Account | Name | Work | Primary system |
|---|---|---|---|
| alex.archer | Alex Archer | Platform engineering | KR-MAC-01 |
| linh.nguyen | Linh Nguyen | Platform engineering | KR-MAC-02 |
| mateo.reyes | Mateo Reyes | Software engineering | KR-MAC-03 |
| nadia.shah | Nadia Shah | Systems administration | KR-MAC-04 |

## Systems

| Host | Address | Operating system | Roles |
|---|---|---|---|
| KR-DNS-01 | 10.88.20.10 | Linux Ubuntu 24.04 | dns server |
| KR-MAC-01 | 10.88.10.21 | macOS 27 (arm64) | workstation |
| KR-MAC-02 | 10.88.10.22 | macOS 27 (arm64) | workstation |
| KR-MAC-03 | 10.88.10.23 | macOS 27 (arm64) | workstation |
| KR-MAC-04 | 10.88.10.24 | macOS 27 (arm64) | workstation |
| KR-REPO-01 | 10.88.20.20 | Linux Ubuntu 24.04 | web server, app server |

## Network and collection

- engineering: `10.88.10.0/24`, internal exposure.
- infrastructure: `10.88.20.0/24`, internal exposure.
- kestrel-core-span: network span, monitoring engineering, infrastructure; sources zeek.

Selected source families: macos_endpoint_security, macos_unified_log, ecar, zsh_history, zeek, syslog, web_access. Source availability also depends on host platform, deployed facilities, routing and source policy.

Native Mac collection covers the supported Endpoint Security and Unified Log families, not a full filesystem image or complete Unified Log archive. The selected endpoint and DNS sources do not establish a direct application-level query-to-process join. Noninteractive service execution does not produce interactive shell history. Native plist contents and launchd lifecycle messages are not collected by this model.
