# Lantern Works Software: environment briefing

Lantern Works Software, a fictional small software vendor with a public support portal and private database.

The modeled inventory contains 4 user accounts and 6 internal endpoints/servers. Logical sensors and third-party infrastructure are separate from that host count.

Collection window: **2026-11-09 14:00–2026-11-09 20:00 UTC** (6 hours). Local window: 2026-11-09 09:00–2026-11-09 15:00 EST; timezone America/New_York, UTC offset -0500. Emitted timestamps are UTC. A one-hour simulation warmup precedes collection.

Ordinary business hours are approximately 09:00–17:00 local time (09:00 EST corresponds to 14:00 UTC; 17:00 corresponds to 22:00 UTC). Individual staff schedules and server activity vary.

## User directory

| Account | Name | Work | Primary system |
|---|---|---|---|
| elena.rossi | Elena Rossi | Software engineering | LW-WS-03 |
| omar.rahman | Omar Rahman | Systems administration | LW-WS-04 |
| sara.bennett | Sara Bennett | Platform engineering | LW-WS-01 |
| theo.martin | Theo Martin | Platform engineering | LW-WS-02 |

## Systems

| Host | Address | Operating system | Roles |
|---|---|---|---|
| LW-DB-01 | 10.64.20.20 | Linux Ubuntu 24.04 | database |
| LW-WEB-01 | 203.0.113.44 | Linux Ubuntu 24.04 | web server, app server |
| LW-WS-01 | 10.64.10.21 | Linux Ubuntu 24.04 | workstation |
| LW-WS-02 | 10.64.10.22 | Linux Ubuntu 24.04 | workstation |
| LW-WS-03 | 10.64.10.23 | Linux Ubuntu 24.04 | workstation |
| LW-WS-04 | 10.64.10.24 | Linux Ubuntu 24.04 | workstation |

## Network and collection

- engineering: `10.64.10.0/24`, internal exposure.
- database: `10.64.20.0/24`, internal exposure.
- public-dmz: `203.0.113.0/25`, both exposure.
- lantern-core-span: network span, monitoring engineering, database, public-dmz; sources zeek.
- lantern-ids: ids span, monitoring engineering, database, public-dmz; sources snort_alert.

Selected source families: zeek, ecar, syslog, bash_history, web_access, snort_alert. Source availability also depends on host platform, deployed facilities, routing and source policy.

HTTP on the public support service is available to the DMZ sensors and web access collection. HTTPS application content remains opaque. IDS collection uses curated signature contexts rather than a complete deployed ruleset. External clients have no local endpoint telemetry.
