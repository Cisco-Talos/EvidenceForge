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
| LW-WEB-01 | 10.64.30.10 | Linux Ubuntu 24.04 | web server, app server |
| LW-WS-01 | 10.64.10.21 | Linux Ubuntu 24.04 | workstation |
| LW-WS-02 | 10.64.10.22 | Linux Ubuntu 24.04 | workstation |
| LW-WS-03 | 10.64.10.23 | Linux Ubuntu 24.04 | workstation |
| LW-WS-04 | 10.64.10.24 | Linux Ubuntu 24.04 | workstation |

## Network and collection

- engineering: `10.64.10.0/24`, internal exposure.
- database: `10.64.20.0/24`, internal exposure.
- dmz: `10.64.30.0/24`, private subnet for the support web server.
- The edge firewall routes among the three subnets and the Internet. It maps the public HTTPS address `203.0.113.44` for `support.lanternworks.example` to `LW-WEB-01`. Its outside address is `203.0.113.45`, which it also uses for engineering outbound address translation.
- `support-origin.lanternworks.example` is the private HTTPS name for the same server. The management workstation can access it from engineering. The web server can reach the database over PostgreSQL and has outbound DNS, HTTP, HTTPS and NTP access.
- `lantern-internet-tap` collects Zeek on the firewall's Internet link. `lantern-dmz-span` collects Zeek on the private DMZ. `lantern-dmz-ids` collects Snort alerts on the DMZ. `lantern-edge-firewall` collects Cisco ASA firewall records.

Selected source families are Zeek, eCAR, syslog, Bash history, web access, Snort alerts, and Cisco ASA. Source availability depends on host platform, deployed facilities, routing, and source policy.

The web server collects its own access logs. Passive sensors can observe HTTPS connection and TLS metadata, while request paths and bodies stay encrypted on the wire. The Internet TAP covers traffic traversing the Internet link. IDS collection uses curated signature contexts. External clients have no local endpoint telemetry.
