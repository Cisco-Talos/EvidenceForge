# Cedar Vale Advisory: environment briefing

Cedar Vale Advisory, a fictional six-person financial advisory office.

The modeled inventory contains 6 user accounts and 8 internal endpoints/servers. Logical sensors and third-party infrastructure are separate from that host count.

Collection window: **2026-11-09 14:00–2026-11-09 22:00 UTC** (8 hours). Local window: 2026-11-09 09:00–2026-11-09 17:00 EST; timezone America/New_York, UTC offset -0500. Emitted timestamps are UTC. A one-hour simulation warmup precedes collection.

Ordinary business hours are approximately 09:00–17:00 local time (09:00 EST corresponds to 14:00 UTC; 17:00 corresponds to 22:00 UTC). Individual staff schedules and server activity vary.

## User directory

| Account | Name | Work | Primary system |
|---|---|---|---|
| caleb.stone | Caleb Stone | Systems administration | CVA-WS-06 |
| evan.brooks | Evan Brooks | Finance operations | CVA-WS-02 |
| lena.ortiz | Lena Ortiz | Management | CVA-WS-05 |
| marcus.reed | Marcus Reed | Finance operations | CVA-WS-04 |
| nina.torres | Nina Torres | Finance operations | CVA-WS-01 |
| priya.shah | Priya Shah | Finance operations | CVA-WS-03 |

## Systems

| Host | Address | Operating system | Roles |
|---|---|---|---|
| CVA-DC-01 | 10.61.20.10 | Windows Server 2022 | domain controller, dns server |
| CVA-MAIL-01 | 10.61.20.20 | Linux Ubuntu 24.04 | mail server |
| CVA-WS-01 | 10.61.10.21 | Windows 11 | workstation |
| CVA-WS-02 | 10.61.10.22 | Windows 11 | workstation |
| CVA-WS-03 | 10.61.10.23 | Windows 11 | workstation |
| CVA-WS-04 | 10.61.10.24 | Windows 11 | workstation |
| CVA-WS-05 | 10.61.10.25 | Windows 11 | workstation |
| CVA-WS-06 | 10.61.10.26 | Windows 11 | workstation |

## Network and collection

- The office LAN (`10.61.10.0/24`) and server LAN (`10.61.20.0/24`) use `cedar-core` as their gateway at `10.61.10.1` and `10.61.20.1`, respectively. The core routes traffic between the two LANs.
- Internet traffic crosses `core-edge-transit` (`10.61.254.0/30`) between `cedar-core` (`10.61.254.2`) and `cedar-edge-fw` (`10.61.254.1`). The firewall provides outbound address translation and maps inbound SMTP on `203.0.113.25` to `CVA-MAIL-01`.
- `cedar-office-zeek` collects Zeek logs in both directions on the `office-access` link between the office LAN and the core. It covers routed office traffic, including traffic to the server LAN. Same-subnet traffic and link-local broadcasts stay on their LANs.
- `cedar-transit-zeek` and `cedar-transit-ids` observe the core–firewall transit link in both directions and provide Zeek logs and Snort fast alerts, respectively. Office Internet flows may appear in both Zeek sources. Traffic confined to the server LAN is outside both TAPs' coverage.
- `cedar-edge-fw` provides Cisco ASA firewall and NAT logs for traffic it handles.

Selected source families include Windows, Zeek, eCAR, syslog, Snort alerts, and Cisco ASA. Source availability also depends on host platform, deployed facilities, routing and source policy.

Mail content is available through the configured message artifacts. STARTTLS relay and IMAPS mailbox access remain opaque to network protocol inspection. No external supplier endpoint collection is modeled.

## Mail

Accepted domains: cedarvale.example.
- primary: mail.cedarvale.example on CVA-MAIL-01; generic_smtp.

Message-artifact policy: all. IMAPS/OWA access remains encrypted. A mailbox session is not a per-message read receipt.
