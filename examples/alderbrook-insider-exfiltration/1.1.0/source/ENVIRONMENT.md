# Alderbrook Lending: environment briefing

Alderbrook Lending, a fictional eight-person commercial lending team using a shared review repository.

The modeled inventory contains 8 user accounts and 10 internal endpoints and servers. The network also includes a core router, an edge firewall, and passive sensors.

Collection window: **2026-11-09 14:00–2026-11-10 14:00 UTC** (24 hours). Local window: 2026-11-09 09:00–2026-11-10 09:00 EST; timezone America/New_York, UTC offset -0500. Emitted timestamps are UTC. A one-hour simulation warmup precedes collection.

Ordinary business hours are approximately 09:00–17:00 local time (09:00 EST corresponds to 14:00 UTC; 17:00 corresponds to 22:00 UTC). Individual staff schedules and server activity vary.

## User directory

| Account | Name | Work | Primary system |
|---|---|---|---|
| amara.okafor | Amara Okafor | Finance operations | ABL-WS-04 |
| erin.walsh | Erin Walsh | Systems administration | ABL-WS-08 |
| grace.bell | Grace Bell | Management | ABL-WS-07 |
| jules.parker | Jules Parker | Finance operations | ABL-WS-01 |
| noah.ellis | Noah Ellis | Analysis | ABL-WS-05 |
| sophie.laurent | Sophie Laurent | Analysis | ABL-WS-06 |
| tessa.morgan | Tessa Morgan | Finance operations | ABL-WS-02 |
| victor.chen | Victor Chen | Finance operations | ABL-WS-03 |

## Systems

| Host | Address | Operating system | Roles |
|---|---|---|---|
| ABL-DC-01 | 10.72.20.10 | Windows Server 2022 | domain controller, dns server |
| ABL-FILE-01 | 10.72.20.20 | Windows Server 2022 | file server |
| ABL-WS-01 | 10.72.10.21 | Windows 11 | workstation |
| ABL-WS-02 | 10.72.10.22 | Windows 11 | workstation |
| ABL-WS-03 | 10.72.10.23 | Windows 11 | workstation |
| ABL-WS-04 | 10.72.10.24 | Windows 11 | workstation |
| ABL-WS-05 | 10.72.10.25 | Windows 11 | workstation |
| ABL-WS-06 | 10.72.10.26 | Windows 11 | workstation |
| ABL-WS-07 | 10.72.10.27 | Windows 11 | workstation |
| ABL-WS-08 | 10.72.10.28 | Windows 11 | workstation |

## Network and collection

- The core router is the gateway for office (`10.72.10.0/24`, gateway `10.72.10.1`) and servers (`10.72.20.0/24`, gateway `10.72.20.1`). Traffic between these subnets is routed at the core.
- The core reaches the Internet through the edge firewall over the `10.72.254.0/30` transit link. The firewall permits outbound traffic from both LANs, denies unmatched traffic, and uses its outside address (`203.0.113.72`) for port address translation.
- `alderbrook-servers-zeek` monitors the bidirectional tap on the server subnet uplink, including routed traffic between office and servers. Traffic that stays within either LAN is outside this tap's coverage.
- `alderbrook-edge-zeek` and `alderbrook-edge-ids` share a bidirectional tap on the core-to-firewall link. They see traffic on that link with internal addresses on the inside of the firewall. The firewall also exports Cisco ASA logs.

The selected source families are Windows, Zeek, eCAR, Cisco ASA, and Snort alerts. File-server auditing and endpoint process and file collection provide host evidence. TLS is opaque to the passive sensors, so encrypted traffic exposes connection and TLS metadata while HTTP form fields and file contents remain encrypted.

## Shared storage

- ABL-FILE-01.loan_reviews: `LoanReviews`, high server audit policy.
- Mapping lending-drive: ABL-FILE-01.loan_reviews, presented as `L:`.
