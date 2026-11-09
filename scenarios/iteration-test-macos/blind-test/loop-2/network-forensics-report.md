# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 68  
**Synthetic-Confidence Score:** 64

## Executive Summary

The Zeek records are internally coherent: connection, DNS, HTTP, and TLS UIDs correlate, and protocol timestamps follow connection opens. The strongest synthetic signals are the unusually high volume concentrated on a few internal hosts and repeated random-looking DNS labels under uncommon TLDs; these are suspicious patterns, but plausible in a threat-hunting capture rather than contradictions.

## Evidence For Synthetic

- **distribution_texture** — `zeek-core/conn.json` contains 12,364 connections over roughly six hours. Five-minute bins range from 42 to 1,696, with a median of 158.5. `zeek-dmz/conn.json` also has large bursts, from 13 to 1,661 connections per five-minute bin.
- **environment_or_collection_plausibility** — `zeek-core/conn.json` attributes about 257 connections each from `10.10.3.10` to destination ports 443, 3306, 445, and 22. This may fit a multi-role server, but the host role is not visible in the network records.
- **weak_signal** — `zeek-core/dns.json` includes random-looking queries such as `status-brnbiakv.tk`, `node-eu68s7bt.bit`, and `sync-if6o4zmj.bit`, with `SERVFAIL` responses. These could be threat activity or generated indicators.

## Evidence For Real

- DNS has varied query types (A, AAAA, PTR, SRV, TXT, MX, SOA, NS) and outcomes including `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`. `_ldap._tcp.dc._msdcs.meridianhcs.local` returns DC SRV records; stale `printer01.meridianhcs.local` fails.
- `zeek-core/conn.json` has varied TCP states: 10,124 `SF`, 1,898 `S0`, and smaller counts of resets, rejects, and partial states. DMZ also includes completed and unsuccessful sessions.
- Core HTTP is dominated by `CONNECT` to port 8080, consistent with an explicit proxy path, and includes varied methods and response codes (200, 403, 407, 304, 503, 504).
- `zeek-dmz/ssl.json` includes TLS 1.2 and 1.3 and varied ciphers. Certificate-chain references resolve across the Zeek datasets; where SNI and certificate SAN are both present, they match.
- `zeek-db/conn.json` is concentrated on MySQL port 3306, fitting a database sensor view, and includes completed, reset, and partial sessions.

## Detailed Analysis

- **Connection and protocol correlation:** In `zeek-core`, all 3,099 DNS, 2,416 HTTP, and 315 SSL rows have matching UIDs in `conn.json`. Their timestamps follow the connection open: DNS by up to 4 ms, HTTP by 7 ms to 4.492 s, and SSL by 14 ms to 618 ms. Matching UID and ordering checks also hold in `zeek-db` and `zeek-dmz`.
- **Network scope and traffic mix:** `zeek-core` is predominantly internal traffic. `zeek-dmz` contains both internal and external sides; common ports include 443, 8080, 53, and 80, along with probes against 445, 22, 3389, and 5985.
- **Proxy and TLS path:** A `zeek-dmz/http.json` record around 13:01:30 UTC shows a `CONNECT` to `downloads.cloud.com:443` through port 8080 with status 200. The corresponding TLS record has SNI `downloads.cloud.com` and TLS 1.3.
- **Database sensor:** `zeek-db/conn.json` records 278 connections to port 3306, mostly involving `10.10.3.10`, along with smaller amounts of DNS, HTTP, SSH, and syslog. One SSH connection is `SF` with a 3564-second duration, long but possible.
- Connection timestamps are sorted, durations are nonnegative, and protocol records follow their connection opens. No SNI/SAN mismatch or unresolved certificate-chain reference was found. The sensor views do not expose endpoint process ownership.

## Synthetic Indicator Summary

- **distribution_texture** — Connection bursts and traffic concentration — `zeek-core` and `zeek-dmz` — moderate score increase.
- **environment_or_collection_plausibility** — Multi-port activity attributed to `10.10.3.10` — moderate uncertainty, small score increase.
- **weak_signal** — Random-looking `.tk` and `.bit` DNS labels with failed resolution — small score increase.
- **hard_contradiction, contract_gap, schema_or_format** — None found.

## Realism Score by Category

- **Field format accuracy:** 9/10 — Zeek fields, connection states, protocol values, and UID references are consistent.
- **Temporal patterns:** 8/10 — Protocol records follow connection opens; bursts merit scrutiny.
- **Cross-source correlation:** 9/10 — DNS, HTTP, and TLS correlate to connection UIDs within each sensor dataset.
- **Behavioral realism:** 7/10 — Proxy use, diverse DNS outcomes, and external TLS destinations look plausible; concentrated multi-port activity is suspicious.
- **Environmental consistency:** 6/10 — Sensor views and service mix are plausible, but the role implied by `10.10.3.10` cannot be confirmed from network data alone.

## Recommendations

- Review flows from `10.10.3.10` on ports 22, 445, 443, and 3306 against its expected network role.
- Keep suspicious DNS queries and resolver outcomes visible together for timing comparisons.
