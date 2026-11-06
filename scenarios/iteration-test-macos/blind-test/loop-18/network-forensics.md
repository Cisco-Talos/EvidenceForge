# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 64

## Executive Summary

The network logs have strong operational coherence: DNS, HTTP, and TLS records resolve to connection UIDs, the observed service mix fits a routed enterprise network with a proxy, and an inbound scan is also visible in endpoint FLOW telemetry. The strongest authenticity concern is that every DMZ Zeek connection record lacks the standard `duration` and `service` fields while the core and database sensors retain them, including for completed sessions; a highly concentrated full-subnet sweep adds a weaker distribution signal.

## Evidence For Synthetic

- [schema_or_format] `zeek-dmz/conn.json` omits both `duration` and `service` from its records, while `zeek-core/conn.json` and `zeek-db/conn.json` contain those fields. The omission affects completed flows as well as unanswered attempts: at 2026-11-02 13:00:32.477 UTC, the DMZ record for `10.10.3.10:37018 → 10.10.4.10:3306` has `conn_state=SF` and `history=ShADadTtF` but no duration or service. Uniform omission across this one Zeek connection source leaves a nonstandard, materially reduced connection record and is not explained by the session being incomplete.
- [distribution_texture] `10.10.3.10` generated a short, dense sweep of the 10.10.2.0/24 range: core Zeek records 254 ICMP Echo probes between 14:40:24.871 and 14:40:28.992 UTC, then about 253–255 distinct targets on each of TCP/22, 80, 443, 445, and 3306 between 14:40:45 and 14:40:52 UTC. This is plausible scanner behavior, but the near-complete per-port coverage compressed into seconds creates a sharp, unusually uniform traffic burst: the 14:30–14:45 UTC core and DMZ bins contain 1,940 and 1,864 connections, respectively, versus roughly 300–600 in most adjacent bins. I treat it as a weak synthetic signal because an actual scanner could produce the same pattern.

## Evidence For Real

- Across all three Zeek sensors, every DNS, HTTP, and SSL record has a UID present in that sensor's `conn.json`; their timestamps are at or after the corresponding connection timestamps. There are no orphaned UIDs among 3,041 core DNS, 2,059 core HTTP, 306 core SSL, 941 DMZ DNS, 2,261 DMZ HTTP, 2,520 DMZ SSL, 58 database DNS, 26 database HTTP, and 14 database SSL records.
- The service mix is plausible for a segmented enterprise: core records include DNS/53, Kerberos/88, LDAP/389, SMB/445, HTTP proxy/8080, syslog/514, MySQL/3306, SMTP/25, and DHCP/67; database sensor traffic is dominated by MySQL/3306 (320 connections), with smaller DNS, syslog, LDAP, and TLS flows.
- DNS has a credible mix of A, AAAA, PTR, SRV, and TXT lookups and successful and failed responses. For example, core DNS has 2,227 A and 273 AAAA queries, with 210 NXDOMAIN responses among 3,041 queries. This does not appear to be a single-type or all-success query set.
- DMZ TLS records use TLS 1.2 and TLS 1.3, with common AES-GCM and ChaCha20-Poly1305 cipher suites. The HTTP mix is dominated by CONNECT requests to an apparent proxy path, alongside GET and POST traffic and a range of response codes.
- The broad scan is cross-source coherent rather than a Zeek-only artifact. At 14:40:48.212 UTC, `APP-INT-01.meridianhcs.local/ecar.json` records an inbound TCP FLOW from `10.10.3.10:33733` to `10.10.2.30:80`; Zeek records the same tuple in both core and DMZ conn logs at 14:40:46.439 and 14:40:46.323 UTC, respectively. Endpoint flow direction and tuple are consistent with the network observation.

## Detailed Analysis

### Scope and volume

The data contains three Zeek network views: `zeek-core`, `zeek-dmz`, and `zeek-db`. Each spans approximately 2026-11-02 13:00–19:00 UTC. Their connection counts are 11,956, 8,943, and 513. The count difference fits distinct observation points; I do not treat thin database-sensor volume by itself as suspicious.

### Connection behavior and protocols

Core Zeek has 9,660 `SF` and 1,932 `S0` connections, plus smaller `RSTO`, `RSTR`, and `REJ` populations. DMZ has 6,016 `SF` and 2,687 `S0` connections. Database Zeek has 422 `SF` and smaller incomplete or reset states. These state distributions include both successful sessions and failed/incomplete attempts rather than only clean completed connections.

The common ports and services line up across segments. Core includes substantial Kerberos and LDAP traffic, while the DMZ captures high TLS, HTTP, and proxy traffic and the database view is dominated by the application-to-MySQL path. In core and database logs, successful TCP examples show plausible histories and nonzero durations, such as the 13:00:32.648 UTC MySQL connection from `10.10.3.10:37018` to `10.10.4.10:3306` (`SF`, 3.897798 seconds) in `zeek-db/conn.json`.

### DNS, HTTP, and TLS

Core and DMZ DNS records contain A and AAAA lookups alongside PTR, SRV, and TXT queries; NXDOMAIN and occasional SERVFAIL/REFUSED outcomes occur among NOERROR responses. The HTTP logs are proxy-heavy: CONNECT is the leading method (1,825/2,059 core; 1,875/2,261 DMZ), with ordinary GET/POST traffic and a broad set of response codes. The logs include common enterprise destinations such as Microsoft 365 and update services, package repositories, and an internal web host. Domains are treated as potentially sanitized.

TLS versions are predominantly TLS 1.2/1.3. In DMZ, 1,597 SSL records are TLS 1.3 and 921 are TLS 1.2; the cipher suite mix includes AES-GCM and ChaCha20-Poly1305. No obvious version/cipher contradiction stands out from the network records.

### Dense subnet sweep

The most conspicuous traffic burst is sourced from `10.10.3.10` and targets nearly every address in `10.10.2.0/24`. Core Zeek shows ICMP Echo probes (`id.orig_p=8`, `id.resp_p=0`) from 14:40:24.871 to 14:40:28.992 UTC, followed by TCP attempts across ports 80, 22, 443, 445, and 3306. Most target attempts are `S0`; a small number complete or reject. The same source/destination tuples are visible at the DMZ sensor with small timestamp offsets, and the endpoint FLOW record for the `.30` target agrees on source, destination, protocol, and port. A broad subnet scan is technically credible, so I do not classify the scan itself as a hard contradiction. Its dense full-range coverage is a limited distribution signal.

### Zeek connection schema discrepancy

The most material network-format concern is confined to `zeek-dmz/conn.json`: its records have no `duration` or `service` keys. Both fields appear in the core and database conn records. The DMZ omission also applies to successful sessions with handshake/data/finish history, so it is broader than missing duration on one-sided or incomplete connections. A deliberately customized collector could omit these fields, but nothing in the supplied network records explains the sensor-specific reduction; it also prevents duration and service analysis for the largest public-facing connection set.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact on score |
|---|---|---|---|
| `schema_or_format` | Zeek DMZ `conn.json` | All 8,943 records; `duration` and `service` absent, including completed `SF` sessions | Strongest concern: uniform sensor-specific loss of standard connection detail without a visible collection explanation. |
| `distribution_texture` | Zeek core and DMZ `conn.json` | One 14:40 UTC burst; nearly full /24 ICMP and five-port TCP sweep in seconds | Weak-to-moderate concern: unusually dense and uniform, though consistent with a real network scan and corroborated by endpoint FLOW evidence. |

## Realism Score by Category

- **Field format accuracy:** 6/10 — Most Zeek record structures and protocol fields look coherent, but the DMZ connection schema omits two key fields throughout.
- **Temporal patterns:** 7/10 — Normal traffic varies over the six-hour window; one scanner burst is sharply concentrated.
- **Cross-source correlation:** 9/10 — Zeek protocol records resolve to conn UIDs, and a sampled endpoint FLOW agrees with Zeek on the inbound scan tuple.
- **Behavioral realism:** 7/10 — Protocol and state distributions are credible, including routine service traffic and incomplete attempts; the full-subnet scan could be operational or hostile.
- **Environmental consistency:** 6/10 — The segment mix is plausible, but the DMZ Zeek connection records have unexplained field loss relative to the other sensors.

## Recommendations

- If this were synthetic, preserve `duration` and `service` in DMZ Zeek conn records, or make any intentional sensor-specific field reduction explicit and internally consistent with the collection profile.
- If the dense sweep is intended to represent a scanner, retain its realistic breadth but vary scan pacing and coverage only if that better matches the intended scanner behavior; the current observable signature is one source sweeping almost the whole /24 and five fixed TCP ports within seconds.
