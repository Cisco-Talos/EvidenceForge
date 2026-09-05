# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 72

## Executive Summary

Most of the network corpus is unusually convincing: the three Zeek vantage points, ASA state/NAT
records, proxy transactions, DNS cache behavior, TLS handshakes, and protocol-specific logs form a
coherent six-hour environment with realistic variation. The decisive exception is a 254-target ICMP
sweep whose unanswered one-packet Zeek flows have impossible positive durations, behavior-specific
`service:"icmp"` labeling, and independently randomized payload sizes; together these are a strong
generator fingerprint rather than ordinary collection noise.

## Evidence For Synthetic

- `[hard_contradiction]` In `zeek-core/conn.json`, 245 unanswered ICMP echo flows from
  `10.10.3.10` have `orig_pkts:1`, `resp_pkts:0`, yet carry positive `duration` values from
  0.003061 to 0.135033 seconds. A representative record is line 2447 at
  `ts=1710769284.524840` (`uid=CsTKE4k5wW0FSRFcHw`, destination `10.10.2.8`), with one total
  packet and `duration=0.052232`. Zeek duration is elapsed time between the first and last packet;
  a one-packet flow cannot have this positive interval. The same defect is independently rendered
  in `zeek-dmz/conn.json` for all 245 unanswered members of the sweep, for example line 2123 at
  `ts=1710769284.411039`, where the corresponding flow has `duration=0.052214`.
- `[schema_or_format]` The sweep is marked `service:"icmp"` on all 254 records in both
  `zeek-core/conn.json` and `zeek-dmz/conn.json`, while ordinary ICMP records elsewhere omit the
  `service` field. For example, core line 15 (`uid=CbUJuBsr5ElmvAGYSp`) and DMZ line 63
  (`uid=CEREm5gUDLDLTfLsVfa`) are otherwise normal successful echo exchanges with no service
  value. This behavior-class-dependent schema change looks like generation intent leaking into
  `conn.log`, not a packet-derived application service.
- `[distribution_texture]` The same sweep covers 254 distinct destinations in 4.20 seconds but
  changes ICMP echo size independently per destination: 18 distinct `orig_bytes` values appear,
  including 32, 40, 48, 56, 64, 84, 120, 256, 512, 1024, 1200, and 1472. Counts include 49 at
  64 bytes, 38 at 56, 30 at 84, 12 at 1024, and 4 at 1200. A single scanner invocation normally
  uses a stable probe shape across a target range; this per-host draw from a broad size pool is
  conspicuously synthetic, and it is visible identically from both sensor vantage points.
- `[environment_or_collection_plausibility]` The ASA logs create and tear down ICMP connection
  state for the unanswered sweep targets in the same whole second. At 13:41:24, for example,
  `fw-perimeter/cisco_asa.log` lines 5012-5030 rapidly alternate `%ASA-6-302020` build and
  `%ASA-6-302021` teardown records for sequential destinations. Given Zeek's explicit lack of
  replies for 245 targets, immediate teardown throughout is questionable; this is supporting
  evidence rather than a decisive indicator because the ASA source has only second precision and
  device timeout policy is unknown.
- `[weak_signal]` The bounded six-hour ASA slice contains 8,128 connection builds and exactly
  8,128 matching teardowns, with no pre-window teardown or post-window open state. Completeness is
  not itself an authenticity failure and was not materially weighted, but the exact boundary
  closure is unusually tidy for a production collection slice.

## Evidence For Real

- The corpus has substantial and believable volume: 11,219 core, 416 database-segment, and 9,029
  DMZ Zeek connection records spanning approximately 12:00-18:00 UTC. Core traffic includes 6,166
  TCP, 4,663 UDP, and 390 ICMP records; DMZ traffic includes 7,708 TCP, 1,021 UDP, and 300 ICMP
  records. The source mix is broad without being uniformly populated.
- TCP state distributions are convincing. Core has 9,004 `SF`, 1,933 `S0`, 115 `RSTO`, 81
  `RSTR`, 23 `REJ`, plus smaller `OTH`, `S1`, `S2`, and `S3` populations; histories such as
  `ShADadfF`, `ShADaDadfF`, `ShADadTtFf`, `ShAR`, and `Sr` agree with the states and packet
  directions. Durations also vary by service and state, including long-lived successful sessions.
- DNS behavior is rich. Core contains A, AAAA, PTR, SRV, TXT, MX, NS, and SOA activity; it also
  includes 170 A-record NXDOMAINs, suffix-search artifacts such as `wpad`,
  `wpad.meridianhcs.local`, and `download.windowsupdate.com.meridianhcs.local`, stale internal
  names, PTR failures, REFUSED, and SERVFAIL outcomes. Answer/TTL vector lengths are consistent in
  every DNS record checked.
- DNS TTL behavior resembles resolver caching rather than fixed template values. Repeated external
  names retain stable answer sets while TTLs decrease and reset over time; for example `pypi.org`
  appears with the same two A answers but many TTL values, while Microsoft and update-service
  names exhibit longer, variable cached TTLs. DNS record timestamps and RTTs always finish within
  the associated `conn.json` interval at all three sensors.
- TLS telemetry is coherent and modern: DMZ SSL traffic contains 1,663 TLS 1.3 and 848 TLS 1.2
  sessions with AES-GCM and ChaCha20 suites, while internal services lean more heavily toward TLS
  1.2. Resumed sessions omit certificate chains, TLS 1.3 histories are appropriately compact, all
  referenced certificate FUIDs resolve, and every inspected certificate is valid at its use time.
- Certificate identity is stable rather than regenerated per flow. Repeated SNI values normally
  map to a single leaf fingerprint, and repeated intermediate certificates retain the same
  fingerprint. SANs, subjects, issuers, key sizes, and validity periods form plausible internal and
  public chains.
- Protocol logs correlate correctly with their connection records. Across DNS, HTTP, SSL, SMTP,
  and SMB, every checked UID resolves to a `conn.json` row, every copied four-tuple agrees, and no
  protocol timestamp precedes its connection or falls beyond its close interval. DNS, HTTP, and
  TLS timing offsets vary within protocol-appropriate ranges rather than collapsing to one fixed
  delay.
- The separate Zeek sensors use distinct UIDs for the same crossing flow and show plausible
  clock/vantage differences. I matched 4,577 core/DMZ five-tuples: all retained the same state and
  identified service, while several hundred differed in packet counts, byte counts, history, or
  duration. That is more realistic than copying identical rows between sensors.
- Proxy behavior is detailed. Client-to-proxy CONNECT records correlate with access-log entries
  carrying control-message bytes, tunnel bytes, tunnel duration, authentication state, deny and
  gateway outcomes; proxy-origin DNS and TLS traffic is separately visible. HTTP includes GET,
  POST, CONNECT, redirects, partial content, caching, denials, and multiple user-agent families.
- ASA records are source-shaped and operationally coherent outside the ICMP concern. TCP/UDP
  build and teardown IDs are unique, monotonic, and correctly paired; NAT build precedes outbound
  connection creation and NAT teardown follows connection close. SYN timeouts, FIN closes, ACL
  denies, and translated addresses align with the Zeek view.
- Internet background activity is not unrealistically quiet. The DMZ sensor sees multiple scanner
  populations with different port preferences, rates, source addresses, and state outcomes, plus
  ordinary inbound web clients, outbound cloud/CDN traffic, and IDS alerts. The scanner timing is
  bursty and heterogeneous rather than one uniform cadence.

## Detailed Analysis

### Scope, volume, and connection behavior

The visible window runs from `1710763211.385151` to `1710784768.457210`, roughly six hours.
`zeek-core/conn.json` has 11,219 rows, `zeek-dmz/conn.json` has 9,029, and
`zeek-db/conn.json` has 416. Dominant core services are DNS (2,798), Kerberos (2,268), HTTP
(1,995), LDAP (1,091), SMB (427), TLS (323), syslog (266), SSH (53), DHCP (48), and SMTP (46).
The DMZ appropriately shifts toward TLS (2,634), HTTP (2,217), and unidentified failed probes while
the database sensor is dominated by MySQL (277). This distribution makes architectural sense from
the logs alone.

The successful TCP duration median is 2.015 seconds in core, 2.386 seconds in DMZ, and 3.008
seconds on the database segment. The tails include long-lived sessions (maximum about 15,248
seconds in core/DMZ and 3,547 seconds in DB), while failed SYNs are normally represented by one or
more origin packets, no responder packets, `S0`, and either no duration or a retry-derived short
duration. Reset direction, packet counts, and histories are mutually consistent in sampled `RSTO`,
`RSTR`, `REJ`, `S2`, and `S3` records.

The exception is the ICMP sweep beginning near `1710769284.4`. Source `10.10.3.10` probes every
usable address in `10.10.2.0/24`: 254 destinations in 4.20 seconds, with nine responses and 245
timeouts. The sweep is a plausible activity, but its rendering is not. Every unanswered entry has
only one packet yet a random positive duration. This is not an edge-window issue: initiation and
the complete sweep are visible, and duration is derived from packets within each individual Zeek
flow. Ordinary one-packet TCP failures in the same files omit duration, which makes the special
ICMP treatment especially conspicuous.

### DNS

Core DNS has 2,791 protocol rows, DMZ has 969, and DB has 37. All DNS UIDs resolve to local
connection rows and preserve the exact tuple. The delay from connection start to DNS record is
0.001-0.092 seconds in core, 0.001-0.012 in DMZ, and 0.001-0.062 in DB; adding each DNS RTT never
passes the associated connection end. Median RTT is 2.64 ms in core and 16.97 ms in DMZ, with a
reasonable long tail to 2.44 seconds.

Core query composition includes 1,940 successful A, 252 successful AAAA, 171 successful TXT, 107
successful PTR, 97 successful SRV, 170 A NXDOMAIN, and smaller negative/error populations.
Internal authoritative responses use `AA:true` and common 300/1,800-second TTLs. External cached
answers exhibit decreasing TTLs and occasional refreshes. Negative answers omit answer and TTL
arrays rather than inserting fake values. The observed suffix-search noise and reverse lookups add
credible Windows and infrastructure texture.

### TLS, HTTP, proxy, and files

All SSL UIDs and tuples align with connections, and all certificate references resolve. Core's 312
SSL records split 169 TLS 1.3 and 143 TLS 1.2; DMZ's 2,511 split 1,663 and 848. TLS 1.2 full
handshakes generally carry two-element certificate chains, resumed sessions omit them, and TLS 1.3
records use compact encrypted-handshake histories. The corpus uses a sensible suite mix and stable
certificate fingerprints. No certificate was expired or not-yet-valid at the observed handshake.

HTTP is dominated by explicit-proxy CONNECT traffic but retains direct GET/POST activity, cache
hits, redirects, errors, content FUIDs, MIME types, and referers. All 2,026 core and 2,244 DMZ HTTP
rows have valid connection UIDs and four-tuples. The proxy access log distinguishes control-plane
CONNECT bytes from tunneled bytes and records tunnel durations, which avoids a common realism
mistake. HTTP and SMB file records resolve to valid FUIDs and connection UIDs; hashes remain stable
for repeated files.

### Multi-source and perimeter consistency

The sensors do not reuse Zeek UIDs across vantage points. Matching on full five-tuples and nearby
timestamps produced 4,577 core/DMZ crossings, 106 core/DB crossings, and 309 DB/DMZ crossings.
Core trails DMZ by about 114 ms for most common flows; DB has a separate slowly drifting offset.
State and service classification agree for every matched pair, while packet counts and TCP history
occasionally differ, as expected from distinct capture points. These are plausible clock and
visibility effects, not impossible ordering.

The firewall file contains 21,513 rows. I found 8,128 TCP/UDP connection IDs, each with one build
and one later teardown, no duplicated IDs, and no teardown-before-build. Dynamic NAT IDs are paired
around outbound DMZ traffic, ACL denies remain failed/unanswered in Zeek, and TCP SYN timeout logs
cohere with single-sided `S0` flows. IDS alerts retain microsecond precision and match the tuples
and suspicious DNS/scan activity visible in Zeek.

The ICMP sweep again breaks the otherwise strong consistency. The ASA emits rapid build/teardown
pairs for requests that Zeek explicitly records as unanswered, and the Zeek renderer assigns both
positive duration and an `icmp` service label only to this sweep. The exact same payload-size draw
and outcome are retained at both Zeek sensors, so this is not packet loss or one corrupt collector.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Zeek `conn.json` ICMP | 245 unique unanswered sweep flows, duplicated at core and DMZ | One total packet cannot produce a positive first-to-last-packet duration; this was the principal synthetic indicator. |
| `schema_or_format` | Zeek `conn.json` ICMP | All 254 sweep flows at both sensors | `service:"icmp"` appears only on the sweep while ordinary ICMP omits service, exposing behavior-class-specific rendering. |
| `distribution_texture` | Zeek ICMP sweep | All 254 destinations | Eighteen payload sizes are independently mixed inside one four-second sweep instead of retaining a scanner-level probe shape. |
| `environment_or_collection_plausibility` | Cisco ASA ICMP | Most sweep targets | Immediate whole-second build/teardown pairs for explicitly unanswered probes are questionable, but source precision prevents treating this as conclusive alone. |
| `weak_signal` | Cisco ASA lifecycle | Entire six-hour file | Exact closure of every one of 8,128 builds at both collection boundaries is unusually tidy but was not materially weighted by itself. |

## Realism Score by Category

- **Field format accuracy:** 7/10 — Most Zeek, ASA, proxy, and IDS records are source-shaped, but the ICMP duration/service fields create a high-confidence exception.
- **Temporal patterns:** 8/10 — Traffic is bursty, service-sensitive, and multi-sensor timing is nuanced; the fabricated one-packet ICMP durations are the principal defect.
- **Cross-source correlation:** 9/10 — UIDs, tuples, FUIDs, certificates, protocol timing, sensor vantage, NAT, and IDS evidence correlate exceptionally well without simple row copying.
- **Behavioral realism:** 7/10 — Baseline, proxy, browsing, infrastructure, and scanner populations are diverse, but one sweep randomizes its probe size per host in a generator-like way.
- **Environmental consistency:** 9/10 — Segment-specific service mixes, public/private routing, proxy egress, database traffic, DNS authority, and perimeter exposure are mutually plausible.

## Recommendations

- If this were synthetic, derive Zeek duration strictly from observed packet timestamps. Omit it (or
  emit source-native zero behavior, if verified for the target Zeek version) whenever only one
  packet exists; do not substitute a timeout or modeled RTT for packet-derived duration.
- Keep ICMP `service` handling source-native and independent of whether the activity is a scan,
  baseline ping, or alert-worthy event. The same analyzer semantics should apply to all ICMP rows.
- Choose ICMP probe size once per scanner invocation or scanner profile, then keep it stable across
  the target range unless the modeled tool specifically changes probe types. If evasion-oriented
  size variation is intentional, make it follow a concrete tool pattern rather than independent
  per-target sampling.
- Model ASA ICMP teardown from reply or configured ICMP state timeout. For unanswered probes, avoid
  immediate teardown at the same second unless that behavior is validated against the intended ASA
  version and timeout configuration.
- Preserve the existing DNS cache texture, TLS chain stability, per-vantage Zeek UIDs and clock
  offsets, packet-count differences, proxy tunnel accounting, and state/history consistency; these
  were the most production-like parts of the dataset.
