# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 38

## Executive Summary

The network telemetry is mostly production-like: flow states, protocol timing, DNS cache behavior, TLS negotiation, DHCP renewal cadence, and differing observations across sensors all hold together under detailed checks. The principal synthetic concern is that every Zeek JSON stream—especially `conn.json`—is perfectly ordered by event start time despite multi-hour connections, which is atypical of a native append-only Zeek connection log but could be explained by a normalized or chronologically sorted export.

## Evidence For Synthetic

- `[schema_or_format]` All 10,960 `zeek-core/conn.json`, 434 `zeek-db/conn.json`, and 7,847 `zeek-dmz/conn.json` records are monotonically ordered by the `ts` connection-start field with zero inversions. This includes core UID `CzV8zZ4n1mFf7ZSHG` at `ts=1710769177.978804` with `duration=15431.728591` seconds and UID `CYOdBjWoEB6vCHZTSa` at `ts=1710771318.350763` with `duration=13300.127738`; in a native append-only Zeek `conn.log`, those rows would normally be written near their close times and therefore appear after many later-starting short flows. A downstream sort/export can explain this, so it is not a hard network contradiction, but the dataset provides no log-visible export marker.
- `[distribution_texture]` Successful ICMP payload sizes have an unusually broad singleton-heavy tail. In `zeek-core/conn.json`, 152 successful ICMP flows use 40 distinct `orig_bytes` values: normal clusters such as 32, 56, 64, and 84 bytes coexist with one-off values including 250, 311, 397, 403, 481, 568, 626, 630, 753, and 1,408 bytes. Diagnostics and path-MTU testing can produce varied sizes, but that much arbitrary per-flow diversity across a six-hour enterprise slice is mildly generator-like.
- `[weak_signal]` Every visible TLS protocol record is marked `established=true`—329/329 in `zeek-core/ssl.json`, 29/29 in `zeek-db/ssl.json`, and 2,013/2,013 in `zeek-dmz/ssl.json`. Failed TCP/443 attempts do exist in `conn.json` and often never progress far enough to become TLS records, so this is only a weak distribution concern, not a missing-companion or lifecycle finding.

## Evidence For Real

- Connection outcomes are not artificially success-only. `zeek-core/conn.json` contains 8,719 `SF`, 1,914 `S0`, 146 `RSTO`, 89 `RSTR`, 30 `REJ`, and smaller `S1`/`S2`/`S3`/`OTH` populations; state/history combinations such as `S0/S`, `REJ/Sr`, `RSTO/ShADaR`, and `RSTR/ShADadr` are coherent.
- All 2,913 core DNS, 1,484 core HTTP, and 329 core TLS records resolve to a same-sensor connection UID. The same is true in the DB and DMZ sensors, and no tested DNS, HTTP, TLS, SMTP, SMB, or file-analysis event occurs before its referenced connection start or after its visible connection interval.
- DNS is especially convincing. Core DNS includes A, AAAA, MX, NS, PTR, SOA, SRV, and TXT traffic plus 216 NXDOMAIN, 16 SERVFAIL, and 6 REFUSED responses. Repeated recursive answers usually exhibit cache countdown: for example, the same `api.snapcraft.io` A answer from `10.10.2.10` drops from TTL 1,734 to 808 across 926.768 seconds, and `ctldl.windowsupdate.com` drops from 1,885 to 660 across 1,225.611 seconds.
- DNS failure texture is source-appropriate: `wpad`, stale internal names, DNS-suffix-expanded external names, and reverse-lookups produce NXDOMAINs, while successful internal SRV answers carry realistic priority/weight/port data for Kerberos and LDAP.
- TLS version/cipher pairing is valid. TLS 1.3 uses AES-GCM or ChaCha20 TLS 1.3 suites, while TLS 1.2 uses ECDHE RSA/ECDSA suites. Every referenced certificate FUID exists, every checked certificate is valid at the handshake timestamp, and each observed leaf issuer matches the next certificate subject in its chain.
- The three sensors do not clone records. Matching five-tuples have independent UIDs, small sensor-specific timestamp offsets, and occasional packet/byte/history differences consistent with distinct observation points. The stable offsets are compatible with the stated source-local collection delay and were not scored as synthetic.
- DHCP renewal timing follows lease half-life with natural jitter. For example, client `10.10.1.21` has a 3,600-second lease and renewals roughly every 1,800 seconds, while `10.10.1.22` has a 14,400-second lease and renews roughly every 7,200 seconds.
- Firewall lifecycle arithmetic is internally credible. All 6,961 visible ASA built-connection IDs are unique and monotonic; all have a later visible teardown, and wall-clock elapsed time differs from the integer duration field by only the expected zero-to-one-second timestamp rounding.
- Packet accounting is coherent: UDP IP-byte deltas equal the 28-byte IPv4/UDP overhead per packet, TCP overhead varies with packet and option mix, `missed_bytes` is usually zero but not universally so, and TCP four-tuples are not reused while a prior visible connection remains active.

## Detailed Analysis

### Connection States, Sessions, and Timing

The three sensors cover approximately six hours. Core carries 10,960 connections, DMZ 7,847, and DB 434. The role-specific mix is credible: core is dominated by DNS (2,919), Kerberos (2,329), proxy HTTP/CONNECT traffic on 8080 (1,382), LDAP (1,192), and SMB (677); DB is dominated by MySQL/3306 (266); DMZ is dominated by TLS/443 (2,542), proxy/8080 (1,597), DNS (962), and internet-facing failed probes.

TCP state and history agree in sampled and aggregate records. Successful flows use handshake/data/FIN histories such as `ShADadfF` and `ShADaDadfF`; origin resets use `ShADaR` or `ShADadTR`; responder resets use `ShADadr`; rejects use `Sr`; and unanswered SYNs use `S`. The large burst beginning around `ts=1710769647` from `10.10.3.10` contains ICMP and TCP probes across many internal targets and ports and explains the minute-level spike of roughly 1,300 records. Its sub-second randomized probe spacing and mixture of `S0`, `REJ`, and successful results are consistent with a real scanner rather than periodic baseline noise.

Long-lived SSH records are technically coherent and remain inside the six-hour slice. Core UID `CzV8zZ4n1mFf7ZSHG` runs from `1710769177.978804` to approximately `1710784609.707395`, with `SF`, 26 origin packets, 14 responder packets, and asymmetric application bytes. Its DMZ counterpart, UID `CJd1FgZbaNannd9d4`, has the same tuple and payload totals but an independently assigned UID and a start offset of about -0.114 seconds. That is convincing multi-sensor behavior. The concern is only that both records appear in file order at their start timestamps despite closing more than four hours later.

### DNS

Core DNS has 2,913 records and 865 unique query names. The type mix—2,119 A, 239 AAAA, 143 PTR, 92 SRV, 303 TXT, plus smaller MX/NS/SOA populations—is plausible for Windows domain operations, user browsing, mail authentication, and infrastructure checks. The response mix is also credible: 2,675 NOERROR, 216 NXDOMAIN, 16 SERVFAIL, and 6 REFUSED.

Specific records show realistic semantics. `_kerberos._tcp.meridianhcs.local` returns two `0 100 88` SRV answers; `_ldap._tcp.meridianhcs.local` returns two `0 100 389` answers. PTR query `52.246.107.13.in-addr.arpa` resolves to `msnbot-13-107-246-52.search.msn.com`. AAAA queries for internal IPv4-only hosts return NOERROR without an answer, which is valid NODATA behavior rather than an inconsistency. NXDOMAIN records include bare `wpad`, `oldserver.meridianhcs.local`, and suffix-expanded names such as `proxy.renderbase.com.meridianhcs.local`.

The recursive TTL behavior is a strong authenticity signal. Among repeated same-resolver, same-query, same-answer observations that occurred before the previous TTL expired, 13 of 15 adjacent pairs matched the expected cache countdown within three seconds and 14 of 15 within ten seconds. The largest exception involves `pypi.org` near expiry, where a refresh to TTL 30 is plausible. RTTs span 0.000101 to 2.384379 seconds rather than occupying a narrow uniform range.

### HTTP, Proxy, and TLS

HTTP records reflect both explicit proxying and direct traffic. Core has 1,310 CONNECT, 157 GET, and 17 POST records; DMZ has 1,367 CONNECT, 312 GET, and 31 POST records. CONNECT outcomes include 200, 403, 407, 502, 503, and 504, and multi-request connections reach `trans_depth` 7. Proxy-access rows preserve control-message bytes separately from tunnel bytes and durations—for example, the 12:01:15 UTC `proxy.opsgenie.com:443` CONNECT records `cs_bytes=452`, `sc_bytes=151`, and distinct tunnel byte counters—avoiding the common error of treating tunneled application bytes as CONNECT bodies.

TLS is modern but mixed. Core contains 173 TLS 1.2 and 156 TLS 1.3 sessions; DMZ contains 677 TLS 1.2 and 1,336 TLS 1.3 sessions. Resumption occurs in 119 core and 683 DMZ sessions, and resumed sessions appropriately omit certificate chains. Certificate observations include RSA and ECDSA keys, public and enterprise issuers, varied validity periods, unique serial/fingerprint combinations, and internally consistent chains. No invalid version/cipher pairing, expired/not-yet-valid observed certificate, missing referenced certificate FUID, or chain issuer/subject contradiction was found.

The only TLS distribution concern is the absence of any `established=false` SSL record across 2,371 rows. Since many failed 443 connections remain `S0`, `RSTO`, or unclassified at the connection layer, this does not create a contradiction and has low weight.

### Cross-Sensor and Firewall Consistency

Matching five-tuples show narrow but nonzero clock/collection offsets: core-to-DMZ matches center near -0.114 seconds, core-to-DB near +0.066 seconds, and DB-to-DMZ near -0.180 seconds. Packet and byte totals sometimes differ between those views, including 209 responder-byte differences among 3,993 matched core/DMZ connections, which is consistent with capture position and loss. Because source-local delay is part of the collection context, the stable offsets are not treated as an authenticity defect.

ASA records align with expected source-native lifecycle shapes: TCP uses 302013/302014, UDP uses 302015/302016, and dynamic translations use 305011/305012. In the visible data, every matched teardown follows its build and its integer duration matches timestamp arithmetic within one second. This completeness was not itself used as evidence of authenticity; the relevant point is the absence of contradictory visible ordering or impossible duration values.

### Distribution and Source-Native Texture

Traffic volume is bursty rather than flat. Core per-minute counts have a median of 26 and a maximum of 1,305 due to the scan; DMZ has a median of 16 and a maximum of 1,288. Background traffic spans DNS, Kerberos, LDAP, SMB, proxy, TLS, mail, DHCP, syslog, ICMP, RDP, SSH, MySQL, and less-common ports, with different sensor distributions matching their apparent network positions.

The remaining texture concerns are bounded. ICMP has realistic default-size modes but too many arbitrary one-off payload lengths to look entirely organic. More importantly, every inspected JSON stream is globally monotonic by `ts`. That is normal for a query/export sorted on event time, but atypical for native Zeek `conn.log` write order because `ts` is connection start while the row is ordinarily finalized on close. This provenance ambiguity keeps the verdict from “Real” despite otherwise strong evidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `schema_or_format` | Zeek JSON, especially `conn.json` | Dataset-wide across all three sensors | Highest-impact concern: perfect start-time sorting is atypical of native Zeek close-time emission, though post-export sorting is a credible alternative. |
| `distribution_texture` | Zeek ICMP connections | Repeated across core, DB, and DMZ | Mild concern: unusually broad, singleton-heavy echo payload sizes weaken host/tool consistency. |
| `weak_signal` | Zeek TLS | Dataset-wide among visible SSL rows | Low impact: all 2,371 parsed TLS sessions are established, but failed TCP/443 flows exist outside `ssl.json`. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, TLS/X.509, DNS, proxy, and ASA fields are source-appropriate; chronological sorting is the only notable source-native format concern.
- **Temporal patterns:** 8 — Bursts, durations, DNS cache countdown, DHCP half-life renewals, and scan timing are strong, but perfect file-level timestamp ordering is atypical.
- **Cross-source correlation:** 9 — UIDs, tuples, protocol timing, certificate references, sensor offsets, and firewall lifecycles show no concrete contradiction.
- **Behavioral realism:** 8 — Service mix, failures, resets, proxy outcomes, scanning, and long sessions are credible; ICMP payload diversity is mildly artificial-looking.
- **Environmental consistency:** 9 — Core, DB, and DMZ source-family and port distributions differ in ways consistent with distinct observation points and host roles.

## Recommendations

- If this were synthetic, preserve native Zeek write semantics for `conn.json`: emit connection rows at close/removal time or retain an explicit ingestion/export timestamp and provenance marker if the deliverable is intentionally sorted by start time. That would remove the largest ambiguity without changing network causality.
- If this were synthetic, make ICMP payload size primarily stable per originating host/tool, with strong operating-system and monitoring defaults and only sparse explicit path-MTU or diagnostic variation. Avoid drawing many unrelated one-off sizes independently per flow.
- If this were synthetic, include a small number of parsed-but-aborted TLS handshakes with source-native `established=false` values, paired with compatible TCP state/history, rather than representing every failed TLS attempt only as an unclassified or pre-handshake connection failure.
