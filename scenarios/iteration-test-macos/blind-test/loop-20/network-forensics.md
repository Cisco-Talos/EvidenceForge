# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 76  
**Synthetic-Confidence Score:** 73

## Executive Summary

The network records have credible Zeek fields, varied TCP outcomes, plausible TLS versions, and useful agreement between core and DMZ sensors. The strongest synthetic indicators are two high-volume patterns concentrated on `10.10.3.10`: a roughly 760-connection three-port sweep across an internal /24 in about six seconds and a 45-minute run of unique `.top` DNS labels at a roughly 29-second median cadence. Either pattern could occur during a real compromise, but their tight counts, timing, and common source make the combined distribution look deliberately constructed.

## Evidence For Synthetic

- [distribution_texture] In `zeek-core/conn.json:2765,2767`, `10.10.3.10` initiates 760 TCP connections to `10.10.2.0/24` on ports 22, 445, and 3306 between 14:40:45.626 and 14:40:51.808 UTC. The per-port totals are 253, 253, and 254; 740 connections are `S0`, and 749 have zero originator and responder bytes. The nearly complete, count-matched service sweep compressed into six seconds is a strong scan-shaped texture, even though a fast scanner could produce it.
- [distribution_texture] `zeek-dmz/dns.json:689–920` records 91 unique random-looking `.top` queries from `10.10.3.10` between 18:00:34 and 18:45:19 UTC. Eighty return `NXDOMAIN`; eleven return `45.33.32.30`. The median interval is about 29 seconds. Sustained unique labels at this cadence form a conspicuous DGA-like pattern.
- [environment_or_collection_plausibility] The same internal address is the origin of both the broad TCP sweep and the prolonged random-label DNS activity. A compromised host can generate both, but this concentrates two distinct high-volume discovery/beacon patterns on one source during a short visible window.

## Evidence For Real

- The connection-state distributions are not a single clean template. `zeek-core/conn.json` has 9,660 `SF` connections, 1,932 `S0`, and smaller tails of `RSTO`, `RSTR`, `REJ`, `OTH`, and `S1`–`S3`. `zeek-dmz/conn.json` likewise contains 6,016 `SF`, 2,687 `S0`, and several reset/reject/partial states.
- The same fast sweep is visible at both core and DMZ vantage points. In the first sample, DMZ sees `10.10.3.10:445 -> 10.10.2.103` at 14:40:45.513 UTC (`zeek-dmz/conn.json:2088`); core sees the same tuple about 114 ms later (`zeek-core/conn.json:2765`). The records retain the corresponding outcome and zero-byte accounting.
- DNS has routine enterprise traffic as well as suspicious activity. For example, `zeek-core/dns.json:5` records an LDAP SRV lookup that returns both domain controllers, and the files contain A/AAAA/PTR/SRV/TXT/MX/SOA/NS requests with varied resolver outcomes.
- HTTP CONNECTs and TLS records have recognizable source-native shapes and varied results. Core has 1,825 CONNECT requests, alongside GET/POST traffic and non-200 responses. TLS includes 150 TLS 1.2 and 153 TLS 1.3 records; common suites include AES-GCM and ChaCha20-Poly1305.
- DNS, HTTP, and TLS UIDs examined in all three Zeek sensors have matching `conn.json` rows. I treated this as positive structural evidence, not as a synthetic clue by itself. Snort also records `.top` DNS alerts for `10.10.3.10`, including `snort-perimeter/snort_alert.log:53–54` at 18:01:23 and 18:06:26 UTC.

## Detailed Analysis

### Connection states and service mix

The three sensor files cover approximately 13:00–19:00 UTC. Core contains 11,956 connection rows with TCP, UDP, and ICMP; the DB sensor contains 513 rows centered on MySQL (313 service-tagged rows); and DMZ contains 8,943 rows with substantial HTTPS, HTTP, DNS, and database traffic. There are routine internal services, proxy traffic, failed connections, resets, and completed sessions. The main concern is not the overall state mix but the exceptional six-second scan burst.

The scan covers 253 distinct targets on port 22, 253 on 445, and 254 on 3306. In core, the port-22 results are 247 `S0`, three `RSTO`, two `REJ`, and one `SF`; port 445 has 246 `S0`, three `SF`, three `RSTO`, and one `REJ`; port 3306 has 247 `S0`, six `REJ`, and one `RSTO`. These results are technically plausible for a high-speed sweep against a subnet, but the near-equal full-subnet coverage across exactly three sensitive services creates an unusually tidy distribution.

### DNS and alert correlation

The `.top` sequence begins at `zeek-dmz/dns.json:689` with `ewnjsaqf1rasgez5.top` at 18:00:34.447 UTC and continues through `t7atlak4r6zk8fd.top` at line 920 at 18:45:19.006 UTC. The names are unique in this run. Eighty queries receive `NXDOMAIN`; eleven return the same `45.33.32.30` address. Snort independently flags the source's `.top` requests; for example, `snort-perimeter/snort_alert.log:54` records a DNS alert from `10.10.3.10:36290` at 18:06:26.140 UTC. The alert and Zeek data agree on the broad pattern, so the concern is the cadence/concentration, not a tuple or sensor contradiction.

### Protocol and sensor consistency

All DNS, HTTP, and SSL UIDs in the examined core, DB, and DMZ files have a matching connection UID. Core HTTP includes proxy CONNECT tunnels to `10.10.3.20:8080`; the mix includes successful tunnels and 403/407/5xx responses. TLS negotiates both TLS 1.2 and TLS 1.3, with modern AES-GCM and ChaCha20 suites alongside some older CBC use. I found no demonstrated Zeek field-shape error or impossible protocol transition in the sampled records.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | Zeek connections | `10.10.3.10` to 10.10.2.0/24; 14:40:45–14:40:51 UTC | 760 attempts split almost evenly across TCP 22/445/3306, with 740 `S0` and 749 zero-byte rows. |
| `distribution_texture` | Zeek DNS and Snort | `10.10.3.10`; 18:00:34–18:45:19 UTC | 91 unique `.top` labels at a roughly 29-second median cadence, mostly NXDOMAIN with repeated sinkhole-like answers and alert coverage. |
| `environment_or_collection_plausibility` | Zeek DNS and connections | Same source address | Two distinct high-volume suspicious patterns are concentrated on one internal address; this is plausible after compromise but unusually focused. |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled Zeek and Snort fields use credible names, types, tuples, and protocol values.
- **Temporal patterns:** 6 — Most traffic spans the six-hour window with varied durations; the sweep and sustained DNS cadence are conspicuous.
- **Cross-source correlation:** 9 — Sampled Zeek UIDs, dual-sensor tuples, and Snort DNS alerts align.
- **Behavioral realism:** 6 — Ordinary service traffic coexists with plausible suspicious activity, but the scan counts and DGA cadence are tightly patterned.
- **Environmental consistency:** 7 — Core, DB, DMZ, proxy, resolver, and domain-controller roles have plausible network traffic; the dual suspicious patterns from one source are unusual.

## Recommendations

If this were synthetic, vary the scan's port participation, target coverage, and duration so it does not resemble a near-equal full-subnet matrix. Give the DGA-like traffic more variation in query spacing, response mix, and source participation while retaining the plausible sinkhole and IDS correlations. Preserve the varied connection states, ordinary proxy traffic, current TLS versions, and sensor-level tuple agreement.
