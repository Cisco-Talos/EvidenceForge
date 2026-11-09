# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 62
**Synthetic-Confidence Score:** 43

## Executive Summary

Across the three Zeek views, the data covers about six hours with thousands of flows, DNS transactions, HTTP proxy requests, and TLS sessions. Zeek-native record structure and UID/tuple joins are consistently coherent, while protocol states, DNS outcomes, TLS versions, and traffic volumes are broadly plausible. The strongest synthetic cue is a tightly synchronized internal sweep: at 14:40:30–14:40:36 UTC, `10.10.3.10` generated approximately 246–248 failed TCP attempts apiece to ports 22, 80, 3306, and 445 against nearly 250 distinct `10.10.2.x` addresses. This is possible for a fast scanner, but its near-equal per-port counts and six-second window give the traffic a deliberately regular texture. Overall evidence supports neither a confident synthetic nor real classification.

## Evidence For Synthetic

- **[distribution_texture]** In `zeek-dmz`, source `10.10.3.10` produced 246 `S0` connections to port 22, 247 to port 80, 248 to port 3306, and 254 to port 445. The main burst for ports 22/80/3306 runs from 14:40:30 to 14:40:36 UTC and covers 246–248 unique destinations in `10.10.2.x`; all are one-packet SYN attempts (`history: "S"`, `orig_pkts: 1`, `resp_pkts: 0`). The closely matched destination cardinality, timing, and all-failed outcome across several ports look unusually regular, although a high-speed scanner could produce this pattern.
- **[distribution_texture]** The `zeek-core` view independently shows the same sweep shape: at 14:40, `10.10.3.10` has 245 `S0` attempts on port 22, 247 on port 80, 246 on port 445, and 249 on port 3306. The corresponding near-identical counts across two views reinforce the repeated pattern. This is a concern about texture, not proof that the scan itself is impossible.

## Evidence For Real

- `zeek-core` contains 12,386 connection records over 13:00–18:59 UTC, `zeek-dmz` 9,094, and `zeek-db` 442. The six hourly connection counts vary rather than following a fixed per-hour quota; the `zeek-core` counts range from 1,662 to 3,208.
- Connection outcomes include successful (`SF`), unanswered (`S0`), reset (`RSTO`/`RSTR`), rejected (`REJ`), and partial (`S1`–`S3`) records. Durations vary from fractions of a millisecond to hours. For example, the SSH flow from `10.10.3.10` to `10.10.2.30:22` starts at 15:14:36 UTC and lasts 13,342 seconds, ending before the observed window closes; long-lived sessions are therefore compatible with the visible interval.
- DNS has ordinary A/AAAA and service-discovery SRV/PTR traffic, as well as a minority of NXDOMAIN and SERVFAIL responses. In `zeek-dmz`, for example, `10.10.3.20` queries an internal resolver at 13:00:19 UTC and receives an NXDOMAIN for `cdn-check-vrkx2npi.top`; other entries show successful responses and varied TTLs. Domain names are treated as visible strings only, with no claim about their resolution or ownership beyond the records.
- `zeek-dmz` HTTP and TLS records show recognizable proxy behavior. At 13:02:00 UTC, an HTTP `CONNECT` from `10.10.1.22` to `10.10.3.20:8080` requests `media.licdn.com:443`; a TLS record at 13:02:00.507 UTC carries `server_name: media.licdn.com` from the proxy address to an external destination. TLS contains TLS 1.2 and 1.3, varied modern cipher suites, both resumed and fresh sessions, and a small number of unestablished handshakes.
- UID-based companions are exact and tuple-consistent: all 3,087 `zeek-core` DNS, 2,189 HTTP, and 389 SSL rows match a connection record with the same UID and four-tuple. The corresponding `zeek-db` and `zeek-dmz` DNS/HTTP/SSL records also all match their connection UID and tuple. This is positive coherence evidence, not evidence by itself that the collection is genuine.

## Detailed Analysis

### Connection and state behavior

The observed connection population is large enough to show varied activity rather than only a narrow storyline. In `zeek-core`, TCP/UDP/ICMP counts are 6,780/5,220/386. Most records are completed exchanges (`SF`), with a meaningful `S0` tail and smaller reset, rejection, and partial-state populations. The `zeek-dmz` population has more failed attempts (2,211 `S0`) than `zeek-core` (1,700), consistent with a view that includes unsolicited inbound traffic. Internal SSH sessions have successful long-lived examples, while inbound RDP and scanning-like traffic includes unanswered SYNs. Nothing in the observed lifecycle durations is intrinsically impossible for the six-hour window.

The clearest concern is the six-second multi-port burst described above. Its destination addresses vary within the subnet rather than increasing sequentially, and the count per port is not exactly identical. A fast inventory scan can plausibly account for it; the close count symmetry and sharply bounded burst make it a moderate texture signal rather than a contradiction.

### DNS

`zeek-core` records 3,087 DNS transactions, overwhelmingly A queries, with AAAA, TXT, PTR, and SRV also represented. `zeek-dmz` records 1,018. Both include successful answers and expected failure classes. DNS records share their UID, tuple, and timestamp with the corresponding UDP connection in the examples checked. Resolver usage is concentrated on `10.10.2.10` and `10.10.2.11`, which is consistent across the views. Queries span internal names and external-looking names; no domain reputation or real-world resolution inference is made.

### HTTP and TLS

The HTTP population is dominated by `CONNECT` to a proxy on port 8080, with a smaller set of GET/POST records. Statuses include 200, redirects, cache responses, access denials, proxy authentication requirements, and upstream errors. Proxy requests, TLS SNI, and external destination tuples align in representative cases. `zeek-dmz` has 2,408 HTTP rows and 2,670 TLS rows; the different totals are plausible because not every HTTP transaction is a TLS tunnel and some TLS sessions do not have a corresponding HTTP request. The TLS distribution is mostly TLS 1.3 and TLS 1.2 with several cipher families, rather than a single fixed handshake profile.

### Volume and lateral movement

Core and DMZ connection volumes average roughly 0.57 and 0.42 records per second across the visible six-hour period; the database view averages roughly 0.02. They contain DNS, proxy/web, Kerberos/LDAP, SMB, SSH, MySQL, and syslog traffic, along with inter-subnet sessions. The visible traffic includes repeated internal connections and failed probes, but the network data alone does not establish whether every source/destination role is expected. The scan is conspicuous, yet its volume is feasible for an internal scanner. No protocol/state ordering contradiction was established from the sampled records and UID joins.

## Synthetic Indicator Summary

- **[distribution_texture]** The `10.10.3.10` sweep produces near-equal batches of 246–248 unanswered attempts across four common service ports, reaching nearly 250 unique `10.10.2.x` destinations in roughly six seconds.
- The signal is bounded: it is compatible with a real high-speed scanner and is outweighed in part by varied connection states, realistic time spans, DNS outcomes, HTTP statuses, TLS handshakes, and complete Zeek UID/tuple companions. No hard contradiction or Zeek schema/format anomaly was established.

## Realism Score by Category

- Field format: 9/10
- Temporal patterns: 8/10
- Cross-source correlation: 9/10
- Behavioral realism: 7/10
- Environmental consistency: 8/10

## Recommendations

1. Review the 14:40:30–14:40:36 UTC `10.10.3.10` burst across ports 22, 80, 3306, and 445. If it reflects a known scanner, the equal-sized target batches are plausible; if not, verify whether the destination sweep and timing were intentionally modeled.
2. Keep the paired proxy `CONNECT` and TLS rows together during any further audit. Their host/SNI and tuple relationship is one of the strongest coherence checks in this set.
3. For a firmer authenticity decision, compare the sweep against collection context and known scanner cadence, and sample additional windows to see whether the same near-equal burst pattern recurs.
