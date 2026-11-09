# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 83
**Synthetic-Confidence Score:** 43

## Executive Summary

The network records are substantially production-like: protocol state, byte accounting, TLS visibility, proxy behavior, and sensor-local references withstand several concrete consistency checks. The strongest concern is a measurable concentration of long SSH connections closing immediately after clock-hour boundaries across different clients and servers; this looks like a scheduling artifact, although a centrally enforced administrative policy could also produce it. I found no demonstrated impossible protocol ordering or certificate identity contradiction, so the evidence does not justify a confident synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] Long SSH sessions repeatedly finish in the first two minutes of a clock hour despite starting at very different times. In `zeek-core/conn.json`, 22 of the 50 `service="ssh"`, `conn_state="SF"` connections with `duration>300` seconds have `(ts+duration) modulo 3600 <120`. This spans five client IPs and seven destination IPs. For example, lines 7, 134, 523, 541, and 797 start between 13:00:11 and 13:27:28 UTC but all finish between 14:00:35 and 14:01:11. Lines 1792, 1796, 2082, 2468, 4567, and 4707 similarly finish between 15:00:40 and 15:01:22. The concentration follows absolute clock boundaries, rather than a common elapsed session lifetime. This is a substantive timing-texture concern, with a plausible policy/automation alternative; it is not an impossibility.

## Evidence For Real

- The three sensors have meaningfully different observed traffic mixes. `zeek-db/conn.json` contains 498 records, including 329 MySQL-classified connections; `zeek-core/conn.json` contains 12,382 records with DNS, Kerberos, LDAP, SMB, proxy, and administration traffic; `zeek-dmz/conn.json` contains 9,629 records with 2,805 SSL-classified and 2,107 port-8080 HTTP-classified connections. This is coherent with differentiated observation locations.
- TCP outcomes are varied and usually agree with their packet histories. Core has 4,894 TCP SF, 1,465 S0, 171 RSTO, 106 RSTR, 45 REJ, and smaller S1/S2/S3/OTH populations. `zeek-core/conn.json:404` has REJ, history `Sr`, one packet each way, and zero payload. Line 470 has S0, history `S`, one originator packet and no responder packets. These are sensible source-native combinations.
- TLS evidence respects observable handshake boundaries: none of the 1,901 TLSv13 rows has a certificate-chain field, and none of the TLSv12 resumed rows has a chain field. Examples are `zeek-core/ssl.json:8` (`TLSv13`, `ssl_history="Cs"`, no chain) and line 6 (`TLSv12`, resumed, `ssl_history="CsiI"`, no chain). No checked TLSv12 RSA/ECDSA cipher disagrees with the linked leaf-certificate key type.
- HTTP proxy semantics are internally sensible. `zeek-core/http.json:1` is a successful CONNECT with zero response body, while line 24 is a 407 authentication response with a 1,732-byte HTML body and a file reference. Across all 4,713 HTTP rows, successful CONNECT, HEAD, 204 and 304 cases have no forbidden nonzero response body; repeated transactions do not reuse `trans_depth` within a UID.
- DNS includes A, AAAA, PTR, SRV, TXT, MX, NS and SOA observations, successful and failed lookups, and varied TTLs. Examples include `zeek-core/dns.json:12` (AAAA answer), line 16 (internal PTR), line 1 (AD SRV lookup), and line 5 (printer NXDOMAIN). This is more plausible than an A-only, always-successful lookup stream.
- The first visible proxy operation has distinguishable client-to-proxy and proxy-to-server legs. `zeek-dmz/conn.json:1` is `10.10.1.32:57530 → 10.10.3.20:8080`; `zeek-dmz/ssl.json:1` is `10.10.3.20:34135 → 142.250.190.110:443` with matching `clients6.google.com` SNI. `fw-perimeter/cisco_asa.log:1-3` records the associated translated source port 43398, and `PROXY-01.meridianhcs.local/proxy_access.log:1` separates CONNECT control-message bytes from tunnel bytes. This is coherent evidence construction, without requiring identical leg-level byte counts.

## Detailed Analysis

### Scope, provenance, and method

I read only the supplied neutral briefing and files under `/private/tmp/log-study-vn4mfwps/data`. I used system `python3` from an explicit `/private/tmp` working directory; I did not inspect repository files, scenario material, prior assessments, or other reviewers. Generic inherited operating instructions were not treated as evidence of data origin. No external research was used.

I parsed every JSON record in all three supplied Zeek sensor directories. Record totals are 22,509 connection rows, 4,196 DNS rows, 4,713 HTTP rows, 3,041 SSL rows, 1,303 X.509 rows and 2,435 file rows. These are observed rows, not deduplicated real-world connection counts: multiple sensors can observe the same traffic. I additionally inspected representative firewall, proxy and Snort records. File/line citations are relative to the supplied data directory and use one-based lines. All human-readable times below are UTC.

The connection start timestamps cover approximately 13:00–19:00 on 2026-11-02. This is a six-hour slice, so I do not infer overnight behavior, daily seasonality, complete host lifetimes, or missing pre-window initiators from it.

### Connection states, packets, and duration

The visible state distribution is neither all-successful nor restricted to one reset pattern. DMZ has 2,586 TCP S0 rows alongside 5,431 TCP SF rows, whereas DB has only 11 S0 rows and 333 SF rows. These differences are consistent with an exposed segment receiving scans and a database segment carrying established service traffic; the numbers alone do not prove either authenticity or maliciousness.

I checked per-direction IP-byte totals against payload bytes and packet counts. Apparent lower-than-minimum aggregate TCP overhead occurred only where `missed_bytes` was nonzero; it would be incorrect to call those rows impossible merely because sequence-derived payload accounting exceeds captured packet payload. For instance, `zeek-core/conn.json:7596` has 8,338,456 responder bytes, 5,689 responder packets, 8,533,500 responder IP bytes, and 32,775 missed bytes, with history `ShADadfFGg`. The gaps are relevant to interpreting that accounting.

As a narrower sanity check, all 16,002 directional observations from SF TCP rows with no missed bytes and no `T/t/G/g` history markers had IP-byte-minus-payload totals divisible by four, as expected for aggregate IPv4/TCP header lengths. This does not validate packets that are not supplied, but it removes an obvious arithmetic tell.

Remote administration is not represented only by tiny placeholder flows. `zeek-core/conn.json:1123` has an RDP-classified SF connection from `10.10.1.31` to `10.10.2.27:3389`, lasting 1,412.640495 seconds, with 93,111 originator bytes and 1,935,432 responder bytes. Conversely, small completed probes also exist, such as line 2479 to that RDP destination with duration 0.077333 seconds. Without endpoint session evidence attached to each of those small flows, a short TCP flow is not proof of a successful interactive desktop session or a contradiction.

### SSH closure concentration

The recurring SSH closure pattern is the one finding that materially raises the synthetic-confidence score. It is not simply that several connections have similar durations: their durations differ enough to pull their ends toward the next absolute hour.

| Core conn line | Start UTC | Duration seconds | Computed end UTC |
|---|---|---:|---|
| 7 | 13:00:11.985611 | 3659.196919 | 14:01:11.182530 |
| 134 | 13:06:58.487625 | 3250.431154 | 14:01:08.918779 |
| 523 | 13:18:05.184648 | 2580.604962 | 14:01:05.789610 |
| 541 | 13:18:33.951240 | 2521.126393 | 14:00:35.077633 |
| 797 | 13:27:28.209603 | 2022.626608 | 14:01:10.836211 |
| 4567 | 14:45:00.106056 | 976.421048 | 15:01:16.527104 |
| 4707 | 14:49:09.599300 | 716.717700 | 15:01:06.317000 |
| 7332 | 16:22:29.350227 | 2300.248410 | 17:00:49.598637 |
| 7359 | 16:23:27.770434 | 2237.669050 | 17:00:45.439484 |

The 22 clustered connections involve client IPs `10.10.1.21`, `.31`, `.32`, `.35`, and `.42`, and destinations in the `.2`, `.3` and `.4` subnets. I counted core observations once rather than inflating this result with DB/DMZ observations of the same traffic. These are interior-window endpoints, so the result does not depend on truncating connections at the collection boundary.

A two-minute interval is 3.3% of a clock hour, while it contains 44% of these long successful SSH closures. That is a descriptive contrast, not a formal probability test against an unjustified uniform model. Cron-driven access revocation, a bastion lease, or another centrally scheduled activity remains possible. The logs supplied do not establish such a policy, so I retain uncertainty instead of calling the timing impossible.

### DNS, HTTP and protocol visibility

All DNS, HTTP and SSL UIDs resolved to a connection record within the same sensor. Their endpoint tuples agreed, and their timestamps fell within the corresponding connection interval using a small comparison tolerance (1 ms before start, 100 ms after end). The same checks passed for the supplied SMTP rows. File timestamps also stayed within their linked connection intervals where those connections were present, and individual observed file sizes did not exceed the relevant direction's connection byte count.

The mix of plaintext HTTP and HTTPS should be interpreted in the context of explicit proxying. The large port-8080 CONNECT population is not evidence that modern browsers are sending their application traffic in plaintext. Nor is the exclusively `version="1.1"` HTTP population enough to infer missing HTTP/2 inside encrypted tunnels.

There is one SMB reference group with no connection row in the supplied slice: UID `Cr7mRCkac27kS4mWeXo`, at `zeek-core/smb_mapping.json:89`, `smb_files.json:153-154`, and `files.json:482`, for `10.10.1.32:61160 → 10.10.2.21:445`. I did not score this as a defect. The visible mapping/read timestamps do not establish that the transport began inside the window, and conn-log filtering or export selection is another possible explanation. An absent reference alone is insufficient here.

### TLS and certificate identity

TLSv12 and TLSv13 coexist, with both resumed and non-resumed sessions and a small failed-handshake population. The DB sensor has 16 SSL observations, all TLSv12, while DMZ is predominantly TLSv13 (1,750 of 2,709 SSL rows). These differences fit heterogeneous services and external versus internal traffic better than requiring every host to use the same TLS policy.

Across the 1,303 X.509 observations, 194 unique certificate fingerprints were present. Repeated fingerprints did not disagree on serial, subject, issuer, validity bounds, key type/length, signature algorithm, SANs or CA status. In linked TLSv12 chains, RSA and ECDSA cipher authentication matched the leaf key type. TLSv13 rows did not expose encrypted certificate metadata, and resumed TLSv12 rows did not invent new chain evidence. These are concrete positive consistency results, not a claim that complete correlation itself proves reality.

### Temporal and environmental limits

Core connection starts by UTC hour were 1,779, 3,113, 1,724, 1,856, 2,192 and 1,718. DMZ counts were 1,561, 2,701, 1,143, 1,485, 1,449 and 1,290. There is visible variation and a concentrated busier hour rather than identical hourly totals. I do not assume the source of that peak or judge its narratability.

Domains may be sanitized, so public DNS ownership and real-world resolution were not used as authenticity tests. I did not penalize missing endpoint audit families, missing protocol collectors, or thin coverage solely because additional sources would be useful.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Zeek SSH connection lifetimes | 22/50 core SF SSH flows longer than 300 seconds end in minute 0 or 1; five clients and seven destinations | Main reason for the score of 43: repeated absolute-hour closure pattern suggests a scheduling artifact, with a plausible centrally managed policy alternative. |

No hard contradiction, demonstrated native-schema defect, or mandatory visible lifecycle violation was established. The unlinked SMB group was examined but excluded from scoring because a pre-window transport is possible.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed Zeek fields, state/history examples, body semantics and certificate relationships are internally credible.
- **Temporal patterns:** 6 — General volume varies, but long SSH closures show strong absolute-hour concentration.
- **Cross-source correlation:** 9 — Protocol/connection tuples and time intervals are coherent; proxy/NAT legs preserve distinct endpoint semantics.
- **Behavioral realism:** 8 — Administrative, infrastructure, database, browsing, failure and scanning patterns coexist; the SSH closure distribution remains a concern.
- **Environmental consistency:** 8 — Sensor-specific service mixes and explicit proxying are plausible; the slice cannot establish the policy behind synchronized SSH closures.

## Recommendations

- If this were synthetic, replace the observed absolute-hour SSH closure concentration with lifetimes based on actual session intent, user behavior and server policy. Preserve the wide range of observed session lengths while avoiding a recurring next-hour-plus-small-jitter endpoint unless a specific scheduled access policy is being modeled.
- If hourly revocation is intentional, make that interpretation testable through an appropriate visible policy or scheduled-maintenance artifact when such a source is collected. Do not add unrelated log families merely to explain it, and do not randomize away behavior that is actually required by the modeled environment.
