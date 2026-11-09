# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 66
**Synthetic-Confidence Score:** 24

## Executive Summary

The network records are mostly production-like: transport states, protocol byte budgets, proxy topology, TLS certificate visibility, and source-local UID relationships withstand detailed checks. I found no demonstrated impossible network relationship; the main reservation is a narrowly timed appearance of ordinary TXT-query activity across many hosts, which is explainable and carries little weight.

## Evidence For Synthetic

- [weak_signal] **A DNS query family appears unusually late across otherwise diverse hosts.** In `zeek-core/dns.json`, no TXT query appears before line 2189 at `2026-11-02 17:42:14.619765 UTC`, although the sensor begins at 13:00. Excluding queries under `westbridge-services.cloud` and its separate `metrics.westbridge-services.net` name, 33 other TXT transactions originate from 18 addresses and appear only between 17:42 and 18:03. They include SPF, DMARC, and DKIM lookups by ordinary client/server addresses. This distribution merits checking as a possible abruptly enabled workload; it is not a protocol contradiction, and scheduled software or collection selection could explain it. I assign only a small authenticity penalty.

## Evidence For Real

- **Protocol records remain inside their own transport intervals.** Every DNS, HTTP, and SSL record in each of the three Zeek sensor directories matches a local connection UID and endpoint tuple. None has a timestamp before that connection begins or after its recorded duration ends.
- **Failed and imperfect traffic has differentiated representations.** Core connections include 1,663 `S0`, 136 `RSTO`, 116 `RSTR`, 26 `REJ`, and smaller `S1`/`S2`/`S3` populations; DMZ connections include 2,467 `S0`, 121 `RSTO`, 63 `RSTR`, and 31 `REJ`. TCP gap histories also carry nonzero `missed_bytes`, rather than implausibly retaining a universally clean capture.
- **DNS contains realistic positive and negative cases.** Core DNS has A, AAAA, PTR, SRV, TXT, NS, MX, and SOA questions; it includes 218 NXDOMAIN, 21 SERVFAIL, and six REFUSED responses. `zeek-core/dns.json:5` is an authoritative NXDOMAIN for `printer01.meridianhcs.local`, while line 12 has an actual IPv6 AAAA answer.
- **Explicit proxy evidence preserves protocol boundaries.** `zeek-dmz/http.json:1` records a successful CONNECT to `clients6.google.com:443`; `zeek-dmz/conn.json:1` identifies the client-to-proxy transport as `10.10.1.32:57530 -> 10.10.3.20:8080`. A separate proxy-to-server TLS transport is observed, and the proxy access record distinguishes CONNECT control-message bytes from tunnel bytes.
- **TLS visibility is restrained and internally coherent.** TLS 1.3 records have no certificate-chain FUIDs, while available TLS 1.2 certificate references resolve to consistent files/X.509 records. Certificate fingerprints, issuer/serial identities, validity windows, and cipher/key-type relationships agree in the checked records.

## Detailed Analysis

### Scope, provenance, and method

I read the supplied neutral briefing at `/private/tmp/log-study-rfg61n4z/network-prompt.md` and inspected files only under `/private/tmp/log-study-rfg61n4z/data`. I used system `python3` from explicit neutral working directory `/private/tmp`; I did not invoke project tools or read project files, scenarios, worklogs, prior results, or other reviewers. Generic inherited operating instructions were excluded from the authenticity judgment. For one source-native question, I opened the direct upstream [Zeek DNS implementation](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/dns/main.zeek); no project-related web pages or general search results were consulted.

The quantitative review parsed all Zeek JSON records, including 12,162 core, 9,382 DMZ, and 392 database connection records. These are sensor observations, not necessarily distinct physical connections: overlapping sensor coverage should not be counted as independent network volume. I also sampled the perimeter ASA and Snort text and the proxy access log. The core connection slice runs from `2026-11-02 13:00:02.512987 UTC` through `18:59:50.133776 UTC`.

Line citations are one-based physical lines in the supplied files. No packet capture, sensor configuration, OS inventory, or cryptographic certificate bytes were supplied, limiting claims about exact packet content and deployment configuration.

### Transport state and packet accounting

Core contains 6,617 TCP, 5,155 UDP, and 390 ICMP observations. DMZ contains 7,995 TCP, 1,077 UDP, and 310 ICMP observations; database contains 334 TCP, 48 UDP, and ten ICMP observations. The core's substantial Kerberos, DNS, LDAP, SMB, and client-to-proxy traffic differs appropriately from the DMZ's much larger SSL population and the database sensor's dominant MySQL population.

Normal closes coexist with resets, unanswered attempts, incomplete closes, and midstream observations. This is more credible than a universal `SF` state. I do not treat scanning or failed connections as evidence of synthetic origin: their source-native states are compatible with the visible activity.

I checked payload bytes, packet counts, and IP-byte lower bounds. Apparent cases where payload plus minimum TCP headers exceed observed IP bytes all carry gap-marked histories and nonzero `missed_bytes`; they therefore do not establish an impossible budget. For example, `zeek-core/conn.json:59`, UID `CQLXYi1jYH2s3pak1o`, has `orig_bytes=1737`, `orig_pkts=4`, `orig_ip_bytes=1894`, `missed_bytes=7`, and history `ShADadfFG`. Sequence-space accounting and missed capture must be considered together. I found no positive payload with zero packets and no IP-byte total smaller than its payload total.

Within each sensor, no pair of TCP records with the same oriented address/port tuple has overlapping visible transport intervals. Successful SSH and RDP transports have meaningful durations rather than tiny authentication placeholders. For example, `zeek-core/conn.json:7` records TCP/22 to `10.10.2.30` for `3659.196919` seconds; line 1123 records TCP/3389 to `10.10.2.27` for `1412.640495` seconds, with 93,111 originator and 1,935,432 responder payload bytes.

### DNS semantics and timing

The core DNS mix is 2,311 A, 330 TXT, 260 AAAA, 163 PTR, 100 SRV, ten NS, seven MX, and two SOA records. RTT deciles span roughly 0.00067 to 0.116 seconds, with both local-resolution and slower recursive-like responses. TTLs include common fixed values and descending/nonround values; AAAA NOERROR records without answers coexist with successful IPv6 answers. This is compatible with an IPv4 transport environment querying both address families.

Every DNS question fits the minimum encoded question length allowed by its matching connection's originator payload. TXT string-length prefixes are consistent with the supplied decoded text, including multi-string DKIM answers. Hostname-only SRV answer summaries are not a defect: upstream Zeek's DNS script deliberately summarizes the SRV answer using the target hostname. The same script logs TXT strings with explicit string-length prefixes. These source-native details were verified against the upstream implementation rather than inferred from DNS wire-format expectations.

The burst of high-entropy TXT questions from `10.10.2.30` is recognizable as unusual network behavior but is not itself an authenticity problem. Its mixture of successful responses and DNS errors is technically plausible. The small concern is the separate ordinary TXT population's abrupt time-window restriction across 18 source addresses, described above. That concern remains weak because a scheduled application, troubleshooting action, or selection policy can produce it.

I did not infer a causality defect merely because a connection lacks a nearby preceding DNS query: cached answers, direct addresses, and pre-window resolution are valid explanations.

### HTTP, proxy, and TLS

Core HTTP is predominantly CONNECT: 1,965 of 2,176 rows. DMZ has 2,019 CONNECT rows among 2,441 rows. The visible explicit proxy makes these proportions intelligible; it would be wrong to interpret the CONNECT rows as plaintext retrieval of every HTTPS resource. Authentication challenges, policy denials, gateway failures, redirects, partial content, and repeated transactions appear alongside success. HTTP body lengths never exceed the corresponding directional connection payload totals in the checked records.

The first proxy access row reports `proxy_action=tunnel`, `byte_scope=connect-control-message`, `cs_bytes=520`, `wire_sc_bytes=213`, `tunnel_cs_bytes=4274`, and `tunnel_sc_bytes=34835`. These sum to the corresponding DMZ client/proxy connection payloads, 4,794 and 35,048 bytes. The separate external TLS row in `zeek-dmz/ssl.json:1` has SNI `clients6.google.com` and an ECDSA cipher with an EC leaf certificate. This is concrete semantic coherence; completeness alone was not used as an authenticity indicator.

TLS versions are mixed: core has 181 TLS 1.3 and 168 TLS 1.2 records plus one attempt without a version; DMZ has 1,834 TLS 1.3, 859 TLS 1.2, and three unversioned attempts. No TLS 1.3 record claims a visible certificate chain. Available certificate-chain FUIDs all resolve in their sensor's files and X.509 logs, SHA-1 file hashes match certificate fingerprints, no issuer/serial pair maps to conflicting fingerprints, and no repeated fingerprint maps to conflicting certificate metadata. All recorded certificate validity windows include the observation time. These checks support credibility without proving the certificate bytes were genuine.

### Traffic timing and environmental interpretation

Hourly core connection counts are 1,779, 2,978, 1,801, 1,771, 2,112, and 1,721 for UTC hours 13 through 18. DMZ counts are 1,561, 2,546, 1,425, 1,472, 1,251, and 1,127. The variation is not a flat fixed-rate workload. The six-hour slice cannot establish overnight behavior, a full workday cycle, or weekday/weekend variation; I make no authenticity deduction from those absent windows.

Service placement is understandable from network evidence: domain-service traffic concentrates on the core, proxy-facing SSL on the DMZ, and MySQL on the database observation path. This does not establish native endpoint telemetry on any platform, and I did not impose Windows-only infrastructure expectations on every host.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `weak_signal` | Core DNS TXT workload | 33 ordinary TXT queries from 18 addresses appear only around 17:42–18:03, after over four hours without TXT observations | Small penalty for an abrupt family-level timing change; a scheduled workload or selection policy remains plausible |

No `hard_contradiction`, `contract_gap`, or demonstrated `schema_or_format` defect was established by this network review. The score reflects mostly realistic data with one explainable distribution reservation, not confidence in identifying a generator.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source-native fields and checked DNS/TLS details are coherent; packet bytes were unavailable for direct validation.
- **Temporal patterns:** 8 — Protocol timestamps fit transport lifetimes and activity varies by hour; the ordinary TXT family has a narrow unexplained window.
- **Cross-source correlation:** 9 — UID, endpoint, certificate, file-hash, and proxy byte-accounting relationships agree in the performed checks.
- **Behavioral realism:** 9 — Successful sessions, scanning, errors, resumptions, proxy denials, and administrative transport durations coexist plausibly.
- **Environmental consistency:** 9 — Core, DMZ, and database protocol distributions fit their visible paths without requiring unspecified collectors or platforms.

## Recommendations

- If this were synthetic, give the ordinary SPF/DMARC/DKIM query workload an explicit application or scheduled-job basis, or distribute it according to the existing clients' activity rather than introducing the entire family late across many addresses. The specific issue to address is the source-family timing distribution, not the suspicious TXT traffic itself.
- Preserve the present distinctions among proxy control-message and tunnel bytes, TLS 1.2 and TLS 1.3 certificate visibility, and transport states with capture gaps. These are substantial strengths in the supplied network evidence.
