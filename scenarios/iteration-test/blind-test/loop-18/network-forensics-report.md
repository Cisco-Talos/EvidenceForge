# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 70
**Synthetic-Confidence Score:** 20

## Executive Summary

The supplied network telemetry is consistent with a production collection from a segmented, proxy-using enterprise, with substantial failed connection traffic alongside ordinary authentication, browsing, mail, database and administration activity. Detailed checks found coherent transport/protocol relationships, credible DNS and TLS variation, and no demonstrated impossible ordering or field-value contradiction; the six-hour window and lack of packets limit how conclusively origin can be established.

## Evidence For Synthetic

- No substantive synthetic indicator survived the protocol and correlation checks. This is an assessment of the supplied evidence, not proof that the records could not have been generated.
- One initially concerning reference is `zeek-core/smb_mapping.json`, UID `CJqVWaauzqBwjEIOtb`, timestamp `1793640924.870101`, which has no matching UID in that sensor's supplied `conn.json`. I did **not** score this as a contract gap: connection summaries can fall outside a collection window, and a mapping observation does not establish that a connection's summary must already appear inside this slice.

## Evidence For Real

- Connection outcomes have meaningful variation: core contains 9,925 `SF`, 1,624 `S0`, 168 `RSTO`, 119 `RSTR`, 42 `REJ`, plus incomplete and other states. DMZ contains 2,539 `S0` versus 7,317 `SF`; the database sensor has only four `S0` versus 290 `SF`. This is consistent with different observation paths and exposure, rather than an identical population at every sensor.
- DNS includes A, AAAA, PTR, SRV, TXT, NS, MX and SOA questions, successful empty answers, NXDOMAIN, SERVFAIL and REFUSED. Core has 244 NXDOMAIN, 11 SERVFAIL and two REFUSED among 3,251 transactions; DMZ has 154 NXDOMAIN among 1,154.
- Explicit proxy CONNECT transactions explain the large HTTP analyzer volume without implying that most browsing is cleartext. At `1793624419.225776`, core HTTP UID `C5W8btdFdykKhFktWhS` records CONNECT to `ctldl.windowsupdate.com:443` through `10.10.3.20:8080`; DMZ separately observes the proxy's external TLS connection.
- TLS varies by observation path. The DMZ has 2,114 TLS 1.3 and 1,075 TLS 1.2 observations, with two rows lacking a negotiated version. All 17 database SSL rows are TLS 1.2. Full and resumed TLS 1.2 handshake histories have correspondingly different certificate visibility.
- Visible protocol rows match their transport UIDs and four-tuples, with no observed DNS/HTTP/SSL transaction preceding its matching visible connection start. Full certificate identity checks also found no conflicting certificate fields for repeated fingerprints within a sensor.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed all 23,125 Zeek connection records: 12,377 core, 10,384 DMZ and 364 database. I inspected the associated DNS, HTTP, SSL, X.509, files, OCSP, SMB, DHCP and SMTP records, and sampled the firewall, IDS, proxy and endpoint FLOW telemetry to understand the observation path. All timestamps below are raw epoch seconds unless explicitly shown in UTC.

The conn timestamps span approximately 2026-11-02 13:00–19:00 UTC. This is not enough to assess overnight or weekly behavior. Likewise, there is no basis for requiring QUIC, NTP or additional endpoint source families solely because they could exist in this environment.

### Transport behavior and accounting

Across all three sensors, no connection had application-byte totals exceeding the corresponding IP-byte totals. No direction's IP bytes exceeded the maximum possible bytes implied by its packet count and an IPv4 maximum-sized packet; the sampled accounting also stays within ordinary Ethernet-sized average packets. Established TCP `SF` rows consistently carry handshake markers in history. Retransmission and content-gap markers occur, and gap-marked rows carry nonzero `missed_bytes`: 543 core rows, 661 DMZ rows and 29 database rows. I found no simple gap-marker/zero-missing-byte contradiction.

Core SSH has 59 successful `SF` flows, 288 unanswered `S0`, seven `RSTO`, three `REJ` and one `RSTR`. This is not a population of universally successful administrative sessions. Successful remote administration can be long-lived: UID `Cp18EN60koScLZ227` starts at 13:00:44.583201 UTC from `10.10.1.21:40111` to `10.10.3.10:22`, lasts `3631.909177` seconds and carries 11,778 originator and 49,556 responder bytes. Short transfers and long interactive connections need different interpretations; duration alone is not contradictory.

### DNS semantics and timing

All 4,442 supplied DNS rows have matching same-sensor connection records and matching endpoint tuples. Every row's answer and TTL arrays have equal lengths. For A/AAAA answers that parse as IP literals, address families agree with the question type. No query has less transport payload than the minimum encoded DNS question size implied by its name. Query payload sizes show several overhead populations, consistent with questions with and without EDNS options rather than a single fixed byte count.

DNS RTT is not a flat constant. The database A-question median is `0.001338` seconds, core A-question median `0.003056`, and DMZ A-question median `0.036645`; internal and externally resolved populations differ. I paired 1,153 core/DMZ DNS observations using tuple, transaction ID, question and nearby timestamps. Their RTT differences were all below 10 ms, with a maximum approximately 1.596 ms. Sensor timestamp offsets therefore do not create a demonstrated disagreement about the underlying transaction duration.

For example, core UID `Cp6MLk46xgCh5RXxuJB` and DMZ UID `CuFcCYZbDRl83hpEUoo` both observe transaction ID 55241 from `10.10.3.20:49904` to `10.10.2.10:53` for `pypi.org`; answers and TTLs agree while timestamps and UIDs remain sensor-local. Domain/IP public resolution was not used as an authenticity test because sanitization is allowed.

### HTTP, proxy and TLS interpretation

Core HTTP has 2,414 CONNECT, 180 GET and eight POST transactions. DMZ has 2,454 CONNECT, 395 GET and 16 POST. These counts include overlapping sensor views and must not be summed as unique requests. Both sensors also have redirects, denials, proxy authentication challenges and upstream errors. Core status counts include 37 HTTP 403, 31 HTTP 407, 19 HTTP 301, 11 HTTP 503, ten HTTP 504 and nine HTTP 502. This is credible proxy and application behavior.

The first proxy access entry records a CONNECT at 13:00:19 UTC with explicit control-message versus tunnel-byte accounting. The transport evidence separates the client-to-proxy TCP/8080 flow from the proxy-to-remote TCP/443 flow. It would be incorrect to demand that the original client directly originate the external TLS tuple.

For TLS 1.2 chains that are visible, I checked RSA/ECDSA cipher authentication against the leaf key type and found no mismatch. Repeated certificate fingerprints retain consistent certificate/SAN fields. DMZ TLS 1.2 histories include 386 resumed `CsiI` observations without certificate chains, versus 496 full `CsxknGIi` and 127 full `CsxknGIti` observations with chains. Some full handshake rows lack exported chains, which does not by itself establish an impossible handshake or collection contradiction. TLS 1.3's limited visible certificate evidence is also not a missing-companion defect for a passive sensor.

### Correlation limits

For every supplied same-sensor DNS, HTTP, SSL, SMTP and SMB file row, its referenced connection was present. The only exception across the inspected protocol families was the one SMB mapping reference described above. Among matched rows there were no tuple mismatches, no transaction timestamps earlier than connection start by more than 1 ms, and none later than the connection interval by more than 100 ms.

These checks support consistency; complete matching itself is not evidence of either origin. I did not infer a missing login, packet or process merely because a neighboring source would have helped investigate the traffic. Packet captures, sensor configuration and a longer time range could change this assessment.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| No demonstrated substantive indicator | Zeek transport and protocol companions | All three supplied sensors | No hard-contradiction, contract-gap or distribution penalty established |
| Unscored reference anomaly | Zeek SMB mapping/connection | One mapping UID without a supplied conn row | Window/connection-summary timing remains a viable explanation; not used to raise the score |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed fields, protocol families, byte accounting, DNS types and certificate/cipher relationships are coherent.
- **Temporal patterns:** 9 — Durations and RTTs vary, long administration sessions exist, and visible protocol/transport order is consistent; only six hours are available.
- **Cross-source correlation:** 9 — Tuple and UID checks are coherent, proxy legs are distinct, and one unmatched mapping has an unresolved window explanation.
- **Behavioral realism:** 9 — Authentication, proxy errors, browsing, infrastructure traffic, failed probes and database activity coexist plausibly.
- **Environmental consistency:** 9 — Core, DMZ and database populations differ in ways supported by their visible services and observation paths.

## Recommendations

- If this were synthetic, preserve the explicit distinction between proxy control bytes, tunneled bytes and the separate external TLS connection; the supplied records already support that interpretation.
- No concrete network defect was established that warrants prescribing a generator change. To resolve the single SMB mapping reference operationally, include any available later connection-summary records or document the connection-summary cutoff; do not fabricate an initiating record merely to fill the slice.
