# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 20

## Executive Summary

The supplied network records look substantially like production telemetry: packet accounting, DNS transactions, TLS certificate relationships, proxy behavior, and independent sensor observations survive a broad set of consistency checks. I did not establish an impossible network relationship or a strong generator fingerprint; this supports a low synthetic-appearance score, but cannot establish that the records actually originated on a production network.

## Evidence For Synthetic

- [weak_signal] All 3,730 TCP `S0` records across the three sensors represent single observed originator SYN packets, with no responder packets and no duration field. Examples include `zeek-dmz/conn.json:1`, `10.10.3.10:42178 -> 10.10.2.21:443`, `history="S"`, and the contemporaneous deny at `fw-perimeter/cisco_asa.log:1`. This narrow failure shape deserves attention, but a large volume of scans, firewall drops, and selective observation can explain it. I do **not** treat it as a demonstrated defect or a strong scoring factor.
- No scored `hard_contradiction`, `contract_gap`, or `schema_or_format` indicator was established in the network evidence examined. Complete matching and coherent records are not themselves synthetic indicators.

## Evidence For Real

- The sensors have meaningfully different traffic mixes. `zeek-core/conn.json` contains 12,314 flows, dominated by DNS, Kerberos, HTTP proxy traffic, and LDAP; `zeek-db/conn.json` has 433, with 260 confirmed MySQL flows; `zeek-dmz/conn.json` has 9,401, including 2,847 SSL and 2,419 HTTP flows. These are plausible differences between internal, database, and perimeter observation paths.
- DNS contains multiple realistic classes of work and failure. Core has 2,333 A, 279 AAAA, 154 PTR, 105 SRV, and 300 TXT records, plus MX, NS, and SOA. Its response codes include 227 NXDOMAIN, 14 SERVFAIL, and four REFUSED. `zeek-dmz/dns.json:15` is an authoritative NXDOMAIN for `wpad.meridianhcs.local`, rather than a fabricated successful address response.
- TLS negotiates a plausible mix of versions and ciphers, and its certificate visibility follows version boundaries. Across the three sensors, none of the 2,007 TLS 1.3 records contains a certificate FUID chain; TLS 1.2 certificate-bearing records link to actual files and X.509 records. Checked ECDSA/RSA authentication suites agree with their leaf public-key types.
- There is coherent, imperfect observation across sensors. For the same HTTP exchange, `zeek-core/http.json:5` reports a 353-byte response while `zeek-dmz/http.json:5` reports 349; `zeek-dmz/files.json:1` explains this as `total_bytes=353`, `seen_bytes=349`, `missing_bytes=4`.
- Connection durations have a substantial range rather than one session length. `zeek-core/conn.json:5457` describes an SSH connection lasting 13,333.985520 seconds, while short service calls and failed handshakes occupy much shorter intervals. The corresponding DMZ observation independently records essentially the same long SSH interval.
- Proxy records distinguish CONNECT setup from inspected HTTP requests inside a tunnel. `PROXY-01.meridianhcs.local/proxy_access.log:1-4` shows CONNECT and subsequent GET activity, tunnel IDs and client source ports, control-message byte scope, and a reused CDN tunnel. Those distinctions make the visible HTTP/HTTPS distribution interpretable.

## Detailed Analysis

### Provenance, access scope, and method

I read the complete neutral briefing at `/private/tmp/log-study-6xx3sa0s/network-prompt.md`, enumerated only the supplied data directory, and parsed all JSON records under its three `zeek-*` directories. I also read small samples of the supplied proxy, firewall, and Snort text logs. The host endpoint and shell-history filenames appeared in that data-directory inventory, but I did not read their contents. No project directory, scenario, source code, TODO, worklog, previous assessment, or other reviewer's report was accessed. Inherited generic operating instructions were present in the environment; they were not treated as data-origin evidence.

The external references used were the official Zeek documentation, primarily the [connection record definition](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html), [SSL record definition](https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html), and [SSL log guide](https://docs.zeek.org/en/current/reference/logs/ssl.html). I ran read-only parsing and aggregation against log files; suspicious commands were not executed.

The three sensors contain 22,148 connection records: 15,032 TCP, 6,393 UDP, and 723 ICMP. They contain 4,313 DNS, 4,610 HTTP, and 3,142 SSL records. These counts include different sensors observing some of the same activity; they are not unique physical-session totals. First-packet timestamps span approximately 13:00–19:00 UTC on 2 November 2026. This is insufficient to assess overnight behavior or a full working-day curve.

### Connection states, timing, and packet accounting

Core's connection states include 10,053 SF, 1,897 S0, 150 RSTO, 116 RSTR, 29 OTH, 28 REJ, and smaller S1/S2/S3 populations. DMZ has 6,516 SF and 2,606 S0, along with resets, rejections, partial flows, and half-closes. The database view has 350 SF, 31 RSTO, 30 RSTR, and fewer other states. The larger overall S0 counts include non-TCP flows; the single-SYN observation above is specifically restricted to TCP.

These states have sensible examples and histories. The first DMZ SYN-only flow is explicitly denied by the firewall. Core's long SSH flow at line 5457 has `service="ssh"`, `conn_state="SF"`, `history="ShADadfF"`, and nonzero traffic in both directions. Its duration and endpoint tuple are also visible from the DMZ path.

I checked every connection for payload bytes exceeding IP bytes, nonzero payload with zero packets, TCP IP totals smaller than the minimum IPv4/TCP headers for the reported packet count, and IP totals exceeding the protocol's per-packet size bound. No violations appeared. UDP payload-to-IP overhead is consistently compatible with IPv4 plus UDP. These are necessary rather than sufficient packet plausibility checks; no packet capture was supplied.

No two TCP connection intervals within one sensor overlapped on the same directional four-tuple by more than 100 milliseconds. Thus, the data did not present a visible impossible concurrent reuse of one TCP identity.

### DNS behavior and cache plausibility

Core's first DNS record, `zeek-core/dns.json:1`, is an SRV request for `_ldap._tcp.meridianhcs.local`, returning two DC names. Its UID `Cuq507OFNo7MpYfALL` matches `zeek-core/conn.json:1`; both describe the same resolver tuple, and the DNS RTT and connection duration are both 0.028925 seconds. The flow's 46/167 payload bytes and 74/195 IP bytes are compatible with one IPv4 UDP packet each way.

Across all sensors, DNS UIDs resolve locally to connections. DNS timestamps do not precede their own connection starts by more than one millisecond or fall more than 100 milliseconds beyond the recorded interval. I found no error response carrying a contradictory successful answer list, no IPv6 literal used as an A answer or IPv4 literal as an AAAA answer, and no UDP request payload too small for its visible question name and required DNS fields.

The same resolver transaction can appear at multiple sensors. Matching address/port tuple and transaction ID within two seconds yielded 1,073 core/DMZ and 50 core/database DNS pairs. Their queries, types, response codes, answer lists, and TTL lists agreed. This is positive consistency evidence, not evidence of synthetic origin.

As a bounded cache check, I grouped successful nonauthoritative A responses by resolver, query, and answer set, then looked for TTL jumps greater than two seconds between observations one to ten seconds apart while the preceding TTL was still valid. None appeared. This does not establish a complete caching implementation, but avoids a common contradiction in repeatedly observed recursive answers.

I did not require every connection to have a new DNS lookup: caches, numeric destinations, and pre-window name resolution are legitimate explanations.

### TLS, X.509, and encrypted traffic visibility

DMZ contains 1,808 TLS 1.3 and 913 TLS 1.2 records, plus four without a negotiated version. Core has 199 TLS 1.3, 201 TLS 1.2, and three without a version. Database has 14 TLS 1.2 records. AES-GCM, ChaCha20-Poly1305, and some internal TLS 1.2 CBC selections occur in plausible roles; I found no TLS-version/cipher family mismatch in these distributions.

`zeek-dmz/ssl.json:1` records TLS 1.3 with `TLS_AES_256_GCM_SHA384`, an established session and `ssl_history="Cs"`, without inventing a visible certificate chain. In contrast, `zeek-core/ssl.json:1` is TLS 1.2, includes a leaf/intermediate chain, and joins the TCP flow at `zeek-core/conn.json:115` with detection after transport start.

Every listed TLS certificate-chain FUID resolves to both files and X.509 records within its sensor. Adjacent chain issuer/subject names agree. Repeated certificate fingerprints do not change their certificate fields, checked validity intervals cover the observed timestamps, and SHA-1 fingerprint and OCSP issuer hashes have the expected 40 hexadecimal characters. These checks do not cryptographically verify certificate signatures because certificate bytes are unavailable.

The 4,610 HTTP records are dominated by CONNECT requests to the explicit proxy, not by unencrypted application browsing. Core alone has 1,967 CONNECT requests; DMZ has 2,013. It would therefore be wrong to interpret the raw HTTP-to-SSL record ratio as the organization's plaintext-to-encrypted browsing ratio.

### HTTP transactions and sensor differences

Every HTTP and SSL UID resolves to a local connection. Applying the same one-millisecond start tolerance and 100-millisecond end tolerance produced no out-of-interval HTTP or SSL timestamps. Every individual HTTP request/response body length fits within the connection's corresponding direction's payload byte total.

HTTP includes GET/POST/CONNECT, authentication challenges, denied access, redirects, conditional 304 responses, and server/upstream errors. Transaction depths above one occur, including requests through depth six. For example, `zeek-dmz/http.json:638` is depth six on a browser connection, requesting a WebP image with a page referrer; `zeek-dmz/http.json:682` has a 304 response and zero body. This is more credible than treating every embedded object as an unrelated, identical transaction.

Of 2,119 matched core/DMZ HTTP observations, 25 have differing selected semantic fields; the checked examples involve response body lengths affected by collection loss. I do not assume every disagreement is a problem. The 353-versus-349-byte example is explicitly reconciled by the files record's four missing bytes. All 49 matched core/DMZ SSL pairs and 14 core/database pairs agree on the compared version, cipher, SNI, resumption, and establishment fields.

### Volume, roles, and limits

Core hourly flow counts are 1,849, 3,233, 1,757, 1,698, 2,068, and 1,709 for hours 13 through 18 UTC. DMZ's corresponding counts are 1,315, 2,713, 1,359, 1,465, 1,295, and 1,254. The elevated 14:00 hour coexists with many failed attempts; it should be interpreted through scanning/firewall behavior, not automatically as human workload.

The database sensor's 267 connections from `10.10.3.10` to `10.10.4.10:3306`, and core's substantial DNS/Kerberos/LDAP traffic, are consistent with differentiated infrastructure roles. I do not infer missing platform-specific services from hosts merely having a Windows, Linux, or Mac-like name. The time slice and supplied sensor placement also prevent a defensible conclusion about absent overnight traffic, full infrastructure coverage, or native endpoint collection.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| weak_signal | Zeek TCP connections | 3,730 S0 records across three sensors use a single-SYN shape | At most marginal; visible firewall denials and scan traffic provide an ordinary explanation. Not a demonstrated realism defect. |
| No established high-impact indicator | Network families examined | Transport, DNS, HTTP, TLS, certificate/file relationships | No hard contradiction or material contract gap found. The low score reflects observed appearance, not proof of production provenance. |

## Realism Score by Category

- **Field format accuracy:** 9 — Source-native fields, byte accounting, cipher/key relationships, and protocol records pass the checks described.
- **Temporal patterns:** 9 — Protocol observations fit their transport intervals, session lengths vary, and no overlapping TCP tuple reuse was found.
- **Cross-source correlation:** 9 — DNS/TLS/HTTP references resolve and sampled observation differences have plausible loss accounting.
- **Behavioral realism:** 8 — Infrastructure, proxy browsing, scans, caching, and long sessions coexist; six hours limit broader behavioral inference.
- **Environmental consistency:** 9 — Traffic and protocol distributions differ plausibly across core, DMZ, and database views.

## Recommendations

No evidence-backed corrective change is justified by this network review. If this were synthetic, retain the demonstrated distinctions between proxy control messages and tunneled traffic, TLS 1.3 encrypted certificate visibility and TLS 1.2 chains, and sensor-specific missing-byte accounting. The single-SYN failure population would merit packet-level or firewall-policy validation before changing it; the logs already show a plausible real-world explanation, so adding arbitrary retries would not be a supported improvement.
