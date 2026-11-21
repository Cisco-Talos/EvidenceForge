# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 28

## Executive Summary

The network evidence is mostly production-like: flow states, protocol companions, certificate visibility, DNS responses, and connection ownership remain coherent under record-level checks. A restricted browser-version vocabulary is a weak synthetic hint, but I found no demonstrated impossible network lifecycle or contradictory certificate/flow relationship; the real verdict is a moderate-confidence preference rather than proof of provenance.

## Evidence For Synthetic

- [weak_signal] A small browser-version vocabulary recurs across otherwise distinct clients in `zeek-core/http.json` and `zeek-dmz/http.json`: Windows clients repeatedly advertise Chrome/120, Edge/120, and Firefox/121, while the Mac browser traffic advertises Chrome/155. For example, core client `10.10.1.32` has 88 Firefox/121, 34 Chrome/120, and 30 Edge/120 requests, and `10.10.1.35` has 34 Chrome/120, 19 Edge/120, and six Firefox/121 requests. This could reflect a shared user-agent pool, but managed images, multiple installed browsers, and compatibility software are adequate alternative explanations. I give it limited weight and do not claim that version disparity is impossible.

## Evidence For Real

- Across all three Zeek sensors, 23,125 connection rows support 4,442 DNS, 5,479 HTTP, and 3,613 SSL rows. All examined protocol UIDs resolve to their sensor's connection table, and their timestamps lie within those connections' visible intervals. The evidentiary value is absence of contradictory lifecycles, not completeness itself.
- Connection outcomes have a plausible tail. Core has 9,925 `SF`, 1,624 `S0`, 168 `RSTO`, 119 `RSTR`, 42 `REJ`, and smaller `S1`/`S2`/`S3` populations; DMZ has a larger `S0` population consistent with its visible scanning. Successful TCP closures have both FIN directions in history; no TCP `S0` row has responder packets.
- DNS contains A, AAAA, PTR, SRV, TXT, MX, NS, and SOA questions in core, with NXDOMAIN, SERVFAIL, and REFUSED responses. AAAA NODATA responses coexist with real IPv6 answers, rather than every question being forced into an IPv4 success.
- TLS 1.3 rows do not expose certificate-chain FUIDs. TLS 1.2 chain references resolve, issuer/subject links agree, cipher authentication matches visible leaf key type, and fingerprints do not identify conflicting certificate contents.
- DHCP renewals retain stable MAC/address/lease identities while varying around half the lease duration. For example, `MAC-MROSS-01` retains a 7,200-second lease with successive renewal intervals of approximately 3,536, 3,760, 3,736, 3,585, and 3,614 seconds.
- The sources distinguish HTTP CONNECT control messages from tunneled TLS and distinguish SMTP STARTTLS from visible mail content. These are substantive protocol visibility boundaries.

## Detailed Analysis

### Scope and method

I inspected only the supplied data directory. Analysis concentrated on every JSON record under `zeek-core`, `zeek-dmz`, and `zeek-db`, supplemented by samples of proxy, ASA, and Snort records. I parsed the network JSON, counted protocol/state distributions, joined protocol rows to connection UIDs, checked time intervals and TCP tuple reuse, compared certificate identities and chain relationships, inspected DNS answer types and TTL behavior, and followed representative infrastructure and administrative flows. Times below are UTC on November 2, 2026.

The core connection window is approximately 13:00:01.809–18:59:58.683; DMZ is 13:00:19.086–18:59:39.858. DB has a smaller but overlapping window and 364 connection rows. I did not require boot-time state, post-window teardown, additional endpoint event types, or packet captures that were not supplied.

### Connection states, accounting, and timing

There are 16,165 TCP observations across the three sensors; these include observations of the same traffic at different sensors and should not be treated as unique conversations. I found no overlapping visible TCP connection intervals for the same origin/address/port and responder/address/port within an individual sensor. No TCP `S0` row claims responder packets, and all TCP `SF` histories contain both `F` and `f`. Gaps marked `G`/`g` coincide with nonzero `missed_bytes`; nonzero missed-byte rows also carry a gap marker.

Some rows have IP-byte totals smaller than sequence-derived payload plus a minimum header calculation. Those occur with capture gaps and are not a demonstrated contradiction: TCP stream-byte accounting can include inferred sequence space not captured as packet bytes. I did not use that shortcut as an authenticity finding.

Durations differ materially by service. In core, the median measured SSH duration is approximately 2,185 seconds, RDP approximately 345 seconds, LDAP 2.15 seconds, and proxy-port 8080 approximately 1.87 seconds. Core SSH UID `Cp18EN60koScLZ227` begins at 13:00:44.583201, from `10.10.1.21:40111` to `10.10.3.10:22`, lasts 3,631.909177 seconds, and has `SF` with 11,778/49,556 payload bytes. This is a plausible low-throughput interactive connection. Core RDP UID `CI0NcQBAEE0nxyDHfRp`, at 13:58:08.206919, connects `10.10.1.35:55305` to `10.10.2.20:3389` for 156.145928 seconds, transfers 326,013/267,699 bytes, and closes with `SF`.

The core hourly connection counts are 1,595, 3,142, 1,914, 1,707, 2,153, and 1,866 from 13:00 through 18:59. These are not flat counts. The 14:00 increase is not inherently suspicious as an authenticity matter; scans and other bursts are visible. A six-hour slice cannot establish overnight or weekly seasonality, so I did not score their absence.

### DNS resolution and cache behavior

Core DNS contains 2,418 A, 285 AAAA, 274 TXT, 156 PTR, 104 SRV, six NS, six MX, and two SOA records. Its response outcomes include 244 NXDOMAIN, 11 SERVFAIL, and two REFUSED records. DMZ adds 154 NXDOMAIN, four SERVFAIL, and one REFUSED among its 1,154 rows. All examined DNS answer/TTL arrays have matching lengths; no parsed A answer is an IPv6 literal and no parsed AAAA answer is an IPv4 literal. Failure responses do not contain contradictory positive answers.

For example, core UID `CJjXxHBVaFeuG3riBIx` asks for the AAAA record of `DC-02.meridianhcs.local`, returns `NOERROR`, and omits positive answers: a credible IPv6 NODATA result. DMZ UID `CShDGu59OKdTJbeVjlP` returns an actual IPv6 address for `update.dbeaver.io`, with TTL 307. I do not assess whether sanitized domains resolve to those addresses publicly.

Core DNS RTT has a median approximately 4.33 ms at the connection level, whereas DB DNS median duration is approximately 1.41 ms and DMZ approximately 26.05 ms. The mixture of short local resolutions, slower recursive responses, low TTLs, and cached TTLs is plausible. In repeated successful same-client/same-resolver/same-question records, I found no example of the same answer's TTL increasing before the earlier minimum TTL expired. Repeated queries alone are not evidence of broken caching because multiple applications can use different caches.

The TXT-heavy subset includes high-entropy labels under `ns1.westbridge-services.cloud`; for example, core UID `C29IMrDExCekbalBDb` at approximately 17:45 resolves a long encoded label and receives a TXT answer with TTL 1 and RTT 0.313231 seconds. This can support investigation of tunneling. Its suspicious content does not establish synthetic origin.

### TLS and certificate visibility

DMZ has 2,114 TLS 1.3, 1,075 TLS 1.2, and two rows without a negotiated version. Core has 186 TLS 1.3, 218 TLS 1.2, and one without a negotiated version. The TLS 1.3 ciphers are AES-GCM and ChaCha20-Poly1305; TLS 1.2 includes RSA- and ECDSA-authenticated ECDHE suites. I found no visible ECDHE-ECDSA/RSA leaf-key mismatch.

Core SSL UID `CbAaBiromtFLT8kcL7`, at 13:06:44.094742, identifies `APP-INT-01.meridianhcs.local`, TLS 1.2, and `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`. Its leaf FUID `FxmuO8baLdfUBiLpfm` has a 4,096-bit RSA key and an issuer matching the next certificate's subject. Repeated leaf observations preserve certificate identity. All examined visible chains have agreeing issuer/subject links and validity intervals covering their handshakes.

TLS 1.3 encryption limits are respected: none of the TLS 1.3 rows claims a passive visible certificate chain. Resumed sessions and failed negotiations also appear. These distinctions materially improve plausibility; I did not penalize consistent chain joins as being too complete.

### HTTP, proxy, SMTP, and collection interpretation

CONNECT dominates HTTP because an explicit proxy is visible. Core has 2,317 successful CONNECT transactions, with 403, 407, 502, 503, and 504 outcomes also present. Ordinary GET/POST traffic includes redirects, caching responses, and partial-content responses. All 204/304 rows examined have zero response-body length, and no individual HTTP response body exceeds its parent connection's response stream bytes.

At approximately 13:00:19, the proxy records a CONNECT to `ctldl.windowsupdate.com:443` from `10.10.2.10`; the DMZ has a separate proxy-originated TLS connection `CVLqENoLEv13zc7PMM` from `10.10.3.20:41424` to the destination. The proxy record explicitly separates control-message bytes and tunnel bytes. This makes the large HTTP count compatible with the substantial TLS count rather than implying implausibly widespread plaintext browsing.

Core SMTP UID `CkBUMe4cQnSNXwaGp` describes submission from `10.10.1.36:58907` to `10.10.2.25:587`, advertises readiness for TLS, and has empty message-envelope/content fields. Its matching SSL row describes the subsequent TLS 1.2 handshake. Conversely, other plaintext SMTP transactions expose recipients, message IDs, and file FUIDs. This is a credible visibility distinction.

A representative SSH tuple is observed in core and DMZ with separate UIDs, nearly identical durations, and a roughly 115 ms timestamp offset. A DNS tuple also shows a similar sensor offset. Sensor clocks can explain this; it is not enough to assert impossible transit time. I would preserve that offset during reconstruction rather than combine sensor timestamps as though clocks were perfectly synchronized.

### Remaining uncertainty

Most successful checks are consistency tests, which a careful simulator could also pass. The shared browser-version vocabulary is the principal weak synthetic indicator I can defend from the visible records. It is not accompanied by an impossible protocol sequence, invariant-count pattern, conflicting certificate identity, or demonstrated collection contradiction. That balance supports a low synthetic-confidence score and only moderate confidence in the binary real verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek HTTP user agents | Repeated Chrome/120, Edge/120, Firefox/121 vocabulary across several Windows clients; Mac Chrome/155 population differs | Small increase; a shared browser/version pool is possible, but managed images and application compatibility provide realistic explanations |

No confirmed hard contradiction, contract gap, or schema/format defect survived the record-level checks described above.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed JSON, coherent field types, plausible histories and DNS answers, and consistent TLS/certificate structures.
- **Temporal patterns:** 9 — Variable service durations, uneven hourly activity, plausible renewal jitter, and no demonstrated within-connection protocol inversion.
- **Cross-source correlation:** 9 — Valid protocol references, consistent certificate chains, and plausible proxy/SMTP visibility boundaries; sensor clock offsets require ordinary reconstruction care.
- **Behavioral realism:** 8 — Mixed failures, infrastructure traffic, admin sessions, scanning, and application traffic; recurring browser versions remain a weak pool-like texture.
- **Environmental consistency:** 9 — Distinct core/DMZ/DB traffic distributions and credible proxy, DNS, mail, and DHCP roles.

## Recommendations

- If this were synthetic, retain host-specific browser/version choices and explain the recurring Chrome/120, Edge/120, and Firefox/121 population through a consistent software inventory or deployment history. Broaden versions only where the modeled estate warrants it; arbitrary per-request version changes would reduce realism.
- Preserve the existing protocol visibility distinctions, stable certificate identities, source-specific UIDs, and DHCP lease ownership. My analysis found no concrete defect that justifies adding unrelated log sources or inflating traffic volume.
