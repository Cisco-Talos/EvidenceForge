# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 85
**Synthetic-Confidence Score:** 72

## Executive Summary

The network records are convincing in most protocol fields, timing, and reference relationships, but the proxy's HTTP request byte accounting and the corresponding client-side Zeek connection accounting are not convincing as native wire telemetry. These are repeated, measurable defects rather than a judgment about the completeness or narrative shape of the activity; undocumented normalization or a reconstructed decrypted packet feed remains an alternative explanation.

## Evidence For Synthetic

- [contract_gap] **Inspected HTTP/1.1 requests are smaller than their logged request line and User-Agent alone.** In `PROXY-01.meridianhcs.local/proxy_access.log:19` (2026-11-02 13:01:58 UTC), the GET for `/vizql/068a8694ed7787ab/bootstrap.js` has `cs_bytes=88`, whereas its origin-form HTTP/1.1 request line, logged User-Agent header, and terminating blank line require at least **145 bytes**, even excluding Host, Referer, and every other header. Line 49 requires at least 180 bytes but reports 109; line 59 requires at least 144 but reports 84. Across all 1,445 `proxy_action=ssl-inspect` rows, **284** fail this conservative bound; **465** fail when the logged Referer header is also included. This is conditional on `cs_bytes` meaning client request bytes, as the transport accounting strongly suggests; the custom field has no supplied schema.
- [contract_gap] **Client-side CONNECT flow accounting repeatedly contains no room for TLS.** Proxy lines 1–2 describe tunnel `PT-a5e41cdf86225d43`, source `10.10.1.22:40446`, `ssl_bump=bump`: CONNECT control bytes are 446/116 and the inspected HTTP exchange is 591/12,536. `zeek-core/conn.json:14`, UID `CELXnfXle5xKKCfE4gp`, records exactly **1,037/12,652** TCP payload bytes, equal to those cleartext sums. `zeek-dmz/conn.json:3` repeats that accounting for its independently observed UID `CiZmkHQSPEg2iX1JD7h`. That leaves zero allowance for the client-to-proxy TLS handshake and record framing/authentication. Among **1,031** unambiguously matched inspected tunnels in the core sensor, **510** have both connection byte counters exactly equal to CONNECT control plus the sum of observed inspected HTTP request/response byte counters. This is a repeated cross-layer accounting defect under a native network interpretation, not a complaint about complete matching.

## Evidence For Real

- The three sensors have different traffic mixes consistent with different observation paths. Core has 2,479 Kerberos and 1,208 LDAP connections; the DB sensor has 260 MySQL connections among 433 total; the DMZ sensor has 2,847 SSL-classified and 2,419 HTTP-classified connections among 9,401 total. Much of HTTP is CONNECT, so a superficially high HTTP count does not imply predominantly plaintext browsing.
- There is a useful and plausible range of connection outcomes, including no-response attempts, rejected connections, originator/responder resets, one-sided closes, midstream observations, and normal closes. Core counts are SF 9,897, S0 1,652, OTH 430, RSTO 150, RSTR 116, REJ 28, S2 16, S3 15, S1 10. I found no HTTP, DNS, or SSL companion attached to an S0/REJ transport in these sensor files.
- DNS includes A, AAAA, PTR, SRV, MX, TXT, NS, and SOA, alongside NXDOMAIN, SERVFAIL, and REFUSED. Core has 227 NXDOMAIN, 14 SERVFAIL, and 4 REFUSED among 3,188 DNS records. Negative AAAA results and internal service discovery are present; DNS response times are varied rather than one constant.
- TLS 1.3 records do not expose certificate chains; TLS 1.2 includes full and resumed sessions, RSA and ECDSA authentication, GCM and some CBC ciphers. All supplied SSL certificate references resolve within their sensor's X.509 records. I found no selected TLS 1.2 ECDSA/RSA cipher contradicting the referenced leaf key type.
- HTTP body lengths do not exceed their same-UID transport payload counters. Certificate file byte totals do not exceed the matching responder payload counters. Application timestamps stay within the matching visible connection intervals under the tolerance described below.

## Detailed Analysis

### Input provenance and limitations

I read the complete neutral briefing at `/private/tmp/log-study-mytn1lc8/network-prompt.md`, enumerated files only under `/private/tmp/log-study-mytn1lc8/data`, and parsed the supplied JSON records in `zeek-core`, `zeek-dmz`, and `zeek-db`. I inspected proxy access, perimeter ASA, and core Snort records, and bounded samples of the supplied WEB-EXT-01, APP-INT-01, and MAC-MROSS-02 normalized eCAR records to understand flow shapes. I did not inspect repository files, scenarios, generated explanatory artifacts, previous assessments, or other reviewers' outputs. Inherited generic project/operating metadata was present in the agent context; that is a blinding limitation, not evidence about this dataset's origin, and was not used in scoring. Log commands were treated as inert strings.

Public reference access used actual `docs.zeek.org`, `www.squid-cache.org`, and `rfc-editor.org` domain filters, plus a direct RFC URL. No task-project web material was accessed. References establish protocol and counter semantics, not the dataset's origin.

The connection timestamps cover approximately **13:00–19:00 UTC on 2026-11-02**. This is a six-hour slice; it cannot establish overnight/weekend behavior, full host lifetimes, or organization-wide volume. No missing out-of-window initiation/closure was scored. Sanitized domains, similar filesystem timestamps, source completeness, and selected/absent Sysmon families were not scored.

### Coverage and connection behavior

I parsed **22,148 connection rows**, **4,313 DNS rows**, **4,610 HTTP rows**, and **3,142 SSL rows** across the three sensors. Counts include different sensors' views of shared traffic, so they are not unique organization-wide activity totals.

| Sensor | Connections | DNS | HTTP | SSL |
|---|---:|---:|---:|---:|
| zeek-core | 12,314 | 3,188 | 2,159 | 403 |
| zeek-dmz | 9,401 | 1,075 | 2,431 | 2,725 |
| zeek-db | 433 | 50 | 20 | 14 |

Each sensor's connection UID is unique within its connection file. Every supplied DNS/HTTP/SSL UID resolves to a same-sensor connection. I checked companion timestamps against connection start and start plus duration, allowing 100 ms tolerance: there were no violations. This is evidence that the records are competently coordinated, not proof of authenticity and not a synthetic indicator.

Service-conditioned durations are credible at a broad level. Core median SSH duration is approximately 2,017.6 seconds, versus 0.020 seconds for Kerberos and 2.378 seconds for LDAP. DMZ median SSL duration is 2.419 seconds. Long sessions have appropriate latitude: for example, `zeek-core/conn.json:5457`, UID `CGYrXIeuDk4edf3RLL`, has an SSH connection `10.10.3.10 -> 10.10.2.30` lasting 13,333.985520 seconds. I did not label that duration suspicious merely because it is long.

Core traffic is burstier at 14:00 UTC (3,233 connections) than its other visible hours (1,698–2,068); DMZ likewise peaks at 2,713 connections at 14:00. There is insufficient visible time to assess a whole workday curve. S0 scan-like volume and incomplete closes can be legitimate traffic or capture behavior; they were not treated as automatic defects.

Zeek explicitly distinguishes TCP sequence-derived payload counters from IP packet counters; capture gaps can therefore make payload counters exceed captured IP payload. I excluded that apparent contradiction rather than scoring it. See [Zeek connection field definitions](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

### Proxy HTTP byte lower bounds

For each inspected HTTP/1.1 row I parsed the method, URI, version, User-Agent, Referer, and `cs_bytes`. I converted the logged absolute URI to its **shorter origin-form path and query**, then computed:

`len(method + " " + path_query + " HTTP/1.1\r\n") + len("User-Agent: " + logged_user_agent + "\r\n") + len("\r\n")`

This intentionally omits the required Host header as well as Referer, cookies, request body, and every other header. It is therefore a conservative lower bound when the logged User-Agent belongs to that request. It still fails for 284/1,445 inspected rows (19.7%). Adding the logged Referer gives 465/1,445 (32.2%).

| Proxy line | UTC time | Reported cs_bytes | Bound excluding Referer/Host | Visible request |
|---|---|---:|---:|---|
| 19 | 13:01:58 | 88 | 145 | GET `/vizql/068a8694ed7787ab/bootstrap.js` |
| 49 | 13:07:04 | 109 | 180 | GET `/bv1-13-8ad21da6/client-boot-155924bb1ad34432.js` |
| 59 | 13:07:10 | 84 | 144 | GET `/favicon.ico` |

HTTP/1.1 serializes a request line and field lines with delimiters; it does not use HTTP/2's header compression. These bounds follow [RFC 9112 message and request-line syntax](https://www.rfc-editor.org/rfc/rfc9112.html#section-2.1).

The field name `cs_bytes` is custom rather than self-documenting protocol truth. It could mean a narrower metric, or the User-Agent might have been enriched rather than observed per request. Those explanations reduce certainty. However, the next cross-source result makes a narrow body-only interpretation difficult: these counters are repeatedly used as the entire transport's post-CONNECT byte contribution.

### Client-side TLS accounting

The first inspected tunnel provides a compact reproducible example:

- `proxy_access.log:1`: source port 40446; CONNECT 446 client bytes and 116 server bytes; `tunnel_cs_bytes=591`, `tunnel_sc_bytes=12536`; `byte_scope=connect-control-message`.
- `proxy_access.log:2`: decrypted HTTPS GET; `cs_bytes=591`, `wire_sc_bytes=12536`, `proxy_action=ssl-inspect`, `ssl_bump=bump`.
- `zeek-core/conn.json:14`: same client/proxy tuple, zero missed bytes, `orig_bytes=1037`, `resp_bytes=12652`, `orig_pkts=4`, `resp_pkts=13`.
- Exact arithmetic: `446 + 591 = 1037`; `116 + 12536 = 12652`.
- `zeek-dmz/conn.json:3`: same tuple and byte counters, separate sensor UID.

For scoped counting, I grouped proxy rows by `tunnel_id`, selected groups with exactly one setup and at least one inspected request, and matched client IP/`client_src_port` to a unique core TCP/8080 connection to `10.10.3.20`. There were 1,031 unique matches, with three absent/ambiguous groups excluded. All 1,031 match the setup's control-plus-declared-tunnel totals, which is reasonable by itself. The important subset is **510** in which both connection payload counters also equal control plus the sum of the **observed inspected HTTP transaction** counters, leaving no TLS budget in that subset.

The proxy's explicit `bump` semantics imply a secure client-to-proxy connection; see [Squid ssl_bump semantics](https://www.squid-cache.org/Doc/config/ssl_bump/). TLS handshakes and records carry additional bytes beyond HTTP messages; even resumed sessions do not make framing/authentication overhead disappear. See [TLS 1.3 record protection](https://www.rfc-editor.org/rfc/rfc8446#section-5.2). The public-server leg is separately observed as TLS: `zeek-dmz/ssl.json:2`, UID `CCPuIXyCJSF2NTECil`, negotiates TLSv13 and `TLS_AES_256_GCM_SHA384` for the corresponding Tableau hostname. Its transport counters are different (`zeek-dmz/conn.json:5`, 764/16,673), so the concern is specifically the client-side representation.

An explicitly documented decrypted/reassembled packet feed could explain plaintext-based counters on a reconstructed client stream. The supplied logs do not establish that collection transformation. I consequently label this a cross-layer contract gap rather than claiming an unconditional on-wire impossibility for every conceivable collection setup. The two byte findings are related and are not counted as two unrelated network-wide failures.

### DNS, TLS, and supporting protocol checks

Core DNS qtypes are A 2,333; TXT 300; AAAA 279; PTR 154; SRV 105; MX 8; NS 6; SOA 3. DMZ has A 891, AAAA 113, PTR 58, SRV 10, TXT 3. These are compatible with mixed internal infrastructure, web egress, and a bounded TXT-heavy interval. I verified that all DNS query packets have enough UDP payload for their header, encoded question name, qtype, and qclass; no undersized queries were found.

There are repeated positive A queries within prior TTLs, including 414 core repeated-query pairs when grouping by client/query/identical answer. This can result from application-specific resolvers or deliberate uncached requests and was **not scored**. I additionally checked same-client/same-resolver/identical-answer nonauthoritative A responses: I found no TTL increase while the preceding TTL was still live. This avoids overcalling ordinary cache behavior.

TLS metadata is substantially plausible. Core has 199 established TLSv13 sessions and 199 established TLSv12 sessions, with five incomplete records; DMZ has 1,807 established TLSv13 and 911 established TLSv12 sessions, with seven incomplete records. TLSv13 rows have no certificate-chain FUIDs, as expected for passive visibility. TLSv12 uses both RSA and ECDSA authentication appropriately for the referenced leaf certificate key types. That passive TLS distinction is documented in [Zeek's SSL log discussion](https://docs.zeek.org/en/current/reference/logs/ssl.html). Certificate subjects, serials, issuer identities, key types and validity windows did not change under the same observed fingerprint in my checks.

The DHCP records include REQUEST/ACK renewal pairs with varying 3,600/7,200-second leases, and their UID references resolve. SMB mappings/file operations and SMTP STARTTLS-shaped records are present; I did not infer missing mandatory application telemetry merely from selected coverage. The brief ASA/Snort inspection did not establish a competing hard contradiction and did not drive the score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| contract_gap | Proxy HTTP request accounting | 284/1,445 inspected requests below request-line-plus-User-Agent lower bound; 465/1,445 including Referer | Measurable request-size incompatibility under the transport-byte interpretation; custom counter semantics limit certainty |
| contract_gap | Proxy ↔ client-side Zeek TCP/8080 | 510/1,031 uniquely matched inspected tunnels have exact cleartext/control sums in both TCP byte counters | Repeated lack of TLS handshake/record budget despite explicit TLS bump semantics; reconstructed decrypted capture remains an alternative |

These are related byte-model defects. UID completeness, source completeness, sanitized destinations, visible-window compactness, attack narratability, and missing unselected sources did not affect the score.

## Realism Score by Category

- **Field format accuracy:** 8 — Source shapes, optional fields, protocol identifiers, and certificate references are largely credible; custom proxy byte fields need explicit semantics.
- **Temporal patterns:** 9 — Variable durations and bursts; no demonstrated same-UID companion interval inversion in the tested network families.
- **Cross-source correlation:** 6 — Tuple/UID relationships are strong, but the inspected HTTP/client-TLS byte budget is materially inconsistent under native wire semantics.
- **Behavioral realism:** 8 — Diverse connection outcomes, practical infrastructure traffic, proxy browsing, and long admin sessions; HTTP request sizes undermine otherwise plausible browsing.
- **Environmental consistency:** 8 — Core/DMZ/DB source mixes are coherent; the client-side decrypted-versus-wire observation model is unresolved.

## Recommendations

- If this were synthetic, derive HTTP/1.1 request byte totals from the actual serialized method, target, headers, and body. Lines 19, 49, and 59 should not report fewer bytes than the request material they visibly log.
- If this were synthetic, account separately for CONNECT control, decrypted HTTP bytes, TLS handshake bytes, TLS record expansion, and TCP/IP packet overhead on each proxy leg. The client-side TCP counters should represent the observed transport rather than cleartext transaction sums.
- If the intended collection is decrypted/reassembled traffic, explicitly identify that representation and its counter semantics. Keep native-wire and reconstructed-cleartext observations distinguishable so the proxy/Zeek relationship can be interpreted without an undocumented transformation.
