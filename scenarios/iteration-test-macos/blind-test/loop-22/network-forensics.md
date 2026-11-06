# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 98
**Synthetic-Confidence Score:** 88

## Executive Summary

The network records are substantially more coherent than simplistic synthetic telemetry: connection states, protocol timing, proxy routing, certificate identities, and file accounting generally agree. However, repeated full TLS handshakes cannot fit inside their reported TCP payload budgets, and HTTPS durations show a narrow shared numerical floor across unrelated connections; the byte-budget contradiction is decisive.

## Evidence For Synthetic

- [hard_contradiction] A fully visible TLS 1.2 ECDHE_RSA handshake with an RSA-2048 server certificate has only **280 server payload bytes beyond its two DER certificates**. `/private/tmp/log-study-20261105-r22/data/zeek-core/conn.json:423` reports UID `ClI8KmgRGHYsTDasQq`, `resp_bytes=3348`, `missed_bytes=0`, `history=ShADadfF`. `/private/tmp/log-study-20261105-r22/data/zeek-core/files.json:20` and `:21` extract 1,395 and 1,673 bytes from that same responder stream: 3,068 bytes total. `/private/tmp/log-study-20261105-r22/data/zeek-core/ssl.json:8` reports `TLSv12`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `resumed=false`, `established=true`; `/private/tmp/log-study-20261105-r22/data/zeek-core/x509.json:3` identifies the leaf RSA key as 2,048 bits. The RSA signature in ServerKeyExchange alone requires 256 bytes. The remaining 24 bytes cannot contain even the mandatory ServerHello, before accounting for certificate-message framing, exchange parameters, TLS records, Finished, and SMTP STARTTLS negotiation.
- [distribution_texture] The same **certificate total + 280** server-payload value recurs in 29 of 98 certificate-bearing core TLS rows and 27 of 550 certificate-bearing DMZ TLS rows. Restricting to RSA-2048 ECDHE_RSA leaves gives 22 core and 15 DMZ examples; 36 of those 37 have `missed_bytes=0`. This repeated arithmetic boundary supports a shared allocation/clamping artifact rather than one corrupted counter. Counts are sensor-local and may include observations of shared traffic; they are not asserted to represent 37 independent physical sessions.
- [distribution_texture] Of 2,516 successful port-443 flows in `/private/tmp/log-study-20261105-r22/data/zeek-dmz/conn.json`, **152 durations fall between 1.200070 and 1.201719 seconds**. Adjacent two-millisecond bins contain 1, 0, 2, 3, and 1 flows immediately below 1.200 seconds, then 6, 3, 2, and 2 immediately above 1.202 seconds. These are successful flows across inbound portal clients and outbound proxy destinations, not a collection of failed connection timeouts. 150 of the 152 are non-resumed TLS 1.2 handshakes, suggesting a TLS-specific duration floor.
- [weak_signal] `/private/tmp/log-study-20261105-r22/data/zeek-core/http.json:385` shows `10.10.1.41` using an iPhone iOS 17.2 User-Agent. Across the core HTTP records that source has 238 iPhone, 59 desktop Safari, and 19 desktop Edge requests. `/private/tmp/log-study-20261105-r22/data/zeek-core/dhcp.json:1` identifies it as `MAC-MROSS-01`; `/private/tmp/log-study-20261105-r22/data/MAC-MROSS-01.meridianhcs.local/ecar.json:2` includes `/sbin/launchd`. Mobile emulation, an application WebView, or forwarding could explain this, so it is a minor contextual concern, not a platform impossibility or a decisive score component.

## Evidence For Real

- Connection-state diversity is credible. Core has 9,660 `SF`, 1,932 `S0`, 155 `RSTO`, 91 `RSTR`, 48 `REJ`, and smaller `OTH`/partial-close populations. DMZ has a larger unsuccessful population, including 2,687 `S0`, consistent with exposed services and unsolicited scanning.
- DNS includes A/AAAA, PTR, SRV, TXT, MX, SOA, and NS rather than only generated-looking A lookups. Core includes 210 NXDOMAIN, 17 SERVFAIL, and 3 REFUSED responses; AAAA NODATA responses are distinguished from NXDOMAIN. For example, `/private/tmp/log-study-20261105-r22/data/zeek-core/dns.json:4` has an internal AAAA query with `NOERROR` and no answers; `:2` carries domain-controller discovery SRV answers.
- Proxy protocol separation is sensible. `/private/tmp/log-study-20261105-r22/data/zeek-dmz/http.json:1` observes a client CONNECT to `10.10.3.20:8080`; `/private/tmp/log-study-20261105-r22/data/zeek-dmz/dns.json:1` observes the proxy resolving that hostname; `/private/tmp/log-study-20261105-r22/data/zeek-dmz/ssl.json:1` observes the proxy's distinct outbound TLS connection to the returned address. This is not plaintext HTTP spuriously rendered on the external TLS connection.
- TLS 1.3 rows generally lack extractable certificate chains while non-resumed TLS 1.2 rows carry files/X.509 links. For example, `/private/tmp/log-study-20261105-r22/data/zeek-dmz/ssl.json:1` has TLS 1.3 history `Cs` and no certificate chain; `:4` has TLS 1.2 and a two-file chain. Resumption and cipher/version pairings are varied and internally sensible.
- Within each sensor, every DNS/HTTP/TLS UID resolves to its connection; no checked protocol record precedes its connection start or exceeds its visible close by more than 10 ms. No overlapping simultaneous TCP connections with identical directional four-tuples were found within an individual sensor.
- Certificate identity remains stable: 182 distinct fingerprints across the three X.509 datasets have no conflicting certificate metadata. Files sharing SHA-256 hashes do not disagree on total size. HTTP bodies and individual extracted files do not exceed their respective directional connection payload budgets; the decisive issue requires summing certificates and mandatory handshake overhead.

## Detailed Analysis

### Scope and connection behavior

I inspected only the supplied data directory and the supplied reviewer briefing. The quantitative network review covered all three Zeek sensors: 21,412 connection rows, 4,040 DNS rows, 4,346 HTTP rows, 2,840 SSL rows, and their files/X.509 companions. Sensor coverage spans approximately 2026-11-02 13:00–19:00 UTC; this is insufficient to judge overnight, weekend, or boot-to-shutdown completeness.

The sensors have differentiated traffic mixes. Core contains substantial DNS, Kerberos, LDAP, SMB, proxy HTTP, and syslog; DB is dominated by MySQL (320 destination-port-3306 rows, including 254 successful flows); DMZ emphasizes TLS, proxy traffic, and unsuccessful incoming attempts. Successful SSH durations include multi-hour sessions, and successful RDP flows extend to approximately 3,373 seconds. Those durations are more plausible than uniformly short administrative sessions.

Basic packet accounting passes the checks performed: directional transport payload never exceeds directional IP-byte totals, and positive payload is not paired with zero packets. ICMP uses type/code-like ports `8/0`, and request/reply histories and equal echo payloads are coherent. I do not treat the absence of another infrastructure protocol as evidence against authenticity.

### TLS byte-budget contradiction

The strongest evidence is not incomplete collection. For UID `ClI8KmgRGHYsTDasQq`, the connection has the observed SYN/handshake/data/FIN history and zero missed bytes, and the SSL row describes a completed, non-resumed TLS 1.2 exchange. Both certificate files are complete (`seen_bytes=total_bytes`, `missing_bytes=0`) and point to that exact UID and responder direction.

At 13:17:14.786881 UTC, core connection line 423 carries 3,348 responder bytes. Its certificate chain consumes 3,068 of them. The RSA-2048 ECDHE_RSA signature requires 256 bytes; mandatory ServerHello fields alone already exceed the remaining 24 bytes. That lower bound does not depend on guessing application content, TLS extension counts, or packet fragmentation. STARTTLS on SMTP port 25 adds further server bytes instead of resolving the deficit.

The same 280-byte residual occurs across distinct certificates, ciphers, hosts, and services. A separate HTTPS example is `/private/tmp/log-study-20261105-r22/data/zeek-dmz/conn.json:364`, UID `CKOMqob1dPPU93E6gY`, with `resp_bytes=3490`; `/private/tmp/log-study-20261105-r22/data/zeek-dmz/files.json:100` and `:101` total 3,210 certificate bytes; `/private/tmp/log-study-20261105-r22/data/zeek-dmz/ssl.json:96` supplies the corresponding TLS record. The repeated residual is a stronger authenticity problem than the otherwise valid individual-file size comparisons suggest.

### HTTPS duration texture

The 1.2-second accumulation is visible at microsecond precision rather than caused by rounding the report. `/private/tmp/log-study-20261105-r22/data/zeek-dmz/conn.json:46`, `:50`, and `:52` describe separate incoming client TLS sessions lasting 1.201695, 1.201194, and 1.200070 seconds at 13:07:14.019027, 13:07:15.635971, and 13:07:20.897058 UTC. Lines `:98` and `:133` describe outbound proxy sessions lasting 1.200382 and 1.200085 seconds at 13:11:21.634617 and 13:13:24.266729 UTC.

Their SSL companions are `/private/tmp/log-study-20261105-r22/data/zeek-dmz/ssl.json:8`, `:11`, `:13`, `:26`, and `:35`, with names including the internal-facing portal, `edge.typekit.org`, and `styles.dataforge.com`. Across the spike, responder volumes range from 2,844 to 412,363 bytes. A configured common timeout can produce real timing spikes, but it does not readily explain this narrow pileup of completed TLS handshakes spanning unrelated inbound and outbound paths and highly variable transfer sizes. This is a strong distribution indicator, not an impossible ordering claim.

### DNS, HTTP, certificates, and observation limits

DNS query diversity, response-code variation, internal authoritative flags, cache-like TTL variation, and resolver placement are credible. Queries are not required before every connection: local caches and a bounded observation window prevent that inference. Potentially sanitized domains and addresses were not scored.

HTTP distinguishes CONNECT control messages from ordinary GET/POST traffic; 304 responses checked have zero response bodies. Some UIDs carry multiple HTTP transactions, rather than every request being forced into a separate connection. Modern TLS 1.2/1.3 suites, resumed sessions, failed handshakes, and enterprise/public certificate chains are present.

The review found no broad protocol-ordering failure, certificate-fingerprint conflict, or impossible simultaneous TCP tuple reuse. These positives lower the synthetic-confidence score from the most extreme range, but cannot overcome a repeated protocol-byte impossibility. Complete cross-source matching was treated as a collection property, not as a synthetic tell.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Zeek conn/SSL/files/X.509 | Fully visible RSA-2048 ECDHE_RSA exchanges; core example UID `ClI8KmgRGHYsTDasQq` | Decisive: the handshake cannot fit within the TCP payload budget. |
| distribution_texture | Zeek TLS/connection accounting | 56 sensor-local certificate-bearing rows have exactly 280 bytes beyond extracted certificates | Repeated arithmetic boundary supports a systematic construction defect. |
| distribution_texture | DMZ HTTPS flow durations | 152/2,516 successful HTTPS flows in a 1.649-ms duration band near 1.2 seconds | Strong shared floor across different clients, sites, and byte volumes. |
| weak_signal | HTTP User-Agent versus DHCP/endpoint host identity | One Mac-identified IP predominantly uses an iPhone UA | Small contextual concern; explicitly explainable by emulation or forwarding. |

## Realism Score by Category

- **Field format accuracy:** 8 — Most source shapes and data types are convincing; handshake payload totals contradict the otherwise plausible fields.
- **Temporal patterns:** 6 — Broad burstiness and session ranges are credible, but the narrow 1.2-second TLS duration floor is conspicuous.
- **Cross-source correlation:** 7 — UID, fingerprint, file identity, and protocol ordering are strong; combined certificate/transport accounting fails.
- **Behavioral realism:** 8 — Proxy use, incoming scans, directory activity, database traffic, and administrative sessions form plausible network behavior.
- **Environmental consistency:** 8 — Sensor roles and infrastructure traffic differ sensibly; the Mac/mobile UA pattern remains a minor uncertainty.

## Recommendations

- If this were synthetic, derive connection responder payload from the complete serialized protocol exchange or a defensible per-message byte budget. Include both DER certificates, certificate-message framing, ServerHello, signed ECDHE parameters, TLS record overhead, Finished, tickets, and any STARTTLS/application dialogue before finalizing counters.
- If this were synthetic, remove the shared 1.2-second duration floor for full TLS 1.2 handshakes. Model handshake and application timing together and verify that successful durations do not accumulate in a narrow numerical band across unrelated destinations.
- If this were synthetic, preserve the existing stable certificate identities, coherent proxy legs, meaningful connection-state mix, and source-local UID integrity while repairing those owning byte/timing relationships.
- If this were synthetic, make the Mac's predominantly iPhone UA activity an explicit mobile-emulation or forwarding behavior when that is intended; otherwise use host-appropriate application identity. This is a lower-priority refinement, not the basis of the verdict.
