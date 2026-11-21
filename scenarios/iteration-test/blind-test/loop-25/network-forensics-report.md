# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 83
**Synthetic-Confidence Score:** 68

## Executive Summary

The network telemetry is broadly convincing at the individual-record and protocol level, but repeated byte-conservation discrepancies across apparently transparent CONNECT tunnels favor synthetic origin. Client-side Zeek totals agree exactly with the proxy's separately logged CONNECT-control and tunnel payload totals, while selected corresponding upstream TLS flows contain fewer server bytes than the proxy delivered or more client bytes than the client supplied. This is a specific cross-leg accounting defect rather than a judgment about how complete or narratively clean the activity looks.

## Evidence For Synthetic

- [contract_gap] At **2026-11-02 14:16:14 UTC**, `PROXY-01.meridianhcs.local/proxy_access.log:823` records a successful transparent `CONNECT assets.signalwire.dev:443` from `10.10.2.25`, with `wire_sc_bytes=214` and `tunnel_sc_bytes=4074`. Client-side `zeek-core/conn.json:2147`, UID `CCIA7JDXxvaFG5WPw7`, has `resp_bytes=4288`, exactly **214 + 4074**. The matching upstream TLS flow, UID `CEKZig3sK7kR0f8wB` in `zeek-dmz/conn.json:2066` and `ssl.json:1004`, has only **2372 responder bytes**, a **1702-byte shortfall** relative to the tunnel payload delivered to the client. Both TCP legs are `SF`, report zero missed bytes, and lack retransmission/gap history markers. The upstream SSL record names the same destination and is established; the proxy row says `proxy_action=tunnel` without a TLS interception marker.
- [contract_gap] The reverse direction exhibits the same ownership problem. At **13:47:55 UTC**, proxy line **448** records `CONNECT smtp.office365.com:443` from `10.10.1.41`, `cs_bytes=359`, and `tunnel_cs_bytes=346`. Client-side UID `Ccv6ER5yTDKWWYoKOd` (`zeek-core/conn.json:1469`) contains **705 originator bytes = 359 + 346**. Upstream UID `Cr2OECAtHs90DWc8y` (`zeek-dmz/conn.json:1377`, `ssl.json:701`) sends **877 originator bytes**, exceeding even the client's entire control-plus-tunnel stream. Its SNI matches, its responder total matches the proxy's `tunnel_sc_bytes=8135`, and both legs are gap-free `SF` connections. An ordinary byte-transparent CONNECT relay cannot independently manufacture additional client TLS bytes.
- [contract_gap] This is repeated rather than a single ambiguous match. A conservative three-way join found **479** eligible sessions with unique nearby client CONNECT and upstream SNI matches, exact agreement between client flow totals and proxy control-plus-tunnel totals, `SF` on both legs, `missed_bytes=0`, and no `G/g/T/t` history flags. **90/479 (18.8%)** differed between upstream and logged tunnel payload totals; **47/479 (9.8%)** had the stronger directional problem of excess upstream client bytes or excess client-delivered server bytes. Counts are a selected diagnostic subset, not a dataset-wide failure estimate. The two examples above are manifestations of this one defect family and are not counted as independent categories of evidence.

## Evidence For Real

- Protocol and state diversity are credible. Across the three sensors there are **23,141 connection rows**: core **12,230**, DMZ **10,481**, database **430**. There are successful connections, unanswered SYNs, rejections, resets in both directions, half-closed sessions, and partial observations; the logs do not collapse all activity into successful `SF` sessions.
- DNS has operational variety: core records include **2348 A, 297 AAAA, 264 TXT, 158 PTR, 103 SRV**, plus NS/MX/SOA queries. Core response codes include **206 NXDOMAIN, 12 SERVFAIL, and 5 REFUSED** among 3188 DNS records. Empty AAAA answers for some internal names are distinguishable from failed A lookups.
- Individual-source reference integrity is strong without obvious native contradictions: every DNS/HTTP/SSL UID resolves to a same-sensor connection with matching endpoints and ports. All tested protocol timestamps fall within their connection intervals; HTTP body counts and file payload sizes do not exceed the corresponding directional flow payloads.
- TLS is internally coherent in the checks performed. TLS 1.2 and 1.3, RSA and ECDSA suites, resumptions, and failed handshakes are present. Referenced certificate chains have consistent issuer/subject links, valid lifetimes, SNI-compatible names, and compatible leaf key types; 212 distinct fingerprints did not acquire contradictory metadata across repeated observations.
- Long SSH sessions coexist with short application transactions. For example, `zeek-dmz/conn.json:1` records `10.10.1.31:49670 -> 10.10.3.20:22`, duration **3682.836674 seconds**, with **46616/81780** directional payload bytes. DHCP renewal intervals vary around the lease's renewal times rather than sharing identical timestamps.

## Detailed Analysis

### Scope and method

I inspected only supplied logs under the data directory. Network analysis covered all Zeek connection, DNS, HTTP, SSL, X.509, and files records; I also examined the available SMB, SMTP, DHCP, OCSP, PE, firewall, IDS, and proxy evidence. No scenario, ground truth, implementation, evaluation output, or earlier assessment informed the judgment.

The connection-start window is approximately **2026-11-02 13:00–18:59 UTC**. This is insufficient to judge overnight coverage, weekday cycles, or absence of pre-window sessions. Domain/IP substitutions and copied filesystem timestamps were not used as clues. The proxy-to-TLS association is inferred from the same hostname/SNI and nearby times, not asserted to be a shared UID relationship: the client-to-proxy and proxy-to-server legs correctly use different tuples and UIDs.

### Connections, accounting, and observation

Core connections comprise 6826 TCP, 4988 UDP, and 416 ICMP rows; DMZ has 8965 TCP, 1217 UDP, and 299 ICMP; database has 359 TCP, 51 UDP, and 20 ICMP. The apparent database path is dominated by MySQL (273 flows), while the core includes substantial Kerberos, LDAP, SMB, and DNS traffic. This distribution fits the visible service destinations without requiring every sensor to have the same view.

I checked TCP state against history: unanswered TCP `S0` flows did not contain responder traffic, `RSTO` and `RSTR` had the appropriate reset-direction markers, and rejected flows did not contain a completed SYN/ACK history. No same-sensor five-tuple connection lifetimes overlapped in the tested records. Basic packet/IP-byte relationships were coherent, and HTTP/file payloads were bounded by flow bytes. Partial `OTH` observations were treated as partial observations rather than failed complete lifecycles.

The principal defect appears only when the two legs of transparent proxy sessions are compared. For the 14:16:14 example, the client tuple is `10.10.2.25:34684 -> 10.10.3.20:8080`; upstream is `10.10.3.20:41344 -> 54.230.120.46:443`. The upstream starts at `1793628974.584038`; client-side start is `1793628974.611870`. The 28 ms difference could be sensor clock offset and is not itself an authenticity indicator. Both flows last roughly four seconds, have identical origin tunnel payload **4534**, and agree on hostname, making a mistaken pairing less likely. Nevertheless the upstream server sends only **2372** bytes while the proxy claims to relay **4074** server bytes, independently confirmed by the client-side total after removing CONNECT response bytes.

A second server-direction example is **14:24:19 UTC**, proxy line **898**, `assets.pollfish.app`: client UID `Ci8S8M7X4k0J44oxidp` contains **4680 responder bytes**, comprising **223** control bytes and **4457** tunnel bytes. Upstream UID `CHOURGZsAAJ5qQxPvai` has only **4204 responder bytes**, a **253-byte shortfall**, again with matching **3984** client tunnel bytes and gap-free `SF` flows.

Buffering or early client closure can explain an upstream receiving more server bytes than it eventually delivers; I therefore did not treat every non-equal pair as impossible. The stronger subset uses the opposite inequalities: bytes delivered to the client without enough upstream server payload, or bytes sent upstream without enough client tunnel payload. Undocumented TLS termination, additional unlogged upstream sessions, unusual counter semantics, or incorrect inferred associations remain alternative explanations. However, these rows specifically describe `proxy_action=tunnel`; other proxy rows explicitly distinguish inspection/setup modes. The repetition, exact agreement on the client leg, and often exact agreement in the unaffected direction make a systematic accounting inconsistency more persuasive than isolated measurement noise.

### DNS and protocol behavior

There are **4385 DNS rows** overall. Core DNS RTTs range from **47 microseconds to 2.151836 seconds**, with a mix of fast internal answers and slower responses. The first core transaction, UID `CmN2OeyFuu5qT4yxIk`, asks for `FILE-SRV-01.meridianhcs.local` and returns `10.10.2.20`, with 58 request bytes, 86 response bytes, and a **678 microsecond** RTT. SRV lookups reference domain controllers; PTRs and negative answers add realistic operational texture.

The 264 TXT queries beginning around **17:44:59 UTC**, including `7bc841b4d7342efad12c2d.e4.ns1.westbridge-services.cloud`, have varied labels and response lengths. Their suspicious character is an investigative observation, not authenticity evidence. I did not penalize their sequence, compactness, or ease of interpretation.

Most visible HTTP transactions are CONNECT exchanges, so a raw HTTP-row/SSL-row ratio would misrepresent cleartext web use. Core has 2265 successful CONNECTs plus authentication failures, policy denials, and gateway failures; successful CONNECTs have zero HTTP body length rather than incorrectly treating tunneled TLS as an HTTP response body. Tested 304 responses likewise have zero bodies. This is a credible explicit-proxy collection shape.

### TLS and certificates

DMZ SSL contains **2288 TLS 1.3**, **1011 TLS 1.2**, and four records without a negotiated version. Its major ciphers are current AEAD suites, with a smaller TLS 1.2 CBC population. Core contains 172 TLS 1.3, 174 TLS 1.2, and two unnegotiated records; the database path is more heavily TLS 1.2. This host/service variation is plausible.

No checked TLS 1.2 certificate-bearing handshake had an obviously insufficient responder-byte budget even under a conservative certificate-size bound. TLS 1.3 rows do not expose an implausible plaintext certificate chain. Failed handshakes align with incomplete TCP/TLS observations rather than being marked established. These strengths materially limit the synthetic-confidence score despite the cross-leg proxy defect.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | Proxy access logs, core Zeek HTTP/conn, DMZ Zeek SSL/conn | 90 mismatches in 479 conservative three-way matches; 47 have the stronger directional conservation problem | Main basis for a score in the likely-synthetic range. Exact client-side accounting plus inconsistent upstream payload totals suggests independently inconsistent representations of the same tunnel. |

No separate hard-contradiction, schema, coverage, or narrative-design finding is claimed. Cross-leg association and undocumented collection semantics prevent absolute attribution.

## Realism Score by Category

- **Field format accuracy:** 9 — Native-looking JSON, valid field relationships, sensible protocol records, and no demonstrated parser-level defect.
- **Temporal patterns:** 8 — Varied connection lengths, renewals, bursts, and partial observations; the six-hour slice limits broader cadence conclusions.
- **Cross-source correlation:** 6 — Excellent same-sensor UID/tuple/lifecycle integrity, reduced by repeated transparent-tunnel byte-conservation discrepancies.
- **Behavioral realism:** 8 — Plausible infrastructure, browsing, mail, administration, failure, and suspicious traffic mixtures.
- **Environmental consistency:** 9 — Sensor-specific service distributions and explicit-proxy behavior are coherent; no unsupported platform or missing-source expectation was imposed.

## Recommendations

- If this were synthetic, preserve one authoritative pair of opaque tunnel payload streams across the client leg, proxy metrics, and upstream leg. Add CONNECT control bytes only to the client-side HTTP connection; protocol handshake sizing must be compatible with those same tunnel streams.
- If TLS is terminated or transformed, identify that mode consistently in the proxy records and keep it distinct from transparent tunneling. The cited `proxy_action=tunnel` examples otherwise imply byte conservation that their flow totals do not satisfy.
- Validate the stronger directional invariants on completed gap-free tunnels, allowing explicitly modeled buffering/abort behavior to leave excess server bytes upstream. A client must not receive more opaque server bytes than the upstream supplied, and an opaque upstream must not send more client bytes than were available from its client leg.
- If different counter definitions or extra upstream sessions legitimately explain the discrepancy, include explicit counter semantics and durable leg identifiers in the collection export so the relationship can be tested without a hostname/time join.
