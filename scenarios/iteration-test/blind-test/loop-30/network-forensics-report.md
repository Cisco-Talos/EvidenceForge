# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 65
**Synthetic-Confidence Score:** 28

## Executive Summary

The network evidence is predominantly production-like: TCP accounting, protocol lifetimes, DNS diversity, proxy behavior, and TLS visibility agree with the apparent collection paths. I found no demonstrated impossible ordering, incompatible TLS certificate/cipher pairing, or broken protocol-to-connection reference in the inspected network records. My reservations concern a small number of client-identity and browser-version patterns; these are explainable and do not establish synthetic origin.

## Evidence For Synthetic

- [weak_signal] An address identified as a Mac by DHCP also emits an iPhone user agent. In `zeek-core/dhcp.json`, `10.10.1.41` is `MAC-MROSS-01`, with MAC `d4:be:d9:a1:ac:76`. In `zeek-core/http.json`, that address has 53 CONNECT records using `Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148`, alongside 148 Chrome-on-Mac and 73 Safari-on-Mac records. One example is UID `C5FJCoCAUB5LDzEGUV`, 2026-11-02 15:17:47.905479 UTC, CONNECT to `github-releases.githubusercontent.com:443`. This could reflect development tools, agent spoofing, or traffic relaying; the apparent mixture is a modest identity-plausibility concern, not an impossible platform claim.
- [weak_signal] Browser version vocabulary is conspicuously separated across the visible client populations. Core HTTP contains 370 Linux Chrome/120 agents, 276 Windows Chrome/120 agents, and 253 Windows Edge/120 agents, while Mac Chrome is predominantly /155 (304 records). For example, Linux client `10.10.1.22` uses Chrome/120 in UID `CaQoGW4ayjBG7ZKT6` at 13:10:38.890184 UTC; Mac client `10.10.1.41` uses Chrome/155 in UID `CEhMx8eGiXbE7tCF0r` at 13:15:55.825576 UTC. Different software management policies can explain this split, so I assign little weight to it and do not assert that any agent string is intrinsically invalid.

## Evidence For Real

- The connection-state population has meaningful variation. Across the three sensors there are 17,582 `SF`, 4,140 `S0`, 304 `RSTO`, 182 `RSTR`, 79 `REJ`, and smaller `S1`/`S2`/`S3` populations, plus 772 `OTH` records. These are sensor observations, with overlapping visibility, rather than 23,141 necessarily distinct network connections.
- DNS includes successful and unsuccessful queries, multiple record types, negative suffix-search-like names, and substantially different internal versus DMZ response-time distributions. Core DNS has 206 NXDOMAINs, 12 SERVFAILs and five REFUSEDs; examples include `isatap`, `isatap.meridianhcs.local`, and `wpad.local`.
- All inspected HTTP, DNS and TLS UIDs resolve to a connection on their own sensor. Their timestamps fall within the associated observed connection interval. File records also resolve and fit within the respective connection lifetimes.
- TLS visibility respects encryption boundaries: none of the 2,460 TLS 1.3 rows exposes a certificate chain through `cert_chain_fuids`. Visible TLS 1.2 ECDSA and RSA cipher choices agree with the referenced leaf key type. Resumption and unsuccessful handshakes are both represented.
- Explicit proxy traffic explains the large HTTP record population. CONNECT control messages are not presented as decrypted HTTPS payload: successful examples have zero response-body length, while a 407 example has a real HTML error body and matching file evidence.
- Infrastructure activity is differentiated: core sees DNS/Kerberos/LDAP/SMB, the DB sensor is dominated by MySQL, and DMZ sees proxy egress plus public-facing web traffic. DHCP renewals have leases of 3,600, 7,200 and 14,400 seconds rather than one universal lease.

## Detailed Analysis

### Scope and method

I examined only supplied evidence under the data directory. I parsed every JSON record in the three Zeek sensor directories, including connection, DNS, HTTP, TLS, certificate, file and available protocol logs, and sampled the supplied proxy, ASA and Snort text logs. The connection files contain 12,230 core, 10,481 DMZ and 430 DB observations. The visible interval is approximately 2026-11-02 13:00–19:00 UTC; I did not infer overnight behavior or require complete session starts/ends outside that interval.

The associated protocol populations are 4,385 DNS, 5,547 HTTP and 3,668 TLS records. These totals likewise include overlapping sensor observations. I checked protocol UID references and timestamps, file references and timing, TCP tuple overlaps, payload/IP-byte lower bounds allowing for `missed_bytes`, and HTTP/file payload sizes against the corresponding flow byte counts. These checks revealed no concrete contradiction. Small byte-accounting deficits without allowance for missed stream bytes were not counted as defects.

### Connections, ports and traffic timing

The dominant core destination ports are 53 (3,200), 8080 (2,487), 88 (2,106), 389 (1,143), and 445 (703). DMZ is led by 443 (3,844), 8080 (2,753), 53 (1,171), and 80 (696). The DB sensor has 273 destination-port-3306 observations out of 430 total. This supports distinct infrastructure, proxy and database paths rather than identical service mixtures at every vantage point.

TCP lifetimes differ by service. Core successful Kerberos connections have a median duration around 0.020 seconds; successful SMB connections have a median around 4.23 seconds and a substantial longer tail. SSH spans brief activity and multi-thousand-second sessions: DMZ UID `CWO3ZQWKkMNB3fiGCb`, from `10.10.1.31:49670` to `10.10.3.20:22`, starts at epoch `1793624405.748486` and lasts 3,682.836674 seconds. Its packet counts, bytes and successful state are compatible with an extended transport session.

Core hourly connection counts are 1,681, 3,138, 1,770, 1,758, 2,146 and 1,737 for hours 13 through 18 UTC. DMZ similarly has a pronounced 14:00-hour increase. I did not score either that increase or the comparatively stable surrounding hours as intrinsically synthetic: the records include substantial failed-connection activity, and a six-hour slice cannot establish a daily behavioral model.

No same-sensor overlapping TCP connections with the same directed five-tuple were found in the interval check. ICMP echo records use type/code-like port values (`id.orig_p=8`, `id.resp_p=0`) and appropriate small packet counts; I did not interpret those fields as TCP/UDP ports.

### DNS

Core DNS contains A, AAAA, TXT, PTR, SRV, NS, MX and SOA queries. It includes 2,348 A, 297 AAAA, 264 TXT, 158 PTR and 103 SRV records. DMZ has 936 A, 138 AAAA and 68 PTR records. Query labels passed the 63-character label-length check.

The first core query, UID `CmN2OeyFuu5qT4yxIk`, has source `10.10.1.31:49610`, destination `10.10.2.11:53`, query `FILE-SRV-01.meridianhcs.local`, A answer `10.10.2.20`, TTL 1,800, and RTT 0.000678 seconds. The matching UDP connection shares that UID and timing. Core median DNS RTT is about 0.003779 seconds; DMZ median is about 0.027823 seconds, with a tail extending past two seconds. These differences are plausible for different query populations and resolver paths.

I observed both positive AAAA answers and successful responses without AAAA answers; I did not demand IPv6 connections for every lookup. The unusual TXT population includes variable labels and response text under a common domain. That traffic may merit security investigation, but unusual DNS content alone is not authenticity evidence.

### HTTP, proxy semantics and source timing

Core HTTP has 2,405 CONNECT records out of 2,614; DMZ has 2,450 out of 2,907. A direct HTTP-to-HTTPS record-count ratio would therefore mischaracterize the environment. Many visible HTTP records are the control plane for encrypted tunnels.

In `zeek-db/http.json`, UID `CejGkF1Vxdvx1XEH8` at epoch `1793624609.745278` is a CONNECT from `10.10.4.10:42023` to proxy `10.10.3.20:8080` for `security.ubuntu.com:443`. It returns `407 Proxy Authentication Required`, response body length 753, and file UID `FQ0iz2f8E8pfvGFcC`. The corresponding file is HTML, has 753 seen/total bytes, is sent from proxy to client, and fits within the flow. The proxy access log independently describes this transaction as `proxy_action=auth-required` with a 753-byte body.

I explicitly investigated apparent upstream-TLS-before-CONNECT cases. Nearest-SNI matching is unsafe in the busy destination populations because several simultaneous tunnels can use the same hostname. Restricting the comparison to destinations with exactly one successful CONNECT and exactly one proxy-origin TLS observation within a ten-second neighborhood produced 1,185 isolated matches; none had TLS before the CONNECT timestamp. I therefore did not report the ambiguous nearest-neighbor inversions as causality defects. Different sensor clocks also preclude treating their raw timestamp differences as exact packet-order evidence.

Public-facing HTTP has varied response outcomes, including redirects, 304s, 404s and successful content. The checked 304 records have zero response body, and HTTP body sizes do not exceed the associated stream accounting.

### TLS, certificate and file visibility

TLS 1.2 appears in 1,201 records and TLS 1.3 in 2,460; seven incomplete records omit a version. Cipher choices include AES-GCM and ChaCha20 for TLS 1.3, and RSA/ECDSA ECDHE combinations for TLS 1.2. The DB population is more conservative than DMZ: its negotiated versions are TLS 1.2, with CBC and GCM variants, rather than an identical fleet-wide mix.

All referenced certificate-chain file identifiers resolve in the same sensor's X.509 records. Negotiated TLS 1.2 ECDSA suites have ECDSA leaf keys and RSA suites have RSA leaf keys. Referenced leaf certificates are valid at the respective connection times. Repeated certificates across connections are expected and were not scored as a fingerprint of synthesis.

Core UID `C88XNNT8XEjEET1urze`, from `10.10.2.26` to `10.10.2.10:636`, records TLS 1.3, `TLS_AES_128_GCM_SHA256`, `ssl_history=Cs`, and no visible certificate chain, which is consistent with passive observation of TLS 1.3. Core SMTP also includes STARTTLS exchanges with `tls=true` and empty message-envelope/content fields rather than invented plaintext visibility after encryption.

SMB file evidence is similarly coherent. Core file UID `FeipCp8MPfysT9eBuBu` references connection `CxQhZyV63qeVw3uEu` and a 13,083-byte SYSVOL ScheduledTasks XML read. The SMB row, file source, direction and byte total agree. This agreement is positive evidence of internal consistency, not a claim that complete coverage proves real origin.

### Residual uncertainty

The two user-agent concerns above are weak because HTTP agents are client-controlled and a DHCP host label does not rule out a relay, test browser or mobile-emulation workload. I found no network-native generator identity leak or impossible protocol value. A sufficiently careful synthetic dataset could pass these checks, so the Real verdict is deliberately moderate in confidence rather than a declaration of proven provenance.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `weak_signal` | HTTP + DHCP client identity | 53 iPhone-agent CONNECT records from `10.10.1.41`, also identified as `MAC-MROSS-01` | Small increase: mixed client identity is unusual but relaying or agent emulation can explain it. |
| `weak_signal` | HTTP user-agent distribution | Predominantly /120 browser agents on Windows/Linux versus /155 on Macs | Small increase: potentially different vocabulary pools, equally compatible with different deployment policies. |
| No demonstrated high-impact defect | Connection, DNS, HTTP, TLS, files | All three Zeek sensors | Keeps the score in the mostly realistic band; reference, timing, payload and negotiated-crypto checks did not establish a contradiction. |

## Realism Score by Category

- **Field format accuracy:** 9 — Native field shapes, protocol-specific values, optional fields and TLS visibility are coherent in the parsed records.
- **Temporal patterns:** 9 — Protocol/file timestamps fit their flows, services have different lifetime scales, and isolated proxy pairs preserve ordering.
- **Cross-source correlation:** 9 — UID/file/certificate references and sampled proxy semantics agree; no impossible correlation was demonstrated.
- **Behavioral realism:** 8 — Service, failure, DNS and web response mixtures are credible; a few client-agent combinations remain unusual.
- **Environmental consistency:** 8 — Sensor populations and infrastructure roles differ sensibly, with modest reservations about agent identity and version distribution.

## Recommendations

- If this were synthetic, bind mobile user-agent selection to the intended client or relay semantics. The 53 iPhone-agent CONNECT requests from the DHCP-labeled Mac are the clearest residual identity question; retain them if mobile emulation or relaying is intentional.
- If this were synthetic, verify that the strong /120 versus /155 browser-version split reflects intended software deployment cohorts. Use the existing host-specific agent distributions as the evidence to review, rather than adding arbitrary diversity solely to make the data messier.
- Preserve the existing proxy control-message/body distinction, protocol timing bounds, loss-aware byte accounting, and TLS 1.3 certificate invisibility. The supplied records do not justify inventing additional telemetry or adding missing source families merely for completeness.
