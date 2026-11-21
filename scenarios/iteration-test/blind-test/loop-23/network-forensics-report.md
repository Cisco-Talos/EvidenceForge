# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 61
**Synthetic-Confidence Score:** 27

## Executive Summary

The network evidence is mostly production-like: protocol records agree with their connections, packet and application accounting are plausible, and the environment has credible proxy, directory, file-service, mail, scanning, and administrative traffic. I favor real telemetry at modest confidence because I found no demonstrated protocol impossibility; one isolated HTTP request-timing anomaly is a weak synthetic signal, and a sufficiently careful simulator could reproduce the many coherent relationships observed here.

## Evidence For Synthetic

- [weak_signal] One browser page load has a suspiciously small initial request gap. In `zeek-dmz/http.json`, lines 344–345, UID `CUndz3AFi0yhIEnnis`, the GET for `/` starts at `1793627680.392176` and the GET for `/assets/css/main.min.07b8945e.css` at `1793627680.392177`: approximately one microsecond apart. Both are HTTP/1.1 requests from `10.10.1.34:51815` to `10.10.3.10:80`, with the stylesheet referring to the initial page. The corresponding core-sensor observations reproduce this gap under UID `CVZ14Uhc67AVJrYgbO`. This resembles a timestamp boundary adjustment, but cached resource knowledge, pipelining, or timestamp normalization remain possible explanations. It occurs in only one of 19 distinct multi-request page connections, so it has limited weight and is not a demonstrated causal impossibility.

## Evidence For Real

- The connection-state mixture has substantial operational variation: among 23,312 sensor observations, 17,748 are `SF`, 4,127 `S0`, 756 `OTH`, 336 `RSTO`, 198 `RSTR`, 67 `REJ`, 38 `S2`, 31 `S3`, and 11 `S1`. This includes unanswered probing, resets, partial connections, ordinary exchanges, UDP, and ICMP rather than one repeated successful-flow shape.
- DNS includes A, AAAA, PTR, SRV, TXT, MX, NS, and SOA queries, successful empty answers, NXDOMAIN, SERVFAIL, and REFUSED responses. Core DNS contains 231 NXDOMAIN responses and 184 `NOERROR` responses without answers, which is credible resolver behavior rather than treating all queries as successful address lookups.
- The 3,806 TLS records include 2,527 TLS 1.3 negotiations, 1,276 TLS 1.2 negotiations, and three incomplete handshakes. TLS 1.3 records do not fabricate visible certificate chains; visible TLS 1.2 certificate chains resolve to X.509 records, match their issuer relationships, and use leaf key types compatible with the negotiated RSA/ECDSA authentication cipher suites.
- HTTP includes realistic CONNECT outcomes (`200`, `403`, `407`, `502`, `503`, `504`), redirects, conditional responses, partial-content responses, referrers, and persistent connections with increasing `trans_depth`. All examined `304` responses have zero response bodies.
- Strong correlation supports physical plausibility: existing connection UIDs match DNS/HTTP/TLS tuples, protocol timestamps fall inside their connection intervals, HTTP response bodies do not exceed responder transport bytes, and DNS packet sizes accommodate their visible questions and address answers. This is favorable evidence of consistency, not proof of real provenance.
- DHCP renewals follow host-specific lease lengths with jitter. For example, MAC `d4:be:d9:a1:ac:76` has a 7,200-second lease renewed at approximately hourly intervals, while MAC `a4:1f:72:c2:30:2e` has a 3,600-second lease renewed approximately every half hour.

## Detailed Analysis

### Scope and method

I read the assigned briefing and examined only the supplied data directory. I parsed every JSON record in the three `zeek-*` directories and used the firewall/proxy/IDS logs and selected normalized endpoint FLOW records to interpret topology and observation scope. I did not inspect scenario material, ground truth, evaluation reports, repository files, or other study material.

The connection data spans approximately 2026-11-02 13:00–19:00 UTC. Counts below are sensor observations: overlapping core, DMZ, and database sensors can observe the same underlying connection with different UIDs and timestamps. I did not treat those observations as independent user activities. A six-hour window does not support conclusions about full-day business-hour contrast, overnight traffic, or weekly seasonality.

The principal parsed source counts are:

| Source family | Core | DMZ | Database |
|---|---:|---:|---:|
| Connection | 12,325 | 10,533 | 454 |
| DNS | 3,194 | 1,118 | 48 |
| HTTP | 2,614 | 2,864 | 15 |
| TLS/SSL | 407 | 3,380 | 19 |
| Files | 630 | 1,827 | 23 |
| X.509 | 165 | 1,177 | 17 |
| OCSP | 17 | 99 | 1 |

Core additionally contains 60 DHCP, 79 SMTP, 229 SMB-file, and 133 SMB-mapping records. Native text logs contain 25,753 firewall lines, 4,471 proxy lines, 57 core IDS alerts, and 88 perimeter IDS alerts; I did not infer packet-level completeness from these counts.

### Transport behavior and volume

Across sensors there are 16,436 TCP, 6,173 UDP, and 703 ICMP observations. The state distribution listed above has a plausible mix of successful sessions and failures. History strings vary by close direction, retransmission indicators, resets, gaps, and partial observation. Nonzero `missed_bytes` occurs on 1,372 connection observations, so the collection is not uniformly loss-free.

An illustrative administrative connection is `zeek-dmz/conn.json` line 1: `10.10.1.31:49670 → 10.10.3.20:22`, UID `CWO3ZQWKkMNB3fiGCb`, starts at `1793624405.748486`, lasts `3682.836674` seconds, and carries 46,616 originator and 81,780 responder bytes. A long-lived, low-throughput SSH connection is credible. SSH durations range from short failures to multi-hour sessions; RDP likewise includes short unsuccessful attempts and much longer established intervals.

Core SMB UID `C48vC73LynYi2GtPwPK`, line 3, starts at `1793624405.356666` and carries 119,613,292 originator bytes over 5.921422 seconds to `10.10.2.20:445`. The approximately 20 MB/s rate is reasonable for an internal transfer. Its many responder packets despite relatively little responder application data are consistent with transport acknowledgements; this is more credible than deriving each direction's packet count solely from its application bytes.

Connection volumes vary during the window. Core hourly counts for 13:00–18:59 UTC are 1,681, 3,140, 1,895, 1,847, 2,043, and 1,719. DMZ counts are 1,575, 2,801, 1,676, 1,514, 1,575, and 1,392. The 14:00-hour increase accompanies substantial failed-connection activity. Core and DMZ observations overlap, so the similar peak is not an independent coincidence or synthetic indicator.

Unanswered activity is concentrated rather than uniformly assigned: `10.10.3.10` accounts for 2,798 `S0` observations across sensors, while several external sources and internal `10.10.2.40` contribute additional failures. Such scanning is security-relevant, but its presence and investigative coherence are not authenticity defects.

### DNS and infrastructure

Core DNS query-type counts are A 2,380, AAAA 275, TXT 262, PTR 159, SRV 104, MX 7, NS 4, and SOA 3. The DMZ has 920 A, 117 AAAA, 71 PTR, and 10 SRV queries. These reflect differing host and sensor roles rather than requiring every platform to emit every discovery protocol.

The first core DNS row, UID `CmN2OeyFuu5qT4yxIk`, queries `FILE-SRV-01.meridianhcs.local` from `10.10.1.31` at `1793624403.868779`, receives `10.10.2.20`, and has RTT `0.000678`. The SMB connection to that address begins approximately 1.49 seconds later. Directory-service SRV lookups name the observed domain controllers, and internal AAAA queries can return `NOERROR` without IPv6 answers. External DNS TTLs vary, including short CDN-like values and cache-aged values, rather than universally using a single TTL.

All 4,360 DNS observations have matching connection UIDs and tuples. Their timestamps are not earlier than their matching connection starts and do not lie beyond the connection interval using the stated 0.1-second tolerance. Visible DNS UDP payload sizes meet the minimum sizes needed for their question names and A/AAAA answers. I did not require a fresh DNS lookup before every connection: caching and direct-address access make that an invalid universal expectation.

Core service ports are consistent with a domain environment: DNS 3,206, Kerberos port 88 at 2,111, LDAP port 389 at 1,193, SMB 716, and multiple mail and administrative ports. Database-sensor connections are dominated by port 3306, with 307 observations, consistent with the observed `DB-PROD-01` host. The limited window and observation paths do not justify penalizing absent NTP, mDNS, QUIC, or any other optional source family.

### Proxy, HTTP, and files

The client/proxy path is explicit. Core HTTP line 1 records a CONNECT from `10.10.1.33:53461` to `10.10.3.20:8080`, requesting `spoprod-a.akamaihd.net:443` at `1793624437.805519`. The proxy access log records the same client and target at 13:00:37 UTC and explicitly separates CONNECT control-message byte counts from tunneled bytes. The DMZ records the proxy's external TLS connection to the requested server name. I do not mistake those proxy-originated external connections for separate workstation activities.

A database-host example is `zeek-db/http.json` line 1: CONNECT to `security.ubuntu.com:443` returns `407 Proxy Authentication Required`, with a 753-byte HTML response and a linked file record. This is a credible failure path with actual response content rather than incorrectly treating every CONNECT as a successful tunnel.

Persistent HTTP traffic comprises 19 distinct connections with multiple requests, visible at both core and DMZ sensors. Transaction depths are consecutive, and resource types and referrers are coherent. The isolated one-microsecond initial HTML/stylesheet gap described above is the only timing observation I assign synthetic weight. Other first-to-second request gaps span approximately 0.20–2.15 seconds. I count the anomalous page load once, despite its two sensor views.

All HTTP response-body lengths fit within responder connection bytes. The DMZ's eighteen `304` responses have zero bodies; the core's ten do too. Download/file metadata includes MIME types appropriate to CSS, JavaScript, SVG, WebP, HTML, and icons. None of these relationships demonstrates provenance, but they avoid common protocol-rendering contradictions.

### TLS, certificates, and OCSP

TLS version and cipher pairings are compatible: TLS 1.3 uses its AES-GCM/ChaCha20 cipher names, while TLS 1.2 uses ECDHE suites. In the visible chains, ECDHE-ECDSA uses ECDSA leaf keys, ECDHE-RSA uses RSA leaf keys, and each subordinate issuer name agrees with its next chain certificate's subject. Every TLS certificate FUID resolves within its sensor's X.509 records. No repeated X.509 fingerprint or identifier maps to contradictory certificate metadata in the supplied files.

The three incomplete handshakes have `established:false`, `ssl_history:"C"`, and no negotiated version or cipher. This is a plausible observation of a ClientHello without a completed handshake. Resumed sessions and TLS 1.3 do not universally expose a fresh certificate chain, which is also consistent with wire visibility.

The first DMZ TLS example, UID `CmoezxyEUXUWa1Vi86`, negotiates TLS 1.2 with `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` to `spoprod-a.akamaihd.net`, and its first certificate FUID `FRyFsEh4MAbEtjYGgt` resolves to an RSA leaf certificate for that name. I did not use domain ownership or public DNS address expectations as evidence because destination names may have been sanitized. I also did not infer certificate-validation success merely from TLS `established:true`.

### Correlation limits and alternative explanations

All examined DNS, HTTP, TLS, SMTP, and SMB-file rows with an existing connection have matching four-tuples and fall inside their connection lifetimes under the timing tolerance above. One core SMB-mapping row, UID `CiasUTGUEwayOvoB44` at `1793640924.870598`, lacks a matching connection row in that sensor's supplied file. An omitted connection observation is possible, and no collection guarantee establishes that this row requires an exported companion. I therefore do not score that absence as a synthetic indicator.

Different sensor timestamps and normalized endpoint timestamps cannot establish precise packet causality without clock calibration. I did not convert subsecond cross-sensor offsets into impossible ordering claims. Likewise, process/session initiators outside this slice and missing endpoint event families are outside the evidence needed for this verdict.

My modest preference for real reflects the consistency and operational texture of the visible records. It does not rule out carefully authored synthetic data; the single weak anomaly is insufficient to substantiate a likely-synthetic verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| `weak_signal` | Zeek HTTP timing | One of 19 distinct multi-request page connections; repeated observation at two sensors | Initial HTML and stylesheet request timestamps differ by approximately one microsecond. Potential timestamp adjustment or request-model artifact, but plausible alternative explanations and limited scope keep its weight low. |

No demonstrated `hard_contradiction` was found. Coverage completeness, strong UID integrity, sanitized domains, and the narratability of suspicious activity did not raise the score.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed network records have plausible native fields, compatible TLS/key types, and sensible protocol body/accounting relationships.
- **Temporal patterns:** 8 — Variable durations, state outcomes, volumes, and lease renewals are credible; one initial HTTP request gap is questionable.
- **Cross-source correlation:** 9 — Matching protocol tuples and lifetimes, linked certificates/files, and coherent proxy paths; clock calibration and selective observation limit certainty.
- **Behavioral realism:** 9 — Service-specific connection durations, resolver outcomes, scanning, administrative sessions, and HTTP failures have plausible network mechanics.
- **Environmental consistency:** 9 — Core directory/file traffic, proxy-mediated external access, DMZ services, and database-heavy traffic align with the visible topology.

## Recommendations

- If this were synthetic, review the first HTML-to-stylesheet request timing for UID `CUndz3AFi0yhIEnnis` and its core counterpart. Model the browser's actual request scheduling or explicitly preserve any justified timestamp normalization so the approximately one-microsecond gap has a source-native explanation. Preserve the observed variation in other page loads rather than applying a fixed delay everywhere.
