# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 62

## Executive Summary

Most network evidence is convincing: transport state, protocol timing, DNS diversity, TLS negotiation, proxy topology, and long-lived administration flows fit a mixed enterprise network. My synthetic verdict rests on a narrow but repeated inconsistency: four HTTP file transfers report missing content without the corresponding same-sensor TCP gap accounting, including one transfer whose complete observation at a second sensor isolates the discrepancy.

## Evidence For Synthetic

- [contract_gap] `zeek-core/files.json:298`, FUID `F0C00BxylghrKqQzwn1`, reports `seen_bytes=317892`, `total_bytes=320932`, `missing_bytes=3040`. Its sole connection UID `CNjsifHcInbRaPC3LY` has `missed_bytes=0`, `history="ShADadTFf"`, and a complete `SF` connection in `zeek-core/conn.json:5986`. `zeek-core/http.json:908` also counts only 317,892 response-body bytes. This is missing file/HTTP content with no corresponding transport gap indication.
- [contract_gap] The same TCP tuple, `10.10.1.21:37402 -> 10.10.3.10:80`, is visible in `zeek-dmz/conn.json:4754`. Both sensors give precisely the same payload and packet counters, including `resp_bytes=698932`, `resp_pkts=484`, and `resp_ip_bytes=724108`, with zero missed bytes. Yet `zeek-dmz/http.json:996` and `zeek-dmz/files.json:604` see all 320,932 bytes of the same `/assets/img/content/2b5a8acb.webp` response. A clock offset explains the timestamps, but does not explain different HTTP content recovery under identical complete transport accounting.
- [contract_gap] This is repeated beyond that one transfer: `zeek-dmz/files.json:74` has 10 missing bytes, `:775` has 3,321, and `:1429` has 777. Their respective sole connections, `zeek-dmz/conn.json:329`, `:5399`, and `:8655`, all have `missed_bytes=0`, `SF`, and histories without `G/g`. These are HTTP 200 image responses, not partial-content 206 responses. The evidence suggests that at least some file-level loss was assigned independently of the transport observation.

## Evidence For Real

- Failed connections have coherent native states and packet histories. For example, `zeek-dmz/conn.json:1` is an unanswered TCP SYN to port 6379 with `S0`, history `S`, one originator packet and zero responder packets. `zeek-core/conn.json:3233` is a rejected port-445 connection with `REJ`, history `Sr`, zero payload, and one packet in each direction.
- DNS has multiple query types and realistic negative responses. `zeek-core/dns.json:1` is a domain-controller SRV lookup with two answers. `zeek-core/dns.json:13` has an authoritative NXDOMAIN for `oldserver.meridianhcs.local`; `zeek-dmz/dns.json:66` contains a suffix-expanded `ocsp.sectigo.com.meridianhcs.local` NXDOMAIN. Negative responses did not contain positive answer arrays in my full-file check.
- The proxy path is intelligible. `zeek-dmz/http.json:1` observes a client CONNECT to `10.10.3.20:8080`, while `zeek-dmz/ssl.json:1` observes that proxy's separate external TLS connection to `13.107.21.200:443` with SNI `www.bing.com`. Those are separate transport legs rather than incompatible identities on one connection.
- TLS records distinguish full TLS 1.2 handshakes, resumption, and TLS 1.3's reduced passive visibility. `zeek-core/ssl.json:4` is resumed TLS 1.2 with `CsiI`; `:1` is TLS 1.3 with `Cs` and no visible certificate chain. Visible ECDSA-authenticated TLS 1.2 connections had compatible leaf key types in the certificate records I joined.
- Capture loss is often propagated coherently. The 407 proxy response in `zeek-core/http.json:37` contains 631 bytes. At the DMZ sensor, `http.json:40` sees 630, `files.json:27` explicitly has one missing byte, and `conn.json:142` has one missed byte and `g` history. This provides a useful positive control against the four inconsistent transfers.

## Detailed Analysis

### Scope and method

I examined the supplied Zeek JSON files only, parsing every record in the connection, DNS, HTTP, SSL, files, and X.509 families and inspecting associated DHCP/SMB/SMTP examples. Line references are one-based physical JSON-lines positions. The connection window is approximately 2026-11-02 13:00–19:00 UTC. There are 12,279 core, 9,287 DMZ, and 464 database connection rows; these are sensor observations, not necessarily unique network connections, because paths overlap.

For each DNS/HTTP/SSL row, I joined the UID to the same sensor's connection record and compared transport tuples and timestamps. For file rows I used their connection UID lists. All examined links resolved, tuples matched, and protocol observations fell inside their associated transport intervals within a 10 ms lower-bound and 100 ms upper-bound allowance. File observation duration also ended within its sole connection's interval. I found no overlapping reuse of the same full transport tuple within a sensor.

### Transport behavior and traffic mix

Core TCP includes 4,968 `SF`, 1,440 `S0`, 166 `RSTO`, 98 `RSTR`, and 23 `REJ` records, with smaller incomplete/midstream populations. DMZ TCP includes 5,482 `SF` and 2,332 `S0` records, consistent with a mixture of working services and exposed-service probing. Database traffic is concentrated on port 3306: 314 observations, of which 254 are `SF`.

Durations are not a single service-independent template. Successful core SSH flows have a median duration around 1,879 seconds and extend to approximately 13,322 seconds. Successful database MySQL connections have a median around 2.88 seconds. The very short successful port-3389 TCP conversations are insufficient on their own to allege a completed remote desktop login; they can be probes or negotiations, so I did not score them as contradictions.

I checked packet counts against the minimal distinct SYN/data/FIN/RST packets implied by history and found no undercount. Apparent IP-byte overhead above header-only limits occurred with retransmission history; I therefore did not incorrectly score the extra retransmitted payload as impossible header size.

### DNS and TLS

Core DNS contains 2,270 A, 266 AAAA, 247 TXT, 142 PTR, 100 SRV, eight NS, and six MX rows. Response codes include 213 NXDOMAIN, 15 SERVFAIL, and four REFUSED among 3,039 queries. RTTs span tens of microseconds through roughly 2.12 seconds. This is substantially more convincing than uniformly successful A-only lookups. Cached DNS means that absence of a fresh query before each connection would not itself establish a defect.

The DMZ has 2,729 SSL rows, including 1,949 TLS 1.3 rows. TLS 1.2 includes AES-GCM, some CBC, ECDSA and RSA authentication; resumption is represented. I found no visible certificate whose validity interval excluded its observation time, and no collision where one fingerprint described different certificate fields. Public-domain names and address mappings were treated as potentially sanitized.

### Where the correlation fails

The strongest example occurs at core timestamp `1793633506.401757` in HTTP transaction depth 2 of UID `CNjsifHcInbRaPC3LY`. Its image file explicitly distinguishes a 320,932-byte total from only 317,892 observed bytes. The same sensor's TCP record claims no missing stream bytes and its history has retransmission `T` but no gap `G/g`. Retransmission alone does not explain an unrecovered 3,040-byte hole in the file while the connection reports complete capture.

The second sensor sees the exact same image transaction completely, while retaining identical transport packet/byte counts. The three additional image cases make this more persuasive than an isolated exporter quirk. I label this a contract gap rather than an absolute packet-level impossibility: the supplied records do not include raw packets, HTTP encoding headers, analyzer diagnostics, or exporter configuration that could test an unusual application-analyzer explanation. That limitation and the otherwise strong coherence keep the score near the bottom of the “likely synthetic” band.

No penalty was applied for dataset completeness, source coverage selection, the visible collection boundaries, or how readily suspicious activity could be narrated. The six-hour daytime window cannot establish overnight or weekend behavior.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Zeek conn + HTTP + files | Four image transfers: one core and three DMZ | Repeated missing content has no same-sensor TCP gap accounting. Primary reason for exceeding 60. |
| contract_gap | Overlapping core/DMZ observations | One particularly clear shared tuple and image response | Identical complete packet accounting accompanies conflicting recovered-body sizes. Strengthens the first finding; not counted as an unrelated defect. |

## Realism Score by Category

- **Field format accuracy:** 9 — Plausible JSON types, UID/FUID structures, states, protocol fields, and certificate relationships.
- **Temporal patterns:** 9 — Bursty traffic and service-dependent durations; no impossible visible same-identity ordering found in the joins.
- **Cross-source correlation:** 6 — Strong ordinary linkage, weakened by the four concrete HTTP/file versus TCP loss inconsistencies.
- **Behavioral realism:** 9 — Working services, connection failures, proxy errors, DNS negatives, and long-lived administration all have plausible network forms.
- **Environmental consistency:** 9 — Proxy, database, domain infrastructure, exposed services and sensor overlap form a coherent network view.

## Recommendations

- If this were synthetic, derive TCP stream gaps, HTTP observed-body lengths, and file `seen_bytes`/`missing_bytes` from one sensor-specific capture decision. Repair the four cited transfers without removing legitimate loss elsewhere.
- If file-analyzer loss is intentionally distinct from packet loss, preserve evidence of its cause, such as analyzer diagnostics or relevant HTTP encoding/range metadata. The present records present ordinary 200 image transfers with unexplained file gaps.
- Retain the coherent positive-control behavior exemplified by the 631-to-630-byte proxy error response, where connection, HTTP, and file accounting explain the same one-byte loss.
