# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 30

## Executive Summary

The bounded network review found plausible connection states, protocol mixtures, DNS failures and certificate relationships, with two coherent exact-identity cross-source pivots. A small database-segment TLS population is unusually concentrated in legacy TLS 1.2 cipher choices, but this is readily explained by a fixed client configuration and does not establish synthetic origin. No demonstrated impossible relationship was found in the inspected records.

## Evidence For Synthetic

- [weak_signal] In `zeek-db/ssl.json`, all 19 TLS rows advertise TLSv12; 11/19 select `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` and 8/19 select `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`. This restricted legacy distribution deserves scrutiny in a November 2026 collection, but a small server population or older client stack could explain it. It carries little weight without client inventory or negotiation details.
- No hard contradiction, demonstrated contract gap, or source-format defect was established in this bounded review. The above weak signal cannot independently support a Synthetic verdict.

## Evidence For Real

- `zeek-dmz/conn.json` UID `CMqVDGDEGOP76UgYg`, timestamp `1793624416.154508`, records an unanswered TCP attempt to `10.10.2.30:443` with `conn_state=S0`, history `S`, one origin packet/52 IP bytes, and no response packets or bytes. The fields agree with the observed state.
- `zeek-dmz/ssl.json` UID `C9aY86RuIQ04K3s7C2`, timestamp `1793629659.228162`, contains an incomplete handshake (`ssl_history=C`, `established=false`) and omits negotiated version and cipher. This is a plausible failed negotiation rather than a successful session populated with invented negotiated values.
- `zeek-dmz/dns.json` UID `CGMbJ73xrATQIV9Zgz` records an A query for `isatap` at `1793624553.581353`, `rcode=3/NXDOMAIN`, RTT `0.031381`, and no answer array. Core DNS also contains A, AAAA, PTR, SRV, TXT, NS, SOA and MX traffic with distinct response codes.
- Exact UID and certificate-FUID relationships for an internal TLS session preserve endpoint identity, plausible handshake timing, SNI/SAN agreement and issuer-to-subject chain continuity; details appear below.
- Exact source tuple, destination hostname, user agent and tunnel identifier link a Zeek proxy connection to both CONNECT and inspected HTTP access entries. Directional connection bytes equal the logged control plus tunnel bytes in that example.

## Detailed Analysis

### Scope, method and limits

I inspected 19 distinct representative records, including the records used in two exact pivots, plus aggregate counts over the three network sensor directories. The record sample covers connection, DNS, HTTP, TLS, X.509 and proxy telemetry. I did not inspect endpoint logs, scenario material, evaluation output or other reviewers' work. The aggregate connection timestamps span approximately `2026-11-02 13:00:00` to `18:59:44.793219 UTC`; this window cannot establish overnight or weekend behavior. Counts below are per sensor, not deduplicated network totals: a flow visible to multiple sensors must not be counted as multiple independent activities. No absence of a pre-window or post-window lifecycle record is scored.

### Connection and protocol distributions

`zeek-core/conn.json` contains 12,943 records: SF 10,406; S0 1,768; OTH 442; RSTO 162; RSTR 101; REJ 29; S3 15; S2 11; S1 9. `zeek-dmz/conn.json` contains 10,263: SF 7,175; S0 2,545; OTH 310; RSTO 118; RSTR 62; REJ 23; S2 15; S1 10; S3 5. `zeek-db/conn.json` contains 438: SF 329; RSTO 38; OTH 23; RSTR 18; S0 13; REJ 9; S2 5; S3 2; S1 1. These are varied state populations, and the inspected S0 example is internally coherent. A 24.8% DMZ S0 share is noticeable but does not demonstrate an unrealistic environment without a workload and sensor-placement baseline.

Core destination-port counts include DNS/53 3,272, Kerberos/88 2,607, proxy/8080 2,406, LDAP/389 1,136, SMB/445 723, HTTPS/443 642 and SSH/22 380. Database sensor records concentrate on port 3306 (255/438), with 48 DNS and 34 syslog/514 records. The sampled database flow `COByFoMz06HxZiuOa` at `1793635028.150177` connects `10.10.3.10:53305` to `10.10.4.10:3306`, service `mysql`, state SF, duration `0.06637`, and asymmetric payloads 4,530/35,432 bytes. This is plausible for a short database exchange; the aggregate port population is compatible with the sensor's apparent role.

The HTTP populations are dominated by CONNECT: core 2,318/2,520, DMZ 2,364/2,776, database 20/22. Therefore an HTTP-row count is not a count of cleartext browsing sessions. Other statuses include authentication failures, policy denials, redirects and gateway/server failures. Core, for example, has 41 responses with status 407, 46 with 403 and 15 with 502. These variations are compatible with proxy observation; I do not score the larger HTTP row count relative to TLS rows as a defect.

### DNS and TLS texture

Core DNS comprises 3,265 rows: A 2,398; TXT 307; AAAA 274; PTR 163; SRV 100; NS 16; SOA 4; MX 3. Responses comprise 3,025 NOERROR, 222 NXDOMAIN, 14 SERVFAIL and 4 REFUSED. The representative internal-host query at `1793636451.985097` (`CMAK59U0DCnDtKGZmPx`) returns `DC-02.meridianhcs.local -> 10.10.2.11`, TTL 300, RTT 0.001149. The range of query types, response errors and sampled RTTs is plausible; these counts alone do not prove organic timing or a realistic long tail.

Core TLS rows are 214 TLSv13 and 199 TLSv12. DMZ TLS rows are 2,125 TLSv13, 909 TLSv12 and four without a negotiated version. This mixed distribution and the inspected incomplete handshake are plausible. Database TLS has the narrow distribution noted above. Sanitized domain names and real-world DNS-to-IP ownership are not used as authenticity evidence.

### Exact pivot 1: TLS connection to certificate chain

In `zeek-core/conn.json`, UID `CfXsGkkuG9lcJw887K` starts at `1793635200.175663` for `10.10.1.21:42707 -> 10.10.2.21:443`, with duration `14.185937`, SF and history `ShADadFf`. The same UID and tuple appear in `zeek-core/ssl.json` at `1793635200.230940`, approximately 55.277 ms after connection start, with TLSv12, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, established=true, resumed=false, and SNI `FILE-LNX-01.meridianhcs.local`.

Its two `cert_chain_fuids` resolve in `zeek-core/x509.json`: leaf `FQKBEGjxMFg4aE9tahU` at `1793635200.238519` has subject `CN=FILE-LNX-01.meridianhcs.local` and SANs `file-lnx-01.meridianhcs.local` / `file-lnx-01`; issuer is `CN=Meridianhcs Enterprise Issuing CA, O=Meridianhcs, C=US`. Intermediate `FAg1hiFlqkGBwA3VphH` at `1793635200.246587` has that same subject and `basic_constraints.ca=true`, while the leaf has `false`. Both displayed validity intervals include the connection timestamp. The visible references and chain metadata agree. I have not validated certificate signatures or inferred cryptographic trust from metadata alone.

### Exact pivot 2: proxy transport, CONNECT and inspected request

In `zeek-core/conn.json`, UID `CcWaxAYQjc7El3HI2J` begins at `1793635511.892404` for `10.10.1.22:38139 -> 10.10.3.20:8080`; SF duration is `0.990148`, placing close at approximately `16:05:12.882552 UTC`. The same UID and tuple in `zeek-core/http.json` at `1793635511.965834` carry `CONNECT drive.google.com:443`, status 200, and the Firefox/121 Ubuntu user agent.

In `PROXY-01.meridianhcs.local/proxy_access.log`, the `02/Nov/2026:16:05:11 +0000` CONNECT row matches client IP, `client_src_port=38139`, target and user agent. It identifies `tunnel_id=PT-2eaa7484f8d1ecf0`, `cs_bytes=224`, `wire_sc_bytes=186`, `tunnel_cs_bytes=1966`, and `tunnel_sc_bytes=4139`. Those give 224+1,966=2,190 origin bytes and 186+4,139=4,325 response bytes, matching conn fields. A GET row at `16:05:12` has that exact tunnel ID and client port, targets `https://drive.google.com/_/DriveFs/data?hl=en`, and records status 301 with SSL inspection. Its second-resolution timestamp fits the connection interval; the logs do not support an ordering contradiction. Matching completeness is evidence of usable shared identity, not a synthetic indicator.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| weak_signal | Zeek TLS | Database sensor: 19/19 TLSv12, 11/19 CBC; aggregate only | Small increase in suspicion; fixed older clients are a plausible explanation. |
| No demonstrated high-impact indicator | Inspected network/proxy records | 19 representative records; two exact pivots | No impossible ordering, source-native contradiction or demonstrated contract gap found. This limits the score and prevents a confident Synthetic verdict. |

## Realism Score by Category

- **Field format accuracy:** 9 — Inspected typed Zeek fields, omission on failed negotiation and proxy semantics are coherent; no packet capture or cryptographic validation was available.
- **Temporal patterns:** 8 — Two pivot timelines are plausible; six hours and a bounded sample cannot establish broader human or infrastructure timing.
- **Cross-source correlation:** 9 — Exact UID/FUID and proxy tuple/tunnel pivots preserve identities and agree on the inspected facts.
- **Behavioral realism:** 8 — Varied connection outcomes, DNS errors and proxy responses are plausible; long-tail behavior was not exhaustively examined.
- **Environmental consistency:** 8 — Infrastructure and database traffic fit apparent segments; database TLS concentration remains a weak, explainable concern.

## Recommendations

- If this were synthetic, tie database TLS choices to explicit, stable client/software profiles and retain the observed legacy concentration only where those profiles justify it. The 19-row sample does not justify simply replacing all TLS 1.2 with TLS 1.3.
- Preserve the exact transport, TLS certificate and proxy tunnel relationships demonstrated above. No additional source collection or lifecycle invention is warranted by this review.
