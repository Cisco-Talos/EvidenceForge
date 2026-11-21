# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 74

## Executive Summary

The network telemetry is largely convincing: transport states, protocol relationships, certificate metadata, proxy paths, and byte accounting remain coherent across thousands of records. However, one HTTP/1.1 conversation has a source-native response-order contradiction independently visible at two sensors: the second response's CSS body appears before the first response's HTML body. This localized but concrete defect drives the synthetic verdict; the otherwise strong realism limits the score.

## Evidence For Synthetic

- [hard_contradiction] HTTP/1.1 response bodies appear in the wrong order on a single TCP connection. In `zeek-core/http.json`, UID `CVZ14Uhc67AVJrYgbO` identifies `10.10.1.34:51815 → 10.10.3.10:80`: transaction 1 is `GET /`, returning 22,000 bytes of HTML; transaction 2 is `GET /assets/css/main.min.07b8945e.css`, returning 44,639 bytes of CSS. In `zeek-core/files.json`, the transaction-2 CSS file `FcAwSXabsOPO4OA3AM1` starts at `1793627680.631737`, whereas transaction-1 HTML `FPYs6Z6M0cYToyUIi26` starts at `1793627680.712795`. The CSS body begins approximately 81 ms before the preceding HTML body. HTTP/1.1 pipelining can overlap requests, but responses on the same connection must retain request order.
- [contract_gap] The same physical conversation has another small response-body interval overlap in `zeek-dmz/files.json`: transaction-5 hero image `F0cETGmt9ZTXn52uqwG` starts at `1793627682.533969` and lasts `0.225849` seconds, ending at approximately `1793627682.759818`; transaction-6 favicon `FwLHmAgHwg8Q3Hjy5` starts at `1793627682.757831`, approximately 1.987 ms before the prior body finishes. This is supporting evidence of independently assigned file timing, with much less weight than the approximately 74–81 ms body-order reversal.
- [weak_signal] Successful SSH authentication latency is concentrated across several hosts and users. Among 36 accepted SSH sessions matched to visible transport tuples, 32 authenticate 8–11 seconds after the earliest corresponding sensor's transport timestamp; median latency is approximately 9.86 seconds. That could reflect a shared authentication service or automated administration, so it contributes little to the verdict and is not a protocol violation.

## Evidence For Real

- The connection population contains meaningful failure and partial-session variety. `zeek-core/conn.json` includes 9,787 `SF`, 1,670 `S0`, 156 `RSTO`, 104 `RSTR`, 44 `REJ`, and smaller `S1`/`S2`/`S3` populations, plus 435 `OTH` records. TCP histories vary, including retransmission and gap markers. I do not treat the success rate or completeness of matching as evidence of fabrication.
- DNS has realistic record and outcome diversity. Core records contain A, AAAA, PTR, SRV, TXT, NS, MX, and SOA queries, with 206 NXDOMAIN, 12 SERVFAIL, and five REFUSED responses. For example, `_kerberos._tcp.meridianhcs.local` resolves to two DC names, while `res.cdn.office.net` has an AAAA answer and a short TTL.
- The apparent HTTP-heavy network is largely an explicit proxy environment rather than mostly plaintext browsing: core HTTP contains 2,405 CONNECT requests among 2,614 HTTP rows. The first visible CONNECT names `spoprod-a.akamaihd.net:443`, while the DMZ has the proxy's separate outbound TLS connection to that name and destination IP.
- TLS evidence distinguishes full handshakes, resumptions, TLS 1.2, TLS 1.3, and incomplete handshakes. Certificate references resolve within their respective sensor exports; checked certificate key types agree with RSA/ECDSA cipher authentication, and referenced leaf validity intervals contain the observed handshakes.
- UID and connection-tuple matching is coherent throughout the examined Zeek DNS, HTTP, SSL, SMTP, and SMB-file rows. Protocol timestamps lie inside their parent connection intervals. All checked HTTP body totals and per-direction file-byte totals fit the corresponding transport-byte budgets.
- SSH transport opens precede the matched accepted-authentication messages and endpoint FLOW observations precede those authentications. For example, the first PROXY-01 SSH login from `10.10.1.31:49670` is accepted at `2026-11-02T13:00:15.802864Z`, approximately ten seconds after transport open, rather than authenticating before transport exists.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory and the assigned instructions. I parsed all records in the three Zeek sensor directories and used selected firewall, IDS, proxy-related, endpoint FLOW, and SSH syslog records to interpret the network paths and timing. No external scenario or ground-truth material was used.

The exports contain 23,141 connection rows, 4,385 DNS rows, 5,547 HTTP rows, and 3,668 SSL rows across `zeek-core`, `zeek-db`, and `zeek-dmz`. These are sensor observations, not counts of unique physical network activities: some connections cross multiple sensor locations. Connection start timestamps span roughly 13:00–19:00 UTC on November 2, 2026. A six-hour daytime slice cannot establish weekend behavior or overnight coverage, so neither was scored.

### Transport behavior and accounting

The core sensor sees internal infrastructure and proxy-client traffic; the DMZ sensor sees external TLS/proxy traffic and substantial unsuccessful connection traffic; the DB sensor is dominated by MySQL connections. For example, 273 of the DB sensor's 430 connection rows target port 3306. These differences are compatible with their visible traffic paths.

I checked for overlapping identical five-tuples within each sensor and found none. Successful TCP rows have both FIN directions represented in their histories, and none of those rows has an implausibly tiny one- or two-packet originator count. HTTP response-body sums do not exceed responder transport bytes, including persistent connections with multiple transactions. The analogous direction-specific sums of visible file bytes also fit transport budgets after allowing recorded gaps.

Some raw payload-versus-IP-byte comparisons initially look unusual on gap-bearing connections. Since Zeek stream byte accounting and observed packet accounting can diverge when `missed_bytes` is nonzero, I did not classify those rows as impossible packet sizes or invalid headers.

### HTTP ordering: the decisive defect

The affected core conversation begins at `1793627680.495048`, lasts `7.716550` seconds, and is explicitly TCP HTTP/1.1. Its seven HTTP transactions have increasing `trans_depth` and include an HTML page, CSS, images, JavaScript, a cached 304 response, and a favicon.

The first two request timestamps are `1793627680.507677` and `1793627680.507678`. The approximately one-microsecond request spacing is unusual, but could be explained by pipelining or prior knowledge of assets. I therefore do not classify request spacing alone as impossible.

The response-file relationship is different. The CSS file is explicitly referenced by the second transaction's `resp_fuids`, and the HTML file by the first transaction's `resp_fuids`; both are responder-direction HTTP files on the same UID. CSS first-seen time is `13:54:40.631737` UTC, with duration `0.002967`; HTML first-seen time is `13:54:40.712795`, with duration `0.004257`. Thus even the CSS file's last observed data precedes the HTML file's first observed data. Parallel connections cannot explain this because the UID and tuple are the same. HTTP/2 multiplexing cannot explain it because these rows say `version: "1.1"`.

This is also visible in the other sensor's own timebase. `zeek-dmz/http.json` assigns the same physical tuple UID `CUndz3AFi0yhIEnnis`. Its first HTML file `FZlLbEyYE2RgJwW7aFd` begins at `1793627680.501652`, while second-transaction CSS `FCZ0EpSNPF1jcHr6FaR` begins at `1793627680.427936`: approximately 73.716 ms earlier. A constant clock offset between sensors does not repair an ordering inversion internal to each sensor.

I examined the consecutive response-file pairs in all visible multi-transaction HTTP conversations: 54 comparable pairs at core and 55 at DMZ. The first-two-body inversion occurs in this one mirrored conversation, rather than throughout the export. The small hero-image/favicon interval overlap occurs in the same DMZ conversation. These are related timing defects and should not be counted as three independent broad failures.

### DNS and TLS

Core DNS counts are 2,348 A, 297 AAAA, 264 TXT, 158 PTR, 103 SRV, nine NS, seven MX, and two SOA rows. This mix is compatible with an internal directory environment plus other visible activity. Responses include NODATA-like empty answers, negative results, multiple answers, differing TTLs, and varied response times. I found no DNS transaction whose timestamp falls outside its own matching connection.

The SSL rows include 2,460 TLS 1.3 and 1,201 TLS 1.2 observations, with seven incomplete rows lacking a negotiated version. TLS 1.3 histories are typically `Cs`, consistent with later handshake material being encrypted. TLS 1.2 full handshakes carry certificate references in many cases; resumed handshakes have abbreviated histories and lack fresh chains. I did not mistake missing fresh certificates on TLS 1.3 or resumed connections for missing mandatory evidence.

For a concrete proxy example, the DMZ TLS row for `spoprod-a.akamaihd.net` at `1793625551.052454` is a resumed TLS 1.2 session to `23.45.101.60`; a nearby DNS A query at `1793625550.924455` returns that address and `23.45.101.61`. An earlier connection to the same hostname does not require another visible lookup because caching and pre-window resolution are possible.

### Endpoint and collection interpretation

Matching SSH acceptance messages occur after corresponding transport opens. Their concentrated latency deserves investigation, but public-key automation, shared authentication infrastructure, and host-specific collection offsets can explain much of it. I did not require every accepted SSH session to have an immediately visible connection row; long-lived sessions and connection-log publication at closure complicate a time slice.

I did not penalize absent QUIC, NTP, particular endpoint audit types, or complete boot/shutdown evidence. Nor did I infer native endpoint collection solely from a network row involving a Mac. Domain names and public IP relationships were treated as potentially sanitized.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Zeek HTTP and files | One physical HTTP/1.1 conversation, independently observed at core and DMZ | High: transaction-2 response body appears before transaction-1 body in both sensor timebases. |
| `contract_gap` | Zeek files | Same DMZ conversation, transactions 5–6 | Low supporting weight: consecutive HTTP/1.1 response-file intervals overlap by approximately 1.987 ms. Likely related to the main timing defect. |
| `weak_signal` | Zeek transport plus SSH syslog | 36 matched accepted sessions; 32 in an 8–11 second authentication band | Minimal: concentrated timing may be templated, but has plausible operational explanations. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek structures, typed fields, protocol identities, and certificate relationships are convincing; the decisive problem is temporal semantics.
- **Temporal patterns:** 6 — Varied flow timing and sensible SSH transport ordering, offset by the demonstrated HTTP response-body inversion and small overlap.
- **Cross-source correlation:** 7 — Strong tuple, UID, byte-budget, TLS, and transport linkage overall; HTTP-to-file timing fails in one mirrored conversation.
- **Behavioral realism:** 8 — Plausible proxy use, directory traffic, database traffic, failed connections, resumptions, caching, and administrative SSH.
- **Environmental consistency:** 9 — Sensor-specific traffic mixes agree with visible network paths; no demonstrated host-platform or collection-scope contradiction.

## Recommendations

- If this were synthetic, order HTTP/1.1 response-body file observations by transaction depth within each connection. A later response body must begin after the previous response body completes; independent per-file timing variation must preserve that relationship.
- Apply sensor observation offsets to an already valid HTTP stream timeline, and preserve source-local ordering when adding observation jitter. The core and DMZ reversals show why a common connection interval alone is insufficient.
- Retain the existing transport byte budgets, protocol UID relationships, status-dependent body lengths, certificate consistency, and proxy separation: those features held up well under the checks performed.
- Investigate the concentrated SSH authentication-delay band against the intended authentication mechanism. If a common delayed authentication service is intended, represent that operational cause consistently; otherwise vary latency using the actual mechanism and host conditions. This is a low-priority distribution check, not a required correction established by these logs.
