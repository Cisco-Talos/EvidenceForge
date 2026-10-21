# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 94  
**Synthetic-Confidence Score:** 84

## Executive Summary

Most network evidence is coherent: connection states vary, DNS includes several query types and failures, TLS versions and certificates are sensibly related, and SMB transfers preserve direction and byte accounting. The strongest contrary evidence is repeated TLS handshake summaries that require responder data absent from the corresponding connection records, supported by incomplete full-handshake histories and an unusually narrow OCSP connection-duration distribution.

## Evidence For Synthetic

- **[hard_contradiction] TLS ServerHello without responder payload.** At `2026-10-20T14:16:38.310955Z`, `office-span/ssl.json:172`, UID `CBogTHFyiqA1QvXD01`, reports `ssl_history="CS"`. Its matching `office-span/conn.json:438` has `resp_bytes=0`, `resp_pkts=1`, `resp_ip_bytes=64`, `history="ShAD"` and `missed_bytes=0`. The single responder packet is consistent with the SYN-ACK already represented by `h`; it cannot also carry the ServerHello represented by `S`. This repeats at `ssl.json:510` / `conn.json:1250` and `ssl.json:630` / `conn.json:1535`.
- **[contract_gap] Full ECDHE handshakes omit server key exchange.** Thirty-four established, non-resumed TLS 1.2 connections advertise ECDHE ciphers but have `ssl_history="CSXNGIFIFD"`, omitting the `K` present in other full handshake histories. Thirty matching connections report `missed_bytes=0`. For example, `ssl.json:9`, UID `CYWk4ifm6jNUgyjxeR`, negotiates `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` at `13:06:25.913692Z`, while `conn.json:24` reports no capture gap. Under standard handshake-history interpretation, ECDHE requires a server key-exchange message.
- **[distribution_texture] OCSP connections share an exceptionally narrow duration band.** Across 28 HTTP connections to OCSP hosts, four clients and nine destination IPs, durations range only from `0.456084` to `0.475017` seconds: median `0.458594`, standard deviation `0.004100` seconds. Examples include `conn.json:26` (`0.457580`, public responder), `:164` (`0.457981`, private responder), `:298` (`0.466753`, Windows CryptoAPI client), and `:996` (`0.459650`, Python requests client). A common timeout or intermediary could contribute, so this receives less weight than the TLS contradictions.

## Evidence For Real

- DNS has meaningful diversity: **743 A, 118 AAAA and 59 PTR** records, including **44 NXDOMAINs**. Answer address families match query types, and successful empty AAAA answers are represented separately from NXDOMAIN.
- TLS respects passive visibility: **568 TLS 1.3** records contain no certificate-chain FUIds, while visible certificate extraction occurs with TLS 1.2. Cipher families agree with leaf public-key types in the checked chains.
- All checked DNS, TLS, HTTP, NTP and SMB companion records match their connection UID and four-tuple, and their timestamps fall within the matching connection interval.
- SMB direction and accounting are convincing. `smb_files.json:2` records an `878226`-byte read; `files.json:1` records the same size and FUID, transmitted by `10.42.0.31` to `10.42.0.21`.
- Connection states include resets, unanswered SYNs, rejected connections, partial closes and midstream observations. Hourly connection counts vary substantially, rather than remaining constant.
- SSH transport and endpoint session timing are compatible. `conn.json:188` opens at `13:30:00.214365Z`; the matching build-host SSH login occurs at `13:30:06.746Z`, with logout near transport close.

## Detailed Analysis

### Scope and method

I examined all **4,619 records** in the ten `office-span` JSON files and used supplied endpoint records for a limited SSH timing cross-check. The connection window runs from `2026-10-20T13:00:15.184781Z` to `18:59:03.761620Z`.

The checks included UID and tuple joins, companion timestamps against connection intervals, directional file sizes against flow byte totals, DNS answer types, certificate-chain relationships, TLS cipher/key compatibility and protocol-specific distributions. No outside documentation or provenance information informed the assessment.

### Connection patterns and packet accounting

The 1,994 connections comprise:

| Transport | Count |
|---|---:|
| TCP | 1,024 |
| UDP | 965 |
| ICMP | 5 |

Connection states include `SF=1884`, `RSTO=45`, `RSTR=25`, `S1=12`, `S0=9`, `S2=5`, `S3=5`, `REJ=5` and `OTH=4`. The overall `SF` proportion is inflated by successful UDP exchanges; its interpretation should therefore account for transport.

The history strings generally agree with connection states. Rejected connections use `Sr`; unanswered SYNs use `S`; the partial-close states distinguish originator and responder FIN observations. I found no TCP direction with nonzero payload accounting but no corresponding data-history indication.

IPv4 packet totals also pass a basic lower-bound check: logged IP bytes accommodate the payload plus minimum IP/transport headers. Files extracted from individual connections do not exceed the corresponding directional flow bytes.

The internal probe sequence at approximately `17:49:53–17:50:21Z` includes both refusals and unanswered SYNs—for example, `conn.json:1654` rejects TCP/8080, while `:1655` receives no response on TCP/22. Those outcomes are plausible network observations.

### DNS

The DNS mixture is credible for these visible clients:

- `dns.json:1` resolves `graph.microsoft.com` at `13:00:15.184781Z`, with an RTT of `0.013185` seconds.
- Its first visible HTTPS connection, `conn.json:2`, begins at `13:00:16.705926Z`, after the DNS response.
- `dns.json:3` contains a valid IPv6 answer to an AAAA query.
- `dns.json:7` contains a successful AAAA response with no answers.
- `dns.json:17` records an NXDOMAIN for `isatap`.
- `dns.json:22` records a PTR response for `20.190.159.64`.

Resolver use is host-specific: `.11` uses the Google resolver pair, `.12` principally uses the Cloudflare pair, `.21` uses `208.67.222.222`, and `.31` uses the Cloudflare pair. This is more coherent than an indiscriminate resolver pool across every client.

I found no demonstrated DNS causality contradiction. The visible window and caching also prevent treating every connection without a fresh lookup as a defect.

### TLS contradictions

The decisive finding concerns three failed TLS exchanges:

| SSL line | Connection line | Time UTC | UID | SSL history | Responder payload / packets |
|---|---|---|---|---|---:|
| 172 | 438 | 14:16:38.310955 | `CBogTHFyiqA1QvXD01` | `CS` | 0 bytes / 1 |
| 510 | 1250 | 16:09:41.406293 | `CaVbA17hzF74FSRRs5f` | `CS` | 0 bytes / 1 |
| 630 | 1535 | 17:29:57.055535 | `Ch9Uy8CfGxqibd8XqK` | `CSL` | 0 bytes / 1 |

All three matching connections have `history="ShAD"` and `missed_bytes=0`. The records describe a responder SYN-ACK followed by originator data, without responder application data. A TLS history asserting ServerHello cannot follow from those observed packets.

This is a same-UID, same-sensor contradiction. Clock offsets and collection-window boundaries do not resolve it.

The missing-key-exchange histories form a separate concern. Among **157 established, non-resumed TLS 1.2** sessions, 34 use `CSXNGIFIFD` despite an ECDHE cipher; 30 have no reported missing bytes. The pattern spans three originators: `.11` contributes 19, `.12` contributes 11 and `.31` contributes four.

For comparison, `ssl.json:3` represents a full ECDHE handshake as `CSXKNGIFIFD`. Examples lacking `K` include:

- `ssl.json:9` / `conn.json:24`, `13:06:25.913692Z`.
- `ssl.json:20` / `conn.json:65`, `13:13:52.453833Z`.
- `ssl.json:32` / `conn.json:93`, `13:17:14.781415Z`.

The key-exchange finding assumes standard meanings for the handshake-history symbols. Without packet capture or a supplied custom logger definition, it is best treated as a strong contract gap. The zero-responder-payload cases carry greater evidential weight.

### TLS and certificate strengths

The broader TLS implementation is convincing:

- TLS 1.3 accounts for approximately **70%** of SSL records.
- There are **275 resumed** connections.
- TLS 1.2 RSA and ECDSA cipher selections agree with the corresponding leaf-key types.
- Presented chain links agree textually: each leaf/intermediate issuer matches the following certificate subject.
- Repeated certificate fingerprints retain consistent certificate properties.
- Referenced certificate validity periods encompass the observed handshakes.
- TLS 1.3 records do not expose certificate chains that a passive observer ordinarily could not read.

A case difference between an internal SNI and certificate SAN is ordinary DNS case insensitivity and is not a defect.

### HTTP and OCSP timing

Twenty-eight of 33 HTTP rows concern OCSP hosts. That predominance is reasonable where ordinary web application traffic uses TLS.

Their connection durations are less convincing. Public responders, a private responder, several browser families, CryptoAPI, Go and Python clients all produce approximately the same 460-millisecond connection lifetime. The coefficient of variation is only **0.89%** across those 28 connections.

This could partly reflect a shared transport policy or intermediary, so it does not establish synthetic origin by itself. Its breadth across client implementations and destinations makes it a meaningful supporting texture signal.

Some OCSP responder names differ from what a reader might expect for the textual certificate issuer. Without certificate AIA extensions, delegated-responder details or documentation of sanitization, those names are insufficient to establish another contradiction.

### SMB, SSH and traffic shape

The SMB evidence preserves useful protocol relationships. For UID `CVOCtOJ581SiLpeAg3`:

1. `smb_mapping.json:1` maps the share at `13:02:15.606686Z`.
2. `smb_files.json:1` opens the file at `13:02:15.990005Z`.
3. `smb_files.json:2` reads it at `13:02:16.075102Z`.
4. `files.json:1` reports matching extracted content at `13:02:16.192623Z`.

The file-transfer direction agrees with the SMB read.

For SSH, `conn.json:188` describes `.21:54438 → .31:22`, lasting `1869.406495` seconds. The matching build-host endpoint login is at `13:30:06.746Z` (`NS-BUILD-01.northstar.example/ecar.json:93`), and logout is at `14:01:11.524Z` (`:167`), close to the transport end at `14:01:09.620860Z`. Small cross-source offsets are plausible.

Hourly connection counts are `283, 472, 453, 192, 288, 306`. This provides believable activity variation within the daytime slice. The window does not support conclusions about overnight infrastructure traffic or weekly seasonality.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | TLS / connection summaries | Three failed TLS exchanges | ServerHello history requires responder payload absent from the matching observed connection. Primary finding. |
| `contract_gap` | TLS handshake histories | 34 full ECDHE sessions; 30 without reported gaps | Required key-exchange step absent under standard history notation. Strong supporting finding. |
| `distribution_texture` | HTTP / OCSP connections | 28 connections, four clients, nine destination IPs | Approximately identical connection lifetimes across otherwise varied exchanges. Moderate supporting finding. |

## Realism Score by Category

- **Field format accuracy:** 8 — Well-formed records and plausible types; TLS history semantics contain important inconsistencies.
- **Temporal patterns:** 7 — Broad traffic variation and credible lifecycle timing, weakened by tightly clustered OCSP durations.
- **Cross-source correlation:** 7 — Strong UID, tuple and file relationships, with repeated TLS/connection contradictions.
- **Behavioral realism:** 8 — Plausible browsing, infrastructure, file-sharing, SSH and failed connection behavior.
- **Environmental consistency:** 8 — Resolver assignments and visible service use are coherent across the four clients.

## Recommendations

If this were synthetic, the following changes would improve it:

- Generate failed TLS summaries and directional packet counters from the same observed handshake outcome. A ServerHello requires visible responder application data.
- Make TLS 1.2 handshake histories follow the selected key-exchange method and resumption state. Represent capture loss explicitly when it explains missing handshake messages.
- Give OCSP connection lifetimes client- and path-dependent variation, including realistic close and reuse behavior, instead of the observed common 460-millisecond band.
- Preserve the existing DNS type diversity, certificate consistency, SMB byte direction and SSH lifecycle relationships.
