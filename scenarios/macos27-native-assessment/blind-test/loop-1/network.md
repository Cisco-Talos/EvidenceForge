# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 95
**Synthetic-Confidence Score:** 90

## Executive Summary

The traffic is operationally coherent, with credible DNS-to-TLS ordering, certificate identity reuse, varied flow durations, and consistent joins among the network logs. However, repeated violations of Zeek's connection-history compression and TLS direction conventions, plus an incompatible NTP reference-ID representation, strongly suggest constructed source records rather than an untouched production export. An undocumented transformation of real logs could explain some formatting defects, so the conclusion is strong rather than absolute.

## Evidence For Synthetic

- [hard_contradiction] `office-span/conn.json` contains repeated responder ACK marker `a` in **352 of 873 TCP records (40.3%)**; 287 of these also repeat originator data marker `D`. Native Zeek history records each directional `a` and `d` marker at most once. At line 4, `2026-10-20T13:04:52.720510Z`, UID `Ccqm0bUSkySepOecTL`, `history="ShADaDadfF"` repeats both `a` and `D`; line 1, UID `CFC20K6LLHisX5lUJlx`, has `ShADaDadfFa`. This affects all four originating IPs and several protocols, so it is a broad source-format contradiction rather than an unusual conversation.
- [hard_contradiction] All **689** `office-span/ssl.json` histories are uppercase; **686** include uppercase `S` for ServerHello. Zeek capitalizes client-sent history letters and lowercases server-sent letters. Line 2, `2026-10-20T13:04:58.487558Z`, UID `C1zhfwA8fxOVmqbrgQq`, has `ssl_history="CSXKNGIFIFD"`, assigning the ServerHello, server certificate, ServerKeyExchange and ServerHelloDone to the client. Line 1 has `CSD` for an established TLS 1.3 exchange. These are incompatible with the native meaning of the field.
- [schema_or_format] All **12** `office-span/ntp.json` records report `stratum=2` and `ref_id=".GOOG."`. For a stratum above 1, Zeek represents the reference ID as an IPv4-address-shaped value, including the IPv6-reference hash case. The six-character ntpq-style display token is inappropriate for that native field. Examples are line 1 at `2026-10-20T13:09:42.660114Z`, UID `CAD2SqFDzX1ACIHxJSI`, and line 12 at `2026-10-20T18:55:01.745817Z`, UID `CC0yGQW9h25lqXsUfn`.

## Evidence For Real

- Network references are coherent: every DNS, TLS, HTTP, NTP, SMB-file and SMB-mapping record resolves to a connection UID with matching source/destination addresses and ports. Their record timestamps lie inside the corresponding visible connection intervals. This is positive consistency evidence; completeness itself is not a synthetic indicator.
- DNS has meaningful variety: 678 A, 106 AAAA and 57 PTR records; 54 NXDOMAINs; and 33 successful responses without answers. Query RTTs range from 2.172 to 346.837 ms, with a 27.143 ms median. `dns.json` line 6 shows a successful AAAA query with no answer rather than an invented IPv6 address for every name.
- TLS version, cipher and certificate behavior generally agree. There are 463 TLS 1.3 and 226 TLS 1.2 records, 218 resumptions, and nine unestablished exchanges. No TLS-version/cipher-family mismatch or visible RSA-versus-ECDSA leaf-key mismatch was found.
- Certificate identity is stable across repeat observations. The 286 X.509 rows represent 77 fingerprints; repeated fingerprints have consistent certificate fields, complete file lengths and alternate hashes. All visible certificate-chain references resolve, leaf names match the recorded SNI, and adjacent issuer/subject names agree.
- Flow duration and volume differ by application. DNS is brief, HTTPS spans milliseconds to tens of seconds, SMB includes both short transactions and an 85.9-second flow, and the six SSH flows last approximately 16.6–59.6 minutes. Hourly connection counts vary substantially, rather than forming a fixed rate.

## Detailed Analysis

### Scope, method and collection limits

I examined only the ten JSON files under the supplied dataset's `office-span/` directory. I did not read endpoint logs, histories, scenario material, ground truth, repository files or host state. All 4,204 network records were parsed for aggregate checks, with bounded examples inspected for the findings below. Line references are one-based physical JSON-record lines. Times are UTC.

The connection window runs from `2026-10-20T13:01:30.950880Z` to a last visible connection close of `2026-10-20T18:58:43.009628Z`. Volumes are: 1,771 connection rows, 841 DNS, 689 TLS, 386 files, 286 X.509, 96 SMB-file, 53 SMB-mapping, 39 HTTP, 31 OCSP and 12 NTP rows. Four IPs originate connections: `10.42.0.11` (772), `.12` (713), `.21` (211) and `.31` (75).

The precise Zeek release and custom logging policy are not stated. Public Zeek documentation and source were used to verify field semantics; the score does not depend on assuming an endpoint platform from these network records. Domain spelling, public-domain/IP correspondence, thin source coverage, absent endpoint companions, and events outside the collection window were not scored.

### Connection states, histories and accounting

There are 889 UDP, 873 TCP and nine ICMP connection rows. Across all protocols the state counts are SF 1,684; RSTO 37; RSTR 22; S1 nine; S2 seven; S3 five; OTH five; and S0 two. The non-SF tail is plausible. UDP SF is valid flow terminology and was not interpreted as a TCP handshake.

The TCP histories are the principal defect. The 352 rows with repeated directional ACK/data symbols comprise 307 SSL, 22 SMB, 19 HTTP, two SSH and two unclassified TCP connections. They originate from all four clients: `.11` has 166 affected rows, `.12` 143, `.21` 30 and `.31` 13. Zeek's documented compression does not accumulate additional `a` or `D` symbols for repeated ACKs or multiple application turns. For example, `conn.json:12`, UID `CoCPs70SDsAQgiquNm`, has `ShADadfFa`, repeating responder ACK after teardown; `conn.json:7`, UID `C1zhfwA8fxOVmqbrgQq`, has `ShADaDadfF`. Both are inconsistent with native marker suppression. [Zeek connection-history definition](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info).

Other accounting checks were favorable. No TCP row had IP-byte totals below its directional payload plus the minimum 40-byte IPv4/TCP header allowance per packet. SF TCP histories contain both FIN directions; S2/S3 histories contain the expected initiating close direction. The five OTH histories lack the opening SYN, which agrees with midstream observation. There are 100 flows with content-gap history markers and exactly 100 with nonzero `missed_bytes`, so the loss fields are not independently random-looking decorations.

### DNS and connection sequencing

DNS uses five public recursive-resolver addresses. A/AAAA/PTR variety and negative responses are present, with sensible numeric/name pairings and no IPv4 answer supplied as an AAAA address. Every logged DNS RTT fits within its associated connection interval.

A concrete correlated sequence is `dns.json:3` at `13:04:58.012848Z`, querying `changelogs.ubuntu.com` from `10.42.0.31` and returning `91.189.91.40` and `.39`. Connection `C1zhfwA8fxOVmqbrgQq` starts at `13:04:58.388359Z` (`conn.json:7`) to `.40:443`; TLS appears at `13:04:58.487558Z` (`ssl.json:2`). The DNS RTT is 20.502 ms, leaving a plausible delay before transport establishment.

Another sequence has `dns.json:5` resolving `objects.githubusercontent.com` at `13:06:53.684113Z`, an unanswered AAAA result at `13:06:54.060153Z` (`dns.json:6`), and TLS to an A-answer address at `13:06:54.405501Z` (`ssl.json:3`). Of 689 TLS records, 656 have an earlier matching visible A answer for the same originating IP, name and destination address. The remaining 33 are compatible with caching or other resolution paths and were not penalized. Likewise, 36 DNS-labelled connection rows lack DNS-detail rows; selected family coverage alone does not prove a defect.

### TLS, certificate chains and source-native direction

TLS 1.3 cipher choices are AES-GCM or ChaCha20-Poly1305; TLS 1.2 uses ECDHE cipher suites, mainly GCM, with five CBC selections. The protocol mix and resumption fraction are plausible. Every TLS 1.3 record omits certificate-chain FUIDs, consistent with passive encrypted-certificate visibility. TLS 1.2 full handshakes often include a leaf and intermediate, while resumed sessions omit them.

The fatal native-format problem is direction. `ssl.json:2` has `CSXKNGIFIFD`, although the server-sent messages must use lowercase history markers. The effect is dataset-wide, including abbreviated histories such as `CSIFIFD`, not restricted to one damaged session. Zeek explicitly preserves client/server direction in this field. [Zeek TLS history definition](https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html#type-SSL::Info).

A related, smaller inconsistency is that the three ClientHello-only histories still contain a selected `version`. For example, `ssl.json:11` at `13:20:01.956811Z`, UID `COcxUVH7JhQj65in1E`, has `ssl_history="C"`, `established=false`, no cipher, but `version="TLSv12"`. Standard Zeek assigns the negotiated version using server-side handshake evidence. This reinforces the same TLS-rendering concern rather than being counted as an independent major indicator. [Zeek TLS implementation](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/ssl/main.zeek).

The chain data itself is strong. For UID `C1zhfwA8fxOVmqbrgQq`, `ssl.json:2` references `FEzT5tBpRtqmeHZFhM` and `FUXC3GpbJqYKFLQL7G`. They resolve to `x509.json:1–2` and `files.json:2–3`. The leaf subject/SAN is `changelogs.ubuntu.com`; its issuer matches the intermediate subject. The file SHA-1 values agree with the X.509 fingerprints, transmission runs from the server to the client, and observation times follow the handshake start. Repeated certificates retain identity and size; I found no same-fingerprint/changing-certificate contradiction.

### HTTP, SMB and file-transfer coherence

Most plaintext HTTP is OCSP traffic: 34 of 39 HTTP records target OCSP-named hosts. The remaining visible requests include redirects and a 404. HTTPS dominates application connections, with 752 SSL-labelled versus 42 HTTP-labelled flows, a plausible modern-office balance given plaintext revocation checks. Exact product-version chronology was not used as a score driver.

All HTTP response-file references resolve and their observed sizes agree with `response_body_len`. For UID `CUCRttBz9eYDlbipfGL`, `http.json:1` at `13:05:58.097811Z` records a 302 and 425-byte HTML body; `files.json:4` observes that same 425-byte object at `13:05:58.135548Z` within `conn.json:11`'s interval.

SMB targets `10.42.0.31:445`, with a share named `Engineering` visible in SMB mappings. UID `CFC20K6LLHisX5lUJlx` has FILE_OPEN at `13:01:31.336760Z` and FILE_WRITE at `13:01:31.448686Z` (`smb_files.json:1–2`), followed by the matching file observation at `13:01:31.481849Z` (`files.json:1`). Its 372,479-byte file fits inside the 441,924-byte originator payload. Across the file logs, no observed file exceeded the associated flow's directional payload; transmission/reception hosts agree with the recorded direction.

### NTP, lateral traffic and temporal texture

NTP is restricted to `10.42.0.21` contacting `216.239.35.0`, with 12 exchanges and a 2,048-second poll value. Actual inter-arrival times vary from roughly 1,253 to 2,337 seconds. The timing and nonzero delay/dispersion values are plausible; clock offsets between packet timestamps and embedded NTP timestamps were not treated as impossible ordering.

The field representation is defective: every response combines `stratum=2` with `ref_id=".GOOG."`, whereas Zeek's above-stratum-1 representation is an IPv4-shaped address or hash. This is a source-format issue, not a complaint about choosing Google's time service. [Zeek NTP reference-ID semantics](https://docs.zeek.org/en/current/scripts/base/protocols/ntp/main.zeek.html#type-NTP::Info).

Internal traffic includes 56 SMB flows, five SSH flows to `.31`, one SSH flow to `.12`, and internal TLS. SSH durations and low-to-moderate byte volumes are compatible with interactive or administrative work. Network records alone cannot attribute them to authorized administration or intrusion. I did not penalize the lack of an SSH-detail file, RDP, LDAP, Kerberos, DHCP or other optional source families.

Hourly connection starts for 13:00 through 18:00 UTC are 208, 513, 252, 179, 336 and 283. This is uneven rather than fixed-rate traffic. The six-hour window does not support conclusions about full-day business-hour behavior, overnight activity or weekly cadence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| hard_contradiction | Zeek connection history | 352/873 TCP records, four originating IPs, five classified application families | Repeated directional ACK/data symbols violate native history suppression; substantial independent support for constructed histories. |
| hard_contradiction | Zeek TLS history | All 689 histories uppercase; 686 contain uppercase ServerHello | Server messages are assigned client direction, including full and abbreviated handshakes; the strongest dataset-wide source-native tell. |
| schema_or_format | Zeek NTP | All 12 records | Stratum 2 paired with a six-character display token instead of the native reference-ID representation; smaller corroborating defect. |

The score is driven by these specific source-native contradictions. Strong reference integrity, stable certificate identity and credible protocol ordering materially improve the assessment of operational realism. No score was added for a compact narrative, sanitized names, completeness, optional source absence or collection boundaries. The three ClientHello-only version anomalies support the TLS finding and are not separately weighted as a fourth major defect.

## Realism Score by Category

- **Field format accuracy:** 5/10 — JSON types and most fields are credible, but connection/TLS histories and NTP reference IDs violate native semantics.
- **Temporal patterns:** 8/10 — Varied flow durations and request timing; checked protocol records and DNS RTTs fit their connection windows.
- **Cross-source correlation:** 9/10 — UID/tuple joins, certificate references, file hashes, directions and response sizes agree across the examined network sources.
- **Behavioral realism:** 8/10 — Credible SaaS/development browsing, revocation checks, SMB transfers and long-lived SSH; six hours limits broader behavioral judgments.
- **Environmental consistency:** 8/10 — Concentrated internal services and client/service differences are plausible; collection policy and release metadata remain unknown.

## Recommendations

- If this were synthetic, construct `conn.history` with Zeek's directional marker suppression: retain only one `a`, `A`, `d` and `D` per connection, while preserving the separate rules for repeatable handshake/close and logarithmic loss/retransmission markers.
- If this were synthetic, render `ssl_history` from ordered client/server message observations. Lowercase the server's messages and ensure selected version/cipher fields are supported by the recorded handshake stage; a ClientHello-only failure should not invent a negotiated server version.
- If this were synthetic, emit NTP `ref_id` according to stratum and Zeek's actual encoding, rather than copying a time-client display token into the field.
- If these are transformed production logs, document the transformation that changes histories or reference IDs and preserve the native values for analysis. That would help distinguish collection-induced artifacts from constructed telemetry.
