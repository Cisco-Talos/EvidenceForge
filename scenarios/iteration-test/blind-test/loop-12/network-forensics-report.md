# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 24

## Executive Summary

The network telemetry is mostly production-like: transport state, DNS transactions, HTTP persistence, proxying, and TLS certificate relationships survive detailed consistency checks. I found one weak software-version distribution concern, but no demonstrated impossible protocol relationship; my preference for Real is therefore moderate rather than a claim of proven provenance.

## Evidence For Synthetic

- [weak_signal] Browser-version families are conspicuously separated by platform in the HTTP observations. In `zeek-core/http.json`, 501 rows advertise Linux Chrome/120 and 214 advertise Windows Chrome/120, while 385 advertise macOS Chrome/155; additional Edge/120 and Firefox/121 strings recur on Windows/Linux. For example, line 2 at `2026-11-02T13:01:12.884086Z`, UID `CSfABEnLLzYoEQVDof`, advertises Windows Chrome/120. This could reflect stock client profiles, but managed application versions, compatibility clients, and user-agent substitution are plausible explanations. It is a weak distribution concern, not a protocol contradiction, and contributes little to the score.

## Evidence For Real

- Protocol-to-transport relationships are coherent across 22,408 sensor connection observations. All 4,237 DNS, 5,180 HTTP, and 3,433 SSL records have a same-sensor connection UID and matching four-tuple; none precedes its connection start or exceeds its end by more than the 100 ms tolerance used in this review. Counts include observations of the same traffic at multiple sensors.
- DNS has meaningful protocol variety and failures. Core contains A, AAAA, PTR, SRV, TXT, NS, MX, and SOA queries, including 207 NXDOMAIN and nine SERVFAIL responses. Authoritative RRsets keep stable TTLs, while external responses show shorter, varying cache TTLs.
- TLS distinguishes older/internal TLS 1.2 traffic from predominantly TLS 1.3 traffic at the DMZ. TLS 1.3 records do not expose certificate-chain file identifiers, consistent with encrypted certificates rather than automatically inventing visible certificate extraction.
- HTTP includes persistent connections with increasing `trans_depth`, CONNECT tunnels, proxy authentication failures, redirects, conditional requests, partial responses, and upstream failures. The 304 responses checked have zero response-body length.
- TCP content-gap histories agree with nonzero `missed_bytes`. Apparent low packet-byte overheads become plausible when missing sequence-space bytes are accounted for; I did not treat those as malformed packet accounting.
- Traffic is differentiated by sensor role: the database sensor is dominated by application-to-database traffic; the core sees directory and authentication activity; the DMZ sees web/proxy traffic and predominantly unanswered probing of exposed services.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed every JSON record in the three Zeek sensor directories, performed aggregate and record-level checks on connection, DNS, HTTP, SSL, X.509, files, OCSP, SMB, DHCP, and SMTP records, and sampled the supplied perimeter firewall, proxy, and normalized endpoint records for context. No scenario documentation, repository implementation, other analyst report, external website, or filesystem modification-time inference was used.

Connection starts span approximately `2026-11-02T13:00Z` through `18:59Z`. There are 12,080 core, 489 database, and 9,839 DMZ connection observations. These are sensor observations, not 22,408 deduplicated sessions. The limited six-hour view does not support an overnight or day-of-week judgment, and connections can legitimately extend past the latest visible connection start.

### Connections, state, and packet accounting

Core has 9,654 SF, 1,631 S0, 151 RSTO, 102 RSTR, and 41 REJ observations, plus other states. DMZ has 6,847 SF and 2,385 S0 observations. Its high S0 population is concentrated in probing rather than distributed indiscriminately across successful application traffic: of 286 TCP/22 observations, 264 are S0; of 85 TCP/3389 observations, 84 are S0.

The database sensor instead has 331 TCP/3306 observations, all between `10.10.3.10` and `10.10.4.10`, including 250 SF, 37 RSTR, and 31 RSTO. This is an application-specific distribution rather than a universal state mix. Frequent application resets warrant operational investigation but are not inherently evidence of fabrication.

I found no overlapping active TCP connections reusing the same directional four-tuple within an individual sensor, using a 100 ms tolerance. Positive TCP payload lengths also consistently have the corresponding directional D/d history flag. Content gaps occur in 551 core, 43 database, and 649 DMZ observations; every such observation has nonzero `missed_bytes`, and every nonzero `missed_bytes` observation has a gap flag. Directional gaps do not exceed the corresponding sequence-space payload totals when only one direction has a gap flag.

One illustrative core connection, UID `CRU4kpUSxtqCSeNgPv` at epoch `1793624405.357006`, carries 119,613,292 originator bytes from `10.10.1.31:57767` to `10.10.2.20:445`, with 32,768 missed bytes and history `ShADadfFG`. Its originator IP-byte total initially appears below payload plus minimum headers, but the documented gap accounts for that difference. Applying an aggregate missing-byte allowance removes all of the apparent minimum-header violations; this is a conservative consistency check, not a reconstruction of individual lost packets.

Long-lived remote access is present rather than every protocol being forced into short web-like durations. For example, core UID `C14DCopAuExo1lBByX` is an SSH flow from `10.10.3.10:43156` to `10.10.2.30:22`, starting at epoch `1793632497.247861` with duration `13322.033479` seconds. The DMZ independently observes the same tuple with another UID and a small sensor time offset. Its duration extending beyond the connection-start observation window is not, by itself, a defect.

### DNS behavior

The core query mix comprises 2,392 A, 284 AAAA, 216 TXT, 139 PTR, 95 SRV, 13 NS, five MX, and three SOA observations. Its response population contains 2,931 NOERROR, 207 NXDOMAIN, and nine SERVFAIL records. The DMZ has 128 NXDOMAIN and two SERVFAIL observations among 1,051 DNS records. This provides both ordinary directory-service discovery and external resolution noise.

Every DNS query fits within its linked originator UDP payload, using the DNS header, encoded question-name, type, and class as a minimum bound. A/AAAA response payloads also meet conservative minimum-size bounds for their displayed questions and answers. DNS RTT does not exceed its corresponding connection duration beyond the small numerical tolerance tested.

I specifically checked whether internal authoritative records acquire arbitrary TTLs on every lookup. They do not: among authoritative core groups having at least three observations, none varies its TTL when grouped by responding server, query, query type, and answer list. For example, all 331 responses for `DC-02.meridianhcs.local A -> 10.10.2.11` from `10.10.2.11` carry TTL 300. Different internal records legitimately have different configured TTLs.

At `2026-11-02T13:01:41.515391Z`, DMZ DNS UID `C0ayjr7AsZchdcCZ6aE` resolves `pypi.org` to two addresses with TTL 30. The subsequent visible upstream TLS connection to `151.101.0.223`, UID `CKwX338KD937UMIYSN`, starts at epoch `1793624502.070793`. This is a sensible resolution-to-connection sequence. I did not require a fresh lookup before every connection because caching and proxy-side resolution change that expectation.

### HTTP and proxy behavior

Most observed HTTP is explicit proxy control traffic: core has 2,202 CONNECT requests among 2,444 HTTP rows, and DMZ has 2,243 CONNECT requests among 2,712 rows. It would therefore be misleading to interpret the raw HTTP-row count as widespread plaintext browsing. Proxy access records explicitly describe CONNECT control bytes separately from tunnel bytes and duration.

HTTP records sharing a connection have correctly increasing transaction depths starting at one in the visible data. DMZ includes 27 connections with three HTTP transactions, five with six, and one with seven. For example, `zeek-dmz/http.json` line 13, UID `CqUhVk5xsXP7iW0Ftu8`, records transaction six at `2026-11-02T13:03:55.903281Z`: a conditional asset GET returning 304 with `response_body_len: 0` and a same-site referrer. No displayed HTTP response body exceeds its linked connection's responder-byte total.

Status distributions include 407 authentication challenges, 403 denials, 502/503/504 failures, redirects, and 206 partial responses. The first supplied proxy record and core/DMZ HTTP observations agree on a Windows client's GET to the proxy, response 301, and 216 response-body bytes, while retaining sensor-local UIDs and timestamps.

The repeated browser-version families are the main remaining weak authenticity question. I cannot infer installed browser patch policy from the network records alone and have not converted that uncertainty into a hard finding.

### TLS, certificates, and extracted files

DMZ SSL has 2,107 TLS 1.3 and 887 TLS 1.2 records, plus four records without a negotiated version; core has 212 TLS 1.3 and 200 TLS 1.2 records, plus two without a version. The database sensor is predominantly TLS 1.2, including CBC ciphers on some internal flows. This is compatible with mixed service generations; internal legacy cipher use is a security concern rather than an impossible negotiation.

TLS 1.3 records have no certificate-chain file references. For visible TLS 1.2 chains, referenced certificate files exist, adjacent issuer/subject names agree, ECDSA ciphers do not reference an RSA leaf in the checked joins, and extracted certificate bytes do not exceed linked responder payload. Repeated certificate fingerprints have consistent metadata within each sensor.

For a concrete example, DMZ SSL line 11 at `2026-11-02T13:04:31.909126Z`, UID `CLjrKS19KCz3DEihRIz`, observes `73.0.142.90:55454 -> 10.10.3.10:443` using `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, SNI `ehr-portal.meridianhcs.com`, and a two-certificate chain. The corresponding leaf X.509 row has that subject/SAN, an RSA key, and the issuing CA named by the next certificate.

### Collection limits and unscored exceptions

One core SMB mapping row, line 88 at `2026-11-02T17:35:24.869790Z`, UID `CPpgHD9SZo76AEy8y4`, has no conn row in the supplied core file. A connection can begin before the observation window or its conn record can be outside the retained slice; the mapping alone does not demonstrate impossible ordering or contradictory collection. I do not score that absence as synthetic evidence.

Likewise, complete matching for the tested protocol rows is useful consistency evidence, not proof of real origin and not a synthetic indicator. Without packets or independent provenance, even very coherent telemetry can be constructed. These limitations are why verdict confidence is 64 despite the relatively production-like synthetic-confidence score of 24.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| weak_signal | HTTP user agents | Repeated Windows/Linux Chrome 120 and Firefox 121 families alongside macOS Chrome 155; examples and core counts above | Small upward influence: potentially static client profiles, but deployment policy or client impersonation can explain it |

No demonstrated hard contradiction, scored lifecycle/observation contract gap, or parser/schema defect was established in this network review. The unmatched SMB mapping is retained as an unscored collection uncertainty.

## Realism Score by Category

- **Field format accuracy:** 9 — JSON types, tuple linkage, payload-size bounds, HTTP semantics, and certificate relationships are plausible in the checked records.
- **Temporal patterns:** 8 — Uneven traffic, varied flow durations, and coherent protocol timing are present; the short window limits broader cadence assessment.
- **Cross-source correlation:** 9 — Protocol/connection and certificate/file relationships hold; one SMB mapping remains an unscored retention-window uncertainty.
- **Behavioral realism:** 8 — Proxy controls, caching, application resets, probing, and long remote sessions have distinct plausible behavior; client-version texture is somewhat narrow.
- **Environmental consistency:** 9 — Sensor-specific directory, web/proxy, and database populations align with their visible network roles.

## Recommendations

- If this were synthetic, ensure the repeated HTTP client-version families are intentional per-host or per-application inventories. Where a less uniform fleet is intended, vary versions through stable client histories rather than randomizing a user agent independently on every request.
- If this were synthetic, retain the observed separation between CONNECT control traffic and tunneled traffic, TLS 1.3 certificate opacity, stable authoritative TTLs, and loss-aware transport accounting; these existing features materially improve realism.
