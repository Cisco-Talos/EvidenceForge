# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 65
**Synthetic-Confidence Score:** 29

## Executive Summary

The supplied network evidence is mostly production-like: connections, application transactions, file observations, and certificate records form a coherent network view with meaningful protocol and observation variation. I found limited distributional concerns but no demonstrated impossible ordering, incompatible TLS certificate/cipher combination, or conflicting visible TCP lifecycle. My modest preference for Real reflects the strength of those checks, while acknowledging that sufficiently careful synthetic data could pass them.

## Evidence For Synthetic

- [weak_signal] A conspicuous connection-duration concentration occurs in `zeek-core/conn.json`: among 2,565 connections labeled `service=http`, 989 have durations in the interval 0.9–1.2 seconds. The 1.0–1.1 second bucket alone contains 579. This concentration deserves investigation, but the prevalence of explicit proxy tunnels offers a plausible timeout or client-policy explanation; it is not a hard contradiction.
- [weak_signal] Successful TCP log-forwarding connections are consistently short. In `zeek-core/conn.json`, all 88 `service=syslog`, `conn_state=SF` records with durations finish within six seconds; all 16 corresponding successful records in `zeek-db/conn.json` do likewise. For example, database-to-collector UID `CrplApR8LAF7xhHgRa` starts at 2026-11-02 13:00:05.219730 UTC and lasts 2.768975 seconds. Repeated short connections could represent batching or a particular forwarding implementation, but the lack of a persistent-connection tail in these observed successful sessions is mildly artificial-looking.

## Evidence For Real

- Every checked DNS, HTTP, and TLS UID resolves to a connection in its own sensor's `conn.json`, with an identical source/destination tuple. Their timestamps lie within the connection interval, allowing a 1 ms tolerance before the opening timestamp and 100 ms after its end.
- TCP lifecycle diversity is substantial. Core connections include 9,787 `SF`, 1,670 `S0`, 435 `OTH`, 156 `RSTO`, 104 `RSTR`, 44 `REJ`, and smaller `S1`/`S2`/`S3` populations; importantly, some `S0` records are one-way UDP, so they should not all be interpreted as failed TCP handshakes.
- DNS has real operational variety rather than just successful A lookups. Core DNS contains 297 AAAA, 158 PTR, 103 SRV, 264 TXT, and smaller MX/NS/SOA populations, with 206 NXDOMAIN, 12 SERVFAIL, and five REFUSED responses. Examples include `isatap` at 13:04:33.548055 and `isatap.meridianhcs.local` at 13:05:53.154411 UTC.
- TLS version, resumption, and certificate visibility are differentiated. DMZ TLS contains 2,288 TLS 1.3 records and 1,011 TLS 1.2 records, with 1,169 resumed sessions and five non-established handshakes. Referenced certificates have compatible public-key types, valid observation-time validity intervals, and consistent chain issuer/subject relationships.
- Network accounting and application relationships withstand multiple checks: no file's observed bytes exceed its connection-direction byte count; no tested file lifetime extends outside its connection by more than the stated tolerance; no HTTP 304 record has a positive response-body length; and no visible TCP connections overlap on an identical ordered four-tuple within a sensor.
- Client software is generally host-specific. For example, `10.10.1.33` is dominated by Windows Edge traffic, while `10.10.1.21` is dominated by Linux Chrome with Python, curl, and APT clients. These are distinct host profiles rather than one browser pool applied indiscriminately to all addresses.

## Detailed Analysis

### Scope and method

I inspected only the supplied data directory and did not use scenario descriptions, ground truth, evaluation results, or external origin hints. I parsed all JSON records in the three `zeek-*` sensor directories, and sampled the perimeter ASA, Snort, and explicit-proxy records to interpret observation paths. Counts below are sensor observations, not deduplicated network activities: traffic may legitimately be visible at multiple sensors.

The connection tables contain 12,230 core, 10,481 DMZ, and 430 database observations, totaling 23,141. The visible connection-start window is approximately 2026-11-02 13:00–19:00 UTC. The application tables contain 4,385 DNS, 5,547 HTTP, and 3,668 TLS observations; these totals include shared traffic observed at different sensors.

I checked connection UID uniqueness, application-to-connection tuple equality, timestamps against connection intervals, overlapping TCP tuples, file durations and byte bounds, HTTP response-body constraints, and TLS key/cipher/chain compatibility. None of these checks established a hard contradiction. A clean result is evidence of plausibility, not proof of real provenance, and completeness itself was not treated as suspicious.

### Connection states, traffic shape, and services

Traffic distribution follows sensor placement. Core sees substantial DNS, Kerberos (`krb`), LDAP, SMB, and proxy traffic; DMZ sees the proxy's outbound TLS traffic, inbound web activity, and application-to-database connections; database observations are dominated by TCP/3306. In the database sensor, 273 of 430 connection records target port 3306.

Service-specific lifetimes have useful differences. Core SSH connections with durations have a median around 2,003 seconds, and core RDP connections have a median around 888 seconds, rather than inheriting web-style request lifetimes. Core SMB has a materially longer tail: 114 of 444 successful SMB connections exceed 30 seconds. Database TCP/3306 durations range from 0.016883 to 29.408688 seconds.

For a concrete long-lived administrative example, core UID `C4beGkgwFA4cdblaSo` starts at 13:00:05.862529 UTC, connecting `10.10.1.31` to `10.10.3.20:22`; it lasts 3,682.836431 seconds and transfers 46,616 originator bytes and 81,780 responder bytes. DMZ observes the same tuple with a separate UID and close but nonidentical timestamps. Separate sensor clocks and observation paths readily explain this; different UIDs across independent sensors are not an integrity error.

The core hourly connection-start counts are 1,681, 3,138, 1,770, 1,758, 2,146, and 1,737 for hours 13 through 18 UTC. These are neither fixed counts nor a smooth monotonic curve. Because the slice covers only six hours, it cannot establish overnight traffic or a whole-day business-hours envelope.

The main distributional reservation is the strong approximately one-second HTTP connection mode. It could come from repeated client policy, proxy behavior, or a shared transport model. Without packet capture or proxy configuration, it remains a weak signal. Short successful TCP syslog sessions also deserve operational explanation but are entirely possible with per-batch connection behavior.

### DNS semantics and timing

Core DNS contains successful internal service lookups, negative suffix-style lookups, external records, reverse queries, and TXT activity. Query and response byte counts do not fall below conservative DNS wire-size minima for the checked A/AAAA records. DNS RTTs are compatible with connection durations; small excess connection durations are possible when more than one exchange occurs within the UDP observation.

At 13:00:03.868779 UTC, core DNS UID `CmN2OeyFuu5qT4yxIk` queries `FILE-SRV-01.meridianhcs.local`, receives `10.10.2.20`, and reports an RTT of 0.000678 seconds, matching the connection duration. The corresponding lookup is followed by a port-445 connection from `10.10.1.31` to that server, represented by SMB mapping UID `C48vC73LynYi2GtPwPK` at 13:00:05.476774 UTC.

The TTL population includes 30-second cached responses, varied remaining external TTLs, and longer internal values such as 300, 1,800, 3,600, and 86,400 seconds. Such variability is plausible for a mix of recursive cache hits, authoritative internal records, and different zones. I did not demand a new DNS query before every connection: caching and pre-window resolution are legitimate.

### HTTP, explicit proxying, and files

A raw HTTP-versus-TLS count would misrepresent this collection. Most HTTP rows are explicit `CONNECT` requests: 2,405 of 2,614 core HTTP observations and 2,450 of 2,907 DMZ HTTP observations. These are tunnel-control requests, not evidence that users predominantly browse in cleartext.

At 13:00:37.805519 UTC, core HTTP UID `CSq0sCAqB8gkLkbWLP8` is a CONNECT from `10.10.1.33` to proxy `10.10.3.20:8080` for `spoprod-a.akamaihd.net:443`, with status 200 and zero request/response entity-body lengths. The proxy access record describes tunnel-control byte accounting separately from tunneled bytes, and DMZ observes a proxy-originated TLS connection to that server. This is a coherent explicit-proxy path.

Failures are also represented in native application terms. At 13:03:29.745278 UTC, database HTTP UID `CejGkF1Vxdvx1XEH8` receives `407 Proxy Authentication Required` with a 753-byte HTML response; its file observation reports the same 753-byte body. Across HTTP records, I found no positive body on a 304 response and no referenced response file exceeding its transaction's response-body length.

### TLS and certificates

The dataset distinguishes TLS 1.3 encrypted certificate visibility from TLS 1.2 certificate observations. TLS 1.3 histories are predominantly `Cs`, whereas full TLS 1.2 histories include `CsxknGIi` and resumed TLS 1.2 histories include `CsiI`. Absence of TLS 1.3 certificates from a passive sensor is not a defect.

For example, DMZ UID `CzzsTBy2jA1ex0MQjO` at 16:47:38.193502 UTC negotiates TLS 1.2 with `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` for `news.ycombinator.com`; its referenced leaf certificate has a compatible ECDSA key. Across all referenced chains, I found no ECDSA-suite/RSA-key mismatch, no RSA-authentication-suite/non-RSA-key mismatch, no expired or not-yet-valid certificate at observation time, and no broken adjacent issuer/subject relationship.

Missing certificate references on other sessions were not scored as synthetic solely because coverage could have been more complete. Likewise, a late TCP reset after an established TLS handshake is not a contradiction: application traffic may succeed before a reset ends the transport.

### Limits of the verdict

This is a network-focused authenticity assessment, not packet-level validation or a complete endpoint review. Packet capture would be needed to verify retransmission sequence details, actual certificate DER encodings, and the cause of the one-second connection mode. The data's high internal consistency is compatible with both real production telemetry and a careful simulator; the weak concerns above do not justify a confident synthetic verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| weak_signal | Zeek HTTP connection lifetimes | Core: 989/2,565 HTTP-service connections last 0.9–1.2 seconds | Small increase for a conspicuous duration mode; plausible proxy/client explanation prevents a stronger finding. |
| weak_signal | Zeek TCP syslog connections | All 88 core and 16 database successful, duration-bearing sessions finish within six seconds | Small increase for uniformly short transport reuse; batching remains a plausible explanation. |
| hard_contradiction / contract_gap | Checked network families | None demonstrated by the checks described above | No increase; neither completeness nor absent optional sources was penalized. |

## Realism Score by Category

- **Field format accuracy:** 9 — Source fields, values, certificate references, DNS wire-size bounds, and HTTP body semantics are consistent in the tested records.
- **Temporal patterns:** 8 — Long administrative sessions, short queries, jitter, failures, and variable hourly volumes are present; the one-second proxy mode deserves explanation.
- **Cross-source correlation:** 9 — Checked tuples, intervals, files, TLS certificates, proxy paths, and independent sensor observations align without a demonstrated contradiction.
- **Behavioral realism:** 8 — Infrastructure, browser, update, proxy, administrative, and database behavior vary meaningfully; short TCP syslog sessions are a modest reservation.
- **Environmental consistency:** 9 — Segmented observation, explicit proxying, host-specific clients, and service distributions form a plausible mixed environment.

## Recommendations

- If this were synthetic, validate the approximately one-second proxy connection mode against a measured target deployment. Preserve it if it reflects a real client/proxy timeout; otherwise derive tunnel lifetimes and connection reuse from the modeled client's actual policy.
- If this were synthetic, make TCP syslog connection reuse reflect the specific forwarding implementation. The observed six-second upper envelope could be reasonable for batching, but a persistent forwarder should generate longer-lived transport sessions rather than one short connection per batch.
- Retain the current separation of proxy control-message accounting from tunnel accounting, TLS-version-dependent certificate visibility, and per-sensor identities. These passed useful consistency checks and should not be weakened merely to make the data appear messier.
