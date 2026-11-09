# Blind Authenticity Review — Network Forensics

## Verdict

**Likely synthetic or heavily curated.** The Zeek evidence is internally coherent and includes several production-like imperfections, but its unusually bounded, synchronized capture profile and repeated cross-sensor application mix suggest a controlled dataset rather than an organically collected production slice.

## Verdict Confidence (0–100)

**76/100**

## Synthetic-Confidence Score (0–100; lower is more production-like)

**74/100**

## Executive Summary

Reviewed only the Zeek network logs under `/private/tmp/eforge-blind-loop-9/data/zeek-core`, `zeek-db`, and `zeek-dmz`. The three sensors contain 22,811 connection records spanning approximately 13:00–19:00 UTC on 2026-11-02. Flow states, roles, ports, DNS outcomes, application events, and TLS details are broadly plausible. UID and tuple links are exceptionally clean, and DNS records consistently precede later connections.

The principal synthetic indicators are the near-identical six-hour observation envelope across all three sensors and a closely repeated HTTP destination profile in the core and DMZ views. These observations are suggestive rather than conclusive: coordinated sensors and a deliberately bounded capture can produce them. Evidence against a simplistic synthetic pattern includes varied connection outcomes and durations, realistic failed handshakes and DNS errors, coherent protocol tuples, and one expired certificate-chain element.

## Evidence For Synthetic

- All three connection tables cover nearly the same deliberately bounded six-hour period: `zeek-core` 13:00:12–18:59:31 UTC, `zeek-db` 13:01:38–18:59:52 UTC, and `zeek-dmz` 13:00:35–18:59:52 UTC. The same near-six-hour envelope appears in the DNS and HTTP tables. This looks like a common configured capture window, though a real exercise capture could also be bounded this way.
- The core and DMZ HTTP logs have strikingly similar leading host counts despite different sensors and totals. For example, `sharepoint.com` appears 85 times in core and 85 times in DMZ; `ctldl.windowsupdate.com` appears 99 times in both; several other leading destinations differ by only one or two records (`protection.outlook.com`: 70/69; `na139.salesforce.com`: 67/66; `news.ycombinator.com`: 56/55). This may reflect mirrored or coordinated proxy activity, but the repeated distribution is more orderly than an independent capture would usually be.
- DNS and connection timestamps are exact matches for most same-UID records: 3,128/3,158 in core and all 47 in DB and all 984 in DMZ. Same-time DNS and flow observations are valid, but this degree of exact timestamp reuse across all DNS records is consistent with a generator constructing the paired records from one event anchor.
- The capture has very high record-level cross-reference completeness: every DNS, HTTP, and SSL UID checked resolves to a connection with an identical tuple; all checked SMB and file connection references also resolve. Strong alignment is a quality signal, not proof of synthesis, and is weighted lightly here.

## Evidence For Real

- Connection outcomes are varied and plausible. `SF` dominates, with meaningful `S0`, `RSTO`, `RSTR`, `REJ`, `S1`–`S3`, and `OTH` populations. DMZ has a substantial inbound `S0` population, consistent with unanswered or incomplete Internet probes.
- Flow duration is not uniform: core ranges from brief exchanges to a maximum of about 13,308 seconds; the database sensor includes an SSH session lasting about 3,564 seconds. Byte and packet fields vary, with no successful `SF` flow lacking bytes in the inspected tables.
- DNS includes realistic response variety: `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`, as well as A, AAAA, PTR, SRV, TXT, MX, NS, and SOA queries. A answers frequently lead to later connections to an answer address within the following hour (1,409/2,114 eligible core answers, 29/29 DB, and 680/707 DMZ), with caching, internal answers, and background traffic explaining the remainder.
- HTTP includes CONNECT proxy traffic, ordinary GET/POST requests, successful responses, redirects, authorization failures, and upstream errors. The destination-port and protocol combinations observed in HTTP and TLS records are coherent.
- TLS records include successful and incomplete handshakes, TLS 1.2 and TLS 1.3, and cipher suites appropriate to those versions. Referenced certificates exist, were generally within their validity periods, and the leaf SAN names matched the associated SNI in the checked records.
- One DMZ TLS chain includes an expired R3 intermediate certificate while visiting `www.reddit.com` (`ssl.json` UID `CP8zMH3ENbU3kZshDg`, certificate ID `FqoqzirF7JPM6YfaBAn`). This is a credible real-world chain/configuration defect and adds useful imperfection.

## Detailed Analysis

### Scope and method

Parsed only JSON records in `zeek-core`, `zeek-db`, and `zeek-dmz` beneath the supplied data directory. Compared connection UIDs and tuples with DNS, HTTP, SSL, SMB, and file records; reviewed connection states, services, ports, durations, DNS ordering and answers, TLS metadata, and X.509 references/validity/SANs. No scenario, host logs, ground truth, source code, or prior reports were consulted. File modification times were not used.

### Connections and topology

The connection counts are 12,532 core, 449 database, and 9,830 DMZ. The observed address ranges and role concentrations are plausible: the database sensor is dominated by MySQL (296 flows), while the DMZ sees large HTTPS/HTTP/proxy, DNS, inbound probe, and some database traffic. The core contains expected DNS, Kerberos, LDAP, SMB, HTTP, TLS, SSH, and syslog services. No TCP/UDP versus IP-protocol mismatches were found. The repeated five-tuples (150 core, 7 DB, 34 DMZ) are compatible with source-port reuse over the six-hour window and do not by themselves indicate duplication.

Connection states are varied rather than fixed. Core: 10,294 `SF`, 1,869 `S0`, with smaller reset/reject/partial populations. DB: 365 `SF`, 30 `RSTO`, 16 `RSTR`, and smaller groups. DMZ: 6,816 `SF`, 2,805 `S0`, plus resets, rejects, and partial states. `S0` records have no response bytes, and successful `SF` records have nonzero duration and some traffic, as expected.

### DNS and ordering

DNS UIDs resolve to connection records with matching source/destination address and port tuples. Every DNS record had a matching DNS connection within five seconds, and the closest DNS connection did not start after its DNS event. Most matching DNS and connection timestamps are identical (counts above), which is both internally valid and a mild generator-style indicator. Answer-to-later-connection matches are substantial but not complete; the remainder can reasonably result from caching, unrelated queries, or observations outside this sensor's path. Response codes and query types are not reduced to a uniform success-only profile.

### HTTP, TLS, and certificates

All HTTP records resolve to a TCP connection with an identical tuple; no HTTP record was attached to an `S0` or `REJ` connection. Methods and status codes show a plausible blend of proxy CONNECT, GET/POST, success, authentication denial, redirects, and server errors. HTTP event times occur after connection starts and within recorded flow duration.

All SSL records resolve to a connection with an identical tuple. TLS events occur after connection start and before flow end, allowing a one-second tolerance for rendered timing. The database and DMZ SNI values matched the SANs on their referenced leaf certificates; no checked leaf SAN/SNI mismatch was found. One DMZ chain contains an intermediate whose `not_valid_after` is 2025-09-15, despite observation on 2026-11-02. That is a concrete certificate-validity defect, but expired intermediates can appear in real captured chains and do not undermine the rest of the chain linkage.

### Overall assessment

The evidence is network-plausible and technically well-joined. The synthetic leaning comes mainly from the common, near-exact six-hour boundary and the near-replicated core/DMZ HTTP host frequencies, with exact DNS/flow timestamp reuse as a lesser signal. These patterns are not contradictions: a fixed exercise window and coordinated observations around a proxy can produce them. The verdict is therefore “likely synthetic or heavily curated,” at moderate confidence, rather than a claim that the logs are impossible in production.

## Synthetic Indicator Summary

| Category | Indicator | Weight |
|---|---|---|
| Capture window | Three sensors share a near-identical six-hour envelope | Moderate |
| Cross-sensor distribution | Core and DMZ top HTTP host counts are unusually close | Moderate |
| Timestamp construction | Most DNS records reuse the exact connection timestamp | Low to moderate |
| Cross-reference quality | Complete UID and tuple linkage across checked records | Low; alignment alone is not treated as proof |

## Realism Score by Category

Scores measure production-likeness, where 100 is highly production-like.

| Category | Score | Notes |
|---|---:|---|
| Connection state and duration distributions | 82 | Varied outcomes and durations, plausible unanswered probes and resets |
| Network roles, ports, and services | 80 | Role-oriented traffic and valid transport/protocol combinations |
| DNS behavior and ordering | 78 | Diverse response codes/types, coherent ordering; exact timestamp reuse is a mild concern |
| HTTP and proxy activity | 66 | Plausible methods/statuses, but cross-sensor host counts are conspicuously similar |
| TLS and X.509 | 83 | Valid UID/tuple/SNI linkage and mostly valid certificates; one expired intermediate |
| Sensor timing and collection shape | 58 | The synchronized six-hour envelope is the clearest synthetic/curation signal |
| **Overall network realism** | **74** | Coherent network evidence with a controlled capture profile |

## Recommendations

- For a more production-like capture, vary the observation start and end independently by sensor, or include sensor-specific collection gaps and late/early edges. Retain realistic overlap where sensors observe the same traffic.
- If core and DMZ observe proxy traffic, preserve the reason for shared destinations while adding modest differences in coverage, parser visibility, or logging loss so host-frequency profiles are not almost identical by construction.
- Keep DNS and connection ordering valid while allowing realistic sub-second sensor timestamp skew rather than copying the same timestamp into nearly every paired record.
- Retain genuine imperfections such as failed handshakes, resolver errors, proxy errors, and expired chains. The reviewed data already includes useful examples of these.
