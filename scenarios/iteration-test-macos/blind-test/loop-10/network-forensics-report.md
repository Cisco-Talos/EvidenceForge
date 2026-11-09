# Network Forensics Blind Authenticity Review

## Verdict

Likely synthetic, with a technically coherent network layer. The observed traffic could plausibly represent a busy healthcare environment with a web proxy, internal application tiers, and internet-facing services, but the regularity and tightly curated concentration of traffic leave a moderate synthetic signal.

## Verdict Confidence (0-100)

72

## Synthetic-Confidence Score (0-100, lower is more production-like)

68

## Executive Summary

Reviewed only the Zeek network logs in the supplied `data` bundle. The three Zeek sensors contain 22,811 connection rows, 4,189 DNS rows, 5,031 HTTP rows, 3,283 TLS rows, and 1,395 X.509 rows. The time window is approximately six hours on 2026-11-02.

The network model is internally coherent. Within each sensor, connection UIDs are unique; every DNS, HTTP, and TLS record maps to a connection with a matching four-tuple; every TLS certificate-chain reference resolves to an X.509 record; and DNS and TLS timestamps fall within their associated connection intervals. Internal DNS/Kerberos/LDAP, database, proxy, and public-facing web roles are recognizable and mostly plausible. I found one TLS handshake referencing an expired certificate-chain record, which merits investigation but is not by itself proof that the client accepted an invalid chain.

The synthetic signal is moderate rather than decisive. High traffic concentration around a small number of modeled services, the short shared capture window, and a few dense scanning/probing patterns may reflect authored exercise traffic. These patterns also have plausible operational explanations, so the network logs alone do not establish origin.

## Evidence For Synthetic

- Traffic is concentrated into cleanly identifiable services and roles: the core sensor has 3,165 DNS, 2,664 Kerberos, and 2,345 HTTP service-classified connections; the DMZ has 650 TLS sessions to `10.10.3.10` with SNI `ehr-portal.meridianhcs.com`. This may reflect deliberate scenario emphasis, though it could also be normal service demand.
- The core HTTP stream has 2,197 `CONNECT` records out of 2,400, strongly emphasizing proxy-mediated browsing. That is plausible for an explicit proxy, but is a conspicuous distribution to verify against the environment.
- The DMZ reports 2,805 `S0` connections (28.5% of its connection rows). Many are from a small set of external scanner-like addresses and from `10.10.3.10`; this is plausible probe/health-check traffic, but the concentration is unusually visible.
- One TLS session to `www.reddit.com` references an X.509 chain certificate with subject `CN=R3` whose recorded validity ended in 2025, while the handshake was logged in November 2026. A passive TLS sensor can observe a presented expired intermediate even when a client constructs an alternate chain, so treat this as an anomaly to explain rather than an impossible event.
- Across the sensors, connection activity is bounded to a roughly six-hour interval. This is consistent with a collection window, but the narrow time slice and abundant fully formed application records give the dataset a deliberately scoped feel.

## Evidence For Real

- The internal service relationships make sense: endpoints query the two domain controllers for DNS/Kerberos/LDAP; web and application systems use the proxy on TCP/8080; and `APP-INT-01` accounts for a coherent volume of MySQL traffic to the database tier.
- HTTP and TLS include a plausible mixture of Microsoft 365, Salesforce, Ubuntu package services, PyPI/npm, software updates, certificate-status services, and healthcare-related domains. Both routine success responses and a smaller number of redirects, denials, and gateway errors appear.
- Connection states and durations vary. The core sensor is 82.1% `SF` and 14.9% `S0`; the DMZ is 69.3% `SF` and 28.5% `S0`. Successful application sessions coexist with unanswered UDP/syslog traffic, failed probes, resets, and short or long-lived SSH sessions.
- TLS uses both TLS 1.2 and 1.3 with plausible cipher suites. Internal host certificates carry matching DNS SANs; where a certificate has SAN entries, I found no SNI-to-SAN mismatch. Certificate-chain records are present and referenceable.
- Network evidence is not perfectly clean: there are NXDOMAIN, SERVFAIL, REFUSED, HTTP 403/407, server errors, unanswered connections, and a stale certificate-chain artifact. These are ordinary sources of noise in operational traffic.

## Detailed Analysis

### Scope and method

This review used only log-visible Zeek data under `zeek-core`, `zeek-db`, and `zeek-dmz`: `conn`, `dns`, `http`, `ssl`, and `x509`, plus their timestamps, UIDs, tuples, service labels, and certificate references. It did not inspect scenario or ground-truth material, source code, prior reports, or files outside the supplied data directory. File modification times were not used to infer origin.

### Connection and tuple integrity

- The three sensors contain 12,532, 449, and 9,830 connection rows respectively. No duplicate connection UID or differing four-tuple for a connection UID was found within an individual sensor.
- All 4,189 DNS, 5,031 HTTP, and 3,283 TLS rows have a corresponding connection UID in their sensor. Their source/destination addresses and ports match the connection record.
- Zeek application rows omit `proto` in some records; this creates an apparent protocol-field difference if comparing every field, but not a tuple inconsistency.
- Each sensor's events span about 13:00–19:00 UTC. There are connections with long durations, particularly SSH, some of which extend past the last connection start in the capture. That is consistent with sessions crossing a bounded capture window.

### DNS and order

- DNS volume is concentrated on A and AAAA lookups, with PTR and SRV activity and a smaller tail of TXT/NS queries. The two domain-controller names are the most frequent internal names; certificate-status and external application domains are also present.
- Responses include NOERROR as well as NXDOMAIN, SERVFAIL, and a small number of REFUSED results. All DNS UIDs map to a matching connection tuple, and DNS timestamps do not precede their connection start or extend beyond connection end.
- No clearly impossible DNS-to-connection ordering was identified. The observed ordering is compatible with normal name resolution preceding application activity, while the available records alone do not prove every network connection had a visible query in this capture.

### HTTP and host roles

- The core HTTP set is dominated by successful `CONNECT` proxy requests to `10.10.3.20:8080`. A smaller set of GET/POST traffic and redirects, authorization failures, and gateway errors adds some operational variation.
- The DMZ HTTP set includes the same proxy pattern as well as requests associated with the public web tier and common external services. The database sensor has a small HTTP sample, mostly successful proxy requests.
- The HTTP UIDs and four-tuples match their connection records. The high CONNECT share is the clearest distribution worth comparing with a real proxy baseline; by itself it is not contradictory.

### TLS and X.509

- TLS rows are overwhelmingly established and use TLS 1.2 or 1.3. The DMZ has 1,953 TLS 1.3 and 966 TLS 1.2 rows; the core has 191 and 161 respectively. Cipher choices are broadly plausible for these versions.
- All TLS UIDs map to a connection with the same tuple. All 1,395 certificate-chain file references resolve to X.509 records. Certificate-record timestamps are near the associated TLS observations, and all but one referenced validity interval contains the handshake timestamp.
- Internal SNI values generally align with the destination host and, when SANs are present, with the certificate's SAN. Many `cert_chain_fuids` point to CA/intermediate records whose SAN list is empty; those are not treated as leaf-hostname mismatches.
- The single expired `CN=R3` record is associated with the `www.reddit.com` handshake. Passive Zeek metadata does not establish whether the client rejected the chain, accepted an alternate path, or proceeded under another policy.

### State, timing, and traffic distribution

- The core and DMZ have substantial `SF` traffic alongside `S0`, resets, rejects, and partial states. The DMZ's `S0` share is higher and includes both external scanner-like sources and repeated traffic involving `10.10.3.10`; this pattern could be perimeter probing or monitoring, but it deserves context from an operator familiar with the sensor placement.
- The database sensor is strongly centered on MySQL at TCP/3306, mostly between the application tier and `10.10.4.10`, which fits the visible role pattern.
- Connection durations vary by service: DNS and Kerberos are generally brief; HTTP, TLS, LDAP, and MySQL range from short requests to longer sessions; SSH includes multi-hour sessions. No single fixed interval or duration dominates all services.
- There is a clear modeled-service emphasis, particularly the EHR endpoint and explicit proxy. That focus is compatible with a training dataset, but service concentration is not a concrete contradiction.

## Synthetic Indicator Summary

| Category | Indicator | Strength |
|---|---|---|
| Traffic distribution | High CONNECT share in core HTTP; concentrated TLS use of the EHR endpoint | Moderate |
| Perimeter behavior | Elevated DMZ S0 rate with concentrated probe/health-check sources | Moderate |
| Capture shape | Similar six-hour sensor windows | Weak to moderate |
| TLS certificate hygiene | One expired R3 chain certificate observed in an established handshake | Weak; plausible in production |
| UID and tuple integrity | No mismatch found | Evidence against synthetic artifacts |
| DNS and TLS timing | Matching connection records and plausible ordering | Evidence against synthetic artifacts |
| Protocol/host roles | Coherent internal and external service relationships | Evidence against synthetic artifacts |

## Realism Score by Category

Scores estimate production-likeness from 0 to 100; higher is more realistic.

| Category | Score | Notes |
|---|---:|---|
| Connection tuples and UID integrity | 96 | UIDs and four-tuples are consistent across Zeek connection and application records. |
| DNS behavior and ordering | 88 | Plausible record mix and response codes; visible timestamps fit associated flows. |
| HTTP behavior | 76 | Realistic methods and errors, with a strong proxy CONNECT concentration. |
| TLS and X.509 | 82 | Plausible versions/ciphers and resolved chains; one expired chain record warrants explanation. |
| Network roles and topology | 87 | Domain controllers, proxy, web/app, and database interactions cohere. |
| State and timing distributions | 78 | Varied states and durations, though DMZ S0 and target concentration are prominent. |
| Overall network realism | 82 | Convincing technical coherence with a few concentrated, scenario-like distributions. |

## Recommendations

- Compare the 91.5% core HTTP CONNECT share with the actual proxy's expected Zeek visibility and workload mix.
- Confirm whether the 650 DMZ TLS sessions to `ehr-portal.meridianhcs.com` and the high `10.10.3.10`-originated S0 traffic match expected health checks, application polling, or perimeter behavior.
- Check the Reddit TLS chain observation against certificate-chain policy. Preserve the distinction between a passively observed expired certificate and proof of successful client validation.
- For stronger provenance assessment, compare these distributions with a known production capture from the same network segment and similar time period; the supplied Zeek evidence alone supports a moderate, not definitive, synthetic verdict.
