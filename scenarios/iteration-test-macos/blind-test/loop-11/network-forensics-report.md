# Network Forensics Blind Authenticity Review

## Verdict

Inconclusive, with a slight synthetic lean.

## Verdict Confidence (0-100)

70

## Synthetic-Confidence Score (0-100, lower is more production-like)

44

## Executive Summary

The network telemetry is well-formed and coherent overall. Across three Zeek sensor datasets, connection UIDs consistently join to DNS, HTTP, and SSL records with matching tuples and plausible record ordering; service/port assignments, DNS answers, host roles, and connection-state distributions are generally credible. The clearest synthetic signal is one externally named TLS certificate chain for `www.reddit.com`: the leaf is newly valid in late 2026, but its reported Let’s Encrypt R3 issuer certificate expired in September 2025. A proxy may complete a handshake without validating a chain, so this is suspicious rather than proof of impossible capture. No other dataset-wide network contradiction stood out.

## Evidence For Synthetic

- In `zeek-dmz/ssl.json`, UID `CP8zMH3ENbU3kZshDg` reports `server_name=www.reddit.com`, `established=true`, and leaf FUID `F4Sd6nkK4GHmUcRxD7z`. The linked leaf in `zeek-dmz/x509.json` is valid from 2026-10-03 to 2027-01-01 and names `www.reddit.com`, but is issued by R3. The linked CA FUID `FqoqzirF7JPM6YfaBAn` reports `not_valid_after=2025-09-15`. This is a conspicuous expired-issuer chain on a public site with a recently issued leaf. A deliberately permissive proxy or client could still record a completed handshake, so I do not treat it as conclusive by itself.
- Zeek traffic volume is substantial: `zeek-core/conn.json` contains 12,532 connections and `zeek-dmz/conn.json` 9,830 over roughly six hours. This is possible for an enterprise network, and volume alone is not a finding; it contributes only weakly because the traffic is largely concentrated in a small set of repeated service roles (notably proxy HTTP/8080, DNS, and Kerberos).

## Evidence For Real

- Within each sensor, every DNS, SSL, and HTTP record UID resolves to a connection and all checked origin/responder address and port fields match. There are no repeated connection UIDs within a sensor, and UIDs do not collide across the three sensor datasets.
- SSL records follow their linked connection start times, and all checked SSL records remain within the corresponding connection lifetime. DNS and HTTP records also follow connection starts. Connection rows have nonnegative durations and valid packet presence for `SF` sessions.
- Protocol and service fields agree with common destination ports across the records checked: DNS/53, Kerberos/88, LDAP/389, SMB/445, SSH/22, HTTP/80 or 8080, TLS/443, MySQL/3306, syslog/514, and RDP/3389. Locality flags match the private/public address ranges.
- Flow states include successful sessions, unanswered SYNs, resets, rejects, and partial TCP states. Both internal and external interactions are represented. There is no strong fixed-interval beacon pattern in repeated high-volume tuples.
- DNS includes plausible enterprise discovery and public service lookups, with NOERROR, NXDOMAIN, SERVFAIL, and REFUSED outcomes. Among TLS sessions with a matching same-source DNS answer for the same SNI within five minutes, most had the lookup before the TLS session; the remaining cases are compatible with cache reuse or later refresh and do not establish an ordering defect.
- TLS versions and cipher suites are plausible TLS 1.2/1.3 combinations. All SSL certificate FUID references resolve. SNI names matched the associated leaf certificate subject/SANs in the checked set. Certificates were valid at observation time except for the single expired intermediate noted above.
- Host roles are coherent in the logs: internal clients issue HTTP CONNECT traffic to `10.10.3.20:8080`, which also originates many outbound TLS sessions; the external web endpoint `10.10.3.10` receives inbound web/TLS traffic; and the application-to-database traffic targets `10.10.4.10:3306`.

## Detailed Analysis

### Scope and volume

Reviewed only the generated data under `/private/tmp/eforge-blind-loop-11/data`, focusing on `zeek-core`, `zeek-db`, and `zeek-dmz` connection, DNS, HTTP, SSL, and X.509 JSON records. The files cover approximately 2026-11-02 13:00–19:00 UTC. Record counts were:

| Sensor | conn | dns | http | ssl | x509 |
|---|---:|---:|---:|---:|---:|
| zeek-core | 12,532 | 3,158 | 2,400 | 353 | 211 |
| zeek-db | 449 | 47 | 21 | 9 | 16 |
| zeek-dmz | 9,830 | 984 | 2,610 | 2,921 | 1,168 |

### UID, tuple, and timing integrity

All DNS, SSL, and HTTP UIDs in each sensor joined to a same-sensor `conn.json` row. Checked origin/responder IPs and ports matched exactly. No same-sensor connection UID duplicates were found; the same UID was not reused across sensor directories. HTTP may have multiple request rows for one flow, which accounts for repeated HTTP UIDs and is consistent with multiple transactions on a persistent connection.

For SSL, record timestamps were later than the connection start (offsets were roughly 0.003–0.650 seconds in core and DMZ) and no SSL row landed more than one second after the flow end. `SF` connections had durations and packet counts. I found no negative durations or missing tuples in these records.

### DNS and protocol behavior

Internal DNS volumes and names are consistent with a domain environment: DC host lookups, LDAP SRV discovery, PTR lookups, and enterprise service names are present. Public DNS in the DMZ includes software repositories, Microsoft 365, OCSP, and healthcare service domains. Query outcomes include normal success as well as failures. DNS answers often precede matching SNI flows; unmatched or later DNS records can result from caching, refreshes, or absence of a captured lookup, so I found no confirmed DNS-after-dependent contradiction.

`zeek-core` and `zeek-dmz` show substantial HTTP CONNECT volume to the same internal proxy endpoint, `10.10.3.20:8080`. DMZ TLS sessions from that proxy to public services fit the forward-proxy role visible in the HTTP records. Inbound connections to `10.10.3.10` and MySQL flows between `10.10.3.10` and `10.10.4.10` also fit plausible web/application and database roles. I saw no high-volume tuple with near-uniform intervals that would strongly resemble a simplistic beacon generator.

### TLS and certificates

TLS 1.2 and TLS 1.3 records use plausible cipher suites. Certificate references resolve, names align with SNI, and the internal enterprise-issued certificates have plausible host names and validity windows. One DMZ chain is anomalous: the leaf for `www.reddit.com` is reported valid in October 2026 through January 2027, while its listed R3 issuer expired in September 2025. The corresponding connection from the proxy to `151.101.65.140:443` is `SF`, and Zeek marks TLS `established=true`. Because Zeek's handshake observation does not prove that the proxy validated the chain, this could represent permissive validation or an untrusted chain that an application accepted. Still, it is a strong mismatch for ordinary public production browsing and is the main score driver.

## Synthetic Indicator Summary with Categories

| Category | Indicator | Scope / weight |
|---|---|---|
| `schema_or_format` | A recently valid `www.reddit.com` leaf is presented with an R3 issuer certificate expired more than a year before observation. | One TLS chain; strong, but not conclusive because handshake completion does not establish endpoint trust validation. |
| `distribution_texture` | High flow volume is concentrated in a few recurring service roles, especially proxy traffic. | Dataset-level but weak; volume and role concentration are plausible for enterprise telemetry and are not defects by themselves. |
| `hard_contradiction` | None confirmed. | No impossible visible ordering or broken UID/tuple relationship found. |
| `contract_gap` | None confirmed. | No confirmed required DNS/connection companion or source lifecycle failure found. |
| `environment_or_collection_plausibility` | None confirmed. | Sensor role and private/public address semantics are broadly coherent. |
| `weak_signal` | One expired external intermediate chain is atypical for a current public endpoint. | Captured under TLS validity above; not an independent additional issue. |

## Realism Score by Category

Scores are network realism scores from 0 (poor) to 100 (strong); these are separate from the overall synthetic-confidence score.

| Category | Realism score | Notes |
|---|---:|---|
| UID and tuple integrity | 98 | Complete same-sensor UID joins and exact tuple agreement. |
| Flow state and timing | 93 | Varied states and durations; no major timing or packet-state contradiction found. |
| DNS semantics and ordering | 88 | Credible enterprise/public query mix; observed unmatched/refresh cases are not sufficient to establish inversion. |
| TLS protocol behavior | 88 | Plausible versions/ciphers and handshake timing. |
| X.509 validity and naming | 72 | SNI and leaf names align, but one clearly expired intermediate chain is a strong anomaly. |
| Protocol and host-role patterns | 92 | Proxy, web, application, database, directory, and logging roles are broadly consistent. |

## Recommendations

- **P1 — Validate certificate-chain time semantics:** For the public `www.reddit.com` SSL record above, use a chain whose issuer is valid at the connection timestamp, or represent the chain/handshake outcome so an expired issuer does not appear as an ordinary established public TLS session. Validate issuer `not_valid_before`/`not_valid_after` at the observation time across generated certificates.
- **P3 — Keep monitoring traffic distribution:** The volume and proxy concentration are plausible, so I do not recommend reducing them based on this review alone. If other reviewers identify repetitive content or interval patterns in these same network families, compare those findings against per-host and per-destination distributions before changing generation behavior.
