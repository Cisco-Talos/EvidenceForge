# Network Forensics Analyst — Authenticity Assessment
## Verdict
**Assessment:** Real
**Verdict Confidence:** 73
**Synthetic-Confidence Score:** 29
## Executive Summary
The network evidence is more consistent with sanitized production telemetry than with a visibly generated dataset. Across a six-hour UTC interval, the three Zeek sensors contain 19,769 connection records with coherent TCP/UDP state semantics, nonuniform durations and volumes, realistic sensor-local UIDs, plausible inter-sensor clock skew, and strong protocol-to-connection linkage. DNS, explicit-proxy, TLS, certificate, OCSP, HTTP, SMTP, SMB, firewall, and IDS records generally agree without impossible visible ordering.

The strongest concerns are limited in scope: two HTTP response FUIDs have no corresponding `files.json` row; six file rows report more missing file bytes than their parent connection reports as `missed_bytes`; and a 623 MB SMB upload to a mapped disk share has no file-operation companion. The first two could result from selective file logging, protocol-derived expected lengths, or per-analyzer truncation. The SMB case could reflect SMB3 share encryption after tree connect. None is a decisive hard contradiction. I found no high-volume generator fingerprint strong enough to outweigh the production-like packet accounting, clock behavior, failure-state texture, DNS ecology, and certificate contracts.

## Evidence For Synthetic
- `[contract_gap]` Two HTTP records contain dangling response-file references. In `zeek-core/http.json` at 2024-03-18 17:04:32.589594 UTC, UID `CFPm6i9Z1iswAJLotO` references `F9DdYzS2DwzPQ1zVHHO`, which is absent from `zeek-core/files.json`. In `zeek-dmz/http.json` at 14:12:43.711020 UTC, UID `CRlzLhE0242JD8NR6eR` references absent FUID `FGI5kCqMApTN53P8c`. This is 2 dangling references among 711 HTTP response-FUID references across the three sensors.

- `[contract_gap]` Six HTTP file rows have `missing_bytes` greater than connection-level `missed_bytes`. Examples include `zeek-core/files.json` FUID `FxDX2XzYe0XccRgnC6h` at 17:24:37.103971 UTC (`missing_bytes=104`) while parent connection `CJ1QIANsPOj3pHEDTQy` has `missed_bytes=0` and no `G/g` gap marker; and `zeek-dmz/files.json` FUID `FgOHm2RWh6ku5I6LFM` at 12:51:39.139378 UTC (`missing_bytes=4487`) while connection `ClAgucIGlzObgeksdhH` reports only one missed byte. Four additional DMZ examples are `FyI6CPwx18xgJe2LiAa` (7 versus 0), `FFMO2cF2DQ4dEgkREw` (269 versus 0), `FUZGMBxDcdizbi8v7` (2,124 versus 0), and `FDp21wTx9DvQLfOzT` (1,360 versus 0). A short HTTP entity relative to a declared content length can produce this pattern, so it is not necessarily packet-loss accounting failure, but the repeated mismatch deserves scrutiny.

- `[contract_gap]` `zeek-core/conn.json` records UID `CKMuqjtC97EMkXt71T` at 14:28:24.092627 UTC as a successful 10.374893-second SMB upload from `10.10.1.22:45935` to `10.10.2.20:445`, with `orig_bytes=623292039`. `zeek-core/smb_mapping.json` maps that same UID to `\\FILE-SRV-01\ClinicalExports`, a ReFS disk share, but the UID has no `smb_files.json` action or `files.json` object. Of 118 mapped SMB connections, 16 have no SMB file-action row and 29 have no generic file row. Share-level SMB encryption or selective file-analysis policy is a viable production explanation, but the exceptionally large transfer makes this the most important companion-evidence gap.

- `[weak_signal]` Inbound DMZ traffic is highly concentrated in several source identities. `185.70.41.45` produces 450 TCP/443 connections over 3,005 seconds, including 399 `SF`, 25 `RSTO`, 14 `RSTR`, and 12 `S0` sessions; 398 have parsed TLS. This could be a credential attack, load-testing source, NATed client population, or service integration, so concentration alone receives little synthetic weight.

- `[environment_or_collection_plausibility]` Of 1,321 proxy-origin connections with a visible prior matching DNS answer, 405 use the address after the last visible DNS TTL expired. For example, `config.zscaler.net` at `147.161.129.40` is reused at 16:37:51.523078 UTC, 15,124.520 seconds after a 30-second answer in `zeek-dmz/dns.json`. All such origin traffic is sourced by proxy `10.10.3.20`; application/proxy DNS caching can deliberately outlive authoritative TTLs, so this is not a contradiction but should be verified against proxy resolver policy.

## Evidence For Real
- `[schema_or_format]` All 19,769 Zeek connection records have internally viable packet and IP-byte accounting: no direction has `ip_bytes` below payload plus minimum IP-header bytes. None of the 4,729 `S0` records contains responder packets or bytes, and every `SF` record contains responder packets. No present duration is zero. State/history combinations include realistic `S0`, `REJ`, `RSTO`, `RSTR`, `S1`, `S2`, `S3`, `OTH`, and gap/ACK variants rather than a single success template.

- `[environment_or_collection_plausibility]` Connection volume and placement are coherent: `zeek-core/conn.json` has 11,102 rows, `zeek-dmz/conn.json` 8,226, and `zeek-db/conn.json` 441 from approximately 12:00-18:00 UTC. Core traffic is dominated by DNS, Kerberos, LDAP, HTTP proxy, SMB, and internal TLS. The DB sensor sees 273 MySQL sessions from `10.10.3.10` to `10.10.4.10`; the DMZ sensor sees 274, a plausible one-record visibility difference rather than forced equality.

- `[schema_or_format]` Zeek UIDs behave like sensor-local identifiers. Each `conn.json` has zero duplicate UIDs, and there is zero UID overlap among the core, DB, and DMZ sensors. Every DNS, HTTP, SSL, SMTP, SMB mapping, and SMB file-action UID exists in its own sensor's `conn.json`. Independent sensors observe the same tuples under different UIDs, as expected.

- `[temporal_patterns]` Cross-sensor timing resembles clock offset plus drift, not copied timestamps. There are 4,103 core↔DMZ, 137 core↔DB, and 304 DB↔DMZ same-five-tuple matches within two seconds. Core↔DMZ offsets center near -0.114255 seconds with about 1.7 ms residual standard deviation; core↔DB shows roughly 18.3 ms of relative drift over six hours with about 1.2 ms residual deviation. At 12:00:43 UTC, `10.10.1.22:48798 → 10.10.3.10:80` appears as core UID `CLA3qE1S4ol5Wmx5X` and DMZ UID `C5eBKR2PJoSC4TB8H`, 0.115472 seconds apart, with the same 600/194 payload-byte counts and `SF` state.

- `[distribution_texture]` Durations and volumes are service-shaped. Core DNS has a 0.002916-second median, HTTP 2.234326 seconds, SMB 3.763923 seconds, SSH 1,971.055637 seconds, and RDP 972.431142 seconds. Core SSH includes both subsecond failures and long interactive sessions; the longest, UID `CcrhpByqvbzFpAEvJzH`, runs 13,320.302448 seconds with 38,251/159,119 payload bytes and a normal FIN close. These are not uniform schedules or fixed-size templates.

- `[environment_or_collection_plausibility]` The DMZ perimeter has realistic mixed exposure: 1,710 inbound connections from 277 external source addresses, all targeting `10.10.3.10`; 859 are `S0`, 763 `SF`, and the remainder include resets and partial sessions. Ports include 443, 80, 445, 3389, 8080, 1433, 8443, 3306, 5432, 135, 22, 139, 23, 6379, 5985, and 9200. `fw-perimeter/cisco_asa.log` pairs allowed connections with sequential connection IDs, NAT translations, FIN/reset teardowns, and 30-second SYN timeouts. `snort-perimeter/snort_alert.log` independently records ICMP, scan, policy, and outbound-client signatures at corresponding tuples.

- `[distribution_texture]` DNS has broad, plausible ecology rather than only attack-supporting names. The three sensors contain 3,800 DNS rows: 2,855 A, 336 AAAA, 212 PTR, 112 SRV, 278 TXT, plus NS, SOA, and MX. Results include 3,432 `NOERROR`, 349 `NXDOMAIN`, 10 `SERVFAIL`, and 9 `REFUSED`. Internal authoritative replies and external recursive replies have distinct `AA` behavior; answer and TTL vector lengths always match. Identical authoritative RRsets retain stable TTLs on both internal resolvers. DHCP renewal timing also follows lease semantics: 48 REQUEST/ACK rows use 3,600-, 7,200-, and 14,400-second leases with approximately half-life renewal intervals and per-client jitter.

- `[schema_or_format]` TLS and certificate evidence is unusually strong. The sensors contain 2,571 SSL rows: 1,628 TLS 1.3 and 943 TLS 1.2, with 873 resumed sessions. Every version/cipher pairing is valid. All 1,139 X.509 rows are referenced by file objects; all certificate-chain FUIDs resolve; leaf issuer names match the next certificate subject; issuing certificates are CA-marked; certificate validity contains the observation time; and every leaf SAN matches its SNI. TLS 1.3 and resumed sessions appropriately omit visible certificate chains, while 591 full TLS 1.2 sessions carry them.

- `[temporal_patterns]` Protocol ordering is coherent within each Zeek sensor. No DNS, SSL, HTTP, SMTP, SMB mapping, SMB file action, or generic file row precedes its parent connection or occurs after its visible connection interval. SSL rows begin 0.006916-0.648465 seconds after their parent connection on the DMZ sensor; HTTP begins 0.001-4.534073 seconds after connection start. No certificate file precedes the SSL event, and no observed certificate is outside its validity window.

- `[environment_or_collection_plausibility]` Explicit proxy behavior is internally consistent. `PROXY-01.meridianhcs.local/proxy_access.log` has 2,450 requests: 1,483 CONNECT, 923 GET, and 44 POST, with 2,193 status 200 responses plus realistic 304/403/407/502/503/504 outcomes. All 661 logged tunnel IDs remain bound to one client, one client source port, and one host. At 17:47:09 UTC, the 159,798,848-byte GlobalProtect MSI appears on the client-to-proxy leg, proxy-to-origin leg, core sensor, and DMZ sensor with distinct UIDs/FUIDs but identical SHA-1 `846e0ce3f1aee21712e80f9d69168396e10eb978`.

## Detailed Analysis
### TCP states, durations, and volume
The state mix is credible at each observation point. Core has 8,775 `SF`, 2,001 `S0`, 136 `RSTO`, 94 `RSTR`, 32 `REJ`, and smaller partial/other classes. DMZ has 5,251 `SF`, 2,714 `S0`, 121 `RSTO`, 74 `RSTR`, and 66 partial/other records. DB has 349 `SF` among 441 rows. Missing duration is confined to `S0` and `REJ`, while successful and reset connections carry nonzero elapsed time.

Packet accounting reflects ACK traffic during large transfers. For the 159.8 MB GlobalProtect download, DMZ client leg UID `CB8olFDtPe5C8IVkjpj` has only 302 request payload bytes but 54,726 origin packets and 2,848,846 origin IP bytes, consistent with ACKs; the responder has 159,799,077 payload bytes in 109,566 packets. The separate origin leg `CfwZNOtrZUeVg8Vb1u` carries the same object size and hash. This kind of asymmetric packet/payload relationship is difficult to dismiss as a simplistic flow template.

### DNS order and ecology
Every DNS UID resolves to a sensor-local connection. On DMZ all 909 DNS rows have `ts` equal to connection start and `rtt` equal to connection duration, appropriate for one-transaction UDP flows; core has 2,824 exact pairs, with the remainder including TCP or atypical transactions. Of 2,571 TLS rows, 1,362 have a visible same-client, same-SNI, same-answer DNS lookup in the prior hour. The rest are dominated by inbound portal TLS, resumed sessions, pre-window/application caches, and proxy-origin caching. I found no case where a required visible matching query occurs only after its connection.

The DNS data includes normal AD discovery (`_ldap._tcp` and `_kerberos._tcp` SRV records), internal A/PTR traffic, public A/AAAA answers, NXDOMAIN noise, OCSP lookups, DKIM/DMARC/SPF TXT records, and a concentrated 239-TXT-query sequence from `10.10.2.30` between 16:44:55 and 17:45:18 UTC. That sequence is suspicious operationally, but its irregular intervals, resolver alternation, mixed NXDOMAIN/NOERROR outcomes, and varied query labels are not themselves authenticity defects.

### TLS, certificates, and protocol companions
TLS is source-native and temporally consistent. Full TLS 1.2 handshakes carry certificate chains; TLS 1.3 and resumed sessions omit them. External and internal issuers are reused by fingerprint rather than recreated inconsistently. On inbound portal UID `CueNO9QFsN9CnameU` at 12:09:51.889840 UTC, the server certificate and intermediate are transmitted from `10.10.3.10` to `73.0.58.199`, have depth 0/1 file objects, consistent SHA-1 fingerprints, matching issuer/subject linkage, and a leaf SAN for `ehr-portal.meridianhcs.com`.

SMTP STARTTLS is also modeled as Zeek would observe it: all 31 SMTP rows marked `tls=true` have an SSL row on the same UID, while post-STARTTLS mail envelope fields are absent because the continuation is encrypted. The 15 cleartext SMTP sessions carry envelope, recipient, subject, message ID, and file references; all listed SMTP FUIDs resolve.

### Lateral movement and topology
Internal service placement is coherent. Core records 2,419 Kerberos, 1,048 LDAP, 405 SMB, 47 SSH, and 23 RDP sessions. RDP sessions are successful and generally long-lived; SSH includes short resets and long sessions. DB traffic is narrowly centered on 273 MySQL sessions from web host `10.10.3.10` to DB host `10.10.4.10`, while administrative SSH, LDAP, Kerberos, SMB, internal HTTPS, and OCSP traffic cross the DB sensor in much lower counts. This asymmetry is consistent with sensor placement and host roles.

The main lateral-visibility caveat is SMB file coverage. Only 118 of 405 core SMB connections have mapping rows, 102 have file-action rows, and 89 have generic file objects. Modern encrypted SMB and selective analyzer policy can explain much of this, but the 623 MB `ClinicalExports` transfer warrants explicit confirmation.

### External destinations, proxy, firewall, and IDS
Outbound DMZ traffic is almost entirely proxy-originated: 1,717 of 1,720 external connections originate from `10.10.3.20`; ports are predominantly 443 (1,597) and 80 (118), with three STUN/3478 and isolated 8443/6881. Destinations and SNI span Microsoft, Google, package repositories, OCSP endpoints, collaboration services, analytics, health-sector services, and update infrastructure. Failure states include resets, rejections, partial sessions, and eight `S0`, preventing an unrealistically perfect-success profile.

Inbound behavior separates legitimate/application TLS from broad scans. The top scan identities repeatedly probe service families, while 161 source addresses establish parsed TLS to the portal. Firewall and IDS records align at second-level granularity without copying Zeek UIDs. This is a plausible layered collection profile rather than a single omniscient source.

## Synthetic Indicator Summary
- `hard_contradiction`: 0 confirmed. No impossible visible ordering, impossible TCP state/packet combination, invalid TLS/certificate relationship, or reused sensor UID was found.
- `contract_gap`: 3 families — two dangling HTTP FUIDs; six file/connection missing-byte mismatches; and incomplete SMB file companions, including one 623 MB mapped transfer.
- `distribution_texture`: 1 weak concern — 450 inbound TCP/443 attempts from one source in about 50 minutes. The broader distributions remain nonuniform and service-shaped.
- `schema_or_format`: 0 decisive defects. JSON types, Zeek identifiers, state/history fields, packet accounting, X.509 structures, and proxy/firewall formats are credible.
- `environment_or_collection_plausibility`: 1 verification item — proxy-origin address reuse beyond visible DNS TTLs; application-level caching is a plausible explanation.
- `weak_signal`: 1 — concentrated inbound source behavior, operationally suspicious but not inherently synthetic.

## Realism Score by Category
- **Field format accuracy:** 9 — Zeek, TLS/X.509, proxy, ASA, and IDS fields are source-plausible; only two dangling FUIDs and limited file-gap ambiguity reduce the score.
- **Temporal patterns:** 9 — connection/protocol ordering is valid, service durations are heterogeneous, and cross-sensor offsets show plausible skew and drift.
- **Cross-source correlation:** 9 — tuples, byte counts, hashes, proxy legs, firewall records, and sensor-local UIDs correlate strongly without inappropriate UID reuse; small visibility gaps remain.
- **Behavioral realism:** 8 — internal service use, external scanning, proxy traffic, retries/failures, DHCP renewal, and long-lived SSH/RDP sessions are convincing; the large SMB transfer lacks file detail.
- **Environmental consistency:** 9 — subnet roles, resolver behavior, DMZ/perimeter exposure, proxy egress, and DB sensor placement are coherent; resolver-cache policy should be confirmed.

## Recommendations
1. Reconcile `files.missing_bytes` with parent `conn.missed_bytes`, TCP history gap markers, HTTP declared length, and analyzer truncation reason for the six cited FUIDs. If the missing bytes reflect declared-but-unsent content rather than capture gaps, record that provenance explicitly.
2. Recover or explain the two missing `files.json` rows referenced by HTTP. A documented file-log sampling/drop policy would make these ordinary collection gaps; absent such a policy, they are referential-integrity defects.
3. Verify whether `\\FILE-SRV-01\ClinicalExports` requires SMB3 encryption. If it does, the mapped-but-unparsed 623 MB session is plausible; if not, investigate why `smb_files.json` and `files.json` lack the UID.
4. Confirm the proxy's positive DNS-cache TTL policy. The observed multi-hour address reuse is defensible for application-level caching but should match configured resolver behavior.
5. Preserve the current sensor-local UID behavior, clock-skew texture, packet accounting, TLS chain semantics, and explicit proxy leg separation; these are the strongest authenticity features in the dataset.
