# Network Forensics Analyst — Authenticity Assessment

## Verdict (Assessment: Synthetic|Real|Inconclusive, Verdict Confidence, Synthetic-Confidence Score)

- Assessment: **Real**
- Verdict Confidence: **78/100**
- Synthetic-Confidence Score: **36/100**

The telemetry falls in the “mostly realistic” band. I found one repeated, substantive proxy
contract defect and several weaker distributional tells, but no decisive transport, DNS, TLS,
firewall, or IDS impossibility. The source-specific clock behavior, packet-loss texture, failure
states, open-at-cutoff lifecycles, and protocol semantics are substantially more production-like
than the synthetic indicators are damaging.

## Executive Summary

The reviewed window spans approximately 12:00–18:00 UTC on 2024-03-18 and contains three Zeek
views, two Snort views, a Cisco ASA log, and an explicit-proxy log. The network is busy but not
uniform: Zeek Core has 11,258 connections, DMZ has 8,321, and DB has 490. TCP, UDP, and ICMP are
all represented, with successful sessions, SYN-only attempts, resets from both sides, partial
sessions, missed bytes, and long-lived SSH/RDP activity.

The principal authenticity concern is visible on six cleartext proxy transactions. The authority
seen on the client-to-proxy request is changed into an unrelated IP-literal `Host` value on the
proxy-to-origin request, even though the destination is a third address. For example, at
12:15:16.362435 the client leg requests `20-205-68-81.microsoft.com`; at 12:15:16.407154 the
forward leg uses `Host: 20.205.68.81` while connecting to `23.45.84.162`. Similar mutations occur
for CloudFront-looking authorities. That is a real HTTP proxy contract gap, although field-level
sanitization could be a contributing explanation.

Against that, the broader telemetry has strong production texture. Corresponding flows at
different sensors have stable but slowly drifting clock offsets rather than copied timestamps;
Zeek state/history/packet arithmetic is coherent; DNS TTLs respect cache aging in the repeated
unexpired samples; TLS versions and ciphers agree; all 546 inspectable SNI/leaf-certificate pairs
match; ASA build/teardown identities are internally consistent; and four late-window ASA
connections correctly remain open with no forced Zeek close record.

## Evidence For Synthetic

- **[contract_gap, repeated, high weight] Proxy authority is rewritten inconsistently between
  legs.** In `zeek-dmz/http.json`, the 12:15:16.362435 client request (UID
  `CXOCg0Eis2dzoKTXze`) has `host=20-205-68-81.microsoft.com` and
  `uri=http://20-205-68-81.microsoft.com/`. At 12:15:16.407154, the paired forward request (UID
  `CFgPW6HWD3FvWskbo4`) goes to `23.45.84.162:80` but has `host=20.205.68.81`. The same client
  transaction appears in `proxy_access.log` line 39 at 12:15:16 with the hyphenated Microsoft
  authority. A forward proxy normally preserves that authority in the outbound `Host` header.

- **[contract_gap, repeated, high weight] The authority mutation is a family, not a one-off.** At
  12:43:34.249649, `zeek-dmz/http.json` UID `C3KK70JalWmryIXnzt` requests
  `server-34-104-145-3.fra56.r.cloudfront.net`; 17 ms later UID `CGLvCBBztj2xspqLWD` connects to
  `151.101.187.128` with `host=34.104.145.3`. At 13:00:33.111218, UID
  `CuzgNZlp4aZXKCRbMA` requests `d1pwzl8d3z61e9.cloudfront.net`; the 13:00:33.179236 forward leg,
  UID `CSBvE4Y3hDJwFdvok8v`, connects to `52.84.93.30` but again uses `host=34.104.145.3`.
  Six matched cleartext proxy pairs show this class of mismatch. Domain sanitization lowers the
  weight, but it does not make the source-visible inconsistency disappear.

- **[distribution_texture, dataset-wide background family, moderate weight] Rare-TLD noise has a
  conspicuously templated vocabulary.** `zeek-core/dns.json` contains 12 `.bit` queries dominated
  by `node-` and `resolver-`, 10 `.to` queries dominated by `cdn-` and `sync-`, and seven `.tk`
  queries dominated by `lookup-`. Examples include `node-m2iu854z.bit` at 12:19:25.234430,
  `resolver-almzqn1i.bit` at 12:23:18.186369, `cdn-ti83pjhh.to` at 13:38:56.878823, and
  `lookup-pkvklomx.tk` at 15:32:19.951682. These are spread across unrelated workstation and
  server addresses. Real adware/noise can look similar, but the TLD-to-prefix coupling resembles
  a small enumerable generator more than an organically mixed resolver population.

- **[distribution_texture, weak-to-moderate weight] Clear HTTP connection reuse is limited.** In
  `zeek-dmz/http.json`, 355 non-CONNECT transactions occupy 296 UIDs; 272 UIDs have only
  `trans_depth=1`, and only 24 carry multiple transactions. In `zeek-core/http.json`, 194
  non-CONNECT transactions occupy 135 UIDs, with 111 single-transaction UIDs. Proxying, opaque
  TLS, short-lived agents, and failures explain much of this, so it is not a contradiction, but
  the residual connection churn is somewhat cleaner and more isolated than expected from a
  six-hour enterprise slice.

## Evidence For Real

- **Transport state is source-native and internally valid.** `zeek-core/conn.json` contains 8,963
  `SF`, 1,969 `S0`, 148 `RSTO`, 92 `RSTR`, plus `OTH`, `REJ`, `S1`, `S2`, and `S3` states. DMZ has
  5,317 `SF`, 2,721 `S0`, 136 `RSTO`, 79 `RSTR`, and smaller failure/partial-state populations.
  Across all three conn logs, I found no negative durations, no `S0` row carrying responder
  packets/bytes, no `SF` row lacking responder packets, and no application-byte count exceeding
  its corresponding IP-byte count.

- **Independent sensor clocks show realistic offset and drift.** For 4,121 matched Core/DMZ
  flows, Core is initially about 114.7 ms later, drifting by approximately -0.16 ms/hour, with
  1.07 ms residual standard deviation. For 121 Core/DB matches, the offset drifts about -3.21
  ms/hour, also with roughly 1.06 ms residual deviation. A concrete pair is
  `10.10.1.22:48798 -> 10.10.3.10:80`: DMZ records 12:00:43.166116 and Core records
  12:00:43.281588, a 115.472 ms difference. This looks like separate clocks/taps, not duplicate
  rows stamped from one event time.

- **Capture imperfections vary by sensor and flow.** Nonzero `missed_bytes` occurs on 522 Core,
  40 DB, and 550 DMZ connections. At 12:17:35.636798, Core UID `CAGCP5mnvKD1mUAY43` is an SMB
  flow with 32,854 missed bytes and history `ShADaDaDadfFGg`; at 14:16:58.058589, DB UID
  `CNfckfzjpTkNA5bJL7O` is MySQL with 479 missed bytes and `ShADaDadfFg`. The differing loss
  scale and history suffixes are plausible for distinct observation points.

- **DNS semantics and resolver timing are coherent.** Core contains 2,913 DNS rows: 2,684
  `NOERROR`, 211 `NXDOMAIN`, 13 `SERVFAIL`, and five `REFUSED`, across A, AAAA, TXT, PTR, SRV,
  NS, MX, and SOA. RTT ranges from 96 microseconds to 2.294566 seconds. I found no NXDOMAIN with
  answers, A/AAAA address-family mismatch, or malformed PTR owner. In the 14 adjacent repeated
  recursive-cache observations where the prior TTL had not expired, none showed an impossible
  early TTL reset/increase.

- **TLS is cryptographically and semantically plausible.** DMZ has 2,211 SSL rows split between
  1,491 TLS 1.3 and 720 TLS 1.2 sessions, with AES-GCM, ChaCha20-Poly1305, and plausible TLS 1.2
  ECDHE suites. Core has 138 TLS 1.2 and 124 TLS 1.3 rows. No version/cipher incompatibility was
  found. All SSL UIDs resolve to conn rows, no SSL timestamp precedes its connection, all chain
  FUIDs resolve to `x509.json`, all certificates are valid at observation time, and all 546
  SNI/leaf-certificate pairs that could be checked match CN/SAN names.

- **Proxy lifecycle semantics are unusually strong.** `proxy_access.log` has 2,411 rows with
  2,140 successes, 127 `304`, 46 `403`, 35 `407`, and 28 total `502/503/504`. Every one of 642
  `tunnel-setup` IDs has exactly one setup, consistent client identity/source port, no child before
  setup, and child requests inside the stated duration. The setup's `tunnel_cs_bytes` and
  `tunnel_sc_bytes` exactly equal its child totals in all 642 cases. For example, lines 59 onward
  at 12:22:04 use tunnel `PT-71493077fd3c0dac` for multiple `cdn.sstatic.net` requests over the
  stated 37.571-second session.

- **Firewall lifecycle is coherent and not artificially drained at the boundary.** The ASA log
  contains 7,317 TCP/UDP builds and 7,313 matching teardowns, with zero orphan teardowns and no
  identity mismatch. Reasons include 4,045 `TCP FINs`, 2,118 `SYN Timeout`, 129 `TCP Reset-O`, and
  59 `TCP Reset-I`. Four SSH connections—IDs 1688044, 1688318, 1688521, and 1688543—remain open
  late in the window and have no Zeek conn close row, which is consistent with a collection slice
  ending while sessions remain active.

- **IDS detections are supported by packet-visible facts.** All 123 parsed TCP/UDP Snort alerts
  have an exact five-tuple Zeek match within 0.5 seconds. At 12:15:16.684204,
  `snort-perimeter/snort_alert.log` raises SID 2013504 for an APT user agent on
  `10.10.3.20:47342 -> 23.45.84.162:80`; `zeek-dmz/http.json` at 12:15:16.407154 has that exact
  tuple and `Debian APT-HTTP/1.3 (2.4.10)`. DNS-alert messages likewise match the queried TLDs and
  response states.

- **Attack and background timing have credible shapes.** The 13:40–13:41 burst is explainable as
  a visible internal sweep: `10.10.3.10` probes the `10.10.2.0/24` population across ports 22, 80,
  443, 445, and 3306 plus ICMP, producing mostly `S0` and a small number of `REJ`/successes over
  roughly 32 seconds. Separately, `10.10.3.10` issues 93 unique `.top` DGA-like queries from
  17:00:20.646275 through 17:45:10.957659 with 83 NXDOMAIN and 11 answers to `45.33.32.30`.
  These are machine-like behaviors, but they are operationally plausible machine behaviors.

- **DHCP renewal cadence respects leases without exact periodicity.** For
  `WS-LNGUYEN-01` (`10.10.1.21`, one-hour lease), 12 REQUEST/ACK observations recur at roughly
  half-lease intervals, but gaps vary from 1,755.775 to 1,989.071 seconds and transaction durations
  vary from 0.047675 to 0.433490 seconds. Two-hour and four-hour leases have correspondingly longer
  renewal gaps.

## Detailed Analysis

**Connection states, duration, and volume.** The six-hour duration distributions are broad rather
than fixed. Core's observed-duration median is 0.043442 seconds, 90th percentile 4.538314 seconds,
and maximum 13,320.302448 seconds. DB's median is 1.598590 seconds and maximum 2,865.514293;
DMZ's median is 1.670834 seconds and maximum 13,320.302713. The longest common Core/DMZ session is
SSH from `10.10.3.10:33658` to `10.10.2.30:22`, beginning around 14:14:58 and lasting roughly
3.7 hours. Packet counts, IP-byte overhead, FIN/reset histories, and missed-byte markers remain
compatible with the reported states. High-volume SMB transfers reach hundreds of Mbps, but remain
possible on a modern LAN; no impossible negative or superluminal timing was identified.

**Protocol distribution and lateral movement.** Core's dominant analyzed services are DNS (2,918
connections), Kerberos (2,490), HTTP (1,574), LDAP (1,183), SMB (422), SSL (294), syslog (248),
SSH (52), DHCP (48), SMTP (46), and RDP (19). DB is appropriately dominated by 329 MySQL
connections, chiefly `10.10.3.10 -> 10.10.4.10:3306`, with successes and both-direction resets.
SMB mapping/file evidence spans DC SYSVOL/NETLOGON, Windows shares, and Linux-backed shares; 106
connection UIDs carry file actions, and action ordering is consistently open-before-read/write.
One 14:20:23.754379 SMB open (UID `ClRjTWwdignYcQl2TJ`, `\\FILE-SRV-01\Users`,
`Desktop\schedule.pdf`) lacks a same-UID mapping row. Because it is a single omission amid 105
mapped file-bearing UIDs, I treat it as realistic collection/analysis loss, not synthetic evidence.

**DNS and external destinations.** Internal DNS is authoritative for local names and presents
stable 300/1,800-second TTL families. External DNS has lower, aging TTLs, dual-stack answers,
NXDOMAIN/SERVFAIL/REFUSED texture, sparse PTR use, and believable resolver switching between
`10.10.2.10` and `10.10.2.11`. Outbound SNI/IP groupings are mostly provider-consistent: Google
names share `142.250.80.46`; Teams/AAD use `13.107.246.40`; package/CDN services have stable but
distinct endpoints. The public identities and domains may be sanitized, so IP ownership or brand
accuracy is not scored independently.

**TLS, HTTP, files, and proxy behavior.** TLS session resumption is present (733 of 2,211 DMZ SSL
rows), and TLS 1.3's lower certificate visibility is reflected by many chainless rows without
breaking rows that do expose chains. Large file movement is staged plausibly across proxy legs.
For example, the 118,845,978-byte MSI appears on the external DMZ leg at 12:12:01.505485 and on
the internal leg at 12:12:06.475030/Core 12:12:06.544730, with distinct FUIDs but consistent size
and MIME type. HTTP method/status/body contracts are sound: no GET carries a request body, and no
204/304 carries a response body. The six authority-rewrite defects described above are the main
exception.

**IDS and firewall.** Signature content agrees with the underlying TLD, method, user agent, or
tuple. Alert latency relative to the matching Zeek event is consistently sub-second without being
identical. ASA connection IDs are contiguous, but the actual lifecycle is not unnaturally uniform:
FINs, both reset directions, 30-second embryonic SYN timeouts, UDP teardowns, ACL denies, PAT
build/teardown records, and unfinished tail sessions all occur. ASA time rounding explains the
observed zero/one-second difference between elapsed wall time and the printed duration.

**Collection plausibility.** The three sensors have different service populations, byte counts,
missed-byte behavior, and clock drift. Duplicate visibility across sensors is expected from the
topology and is not treated as synthetic. The data also avoids forced lifecycle closure at 18:00,
which is an important production characteristic. No conclusion relies on filesystem timestamps,
absent Sysmon coverage, completeness of cross-source matching, or the mere presence of suspicious
activity.

## Synthetic Indicator Summary

| Indicator category | Concrete finding | Scope | Weight |
|---|---|---:|---:|
| hard_contradiction | No decisive transport, DNS, TLS, IDS, or firewall impossibility established | None | None |
| contract_gap | Client proxy authority becomes an IP-literal outbound `Host` unrelated to the connected destination | Six cleartext proxy pairs | High |
| contract_gap | One SMB file-open UID lacks a same-UID tree mapping | One event | Not scored; plausible loss |
| distribution_texture | Rare `.bit`/`.to`/`.tk` background names use TLD-linked semantic prefix templates across unrelated hosts | Repeated | Moderate |
| distribution_texture | Most clear HTTP UIDs carry one transaction | Dataset-wide | Low |
| schema_or_format | JSONL, Snort unified-style text, ASA syslog, and combined proxy syntax parse consistently; no decisive defect | Dataset-wide | Evidence for real |
| environment_or_collection_plausibility | Independent clock drift, sensor-specific missed bytes, and active-at-cutoff sessions | Dataset-wide | Strong evidence for real |
| weak_signal | Exact proxy tunnel byte aggregation is unusually tidy, but semantic completeness alone is not scored synthetic | 642 tunnels | Excluded |

## Realism Score by Category (Field format accuracy, Temporal patterns, Cross-source correlation, Behavioral realism, Environmental consistency, each 1-10)

| Category | Score | Rationale |
|---|---:|---|
| Field format accuracy | 8/10 | Strong Zeek/Snort/ASA/proxy syntax and field semantics; reduced by repeated outbound `Host` mutation |
| Temporal patterns | 9/10 | Broad durations, bursty activity, lease-aware jitter, clock drift, and unfinished tail lifecycles |
| Cross-source correlation | 9/10 | Tuple, IDS, TLS, certificate, proxy-tunnel, and firewall lifecycles agree without impossible visible ordering |
| Behavioral realism | 8/10 | Credible scanning, DGA/tunnel-like DNS, browsing, updates, DB, SMB, SSH, and RDP; some templated background texture |
| Environmental consistency | 8/10 | Role-appropriate protocol mix, resolver/proxy/firewall topology, NAT, capture loss, and sensor-specific visibility |

## Recommendations

1. Preserve HTTP authority end to end. For every explicit-proxy transaction, derive the outbound
   `Host`, DNS name, destination selection, TLS SNI, and proxy target from one canonical authority.
   Specifically regression-test the six IP-encoded/CloudFront examples found here.
2. If the domains are sanitized, sanitize correlated authority fields as one unit. Independent
   replacement of proxy URL host, outbound `Host`, DNS owner, SNI, and destination mapping can
   create exactly the contradictions observed here.
3. Diversify low-volume rare-TLD background noise. Reduce the repeated `node-`/`resolver-`,
   `cdn-`/`sync-`, and `lookup-` vocabulary coupling, or tie each family to a stable software/host
   population with repeatable cadence and resolver outcomes.
4. Increase ordinary HTTP/1.1 connection reuse where the source behavior supports it, while
   retaining one-shot updater and failed proxy transactions. Do not increase reuse mechanically
   for CONNECT control messages.
5. Retain the strongest current realism features: source-specific clock offset/drift, asymmetric
   capture loss, varied TCP termination states, resolver cache aging, proxy error/authentication
   outcomes, and connections left active at the collection boundary.
