# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 84  
**Synthetic-Confidence Score:** 72

## Executive Summary

This collection is highly convincing at the topology, cross-sensor, packet-accounting, certificate, firewall-lifecycle, IDS, and proxy-identity layers. I nevertheless assess it as synthetic because the Zeek DNS timestamps violate same-sensor packet semantics across all three sensor views, with supporting source-timing and distribution artifacts in SMTP, ASA PAT allocation, and browser proxy lifetimes that are difficult to reconcile with packet-derived production telemetry.

## Evidence For Synthetic

- **[hard_contradiction] Zeek UDP DNS timestamps do not represent the packet that created the DNS transaction.** There are 3,885 UDP DNS rows, each the sole DNS transaction for its UID. In 3,863 cases the associated `conn.json` row contains exactly one origin packet, one response packet, and history `Dd`; nevertheless, every `dns.ts` is 1.037–11.950 ms after `conn.ts`, and every connection ends after `dns.ts + rtt`. With one query and one response, the first origin packet is the query: `conn.ts` and the DNS transaction start must be the same packet timestamp, and the connection end must coincide with the response represented by the RTT. Example: `zeek-core` UID `CenqoOvjv53RQ9uyVy1` has `conn.ts=1710763225.824975`, duration `0.004686`, one packet each way, and history `Dd`, while `dns.ts=1710763225.829115` and `rtt=0.000314`. The query is therefore placed 4.140 ms after its only possible query packet, and the modeled response precedes the connection end by another 0.232 ms. This is dataset-wide across core (2,868 UDP rows), DB (44), and DMZ (973), not an edge-of-window artifact.

- **[contract_gap] SMTP transaction timestamps are effectively coincident with TCP start, including WAN sessions.** All 46 `zeek-core/smtp.json` rows occur only 0.052–0.969 ms after their matching TCP `conn.ts`; all 17 external sessions fall within 0.072–0.969 ms. For example, outbound UID `C6SJIZ63Ab9lfHvttQK` starts at `1710763901.977047` and has a populated SMTP transaction at `1710763901.977615`, only 0.568 ms later. An external TCP handshake plus banner/SMTP exchange cannot complete on that timescale. If the field is intentionally being used as a connection-start timestamp rather than a transaction timestamp, it is still source-native timestamp semantics that should be corrected.

- **[distribution_texture] TCP PAT ports come from a small, noncontiguous, almost perfectly balanced pool.** The ASA log contains 1,783 TCP translation lifecycles but only 480 translated source ports spanning 1034–65369. Of those ports, 347 occur exactly four times, 129 exactly three times, four exactly twice, and none once; no reuse overlaps in time. That balanced reuse of a scattered preselected set is unlike normal original-port preservation or demand-driven PAT allocation and looks like a bounded synthetic pool being consumed evenly.

- **[distribution_texture] Browser proxy tunnels are systematically short and weakly reused.** Of 672 inspected tunnel setups, 660 carry browser user agents. For those browser tunnels, median lifetime is 1.839 s, 358/660 (54.2%) last under two seconds, and 510/660 (77.3%) carry exactly one inspected request. Only 18 browser tunnels carry five or more requests. The internal joins are coherent, but the population underrepresents persistent HTTP/2-era browser connections and multiplexing.

- **[contract_gap] Three same-sensor file identifiers are orphaned.** `zeek-core/http.json` references absent FUID `FLEcSIMuqYpc4eduGR`; `zeek-core/smb_files.json` references absent FUID `FQYdmIvDpRskFMvCD2`; and `zeek-dmz/http.json` references absent FUID `FzA0m4BcX0G6KgEYDq3`. All occur well inside the six-hour window, so window truncation does not explain them. The rate is small and could reflect selective `files.log` loss, but no corresponding collection-loss marker is visible.

## Evidence For Real

- All inspected newline-delimited JSON parsed successfully. The three Zeek views contain 19,833 `conn` rows, 3,895 DNS rows, 3,424 HTTP rows, 2,538 SSL rows, and 1,928 file rows, with heterogeneous source volumes appropriate to core, DB, and DMZ visibility.

- Every one of the 9,903 Zeek DNS/HTTP/SSL/SMTP rows joins to a same-sensor `conn` UID with an exact four-tuple, and every protocol timestamp falls inside its connection interval. All 1,928 `files` rows link to an existing connection UID and occur within that connection.

- Packet accounting is physically plausible across all 19,833 Zeek connections: no payload count exceeds IP-byte count, no positive payload appears with zero packets, and no duration is negative. UDP IP-byte overhead is exactly 28 bytes per packet; TCP overhead is varied and never below the minimum header size.

- Cross-sensor duplication looks like genuinely separate observation points rather than copied records. Exact tuples produce 134 core↔DB, 4,184 core↔DMZ, and 327 DB↔DMZ overlaps, with distinct UIDs and modest packet-count/history differences. Strict same-byte matches show stable but drifting clock offsets: core→DB grows from about +54.9 ms at window start by 3.13 ms/hour (`R²=0.959`), core→DMZ is about −114 ms, and DB→DMZ drifts by about −2.93 ms/hour (`R²=0.950`). Residual jitter is roughly 1.1–1.2 ms.

- ASA lifecycle behavior is strong. There are 6,417 TCP and 986 UDP connection builds with gap-free numeric connection IDs; 7,401/7,403 have exact-tuple teardowns, and the two open TCP sessions begin at 17:39:37 and 17:46:31, making post-window teardown plausible. Teardown reasons align with Zeek states (`SF`→TCP FINs, `S0`→SYN Timeout, `RSTO`→Reset-O, `RSTR`→Reset-I). All 1,788 NAT builds have matching teardowns.

- 7,355/7,403 ASA TCP/UDP builds (99.35%) match an exact DMZ Zeek five-tuple within the firewall's one-second timestamp precision. The 48 nonmatches cluster in routes such as inside↔inside and inside↔outside mail traffic that need not traverse the DMZ sensor.

- All 185 Snort alerts parse, and every alert matches an exact Zeek flow tuple on the corresponding sensor. All 92 DNS alerts also match the exact DNS transaction and the signature's TLD semantics. Signature IDs, revisions, classifications, and priorities are internally varied and plausible.

- Proxy causal identity is exceptionally coherent. All 2,524 access rows parse. Every one of 982 inspected requests resolves to a unique prior/same-second tunnel setup with identical client, user, client source port, and host and falls within the declared tunnel lifetime. Of 672 setup records, 671 have an exact DMZ ingress connection by source port and 668 also have the same-UID cleartext CONNECT row; the few gaps are sparse enough to fit selective observation loss.

- TLS and certificate relationships are strong. All 1,074 server-chain FUID references resolve to both `files` and `x509`; no certificate is used outside its validity period; repeated fingerprints have identical certificate fields; and all 553 handshakes with an inspectable leaf and SNI pass CN/SAN hostname matching. TLS 1.2/1.3 and cipher distributions are modern and diverse.

- HTTP/file behavior is internally consistent. All HTTP transaction depths are monotonic within a UID and remain inside connection duration. Where HTTP body length differs from `files.total_bytes`, `files.seen_bytes` equals the HTTP observed body and the difference is explicitly represented by `missing_bytes`.

- Endpoint/network topology is coherent. eCAR FLOW records consistently place each hostname at one stable IP, and 24,007/24,239 flows (99.04%) match an exact Zeek tuple within five seconds after accounting for ICMP's lack of ports. Per-host time offsets differ in stable ways, consistent with independently clocked endpoints.

- DHCP renewal behavior is credible: six stable IP/MAC/hostname bindings use 1-, 2-, or 4-hour leases, renew near T/2 with jitter, and occasionally skip an observed renewal. No IP changes MAC and no MAC is assigned to multiple IPs.

## Detailed Analysis

### Scope and method

I examined only the supplied six-hour data directory. The packet-derived time range is 2024-03-18 12:00:04.459823 UTC through 17:59:56.648301 UTC (21,592.188 seconds). I parsed every network JSON line; grouped records by sensor, UID, five-tuple, source port, FUID, certificate fingerprint, proxy tunnel ID, ASA connection ID, and Snort signature; and ran exact lifecycle and timing joins rather than relying on visual samples. Filesystem timestamps were not used.

### Zeek connection state, histories, and accounting

The core sensor has 11,012 connections: 8,716 `SF`, 1,951 `S0`, 150 `RSTO`, 98 `RSTR`, 27 `REJ`, and a small tail of `S1/S2/S3/OTH`. The DMZ has 8,360 connections: 5,373 `SF`, 2,742 `S0`, 128 `RSTO`, 58 `RSTR`, 27 `REJ`, and a similar tail. The DB view is appropriately narrower at 461 rows, dominated by MySQL and showing 374 `SF`, 36 `RSTO`, 21 `RSTR`, and 19 `S0`.

Histories are diverse and state-compatible. UDP successes are primarily `Dd`; established TCP includes multiple realistic sequences such as `ShADadfF`, `ShADaDadfF`, retransmission/partial-close variants, and reset paths. The large `S0` population is explained by scanning rather than baseline uniformity: at 13:40 UTC, 10.10.3.10 originates approximately 1,524 attempts spanning 254 targets across several ports/protocols, while normal minutes remain much smaller and bursty. External inbound DMZ traffic also has varied states and destination ports.

No impossible packet or byte relationships were found. The same flows differ slightly between observation points in packet counts, history letters, and payload bytes, which is expected from sensor location, capture timing, and loss. Importantly, those differences coexist with stable sensor-specific clock relationships rather than arbitrary timestamp noise.

### DNS semantics and causality

DNS content is otherwise plausible: core qtypes include 2,114 A, 272 AAAA, 250 TXT, 127 PTR, 98 SRV, plus NS/MX/SOA; core rcodes include 220 NXDOMAIN, 15 SERVFAIL, and four REFUSED. Suffix-search texture includes `wpad`, `isatap`, stale internal names, and PTR failures. Authoritative flags line up with internal forward/reverse zones; recursive external answers generally clear `AA`. Transaction IDs and source ports are high-cardinality, TTLs include cache-like decrementing values as well as policy constants, and RTTs span local sub-millisecond responses through multi-second failures.

The timestamp contract is the decisive defect. For a UDP UID with one origin and one response packet, Zeek's connection start and DNS transaction start are the same query packet; `rtt` spans that query to its response, and the connection duration spans the same two packets. Instead, all 3,885 UDP DNS rows insert a positive pre-query phase and a positive post-response phase. Median `dns.ts - conn.ts` is 2.544 ms on core, 2.642 ms on DB, and 2.518 ms on DMZ. The residual `conn.duration - (dns.ts - conn.ts) - rtt` is positive for every row, with medians near 0.39–0.57 ms. This patterned decomposition is internally neat but cannot be produced by the observed packet counts.

This finding does not depend on a missing pre-window initiator, cross-source clock synchronization, or unusually complete correlation: both timestamps and packet counts come from the same Zeek sensor and same UID, and the relevant query/response are visible inside the window.

### SMTP timing

SMTP content has realistic HELOs, paths, recipients, status text, STARTTLS-only setup rows, and inbound/outbound relay structure. The same-source timing is not credible, however. External SMTP rows with fully populated SMTP fields begin less than one millisecond after the matching TCP connection start. UID `CkxJe81jNguXBIqH1a`, for example, is an inbound public-IP session with a 3.104485-second connection and 5/6 packets, but `smtp.ts` is only 0.306 ms after `conn.ts`. Even if the sensor sits directly beside the server, the remote TCP handshake must traverse the WAN before application data can be observed.

### Proxy ordering and tunnel behavior

The proxy uses several coherent modes: 723 plain tunnels, 672 tunnel setups with peek metadata, 982 SSL-inspected requests, and smaller forward/deny/auth/gateway-error populations. Tunnel IDs are unique at setup and correctly reused by inspection rows. Exact joins found no inspection request before its setup, no request beyond setup lifetime (allowing the proxy log's one-second timestamp precision), and no mismatch in client, authenticated user, source port, or host.

Apparent nearest-neighbor inversions around repeated hosts disappeared when the `client_src_port` was enforced. For example, three `accounts.cloud.com` CONNECTs at 16:25:22–16:25:25 are distinct sessions with ports 62988, 64971, and 55314; source-port matching restores ingress-before-egress order. I therefore do not treat proxy causal ordering as a defect.

The remaining concern is population texture. Modern browser traffic normally amortizes requests over persistent TLS connections, especially under inspection where tunnel IDs expose connection reuse. Here 77.3% of browser tunnels carry one request and the median lifetime is 1.839 seconds. The long tail exists (maximum 61.419 seconds; a few tunnels carry 8–12 requests), but it is too weak relative to the one-request majority.

### ASA lifecycle, NAT, and topology

ASA build/teardown ordering, tuple preservation, duration rounding, bytes, reason text, and connection ID monotonicity are excellent. The two unmatched teardowns are not a defect: they are actually two builds without visible teardown, both late-window SSH sessions whose continuation can legitimately fall outside the bounded collection.

The PAT allocator is the anomaly. The 1,783 TCP translations reuse only 480 widely scattered outside ports, with an almost perfectly even 2–4 uses each and no singleton port. This is not a contiguous ASA port block, and no concurrency pressure forced the reuse: the same outside port is never active twice simultaneously. The shape is much more consistent with a synthetic precomputed pool than an allocator reacting to available ports and attempting original-port preservation.

Sensor placement is otherwise coherent. Core and DMZ share internal↔DMZ visibility; DB sees traffic involving the database segment; firewall-only paths explain nearly all ASA rows absent from DMZ Zeek. `local_orig`/`local_resp` flags are consistent with the observed 10.10.0.0/16 environment in every connection row.

### IDS consistency

Core Snort contains 73 alerts and perimeter Snort 112. The mix includes DNS TLD policies, P2P, STUN, scan, HTTP CONNECT, basic auth, package-manager/curl user agents, and JA3-oriented TLS alerts. Every alert joins an exact tuple; all DNS alert messages match the queried TLD. Alert timestamps are typically 0.22–0.32 seconds after the Zeek start on their respective sensor paths. Because Snort and Zeek are separate clocks and the offsets are stable, I do not treat apparent post-close DNS alerts as impossible ordering.

### TLS, HTTP, X.509, OCSP, and files

TLS version/cipher distributions are appropriate for March 2024: TLS 1.3 dominates DMZ external traffic, while internal services retain more TLS 1.2. Resumption, handshake-history, RSA/ECDSA, 2048/4096-bit RSA and 256-bit EC, and certificate-chain-length distributions are varied. Certificate reuse follows stable fingerprints and fields; validity and SNI checks found no contradiction. OCSP objects link to files and have coherent `thisUpdate`/`nextUpdate` windows.

HTTP is dominated by CONNECT at the core proxy view and includes GET/POST, realistic status diversity, user-agent diversity, redirects, caching, errors, and multi-transaction UIDs. File extraction preserves byte-loss semantics and links PE, OCSP, X.509, SMB, and SMTP artifacts. The three orphan FUIDs are genuine local referential gaps, but they are 3 among hundreds of references and do not outweigh the otherwise strong file graph.

### Traffic timing and environment texture

Traffic is neither uniform nor mechanically flat. Core interarrival median is 0.771 s, DMZ 0.380 s, and DB 19.032 s, with bursts tied to browsing, authentication, proxy egress, and the visible scan. Hourly totals vary materially. External inbound scanning has many source IPs, states, and sensitive ports; internal traffic includes DNS, Kerberos, LDAP, SMB, MySQL, SMTP, SSH, RDP, DHCP, syslog, and ICMP. This breadth, plus endpoint-specific eCAR clock offsets and DHCP renewal jitter, is strong production-like evidence.

## Synthetic Indicator Summary

| Indicator | Category | Affected family | Scope | Effect on score |
|---|---|---|---|---|
| UDP DNS transaction time cannot arise from the visible packet sequence | `hard_contradiction` | Zeek DNS + conn | Dataset-wide: 3,885/3,885 UDP DNS UIDs; strongest on 3,863 one-packet-each-way flows across all three sensors | Decisive; same-sensor, exact-UID contradiction |
| SMTP application time is <1 ms after TCP start, including WAN peers | `contract_gap` | Zeek SMTP + conn | 46/46 SMTP rows; 17/17 external sessions | High; repeated source-native timing defect |
| PAT ports are drawn evenly from a scattered 480-value pool | `distribution_texture` | Cisco ASA NAT | 1,783 TCP translations; every chosen port reused 2–4 times, none once | Medium-high; strong generator-like allocation texture |
| Browser tunnels are short and usually single-request | `distribution_texture` | Proxy + DMZ TLS | 660 browser inspection tunnels; 510 single-request and 358 under two seconds | Medium; weak HTTP/2-era persistence texture |
| Visible FUID references lack matching file records | `contract_gap` | Zeek HTTP/SMB/files | Three isolated references across core and DMZ | Low; sparse and potentially explainable by selective log loss |

## Realism Score by Category

- **Field format accuracy: 9/10** — Zeek, ASA, Snort, proxy, eCAR, X.509, OCSP, PE, and file records parse and use convincing source-native structures; only sparse referential gaps were found.
- **Temporal patterns: 5/10** — sensor drift, DHCP, scanning, and workload bursts are strong, but DNS packet timing is impossible and SMTP/proxy timing populations remain synthetic-looking.
- **Cross-source correlation: 9/10** — exact UID/tuple, firewall, IDS, proxy, eCAR, certificate, and file joins are exceptionally strong without simple copied-record identity.
- **Behavioral realism: 7/10** — service mix, failures, scans, DNS texture, and protocol variety are credible; browser connection reuse and PAT allocation are less organic.
- **Environmental consistency: 9/10** — topology, sensor visibility, host/IP ownership, route coverage, TLS deployment, infrastructure protocols, and collection boundaries agree well.

## Recommendations

1. **P0 — Anchor Zeek DNS fields to packet-derived truth.** For UDP, set `dns.ts` to the query packet timestamp/connection start when the query is the first origin packet; set `rtt` from query to response; and ensure the terminal packet produces `conn.ts + duration == dns.ts + rtt` for the one-query/one-response case. Add an invariant test across core, DB, and DMZ views, including retransmission cases where packet counts exceed one.

2. **P1 — Model SMTP application readiness after transport establishment.** Place the first SMTP event after the TCP handshake and, for WAN peers, after a realistic RTT/banner delay. Preserve the current total session duration and packet history while ensuring the application timestamp cannot precede the packets required to carry it.

3. **P1 — Replace the balanced PAT sample pool with a stateful allocator.** Model original-port preservation, collision fallback, interface/global-address policy, and active translation occupancy. Reuse ports only after teardown, but do not force near-equal reuse of a scattered fixed set; validate the resulting singleton/reuse distribution over several six-hour windows.

4. **P1 — Increase browser tunnel persistence and multiplexing.** Keep a larger share of browser CONNECT/TLS sessions alive for tens of seconds to minutes, attach realistic request bursts to the same tunnel, and vary reuse by browser, destination, idle timeout, HTTP version, and response behavior. Retain short one-shot connections for command-line clients and failures.

5. **P2 — Make file-log observation decisions referentially coherent.** If a FUID is visible in HTTP/SMB metadata, normally retain its corresponding `files` row; if selective file logging or loss is intended, model and expose that collection behavior consistently rather than creating isolated unexplained orphans.

6. **Preserve the strongest existing contracts.** The independent sensor clocks, ASA reason/state mapping, exact proxy tunnel identity, SNI/certificate chains, IDS tuple matches, packet accounting, eCAR topology, DHCP renewal jitter, and bounded-window lifecycle handling materially improve authenticity and should remain regression gates.
