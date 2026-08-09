# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 72

## Executive Summary

The network telemetry is carefully constructed and unusually strong in flow accounting, protocol timing, TLS behavior, and dual-sensor consistency, but two dataset-wide textures push it into likely-synthetic territory. DNS responses systematically lack CNAME/alias-chain texture despite extensive modern SaaS/CDN traffic, while DHCP renewal schedules are almost perfectly periodic per client with inconsistent client-specific fractions of the advertised lease time; the complete absence of ordinary time-sync and local-discovery traffic from an otherwise broad core sensor adds supporting weight.

## Evidence For Synthetic

- `[schema_or_format]` Across `zeek-core/dns.json`, 1,364 A-query rows and 308 AAAA-query rows contain only address literals in `answers`; across `zeek-dmz/dns.json`, the same is true of all 590 A and 110 AAAA rows. There are no CNAME query records and, more importantly, no alias names embedded in any A/AAAA answer vector, even for a large mix of SaaS/CDN-style names such as `r1.res.office365.com`, `ctldl.windowsupdate.com`, `cdn.onenote.net`, `fonts.googleapis.com`, `registry.npmjs.org`, and `api.snapcraft.io`. A six-hour recursive-DNS trace of this breadth would normally expose at least some CNAME-chain answer texture. The uniform type-pure answer construction looks like a simplified DNS renderer rather than packet-derived Zeek output.
- `[distribution_texture]` DHCP renewals in `zeek-core/dhcp.json` are nearly metronomic for each client. `WS-OHADDAD-01` has 13 REQUEST/ACK transactions from 12:01:43 through 17:59:14 with successive gaps confined to about 1,786.2–1,788.8 seconds; `WS-MCHEN-01` has 11 at about 1,969.2–1,970.6 seconds; `WS-PPATEL-01` has 12 at about 1,691.5–1,693.7 seconds; and `LT-MRIVERA-02` has 10 at about 1,929.4–1,931.5 seconds. These clients all advertise 3,600-second leases, yet each receives a different stable apparent renewal fraction, with only roughly one second of per-cycle disturbance over six hours. Other clients show the same template at 7,200- and 14,400-second lease scales. A server-supplied T1 could explain a stable timer, but the combination of per-client randomized ratios and extremely narrow jitter across every visible cycle is generator-like.
- `[environment_or_collection_plausibility]` The core `conn.json` records 6,408 connections and broad UDP visibility—2,260 UDP/53 DNS flows, 731 UDP/88 Kerberos flows, 69 UDP/67 DHCP flows, and three UDP/3478 flows—yet contains zero UDP/123 NTP, UDP/137-138 NetBIOS, UDP/1900 SSDP, UDP/5353 mDNS, or UDP/5355 LLMNR flows. Policies can suppress individual discovery protocols, but a mixed Windows/Linux environment with this level of infrastructure visibility producing none of these families over six hours looks selectively modeled. This is supporting evidence, not a standalone contradiction.
- `[distribution_texture]` Source activity is somewhat compressed into a curated service vocabulary. On the core sensor, DNS (2,259), Kerberos (1,076), HTTP (959), SMB (921), and LDAP (629) account for most classified connections, while only 214 connections lack a recognized service. Given the otherwise broad packet-level view, the near-total absence of miscellaneous protocol tail reinforces the selective-traffic impression.

## Evidence For Real

- TCP state texture is convincing rather than uniformly successful. `zeek-core/conn.json` contains 6,161 `SF`, 84 `RSTO`, 57 `RSTR`, 44 `REJ`, 29 `S0`, plus smaller `OTH`, `S1`, `S2`, and `S3` populations. The DMZ view plausibly shifts toward hostile Internet background noise with 1,280 `S0` flows, 111 `RSTO`, 75 `RSTR`, and 29 `REJ` among 5,467 connections.
- The Internet scan background is bursty and heterogeneous. For example, `145.78.103.167` generates 203 attempts across ports 23, 2323, 22, 8080, and 80 during nearly the whole window, predominantly `S0`; `45.33.74.51` focuses on 445/3389/135/5985/139; and mail-oriented scanners concentrate on 25/587/465/110/143. Inter-arrival gaps are irregular, with long pauses and occasional sub-second bursts, not fixed-rate loops.
- Dual Zeek observations are coherent without being byte-for-byte clones. I matched 1,930 shared five-tuples between the core and DMZ sensors. Their connection states and inferred services agree, DMZ timestamps trail core timestamps by about 23.5–66.4 ms, UIDs differ appropriately between independent sensors, and 242 shared flows show modest byte/packet/missed-byte differences consistent with vantage-specific capture loss. At 12:00:10.535388 UTC, for example, core UID `CrvarJ0RhPEemVVjeo` observes `10.10.1.21:60822 -> 10.10.3.10:80`; DMZ UID `CkzvLUSypuw1Bp65Hi` observes the same flow at 12:00:10.580582 with slightly different packet and byte counts.
- Protocol records remain within their parent connection lifetimes. Every DNS, HTTP, SSL, SMTP, and file record with a connection UID is present in the corresponding sensor's `conn.json`, and none is timestamped after its parent connection ends. This includes HTTP timestamps delayed up to about 4.72 seconds after connection start and TLS handshakes delayed up to about 0.65 seconds, plausible rather than zero-offset fan-out.
- TLS details are technically credible. The DMZ mix is 1,066 TLS 1.3 and 517 TLS 1.2 sessions, with plausible AES-GCM and ChaCha20 suites and 535 resumed sessions. TLS 1.3 records correctly lack passive certificate extraction, while non-resumed TLS 1.2 sessions carry one- or two-certificate chains. Repeated servers retain stable fingerprints/serials: all 94 visible `ehr-portal.meridianhcs.com` leaf observations share one fingerprint and serial, as do recurring `api.snapcraft.io`, Microsoft, Google, and internal CA certificates. All referenced certificates checked were valid at the observed session time.
- Network accounting is internally sound. Across both conn logs, IP-byte totals meet transport/header lower bounds for every TCP, UDP, and ICMP direction. DNS response codes, answer types, and TTL vector lengths are also structurally consistent: NXDOMAIN responses have no answers, A values are IPv4, AAAA values are IPv6, and PTR names reverse correctly.
- DNS timing and failure texture are otherwise realistic. Matching DNS answers generally precede TLS use, with median prior-to-TLS gaps near four seconds, while cache reuse creates a long tail. Core DNS includes 217 NXDOMAIN, 17 SERVFAIL, and four REFUSED responses, including suffix-search artifacts such as `wpad`, `wpad.meridianhcs.local`, `isatap`, `isatap.meridianhcs.local`, stale `oldserver`/`printer01` names, and failed PTR lookups.
- Firewall lifecycle handling is strong. `cisco_asa.log` contains 4,877 TCP/UDP connection IDs; 4,875 have exactly one build and one teardown, no teardown precedes its build, and declared teardown durations agree with wall-clock deltas to within one-second log precision. The two unmatched builds begin at 17:18:18 and 17:43:06 and correspond to long-lived SSH sessions still open when the six-hour capture ends, a realistic right-censoring effect.
- Explicit proxy behavior is source-native. CONNECT control responses have zero HTTP body in Zeek while the proxy log separately reports control-message bytes and tunneled byte counts. Successful tunnels produce proxy-origin TLS/flow evidence, whereas denied responses such as the 12:01:51 UTC `r1.res.office365.com:443` request return 403 without pretending a completed origin tunnel.

## Detailed Analysis

### Scope and traffic profile

The two conn logs span 2024-03-18 12:00:07–17:59:45 UTC. The core sensor sees 6,408 flows (3,264 TCP, 3,064 UDP, 80 ICMP), while the DMZ sensor sees 5,467 (4,601 TCP, 806 UDP, 60 ICMP). Core traffic is dominated by internal identity/file/application services; DMZ traffic is dominated by TLS, proxy HTTP, DNS, and unsolicited inbound scanning. Fifteen-minute core counts vary from 174 to 570 (coefficient of variation about 0.30), so the top-level volume is not suspiciously flat.

The port and state mixes reflect topology. Core has 938 TCP/445, 1,081 TCP/UDP 88, 649 TCP/389, 131 TCP/22, 18 TCP/3389, and one TCP/5985 flow. DMZ has 1,837 TCP/443, 1,014 TCP/8080, 791 UDP/53, plus substantial hostile probing of 23, 2323, 445, 22, 3389, 25, and related ports. Long SSH/RDP durations coexist with short rejected and reset attempts; the maximum 15,439-second connections are sensibly right-censored long sessions rather than all flows sharing one duration model.

### DNS

DNS has good timing, response-code, qtype, suffix-search, and TTL variety. Core qtypes include A (1,364), TXT (336), AAAA (308), PTR (159), SRV (68), NS (7), MX (5), and SOA (3). RTTs range from sub-millisecond internal responses to tens or hundreds of milliseconds rather than a small fixed set. The 217 core NXDOMAINs include normal operational debris as well as high-entropy suspicious names.

The decisive weakness is record-content diversity: not one A/AAAA response includes a CNAME alias string. Type-pure answer vectors are structurally valid but implausibly universal across hundreds of modern public-service queries. This is not a claim that any particular sanitized name must resolve to a particular real-world address; it is a dataset-level observation that recursive response alias chains never occur at all.

### DHCP and infrastructure protocols

The DHCP records correctly correlate to UDP connection UIDs and consistently show renewal-style REQUEST/ACK exchanges with matching address, MAC, server, hostname, domain, lease time, and realistic sub-second transaction duration. The capture can reasonably begin after initial DORA exchanges, so the absence of DISCOVER/OFFER is not itself suspicious.

What is suspicious is the scheduler texture. Every multi-renewal client repeats at an almost invariant, client-specific interval. The apparent interval is sometimes below and sometimes above the nominal 50% T1 default, yet it remains stable to roughly one second for that client. A real server may send explicit renewal timers, but the same DHCP infrastructure would more naturally show shared policy, client retries, network queuing, missed renewals, sleep/wake effects, or at least a broader perturbation over 69 transactions.

The protocol tail is also too clean. Because `conn.json` demonstrably captures many UDP families and internal subnets, zero NTP plus zero common discovery/name-service chatter is difficult to attribute merely to absent log sources. It remains possible that host hardening and sensor policy explain it, so I treat this as medium-weight environmental evidence.

### TLS, HTTP, and proxy traffic

TLS is one of the strongest areas. Versions, cipher suites, session resumption, passive TLS 1.3 certificate opacity, certificate validity, chain reuse, and SNI/endpoint patterns are mutually compatible. The x509 data uses stable certificate identity across repeated sessions instead of minting session-specific serials. HTTP status and method distributions are plausible for an explicit-proxy environment: core has 808 CONNECT, 223 GET, and eight POST records, with 200 dominant but 403, 407, 304, 301/302, 502, 503, and 504 outcomes present.

The sample proxy transaction at 12:00:13 UTC is coherent: `10.10.2.30:40920` opens a CONNECT to `10.10.3.20:8080` for `api.snapcraft.io:443`; the proxy then opens `10.10.3.20:36392 -> 185.125.188.60:443` at 12:00:14.166258 and observes TLS at 12:00:14.638716. Client/proxy and proxy/origin byte scopes remain distinct. Similar behavior repeats with cache/deny texture rather than every request forcing identical fan-out.

### Cross-vantage and firewall consistency

The core-to-DMZ propagation delay is narrow but not constant, and independent UIDs plus realistic capture loss make the two sources look like separate sensors. Shared tuple state/service mismatches are absent. The ASA data adds NAT/build/teardown semantics with monotonically allocated but non-consecutive connection IDs, plausible one-second timestamp rounding, and clean right-edge censoring. These details significantly reduce the likelihood of a crude row generator and are why the score does not enter the 81–100 range.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---:|---|
| `schema_or_format` | Zeek DNS | All 1,364 core A + 308 core AAAA and 590 DMZ A + 110 DMZ AAAA rows | No CNAME/alias-chain answers anywhere despite broad SaaS/CDN traffic; suggests simplified type-pure answer construction. |
| `distribution_texture` | Zeek DHCP | All 69 rows across eight clients | Per-client renewal periods repeat within roughly one second, while their ratios to identical lease lengths differ materially; this looks scheduled rather than organically timed. |
| `environment_or_collection_plausibility` | Zeek conn/infrastructure UDP | Entire six-hour core window | Broad UDP visibility includes DNS, Kerberos, DHCP, and STUN but no NTP, NetBIOS, SSDP, mDNS, or LLMNR. |
| `distribution_texture` | Zeek conn protocol mix | Entire core window | Traffic concentrates in a small modeled service set with a weak miscellaneous long tail. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, ASA, proxy, TLS, certificate, and packet-accounting fields are source-native and internally valid; DNS answer-content diversity is the main exception.
- **Temporal patterns:** 6 — User/scan/connection traffic is bursty and lifecycles are sound, but DHCP scheduling is conspicuously periodic.
- **Cross-source correlation:** 9 — UID parentage, protocol timing, dual-sensor tuples, proxy fan-out, and firewall lifecycles are exceptionally coherent without impossible ordering.
- **Behavioral realism:** 7 — Service use, scans, resets, denials, caching, and long sessions are plausible, but the DNS and infrastructure protocol tail is underdeveloped.
- **Environmental consistency:** 6 — Host/segment roles are coherent, yet the mixed environment emits an implausibly selective set of housekeeping/discovery protocols.

## Recommendations

- If this were synthetic, model recursive DNS answer sections as RR chains rather than type-pure terminal values. Include realistic CNAME sequences (with per-hop TTLs), occasional multi-alias chains, and cache-dependent cases where only the terminal answer is returned; preserve the same chain consistently across sensors observing the same packet.
- If this were synthetic, derive DHCP renewal scheduling from explicit server/client T1/T2 semantics. Use shared server policy where appropriate, add bounded clock/network jitter, and include occasional late renewals, retransmitted REQUESTs, sleep/wake gaps, and lease reacquisition so every client does not repeat indefinitely on a perfect private cadence.
- If this were synthetic, add a low-volume, role-aware infrastructure tail to the canonical connection model: Windows domain-time NTP to the DC, Linux chrony/systemd-timesyncd polls, and policy-dependent LLMNR/mDNS/NetBIOS/SSDP traffic. If these protocols are intentionally suppressed, introduce visible collection or policy texture that makes the suppression plausible.
- If this were synthetic, expand the long tail of low-frequency network behavior outside the dominant DNS/Kerberos/SMB/LDAP/proxy families while retaining the strong existing topology and lifecycle ownership.
