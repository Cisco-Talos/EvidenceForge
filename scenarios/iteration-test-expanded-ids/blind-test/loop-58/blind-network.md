# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 69

## Executive Summary

The flow and protocol records are unusually coherent and contain substantial realistic detail, but the traffic assigned to the apparent domain controller is a strong environmental contradiction: an infrastructure host that is visibly the DNS, Kerberos, LDAP, and DHCP server also produces a workstation-like proxy workload. A second, weaker tell is the narrowly templated TLS history vocabulary. On balance, the data looks deliberately modeled rather than captured from this particular network.

## Evidence For Synthetic

- [environment_or_collection_plausibility] `10.10.2.10` is identified by the network evidence as `DC-01.meridianhcs.local`: PTR DNS at `1710763220.300682` returns that name, and the address is the common DNS, DHCP, Kerberos, and LDAP responder. Nevertheless, `proxy_access.log` contains 95 requests from this host in six hours, including 17 with `python-requests/2.31.0`, six with `Zscaler Client Connector/4.3.0`, four with `GlobalProtect/6.2.3 Windows`, four with `Cisco Secure Client/5.1.4 Windows`, and interactive-looking Bing/Citrix activity. Examples include Bing searches at `18/Mar/2024:14:21:58 +0000`, repeated Zscaler client keepalives/PAC retrieval, and a 50,294,312-byte Citrix Workspace executable download at `17:42:52`. That blend is characteristic of a generic endpoint activity pool applied to a domain controller rather than a tightly administered DC.
- [distribution_texture] Across 1,591 TLS rows, `ssl_history` takes only ten values. The largest are `CSOFFD` (361), `CSOXYFFD` (342), `CSOXYFFTD` (175), and `CSXKNGIFIFD` (173). The protocol/version/certificate handling is internally plausible, but the repeated small template vocabulary across many unrelated internal and external sessions is cleaner than normal passive enterprise TLS telemetry.
- [environment_or_collection_plausibility] The sensor records 11,235 connections, 2,875 DNS transactions, 69 DHCP transactions, and extensive Kerberos/LDAP/SMB traffic over about six hours, yet there is no UDP/123 traffic or NTP source at all. Absence alone is not decisive, but against the otherwise broad infrastructure collection profile it weakens environmental completeness.
- [distribution_texture] All 69 DHCP application timestamps differ from their associated `conn.json` start by only exactly 0, 1, 2, or 3 milliseconds (within floating-point representation), despite the DHCP durations ranging much more continuously. The causal ordering is valid, but the quantized child-record offset is a generator-like timing texture.

## Evidence For Real

- Connection-state texture is strong: among 11,235 flows there are 9,464 `SF`, 1,394 `S0`, 177 `RSTO`, 93 `RSTR`, 36 `REJ`, plus smaller `OTH`, `S1`, `S2`, and `S3` populations. TCP histories and byte/packet accounting vary sensibly with the states.
- All inspected DNS, HTTP, SSL, SMTP, and file UIDs have a corresponding connection record in the same sensor zone, and sampled protocol timestamps fall within the associated connection interval. This permits credible session reconstruction without impossible ordering.
- DNS has production-like breadth: A, AAAA, PTR, SRV, TXT, NS, MX, and SOA queries; 370 NXDOMAINs plus small SERVFAIL/REFUSED populations; suffix-search names such as `wpad`, `isatap`, and `oldserver`; and varied RTTs rather than a single fixed latency.
- TLS details are generally source-native: TLS 1.2/1.3 cipher choices are credible, resumed sessions omit certificate chains, TLS 1.2 chains link to x509 records, and certificates have coherent subjects, issuers, SANs, validity intervals, and repeated fingerprints for reused certificates.
- Explicit-proxy behavior is thoughtfully represented: CONNECT control bytes are separated from tunnel bytes, deny/auth-required outcomes terminate tunnels, inspection produces related HTTPS requests, and client-to-proxy durations align with logged tunnel durations.

## Detailed Analysis

The capture spans `1710763207.545586` through `1710784796.686097` (about 5 hours 59 minutes) and includes 6,055 core plus 5,180 DMZ connection rows. The protocol mix is believable for a mixed enterprise: 2,883 UDP DNS flows, 1,627 TLS/443 flows, 1,562 proxy HTTP/8080 flows, 914 SMB, 738 UDP Kerberos, 636 LDAP, 272 MySQL, 157 unclassified SMB-port attempts, and smaller RDP, SSH, SMTP, DHCP, STUN, and scan populations.

Session mechanics survived spot checks. Every distinct UID in core/dmz DNS, HTTP, SSL, and SMTP existed in the corresponding `conn.json`; no companion timestamp examined occurred before its connection or after its recorded close. Successful TCP connections had at least two packets in both directions. S0 and REJ entries carry zero duration, while resets have short nonzero lifetimes. This is substantially better than simplistic flow generation.

DNS is one of the strongest areas. `DC-01` answers internal authoritative names with 300-second TTLs, NXDOMAIN noise includes Windows discovery/suffix-search patterns, external latencies show a plausible longer tail, and TXT volume is explained by both mail-security queries and a concentrated high-entropy sequence from `10.10.2.30` to `ns1.westbridge-services.cloud`. The latter looks like an actual huntable DNS-tunneling event rather than a format error, so I did not score its compact narrative as synthetic.

TLS 1.3 rows correctly tend not to expose certificate chains to the passive sensor, while fresh TLS 1.2 rows commonly do. Certificate reuse for `ehr-portal.meridianhcs.com` is coherent. The weakness is not the TLS fields themselves but the highly finite handshake-history grammar: ten exact strings account for the entire population, with four strings accounting for 1,051 rows.

The decisive issue is role placement. Independent network evidence identifies `10.10.2.10` as the domain controller/infrastructure server. Its proxy stream nevertheless looks like a composite workstation baseline: VPN and endpoint-client updates, Zscaler connector telemetry, Duo health, Cisco Secure Client, generic Go and Python HTTP, Bing searches, and Citrix installer retrieval. Some management-agent egress from a DC is normal; this many mutually overlapping endpoint stacks and user-oriented destinations on the same DC is not. This is a concrete host-role inconsistency, not merely an objection that the activity is easy to narrate.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect |
|---|---|---:|---|
| environment_or_collection_plausibility | Proxy / network role model | 95 proxy rows from apparent DC | Strongest indicator; generic workstation/client traffic is assigned to critical infrastructure |
| distribution_texture | Zeek SSL | 1,591 rows, ten histories | Handshake sequencing has a small repeated template vocabulary |
| environment_or_collection_plausibility | Zeek infrastructure coverage | Entire six-hour window | No NTP despite otherwise broad, dense infrastructure telemetry |
| distribution_texture | Zeek DHCP timing | 69 transactions | Application timestamps are quantized to four exact millisecond offsets |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, proxy, firewall, and IDS fields are well formed and protocol-appropriate.
- **Temporal patterns:** 8 — Connection/protocol ordering and durations are coherent; DHCP offsets are overly quantized.
- **Cross-source correlation:** 9 — UID integrity, proxy transactions, TLS/x509, and connection intervals correlate very well.
- **Behavioral realism:** 6 — Network behavior is varied, but workstation-like client activity on the DC is a major role error.
- **Environmental consistency:** 5 — Dense broad telemetry conflicts with the DC workload and the total absence of NTP.

## Recommendations

- If this were synthetic, constrain outbound activity pools by host role. Domain controllers should receive only defensible infrastructure/management destinations and agents; do not assign consumer searches, generic Python browsing, multiple overlapping VPN clients, or end-user software downloads without explicit scenario intent.
- Expand TLS handshake/history generation from protocol state and observed connection behavior rather than selecting from a ten-value template pool; include a longer source-native tail while preserving valid TLS-version semantics.
- Add role-appropriate NTP polling where the network collection profile is otherwise broad enough to observe DNS, DHCP, and authentication infrastructure.
- Preserve DHCP transaction ordering but jitter packet/application timestamps at sub-millisecond resolution instead of selecting only integer-millisecond offsets.
