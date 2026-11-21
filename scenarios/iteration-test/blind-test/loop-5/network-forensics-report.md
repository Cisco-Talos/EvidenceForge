# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 38

## Executive Summary

The supplied network evidence is mostly production-like, with realistic protocol mixtures, capture imperfections, sensor clock offsets, and coherent application-to-transport relationships. I found one isolated dangling SMB connection reference, but no demonstrated impossible ordering, packet-accounting contradiction, or TLS/certificate contradiction; the network evidence alone does not justify a confident real-versus-synthetic attribution.

## Evidence For Synthetic

- [weak_signal] `zeek-core/smb_mapping.json` contains UID `CLdoPIvfhoFQpKDWCvu` at `1793640924.870255` (2026-11-02 17:35:24.870255 UTC), mapping `10.10.1.22:50839` to `10.10.2.20:445`, without that UID in the supplied core connection file. No matching tuple was found in the supplied core or DMZ connection records. This is an isolated reference-integrity irregularity, explainable by record loss or selective export; it is not sufficient evidence of synthetic origin and has only minor weight. I do not infer that an unobserved transport did not exist.
- No high-impact synthetic indicator survived the transport, protocol, certificate, and cross-sensor checks described below. In particular, complete correlation is not treated as suspicious, and the six-hour collection window is not treated as a complete lifecycle capture.

## Evidence For Real

- All supplied DNS, HTTP, SSL, and SMTP rows with a single connection UID matched a same-sensor connection with the same endpoint tuple; their timestamps fell inside the corresponding recorded connection intervals. This is evidence of technical coherence, although a careful generator could also produce it.
- The core sensor has 12,095 connections with nine connection states, including 1,643 `S0`, 154 `RSTO`, 106 `RSTR`, and 28 `REJ`, rather than an implausible all-success population. The DMZ sensor has 2,495 `S0` among 9,798 connections, consistent with its substantially different exposure and traffic mix.
- TLS 1.3 records do not expose certificate chains: zero of 231 core and zero of 1,956 DMZ TLS 1.3 rows contain `cert_chain_fuids`. This respects passive observation limits rather than fabricating visible encrypted certificates.
- TLS 1.2 certificate key types agree with their negotiated authentication ciphers, repeated certificate fingerprints retain stable metadata, and certificate-chain issuer/subject links agree in the supplied X.509 records.
- Capture imperfections are represented coherently. For example, core connection `CRU4kpUSxtqCSeNgPv` has `missed_bytes=32768` and history `ShADadfFG`; its apparent deficit between sequence-space payload and captured IP bytes is explained by the logged gap.
- DNS contains A, AAAA, PTR, SRV, TXT, MX, NS, and SOA queries, including NXDOMAIN, SERVFAIL, REFUSED, and successful responses without answer data. Core UID `CSpZAop5VyqxwXmms8`, at `1793624433.560457`, records an NXDOMAIN for `wpad.meridianhcs.local`, a plausible discovery failure.
- Multiple sensor observations preserve flow identity while retaining sensor-specific timestamps. Among matched core/DMZ flows, the median timestamp difference is approximately 114 ms; the database/DMZ median is approximately 180 ms. These offsets are mutually compatible and should not be mistaken for application causality failures.

## Detailed Analysis

### Scope and method

I examined only the supplied data and my assigned briefing. The primary population was all JSON rows under `zeek-core`, `zeek-db`, and `zeek-dmz`, including connection, DNS, HTTP, SSL, X.509, file, OCSP, SMB, DHCP, SMTP, and PE records where present. I also inspected representative perimeter ASA, proxy-access, and Snort records. Endpoint data was used only to inspect the shape of an example FLOW record; I did not conduct an endpoint authenticity assessment.

The connection population comprises 12,095 core, 9,798 DMZ, and 465 database observations. These are sensor observations and must not be added together as a count of unique network sessions. The core first/last connection starts are 13:00:02.649837 and 18:59:49.834286 UTC on 2026-11-02; the database view starts later and ends earlier. I did not penalize activity for lacking an initiator or terminator outside that slice.

### Transport states and packet accounting

Core protocol counts are TCP 6,725, UDP 4,959, and ICMP 411. Database traffic is predominantly TCP (396 of 465), whereas the DMZ has 8,346 TCP, 1,152 UDP, and 300 ICMP connections. Connection histories include orderly closes, resets, retransmissions, gaps, and one-sided traffic. I found no TCP `SF` record lacking both originator and responder FIN history, and no `S0` record reporting responder packets or responder payload.

I checked whether captured IP bytes could accommodate payload plus minimum IPv4/TCP or IPv4/UDP headers. Initial apparent deficits affected 86 core, five database, and 85 DMZ directional observations. Every deficit was within that connection's recorded `missed_bytes`; these are not demonstrated impossible byte counts because Zeek sequence-space payload can include uncaptured data. Among UDP rows without capture gaps, the IP-byte/payload difference was exactly 28 bytes per packet, compatible with IPv4/UDP headers. I found no tested connection exceeding 10 Gbit/s on its recorded IP-byte count and duration; this is a sanity check, not a claim about link capacity.

Successful remote-service durations are not all fixed: core TCP/22 `SF` sessions span approximately 1.387 to 13,318.275 seconds, while core successful TCP/3389 sessions span approximately 123.565 to 3,485.770 seconds. The short SSH example could be a brief exchange or failed application authentication despite a normally closed TCP transport; `SF` does not prove a successful SSH login.

### DNS content and timing

Core DNS has 3,203 rows: 2,380 A, 323 AAAA, 253 TXT, 132 PTR, 98 SRV, nine MX, six NS, and two SOA. Core response codes include 224 NXDOMAIN, nine SERVFAIL, and six REFUSED. DMZ DNS has 1,083 rows with 144 NXDOMAIN; database DNS has 50 rows. The differing mixes fit differing visibility and host roles without requiring every host to emit all protocol families.

DNS round trips range from 61 microseconds to approximately 2.339 seconds in the core view. TTLs include infrastructure-sized values and shorter external values, rather than one universal constant. A/AAAA answers that parse as IP addresses have the correct address family. I did not compare sanitized names against live public DNS, and I did not require a new DNS lookup before every connection: caches, literal addressing, proxy resolution, and pre-window lookups all matter.

For cross-sensor DNS, I matched tuples, protocol, query, transaction ID, and timestamps within one second. All 1,080 matched core/DMZ observations and all 50 matched core/database observations agreed on response code, answer data, and TTLs. Different sensor UIDs are expected and were not interpreted as conflicting identities.

### HTTP, proxy, and TLS

The 2,359 core HTTP rows contain 2,143 CONNECT requests, 212 GETs, and four POSTs. The DMZ has 2,617 HTTP rows, including 2,181 CONNECT requests. Consequently, the apparent volume of HTTP records should not be interpreted as that much unencrypted browsing: most observed HTTP is explicit-proxy tunnel establishment. Authentication and gateway failures occur alongside successful responses, including 403, 407, 502, 503, and 504.

At the start of the window, DMZ connection `CYojqFDPCJdzCFXCYk` observes `10.10.2.30:37659` connecting to `10.10.3.20:8080`. Its HTTP record requests `CONNECT api.carepoint.com:443`. A separate proxy-originated connection, `C8cJFHtsgeUYKITdHMu`, runs from `10.10.3.20:60315` to `23.72.175.240:443`, with matching TLS SNI. The proxy access log records the CONNECT request at 13:00:03 UTC and distinguishes CONNECT control-message bytes from tunnel bytes. ASA records show the corresponding proxy egress NAT translation and connection construction. This is a plausible two-leg proxy path, rather than a mistaken expectation that client and server legs share one tuple.

The TLS populations include TLS 1.2 and TLS 1.3, resumption, and incomplete handshakes. Resumed sessions comprise 141 of 450 core rows, 11 of 26 database rows, and 992 of 2,963 DMZ rows. Modern AES-GCM and ChaCha20 suites coexist with older internal TLS 1.2 CBC suites. Older suites alone are not proof of synthesis.

I checked all available leaf certificate/cipher pairings: no RSA-versus-ECDSA authentication mismatch was found. No available leaf certificate was outside its validity interval at the corresponding SSL timestamp. Repeated fingerprints had stable certificate fields within each sensor. Available certificate-chain links had matching issuer/subject names. The sum of extracted certificate sizes never exceeded the connection's response payload. HTTP body sizes likewise never exceeded their owning connection's directional payload totals. STARTTLS SMTP rows marked `tls=true` did not also claim decrypted sender/recipient/body metadata in the examined SMTP population.

### Multiple sensors and collection interpretation

Matching connection tuples within one second produced 4,995 core/DMZ pairs, 308 database/DMZ pairs, and 155 core/database pairs. No matched pair disagreed on connection state, and no directional payload difference exceeded the combined logged capture-loss allowance. Timestamp differences are consistent with separate sensor clocks: core minus DMZ ranges approximately 110–118 ms, and database minus DMZ approximately 169–188 ms. Core minus database has a median of approximately -62 ms, consistent with those other offsets.

Hourly core connection starts are 1,627, 3,322, 1,698, 1,744, 2,037, and 1,667 from 13:00 through 18:59 UTC. The second-hour elevation also occurs in the DMZ. This is visible burstiness, but the six-hour slice cannot establish a daily business-hours curve or overnight behavior. I do not score the missing rest of the day as a defect.

The one SMB mapping without a supplied connection reference is a legitimate follow-up target. However, an isolated omitted connection record is consistent with export or collection loss and does not establish a self-contradictory collection profile. The remaining evidence supports plausibility rather than provenance: none of these consistency checks can distinguish real telemetry from a sufficiently careful synthetic dataset by itself.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek SMB/connection reference | One core mapping UID, `CLdoPIvfhoFQpKDWCvu`, absent from supplied connection records | Minor unresolved irregularity; record loss/export filtering remains a credible explanation. |
| No demonstrated high-impact indicator | Transport, DNS, HTTP/proxy, TLS/X.509 | All supplied primary Zeek populations checked | No hard contradiction or strong distribution artifact established; prevents a high synthetic-confidence score. |

## Realism Score by Category

- **Field format accuracy:** 9 — JSON types, address families, protocol fields, packet accounting, and certificate identities are coherent in the checks performed.
- **Temporal patterns:** 9 — Protocol rows fit connection intervals, remote-service durations vary, and cross-sensor clock differences are compatible.
- **Cross-source correlation:** 9 — Tested protocol/connection and sensor-to-sensor relationships agree, with one isolated SMB reference omission.
- **Behavioral realism:** 8 — Proxy use, failures, scans, infrastructure traffic, and varied remote-session durations are plausible; only a limited daytime window is visible.
- **Environmental consistency:** 9 — Core, DMZ, and database views have differentiated traffic mixes and a coherent explicit-proxy/NAT path.

## Recommendations

- If this were synthetic, resolve or deliberately account for the missing `CLdoPIvfhoFQpKDWCvu` connection reference at 17:35:24.870255 UTC. If the gap represents an export or collection policy, retain enough collection metadata for an analyst to distinguish that policy from an accidental orphan. This recommendation does not imply that all collected source rows must match perfectly.
