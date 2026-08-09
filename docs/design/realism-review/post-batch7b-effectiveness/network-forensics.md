# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment: Synthetic**

**Verdict Confidence: 97**

**Synthetic-Confidence Score: 96**

## Executive Summary

The dataset is highly realistic at the architectural and formatting levels, but it contains network-accounting contradictions that packet-derived production telemetry should not produce.

The decisive defect is the SMB file accounting. Across all 196 SMB file records, the associated connection’s directional TCP payload is never larger than the file itself: it equals `total_bytes` in 172 cases and is smaller in 24. This leaves no bytes for SMB/NetBIOS framing in 87.8% of transfers and makes the file larger than the entire corresponding TCP payload in the remainder. Capture-loss metadata is also internally inconsistent: 401 TCP connections report nonzero `missed_bytes`, yet none has the expected `g/G` content-gap marker in Zeek `history`. Several file records remain complete despite the connection declaring missing content.

These hard and systemic contradictions outweigh substantial strengths: plausible TCP states, valid packet/IP-byte minima, realistic ephemeral-port ranges, coherent DNS types and responses, strong TLS cipher/certificate logic, and credible firewall/NAT/proxy topology.

## Evidence For Synthetic

- **hard_contradiction — SMB payload conservation fails systemically.** There are 196 SMB entries in `files.json`. For every one, the associated connection’s file-direction `orig_bytes` or `resp_bytes` is less than or equal to the file’s `total_bytes`; 172/196 are exactly equal and 24/196 are smaller. A TCP SMB stream must contain SMB framing in addition to file content.

  - `conn.json:11`, UID `C8zc1wpHOUjciGzJrK`, reports `resp_bytes:47250`.
  - `files.json:1` associates that UID with an SMB file having `seen_bytes:47250` and `total_bytes:47250`. This allocates zero bytes to SMB2/3 and NetBIOS Session Service framing.
  - The pattern is not isolated: 87.8% of all SMB files have exact file-to-connection equality.

- **hard_contradiction — extracted file bytes exceed the entire corresponding TCP payload.** In 22 SMB transfers, `seen_bytes` alone exceeds the connection’s directional payload by 36–559 bytes.

  - `conn.json:1869`, UID `CWBNWQnG474cH7g5bx`, reports `resp_bytes:46345` and `missed_bytes:587`.
  - `files.json:214` reports a fully observed SMB file with `seen_bytes:46904`, `total_bytes:46904`, and `missing_bytes:0`.
  - The extracted file is 559 bytes larger than all observed responder TCP payload, before allowing for any SMB framing. All 22 violations have `file missing_bytes:0`.

- **contract_gap — Zeek loss metadata is incompatible with connection history.** Of 6,547 connections, 401 report `missed_bytes > 0`; all 401 are TCP. None of their `history` strings contains Zeek’s `g/G` content-gap marker.

  - `conn.json:205`, UID `CpjWWhvtC1TKjJV3bV`, declares `missed_bytes:49586` but has history `ShADaDadfF`.
  - `conn.json:1869` similarly declares 587 missed bytes with history `ShADadTtFf`.
  - The absence is universal across the 401-record sample, making customized or isolated analyzer behavior unlikely.

- **hard_contradiction — large HTTP extraction ignores declared capture loss.** UID `CHlGsNTk6xq5t0gaHr` declares 32,770 missed bytes in `conn.json:4885`. Nevertheless:

  - `http.json:609` reports `response_body_len:93626042`.
  - `files.json:648` reports the same 93,626,042 bytes as both fully seen and total, with `missing_bytes:0`.
  - `conn.json` also gives `resp_bytes:93626042`, leaving zero bytes for the HTTP status line and headers. This simultaneously violates HTTP framing and loss propagation.

- **distribution_texture — repeated exact TLS durations are implausibly quantized.** Thirty-one unrelated successful TLS connections have duration exactly `1.2` seconds, and another seven have exactly `1.125` seconds. The 31 records span inbound and outbound paths, unrelated endpoints, different TCP histories, and approximately 4 KB to 396 KB of TCP payload.

  - `conn.json:25`, UID `CRYPYr6nn89EUk0ngk1`: `duration:1.2`, 12,711 payload bytes.
  - `conn.json:2319`, UID `C3ObJc0pr2JR3rks5`: `duration:1.2`, 166,576 payload bytes.
  - `conn.json:6144`, UID `CGVeMcYGxnsoUae3BAI`: `duration:1.2`, 391,863 payload bytes.

  Exact recurrence at this rate—38 of 1,103 successful SSL-classified connections—is characteristic of template duration selection rather than packet timestamp subtraction.

## Evidence For Real

- TCP state and packet accounting are otherwise well formed. Among 4,758 TCP connections, states include 3,214 `SF`, 1,273 `S0`, 111 `RSTO`, 69 `RSTR`, and smaller populations of `OTH`, `S1`, `S2`, `S3`, and `REJ`. SYN-only `S0` records consistently contain one originator packet and no responder packet.

- Across all 6,547 connections, there are no cases where payload exists without packets, no `ip_bytes < payload_bytes`, and no violation of minimum IPv4 plus TCP/UDP/ICMP header size.

- Source-port ranges reflect host-stack roles:

  - Workstations use Windows-style ephemeral ports beginning near 49152.
  - `10.44.20.30` and `10.44.30.10` use Linux-style ranges beginning near 32768.
  - High-volume external scanner sources maintain stable SYN header sizes across repeated probes.

- DNS texture is credible. The 1,057 records contain 679 A, 208 AAAA, 118 PTR, and 52 SRV queries; results include 938 `NOERROR`, 112 `NXDOMAIN`, and seven `SERVFAIL`. AAAA answers are IPv6, A answers are IPv4, SRV answers have valid priority/weight/port/target syntax, and all DNS RTTs equal the corresponding UDP connection durations.

- TLS mechanics are unusually strong:

  - 1,099 TLS records comprise 599 TLS 1.3 and 500 TLS 1.2 sessions.
  - Cipher suites are version-compatible.
  - There are 331 resumed sessions, all lacking retransmitted certificate chains as expected.
  - All 346 visible leaf chains resolve through `cert_chain_fuids` into `files.json` and `x509.json`.
  - All visible SNI names match their leaf SANs, and no certificate is outside its validity interval.
  - `ssl.json:2`, `files.json:2-3`, and the corresponding X.509 records provide a coherent two-certificate TLS 1.2 chain for UID `CRYPYr6nn89EUk0ngk1`.

- Firewall and NAT behavior is credible at the individual-record level. For example, ASA connection 1206848 in `cisco_asa.log:3-4` maps public `45.83.220.5:443` to `10.44.30.10:443`. Its reported 53,343 bytes exactly equal the two Zeek IP-byte counters in `conn.json:5`, while its teardown reason matches Zeek `SF`.

- The explicit-proxy topology is plausible. Workstations predominantly connect to `10.44.20.30:8080`; the proxy generates external HTTP/TLS egress, while ASA PAT translates successful egress through `45.83.220.1`. Proxy actions include forwarding, tunneling, TLS inspection, authentication challenges, denies, and gateway errors.

- The 50 IDS alerts have plausible signatures and visible matching tuples. Their trigger timestamps fall 9–57 milliseconds after the corresponding Zeek connection starts, and HTTP, ICMP, and STUN classifications appear on suitable protocols.

## Detailed Analysis

**Capture profile.** The network observation covers 2024-05-14 12:00:05–17:59:31 UTC. Hourly connection counts are 1,118, 1,215, 1,267, 962, 1,001, and 984. This is a reasonably textured six-hour window rather than a fixed-rate stream.

**Connection composition.** The dataset contains 4,758 TCP, 1,689 UDP, and 100 ICMP records. Major services include 1,190 SSL, 1,059 DNS, 875 Kerberos, 772 HTTP, 763 SMB, 343 LDAP, 48 SSH, and smaller RDP, PostgreSQL, RPC, and SMTP populations. Failed external scans produce realistic `S0`, `REJ`, and reset states, while identified protocols overwhelmingly use established flows.

**Packet accounting.** IP-byte and packet counts obey minimum physical sizes. UDP records consistently account for 28 bytes of IP/UDP overhead per packet. TCP records show varied 40–60-byte header structures and retransmission-sensitive history strings. The defect is at the application-to-transport boundary: file sizes were evidently assigned as connection payload rather than embedded within framed SMB or HTTP streams.

**DNS and caching.** All 1,057 DNS records use `10.44.20.10:53` as resolver, with mixed internal authoritative and recursive behavior. Internal AD discovery uses Kerberos and LDAP SRV records. External A/AAAA TTLs have substantial variation, while internal records use stable 600, 3,600, and 86,400-second values. Of 768 proxy-originated external connections, 480 have a same-client, same-address DNS answer still within its visible TTL; the remainder can plausibly involve application caching, connection reuse, or queries outside the window. No systematic connection-before-DNS inversion was established.

**TLS and certificates.** TLS timestamps fall inside their parent connection intervals, certificate file identifiers resolve correctly, and certificate transmission direction is correct for inbound and outbound handshakes. The repeated portal leaf certificate is stable across connections, while external services show diverse RSA/ECDSA chains and issuers. This is one of the dataset’s strongest realism areas.

**Firewall, proxy, and sensor paths.** The network view consistently places public inbound services behind `45.83.220.5` on `10.44.30.10`. Outbound proxy traffic is dynamically translated through `45.83.220.1`. ASA build/teardown pairs, Zeek tuples, endpoint FLOW direction, and IDS tuples are individually coherent. Endpoint FLOW records also preserve host-relative direction correctly; no flow on a modeled host reverses local source/destination semantics.

**External and lateral behavior.** External traffic concentrates on the DMZ web host and includes broad Internet scanning of ports 22, 23, 25, 80, 443, 445, 3389, and related services. Internal traffic shows AD Kerberos/LDAP use, SMB access to file and domain-controller systems, explicit proxying, SSH administration, and limited RDP. The topology and ephemeral-port behavior are credible. The authenticity verdict does not rely on the attack sequence being clean or correlated.

## Synthetic Indicator Summary

| Indicator | Label | Scope | Materiality |
|---|---|---:|---|
| SMB connection payload never exceeds file total | `hard_contradiction` | 196/196 SMB files | Decisive |
| Fully seen SMB file exceeds directional TCP payload | `hard_contradiction` | 22 files; excess 36–559 bytes | Decisive |
| Nonzero Zeek `missed_bytes` without `g/G` history | `contract_gap` | 401/401 gapped connections | High |
| Complete 93.6 MB HTTP file despite 32,770 missed bytes and no header allowance | `hard_contradiction` | One high-volume transfer | High |
| Exact 1.2/1.125-second TLS durations across unrelated flows | `distribution_texture` | 38/1,103 successful SSL flows | Moderate |
| Correct but exceptionally regular application/transport linkage | `weak_signal` | Multiple sources | Low; not used independently |

## Realism Score by Category

| Category | Score | Assessment |
|---|---:|---|
| Field format accuracy | 7/10 | Schemas and native-looking values are strong, but loss-history and application-byte contracts fail. |
| Temporal patterns | 7/10 | Good hourly variation and subsecond ordering; repeated exact TLS durations reduce realism. |
| Cross-source correlation | 9/10 | Tuples, UIDs, NAT, IDS, TLS chains, and endpoint directions correlate very well. |
| Behavioral realism | 8/10 | Proxy, AD, SMB, Internet scanning, and administrative traffic are plausible. |
| Environmental consistency | 9/10 | Host roles, address zones, source-port ranges, proxy paths, and exposed DMZ services agree. |

## Recommendations

1. Derive connection payload accounting from protocol-framed bytes. For SMB transfers, add NetBIOS and SMB2/3 request/response headers, control messages, and acknowledgments around the file content. Enforce `directional_tcp_payload > file_total_bytes` for clear, extracted SMB files.

2. Use a single loss model across connection and file analysis. Any TCP content gap should update Zeek `history` with `g/G`, reduce file `seen_bytes`, increase file `missing_bytes`, and suppress full-file hashes when required bytes were not observed.

3. Apply the same invariant to HTTP: connection payload must include status/request lines and headers in addition to body bytes. A fully seen response body cannot equal all responder TCP payload.

4. Derive connection durations from simulated packet timing rather than selecting protocol-level constants such as 1.2 or 1.125 seconds. Add microsecond-scale timing variation based on RTT, packet count, congestion, and close behavior.

5. Add automated conservation tests covering:

   - `file seen_bytes <= directional connection payload`;
   - `file total_bytes + framing <= directional payload` for complete files;
   - nonzero `missed_bytes` implies compatible connection history;
   - file gaps and hashes agree with transport loss;
   - HTTP bodies leave room for headers;
   - source-specific timestamps stay within the canonical connection interval.

6. Preserve the existing TLS chain logic, DNS type correctness, OS-specific ephemeral ranges, NAT topology, and firewall/IDS tuple semantics; these materially improve investigative realism.
