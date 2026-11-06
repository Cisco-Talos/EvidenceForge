# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 38

## Executive Summary

The Zeek core, DMZ, and database records show internally plausible TCP states, DNS responses, TLS versions, and protocol-specific connection lifecycles. A proxy request, proxy-side DNS lookup, resolved address, and matching upstream TLS session form a coherent ordered chain; Snort alerts also align with visible DNS traffic. The clearest reservation is a DHCP-identified Mac address carrying a large volume of iPhone user-agent traffic alongside Mac browser traffic, which is unusual but can result from shared use or user-agent emulation.

## Evidence For Synthetic

- [weak_signal] In `zeek-core/http.json`, source `10.10.1.41` issued 272 requests with an iPhone OS 17.2 user agent between 2026-11-02 13:39:28 and 18:32:33 UTC, 64 with a macOS Safari 26 user agent between 13:08:38 and 18:38:39, and 26 with a macOS Chrome/155 user agent between 13:30:53 and 18:39:21. `zeek-core/dhcp.json` maps `10.10.1.41` to MAC `d4:be:d9:a1:ac:76`, hostname `MAC-MROSS-01`. Several browser identities on this one leased endpoint are possible through emulation or shared use, but the high iPhone share is a modest environment/identity plausibility concern.

## Evidence For Real

- The connection state and packet-counter combinations examined across `zeek-core/conn.json`, `zeek-dmz/conn.json`, and `zeek-db/conn.json` were valid: completed `SF` sessions had packets in both directions, `S0` sessions did not show responder packets, rejected connections had reset traffic, and no negative durations appeared. The mix includes successful sessions, unanswered attempts, resets, and rejects rather than only completed flows.
- The proxy and upstream TLS records demonstrate sensible causal ordering. At 2026-11-02 14:18:17.098 UTC, `zeek-core/http.json` records a successful HTTP/1.1 `CONNECT downloads.cloud.com:443` from `10.10.2.10:65299` to proxy `10.10.3.20:8080` (`status_code=200`). At 14:18:17.103, `zeek-core/dns.json` records the proxy querying `downloads.cloud.com` and receiving `23.45.127.51` and `23.45.126.51` with 30-second TTLs. At 14:18:18.621, `zeek-dmz/conn.json` records proxy `10.10.3.20:58684` connecting to `23.45.127.51:443`; `zeek-dmz/ssl.json` associates that connection with SNI `downloads.cloud.com`, TLS 1.3, and `TLS_AES_128_GCM_SHA256`.
- Zeek protocol companions are linked to connection UIDs throughout the examined sets: DNS, HTTP, SSL, SMTP, and SMB companion records in `zeek-core` and the available DNS, HTTP, SSL, and file records in `zeek-dmz` and `zeek-db` all resolved to connection records. Companion timestamps follow connection start times by small, plausible intervals. For example, `zeek-core/http.json` HTTP records have a median offset of about 0.094 seconds from their connection timestamps; `zeek-dmz/ssl.json` has a median offset of about 0.117 seconds.
- Protocol behavior and field values are varied and plausible for the observed roles. `zeek-core/dns.json` contains A, AAAA, PTR, SRV, TXT, and other query types, with NOERROR, NXDOMAIN, SERVFAIL, and REFUSED responses. The DMZ has both TLS 1.2 and TLS 1.3 sessions with common AES-GCM and ChaCha20 ciphers. `zeek-db/conn.json` is dominated by MySQL traffic, consistent with a database sensor view.
- Network alerts have corresponding traffic. For example, `snort-core/snort_alert.log` flags a `.tk` DNS query from `10.10.3.10:35707` at 13:16:12.652 UTC. `zeek-core/dns.json` records that tuple at 13:16:12.410 UTC querying `status-brnbiakv.tk` for an A record, with `SERVFAIL`. The alert follows the visible query by about 0.24 seconds.
- The perimeter records include ordinary lifecycle diversity. `fw-perimeter/cisco_asa.log` shows built and torn-down TCP and UDP connections, denied traffic, and an inbound TCP attempt ending in `SYN Timeout`; these are compatible with the mix of sessions and unsuccessful attempts visible in the network evidence.

## Detailed Analysis

### Connection and transport behavior

The supplied Zeek connection logs span roughly six hours on 2026-11-02. `zeek-core/conn.json` contains 12,532 records, `zeek-dmz/conn.json` 9,830, and `zeek-db/conn.json` 449. Core traffic includes TCP, UDP, and ICMP; DMZ traffic is predominantly TCP; the database view is predominantly TCP and mostly MySQL. The connection states are varied: core has 10,294 `SF`, 1,869 `S0`, 170 `RSTO`, 91 `RSTR`, 35 `REJ`, and smaller counts of other states; DMZ has 6,816 `SF` and 2,805 `S0`, plus resets and other states; database connections include successful, rejected, reset, and incomplete flows. The packet counters and histories examined are consistent with those states.

A concrete perimeter example shows an inbound TCP connection to `10.10.3.10:8080` at 13:00:35, followed by a 30-second `SYN Timeout` teardown at 13:01:05 in `fw-perimeter/cisco_asa.log`. This is a plausible unanswered attempt and is not evidence of an impossible connection lifecycle.

### DNS, proxy, and TLS

The 14:18 `downloads.cloud.com` chain above is a useful end-to-end example: the client requests the tunnel, the proxy resolves the destination, and the proxy then opens the TLS connection to one of the returned addresses. The separate sensor UIDs and tuples are expected because the proxy terminates the client-side CONNECT and originates a distinct upstream connection. The Zeek DNS, HTTP, SSL, and connection records therefore agree in host, address, and visible event order without requiring their UIDs to match across those separate sessions.

Across the core and DMZ, HTTP includes CONNECT, GET, and POST methods, and TLS uses both TLS 1.2 and TLS 1.3 with commonly seen cipher suites. Five SSL records have `established=false` in core and four in DMZ; a small number of incomplete TLS handshakes is credible. Some connections have no SSL version or cipher populated, which is compatible with incomplete handshakes and does not establish a schema defect.

### Alerts and network ownership

The perimeter and core Snort logs include DNS, scan, CONNECT, and other alerts. The `.tk` example is directly corroborated by the Zeek DNS tuple, query, and failure response. Internal DHCP records also make the apparent network locations interpretable: the core sensor maps workstation and Mac addresses to hostnames, and the database sensor shows `10.10.4.10` contacting the MySQL service. These host-role clues are consistent with the DNS, proxy, and database service patterns visible in Zeek.

The main ambiguity is the three user-agent families at `10.10.1.41`. DHCP identifies that address as `MAC-MROSS-01`, but its dominant iPhone user agent is not the identity expected from the hostname alone. This is not a packet or protocol contradiction: a user agent is client-supplied text, and the network evidence does not establish whether the endpoint used emulation, shared access, or another application. It remains a limited plausibility concern rather than decisive evidence of synthetic generation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `weak_signal` | `zeek-core/http.json` with `zeek-core/dhcp.json` | One DHCP-mapped endpoint, `10.10.1.41` / `MAC-MROSS-01` | Its high count of iPhone user-agent requests alongside Mac browser user agents is unusual, but user-agent strings are spoofable and the records do not prove a contradiction. This kept the score above a strongly production-like assessment without making the verdict Synthetic. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek fields and source-native state/protocol values examined are plausible; no impossible field combination was found.
- **Temporal patterns:** 8 — Connection and protocol companion timestamps are close and lifecycle-consistent; the proxy/DNS/upstream TLS sequence is correctly ordered.
- **Cross-source correlation:** 9 — Zeek UID companions and the sampled Snort DNS alert agree with the corresponding visible traffic.
- **Behavioral realism:** 7 — Protocol and state variety is credible; the browser identity mixture on one Mac-mapped address is mildly unusual.
- **Environmental consistency:** 7 — Hostnames, DHCP addresses, proxy behavior, DMZ TLS, and database traffic align overall, with the `10.10.1.41` browser-family ambiguity as a reservation.

## Recommendations

- If this were synthetic, bind browser user-agent profiles to modeled endpoints more deliberately or represent an explicit browser-emulation/shared-client context for `10.10.1.41`. The current mix is possible, but without such context it stands out against the DHCP hostname `MAC-MROSS-01`.
- Keep the proxy-side DNS request and upstream TLS connection ordered after the client CONNECT, as in the 14:18 `downloads.cloud.com` chain. That sequence is especially useful because it makes the separate client and upstream sessions understandable from network telemetry alone.
