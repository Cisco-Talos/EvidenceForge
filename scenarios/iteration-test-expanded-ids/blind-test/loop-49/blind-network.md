# Network Forensics — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 72/100  
**Synthetic-Confidence Score:** 68/100

## Executive Summary

The dataset is likely synthetic, but it is technically sophisticated and largely contract-consistent. Zeek child records align with their parent connections, TCP/UDP state and history fields are generally coherent, firewall lifecycles are complete, and proxy/TLS semantics are substantially more realistic than simple fabricated logs.

The synthetic judgment rests primarily on distributional and collection-texture signals rather than hard protocol contradictions:

- All 1,857 matching core/DMZ flow observations place the DMZ timestamp after the core timestamp within an unusually narrow 41.655–66.399 ms band.
- DHCP renewals exhibit almost perfectly stable, client-specific periods with roughly one second of jitter across six hours.
- Public HTTP traffic is built from a very small reusable vocabulary: 64 requests from 60 external IPs use only seven user agents and eleven URIs.
- Several timing fields show distinct generated regimes, such as external DNS RTTs frequently landing on exact millisecond values while internal RTTs retain microsecond texture.

No decisive `hard_contradiction` was found. The result therefore belongs in the “likely synthetic” range, not “confidently synthetic.”

## Evidence For Synthetic

1. **`distribution_texture` — Mechanically stable DHCP renewal schedules**

   All 69 DHCP records are `["REQUEST","ACK"]`. Within each client, renewal intervals remain extremely close to a fixed client-specific period:

   - `10.10.1.21`: ten intervals from 1939.921 to 1941.305 seconds.
   - `10.10.1.22`: twelve intervals from 1786.993 to 1788.470 seconds.
   - `10.10.1.31`: ten intervals from 1968.192 to 1970.870 seconds.
   - `10.10.1.32`: eleven intervals from 1691.360 to 1693.607 seconds.
   - `10.10.1.35`: five intervals from 3840.746 to 3842.451 seconds.
   - `10.10.1.36`: two intervals of 7907.946 and 7906.975 seconds.

   Stable DHCP renewal timers are realistic, but the combination of per-client arbitrary base periods and uniformly tiny jitter is characteristic of periodic-plus-jitter generation.

2. **`environment_or_collection_plausibility` — Uniformly positive, tightly bounded inter-sensor timestamp displacement**

   There are 1,857 matching five-tuples between `zeek-core/conn.json` and `zeek-dmz/conn.json`. Every DMZ observation follows its core counterpart:

   - Minimum offset: 41.655 ms.
   - Median offset: 55.677 ms.
   - Maximum offset: 66.399 ms.
   - No negative offsets.

   For sensors observing traffic across an internal firewall, packet timestamps would normally show a smaller transit delay, a relatively stable clock skew, or occasional sign variation from independent clock behavior. A strictly positive bounded jitter envelope looks more like a modeled sensor-latency rule.

3. **`distribution_texture` — Restricted public-web request vocabulary**

   The DMZ HTTP log contains 64 inbound HTTP requests from 60 external source IPs, yet those requests use:

   - Only seven user-agent strings.
   - Only eleven URI values.
   - Only `GET`.
   - Predominantly one request per external address.

   The URI pool is limited to values such as `/`, `/index.html`, `/login`, `/dashboard`, `/api/v1/status`, `/api/v2/data`, `/assets/app.js`, and `/favicon.ico`. Except for three Bingbot requests from one address, public clients repeatedly draw from the same contemporary corporate-browser user-agent pool. Real Internet traffic over six hours normally has more malformed clients, scanners, bots, odd methods, missing or unusual user agents, and long-tail request paths.

4. **`distribution_texture` — Discrete external DNS latency regime**

   External DNS RTTs land on exact millisecond boundaries much more often than internal requests:

   - Core external DNS: 262 of 999 RTTs, 26.2%.
   - DMZ external DNS: 262 of 648 RTTs, 40.4%.
   - Internal DNS: zero exact-millisecond RTTs at either sensor.

   Examples recurring across the logs include exactly `0.015`, `0.028`, `0.035`, `0.064`, `0.085`, `0.096`, `0.105`, and `0.111` seconds. Separate internal and external latency models are sensible, but the sharp precision boundary suggests external RTTs are sometimes selected from a discretized pool.

5. **`weak_signal` — Highly curated Internet-background actors**

   The public HTTPS service receives 754 TLS sessions with SNI `ehr-portal.meridianhcs.com`. One address, `185.70.41.45`, accounts for 329 sessions over approximately 48 minutes, all using TLS 1.3 with `TLS_AES_128_GCM_SHA256`; 172 are full handshakes and 157 resumed.

   This is possible as load testing or abusive traffic, but alongside the small HTTP vocabulary it resembles a generated “high-volume source” pattern more than naturally heterogeneous public traffic.

6. **`weak_signal` — Traffic-generation families remain visibly compartmentalized**

   Internal DNS RTTs have microsecond-scale variation, external DNS sometimes uses millisecond grids, DHCP uses fixed client cadences with roughly one-second jitter, and inter-sensor duplication uses a 42–66 ms envelope. Each model is plausible alone, but the clean separation of timing regimes is a synthetic-generation tell.

## Evidence For Real

1. **`contract_gap` rebuttal — Zeek parent/child lifecycle contracts are intact**

   Across both sensors:

   - Every DNS, HTTP, and SSL record has a matching `conn.json` UID.
   - No DNS, HTTP, or SSL record precedes its parent connection.
   - No such child record falls after the connection’s recorded close.
   - Median child offsets are plausible: HTTP approximately 96–112 ms and TLS approximately 316–330 ms after connection start.

2. **`schema_or_format` — Zeek records are structurally credible**

   The dataset uses plausible Zeek fields and values:

   - DNS includes transaction IDs, RTT, qclass/qtype names, flags, answer arrays, TTL arrays, and rcodes.
   - TCP histories vary meaningfully rather than using one template.
   - State distribution includes `SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `S1`, `S2`, `S3`, and `OTH`.
   - UDP DNS commonly uses `Dd`, while unanswered UDP traffic uses `S0` with originator data.
   - No lower-bound inconsistencies were found between payload bytes, packet counts, and IP-byte counts.

3. **`contract_gap` rebuttal — TLS and certificate references are coherent**

   Certificate-chain FUIDs referenced by SSL records all resolve in both `files.json` and `x509.json`:

   - Core: 88 references, zero missing.
   - DMZ: 506 references, zero missing.

   No certificate was outside its validity period at observation time. Repeated certificate serial/subject/issuer identities consistently retain the same fingerprint.

4. **`environment_or_collection_plausibility` — Dual-sensor visibility is sensibly scoped**

   The core sensor observes heavy DNS, Kerberos, SMB, LDAP, proxy, and internal-service activity. The DMZ sensor observes extensive external TLS, inbound scanning, proxy-origin traffic, and public web requests. Client-to-proxy connections appear at both sensors with different sensor-local UIDs, which is reasonable.

5. **`contract_gap` rebuttal — Firewall connection lifecycles are unusually complete but valid**

   The ASA log contains:

   - 4,137 TCP builds and 4,136 TCP teardowns, leaving one connection open at the window boundary.
   - 795 UDP builds and 795 UDP teardowns.
   - 1,057 dynamic TCP translation builds and 1,057 translation teardowns.
   - Teardown reasons including `TCP FINs`, `SYN Timeout`, `TCP Reset-O`, and `TCP Reset-I`.

   Declared TCP durations agree with second-resolution build/teardown timestamps within normal rounding.

6. **`contract_gap` rebuttal — Proxy semantics are internally convincing**

   The proxy log distinguishes:

   - `tunnel`, `tunnel-setup`, `ssl-inspect`, `forward`, `deny`, `auth-required`, and `gateway-error`.
   - CONNECT control-message bytes from tunneled client/server byte totals.
   - Peek/bump/terminate behavior.
   - Authenticated and unauthenticated identities.
   - Correct unauthenticated identities for all HTTP 407 responses.

   All 1,916 parsed rows have their main response-byte field equal to `sc_bytes`.

7. **`schema_or_format` — HTTP transaction depth is not naively fixed**

   Although most connections contain one request, persistent connections correctly progress through transaction depths 2–7. POST records carry request bodies, while GET and CONNECT records do not.

8. **`environment_or_collection_plausibility` — IDS alerts have corresponding traffic**

   Every parseable TCP/UDP Snort alert had a matching five-tuple in the appropriate Zeek sensor. Alert-to-connection timing differences remained within roughly 70 ms. This is strong sensor-level coherence, though completeness alone is not evidence of authenticity.

## Detailed Analysis

### Zeek Flows

Connection-state and history combinations are generally plausible. Successful TCP sessions contain varied histories reflecting retransmissions, resets, and teardown asymmetry. Failed inbound scans commonly appear as `S0` with a single SYN, and rejected sessions use `REJ`/`Sr`. Packet/byte accounting is arithmetically defensible.

The main authenticity concern is the dual-sensor timing model. Matching observations preserve state and usually preserve byte accounting, but all DMZ timestamps are delayed by a narrowly bounded positive amount. The sensor-local UIDs themselves are appropriate; the suspicious element is the offset distribution.

### DNS

DNS behavior has credible diversity: A, AAAA, TXT, PTR, SRV, NS, MX, and SOA appear, together with NOERROR, NXDOMAIN, SERVFAIL, and REFUSED. Internal authoritative responses generally have `AA=true`, while external recursive results usually have `AA=false, RA=true`. Empty-answer NOERROR responses are present and not automatically contradictory.

The exact-millisecond external RTT component and recurring canned TTLs weaken authenticity. The most common core TTL values include 300, 1800, 3600, 1, 30, 3, 7200, and 86400 seconds. Those values are individually normal, but the overall distribution looks pool-driven.

### HTTP and Proxy

Internal HTTP behavior is comparatively strong. CONNECT dominates the inside-to-proxy view, while the proxy access log contains decrypted HTTPS GET/POST records under `ssl-inspect`. Denials, authentication challenges, gateway failures, redirects, partial content, and cached 304 responses add useful variation.

The public-server traffic is less convincing. It uses too few request paths, methods, and clients for a genuinely Internet-facing service. The request outcomes also appear selected from a compact template set rather than arising from a richer application surface.

### TLS and X.509

TLS versions and ciphers are plausible for the stated period:

- TLS 1.3 with AES-128-GCM, AES-256-GCM, and ChaCha20.
- TLS 1.2 with ECDHE RSA/ECDSA GCM and limited CBC use.
- Resumed and full sessions.
- STARTTLS-associated SSL on SMTP ports, HTTPS, IMAPS, and LDAPS.

Certificate identities, fingerprints, validity windows, and file references are coherent. This is one of the dataset’s strongest realism areas.

### Firewall

ASA formatting, PRI/severity alignment, connection directions, NAT translations, access-group denies, lifecycle pairing, teardown causes, duration rounding, and byte fields are credible. The firewall apparently permits inbound embryonic sessions to numerous DMZ ports, including 22, 23, 445, and 3389, which is operationally questionable but not impossible for a deliberately exposed or monitored environment.

### IDS

Snort formatting and alert classifications are plausible. TCP/UDP alerts correlate to visible traffic with realistic sub-second timing displacement. Multiple ICMP signatures can fire on closely related packets, which is consistent with overlapping rule coverage.

The alert set is somewhat curated—common suspicious TLDs, BitTorrent, scans, and ICMP—but there is no log-visible semantic contradiction sufficient to elevate this beyond a weak signal.

## Synthetic Indicator Summary

| Indicator | Label | Strength | Log-visible basis |
|---|---|---:|---|
| Fixed per-client DHCP periods | `distribution_texture` | Strong | Repeated intervals remain within about 1–3 seconds of client-specific periods across the full window |
| One-way bounded core-to-DMZ offset | `environment_or_collection_plausibility` | Strong | All 1,857 matches are DMZ-later by 41.655–66.399 ms |
| Small public HTTP vocabulary | `distribution_texture` | Strong | 64 requests, 60 source IPs, seven UAs, eleven URIs, only GET |
| Discrete external DNS RTTs | `distribution_texture` | Moderate | 26.2%–40.4% exact-millisecond external RTTs versus none internally |
| Concentrated HTTPS source pattern | `weak_signal` | Moderate | One source produces 329 same-cipher sessions in about 48 minutes |
| Distinct timing “families” | `weak_signal` | Moderate | Different data sources exhibit cleanly separated precision/jitter regimes |
| Hard protocol contradiction | `hard_contradiction` | None found | Parent/child, tuple, state, byte, certificate, and lifecycle checks passed |

## Realism Score by Category

| Category | Score |
|---|---:|
| Protocol and Tuple Semantics | 9/10 |
| Cross-Source and Lifecycle Consistency | 9/10 |
| Timing Realism | 6/10 |
| Distributional Texture | 5/10 |
| Environment and Sensor Plausibility | 7/10 |

## Recommendations

1. Replace bounded per-sensor timestamp jitter with a realistic clock model: stable skew, gradual drift, packet-path latency, occasional capture buffering, and source-specific timestamp precision.

2. Model DHCP renewal timing from explicit T1/T2 options and client behavior. Include boot-time acquisition, retransmission, NAK, lease loss, and occasional delayed or skipped renewal cycles where appropriate.

3. Expand public HTTP traffic substantially: more user agents, bots, scanners, malformed requests, HEAD/POST/OPTIONS, TLS failures, HTTP/1.0, missing Host headers, long-tail URIs, query strings, and multi-request client sessions.

4. Generate external DNS RTTs from continuous, resolver-specific latency distributions rather than exact-millisecond pools. Preserve cache, upstream, timeout, and retry effects.

5. Add more heterogeneous public TLS clients: varying cipher preferences, failed handshakes, absent SNI, protocol intolerance, certificate alerts, and client-specific resumption behavior.

6. Preserve the existing strengths: canonical connection ownership, Zeek child-record timing, certificate/FUID integrity, proxy byte-scope distinctions, firewall lifecycle pairing, and IDS tuple alignment.
