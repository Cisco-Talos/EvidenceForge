# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 97  
**Synthetic-Confidence Score:** 91

## Executive Summary

The dataset is sophisticated and realistic in its topology, traffic mix, sensor offsets, DNS behavior, TCP states, certificate reuse, and firewall correlation. However, repeated impossible proxy ordering, invalid TLS 1.2 ECDHE histories, systematic omission of aborted TLS sessions, and inconsistent Zeek file-analyzer provenance are strong generator fingerprints. These defects outweigh the otherwise high production realism.

## Evidence For Synthetic

- `[hard_contradiction]` In at least 392 of 522 successful proxy transactions matched by hostname, SNI, and exact tunnel byte counts, the proxy’s outbound TCP connection begins before the initiating HTTP `CONNECT` request. For `proxy.wellbridge.io`, the client-side `CONNECT` is timestamped `2024-03-18 13:42:50.932408 UTC`, but the proxy-origin TCP connection starts at `13:42:50.540040` and TLS is detected at `13:42:50.649667`. The proxy log confirms that this is the same transaction through the exact `2702/45414` tunnel-byte pair.
- `[hard_contradiction]` Of 586 non-resumed TLS 1.2 sessions, 122 negotiate an ECDHE cipher but have an `ssl_history` lacking `K`, Zeek’s server-key-exchange marker. ECDHE in TLS 1.2 requires ServerKeyExchange. In 109 of those sessions, `missed_bytes=0`, so packet loss does not explain the omission.
- `[contract_gap]` All 2,538 `ssl.json` records are `established=true` and belong to `SF` connections. Meanwhile, 180 non-`SF` connections are labeled `service:"ssl"` but have no SSL record, including resets after substantial bidirectional payload exchange. This state-dependent omission is inconsistent with normal Zeek SSL logging, which supports `established:false` for aborted handshakes.
- `[contract_gap]` Application timestamps do not preserve the stable cross-sensor clock relationship. Across 1,565 paired HTTP records, application-time residuals relative to the connection clock offset range from approximately `-0.373` to `+0.398` seconds, whereas 969 paired DNS records preserve the offset within microseconds. This looks like independent per-record timing jitter rather than packet-derived timestamps.
- `[schema_or_format]` `files.json` analyzer provenance contradicts companion records. One hundred SMB files contain MD5, SHA-1, and SHA-256 values while listing only `["MIME"]`; all 12 files that generate `pe.json` entries list only `["SHA1"]`, omitting `PE`; and 82 files associated with `ocsp.json` list no analyzers.
- `[distribution_texture]` Identical static download URLs return unrelated sizes and hashes within hours. The same host and user agent downloaded `http://downloads.cloud.com/workspace/windows/CitrixWorkspaceApp.exe` at `14:28:18` as 11,716,281 bytes/SHA-1 `787f4b...`, then at `17:22:35` as 17,260,002 bytes/SHA-1 `69012c...`. Two requests for the same Windows `pinrulesstl.cab` URL only 14 minutes apart similarly returned 19,857 and 32,650 bytes.

## Evidence For Real

- TCP state and history combinations are generally source-native: TCP `S0` records use `S`, rejected connections use `Sr`, UDP request-only traffic uses `D`, and bidirectional UDP uses `Dd`.
- Sensor clocks form a coherent topology. For 4,181–4,184 core/DMZ flow pairs, the DMZ clock leads core by a median of approximately 114 ms with only about 2.4 ms standard deviation. DMZ/database pairs show a consistent approximately 179 ms offset.
- DNS has credible enterprise diversity: A, AAAA, PTR, SRV, TXT, MX, NS, and SOA queries; suffix-search NXDOMAINs such as `wpad.local`, `wpad.meridianhcs.local`, `isatap`, and `oldserver.meridianhcs.local`; mixed authoritative/recursive flags; and RTTs from sub-millisecond to 2.277 seconds.
- The 2,878 core DNS records contain 2,817 distinct transaction IDs, a plausible collision count for the 16-bit ID space. Source-port reuse is likewise non-pathological.
- Host source-port ranges are OS-aware. Apparent Windows systems consistently use the Windows dynamic range above 49152, while Linux systems use roughly 32768–60999.
- TLS versions, ciphers, and certificate identity are otherwise strong. TLS 1.3 sessions appropriately lack passive certificate visibility; full TLS 1.2 handshakes have certificate chains; resumed sessions omit them; SNI matches SANs; and repeated connections to the same endpoint reuse the same leaf fingerprint and serial.
- DHCP renewals occur around T/2 with nonuniform jitter rather than exact fixed intervals. Lease periods vary among 3,600, 7,200, and 14,400 seconds.
- Firewall evidence is detailed and coherent: 6,417 TCP build records, 6,415 teardowns, plausible two-session window truncation, and teardown reasons that generally agree with Zeek states (`TCP FINs`/`SF`, `SYN Timeout`/`S0`, reset directions).
- External scanning is heterogeneous in interarrival times, SYN sizes, ports, states, and source behavior. Legitimate-looking web clients also produce short page-load bursts distinct from the scanners.
- Internal traffic reflects recognizable roles: 308 web-to-database MySQL connections, long-lived SSH/RDP sessions, domain-controller DNS/Kerberos/LDAP activity, SMB traffic, and explicit proxy egress.

## Detailed Analysis

### Corpus and Time Window

The Zeek telemetry covers approximately six hours, from `2024-03-18 12:00:04` through `17:59:56 UTC`.

- `zeek-core/conn.json`: 11,012 connections
- `zeek-dmz/conn.json`: 8,360 connections
- `zeek-db/conn.json`: 461 connections
- Total: 19,833 unique Zeek UIDs

The core sensor records 8,716 `SF`, 1,951 `S0`, 150 `RSTO`, 98 `RSTR`, and smaller numbers of `REJ`, `S1`, `S2`, `S3`, and `OTH`. The DMZ has a higher incomplete-connection fraction—2,742 `S0` among 8,360 records—which is consistent with Internet scanning.

Core volume rises from 1,734 connections during 12:00–12:59 to 3,041 during 13:00–13:59, then settles between 1,360 and 1,736 per hour. On a Monday in March, this corresponds plausibly to a morning business-activity increase in an Eastern US timezone.

Connection durations are service-sensitive rather than globally uniform. Core DNS has a median near 7.6 ms, Kerberos 17.4 ms, HTTP 2.27 seconds, LDAP 2.68 seconds, SMB 3.37 seconds, and TLS 5.03 seconds. SSH and RDP include multi-thousand-second sessions. Packet and IP-byte arithmetic satisfies minimum TCP, UDP, and ICMP header constraints.

### DNS Behavior

The DNS mix is one of the strongest realistic portions:

- Core: 2,114 A, 272 AAAA, 250 TXT, 127 PTR, 98 SRV, plus NS/MX/SOA.
- DMZ: 792 A, 118 AAAA, 46 PTR, 10 SRV, and 7 TXT.
- Core response codes include 2,639 `NOERROR`, 220 `NXDOMAIN`, 15 `SERVFAIL`, and 4 `REFUSED`.

Internal zones are authoritative, while most external answers have `AA=false`. NXDOMAIN behavior includes normal Windows suffix-search residue. AAAA responses include both IPv6 answers and `NOERROR`/empty NODATA responses.

All 3,895 DNS UIDs resolve to sensor-local connection records with matching tuples and timestamps inside the UDP transaction. For prior resolutions that can be associated with later flows, delays range from tens of milliseconds through cache-scale intervals of several minutes, rather than following one fixed offset.

The few connections occurring before the first visible matching query are not sufficient evidence of a defect because pre-window or still-valid resolver cache entries can explain them.

### Explicit Proxy Causality

This is the clearest synthetic defect.

The `proxy.wellbridge.io` transaction shows:

- Client-to-proxy TCP start: `13:42:50.506032`
- Zeek HTTP `CONNECT` request: `13:42:50.932408`
- Proxy-to-origin TCP start: `13:42:50.540040`
- Outbound TLS detection: `13:42:50.649667`
- Proxy log tunnel bytes: client-to-server `2702`, server-to-client `45414`
- Outbound Zeek payload bytes: `orig_bytes=2702`, `resp_bytes=45414`

The exact byte identity and SNI establish that the records describe the same transaction. Nevertheless, the dependent outbound connection starts 392 ms before the initiating request. The core sensor also timestamps the same `CONNECT` at `13:42:50.713502`, still after the outbound connection and TLS detection.

This is repeated. In a conservatively matched subset of 522 successful CONNECT transactions using exact tunnel bytes and SNI, 392 outbound TCP sessions begin before the HTTP request and 115 have outbound TLS detection before it. Zeek defines HTTP `ts` as when the request happened, while SSL `ts` is when TLS was first detected. [Zeek HTTP field reference](https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html), [Zeek SSL field reference](https://docs.zeek.org/en/master/scripts/base/protocols/ssl/main.zeek.html).

The same timing construction problem appears between sensors. DNS timestamps preserve the fixed sensor offset almost exactly, but HTTP, SSL, and file timestamps receive independent residuals of several hundred milliseconds. That is inconsistent with deriving each source record from the packet that caused the protocol event.

### TLS and X.509

The TLS mix is credible at a high level:

- TLS 1.3: 1,699 sessions
- TLS 1.2: 839 sessions
- Modern AES-GCM, ChaCha20-Poly1305, and some legacy CBC
- 109 resumed sessions on core and 757 on DMZ
- Stable endpoint certificate fingerprints, serial numbers, subjects, and validity periods
- No SNI/SAN mismatches among sessions with visible certificates
- Cipher authentication type agrees with leaf key type

The SSL histories expose a serious problem. In TLS 1.2, `K` denotes ServerKeyExchange. The dataset contains 122 full ECDHE handshakes with histories such as:

`CSXNGIFIFD`

rather than a sequence containing `K`, such as:

`CSXKNGIFIFD`

One example is UID `ChE3DMJEncLV9DkgBm` at `12:02:41.950662`, negotiating `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` to `ehr-portal.meridianhcs.com`, with `missed_bytes=0`. Another is UID `CkfvDCvr2HjYKKMbHY` at `12:11:34.142391`, negotiating ECDHE during SMTP STARTTLS, also with no missing bytes. Zeek’s published history mapping confirms that `K` is ServerKeyExchange. [Zeek SSL history reference](https://docs.zeek.org/en/master/scripts/base/protocols/ssl/main.zeek.html).

Failed-session representation is also unnaturally binary. There are 180 non-`SF` connections with `service:"ssl"` and no SSL companion, while every emitted SSL row is both `established=true` and attached to an `SF` connection. Several omitted connections exchanged tens of kilobytes before reset. Normal Zeek SSL records can represent aborted handshakes with `established:false`. [Zeek failed-handshake example](https://docs.zeek.org/en/lts/logs/analyzer.html).

### HTTP and File Analysis

HTTP status/method relationships are mostly sound:

- Successful CONNECT responses have zero HTTP response-body length.
- Failed CONNECT responses can carry small HTML error files.
- `304` responses generally have zero bodies.
- File sizes do not exceed connection payload after accounting for reported missing bytes.
- Transaction depths are sequential within reused connections.

The file-analysis metadata is not source-native. For example, core file `Fq8APSJjlgcPJMj2qA` records an SMB-transferred spreadsheet with `analyzers:["MIME"]` but also includes MD5, SHA-1, and SHA-256. File `Fp9s6tVfq0GqHdcLFh` has a companion PE record yet lists only `["SHA1"]`. All 12 PE-linked files omit `PE`, and all 82 OCSP-linked files omit an OCSP analyzer. Zeek models PE, OCSP, and hash processing as file analyzers, so the resulting provenance is internally inconsistent. [Zeek file-analyzer reference](https://docs.zeek.org/en/v7.2.2/script-reference/file-analyzers.html).

Content identity is also unstable for repeated static URLs. A single server, client, and Apache HttpClient combination receives two unrelated executables from the same `CitrixWorkspaceApp.exe` URL less than three hours apart. A similar pattern appears for `receiver.citrix.com` and a Windows trust-list CAB. Any one change might be operationally explainable, but several such changes in six hours form a synthetic-looking texture.

### Cross-Sensor and Firewall Correlation

At the connection layer, correlation is excellent without reusing UIDs. Core/DMZ observations of the same tuple use different Zeek UIDs and maintain an approximately fixed clock relationship. DMZ/database observations show a second stable offset, and the core/database offset is approximately the sum of the two.

The firewall logs use plausible ASA message forms and severities:

- `%ASA-6-302013`/`302014` for TCP build/teardown
- `%ASA-6-302015`/`302016` for UDP
- `%ASA-6-302020`/`302021` for ICMP
- `%ASA-4-106023` for ACL denies
- `%ASA-6-305011`/`305012` for dynamic translations

TCP teardown reasons align closely with Zeek states. Two TCP build records lack teardown records near the end of the collection, which is consistent with sessions extending beyond the window and is not treated as synthetic evidence.

### External Traffic and Lateral Movement

The DMZ captures 1,773 internal-to-external and 1,725 external-to-internal connections. Proxy `10.10.3.20` originates 1,765 of the outbound external flows, giving the environment a coherent egress architecture.

Inbound background scanning targets realistic service families including 445, 3389, 135, 139, 5985, 1433, 3306, 5432, 6379, and 9200. Scanner source ports are diverse, interarrival times are irregular, and SYN sizes vary by apparent scanner implementation.

The internal service graph is plausible:

- 308 connections from the web tier to database TCP/3306
- Kerberos and LDAP concentrated on domain controllers
- SMB centered on file and server roles
- Long SSH and RDP sessions mixed with short failures
- Monitoring/scanning behavior from identifiable internal hosts
- SMTP relays and STARTTLS sessions consistent with mail roles

No synthetic score was added merely because suspicious internal activity is discoverable or coordinated.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---:|---|
| `hard_contradiction` | Zeek HTTP/conn/SSL and proxy access | 392 of 522 exact-byte-matched tunnels | Dependent proxy-origin TCP begins before its initiating CONNECT request. |
| `hard_contradiction` | Zeek SSL | 122 of 586 full TLS 1.2 sessions | ECDHE histories omit mandatory ServerKeyExchange; 109 have no packet-loss explanation. |
| `contract_gap` | Zeek conn/SSL | 180 non-SF SSL-labeled flows | Aborted or reset TLS is systematically omitted; every retained SSL row is successful. |
| `contract_gap` | Cross-sensor HTTP/SSL/files | Dataset-wide | Application timestamps receive independent ±hundreds-of-ms residuals despite stable sensor clocks. |
| `schema_or_format` | Zeek files/PE/OCSP/SMB | 100 SMB hash records, 12 PE records, 82 OCSP records | `analyzers` does not identify the analyzers that visibly produced companion metadata. |
| `distribution_texture` | HTTP/files | Several repeated static downloads | Exact URLs produce unrelated sizes and hashes within minutes or hours. |

## Realism Score by Category

- **Field format accuracy:** 6 — Most Zeek, ASA, DNS, TLS, and HTTP fields are strong, but SSL histories and file-analyzer provenance contain source-native contradictions.
- **Temporal patterns:** 4 — Business-hour, DHCP, scanner, and session timing are realistic, but repeated proxy causality inversions are decisive.
- **Cross-source correlation:** 6 — UID, tuple, byte, firewall, and sensor relationships are excellent; the proxy child ordering and application timestamp jitter undermine them.
- **Behavioral realism:** 8 — Protocol ratios, scanning, proxy use, lateral services, mail, database, and web behavior are varied and role-appropriate.
- **Environmental consistency:** 8 — Topology, OS-specific source ports, certificate reuse, DNS roles, and firewall placement are unusually well modeled.

## Recommendations

- If this were synthetic, anchor each proxy transaction to the observed HTTP `CONNECT` request. DNS lookup, outbound TCP, TLS detection, and the eventual 200 response must be scheduled causally after that anchor.
- Derive repeated observations of HTTP, SSL, and file events from one canonical packet/event timestamp, then apply stable sensor clock offset and direction-appropriate propagation delay. Do not independently jitter each rendered source record.
- Construct TLS histories from the negotiated protocol. Every full TLS 1.2 ECDHE handshake must include ServerKeyExchange unless a concrete capture gap accounts for its absence.
- Emit `ssl.json` records with `established:false` for visible aborted handshakes, or avoid labeling a connection `service:"ssl"` when insufficient TLS evidence exists. Do not filter failed TLS solely by connection state.
- Populate `files.analyzers` from the operations actually represented: include PE for files with `pe.json` records, OCSP analyzers for OCSP objects, and relevant hash analyzers when digests are present.
- Preserve a stable content identity for identical static URLs during the window unless an explicit version/publication event changes the object. When content changes, correlate the new size and hash with a defensible update boundary.
