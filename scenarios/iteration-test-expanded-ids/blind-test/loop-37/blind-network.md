# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 87
**Synthetic-Confidence Score:** 72

## Executive Summary

The corpus is unusually strong at network-layer correlation: TCP states, protocol fan-out, proxy causality, DNS diversity, TLS variation, dual-sensor clock offsets, and long-lived session lifecycles are all convincing. The verdict turns on repeated source-native contradictions in Zeek file analysis—64 incomplete certificate files still produce full X.509 fingerprints and decoded metadata—and a systematic noncanonical IPv6 rendering pattern, reinforced by ambiguous proxy byte accounting.

## Evidence For Synthetic

- `[hard_contradiction]` Zeek emits complete X.509 metadata, including a SHA-1 certificate fingerprint, for files that `files.json` says were not fully observed. In `zeek-dmz/files.json`, FUID `F6WIDCPb3HxFlz6cs` at `1710763407.761236` has `seen_bytes=1276`, `total_bytes=1279`, `missing_bytes=3`, no `analyzers`, and no file hashes. Nevertheless, `zeek-dmz/x509.json` at `1710763408.244435` contains a fully decoded certificate and fingerprint `3651b5e55376bf36c3b2ccf3fd44c5fdbe60195f` for that same FUID. The same fingerprint equals the `files.json` SHA-1 for later complete observations of the certificate, so it is specifically the full-file digest, not an unrelated identifier.
- `[contract_gap]` This incomplete-file/parser contradiction is systematic: 12 of 84 core X.509 rows and 52 of 613 DMZ X.509 rows reference certificate files with nonzero `missing_bytes`, no X509 analyzer, and no file SHA-1, yet every one has a decoded X.509 fingerprint. Complete files are internally sound—72 core and 561 DMZ rows have file SHA-1 values, and all match the X.509 fingerprint—making the incomplete subset look like canonical metadata leaking past an observation-loss decision.
- `[contract_gap]` The same problem appears in OCSP fan-out. Two of five core OCSP records and four of 41 DMZ OCSP records are decoded from files marked incomplete. For example, DMZ FUID `Fq0m94GMLbb0Xe4OT2` has `seen_bytes=1294`, `total_bytes=1302`, and `missing_bytes=8` in `files.json`, but `ocsp.json` still supplies issuer hashes, serial number, `certStatus="good"`, `thisUpdate`, and `nextUpdate`.
- `[schema_or_format]` AAAA answers are repeatedly rendered with leading zeroes inside IPv6 hextets, which a native Zeek address formatter would normally canonicalize away. Both sensors contain the same 39 padded observations spanning 29 unique addresses, including `2600:1f18:e6e2:0068::1`, `2606:4700:1205:00ac::1`, `2620:1ec:6bd1:0088::1`, and `2a04:4e42:a734:0089::1`.
- `[schema_or_format]` Proxy tunnel counters appear to include the CONNECT control exchange despite being labeled `tunnel_*`. At 12:02:30, the `drive.google.com` proxy row reports `cs_bytes=271`, `sc_bytes=137`, `tunnel_cs_bytes=3150`, and `tunnel_sc_bytes=34765`. The client-to-proxy Zeek connection contains exactly 3150/34765 payload bytes, while the proxy-to-origin TLS connection contains 2879/34628—exactly 271/137 fewer. The same identity occurs for `fonts.pixeltrack.org`: 4187/17113 labeled tunnel bytes equal client-side totals, while origin TLS carries 3820/17014 and CONNECT control accounts for the 367/99 differences. This makes the fields semantically double-count control bytes if used together.

## Evidence For Real

- Zeek connection-state texture is strong. Core contains 5,966 `SF`, 76 `RSTO`, 46 `RSTR`, 20 `REJ`, 20 `OTH`, 12 `S0`, and smaller `S1`/`S2`/`S3` populations. DMZ exposure produces a plausibly different mix: 4,223 `SF` and 1,161 `S0`, with smaller reset, reject, partial, and other states.
- State/accounting invariants hold throughout both `conn.json` files: no `S0` record has responder packets, no `REJ` record carries payload, no non-ICMP `SF` record lacks a response, no duration is negative, and IP byte totals never fall below payload bytes.
- DNS has convincing enterprise diversity. Core counts include 1,376 A, 313 AAAA, 282 TXT, 185 PTR, and 65 SRV requests, with 1,976 `NOERROR`, 230 `NXDOMAIN`, 18 `SERVFAIL`, and eight `REFUSED` responses. Visible traffic includes reverse lookups, AD LDAP/Kerberos service discovery, WPAD and suffix-search failures, NODATA AAAA responses, mail-policy TXT records, and low-TTL anomalous traffic.
- DNS, connection, and application fan-out is structurally correct. Every DNS, HTTP, and SSL row has a matching Zeek connection UID and tuple; no HTTP or TLS application row precedes its connection or falls after connection close.
- Explicit-proxy causality is realistic. For `drive.google.com`, the proxy DNS A lookup at `1710763350.518162` returns `142.250.191.46`; proxy egress starts at `1710763350.543162`; TLS metadata follows at `1710763350.628915`. The client-side CONNECT occurs first and the proxy access record agrees on host, status, user agent, and traffic scale.
- TLS coverage has an appropriate mixture of TLS 1.2 and 1.3, AES-128/256-GCM and ChaCha20 suites, RSA and ECDSA certificates, resumed and full handshakes, differing SSL histories, certificate-chain depths, and OCSP observations. All SSL certificate FUID references resolve to X.509 rows.
- Long session lifecycle timing is coherent rather than artificially collapsed. The SSH connection from `10.10.1.36:58598` to `10.10.3.10:22` begins in Zeek at `1710769184.324030`; endpoint FLOW observations follow within a fraction of a second; target syslog records connection, password acceptance, PAM open, and logind session creation; Zeek closes after 15,209.024949 seconds; PAM closes at 17:53:14.977937, about 1.6 seconds after transport close.
- DHCP renewals use multiple lease lengths and per-client jitter. The 3,600-second clients renew near T/2 rather than at one exact global tick, while 7,200- and 14,400-second leases follow their own schedules.
- Internet-facing scan texture is credible. DMZ `S0` traffic spans multiple persistent and low-frequency sources, target ports such as 23, 25, 445, 3389, 22, 2323, 80, 587, 443, 8080, and 5985, and correlates with ASA SYN-timeout teardown and UFW block records.

## Detailed Analysis

### Zeek Connection Semantics

The two sensors contain 11,776 connection records over approximately six hours. Core traffic is dominated by successful enterprise services—DNS, Kerberos, SMB, LDAP, proxy HTTP, SMTP, SSH, and RDP—while DMZ traffic adds 1,161 unanswered SYNs, 1,856 TLS-classified connections, web ingress, and proxy-origin egress. That difference is appropriate for the observation points.

TCP histories are varied and state-compatible. Common successful histories include `ShADadfF`, `ShADaDadfF`, `ShADadTtFf`, `ShADadfFa`, and retransmission/gap variants ending in `Gg`; rejected traffic uses `Sr`; unanswered scans use `S`; reset cases use histories such as `ShADaR` and `ShADadR`. Counts, packet directions, payload totals, and state meanings remain internally consistent.

Service durations are plausible: core DNS has a median near 3.6 ms, SMTP near 3.36 seconds, SMB near 3.69 seconds, and SSH near 1,245 seconds; RDP has a median around 1,456 seconds. DMZ TLS has a median around 2.89 seconds with a longer tail, and MySQL traffic has a median around 2.61 seconds. The distributions contain both short failures and persistent administrative/application sessions.

### DNS and Name Resolution

DNS traffic is one of the strongest parts of the corpus. Internal authoritative answers use stable enterprise TTLs, external recursive responses show a broad TTL distribution, and negative behavior includes `NXDOMAIN`, `SERVFAIL`, `REFUSED`, and successful NODATA AAAA replies. PTR, SRV, SOA, MX, NS, and TXT records add believable long-tail texture.

The automatic resolver-to-connection sequencing is also credible. The `drive.google.com` A query from proxy `10.10.3.20` at `1710763350.518162` returns two addresses, including `142.250.191.46`; the matching egress TCP connection starts about 25 ms later and the TLS ClientHello/application metadata follows inside that connection.

The defect is textual rendering of IPv6 answers. Thirty-nine AAAA-answer observations per sensor preserve zero-padded hextets. This is valid IPv6 in a general parser, but it does not resemble Zeek's usual canonical textual address output and repeats across 29 values, making it a systematic source-format fingerprint rather than a one-off upstream oddity.

### TLS, X.509, Files, and OCSP

TLS protocol choices, ciphers, resumption, SNI, and chains are varied and mutually compatible. Certificate references are complete: 84 core chain FUIDs and 613 DMZ chain FUIDs all resolve to X.509 rows, and no X.509 row is orphaned. For fully observed certificate files, the SHA-1 in `files.json` matches the X.509 fingerprint in every case.

That otherwise strong integrity makes the loss-handling contradiction especially probative. Across both sensors, 64 certificate files are explicitly incomplete and lack analyzers and hashes, but still produce full decoded X.509 rows and full-file SHA-1 fingerprints. A sensor cannot derive the missing certificate bytes required for that digest merely from the partial file. Repeated instances across both source families point to independently applying a file-loss texture after higher-level certificate metadata was already created.

OCSP shows an analogous, smaller inconsistency: six incomplete HTTP response files still yield fully decoded OCSP status structures. While an ASN.1 parser might recover some early fields from a truncated response in edge cases, the consistency with the X.509 leakage makes a shared synthetic observation-order defect more likely.

### Proxy and HTTP

The proxy topology is well modeled. Client CONNECT requests target `10.10.3.20:8080`; successful requests cause proxy DNS and origin TCP/TLS activity; 502 failures may end without origin TLS; source and destination user-agent/host/status information agree across proxy access and Zeek HTTP records. The `fonts.pixeltrack.org` transaction, for example, progresses from client CONNECT at `1710763337.069956` to proxy-origin TCP at `1710763337.129959` and TLS at `1710763337.312000`.

The byte relationship is internally exact but mislabeled. In successful CONNECTs, `tunnel_cs_bytes` and `tunnel_sc_bytes` equal the entire client-to-proxy Zeek payload totals. The actual proxy-origin TLS payload equals those totals minus the separately reported `cs_bytes`/`sc_bytes` CONNECT control sizes. If `tunnel_*` is meant to represent tunneled application bytes, this creates deterministic control-byte double counting.

HTTP itself has a plausible method/status mix. Core includes 886 CONNECT, 188 GET, and ten POST requests with 200, 403, 407, 304, 5xx, redirect, and partial-content outcomes. User agents cover contemporary Chrome, Edge, Firefox, Python requests, CryptoAPI, Go, wget, Google Drive, Zscaler, and update clients rather than one repeated browser token.

### Boundary, IDS, and Endpoint Correlation

ASA and Zeek agree on externally initiated scans and NAT-facing destinations. At 12:00:51, ASA builds inbound connection 1218002 for `185.249.5.220:18070` to `10.10.3.10:22`, then tears it down after 30 seconds with zero bytes and `SYN Timeout`; DMZ Zeek records the corresponding tuple as `S0`, `history="S"`, one originator packet, and no response.

Snort alerts land inside corresponding Zeek flows. The core STUN alert at 12:07:23.166401 for `10.10.2.25:38321 -> 87.136.158.10:3478` corresponds to a response-bearing UDP connection beginning at `1710763643.126313`. The BitTorrent alert at 12:14:12.847992 corresponds to a completed TCP connection beginning at `1710764052.825669`.

Endpoint FLOW timestamps also preserve transport ordering. For the failed `sdk.split.io` proxy request, source and destination eCAR FLOW records occur at `1710763330.884` and `1710763330.883`, core Zeek begins at `1710763330.905356`, DMZ Zeek begins at `1710763330.949307`, and the CONNECT application record follows. This kind of bounded source-native delay is realistic and is not itself evidence of synthesis.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `hard_contradiction` | Zeek files/X.509 | 64 of 697 X.509 rows | Full-file fingerprints and decoded certificates exist despite explicitly missing bytes and absent file hashes/analyzers. |
| `contract_gap` | Zeek files/OCSP | 6 of 46 OCSP rows | Fully decoded status metadata is emitted from files marked incomplete, matching the X.509 loss-leak pattern. |
| `schema_or_format` | Zeek DNS | 39 observations, 29 unique AAAA answers on each sensor | IPv6 hextets retain systematic leading-zero padding instead of native canonical rendering. |
| `schema_or_format` | Proxy access/Zeek conn | Multiple sampled successful CONNECTs | `tunnel_*` counters equal total client-side payload and include separately reported CONNECT control bytes. |

## Realism Score by Category

- **Field format accuracy:** 7 — Most Zeek, ASA, Snort, proxy, and syslog shapes are convincing, but padded AAAA answers and proxy counter semantics are source-format defects.
- **Temporal patterns:** 9 — Connection, DNS, proxy, TLS, IDS, and long-session timing is varied and causally ordered.
- **Cross-source correlation:** 7 — Network correlation is excellent overall, but incomplete files still producing complete X.509/OCSP metadata is a repeated observation-contract failure.
- **Behavioral realism:** 9 — Enterprise services, proxy browsing, mail, remote administration, hostile scanning, and suspicious activity all have credible network behavior and distributions.
- **Environmental consistency:** 9 — Host roles, segmented routing, NAT, proxy egress, resolver use, and DMZ exposure remain coherent across the visible window.

## Recommendations

- If this were synthetic, apply source-observation loss before protocol parsers and hashes are produced. An incomplete certificate file should not emit a full X.509 fingerprint or decoded row unless the remaining bytes are demonstrably sufficient; otherwise suppress the parser artifact or keep the file complete.
- Enforce the same lifecycle rule for OCSP: a truncated response should yield only metadata the parser could actually recover, and complete decoded status rows should require parser-compatible bytes.
- Canonicalize every AAAA answer through an IPv6 address formatter before Zeek rendering so values such as `2600:1f18:e6e2:0068::1` become `2600:1f18:e6e2:68::1`.
- Define proxy byte fields unambiguously. If `cs_bytes`/`sc_bytes` are CONNECT control bytes, `tunnel_cs_bytes`/`tunnel_sc_bytes` should exclude them and align with the proxy-origin payload; alternatively rename the latter as total connection bytes and prevent consumers from summing both sets.
