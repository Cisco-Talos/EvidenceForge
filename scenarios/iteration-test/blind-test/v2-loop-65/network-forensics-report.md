# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 36

## Executive Summary

The network telemetry is mostly production-like: connection states and byte accounting are coherent, DNS behavior has realistic resolver and cache semantics, TLS details are internally consistent, and independent sensor/firewall/IDS views agree without being byte-for-byte clones. The main synthetic-looking defect is a repeated approximately 600 ms cadence in proxy HTTP connection creation; perfectly timestamp-sorted Zeek files and a handful of dangling HTTP file references add weaker concern, but together they do not outweigh the protocol-level realism.

## Evidence For Synthetic

- `[distribution_texture]` Proxy-bound HTTP connections repeatedly arrive at a narrowly fixed interval. In `zeek-core/conn.json`, 177 of 1,621 same-client/same-proxy HTTP inter-arrival gaps fall within 595-605 ms, and 197 fall within 550-650 ms. Examples include three successive `10.10.1.35 -> 10.10.3.20:8080` connections beginning at `2024-03-18T12:12:33.391311Z` and then approximately 0.600 seconds apart, and a four-connection `10.10.1.22` run beginning at `12:48:43.749834Z`. The same physical bursts appear at the DMZ sensor with its normal clock offset. Browser fan-out can be bursty, but this repeated 600 ms scheduler-like spacing across clients is unusually crisp.
- `[schema_or_format]` Every Zeek JSON file examined is strictly ascending by its `ts` field with zero inversions, including all three `conn.json` files. This is notable because `conn.log` records normally carry connection-start timestamps but are written at connection removal; multi-hour flows such as core UID `CTOKv1sJGKkzSsG8zPg` (`14:14:36.481736Z`, duration `13342.181861` seconds) would ordinarily create start-time inversions in native write order. An ETL or study-preparation sort fully explains this, so it is evidence of normalization rather than a hard authenticity contradiction.
- `[contract_gap]` Five HTTP records contain `resp_fuids` that are absent from the corresponding sensor's `files.json`: two on core (`Ft6I9KLnMKjR7W41gC`, `FpU8hcea6VHFozyuX3`) and three on DMZ (`FqAQIx3LH0EbjCiwPq`, `FdkCtk99PLXTK4X8xx`, `F81tkwCaSdi4YjnNvv`). This is a concrete local reference gap, although the very low rate and the possibility of file-log filtering or collection loss make it weak evidence.

## Evidence For Real

- The three connection sensors contain believable mixtures rather than one dominant canned state: core has 9,000 `SF`, 2,028 `S0`, 137 `RSTO`, 90 `RSTR`, 29 `OTH`, 21 `REJ`, and smaller `S1/S2/S3` populations. State/history pairs are source-native (`S0/S`, `REJ/Sr`, `SF/ShADadfF`, one-way UDP `S0/D`), and TCP payload/header arithmetic has no impossible cases.
- Protocol records are temporally and structurally coherent. All DNS, HTTP, SSL, SMTP, SMB mapping, and SMB file records have an existing same-sensor connection UID, matching five-tuples, timestamps at or after connection open, and timestamps no later than the visible connection close.
- DNS has an organic mix of A, AAAA, PTR, SRV, TXT, NS, SOA, and MX requests. Core DNS includes 221 NXDOMAINs with recognizable suffix-search and stale-name texture such as `wpad`, `wpad.local`, `isatap`, `printer01.meridianhcs.local`, and external names suffixed with `meridianhcs.local`.
- Recursive TTL behavior is convincing. For `ctldl.windowsupdate.com`, resolver `10.10.2.10` returns TTL 470 at `12:11:49Z` and 345 roughly 125 seconds later, then refreshes after expiration. Other repeated names likewise decay between cache hits and jump only after plausible expiry.
- TLS version/cipher combinations are valid and heterogeneous: TLS 1.3 uses AES-GCM or ChaCha20 suites, while TLS 1.2 uses ECDHE RSA/ECDSA suites. All 1,192 examined X.509 records are valid at their associated handshake time; every multi-certificate chain links leaf issuer to issuer subject, and every leaf SAN matches the associated SNI.
- Sensor overlap looks like separate observation points. Matching core/DMZ flows use different Zeek UIDs, have a stable approximately 114 ms clock skew, and often differ slightly in packet counts, byte counts, duration, or history when `missed_bytes` is present. That is more credible than duplicated records pretending to be independent sensors.
- Firewall and IDS views preserve source-native timing. Of 7,504 ASA TCP/UDP build events, 7,502 have a later teardown; the two still-open records are long SSH sessions near the end of the bounded window. Matched ASA durations differ from Zeek durations by less than one second, consistent with ASA whole-second formatting. All 65 core and 102 perimeter Snort alerts match a visible Zeek five-tuple within two seconds, with the alert following connection observation by roughly 0.1-0.3 seconds.
- Host networking defaults vary by apparent OS. Windows-addressed systems such as `10.10.1.31`, `.33`, `.34`, `.35`, and `.36` use TCP ephemeral ports at or above 49152, while Linux systems such as `10.10.1.21`, `.22`, and `10.10.2.21` use the 32768-60999 range. HTTP user agents align with those distinctions.
- The internal scan at `13:40:16-13:40:39Z` has realistic mechanics rather than every address answering. `10.10.3.10` probes the `10.10.2.0/24`; 244 of the ping-sweep observations are one-way `S0`, while only 11 receive replies. The subsequent five-port SYN sweep produces mostly `S0` records, with source-native `REJ`, reset, and short successful handshakes only on apparent live systems.

## Detailed Analysis

### Collection window and volume

The Zeek view spans approximately six hours on 18 March 2024. Core contains 11,337 connections from `12:00:06.923784Z` through `17:59:26.105511Z`; DMZ contains 8,448 from `12:00:18.060541Z` through `17:59:25.990587Z`; and DB contains 474 from `12:00:31.657572Z` through `17:57:29.818080Z`. The hour beginning 13:00 is visibly busier on core and DMZ, but the increase is explained by the `/24` scan rather than a smooth business-hour curve.

Core protocol volume is plausible for an internal sensor: 2,974 DNS-classified connections, 2,251 Kerberos, 1,142 LDAP-port connections, 1,726 HTTP, 670 SMB-port connections, 382 TLS, 315 syslog, 49 SSH, 48 DHCP, 46 SMTP, and 25 RDP. DMZ is appropriately dominated by TLS/HTTP and unsolicited inbound `S0` traffic, while DB is dominated by 318 MySQL connections from `10.10.3.10` to `10.10.4.10`.

### TCP and flow lifecycle

TCP state transitions are semantically credible. Core `REJ` records all use `Sr`; successful TCP flows contain handshake/data/close histories; one-sided scans are `S0/S`; and midstream `OTH` records carry data/ack histories rather than fabricated handshakes. No repeated five-tuple overlaps another still-open instance on any of the three sensors. TCP `orig_ip_bytes` and `resp_ip_bytes` are always sufficient to contain application bytes plus at least the minimum per-packet IP/TCP headers.

Durations fit service roles. Core median HTTP duration is approximately 2.26 seconds, median LDAP duration 2.34 seconds, and successful SSH/RDP sessions extend from minutes to roughly an hour or more. The longest SSH flow, core UID `CTOKv1sJGKkzSsG8zPg`, runs from `14:14:36.481736Z` until about `17:56:58.663597Z`; the ASA reports the same flow closing at `17:56:58` after `3:42:22` with TCP FINs. The only two ASA builds lacking teardown are SSH connections opened at `17:09:10` and `17:38:42`, which is consistent with the stated bounded window.

The attack-like scan is also mechanically sound. The ping sweep begins around `13:40:16Z`, and the TCP probes begin around `13:40:31.696170Z`, so discovery precedes service scanning. Approximately 1,244 one-sided SYN probes span five ports across almost the entire `/24` in eight seconds, while the small number of live targets produce short successful, rejected, or reset responses. For example, `10.10.2.30` answers HTTP on core UID `CZa566vBVgHaxFlhtp` at `13:40:32.617190Z`, SSH on `CFVIgzOXMPBgPOajUU` at `13:40:36.720721Z`, and TLS on `CTi5FFFnOzDjCXQ22H` at `13:40:37.463933Z`; its MySQL probe times out. That service differentiation is realistic.

### DNS behavior

Core DNS has 2,962 records: 2,151 A, 237 AAAA, 141 PTR, 97 SRV, 311 TXT, and a small NS/SOA/MX tail. Response codes include 2,717 NOERROR, 221 NXDOMAIN, 15 SERVFAIL, and 9 REFUSED. Internal authoritative answers correctly set `AA=true`, while recursive external answers generally do not; both DNS servers advertise recursion. A and AAAA answers have valid address families, answer and TTL vector lengths agree, and NOERROR/no-data AAAA responses are represented by omitted answer fields rather than malformed values.

Name-service texture is especially persuasive. Domain-controller A lookups, LDAP/Kerberos SRV lookups, PTR traffic, `wpad`/`isatap` suffix-search failures, stale internal names, software-update domains, and short-lived suspicious TXT traffic all coexist. The 276 TXT queries from `10.10.2.30` to `*.ns1.westbridge-services.cloud` between `16:45:12.987641Z` and `16:59:45.494858Z` vary in label structure, response code, answer length, resolver selection, and interval; their median gap is about 2.02 seconds. This is compatible with a DNS application channel and does not exhibit a fixed-rate beacon.

DNS-to-connection causality is strong. On core, 340 of 353 TLS records carrying SNI have an earlier same-client A response containing the destination address; the exceptions are explainable by caching, inbound TLS, or pre-window state. On DMZ, most misses are inbound clients connecting to `ehr-portal.meridianhcs.com` or proxy-origin traffic with cacheable resolution. There is no same-UID DNS record occurring before its DNS connection or outside that connection's interval.

### HTTP, proxy, and file extraction

Core HTTP contains 1,560 CONNECT transactions, showing a clear explicit-proxy environment at `10.10.3.20:8080`, plus 193 GET and 15 POST records. Statuses include successful tunnels, 403 policy blocks, 407 authentication failures, upstream 502/503/504 responses, redirects, 304 caching, and partial content. CONNECT error responses carry small HTML bodies and file references, which is valid proxy behavior; successful 200 CONNECT responses have no body.

Persistent HTTP/1.1 connections reach `trans_depth` 6, and subordinate object fetches remain inside connection duration. Static resources are stable across fetches: `/assets/js/vendor.757467b6.js` is 141,609 bytes in both observed core requests, while DMZ requests for `/assets/main.css` are consistently 277 bytes and `/assets/app.js` consistently 75,107 bytes. Where summed extracted-file bytes exceed captured connection payload bytes, adding the connection's `missed_bytes` closes the gap; no file total exceeds `payload + missed_bytes`.

The one material timing concern is the repeated 600 ms connection spacing. It occurs in about 11% of same-client/same-proxy HTTP gaps and also produces visible multiples such as 1.8 and 3.6 seconds. This looks more like a generation or workload scheduler quantum than natural browser socket creation, even though the surrounding burst sizes and destinations vary.

### TLS and certificates

Core TLS is split nearly evenly between TLS 1.2 (183) and TLS 1.3 (175); DMZ has 1,456 TLS 1.3 and 783 TLS 1.2 records. TLS 1.3 handshakes lack visible certificate chains, while non-resumed TLS 1.2 handshakes usually carry them, matching the observability difference caused by encrypted TLS 1.3 handshake content. Resumed sessions omit chains. Certificate fingerprints repeat consistently for repeated services instead of being regenerated per session: the Meridian enterprise issuing CA fingerprint appears 97 times on core, and the `LOG-MON-01` leaf fingerprint appears 69 times.

All cipher/version pairs are valid. SAN/SNI matching, leaf-to-intermediate issuer chaining, certificate validity windows, key types, and key sizes are coherent. The dataset includes both RSA and ECDSA external leaves, 2048/4096-bit RSA issuers, and a small internal PKI population, which is a credible mixed environment.

### Multi-sensor, firewall, and IDS correlation

The sensors do not reuse Zeek UIDs for the same physical connection. There are 4,328 tuple/time matches between core and DMZ, 130 between core and DB, and 344 between DMZ and DB, but zero shared connection UIDs. Core/DMZ timestamps differ by a median of about 114 ms, core/DB by about 64 ms, and DMZ/DB by about 179 ms; the stable offsets look like imperfect clock synchronization. Connection state and detected service are preserved across shared flows, while byte/packet counts and histories sometimes differ, especially when packets are missed.

ASA lifecycle evidence strongly agrees with Zeek. The ASA has 7,504 TCP/UDP connection builds and 7,502 teardowns; no teardown precedes its build. `S0` flows map to 30-second `SYN Timeout` teardowns, `SF` flows generally map to `TCP FINs`, and reset states map to reset reasons. The firewall's whole-second durations differ from Zeek's microsecond durations by at most approximately one second.

Snort has 65 core and 102 perimeter alerts covering DNS policy names, STUN, BitTorrent, scan, JA3, HTTP policy, and ICMP signatures. Every alert has a matching Zeek connection tuple within two seconds, and the Snort timestamp typically trails connection observation by 0.1-0.3 seconds. This supports a shared packet-level basis rather than contradictory independent event invention.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `distribution_texture` | Zeek `conn` / proxy HTTP | Repeated across multiple clients and both core/DMZ views | Approximately 11% of same-client proxy HTTP gaps cluster within 595-605 ms, with related multiples; this is the strongest generator-like cadence. |
| `schema_or_format` | All Zeek JSON logs | Dataset-wide | Zero `ts` inversions, including start-time-sorted `conn` logs with multi-hour sessions, implies deterministic post-processing or generation rather than untouched native write order. |
| `contract_gap` | Zeek HTTP/files | Five records | HTTP explicitly names five FUIDs absent from local `files.json`; low volume and filtering/loss make the impact small. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, ASA, Snort, DNS, TLS, and X.509 fields are source-native and internally valid, with only a few dangling file references.
- **Temporal patterns:** 7 — Human, infrastructure, scan, DHCP, and tunnel timing are varied, but the repeated 600 ms proxy cadence and globally sorted files are visible artifacts.
- **Cross-source correlation:** 9 — Tuples, UIDs, lifecycle bounds, firewall durations, sensor clocks, and IDS timing agree without impossible ordering or inappropriate UID reuse.
- **Behavioral realism:** 8 — Proxy browsing, Windows domain traffic, service scanning, DNS tunneling, admin protocols, and database traffic have plausible mechanics and long-tail variation.
- **Environmental consistency:** 8 — OS-specific ephemeral ports and user agents, segmented sensor visibility, internal PKI, dual DNS/DC infrastructure, and role-consistent services form a coherent environment.

## Recommendations

- If this were synthetic, model browser and proxy fan-out with connection reuse, concurrent socket creation, cache state, and wider per-request jitter rather than a recurring approximately 600 ms launch interval. Preserve burstiness, but eliminate the scheduler quantum and its 1.8/3.6-second multiples.
- If the files are intended to represent native Zeek output rather than a normalized export, preserve write-time ordering. In particular, `conn.log` should be emitted when flows close or expire, which naturally produces inversions in its connection-start `ts` field when long and short sessions overlap. If sorting is an intentional collection transform, document that transform.
- Keep HTTP/file observation decisions coherent: when a `files.json` record is dropped or filtered, avoid retaining a dangling `orig_fuids`/`resp_fuids` reference unless the intended collection model explicitly permits independent log loss. Add a validation check for same-sensor FUID referential integrity.
