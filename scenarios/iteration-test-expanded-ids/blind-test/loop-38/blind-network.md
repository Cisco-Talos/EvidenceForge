# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 98  
**Synthetic-Confidence Score:** 95

## Executive Summary

The dataset is highly detailed and realistic in DNS, TLS, packet accounting, proxy routing, and cross-source correlation. However, Zeek TCP reset direction is contradicted by its own `history` field across 108 unique `RSTR` flows, a dataset-wide source-native impossibility that strongly indicates generated telemetry; additional HTTP transaction-order inversions reinforce that verdict.

## Evidence For Synthetic

- `[hard_contradiction]` Every `RSTR` record uses an uppercase originator-side `R` in `history`, even though `RSTR` means the responder reset the connection. This affects all 46 core and 65 DMZ `RSTR` rows, representing 108 unique five-tuples. Examples include:
  - `zeek-core/conn.json`, `2024-03-18T12:04:55.196035Z`, UID `CB9zRILAQREKdNgksA`, LDAP `10.10.2.25:32805 -> 10.10.2.10:389`: `conn_state="RSTR"` with `history="ShADadR"`.
  - `zeek-core/conn.json`, `2024-03-18T12:22:54.346757Z`, UID `C3QD5Q4nPTCYDXUZFtC`, SMB `10.10.1.36:50993 -> 10.10.2.20:445`: `RSTR` with `ShADadR`.
  - `zeek-dmz/conn.json`, `2024-03-18T12:14:20.459235Z`, UID `Caj1BoDDD7LrCjXUGDb`, TLS `10.10.3.20:50809 -> 52.114.132.73:443`: `RSTR` with `ShADadR`.
  - `zeek-dmz/conn.json`, `2024-03-18T12:21:59.154189Z`, UID `CoKgRrNFSHHPZhzWQxw`, MySQL `10.10.3.10:52839 -> 10.10.4.10:3306`: `RSTR` with `ShADadR`.
- `[hard_contradiction]` The reset-direction problem is not a harmless case convention. The same files correctly use uppercase `R` for `RSTO`, such as core UID `CuqY9rI3St8jPrls0w` with `conn_state="RSTO"` and `history="ShADadTR"`. Thus both originator-reset and responder-reset states are rendered with an originator-side reset marker.
- `[hard_contradiction]` One additional core flow has `conn_state="S1"`—established and not terminated—despite `history="ShR"`, which visibly contains an originator reset. At `2024-03-18T14:32:21.628880Z`, UID `CuL3Tf2WCJYnEdDD3Uz`, `10.10.4.10:56755 -> 10.10.1.33:9997`, the packet counts are consistent with SYN, SYN-ACK, then reset (`orig_pkts=2`, `resp_pkts=1`), not an open S1 connection.
- `[hard_contradiction]` Two HTTP/1.1 keep-alive connections have non-monotonic `trans_depth` timestamps:
  - Core UID `CecjjOXB8egdClbvToX` records depth 4 at `13:57:57.859086Z`, then depth 3 at `13:57:57.871818Z`. DMZ UID `C0fdRdxMqTxzo5Ax4F9` mirrors the same inversion at `13:57:57.910697Z` and `13:57:57.923429Z`.
  - Core UID `CskJzGl1PQlo6qmmqV` records depth 3 at `16:14:32.587939Z`, then depth 2 at `16:14:32.712087Z`. DMZ UID `CQHWMoEE72HKv1IZyx` mirrors it at `16:14:32.646543Z` and `16:14:32.770692Z`.
  Zeek’s transaction depth is assigned in request order; a later depth cannot have been first observed before an earlier request on the same UID.
- `[schema_or_format]` All 60 rejected or authentication-required CONNECT records in `proxy_access.log`—32 status 403 and 28 status 407—still carry nonzero `tunnel_cs_bytes`, `tunnel_sc_bytes`, and `tunnel_duration_ms` while declaring `proxy_action=deny` or `auth-required` and `ssl_bump=terminate`. For example, the `12:03:27Z` denial for `analytics.statuspage.io:443` reports `tunnel_cs_bytes=328 tunnel_sc_bytes=523 tunnel_duration_ms=460`. Those values actually match the whole client-to-proxy TCP payload, making the fields semantically mislabeled as tunnel accounting.
- `[distribution_texture]` Across 1,997 five-tuple matches between core and DMZ `conn.json`, 1,996 DMZ timestamps are later. Excluding one negative outlier, offsets are tightly bounded at approximately 42.6–65.9 ms, with a 56.0 ms median, across DNS, HTTP, SSH, TLS, SMB, and LDAP. The per-flow bounded jitter looks unlike either LAN transit time or a stable capture-clock offset, although this is secondary to the hard contradictions.

## Evidence For Real

- DNS behavior is unusually strong. Core telemetry contains 2,232 DNS records with a credible mix of A (1,376), AAAA (313), TXT (282), PTR (185), SRV (65), and lower-volume NS/MX/SOA queries. Response texture includes 230 NXDOMAIN, 18 SERVFAIL, and 8 REFUSED results.
- Cached external DNS TTLs decrement correctly across clients. Repeated answers observed before their prior TTL expired tracked the expected countdown to within approximately 0.53 seconds, including `_verify.github.com`, DKIM, SPF, and other repeated records.
- Every DNS row has a matching `conn.json` UID, tuple, protocol, and timestamp at both sensors. This is treated as positive/neutral correlation, not a synthetic indicator.
- TCP and UDP state distributions otherwise look credible. The core has predominantly successful internal DNS, Kerberos, LDAP, SMB, proxy, SSH, and RDP traffic, while the DMZ has 1,151 TCP `S0` records associated with believable Internet scanning against ports 22/23/2323, 25/465/587, 80/443/8080, 445, 3389, and 5985.
- Packet histories and accounting are generally detailed: no examined connection violates the minimum IP-byte-versus-payload/packet invariant, and protocol rows remain inside their parent connection intervals.
- TLS is plausible for March 2024. DMZ telemetry contains 1,183 TLS 1.3 and 578 TLS 1.2 handshakes using current AES-GCM and ChaCha20 suites, with 560 resumed sessions and heterogeneous certificate issuers and key types.
- Apparently missing X.509 rows are convincingly explained. Every SSL `cert_chain_fuid` without a corresponding `x509.json` record has a matching `files.json` record with nonzero `missing_bytes` and no X509 analyzer result—12 references in core and 52 in DMZ.
- The explicit proxy path is coherent across client-to-proxy HTTP CONNECT, proxy access logs, proxy-origin DNS/TLS, ASA NAT, and teardown accounting. In sampled flows, ASA teardown byte totals equal the corresponding Zeek origin-plus-response IP byte counts.
- Source-port ranges reflect apparent operating systems: Windows workstations use ports at or above 49152, while Linux systems use the 32768-and-up range.
- DHCP renewal behavior, lease times, internal addressing, hostnames, MAC formatting, and request/ACK structure are plausible for the bounded six-hour window.

## Detailed Analysis

### TCP State and History Semantics

The decisive defect is the relationship between `conn_state` and `history`. Zeek history direction is case-sensitive: uppercase markers come from the originator and lowercase markers come from the responder. Therefore, an established connection labeled `RSTR` must contain a responder-side lowercase `r`.

Instead, all 46 core `RSTR` rows use either `ShADadR` or `ShADadRGg`; all 65 DMZ rows use the same uppercase forms. The defect spans LDAP, SMB, SSL, HTTP, MySQL, RPC, and internal and Internet-facing traffic. Only three five-tuples overlap between sensors, leaving 108 unique affected flows. This is a systematic state-machine defect rather than packet loss or a single malformed record.

By comparison, `RSTO` rows correctly use uppercase reset markers: core has 76 such rows and DMZ has 111, with histories such as `ShADaR`, `ShADadTR`, and `ShAR`. Thus `RSTR` has evidently been assigned without changing reset direction in the history or packet actor.

The core `S1/ShR` record adds a second state-machine contradiction. `S1` means an established connection for which no termination was observed; `ShR` explicitly shows a reset. This cannot be explained by a pre-window initiator or post-window terminator because the reset itself is visible in the same record.

### HTTP Transaction Semantics

Most HTTP records are internally sound: successful CONNECT responses have zero response-body length, 304 responses have zero bodies, and error statuses carry plausible bodies. Multi-request connections generally use depths 1, 2, 3, and so forth.

Two UIDs violate that rule. The `/login` connection on `10.10.1.36:63448 -> 10.10.3.10:80` assigns depth 4 to the JavaScript request 12.7 ms before depth 3 for `/favicon.ico`. The `/products` connection from `10.10.1.34:58141` assigns depth 3 to one image 124 ms before depth 2 to another. Both inversions appear independently in core and DMZ views, demonstrating that this is shared event timing rather than line-order corruption in one file.

HTTP/1.1 pipelining does not explain this: transactions may overlap, but Zeek assigns depth as requests are parsed, so the request-first-seen timestamps cannot decrease with depth.

### DNS

DNS is one of the most convincing parts of the dataset. Core DNS is dominated by the internal resolver at `10.10.2.10`, with authoritative/recursive flags that distinguish local-zone and external answers. PTR, SRV, suffix-search failures, external A/AAAA lookups, mail-security TXT records, and a burst of low-TTL TXT activity all have plausible source-native shapes.

All 2,232 core and 822 DMZ DNS records have matching connection companions. UDP histories use `Dd`, successful queries have response-bearing `SF` connections, and failed/no-response traffic does not incorrectly receive protocol records.

Repeated external answers show resolver-cache countdown behavior rather than independent random TTL assignment. That substantially improves authenticity.

### TLS, X.509, and Files

TLS versions, ciphers, SNI, resumption, certificate key types, and certificate validity periods are broadly plausible. Every SSL protocol row is tied to a connection and occurs inside its connection interval.

The certificate/file relationship is particularly convincing. Missing `x509.json` rows initially appear suspicious, but all missing certificate FUIDs are present in `files.json` with small missing-byte counts and without X509/hash analyzers. Complete certificate observations carry consistent SHA-1 fingerprints between `files.json` and `x509.json`, including repeated presentation of the same portal certificate.

TLS handshake-history vocabulary is limited to a small set of patterns, but those patterns vary consistently by TLS version and are not strong evidence compared with the reset-state contradiction.

### Proxy and Firewall

The explicit proxy topology is coherent: internal clients connect to `10.10.3.20:8080`; accepted CONNECT requests cause proxy-side resolver and origin traffic; ASA records show the DMZ source translated to `203.14.220.1`; and connection teardown bytes agree with Zeek IP-byte accounting.

The proxy’s denied/auth-required CONNECT enrichment is semantically weak. For example, the `analytics.statuspage.io` 403 line explicitly says `byte_scope=connect-control-message`, `proxy_action=deny`, and `ssl_bump=terminate`, but then labels the client/proxy transport totals as tunnel bytes. No tunnel has been established at that point. The underlying traffic is plausible, but the custom field names overclaim lifecycle state.

### Traffic Volume, Scanning, and Timing

The DMZ state mix is believable for an exposed service. Internet scanners generate broad S0 distributions and differentiated port families, while legitimate or application-layer traffic produces SF/RST states. Source ports, interarrival times, and scanner targets are varied rather than fixed loops.

A notable inbound source, `185.70.41.45`, generated 424 portal connections over roughly 50 minutes, including 374 SF, 22 RSTO, 21 S0, and 7 RSTR states. Snort appropriately labels rapid HTTP/HTTPS connection attempts. The volume is aggressive but operationally possible.

Cross-sensor tuple matches exhibit a tightly bounded approximately 42–66 ms timestamp shift. A stable sensor clock skew could explain a consistent offset, and complete matching is not penalized. What is less natural is the per-flow bounded variation across nearly every protocol and direction; real capture timestamps on adjacent network segments would normally show much smaller transit differences or a slowly changing clock offset. I treat this as supporting texture, not a contradiction.

### DHCP and Infrastructure Traffic

The 69 DHCP transactions are all REQUEST/ACK renewals, which is plausible in a bounded window. Clients maintain stable lease lengths and renew on consistent per-client schedules. The regularity is visible but consistent with server-supplied T1 timers, so it does not materially affect the verdict.

Kerberos, LDAP, SMB, DNS, DHCP, SMTP, proxy, MySQL, SSH, RDP, and scanner traffic are placed on sensible host/port combinations. I found no reason to penalize absent NTP or other thin source families merely because their inclusion would improve investigation completeness.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `hard_contradiction` | Zeek core and DMZ `conn.json` | 111 rows / 108 unique flows | Every `RSTR` state claims a responder reset while its uppercase `R` history records an originator reset. This is a dataset-wide state-machine fingerprint. |
| `hard_contradiction` | Zeek core `conn.json` | One flow | UID `CuL3Tf2WCJYnEdDD3Uz` is labeled open `S1` while `ShR` visibly records a reset. |
| `hard_contradiction` | Zeek core and DMZ `http.json` | Two connection families, mirrored at both sensors | `trans_depth` decreases in timestamp order on the same HTTP/1.1 connection. |
| `schema_or_format` | Proxy access log | All 60 status-403/407 CONNECT transactions | Denied or unauthenticated requests are assigned nonzero “tunnel” accounting despite terminate/deny semantics. |
| `distribution_texture` | Cross-sensor Zeek `conn.json` | 1,996 of 1,997 matched tuples | A tightly bounded 42–66 ms per-flow timestamp offset resembles modeled observation jitter more than capture-clock behavior. |

## Realism Score by Category

- **Field format accuracy:** 3/10 — Most schemas are detailed, but the dataset-wide RSTR/history direction mismatch violates core Zeek semantics.
- **Temporal patterns:** 5/10 — General traffic timing is varied, but HTTP transaction-depth inversions and bounded cross-sensor timing texture are conspicuous.
- **Cross-source correlation:** 9/10 — DNS, TLS, files, proxy, ASA, Snort, and multi-sensor relationships are generally coherent and source-native.
- **Behavioral realism:** 8/10 — Service mix, scanning, browsing, proxying, DNS caching, TLS, and DHCP behavior are operationally plausible.
- **Environmental consistency:** 9/10 — Addressing, host roles, source-port ranges, internal services, and perimeter routing form a credible enterprise environment.

## Recommendations

- If this were synthetic, derive both `conn_state` and history reset case from one canonical reset actor. `RSTO` must carry an originator-side uppercase `R`; `RSTR` must carry a responder-side lowercase `r`, with packet direction and close ownership changed consistently. Add coverage across LDAP, SMB, HTTP/TLS, MySQL, and raw/unclassified TCP paths.
- Validate every state/history pair against Zeek’s connection-state automaton. In particular, prevent `S1` from carrying FIN or RST markers and verify S2/S3 close direction.
- Preserve monotonic request-first-seen timestamps for increasing HTTP `trans_depth` on a UID. If response completion timing is also needed, keep it separately rather than using it as the Zeek HTTP `ts`.
- For rejected or authentication-required CONNECT requests, omit or zero tunnel-only fields. If whole client/proxy TCP totals are useful, rename them to transport or connection accounting so they do not claim that a tunnel existed.
- Model cross-sensor timestamps as coherent sensor clock offset plus realistic drift and path transit, rather than applying a newly bounded delay to each flow. Keep source-local lifecycle records on the same clock model.
