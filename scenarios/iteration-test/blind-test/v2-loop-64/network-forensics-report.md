# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 68

## Executive Summary

The dataset is technically sophisticated and often resembles a real multi-vantage collection: connection-state diversity, packet loss, sensor clock offsets, DNS texture, TLS/certificate behavior, and proxy leg construction are all convincing. I nevertheless assess it as synthetic because several repeated, log-visible protocol contracts break in systematic ways, especially HTTP redirects with no `location`, complete separation between HTTP redirect clients and HTTPS portal clients, proxy-origin connections preceding their first visible exact DNS resolution, and Zeek DNS field/IPv6 rendering anomalies.

## Evidence For Synthetic

- [contract_gap] Every HTTP redirect lacks Zeek's `location` value: all 19 status 301/302 records in `zeek-core/http.json` and all 82 in `zeek-dmz/http.json`. This spans unrelated hosts such as `accounts.google.com`, `www.dropbox.com`, `www.bing.com`, and the internal-facing `ehr-portal.meridianhcs.com`, rather than one plausibly misconfigured application. Several DMZ redirects also carry content-derived MIME values that match the requested suffix instead of a normal redirect entity, including seven 301 responses logged as `text/css`, three as `application/javascript`, and four 302 responses as `image/x-icon`.
- [contract_gap] The public portal's HTTP-to-HTTPS client continuity is absent at dataset scale. In `zeek-dmz/http.json`, 74 inbound HTTP requests to `ehr-portal.meridianhcs.com` come from 74 distinct external source IPs; 40 receive 301/302 responses. None of those 74 source IPs appears anywhere among the 136 external source IPs making 587 TLS connections with SNI `ehr-portal.meridianhcs.com` in `zeek-dmz/ssl.json`/`conn.json`. For example, `98.0.214.7` receives a 301 at `2024-03-18T12:05:18.971691Z`, but no TLS flow from that address follows. Some users may decline redirects, but zero continuation or source reuse across this volume is an implausibly clean population split.
- [contract_gap] A repeated proxy transaction ordering has origin TLS connections before the proxy's first visible exact hostname/IP DNS lookup. Correlating successful client CONNECTs to `10.10.3.20:8080` with same-host proxy-origin flows within 0.6 seconds yielded 1,499 pairs; 24 origin flows had no earlier exact source/hostname/address DNS answer anywhere in the visible window and were followed by one 0.53–7.82 seconds later. At `13:12:48.138271Z`, `10.10.3.20` opens TLS to `20.190.151.70` with SNI `portal.azure.com`; two more such origin flows begin at `13:12:49.727347Z` and `13:12:50.211302Z`, while the first visible A lookup returning that address is only at `13:12:50.844831Z`. A stale cache could explain isolated cases, but the same pattern occurs hours into the window for low-TTL names including `news.ycombinator.com` (TTL 65), `tracking.loadbalance.dev` (TTL 60), `www.gstatic.com` (TTL 35), and `en.wikipedia.org` (TTL 46).
- [hard_contradiction] All three DNS `REFUSED` responses in `zeek-core/dns.json` retain `"rejected":false`, contrary to the source-native meaning of a refused query. Concrete examples are `resolver-98vrt3pd.bit` at `15:06:12.662318Z` (`rcode:5`, `rcode_name:"REFUSED"`), the TXT lookup for `961715c616c32059bf3f.img.c51.ns1.westbridge-services.cloud` at `16:44:50.237546Z`, and `0771f2fdcb2bdb3e26df.d33.ns1.westbridge-services.cloud` at `16:56:37.799241Z`.
- [schema_or_format] IPv6 answers are repeatedly rendered in non-canonical textual form in Zeek DNS JSON. In `zeek-core/dns.json`, 44 of 79 returned AAAA addresses contain zero-padded hextets; `zeek-dmz/dns.json` has 43 of 78. Examples include `2a04:4e42:6500:00df::1`, `2600:1f18:e6fc:0084::1`, and `2a03:2880:c76c:0099::1`. These are valid IPv6 values, but native Zeek address rendering normally emits the compressed hextets (`df`, `84`, `99`), so the repeated padding looks renderer-produced.
- [contract_gap] Zeek HTTP rows contain orphaned file references. Six of 285 HTTP FUID references in `zeek-core/http.json` and two of 508 in `zeek-dmz/http.json` have no matching `fuid` in the same sensor's `files.json`. Several occur on zero-loss connections, including core UID `CVnXO0JMP2B7FNCtAf` at `12:06:38.312682Z` referencing absent FUID `FfAS2xci1UFkFgFtEG`, and DMZ UID `CXRKEcyP8vUW7V84ux` at `12:02:52.918818Z` referencing absent `F4J3AuHzvopmDw2JyV` while `missed_bytes` is zero.
- [weak_signal] One SMB read lacks a preceding file-open record on the same connection despite zero observed packet loss. In `zeek-core/smb_files.json`, UID `CCaYQU08lZ9uHDCYpZ` reads `Templates\team-roadmap-final.pptx` at `17:17:04.791350Z`; its `conn.json` row has `missed_bytes:0`, but no same-UID `SMB::FILE_OPEN` exists. This is isolated and could reflect a durable/open handle, so it only modestly affects the verdict.

## Evidence For Real

- The three Zeek views behave like separate sensors, not duplicated exports. Of 4,299 matched core/DMZ five-tuples, service and connection state always agree, while timestamps differ by a median of about 114 ms and packet loss changes the byte counts, packet counts, and histories on a realistic subset. For UID-independent views of `10.10.1.34:57534 -> 10.10.3.10:80` at about `12:00:21Z`, DMZ observes 597,722 response bytes with no loss while core observes 590,876 with `missed_bytes:6846` and a loss-marked history.
- Connection-state texture is credible. `zeek-dmz/conn.json` contains 5,629 `SF`, 2,706 `S0`, 99 `RSTO`, 67 `RSTR`, 33 `REJ`, plus smaller `OTH`/`S1`/`S2`/`S3` populations. The `S0` volume has visible causes: external scanning and a 21.85-second internal `/24` scan from `10.10.3.10` at `13:40Z`, with ICMP plus ports 22, 80, 443, 445, and 3306, realistic randomized target order and microsecond spacing, and live hosts producing responses while unused addresses remain unanswered.
- DNS is rich and environmentally coherent. Core DNS has 2,107 A, 266 AAAA, 149 PTR, 96 SRV, 235 TXT, and smaller MX/NS/SOA populations, along with 198 NXDOMAINs, 13 SERVFAILs, and 3 REFUSED responses. Windows-like suffix-search noise (`wpad`, `wpad.local`, `isatap`, `oldserver.meridianhcs.local`) and mixed authoritative/recursive `AA` behavior are present. Repeated TTLs often model resolver cache countdown correctly: `ctldl.windowsupdate.com` returns TTL 2528 from `10.10.2.10` at `12:37:30.996948Z` and TTL 98 at `13:18:01.343966Z`, matching the elapsed time to within roughly one second.
- TLS behavior is internally strong. DMZ has 1,504 TLS 1.3 and 810 TLS 1.2 observations, six plausible modern/legacy cipher families, and 805 resumed sessions. Certificate chains appear mainly on non-resumed TLS 1.2 sessions, while TLS 1.3 and resumed sessions generally omit them. Every logged chain reference resolves, issuer-to-subject links align, observed certificates are valid at the event time, and no SNI-to-SAN mismatch was found. TLS 1.2 RSA/ECDSA cipher authentication also agrees with leaf key type.
- HTTP/file and packet accounting handle loss plausibly. File observations remain within their parent connection intervals, and `seen_bytes + missing_bytes` covers `total_bytes`. Two SMB reads whose declared file size exceeds observed response payload are fully accounted for by `missed_bytes` (32,768 and 27,156 bytes respectively), rather than presenting impossible transport totals.
- SMTP STARTTLS is modeled with source-native restraint. All 31 SMTP records marked `tls:true` have an SSL record on the same UID and expose only pre-encryption greeting/STARTTLS metadata; the 15 non-TLS SMTP records retain sender, recipient, subject, path, and attachment FUID information.
- DHCP renewals are host-specific and lifecycle-coherent. Six clients retain stable IP/MAC/hostname bindings; 3,600-second leases recur near 30-minute T1 intervals, 7,200-second leases near hourly intervals, and 14,400-second leases near two-hour intervals, each with jitter rather than identical timestamps.
- IDS and firewall evidence correlate without being byte-identical. All 57 core and all 83 perimeter Snort alerts parse consistently and have a matching Zeek tuple within five seconds; median Snort-versus-Zeek offsets are about 0.26 and 0.25 seconds. The ASA log includes coherent built/teardown pairs, NAT translation lifecycles, SYN timeouts, resets, ACL denies, and two connections still active at the collection cutoff rather than forced teardown.

## Detailed Analysis

### Collection Scope and Traffic Shape

The visible interval is approximately six hours, from `12:00:05Z` through `17:59:58Z`. Core records 11,230 connections, DMZ 8,571, and the database vantage 432. Core is dominated by DNS (2,873), Kerberos (2,290), proxy HTTP (1,743), LDAP (1,167), SMB (419), and TLS (390); DMZ is dominated by TLS (2,423), HTTP (2,024), DNS (948), and MySQL (292). This division fits the visible segmentation: endpoint/domain traffic is strongest at core, public/proxy traffic at DMZ, and application-to-database traffic at the DB sensor.

The conspicuous `13:40Z` spike is explainable in the records rather than merely smooth volume. `10.10.3.10` probes every address from `10.10.2.1` through `.254` with ICMP and five TCP ports. Core records 1,522 source flows during the minute, including 1,476 `S0`, 24 `REJ`, and a smaller number of completed/reset flows. This is consistent with a rapid discovery/port scan. External scanners add long-tail S0 traffic throughout the window, while the public portal and proxy account for successful DMZ traffic.

### DNS and Causality

Query-type, result-code, authority, and TTL distributions are among the strongest parts of the dataset. Internal names normally return `AA:true`; public recursion is generally `AA:false`; NODATA AAAA replies use `NOERROR` with no answers; PTR responses include both internal names and provider-style public names. DNS RTTs range from tens of microseconds to roughly 2.4 seconds rather than occupying one narrow band.

The problematic area is transaction ordering at the explicit proxy. Successful client CONNECTs are followed by proxy-origin connections quickly and consistently (median approximately 171 ms across 1,499 matched pairs), which makes the causal association strong. In 24 first-visible exact hostname/address cases, however, the origin SYN precedes the DNS query. The `portal.azure.com` cluster is especially clear because three client CONNECTs are each followed within 72–104 ms by a proxy-origin TLS flow to the eventual answer, and only afterward does the proxy issue the first visible lookup. Cached or stale DNS can explain an individual case, but the repetition across low-TTL names and events several hours after collection start makes a generalized stale-cache explanation weak. I therefore treat this as a contract gap, not an absolute impossibility.

The three `REFUSED`/`rejected:false` records are narrower but more source-native. `rcode=5` explicitly says the server refused the operation, while the Zeek convenience boolean denies that condition. The record should not encode both propositions simultaneously.

### HTTP, Proxy, and Public Portal Behavior

The proxy architecture is otherwise convincing. Client-to-proxy HTTP uses absolute URLs or CONNECT authority targets; proxy-to-origin HTTP uses relative paths; successful CONNECTs create separate TLS origin flows; 403/407/502/503/504 outcomes terminate without pretending every transaction succeeds. Large package downloads show plausible high-throughput enterprise links and sensor-specific loss. For example, the `updates.paloaltonetworks.com` MSI at `12:54:38Z` is 151,695,174 bytes at DMZ, while core sees 151,662,406 body bytes and 32,768 missed bytes.

Redirect handling breaks that realism. A 301 or 302 without `Location` is legal only as a malformed or unusual response, yet it occurs in every redirect across unrelated public services and the portal. The portal also generates suffix-derived MIME types on redirect entities, such as a 301 `text/css` response for `/assets/main.css` at `12:07:07.219842Z` and a 302 `image/x-icon` response for `/favicon.ico` at `12:26:23.799098Z`. Combined with zero source-IP continuity from 40 redirecting HTTP clients into TLS, the evidence suggests separately sampled HTTP and HTTPS generators rather than clients traversing one protocol lifecycle.

### TLS, Certificates, and OCSP

TLS versions and ciphers are plausible for a March 2024 mixed estate. TLS 1.3 prefers AES-128-GCM, AES-256-GCM, and ChaCha20; TLS 1.2 includes ECDHE-RSA/ECDSA with GCM plus a smaller CBC population on internal services. SNI, certificate SAN, chain issuer, validity, and key/cipher authentication checks pass. Reused certificate fingerprints preserve identical metadata while each extraction receives a separate FUID, which is what multiple sensor observations should look like.

The principal TLS-adjacent format concern is IPv6 answer rendering, not TLS itself. More than half of returned AAAA strings use fixed-width zero padding inside otherwise compressed addresses. The consistency of this unusual representation across dozens of answers and both core/DMZ views is more suggestive of a custom formatter than native sensor output.

### Cross-Sensor and Source Correlation

Cross-vantage differences are a major authenticity strength. Matched flows preserve tuple, service, and state but vary packet counts and `missed_bytes` in ways that propagate into HTTP/file totals. DB observations are about 64 ms after core on median; DMZ is about 114 ms before core and 178 ms before DB. These offsets are stable enough to represent clocks yet include per-event jitter. Snort alerts likewise maintain source-specific offsets while matching exact tuples.

The orphaned FUIDs are the exception. A Zeek HTTP record that publishes `resp_fuids` has already assigned a file-framework identity. Absent filtering metadata, retaining the HTTP reference while dropping the corresponding same-sensor file row creates an analyst pivot that terminates unexpectedly. Packet loss explains some missing file extraction, but not the cited zero-loss examples.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | Zeek HTTP / proxy / public portal | Dataset-wide: all redirects; 40 inbound portal redirects with no client TLS continuation | Highest-impact indicator because two ordinarily linked protocol phases form completely separate populations. |
| `contract_gap` | Zeek DNS + proxy-origin TLS | Repeated: 24 first-visible exact hostname/IP resolutions occur after origin flow start; 84 matched transactions have DNS-after within 10 seconds | Strong causal fingerprint, moderated because stale resolver cache is possible in isolated cases. |
| `hard_contradiction` | Zeek DNS | Three REFUSED responses | Narrow but direct source-native semantic contradiction (`rcode=REFUSED`, `rejected=false`). |
| `schema_or_format` | Zeek DNS AAAA | Broad: 44/79 core and 43/78 DMZ returned AAAA values | Repeated non-native-looking zero-padded IPv6 rendering across many domains. |
| `contract_gap` | Zeek HTTP/files | Eight orphaned HTTP FUID references across core and DMZ | Breaks same-sensor analyst pivots, including on zero-loss flows; low frequency limits impact. |
| `weak_signal` | Zeek SMB | One read without same-UID open | Isolated lifecycle gap with plausible alternate explanations. |

## Realism Score by Category

- **Field format accuracy:** 7/10 — Most Zeek, Snort, ASA, TLS, and certificate fields are strong, but REFUSED semantics and systematic zero-padded AAAA rendering are conspicuous.
- **Temporal patterns:** 7/10 — Flow durations, scanning cadence, clock offsets, and DHCP/TTL timing are convincing; proxy DNS sometimes follows the origin connection it appears to authorize.
- **Cross-source correlation:** 8/10 — Multi-sensor packet loss, tuple/state agreement, Snort timing, SMTP STARTTLS, and proxy legs correlate well, offset by orphaned FUIDs and HTTP-to-HTTPS client discontinuity.
- **Behavioral realism:** 6/10 — Protocol and service mixes are strong, but universal malformed redirects and disjoint portal client populations are difficult to reconcile with real browser behavior.
- **Environmental consistency:** 8/10 — Network segmentation, authoritative/recursive DNS roles, public portal use, proxy egress, scanners, mail, SMB, Kerberos, LDAP, and database traffic form a credible enterprise environment.

## Recommendations

- If this were synthetic, model an HTTP redirect as a complete response contract: emit a plausible `Location` header/value, use a redirect-appropriate entity MIME type, and carry the same client IP/user-agent into a follow-on TLS connection probabilistically. Validate this over both direct portal traffic and explicit-proxy client/origin legs.
- If this were synthetic, make proxy DNS resolution an owned prerequisite of a fresh origin connection. Reuse cached answers only while an explicit cache entry remains valid (or is deliberately served stale), decrement TTL by elapsed time, and record refresh/prefetch behavior separately so DNS-after-flow cases are explainable rather than random.
- If this were synthetic, align Zeek DNS projection semantics: set `rejected:true` for `REFUSED` transactions and canonicalize IPv6 strings before writing `answers`.
- If this were synthetic, make source-local observation decisions coherent for HTTP/FUID/file lifecycle groups. If a `files.json` row is dropped, either retain a documented collection/filter explanation or avoid publishing an orphaned `resp_fuids` reference; preserve the full group on zero-loss connections.
- If this were synthetic, preserve SMB open/read lifecycle grouping when no packet loss or pre-window handle explains the omission, while retaining the already realistic transfer-size and loss accounting.
