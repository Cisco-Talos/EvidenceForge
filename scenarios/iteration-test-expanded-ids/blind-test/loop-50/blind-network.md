# Network Forensics — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 76/100  
**Synthetic-Confidence Score:** 56/100

The evidence is technically coherent and substantially more realistic than a basic synthetic corpus. It does not support a confident synthetic verdict. Its main weakness is behavioral texture: several traffic families appear assembled from bounded templates and reusable actor roles, while the strongest evidence for authenticity is the convincing cross-sensor timing, protocol fan-out, and source-native firewall/proxy behavior.

## Executive Summary

The six-hour capture presents a coherent enterprise network with internal, DMZ, and perimeter observation points. Zeek connection, DNS, HTTP, TLS, X.509, file, OCSP, SMTP, and DHCP records generally obey their expected tuple and protocol semantics. The explicit proxy path is especially convincing: client-to-proxy `CONNECT` activity is separated from proxy-origin DNS and TLS traffic, while proxy access records preserve authentication, policy actions, inspection modes, and distinct control-message versus tunnel byte counts. ASA build, NAT, teardown, timeout, and deny messages are plausible and temporally compatible with the corresponding traffic.

The dual Zeek sensors are not simple duplicates. Shared flows receive different UIDs, modest differences in duration, packet accounting, history, and missing bytes, and a clock offset that grows from roughly 45 ms to 63 ms over the window. That smooth sensor drift is a strong real-world feature.

Synthetic suspicion comes chiefly from repeated behavioral motifs. A small set of prolific external addresses performs a wide menu of scanning, HTTPS, ICMP, and occasional STUN-like activity. Web visits repeatedly draw from a bounded asset and user-agent repertoire, and IDS alerts are concentrated in a compact catalog of conspicuous “interesting traffic” signatures. ICMP and several UDP families are unusually clean and categorical. These patterns resemble a well-engineered traffic model more than unconstrained packet-derived telemetry, but none is individually decisive.

## Evidence For Synthetic

### Behavioral/template texture

- Several external sources behave like reusable “scanner personas.” Addresses such as `185.70.41.45`, `37.75.195.175`, `145.78.103.167`, `38.186.148.245`, and `156.32.3.55` recur across many ports and activity types. Some combine broad TCP probing with ICMP or STUN-like records. Real scanners can do this, but the repeated assignment of diverse behaviors to a small prominent cast looks modeled.
- Public web traffic repeatedly cycles through a bounded set of paths: `/`, `/favicon.ico`, a small asset bundle, common administrative probes, and a short API vocabulary. Legitimate browser sessions also tend to retrieve the same compact asset sequence. This is plausible for one application but visually templated over hundreds of requests.
- User agents are varied but drawn from a small, stable version catalog. Browser, `curl`, Python, Go, bot, and update-client families are represented, yet reuse is strong enough to suggest enumerable pools.

### Protocol distribution

- Every observed ICMP connection is an echo-request/echo-reply transaction with type/code `8/0`, one packet each way, symmetric payload bytes, state `SF`, and history `-`. The payload sizes vary, but the complete absence of one-way pings, unreachable messages, duplicates, or other ICMP texture is unusually clean.
- All 1,769 TLS records across both sensors have `established=true`. Non-TLS connections contain failures, so this can partly reflect analyzer behavior, but a real six-hour perimeter capture often includes at least some partially parsed or failed TLS handshakes in `ssl.log`.
- TLS parameters are semantically correct but strongly categorical: a small set of cipher/version/history combinations accounts for nearly all rows. TLS 1.3 consistently omits visible certificate chains and TLS 1.2 certificate/resumption behavior is sharply partitioned. This is correct at a high level but has a rule-driven appearance.

### IDS composition

- The IDS stream is concentrated in a compact menu of recognizable signatures: suspicious TLD DNS queries, STUN, ICMP variants, BitTorrent, generic scans, policy user agents, certificate observations, and selected download types.
- The alert mix appears curated to provide hunting interest. The repeated `.top`, `.to`, `.tk`, `.bit`, and `.cloud` alerts are plausible individually, but their balanced recurrence alongside many unrelated “informational” signatures looks more like designed coverage than the uneven noise of a deployed ruleset.

### Repetition and regularity

- DHCP renewal behavior is highly orderly: every record is `REQUEST, ACK`, clients retain stable MAC/IP/hostname mappings, and renewal intervals track a small set of lease durations. Pre-window acquisition legitimately explains the absence of initial discovery, but the observed renewal population remains unusually tidy.
- DNS A/AAAA companion queries are frequently separated by randomized fractions of a second, with a median near 0.4–0.5 seconds. That is plausible for sequential resolver behavior, but across many clients it reads more like a shared timing model than heterogeneous resolver implementations.

## Evidence For Real

### Cross-sensor observation

- Of 1,857 shared connection tuples found across core and DMZ sensors, sensor timestamps differ by approximately 42–66 ms.
- The mean offset increases smoothly by hour, from about 44.5 ms in the first hour to 62.8 ms in the sixth, while retaining roughly 1–2 ms of local variation. This resembles genuine clock drift or asymmetric sensor timestamping.
- Shared observations receive different Zeek UIDs. Durations, byte counts, packet counts, histories, and `missed_bytes` sometimes differ between sensors rather than being copied wholesale.
- Cross-sensor service classifications and connection states remain consistent despite those observation differences.

### Zeek protocol integrity

- DNS, HTTP, and TLS rows resolve to same-sensor connection UIDs with matching five-tuples.
- DNS rows exhibit credible diversity: A, AAAA, TXT, PTR, SRV, NS, MX, and SOA; `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`; authoritative and recursive responses; variable TTL sets; and a wide RTT distribution.
- Connection-state coverage includes `SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `OTH`, `S1`, `S2`, and `S3`, with sensible concentration by traffic family.
- TCP histories, packet counts, IP-byte overheads, and `missed_bytes` are not universally pristine. Perimeter TLS and scan traffic includes resets, incomplete handshakes, asymmetric accounting, and capture loss.
- TLS cipher/version combinations are valid. Resumed sessions do not improperly carry certificate chains, and X.509/file fingerprints and chain FUIds are internally aligned.
- OCSP records refer to certificate serials and use plausible update windows and statuses.

### Proxy behavior

- Client-to-proxy `CONNECT` records target the proxy on port 8080, while proxy-origin DNS and TLS transactions use the proxy as the originator toward public addresses.
- Proxy logs distinguish tunnel setup, SSL inspection, denial, authentication requirement, and upstream failure.
- Denied `CONNECT` requests terminate at the proxy and include control-message byte scope. Successful tunnels distinguish `CONNECT` control bytes from tunneled request/response bytes.
- User attribution varies appropriately: interactive requests may carry principals while update and service activity is often anonymous.
- HTTP status and message pairings are sensible, including `200 Connection Established`, `403`, `407`, `502`, `503`, and `504`.

### Firewall behavior

- ASA records use plausible native message families: TCP/UDP build and teardown, dynamic translation build and teardown, ICMP build/teardown, and ACL denies.
- Public-to-DMZ traffic is represented as inbound NAT to the exposed server, while proxy-origin Internet traffic uses outbound PAT.
- SYN-only scans receive delayed `SYN Timeout` teardowns; successful sessions receive FIN/reset-related teardown reasons and nonzero byte counts.
- NAT and connection lifecycles use stable source ports and translations and remain temporally compatible with Zeek.

### Web and perimeter texture

- The public web server sees both ordinary browsing and Internet background noise: browser asset retrieval, redirects, partial content, cache responses, bots, administrative probes, API requests, errors, rate limiting, and authentication failures.
- Inbound activity involves hundreds of unique source addresses, not just a handful of scripted scanners.
- The DMZ sensor sees external scans, inbound application traffic, proxy egress, internal-to-DMZ traffic, and DMZ-to-internal dependencies, giving it a plausible observation footprint.

## Detailed Analysis

### Zeek connections and tuple semantics

The core sensor contains 6,218 connections, dominated by internal DNS, Kerberos, SMB, LDAP, proxy HTTP, SSH, DHCP, SMTP, and limited RDP. The DMZ sensor contains 5,445 connections, dominated by TLS, public scanning, proxy HTTP, DNS, database traffic, and web traffic. This division is architecturally credible.

State distributions differ meaningfully by sensor. Core traffic is overwhelmingly successful, while the DMZ includes 1,256 `S0` connections, consistent with unsolicited Internet SYN traffic. Internet scans target a credible set of exposed and commonly probed ports. Successful application traffic has duration and byte asymmetry, while unanswered scans contain zero application bytes and one originating packet.

The packet accounting is internally sound: UDP IP bytes consistently include the expected 28-byte IPv4/UDP overhead, and TCP overhead varies with packet count and header size. Some perimeter records include missing bytes and nontrivial histories.

### DNS

DNS is one of the stronger areas. Internal AD-related lookups, reverse records, service discovery, external application queries, OCSP names, WPAD noise, suspicious TLDs, TTL aging, and negative responses coexist. Query IDs and source ports are mostly unique but include plausible collisions.

The main authenticity reservation is population-level regularity. Companion A/AAAA timing is broadly randomized in a similar range across hosts, and internal record TTLs are concentrated around a few policy values. Those values are individually normal; the shared timing texture is what appears modeled.

### TLS, X.509, OCSP, and files

TLS records respect version/cipher constraints. TLS 1.3 uses AES-GCM or ChaCha20 suites; TLS 1.2 uses ECDHE RSA/ECDSA suites. Resumption and certificate visibility are compatible with passive inspection limitations, particularly for TLS 1.3. Certificate chains use plausible issuers, validity periods, key types, SANs, and CA flags.

X.509 timing follows SSL/file observation with small source-native delays. File records distinguish host certificates, intermediates, and OCSP bodies. This is technically strong.

The weakness is categorical completeness: the TLS population appears generated from a controlled set of valid combinations, and all emitted TLS sessions are established. More malformed, aborted, version-intolerant, or unclassified handshake texture would improve authenticity.

### HTTP, web, and proxy

HTTP status/message combinations and transaction delays are credible. The explicit proxy model is particularly persuasive because it does not collapse client-to-proxy and proxy-to-origin legs into one tuple. Denied and tunneled transactions behave differently, and the proxy record carries useful source-native details rather than merely restating Zeek.

The public web log has plausible scanners, browsers, redirects, cached resources, partial responses, application errors, and rate limiting. Its repeated asset bundles and finite client personas are the most visible templating artifact.

### Firewall and IDS

ASA connection, translation, teardown, timeout, and deny messages are structurally credible. The NAT boundary is coherent, and UDP lifecycle durations and byte totals fit their corresponding transactions.

IDS timestamps sit within milliseconds of matching packet observations, as expected for colocated sensors. Signature metadata, classifications, priorities, and directions are plausible. The concern is not correctness but selection: the alert catalog appears intentionally broad and evenly useful for an analyst, with less low-value repetition and ruleset-specific mess than many real deployments.

### Sensor timing

Timing is the strongest authenticity signal. Shared core/DMZ observations exhibit a smoothly increasing offset rather than an exact fixed delay. They also retain local jitter and source-specific accounting differences. HTTP and TLS parser timestamps occur after connection opening by plausible, variable intervals. IDS alerts remain near the triggering packet rather than being assigned coarse log times. ASA and access logs appropriately lose subsecond precision.

## Synthetic Indicator Summary

| Category | Indicator | Weight |
|---|---|---:|
| Behavioral | Reusable external scanner personas span many protocols and behaviors | Moderate |
| Behavioral | Web sessions repeatedly use compact path, asset, and user-agent pools | Moderate |
| Protocol | ICMP is universally clean, symmetric echo request/reply | Moderate |
| Protocol | All emitted TLS records are established | Low–Moderate |
| Timing | A/AAAA companion timing has shared randomized texture across clients | Low–Moderate |
| IDS | Alert selection is unusually curated and evenly analyst-interesting | Moderate |
| Lifecycle | DHCP renewal population is orderly and categorical | Low |
| Cross-source | Smooth sensor drift and source-specific differences oppose a simple synthetic verdict | Strong counter-indicator |
| Network architecture | Proxy, NAT, DMZ, and internal visibility boundaries are coherent | Strong counter-indicator |

## Realism Score by Category

| Category | Score |
|---|---:|
| Zeek flows, tuples, and protocol semantics | 8/10 |
| DNS and infrastructure traffic | 7/10 |
| TLS, HTTP, web, and proxy behavior | 8/10 |
| Firewall and IDS telemetry | 8/10 |
| Sensor timing and cross-source observation | 9/10 |

## Recommendations

1. Add imperfect ICMP texture: unanswered requests, ICMP unreachable/time-exceeded messages, duplicate replies, variable packet counts, and occasional one-sided sensor visibility.
2. Broaden TLS failure modes with aborted handshakes, non-established SSL entries, unsupported versions, certificate truncation, and analyzer gaps that do not resolve into clean categorical groups.
3. Increase behavioral entropy in public web traffic by expanding path grammar, request-header behavior, connection reuse, asset concurrency, crawler pacing, and session-specific cache state.
4. Decouple external actor behaviors so the same prominent IPs do not repeatedly cover scanning, ICMP, STUN, and application activity unless a coherent campaign justifies it.
5. Diversify DNS client implementations: parallel A/AAAA issuance, retransmissions, TCP fallback, EDNS differences, resolver-specific timeout patterns, and more heterogeneous cache behavior.
6. Let IDS output reflect a messier deployed ruleset: duplicated alerts on streams, suppressed categories, uneven noisy signatures, flowbit dependencies, and occasional alerts without a clean analyst-friendly companion.
7. Preserve the current proxy, NAT, cross-sensor drift, and source-specific accounting model; these are the corpus’s strongest realism features.
