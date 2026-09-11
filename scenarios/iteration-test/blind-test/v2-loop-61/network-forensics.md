# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 81  
**Synthetic-Confidence Score:** 68

## Executive Summary

The network telemetry is technically sophisticated: protocol lifecycles, sensor-specific clocks, DNS caching, proxy chronology, TLS certificates, and firewall state generally agree. However, several dataset-wide distribution patterns—especially templated multi-host DNS noise, role-inappropriate TXT queries, uniform IDS timing offsets, and weak proxy connection reuse—are difficult to reconcile with organic production traffic and make the data likely synthetic.

## Evidence For Synthetic

- `[distribution_texture]` In `zeek-core/dns.json`, 46 unique queries from 15 internal hosts share the exact grammar `<service-word>-<8 alphanumeric characters>.<risky TLD>`. The prefixes come from a small pool such as `sync`, `api`, `storage`, `telemetry`, `node`, and `cdn-check`; all 46 tokens are exactly eight characters, across `.cloud`, `.bit`, `.top`, `.to`, and `.tk`. Examples include `api-nt93ppcv.cloud` from `10.10.1.99` at 12:09:34, `update-kngbz4ut.top` from `10.10.3.10` at 13:02:20, and `api-qil3jbib.cloud` from `10.10.3.20` at 17:45:34. A single malware family could impose a grammar, but this combination of varied human-readable prefixes, fixed token length, multiple TLDs, and broad host distribution resembles a reusable generator pool.

- `[distribution_texture]` All 14 successful responses from that background-DNS family return `0.0.0.0`, but with nearly unique TTLs ranging from 3 to 890 seconds. The same apparent sinkhole behavior produces TTLs such as 3, 11, 13, 259, 598, 783, 844, and 890. A centrally imposed DNS sinkhole normally has a stable or narrowly configured TTL rather than a separately randomized value for each one-off domain.

- `[environment_or_collection_plausibility]` Excluding the concentrated DNS-tunnel source `10.10.2.30`, the dataset contains 36 TXT lookups distributed across 17 clients, including workstations, the database host, web/proxy systems, file servers, and mail infrastructure. Eleven are DMARC lookups, 13 are DKIM selector lookups, and four are verification records. For example, `10.10.1.36` queries `_dmarc.github.com`, `10.10.4.10` queries `_dmarc.sendgrid.net`, and `10.10.1.21` queries `selector2._domainkey.okta.com`. These are plausible on mail gateways, DNS-security systems, or administrative resolvers, but their broad sprinkling among ordinary endpoints and unrelated server roles is not typical production behavior.

- `[distribution_texture]` All 185 parsed Snort alerts occur in a narrow band 0.214974–0.324603 seconds after the matching Zeek connection timestamp, regardless of whether the alert is DNS, ICMP, BitTorrent, HTTP, JA3, or scanning related. At 12:48:23, for example, the core Zeek record for the `.top` query begins at `.507551`, while the Snort alert is at `.760130`; the corresponding perimeter observations have the same general delay shape. Independent clock offsets could explain a stable displacement, but two sensor pairs sharing an approximately 250 ms randomized kernel across unrelated signature trigger points looks modeled.

- `[distribution_texture]` Proxy connection reuse is weak. `PROXY-01.../proxy_access.log` contains 672 inspected tunnel IDs for 982 `ssl-inspect` requests, and 522 of the 672 tunnels—77.7%—carry only one inspected request after setup. During the `edge.pollfish.com` activity beginning at 12:05:02, the root document and successive CSS, image, application-JavaScript, and vendor-JavaScript requests use distinct tunnel IDs and client source ports. Modern browsers normally reuse or multiplex more of this traffic, although proxy policy and bump implementation could partly explain the result.

- `[weak_signal]` External TLS negotiation is almost entirely pinned to a single version/cipher pair per SNI. Among 41 SNI groups with at least ten TLS sessions, 38 use exactly one pair. All 26 groups that also have at least three distinct front-side user agents use one TLS fingerprint—for example, all 55 `pypi.org` sessions use TLS 1.3 with AES-256-GCM, while all 48 `registry.npmjs.org` sessions use TLS 1.2 with ECDHE-RSA/AES-256-GCM. Server preference and TLS interception make this possible, so I assigned this limited independent weight.

## Evidence For Real

- Connection-state semantics are internally credible. Core Zeek records include 8,716 `SF`, 1,951 `S0`, 150 `RSTO`, 98 `RSTR`, 27 `REJ`, and smaller `S1`–`S3`/`OTH` populations. Histories agree with their states: `S0` TCP flows use `S`, rejected flows use `Sr`, origin resets end in `R`, responder resets in `r`, and normal sessions carry plausible handshake/data/FIN histories.

- Every DNS, HTTP, and SSL record examined has a same-sensor `conn.json` UID with an identical 4-tuple. None precedes its associated connection, and none falls beyond the visible connection lifetime. All 539 core, 1,355 DMZ, and 34 DB file records also reference visible connection UIDs without impossible ordering.

- Separate Zeek sensors use independent UIDs and show plausible clock offsets rather than copied rows. There are 4,184 same-tuple core/DMZ observations, with the DMZ sensor typically about 114 ms earlier; the DB sensor is approximately 63 ms later than core. Some packet counts, byte counts, and histories differ across those observations, as expected from different vantage points.

- DNS cache behavior is unusually well modeled. Of 22 repeated same-resolver answers observed before the prior TTL should expire, 17 decrement to within 1.1 seconds of elapsed wall time. For example, `registry.npmjs.org` changes from TTL 870 at 12:06:21 to 251 at 12:16:40, matching the elapsed 619 seconds.

- DNS includes a credible mix of 2,114 A, 272 AAAA, 250 TXT, 127 PTR, 98 SRV, and smaller NS/MX/SOA populations. Results include NOERROR, NXDOMAIN, SERVFAIL, and REFUSED, with realistic suffix-search artifacts such as `wpad.local`, `wpad.meridianhcs.local`, `isatap`, and external names suffixed with `meridianhcs.local`.

- Proxy chronology is sound. I matched 1,390 client-side CONNECT requests to same-SNI outbound TLS sessions; every outbound TLS handshake follows the CONNECT request, with delays from approximately 32 ms to 9.89 seconds. This materially reduces concern about impossible proxy causality.

- TLS details are credible. The DMZ sensor contains 1,531 TLS 1.3 and 689 TLS 1.2 sessions using current cipher suites. All referenced certificate FUIDs resolve to `x509.json`, certificate validity windows cover the traffic timestamp, SNI values match leaf SANs, issuer/subject chains align, certificate-file SHA-1 values match X.509 fingerprints, and ECDSA/RSA ciphers agree with certificate key types.

- Missing TLS chains have a packet-loss explanation. The 26 non-resumed TLS 1.2 sessions with an X.509 handshake marker but no chain FUID all have nonzero `missed_bytes`; sessions without capture loss consistently carry the expected chain.

- Topology and host behavior are coherent: `10.10.2.10` and `.11` act as DNS/domain infrastructure, `10.10.3.20` as the proxy, `10.10.3.10` as the public web/application system, and `10.10.4.10` as the MySQL server. Successful app-to-DB, SMTP, SMB, Kerberos, LDAP, SSH, and RDP traffic follows those roles.

- Ephemeral-port ranges differ by apparent operating-system family: Linux-like hosts use approximately 32768–60999, while Windows-like hosts use 49152–65535. This is a subtle production-like detail.

- Traffic is bursty rather than uniformly spaced. Excluding the 13:40 scan minute, core traffic averages 26.4 connections per minute with a standard deviation of 13.1 and an inter-arrival coefficient of variation of 1.61.

- The 13:40 internal scan is technically convincing: `10.10.3.10` probes 253 addresses with ICMP and TCP ports 22, 80, 443, 445, and 3306 over roughly 25 seconds. Responsive and nonresponsive targets produce coherent `SF`, reset/reject, and `S0` outcomes rather than a single forced state.

- Firewall lifecycles are consistent. Of 7,403 ASA TCP/UDP connection IDs, 7,401 have correctly ordered build/teardown pairs whose reported duration agrees with elapsed timestamps; two remain open near the window boundary. No protocol mismatch or teardown-before-build condition was found.

## Detailed Analysis

### Collection and volume

The Zeek telemetry covers approximately 12:00–18:00 UTC on 18 March 2024. The core sensor records 11,012 connections, the DMZ sensor 8,360, and the DB sensor 461. Core hourly counts are 1,734, 3,041, 1,360, 1,547, 1,736, and 1,594; the 13:00 peak is explained by the concentrated 13:40 scan.

Core traffic consists of 5,858 TCP, 4,743 UDP, and 411 ICMP flows. Dominant services are DNS (2,887), Kerberos (2,285), HTTP (1,564), LDAP (1,157), SMB (415), TLS (325), and syslog (266). This is a plausible protocol mix for a small domain environment with an explicit proxy and centralized logging.

### TCP and connection behavior

The connection states and histories are mechanically correct across all three sensors. Median durations are 0.043 seconds on core, 1.526 seconds on DMZ, and 1.855 seconds on the DB segment, with long-lived SSH/RDP sessions extending into thousands of seconds.

Successful core SSH sessions have a median duration of approximately 2,108 seconds, while successful RDP sessions have a median near 1,978 seconds. SMB sessions are shorter, with a median around 3.37 seconds and several realistic larger transfers. Failed scans and closed ports correctly lack service classification because application analysis never completed.

Packet accounting is generally credible. IP-byte totals exceed payload byte totals by valid transport/header amounts, no negative byte or packet values appear, and no flow reports payload with zero packets. One large SMB transfer has more apparent payload per captured packet than a standard MTU would permit, but that connection records 32,768 missed bytes, which explains sequence-space versus captured-packet accounting.

### DNS

DNS response times range from tens of microseconds to 2.277 seconds, with a median of 2.55 ms on core and 8.40 ms on DMZ. Internal authoritative responses generally have `AA=true`, while external recursive answers use `AA=false, RA=true`. Both domain controllers serve DNS, and clients alternate between them.

The cache countdown behavior is a particularly convincing feature. Repeated records against the same resolver and RRset commonly decrease TTL by elapsed time, then reset after expiry. The A/AAAA pairing also has varied subsecond spacing rather than one fixed offset.

The main authenticity problems are not DNS mechanics but DNS population. Exactly eight-character pseudorandom suffixes are reused across a small set of semantic prefixes and risky TLDs on nearly every host type. Successful instances consistently return `0.0.0.0`, but with highly variable one-off TTLs. Likewise, mail-policy TXT lookups appear on many clients that have no evident reason to perform DMARC or DKIM validation directly.

The 214 TXT queries from `10.10.2.30` to `ns1.westbridge-services.cloud` form a distinct DNS-tunneling pattern. They use varied hexadecimal labels, nested channel markers, mixed responses, and TTLs mostly around one second. I did not score this as synthetic merely because it is suspicious or narratively concentrated; its wire-visible structure is internally plausible.

### HTTP, proxy, and TLS

HTTP records are dominated by explicit-proxy CONNECT requests: 1,428 of 1,589 core HTTP records and 1,480 of 1,818 DMZ HTTP records. Normal response codes include 200, 301/302, 304, 403, 407, 502–504, and 206. CONNECT response bodies remain zero in Zeek while the proxy’s custom access log separately records control-message and tunnel byte scopes, which is correct.

The proxy front/back timing is coherent. Outbound TLS follows client CONNECT requests, and external destination/SNI values correspond to the requested host. Certificate files, X.509 rows, TLS sessions, and OCSP responses preserve their identifiers and chronology.

Connection reuse is the weaker aspect. Of 672 bumped tunnel lifecycles, most contain only one decrypted request, and browsing bursts frequently create one tunnel per asset. That produces an overly connection-heavy texture for modern browser traffic, even allowing for proxy interception and parallel connections.

TLS versions and ciphers are current, and the directly accessed public portal has healthy client diversity: its 625 sessions include 509 TLS 1.3 and 116 TLS 1.2 negotiations across six ciphers. In contrast, most proxy-origin SNI groups are pinned to one version/cipher despite multiple front-side clients and user agents. This could be a proxy-stack or server-preference effect, so it remains supporting rather than decisive evidence.

### Firewall and IDS

The Cisco ASA records use plausible build, teardown, denial, and dynamic-PAT messages. Connection identifiers increase monotonically, lifecycle order is valid, and reported durations match second-resolution timestamps. For the BitTorrent flow at 12:02:12, for example, Zeek reports 792 origin and 382 responder IP bytes; the ASA teardown reports 1,174 bytes, exactly the two directions combined.

Snort signature names, SIDs, classifications, priorities, and tuples are plausible. Every alert maps to an appropriate visible connection, including DNS-TLD policies, ICMP scans, BitTorrent, HTTP CONNECT, basic authentication, and JA3 detections.

The alert timing distribution is the concern. A DNS-rule alert should normally inherit the triggering packet timestamp; different content signatures should trigger at different points in their sessions. Instead, every alert family on both sensors receives approximately the same 250 ms displacement from Zeek’s connection start, with little variance. Separate clocks or collector timestamps could explain some displacement, but the shared kernel across protocols is generator-like.

### Internal and lateral traffic

Internal traffic includes normal domain-controller Kerberos/LDAP exchanges, SMB use against file servers and SYSVOL/NETLOGON, SSH to Linux systems, RDP to Windows systems, and MySQL from the application host to the database segment. State and duration distributions are credible.

The SMB content contains some additional templated texture—repeated names such as `action-items`, `onboarding`, `policy`, `startup`, and `meeting-notes`, including future-year folders such as `Team\2026` during 2024—but these remain possible business document names and had little effect on the final score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---:|---|
| `distribution_texture` | Zeek DNS | 46 queries, 15 hosts | Exact eight-character suffix grammar, small semantic prefix pool, five risky TLDs, and broad host distribution look like reusable generated noise. |
| `environment_or_collection_plausibility` | Zeek DNS TXT | 36 queries, 17 hosts | DMARC, DKIM, SPF, and verification lookups are scattered across workstations and unrelated server roles instead of being concentrated on mail/security infrastructure. |
| `distribution_texture` | Snort + Zeek | All 185 alerts | Every alert family uses approximately the same 215–325 ms offset from connection start, independent of triggering protocol or packet position. |
| `distribution_texture` | Proxy access | 672 inspected tunnels | 522 tunnels carry only one inspected request, producing weak connection reuse and one-tunnel-per-object browsing texture. |
| `weak_signal` | Zeek TLS + proxy | 38 of 41 repeated SNI groups | Version/cipher choice is nearly deterministic per SNI despite varied front-side clients; proxy and server preferences provide a plausible alternative explanation. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, ASA, Snort, proxy, X.509, OCSP, and SMB fields are source-appropriate and internally valid.
- **Temporal patterns:** 7 — General traffic and protocol lifecycles are bursty and plausible, but IDS offsets and proxy connection reuse have modeled-looking distributions.
- **Cross-source correlation:** 9 — Tuples, UIDs, certificate references, sensor clocks, firewall lifecycles, and proxy front/back ordering are highly coherent without impossible visible chronology.
- **Behavioral realism:** 6 — Normal infrastructure and scanning behavior are credible, but DNS background grammars and one-request tunnel prevalence weaken authenticity.
- **Environmental consistency:** 7 — Host roles and service placement are coherent; widespread endpoint-originated mail-policy TXT lookups are the principal exception.

## Recommendations

- If this were synthetic, generate suspicious background DNS as coherent per-host or per-malware-family campaigns. Vary token grammar between families instead of giving unrelated hosts the same fixed eight-character pattern and small semantic prefix pool.

- If this were synthetic, model DNS sinkhole policy explicitly. A common enterprise resolver policy should return a stable or narrowly varying TTL for blocked domains rather than an independent random TTL between 3 and 890 seconds.

- If this were synthetic, bind DNS query types to host roles and applications. DMARC, DKIM, SPF, and verification TXT lookups should primarily originate from mail gateways, security resolvers, or documented administrative tools.

- If this were synthetic, timestamp IDS alerts from the actual triggering packet or model a stable sensor clock transformation. Avoid applying one approximately 250 ms latency distribution to DNS, ICMP, scanning, HTTP, and TLS signatures alike.

- If this were synthetic, add realistic browser and proxy connection reuse. Several resources from one origin should share a tunnel or multiplexed connection where the modeled HTTP/TLS stack permits it.

- If this were synthetic, derive TLS negotiation from both client-stack capabilities and server policy, with interception mode taken into account, rather than making repeated SNI groups almost universally select one fixed version/cipher pair.

