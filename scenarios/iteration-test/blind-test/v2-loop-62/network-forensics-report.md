# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 94  
**Synthetic-Confidence Score:** 89

## Executive Summary

The dataset has unusually strong network-layer construction: TCP state transitions, packet accounting, DNS cache behavior, TLS certificates, firewall lifecycles, and proxy-origin correlations are internally coherent. Nevertheless, several concrete source-native fingerprints—especially noncanonical IPv6 rendering, start-time-sorted Zeek connection files, and a synchronized burst of role-inappropriate TXT lookups—make synthetic generation substantially more likely than sanitized production telemetry.

## Evidence For Synthetic

- `[schema_or_format]` Zeek DNS output contains noncanonical IPv6 text that should have been normalized when binary AAAA RDATA was rendered. In `zeek-core/dns.json`, 46 of 81 IPv6 answers were noncanonical, representing 36 distinct values; examples include `2600:1f18:54d7:0044::1` at `2024-03-18T12:05:42.162263Z` and `2a02:26f0:2d65:000c::1` at `12:06:04.232162Z`. Canonical forms would omit the leading zeros (`...:44::1`, `...:c::1`).
- `[distribution_texture]` The same 36 noncanonical IPv6 values all end in `::1`, across otherwise unrelated provider-style prefixes and domains. The pattern—random-looking fourth hextet, zero-padded to four digits, followed by `::1`—resembles an address-generation template rather than heterogeneous public DNS.
- `[distribution_texture]` All 27 Zeek JSON files are monotonically sorted by their `ts` field, including every `conn.json` file. Native `conn.log` output is normally written when flows terminate or time out, while `ts` records the connection start; long-lived flows should therefore create start-time inversions. For example, core UID `CSA18dYSdDfqaAF2C5` starts at `14:14:42.511082Z`, lasts `13,337.339384` seconds, and ends near `17:57:59.850Z`, yet appears at line 5,153 among the 14:14 start-time records. `zeek-core/conn.json` has zero inversions across 11,553 records, as do the 8,663-row DMZ and 507-row DB connection files. A deliberately re-sorted export could explain this, but no comparable export markers are visible.
- `[environment_or_collection_plausibility]` TXT behavior is both temporally batched and poorly aligned with host roles. Excluding the visible `ns1.westbridge-services.cloud` TXT stream, 36 of 37 other TXT records occur between `16:41:08.768896Z` and `17:03:54.445143Z`, spread across 19 clients. Examples include workstation-like `10.10.1.31` querying `_dmarc.microsoft.com`, DB host `10.10.4.10` querying `_verify.zoom.us`, domain controllers querying DMARC records, and file server `10.10.2.20` querying `_dmarc.microsoft.com`. Ordinary endpoints and infrastructure servers generally do not independently perform this heterogeneous sweep of SPF, DKIM, DMARC, and verification lookups within the same 23-minute interval.
- `[distribution_texture]` Resolver behavior is overly uniform across the apparent mixed-OS population. Every AAAA record has a matching A lookup from the same client and name within one second, and the AAAA always follows the A: 256/256 in core, 125/125 in DMZ, and 5/5 in DB. Deterministic A-then-AAAA behavior is possible for an individual resolver stack, but the absence of any reverse ordering or unpaired AAAA behavior across the whole environment is suspicious.
- `[environment_or_collection_plausibility]` UDP traffic has a very weak infrastructure long tail. Among 4,946 core UDP flows, destinations are almost entirely DNS/53, Kerberos/88, syslog/514, DHCP/67, three STUN/3478 flows, and three RADIUS/1812 flows; there are no UDP/123 connections anywhere. A six-hour mixed Windows/Linux, Active Directory-dependent environment would ordinarily produce at least some visible NTP traffic unless the routed collection policy specifically excluded it.
- `[contract_gap]` Four HTTP records explicitly reference FUIs absent from the corresponding sensor’s `files.json`: one in core, two in DMZ, and one in DB. Examples include core UID `CZuVG5Y6ynGI7hfeGF` at `17:57:52.195244Z`, which names `FHRBkJvybeG12BZVAz` despite `missed_bytes=0`, and DB UID `Cxmg2XpDRo5RHupEFXz` at `17:46:34.407684Z`, which names missing `FzsJV6pqBAaVFlxSsn`. This is low impact because independent log-export loss could produce the same result.

## Evidence For Real

- TCP states and histories are source-native and varied. Core contains 9,269 `SF`, 1,935 `S0`, 142 `RSTO`, 114 `RSTR`, 30 `REJ`, and smaller `S1`/`S2`/`S3`/`OTH` populations with compatible history strings.
- Packet accounting is sound. No connection violates minimum TCP, UDP, or ICMP header accounting, no TCP flow carries more payload than its packet count permits under a normal MTU, and no duration-bearing five-tuple overlaps a previous use of that exact tuple.
- The `13:40Z` scan has realistic network texture: approximately 1,523 attempts from `10.10.3.10`, predominantly `S0`, across ICMP and TCP ports 22, 80, 443, 445, and 3306, with a small number of `REJ` and established connections.
- DNS data has strong production-like detail: A, AAAA, PTR, SRV, TXT, MX, NS, and SOA records; NODATA AAAA responses encoded as `NOERROR` without answers; suffix-search NXDOMAINs such as `wpad.local`, `wpad.meridianhcs.local`, and `isatap`; plus `SERVFAIL` and `REFUSED` cases.
- Recursive TTL behavior is realistic. Of 21 repeated core responses observed while the prior cache entry remained live, 20 decayed within five seconds of the TTL expected from elapsed time. The single exception could reflect resolver prefetch or cache refresh.
- Fresh DNS answers correlate correctly with network use: all 1,035 DMZ TLS sessions for which a still-valid preceding A response was visible used an IP contained in that response.
- TLS is convincing. DMZ contains 1,521 TLS 1.3 and 861 TLS 1.2 sessions with modern GCM and ChaCha20 suites, plus a small CBC tail. All examined leaf certificates were valid at connection time, all SNI values matched the leaf CN or SAN, all 500 observed certificate-chain links had matching issuer/subject names, and every parent was marked as a CA.
- Proxy behavior is temporally coherent. Of 1,587 successful CONNECT requests to `10.10.3.20:8080`, 1,571 had a corresponding proxy-origin TLS session for the same hostname within two seconds; the median delay was approximately 198 milliseconds.
- Cross-sensor behavior is credible. A five-tuple/time join found 4,486 shared core/DMZ flows with identical connection states, independent Zeek UIDs, small sensor-clock offsets, and occasional packet/byte differences consistent with separate observation points.
- Firewall lifecycle behavior is strong. All 6,643 parsed ASA TCP teardown durations agree with their build/teardown timestamps. `SYN Timeout` maps overwhelmingly to Zeek `S0`, `TCP FINs` to `SF`, and reset directions to compatible `RSTO`, `RSTR`, or refusal states.
- All 67 core Snort alerts and all 111 perimeter alerts join to corresponding Zeek flows. Every matched DNS alert also joins to a DNS transaction under the same Zeek UID.
- Capture imperfections are present rather than absent: 553 core, 618 DMZ, and 55 DB flows report nonzero `missed_bytes`, with compatible `G`/`g` gap markers in TCP history.

## Detailed Analysis

### Collection Shape and Sensor Placement

The visible interval runs from approximately `2024-03-18T12:00Z` through `18:00Z`. The principal network sources contain:

- Core: 11,553 connections, 3,013 DNS transactions, 1,812 HTTP transactions, 337 TLS records, 582 files, 126 SMB mappings, 215 SMB file operations, and 46 SMTP records.
- DMZ: 8,663 connections, 1,054 DNS transactions, 2,082 HTTP transactions, 2,382 TLS records, and 1,597 files.
- DB: 507 connections, dominated by 331 identified MySQL sessions, with smaller DNS, HTTP, TLS, SSH, LDAP, Kerberos, and syslog populations.

The topology is coherent. `10.10.3.20` behaves as an explicit proxy, `10.10.3.10` as an externally reachable web system with an application path to `10.10.4.10:3306`, `10.10.2.10` and `.11` as domain controllers/DNS servers, and `10.10.2.40` as a logging destination.

### Connection States, Durations, and Packet Accounting

The core sensor’s connection population is 80.2% `SF` and 16.7% `S0`; the latter is heavily influenced by the `13:40Z` scan. DMZ is 68.1% `SF` and 28.4% `S0`, consistent with external scanning plus the internal scan crossing the DMZ boundary. DB traffic is 80.1% `SF`, with a believable tail of application-origin and responder resets.

TCP history strings match state semantics. Representative patterns include:

- `S0` with `S`
- `REJ` with `Sr`
- `RSTO` with `ShADaR` or `ShADadTR`
- `RSTR` with `ShADadr`
- `S2` with `ShADadF`
- `S3` with `ShADadf`
- `SF` with several FIN, retransmission, and gap variants

Successful SSH and RDP are somewhat bimodal. Of 51 successful core SSH sessions, approximately 13 last under 30 seconds while most interactive-looking sessions last 9–60 minutes, plus one 3.7-hour session. This could reflect automated probes versus interactive administration, so it is not independently decisive.

### DNS Semantics and Causality

Core DNS has 2,241 A, 256 AAAA, 256 TXT, 150 PTR, 94 SRV, seven MX, seven NS, and two SOA observations. The response-code distribution—2,759 `NOERROR`, 230 `NXDOMAIN`, 20 `SERVFAIL`, and four `REFUSED`—is believable.

DNS-to-connection ordering is sound where causality is directly visible. No application record precedes its parent Zeek connection, and all fresh checked DNS answers agree with subsequent TLS destination addresses.

The strongest DNS defect is representation rather than causality. AAAA RDATA originates as binary network data, so strings such as `2600:1f18:54d7:0044::1` should not survive Zeek address serialization with padded hextets. The related `::1` concentration across 36 distinct values strengthens the inference that addresses were constructed from a template.

The TXT population also has an implausible environmental distribution. The 219-record `westbridge-services.cloud` stream is internally plausible as a discrete high-entropy activity and is not synthetic merely because it is easy to identify. The separate 36-record sweep of unrelated SPF, DKIM, DMARC, and verification queries across workstations, DCs, file infrastructure, a DB host, and the monitoring host—during the same narrow interval—is the actual synthetic indicator.

### TLS and X.509

TLS protocol selection is realistic for March 2024. DMZ is approximately 64% TLS 1.3 and 36% TLS 1.2. Internal DB-facing TLS is entirely TLS 1.2, which is plausible for enterprise services. Negotiated suites are valid for their protocol versions.

Certificate handling is strong:

- No certificate is expired or not-yet-valid at its TLS timestamp.
- No SNI-to-CN/SAN mismatch was found.
- No referenced leaf certificate is absent.
- Certificate fingerprints are internally stable across repeated observations.
- Issuer/subject linkage is consistent through observed chains.
- Intermediate certificates are correctly marked as CAs.

The relationship between TLS version, resumption, and certificate visibility is also plausible: TLS 1.3 and resumed sessions frequently lack visible chains, while non-resumed TLS 1.2 sessions supply them.

### HTTP, Proxy, and File Evidence

HTTP method/status combinations are coherent. Successful CONNECT responses have no message body, GET requests do not carry request bodies, and 304 responses have zero response-body length. Per-UID `trans_depth` sequences begin at one and remain contiguous.

The proxy transaction model is especially convincing. Client-to-proxy CONNECT requests are followed by proxy-origin TLS with corresponding SNI and realistic subsecond delay. Failed CONNECTs use 403, 407, 502, 503, or 504 responses with plausible proxy-specific messages.

Four missing file references are the main contract weakness. Because three occur on connections with `missed_bytes=0` and away from the window boundary, packet loss does not explain them directly. A selective files-log export or collection drop remains possible.

### Firewall and IDS Correlation

ASA records use plausible native message families:

- `%ASA-6-302013/302014` for TCP builds and teardowns
- `%ASA-6-302015/302016` for UDP
- `%ASA-6-302020/302021` for ICMP
- `%ASA-6-305011/305012` for dynamic translations
- `%ASA-4-106023` for ACL denies

Connection IDs are monotonic, teardown timing matches declared duration, and reason/state mappings agree with Zeek. Firewall-visible flows absent from `zeek-dmz` are generally direct inside-to-outside or inside-to-inside paths visible on `zeek-core`, which is consistent with sensor placement rather than a contradiction.

Snort alert timestamps and tuples join cleanly to Zeek. Alerts include DNS TLD rules, BitTorrent, STUN, HTTP CONNECT, curl/APT policy signatures, ICMP signatures, JA3, and rapid-connection scanning. The rule mix is plausible and is not limited to the principal suspicious sequence.

### Timing and Distribution Texture

Minute-level connection counts are bursty rather than smooth. Core has a per-minute coefficient of variation around 2.54, largely because the scan creates a 1,553-record minute. High-volume ordinary pairs have broad, nonrepeating interarrival distributions.

The problem is source-native ordering. Every Zeek JSON file is sorted strictly by `ts`, despite connection and file-transfer lifetimes that should cause records to be written out of start-time order. This pattern is consistent with a deterministic renderer or post-generation sort. A real SIEM export explicitly sorted by event time could produce it, but these files otherwise resemble per-source Zeek logs rather than query results.

The second distribution concern is missing infrastructure diversity. The core sees thousands of routed UDP transactions but no NTP and almost no UDP outside six modeled service ports. This does not make individual records invalid, but the aggregate lacks the long tail expected from a live mixed-OS enterprise.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---:|---|
| `schema_or_format` | Zeek DNS | 46 core and 46 DMZ AAAA observations; 36 distinct values | Padded IPv6 hextets should not survive native serialization of binary DNS RDATA. |
| `distribution_texture` | Zeek DNS | 36 distinct generated-looking IPv6 values | Every noncanonical value ends in `::1` and follows the same prefix/hextet/suffix construction. |
| `distribution_texture` | All Zeek JSON | 27/27 files; 20,723 connection UIDs | Strict `ts` sorting persists even where multi-hour connection lifetimes should force native write-order inversions. |
| `environment_or_collection_plausibility` | DNS | 36 records, 19 clients, 23-minute interval | SPF/DKIM/DMARC/verification queries are batched across workstations, DCs, file, DB, proxy, and monitoring roles. |
| `distribution_texture` | DNS | All observed AAAA transactions | Every AAAA follows a matching A within one second; no reverse order or unpaired behavior occurs. |
| `environment_or_collection_plausibility` | Zeek conn/UDP | Dataset-wide | No NTP and almost no UDP long tail despite six hours of mixed Windows/Linux and AD activity. |
| `contract_gap` | Zeek HTTP/files | 4 of 755 HTTP FUID references | Referenced file objects are absent, including three cases without visible packet loss. |

## Realism Score by Category

- **Field format accuracy:** 6/10 — Most Zeek, ASA, Snort, HTTP, TLS, and X.509 fields are excellent, but the IPv6 textual representation is a significant native-format defect.
- **Temporal patterns:** 6/10 — Ordinary traffic is bursty and causally ordered, but native Zeek write ordering and the TXT batch are conspicuous.
- **Cross-source correlation:** 9/10 — Firewall, IDS, Zeek, DNS, proxy, TLS, certificate, and file relationships are exceptionally coherent, with only sparse FUID gaps.
- **Behavioral realism:** 7/10 — Flow states, scans, proxy browsing, TLS, SMB, SSH, and application traffic are plausible; role-inappropriate TXT activity weakens the picture.
- **Environmental consistency:** 6/10 — Host roles and network segmentation are coherent, but TXT-client placement and the constrained UDP infrastructure distribution are difficult to reconcile with production behavior.

## Recommendations

If this were synthetic, the highest-value improvements would be:

- Render IPv6 addresses through the same canonical conversion used by Zeek, ensuring leading zeros are removed. Replace the repeated random-hextet-plus-`::1` construction with provider-specific IPv6 address distributions and more varied interface identifiers.
- Preserve source-native emission semantics. `conn.json` should be ordered by connection termination/log-write time, not solely by connection-start `ts`; long-lived sessions should naturally create start-time inversions.
- Make TXT queries role-aware. Restrict SPF, DKIM, and DMARC resolution primarily to mail infrastructure or explicit security-validation services, and distribute legitimate TXT activity independently across the collection window.
- Introduce resolver-stack diversity so A/AAAA ordering, delay, and pairing depend on OS, application, cache state, and resolver behavior.
- Add realistic routed UDP infrastructure according to the modeled environment and sensor visibility—particularly NTP, plus an appropriate sparse tail of SNMP, QUIC attempts, or other deployed services.
- Keep HTTP and file observation decisions lifecycle-coherent. If a referenced `resp_fuid` is retained in `http.json`, retain its `files.json` row unless the collection profile explicitly models per-log export loss.
- Preserve the existing strengths: TCP state/history logic, packet accounting, TTL decay, proxy-to-origin sequencing, certificate-chain construction, independent sensor UIDs/clocks, and firewall/IDS correlation.
