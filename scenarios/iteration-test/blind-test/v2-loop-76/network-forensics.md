# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 74

## Executive Summary

The network telemetry is technically sophisticated and preserves many Zeek-native relationships, including believable DNS caching, TCP state behavior, proxy flow chaining, and firewall byte accounting. However, dataset-wide timing and packet-loss distributions—especially the 1.200-second connection-duration spike and nearly uniform tiny `missed_bytes` injection—combine with host-role-inappropriate client software and several referential gaps to make synthetic generation more likely.

## Evidence For Synthetic

- `[distribution_texture]` A sharp duration spike occurs at approximately 1.200 seconds across unrelated traffic. In `zeek-dmz/conn.json`, 79 connections fall within ±1 ms of 1.200 seconds, 78 of them TLS sessions spanning 31 different SNI values and both inbound portal and outbound proxy traffic. The same artifact appears in 13 core TLS sessions and four DB-sensor TLS sessions. Values cluster tightly around `1.200076`–`1.2008`, suggesting a shared duration floor or template rather than independent network behavior.

- `[distribution_texture]` TCP content gaps have an unusually uniform, source-independent profile. After excluding `S0` and `REJ`, nonzero `missed_bytes` occurs in 505/4,465 core connections (11.3%), 526/4,382 DMZ connections (12.0%), and 38/333 DB connections (11.4%). The rate remains near 8–15% in almost every half-hour bin despite major changes in traffic volume, while the median gap is only 23 bytes and 158 core and 192 DMZ gaps are ten bytes or smaller. Real SPAN/TAP loss normally correlates more strongly with sensor load and missing packet payload sizes; this looks like per-connection random gap injection.

- `[environment_or_collection_plausibility]` Client software is placed on implausible host roles. In `zeek-dmz/http.json`, DC-01 (`10.10.2.10`) originates eight Cisco Secure Client, eight GlobalProtect, five Zscaler Client Connector, and three Duo Device Health requests during six hours. DC-02 (`10.10.2.11`) originates seven Cisco, nine Zscaler, and three Duo requests. The proxy itself (`10.10.3.20`) also emits Cisco, Zscaler, Duo, and Windows client-management user agents. Simultaneous placement of several competing remote-access/client products on both domain controllers resembles a broadly reused application pool.

- `[contract_gap]` Four HTTP file references lack corresponding `files.json` records. Examples include core HTTP UID `C91mYq6UYcA27ppIeH4` at `2024-03-18T17:44:29.412273Z`, whose `resp_fuids:["F2cWGfDL3ILRcnWeKxj"]` has no core files record despite `missed_bytes:0`, and DMZ UID `CsvBzxftimGwQ091VW` at `13:55:18.351380Z`, whose request and response FUIDs are both absent despite a completed `200` response, 47,821 response bytes, and no missed bytes.

- `[weak_signal]` The proxy lifecycle has one isolated child-flow anomaly. Of 1,268 successful DMZ HTTP CONNECT transactions, 1,267 have a same-host outbound TLS handshake within ten seconds. The exception is a `sharepoint.com` CONNECT at `13:36:44.942102Z`; the nearest TLS handshake began 0.313 seconds earlier and belongs temporally to the preceding CONNECT at `13:36:44.366269Z`. Upstream pooling or interception could explain this, so it is not treated as a hard contradiction.

## Evidence For Real

- TCP state semantics are strong. Across all three sensors, no `SF` connection lacks packets from either side, no `S0` connection has response packets, and every `REJ` checked has the expected one-origin/one-response packet pattern. Histories such as `S`, `Sr`, `ShADadfF`, and `ShADadr` align with the recorded states.

- DNS behavior contains realistic long-tail detail. Core DNS includes A, AAAA, PTR, TXT, SRV, NS, SOA, and MX queries, plus 200 NXDOMAINs, 21 SERVFAILs, four REFUSED responses, and AAAA/NODATA responses represented as `NOERROR` without answers.

- Recursive DNS cache behavior is unusually convincing. Nine observable repeated external-answer cases within a prior TTL all count down correctly to within three seconds. For example, `api.snapcraft.io` from resolver `10.10.2.10` falls from TTL 618 at `13:13:30Z` to 554 after 64 seconds, and `registry.npmjs.org` falls from 1,460 to 304 after 1,156 seconds.

- DNS response times are varied and plausible: core median RTT is 3.2 ms with a 2.397-second maximum, while the DMZ median is 9.9 ms with a similar long tail. Windows-style `wpad`, `isatap`, suffix-appended, SRV, and reverse lookups are present.

- Proxy correlation is excellent. `zeek-dmz/http.json` contains 1,376 CONNECT requests; failure statuses appropriately lack outbound handshakes in almost every case, while 1,267/1,268 successful requests have a subsequent matching SNI from `10.10.3.20`.

- TLS semantics are internally consistent. TLS 1.3 appears only with TLS 1.3 cipher suites, and TLS 1.2 uses appropriate ECDHE RSA/ECDSA suites. All 563 inspected TLS leaf certificates with visible chains match their SNI through the subject or SAN and are valid at observation time.

- TLS 1.2 handshakes containing a certificate-history marker but no recorded chain all have nonzero `missed_bytes`. This plausibly explains the missing certificate extraction and demonstrates correlation between packet loss, TLS history, and file-analysis output.

- Firewall accounting matches Zeek at the IP-byte level. For the proxy connection beginning at `12:00:10Z`, Zeek records 3,723,000 origin IP bytes plus 70,206 response IP bytes; ASA connection `1681558` tears down with exactly 3,793,206 bytes. The associated outbound TLS flow similarly totals 3,828,613 Zeek IP bytes, matching ASA connection `1681559`.

- Background traffic is heterogeneous. The core sensor records 9,034 `SF`, 1,985 `S0`, 140 `RSTO`, 82 `RSTR`, 22 `REJ`, and several partial/other states. DHCP renewals occur at plausible lease fractions, and internal traffic includes Kerberos, LDAP, SMB, SMTP, SSH, RDP, DHCP, and syslog.

## Detailed Analysis

### Collection Window and Volume

The Zeek data covers approximately `2024-03-18T12:00:10Z` through `17:59:24Z`. There are 11,339 core, 7,986 DMZ, and 403 DB connection records. Core and DMZ have traffic in essentially every minute, with a major but explainable scan burst at `13:40Z`.

The core connection mix is 5,910 TCP, 5,001 UDP, and 428 ICMP. Services include 2,871 DNS, 2,576 Kerberos, 1,482 HTTP, 1,182 LDAP, 416 SMB, 362 TLS, 317 syslog, 62 SSH, 48 DHCP, 46 SMTP, and 20 RDP connections. This is a credible modern mixed Windows/Linux enterprise protocol mix.

### Connection States and Scan Behavior

TCP state progression is source-native and coherent. `S0` flows contain an origin SYN and no response, `REJ` flows contain a responding reset, established flows have bidirectional packets, and byte counts never exceed corresponding IP-byte totals.

At `13:40:35.600849Z`, `10.10.3.10` begins a roughly 22.5-second sweep of the full `10.10.2.1–254` range. The DMZ sensor sees 1,525 records and the core sees 1,524. The principal probe set consists of ICMP plus TCP ports 22, 80, 443, 445, and 3306. Target order and inter-packet gaps vary, while responsive systems return `SF`, `REJ`, or reset states. This resembles an actual parallel network scanner and was not treated as synthetic merely because the scan is reconstructable.

The suspicious timing defect instead lies in unrelated successful connections. The 1.200-second pile-up spans external clients connecting to `ehr-portal.meridianhcs.com`, proxy-originated cloud sessions, and internal TLS services. A common application timeout could create a local spike, but the same microsecond-scale cluster across unrelated directions and services is difficult to explain organically.

### DNS Behavior

Core DNS contains 2,860 records: 2,092 A, 249 AAAA, 124 PTR, 288 TXT, 96 SRV, and eleven other records. The 200 NXDOMAINs include realistic suffix-search artifacts such as `wpad`, `wpad.local`, `wpad.meridianhcs.local`, `isatap`, retired internal hosts, and unsuccessful PTR requests. AAAA queries frequently return `NOERROR` with no answer, which is normal NODATA behavior.

Internal authoritative responses use stable configured TTLs such as 300, 1,800, 7,200, and 86,400 seconds. External recursive responses show remaining-TTL countdown rather than simply repeating a fixed value. No violations were found among nine directly testable same-resolver, same-RRset observations occurring before the prior cache lifetime expired.

The dataset also includes 254 TXT queries from `10.10.2.30` to two internal resolvers between `16:44:54Z` and `16:59:50Z`, primarily under `westbridge-services.cloud`. Inter-arrival times vary substantially and successful replies use TTL 1, while some names return NXDOMAIN. This is plausible DNS tunneling behavior; its suspiciousness does not itself indicate synthetic origin.

### HTTP Proxy and TLS

DMZ HTTP contains 1,764 transactions, of which 1,376 are CONNECT requests. Statuses include 200, 403, 407, 502, 503, and 504. Successful CONNECTs normally cause a proxy-originated TLS connection with the same destination name approximately 0.08–0.5 seconds later. Failure responses generally have no such child flow.

TLS coverage includes 1,398 TLS 1.3 and 726 TLS 1.2 DMZ handshakes. Cipher selection is compatible with each version and includes AES-128/256-GCM, ChaCha20-Poly1305, and appropriate TLS 1.2 ECDHE suites. Session resumption correctly omits certificate chains, while visible full TLS 1.2 chains join to both `files.json` and `x509.json`.

The proxy child-flow model is therefore highly realistic overall. The single unmatched successful `sharepoint.com` CONNECT is notable specifically because the other 1,267 successful transactions establish a strong local lifecycle contract.

### File and Certificate Relationships

Every TLS certificate FUID that is present in `cert_chain_fuids` resolves to both a file record and an X.509 record. Certificate validity periods, SANs, subjects, issuers, key types, and signing algorithms are coherent.

The HTTP-side exceptions are narrower but concrete. Four referenced file identifiers from three transactions are absent. Two core exceptions occur at `16:51:10.432651Z` and `17:44:29.412273Z`; the latter has zero missed bytes. The DMZ transaction at `13:55:18.351380Z` lacks both its request and response file records despite zero missed bytes. Selective file-analysis policy is possible, but the surrounding HTTP records routinely create `files.json` entries for the same MIME types.

### Lateral and Infrastructure Traffic

Core port 445 has 667 connections: 412 `SF`, 246 `S0`, and nine reset/rejected flows. Normal SMB includes domain-controller `SYSVOL`/`NETLOGON`, Windows file shares, and Samba-hosted shares. SMB mapping, file-open, read, write, and rename activity joins correctly to connection UIDs.

Port 3389 has 20 successful sessions and 56 unanswered probes. Port 22 has 61 successful connections, 316 unanswered attempts, and five other outcomes. A monitoring host at `10.10.2.40` probes ports 22, 3389, and 5900 across endpoints, while workstations establish longer SSH/RDP sessions to servers. These behaviors are unusual in places but consistent with monitoring and administration; no impossible lateral-service ordering was found.

### Collection-Loss Texture

All nonzero `missed_bytes` values have corresponding gap indicators in connection history, and missing TLS certificate extraction occurs only where packet loss is recorded. That field-level relationship is realistic.

The distribution is not. Roughly the same fraction of otherwise established TCP connections receives a gap on every sensor and throughout the window. Small gaps dominate: the core and DMZ medians are both 23 bytes, and hundreds are only one to ten bytes. A real capture-loss process would normally depend on sensor load and lost packet sizes; it would not be expected to produce nearly identical per-connection incidence on core, DMZ, and DB sensors.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Zeek `conn.json` | Dataset-wide across all sensors | The microsecond-tight 1.200-second duration mode spans unrelated TLS destinations and traffic directions, strongly suggesting a shared generator duration floor. |
| `distribution_texture` | Zeek `conn.json` | Dataset-wide across sensors and time bins | Nearly identical 11–12% TCP gap incidence and tiny-byte gap distributions resemble uniform record-level injection rather than packet-level capture loss. |
| `environment_or_collection_plausibility` | Zeek HTTP | Repeated on domain controllers and proxy | Multiple competing endpoint/VPN client user agents appear on infrastructure hosts where their simultaneous deployment is unlikely. |
| `contract_gap` | Zeek HTTP/files | Three transactions, four FUIDs | Completed HTTP transactions reference file objects absent from `files.json`, including no-loss flows. |
| `weak_signal` | Zeek HTTP/TLS | One proxy transaction | One successful CONNECT lacks the subsequent TLS child flow demonstrated by 1,267 peer transactions. |

## Realism Score by Category

- **Field format accuracy:** 8 — Zeek fields, histories, TLS values, and identifiers are highly accurate, with only a few missing file-reference targets.
- **Temporal patterns:** 6 — Bursts, DNS timing, and flow ordering are convincing, but the dataset-wide 1.200-second duration mode is a strong artifact.
- **Cross-source correlation:** 9 — DNS, HTTP, TLS, files, X.509, Zeek sensors, and ASA records correlate exceptionally well; only isolated contract gaps remain.
- **Behavioral realism:** 7 — Scans, proxy browsing, authentication, DHCP, and lateral protocols are plausible, but client-software placement looks pool-driven.
- **Environmental consistency:** 6 — Network roles and services mostly cohere, while domain controllers and the proxy exhibit an implausibly broad set of competing client products.

## Recommendations

If this were synthetic, the following changes would improve it:

- Generate connection durations from packetized protocol lifecycles rather than applying a shared 1.200-second floor or template. Specifically test for narrow duration modes reused across different services, directions, and source families.

- Model capture loss at the packet and sensor-load level. Lost-byte sizes should follow actual segment/application payload sizes, rates should rise with local packet pressure, and separate sensors should develop distinct loss profiles rather than receiving a near-uniform per-connection probability.

- Scope HTTP user-agent catalogs by host role and installed-software inventory. Domain controllers and network proxies should not emit Cisco Secure Client, GlobalProtect, Zscaler Client Connector, Duo Device Health, and workstation-management agents unless their simultaneous installation is explicitly represented.

- Enforce the Zeek File Analysis reference contract for completed no-loss HTTP transactions. Every `orig_fuids` or `resp_fuids` value should resolve to a `files.json` record unless a visible truncation, policy exclusion, or stream gap explains the omission.

- Preserve the proxy lifecycle invariant demonstrated by the majority of the dataset: a successful CONNECT should have an appropriately ordered outbound connection/TLS child, or the telemetry should visibly represent upstream pooling or TLS interception when no new child is created.