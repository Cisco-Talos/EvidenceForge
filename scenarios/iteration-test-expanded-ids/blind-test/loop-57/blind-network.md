# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 68

## Executive Summary

The network telemetry is technically strong: Zeek protocol records remain inside their parent connection intervals, cross-sensor observations differ in realistic ways, and the firewall, proxy, TLS, DNS, SMTP, and web evidence form a coherent topology. I nevertheless assess it as synthetic because several dataset-wide textures are difficult to reconcile with one production environment: almost metronomic per-client DHCP renewals, extreme concurrent SSH/RDP use from a few workstations, highly concentrated scanner populations, and no NTP traffic in an otherwise broad mixed-protocol capture.

## Evidence For Synthetic

- `[distribution_texture]` DHCP renewal timing is implausibly deterministic by client. All 69 `zeek-core/dhcp.json` records are `REQUEST,ACK`; for `10.10.1.31` the ten successive gaps stay between 1,968.90 and 1,970.83 seconds, while `10.10.1.32` stays between 1,691.49 and 1,693.68 seconds. Other clients show the same pattern with a different fixed offset (for example, `10.10.1.21` at roughly 1,940 seconds). The sub-two-second cycle jitter around a host-specific offset, repeated for six hours, looks like periodic-plus-jitter generation rather than normal lease/T1 scheduling and network delay.
- `[environment_or_collection_plausibility]` There are zero UDP/123/NTP connections across 6,306 core and 5,424 DMZ `conn.json` rows during the six-hour window, even though the same sensors record DNS, DHCP, ICMP, Kerberos, LDAP, Windows clients, Linux systems, a domain controller, and Internet egress. This is not merely a request for another source: the visible collection profile is broad enough that total absence of domain and Linux time synchronization is an odd protocol-distribution hole.
- `[distribution_texture]` Successful remote administration is vastly overrepresented. In `zeek-core/conn.json`, `10.10.1.35` opens 49 successful SSH sessions totaling 19.29 session-hours and `10.10.1.31` opens 47 totaling 18.63 session-hours during only six wall-clock hours; each reaches six different mail, application, web, proxy, and database systems and peaks at seven simultaneous SSH sessions. `10.10.1.21` adds 24 sessions totaling 8.29 hours and peaks at five concurrent sessions. The same sources also produce substantial RDP activity (eight sessions/3.94 hours from `10.10.1.31`, four/1.26 hours from `10.10.1.35`). Persistent multiplexed administration is possible, but this repeated breadth and density across several workstations is generator-like baseline texture.
- `[distribution_texture]` Failed inbound scanning is concentrated into a small, stylized cast. Of 1,225 DMZ TCP `S0` rows, only 14 external sources appear and nine account for nearly all activity; individual sources specialize heavily in fixed service families (for example, `38.186.148.245` produces 86 port-25 and 38 port-587 attempts, while `37.75.195.175` produces 82 port-23 and 29 port-2323 attempts). The repeated port-family personas over the full window are cleaner and less diverse than typical background Internet scanning.
- `[weak_signal]` Two long core sessions whose starts fall inside the window carry computed closes after the apparent 18:00 UTC boundary: SSH UID `CJilQwMG481aErv3gd` starts at 17:54:20 UTC and its 1,721.606821-second duration ends around 18:23:02, while RDP UID `C4OZtmYnU27ZD3hZwJ` ends around 18:08:30. This is explainable if the records were selected later by connection start time, so it is not a contradiction, but it is consistent with a bounded scenario that retained preplanned durations.

## Evidence For Real

- The two Zeek sensors behave like independent observers rather than copied files. The 10.10.1.22:55108 to 10.10.3.10:80 request appears at epoch `1710763550.384042` in core and `1710763550.426481` in DMZ, with different UIDs (`CjA7h4oHv8CTeIFnZW` versus `CfpjhD0joYEqG4OYFn`) but the same HTTP semantics and byte counts. Connection durations differ slightly across sensors while payload counters agree, which is realistic for separate taps.
- Zeek connection mechanics are convincing. Core TCP states include 3,022 `SF`, 93 `RSTO`, 52 `RSTR`, 19 `S0`, 19 `REJ`, 11 `S2`, six `S3`, and 17 `OTH`; histories vary across normal close, reset, partial, and gap patterns. IP-byte accounting is physically consistent with packet counts and minimum protocol headers in every checked core and DMZ row.
- DNS has credible breadth and semantics: A, AAAA, PTR, SRV, TXT, MX, NS, and SOA records; NOERROR, NXDOMAIN, SERVFAIL, and REFUSED outcomes; suffix-search noise such as `isatap`, `wpad`, and `oldserver`; and internal reverse/SRV answers that agree with visible infrastructure. Empty-answer internal AAAA responses are correctly represented as NOERROR/NODATA rather than NXDOMAIN.
- Protocol fan-out is structurally sound. Every DNS, HTTP, SSL, and SMTP UID checked resolves to a parent connection on the same sensor, and none occurs before the connection or after its visible interval. All TLS certificate FUIDs resolve through `files.json` and `x509.json`, and no observed certificate is outside its validity period.
- TLS behavior is modern and nuanced: TLS 1.2 and 1.3, RSA and ECDSA suites, AES-GCM/ChaCha20, session resumption without certificate chains, varied SNI, OCSP, and repeated certificate fingerprints with per-observation FUIDs. The public web service, mail STARTTLS, and proxy-origin TLS patterns are distinct rather than one universal template.
- Proxy and firewall evidence reflects a plausible routed network. Client `CONNECT` requests to 10.10.3.20:8080 are followed by proxy-origin TLS flows, the proxy log distinguishes tunnel setup, SSL inspection, denial, cache/status outcomes, and tunnel byte counters, and ASA build/teardown/NAT records match visible tuples. For 10.10.3.20:49394 to 52.84.255.1:443, the ASA teardown reports 5,450 bytes, exactly matching Zeek IP-byte totals of 1,163 plus 4,287.
- Public web traffic has realistic diversity: successful TLS visitors, crawlers, internal HTTP browsing, varied methods and response statuses, asset bursts with stable object sizes, changing dynamic page sizes, and 79 external addresses in the web access log. This is substantially more production-like than the scanner subset alone.

## Detailed Analysis

### Scope and topology

The observable window runs from approximately 2024-03-18 12:00:11 through 17:59:58 UTC. Network-facing sources comprise 6,306 core and 5,424 DMZ Zeek connections, 2,206 core and 765 DMZ DNS rows, 1,017 core and 1,198 DMZ HTTP rows, 117 core and 1,675 DMZ TLS rows, plus DHCP, SMTP, files, X.509, OCSP, PE, Cisco ASA, two Snort sensors, a 2,146-row explicit-proxy log, and an 804-row web access log. The apparent topology separates workstations (10.10.1.0/24), servers/DC (10.10.2.0/24), DMZ web/proxy (10.10.3.0/24), and a database segment (10.10.4.0/24).

### Connection states, packets, and timing

Core traffic is balanced between successful TCP (3,022 `SF`) and UDP (2,983 `SF`), with a credible smaller tail of reset, reject, partial, and anomalous states. The DMZ has 3,171 successful TCP rows and 1,225 TCP `S0` rows, consistent in principle with an exposed perimeter. Histories fit their states: `S0/S`, `REJ/Sr`, normal `ShAD...Ff` closes, originator resets, responder resets, and gap markers. Checks of all rows found no case where IP byte totals were too small to contain payload plus minimum TCP, UDP, or ICMP headers.

The strongest behavioral concern is remote-administration density. At 12:02:41 UTC, SSH from 10.10.1.31:53988 to 10.10.3.10 lasts 1,068.166185 seconds; numerous similar long sessions overlap. By source, the top three clients accumulate about 46.2 SSH session-hours in a six-hour period and maintain peak concurrent counts of seven, seven, and five. The RDP set is smaller but reinforces the same pattern, including multiple sessions to server systems and the domain controller. No individual tuple overlaps impossibly, but the aggregate texture is substantially more saturated than routine human administration.

### DNS behavior

Core DNS contains 1,185 successful A, 298 successful AAAA, 269 successful TXT, 122 successful PTR, and 69 successful SRV rows, plus realistic failures. Internal examples include `_ldap._tcp.meridianhcs.local` returning `0 100 389 DC-01.meridianhcs.local` and reverse `10.2.10.10.in-addr.arpa` returning the DC. Internet TTLs vary widely, while internal authoritative answers use recognizable 300/600/3,600/7,200/86,400-second values. Resolver RTTs span sub-millisecond local responses through slower recursive lookups.

The 257 TXT queries under `westbridge-services.cloud` from 10.10.2.30 form obvious DNS-tunnel-like activity, with randomized labels, mixed NOERROR/NXDOMAIN/SERVFAIL, and predominantly one-second TTLs. I treated this as suspicious behavior in the environment, not as authenticity evidence: its UDP/53 connection accounting and DNS response fields remain coherent.

### DHCP and infrastructure protocols

DHCP records correctly bind MAC, hostname, address, server, domain, UID, duration, and lease time. The issue is the renewal process, not field shape. Each client repeats at an almost fixed private cadence with tiny jitter: 10.10.1.22 renews every roughly 1,787 seconds for a 3,600-second lease; 10.10.1.31 roughly 1,969 seconds; 10.10.1.32 roughly 1,693 seconds; and 10.10.1.35 roughly 3,841 seconds for a 7,200-second lease. Host-specific T1 values can differ, but the combination of large offsets from nominal half-life and extremely narrow repeated jitter across every client resembles a scheduling model.

Conversely, not one connection targets UDP/123. Because both sensors expose ordinary UDP and infrastructure traffic, and the environment visibly mixes Windows domain members and Linux hosts, this is an environment-wide protocol-distribution inconsistency rather than a complaint that a separate NTP log file was not supplied.

### HTTP, proxy, and web traffic

Core HTTP is dominated by 788 successful `CONNECT` transactions, while DMZ sees 825, fitting an explicit proxy. Status diversity includes authentication required (407), policy denial (403), upstream errors (502/503/504), redirects, partial responses, and cache validation. User agents span browsers on Windows and Linux, Microsoft update/crypto clients, VPN/security agents, package tools, Wget/curl, Python, Go, and Java.

The proxy's two-leg evidence is particularly convincing. At 12:04:49, 10.10.1.21 connects to proxy 10.10.3.20:8080 for `assets.adobedtm.com`; the ASA then records a separately NATed proxy-to-origin flow. SSL-inspected transactions appear as tunnel setup followed by a full HTTPS URL, whereas ordinary tunnels retain only control-message and tunnel-byte metadata. Public web access similarly includes browser asset cascades, bots, method/status variety, and internal browsing.

### TLS, certificates, and auxiliary protocol logs

TLS distributions favor current TLS 1.3 AES-128-GCM, with meaningful TLS 1.2, AES-256-GCM, ChaCha20, ECDSA, CBC fallback, and resumed sessions. TLS 1.3 observations appropriately lack visible passive certificate chains, while non-resumed TLS 1.2 commonly links to certificate files and X.509 records. Certificate subjects, issuers, SANs, key sizes, serials, signature algorithms, validity, intermediates, and host/CA flags are structurally credible. All tested certificate links resolve and all validity windows cover the observation time.

SMTP rows align to port 25/587 connections and correctly stop exposing message content after STARTTLS. File logs contain a plausible mix of certificates, OCSP responses, SMB office/PDF/text content, SMTP bodies, and a small number of HTTP executables/installers. Snort alerts align with visible DNS, ICMP, TLS, policy, and scan tuples without creating impossible event ordering.

### Perimeter scanning and collection texture

ASA state transitions agree well with Zeek. For example, the first inbound TCP attempt at 12:00:44 from 45.33.74.51:53321 to 10.10.3.10:80 is `S0` in Zeek and receives a 30-second `SYN Timeout` teardown in ASA. The concern is distribution: most of 1,225 failed SYN observations are generated by a handful of recurring addresses with strongly segmented target-port preferences. Real targeted scans can look like this, so I score it below the DHCP and remote-administration issues, but the small cast and repeated roles add to the synthetic impression.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Zeek DHCP/conn | All 69 renewals across eight clients | Near-fixed, host-specific renewal periods with only tiny cycle jitter are the clearest generator-like timing signature. |
| `environment_or_collection_plausibility` | Zeek core/DMZ conn | 11,730 connections, mixed Windows/Linux infrastructure | No UDP/123 traffic despite otherwise broad UDP and infrastructure visibility creates a notable environment-wide gap. |
| `distribution_texture` | Zeek SSH/RDP conn | 133 successful core SSH and 16 successful RDP sessions | A few workstations produce roughly 46 SSH session-hours and high concurrency within six hours, making remote admin baseline behavior over-dense. |
| `distribution_texture` | Zeek DMZ conn, ASA | 1,225 TCP `S0` rows | Nearly all failed scans come from nine recurring sources with cleanly specialized port families. |
| `weak_signal` | Zeek core conn | Two long sessions near window end | Computed closes after the visible boundary are explainable by start-time filtering and only marginally affect the score. |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Zeek, ASA, proxy, Snort, TLS/X.509, and protocol fields are structurally convincing with sound packet accounting.
- **Temporal patterns:** 6/10 — Session-level ordering is strong, but DHCP recurrence and remote-admin concurrency expose synthetic scheduling texture.
- **Cross-source correlation:** 9/10 — Independent sensor UIDs, realistic timestamp offsets, coherent parent-child UIDs, NAT/proxy legs, and certificate links correlate cleanly without impossible ordering.
- **Behavioral realism:** 6/10 — Web, DNS, TLS, mail, and scan behaviors are varied, but SSH/RDP volume and scanner specialization are too stylized.
- **Environmental consistency:** 7/10 — Network roles and routing are coherent; the absence of any time-sync traffic and overactive administration weaken the production impression.

## Recommendations

- If this were synthetic, model DHCP T1 negotiation and client behavior explicitly: use lease-relative renewal times, occasional retries/rebinds, clock drift, delayed ACKs, and less perfectly stable per-host periodicity.
- If this were synthetic, add time synchronization appropriate to the visible estate: domain members querying the DC/PDC hierarchy and Linux systems using configured NTP sources, with stable polling plus observation gaps.
- If this were synthetic, substantially reduce routine SSH/RDP rates and concurrent session-hours, preserve a smaller number of long-lived admin sessions, and tie bursts to distinct maintenance tasks and host roles.
- If this were synthetic, broaden low-rate Internet scan sources and port-selection behavior. Retain occasional persistent campaign scanners, but mix in a larger long tail of one-off sources, short multiport sweeps, retransmission variation, and changing scan cohorts.
- If this were synthetic, clip or explicitly mark sessions that remain open at the extraction boundary, or document/export them as still active rather than assigning a close beyond the visible collection window.
