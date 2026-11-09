# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 95
**Synthetic-Confidence Score:** 90

## Executive Summary

The network dataset has credible protocol diversity, proxy behavior, certificate relationships, and connection/protocol correlation, but two reproducible source-native contradictions strongly favor synthetic data. ICMP records systematically use TCP/UDP-style connection states instead of standard Zeek ICMP semantics, and several TCP records claim fewer observed packets than their own recorded history requires.

## Evidence For Synthetic

- [hard_contradiction] Every ICMP connection observation has a nonstandard Zeek state: `zeek-core/conn.json` contains 401 ICMP records (156 `SF`, 245 `S0`), `zeek-db/conn.json` contains 18 (`SF`), and `zeek-dmz/conn.json` contains 304 (59 `SF`, 245 `S0`). Standard Zeek's `Conn::conn_state` handles TCP and UDP separately and returns `OTH` for other transports, including ICMP. For example, core line 139, UID `CUB1N8GidfwdC1qu4a`, has `proto=icmp`, `ip_proto=1`, origin pseudoport 8, response pseudoport 0, `conn_state=SF`, and `history=Dd`; core line 3092, UID `CDqsnYFIHuC3TUuQ3o`, has `conn_state=S0`, `history=D`. These are 723 sensor observations, including overlap between sensors, not 723 distinct exchanges. [Upstream Zeek connection implementation](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/conn/main.zeek).
- [hard_contradiction] A conservative TCP history check finds 13 observations with fewer than three packets on a side whose history explicitly records SYN/SYN-ACK, pure ACK, and data on that same side: core 3, DB 2, DMZ 8. For example, `zeek-db/conn.json:2`, UID `CQWbtKB9csDTuaq42P`, at `2026-11-02T13:03:15.031889Z`, records `history=ShADadrG`, `orig_pkts=2`, and `orig_bytes=531`. Uppercase `S`, `A`, and `D` require at least three originator packets; Zeek records these through mutually exclusive SYN, empty ACK, and data branches. `zeek-core/conn.json:583`, UID `CUa5XVnKjHhEAOdmfS`, has the same `S/A/D` contradiction with `orig_pkts=2`; `zeek-core/conn.json:2435`, UID `C4NDPem0M0CYh6kRHub`, has `history=ShADadFg`, `resp_pkts=2`, despite responder `h/a/d`. All 13 carry positive `missed_bytes`; capture loss cannot give a sensor a history of packets it did not observe. [Upstream Zeek TCP history implementation](https://raw.githubusercontent.com/zeek/zeek/master/src/packet_analysis/protocol/tcp/TCPSessionAdapter.cc).

## Evidence For Real

- Connection outcomes are varied, with resets, refusals, unanswered attempts, partial connections, and successful sessions. Core has 150 `RSTO`, 116 `RSTR`, 28 `REJ`, and 29 `OTH`; DMZ has 129, 70, 32, and 19 respectively. Large `S0` populations occur alongside scanning-shaped traffic rather than being treated as unexplained baseline failure rates.
- DNS includes A, AAAA, PTR, SRV, TXT, and other query types; negative results and response latency are varied. Core has 227 NXDOMAIN, 14 SERVFAIL, and 4 REFUSED results. `zeek-core/dns.json:58` contains `wpad.local` NXDOMAIN, while line 1 contains `_ldap._tcp.meridianhcs.local` SRV answers pointing to two domain controllers.
- Proxy telemetry represents CONNECT setup separately from inspected application traffic. `PROXY-01.meridianhcs.local/proxy_access.log:1-4` distinguishes control-message bytes from tunnel totals, links rows using `tunnel_id`, and shows application bootstrap requests followed by a JavaScript resource with a relevant referrer.
- TLS has a plausible mixture of TLS 1.2/1.3, resumption, unsuccessful negotiation, RSA/ECDSA authentication, and internal/public certificate profiles. The examined certificate chains match their issuer/subject links and do not exceed the carrying flow's server payload budget.
- Protocol references and tuples are coherent within each sensor. No DNS, HTTP, SSL, SMTP, SMB mapping, or SMB file row referenced an absent connection UID or a different connection tuple in the complete parsed network input.

## Detailed Analysis

### Inputs, provenance, and limits

I read the supplied neutral briefing at `/private/tmp/log-study-p29dfwbp/network-prompt.md` and examined only the supplied data directory. I parsed every JSON file in `zeek-core`, `zeek-db`, and `zeek-dmz`, including all connection, DNS, HTTP, SSL, X.509, OCSP, files, DHCP, SMTP, SMB, and PE families present. I also read representative opening rows and counted the entire firewall, proxy access, web access, and both Snort alert files. The directory inventory revealed endpoint filenames, but I did not open endpoint logs, histories, project files, scenarios, prior assessments, or another reviewer's output. Logged command strings were not executed.

The only external references consulted were public Zeek documentation and upstream Zeek source implementations, used to verify network field semantics. Those references are distinct from the prohibited local project source. Inherited generic project metadata is an environmental limitation and contributes no origin evidence to this assessment. No forbidden project or prior-assessment information was accessed during this review.

No packet capture, sensor version/configuration, or collector transformation manifest was supplied. A documented custom transformation of Zeek state/history fields could alter the first finding's interpretation; no such transformation is evident in the records. I assess the files as the Zeek records described in the briefing. I do not interpret filesystem timestamps, domain existence, missing endpoint event types, source completeness, or attack narratability as authenticity evidence.

### Scope and distributions

| Sensor | Connections | TCP / UDP / ICMP | DNS | HTTP | SSL |
|---|---:|---:|---:|---:|---:|
| Core | 12,314 | 6,715 / 5,198 / 401 | 3,188 | 2,159 | 403 |
| DB | 433 | 357 / 58 / 18 | 50 | 20 | 14 |
| DMZ | 9,401 | 7,960 / 1,137 / 304 | 1,075 | 2,431 | 2,725 |

The connection start window is approximately `2026-11-02 13:00–19:00 UTC`. Per-hour core starts are 1,849, 3,233, 1,757, 1,698, 2,068, and 1,709; DMZ starts are 1,315, 2,713, 1,359, 1,465, 1,295, and 1,254. This is not a uniform hourly distribution. A six-hour daytime slice cannot establish overnight behavior or a full business-hours curve, so those are unscored.

The internal port mix supports apparent directory, file, monitoring, and database roles: core has 2,479 port-88, 1,235 port-389, and 716 port-445 connections; DB has 267 port-3306 connections. Core port-3306 attempts are predominantly unanswered, while DB observes successful database traffic on its segment. Segmented visibility and policy can explain this, so I do not infer a contradiction from that difference.

SSH and RDP have variable lifetimes rather than uniformly short placeholder flows. Core successful/specified-duration SSH observations reach 13,333.99 seconds and RDP 3,427.47 seconds. Those lifetimes and mixed success/failure outcomes are plausible. No absence of an SSH-specific log file is penalized.

### DNS, HTTP, and TLS

Core DNS query types include 2,333 A, 279 AAAA, 154 PTR, 105 SRV, and 300 TXT records. Its response-time 10th/50th/90th percentiles are approximately 0.657/3.584/116.500 ms. TTLs include fixed internal values and many smaller external/cache-like values. DNS need not immediately precede every connection because cached or pre-window resolution is possible; I did not score missing per-flow lookups.

Most HTTP rows are explicit proxy CONNECT requests: 1,967 core, 19 DB, and 2,013 DMZ. Raw HTTP-row counts therefore do not imply that cleartext web browsing exceeds HTTPS. DMZ's SSL records contain 1,808 TLS 1.3 and 913 TLS 1.2 negotiations, plus four with no selected version; DB's 14 are TLS 1.2. Internal TLS 1.2 CBC suites differ from the more modern external population, which is possible in a mixed environment and is not scored as a defect.

Every SSL certificate-chain reference resolves to files/X.509 records in the same sensor input. Checked leaves are within validity windows; cipher authentication and leaf key types agree; adjacent chain subjects/issuers agree; SHA-1 file fingerprints agree with X.509 fingerprints. TLS 1.3 rows without visible certificates are neutral because the certificate handshake is encrypted. No HTTP response/request body exceeded its connection's corresponding payload count, and no extracted HTTP file exceeded its carrying directional payload budget.

### Correlation and packet accounting

For all present DNS, HTTP, SSL, SMTP, SMB mapping, and SMB file rows, same-sensor UID joins retained the same addresses and ports. Their timestamps neither preceded the carrying connection by more than 1 ms nor exceeded its duration by more than 100 ms. Every connection's reported payload fit inside its directional IP-byte count, and no positive payload was paired with a zero directional packet count. These useful consistency checks support realism; their success is not itself a synthetic indicator.

The stricter history-versus-packet check reveals the specific failure missed by aggregate byte checks. Its conservative rule counts only the three mutually exclusive `S/A/D` or `h/a/d` observations, ignoring retransmission/gap flags and requiring no assumptions about FIN/RST packet combinations. The exact current-upstream branch behavior yields a broader 312-row lower-bound failure (core 163, DB 9, DMZ 140), but the score relies on the smaller, easiest-to-reproduce 13-row contradiction. All such records have positive `missed_bytes`, consistent with a loss-related accounting problem. This does not demonstrate its implementation cause.

S1 records containing byte counts are not scored as synthetic: despite potentially confusing prose in the field reference, upstream `set_conn` populates sizes whenever duration is positive. Likewise, missing pre-window initiation and post-window termination are neutral.

### Weight of evidence

The verdict rests on two independent observable field contracts, not on polished incident sequencing or unusually complete coverage. One is systematic across the ICMP family and three sensors; the other makes individual TCP rows internally irreconcilable with their own observed-history claims. Substantial protocol and correlation strengths prevent a maximum score, but cannot explain these native contradictions as ordinary real-network variation.

## Synthetic Indicator Summary

| Indicator | Category | Affected source family | Scope | Effect on score |
|---|---|---|---|---|
| ICMP uses `SF`/`S0` rather than standard Zeek `OTH` | hard_contradiction | Zeek conn | All 723 ICMP observations across three sensors; overlapping observations are not independent sessions | Major: systematic source-native semantic mismatch |
| Packet counts cannot contain their own SYN/pure-ACK/data history | hard_contradiction | Zeek TCP conn | Conservative 13 observations: core 3, DB 2, DMZ 8; all loss-marked | Major: within-row impossibility independent of coverage or clock synchronization |

## Realism Score by Category

- **Field format accuracy:** 5 — JSON types and references are strong, but ICMP states and TCP packet/history accounting violate source-native semantics.
- **Temporal patterns:** 8 — Variable hourly volume, DNS response times, and protocol lifetimes; no demonstrated impossible cross-protocol timestamps in tested joins.
- **Cross-source correlation:** 8 — Strong same-sensor UID/tuple and certificate/file relationships; packet history versus packet count remains inconsistent.
- **Behavioral realism:** 8 — Proxy transactions, directory services, lateral traffic, scan failures, and session durations are plausible in the observed slice.
- **Environmental consistency:** 8 — Segmented database, core, and DMZ populations fit different observation paths; exact sensor version and transformation policy remain unspecified.

## Recommendations

- If this were synthetic, render ICMP with the source-native Zeek connection-state semantics for the intended Zeek release; do not apply TCP/UDP success/failure labels to ICMP.
- If this were synthetic, derive packet counts, history, IP bytes, and content gaps from one coherent sensor-observed packet representation. A lost packet cannot remain counted as an observed SYN, pure ACK, or data history transition while being removed from that sensor's packet count.
- If these are transformed production records, supply the sensor version and field-transformation contract, especially for ICMP state rewriting. That would make the observed deviation testable without inferring undocumented collection behavior.
