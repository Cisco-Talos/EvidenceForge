# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 55

## Executive Summary

The network data is substantially production-like: protocol-specific byte accounting, proxy behavior, TLS visibility, DNS variety, and independent sensor identities withstand detailed checks. My synthetic verdict rests on a narrower problem: one-way UDP syslog traffic repeatedly receives immediate firewall state deletion, while the corresponding Zeek flows systematically lose duration information. These are meaningful source-lifecycle and field-shape concerns, but they do not justify an assertion of pervasive impossible traffic or near-certain synthetic origin.

## Evidence For Synthetic

- [contract_gap] All 11 uniquely matched UDP syslog flows in `zeek-dmz/conn.json` have ASA build and teardown records in the same displayed second, with `duration 0:00:00`. For example, `fw-perimeter/cisco_asa.log:9-10` creates and deletes connection `1681561` at `13:00:27`, for `10.10.3.10:47640 → 10.10.2.21:514`; `zeek-dmz/conn.json:4` records two originator packets, 1,904 payload bytes, and no response. The pattern repeats at firewall lines `62/64`, `77/78`, `82/83`, `86/87`, `96/97`, `859/860`, `1977/1981`, `2026/2028`, `2029/2031`, and `2348/2349`. This resembles application-activity completion being substituted for firewall state expiration. UDP has no FIN; ordinary idle expiration would retain the state longer. Forced clears or an external error could explain individual cases, so I classify this as a contract gap rather than an unconditional hard contradiction.
- [schema_or_format] Every one-way UDP `S0` record omits `duration`, including 193 core-sensor records and seven DMZ-sensor records with **two to five originator packets**. For example, `zeek-core/conn.json:4` contains `orig_pkts=2`, `orig_bytes=2003`, `history="D"`, and no duration; `zeek-dmz/conn.json:27` contains three packets and 2,692 payload bytes, also without duration. The native distinction should depend on measured elapsed time, rather than merely having no responder. Simultaneous packet timestamps or a transformed export could explain individual omissions; the systematic relationship to one-way flow state is the concern. This is related to the UDP lifecycle finding and is not counted as a wholly independent failure family.
- [weak_signal] All 3,841 TCP `S0` sensor records contain exactly one originator packet: 1,441 core, 2,397 DMZ, and three DB records. Raw SYN scanning explains much of this and substantially limits its significance. The same texture also includes ordinary-looking syslog connection failures, such as `zeek-core/conn.json:35` and `zeek-db/conn.json:4`, both a single SYN to TCP/514. I give this little weight; a probe policy or short application timeout could produce it.

## Evidence For Real

- Source-native protocol relationships are strong. All examined DNS, HTTP, SSL, SMTP, SMB mapping, and SMB file rows reference a connection UID within their own sensor, agree on the four-tuple, and have timestamps within that connection's recorded interval. This is positive consistency evidence, not a synthetic indicator.
- DNS includes A, AAAA, PTR, SRV, TXT, MX, SOA, and NS queries; NXDOMAIN, SERVFAIL, and REFUSED outcomes; authoritative internal responses; and empty successful AAAA answers. Examples are `zeek-core/dns.json:10`, `:23`, `:50`, and TCP DNS at `:288`.
- The HTTPS observation model respects encryption boundaries. All 1,867 TLS 1.3 SSL records across the sensors lack certificate-chain FUIDs; TLS 1.2 records include inspectable chains when not resumed. `zeek-dmz/ssl.json:35` uses an ECDSA cipher and its referenced leaf has an ECDSA key. No mismatched RSA/ECDSA leaf selection was found.
- Proxy control traffic is distinguished from tunneled data. `PROXY-01.meridianhcs.local/proxy_access.log:2` records a successful CONNECT with control-message byte scope and separate tunnel byte counters; lines `6-7` separate tunnel establishment from an inspected HTTPS GET using a shared tunnel ID. Failed CONNECTs have plausible 403/407/502/503/504 responses rather than always succeeding.
- TCP histories and outcomes include normal closure, rejection, reset, half-close, retransmission, and content-gap variants. The DB sensor's MySQL-heavy profile differs appropriately from the core's DNS/Kerberos/LDAP traffic and the DMZ's proxy/TLS traffic.
- Immediate TCP PAT deletion is **not** scored as an error. I found 2,180 matched TCP translation deletions in the same second as transport teardown, but this fits modern ASA per-session PAT behavior. Cisco explicitly describes immediate xlate removal for that mode. [Cisco ASA per-session PAT explanation](https://spg.xgslb-v3.cisco.com/c/en/us/support/docs/security/adaptive-security-appliance-asa-software/115993-asa-xlate-qanda.html)

## Detailed Analysis

### Scope, provenance, and method

I read the supplied neutral briefing and examined files only under `/private/tmp/log-study-8xqzbmnd/data`. I used system Python from `/private/tmp` for read-only JSON parsing and correlation, plus official Zeek source/documentation and Cisco documentation to resolve protocol questions. I did not open project code, authored scenarios, repository memory, prior assessments, or other reviewers' reports. Inherited generic operating instructions were not used as evidence of origin.

File citations below use physical, one-based lines. Numerical epoch timestamps were interpreted as UTC. Counts are **sensor records**, not deduplicated physical connections: a flow traversing two sensors can contribute two records.

I parsed all supplied Zeek JSON families, examined the proxy, firewall and IDS records, and concentrated on network evidence. I did not infer a native endpoint collector from the Mac names, demand missing products or event families, penalize the limited window, or use domain ownership/resolution as an authenticity test.

### Volume, observation paths, and traffic composition

The three connection files contain 21,805 rows:

| Sensor | Connections | DNS rows | HTTP rows | SSL rows | Principal visible character |
|---|---:|---:|---:|---:|---|
| Core | 12,251 | 3,171 | 2,122 | 352 | Internal authentication, directory, file, proxy-client traffic |
| DMZ | 9,122 | 1,034 | 2,361 | 2,535 | Proxy upstream traffic, web exposure, scanning, application/database traffic |
| DB | 432 | 40 | 18 | 16 | Primarily application-to-MySQL traffic |

Connection start timestamps span approximately `2026-11-02 13:00–19:00 UTC`. This is insufficient to assess an overnight/business-day contrast, and I do not penalize absent overnight activity.

Core hourly counts are `1715, 3224, 1807, 1677, 2015, 1813` for hours 13–18 UTC. DMZ counts are `1397, 2739, 1293, 1165, 1218, 1310`. The 14:00-hour increase is visible rather than artificially flattened. TCP/UDP/ICMP counts are respectively `6644/5230/377` at core, `7732/1093/297` at DMZ, and `378/45/9` at DB. The prominence of HTTP is largely CONNECT on TCP/8080, so simply comparing HTTP row count with SSL row count would mischaracterize this environment's HTTPS use.

### UDP state lifetime: the highest-impact concern

The important issue is **not** that UDP syslog is one-way. That is normal. It is that firewall state is repeatedly created and deleted immediately for that one-way traffic.

For connection `1681584`, firewall lines `62` and `64` both show `13:03:02` and the teardown declares `duration 0:00:00`. The tuple is `10.10.3.10:41367 → 10.10.2.21:514`. Zeek DMZ line `27` sees three datagrams, no response, and `conn_state="S0"`. Connection `1681590`, firewall lines `77-78`, repeats the behavior at `13:03:28`; DMZ line `34` sees two datagrams and no reply. Seven of the 11 DMZ UDP syslog observations have multiple packets; the other four have one packet.

Cisco documents UDP state as idle-timeout state, with a two-minute global default. Importantly, per-traffic policy can override the global minimum: its documented idle-timeout range begins at **one second**, so I do not incorrectly claim that a global one-minute minimum is universal. Same-second build/delete with a reported zero lifetime for every observed syslog flow remains poorly explained by ordinary expiration. [Cisco ASA connection settings](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/conns-connlimits.html)

Administrative deletion, an error indication, or another exceptional state-removal path could produce early deletion. The logs do not establish that these alternatives are impossible, and absent appliance administrative logs alone are not a defect. The repeated association with individual syslog sends is what shifts the balance toward synthetic. I also avoid applying this conclusion automatically to DNS: protocol inspection can make its firewall state handling different.

### Zeek duration and optional-field texture

There are 283 UDP `S0` rows across the supplied sensors: 241 core and 42 DMZ. Every one omits `duration`; 200 sensor rows have multiple originator packets. This includes syslog and other one-way UDP activity.

The current upstream Zeek connection script populates `duration`, `orig_bytes`, and `resp_bytes` together when elapsed duration is positive. Its condition is elapsed time, not `S0`. The supplied rows retain byte counts while systematically suppressing duration. A custom log policy or normalization stage could produce this shape, but no such transformation is identifiable from the supplied raw records. This warrants a field-shape concern rather than treating a missing optional key as intrinsically impossible. [Zeek connection logging implementation](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/conn/main.zeek)

For example, core line `4` has two datagrams and 2,003 bytes from `10.10.2.26:32884` to `10.10.2.40:514`, but no duration. Core line `8` and DMZ line `4` independently describe `10.10.3.10:47640 → 10.10.2.21:514` with two datagrams and no duration. Although two packets can share a timestamp at a particular capture resolution, the all-or-none pattern across the one-way class is unusual.

### TCP and lateral traffic

I found no overlapping visible TCP intervals for an identical full transport tuple within a sensor. Failed TCP attempts do not carry fabricated application payload. For no-gap TCP rows without retransmission/gap history, packet-level byte accounting passes basic lower-bound and four-byte header-alignment checks.

The all-single-SYN `S0` distribution is weak evidence because scanning is plainly visible. The core scanner-like volumes on TCP/22, 3306, 443, 445 and 80 and external DMZ probes make one-packet attempts reasonable. Ordinary service failures would usually offer a broader retry texture, but their application timeout settings are unknown.

Internal SSH and RDP are not represented exclusively as tiny placeholder connections. Core line `5046`, UID `CvpV3YHvDtNGpICCX`, records `10.10.1.31 → 10.10.2.27:3389`, duration `3423.842268`, and substantial bidirectional bytes. Core line `8505` instead records a brief RDP attempt with `RSTO` and `history="ShADaR"`. SSH durations span short transactions and multi-hour sessions; core line `5387` has duration `13295.14678`. Long connections extending beyond the range of connection **start** timestamps are not scored as impossible; a connection summary can describe a later closure.

### DNS, TLS, and cross-source integrity

Core DNS type counts include 2,315 A, 282 AAAA, 160 PTR, 102 SRV, and 301 TXT rows. Outcomes include 206 NXDOMAINs, 13 SERVFAILs, and three REFUSED responses. `zeek-core/dns.json:9` queries `printer01.meridianhcs.local` and receives NXDOMAIN; line `10` is a successful empty AAAA answer for `DC-02.meridianhcs.local`, a distinct and plausible NODATA case. Line `50` is a PTR response mapping `10.10.2.10` to its internal hostname. These are materially better than an all-A/all-success lookup stream.

I checked DNS answer/TTL cardinality and conservative DNS message-size lower bounds against the associated UDP connection bytes, without finding violations. TXT string-length prefixes, including multi-string DKIM answers, were interpreted as Zeek's formatted summaries rather than mistaken for literal on-wire text.

TLS has a coherent version/cipher split: the core has 178 TLS 1.3 rows, DMZ 1,689, and DB none; DB instead has 16 TLS 1.2 rows. I found no TLS 1.3 certificate chains exposed in these passive records, no missing referenced TLS 1.2 certificate IDs, and no cipher/leaf-key mismatch. TLS certificate FUIDs, HTTP file references, file timestamps, and HTTP response-body sizes were also checked against their parent connections. No orphan protocol UID, mismatched tuple, protocol timestamp outside its connection interval, or individual HTTP response body exceeding connection responder bytes was found.

Some connection payload totals exceed a naive observed-packet lower bound when `missed_bytes` and gap history are present. That is not an impossible byte count: Zeek's TCP payload totals derive from sequence information, while packet/IP totals describe observed packets. I excluded those apparent discrepancies rather than scoring capture loss as synthetic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| contract_gap | ASA UDP lifecycle with Zeek syslog corroboration | All 11 uniquely matched DMZ UDP syslog flows; repeated same-second state build/delete, zero lifetime | Main upward driver; source state appears to end with a send burst rather than its own lifetime. Exceptional deletions remain possible. |
| schema_or_format | Zeek one-way UDP connection summaries | 283 `S0` rows lack duration; 200 multi-packet sensor rows | Moderate support; systematic optional-field suppression differs from ordinary elapsed-time semantics. Related to the first finding, so not double-counted as independent proof. |
| weak_signal | TCP connection attempt texture | All 3,841 TCP `S0` sensor records have one SYN packet | Very small upward effect; visible scans and unknown probe/application settings explain much of it. |

The score remains in the mixed range because most network semantics survive testing, the strongest defect is concentrated in one lifecycle family, and I found no demonstrated impossible visible same-identity ordering.

## Realism Score by Category

- **Field format accuracy:** 8 — Strong protocol-specific shapes and accounting, with systematic one-way UDP duration omissions.
- **Temporal patterns:** 7 — Bursts and variable connection lengths are credible; immediate UDP firewall deletion is the main weakness.
- **Cross-source correlation:** 8 — UID, tuple, certificate, and file relationships are coherent; firewall state lifetime needs a source-specific explanation.
- **Behavioral realism:** 8 — Plausible proxy use, authentication traffic, scanning, DNS failures, and long/short remote sessions.
- **Environmental consistency:** 8 — Sensor profiles and proxy observation paths fit their visible roles; unusual UDP state handling remains unresolved.

## Recommendations

- If this were synthetic, model ASA UDP state expiration separately from the last application datagram. For the 11 UDP/514 cases, retain state through the configured idle timeout or represent the actual exceptional deletion mechanism; do not end the firewall connection merely because a send burst finished.
- If this were synthetic, derive Zeek duration presence from packet timing and the selected native logging/export policy. Preserve elapsed time for multi-packet one-way UDP when the packets span time, and keep any export normalization consistent with the optional byte fields.
- If this were synthetic, distinguish raw SYN probes from operating-system connection attempts. Where routine TCP/514 failures arise from a normal client, include only the retries permitted by that client's real timeout behavior; retain single-packet attempts where a scanner or short timeout explains them.
