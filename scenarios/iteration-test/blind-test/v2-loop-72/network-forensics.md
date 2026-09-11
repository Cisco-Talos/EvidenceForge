# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 34

## Executive Summary

The network telemetry is mostly consistent with a real, imperfectly observed six-hour production
slice. Zeek state, byte, packet, DNS-cache, TLS-certificate, SMB, and multi-sensor relationships
hold together unusually well without becoming mechanically identical; the main concern is a
systematic SSL logging boundary that suppresses every non-`SF` TLS parent and leaves a small number
of normally closed TLS and HTTP-file children absent.

## Evidence For Synthetic

- [contract_gap] SSL child coverage has a conspicuously clean state boundary across all three
  sensors. All 2,496 records in `zeek-core/ssl.json`, `zeek-dmz/ssl.json`, and
  `zeek-db/ssl.json` have `established:true`, and every one has an `SF` parent connection. At the
  same time, 207 `conn.json` records already classified as `service:"ssl"` have no SSL row: 62 in
  core, 138 in DMZ, and 7 in DB. Of these, 195 are non-`SF` and 12 are `SF`. This is more selective
  than ordinary packet loss and resembles a renderer or collection rule that only publishes
  successful TLS sessions.
- [contract_gap] Some omitted SSL children cannot be explained by a SYN-only or unrecognized TLS
  attempt. Core UID `C205COeU4dYcmFx2Zy` at `2024-03-18T14:26:36.169742Z` is explicitly
  `service:"ssl"`, has `history:"ShADadrg"`, 5,636 origin bytes, 22,764 response bytes, and an
  `RSTR` close, but has no `ssl.json` record. DMZ UID `CkWItro0jFYGxqieDL` at
  `2024-03-18T15:48:16.799782Z` is an ordinary `SF` TLS flow carrying 4,781/625,601 bytes over
  10.088518 seconds and likewise has no SSL row.
- [contract_gap] Five of 751 HTTP file references (0.67%) name a `resp_fuid` absent from the same
  sensor's `files.json`. Examples are core HTTP UID `CyJvHHmYuGP0WFCHbc`, transaction depth 2,
  which references `FpjoaSr7TpZDgauAoF` for a 44,932-byte WebP response, and DMZ UID
  `CRlzLhE0242JD8NR6eR`, which references `FGI5kCqMApTN53P8c` for an 875-byte proxy error body.
  Sparse pipeline loss or filtering could produce this, so it is a low-weight indicator rather
  than a hard contradiction.
- [weak_signal] The emitted TLS population is unusually tidy for an Internet-facing sensor: only
  TLS 1.2 and 1.3 appear, with seven cipher suites, no `established:false` SSL rows, and certificate
  validity/SNI relationships that are nearly uniformly well formed. Modern policy can explain the
  version and cipher palette, but its combination with the selective SSL-child gap modestly raises
  synthetic suspicion.

## Evidence For Real

- All JSON lines parsed successfully. Connection UIDs are unique within each Zeek sensor and do
  not collide across sensors. Every DNS, HTTP, SSL, SMTP, and SMB protocol UID resolves to a
  same-sensor `conn.json` parent with the same five-tuple, and no checked protocol timestamp falls
  outside its connection interval. All 2,013 checked `files.json` connection references also have
  valid parents inside their connection intervals.
- DNS has convincing resolver and endpoint texture. Core contains 2,913 DNS transactions spanning
  A (2,152), AAAA (241), TXT (265), PTR (143), SRV (98), NS (7), MX (5), and SOA (2), with 211
  NXDOMAIN, 13 SERVFAIL, and 5 REFUSED results. The NXDOMAINs include plausible Windows suffix
  search and stale-name activity such as `wpad`, `wpad.meridianhcs.local`, `isatap`,
  `isatap.meridianhcs.local`, `oldserver.meridianhcs.local`, and
  `printer01.meridianhcs.local`.
- DNS TTL behavior looks cache-derived rather than independently randomized. For
  `api.snapcraft.io`, the core sensor sees TTL 758 at `12:11:10.936013Z` and TTL 286 at
  `12:19:02.522072Z`, a 472-second decrease over roughly 471.6 elapsed seconds. It later sees TTL
  259 at `12:49:29.026825Z` and TTL 74 at `12:52:34.925216Z`, a 185-second decrease over roughly
  185.9 seconds. A-to-AAAA companion delays are broadly distributed (47-805 ms in core), not a
  fixed offset.
- TCP states and histories are diverse and source-consistent. Core has 8,963 `SF`, 1,969 `S0`,
  148 `RSTO`, 92 `RSTR`, 24 `OTH`, 21 `REJ`, and smaller `S1`/`S2`/`S3` populations. Positive
  `missed_bytes` appears only on TCP and always has a corresponding `G` or `g` history marker; the
  522 core gaps divide into 246 origin-only, 217 response-only, and 59 bidirectional cases. This is
  substantially more production-like than uniform or perfectly lossless traffic.
- Independent sensor observations correlate without being bit-identical. For the HTTP connection
  `10.10.1.22:48798 -> 10.10.3.10:80`, core uses UID `CLA3qE1S4ol5Wmx5X` at
  `1710763243.281588`, while DMZ uses UID `C5eBKR2PJoSC4TB8H` at `1710763243.166116`.
  Payload and packet counts match, but timestamps differ by 115.472 ms and durations by 52 us.
  Across 4,122 exact-tuple core/DMZ matches, state agrees in all cases, while history, byte, and
  loss fields differ on hundreds of observations. The clock offset also has millisecond-scale
  jitter rather than one copied timestamp.
- Endpoint telemetry independently observes that same HTTP tuple in both directions:
  `WS-OHADDAD-01` records the outbound flow at `1710763243494` ms and `WEB-EXT-01` records the
  inbound flow at `1710763243311` ms. Across 9,516 internal bidirectional eCAR tuple pairs, only 12
  share an exact millisecond; the median inter-endpoint observation difference is 680 ms. Host/IP
  ownership is one-to-one across all 20 modeled internal addresses.
- TLS semantics are otherwise strong. The DMZ mix is 1,491 TLS 1.3 and 720 TLS 1.2 sessions with
  modern AES-GCM, ChaCha20-Poly1305, and limited TLS-1.2 CBC use. TLS 1.3 records appropriately do
  not expose passive certificate chains, while full TLS 1.2 handshakes do. Every emitted chain
  FUID resolves in both `files.json` and `x509.json`, file SHA-1 matches the X.509 fingerprint, all
  certificates are valid at observation time, and all 70 OCSP records resolve to HTTP/file
  objects. Chain-bearing SNI matches leaf SANs except for eight explainable empty-SNI cases
  involving SMTP or IP-literal sessions.
- HTTP and SMB behavior has credible protocol detail. There are 3,480 HTTP records across the
  three sensors with GET, POST, and explicit-proxy CONNECT traffic, varied 2xx/3xx/4xx/5xx status
  codes, multiple user-agent families, and multi-transaction connections. Core has 119 SMB share
  mappings and 209 SMB file operations; every mapped file operation occurs after its mapping, and
  every READ/WRITE/RENAME sequence examined begins with `SMB::FILE_OPEN` for that pathname.
- Large and lateral flows have plausible wire characteristics. Core UID `CKMuqjtC97EMkXt71T`
  uploads 623,259,271 origin bytes to `FILE-SRV-01` over SMB in 10.374893 seconds with 518,897
  origin packets, 213,457 response packets, a ReFS `ClinicalExports` mapping, and a directional
  32,768-byte capture gap. Successful RDP sessions have hundreds-to-thousands of seconds of
  duration and asymmetric interactive byte counts; for example UID `CqVeONfHICK3GC3GJ7a` runs
  1,063.387286 seconds and carries 435,373/1,804,716 bytes.
- Infrastructure traffic aligns with visible roles: DNS/Kerberos/LDAP concentrate on the two DCs,
  SMB on file servers, MySQL on the DB path, syslog and TLS on the monitoring host, SMTP on mail
  systems, and CONNECT/TLS traffic on the explicit proxy. DHCP renewals use 3,600-, 7,200-, and
  14,400-second leases with substantial per-client renewal jitter rather than exact fixed
  intervals. The 1,500-plus-flow burst at about `13:40:47Z` resolves to a coherent internal
  ICMP/22/80/443/445/3306 sweep from `10.10.3.10`, not unexplained global rate regularity.

## Detailed Analysis

The observable Zeek window runs from `2024-03-18T12:00:22.752904Z` through
`2024-03-18T17:59:53.669518Z`. The core, DMZ, and DB sensors contain 11,258, 8,321, and 490
connection rows respectively. Their placement is internally coherent: DB visibility is narrowly
focused on `10.10.4.10`; DMZ sees the public-facing and proxy paths; core sees broad internal AD,
file, mail, and workstation traffic. The differing source-family volumes therefore have a visible
topological explanation.

Connection-state behavior is credible at both aggregate and service levels. Core DNS is almost
entirely short `SF` UDP, one-way UDP syslog appears as `S0`/`D`, successful RDP is long-lived, and
the failed reconnaissance population is mostly zero-duration `S0` with one SYN. Port 443 contains
successful, reset, rejected, and partial states; port 389 includes `SF`, `RSTO`, `RSTR`, `S2`,
`S3`, and `OTH`; and DB MySQL includes normal closes plus both-side resets and half-closed states.
Packet accounting remains non-negative throughout, UDP and ICMP consistently add 28 bytes of
IPv4/transport overhead per packet, and TCP overhead varies with control packets, options,
retransmissions, and directional loss.

The major `13:40-13:42Z` volume spike is behaviorally attributable. Core records 1,521 flows from
`10.10.3.10`, including roughly one /24 sweep each for ICMP and TCP ports 22, 80, 443, 445, and
3306. Probe inter-arrival times are bursty (median about 4.7 ms) with broad tails, responding hosts
produce `SF`/`REJ`/reset evidence, and nonresponders produce `S0`. This is consistent with an
actual scanning tool and is not treated as a synthetic indicator merely because the activity is
easy to identify.

DNS sequencing is strong. DNS UIDs and five-tuples exactly match their connection parents; DNS
timestamps normally equal the first packet timestamp, and single exchange RTT normally equals the
UDP connection duration. A/AAAA ordering has nonuniform client-side delay. Public TTLs decrement
with elapsed cache time and reset only after expiry, while internal authoritative answers commonly
use stable 300-, 1,800-, 3,600-, and 86,400-second values. The response population contains both
ordinary SaaS/update lookups and low-TTL TXT activity, and the suspicious TXT family includes
NOERROR, NXDOMAIN, SERVFAIL, and REFUSED outcomes rather than a single success template.

TLS field values and certificate graphs are internally sound, but the logging boundary is the
assessment's main negative evidence. The observed SSL rows use plausible version/cipher pairs,
resumption suppresses certificate chains, passive TLS 1.3 visibility does not invent X.509 data,
and full TLS 1.2 chains link correctly to file and certificate records. Conversely, the complete
absence of `established:false` records and the deterministic association of all emitted SSL rows
with `SF` parents is difficult to reconcile with the 207 recognized SSL connections whose child
records are absent. An explicit collection filter could explain this, so the issue is not an
impossibility, but it is a repeatable three-sensor contract gap.

HTTP parent-child timing is also generally convincing. All 3,480 HTTP rows have valid parent UIDs,
matching tuples, and timestamps inside the connection. Response lengths, MIME types, and file
directions agree for 746 of 751 explicit FUID references. The five missing file rows are concrete
but sparse. On core UID `CyJvHHmYuGP0WFCHbc`, adjacent depth-1 and depth-3 responses do produce
valid file rows while the depth-2 WebP does not; this looks more like selective collection loss
than a wholesale implementation failure, but no visible file policy explains it.

SMB mapping and operation ordering is sound for nearly the entire set. One connection,
`ClRjTWwdignYcQl2TJ`, begins at `2024-03-18T14:20:23.058309Z` and contains a FILE_OPEN to
`\\FILE-SRV-01\Users\Desktop\schedule.pdf` at +0.696 seconds without a visible mapping row. That
is a second sparse companion gap, but it is consistent in scale with the HTTP omissions and could
reflect a filtered or dropped source-local record. The 623 MB SMB upload lacks file-operation
records after its mapping, but its explicit origin-side gap marker and 32 KB of missed bytes give a
credible packet-loss reason for analyzer desynchronization; I do not count that as synthetic.

Cross-source coherence is particularly persuasive. Exact five-tuples and source ports survive
across sensor and endpoint views, no overlapping reuse of a live TCP five-tuple was found, and
sensor-specific UIDs remain independent. Clock offsets are sensor-specific but noisy: among 4,122
core/DMZ matches, core trails DMZ by a median 114.227 ms, while the observed range is mostly about
113-117 ms rather than a single copied constant. Packet/history disagreement occurs where one
sensor reports missed bytes, which is how independent observation points should behave.

No `hard_contradiction` was found in visible ordering, tuple ownership, TCP lifecycle, DNS family,
certificate validity, or source-native numeric ranges. Standalone IDS, firewall, and proxy access
files are not present, but their absence is not scored: the visible data does not establish that
those source families were collected, and Zeek/eCAR already provide coherent observations of the
relevant traffic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `contract_gap` | Zeek SSL/conn | Dataset-wide: 207 recognized SSL parents lack SSL children; 0/2,496 emitted SSL rows are non-established or have non-`SF` parents | Moderate-high; the clean selection boundary is the main synthetic tell |
| `contract_gap` | Zeek HTTP/files | 5 of 751 explicit HTTP FUID references have no same-sensor file row | Low; concrete but compatible with sparse collection loss |
| `contract_gap` | Zeek SMB | One FILE_OPEN connection has no same-connection mapping record | Low; isolated and not impossible under filtering/loss |
| `weak_signal` | Zeek TLS | TLS 1.2/1.3 and seven ciphers only, with exceptionally clean emitted certificate semantics | Low; plausible for a modern managed environment and not independently diagnostic |

No `hard_contradiction` or standalone `schema_or_format` defect was observed. The synthetic score is
kept in the “mostly realistic” band because the systemic SSL boundary is significant but has a
plausible collection-filter explanation, while the remaining checks strongly resemble independent
production observations.

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek/eCAR JSON parses cleanly; UIDs, tuples, protocol fields,
  certificate chains, byte counters, and state/history combinations are source-appropriate.
- **Temporal patterns:** 9 — DNS cache countdowns, A/AAAA delays, connection durations, DHCP jitter,
  scan burst timing, and sensor clock skew have convincing nonuniform texture.
- **Cross-source correlation:** 8 — Parent/child and sensor/endpoint tuples are highly coherent,
  reduced by the systemic SSL-child omission and five missing HTTP FUID rows.
- **Behavioral realism:** 9 — Proxy browsing, AD infrastructure, mail, SMB, database traffic,
  scanning, SSH, and RDP exhibit plausible state, duration, byte, and direction distributions.
- **Environmental consistency:** 8 — Host/IP ownership and service placement are coherent; the
  unexplained success-only SSL collection shape is the principal reservation.

## Recommendations

- If this were synthetic, emit `ssl.json` records for TLS handshakes that Zeek has identified but
  that terminate by reset, alert, or partial close, including realistic `established:false` rows.
  Do not use `conn_state == SF` as the effective admission rule; derive logging from analyzer
  activation and observed handshake progress.
- Preserve source-local logging policy explicitly. If SSL or file records are intentionally
  sampled or filtered, apply a plausible policy boundary and make companion gaps consistent with
  observable loss or policy rather than isolated unexplained omissions.
- Add focused integrity checks for every HTTP `orig_fuids`/`resp_fuids` reference and for SMB
  FILE_OPEN operations whose connection starts in-window without a tree mapping. Either retain the
  referenced child/mapping row or attach a realistic source-local reason for its absence.
- Retain the existing DNS cache-state behavior, directional `missed_bytes`/history coupling,
  independent per-sensor UIDs and clocks, endpoint timing jitter, and role-aligned infrastructure
  mix; these features materially reduce synthetic detectability.
