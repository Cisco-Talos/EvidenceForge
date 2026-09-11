# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 94  
**Synthetic-Confidence Score:** 89

## Executive Summary

The network telemetry is highly polished and, in most families, impressively source-aware. The
Zeek, ASA, proxy, IDS, DNS, TLS, DHCP, SMB, SMTP, and endpoint FLOW records describe a plausible
segmented enterprise over a six-hour observation window. Firewall teardown reasons agree with
Zeek connection states, TLS version/cipher pairs are valid, certificate chains are coherent, DNS
contains realistic response and failure variation, and independent sensors show modest capture
differences rather than byte-for-byte cloning.

The decisive adverse evidence is a repeated, log-visible proxy lifecycle impossibility. Of 639
proxy CONNECT records carrying an explicit `client_src_port` that resolves uniquely to a completed
Zeek `SF` client-to-proxy connection, 416 claim a `tunnel_duration_ms` longer than the entire Zeek
TCP connection. In 262 of those cases, the Zeek originator and responder byte totals exactly equal
the proxy control-plus-tunnel byte totals in both directions, removing reasonable doubt about the
record pairing. A CONNECT tunnel is created after the client TCP connection starts and cannot
remain active longer than the TCP connection that carries it.

A second strong indicator is mechanical 600 ms pacing. Across 1,487 client-to-proxy HTTP
connections in `zeek-core`, 131 consecutive start gaps fall within 0.595–0.605 seconds, forming 30
runs of three to six connections across eight different clients. The same exact spacing also
appears between transactions on persistent HTTP connections. This cross-client reuse of an almost
fixed scheduler interval is not characteristic of normal browser concurrency or network-induced
timing.

Those two findings outweigh the substantial realism elsewhere. Sanitized names, broad source
coverage, compact intrusion activity, and cross-source completeness were not used as synthetic
indicators.

## Evidence For Synthetic

1. **[hard_contradiction] Proxy tunnels outlive their carrying TCP sessions.**

   The proxy log exposes `client_src_port`, separate control and tunnel byte counts, and
   `tunnel_duration_ms`. Matching that source port to `zeek-core/conn.json` produced 639 unique
   client-to-`10.10.3.20:8080` sessions; all 639 are completed `SF` sessions. In 416 cases, the
   proxy-reported tunnel duration exceeds the whole Zeek connection duration by more than 10 ms.
   The excess is repeated rather than marginal: the most common gaps are approximately 0.7 s
   (178 records), 0.8 s (80), and 0.6 s (78).

   The identity of the records is especially strong in 262 cases where both directional byte
   totals also agree exactly. Representative examples include:

   - Zeek UID `CqFmQK9O9owUWSmnW`, source `10.10.1.21:38179`, has duration `1.040353` s and bytes
     `743/1159`; the matching proxy CONNECT to `stackoverflow.com:443` has the same combined
     bytes and a tunnel duration of `1.717` s.
   - Zeek UID `Cf9qKskGK17PnCJAZJW`, source `10.10.1.21:52469`, has duration `0.983703` s and bytes
     `594/139755`; the matching proxy record to `cdn.onenote.net:443` has identical totals and a
     tunnel duration of `1.904` s.
   - Zeek UID `CjsnVH39tK9THfr8w6`, source `10.10.1.21:51704`, has duration `1.829276` s and bytes
     `778/50162`; the proxy record has identical totals and a tunnel duration of `2.211` s.

   This is a systemic semantic contradiction, not a completeness judgment or an artifact of
   matching only by time.

2. **[distribution_texture] Reused near-exact 600 ms browser/proxy pacing.**

   Among 1,487 core client-to-proxy HTTP connections, 131 adjacent starts are separated by
   0.595–0.605 s, with a median of `0.599945` s. They form 30 runs of at least three consecutive
   connections: twenty runs of length three, seven of length four, two of length five, and one of
   length six. The pattern affects eight clients (`10.10.1.21`, `.22`, `.31`–`.36`) and many
   unrelated destinations.

   One six-connection sequence to `metrics.snapwidget.app` starts at
   `1710772415.226061`, `1710772415.826105`, `1710772416.426308`,
   `1710772417.026026`, `1710772417.625238`, and `1710772418.226145`. Similar runs occur for
   Azure, Microsoft 365, Salesforce, Google, and other sites. Separately, 27 of only 59
   within-connection HTTP transaction gaps are also 0.600 s within the same tolerance. Browsers
   can burst, but real connection setup and resource scheduling normally produce concurrent,
   millisecond-scale, or variably delayed starts—not a shared 600 ms metronome across operating
   systems, users, and destinations.

3. **[contract_gap] A small number of HTTP file references have no same-sensor file record.**

   Five `resp_fuids` referenced by Zeek HTTP records are absent from the corresponding
   `files.json`: two in `zeek-core` and three in `zeek-dmz`. The records include successful bodies
   of 44,932 and 92,011 bytes and proxy error bodies, so the FUIDs are not empty placeholders. In
   one mirrored local-web session, core omits the WebP file record while DMZ omits the JPEG file
   record, even though both connection records report `missed_bytes: 0`. This could arise from
   selective log shipping or per-stream file-analysis policy and is therefore low weight, but it
   is a concrete required-companion gap rather than a complaint about generally thin coverage.

4. **[weak_signal] Mirrored Zeek sensors exhibit an unusually fixed clock relationship.**

   For 4,121 matched TCP/UDP flows visible in both `zeek-core` and `zeek-dmz`, the DMZ timestamp is
   consistently about 110–118 ms earlier than the core timestamp. A stable sensor clock offset is
   entirely possible, so this is not a contradiction. The exceptionally narrow band across six
   hours is nevertheless compatible with a fixed per-source timing transform and receives only
   minor weight.

## Evidence For Real

1. **ASA and Zeek connection semantics are unusually strong.** Of 7,317 ASA built TCP/UDP
   connections, 7,313 resolve to the same tuple in Zeek; the four unmatched records are long-lived
   SSH sessions opened late in the window and lacking teardowns, which is consistent with Zeek
   writing `conn.log` at closure. For closed matches, every comparable ASA duration is within 1.1
   seconds of Zeek's value, consistent with ASA's whole-second rendering. Teardown semantics align:
   4,030 `TCP FINs` map to Zeek `SF`, 2,118 `SYN Timeout` entries map to `S0`, 94 `TCP Reset-O`
   entries map to `RSTO`, and 59 `TCP Reset-I` entries map to `RSTR`.

2. **The sensors do not look like simple copied rows.** The 4,122 apparent core/DMZ mirrored
   connections use different Zeek UIDs. Their states agree, but 205 have directional byte
   differences, 200 have packet-count differences, and 358 have different history strings. Zeek
   also reports nonzero `missed_bytes` on 522 core, 40 database, and 550 DMZ connections. Those
   differences are plausible for independent taps with asymmetric loss and analyzer state.

3. **Zeek protocol contracts are mostly source-native and coherent.** Every DNS, HTTP, TLS, SMTP,
   SMB mapping, and SMB file row carrying a UID resolves to a same-sensor connection with the same
   four-tuple. Protocol offsets are plausible: DNS begins at connection time; HTTP appears after
   request parsing; TLS appears tens to hundreds of milliseconds after the SYN; SMB file actions
   follow mapping and connection setup. TCP histories, packet totals, IP-byte totals, connection
   states, and absent durations on `S0`/`REJ` records are broadly credible.

4. **DNS has realistic semantic and distributional texture.** Across sensors it contains A, AAAA,
   PTR, SRV, TXT, NS, MX, and SOA traffic; `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`
   outcomes; varied RTTs; and TTL lists whose cardinality always matches the answer list. All 1,661
   queries under the internal `.meridianhcs.local` namespace are marked authoritative. The
   high-volume TXT activity from `10.10.2.30` uses variable labels, resolvers, RTTs, low TTLs, and
   mixed failures rather than an overly regular tunnel cadence.

5. **TLS/X.509 behavior is technically convincing.** Observed version/cipher pairings are valid.
   TLS 1.3 sessions omit visible certificate chains, which is appropriate for passive inspection of
   encrypted TLS 1.3 handshake certificates, while visible TLS 1.2 chains are populated. All 1,054
   certificate FUID references across the three sensors resolve to an X.509 row, all checked leaf
   names match their SNI through CN or SAN (83 core, 17 database, 446 DMZ sessions), and all
   certificates are valid at observation time. Resumption, issuer, key algorithm, chain depth, and
   OCSP records are varied but coherent.

6. **Infrastructure traffic fits the visible environment.** Six DHCP clients renew at roughly
   half of 3,600-, 7,200-, or 14,400-second leases with per-renewal jitter and stable MAC/hostname
   identity. Kerberos, LDAP, SMB, MySQL, SMTP, proxy, syslog, SSH, RDP, and web traffic follow
   plausible subnet and server roles. Internet background includes successful HTTPS, failed scans,
   resets, ICMP, policy alerts, and mixed destination ports rather than a single attack-only
   distribution.

7. **IDS alerts are not isolated decorations.** Snort DNS, HTTP CONNECT, APT/curl, TLS, STUN,
   BitTorrent, SSH scan, and ICMP alerts use plausible fast-alert formatting and resolve to visible
   network tuples at the expected sensor locations. Duplicate core/perimeter sightings carry the
   same sensor-offset pattern seen in the underlying flows.

## Detailed Analysis

The reviewed network corpus contains 11,258 core, 490 database, and 8,321 DMZ Zeek connection
records; 19,065 ASA messages; 2,411 proxy access records; 146 Snort alerts; 883 web access records;
and 24,590 endpoint FLOW records. The approximately six-hour span has enough traffic to distinguish
isolated anomalies from repeated generator-like behavior.

**Connection and firewall layer.** The connection-state mix is plausible. Core traffic contains
8,963 `SF` and 1,969 `S0` records; DMZ contains 5,317 `SF` and 2,721 `S0`; database traffic is
smaller and dominated by successful MySQL. Reset direction is maintained through the firewall
contract, one-way UDP syslog appears as expected, and internet scan SYNs receive 30-second ASA SYN
timeouts. ASA connection identifiers are contiguous from 1681558 through 1688874, which is
noticeably tidy but can occur when the firewall logs every connection family; it was not counted
as an adverse indicator.

**Proxy layer.** HTTP methods, response phrases, usernames, user agents, denial/authentication
states, and control-versus-tunnel byte fields are plausible. The problem is lifecycle ownership:
the proxy duration and Zeek TCP duration disagree on hundreds of directly identified sessions.
Because this occurs in completed sessions with exact byte equality, neither sensor incompleteness
nor an alternate flow match explains it. The adjacent 600 ms launch pattern compounds the issue by
showing a repeated scheduling primitive in the same traffic family.

**DNS and DHCP.** DNS response semantics pass basic source checks, including authoritative behavior
for the internal namespace and realistic negative responses. DNS RTTs range from sub-millisecond to
multi-second and are not zero-filled. DHCP contains only REQUEST/ACK renewals, but the bounded window
does not require a visible DISCOVER. Renewal spacing follows half-lease behavior with useful jitter.

**TLS, certificates, and HTTP files.** TLS negotiation is internally valid and stable per
destination, certificate chains and names are coherent, and certificate visibility differs
appropriately between TLS 1.2 and TLS 1.3. HTTP persistent sessions use increasing `trans_depth`,
and most response FUIDs resolve to files with the expected size and MIME type. The five missing
same-sensor file records are a small contract gap, not a broad coverage complaint.

**Segmentation and lateral movement.** Core, DMZ, and database visibility generally follows the
apparent topology. Mirrored sensors assign independent UIDs and sometimes disagree on packet,
history, or missed-byte details while retaining tuple and state identity. Internal SMB mappings and
file actions, web-to-database MySQL, workstation/server SSH, and domain-service traffic all have
plausible directions and service ports. Late SSH starts without Zeek closure records are consistent
with open sessions at the end of the collection window and were not treated as defects.

**Traffic volume and timing.** Aggregate volumes and service proportions are plausible for a small
enterprise slice. Most recurring flows have high interarrival variability, and external scanning
is irregular. The sharply repeated 600 ms browser/proxy sequences are the exception and stand out
against that otherwise heterogeneous background.

## Synthetic Indicator Summary

| Indicator | Category | Scope | Weight |
|---|---|---:|---|
| Proxy tunnel duration exceeds the exact matching completed TCP lifetime | `hard_contradiction` | 416/639 explicitly keyed CONNECT sessions; 262 with exact two-way byte equality | Decisive |
| Near-exact 600 ms connection and HTTP transaction pacing across clients | `distribution_texture` | 131 connection gaps, 30 multi-connection runs, eight clients; 27 within-session HTTP gaps | Strong |
| Referenced HTTP FUID absent from same-sensor `files.json` | `contract_gap` | Five records across core and DMZ | Low |
| Almost fixed 110–118 ms core/DMZ clock relationship | `weak_signal` | 4,121 mirrored TCP/UDP flows | Low |

No adverse finding was assigned solely because domains appear sanitized, some source families are
thin or absent, multiple sources correlate completely, or the suspicious activity is compact and
easy to follow.

## Realism Score by Category

| Category | Score | Rationale |
|---|---:|---|
| Field format accuracy | 9/10 | Zeek JSON, ASA syslog, Snort fast alerts, proxy/web logs, and eCAR FLOW fields are consistently parseable and source-plausible; only minor FUID gaps appear. |
| Temporal patterns | 4/10 | Broad timing is varied, but the cross-client 600 ms metronome and impossible proxy tunnel lifetimes are high-impact failures. |
| Cross-source correlation | 7/10 | Firewall/Zeek, Zeek protocol, TLS/X.509, and endpoint tuples correlate extremely well, but the proxy lifecycle contradiction breaks a core cross-source invariant. |
| Behavioral realism | 8/10 | Protocol mix, scans, normal browsing, DNS behavior, DHCP renewal, lateral services, and failure/reset behavior are convincing. |
| Environmental consistency | 8/10 | Segmentation, host roles, sensor visibility, collection loss, and bounded-window open sessions are plausible; fixed sensor timing and small file-contract gaps reduce the score. |

## Recommendations

1. Make the client-to-proxy TCP session the hard outer bound for CONNECT lifecycle data. For every
   tunnel, enforce `tcp_duration >= tunnel_duration + CONNECT setup time`, and derive Zeek duration,
   proxy duration, close time, and byte totals from one canonical lifecycle. Add an invariant test
   keyed by client source port and tunnel ID.

2. Remove the fixed 600 ms browser scheduler. Model resource discovery, HTTP connection reuse,
   browser connection limits, parallel launches, service-worker/background traffic, and
   destination-dependent latency with nonuniform per-session timing. Validate the result using
   run-length and interarrival histograms across clients, not only per-record jitter.

3. Keep FUID observation atomic within each Zeek sensor: if an HTTP row exports `resp_fuids`, emit
   the corresponding `files.json` record unless a modeled collection policy explicitly drops it.
   If log loss is intended, make the collection reason visible through coherent source-local loss
   behavior rather than an unexplained dangling reference.

4. Review cross-sensor clock modeling. A stable offset is plausible, but production-like clocks
   usually include small drift, synchronization corrections, and path-dependent observation noise.
   Preserve the realistic independent UIDs and asymmetric missed-byte behavior.

5. Preserve the strong portions of the dataset: ASA state/reason semantics, TLS 1.2 versus TLS 1.3
   certificate visibility, DNS response diversity, DHCP half-lease jitter, independent sensor
   observations, and bounded-window treatment of still-open sessions.
