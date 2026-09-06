# Network Forensics Analyst — Authenticity Assessment

## Verdict

- Assessment: Synthetic
- Verdict Confidence: 89
- Synthetic-Confidence Score: 84

## Executive Summary

The dataset is highly polished at the flow, DNS, TLS, proxy, and firewall layers, but it is more
likely synthetic than sanitized production data. The strongest discriminator is not coverage or
cross-source completeness. It is a set of concrete Snort-to-Zeek semantic contradictions: Snort
labels five plaintext HTTP flows as `curl` User-Agent detections, while the matching Zeek HTTP
transactions identify `Go-http-client/1.1` or `Wget/1.21.3`; another APT User-Agent alert maps to a
Zeek transaction using `Go-http-client/1.1`. Two Python-urllib request alerts are attached to
end-to-end TLS flows for which the adjacent Zeek view records only TLS and no observable HTTP
request. These are source-visible contract failures, not an objection that the evidence is “too
complete.”

There are also repeated timing textures: 3,993 matching core/DMZ Zeek flows have an almost fixed
sensor offset centered near 114 ms, and all 94 matched DNS-rule Snort alerts fall only 204–300 ms
after the associated Zeek DNS record. Fixed clock skew can occur in production, so these are not
impossibilities by themselves, but their consistency across thousands of flows and heterogeneous
alert types reinforces the synthetic verdict.

Conversely, much of the corpus is impressively production-like. Zeek UIDs are sensor-local;
packet loss and byte counts differ realistically between observation points; DNS answer/TTL,
connection lifecycle, TLS certificate, proxy tunnel, NAT, and ASA teardown semantics are broadly
coherent. Those strengths materially reduce the synthetic-confidence score from what the Snort
contradictions alone might warrant.

## Evidence For Synthetic

- **hard_contradiction:** All five Snort perimeter alerts labeled `ET POLICY curl User-Agent
  Outbound` conflict with the corresponding plaintext Zeek HTTP transaction. At
  `03/18-12:09:49.165750`, Snort identifies `10.10.3.20:41512 -> 87.136.158.10:80` as curl, but
  Zeek UID `CHmHRIF615OCarF8rGx` records `user_agent="Go-http-client/1.1"`. At
  `12:15:06.738081`, tuple `10.10.3.20:52164 -> 13.107.13.246:80` maps to Zeek UID
  `CnKfU3tNkJGlFD0it3` with `user_agent="Wget/1.21.3"`. The remaining three curl alerts—source
  ports 44261, 51613, and 47332—also map to `Wget/1.21.3`. Each matching connection contains one
  Zeek HTTP transaction (`trans_depth=1`), leaving no second request with a curl header visible in
  the flow.

- **hard_contradiction:** Snort alert `ET POLICY GNU/Linux APT User-Agent Outbound` at
  `03/18-15:47:26.397266` names `10.10.3.20:36624 -> 23.45.197.190:80`. The same tuple is Zeek UID
  `CkEaKOUEpoAl3Tr1R18`, whose only HTTP transaction is a POST to
  `api.segment-analytics.io/report` with `user_agent="Go-http-client/1.1"`, not an APT client.
  One other APT alert is correctly supported by `Debian APT-HTTP/1.3 (2.4.10)`, which makes the
  unsupported assignment look record-specific rather than a wholesale naming convention.

- **contract_gap:** Snort emits `ET INFO Python-urllib Outbound Request` for
  `10.10.3.20:48048 -> 52.84.215.166:443` at `13:35:47.438300` and
  `10.10.3.20:42257 -> 104.16.197.212:443` at `17:21:50.458089`. The matching Zeek records are
  established encrypted TLS sessions: UID `CIi4WZrbxJTiv2BZb4r` uses TLS 1.3 with SNI
  `static.hotjar.com`, and UID `CFwG2W2HBVPddGQWHt` uses TLS 1.2 with SNI `api.segment.io`.
  Neither UID has a Zeek HTTP record. No log-visible decryption context explains how a perimeter
  IDS could inspect a Python `User-Agent` inside those origin-side TLS streams.

- **distribution_texture:** Cross-sensor timing is unusually rigid. Matching exact five-tuples
  within two seconds produced 3,993 core/DMZ flow pairs. Their absolute first-packet timestamp
  difference has a median of 0.114210 seconds and spans only 0.110559–0.118160 seconds across the
  six-hour window. For 142 core/database pairs, the corresponding offset centers near 0.065626
  seconds. Stable clock offsets are possible, but millisecond-bounded sensor relationships over
  thousands of unrelated DNS, proxy, web, TLS, SMB, and other flows are a strong generated timing
  texture.

- **distribution_texture:** Snort alert latency occupies a narrow, source-independent envelope.
  All 64 matchable TCP/UDP core alerts occur 0.210751–0.306271 seconds after Zeek connection start,
  and all 82 matchable TCP/UDP perimeter alerts occur 0.211935–0.317357 seconds after start. More
  specifically, 58 core and 36 perimeter DNS alerts occur only 0.204664–0.300458 and
  0.211440–0.292962 seconds, respectively, after the exact Zeek DNS record. DNS-name matches,
  JA3/TLS indications, rapid-connection thresholds, and HTTP content signatures normally trigger
  on different packets and processing paths; the shared narrow delay band looks imposed.

- **environment_or_collection_plausibility:** The DMZ records 868 inbound `S0` connections in six
  hours, but only ten source IPs produce them and the top eight account for 844 (97.2%). Those
  sources repeatedly specialize in small fixed port sets: `38.186.148.245` contributes 138
  identical 60-byte SYN observations concentrated on mail ports, while `37.75.195.175` contributes
  136 identical 48-byte SYNs concentrated on Telnet/SSH/web ports. Campaign-level reuse and stable
  SYN fingerprints are realistic, so this is not a contradiction, but the combination of high
  volume and extremely low source diversity is more curated than typical exposed-service noise.

- **weak_signal:** HTTP application texture comes from a compact repeated pool. In the DMZ Zeek
  view, 1,710 HTTP records use only 39 User-Agent strings; 793 records repeat an exact combination
  of method, host, URI, User-Agent, status, and body lengths. One exact CONNECT shape for
  `ctldl.windowsupdate.com:443` with `Microsoft-CryptoAPI/10.0` appears 85 times. Repetition is
  expected for updaters and proxy traffic, so this contributes only weakly.

## Evidence For Real

- The Zeek records are structurally sound and internally consistent. Across all three sensors,
  every DNS, HTTP, and SSL UID resolves to a local `conn.json` row, and no protocol record occurs
  before its own connection or after the visible connection close. There are no duplicate Zeek
  connection UIDs or overlapping reuse of an exact TCP four-tuple.

- Packet and byte arithmetic is credible. All UDP flows satisfy the expected IPv4 relationship
  between payload bytes, packet counts, and IP bytes. TCP IP-byte totals never fall below payload
  plus minimum TCP/IP header cost. HTTP request and response body lengths never exceed the
  corresponding directional connection bytes.

- Adjacent sensors do not simply clone records. For the first proxy flow, DMZ UID
  `CpVuqkUHyHUHlifqRVC` sees 1,232 origin bytes, 38,789 response bytes, no loss, and four origin
  packets, while core UID `CpzZTIVmBBMgTCxSkov` sees 1,218 origin bytes, 38,789 response bytes,
  14 missed bytes, and three origin packets. Across 3,993 core/DMZ pairs, only about 95% have equal
  directional byte and packet counts and 91.2% have identical history strings. This is convincing
  multi-vantage packet-loss texture.

- TLS semantics are strong. Version/cipher combinations are valid, every referenced certificate
  FUID resolves locally, and every checked certificate is valid at the session timestamp. For 549
  TLS sessions with both SNI and an observed leaf certificate across the three sensors, the SNI
  matches a SAN or certificate common name, including wildcard handling. Resumed sessions omit
  certificate chains, while full handshakes variably expose chains depending on vantage and loss.

- DNS behavior is varied and coherent. Core DNS contains 2,913 transactions with A, AAAA, PTR,
  SRV, TXT, NS, MX, and SOA types, plus NOERROR, NXDOMAIN, SERVFAIL, and REFUSED responses. Answer
  and TTL cardinalities agree in every record, and every DNS RTT fits within its connection
  duration. Concrete alerts also line up correctly: the `.top` Snort alert at
  `12:17:57.106896` maps to Zeek UID `CwwG0cCHR4flBHCOy3`, query
  `metrics-r64kftua.top`, with NXDOMAIN.

- Proxy lifecycle modeling is unusually good. The proxy log contains 585 SSL-inspection tunnel
  setup records with 585 unique tunnel IDs and 829 decrypted requests. Every decrypted request
  references an existing setup, with consistent client IP, user, User-Agent, and client source
  port; some tunnels carry multiple requests, up to twelve. Ordinary CONNECT tunnels, SSL-bumped
  tunnels, denies, authentication challenges, and gateway failures have distinct byte scopes and
  actions.

- Firewall lifecycle and NAT semantics are credible. The ASA log has 6,961 built and 6,961 teardown
  connection messages, 1,671 paired dynamic translation build/teardown messages, and 321 denies.
  Teardown reasons vary among FINs, SYN timeouts, origin resets, and responder resets. For example,
  UDP connection 1681559 reports 171 bytes, exactly matching the observed DNS flow's 89 plus 82 IP
  bytes, while a failed outbound TLS connection uses `TCP Reset-O` and a SYN-only inbound attempt
  closes after 30 seconds with `SYN Timeout`.

- Traffic composition is plausible for the represented environment: internal Kerberos, LDAP,
  SMB, DNS, syslog, DHCP renewals, SSH, RDP, SMTP, web, TLS, proxy-origin flows, unsolicited DMZ
  scans, and ICMP all appear with varied connection states and histories. DHCP renewals occur near
  half-lease intervals with per-client jitter rather than exact periodic timestamps.

## Detailed Analysis

The review was confined to the assigned data directory. I parsed all three Zeek sensor families,
the ASA firewall log, both Snort logs, the explicit-proxy access log, and the external web access
log. Network record volume covers a six-hour window: 10,960 core Zeek connections, 7,847 DMZ
connections, and 434 database-segment connections. The core mix includes 5,743 TCP, 4,820 UDP,
and 397 ICMP records; the DMZ mix includes 6,544 TCP, 1,008 UDP, and 295 ICMP records. This is
enough volume to distinguish isolated anomalies from repeated generator-like behavior.

At the Zeek layer, connection state/history combinations are diverse and generally credible.
Core states include 8,719 `SF`, 1,914 `S0`, 146 `RSTO`, 89 `RSTR`, 30 `REJ`, and smaller numbers
of partial/other states. DMZ contains 4,966 `SF` and 2,645 `S0`, consistent with an exposed
service receiving scan traffic. Services and ports align: DNS dominates UDP/53, Kerberos appears
on 88, LDAP on 389, SMB on 445, proxy HTTP on 8080, database traffic on 3306, and TLS on 443.
Packet histories vary with loss, retransmission, reset, and closure outcomes rather than collapsing
to one idealized string.

The multi-sensor correlations are technically sophisticated. Identical real-world tuples receive
different UIDs at different Zeek sensors, while protocol facts remain aligned. Timestamp offsets
are directional and sensor-specific. Byte discrepancies and `missed_bytes` are reflected in packet
counts and histories. This would be persuasive production evidence if the timing offsets had more
natural drift or packet-path variance; their very narrow long-window bands instead suggest a
sensor-delay model applied to otherwise strong canonical flows.

The explicit proxy is the most convincing source family. A representative sequence at 12:32:14
creates tunnel `PT-0000000096cbb985` for client `10.10.1.34`, source port 50673, user
`MERIDIANHCS\\diego.ramirez`, and `aws.amazon.com:443`; the following SSL-inspected GET reuses the
same tunnel ID, identity, port, and User-Agent. Subsequent asset tunnels preserve referrers and
host-specific IDs. Failed CONNECTs terminate without tunneled byte counters, while successful
passthrough CONNECTs separate control-message bytes from tunneled bytes. The proxy-to-origin Zeek
view likewise uses the proxy address as origin and preserves the requested SNI.

TLS and X.509 data also resist easy synthetic detection. TLS 1.2 and 1.3 use compatible suites;
certificate validity windows contain the traffic timestamps; full handshakes can carry one- or
two-element chains; SANs agree with SNI; and session resumption changes certificate visibility.
The certificate evidence is not merely complete—many non-resumed handshakes lack a visible chain,
which is compatible with collection gaps.

The decisive failure is the IDS content contract. A production IDS can generate false positives,
but a rule explicitly named for a visible HTTP User-Agent should not repeatedly disagree with the
same flow's parsed HTTP User-Agent. Here the disagreement is systematic for the curl rule (five of
five alerts), recurs for an APT rule, and extends to purported Python-urllib requests on encrypted
TLS-only flows. This looks like alert labels selected independently of the canonical application
content. The correctly matched DNS TLD alerts and one correctly matched APT alert show that the
dataset is capable of content-aware matching, making the unsupported cases more probative.

Temporal behavior is otherwise varied. DNS response times fit flow durations; DHCP renewals use
jitter; proxy tunnels have varied durations and request multiplicity; TCP closures include FINs
and both reset directions. The suspicious timing is concentrated in source-to-source observation
offsets and alert delay. These patterns could be explained by stable clock skew or logging latency
in isolation, so they are supporting evidence rather than standalone proof.

The unsolicited DMZ traffic has source-specific packet sizes and port preferences that resemble
real scanner fingerprints. However, 97.2% of all inbound `S0` attempts come from just eight IPs
over a high-volume six-hour period. That compact campaign pool, combined with the repeated HTTP
template pool, gives the background traffic a curated texture. I weight these observations lightly
because sanitization or a bounded collection policy could preserve only selected campaigns.

## Synthetic Indicator Summary

| Indicator | Category | Scope | Strength |
|---|---|---:|---|
| Five of five curl alerts conflict with the matching Zeek User-Agent | hard_contradiction | Repeated | Very high |
| APT User-Agent alert conflicts with a Go HTTP client transaction | hard_contradiction | One confirmed record | High |
| Python-urllib request alerts occur on two TLS-only origin flows | contract_gap | Repeated | High |
| Nearly fixed Zeek sensor-to-sensor flow offsets | distribution_texture | 3,993 core/DMZ pairs plus other segments | Medium-high |
| Narrow Snort-to-Zeek timing envelope across rule families | distribution_texture | 146 TCP/UDP alerts; 94 DNS alerts | Medium |
| High-volume inbound scan noise concentrated in eight sources | environment_or_collection_plausibility | Dataset-wide DMZ background | Low-medium |
| Compact repeated HTTP/User-Agent combinations | weak_signal | Broad, especially proxy traffic | Low |

The first three indicators drive the verdict. The timing, scanner, and HTTP-distribution findings
raise confidence but would not independently justify a synthetic classification.

## Realism Score by Category

- field format accuracy: 8/10
- temporal patterns: 7/10
- cross-source correlation: 8/10
- behavioral realism: 7/10
- environmental consistency: 8/10

## Recommendations

1. Make IDS alerts contingent on the exact source-visible payload that would trigger the named
   rule. For HTTP User-Agent rules, derive the alert from the same User-Agent rendered in Zeek and
   proxy evidence, and add negative checks proving that `curl`, APT, Wget, Go, and urllib labels
   cannot be assigned interchangeably.

2. Do not emit plaintext HTTP content signatures on TLS-only flows unless the logs also establish
   an observation point with decryption. If inspection occurs at the explicit proxy, associate the
   alert with the proxy's decrypted client-side transaction or provide source-visible inspection
   metadata; otherwise use TLS-observable signatures such as certificate, SNI, JA3/JA4, or flow
   behavior.

3. Timestamp IDS records from the actual triggering packet or threshold event. DNS-name rules
   should track the query packet; TLS fingerprints should track ClientHello; rapid-connection
   alerts should occur when the threshold is crossed; HTTP content rules should track the packet
   carrying the matched header. Avoid applying one shared 200–320 ms post-connection delay band.

4. Model per-sensor clocks and packet arrival paths with slow drift, asymmetric routing effects,
   queueing, and capture-specific loss rather than a nearly fixed offset for every shared flow.
   Preserve the existing sensor-local UIDs and vantage-specific byte/history differences, which
   are strong.

5. Broaden unsolicited-scan campaign diversity for this traffic volume, or reduce the volume if
   the intent is a tightly filtered collection. Retain source-specific SYN fingerprints and port
   preferences, but vary campaign start/stop behavior and source population.

6. Keep the current proxy tunnel identities, NAT lifecycles, TLS certificate/SNI contracts, DNS
   response semantics, and loss-aware multi-sensor accounting. These are the most production-like
   aspects of the dataset and should serve as invariants while the IDS layer is corrected.
