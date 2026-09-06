# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real  
**Verdict Confidence:** 82  
**Synthetic-Confidence Score:** 24

## Executive Summary

The network corpus is highly production-like: its Zeek connection states, packet and byte
accounting, DNS behavior, TLS/X.509 visibility, multi-sensor clock offsets, packet-loss effects,
and endpoint-flow outcomes form a coherent six-hour observation. I found no P0 or P1 network
contradiction; only a constrained firewall event vocabulary and two low-impact distribution
signals keep the data out of the indistinguishable 0–20 band.

## Evidence For Synthetic

- **P2 — [distribution_texture]** The 18,175-line perimeter ASA file has an unusually bounded
  message vocabulary. `%ASA-6-302013` and `302014` occur exactly 6,001 times each, `305011` and
  `305012` exactly 1,671 times each, and `302015` and `302016` exactly 960 times each; only nine
  message IDs appear in total. The individual records are credible—for example, connection
  1681558 is built at `Mar 18 12:00:12` and torn down after a 30-second SYN timeout at
  `12:00:42` (`fw-perimeter/cisco_asa.log`, records 1 and 12)—but the family looks more like a
  deliberately traffic-focused export than an unfiltered production ASA stream.
- **P3 — [distribution_texture]** A single public source, `185.70.41.45`, produces 399 TCP/443
  flows to `10.10.3.10` between `1710765004.478029` and `1710767981.690644`: 350 `SF`, 23 `S0`,
  16 `RSTO`, and 10 `RSTR`. Its 349 parsed TLS sessions are all TLS 1.3 with
  `TLS_AES_128_GCM_SHA256` and the same SNI, while the resumed flag alternates (185 false, 164
  true). This can be a real scanner with a shared session cache, and the failed/reset texture is
  convincing, but the long homogeneous run is a mild authored-workload signal
  (`zeek-dmz/conn.json`, records 404, 410–415; `zeek-dmz/ssl.json`, records 96–101).
- **P3 — [weak_signal]** Two repeated `pypi.org` answers from the same client, resolver, and
  RRset show a small TTL discontinuity: `10.10.3.20 -> 10.10.2.10` receives TTL 45 at
  `1710774439.999765`, then TTL 30 only 41.121 seconds later, whereas a simple cache countdown
  would be near four seconds (`zeek-core/dns.json`, records 1307 and 1320). A resolver-side
  30-second floor or refresh policy readily explains this; importantly, nine of eleven comparable
  same-resolver repeats did decrement coherently, so this is not a broad DNS defect.

## Evidence For Real

- The three Zeek views have believable scale and distinct sensor identity: 10,960 core, 7,847
  DMZ, and 434 database `conn` records over approximately six hours. Cross-sensor instances use
  different UIDs and stable clock offsets rather than cloning records. I matched 3,993 core/DMZ
  tuples within one second; all had the same connection state, while 348 had different packet
  counters or histories consistent with sensor-local visibility and loss.
- Connection-state texture is varied and protocol-appropriate. Core contains 8,719 `SF`, 1,914
  `S0`, 146 `RSTO`, 89 `RSTR`, 30 `REJ`, and smaller `OTH`/`S1`/`S2`/`S3` populations. Sensitive
  services include 420 successful SMB sessions, 62 successful SSH sessions, seven successful RDP
  sessions, and realistic failed-scan populations rather than one universal outcome.
- Packet accounting is internally sound. Across all 19,241 Zeek connection rows, no record had
  IP-byte overhead below the minimum implied by its protocol and packet count. The opening DNS
  transaction (`zeek-core/conn.json`, record 1; `zeek-core/dns.json`, record 1) shares UID
  `Cl6dXZAWxQDQ8B6wk5`, has matching tuple fields, and places the DNS observation and RTT inside
  the 33.958 ms UDP flow.
- DNS has a credible enterprise mix: core includes 2,119 A, 239 AAAA, 143 PTR, 92 SRV, 303 TXT,
  plus NS/MX/SOA; it also has 216 NXDOMAIN, 16 SERVFAIL, and six REFUSED responses. Samples include
  Windows-style `wpad`, `wpad.local`, `isatap.meridianhcs.local`, suffix-appended public names,
  stale internal names, reverse lookups, NODATA AAAA answers, and low-TTL TXT traffic. All 3,891
  DNS rows across sensors have answer/TTL cardinality consistency, no error response carries an
  answer, and no DNS RTT exceeds its parent connection duration.
- DHCP renewal behavior is especially credible. Six clients use 3,600-, 7,200-, or 14,400-second
  leases, and the 3,600-second clients renew roughly at T/2 with per-client jitter: observed
  intervals span about 1,756–1,989 seconds rather than landing exactly every 30 minutes. The
  bounded window reasonably contains REQUEST/ACK renewals without requiring a visible initial
  DISCOVER.
- TLS semantics survive detailed checks. The corpus mixes TLS 1.2 and 1.3, modern RSA/ECDSA
  suites, resumed and full sessions, internal enterprise chains, public CA chains, SNI-less
  traffic, self-signed IP certificates, and resets. For all 558 inspectable TLS 1.2 handshakes
  with certificates, the cipher authentication family matched the leaf key type. All 45 TLS 1.2
  rows whose `ssl_history` showed a certificate but lacked `cert_chain_fuids` belonged to
  connections with positive `missed_bytes`, while complete examples had exact SSL/files/X.509
  linkage. UID `CHob1xHkZfVrSFdSBN`, for example, links SMTP STARTTLS, TLS, two partially observed
  certificate files, and eight missed bytes (`zeek-core/conn.json`, record 226;
  `smtp.json`, record 1; `ssl.json`, record 4; `files.json`, records 9–10).
- HTTP keep-alive and loss handling are credible. Most proxy CONNECTs are one transaction, while
  direct HTTP connections reach `trans_depth` 7. UID `CRQ6rzE7pImLn0STlN` carries three ordered
  requests on one TCP connection (`zeek-core/http.json`, records 1298–1300); the summed declared
  bodies exceed observed `resp_bytes` by 2,892 bytes, but the connection records 3,492
  `missed_bytes`, and its file records preserve per-object missing-byte accounting
  (`conn.json`, record 9806; `files.json`, records 581–583). No file's `seen_bytes` exceeds the
  available directional connection bytes.
- Protocol children are temporally and structurally joined. Across each sensor, every DNS, HTTP,
  SSL, SMTP, SMB mapping, SMB file, and files-framework UID reference resolves to a parent
  connection; tuple mismatches and child timestamps outside connection intervals were both zero.
- Endpoint/network agreement is strong without being timestamp-cloned. Of 23,866 eCAR FLOW rows,
  23,107 matched a Zeek tuple and every match was within five seconds of the network start. The
  dominant outcome pairs were 19,537 endpoint successes with Zeek `SF`, 2,120 endpoint failures
  with `S0`, 391 failures with `RSTO`, 278 failures with `RSTR`, and 71 failures with `REJ`.
  Paired source/destination endpoint observations had broad millisecond deltas, with only six
  exact timestamp ties among 7,256 pairs.
- Traffic timing is not uniformly smooth. Fifteen-minute core counts range from 266 to 668 in
  ordinary bins, with a distinct 1,899-flow burst around 13:45 UTC caused by an internal ICMP and
  five-port `/24`-style sweep. The sweep has responsive, rejected, and silent hosts, while normal
  DNS, Kerberos, LDAP, SMB, proxy, mail, and user traffic continues through the burst.

## Detailed Analysis

### Scope and Connection Behavior

The visible window begins at `1710763205.580965` and ends at approximately
`1710784793.188794`, just under six hours. The core sensor is dominated by expected enterprise
traffic: 2,919 DNS flows, 2,329 Kerberos flows split across UDP and TCP, 1,457 HTTP flows, 1,163
LDAP flows, 424 analyzed SMB flows, and smaller SSH, SMTP, DHCP, TLS, database, and RDP
populations. The DMZ view appropriately shifts toward TLS/443, proxy/8080, public scanning, web,
and database traffic; the database view is smaller and dominated by 261 MySQL sessions.

TCP histories agree with states and counters. Completed sessions show varied histories such as
`ShADadfF`, `ShADaDadFf`, and loss-marked `ShADadfFg`; silent scans show `S`/`S0`; resets appear
from both originator and responder. Positive `missed_bytes` occurs in 522 core, 531 DMZ, and 43
database flows and is accompanied by gap markers in history. This is not decorative loss: it
propagates into absent or partial protocol artifacts, as the STARTTLS and HTTP examples above
demonstrate.

### DNS and Infrastructure Protocols

DNS source/destination tuples, transaction IDs, query types, flags, answers, TTL arrays, and RTTs
are source-native and coherent. Internal A/PTR responses commonly use authoritative 300–7,200
second TTLs; public records show cache countdowns, CDN-sized RRsets, short TTLs, occasional
multi-second retries, and negative answers. Of 1,110 core A/AAAA answer-to-connection matches
within 30 seconds, the median delay was about 1.051 seconds. A few connections began before the
contemporaneous DNS response completed, but those names or addresses can be explained by an
existing cache; I did not treat that as impossible visible ordering.

The DHCP file has 47 rows and six clients. Renewal counts and lease-dependent cadence are
consistent with a slice-of-time collection. The absence of a separate NTP source was not scored:
source omission alone is not an authenticity indicator, and no visible record creates a required
but contradictory NTP companion.

### TLS, HTTP, Proxy, and Files

TLS 1.3 correctly lacks visible certificate chains in ordinary passive inspection, while full
TLS 1.2 handshakes usually expose leaf/intermediate files and X.509 rows. Resumed sessions omit
chains, certificate validity covers the observation time, repeated SNIs retain stable leaf
fingerprints, internal names use an enterprise hierarchy, and public names use several plausible
CA families. Certificate-file timestamps follow the SSL record and remain within the connection.

HTTP is modern and proxy-heavy: CONNECT dominates core and DMZ traffic, with 403/407/502/503/504
failures mixed into successful tunnels. Direct HTTP includes redirects, caching (`304` with zero
body), range responses, POSTs, executable downloads, and multi-object browser sessions. Client
and proxy-origin legs preserve host, user-agent, method, and payload relationships while using
separate network identities. SMB likewise joins mapping, open/read/write/rename operations,
files-framework FUIds, hashes, direction, and connection accounting without out-of-window file
events.

### Firewall, IDS, and Cross-Source Timing

ASA connection IDs pair correctly across build/teardown records; NAT translations pair around
outbound public traffic; ACL denies use severity 4 and include interface, tuple, access-group, and
flags. Snort alerts have plausible source-native formatting and directional tuples for DNS TLD,
JA3, HTTP basic-auth, curl, STUN, BitTorrent, SSH, ICMP, and rapid HTTPS-scan signatures. Shared
events can appear at both core and perimeter sensors with independent timestamps, as expected.

The stable offsets between Zeek sensors are a strong real-world detail: matched core/DMZ flow
starts cluster roughly 114 ms apart, core/database roughly 55 ms apart, and DMZ/database roughly
170 ms apart, with jitter and occasional counter differences. This resembles separate clocks and
vantage points, not duplicated rows. Endpoint-flow timestamps add broader host-local observation
delay rather than inheriting Zeek microseconds.

## Synthetic Indicator Summary

| Priority | Category | Affected source family | Scope | Effect on score |
|---|---|---|---|---|
| P0 | — | Network corpus | None observed | No impossible ordering, impossible field value, generator leak, or source-native hard contradiction was found. |
| P1 | — | Network corpus | None observed | No repeated high-impact contract or schema defect was found. |
| P2 | `distribution_texture` | Cisco ASA | Dataset-wide within that file | Nine message IDs and exact paired family counts make the firewall export feel deliberately bounded, although a traffic-only export explains it. |
| P3 | `distribution_texture` | Zeek TLS/conn | One source, repeated for ~49 minutes | The 399-flow TLS scanner is unusually homogeneous, but its failures, resets, timing, and resumption behavior remain technically plausible. |
| P3 | `weak_signal` | Zeek DNS | Two same-resolver repeat intervals | Small TTL discontinuities could indicate a floor/reset rule, but ordinary resolver refresh policy is an adequate explanation. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, ASA, Snort, proxy, and eCAR fields are source-native and
  internally valid; no hard field contradiction was found.
- **Temporal patterns:** 8 — Human/infrastructure traffic, scanning bursts, lease renewals,
  multi-sensor skew, and packet-loss timing are convincing, with only mild repeated-workload
  texture.
- **Cross-source correlation:** 9 — UID, tuple, file, TLS, SMTP, proxy, firewall, IDS, and endpoint
  pivots agree without simply cloning every sensor timestamp or packet count.
- **Behavioral realism:** 8 — Service distributions, failures, web keep-alive, scanning, lateral
  protocols, and public egress look operationally plausible; one TLS source is conspicuously
  homogeneous.
- **Environmental consistency:** 8 — The core, DMZ, database, proxy, firewall, and endpoint views
  fit a segmented enterprise, though the ASA export's narrow vocabulary suggests deliberate
  collection shaping.

## Recommendations

- **P2:** If this were synthetic, broaden the perimeter firewall's source-native event population
  beyond the nine observed IDs, or make the traffic-only collection boundary visible in-band. Add
  low-volume interface, routing, failover, VPN, inspection, and operational messages only when
  consistent with the modeled appliance and logging configuration; do not disturb the strong
  connection/NAT pairing.
- **P3:** If this were synthetic, give long-lived scanner/client families a stateful TLS profile:
  stable implementation traits should remain, but resumption should follow an explicit session
  cache and ticket lifetime rather than merely achieving a plausible aggregate ratio. Preserve
  the current mix of `SF`, `S0`, and bidirectional resets.
- **P3:** If this were synthetic, retain the strong resolver-specific TTL countdown model and
  explicitly represent minimum-TTL floors, prefetch, cache eviction, or authoritative refresh
  when a same-client/same-resolver/same-RRset answer jumps before expiry. The two `pypi.org`
  examples are low urgency because a 30-second resolver floor already explains them.
