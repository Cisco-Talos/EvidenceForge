# Network Forensics Analyst — Authenticity Assessment
## Verdict
**Assessment:** Synthetic
**Verdict Confidence:** 94
**Synthetic-Confidence Score:** 89

## Executive Summary
The network corpus is highly polished and gets many difficult details right, but two repeated,
log-visible lifecycle contradictions outweigh those strengths. First, an eCAR-attributed
`nmap -sT` process produces ordinary HTTP, TLS, SMB, and SSH application payloads on the exact
scan sockets. A connect-only port scan establishes sockets and closes them; it does not issue an
HTTP request, a TLS ClientHello, or an SMB negotiation. Second, 431 of 715 explicitly linked
SSL-inspection tunnels report a proxy `tunnel_duration_ms` more than 200 ms longer than the
complete `SF` TCP connection carrying that tunnel, even though `tunnel_id`, client source port,
host, and byte rollups identify the same transport. These are not judgments based on narrative
neatness or complete correlation; they are contradictions between named commands/application
behavior and between linked lifecycle intervals.

The corpus otherwise resembles a mature synthetic renderer or an unusually well-curated
production export. It contains 11,354 core, 8,432 DMZ, and 475 database Zeek connections over
roughly six hours; realistic Zeek state/history combinations; independent sensor UIDs; stable but
non-identical sensor clocks and packet counts; coherent ASA lifecycles; sensible DNS cache and
failure behavior; valid TLS certificate chains; OS-appropriate ephemeral-port ranges; and DHCP
renewals near lease T1. Those strengths keep the score below 100, but they do not explain the two
repeated impossible contracts.

## Evidence For Synthetic
- **`hard_contradiction` — A connect-only Nmap scan emits full application transactions.**
  `WEB-EXT-01.meridianhcs.local/ecar.json:1257` creates PID 2705135 at
  `2024-03-18 13:40:28.696Z` with exactly
  `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24`. Its eCAR FLOW records retain that same command,
  PID, and actor ID. For example, line 1387 attributes source port 44057 to destination
  `10.10.2.30:80`, line 2006 attributes source port 50002 to `10.10.2.10:445`, and line 2270
  attributes source port 54370 to `10.10.2.30:443`. The exact sockets in
  `zeek-core/conn.json` contain application payload and protocol identification:
  line 3095 is `service=http`, `orig_bytes=125`, `resp_bytes=72`; line 3795 is `service=smb`,
  `orig_bytes=81`, `resp_bytes=861`; line 4067 is `service=ssl`, `orig_bytes=59`,
  `resp_bytes=160`; and line 3029 is SSH with `orig_bytes=22`, `resp_bytes=29`. All are tied to
  the visible Nmap process and occur between its creation and termination at
  `13:41:01.777Z` (`ecar.json:2531`). Plain `-sT` does not perform HTTP, TLS, or SMB protocol
  negotiation. This indicates that normal service-transaction payloads were substituted for
  successful scan sockets.

- **`contract_gap` — The same Nmap command bypasses its own host-discovery semantics.** The
  preceding root process at `ecar.json:998` is `nmap -sn 10.10.2.0/24`; during
  `13:40:16.534–13:40:19.975Z`, `zeek-core/conn.json` shows 250 ICMP probes and no TCP discovery
  probes, with only nine ICMP responders. The separate `-sT` invocation nevertheless probes all
  254 usable addresses on all five requested ports: 1,270 Zeek core connections, exactly 254 per
  port. The command does not contain `-Pn`, and there is no second discovery set between process
  creation and the port connections. A default Nmap invocation should discover hosts and scan the
  hosts considered up; the rendered behavior instead expands the CIDR directly into a Cartesian
  host-by-port matrix.

- **`distribution_texture` — Unanswered connect-scan sockets have no TCP retransmission
  texture.** Of those 1,270 scan connections, 1,244 are `S0`; every one has exactly
  `orig_pkts=1`, `resp_pkts=0`, `history="S"`, and no duration in `zeek-core/conn.json`. The
  process remains alive for 33.081 seconds, including about 21.8 seconds after the final new
  socket, yet none of the unanswered sockets contains a repeated SYN. A real Linux `connect()`
  scan across heavily filtered targets normally exposes at least some retransmissions during
  that wait. The exact one-SYN texture across all 1,244 unanswered sockets is a strong generated
  distribution fingerprint.

- **`hard_contradiction` — Proxy tunnel duration exceeds its carrying TCP lifetime.** The proxy
  log contains 715 `proxy_action=tunnel-setup` records with `tunnel_id` and `client_src_port`, each
  linked to one or more `ssl-inspect` child requests whose `cs_bytes`/`sc_bytes` sum exactly to the
  setup record's `tunnel_cs_bytes`/`tunnel_sc_bytes`. Exact tuple matching to
  `zeek-dmz/conn.json` succeeds for all 715. In 431 cases, reported tunnel duration exceeds the
  complete `SF` TCP duration by more than 200 ms; 408 exceed it by more than 500 ms. For example,
  `PROXY-01.meridianhcs.local/proxy_access.log:2099` identifies tunnel
  `PT-07f330a8598e8872`, client `10.10.1.22:33060`, and `tunnel_duration_ms=1841`; its sole child
  at line 2102 has the same tunnel ID and source port. The exact Zeek transport at
  `zeek-dmz/conn.json:6867` is `SF`, has no missed bytes, but lasts only 0.976767 s. Likewise,
  proxy lines 1763/1767 report a 1.865 s Salesforce tunnel while
  `zeek-dmz/conn.json:6046` reports the exact no-loss TCP transport lasting 1.004694 s. A child
  transaction cannot remain inside a tunnel after the carrying TCP connection has closed.

- **`contract_gap` — A small set of HTTP file gaps is not reflected in connection loss.** Five
  HTTP file observations with status 200 or no surviving HTTP row report positive
  `missing_bytes` while their linked `SF` connection reports `missed_bytes=0`. Examples include
  `zeek-core/files.json:179` (888 missing bytes) linked to `zeek-core/conn.json:2671`, and
  `zeek-core/files.json:550` (3,473 missing bytes) linked to `zeek-core/conn.json:9974`;
  `zeek-dmz/files.json:1042` reports 739 missing bytes while `zeek-dmz/conn.json:6228` reports no
  missed bytes. A short body relative to declared Content-Length can sometimes explain this, so
  this is lower-weight than the Nmap and proxy contradictions, but the repeated independent gap
  accounting is suspicious.

- **`weak_signal` — Highly exact family quotas appear in the scan expansion.** The core sensor
  contains exactly 254 connections for each of five ports, while observation loss changes the DMZ
  view by only one row and eCAR by six rows. Exact CIDR expansion is understandable for a test or
  renderer, but by itself it would not justify a synthetic verdict; it matters here only because
  it accompanies the command and retransmission contradictions above.

## Evidence For Real
- **Independent multi-sensor observation is convincing.** Matching by five-tuple and time finds
  4,292 shared core/DMZ connections, but there are zero shared Zeek UIDs. The DMZ clock is about
  114 ms earlier at the median, with small per-flow variation. States and services agree for all
  4,292 matches, while packet/byte counters differ on 429, consistent with distinct capture
  vantage points rather than copied rows.

- **Connection and firewall lifecycles are source-native.** Of 7,476 ASA TCP/UDP build records,
  7,428 have an exact DMZ Zeek tuple within one second. The paired outcomes are coherent:
  4,171 Zeek `SF` TCP flows end with ASA `TCP FINs`; 2,092 `S0` flows end with `SYN Timeout`;
  78 `RSTO` flows end with `TCP Reset-O`; 51 `RSTR` flows end with `TCP Reset-I`; and 23 `REJ`
  flows end with `TCP Reset-O`. ASA duration is integer-rounded below the Zeek duration, and ASA
  byte counts differ by plausible header/accounting amounts. Three firewall connections are
  unpaired at the visible edge rather than every lifecycle being artificially closed.

- **Zeek transport fields are internally strong.** Across all three sensors, there are no cases
  where IP bytes are smaller than payload bytes. UDP and ICMP overhead is consistently 28 bytes
  per packet; TCP overhead varies with packet mix and options. Every one of the 1,203 connections
  with nonzero `missed_bytes` has a `g`/`G` gap marker in `history`. `S0`, `REJ`, reset, partial,
  and `SF` states have credible packet and history forms.

- **DNS behavior has production-like texture.** The core sensor has 2,987 DNS rows spanning 877
  unique queries, eight qtypes, 224 NXDOMAIN, 15 SERVFAIL, four REFUSED, and both UDP and TCP.
  Answer and TTL array lengths agree in every row. Internal authoritative answers commonly retain
  fixed 300/1,800/7,200/86,400-second TTLs, while repeated external names show decrementing cache
  TTLs and broader RTTs. DNS tunnel-like TXT traffic respects qname/label lengths and is visible
  as a burst rather than being used as authenticity evidence by itself.

- **TLS and certificate evidence is unusually careful.** There are 2,572 SSL rows and 1,096 X.509
  rows across the sensors. TLS 1.3 sessions appropriately lack visible certificate chains, while
  TLS 1.2 full handshakes often carry them and resumed sessions do not. Every observed chain has
  issuer-to-subject continuity; every linked SNI is covered by the leaf SAN; all certificates are
  valid at capture time; repeated fingerprints have identical metadata; and all X.509 file IDs
  resolve. OCSP file IDs, status windows, and observed serials are also coherent.

- **Host network stacks differ by OS.** The Windows workstations use source ports only in the
  modern Windows dynamic range (for example, `10.10.1.31` has 517 TCP/UDP flows with minimum
  49167 and maximum 65530), while Linux clients use the lower Linux range (for example,
  `10.10.1.21` has 427 ephemeral flows from 32800 through 60975). The same split holds across
  servers. This is difficult, concrete environmental texture.

- **DHCP timing is strong.** The 48 core DHCP records cover six stable host/MAC/address mappings.
  Hosts with 3,600-second leases renew near 1,800 seconds, the 7,200-second lease renews near
  3,600 seconds, and 14,400-second leases renew near 7,200 seconds, all with realistic jitter and
  varied request/ACK duration.

- **Protocol companions are coherent without being identical copies.** Every DNS, HTTP, SSL,
  SMTP, and SMB row has a same-sensor Zeek connection and matching tuple. All 173 Snort alerts
  match a sensor connection, and DNS-TLD and HTTP user-agent signatures match the visible query or
  user agent. SMB mappings precede file operations and stay inside connection intervals. A
  128,125,507-byte executable traverses upstream and downstream proxy legs with the same SHA-1 but
  distinct sensor file IDs and timings, as expected.

## Detailed Analysis
The visible network window runs approximately `2024-03-18 12:00–18:00Z`. The sensor mix is
role-sensitive rather than uniform. Core traffic is dominated by DNS (2,997 connection records),
Kerberos (2,272), proxy HTTP (1,678), LDAP (1,162), SMB (414), TLS (363), and syslog (324).
The DMZ has 1,592 external inbound connections from 248 source addresses to the public web host,
1,868 internal-to-external connections dominated by the proxy, and 4,972 internal cross-zone
connections. The database sensor is much smaller and dominated by 334 MySQL connections. That
distribution is plausible for three differently placed sensors and is not penalized for thinness.

External behavior contains both routine and hostile texture. The DMZ records 661 successful and
848 unanswered external-inbound connections, with web traffic concentrated on ports 80/443 and
scanner traffic spread across 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5985, 6379, 8443,
and 9200. Outbound activity is concentrated through `10.10.3.20` and uses 529 distinct external
destinations. HTTP contains persistent connections with transaction depths up to six rather than
forcing every request onto a new socket. TLS uses both 1.2 and 1.3, six RSA/AEAD cipher choices
plus ECDSA-bearing chains, and about one-third resumed sessions. These distributions are
credible.

The strongest negative finding is specific to the modeled Nmap process, not the fact that an
attack is easy to reconstruct. The preceding `-sn` command creates an ICMP sweep; the later
`-sT` command creates a complete five-port matrix. The latter's seven `SF` results are not bare
connects: they contain application-layer client bytes and are labeled as SSH, HTTP, SMB, or SSL.
Even if one allowed customized discovery defaults, those client payloads still contradict
connect-only scan behavior. The 1,244 filtered results then collapse to one identical SYN-only
shape, removing ordinary retry variation. This combination is characteristic of an activity
renderer selecting canned per-port success/failure connection templates.

The proxy issue is similarly based on exact lifecycle facts. The 715 inspected CONNECT records
have sufficient identifiers to bind proxy and Zeek records without relying on coincidental host
and second-level time matching. Child bytes roll up exactly under each tunnel ID, confirming the
relationship. Multi-request tunnels generally fit within the TCP lifetime, but 431 single-child
tunnels do not. This sharp family split suggests separate timing paths for single-child and
multi-child tunnels, with the single-child path adding tunnel/application delay after the
transport duration was finalized.

No equivalent contradictions were found in DNS response structure, TLS certificate validity,
ASA state mapping, IDS tuple matching, DHCP T1 behavior, SMB operation ordering, or eCAR process
lifecycles. Among 2,642 FLOW records whose actor process begins visibly inside the window, none
precedes its process creation, follows its termination, or disagrees on PID. This substantially
raises the baseline realism score but does not neutralize the two network lifecycle failures.

## Synthetic Indicator Summary
| Indicator | Category | Scope | Weight |
|---|---|---:|---:|
| `nmap -sT` sockets contain HTTP/TLS/SMB/SSH client payload | `hard_contradiction` | All seven successful scan sockets, plus partial/reset scan sockets | Very high |
| Proxy tunnel duration exceeds exact `SF` carrier duration | `hard_contradiction` | 431/715 inspected tunnels by >200 ms; 408 by >500 ms | Very high |
| Port scan expands all 254 hosts despite visible discovery result and no `-Pn` | `contract_gap` | 1,270 core scan connections | High |
| Every filtered scan connection is one SYN with no retry | `distribution_texture` | 1,244/1,244 `S0` scan flows | High |
| HTTP file gaps sometimes lack connection missed-byte accounting | `contract_gap` | Five low-volume HTTP file observations | Low |
| Exact 254-by-five scan matrix | `weak_signal` | One scan episode | Low alone |

## Realism Score by Category
- **Field format accuracy:** 9 — Zeek JSON fields, UIDs, states/history, byte accounting, ASA syntax, IDS records, TLS/X.509 chains, and proxy fields are overwhelmingly source-native; the HTTP gap accounting is the main exception.
- **Temporal patterns:** 6 — Broad activity, DHCP renewals, sensor skew, and protocol timing are strong, but 431 proxy tunnels outlive their carrier and the scan lacks retry timing.
- **Cross-source correlation:** 9 — Tuples, outcomes, IDs, hashes, DNS/HTTP/TLS companions, IDS alerts, and firewall states correlate extremely well while independent sensors retain different UIDs and some packet-level differences.
- **Behavioral realism:** 5 — Routine browsing, DNS, TLS, SMB, mail, scanner background, and proxy behavior are convincing, but the directly attributed Nmap activity violates the named command's network behavior at high volume.
- **Environmental consistency:** 9 — Segmentation, server roles, explicit proxy routing, OS-specific ephemeral ports, DHCP lease classes, DNS authorities, external ingress, and sensor visibility are mutually consistent.

## Recommendations
1. Model scan sockets from the invoked tool contract. For `nmap -sT`, emit TCP connect/close
   behavior without HTTP requests, TLS ClientHello, SMB negotiation, or client SSH payload unless
   `-sV`, NSE scripts, or an explicit follow-on client is visible. If every address must be port
   scanned, include `-Pn`; otherwise perform host discovery and restrict port probes to hosts
   considered up.
2. Give filtered TCP scan sockets retry timing and packet history appropriate to the OS TCP stack
   and Nmap timing mode. Preserve adaptive variation rather than emitting one SYN for every
   unanswered target.
3. Make the proxy tunnel interval the owning lifecycle. The client TCP connection must begin
   before CONNECT and end after the last child transaction; derive Zeek duration, proxy
   `tunnel_duration_ms`, and any endpoint FLOW close from that one interval. Add an invariant test
   that every tunnel duration is less than or equal to its exact carrier duration.
4. Reconcile `files.missing_bytes` with the reason for incompleteness. Packet loss should be
   reflected in the associated connection's `missed_bytes` and gap history; a short HTTP body
   should instead be represented explicitly as a Content-Length/body truncation condition.
5. Preserve the strongest existing features: independent sensor UIDs and clock offsets,
   vantage-specific byte differences, OS-specific ephemeral-port ranges, TLS 1.2/1.3 certificate
   visibility, DHCP T1 jitter, ASA teardown semantics, and realistic source-level observation
   gaps.
