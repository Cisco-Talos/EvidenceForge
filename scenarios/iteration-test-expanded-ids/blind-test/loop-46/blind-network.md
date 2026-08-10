# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 66

## Executive Summary

The network corpus is substantially more realistic than a simple generated dataset: connection-state texture, DNS variety, protocol timing, proxy tunneling, firewall lifecycle records, and TLS identities mostly cohere. I nevertheless assess it as synthetic because the Zeek TLS/x509 contract is broken at meaningful scale and short ICMP echo bursts repeatedly change payload size packet by packet, a generator-like texture that is difficult to explain as ordinary host behavior.

## Evidence For Synthetic

- `[contract_gap]` In 47 established, non-resumed TLS sessions, `ssl.json` explicitly names certificate file IDs that do not exist in the corresponding zone's `x509.json`: 5 affected TLS rows/10 missing FUIDs in `zeek-core`, and 42 rows/60 missing FUIDs in `zeek-dmz`. For example, `zeek-core/ssl.json` at `ts=1710766359.548837` (`2024-03-18T12:52:39Z`), UID `CyTDfKjWiJHnTgmfz0i`, has `resumed=false`, `established=true`, and `cert_chain_fuids=["Fl2tmJLA9GIFURSxTpG","FLteRSceMByeHacFn"]`, but neither ID appears in `zeek-core/x509.json`. Likewise, DMZ UID `Cbbqx2EsrxNo6DNjEC` at `ts=1710763549.646827` names `Fm7snGliotQnletJWO`, absent from `zeek-dmz/x509.json`.
- `[distribution_texture]` ICMP echo bursts repeatedly randomize payload size within what looks like one ping invocation. Of 15 zone-visible same-tuple bursts with at least two echoes no more than one second apart, 13 vary payload size. In `zeek-core/conn.json`, `10.10.2.20 -> 10.10.2.27` sends three replies in 65 ms at `ts=1710765972.444073`, `.488887`, and `.509538` (UIDs `C0QkQhHmj9QFnrpYYA`, `CAKoNBxRSXatiuwpBn`, `CsOvNF2PreUJY90IqP`) with `orig_bytes/resp_bytes` of `1287/1287`, `256/256`, and `56/56`. A separate two-packet burst from `10.10.2.30 -> 10.10.2.20` changes from 56 to 120 bytes in 53 ms (`CbrKSSzCgUkS6AGuXR` then `C1HVI1gDa3bKrSy2uo`). Normal ping tools generally keep payload length stable within an invocation.
- `[weak_signal]` DHCP renewal series are extremely smooth per client. For `10.10.1.22`, 13 REQUEST/ACK records with a 3600-second lease recur at approximately 1788-second intervals, beginning at `1710763303.172328` and `1710765091.054763`; other clients have similarly stable host-specific periods. Timer-driven regularity is expected, so this only modestly affects the score, but the persistent per-client offsets from the displayed half-lease interval look modeled.

## Evidence For Real

- Zeek connection-state distributions have credible contrast by sensor: core has 5,908 `SF`, 73 `RSTO`, 55 `RSTR`, 23 `S0`, and small tails of `OTH/S3/REJ/S2/S1`; DMZ has 3,886 `SF` and 1,162 `S0`, consistent with an internet-exposed segment receiving unsolicited scans.
- DNS contains a believable enterprise mix rather than only connection prerequisites: A, AAAA, PTR, SRV, MX, NS, SOA, TXT; NOERROR, NXDOMAIN, SERVFAIL, and REFUSED; suffix-search artifacts such as `wpad.local`, `isatap.meridianhcs.local`, and `ctldl.windowsupdate.com.meridianhcs.local`; and authoritative internal answers alongside recursive external answers.
- UID and timing semantics are generally sound. Core UID `CxJwiErtmAd3ay4QeqT` has a UDP/53 `conn.json` row at `ts=1710763283.604854`, duration `2.019006`, bytes `62/82`, and a DNS row at the same timestamp with `rtt=2.019`, query `outlook.office365.com`, two A answers, and matched TTLs. Across DNS, HTTP, SSL, and SMTP, no child record timestamp fell before its matching connection or after the connection interval.
- TLS content is plausible: TLS 1.2/1.3 dominate, cipher suites are modern, session resumption exists, all checked SNI-to-leaf-SAN relationships match, and no logged certificate was outside its validity period. Core UID `C3pl2DNz8A9yGWU1EW` joins an `SF` connection to SNI `APP-INT-01.meridianhcs.local` and a leaf certificate FUID `FApLXKkCsnMuWPgZdP` whose SANs include `app-int-01.meridianhcs.local`.
- Proxy and firewall records reflect real operational distinctions: CONNECT control-message bytes are separated from tunnel byte counts, SSL inspection creates associated HTTPS request rows, and ASA build/teardown records include NAT translations, connection IDs, rounded durations, byte counts, and FIN/reset causes.

## Detailed Analysis

### Connection states, services, and exposure

The six-hour window runs from approximately `2024-03-18T12:00:01Z` through `17:59:55Z`. Core has 6,106 connections, led by DNS (2,203), Kerberos (1,013), HTTP (885), SMB (879), LDAP (615), SSH (102), TLS (75), DHCP (69), and SMTP (67). DMZ has 5,279 connections, led by TLS (1,759), HTTP (1,083), DNS (758), MySQL (325), and SSH (50). This is a plausible split: directory/authentication activity concentrates on the core sensor, while encrypted egress, public web traffic, and scanning dominate the DMZ.

The 1,162 DMZ `S0` records are not uniformly scattered noise. They concentrate on commonly scanned ports including 23 (196), 25 (105), 445 (90), 22 (79), 3389 (77), 2323 (62), and 587 (61), while successful web traffic remains prevalent. There are 296 distinct external origin IPs, with a long tail plus several high-volume scanners. This is convincing internet-background texture rather than a defect.

Transport accounting is internally coherent. TCP `SF` records examined have bidirectional packets and payload, UDP DNS uses one query and one response with 28 bytes of IP+UDP overhead per direction, and no overlapping reuse of an identical TCP five-tuple was found within a sensor. Cross-zone copies of traversing traffic preserve payload/duration while allowing small sensor-specific timestamp offsets, which is reasonable.

### DNS and DHCP

Core DNS has 2,194 records and DMZ DNS has 751. Core response mix includes 1,157 A/NOERROR, 304 TXT/NOERROR, 283 AAAA/NOERROR, 188 A/NXDOMAIN, 151 PTR/NOERROR, and 65 SRV/NOERROR, plus low-volume errors and less common RR types. NXDOMAIN records do not carry impossible nonempty answer arrays. PTR answers map private addresses to internal names, while successful AAAA records contain IPv6 answers. Internal `*.meridianhcs.local` records are authoritative (`AA=true`), whereas external recursive answers are not.

DNS/connection contracts are especially strong: every DNS UID exists in its zone's connection log, DNS timestamps fall inside the associated UDP interval, and DNS RTTs agree with connection durations. This completeness is treated as neutral-to-positive engineering quality, not as a synthetic tell.

DHCP records map consistently to UDP 68->67 connection UIDs and preserve client IP, server, MAC, host name, lease, and transaction duration. For example, DHCP UID `C79fMArsCjistyqhC` has `ts=1710763303.172328`, host `WS-OHADDAD-01`, address `10.10.1.22`, REQUEST/ACK, and duration `0.319968`; its connection begins at `1710763303.169328` and lasts `0.322968`. The renewal-only view is not penalized: initial acquisition may predate the window. The only reservation is the exceptionally smooth, client-specific renewal cadence noted above.

### HTTP, proxy, and firewall behavior

HTTP method/status diversity is credible. Core includes CONNECT 200/403/407/502/503/504 plus GET/POST with 200, 206, 301, 302, 304, and 403. DMZ adds inbound 404s and a broader mix of user agents including Chrome, Edge, Firefox, Wget, curl, Python requests, Microsoft CryptoAPI, Java, Go, VPN clients, and update agents.

The explicit proxy records preserve useful source-native distinctions. At `18/Mar/2024:12:01:23 +0000`, user `MERIDIANHCS\marcus.chen` has a CONNECT to `outlook.office365.com:443` with `cs_bytes=392`, `sc_bytes=185`, `proxy_action=tunnel-setup`, `ssl_bump=peek`, and separate tunnel counts `8316/70031`; a corresponding inspected GET carries those request/response sizes. ASA records independently show build and teardown lifecycles and NAT only for the appropriate outbound paths. I found no concrete impossible ordering in these layers.

### TLS and certificate evidence

TLS negotiation itself looks strong. Core shows 113 TLS rows (96 full and 17 resumed); DMZ shows 1,655 (1,136 full and 519 resumed). TLS 1.2 and 1.3 use plausible AES-GCM, ChaCha20-Poly1305, and a small CBC tail. Logged leaf certificates match SNI, contain plausible SANs and issuer chains, and are valid during the observation window.

The decisive defect is referential integrity. A Zeek `ssl.log` record that emits `cert_chain_fuids` is explicitly linking to certificate records. Yet 47 full established handshakes have dangling references. This is not merely absence of an optional log family: the certificate identity is present in the SSL row, but its referenced object is missing from the same observation zone. Independent source-level dropping appears to have orphaned a lifecycle group, which is a concrete contract gap.

### ICMP texture

Individual echo request/reply accounting is plausible: request and response payload sizes match and each direction has one packet. The sequence-level behavior is not. Most detected rapid same-tuple echo bursts change payload size on every packet, sometimes by an order of magnitude. The `1287 -> 256 -> 56` byte series in 65 ms and `56 -> 120` series in 53 ms resemble independent random draws per event rather than a stable command invocation. This repeated pattern appears on internal and external-origin traffic and is the strongest distributional clue.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `contract_gap` | Zeek SSL/x509 | 47 TLS rows; 70 dangling certificate FUID references across core and DMZ | High: explicit source-native references fail to resolve for full established handshakes |
| `distribution_texture` | Zeek ICMP connection telemetry | 13 of 15 zone-visible rapid multi-echo bursts vary payload size | High: repeated per-packet randomization is unlike normal ping invocation behavior |
| `weak_signal` | Zeek DHCP | Repeated renewal series for multiple clients | Low: cadence is unusually smooth, but timer-driven regularity is inherently plausible |

## Realism Score by Category

- **Field format accuracy:** 8/10 — Zeek, ASA, proxy, and IDS fields are convincing, but dangling certificate FUIDs break a core Zeek reference contract.
- **Temporal patterns:** 7/10 — Protocol events remain within connection intervals and state timing is credible; ICMP burst construction and very smooth DHCP cadence reduce realism.
- **Cross-source correlation:** 7/10 — Network/protocol/firewall/proxy relationships are strong, but SSL-to-x509 lifecycle grouping is incomplete despite explicit references.
- **Behavioral realism:** 7/10 — Service mix, web clients, scanning, and enterprise DNS look lived-in; rapid pings with changing payload sizes do not.
- **Environmental consistency:** 8/10 — Core-versus-DMZ roles, public exposure, directory services, proxying, and mail/web infrastructure are mutually plausible.

## Recommendations

- If this were synthetic, enforce observation decisions at the TLS lifecycle-group level: when an `ssl.json` row retains `cert_chain_fuids`, retain the corresponding `x509.json` objects in that sensor zone; otherwise omit the references coherently.
- Generate ICMP as multi-packet command/session bundles with a stable payload length, interval, identifier, and sequence progression for each invocation. Vary sizes between invocations or for explicitly modeled path-MTU tests, not independently for every echo.
- For DHCP renewal texture, derive T1 from lease/server options and introduce realistic scheduler/network delay around each newly granted T1 while avoiding a perfectly persistent host-specific offset across the whole window.
