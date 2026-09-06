# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 70
**Synthetic-Confidence Score:** 62

## Executive Summary

The network telemetry is substantially production-like: three Zeek viewpoints show coherent but non-identical observations, protocol children remain inside their connection intervals, DNS and TLS distributions are credible, and ASA lifecycle/NAT records correlate well. I nevertheless assess it as synthetic because two TCP DNS connections have source-native combinations that Zeek could not derive from the displayed packet histories, and several long interactive sessions are terminated in a tight cluster immediately before the six-hour cutoff.

## Evidence For Synthetic

- `[hard_contradiction]` In `zeek-core/conn.json`, UID `CGcRbtGJ9RHDmRjED` at `2024-03-18T12:54:37.469642Z` is labeled TCP `conn_state="SF"` while its history is only `DdG`, with one originator packet and one responder packet. UID `CGU0KB8BadJbROjPQO` at `2024-03-18T17:54:54.759093Z` is likewise TCP `SF` with history `Dd`, one packet each way, and `missed_bytes=0`. A fully established and normally closed TCP flow cannot be inferred from one data packet in each direction with no visible SYN/SYN-ACK/FIN history; these records should be partial/midstream states rather than `SF`, or their packet/history fields should contain the handshake and close.
- `[distribution_texture]` The end of the slice has a small but conspicuous lifecycle drain. Two independent long SSH flows end at `17:59:38.427728Z` and `17:59:38.705757Z` in `zeek-dmz/conn.json`; their corresponding ASA connections `1687821` and `1688213` both tear down at `17:59:38`. A long RDP flow in `zeek-core/conn.json` ends at `17:59:42.671753Z`. The ASA log contains no open connection among 6,961 connections built during the slice: all 6,961 have in-file teardown records. The six-hour boundary does not require post-window closes, so this is not a penalty for absent termination; the concern is the opposite—multiple long sessions are visibly forced closed seconds before the boundary and the firewall is left perfectly drained.
- `[weak_signal]` TCP DNS has a sharp quality discontinuity: eight other TCP/53 `SF` connections in `zeek-core/conn.json` use plausible handshake/data/close histories, while the two records above use UDP-like `Dd` histories. The isolated family-specific discontinuity looks more like a construction edge case than ordinary packet loss, especially because one record claims no missed bytes.

## Evidence For Real

- The three Zeek sensors do not simply repeat byte-identical rows. For 942 DNS transactions visible at both core and DMZ, the DMZ timestamps lead core by approximately 110.6–118.1 ms (median 114.5 ms), consistent with independent sensor clocks; Zeek UIDs are sensor-local, and packet/byte fields can differ where one sensor reports loss.
- All inspected `dns.json`, `http.json`, `ssl.json`, `smtp.json`, `smb_mapping.json`, and `smb_files.json` records reference a connection UID present on the same sensor and occur inside that connection's visible interval. HTTP transaction depths are unique and ordered per UID.
- Connection-state texture is credible rather than uniformly successful. Core contains 8,719 `SF`, 1,914 `S0`, 146 `RSTO`, 89 `RSTR`, 30 `REJ`, and smaller `OTH`/`S1`/`S2`/`S3` populations; DMZ has a scan-heavy 2,645 `S0` records alongside 4,966 `SF` and realistic reset/reject tails.
- DNS is varied and operationally plausible. Core includes A, AAAA, PTR, SRV, TXT, NS, MX, and SOA traffic, with 216 NXDOMAINs, 16 SERVFAILs, and six REFUSED responses. Empty NOERROR answers are concentrated in AAAA NODATA responses for IPv4-only internal names, not malformed positive A records. DHCP is visible as renewal-only `REQUEST`/`ACK` activity, which is reasonable for a six-hour slice that begins after lease acquisition.
- TLS version/cipher pairing is internally sound: TLS 1.3 uses AES-GCM or ChaCha20 suites, while TLS 1.2 uses ECDHE suites. ECDSA suites map to EC leaf certificates and RSA suites to RSA leaves. Every referenced certificate FUID exists in both `x509.json` and `files.json`, chains link leaf issuer to CA subject, CA constraints are set, and all checked leaf certificates are valid at handshake time.
- Firewall lifecycle and NAT syntax are coherent. ASA connection IDs are unique, teardown never precedes build, NAT build/teardown pairs surround outbound DMZ flows, and examples near `17:58` align with Zeek tuples and rounded durations. Snort alerts use plausible tuples and signature families for DNS TLD activity, scanning, ICMP, TLS, STUN, and HTTP policy events.
- Traffic is not temporally flat. Fifteen-minute core connection counts range from 266–491 in most bins but rise to 1,899 during a visible burst; DMZ similarly rises to 1,759. Long SSH/RDP durations vary from minutes to hours, while DNS, web, database, reset, and SMB durations occupy service-appropriate ranges.

## Detailed Analysis

### Scope and connection behavior

The visible interval is `2024-03-18 12:00:05Z` through approximately `18:00Z`. `zeek-core/conn.json` has 10,960 rows, `zeek-dmz/conn.json` 7,847, and `zeek-db/conn.json` 434. Core traffic contains a plausible enterprise mix: DNS (2,919 service-labeled rows), Kerberos (2,329), HTTP/proxy (1,457), LDAP (1,163), SMB (424), TLS (345), syslog (276), SSH (65), DHCP (48), SMTP (46), and smaller RDP/DCE-RPC populations. DMZ appropriately shifts toward TLS/HTTP and unaffiliated scan traffic, while the database sensor is dominated by MySQL.

TCP state histories are generally consistent: successful flows commonly use `ShADadfF`, `ShADaDadfF`, and close variants; refused traffic uses `Sr`; origin resets use histories such as `ShADaR`; and incomplete scans commonly use `S` with `S0`. Packet accounting is also credible: no record has payload bytes with zero packets, IP-byte totals cover payload plus headers, and high-volume SMB/HTTP transfers remain below roughly 250 Mb/s. The two TCP DNS `SF` records with `Dd`-family histories are therefore conspicuous exceptions, not a dataset-wide Zeek formatting convention.

### DNS and DHCP

Core has 2,913 DNS rows: 2,119 A, 239 AAAA, 143 PTR, 92 SRV, 303 TXT, plus smaller NS/MX/SOA sets. Response codes and TTLs show useful texture, including NODATA, NXDOMAIN, SERVFAIL, REFUSED, internal 300/1,800/3,600/7,200/86,400-second TTLs, and shorter external TTLs. PTR traffic includes internal names, provider-style external names, and NXDOMAIN results. DNS RTTs range from sub-millisecond to about 2.38 seconds, and every DNS timestamp remains inside its corresponding UDP or TCP connection interval.

The 47 DHCP records show stable MAC/address/hostname ownership and renewal times near half of each 3,600-, 7,200-, or 14,400-second lease with per-client jitter. Seeing only renewal `REQUEST`/`ACK` pairs is compatible with clients whose initial lease acquisition occurred before this slice.

### HTTP, proxy, and file protocols

Core has 1,484 HTTP rows across 1,443 UIDs; DMZ has 1,710 across 1,669 UIDs. Multi-transaction connections have monotonically increasing, nonduplicated `trans_depth` values starting at one. Client-to-proxy CONNECT records are matched by proxy access records with status/action semantics, and proxy-origin legs appear separately on the DMZ side. The final records around `17:59:35Z` preserve this ordering and remain within the connection intervals.

SMB mappings, SMB operations, and file-analysis rows share UIDs and occur in order within the transport lifetime. For example, core UID `C6gWvyN4SpblUaKy6n` maps `\\FILE-SRV-01\Finance`, opens `Procedures\performance-summary-v2.xlsx`, and emits the corresponding SMB file record with matching hosts and transfer direction. Large SMB and proxied HTTP byte counts are supported by packet counts and plausible sub-gigabit rates.

### TLS and certificates

The mix is believable for mixed enterprise software. DMZ has 1,336 TLS 1.3 and 677 TLS 1.2 sessions; core is closer to even at 156 TLS 1.3 and 173 TLS 1.2; the database view contains only 29 TLS 1.2 sessions. Resumption occurs but is not universal. TLS 1.3 sessions lack extractable certificate chains in many cases, while observed TLS 1.2 chains consistently link SSL, files, and X.509 rows. Certificate fingerprints, serials, subjects, issuer chains, validity windows, key types, and cipher authentication types do not contradict one another.

### Cross-source and collection-tail behavior

Core/DMZ copies of the same DNS transaction have stable clock offset but independently generated Zeek identities, which is characteristic of separate monitors. The ASA log also gives a credible firewall view: sequential unique connection IDs, public-address translations for DMZ egress, denials without built-flow lifecycles, and teardown reasons such as SYN timeout, resets, and FINs. The suspicious part is specifically the terminal state: two unrelated SSH sessions close within 0.28 seconds at `17:59:38Z`, the firewall records both in that same second, and a long RDP session closes four seconds later. Combined with zero unclosed ASA builds, this looks like explicit end-of-window drainage rather than ordinary observation cutoff.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Zeek TCP connection metadata | 2 of 10 TCP/53 core flows | `SF` cannot be supported by one packet each way and `Dd`/`DdG` histories with no handshake/close; strongest authenticity defect. |
| `distribution_texture` | Zeek SSH/RDP and ASA lifecycle | 3 long sessions at the final 22 seconds; all 6,961 in-slice ASA builds closed | Tight pre-cutoff termination cluster and perfectly drained firewall state suggest boundary-driven generation. |
| `weak_signal` | Zeek TCP DNS family | Isolated edge case | UDP-like history appears only on the two contradictory TCP DNS successes, indicating a likely construction-path defect. |

## Realism Score by Category

- **Field format accuracy:** 8 — Zeek, ASA, HTTP, SMB, TLS, and X.509 fields are strong overall, but two TCP connection records contain impossible state/history/packet combinations.
- **Temporal patterns:** 7 — Service timings and burstiness are generally credible; the synchronized cutoff-adjacent session closes reduce confidence.
- **Cross-source correlation:** 9 — Protocol UIDs, sensor clock offsets, TLS chains, proxy legs, IDS tuples, and firewall lifecycles correlate without suspicious identity reuse.
- **Behavioral realism:** 8 — Protocol and service distributions fit a mixed enterprise network with browsing, infrastructure, administration, scanning, and transfers.
- **Environmental consistency:** 8 — Core, DMZ, database, proxy, firewall, and IDS viewpoints have differentiated and plausible coverage, aside from the fully drained tail.

## Recommendations

- If this were synthetic, derive TCP `conn_state`, history, and packet counts from one coherent packet-lifecycle model. For the two TCP DNS examples, either emit a handshake/close-bearing history with sufficient packet counts or classify the partial observation as an appropriate midstream/incomplete state.
- If this were synthetic, stop finalizing active network state merely because the collection window ends. Preserve sessions active at cutoff and omit their post-window teardown rows; do not pull SSH, RDP, or firewall teardown timestamps back into the final seconds of the slice.
- If this were synthetic, add a regression check that rejects TCP `SF` rows lacking enough visible evidence for establishment and normal closure, while permitting legitimate partial-capture states and sensor packet loss.
