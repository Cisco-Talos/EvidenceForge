# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 64  
**Synthetic-Confidence Score:** 58

## Executive Summary

The network corpus is technically strong: Zeek records are source-native in shape, multi-sensor observations exhibit coherent clock offsets, and DNS, HTTP, TLS, X.509, file, and connection identities reconcile without visible causal contradictions. I nevertheless assess it as synthetic with moderate confidence because the ICMP payload-size distribution and SMB connection granularity look generated at family scale, while the complete absence of NTP is difficult to reconcile with the otherwise broad internal collection profile.

## Evidence For Synthetic

- **P1 — [distribution_texture] ICMP payload sizing has implausibly high entropy within individual hosts.** After collapsing duplicate multi-sensor observations by tuple/time, 172 successful echo flows use 53 request sizes. `DC-01` (`10.10.2.10`) alone uses 19 sizes and `DC-02` (`10.10.2.11`) uses 17 during a six-hour window. Concrete `zeek-core/conn.json` examples include 753-byte request/reply payloads at `2024-03-18T12:06:41.962413Z` (`uid=C6Nwuo7HIiEx3dr4n`), 1,408 bytes at `12:13:44.311816Z` (`uid=CSEgxdJ3XUBloyRdEo`), and 963 bytes at `12:36:21.348284Z` (`uid=CU1a44ks84k91v3RFG`), all one request and one equal-sized reply. This resembles per-event randomization more than stable payload defaults belonging to a host, monitoring product, or diagnostic session.
- **P2 — [distribution_texture] SMB file activity is over-fragmented into short, mostly single-file transports.** `zeek-core/smb_mapping.json` contains 216 mappings on 216 distinct UIDs. Of 191 UIDs represented in `smb_files.json`, 158 have exactly two records, generally one `SMB::FILE_OPEN` plus one read/write, and 31 have only one record; only two UIDs have more than two records. Real workstation SMB behavior more commonly reuses authenticated transports and tree connections for a longer, messier series of opens and metadata/file operations.
- **P2 — [environment_or_collection_plausibility] No NTP traffic is visible anywhere in the connection corpus.** Across 19,241 sensor-level `conn.json` rows spanning core, database, and DMZ sensors, there are zero UDP/123 records, despite visible DNS, DHCP, Kerberos, LDAP, syslog, ICMP, update, and monitoring traffic from a mixed Windows/Linux estate. A six-hour slice can miss some periodic services, but this absence is conspicuous because DHCP clients renew repeatedly and the collection otherwise records broad low-level infrastructure traffic.
- **P3 — [weak_signal] TLS negotiation texture is narrower than the rest of the environment.** Across 2,371 `ssl.json` rows, only TLS 1.2 and TLS 1.3 appear, drawn from a small modern cipher palette; all logged sessions are established. This is plausible for a modern, policy-controlled estate and did not drive the verdict by itself, but the uniform success and limited legacy/edge-case texture are cleaner than the connection-state diversity elsewhere.
- **P0:** No hard contradiction, impossible visible ordering, invalid TLS key/cipher pairing, or generator identity leak was found in the sampled network sources.

## Evidence For Real

- The three sensors show stable, directionally consistent clock offsets on shared flows rather than identical timestamps: for 3,987 core/DMZ connection matches, DMZ timestamps lead core by approximately 111–118 ms (median 114 ms); for 131 core/database matches, database timestamps trail core by approximately 55–74 ms (median 66 ms). That is credible independent-sensor clock behavior.
- Connection texture is varied and service-aware. Core states include 8,719 `SF`, 1,914 `S0`, 146 `RSTO`, 89 `RSTR`, 30 `REJ`, 28 `OTH`, and smaller `S1`/`S2`/`S3` populations. Durations range from millisecond DNS/Kerberos exchanges through multi-minute IMAPS and multi-hour SSH/RDP sessions.
- Cross-source identity and timing held up under direct checks. Every DNS, HTTP, SSL, SMTP, SMB-file, and SMB-mapping row had a matching same-sensor `conn.json` UID and tuple; none occurred outside its connection interval. Every `files.json` connection UID also resolved and remained inside the parent interval.
- DNS cache behavior is unusually convincing. For `api.snapcraft.io` from `10.10.3.20`, an A response at `2024-03-18T12:24:53.958804Z` has TTL 1,734; the response at `12:40:20.725793Z`, roughly 927 seconds later, has TTL 808—within rounding of the expected cached decrement. After expiry, the TTL refreshes to 1,747 at `12:54:41.586752Z`. A/AAAA/PTR/SRV/TXT/MX/NS/SOA coverage, NODATA AAAA responses, suffix-search NXDOMAINs, and mixed recursive latency are similarly plausible.
- TLS and certificate contracts are coherent. All 558 sampled sessions carrying certificate chains resolved every FUID; leaf issuer names matched the next chain subject, SHA-1 values matched corresponding `files.json` records, SNI matched leaf CN/SAN, certificates were valid at observation time, and TLS 1.2 authentication ciphers agreed with RSA/ECDSA key type.
- Explicit proxy behavior reconciles across network legs. Client-to-proxy HTTP uses absolute URIs or CONNECT authorities, while proxy-to-origin records use origin-form URIs and DNS answers matching the destination IP. The same downloaded executable is represented by distinct sensor-local FUIDs but stable size and SHA-1—for example the 95,385,680-byte Citrix download has SHA-1 `3c39e5a0b5ad7fb174b1c9a07c6722ef9f7ac384` on both proxy-facing and origin-facing observations.
- Ephemeral source-port ranges track apparent operating system families. Windows systems visible in endpoint FLOW rows use ports at or above 49,152 (for example, all 711 outbound `DC-01` flows), while Linux systems use the expected lower range beginning near 32,768 (for example, `APP-INT-01` ranges from 32,780 to 60,937).
- HTTP loss accounting is credible. Three connections had summed HTTP response-body lengths slightly above observed `resp_bytes`, but each deficit was bounded by `missed_bytes` and accompanied by Zeek gap history (`g`/`G`), so these are not contradictions.

## Detailed Analysis

### Scope and collection window

The network evidence consists of three Zeek sensor families: `zeek-core`, `zeek-db`, and `zeek-dmz`. Their connection logs contain 10,960, 434, and 7,847 rows respectively. The observed window runs from `2024-03-18T12:00:05.580965Z` through `17:59:52.537563Z`, approximately six hours. Protocol logs include DNS, DHCP, HTTP, TLS/SSL, X.509, OCSP, SMTP, SMB mappings/files, generic files, and PE metadata.

Hourly connection counts are bursty rather than flat. Core counts by hour are 1,358, 3,139, 1,502, 1,599, 1,855, and 1,507; DMZ counts are 1,139, 2,618, 992, 962, 1,053, and 1,083. The second-hour spike is reflected in both sensors, which is consistent with shared activity crossing sensor boundaries rather than unrelated per-file smoothing.

### Connection and multi-sensor behavior

Connection-state distributions are credible overall. The DMZ contains 4,966 `SF`, 2,645 `S0`, 91 `RSTO`, 81 `RSTR`, 33 `REJ`, plus smaller partial/other states. Failed external probes target a realistic range including 22, 23, 25, 80, 135, 139, 143, 445, 465, 587, 2,323, 3,389, 5,985, 8,080, and 8,443. Successful traffic is dominated by TLS, proxy HTTP, DNS, and expected internal services.

Shared-flow comparison was a strong authenticity signal. Matching on the five-tuple, all 3,987 core/DMZ overlaps had the same state, with duration differences bounded to about 1.9 ms. Sensor clocks had stable offsets but independent UIDs. Core/database and database/DMZ overlaps behaved similarly. Protocol-log timestamps varied more than connection start times, as expected when protocol milestones are observed at different points along a path.

### DNS

The combined DNS set contains 3,891 sensor-level records. Core alone includes 1,917 successful A, 239 successful AAAA, 125 successful PTR, 92 successful SRV, 285 successful TXT, and realistic NXDOMAIN/SERVFAIL/REFUSED minorities. Of 327 successful AAAA queries across sensors, 128 return IPv6 answers and 199 are authoritative/recursive NODATA responses, which is consistent with dual-stack-capable clients querying names that lack AAAA records.

UID/tuple relationships to `conn.json` were exact, and TLS destinations matched a prior same-client A answer whenever an applicable recent answer was present. Apparent A/AAAA mismatches disappeared when query type was accounted for. Cache TTLs decrement and refresh coherently, while internal authoritative records use stable values such as 300 seconds for DC A records and 3,600/7,200 seconds for selected PTR/NS data.

### HTTP, proxying, files, and PE metadata

HTTP is modern-proxy dominated: 2,510 successful CONNECTs, with denied/auth/error outcomes including 78 status 403, 59 status 407, 26 status 503, 15 status 502, and 13 status 504. Cleartext GET/POST traffic includes update downloads, OCSP, internal web activity, and proxy-accessible resources. Absolute-form proxy requests and origin-form egress requests are used in the appropriate legs.

Files reconcile with HTTP bodies and parent connections. Large downloads have plausible packet accounting and ACK ratios. PE metadata initially appears repetitive, but the eight sensor records reduce to three content hashes observed at multiple points; identical compile timestamps and section layouts belong to identical SHA-1 content, while distinct hashes have distinct PE profiles. That is correct multi-sensor behavior, not duplication leakage.

The weaker area is SMB session texture. Although the example `uid=CYqPOnj5AfjaZyIflLn` coherently maps `\\FILE-SRV-01\\Finance` and reads five named Q1 documents inside a two-second, 8.7 MB flow, nearly all other file-active UIDs carry only one open/read or open/write pair. The family needs more long-lived transport/tree reuse and multi-file operation diversity to look like ordinary workstation SMB rather than isolated rendered actions.

### TLS, X.509, and OCSP

TLS versions and ciphers are internally consistent and current. Resumption appears on 813 sessions and correctly omits certificate chains; full handshakes carry coherent chain/file references where the protocol permits certificate visibility. No SNI-to-certificate mismatch, validity-window violation, chain issuer mismatch, cipher/key mismatch, or X.509/file hash mismatch was found.

The narrow protocol-version and cipher palette remains a weak texture concern, not a correctness defect. A uniformly modern fleet or policy-controlled sensor population can explain it, especially in a short collection window.

### Infrastructure and ICMP texture

DHCP renewal behavior is credible: 47 records contain REQUEST/ACK sequences, with 3,600-, 7,200-, and 14,400-second leases and renewal intervals clustered around T1 with jitter. For example, `10.10.1.21` renews its 3,600-second lease at roughly 1,756–1,989-second intervals rather than an exact fixed cadence.

ICMP is less convincing. All 279 deduplicated failed echo attempts use a 64-byte request, while successful one-request/one-reply observations fan out across 53 payload sizes, including many unusual singletons. Repeated diagnostics from the same DC vary among standard and arbitrary sizes without visible session grouping. Combined with zero visible NTP despite broad infrastructure capture, this is the principal reason the corpus does not clear a production-real verdict.

## Synthetic Indicator Summary

| Priority | Category | Affected source family | Scope | Score impact |
|---|---|---|---|---|
| P1 | `distribution_texture` | Zeek conn / ICMP | Dataset-wide; strongest on DCs and servers | High — per-event payload randomization is a recognizable generator-like pattern. |
| P2 | `distribution_texture` | Zeek SMB mapping/files/conn | Repeated across almost all file-active SMB UIDs | Medium-high — unrealistic connection granularity weakens session realism. |
| P2 | `environment_or_collection_plausibility` | Zeek conn / infrastructure traffic | Dataset-wide absence | Medium — zero NTP conflicts with otherwise broad infrastructure visibility, though a collection filter remains possible. |
| P3 | `weak_signal` | Zeek SSL | Broad but plausible | Low — only modern versions/ciphers and established sessions make TLS cleaner than expected, but do not establish synthetic origin. |
| P0 | `hard_contradiction` | All reviewed network families | None observed | None — no impossible ordering or source-native contradiction was confirmed. |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Zeek JSON fields, UIDs/FUIDs, connection histories, DNS response shapes, TLS chains, and file metadata are consistently source-native.
- **Temporal patterns:** 8/10 — DNS caching, DHCP T1 jitter, flow durations, sensor clock offsets, and hourly bursts are strong; ICMP family texture is the main exception.
- **Cross-source correlation:** 10/10 — sampled protocol/file/certificate relationships reconcile without impossible ordering or tuple/identity contradictions.
- **Behavioral realism:** 6/10 — proxy, browsing, scanning, mail, and downloads are plausible, but ICMP sizing and SMB transport fragmentation look modeled rather than organic.
- **Environmental consistency:** 7/10 — segmentation, service placement, OS-specific source ports, and infrastructure protocols cohere; absent NTP and uniformly clean TLS reduce confidence.

## Recommendations

- If this were synthetic, assign ICMP payload profiles to the originating tool and host, then keep size stable within a probe/session. Use common platform defaults and a small long tail tied to explicit MTU/path-MTU or monitoring behavior instead of independently varying successful echo sizes.
- If this were synthetic, make SMB clients reuse durable TCP/session/tree state across ordinary file operations. Generate realistic metadata chatter and several opens/reads/writes over a shared connection, with new connections driven by timeout, credential, server, or failure boundaries rather than by each file action.
- If this were synthetic, add source-profile-controlled NTP/chrony/w32time traffic, or make the collection policy visibly consistent with filtering UDP/123. Periodic timing should vary by host role and synchronization state.
- If this were synthetic, broaden TLS edge texture conservatively through policy- and software-bound handshake failures, occasional legacy TLS 1.2 suites, and source-specific cipher preferences. Do not add obsolete versions indiscriminately; the current modern baseline is otherwise coherent.
