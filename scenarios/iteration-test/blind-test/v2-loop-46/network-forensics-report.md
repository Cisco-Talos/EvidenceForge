# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 68

## Executive Summary

The network telemetry is technically sophisticated and unusually strong in flow-state, protocol,
certificate, and multi-sensor consistency. I nevertheless assess it as synthetic because the Zeek
SMB namespace contains a repeated future-year and invented Group Policy path vocabulary relative
to the 2024 capture, while every inspected Zeek stream is perfectly ordered by event start time even
in the presence of multi-hour connections—two broad artifacts that are difficult to reconcile with
unaltered production Zeek output.

## Evidence For Synthetic

- `[environment_or_collection_plausibility]` The six-hour capture runs from
  2024-03-18 12:00:11Z through 17:59:58Z, yet 37 of 203 SMB `FILE_OPEN` records contain year
  directories later than 2024: fifteen each for 2025 and 2026, and seven for 2027. Examples include
  `Team\\2026\\action-items-draft.pdf` at 12:04:53.483562Z,
  `User\\2025\\startup-draft.pol` at 12:13:55.171449Z, and
  `Operations\\2027\\project-plan.xlsx` at 12:54:22.657806Z in
  `zeek-core/smb_files.json`. A few future-planning folders would be explainable; a broad,
  near-balanced 2023–2027 year pool across routine accesses is a generator-like vocabulary pattern.
- `[schema_or_format]` Nineteen of those future-dated opens occur on the domain controllers'
  `SYSVOL` or `NETLOGON` shares. More generally, the 79 DC-share opens repeatedly use invented
  combinations such as `User\\2025\\logon.pol`, `Machine\\2025\\startup-v2.xml`,
  `Policies\\2027\\groups-v2.pol`, and `Scripts\\groups.xml`. These do not resemble normal GPO
  storage paths beneath domain and policy-GUID directories, and `.pol` files are given descriptive
  names instead of the conventional `Registry.pol` placement. This is a source-visible SMB namespace
  defect, not merely an absent-log complaint.
- `[distribution_texture]` All records in every inspected Zeek stream are strictly ascending by
  their `ts` field: zero adjacent timestamp inversions in all three `conn.json` files (11,340 core,
  431 database, and 8,534 DMZ records), as well as zero inversions in each DNS, HTTP, SSL, files,
  X.509, and OCSP stream. That is especially conspicuous in `conn.json`, where `ts` is connection
  start time but records ordinarily become loggable on termination or timeout. For example,
  `zeek-core/conn.json` contains an SSH connection starting at 13:39:59.190791Z with duration
  15,037.568321 seconds, ending around 17:50:36.759112Z, yet the file remains globally sorted by
  start time rather than exhibiting the inversions expected from intermixed short and long flow
  closure. A downstream export could sort each file, so this is not a hard contradiction, but the
  dataset-wide perfection materially raises synthetic likelihood.
- `[weak_signal]` The HTTP vocabulary is broader than a simple mockup but still pool-like. Across
  the core and DMZ sensors, HTTP is entirely version `1.1`, and high-volume user-agent strings recur
  in fixed full-version forms (for example Firefox 121 on Ubuntu appears 346 times in core and 350
  times in DMZ). An explicit proxy and a narrow six-hour window can explain much of this, so it is
  only supporting evidence.

## Evidence For Real

- Connection-state and packet-history texture is excellent. Core telemetry contains 9,065 `SF`,
  1,929 `S0`, 139 `RSTO`, 85 `RSTR`, 41 `REJ`, and smaller `OTH`/`S1`/`S2`/`S3` populations, with
  histories appropriate to each state (`S` for TCP `S0`, `Sr` for `REJ`, `ShADaR` variants for
  `RSTO`, and many retransmission/partial-close variants for `SF`). I found no TCP `S0` record with
  responder traffic and no successful TCP flow lacking responder packets.
- The three sensors do not reuse Zeek UIDs. For 4,322 tuple-matched core/DMZ observations, UIDs are
  independent, the median timestamp offset is about -114 ms, state agrees in all 4,322 pairs, and
  byte/packet differences occur in a minority of pairs as expected from different capture points.
  Core/database and database/DMZ comparisons similarly show stable sensor offsets of about +64 ms
  and -178 ms. This is much more convincing than simply cloning records between sensors.
- Protocol-to-connection correlation is coherent. Every DNS, HTTP, and SSL record in each sensor has
  a matching `conn.json` UID and exact 4-tuple; no child protocol timestamp precedes its matching
  connection start. All 701 core, 29 database, and 1,547 DMZ `files.json` connection references
  resolve to a local connection record.
- DNS has credible breadth: A, AAAA, PTR, SRV, TXT, MX, NS, and SOA records occur in the core view,
  with NOERROR, NXDOMAIN, SERVFAIL, and REFUSED outcomes. Address-family answers match their query
  types. The suspicious high-entropy TXT traffic from 10.10.2.30 has variable labels, responses,
  RTTs, recursive-server selection, failures, and one-second TTLs rather than a single repeated
  template.
- TLS semantics are internally strong. TLS 1.2 ciphers are not assigned to TLS 1.3 sessions or vice
  versa; SNI matches leaf SANs in every chain-bearing session checked; all certificates are valid at
  observation time; repeated fingerprints retain stable serial, subject, issuer, validity, and SAN
  data. Certificate-chain FUIDs resolve completely to X.509 records, with realistic resumed-session
  omission of chains and a varied issuer/key mix on the DMZ sensor.
- DHCP timing is plausible rather than mechanically uniform. Six clients use 3,600-, 7,200-, or
  14,400-second leases, and renewal intervals jitter around the expected half-lease points rather
  than landing on exact fixed boundaries. External scan traffic is also varied in source, target
  port, timing, and outcome rather than appearing as a single evenly spaced sweep.
- Endpoint/network FLOW evidence supports the Zeek view. Of 24,863 eCAR FLOW records inspected,
  24,102 matched a Zeek tuple within ten seconds using a conservative nearest-match procedure;
  failures align predominantly with `S0`, `RSTO`, `RSTR`, and `REJ`, while successful/unspecified
  outcomes align predominantly with `SF`. Host directionality also places known server IPs on the
  correct side of inbound and outbound flows.

## Detailed Analysis

### Scope and traffic shape

The capture is a six-hour Monday slice. The core sensor has 11,340 connections, led by DNS (2,977),
Kerberos (2,325), HTTP (1,753), LDAP (1,150), SMB (428), TLS (342), syslog (250), SSH (57), DHCP
(48), SMTP (46), and RDP (13). The DMZ sensor has 8,534 connections, with 2,453 TLS and 2,009 HTTP
service identifications plus substantial failed inbound scanning. The database sensor is narrower at
431 flows, dominated by 276 MySQL sessions. Those source volumes fit the apparent sensor roles.

The DMZ `S0` population is explainable by internet background traffic rather than a blanket failure
rate: repeated sources probe service-specific port families, while successful external HTTPS clients
show bursty sessions and stable per-client TLS capabilities. For example, 45.33.74.51 generated 162
inbound observations over roughly 5.8 hours, mainly to 445, 3389, 135, 139, and 5985, with 151 `S0`
and 11 answered flows. By contrast, 185.70.41.45 produced 410 mostly successful web connections,
355 of them `SF`. Inter-arrival times are nonuniform in both cases.

### DNS and application protocols

Core DNS contains 2,964 records and 817 unique names. Query composition is not artificially limited:
2,148 A, 263 AAAA, 144 PTR, 96 SRV, 292 TXT, plus smaller MX/NS/SOA sets. There are 210 NXDOMAINs,
13 SERVFAILs, and three REFUSED responses. DNS records begin 1–63 ms after their associated
connection starts; tuples match exactly, answer and TTL cardinalities agree, and A/AAAA answer types
are valid.

HTTP shows proxy-aware behavior, including CONNECT tunnels, authentication failures, denials, and
multiple upstream-failure reason phrases. It also includes persistent HTTP/1.1 transactions with
incrementing `trans_depth`, response FUIDs, referrers, and MIME types. The complete lack of HTTP
version diversity and heavily reused full-version user agents is somewhat curated-looking, but an
explicit proxy and this short capture make it insufficient on its own.

### TLS, certificates, and OCSP

The core sensor contains 172 TLS 1.3 and 155 TLS 1.2 sessions; DMZ has 1,565 TLS 1.3 and 759 TLS 1.2.
Cipher/version pairings are valid. The DMZ leaf set spans DigiCert, GlobalSign, Let's Encrypt,
Amazon, Microsoft, Google, Sectigo, and Cloudflare issuers and includes RSA and ECDSA keys. All 1,151
certificate-chain references across the three sensors resolve, while resumed sessions commonly omit
chains. OCSP records use matching serials and credible `thisUpdate`/`nextUpdate` windows. This is one
of the dataset's strongest areas.

### SMB and file-transfer semantics

SMB lifecycle ordering is coherent: all 375 core `smb_files.json` rows reference mapped UIDs and
connections, no file operation precedes its mapping, and repeated file identities generally preserve
size and SHA-256 unless a visible write changes the object. Packet and byte totals are compatible
with the represented transfer sizes.

The weakness is the namespace content. Future years are distributed nearly like selections from a
year pool rather than tied to a limited planning use case, and they contaminate both ordinary shares
and active domain-policy shares. At 14:07:14.792153Z, for example, DC-01 reads
`User\\2027\\startup-final.ps1` from `\\DC-02\\NETLOGON`; other DC-to-DC accesses use similarly
invented year/name/extension combinations. The breadth and repetition of this issue make it more
diagnostic than a single anomalous filename.

### Temporal and cross-sensor behavior

Per-event timing is convincing. DNS follows flow open; HTTP and TLS handshakes occur within plausible
subsecond-to-few-second offsets; mapped SMB operations follow TCP start; different sensor views have
small stable clock offsets and slightly different duration/history/packet observations. I found no
visible dependent event whose matching initiating network event occurs later.

At the file-stream level, however, every source is perfectly sorted on `ts`. This erases the natural
write-order texture produced when short connections finish before earlier long-running SSH sessions.
Because a batch export could intentionally sort records, I treat this as a strong distribution and
collection artifact rather than impossible causality.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `environment_or_collection_plausibility` | Zeek SMB/files | Repeated: 37/203 opens use 2025–2027 paths during a 2024 capture | Broad future-year vocabulary resembles generation-time data leakage |
| `schema_or_format` | Zeek SMB on SYSVOL/NETLOGON | Repeated across 79 DC-share opens | Invented GPO path/name/extension combinations do not resemble normal policy storage |
| `distribution_texture` | All Zeek streams, especially conn | Dataset-wide | Perfect `ts` ordering suppresses expected long/short connection closure inversions |
| `weak_signal` | Zeek HTTP | Repeated | HTTP/1.1-only and fixed full-version user-agent pool looks curated but remains explainable |

## Realism Score by Category

- **Field format accuracy:** 8/10 — Core Zeek fields, TLS ciphers, DNS answer types, UIDs,
  certificates, and connection histories are strong; SMB policy paths are the principal exception.
- **Temporal patterns:** 6/10 — Event-level timing and renewal/scan jitter are credible, but every
  output stream is perfectly sorted on event start time.
- **Cross-source correlation:** 9/10 — Multi-sensor and endpoint-flow matches preserve distinct UIDs,
  clock offsets, and capture-point differences without visible causal contradictions.
- **Behavioral realism:** 7/10 — User, proxy, server, scanner, tunneling, and lateral traffic are
  varied, though some HTTP and SMB vocabularies look pool-driven.
- **Environmental consistency:** 6/10 — Sensor roles and protocol volumes fit, but future-year files
  and non-native domain-policy namespaces are repeated environmental breaks.

## Recommendations

- If this were synthetic, derive file-path years from the simulated event date and constrain future
  years to explicit planning use cases. Do not sample a symmetric year range around generation time.
- Model SYSVOL and NETLOGON as source-specific namespaces. Use domain/GPO GUID hierarchy and native
  filenames such as `Registry.pol`, `GptTmpl.inf`, scripts, and Group Policy Preferences paths rather
  than freely combining generic stems, extensions, and year directories.
- Preserve source-native Zeek emission order where reports are meant to resemble raw logs, or document
  that the files are normalized exports. Long connections should naturally create start-time
  inversions when logged at closure/timeout.
- Broaden HTTP client-version texture only if the visible software population supports it; this is a
  lower-priority refinement than correcting SMB namespace semantics and stream ordering.
