# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 90
**Synthetic-Confidence Score:** 74

## Executive Summary

The network records are broadly coherent, with plausible sensor segmentation, DNS diversity, proxy behavior, TLS visibility limits, and consistent protocol/file references. Two concrete defects change the verdict: every ICMP observation uses a connection-state classification inconsistent with upstream Zeek, and twelve connections explicitly owned by a plain Nmap TCP connect scan contain client payload. These are source semantics and activity-contract problems, not objections to complete matching or to the intrusion's narrative.

## Evidence For Synthetic

- [schema_or_format] **Systematic ICMP state mismatch across all three sensors.** All 723 `proto="icmp"` observations have `conn_state="SF"` or `"S0"`: core has 156 SF and 245 S0; DMZ has 59 SF and 245 S0; DB has 18 SF. For example, `zeek-core/conn.json:139`, UID `CUB1N8GidfwdC1qu4a`, has ICMP type/code 8/0, `ip_proto=1`, and `conn_state="SF"`; line 3092 has the same protocol with `conn_state="S0"`. Upstream Zeek handles TCP and UDP separately and returns `OTH` for other transports. This is a systematic departure from native Zeek semantics, rather than an impossible ICMP packet exchange. Custom normalization could explain it, but none is established by the supplied records. [Zeek 8.0.0 connection logger](https://raw.githubusercontent.com/zeek/zeek/v8.0.0/scripts/base/protocols/conn/main.zeek)
- [contract_gap] **Client application payload attributed to a scan that only connects.** `WEB-EXT-01.meridianhcs.local/ecar.json:1183` identifies PID 2705135, UUID `72153552-bc9a-448f-9b86-10758eb2deff`, running `/usr/bin/nmap` with `nmap -Pn -sT -p 22,80,443,445,3306 10.10.2.0/24`. Of 1,256 matching endpoint FLOW tuples in DMZ Zeek, twelve have nonzero `orig_bytes`, although the command requests no version detection, scripts or data payload. Examples: `zeek-dmz/conn.json:2370` reports 170 client payload bytes to 10.10.2.21:22, line 2413 reports 55 to 10.10.2.30:80, and line 2660 reports 147 to 10.10.2.10:445. Nmap documents ordinary connect scanning as establishing and then closing connections without sending data. This is a mismatch between exact process intent/ownership and observed network evidence. [Nmap TCP connect scanning](https://nmap.org/book/scan-methods-connect-scan.html)

## Evidence For Real

- Sensor traffic mixes differ plausibly: core emphasizes DNS, Kerberos-port, LDAP and SMB traffic; DB emphasizes TCP/3306; DMZ emphasizes TLS and explicit proxy traffic.
- All 4,313 DNS, 4,610 HTTP and 3,142 TLS records join a same-sensor connection UID with a matching four-tuple. Their protocol timestamps fall within associated connection intervals, allowing 1 ms for numeric precision. Complete joins are a positive coherence check, not an authenticity discriminator by themselves.
- TLS 1.3 rows correctly omit certificate-chain identifiers. TLS 1.2 includes full and resumed handshakes, failures and certificate/file references. `zeek-dmz/ssl.json:1` has `TLSv13`, `TLS_AES_256_GCM_SHA384`, `established=true` and no exposed certificate chain, matching the passive visibility limitation. [Zeek TLS logging](https://docs.zeek.org/en/master/reference/logs/ssl.html)
- Repeated certificate fingerprints do not change certificate/SAN attributes within or between sensors. Resolvable adjacent chain entries have matching issuer/subject names, and none of the 1,318 certificate rows is visibly outside its validity interval.
- DNS includes A, AAAA, PTR, SRV, TXT, MX, NS and SOA responses. Core contains 227 NXDOMAIN, 14 SERVFAIL and four REFUSED observations rather than universally successful resolution.
- `PROXY-01.meridianhcs.local/proxy_access.log:1-4` distinguishes CONNECT control bytes from tunneled and inspected HTTP bytes, two tunnel identities/durations, and a related CDN request with a referer.

## Detailed Analysis

### Input provenance and limits

I read the complete neutral briefing `/private/tmp/log-study-gel6klid/network-prompt.md`. I enumerated only `/private/tmp/log-study-gel6klid/data`, parsed every JSON row in its three `zeek-*` directories, sampled the first four records from the supplied proxy, ASA and two Snort logs, and read the relevant WEB-EXT-01/FILE-LNX-01 eCAR and syslog files to test an exact scan tuple and process identity. Logged commands were evidence and were never executed.

Public verification used official Zeek documentation, upstream `zeek/zeek` source and official Nmap documentation. The initial search used textual official-site qualifiers and returned some unrelated public summaries, which were not relied upon. Subsequent research used explicit domain filtering or direct upstream URLs. No project source, scenario, project documentation, roadmap, worklog, prior assessment or other reviewer output was accessed. Inherited operating metadata is an environment limitation and was not used as evidence of origin.

The slice runs approximately 2026-11-02 13:00–19:00 UTC. Overnight, weekend and full-session completeness cannot be inferred. Sensor record counts include repeated observations of the same activity; they are not unique enterprise action counts. No packet capture or collector build/configuration was supplied, so established source-semantic mismatches are distinguished from possible custom processing.

### Connection states and accounting

| Sensor | Connections | TCP | UDP | ICMP | SF | S0 |
|---|---:|---:|---:|---:|---:|---:|
| zeek-core | 12,314 | 6,715 | 5,198 | 401 | 10,053 | 1,897 |
| zeek-dmz | 9,401 | 7,960 | 1,137 | 304 | 6,516 | 2,606 |
| zeek-db | 433 | 357 | 58 | 18 | 350 | 4 |

RSTO, RSTR, REJ, S1, S2, S3 and OTH also occur. Large S0 counts are not inherently suspicious: the records include an internal scan with many unanswered probes. The existence or compact timing of scanning was not penalized.

The ICMP issue concerns native `conn_state`. `zeek-dmz/conn.json:36`, UID `C14aqtUjuUOwh6hEvu`, reports an external echo exchange with 1,472 payload and 1,500 IP bytes each way. Those dimensions are physically plausible, but its `SF` differs from upstream Zeek's classification. `zeek-db/conn.json:60`, UID `C9CbB4yMa4VoWQliJD`, repeats the classification for a smaller internal exchange. `zeek-dmz/conn.json:2075`, UID `CEMuhK45id8jbHHLV5`, uses `S0` for an unanswered request. All 723 ICMP rows use this alternative mapping across all segments. I verified the relevant upstream branch both in stable v8.0.0 and current master; the actual deployed version is unknown.

I tested IP-byte totals against TCP payload plus minimum headers. Every apparent undercount coincided with content-gap evidence (`G/g` or nonzero `missed_bytes`). Because payload sizes derive from sequence space while IP bytes measure observed packets, those rows were excluded as authenticity defects. S1 byte fields were also not treated as defects: despite an ambiguous explanatory documentation sentence, upstream code can populate byte counts independently of the state label. [Zeek connection fields and accounting](https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html)

### Exact scan ownership and payload

The process CREATE at endpoint eCAR line 1183 precedes the scan FLOWs. TERMINATE at line 2442 ends the same UUID, providing direct process ownership rather than attribution by destination port.

| Endpoint eCAR line | Exact scan tuple | DMZ conn line | Originator payload | State/service |
|---:|---|---:|---:|---|
| 1210 | 10.10.3.10:36200 → 10.10.2.21:22 | 2370 | 170 | SF / ssh |
| 1250 | 10.10.3.10:56371 → 10.10.2.30:80 | 2413 | 55 | SF / http |
| 1994 | 10.10.3.10:54909 → 10.10.2.30:443 | 3217 | 13 | SF / ssl |

The first tuple also appears in `zeek-core/conn.json:3387`, UID `Cq1U2c3goOfrpS5OrYv`, at Unix time 1793630429.550329, with `orig_bytes=170`, `resp_bytes=1`, `history="ShADadfF"`, and `missed_bytes=0`. Its nonzero client payload therefore occurs on two observation paths, including one without a logged gap.

Server-first banners can occur during connect scans; they do not explain client application data. The full recorded command lacks the options that request version probing. Twelve affected DMZ rows are a small fraction of all traffic, and a modified executable or incorrect endpoint attribution remains possible. I therefore classify this as a bounded contract gap, not impossible TCP. Service labels reinforce the concern but are not a separate scored defect, since no packet contents or deployed analyzer configuration are available. [Nmap version detection](https://nmap.org/book/man-version-detection.html)

### DNS and protocol behavior

Core DNS type counts are A 2,333, AAAA 279, PTR 154, SRV 105, TXT 300, MX eight, NS six and SOA three. DMZ has A 891, AAAA 113, PTR 58, SRV ten and TXT three; DB has A 36, AAAA five, PTR one, SRV five and TXT three.

Answer and TTL vectors have matching lengths throughout. DNS RTTs do not exceed joined connection durations by more than 1 ms, and packet sizes satisfy conservative DNS question/answer lower bounds. Examples include internal service discovery at `zeek-core/dns.json:1` and a proxy-originated external A lookup at `zeek-dmz/dns.json:1`.

TXT traffic becomes prominent late in the slice, but most of the burst involves high-entropy names under one external domain. That can reflect real scripted or malicious DNS behavior. I did not score its concentration or ease of narration. Missing IPv6 connections, NTP or other infrastructure families alone do not establish an inconsistent collection profile.

HTTP is dominated by CONNECT: 1,967 of 2,159 core rows and 2,013 of 2,431 DMZ rows. A naive HTTP-to-HTTPS row ratio would therefore confuse proxy negotiation with unencrypted browsing. Visible 403/407 and 502/503/504 outcomes provide plausible denials, authentication challenges and upstream failures. No individual HTTP body exceeds its associated directional whole-connection payload; no single-connection file's seen bytes exceed that direction's connection payload.

### TLS, certificates and lateral traffic

Core has 201 TLS 1.2, 199 TLS 1.3 and three rows without a negotiated version. DMZ has 913 TLS 1.2, 1,808 TLS 1.3 and four without one. DB has fourteen TLS 1.2 rows. TLS 1.3 uses AES-GCM or ChaCha20; TLS 1.2 includes GCM and legacy CBC on internal services, a plausible mixed-service pattern.

There are no TLS 1.3 certificate-chain FUIDs. TLS 1.2 resumed rows omit fresh chains; repeated fingerprints retain stable attributes. RSA/ECDSA leaf-key ownership was checked without confusing issuer signature algorithms with leaf public-key algorithms; no demonstrated cipher/key contradiction emerged.

Internal TCP/22, 445 and 3389 traffic includes short scans and longer sessions. Median duration among connections actually classified `ssh` is approximately 2,018 seconds at core and 1,434 at DMZ. No blanket requirement for missing SSH/RDP protocol logs or endpoint collectors was imposed, and absent pre-window initiation or post-window closure was neutral.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| schema_or_format | Zeek conn | All 723 ICMP observations across three sensors | Largest contribution: systematic native-state mismatch, verified against upstream; custom processing remains a caveat. |
| contract_gap | eCAR process/FLOW ↔ Zeek conn | Twelve payload-bearing tuples among 1,256 FLOWs owned by one plain connect scan | Material bounded command-to-payload inconsistency; repeated sensor observations are not separate incidents. |

These issues support the 61–80 rubric band. Broadly correct DNS/TLS/file accounting and unknown collector configuration keep the score below the 81–100 band.

## Realism Score by Category

- **Field format accuracy:** 7 — Valid JSON and coherent protocol fields, with a systematic ICMP state-semantic defect.
- **Temporal patterns:** 9 — Diverse durations and flow bursts; no verified same-UID protocol timestamp inversion in the tests performed.
- **Cross-source correlation:** 8 — Strong UID/tuple/file/certificate consistency, reduced by scan process-to-payload mismatch.
- **Behavioral realism:** 7 — Convincing segmentation and proxy behavior; plain connect scanning carries inappropriate client payload.
- **Environmental consistency:** 9 — Traffic mixes fit observed segments and explicit proxy use; unsupported source/platform requirements were excluded.

## Recommendations

- If this were synthetic, make ICMP connection-state rendering follow the chosen upstream Zeek release. If custom normalization is intended, preserve or document it so transformed records are distinguishable from unmodified Zeek.
- If this were synthetic, align scan transport evidence with the exact scan mode: plain TCP connect scanning should not acquire invented client payload. If application probing is intended, visible process options and ownership must establish it.
- Preserve coherent UID/tuple relationships, TLS 1.3 visibility limits, stable certificate identities, proxy byte scopes and packet-loss accounting. No recommendation requires unrelated source families or artificial mistakes in the activity.
