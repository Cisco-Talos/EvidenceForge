# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 74
**Synthetic-Confidence Score:** 44

## Executive Summary

The network telemetry is largely production-like: protocol state, byte accounting, TLS behavior, capture loss, exposed-DMZ scanning, and source-to-source timing are coherent, and I found no hard contradiction. A few repeated timing textures—especially highly stable per-client DHCP renewal intervals and a narrow, always-positive offset between matching core and DMZ observations—keep the result from a Real verdict, but they are also explainable by client timers and sensor clock offset.

## Evidence For Synthetic

- `[distribution_texture]` DHCP renewal timing is unusually stable within each client. In `zeek-core/dhcp.json`, all 69 visible transactions are renewals with stable per-host intervals: `WS-OHADDAD-01` has 13 observations separated by 1786.2–1788.8 seconds, `WS-PPATEL-01` has 12 separated by 1691.5–1693.7 seconds, and `WS-MCHEN-01` has 11 separated by 1969.2–1970.6 seconds. Periodicity is expected, but the repeated host-specific cadence with only about one second of variation is mildly generator-like.
- `[distribution_texture]` Matching observations across `zeek-core/conn.json` and `zeek-dmz/conn.json` have an unusually bounded one-direction offset. For 1,930 exact five-tuple matches within one second, every DMZ timestamp followed the core timestamp; the median offset was 56.13 ms, the 10th–90th percentile range was 46.09–62.52 ms, and the overall range was 23.54–66.42 ms. A persistent sensor clock offset could explain this, so it is not a contradiction, but the narrow always-positive distribution is a synthetic-looking observation texture.
- `[environment_or_collection_plausibility]` Across 11,875 Zeek connection records, there are no UDP/123 observations despite visible DHCP, DNS, Kerberos, domain infrastructure, and two internal sensor views. A six-hour window can miss a long NTP poll cycle, so this is only a weak source-family distribution concern rather than a required-companion failure.
- `[weak_signal]` The internal remote-administration volume is dense for the apparent environment: `zeek-core/conn.json` contains 119 SSH sessions (117 `SF`, median duration 1,234.874 seconds) plus 16 RDP sessions. The associated endpoint flows show multiple named users and a broad workstation/server mesh. This can be legitimate administration and is not independently probative, but it modestly reinforces the timing-texture concerns.

## Evidence For Real

- Connection-state texture is varied and service-appropriate. `zeek-core/conn.json` contains 6,161 `SF`, 84 `RSTO`, 57 `RSTR`, 44 `REJ`, 29 `S0`, and smaller `OTH`/`S1`/`S2`/`S3` populations. `zeek-dmz/conn.json` contains 3,937 `SF` and 1,280 `S0`, with the latter dominated by Internet-origin probes against ports 23, 2323, 25, 445, 3389, 22, and related services.
- External scanning has realistic specialization and entropy. Eight major scanner IPs account for most DMZ `S0` traffic, but use different port families (Telnet/SSH, mail, Windows administration, and web); inter-arrival times are nonuniform, and the complete external population contains 273 unique origin IPs.
- DNS behavior is rich rather than mechanically minimal. The core DNS data includes A, AAAA, PTR, SRV, TXT, NS, MX, and SOA traffic; `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED` outcomes; Windows-like `wpad`, `isatap`, suffix-search, and reverse-lookup failures; and a high-entropy TXT tunnel burst from `10.10.2.30`. DNS RTTs have 1,762 unique values among 2,250 records.
- TLS version/cipher combinations are source-native and coherent. Core and DMZ data use TLS 1.2 and 1.3 with compatible suites; no TLS 1.3 record uses a TLS 1.2-only ECDHE suite and no TLS 1.2 record uses a TLS 1.3-only `TLS_AES_*` suite. Resumption is present, certificate reuse is stable per SNI, and TLS 1.3 appropriately lacks passively visible certificate chains.
- Capture imperfections behave coherently. There are 408 core and 371 DMZ connections with nonzero `missed_bytes`. All SSL certificate FUIDs resolve to `files.json`; 10 core and 58 DMZ certificate files lack `x509.json` records specifically when the file is truncated (`missing_bytes` 1–20 and no X509 analyzer), which is realistic packet-loss behavior rather than arbitrary missingness.
- Protocol child records obey visible connection lifetimes. All 2,250 core DNS, 1,039 core HTTP, 110 core SSL, 774 DMZ DNS, 1,232 DMZ HTTP, and 1,583 DMZ SSL rows resolve to a same-sensor connection UID and fall within that connection's visible interval. All 920 Zeek file observations likewise reference visible connections and end before connection close.
- Explicit-proxy behavior is plausible. Of 734 successful core `CONNECT` transactions, 729 have a same-SNI proxy-origin TLS session beginning within five seconds, normally 0.1–0.8 seconds after the client request. Denied/authentication/error CONNECT responses carry bodies while successful 200 responses have zero HTTP body length.
- IDS evidence matches the underlying protocol content. All sampled and programmatically joined DNS alerts point to the claimed TLD/query: for example, the core alert at `03/18-12:23:29.167074` for a `.bit` query matches `sync-aef65e3t.bit` within 5.3 ms, while later `.cloud`, `.to`, `.top`, and `.tk` alerts resolve to corresponding DNS records.

## Detailed Analysis

### Scope and time window

Both Zeek sensors cover approximately 2024-03-18 12:00–18:00 UTC. Core has 6,408 connections; DMZ has 5,467. I treated this strictly as a slice-of-time capture. Firewall teardown-only records and processes/sessions whose initiators could precede 12:00 were not counted as defects.

### Connection and protocol behavior

Core traffic is dominated by DNS (2,259 service classifications), Kerberos (1,076), HTTP/proxy (959), SMB (921), and LDAP (629), followed by SSH (119), TLS (70), DHCP (69), and SMTP (67). The DMZ view is appropriately different: TLS (1,697), HTTP (1,166), DNS (781), MySQL (312), and a large unclassified scan population. TCP, UDP, and ICMP packet accounting is internally valid, successful flows carry bidirectional payload, and failed SYN probes generally show `history=S`, zero payload, and no response.

The exposed host `10.10.3.10` sees a believable mix of successful web traffic and unsolicited probes. Major scanners have distinct preferences: `145.78.103.167` and `37.75.195.175` emphasize ports 23/2323/22; `38.186.148.245` emphasizes mail ports; and `45.33.74.51` emphasizes 445/3389/135/5985. This is much closer to real Internet background radiation than a uniform scan matrix.

### DNS

Core query outcomes include 1,170 A/NOERROR, 308 AAAA/NOERROR, 312 TXT/NOERROR, 181 A/NXDOMAIN, 139 PTR/NOERROR, 68 SRV/NOERROR, plus smaller failure and referral-related populations. Internal DNS answers have stable authoritative TTLs (for example, `DC-01.meridianhcs.local` at 300 seconds and `FILE-SRV-01.meridianhcs.local` at 1,800 seconds), while public names show varied TTLs and recursive latency.

The TXT burst from `10.10.2.30` contains 301 requests. Its main high-entropy run spans 15 minutes with 299 of 300 inter-arrival values unique, varied sublabels, mixed `NOERROR`/`NXDOMAIN`/`SERVFAIL`, and low response TTLs. That looks like plausible tunneled activity rather than a fixed-interval placeholder.

### TLS, certificates, and files

Core TLS contains 61 TLS 1.3 and 49 TLS 1.2 sessions; DMZ contains 1,066 TLS 1.3 and 517 TLS 1.2. The cipher sets are compatible with those protocol versions and include AES-128/256-GCM, ChaCha20-Poly1305, RSA/ECDSA authentication where visible, and a small TLS 1.2 CBC tail. Repeated SNIs reuse certificate fingerprints; resumed sessions omit certificate chains.

The certificate/file relationship is especially persuasive. Every referenced certificate FUID is present in `files.json`. When packet loss truncates a certificate, `files.json` records the expected `application/pkix-cert`, total/seen byte difference, and absent analyzer; only then is the corresponding `x509.json` parse absent. Fully observed certificates have internally consistent issuer, validity, key, SAN, fingerprint, and chain fields.

### Cross-source timing and lifecycle

No protocol row precedes its same-UID Zeek connection or occurs after its visible close. ASA parsing produced 2,185 complete visible build/teardown pairs with no teardown-before-build identity and no duration discrepancy greater than one second. Endpoint FLOW actors that had a visible process creation never preceded that creation or followed that process's visible termination.

The narrow core-to-DMZ offset is the main cross-source concern, but it remains possible under stable sensor clock skew. It did not create reversed lifecycle semantics: all 1,930 matched flows retained the same connection state, and relevant protocol observations stayed coherent.

### Volume and timing

Traffic is bursty at ten-minute resolution rather than flat. Core bins range from 95 to 346 connections, with a visible burst around 16:40–17:00 UTC; DMZ bins range from 75 to 324. DHCP cadence is the exception: renewal intervals are nearly fixed per host, producing the clearest repeated timing texture in the dataset.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `distribution_texture` | Zeek DHCP | 69 renewals across 8 clients | Stable host-specific intervals with roughly one-second variance are mildly generator-like. |
| `distribution_texture` | Core/DMZ Zeek conn | 1,930 matched tuples | Always-positive, narrowly bounded 23.54–66.42 ms sensor offset is suspicious but explainable by clock skew. |
| `environment_or_collection_plausibility` | Zeek infrastructure traffic | 11,875 connections | No UDP/123 in six hours is a weak distribution gap, not a required missing companion. |
| `weak_signal` | Zeek SSH/RDP and endpoint FLOW | 135 remote sessions | Dense remote-admin mesh is unusual but plausible without role context. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, ASA, Snort, proxy, TLS, and certificate fields are source-native and mutually coherent.
- **Temporal patterns:** 7 — Bursty traffic and varied session durations are strong, offset by DHCP cadence and narrow cross-sensor delay texture.
- **Cross-source correlation:** 9 — No impossible visible ordering or dangling connection identity was found; capture loss degrades child parsing coherently.
- **Behavioral realism:** 8 — DMZ scanning, proxy traffic, DNS behavior, TLS use, and remote sessions have credible protocol semantics.
- **Environmental consistency:** 7 — Host/service placement is plausible, with only weak concerns about remote-admin density and absent NTP.

## Recommendations

- If this were synthetic, model DHCP T1 behavior from explicit server/client policy and introduce occasional timer drift, delayed renewals, retransmission, or lease-policy changes so long renewal sequences are not nearly constant per host.
- If this were synthetic, represent sensor clocks as independent drifting clocks (or a documented fixed offset) instead of applying a narrowly distributed positive delay to every shared core-to-DMZ flow.
- If this were synthetic, add sparse NTP/chrony/W32Time traffic when the visible collection profile includes comprehensive internal UDP and domain infrastructure, unless the environment explicitly uses a poll interval longer than the capture window.
- If this were synthetic, condition dense SSH/RDP background on explicit administrator roles and reduce broad workstation-to-server remote sessions for ordinary personas, while retaining the realistic durations and failure texture already present.
