# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 32

## Executive Summary

The network records are predominantly production-like: transport states, DNS diversity, explicit-proxy behavior, TLS visibility, and protocol-to-flow relationships withstand broad consistency checks. I found one unusual TCP-history/payload relationship, but upstream Zeek implementation details prevent treating it as a demonstrated impossibility; the visible evidence does not reliably distinguish a well-constructed synthetic capture from sanitized production telemetry. The confidence of 80 applies to the inconclusive verdict, while 32 describes the comparatively low level of synthetic appearance.

## Evidence For Synthetic

- [weak_signal] `zeek-dmz/conn.json:7029`, UID `CfGFWEfryq7DWocEk`, reports `history="ShADafF"`, `resp_bytes=75346`, `resp_pkts=55`, and `missed_bytes=0`. Its corresponding HTTP response contains 75,107 bytes (`http.json:1666`), fully observed as file `FGjLj37OytJgUaty8Hw` (`files.json:1119`, `missing_bytes=0`), yet the connection history lacks responder data marker `d`. This is unusual for a multi-packet HTTP response. **Qualification:** Zeek's implementation records FIN/SYN/RST history in preference to `D/d` on packets carrying those flags, so missing `d` is not itself a hard contradiction. Without packets, I cannot exclude special flag/payload behavior, collector modification, or a logging defect. I give this observation limited weight and do not claim impossible causality.

## Evidence For Real

- DNS contains operational variety rather than only successful A lookups. Core has 302 successful AAAA records, 156 PTR transactions including 16 NXDOMAINs, 97 SRV records, successful TXT/MX/NS/SOA traffic, SERVFAILs, and REFUSEDs. Examples include `zeek-core/dns.json:12` (AAAA), `:17` (internal PTR), and `:43` (SERVFAIL).
- Fresh resolution can precede connection establishment with realistic timing. `zeek-dmz/dns.json:3` starts at `1793624513.710807`, has `rtt=0.037560`, and returns `151.101.1.140`; the same client's TCP connection to that address begins at `1793624513.759038` (`conn.json:26`), approximately 10.7 ms after the DNS answer.
- Proxy control bytes and tunneled traffic are distinguished. `PROXY-01.meridianhcs.local/proxy_access.log:1` records a successful CONNECT with `cs_bytes=520`, `wire_sc_bytes=213`, `tunnel_cs_bytes=4274`, and `tunnel_sc_bytes=34835`; `zeek-dmz/conn.json:1` accounts for 4,794 originator and 35,048 responder payload bytes, the respective sums. The HTTP CONNECT has zero HTTP response body, while separate upstream TLS evidence exists.
- TLS 1.3 records do not expose certificate chains, while non-resumed TLS 1.2 sessions can carry certificate/file references. `zeek-dmz/ssl.json:1` uses an ECDSA-authenticated TLS 1.2 suite with an EC leaf certificate (`x509.json:1`); `ssl.json:3` uses TLS 1.3 without certificate references. Resumed TLS 1.2 examples also omit chains (`ssl.json:11`). These differences match passive visibility constraints described in the [Zeek SSL documentation](https://docs.zeek.org/en/current/reference/logs/ssl.html).
- Successful, unanswered, rejected, reset, and partially closed connections coexist. This is not a dataset composed solely of successful HTTP sessions. Core contains 128 RSTO, 102 RSTR, 23 REJ, 21 S2, 21 S3, and seven S1 records in addition to SF/S0/OTH traffic.
- Remote administration has substantial transport lifetimes and byte budgets. `zeek-core/conn.json:1101` records a 2,743.584692-second RDP flow with roughly 470 KB sent and 625 KB received; `:1287` records another lasting 999.182095 seconds with approximately 1.81 MB received. SSH sessions likewise range into tens of minutes; these are not all tiny placeholder connections.

## Detailed Analysis

### Actual input provenance and limitations

I read the supplied briefing at `/private/tmp/log-study-wxj1n2j_/network-prompt.md`, inventoried only its specified `data` directory, and analyzed the JSON records in all supplied `zeek-core`, `zeek-dmz`, and `zeek-db` files. I also read the supplied `snort-core/snort_alert.log`, `snort-perimeter/snort_alert.log`, `fw-perimeter/cisco_asa.log`, and `PROXY-01.meridianhcs.local/proxy_access.log`. These are the actual dataset inputs to this report. Endpoint file paths appeared in the permitted inventory, but I did not read endpoint telemetry or shell-history contents.

No project source, scenario, TODO, worklog, prior assessment, other reviewer's report, or neighboring dataset inventory was accessed. Generic inherited operating instructions were treated as an environment limitation, not evidence about origin. Public verification used searches with an actual `docs.zeek.org` domain filter and direct URLs to the upstream `zeek/zeek` repository. No project-related public documentation was searched or opened. Logged activity was treated as inert evidence; no logged command was executed.

This is a log-only review without packet capture, collector configuration, Zeek build identity, firewall policy, or definitive host inventory. I cannot prove that JSON exports are untouched source-native output. Different sensors may have different clocks, so I did not infer impossible ordering by directly comparing their timestamps. This is a six-hour slice, approximately 2026-11-02 13:00–19:00 UTC; the slice cannot establish overnight, weekend, boot-to-shutdown, or full-day behavior. Domains and addresses were treated as potentially sanitized.

### Scope and record volumes

All 39,681 supplied Zeek JSON records parsed successfully. The counts below are observations, not authenticity indicators by themselves; independently observing one flow at two sensors increases these counts.

| Sensor | Connection | DNS | HTTP | TLS | Files | X.509 |
|---|---:|---:|---:|---:|---:|---:|
| Core | 12,556 | 3,321 | 2,221 | 441 | 793 | 274 |
| DMZ | 9,646 | 1,091 | 2,493 | 2,759 | 1,690 | 1,054 |
| Database | 448 | 44 | 22 | 19 | 28 | 22 |

Other supplied Zeek families comprise 127 OCSP records, 59 DHCP records, 78 SMTP records, 312 SMB-file records, 180 SMB-mapping records, and three PE records. The two IDS logs contain 55 and 88 alerts; the firewall has 23,193 lines and the proxy 3,551 lines.

### Transport states, lifetimes, and accounting

Core transport is 6,824 TCP, 5,329 UDP, and 403 ICMP records. DMZ is 8,194 TCP, 1,153 UDP, and 299 ICMP; the database sensor has 379 TCP, 52 UDP, and 17 ICMP. State distributions differ by observation area: S0 appears 1,709 times at core and 2,525 times at DMZ, compared with eight times at the database sensor. A mix of unanswered scan attempts, successful application sessions, infrastructure requests, and resets is plausible on these paths; the S0 fraction alone does not establish fabrication.

I checked same-sensor TCP/UDP tuple intervals and found no overlapping distinct connection intervals for the same directed five-tuple. I also found no repeated UDP DNS five-tuple assigned a new UID within 60 seconds of the prior interval's end. No flow had IP-byte counters below its reported payload-byte counters. Cases where IP bytes minus sequence-derived TCP payload fell below a simple minimum-header calculation all involved nonzero missed bytes; I did not mistake these for impossible packet accounting. The [Zeek connection-field reference](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html) specifically distinguishes sequence-derived TCP payload accounting from observed IP-byte counters.

The sole unusual no-gap data/history case is the HTTP UID discussed above. Its timestamp is `1793638410.566170` and duration 2.851800 seconds. The HTTP row begins at `1793638410.578778`; file observation begins at `1793638410.631311` and lasts 0.793062 seconds. These times fit inside the connection; the concern is the absent `d`, not timing. I verified the important exception directly in [upstream Zeek TCP history handling](https://raw.githubusercontent.com/zeek/zeek/master/src/packet_analysis/protocol/tcp/TCPSessionAdapter.cc): SYN/FIN/RST-bearing packets take a separate history branch from ordinary payload packets. Consequently this report retains the anomaly only as a weak signal, not a hard contradiction.

### DNS and protocol behavior

The core DNS totals include 2,240 successful A lookups, 181 A/NXDOMAINs, 13 A/SERVFAILs, 302 successful AAAAs, and the additional types already described. Core RTTs range from seven microseconds to about 2.069 seconds. TTLs include familiar fixed infrastructure values and less uniform remaining-cache lifetimes; `zeek-dmz/dns.json:3` has TTL 1,664 seconds, while `zeek-core/dns.json:17` has TTL 7,200 seconds.

A second causal example is `zeek-core/dns.json:2`: the A lookup for `FILE-SRV-01.meridianhcs.local` begins at `1793624404.045675`, with a 0.071049-second RTT. SMB UID `CFOFT6tbToZmDebaR4` begins at `1793624405.356835` (`conn.json:4`) and accesses the resulting `10.10.2.20` address. This is a plausible answer-before-connect sequence. I did not require every connection to have a fresh lookup because cached resolution and pre-window activity remain valid explanations.

I specifically checked two unfamiliar-looking DNS shapes before judging them. SRV `answers` containing only target names (`zeek-core/dns.json:1`) are consistent with Zeek's standard logging handler; omission of priority/weight/port is not a defect. TXT answers such as `"TXT 12 zcU3iCFW48yn"` (`dns.json:2399`) also use a native Zeek representation. Both are confirmed by the [upstream DNS logging script](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/dns/main.zeek). I did not score either shape as synthetic.

The source mix is compatible with the observed paths: core includes substantial Kerberos, LDAP, SMB, and DNS; the database path is dominated by MySQL (275 service-identified connections), while the DMZ has extensive TLS and proxy HTTP. Port 8080 CONNECT traffic is a control layer for encrypted tunnels, so simply comparing HTTP-row counts to TLS-row counts would misstate the cleartext/HTTPS ratio. I did not penalize missing NTP, QUIC, Bonjour, or other optional traffic.

### HTTP, proxy, IDS, and firewall checks

Core HTTP includes 1,895 successful CONNECT rows and 119 unsuccessful CONNECT rows, with 403, 407, 502, 503, and 504 responses. DMZ contains the same response classes and additional direct HTTP activity. The inspected non-2xx CONNECT responses carry plausible HTML error bodies; successful CONNECT rows have no HTTP body. No 204/304 or HEAD row had a prohibited positive response body. Multiple HTTP transactions sharing a connection have distinct transaction depths; I found no duplicated transaction depth within a UID.

The first proxy example separates the inside client-to-proxy socket from the proxy-to-Internet socket. The upstream TLS UID `CyfuWzWe7S7ISfAaY3` at `zeek-dmz/ssl.json:1` uses originator `10.10.3.20:34135`, rather than attributing the external TCP connection to the original client. `fw-perimeter/cisco_asa.log:1–8` then provides an outside PAT address/port, separate connection identifiers, TCP teardown messages, and translation teardown. This makes the visible path internally understandable without requiring identity reuse across different sockets.

The DNS-category IDS alerts I joined on source/destination addresses and ports agree with the visible query suffixes. For example, `snort-core/snort_alert.log:1` identifies a `.to` query from `10.10.3.20:47366` to `10.10.2.10:53`, which matches `zeek-core/dns.json:13`; the perimeter counterpart matches `zeek-dmz/dns.json:5`. This is useful positive consistency evidence, not a claim that alert coverage must be complete. I did not independently validate every rule SID against a versioned IDS ruleset, nor infer that every encrypted payload was inspected.

### TLS, certificate identity, and file relationships

Across the three sensors there are 3,219 TLS records. DMZ includes 1,825 records declaring TLS 1.3, 929 declaring TLS 1.2, and five without a negotiated version. The negotiated suites include AES-GCM, ChaCha20-Poly1305, and some TLS 1.2 CBC; without a software/configuration inventory, legacy TLS 1.2 usage does not prove an authenticity defect.

I checked each supplied chain where its certificates were available: leaf cipher authentication type agreed with the leaf key type; each child's issuer matched the next certificate's subject; and signature algorithm family agreed with the issuer key family. Certificate validity windows contained their observation timestamps. File SHA-1 and X.509 fingerprints agreed for linked certificate files. Repeated fingerprints did not change certificate metadata across the sensors, and I found no issuer/serial pair assigned conflicting fingerprints. Available certificate-file byte totals did not exceed corresponding flow response-byte totals. These checks support internal realism but cannot authenticate actual DER certificates without the certificate bytes.

TLS 1.3's absence of visible chain files is expected under passive collection. Likewise, I did not penalize missing certificate files on resumed TLS 1.2 sessions or assume every unresumed record must retain X.509 metadata after configurable certificate suppression.

### Correlation and time-window qualifications

I joined same-sensor DNS, HTTP, TLS, SMTP, SMB mapping, and SMB file rows to their conn UIDs. Every matched row preserved its connection four-tuple, and its protocol timestamp lay inside the corresponding connection interval. Every matched file's start and duration also fit its associated connection interval.

Three protocol rows have no supplied conn row: `zeek-core/http.json:2221`, `zeek-dmz/http.json:2493`, and `zeek-dmz/ssl.json:2759`. All occur at approximately 18:59:57 UTC, immediately at the visible boundary. Since protocol observations may be exported before the eventual conn summary, these are compatible with sessions remaining open beyond the slice. They are not scored as missing required evidence.

Core hourly connection counts are 1,767, 3,281, 1,762, 1,918, 2,181, and 1,647 across the six hours. DMZ has its own uneven hourly distribution. Neither series is flat. With only this window, I cannot evaluate overnight infrastructure baselines or establish a particular organization-wide business-hours profile.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| weak_signal | Zeek TCP history / HTTP / files | One DMZ UID: `CfGFWEfryq7DWocEk`; `conn.json:7029`, `http.json:1666`, `files.json:1119` | Large, fully observed HTTP response lacks ordinary responder data marker. Limited weight because Zeek has flag-bearing payload exceptions and no packet capture establishes the actual sequence. |

No demonstrated hard contradiction, source-format defect, or strong dataset-wide distribution artifact was established. Complete matching, optional source coverage, sanitized names, filesystem timestamps, narrative completeness, and slice-boundary missing closures did not increase the score.

## Realism Score by Category

- **Field format accuracy:** 9 — JSON and protocol shapes are consistent with the inspected Zeek interfaces; one unusual history/payload case remains unresolved.
- **Temporal patterns:** 9 — Variable lifetimes, uneven activity, valid matched protocol/file intervals, and plausible resolution-to-connect examples; six-hour scope limits wider assessment.
- **Cross-source correlation:** 9 — Socket, UID, certificate/file, proxy byte-budget, and sampled IDS relationships cohere; no packets or collector configuration authenticate the exports themselves.
- **Behavioral realism:** 9 — Mixed success/failure states, infrastructure activity, application traffic, proxy errors, and substantial remote-session lifetimes.
- **Environmental consistency:** 9 — Distinct sensor protocol mixes and explicit-proxy/PAT semantics are plausible; definitive topology and collection configuration were not supplied.

## Recommendations

- If this were synthetic, review UID `CfGFWEfryq7DWocEk` against the modeled packet/flag sequence so the connection history agrees with the observed response. Do not mechanically insert `d` merely because `resp_bytes` is positive: upstream Zeek suppresses that marker for payload carried on SYN/FIN/RST-bearing packets. Preserve or document a real collector exception if that is the explanation.
- No further changes are justified by this review's concrete evidence. Additional packet capture or collector metadata would resolve the remaining ambiguity more effectively than adding optional log families or increasing event volume.
