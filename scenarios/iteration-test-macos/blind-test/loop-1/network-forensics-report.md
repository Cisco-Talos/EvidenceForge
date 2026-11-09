# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 64

## Executive Summary

The network evidence is substantially production-like: protocol identities, certificate relationships, DNS variety, transport states and SSH ordering are generally coherent. My qualified synthetic verdict rests mainly on repeated TLS transport counters that fit a minimal TCP exchange but appear too small for the full, non-resumed TLS 1.2 handshakes recorded on the same UIDs. This is a probable protocol/transport modeling artifact, not a proven impossibility under every capture implementation; TCP Fast Open and undocumented counter transformations remain alternatives without packets or collector configuration.

## Evidence For Synthetic

- **[contract_gap] P2 — Repeated apparent TLS handshake/packet-budget mismatch.** Across the three sensors, 77 distinct TCP tuples have all of: `ssl.version="TLSv12"`, `established=true`, `resumed=false`, `conn.orig_pkts=4`, `conn.history="ShADadfF"`, and `missed_bytes=0`. These comprise 5 core and 72 DMZ observations out of 736 established, non-resumed TLS 1.2 observations. For example, `zeek-core/conn.json:102`, UID `Cbyiy35UOODL2R3B0D`, at **2026-11-02 13:05:43.381954 UTC**, gives four originator packets for `10.10.2.30:51838 → 10.10.2.40:443`; `zeek-core/ssl.json:2` records a full `CsxknGIi` handshake. In an ordinary TCP exchange, the observed SYN, pure ACK, ClientHello, later ClientKeyExchange flight, and originator FIN following responder FIN already require at least five client packets. The principal qualification is that ClientHello could have traveled in a TCP Fast Open SYN, which Zeek's history implementation does not mark as `D`; see Detailed Analysis. This repeated issue carries nearly all of the score increase.
- **[weak_signal] P4 — Mobile browser identity concentrated on a native Mac address.** Of 707 proxy rows from `10.10.1.41`, 641 advertise `Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148`, while endpoint records identify `MAC-MROSS-01` and show native macOS process paths. `PROXY-01.meridianhcs.local/proxy_access.log:351-352` at **13:39:28 UTC** associates this UA with `maya.ross`, tunnel `PT-ce50cc39c7c55135`, and client source port `58955`; `MAC-MROSS-01.meridianhcs.local/ecar.json:56` observes that exact client tuple to the proxy. Mobile emulation, an overridden UA, or another application using that UA are viable real explanations. The FLOW has no process identity, so this does not establish that a specific desktop browser emitted it, and it receives only negligible weight.

## Evidence For Real

- **Broad protocol coherence.** All 4,062 DNS, 5,105 HTTP and 3,142 SSL observations have a matching connection UID within their own sensor; their four-tuples agree and their event timestamps fall within the associated connection intervals using a 1 ms comparison tolerance. The same checks pass for all 67 core SMTP observations. Complete matching is treated as supporting coherence, never as a synthetic tell.
- **Believable transport diversity.** The 22,400 connection observations contain successful, rejected, reset, partial and unanswered traffic. Core TCP counts include 5,013 `SF`, 1,448 `S0`, 154 `RSTO`, 75 `RSTR`, 46 `REJ`, and 27 `OTH`; DMZ contains 5,639 `SF`, 2,449 `S0`, 107 `RSTO`, 57 `RSTR`, 45 `REJ`, and 10 `OTH`. Checked `OTH` histories lack a SYN, rejected histories are `Sr`/`Srr`, and all TCP `SF` histories include both FIN directions.
- **DNS is not limited to successful A lookups.** Core DNS contains A, AAAA, PTR, SRV, TXT, MX, SOA and NS records; its response distribution includes 206 `NXDOMAIN`, 14 `SERVFAIL`, and 8 `REFUSED`. For 244 repeated authoritative groups holding client, resolver, name, qtype and answer constant, TTL values remain stable. That stability contradicts a simple per-record random-TTL hypothesis.
- **TLS/certificate relationships hold up.** There are 1,973 TLS 1.3 and 1,167 TLS 1.2 observations, plus two without a negotiated version. Resumed sessions do not acquire certificate chains; certificate references resolve; checked leaf validity periods cover the connection time; ECDSA cipher suites use ECDSA leaf keys; adjacent chain subject/issuer names agree; repeated fingerprints do not change certificate metadata.
- **SSH has meaningful endpoint ownership and temporal order.** Thirty-nine matched successful SSH LOGIN observations occur 6.055–14.586 seconds after a matching Zeek transport open and before its close. In a native Mac-to-Mac example, a zsh child execs `/usr/bin/ssh` before the TCP connection, the receiver builds its SSH process chain before authentication, and the source process exits after the transport close. These are actual distinct process/exec/session relationships, not merely hostname matches.
- **File bytes have credible transport bounds.** No tested individual or aggregate complete file payload exceeds the associated directional TCP byte count. Checks cover the available HTTP, SSL, SMB and SMTP file families; five files with an absent connection UID are excluded from that bound rather than silently treated as matched.

## Detailed Analysis

### Scope and method

I read only the supplied instructions and records under `/private/tmp/log-study-9lowe06w/data`, and wrote analysis scripts/results under the assigned network-forensics work directory. JSON files were parsed with Python standard-library code, aggregates were computed over whole network files, and output examples were bounded. No embedded commands were executed and no observed address, domain or URL was contacted. Public primary documentation was consulted only for the disputed Zeek/TLS interpretation.

All times below are UTC on 2026-11-02. The connection slice spans approximately **13:00–19:00**. Connection counts are sensor observations, not deduplicated enterprise flow totals:

| Sensor | conn | DNS | HTTP | SSL | files | x509 |
|---|---:|---:|---:|---:|---:|---:|
| zeek-core | 12,364 | 3,099 | 2,416 | 315 | 684 | 179 |
| zeek-dmz | 9,621 | 925 | 2,664 | 2,817 | 1,789 | 1,125 |
| zeek-db | 415 | 38 | 25 | 10 | 15 | 10 |

I also reviewed proxy records, ASA message families, bounded Snort examples, eCAR flow/process/session relationships, and the two Mac hosts' native Endpoint Security and Unified Log records where they explain network ownership.

### Main finding: packet counts and full TLS handshakes

The reproducible selector is:

```text
join same-sensor ssl.json to conn.json by uid
ssl.version == "TLSv12"
ssl.established is true
ssl.resumed is false
conn.orig_pkts == 4
conn.history == "ShADadfF"
conn.missed_bytes == 0
```

It selects **77 observations and 77 distinct four-tuples**: core 5, DMZ 72, DB 0. The denominator of established, non-resumed TLS 1.2 observations is 96 core + 635 DMZ + 5 DB = 736. I used this narrow selector rather than treating every small TLS flow as defective.

Two representative cases are:

| Evidence | Tuple and time | Recorded fields |
|---|---|---|
| `zeek-core/conn.json:102`, `ssl.json:2`, UID `Cbyiy35UOODL2R3B0D` | `10.10.2.30:51838 → 10.10.2.40:443`, 13:05:43.381954 | `orig_pkts=4`, `orig_bytes=898`, `resp_pkts=33`, `resp_bytes=42710`, `SF`, `ShADadfF`, no gaps; full TLS 1.2 `CsxknGIi`, RSA/ECDHE AES-GCM; SSL timestamp 13:05:43.546800 |
| `zeek-dmz/conn.json:9`, `ssl.json:5`, UID `CvmM76Za062THlo2pGW` | `98.0.64.32:62501 → 10.10.3.10:443`, 13:03:42.464213 | `orig_pkts=4`, `orig_bytes=695`, `resp_pkts=19`, `resp_bytes=18992`, `SF`, `ShADadfF`, no gaps; full TLS 1.2 `CsxknGIi`; SSL timestamp 13:03:42.790656 |

Zeek documents `A` as a pure ACK and packet counters as packet counts, while TLS 1.2 full negotiation has a ClientHello flight and a subsequent ClientKeyExchange/Finished flight separated by a server response. Thus an ordinary exchange with the displayed responder-first FIN order has a lower bound of SYN + pure ACK + two separate client payload flights + the later client FIN. Packet coalescing can combine messages within a flight but cannot combine the two client flights across the required server response. [Zeek Conn::Info](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html), [TLS 1.2 RFC 5246, §7.3](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.3).

**Why this is qualified rather than labeled a hard contradiction:** Zeek's TCP history implementation chooses the SYN/FIN flag instead of `D` when such a packet also carries payload. A TCP Fast Open SYN carrying ClientHello could therefore conserve a packet and leave a superficially ordinary history. The supplied logs do not expose TCP options. SSL detection timestamps are later than connection start in the examples, which favors ordinary post-open ClientHello, but analyzer attachment/reassembly behavior prevents me from using that timing alone as a categorical exclusion of Fast Open. Likewise, a downstream exporter could have transformed counters. [Zeek TCP history implementation](https://github.com/zeek/zeek/blob/master/src/packet_analysis/protocol/tcp/TCPSessionAdapter.cc), [Zeek SSL timestamp initialization](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/ssl/main.zeek).

The repeated family across internal service traffic and external web traffic makes a simplified packet-budget calculation more likely to me than an exceptional exchange explanation for every selected case. That is an inference from the records, not proof of the generation mechanism. A packet capture or a known collector-counter transformation could materially change this judgment.

### Connection states, accounting and protocol mix

Minimum IP-header/payload accounting checks find no directional byte underflow. There are no overlapping same-sensor TCP connections using the identical four-tuple with distinct start times. The state/history checks are largely sensible: all 44 TCP `OTH` observations across the sensors use midstream histories such as `DAd`, `DdA` and `ADad`, rather than asserting a visible handshake. S2/S3 histories use the appropriate one-sided FIN direction.

Service placement is plausible from the observed addresses. Core traffic includes DNS, Kerberos, LDAP, SMB, syslog and HTTP proxy connections; the DB sensor is dominated by MySQL (269 service-tagged connections), with some SSH and administrative traffic. DMZ includes public-facing HTTPS and a proxy's external connections. Core SSH durations range from about 0.068 seconds to 13,346 seconds, giving both short failures and long sessions; DB MySQL durations range from about 0.010 seconds to 28.527 seconds.

The hourly observation counts are not flat. Core counts for 13–18 UTC are 1,790, 3,084, 1,762, 1,763, 2,035 and 1,930; DMZ counts are 1,675, 2,652, 1,275, 1,238, 1,259 and 1,522. A six-hour daytime slice cannot establish weekday/weekend or overnight behavior, so I do not penalize absent overnight evidence.

The apparent volume of cleartext HTTP needs the proxy context. There are 2,134 core and 2,181 DMZ HTTP `CONNECT` observations; these are tunnel control exchanges rather than proof that the corresponding application traffic was cleartext. Proxy records distinguish `proxy_action=tunnel` from `tunnel-setup ssl_bump=peek` and decrypted `ssl-inspect ssl_bump=bump` rows, and separate CONNECT control bytes from tunnel bytes. This makes the HTTP/HTTPS mix substantially more credible than a raw HTTP-row count suggests.

ASA records include 7,686 TCP builds and 7,681 TCP teardowns, 953 UDP build/teardown pairs, 2,395 dynamic translation build/teardown pairs, and 422 denied packets. I do not treat the five unequal TCP build/teardown counts as a defect: sessions may cross the slice boundary. The first observed failed inbound SYN has an ASA SYN-timeout teardown after 30 seconds and a Zeek `S0` observation without fabricated response payload, which is coherent.

### DNS and certificate texture

Core DNS type counts are A 2,255; AAAA 261; PTR 160; SRV 103; TXT 299; MX 10; SOA 7; NS 4. Internal authoritative responses and external recursive responses differ in AA flags and response timing. There are successful empty AAAA responses, reverse records, service-location records, external failures and varied TTLs. The answer and TTL arrays have matching lengths throughout.

A preliminary suspicion that PTR/SRV TTLs were independently randomized did not survive grouping: every repeated authoritative fixed client/resolver/name/type/answer group retained its TTL values. I therefore exclude that hypothesis from the synthetic score. DNS may be cached or queried outside the slice, so absence of a fresh DNS lookup before an individual connection is not counted as a causal failure.

TLS versions and ciphers form a reasonable mixed environment. The DB sensor's ten SSL observations use TLS 1.2 and RSA suites; DMZ has a larger TLS 1.3 share and both RSA and ECDSA leaf keys. No resumed session has an attached certificate chain in these records. All referenced chain FUIDs resolve to x509 rows, checked validity periods contain the SSL observation time, and stable fingerprints retain the same subject, issuer, serial and other certificate metadata. Domains and IP ownership were not tested against public resolution because sanitization is explicitly allowed.

### SSH and native Mac relationships

The Mac endpoints are assessed as native Endpoint Security/eCAR/Unified Log sources, not inferred from the network sensor alone.

For `10.10.1.41:63687 → 10.10.1.42:22`:

1. `MAC-MROSS-01.../macos_endpoint_security.ndjson:44-45` records zsh PID `42173` forking PID `51591` at **14:24:10.216737**, followed by the same child execing `/usr/bin/ssh` at **14:24:10.227493**. PID version advances from 49 to 50; this is one process lifetime with an exec transition.
2. `zeek-core/conn.json:2505`, UID `Coj3WFJnElPQ0jmo7o`, opens at **14:24:21.075928**, with duration **638.367366** seconds and `SF` transport state.
3. `MAC-MROSS-02.../macos_endpoint_security.ndjson:60-65` shows PID `30016` progress from launchd child through xpcproxy, sshd-keygen-wrapper, sshd and sshd-session around **14:24:26.016–26.199**. Its POSIX session changes as the process sets up service context; I do not conflate that with the audit session identifier.
4. `MAC-MROSS-02.../macos_unified_log.ndjson:2` records SSH acceptance at **14:24:27.825271** for `maya.ross` from `10.10.1.41 port 63687`; its eCAR LOGIN follows at **14:24:28.515**.
5. Transport close is about **14:34:59.443294**; the source's native SSH exit is **14:35:00.304340** (`macos_endpoint_security.ndjson:46`). The source client therefore survives the visible transport.

Across all hosts, no actor-linked eCAR FLOW occurs more than five seconds outside a visible owning process lifetime under the checked same-object identity join. I used that tolerance to avoid turning small source observation delays into alleged process/network contradictions. The Unified Log policy message concerning another Mac process is not used to infer an authorization denial or prevent execution.

### Localized linkage limitation excluded from scoring

Core SMB UID `CfwamgYPNpASbWX3cXo` has one mapping, ten SMB file-action rows and five files rows, but no core conn row for its UID or exact tuple `10.10.1.35:52840 → 10.10.2.20:445`. For example, `zeek-core/smb_mapping.json:94` is at **18:01:11.710142**, and `files.json:594` carries that connection UID for a 4,928,307-byte PDF. This limits reconstruction, but an unclosed connection, selective conn logging or dropped export could explain it. I assign no synthetic-score penalty merely for this absent companion without a demonstrated within-window close or contradictory collection guarantee.

## Synthetic Indicator Summary

| Priority | Category | Affected source family | Scope | Score impact and qualification |
|---|---|---|---|---|
| P2 | `contract_gap` | Zeek conn + SSL | 77 distinct tuples: 5 core, 72 DMZ; 77/736 established non-resumed TLS 1.2 observations | Dominant reason for a likely-synthetic score: four-packet originator budgets appear inconsistent with ordinary full-handshake and responder-first close semantics. Fast Open or transformed counters remain unresolved alternatives; not labeled universally impossible. |
| P4 | `weak_signal` | Proxy + Mac endpoint context | 641/707 proxy rows from `10.10.1.41` use an iPhone UA | Negligible weight: reproducible platform/UA contrast, but spoofing/emulation is entirely possible and the exact FLOW lacks owning PID. |

The isolated SMB reference limitation is excluded from this table's scored indicators. No score is based on narrative compactness, attack linearity, complete matching, sanitized domain ownership, missing selected Sysmon types, absent overnight records, or thin coverage by itself.

## Realism Score by Category

- **Field format accuracy:** 8 — JSON shapes, native field values and most accounting relationships are credible; the TLS packet budgets are the principal semantic reservation.
- **Temporal patterns:** 8 — Variable volumes, sensible connection/protocol timing and correctly ordered SSH examples; the slice is too short for broad diurnal claims.
- **Cross-source correlation:** 7 — UID/tuple/certificate/file relationships are strong, but the full-handshake versus transport-counter issue is consequential.
- **Behavioral realism:** 8 — Proxy, browsing, internal service and long-lived administrative traffic coexist plausibly; the mobile UA deserves contextual explanation.
- **Environmental consistency:** 8 — Sensor/service placement and mixed endpoint platforms are coherent, with no demonstrated role impossibility.

## Recommendations

If this were synthetic, these changes would improve realism:

- Derive TCP packet counts from the actual TLS handshake flights and close ordering, including necessary pure ACKs and additional data flights. Check the 77 selected cases against an ordinary full TLS 1.2 packet trace; if Fast Open is intentional, preserve enough observable option/collector context to establish that interpretation.
- Keep packet counters, connection history and protocol handshake history consistent under retransmission, packet coalescing, capture gaps and resumption. A payload-size formula alone should not erase required protocol exchanges.
- Tie browser UA behavior to the actual endpoint/application behavior. If the Mac's mobile UA is intentional emulation, preserve accurate application evidence; otherwise use the browser/platform identity supported by the owning process.

For real data, the highest-value follow-up would be a small packet sample or collector counter specification for the two cited TLS UIDs. That would test the main inference directly and could substantially reduce the synthetic-confidence score without requiring broader source coverage.
