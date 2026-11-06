# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 44

## Executive Summary

The visible network evidence is substantially production-like: protocol records have coherent parent flows, TLS authentication types agree with referenced certificate keys, and the explicit proxy path explains much of the HTTP traffic. A pervasive connection-history texture warrants scrutiny: every observed content-gap marker appears at the end of its history, usually after connection termination markers, with many very small gaps. This is a distribution concern rather than a demonstrated impossible network event; capture and reassembly behavior could explain it.

## Evidence For Synthetic

- [distribution_texture] All 1,289 sensor rows with positive `missed_bytes` have their `G`/`g` content-gap markers confined to a trailing suffix: 591 in `zeek-core/conn.json`, 44 in `zeek-db/conn.json`, and 654 in `zeek-dmz/conn.json`. Common histories are `ShADadfFG`, `ShADadfFg`, and `ShADadfFGg`; there are no intervening gap markers followed by further data or termination markers. For example, core line 21 has `history="ShADadfFG"`, `missed_bytes=1`, `orig_bytes=329`, and `resp_bytes=118` at `ts=1793624551.351920`; core line 23 has `ShADadfFg` and 15 missed bytes; DMZ line 9 has `ShADadfFG` and 28 missed bytes. The uniform placement across diverse services resembles a field augmentation applied after selecting an otherwise complete history. However, TCP reassembly can discover gaps during teardown, so I do not classify these rows as hard contradictions.
- [weak_signal] Small gap lengths reinforce that texture: 368 of those 1,289 sensor rows report only 1–7 missed bytes, including 67 reporting exactly one byte. This is possible with small application writes or sequence-space edge cases, but deserves packet-level confirmation before interpreting these values as organic packet loss. The sensor views overlap, so these are row counts, not 1,289 independent affected network sessions.

## Evidence For Real

- The explicit proxy relationship is concrete. `zeek-dmz/http.json:1` records a client CONNECT from `10.10.1.42:62846` to `10.10.3.20:8080`; `dns.json:1` then records the proxy resolving the requested hostname to `23.72.51.162`. `conn.json:6` records the proxy's separate upstream TLS connection to that address, and `ssl.json:1` uses the same UID and requested SNI. The DNS response timing fits before the upstream connection.
- Connection state diversity is credible rather than uniformly successful. Core contains 1,427 TCP `S0`, 134 `RSTO`, 86 `RSTR`, and 27 `REJ` rows alongside 4,697 TCP `SF` rows. DMZ contains 2,464 TCP `S0` rows, consistent with its visible inbound probing; `zeek-dmz/conn.json:1` is a no-response inbound SYN with zero response packets and bytes.
- DNS has meaningful protocol variety: core includes A, AAAA, PTR, SRV, TXT, NS, SOA, and MX queries, plus NXDOMAIN, SERVFAIL, and REFUSED responses. `zeek-core/dns.json:4` is a successful AAAA query without an address answer, a plausible IPv4-only internal name rather than a fabricated IPv6 address.
- TLS is internally coherent in the tested identity relationships. `zeek-dmz/ssl.json:50` negotiates `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` and references `FLOSP2hZeHkUS9Ji8q`; `x509.json:32` identifies an EC public key of length 256, with matching `cdn.newrelic.com` identity. Certificate signing by an RSA issuer is compatible with that EC leaf key.
- HTTP error/status semantics and payload accounting survived the checks described below; no invalid 304 response bodies or body lengths larger than their parent directional TCP byte totals were found in the checked records.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. The primary population consisted of the three Zeek sensors' `conn`, `dns`, `http`, `ssl`, `files`, and `x509` JSON records, with a representative proxy access row used to interpret the observation path. This was a bounded review, not an exhaustive reconstruction of every session, endpoint event, or IDS alert.

The conn populations are 11,853 core rows, 9,158 DMZ rows, and 452 DB rows. Their connection start times span approximately 2026-11-02 13:00–19:00 UTC. Six hours of observation cannot establish overnight patterns, weekend differences, or whether business-hour activity is representative.

### Connections, histories, and byte accounting

The sources distinguish protocol and service roles sensibly. Core is rich in DNS, Kerberos, LDAP, HTTP proxy, SMB, and internal TLS; the DB sensor is dominated by MySQL; DMZ contains substantial TLS and unsuccessful TCP probing. This makes the service mix interpretable without assuming that every sensor should see every platform's background protocol.

All checked conn rows satisfy the conservative minimum IPv4 packet-header accounting constraint: directional IP bytes are at least directional payload bytes plus 40 bytes per TCP packet or 28 per UDP/ICMP packet. This is a lower-bound check, not proof of packet-exact fidelity.

The gap-history pattern is the main concern. Core line 28, for example, is LDAP with `orig_bytes=1591`, `resp_bytes=35832`, `missed_bytes=322`, and `history="ShADadFfg"`. DB line 17 has MySQL, 62 missed bytes, and `ShADadfFg`. The same suffix placement appears across different payload sizes, termination shapes, services, and sensors. It could reflect reassembly gaps flushed at close, but the absence of any gap followed by later observable activity limits the apparent diversity of capture failure behavior. I cannot establish a collector defect without packet data and Zeek capture/reassembly settings.

Short SSH and RDP `SF` rows are not automatically successful authenticated sessions. For example, core line 2799 has only 60 originator bytes, 681 responder bytes, and 0.253550-second duration on TCP/22. That can be a banner/protocol probe with an orderly close. I did not penalize such rows or infer missing endpoint logins from them.

### DNS and explicit proxy timing

Every DNS, HTTP, and SSL row in these three sensor families references an available conn UID, and its timestamp lies within that conn's start/duration interval with a 1-millisecond tolerance. This supports coherent observation timing; matching completeness itself does not determine authenticity.

The first DMZ DNS query has `ts=1793624490.729597` and `rtt=0.086179`, yielding response time approximately `1793624490.815776`. The upstream connection in DMZ conn line 6 starts at `1793624490.826235`, about 10.459 milliseconds later, and its SSL observation occurs at `1793624491.182604`. The client's CONNECT request timestamp precedes the DNS result, which is reasonable: the proxy can resolve after receiving the request. HTTP's logged request time does not itself specify when the 200 response arrived.

There is a plausible split between authoritative internal answers and external recursion. Repeated authoritative DC A answers retain TTL 300 in the groups checked, while internal monitoring-name answers retain TTL 1800. Domains and public mappings may have been sanitized, so I did not evaluate authenticity from real-world DNS ownership.

### HTTP, TLS, and files

Of 2,078 core HTTP rows, 1,778 are successful CONNECTs, with additional 403/407/502/503/504 CONNECT outcomes. These are control exchanges for TLS tunnels, so the raw HTTP row count should not be read as a modern network predominantly browsing plaintext HTTP. The visible proxy access example explicitly distinguishes CONNECT control-message bytes from tunnel bytes.

There were no nonzero bodies on HEAD/204/304/1xx records in the HTTP families checked. For the first 500 HTTP and files rows per sensor, or all rows where fewer were present, body/file `seen_bytes` did not exceed the matching parent flow's directional payload total. This does not verify aggregate multi-file accounting or encrypted payload interpretation.

DMZ TLS is mostly TLS 1.3, with a TLS 1.2 tail. Internal/DB TLS has more TLS 1.2 and CBC suites, compatible with legacy internal applications; without software inventory I do not score this as an authenticity defect. Across certificate-linked TLS rows, the checked ECDSA suites reference EC leaf keys and RSA suites reference RSA keys. Repeated certificate fingerprints also retain consistent certificate/SAN metadata across the supplied x509 views. I did not demand TLS 1.3 certificate visibility from passive encrypted traffic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Zeek conn histories | All 1,289 positive-missed-byte sensor rows have only trailing gap markers | Main reason the score remains in the mixed/inconclusive band; compatible collector/reassembly explanations prevent a synthetic verdict |
| weak_signal | Zeek conn loss metadata | 368 affected sensor rows have 1–7 missed bytes; 67 have one byte | Adds modest concern about capture-loss texture; overlapping views and possible short writes limit weight |

## Realism Score by Category

- **Field format accuracy:** 9 — Coherent JSON types, protocol/status semantics, and conservative packet accounting in the checks performed.
- **Temporal patterns:** 8 — Protocol observations fit flow intervals and the sampled DNS/proxy/TLS sequence; teardown-only gap texture remains unusual.
- **Cross-source correlation:** 9 — Proxy legs, protocol UIDs, file byte bounds, and certificate identities agree in the checks performed.
- **Behavioral realism:** 8 — Credible service/state diversity and proxy failures; six hours limits broader rhythm assessment.
- **Environmental consistency:** 9 — Sensor-specific service mixes and explicit proxy routing form a plausible network observation model.

## Recommendations

- If this were synthetic, model content-gap placement and sizes from concrete TCP capture/reassembly behavior. Include cases where an acknowledged hole is exposed before later traffic, when the modeled packet sequence calls for them, rather than always appending `G`/`g` after the rest of the history.
- Validate tiny missed-byte values against an actual packet/reassembly trace for representative small HTTP, syslog, and MySQL exchanges. Retain small gaps when supported; do not replace them mechanically with a fixed MTU-sized loss model.
- Preserve the demonstrated DNS-before-upstream-connection timing, separation of proxy client and server legs, correct certificate-key authentication relationships, and source-native HTTP body semantics.
