# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 66  
**Synthetic-Confidence Score:** 56

## Executive Summary

The network telemetry is mostly production-like: Zeek, ASA, Snort, proxy, and web logs have plausible formats, varied failure states, and strong cross-source timing. I found one repeated proxy/DNS/TLS contract gap around `mail-fin.meridianhcs.com` that leans synthetic, but it is isolated enough that I would not call the whole dataset definitively synthetic.

## Evidence For Synthetic

- **contract_gap:** The proxy repeatedly resolves `mail-fin.meridianhcs.com` to internal `10.10.2.27`, then seconds later opens outbound TLS to `54.230.228.12` with the same SNI. Example: DNS at `12:19:39.569Z` returns `answers:["10.10.2.27"]` from `10.10.3.20` in [zeek-dmz/dns.json:107](/private/tmp/research-data-40617/dataset/zeek-dmz/dns.json:107), followed by TLS from `10.10.3.20:46060` to `54.230.228.12:443` with `server_name:"mail-fin.meridianhcs.com"` at `12:19:42.972Z` in [zeek-dmz/ssl.json:71](/private/tmp/research-data-40617/dataset/zeek-dmz/ssl.json:71).
- **contract_gap:** This repeats, not a one-off: matching mismatches occur at [zeek-dmz/dns.json:171](/private/tmp/research-data-40617/dataset/zeek-dmz/dns.json:171) → [zeek-dmz/ssl.json:208](/private/tmp/research-data-40617/dataset/zeek-dmz/ssl.json:208), [zeek-dmz/dns.json:197](/private/tmp/research-data-40617/dataset/zeek-dmz/dns.json:197) → [zeek-dmz/ssl.json:319](/private/tmp/research-data-40617/dataset/zeek-dmz/ssl.json:319), and [zeek-dmz/dns.json:250](/private/tmp/research-data-40617/dataset/zeek-dmz/dns.json:250) → [zeek-dmz/ssl.json:510](/private/tmp/research-data-40617/dataset/zeek-dmz/ssl.json:510).
- **contract_gap:** ASA confirms the proxy really egressed to `54.230.228.12:443`, e.g. [fw-perimeter/cisco_asa.log:756](/private/tmp/research-data-40617/dataset/fw-perimeter/cisco_asa.log:756), so this is not only an SSL-log labeling artifact.
- **weak_signal:** The `mail-fin` proxy access entries show normal `CONNECT mail-fin.meridianhcs.com:443` requests, e.g. [PROXY-01/proxy_access.log:99](/private/tmp/research-data-40617/dataset/PROXY-01.meridianhcs.local/proxy_access.log:99), but the downstream origin path does not honor the visible DNS answer.

## Evidence For Real

- ASA and Zeek align naturally for NATed inbound scans: ASA logs public `203.14.220.10:3389` NATing to `10.10.3.10:3389` in [fw-perimeter/cisco_asa.log:1](/private/tmp/research-data-40617/dataset/fw-perimeter/cisco_asa.log:1), and Zeek sees the corresponding private-side S0 in [zeek-dmz/conn.json:1](/private/tmp/research-data-40617/dataset/zeek-dmz/conn.json:1).
- Snort alerts match Zeek packet evidence with plausible sub-second offsets: [snort_alert.log:2](/private/tmp/research-data-40617/dataset/snort-perimeter/snort_alert.log:2) maps to Zeek `185.70.41.45:61074 -> 10.10.3.10:443` in [zeek-dmz/conn.json:605](/private/tmp/research-data-40617/dataset/zeek-dmz/conn.json:605).
- Zeek protocol UID integrity is strong: DNS/HTTP/SSL/files/SMTP/NTP UIDs all resolved to conn rows in the checked Zeek logs, with matching tuples and no packet-byte impossibilities.
- DNS has realistic texture: mixed `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`; A/AAAA/PTR/TXT/SRV traffic; varied TTLs; and internal/external authoritative flag differences.
- TLS and web traffic look source-native: TLSv1.2/TLSv1.3 mix, resumed and non-resumed sessions, realistic cipher spread, inbound web scans, 404/403/429/500 responses, and varied user agents.

## Detailed Analysis

The strongest synthetic-leaning issue is the explicit proxy path. `10.10.3.20` asks DNS for `mail-fin.meridianhcs.com`; the visible resolver answer is private `10.10.2.27`, yet the proxy opens TCP/TLS to public `54.230.228.12`. For a CONNECT proxy, absent visible evidence of an alternate resolver or parent proxy, the origin destination should follow the resolver result.

This mismatch is narrow: other proxy-origin TLS/HTTP flows generally had DNS answers containing the destination IP. I found 9 near-time DNS/TLS mismatches under 30 seconds, all for `mail-fin.meridianhcs.com`; I found no Zeek DNS answer to `54.230.228.12` in either `zeek-core/dns.json` or `zeek-dmz/dns.json`.

Outside that, the network data is convincing. ASA TCP/UDP lifecycles have plausible missing-at-window-edge connections, SYN timeouts, resets, and FINs. Zeek conn states include realistic `SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `S1/S2/S3`, and `OTH` distribution. Snort scan alerts correspond to Zeek-visible flows rather than floating independently.

## Synthetic Indicator Summary

| Category | Source family | Scope | Score impact |
|---|---|---:|---:|
| contract_gap | Zeek DNS/SSL + ASA + proxy | 9 repeated `mail-fin` proxy-origin sessions | High |
| weak_signal | Proxy access | CONNECT control logs do not explain alternate resolution path | Low |
| realism counterweight | Zeek/ASA/Snort/proxy/web | Broad source-native consistency elsewhere | Lowers score |

## Realism Score by Category

- **Field format accuracy:** 8/10 — Zeek, ASA, Snort, proxy, and web fields are source-native and internally well formed.
- **Temporal patterns:** 8/10 — Sensor offsets, DHCP renewals, scans, and web activity have realistic jitter.
- **Cross-source correlation:** 7/10 — Strong overall, but the `mail-fin` proxy DNS/TLS path is a notable exception.
- **Behavioral realism:** 8/10 — Traffic mix, scan noise, proxy use, DNS failures, and TLS behavior are plausible.
- **Environmental consistency:** 6/10 — Internal DNS naming is coherent except for the repeated `mail-fin` public-IP proxy egress.

## Recommendations

- Make proxy-origin destination selection follow visible DNS evidence: either resolve `mail-fin.meridianhcs.com` to `54.230.228.12`, or send the proxy-origin TLS/ASA flow to `10.10.2.27`.
- If split-horizon or an alternate resolver is intended, add source-visible evidence for that resolver path or parent proxy behavior.
- Preserve the existing Zeek/ASA/Snort timing and state texture; it is one of the dataset's strongest realism features.
