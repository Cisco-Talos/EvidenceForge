# Network Forensics Analyst - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 70

## Executive Summary

The network logs are high quality and mostly source-native, with convincing Zeek field structure, proxy behavior, TLS/X.509 handling, DHCP renewals, inbound scanning, and multi-sensor correlation. I judge the dataset synthetic because several patterns feel authored rather than naturally observed, especially mirrored DNS PTR/A behavior, templated malicious DNS vocabulary, and a very clean staged exfiltration chain.

## Evidence For Synthetic

- `zeek-dmz/dns.json` contains 52 PTR records; all had a same-origin A lookup for the same name/IP within roughly one second, with 25 PTRs occurring before the matching A lookup. Example: `2024-03-18T12:00:11.297678Z` PTR `120.161.230.54.in-addr.arpa -> fonts.carepoint.org`, followed at `12:00:11.369130Z` by A `fonts.carepoint.org -> 54.230.161.120`.
- Malicious-looking DNS names are highly template-like: `status-rbq4f1kr.tk`, `metrics-37nyymq4.top`, `cdn-check-tm4co9rs.top`, `lookup-7nmpnxxh.tk`, etc., queried to a small set of external DNS servers.
- `zeek-core/dns.json` shows 263 TXT queries from `10.10.2.30` to `*.ns1.westbridge-services.net` with generated-looking answer formats such as `x-c65:1:TOZvzUc`, `ok:0:5GQ3YOCPSTPROIF5`, and `srv.c64.2.dLpk5dzG06M`.
- The major exfiltration sequence is almost narratively perfect: `10.10.1.35 <- 10.10.2.20` SMB transfer of `313,518,759` bytes at `17:25:01Z`, then `10.10.1.35 -> 10.10.3.20` proxy CONNECT of `314,782,888` bytes at `17:25:28Z`, then `10.10.3.20 -> 45.33.32.30` TLS upload of `315,378,702` bytes at `17:25:30Z`.
- Proxy outbound DNS distribution is unusually even across public resolvers: `9.9.9.9` with 321 queries, `8.8.8.8` with 311, and `1.1.1.1` with 303.

## Evidence For Real

- Zeek field formats are mostly accurate: ICMP uses `id.orig_p=8`, `id.resp_p=0`; failed TCP scans use `S0`/`history=S`; HTTP `304` responses have zero body length; proxy failures have small byte counts.
- TLS behavior is especially convincing: TLS 1.3 records do not expose cert chains, while non-resumed TLS 1.2 records do; resumed TLS 1.2 sessions lack cert chains.
- Multi-sensor correlation looks plausible without being byte-identical. The same client-to-proxy flow appears in `zeek-core` and `zeek-dmz` with independent UIDs, close timestamps, and slightly different packet counts.
- The environment has believable background noise: DHCP renewals, Kerberos/LDAP/SMB, RDP/SSH sessions, Windows Update, Ubuntu/APT, OCSP, inbound internet scanning, proxy 407/502/503/504 failures, and web probes like `/phpmyadmin/`.
- The proxy sequence around `fonts.carepoint.org` is strong: internal CONNECT at `12:00:11Z`, proxy DNS immediately after, outbound TLS at `12:00:12Z`, and X.509 file extraction tied to the TLS UID.

## Detailed Analysis

The strongest realism signal is the proxy and TLS chain. In `zeek-dmz/http.json`, `10.10.2.30:52440 -> 10.10.3.20:8080` issues `CONNECT fonts.carepoint.org:443` at `2024-03-18T12:00:11.178011Z`. The proxy then performs DNS to `9.9.9.9`, opens TLS to `54.230.161.120:443`, logs SNI `fonts.carepoint.org`, and extracts two X.509 cert files. That sequence is source-native and well ordered.

The DNS subsystem is where the data starts to feel synthetic. PTR/A pairs are too consistently mirrored: every PTR I checked had an exact same-origin A counterpart within about one second. A reverse lookup before the forward lookup can happen with cache state, but seeing this repeatedly across internal and external domains suggests generation logic rather than resolver behavior.

The exfiltration story is coherent but too clean. The staged transfer from file server to workstation to proxy to external TLS host preserves size and timing in a way that is analytically excellent, but the handoff is unusually compact and lossless for hundreds of thousands of packets. I would not call it impossible, but it reads like a designed training narrative.

## Realism Score by Category

- **Field format accuracy:** 8 - Zeek schemas and protocol-specific fields are mostly correct.
- **Temporal patterns:** 7 - Workday bursts and long sessions are plausible, but the exfiltration timing feels staged.
- **Cross-source correlation:** 9 - Core/DMZ/proxy/TLS/X.509 relationships are strong and source-native.
- **Behavioral realism:** 7 - Good mix of benign and malicious behavior, with some templated DNS/C2 artifacts.
- **Environmental consistency:** 8 - Topology and service placement are coherent, though DNS resolver behavior is suspicious.

## Recommendations

- **P1:** Make PTR behavior less perfectly mirrored with A lookups; include PTRs with no nearby A match and avoid frequent PTR-before-A ordering.
- **P2:** Add more entropy to malicious DNS label grammar and TXT answer formats.
- **P2:** Loosen the exfiltration chain timing and packet accounting so large transfers show more natural delay, retries, or throughput variation.
- **P3:** Skew public resolver usage toward a primary resolver unless the environment explicitly models DNS load balancing.
- **P4:** Add more source-local quirks in proxy and DNS error behavior, such as varied response bodies, resolver cache effects, and inconsistent retry timing.
