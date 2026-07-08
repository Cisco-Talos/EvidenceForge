# Network Forensics Analyst - Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 62
**Synthetic-Confidence Score:** 26

## Executive Summary

The network telemetry is internally coherent across Zeek, ASA, Snort, proxy, web, DNS, TLS, SMTP, and DHCP sources. I found weak synthetic texture in the neat six-hour window and some repeated palettes, but no hard source-native contradictions or impossible protocol ordering.

## Evidence For Synthetic

- `weak_signal`: Zeek core spans almost exactly 12:00:23-18:00:22 UTC and Zeek DMZ spans 12:01:39-18:00:25 UTC, which is a tidy slice but not by itself invalid.
- `distribution_texture`: HTTP CONNECT and TLS traffic reuse a small enterprise-like set of user agents, ciphers, and popular domains; plausible for a managed environment, but somewhat clean.
- `weak_signal`: Some suspicious DNS tunnel labels under `ns1.westbridge-services.net` look intentionally structured, but their TXT/NXDOMAIN/SERVFAIL mix and timing remain plausible.

## Evidence For Real

- Zeek UID fan-out is consistent: DNS/HTTP/SSL/SMTP rows all reference existing `conn.json` UIDs with sensible timestamp deltas.
- ASA/Snort/Zeek NAT alignment is realistic: Snort alert `185.70.41.45:61074 -> 203.14.220.10:443` at `12:32:24.358` aligns with Zeek DMZ `185.70.41.45:61074 -> 10.10.3.10:443` at `12:32:24.248`.
- DHCP renewals show stable MACs and jittered half-lease behavior, e.g. `10.10.1.32` renews a 3600s lease with gaps around 1647-1933s.
- DNS contains realistic enterprise noise: WPAD/ISATAP NXDOMAIN, AD SRV lookups, PTR lookups, split-horizon mail answers, and mixed TTLs.
- TLS/x509/OCSP show realistic diversity: TLS 1.2/1.3, resumed and full sessions, certificate chains, OCSP HTTP file artifacts, and repeated intermediates.
- Web logs show normal browser asset waterfalls, cache statuses, health checks, and Nikto-style scanning rather than a single scripted path.

## Detailed Analysis

Zeek core traffic is dominated by DNS, Kerberos, HTTP proxy, SMB, LDAP, DHCP, SSH, SMTP, and RDP, which matches an internal enterprise sensor. Zeek DMZ adds external HTTPS, scan noise, proxy egress, and public-facing web traffic. Connection states and byte counters generally match service expectations, including S0 scan probes with zero response bytes and UDP DNS/DHCP with normal 28-byte overhead.

Explicit proxy behavior is coherent. For example, `zeek-core/http.json` shows `10.10.1.22 -> 10.10.3.20:8080 CONNECT media.licdn.com:443` at `12:02:45`, followed by `zeek-dmz/ssl.json` showing `10.10.3.20 -> 13.107.45.52:443` with SNI `media.licdn.com` at `12:02:52`. The client-proxy connection duration covers the later upstream flow.

The suspicious DNS sequence from `10.10.2.30` under `ns1.westbridge-services.net` uses TXT queries, short TTLs, varied labels, and mixed `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`. That is suspicious activity, but not a synthetic authenticity defect.

## Synthetic Indicator Summary

| Category | Source Family | Scope | Impact |
|---|---|---:|---|
| `weak_signal` | Zeek timing | Dataset-wide | Low |
| `distribution_texture` | HTTP/TLS/DNS | Repeated palettes | Low |
| `weak_signal` | DNS tunnel labels | Suspicious sequence | Low |

## Realism Score by Category

- **Field format accuracy:** 88 - Zeek, ASA, Snort, proxy, web, DNS, TLS, and SMTP fields are source-native and mostly coherent.
- **Temporal patterns:** 82 - DHCP, proxy, IDS, web, and scan timing are plausible, despite a tidy collection window.
- **Cross-source correlation:** 91 - NAT, UID fan-out, proxy, TLS, OCSP, and IDS relationships line up.
- **Behavioral realism:** 85 - Enterprise baseline, web browsing, SMTP, scanning, and DNS tunnel activity have believable texture.
- **Environmental consistency:** 87 - Internal roles, split DNS, DMZ exposure, proxy egress, and domain-controller services are consistent.

## Recommendations

- Add more messy long-tail TLS and HTTP client diversity if this is synthetic; the visible user-agent and cipher palettes are plausible but slightly tidy.
- Preserve the strong Zeek/ASA/Snort NAT alignment; it is one of the most production-like aspects of the dataset.
- If synthetic, vary collection boundaries and include more partial in-flight sessions near start/end to reduce the neat six-hour-window feel.
