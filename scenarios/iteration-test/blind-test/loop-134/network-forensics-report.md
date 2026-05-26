# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 72

## Executive Summary

This dataset has strong network realism: Zeek UID integrity, proxy-to-TLS sequencing, TLS 1.3 certificate visibility behavior, DNS noise, DHCP renewals, and public scan traffic all look plausible. I still assess it as synthetic because duplicated cross-sensor SSH flows show a repeated, mechanically exact `+0.750000s` duration delta that is difficult to explain as real packet observation across many unrelated sessions.

## Evidence For Synthetic

- `/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/data/zeek-core/conn.json` and `/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/data/zeek-dmz/conn.json` contain 65 duplicated SSH flows where the DMZ duration is exactly core duration `+ 0.750000` seconds while bytes are identical.
- Example: core UID `Coho0GqOHnO8eTeYB5` at `2024-03-18T12:01:32.024294Z`, `10.10.1.99:56949 -> 10.10.3.10:22`, duration `893.395670`, bytes `32297/108935`; DMZ UID `CcPuQae8qrRybhWFtI`, same tuple, duration `894.145670`, same bytes.
- Same pattern repeats at `12:06:55Z`, `12:11:26Z`, `12:16:00Z`, and `12:18:58Z` across different clients and destinations. A fixed 750 ms observation delta across independent SSH sessions is more consistent with generated multi-sensor modeling than real Zeek sensors.
- Kerberos is unusually cleanly represented as TCP-only on `/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/data/zeek-core/conn.json`: `1120` port-88 connections, all TCP, no UDP Kerberos observed. This is possible by policy, but atypically tidy for a Windows enterprise slice.

## Evidence For Real

- Zeek UID/reference integrity is source-native and coherent: every `dns`, `http`, `ssl`, `dhcp`, and `files.conn_uids` reference resolves to a matching `conn.json` UID; HTTP `resp_fuids` resolve into `files.json`; TLS cert FUIDs resolve into `files.json` and `x509.json`.
- TLS behavior is realistic: TLS 1.3 records generally lack certificate chains, while non-resumed TLS 1.2 records have visible `cert_chain_fuids`. Example: DMZ SSL UID `CXLdbZC5Ejw0DruPP2` at `2024-03-18T12:05:16.969902Z` has TLS 1.2, cipher `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, and a matching `edge.loadbalance.com` certificate.
- Proxy sequencing looks natural. `/zeek-core/http.json` UID `CFIcfX5RLynAyACm8g` records a `CONNECT pypi.org:443` from `10.10.2.30` to `10.10.3.20:8080` at `12:00:19Z`; `/zeek-dmz/ssl.json` UID `CO3h8BlazMFoxMKkLY` then shows `10.10.3.20 -> 151.101.0.223:443`, SNI `pypi.org`, at `12:00:20Z`.
- DNS noise is plausible: WPAD/ISATAP/local suffix leakage, internal A/AAAA/PTR lookups, and a burst of suspicious TXT lookups to `westbridge-services.net` from `10.10.2.30` between `16:45:23Z` and `17:45:00Z`.
- Public exposure noise is credible: `/zeek-dmz/conn.json` shows many inbound `S0` scans to `10.10.3.10` across ports `22`, `23`, `25`, `80`, `443`, `445`, `3389`, and `8080`.

## Detailed Analysis

The strongest realism is in protocol layering. Proxy CONNECT flows, outbound TLS flows, DNS answers, TLS SNI, X.509 subjects/SANs, and HTTP/file records line up cleanly without source-native contradictions. The dataset also avoids a common synthetic mistake around TLS 1.3: passive Zeek generally cannot extract encrypted server certificates for TLS 1.3, and these logs mostly reflect that.

The suspicious artifact is the duplicated SSH timing across the core and DMZ sensors. Two Zeek sensors can absolutely observe the same flow with different UIDs, near-identical byte counts, and slight timestamp offsets. What stands out is the exact `0.750000` second duration extension repeated 65 times across unrelated SSH sessions and multiple host pairs, while byte counts remain identical. Real sensor placement, routing latency, and TCP teardown visibility would not usually produce a constant three-quarter-second duration delta at microsecond precision across that many flows.

The behavioral content itself is plausible: internal SMB/Kerberos/LDAP, web browsing, proxy egress, OCSP, external scans, and DNS tunneling-style TXT activity all fit a believable enterprise investigation window. My verdict rests less on content and more on the repeated cross-sensor timing regularity.

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek JSON fields, UIDs, FUIDs, TLS/X.509, HTTP, DNS, and conn fields are mostly source-native.
- **Temporal patterns:** 6 — Overall timing is plausible, but the repeated exact `+0.750000s` SSH cross-sensor duration delta is synthetic-looking.
- **Cross-source correlation:** 8 — Correlations are coherent and mostly realistic; the SSH duration pattern is the main concern.
- **Behavioral realism:** 8 — Proxy use, scans, DNS tunneling, OCSP, DHCP renewals, and enterprise protocols are believable.
- **Environmental consistency:** 8 — IP roles, local flags, service placement, and certificate naming are internally consistent.

## Recommendations

If synthetic, improve cross-sensor modeling by deriving each sensor’s `duration`, first-packet time, and last-packet time from packet-visible timing rather than applying fixed offsets. Add more natural Kerberos transport variety or document a TCP-only Kerberos policy in the generated environment assumptions.
