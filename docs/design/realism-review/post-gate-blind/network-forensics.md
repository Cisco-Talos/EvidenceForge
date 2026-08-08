# Network Forensics — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 84

## Executive Summary

The corpus is highly polished and mostly obeys network-sensor contracts, but it contains one strong
payload-level contradiction and two systematic generation artifacts.

The decisive defect is a content-specific Snort SQL-injection alert on a TCP connection for which
both Zeek and the ASA report zero application bytes. The Zeek history shows only handshake/reset
activity and `missed_bytes` is zero. Secondary indicators are premature NAT teardown on three
SYN-timeout connections and non-native-looking Zeek UID/FUID length distributions. Against those
defects, most accounting, protocol fan-out, TLS certificate handling, DHCP timing, firewall
visibility, and sensor-clock relationships are impressively realistic.

## Evidence For Synthetic

- **hard_contradiction:** At `2024-05-14 17:07:34.016691 UTC`, Snort reports
  `ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT` on
  `45.33.74.51:54736 -> 10.44.30.10:80`. Corresponding Zeek UID `CH09DlhXMdixtxjTy` has
  `orig_bytes=0`, `resp_bytes=0`, `orig_pkts=3`, `resp_pkts=1`, `conn_state=RSTO`, history `ShAR`,
  and `missed_bytes=0`; ASA independently reports zero bytes and `TCP Reset-O`. A content-specific
  SQL-injection signature cannot arise from the payload-free connection represented by both
  accounting sources.

- **contract_gap:** Three dynamically translated TCP SYN-timeout connections lose their NAT
  translation 30 seconds before the ASA connection object closes. In contrast, 701 other translated
  TCP lifecycles tear down the translation and connection together.

- **schema_or_format / distribution_texture:** Among 5,957 Zeek connection UIDs, 595 are length 17,
  3,582 length 18, and 1,780 length 19. File IDs repeat the same approximate 10/60/30 distribution.
  This resembles sampled identifier lengths rather than a single native generation routine.

- **weak_signal:** Several other content-specific IDS labels have benign or incomplete protocol
  support, including a PHP upload label on `GET /` and SQL-injection labels on static or login GETs.
  Signatures can false-positive on headers or cookies, so these are not contradictions individually.

## Evidence For Real

- All 5,957 Zeek connection UIDs are unique. All 967 DNS, 649 HTTP, 1,016 TLS, and 785 file records
  reference existing connections.
- Protocol fan-out occurs within connection lifetimes.
- TCP state/history and packet accounting are internally coherent; all `S0` rows are response-less
  one-SYN connections and IP-byte totals respect payload and header lower bounds.
- Firewall visibility is topology-sensitive. 2,456 of 2,457 ASA TCP/UDP builds match Zeek within
  three seconds, and outside-to-DMZ denies are absent from the internal sensor as expected.
- Firewall termination reasons track Zeek states.
- TLS versions, cipher suites, resumptions, certificate reuse, validity, and OCSP validity windows
  are diverse and consistent.
- Four DHCP clients renew one-hour leases around T1 with 1,620–1,979 second gaps.
- Source volumes are credible for a six-hour branch-office capture.

## Detailed Analysis

Zeek connection modeling is generally excellent. UIDs are unique, tuple joins are preserved, TCP
histories agree with states, and UDP/ICMP overhead accounting is exact. Failed sessions do not
improperly generate TLS or HTTP fan-out. DNS is resolver-centered and includes plausible A, AAAA,
PTR, SRV, NXDOMAIN, SERVFAIL, REFUSED, internal, WPAD/ISATAP, reverse, and external TTL behavior.

HTTP contains 649 transactions: 319 CONNECT, 310 GET, ten POST, eight HEAD, and two OPTIONS. Proxy
access contains 726 transactions with tunnel, inspection, forwarding, authentication, denial, and
gateway-error outcomes. TLS/X.509/OCSP/file fan-out is structurally consistent and all file records
join existing connections.

The ASA log has realistic connection and translation pairing, NAT address/port variation, and
termination semantics. The three premature xlate removals are conspicuous precisely because the
other 701 translated flows preserve lifecycle alignment. IDS tuple correlation is strong—every
alert matches a Zeek connection within roughly 200 ms—but the zero-byte SQL alert is semantically
unsupported.

## Synthetic Indicator Summary

- **hard_contradiction:** Content SQL-injection alert on a zero-payload connection.
- **contract_gap:** Three NAT translations terminate before their connections.
- **schema_or_format:** Variable Zeek UID/FUID lengths with matching sampled proportions.
- **distribution_texture:** Identifier-family length frequencies repeat at about 10/60/30.
- **environment_or_collection_plausibility:** Generally strong.
- **weak_signal:** Additional content alerts have weak protocol support.

## Realism Score by Category

- **Field format accuracy:** 7/10
- **Temporal patterns:** 8/10
- **Cross-source correlation:** 7/10
- **Behavioral realism:** 8/10
- **Environmental consistency:** 8/10

## Recommendations

Attach content alerts only to canonical payload-bearing transactions, keep NAT state alive through
the owning connection, verify Zeek identifier morphology against native source, and preserve the
current topology-sensitive visibility, state/history, accounting, certificate, and DHCP strengths.
