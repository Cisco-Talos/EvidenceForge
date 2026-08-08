# Network Forensics Analyst — Blind Authenticity Assessment

## Verdict

- Assessment: Synthetic
- Verdict confidence: 93/100
- Synthetic-confidence score: 86/100

## Executive summary

The dataset demonstrates unusually strong field-level construction and cross-source correlation,
including coherent NAT, proxy, TLS, DNS, SSH, and file-transfer lifecycles. One impossible
IDS/transport combination and several repeated timing fingerprints nevertheless reveal
deterministic generation behavior that is not credibly attributable to sanitization or ordinary
collection loss.

## Evidence for synthetic

- **Hard contradiction — response alert on a SYN-only flow.** At
  `2024-05-14T12:54:41.505759Z`, Snort reports SID `2101411`, `GPL WEB_SERVER 403 Forbidden`, for
  `185.199.110.42:53211 -> 10.44.30.10:80`. Zeek UID `CpFZfhQefW6f0iHWy` is `S0`, history `S`,
  one originator packet, no responder packets, and no payload. ASA connection ID `1213786` tears
  down after 30 seconds with zero bytes and `SYN Timeout`; no HTTP or access-log record exists. A
  403 response cannot be observed when the responder sent nothing, and the alert is also rendered
  client-to-server despite describing a server response.
- **Distribution fingerprint — DHCP renewal scheduling.** All 47 Zeek DHCP rows are
  `REQUEST,ACK` transactions with a 3,600-second lease. Across four clients and 43 renewal
  intervals, every interval lies in `1622.145–1978.917` seconds, a nearly uniform ±10 percent band
  around half-lease rather than a stable server-provided T1 with limited retry variation.
- **Repeated constant — OCSP transfer duration.** All 36 `application/ocsp-response` Zeek file
  records have exactly `duration: 0.02` despite sizes from 935 to 2,450 bytes, different origins,
  and different times. Other HTTP files vary, making this a type-specific generator fingerprint.
- **Lifecycle gap — file envelopes exceed their connections.** At least 21 meaningful SMB and
  HTTP file records end exactly one or two milliseconds after the associated Zeek connection.
  FUID `Fl8SlmUKT40IBQUita` exceeds UID `CFH626oUP7bxUMEdZK` by two milliseconds; SMB FUID
  `FZKTO5DyLhjAjX5fFz` similarly exceeds UID `ChjUiFKF74r34W0Df` by two milliseconds.
- **Weak DNS texture — uniformly successful AAAA.** All 198 AAAA queries succeed with non-empty
  IPv6 answers, while A queries include NXDOMAIN, SERVFAIL, and REFUSED outcomes.

## Evidence for real

- Of 2,499 parsed ASA TCP/UDP connection builds, 2,497 match Zeek tuples within about 1.23 seconds.
  All 707 dynamic NAT build/teardown pairs correlate, and 1,191 of 1,515 matched `SF` connections
  have exact ASA-to-Zeek byte totals.
- ASA timestamp displacement is bounded at approximately `-1.228` to `+0.029` seconds, resembling
  stable clock offset plus second-level precision.
- Of 336 client-to-proxy Zeek HTTP records, 331 match proxy access semantics. All 387
  `ssl-inspect` entries have a preceding CONNECT, and 279 of 282 successful CONNECTs lead to
  matching proxy-origin TLS within `0.135–3.243` seconds.
- TLS 1.2/1.3, resumption, certificate evidence, validity, SNI/SAN relationships, connection state,
  histories, packet counts, and IP-byte accounting are protocol-aware and coherent.
- All 784 Zeek file records join a parent connection; all 577 X.509, 36 OCSP, and two PE identifiers
  join the expected parent records.
- All 54 SSH connection-start syslog rows match Zeek TCP/22 tuples. Successful auth/session
  ordering and endpoint cleanup delays are plausible.
- Host roles and small visibility gaps match the modeled enterprise topology.

## Detailed analysis

The six-hour dataset contains 6,032 Zeek connections: 4,266 TCP, 1,659 UDP, and 107 ICMP. Hourly
and five-minute volumes vary naturally, and most source families have excellent relational
integrity. That precision makes the 403 incident decisive: an independent sensor and firewall both
show an unanswered SYN, while the IDS claims a server response. Packet loss cannot reconcile zero
firewall bytes, SYN timeout, no responder packets, and no application record.

The remaining indicators are systemic timing fingerprints. DHCP appears to independently resample
each renewal from a broad T1 band. Every OCSP file receives one fixed 20-millisecond duration, and
file envelopes repeatedly overshoot their owning connection by exactly one or two milliseconds.
Sanitization cannot plausibly introduce these contradictions.

## Realism scores

| Category | Score |
| --- | ---: |
| Field-format accuracy | 9/10 |
| Temporal patterns | 7/10 |
| Cross-source correlation | 8/10 |
| Behavioral realism | 9/10 |
| Environmental consistency | 8/10 |

## Reviewer recommendations

- Gate response-oriented IDS signatures on established transport and responder payload, preserve
  signature direction, and reject alerts that conflict with firewall/network accounting.
- Make DHCP T1 a stable lease-policy fact with bounded retry/clock jitter.
- Derive OCSP file duration from the parent HTTP transaction rather than a fixed constant.
- Enforce that a file's observed end remains within its parent connection interval after
  source-native timestamp precision is applied.
- Model AAAA NODATA/failure based on domain IPv6 support.

## Isolation statement

The reviewer received only `/private/tmp/eforge-realism-review/branch-enterprise/data`; scenario,
ground truth, code, prior reports, and other reviewers' conclusions were withheld.
