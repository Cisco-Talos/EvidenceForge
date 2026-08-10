# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 97
**Synthetic-Confidence Score:** 95

## Executive Summary

The dataset demonstrates unusually strong source-native formatting and extensive cross-source correlation, but several systematic causal and protocol contradictions cannot be explained by ordinary collection gaps. Most decisively, hundreds of KDC audit events precede the same host’s WFP permit event for the identical network tuple, every HTTP `HEAD` response carries a nonzero body, and SSH processes repeatedly emit syslog before their recorded process creation.

## Evidence For Synthetic

- **`hard_contradiction` — KDC processing occurs before network permission.** In `DC-BO-01.../windows_event_security.xml`, 852 temporally proximal Event 4768/4769/4771 records had an exact matching Event 5156 based on client IP, client port, DC address, port 88, and protocol. All 852 KDC events precede the WFP permit event by 0.467–1.653 seconds. Because both records come from the same Windows Security channel, sensor clock skew cannot explain the inversion.

  - EventRecordID 15387546: Event 4768 at `2024-05-14T12:06:19.4046835Z`, client `10.44.10.25:57641`, service `krbtgt`.
  - EventRecordID 15387547: Event 5156 at `2024-05-14T12:06:20.5839994Z`, permitting that exact UDP tuple.
  - Another example is EventRecordID 15385826, Event 4769 at `12:03:07.4416930Z`, followed by EventRecordID 15385837, Event 5156 at `12:03:08.3270854Z`, for `10.44.10.22:64717 → 10.44.20.10:88`.

- **`hard_contradiction` — HTTP `HEAD` responses contain bodies.** All 10 `HEAD` transactions in `ZEEK-BO-CORE/http.json` have nonzero `response_body_len` values: 136–478 bytes. A `HEAD` response has headers only; Zeek’s body-length field represents transferred response content.

  - UID `Ciocp6L1Ok38JBVHZvt`, `2024-05-14 12:55:40.183806Z`, `HEAD /cgi-bin/test-cgi`, status 301, reports `response_body_len: 437`.
  - The corresponding `WEB-BO-01.../web_access.log` line 125 also records 437 response bytes.
  - All 10 corresponding web access entries likewise report nonzero byte counts. By contrast, the generator correctly sets all 19 HTTP 304 responses to zero body length, making the `HEAD` defect systematic and method-specific.

- **`hard_contradiction` — SSH processes log before they exist in endpoint telemetry.** On `PROXY-BO-01`, all 14 SSH daemon PIDs with both syslog and eCAR creation records emit their first same-PID syslog record 1.548–2.874 seconds before their `PROCESS/CREATE`.

  - PID 233723 logs `Connection from 10.44.10.24 port 58093` at `12:10:03.573531Z`.
  - `PROXY-BO-01.../ecar.json` records creation of PID 233723 at `12:10:06.016Z`, after that PID also logged successful authentication and session opening at `12:10:05.801712Z` and `12:10:05.900851Z`.
  - On `WEB-BO-01`, 43 of 44 matched SSH PIDs show the same ordering, although usually by less than 1.2 seconds. This could only be reconciled if eCAR `timestamp_ms` were an undocumented ingest timestamp rather than event time.

- **`contract_gap` — Selective absence of Kerberos network requests.** The DC records 1,484 KDC audits: 397 Event 4768, 1,085 Event 4769, and two Event 4771. Only 855 have a Zeek port-88 connection with the event’s exact `IpAddress` and `IpPort`; 629, or 42.4%, have no such transport.

  This is inconsistent with the rest of the collection profile: 5,445 of 5,452 non-loopback Event 5156 records across the Windows hosts have exact Zeek tuple matches. The selective Kerberos gap affects every workstation and server rather than one missing route or collector.

- **`distribution_texture` — Machine-account TGT caching is effectively absent.** Successful Event 4768 volume is implausibly high for the small environment:

  - `FILE-BO-01$`: 91 successful TGT requests in six hours, median gap 217 seconds.
  - `WS-OREED-01$`: 63, median gap 288 seconds.
  - `WS-MPATEL-01$`: 60, median gap 292 seconds.
  - `WS-VHALE-01$`: 57, median gap 301 seconds.
  - `WS-LMORRIS-01$`: 50, median gap 285 seconds.
  - `WS-NKAPOOR-01$`: 43, median gap 371 seconds.

  Domain-joined machines normally cache and renew TGTs over much longer lifetimes; they do not obtain a fresh successful TGT every few minutes throughout a stable workday.

- **`schema_or_format` — Snort classification output uses rule keys rather than native descriptions.** `IDS-BO-EDGE/snort_alert.log` uses values such as `[Classification: attempted-recon]`, `[Classification: icmp-event]`, and `[Classification: web-application-attack]`. Standard Snort fast-alert output normally renders the classification description configured for those classtype keys, such as “Attempted Information Leak” or “Generic ICMP event.” A custom classification configuration could cause this, so it is supportive rather than decisive.

## Evidence For Real

- All seven Windows Security XML files and seven Sysmon XML files parse successfully. The assessment covered 10,212 Security events across IDs 4624, 4625, 4634, 4648, 4672, 4688, 4689, 4768, 4769, 4771, 4776, 4800, and 5156, plus 3,512 Sysmon events across IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22. Providers, channels, versions, tasks, SIDs, hex PIDs, WFP direction tokens, and field sets are generally source-accurate.

- Sysmon process GUIDs have credible native structure. For example, the middle words of `{aab87a56-5265-6643-...}` encode `0x66435265`, the process creation epoch for `2024-05-14 12:00:37Z`. Repeated binaries maintain stable hashes, and process creation/termination ordering is valid for every visible paired ProcessGuid.

- Windows process evidence correlates well: 668 Sysmon Event 1 records match Security Event 4688 by PID and image, with no command-line or parent-image mismatches. eCAR usually carries the same PID, image, parent, principal, session, and process UUID relationships.

- Zeek fan-out is internally strong. Every one of 1,007 DNS, 700 HTTP, and 1,030 SSL records references an existing `conn.json` UID and occurs within that connection’s interval. All 768 file records reference existing connections, and all 537 X.509 records map to a certificate-chain FUID.

- TLS behavior is unusually precise:

  - All 286 non-resumed TLS 1.2 handshakes include certificate chains.
  - All 146 resumed TLS 1.2 handshakes omit them.
  - All 598 TLS 1.3 records omit passively unavailable certificate chains.
  - Certificate validity, key algorithm, issuer, SAN, and SNI values are coherent.

- Twenty-eight parsed OCSP responses correlate with HTTP response FUIDs. Decoding their request URIs produced the same issuer-name hash, issuer-key hash, and certificate serial found in `ocsp.json`. One of 29 HTTP OCSP objects lacks a parsed OCSP record, a plausible parser or payload gap.

- Cisco ASA evidence is coherent: 2,469 TCP connection builds have matching teardowns with identical tuples, 707 dynamic translations have matching translation teardowns, and 2,467 of the TCP builds match exact Zeek tuples. PRI/severity combinations also agree with the `%ASA` message severity.

- All 58 SSH `Connection from` syslog records have exact Zeek TCP/22 tuple matches. Authentication, PAM session opening, and session closing sequences are otherwise credible.

- DHCP activity shows realistic policy-driven periodicity: 47 REQUEST/ACK renewals for four workstations, a one-hour lease, and host-specific renewal gaps of roughly 27–33 minutes rather than exact half-hour ticks.

## Detailed Analysis

The Windows logs are superficially excellent. Security Event 4624 and 4634 share LogonIDs correctly, WFP Event 5156 uses the proper local application and direction for inbound versus outbound flows, and Sysmon Event 1, 3, 5, 7, 8, 10, 11, 13, and 22 field names and value types are largely accurate. Host roles and OS families also remain coherent: the DC uses Server 2022-era `10.0.20348` metadata, the file server uses Server 2019-era `10.0.17763`, and workstation metadata is Windows 10/11-like.

The KDC/WFP ordering breaks that credibility. The inversion is not a cross-device clock problem: both KDC and WFP events are in `DC-BO-01.../windows_event_security.xml`, with monotonically increasing EventRecordIDs confirming the KDC record was inserted first. Ordinary Type 3 logons do not have this defect: 224 matched DC logons and all 426 matched file-server logons occur after their WFP permit event, generally by 8–140 milliseconds. The anomaly is isolated to the Kerberos audit-generation path.

The Kerberos volume adds an independent defect. Hundreds of successful machine-account AS requests recur every few minutes, and 629 KDC records lack an observable request despite near-complete tuple coverage for other non-loopback traffic. This resembles per-activity prerequisite fabrication rather than normal Windows ticket caching and network collection.

Zeek’s lower-level structure is otherwise strong. DNS RTTs never exceed connection durations; HTTP, SSL, X.509, file, and OCSP timestamps remain inside their owning connection intervals; TLS certificate visibility follows protocol-version and resumption behavior; and UID/FUID integrity is complete. That quality makes the `HEAD` defect more significant: all 10 affected records were assigned plausible redirect bodies even though HTTP semantics forbid a response body for `HEAD`.

The Linux logs contain realistic RFC 5424 formatting, PAM sequences, stable account UID 4614 across servers, high-uptime PID ranges, cron activity, kernel UFW messages, and varied service noise. Nonetheless, same-PID SSH process creation consistently follows messages already emitted by that PID. The PROXY timing offset is especially large and uniform enough to exceed ordinary scheduler variance.

The ASA and web/IDS paths show broad tuple and timestamp agreement. The primary IDS formatting defect is the use of Snort classtype keys as rendered classification names. Alert tuples themselves correlate with Zeek and web access events, including the Nikto activity from `185.199.110.42`.

## Synthetic Indicator Summary

| Category | Source | Scope | Impact |
|---|---|---:|---|
| `hard_contradiction` | DC Security 4768/4769/4771 vs 5156 | 852/852 proximal tuple matches inverted | Decisive same-clock causality failure |
| `hard_contradiction` | Zeek HTTP and web access | 10/10 `HEAD` responses have bodies | Decisive HTTP protocol defect |
| `hard_contradiction` | Linux syslog vs eCAR | PROXY 14/14; WEB 43/44 process creates follow same-PID logs | Strong lifecycle ordering failure |
| `contract_gap` | KDC audits vs Zeek port 88 | 629/1,484 audits lack exact transport | Selective coverage contradiction |
| `distribution_texture` | Windows Event 4768 | 43–91 machine TGTs per host in six hours | Implausible ticket-cache behavior |
| `schema_or_format` | Snort fast alerts | Dataset-wide classification rendering | Moderate native-format fingerprint |

## Realism Score by Category

- **Field format accuracy:** 8/10 — Windows, Zeek, ASA, syslog, and eCAR fields are mostly convincing; Snort classification rendering and `HEAD` body semantics reduce the score.
- **Temporal patterns:** 4/10 — Ordinary process, session, DHCP, and network lifecycles are coherent, but KDC/WFP and SSH process ordering are systemic causal failures.
- **Cross-source correlation:** 7/10 — UID, tuple, PID, hash, TLS, OCSP, firewall, and SSH correlation are excellent, offset by the large selective Kerberos transport gap.
- **Behavioral realism:** 5/10 — User, server, scan, proxy, and maintenance behavior is varied, but machine-account TGT churn is not credible.
- **Environmental consistency:** 8/10 — Host roles, IP semantics, OS metadata, services, certificates, and routing remain internally consistent.

## Recommendations

- Emit the TCP/UDP port-88 permit and transport evidence before Event 4768/4769/4771 for the same tuple. Add an invariant that KDC processing cannot precede the matching inbound WFP permit.
- Require every network-originated KDC audit to reference an observed port-88 transport, unless explicitly marked as loopback or outside sensor visibility.
- Model Kerberos ticket caching and renewal. Stable machine logon sessions should reuse their TGT rather than request a new one every few minutes.
- Force `response_body_len` and transferred access-log bytes to zero for all `HEAD` responses; retain advertised `Content-Length` only in a separate header field.
- Timestamp eCAR process creation before any same-PID syslog output, or explicitly distinguish event time from ingest time in the eCAR schema.
- Resolve Snort classtype keys through the configured classification description before rendering fast-alert output.
