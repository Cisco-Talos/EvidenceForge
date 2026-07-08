# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 43

## Executive Summary

The dataset is highly realistic in schema, field semantics, and cross-source SIEM behavior, with no hard contradictions found in Windows logon/process lifecycles, Zeek UID linkage, or firewall connection pairing. The main synthetic-leaning evidence is a repeated timestamp-model artifact where eCAR `FLOW` records lag Zeek/syslog transport evidence by small but systematic amounts.

## Evidence For Synthetic

- **[contract_gap]** SSH endpoint flow timing sometimes trails server-side session evidence for the exact same tuple. Example: `zeek-core/conn.json` shows `10.10.1.31:57075 -> 10.10.2.30:22` starting at `2024-03-18T15:12:10.001Z`, while `APP-INT-01/syslog.log` logs `Accepted publickey` at `15:12:11.856Z` and `New session 377673` at `15:12:12.665Z`; matching eCAR `FLOW` rows appear later at `WS-MCHEN-01/ecar.json timestamp_ms=1710774733313` and `APP-INT-01/ecar.json timestamp_ms=1710774733597`.
- **[distribution_texture]** This eCAR lag is dataset-wide: 74 of 121 accepted SSH sessions had source-host eCAR `FLOW` after server `Accepted`, and 60 of 121 had target-host eCAR `FLOW` after server `Accepted`. The deltas are small, but the repeated pattern looks more like a deterministic observation model than varied production clocks.
- **[distribution_texture]** For exact eCAR-to-Zeek tuple matches with Zeek duration, 1,249 of 17,098 eCAR `FLOW` rows landed more than 0.5s after the Zeek connection end. Example: `zeek-core/dns.json` UID `CaqolmOPGKEtVZzA5D` for `10.10.1.35:50104 -> 10.10.2.10:53` has `ts=1710776953.607258`, `rtt/duration=0.000594`; matching `WS-AJOHNSON-01/ecar.json` `FLOW` is `timestamp_ms=1710776954436`, about 828 ms later.
- **[weak_signal]** Windows Security 4672 privilege events are very tightly distributed after corresponding 4624 logons: 363/363 have a prior same-LogonID 4624, with delays only 2-45 ms. Correct, but slightly over-regular.

## Evidence For Real

- Windows Security field semantics are strong. Example: `FILE-SRV-01/windows_event_security.xml` has 5156 at `2024-03-18T12:31:20.1225897Z` for `SourceAddress=10.10.1.35`, `SourcePort=62752`, `DestPort=3389`, followed by 4624 Type 10 at `12:31:21.8859888Z` for `TargetUserName=aisha.johnson`, `IpAddress=::ffff:10.10.1.35`, `IpPort=62752`, `LogonProcessName=User32`.
- Windows lifecycle checks were clean: no visible 4689-before-4688 process inversions, no 4634-before-4624 logoff inversions for paired LogonIDs, and 363 Security 4672 events all had a prior matching 4624.
- Zeek protocol linkage is robust. DNS/HTTP/SSL/SMTP/file references resolve to parent `conn.json` UIDs; DHCP `uids` resolve; SSL certificate `cert_chain_fuids` resolve to `files.json` and `x509.json`.
- Perimeter telemetry is coherent. `snort_alert.log` at `03/18-12:32:24.358` flags `185.70.41.45:61074 -> 203.14.220.10:443`; `cisco_asa.log` builds and tears down that connection at `12:32:24-12:32:27`; `WEB-EXT-01/web_access.log` shows the same scanner requesting `/web.config` at `12:32:24`.
- ASA behavior is production-like: 6,048 builds, 6,042 teardowns, only 6 open at slice boundary, with varied reasons including `TCP FINs`, `SYN Timeout`, resets, and one `Conn-timeout`.

## Detailed Analysis

Windows telemetry is the strongest realism area. Event IDs and fields match expected source-native semantics: 5156 uses decimal protocol values and device paths, 4624 Type 10 carries `IpAddress`/`IpPort`, 4768/4769 Kerberos records use `::ffff:` IPv4-mapped addresses and realistic ticket fields, and Sysmon Event IDs 1/3/7/10/11/13/22 have appropriate field names and value formats.

Zeek is internally consistent. `conn_state` distribution includes `SF`, `S0`, `RSTO`, `RSTR`, `REJ`, and `OTH`; DNS includes `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`; protocol rows reference parent UIDs. X.509 and file chains are especially convincing, with certificate `fuid` linkage and matching SHA hashes.

The main concern is not schema but timestamp causality across eCAR versus Zeek/syslog. The lag is small enough to be explained by endpoint observation latency or clock offset, but it is frequent and regular enough to raise the synthetic score into the mixed range.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score impact |
|---|---|---:|---:|
| contract_gap | eCAR + syslog + Zeek SSH | 74/121 accepted SSH sessions source eCAR after server accept | +9 |
| distribution_texture | eCAR + Zeek FLOW timing | 1,249/17,098 duration-bearing tuple matches after Zeek close by >0.5s | +7 |
| weak_signal | Windows Security timing | 363/363 4672 events within 2-45 ms after 4624 | +2 |
| realism counterweight | Windows, Zeek, ASA, Snort, web | Broad schema and lifecycle consistency | -15 |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Windows, Sysmon, Zeek, ASA, Snort, and web fields are source-native and well formed.
- **Temporal patterns:** 7/10 — Mostly coherent, but eCAR flow timestamps repeatedly lag transport/session evidence.
- **Cross-source correlation:** 8/10 — UID, port, LogonID, and scanner correlations are strong, with only timing-skew concerns.
- **Behavioral realism:** 8/10 — User activity, RDP/SSH, proxy, web scanning, Kerberos, and firewall behavior are plausible.
- **Environmental consistency:** 8/10 — Host roles, domains, IP ranges, and service behavior are coherent across sources.

## Recommendations

- Preserve separate event-time and observed/ingest-time fields for eCAR-style telemetry, or align eCAR `FLOW` timestamps to the actual transport open so SIEM timelines do not place endpoint flow after server authentication.
- Add explicit per-source clock skew metadata if the eCAR lag is intentional collection latency.
- Keep the current Windows Event ID field modeling, Zeek UID/file/X.509 linkage, and ASA build/teardown pairing; these are strong realism anchors.
