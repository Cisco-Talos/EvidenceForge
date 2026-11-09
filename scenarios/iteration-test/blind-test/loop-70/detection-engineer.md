# Detection Engineer — Authenticity Assessment

## Verdict

- **Assessment:** Synthetic
- **Verdict Confidence:** 72/100
- **Synthetic-Confidence Score:** 66/100

## Executive Summary

The data has substantial source-native detail and strong joins across endpoint, Windows, Zeek, proxy, IDS, firewall, and host logs. Sampled Windows process, authentication, and network events have credible schemas and mostly coherent timestamps. A macOS SSH exchange also aligns across endpoint records and a Unified Log authentication message. Those are meaningful production-like traits.

The strongest contrary evidence is a fleet-wide, unusually regular Linux telemetry rhythm: all ten hosts with Linux `syslog.log` files emit the same `debian-sa1 1 1` cron command exactly every 30 minutes for 12 consecutive runs, with a stable per-host minute offset and only sub-second execution jitter. The common cadence across application, mail, proxy, monitoring, file, and workstation roles looks templated. This is a distribution-texture finding, not a claim that a 30-minute sysstat schedule is impossible. The remainder of the evidence is not strong enough to support a hard schema or correlation failure, so confidence is moderate rather than high.

## Evidence For Synthetic

- **[distribution_texture]** `APP-INT-01.meridianhcs.local/syslog.log:1,45,58,83,96,117,126,141,158,178,184,204` records `(sysstat) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)` at 13:00, 13:30, 14:00, …, 18:30 UTC. The minute values are always `:00`; the seconds vary only from `.109` to `.360`.
- **[distribution_texture]** The same command occurs 12 times at exact 30-minute spacing on each of ten separate Linux hosts. Examples: `FILE-LNX-01.meridianhcs.local/syslog.log:2,66,107,171,190,246,282,327,372,413,458,536` runs at `:01` each half hour; `LOG-MON-01.meridianhcs.local/syslog.log:22,62,82,109,125,141,155,174,191,209,226,239` runs at `:07`; `MAIL-EDGE-01.meridianhcs.local/syslog.log:6,82,130,142,170,187,239,279,314,360,404,434` runs at `:06`; and `WS-LNGUYEN-01.meridianhcs.local/syslog.log:5,23,41,64,79,94,104,118,133,154,186,208` runs at `:03`. Different offsets suggest per-host phase selection, but the exact six-hour, 12-run pattern and fixed 30-minute period recur across very different roles.
- **[weak_signal]** Linux eCAR process IDs can be in the millions (for example, `APP-INT-01.meridianhcs.local/ecar.json` starts with PID `2931365` and later reaches `2986085`). Large Linux PIDs are valid, and the corresponding first syslog cron PID agrees, so this is not a contradiction. It does add to the unusually regular, modeled appearance of the Linux host activity when viewed with the fleet-wide cron pattern.

## Evidence For Real

- The Windows XML is source-shaped and field-rich in the sampled records. On `DC-01.meridianhcs.local`, Security Event 5156 at `2026-11-02T13:00:04.3912657Z` records DNS PID 2420 and tuple `10.10.1.31:62028 → 10.10.2.10:53`; Sysmon Event 3 at `13:00:04.4237594Z` carries the same PID, image, and tuple. `zeek-core/conn.json` and `zeek-core/dns.json` independently record that tuple at epoch `1793624404.209087`, with a matching DNS query for `FILE-SRV-01.meridianhcs.local` and answer `10.10.2.20`.
- The same Windows network/authentication area has plausible causal ordering: on DC-01, the Kerberos Event 4768 at `13:00:13.2111953Z` follows the Event 5156/ Sysmon network observation for the client’s UDP/88 request. The records carry normal-looking domain, machine-account, SID, ticket-option, encryption-type, address, and port fields.
- SMB evidence is coherent across endpoint and server views. `zeek-core/conn.json` records `10.10.1.31:60467 → 10.10.2.20:445` as `SF` with SMB service and nonzero byte counts. `FILE-SRV-01.meridianhcs.local/ecar.json` shows the matching inbound flow at `13:00:05.626Z`, followed by a successful type-3 session for `marcus.chen` at `13:00:05.635Z`, using the same source tuple. This is a useful cross-source join, not merely a complete-looking lifecycle.
- Windows process lifecycle samples correlate across formats. For example, `WS-SMARTINEZ-01.meridianhcs.local/windows_event_sysmon.xml` Event 1 at `13:03:26.0808512Z` identifies `wsqmcons.exe` PID 6748, and Security Event 4688 at `13:03:26.1459639Z` records the same process and PID in `NewProcessId=0x1a5c`. A later Security 4689 and Sysmon Event 5 refer to that process. The schemas and hexadecimal/decimal PID representation agree.
- Zeek companion records have valid-looking field types and joins in the sampled sets: every sampled DNS, HTTP, SMTP, SSL, SMB-mapping, and SMB-file `uid` resolves to a connection in the corresponding sensor’s `conn.json`. Zeek `conn_state`, byte/packet counters, protocol values, and UID-shaped identifiers look internally consistent in those samples.
- Native macOS data is distinct from normalized eCAR. `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` uses version 11 records with audit tokens, PID versions, signing metadata, and separate fork/exec/exit shapes. The Unified Log SSH line at `2026-11-02 14:24:51.313456+0000` reports an accepted keyboard-interactive/PAM login for `maya.ross` from `10.10.1.41:50608`; the same host’s eCAR records the inbound TCP/22 flow, then a successful SSH session login from that tuple at `14:24:52.310Z`. The client-side eCAR flow also shows `10.10.1.41:50608 → 10.10.1.42:22` and `/usr/bin/ssh` under `maya.ross`.
- The firewall, IDS, and HTTP/proxy sources show varied traffic and some failed or noisy activity. Examples include perimeter ASA translation/teardown messages, Snort alerts for BitTorrent and unusual DNS, and proxy `CONNECT` tunnel metadata. There is no need to infer unsupported product coverage from missing event types.

## Detailed Analysis

### Field format

**Generally strong.** I sampled Windows Security events 4624, 4688, 4768, 4769, and 5156; Sysmon events 1, 3, 5, 10, and 22; Zeek connection/DNS/HTTP/SSL records; eCAR process, flow, and session records; Linux RFC 5424-style syslog; and native macOS ES and Unified Log records. XML event providers, IDs, timestamps, event data names, process paths, and common SID formats are coherent in the sampled Windows records. Zeek’s integer ports and boolean flags are distinct from the string ports in eCAR’s `properties`; that difference is consistent with the separate representations. No recurring malformed XML/JSON or obvious invalid field-type pattern appeared in the samples.

### Temporal patterns

Windows and macOS sampled event timestamps are consistent to sub-second precision and correlate with matching event-specific timestamps. In particular, the Windows process creation times differ by tens of milliseconds between Sysmon and Security records, a plausible source-specific delay. The macOS SSH sequence has transport observation before login and an authentication message near the eCAR session event.

The Linux cron cadence is the main concern. It is repeated without a missed or shifted half-hour slot across a range of host roles and across the full six-hour visible period. Per-host offsets and small scheduler jitter add some variation, but the exact 12-run pattern remains unusually uniform. This is not a lifecycle-completeness objection; it is the observed recurrence distribution itself.

### Cross-source correlation

Correlation is a strength in the inspected evidence. The Windows DNS and Kerberos tuples align among Sysmon, Security auditing, eCAR, and Zeek. The SMB endpoint flow, Zeek connection, and server logon share a tuple and sensible ordering. In the sampled Zeek datasets, companion UIDs point to actual connection records. The macOS client/server SSH tuple, server-side login principal, and native Unified Log authentication agree. I did not find a sampled source-tuple or process-identity contradiction.

### Behavioral and environmental realism

The inferred environment is a mixed Windows AD domain with two domain controllers and user workstations, alongside Linux service hosts, two Macs, a proxy, DMZ web server, perimeter firewall, Zeek sensors, and Snort sensors. Hostnames, subnet placement, roles, and common services mostly agree with the records. Traffic includes internal DNS/Kerberos/SMB, proxy use, inbound web requests, server maintenance, and suspicious/noisy connections. These patterns are plausible.

The broad same-day, six-hour activity window is not used as an indicator by itself. Nor are the presence of complete process/session pairs, narratable sequences, eCAR normalization, or sparse native Unified Log content. The Linux sysstat cadence is the concrete signal that lowers the authenticity assessment.

## Synthetic Indicator Summary

| Category | Indicator | Weight |
|---|---|---:|
| `distribution_texture` | Ten Linux hosts each show 12 identical sysstat command records exactly 30 minutes apart, with a consistent host-specific minute phase and near-fixed execution seconds. | High |
| `weak_signal` | Linux eCAR PIDs are often high but remain within valid ranges and match at least one corresponding syslog process PID; not independently diagnostic. | Low |

No `hard_contradiction`, `contract_gap`, or `schema_or_format` finding was established from the inspected records. The positive source and cross-source checks lower the synthetic score from a high-confidence result.

## Realism Score by Category

- **Field format:** 9/10
- **Temporal patterns:** 6/10
- **Cross-source correlation:** 9/10
- **Behavioral realism:** 8/10
- **Environmental consistency:** 8/10

## Recommendations

- Review the Linux `debian-sa1` cron schedule against the expected fleet configuration. If production uses host-specific schedules, preserve evidence of that; otherwise, vary intervals, missed runs, and phase behavior in representative data.
- Preserve the strong tuple, PID, process-lifecycle, and authentication joins observed across eCAR, Windows, Zeek, native macOS, and server logs.
- For future validation, compare scheduled-event interval distributions across additional days and hosts. A longer window would show whether this half-hour cadence is a real configured policy or a dataset-wide modeling signature.
