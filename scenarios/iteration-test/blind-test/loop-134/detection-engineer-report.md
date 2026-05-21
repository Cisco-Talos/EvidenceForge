# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 78

## Executive Summary

This is a strong, detection-usable dataset with mostly correct Windows/Sysmon/Zeek schemas and good cross-source continuity. I still assess it as synthetic because several artifacts look generated rather than collected: cron timing jitter in source-native syslog, host-local Security log clear semantics, and endpoint process telemetry that repeatedly captures only the terminal side of shell pipelines.

## Evidence For Synthetic

- `APP-INT-01.meridianhcs.local/syslog.log` shows `CRON ... (sysstat) CMD ... debian-sa1 1 1` at `12:00:01.169110`, `12:30:34.301701`, `13:00:41.092085`, `13:30:36.557346`, etc. A cron-originated job has minute granularity and should not have randomized seconds like a systemd timer; if randomized, it should not appear as `CRON`.
- `WS-LNGUYEN-01.meridianhcs.local/syslog.log` repeats the same pattern at `12:03:43.813671`, `12:33:24.622037`, `13:03:21.068296`, and `13:33:40.073739`.
- `DC-01.meridianhcs.local/windows_event_security.xml` has `wevtutil cl Security` at `2024-03-18T17:41:41.9213396Z`, then Event ID `1102` at `17:41:42.8093377Z`, with `EventRecordID` dropping from `11621279` to `3` while earlier pre-clear Security events remain in the same host XML stream. Plausible in a SIEM export, but not source-native for a direct post-clear host log export.
- `DB-PROD-01.meridianhcs.local/bash_history/marcus.chen.bash_history` has `#1710763201 snap list 2>/dev/null | head`; the corresponding ECAR record at `1710763201832` logs only `/usr/bin/head`, with no nearby `snap list` process. Similar cases occur for `udevadm ... | head` and `dmesg --ctime | tail -20`; ECAR contains 52 `head`, 17 `tail -20`, and 10 bare `tail` process creates, suggesting a pipeline modeling artifact.

## Evidence For Real

- Windows Event IDs and field names are largely source-native: 4688 v2 process creation, 5156 WFP fields, 4768/4769 Kerberos ticket fields, and Sysmon 1/3/10/11/13/22 structures are well formed.
- The DC attack chain is coherent: PSEXESVC service install at `16:00:12`, Sysmon file/process creation, `net user svc_mhsync`, Domain Admins membership, service/task persistence, C2, `wevtutil`, and cleanup all line up across Security and Sysmon.
- Zeek reference integrity is excellent: HTTP/SSL/DNS/files/X.509 child records reference existing `conn.json` UIDs, and observed child timestamps fall within their parent connection windows.
- Cross-source examples behave correctly, such as the `17:25:26` Chrome upload from `10.10.1.35` to `api.westbridge-services.net`, visible in Sysmon Event 3, proxy access logs, and Zeek TLS/connection records.

## Detailed Analysis

The Windows telemetry is the strongest part of the dataset. Event field names, provider GUIDs, Sysmon `ProcessGuid` behavior, WFP `Application` paths, Kerberos ticket fields, and process/logon correlation would generally work in SIEM detections. The PSEXESVC and `svc_mhsync` sequence is especially convincing and has realistic subsecond offsets between Security 4688 and Sysmon Event 1.

The Zeek corpus is also internally consistent. `http.json`, `ssl.json`, `dns.json`, `files.json`, and `x509.json` maintain UID/FUID relationships, and no impossible visible ordering appeared in parent/child timing. Core/DMZ duplicate flow visibility is very complete, but per the collection assumptions I do not treat that completeness as synthetic by itself.

The Linux/syslog layer is where the synthetic signal is clearest. `CRON` messages with randomized seconds and half-hour cadence look like a jitter model applied to a cron source, which is source-native wrong: cron has minute-level scheduling, while randomized delay belongs to timer frameworks. ECAR/bashaudit-style process records also under-model shell pipelines by repeatedly showing only `head`/`tail` without the left-hand process that the bash history shows should have executed.

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Sysmon, Zeek, proxy, and ASA fields are mostly source-native.
- **Temporal patterns:** 6 — Cross-source ordering is good, but CRON jitter is a clear timing artifact.
- **Cross-source correlation:** 9 — UID, PID, port, proxy, and endpoint correlations are very strong.
- **Behavioral realism:** 7 — Attack and baseline activity are plausible, but pipeline/process modeling is too selective.
- **Environmental consistency:** 8 — Hostnames, IPs, roles, SIDs, MACs, and services are mostly coherent.

## Recommendations

Align cron-originated syslog to minute boundaries, or model randomized jobs as systemd timers instead of `CRON`. For ECAR/Linux process telemetry, emit all execs in a pipeline, not only `head`/`tail`, and preserve enough parent/pipe context for detections. Treat Security log clear exports explicitly: either model SIEM aggregation without implying host-local XML continuity, or make post-clear host exports contain only post-clear records.
