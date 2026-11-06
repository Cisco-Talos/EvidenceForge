# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 84  
**Synthetic-Confidence Score:** 73

## Executive Summary

The data shows a plausible, cross-platform intrusion and collection trail: a web-host process launches a reverse shell, a Windows host stages files from shares for upload, a Linux workstation uploads support logs, and a database archive moves over SSH. Host, proxy, Zeek, and endpoint records often corroborate one another, but some cross-source file evidence conflicts, and the records show repeated, highly structured patterns.

## Evidence For Synthetic

- **contract_gap** — `zeek-core/smb_files.json` records `SMB::FILE_WRITE` for `Integration/DB-Staging/rpt_0318.sql.gz` at 2026-11-02 18:18:35 with `size: 0`; `zeek-core/files.json` reports zero bytes and empty-file hashes. At the same time, `FILE-LNX-01/syslog.log` records successful `open`, `write`, and `close` for that archive. These visible records do not reconcile the successful server-side write with the zero-byte network artifact.
- **distribution_texture** — In `zeek-core/http.json`, repeated `api.westbridge-services.net` beacon connections from `10.10.2.10` use the same `Go-http-client/1.1` identity and recurring `CONNECT` then `GET /api/v2/checkin` pattern across 17:31–18:51 UTC.
- **weak_signal** — Multiple distinct intrusion narratives use carefully staged archives, named destinations, and matching transfer telemetry: `mhs-support-48217.tar.gz` and `rpt_0318.sql.gz` on Linux; `cache_7f3a.zip` on Windows. The polished repeated structure adds modest synthetic weight.

## Evidence For Real

- `WS-LNGUYEN-01/ecar.json` records Lina Nguyen creating `/tmp/mhs-support-48217.tar.gz` at 16:31:35 UTC, followed by `curl` reading it and connecting to proxy `10.10.3.20:8080`. Zeek records the matching POST to `support.valeworks-health.net` with HTTP 200 and the same filename; the proxy log records the upload at 16:31:57.
- `DB-PROD-01/ecar.json` records `mysqldump`, gzip, and `scp` of `rpt_0318.sql.gz` to `10.10.2.30`. `APP-INT-01/ecar.json` then records a root SSH session and creation of `/tmp/.cache/rpt_0318.sql.gz`. The transfer sequence is temporally coherent.
- `WEB-EXT-01/ecar.json` ties an Apache child running a base64-decoded Bash command to an outbound connection from `10.10.3.10` to `45.33.32.30:8443`. Process and flow agree on PID and principal.
- `WS-AJOHNSON-01/ecar.json` shows share access, staging and compression of files under `C:\ProgramData\Microsoft\VaultCache`, and `curl.exe` reading the ZIP. The proxy records a matching 18.8 MB upload at 18:25 UTC.
- Mac records use distinct Unified Log, Endpoint Security, and shell-history files. An ES notification was not treated as proof of authorization.

## Detailed Analysis

- **Host and account activity:** Linux histories contain operational commands consistent with the recorded accounts and hosts. Lina's history includes the exact `tar` and `curl` commands later visible in EDR; root's history on `DB-PROD-01` contains the dump, compression, and `scp` sequence.
- **Network and exfiltration:** Zeek and proxy records corroborate Lina's upload, including filename, request size, destination path, and HTTP 200 response. Aisha's Windows upload similarly appears in the proxy log with a large client byte count. The Web host's shell and outbound flow correlate on PID, source, and destination.
- **Windows staging:** At 18:01:02 UTC, EDR records PowerShell copying files from `FILE-SRV-01` and `FILE-LNX-01` into `VaultCache`; it creates `cache_7f3a.zip` at 18:01:38 and `curl.exe` reads it at 18:24:59. The sequence is credible, though the tidy staging and transfer chain contributes synthetic texture.
- **Persistence and beaconing:** EDR records creation of `DeviceSyncSvc` and a scheduled task, followed later by encoded PowerShell `DownloadString` activity to `api.westbridge-services.net/v2/manifest`. Proxy records corresponding requests from `10.10.2.10`; the repeated check-in shape is the main distribution concern.
- **Cross-source file transfer:** The root archive's apparent arrival on `APP-INT-01` is followed by an SMB write to `FILE-LNX-01`, where host audit logs say the write succeeded. Zeek's zero-byte file accounting conflicts with that host-side evidence.

## Synthetic Indicator Summary

- **contract_gap** — Zeek SMB file telemetry vs. `FILE-LNX-01` audit for `rpt_0318.sql.gz`; one transfer; moderate score effect.
- **distribution_texture** — Repeated check-ins to `api.westbridge-services.net` in Zeek and proxy logs; recurring pattern; moderate score effect.
- **weak_signal** — Similar staged-archive narratives across Windows and Linux; small score effect.

## Realism Score by Category

- **Field format accuracy:** 8/10 — XML, syslog, Zeek JSON, proxy, and endpoint records use credible source-specific fields.
- **Temporal patterns:** 7/10 — Most sequences and host/network timestamps align; periodic check-ins are conspicuously regular.
- **Cross-source correlation:** 8/10 — Several process, file, HTTP, and proxy events correlate closely; the SMB archive size is an exception.
- **Behavioral realism:** 7/10 — Commands and account behavior are plausible, with visible red-team activity and ordinary administrative noise.
- **Environmental consistency:** 7/10 — The Windows, Linux, and macOS host mix and shared services cohere; repeated polished incident staging lowers confidence.

## Recommendations

- Reconcile the successful SMB write audit for `rpt_0318.sql.gz` with Zeek's zero-byte file record; retain transfer size or explain why payload accounting is unavailable.
- Add variation or interruptions to the recurring check-in pattern if those events are intended to model independent real-world activity.
