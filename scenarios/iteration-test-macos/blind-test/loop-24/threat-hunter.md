# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 43

## Executive Summary

The collection supports credible hunting pivots across endpoint, network, authentication, shell-history and proxy evidence. Repeated short-lived root desktop-indexer activity on infrastructure servers and repeated Windows management commands aimed at Linux hosts raise questions about baseline composition, but this bounded review found no demonstrated impossible lifecycle or decisive authenticity fingerprint. The score reflects those concrete, limited concerns rather than the completeness or narratability of the suspicious activity.

## Evidence For Synthetic

- [environment_or_collection_plausibility] Three infrastructure hosts run `/usr/libexec/tracker-miner-fs-3` directly under PID 1, as `root`, for only a few seconds: `WEB-EXT-01.meridianhcs.local/ecar.json:3403` to `:3405` (1.280 seconds), `APP-INT-01.meridianhcs.local/ecar.json:646` to `:647` (2.254 seconds), and `LOG-MON-01.meridianhcs.local/ecar.json:775` to `:776` (3.505 seconds). This is an unusual repeated placement/ownership/lifetime combination for a desktop file indexer on web, application and monitoring infrastructure. It could arise from a shared installed image or failing service; it is not an impossible event.
- [weak_signal] The same Windows-specific management pattern targets different Linux systems: `WS-PPATEL-01.meridianhcs.local/ecar.json:477` runs `Get-CimInstance Win32_OperatingSystem -ComputerName 'FILE-LNX-01' -Credential 'priya.patel-admin'`; `WS-MCHEN-01.meridianhcs.local/ecar.json:483` targets `LOG-MON-01` with the corresponding Marcus credential name. Both targets independently have Linux syslog and POSIX process evidence. This suggests a management-command pool insufficiently constrained by target platform, although unsuccessful operator attempts or custom management arrangements remain plausible. Execution of the commands alone does not establish successful Windows management on Linux.

## Evidence For Real

- A root SSH pivot from `APP-INT-01` to `DB-PROD-01` has a consistent tuple and meaningful ordering: source SSH process creation, transport evidence, successful target authentication, shell creation, then database collection. See the detailed timeline below.
- The subsequent SCP transfer reverses the network direction coherently: DB endpoint `ecar.json:601–604` identifies `/tmp/rpt_0318.sql.gz`, source port `45342` and destination `10.10.2.30:22`; APP endpoint `ecar.json:675–682` identifies the matching inbound tuple, root session and receiver file `/tmp/.cache/rpt_0318.sql.gz`.
- Shell history preserves a detail correctly absent from the executable argument vector: `DB-PROD-01.meridianhcs.local/bash_history/root.bash_history:2` contains `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql`, while endpoint `ecar.json:591` has the `mysqldump` executable arguments without shell redirection. That distinction supports interpretable shell/process semantics; it does not prove real provenance.
- A legitimate-looking support upload is internally explainable: `WS-LNGUYEN-01.meridianhcs.local/ecar.json:349–357` shows archive preparation and a multipart curl upload; `zeek-core/http.json:1147` records the matching POST, host, case path and `curl/7.81.0`; proxy line 1742 has the same host/path, user, time, status and response size.
- Broad process-identity screening did not find a visible actor reference more than 100 ms before its observed creation or after its observed termination in the supplied normalized endpoint records. This is a positive lifecycle result, subject to the normalization and identity semantics of that source.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. Its 23 endpoint directories include Windows Security/Sysmon XML, Linux syslog and bash history, macOS Endpoint Security/unified-log exports and zsh history, and normalized eCAR records. Network/edge sources include three Zeek sensor directories, Snort, Cisco ASA, proxy and web access logs. The eCAR timestamps span approximately 2026-11-02 13:00–19:00 UTC; this is a six-hour bounded window.

The collection contains 35,313 normalized endpoint rows, 18,626 Security XML events, 11,665 Sysmon XML events, 21,463 Zeek connection rows across sensors, 4,431 HTTP rows, 3,353 proxy rows and 4,201 syslog rows. Connection counts across sensors are observations, not unique enterprise connections. These volumes provide substantial background traffic; neither source completeness nor a short window is scored as synthetic evidence.

This was a bounded review: source inventory, representative XML/JSON inspection, suspicious-command screening, two operational pivots, a support-upload pivot, an endpoint process-identity ordering check, and an HTTP body/accounting check. I did not exhaustively reconstruct every session, validate every native schema version or determine business authorization for all observed actions. All line numbers below are one-based; paths are relative to the supplied data directory.

### Root SSH and database collection pivot

The following events describe one technically coherent remote session, rather than unrelated activity joined only by hostname:

| Source and line | UTC time | Observation |
|---|---|---|
| `APP-INT-01.meridianhcs.local/ecar.json:665` | 18:14:35.165 | Root creates PID 2983764, `/usr/bin/ssh`, command `ssh root@DB-PROD-01.meridianhcs.local`, under an existing root bash process. |
| `zeek-core/conn.json:10506` | 18:14:52.064499 | `10.10.2.30:41321 → 10.10.4.10:22`, service SSH, state `SF`, duration 978.117752 seconds. |
| `APP-INT-01.meridianhcs.local/ecar.json:669` | 18:14:53.953 | Outbound FLOW uses the same tuple and source PID 2983764. |
| `DB-PROD-01.meridianhcs.local/syslog.log:195–196` | 18:15:03.248930–18:15:03.326505 | Password accepted for root from `10.10.2.30:41321`; PAM session opened. |
| `DB-PROD-01.meridianhcs.local/ecar.json:589–590` | 18:15:03.361–18:15:05.032 | Root login then bash PID 1088964, session `279042`, logon `0x1185ed49`. |
| `DB-PROD-01.meridianhcs.local/ecar.json:591–596` | 18:15:11.587–18:15:39.572 | `mysqldump` creates the SQL artifact, terminates, then `gzip -9` creates the compressed artifact. |

`zeek-db/conn.json:399` observes the same tuple with a different sensor UID and slightly different timestamp; its payload/packet counters agree with the core observation. That is a feasible multi-sensor pivot. The evidence establishes activity and account usage, not whether the root access was authorized.

The reverse SCP tuple appears in `zeek-core/conn.json:10571` with `359588` origin bytes and `30613` response bytes. Later, `zeek-core/smb_files.json:164–165` records APP writing `Integration\DB-Staging\rpt_0318.sql.gz` to `\\FILE-LNX-01\ClinicalResearch`; the file observation in `zeek-core/files.json:524` has `348477` seen/total bytes. The SSH transfer volume can accommodate that file plus protocol overhead. No byte-volume contradiction was found in this pivot.

### Support upload and accounting

The multipart POST at `zeek-core/http.json:1147` has request body length `1573258`, two origin FUIDs, and origin MIME types `application/json` and `application/gzip`. The gzip part at `zeek-core/files.json:342` is `1572864` bytes and names `mhs-support-48217.tar.gz`; the larger request body allows metadata and multipart framing. Proxy line 1742 reports `cs_bytes=1573595`, appropriately larger again, and a 96-byte response matching HTTP `response_body_len=96`.

As an inexpensive consistency screen, I joined all 4,431 supplied HTTP rows to their sensor-local connection records by UID and compared request/response body lengths with origin/response payload counters. No individual body exceeded the corresponding connection-direction payload. This checks only a necessary accounting condition; it does not establish full HTTP stream validity or account for every multi-transaction connection.

### Baseline concerns and limits

The repeated indexer processes are the clearest environmental concern. Their server placement, root principal, PID-1 parent and brief lifetimes recur across otherwise different roles. A shared image or misconfigured service is a credible alternative explanation; the records do not include unit definitions or exit reasons that would distinguish it from synthetic baseline pooling.

The Windows management commands aimed at Linux are a weaker corroborating observation. I do not infer an impossible successful operation, because the process creation rows do not show command output or success. Nor do I treat a lack of retries, a complete intrusion sequence, absent selected Sysmon types, domain names, or missing out-of-window events as authenticity evidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `environment_or_collection_plausibility` | Normalized Linux endpoint process telemetry | Three infrastructure servers with the same root/PID-1 desktop indexer and 1.280–3.505 second visible lifetimes | Moderate concern about software/role and lifecycle texture; plausible shared-image explanation prevents a strong verdict. |
| `weak_signal` | Windows process telemetry targeting Linux systems | Two different users and Linux targets | Small contribution: repeated target-platform mismatch, without evidence that the commands succeeded. |

No hard contradiction or generator identity leak was demonstrated in this review.

## Realism Score by Category

- **Field format accuracy:** 8 — Representative native XML and JSON were readable and useful; detailed platform/version compliance was not exhaustively verified.
- **Temporal patterns:** 8 — The inspected SSH/auth/shell/collection sequence is feasible; repeated short indexer lifetimes remain questionable.
- **Cross-source correlation:** 9 — Tuple, session, file, proxy and byte-accounting pivots worked in the selected examples.
- **Behavioral realism:** 7 — Collection and upload actions are technically interpretable, with a limited concern about repeated platform-insensitive management commands.
- **Environmental consistency:** 6 — Desktop-indexer placement and root ownership recur on distinct infrastructure roles without a visible explanation.

## Recommendations

- If this were synthetic, condition desktop-indexer activity on actual installed software, host role, service ownership and expected service lifecycle; alternatively, represent the shared-image/service failure that explains the observed root, PID-1 and brief-duration pattern.
- If this were synthetic, constrain management-command target selection by actual platform/capability. Preserve these Win32 queries against Linux only when modeling a failed operator attempt or a documented custom management arrangement, with outcomes that support that interpretation.
- Retain the demonstrated shell-history/argument-vector distinction, SSH session identities, reverse-transfer tuple consistency and multipart accounting when making changes.
