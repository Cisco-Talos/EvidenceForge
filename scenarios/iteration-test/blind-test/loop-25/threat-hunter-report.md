# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 45

## Executive Summary

The dataset is operationally convincing: suspicious processes, remote sessions, file transfers, and network observations generally support technically workable investigations across three operating systems. A repeated executable-metadata timestamp pattern in the macOS Endpoint Security records suggests templated or normalized data, but I did not establish an impossible visible lifecycle or cross-source contradiction in the checks performed. This supports an inconclusive verdict with a modest lean toward production-like telemetry, rather than confident identification as either real or synthetic.

## Evidence For Synthetic

- [distribution_texture] Unrelated third-party executables on both Macs have all four embedded file timestamps—`st_atimespec`, `st_mtimespec`, `st_ctimespec`, and `st_birthtimespec`—set to precisely `2026-10-15T00:00:00.000000000Z`. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, this affects Homebrew curl, Slack, Visual Studio Code, and a Chrome renderer; on `MAC-MROSS-02`, it affects DBeaver, Microsoft Word, iTerm2, and two Chrome helper executables. There are nine affected host/path combinations across eight distinct executable paths. For example, Mac 01 line 36, `2026-11-02T13:48:41.201976000Z`, reports this metadata for `/opt/homebrew/opt/curl/bin/curl`, while Mac 02 line 85, `15:24:09.918612000Z`, does so for Microsoft Word. The alignment across unrelated software, timestamp meanings, and hosts looks like a default metadata fixture. It is not impossible: image deployment or timestamp normalization could explain it, so it has moderate weight only. These are timestamps inside log records, not modification times of the copied study files.

## Evidence For Real

- The source mix has meaningful environmental structure. Domain controllers have substantially more Windows network/audit activity than workstations; the proxy and public web host have high flow volumes; database visibility is much narrower. Twenty-three endpoint directories contain 37,414 eCAR records. The available sources include Windows Security/Sysmon, Linux syslog and shell history, macOS Endpoint Security/Unified Log/zsh history, three Zeek sensor views, proxy/web access logs, ASA logs, and two Snort views.
- The public-web reverse-shell pivot is feasible. `WEB-EXT-01/web_access.log` line 509 shows a `POST /ehr/admin/upload.php` from `185.70.41.45` at `14:20:17 +0000`. eCAR lines 960–963 show Apache spawning bash, decoding a payload, and a bash-owned connection to `45.33.32.30:8443`. `zeek-dmz/conn.json` line 2170 records that same connection with an approximately 22.4-second successful TCP interval. The visible bash process exits after the connection closes.
- SSH authentication follows transport establishment. APP-INT-01 connects to DB-PROD-01 on TCP/22 using source port 39333 at about `18:14:57`; DB syslog records the connection at `18:15:00.571078Z`, accepted password at `18:15:07.783407Z`, and PAM session open at `18:15:07.936251Z`. The target shell appears afterward at `18:15:10.415Z` in eCAR.
- The subsequent SCP transfer has receiver-side authentication and compatible closure. The DB-originated `10.10.4.10:49550 -> 10.10.2.30:22` flow closes around `18:16:07.7Z`; APP syslog records PAM session close at `18:16:08.532972Z`, and the DB's SCP process terminates at `18:16:09.477Z`.
- macOS shell execution is represented as fork/exec/exit transitions rather than inventing a fresh process for every image change. Mac 01's zsh history entry for executing the downloaded script at epoch `1793627348` agrees with an ES exec notification at `13:49:08.207155Z` whose target is `/bin/bash` and arguments include `connector-check.sh --check-config`.
- HTTP/file accounting survived broad checks: aggregating HTTP body lengths by sensor-local UID did not exceed corresponding directional connection payload bytes, and aggregating file `seen_bytes` by direction did not exceed those byte budgets either. This held for the matched rows in all three Zeek sensor directories.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory after reading the reviewer instructions. I inventoried its files, parsed all endpoint eCAR streams and the Windows Security/Sysmon XML streams, and performed targeted reads and cross-references in Linux syslog, macOS ES/Unified Log/history, Zeek, proxy, and web logs. Conclusions about native schema details are limited to what these records demonstrate; I did not consult external documentation or infer that every possible source should have been collected.

The visible activity is approximately `2026-11-02 13:00–19:00 UTC`. Endpoints span Windows domain infrastructure/workstations, Linux servers/workstations, and two Macs. Internal addresses expose at least `10.10.1.x`, `10.10.2.x`, `10.10.3.x`, and `10.10.4.x` segments. Hostnames, destinations, and domain spellings were treated as potentially sanitized.

Network volumes are substantial enough to require investigation: Zeek core contains 12,230 connection rows, DMZ 10,481, and DB 430. There are 4,379 proxy access rows, 899 public-web access rows, 25,529 firewall lines, and 145 Snort alert lines across the two Snort views. These are source-row counts, not a deduplicated event count; multiple sensors observe some of the same traffic.

### Web compromise and process/network ownership

The upload request at `14:20:17` is a useful starting point, but a successful HTTP status alone does not prove code execution. Independent endpoint evidence supplies that next step: at `14:20:27.968Z`, WEB-EXT-01 creates bash as `www-data`, parent `/usr/sbin/apache2`, PID 3044224. It spawns `base64 -d` PID 3044225 and bash PID 3044226. At `14:20:31.414Z`, the latter owns the outbound tuple `10.10.3.10:48003 -> 45.33.32.30:8443`.

The DMZ Zeek row has UID `Ctm27uUQMZeRQHTLqj`, start `14:20:31.482414Z`, duration `22.413812`, state `SF`, originator payload 620 bytes, and responder payload 1,840 bytes. Its observed close is `14:20:53.896226Z`. Endpoint bash PID 3044226 terminates at `14:20:59.920Z`, followed by its parent at `14:21:00.440Z`. This is compatible with the visible transport and process lifetimes. I do not count the readable sequence or compact timing as an authenticity defect.

### Database access and file movement

APP-INT-01 eCAR line 782 creates `ssh root@DB-PROD-01` at `18:14:42.160Z`. Line 785 associates it with TCP source port 39333. Target eCAR line 471 records the inbound flow at `18:14:57.806Z`; line 472 records root SSH login at `18:15:08.055Z`; line 473 creates the authenticated shell at `18:15:10.415Z`.

Zeek core UID `CpEsMLsWeR7BE9b4WOb` and DB-sensor UID `ClY7IbRh4hFEL9xH54c` have the same tuple and byte totals, with slightly different sensor timestamps. The local UIDs differ, which is compatible with separate sensors. The long SSH transport remains open beyond the short command sequence; that is not a defect.

Within that session, DB eCAR shows `mysqldump --single-transaction ehr patients insurance_claims`, subsequent `/tmp/rpt_0318.sql` creation, gzip execution and `/tmp/rpt_0318.sql.gz` creation, followed by SCP to APP-INT-01. The SCP process exists before its transport and file-read observations. The receiver syslog contains a public-key acceptance and session lifecycle for the same source tuple. I found no visible attempt to attribute the transfer to a session that had already ended.

### Windows identity and lifecycle checks

I parsed all ten Windows Sysmon XML files and compared visible process creation/termination times with their process GUID references, including parent and process-access references where present. The automated comparison found no referenced process created after its dependent event and no dependent event after a matching visible termination in these checks. I also checked Security process-creation records against visible logon/logoff IDs.

An initial naive logon-time comparison surfaced records whose only visible 4624 was a later Type 7 unlock. I excluded these: unlocking an existing session is not that session's original creation, and its process activity may legitimately precede the unlock. Likewise, unmatched starts or ends at the collection boundaries were not counted as defects.

Suspicious Windows activity includes DC-01's `net user svc_dirsync ... /add /domain` at about `17:15:02`, membership change command `net group "Domain Admins" svc_dirsync /add /domain` at `17:15:06`, and service/task registration commands around `17:19:40–43`. The latter commands have SYSTEM identity with WmiPrvSE ancestry, and `DeviceSyncSvc.exe` subsequently appears under services.exe at `17:29:17.4542923Z` in Sysmon. These are usable pivots; their visibility does not by itself establish that every attempted action succeeded.

### macOS evidence and limits

Mac 01 ES line 36 records curl execution with an explicit output path for `connector-check.sh`; line 39 records a later bash execution of that script. Thus download and execution are separate observations. The shell history and ES arguments agree on this distinction. The later Unified Log message at `15:42:09.009673+0000` says security policy would not allow MeetingAssist; I did not infer successful MeetingAssist execution or effects from that message.

The nine host/path combinations with four identical midnight executable timestamps are the main authenticity concern. They coexist with substantially richer, varied metadata for system binaries, making the third-party group stand out. A deployment snapshot could synchronize installation timestamps, but access, content modification, metadata change, and birth timestamps all collapsing to the same exact instant across unrelated packages is a stronger normalization signature than a shared install date alone. Without collection/export provenance, I cannot determine whether this reflects a synthetic fixture or real telemetry with transformed metadata.

### Payload and volume checks

For HTTP records with matching connection UIDs, I aggregated `request_body_len` against `orig_bytes` and `response_body_len` against `resp_bytes`. No aggregate exceeded its corresponding budget across 26 DB, 2,548 core, and 2,841 DMZ HTTP-associated UIDs. The analogous file-byte check covered 22 DB, 518 core, and 1,189 DMZ file-associated UIDs and found no excesses. These checks establish arithmetic compatibility, not packet-level proof of authenticity.

The proxy also preserves useful upload context. Line 2221 identifies lina.nguyen's `MHS-48217` diagnostic upload with `cs_bytes=1573700`, while line 4045 identifies aisha.johnson's `18:25:21` upload to `/upload/telemetry/7f3a2b19` with `cs_bytes=18783258`, `proxy_action=ssl-inspect`, and an explicit tunnel ID/client source port. The latter corresponds to a visible curl process with `--proxy` and a multipart archive argument. Large or suspicious uploads therefore remain distinguishable from routine web traffic without relying on an unobserved product or audit facility.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS Endpoint Security embedded executable metadata | Nine host/path combinations, eight distinct third-party executable paths across both Macs | Moderate upward pressure: four semantically distinct file timestamps repeat at one exact midnight instant. Deployment or normalization remains an alternative explanation. |

No verified hard contradiction, impossible visible process ordering, or demonstrated mandatory-companion gap was established by the checks performed. Complete source matching, collection omissions, attack readability, domain sanitation, and copied-file timestamps were not scored as synthetic indicators.

## Realism Score by Category

- **Field format accuracy:** 8 — Parseable native-looking XML/JSON and useful identity fields; repeated third-party executable metadata remains questionable.
- **Temporal patterns:** 8 — Tested process/session/network lifecycles are compatible; embedded macOS metadata has conspicuous timestamp collapse.
- **Cross-source correlation:** 9 — Web execution, SSH, SCP, proxy uploads, and Zeek byte budgets support practical pivots without a demonstrated contradiction.
- **Behavioral realism:** 8 — Privilege boundaries, command ancestry, remote transport, and file movement are operationally credible in the investigated chains.
- **Environmental consistency:** 8 — Segmentation, server roles, relative source volumes, and mixed-platform observations fit a plausible enterprise collection.

## Recommendations

- If this were synthetic, replace the shared `2026-10-15T00:00:00.000000000Z` third-party executable metadata fixture with coherent per-file installation/content/access histories. Preserve shared metadata for repeated observations of the same file, while allowing unrelated software and hosts to differ realistically.
- If those timestamps instead reflect intentional export normalization, documenting that transformation would resolve the principal uncertainty without changing the underlying telemetry. Avoid interpreting normalized metadata as original host filesystem history.
