# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 62

## Executive Summary

The operational trail is largely credible: downloads, endpoint execution, remote administration, account changes, database staging, and proxy uploads can be followed across distinct source families without a demonstrated impossible lifecycle. I lean synthetic primarily because the Windows process telemetry has a conspicuous population-wide lifetime floor: all 774 matched Sysmon creation/termination pairs across ten hosts last at least 3.029 seconds, including short diagnostic utilities; that distribution is substantially less convincing than the individual attack pivots.

## Evidence For Synthetic

- [distribution_texture] **Windows process lifetimes have an apparent common minimum near three seconds.** Matching Sysmon Event 1 to Event 5 by `ProcessGuid` within each host yields 774 visible pairs across the ten Windows hosts. None lasts under 3.029 seconds; 25 last between 3.029 and 3.298 seconds. The shortest matched lifetime on every Windows host is between 3.029 and 3.222 seconds. Examples include `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml`: PID 7552, `ipconfig.exe /all`, 14:47:17.734–14:47:20.944 (3.210 seconds), and PID 7264, `gpresult.exe /r`, 14:41:42.591–14:41:45.727 (3.136 seconds). `DC-01` PID 4508, `conhost.exe 0x4`, lasts 15:23:57.744–15:24:00.775 (3.031 seconds). A particular command taking three seconds is ordinary; the absence of a shorter tail over hundreds of varied processes and ten hosts is the indicator. A collection policy that suppresses short-lived Windows processes could explain it, so this is a strong distribution concern rather than a hard contradiction.

## Evidence For Real

- **The database-transfer pivot preserves transport, authentication, and file ownership.** `zeek-db/conn.json`, record 316, observes `10.10.4.10:58224 → 10.10.2.30:22` at 18:15:45.094057, UID `COd5HRT39dG0PaqT4`, with an `SF` connection lasting 26.241655 seconds. `APP-INT-01.meridianhcs.local/syslog.log`, lines 233–236, then records the same source tuple, accepted root public-key authentication at 18:15:51.021793, PAM session opening, and logind session 323. The receiver's eCAR identifies the receiving SSH process as root and creates the transferred file before the subsequent SMB read.
- **Distinct account namespaces survive a protocol change.** `APP-INT-01/ecar.json`, record 817, runs `smbclient` as local root but supplies `-U "svc_mhsync" --use-kerberos=off`; `FILE-LNX-01/ecar.json`, record 1382, attributes the resulting write to directory account `svc_mhsync`, `auth_protocol=ntlmssp`. This is a useful, technically appropriate distinction between the initiating process user and remote authentication identity.
- **The support upload distinguishes the client proxy hop from the upstream hop.** `zeek-core/http.json`, record 1350, contains the absolute-form POST URI from `10.10.1.21:37572` to proxy `10.10.3.20:8080`; `zeek-dmz/http.json`, record 1490, contains the proxy's separate connection from `10.10.3.20:38934` to `52.44.186.73:80` with an origin-form URI. The request body size is 1,573,258 bytes on both observations. The proxy access record at 16:32:14 attributes the request to `lina.nguyen@meridianhcs.local` and reports `cs_bytes=1573700`, which reasonably includes overhead beyond the body.
- **Source-specific distinctions are retained.** The macOS records distinguish fork, exec, and exit; their normalized eCAR records distinguish creation from exec modifications. The macOS Unified Log policy message about MeetingAssist is not accompanied by a claim of successful MeetingAssist execution in the inspected Endpoint Security records. Windows Event 1102 uses the Eventlog provider and `UserData/LogFileCleared`, and its record ID resets to 1.
- **The network and baseline are not entirely successful or uniform.** The three Zeek sensors include failed attempts, resets, partial observations, variable durations, and sensor-specific loss. For the same database-transfer tuple, `zeek-core` and `zeek-db` have different UIDs and slightly different timestamps and packet observations, rather than pretending to share one sensor identity.

## Detailed Analysis

### Orientation and scope

I examined only the supplied data directory. It contains 23 endpoint host directories spanning Windows, Linux, and two Macs, plus three Zeek sensors, two Snort streams, and a perimeter ASA stream. Endpoint records span approximately 2026-11-02 13:00–19:00 UTC. The address space visibly includes `10.10.1.x`, `10.10.2.x`, `10.10.3.x`, and `10.10.4.x`; names and traffic imply workstations, directory servers, file servers, a database, an application server, web infrastructure, mail servers, a proxy, and monitoring.

The collection includes 37,971 normalized eCAR records, 17,663 Windows Security events, 23,125 Zeek connection records across sensors, 4,496 syslog lines, 4,594 proxy access records, and 324 macOS Endpoint Security notifications. Sensor totals overlap and are not counts of unique enterprise connections. There are 38 distinct eCAR principals, including human, machine, system, and service identities. The volumes and role differences permit meaningful hunting; I did not use the mere presence or absence of a source as an authenticity indicator.

### Download and execution pivots

The support domain appears in several endpoint workflows. On `MAC-MROSS-01`, history and exec telemetry show the Homebrew curl download of `connector-check.sh`, followed by `/bin/bash ... --check-config` at approximately 13:49. On `WS-MCHEN-01`, `curl.exe` downloads the Windows executable around 14:45:35, followed by execution around 14:46:18. On `WS-LNGUYEN-01`, the Linux workflow separates curl at 15:12:25, chmod at 15:12:49, and execution at 15:13:06.

These steps warrant investigation but are not intrinsically malicious or synthetic. In particular, the Linux archive and multipart support upload at approximately 16:31–16:32 have explicit command, file, proxy, and HTTP evidence. I would keep that workflow distinct from the later database export until additional evidence connects them. A narrative that is easy to follow contributes nothing to my synthetic score.

### Privileged Windows activity

`DC-01` contains a service-install pivot for `PSEXESVC` around 17:00:12 and a corresponding process around 17:00:14. The later `svc_dirsync` commands have matching Security account events: account creation at 17:15:07.3475948, password reset at 17:15:08.9516065, account change at 17:15:09.9400573, and Domain Admins membership addition at 17:15:12.8891352. The account SID remains `S-1-5-21-1524654518-2022274387-1755902678-7841` through deletion at 18:50:30.0674830.

Service and scheduled-task commands for `DeviceSyncSvc` have corresponding Security events around 17:19, and its process appears at 17:31:33. A later `wevtutil cl Security` process is followed by Event 1102 at 18:42:21.4159803. I decoded and parsed the embedded TaskContent XML successfully; escaping in a textual representation was not a demonstrated schema defect and was excluded from scoring.

### Database export and receiver behavior

`DB-PROD-01/ecar.json`, records 444–454, provides a concrete export chain: root executes `mysqldump --single-transaction ehr patients insurance_claims` at 18:15:14.955; the process terminates at 18:15:32.907; gzip starts at 18:15:34.725; and scp starts at 18:15:42.334. The transport precedes the receiver's successful authentication. Receiver file creation is observed at 18:16:11.937, with the SSH session closing at 18:16:12.611941 in syslog. Small source timestamp differences around transport close are compatible with observation latency.

At 18:18:51.980, the application host starts the SMB upload. Its local file read at 18:18:58.444 precedes the target's write at 18:18:58.722 to `/srv/samba/ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz`. These pivots support operational feasibility rather than expose a contradiction.

### Process-duration population

For the principal authenticity concern, I used host-local Sysmon `ProcessGuid`, not PID alone, and compared EventData `UtcTime` in visible creation and termination records. Thus the finding does not count pre-window processes as missing or mistake PID reuse for one lifetime. The 774 matched pairs span servers and workstations and have no observed duration below 3.029 seconds.

As a contextual control, the Linux eCAR collection contains 1,612 matched process pairs, including 110 under one second and 1,090 under three seconds, with a minimum of 0.070 seconds. These are different source families and operating systems, so their distributions need not agree. Nevertheless, they show that the supplied data can represent short lifetimes, while the Windows population has a striking shared lower edge across unrelated process families. This is the main reason my score crosses into “likely synthetic”; I did not establish an impossible individual process lifetime, an impossible authentication order, or an identity leak.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Windows Sysmon process creation/termination; supported by normalized endpoint timelines | 774 matched process pairs across ten Windows hosts; every lifetime ≥3.029 seconds, with 25 between 3.029 and 3.298 seconds | Strong apparent shared duration floor, inconsistent with the expected short-lived utility tail. Drives the synthetic lean, but an undocumented short-process filter remains an alternative. |

## Realism Score by Category

- **Field format accuracy:** 9 — Inspected XML, task content, JSON, protocol fields, and native macOS versus normalized records are coherent; no verified format defect was retained.
- **Temporal patterns:** 6 — Individual pivots work, but the Windows process-duration lower edge is conspicuous across the collection.
- **Cross-source correlation:** 9 — SSH, SMB, file ownership, proxy hops, and account changes permit technically sound pivots with plausible source timing differences.
- **Behavioral realism:** 8 — Administrative, support, and suspicious workflows use plausible tools and account boundaries; short-lived Windows process behavior is less convincing.
- **Environmental consistency:** 9 — Visible roles, network segments, remote identities, and source mixes generally agree; no hard environmental contradiction was established.

## Recommendations

- If this were synthetic, remove the apparent common three-second floor from Windows process lifetimes. Model elapsed time by the actual executable and operation, retaining a substantial short-lived tail for lightweight commands and console helpers while preserving longer applications and sessions.
- If the floor instead reflects the real collection pipeline, document that filter or export transformation explicitly. That would materially change interpretation of the strongest authenticity concern without requiring additional log sources.
