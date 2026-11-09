# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 77
**Synthetic-Confidence Score:** 63

## Executive Summary

The telemetry supports useful, technically coherent hunts across Windows, Linux, macOS, network sensors, and a proxy. I lean synthetic because a sustained interactive development session repeatedly advances on an approximately 96-second grid despite changing commands, editors, files, and command runtimes. This is a distribution finding, not a demonstrated impossible intrusion lifecycle; the otherwise strong operational correlations keep the score near the bottom of the “likely synthetic” band.

## Evidence For Synthetic

- [distribution_texture] Interactive development commands repeatedly start approximately 96 seconds apart. In `WS-LNGUYEN-01.meridianhcs.local/ecar.json`, lines 287, 293, 295, and 303 start `vim`, `vim`, `emacs`, and `cargo clippy` at 16:09:40.789, 16:11:16.610, 16:12:52.196, and 16:14:28.284 UTC: gaps of 95.821, 95.586, and 96.088 seconds. Lines 325, 329, 331, 333, and 335 repeat the pattern at 16:25:45.353, 16:27:21.342, 16:28:56.562, 16:30:32.717, and 16:32:08.548: gaps of 95.989, 95.220, 96.155, and 95.831 seconds. Across the 16 consecutive process-start gaps from line 287 through line 335, ten lie between 95.220 and 96.330 seconds. The commands operate on different projects and file types, while their visible runtimes differ substantially. A repeated scheduling interval with small jitter is a stronger explanation than ordinary manual editing, although scripted demonstrations remain a possible real-data explanation.

## Evidence For Real

- Identity boundaries survive a useful hunting pivot. `WS-AJOHNSON-01.meridianhcs.local/ecar.json` lines 1221 and 1230 show `runas.exe /netonly /user:marcus.chen` followed by a local `aisha.johnson` command shell. Security XML line 28252 identifies the corresponding Type 9 logon, `TargetLogonId=0x27caa1f`, with local target user `aisha.johnson` and `TargetOutboundUserName=marcus.chen`. Subsequent server-side SMB logons correctly identify `marcus.chen` from `10.10.1.35`, including `FILE-SRV-01.meridianhcs.local/ecar.json` line 1211 and `FILE-LNX-01.meridianhcs.local/ecar.json` line 1293. The different local and remote principals are meaningful, rather than an identity contradiction.
- SSH pivots are technically usable. `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` line 42 executes SSH to DB-PROD-01 at 14:01:49.324880 UTC. `zeek-db/conn.json` line 76 records `10.10.1.41:62565 → 10.10.4.10:22`, UID `C5Bjqwolr19auVnTjl`, and DB syslog lines 77–80 record connection, public-key acceptance, PAM opening, and a logind session for that tuple. The DB account UID is 2176, while the Mac account UID is 501; these are separate local account namespaces and are plausible.
- Suspicious file movement has receiver-side effects. DB process and file records at 18:15–18:16 show database export, compression, and SCP; APP-INT-01 subsequently records the receiving SSH session and `/tmp/.cache/rpt_0318.sql.gz`. A later SMB transfer reaches FILE-LNX-01, whose syslog lines 462–464 record successful open, write, and close under `svc_mhsync`, and whose eCAR line 1366 names the corresponding destination file.
- Background evidence has useful variation. Windows failed logons include incorrect passwords on workstations and disabled `svc_deploy` attempts on MAIL-FIN-01. Linux records include cron, anacron, privilege escalation sessions, name-resolution degradation/recovery, mail queue activity, and service-specific logs. This is considerably more believable than an environment consisting only of suspicious commands.
- Protocol evidence is not uniformly pristine. For example, `zeek-db/conn.json` line 76 has `missed_bytes=692` and retransmission/gap-bearing history `ShADadTtFfGg`, whereas line 141 has zero missed bytes and a different history. Web responses include 200, 404, 403, 304, redirects, partial responses, and a small number of server errors and throttles.

## Detailed Analysis

### Scope, provenance, and method

I read the supplied neutral briefing and files beneath the specified `data` directory only. I did not inspect project files, scenarios, previous assessments, or other reviewers' reports, and did not use web sources. Generic inherited operating instructions were not treated as evidence of origin.

The directory contains 119 files and 23 endpoint directories with 35,635 normalized eCAR records. Endpoint timestamps span approximately 13:00–19:00 UTC on 2 November 2026. The apparent environment includes Windows domain controllers and workstations, Windows and Linux file servers, Linux application/database/web/mail/proxy/monitoring systems, Linux user endpoints, and two Macs. Network addresses show user systems in `10.10.1.0/24`, internal infrastructure in `10.10.2.0/24`, DMZ infrastructure in `10.10.3.0/24`, and the database at `10.10.4.10`.

There are three Zeek collections, with 12,251 core, 9,122 DMZ, and 432 database connection records: 21,805 observations, not 21,805 distinct enterprise flows, because sensors overlap. Other sources include Windows Security and selected Sysmon XML, Linux syslog and shell histories, macOS Endpoint Security and Unified Log, web/proxy access logs, ASA messages, and Snort alerts.

I parsed endpoint records across the supplied fleet, inspected Windows event-family counts, checked visible process identities and parent references against their visible creation/termination times, examined suspicious commands and file paths, and pivoted selected activity into native and network evidence. I found no confirmed same-process use-before-creation, use-after-termination, or overlapping visible PID allocations in those eCAR checks. This is bounded evidence of coherence, not proof that every native field is authentic.

### The strongest authenticity concern: interactive pacing

The development session is the reason for the synthetic verdict. The repeated spacing occurs across `vim`, `emacs -nw`, `nano`, and test/build commands; it is not a periodic system service or cron job. Its timing pattern is also reflected at whole-second resolution in `WS-LNGUYEN-01.meridianhcs.local/bash_history/lina.nguyen.bash_history`.

The visible process durations do not account for the repeated start interval. For example:

| eCAR create / terminate lines | Command | Visible runtime |
|---|---|---:|
| 287 / 290 | `vim .../monitoring/index.js` | 41.747 s |
| 293 / 294 | `vim .../api-server/index.js` | 86.249 s |
| 295 / 300 | `emacs -nw .../api-server/server.go` | 35.957 s |
| 325 / 328 | `emacs -nw .../monitoring/Makefile` | 41.479 s |
| 329 / 330 | `nano .../data-pipeline/Makefile` | 65.484 s |
| 331 / 332 | `nano /opt/company/webapp/server.go` | 70.810 s |
| 333 / 334 | `nano .../data-pipeline/index.js` | 68.928 s |

Despite those runtime differences, the next command after each listed editor launch starts approximately 96 seconds after the preceding launch. Ten narrow gaps among 16 consecutive start gaps over more than twenty minutes make this a sustained local distribution artifact. The finding concerns measurable command timing, not the narratability or completeness of suspicious activity. It could also arise from automation captured in a real environment, which is why verdict confidence is 77 rather than near certainty.

### Hunting suspicious activity and testing the pivots

The web server has a suspicious Apache-child shell at 14:20:13.292 (`WEB-EXT-01.meridianhcs.local/ecar.json` line 850), followed by an outbound connection from its recorded process identity to `45.33.32.30:8443` at line 852. Web access line 462 records a POST to `/ehr/admin/upload.php`. A nearby TLS connection from `185.70.41.45:60647` is visible in `zeek-dmz/conn.json` line 1743 and `ssl.json` line 735, and ASA lines 4069 and 4079 provide its build and teardown. These are strong investigation leads. The records do not expose the POST body or an explicit request-to-process identifier, so I do not claim that the nearby request is conclusively the initiating exploit, or score subsecond cross-source differences as impossible causality.

APP-INT-01 then has a successful root SSH login from `10.10.3.10:59954`, with native syslog connection/authentication/session records at lines 109–112. eCAR lines 209–210 record the root login and shell, and lines 248 and 250 show reads of `/etc/passwd` and `/etc/shadow`. The visible privileged account establishes the permission context for those reads; no invented privilege-escalation step is needed to explain them.

On DC-01, eCAR line 3661 shows `PSEXESVC.exe` and line 3669 its `cmd.exe /c whoami && hostname` child. Security records show service installation at 17:00:03.9729050, user creation for `svc_dirsync` at 17:15:06.3412978, and Domain Admins membership addition at 17:15:11.5179152. Later service and scheduled-task command lines are also present. These are actionable privilege/persistence leads, but their compactness and completeness are not authenticity evidence.

The DB-to-APP-to-file-server movement is another coherent pivot. DB eCAR lines 476–477 identify `mysqldump` and its SQL output, lines 479–480 identify compression and the compressed output, and lines 482–484 identify SCP and the source-file read. APP eCAR line 746 records the receiving file, and line 749 the later `smbclient` upload. `zeek-core/smb_files.json` lines 228–229 carry UID `CUeHjW83VFwDO8jMRNQ` and the destination `Integration\DB-Staging\rpt_0318.sql.gz`; FILE-LNX-01 syslog and eCAR independently expose the receiver-side write. The records allow a hunter to follow the same artifact without conflating root on Linux with the directory service account used for SMB.

The Windows archive sequence preserves the important `/netonly` boundary discussed above. Local archive creation is attributed to `aisha.johnson`; remote file-server authentication is attributed to the supplied outbound credentials. ECar line 1405 later shows `curl.exe` submitting `cache_7f3a.zip` through the proxy. This is a realistic credential-use distinction that often determines whether a hunt attributes remote access correctly.

### Signal, noise, and platform interpretation

I would need to hunt rather than merely read a few attack rows. The collected connection mix includes DNS, Kerberos, LDAP, SMB, proxy traffic, database connections, SSH, mail, and RDP. Security data includes authentication noise as well as privilege and object-access events. Its existence and diversity support realism; exact completeness is neutral under the study's collection assumptions.

I did not penalize sparse Unified Log exports, deliberately selected Sysmon types, missing out-of-window process/session boundaries, or the absence of optional endpoint products. The Mac ES records are distinct from normalized eCAR, and shell history is distinct from an execution notification. In particular, the policy message for MeetingAssist in `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson` line 2 is not by itself proof that the application ran successfully, and I did not attribute downstream effects to it.

Likewise, slow commands are not automatically contradictions. The remote Mac `id` process in ES lines 87–88 lasts roughly 85 seconds, but name-service delays can make that possible. Mac commands from a common shell while SSH exists could involve suspension or other shell interaction that these selected records do not expose. Neither observation supports a hard-contradiction finding here.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Linux eCAR process lifecycle; supporting Bash history | One development workstation, 16:09:40–16:32:08 UTC; ten of sixteen consecutive process-start gaps within 95.220–96.330 s | Strong local scheduling fingerprint across changing interactive commands and variable runtimes; drives the score to 63. It is not a dataset-wide impossible lifecycle. |

No confirmed `hard_contradiction` is included. Source alignment, thin coverage, suspicious-activity linearity, and absence of attacker mistakes did not increase the score.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source structures and the inspected identities/paths are credible; this was not an exhaustive vendor-schema audit.
- **Temporal patterns:** 6 — Most observed lifecycle timing is usable, but repeated approximately 96-second interactive scheduling is a substantial artifact.
- **Cross-source correlation:** 9 — Selected SSH, SMB, explicit-credential, proxy, and file-transfer pivots preserve useful tuples and identities.
- **Behavioral realism:** 7 — Operational privilege and transfer semantics are convincing; the development-session pacing weakens the human-activity texture.
- **Environmental consistency:** 9 — The mixed fleet, segmented addressing, service roles, and background source mix largely fit together.

## Recommendations

- If this were synthetic, replace the repeated approximately 96-second interactive command schedule with timing conditioned on the actual activity and prior command completion. In the cited development session, editor runtimes, thinking time, quick follow-up commands, and longer idle gaps should produce a broader and less quantized start-gap distribution.
- If that development activity intentionally represents a scripted demonstration or automated exercise, preserve log-visible evidence of that execution context. A real automation explanation would materially change how the measured pacing should be interpreted.
