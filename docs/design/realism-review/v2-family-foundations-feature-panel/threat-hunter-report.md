# Threat Hunter — Feature-Branch Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 96
**Synthetic-Confidence Score:** 92

## Executive Summary

The data is operationally rich and often correlates convincingly across endpoint, network, firewall, and native OS sources. However, repeated SSH lifecycle contradictions and dataset-wide end-of-window closure behavior form a strong generator fingerprint: unrelated sessions across hosts terminate within seconds of the collection boundary, some source-native `systemd-logind` removals reference the wrong session IDs, and every one of 6,994 ASA connection builds has a visible in-window teardown.

## Evidence For Synthetic

- **[hard_contradiction] Repeated SSH session-ID mismatches at the collection boundary.**
  - On `PROXY-01`, eCAR ties sshd PID `630247` and Marcus Chen’s session to `session_id=267743`, beginning at `17:18:42.652`; at `17:59:39.682`, syslog closes that same PID/user, but `systemd-logind` removes session `266605` at `17:59:40.050`, not `267743`.
  - On `MAIL-EDGE-01`, eCAR ties sshd PID `235340` to `session_id=275297`, beginning at `17:39:48.791`; syslog closes PID `235340` at `17:59:39.379`, then removes session `272328` at `17:59:40.077`, not `275297`.
  - On `APP-INT-01`, eCAR assigns Marcus Chen’s session to `378710`; syslog closes its sshd PID `1935411` at `17:59:40.341` and then removes session `375891`, not `378710`.
  - These are not merely missing pre-window starts: the initiating eCAR sessions and terminating sshd processes are visible inside the window, and the immediately adjacent source-native removal references a different identifier.
- **[distribution_texture] Unrelated sessions converge artificially on the six-hour boundary.**
  - The final five-minute bin contains 16 eCAR logouts, versus a maximum of 9 in any prior five-minute bin except the terminal bin.
  - Marcus Chen’s SSH sessions on `PROXY-01`, `MAIL-EDGE-01`, and `APP-INT-01` close between `17:59:39` and `17:59:41`; the root DB session closes at `17:59:40`; interactive Windows sessions on `WS-AJOHNSON-01`, `FILE-SRV-01`, `MAIL-FIN-01`, and `DC-01` close around `17:59:42–17:59:45`.
  - This multi-host, multi-session convergence is far tighter than normal user or administrator behavior and coincides exactly with the collection cutoff.
- **[distribution_texture] Complete firewall lifecycle closure is implausibly boundary-clean.**
  - `fw-perimeter/cisco_asa.log` contains 6,994 `Built` connection records and exactly 6,994 corresponding teardowns: zero unmatched builds, zero teardown-before-build cases, and zero connections continuing beyond the slice.
  - The log still records new TCP connections as late as `17:58:36` (IDs `1699861` and `1699862`), demonstrating that connection starts were being collected near the boundary. In a raw six-hour production slice containing thousands of TCP connections and several long-lived SSH sessions, some visible builds would normally remain open past the cutoff.
- **[contract_gap] Selectively orphaned SSH lifecycle evidence recurs in local syslog.**
  - `APP-INT-01` eCAR records the DB-to-APP SCP receiver flow, root login `378847`, and file creation `/tmp/.cache/rpt_0318.sql.gz` at `17:28:20–17:28:27`, while local syslog contains only the root session-close/removal at `17:28:41`; connection, acceptance, PAM open, and new-session records are absent.
  - More broadly, eCAR exposes eight remote SSH logins on `APP-INT-01` but syslog has seven PAM opens; `DB-PROD-01` shows five versus four; `MAIL-EDGE-01` five versus four. Individual loss is plausible, but the repeated fragmentation around otherwise intact local lifecycle records adds to the synthetic assessment.
- **[weak_signal] Highly regular scheduled baseline texture.**
  - `debian-sa1` runs at exact 30-minute intervals with only sub-second variation on nearly every Linux host, using stable host-specific minute offsets. Cron regularity is source-realistic, so this has low impact by itself, but combined with the boundary behavior it resembles deterministic scheduled generation.

## Evidence For Real

- The intrusion chain has strong, technically meaningful pivots:
  - ASA records external SSH `10.10.1.99:37339 → 10.10.3.10:22` at `13:39:37`.
  - `WEB-EXT-01` root reads `/var/www/html/config.php` and `/root/.ssh/id_rsa`, then runs `ssh root@APP-INT-01` at `14:14:18`.
  - ASA sees the WEB-to-APP SSH flow at `14:14:29`; `APP-INT-01` records root SSH acceptance/open around `14:14:39`.
  - APP pivots to `DB-PROD-01` at `17:14:36`; DB syslog records connection at `17:14:38`, root password acceptance at `17:14:45`, and session open immediately afterward.
  - DB activity progresses through database discovery, `mysqldump`, compression, hashing, and SCP; APP records the matching inbound tuple and file creation.
- The Windows portion uses plausible source-native semantics:
  - On `DC-01`, SYSTEM creates `svc_dirsync` at `16:15:02`, adds it to Domain Admins, creates `DeviceSyncSvc` and a scheduled task around `16:20`, clears Security at `17:41:41`, and deletes the account at `17:50:26`.
  - Event ID 1102 correctly resets the Security `EventRecordID` from the 28-million range to `1`, rather than producing a simple monotonicity error.
- Host roles are visible in source mix:
  - `DC-01` is dominated by DNS, Kerberos, LDAP, and machine-account authentication.
  - Mail hosts contain SMTP/IMAP activity; `PROXY-01` carries high proxy-flow volume; `WEB-EXT-01` shows heavy inbound scanning and web activity; `DB-PROD-01` shows database administration and application traffic.
- Zeek texture is varied rather than trivially uniform:
  - Core connection states include `SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `OTH`, `S1`, `S2`, and `S3`.
  - Protocol companion records have valid connection UIDs and occur within their associated connection intervals.
- Baseline activity includes failures, stale or pre-window state, scanner noise, transient service behavior, and varied human administration commands. These provide credible operational clutter.

## Detailed Analysis

The visible environment comprises user workstations, Linux and Windows servers, a domain controller, mail systems, an explicit proxy, DMZ web infrastructure, Zeek sensors, IDS sensors, and an ASA perimeter device. The six-hour window runs approximately `12:00–18:00 UTC` on 2024-03-18.

The primary threat-hunting pivot is external root access to `WEB-EXT-01`, followed by credential/key discovery, SSH to `APP-INT-01`, and later APP-to-DB root access. The DB session performs credible collection and staging: `SHOW DATABASES`, `SHOW TABLES FROM ehr`, `mysqldump --single-transaction ehr patients insurance_claims`, `gzip`, `sha256sum`, then SCP to APP. Tuple reuse and timing across eCAR, syslog, ASA, and network records are generally coherent.

The Windows branch is similarly usable for hunting. `PSEXESVC.exe`, WMI-hosted commands, account creation, privileged group modification, service installation, scheduled-task persistence, encoded PowerShell, Security-log clearing, and account deletion appear in appropriate source families. The Event ID 1102 and record-number reset are particularly production-like.

The decisive authenticity defect is lifecycle handling at the right edge of the window. Several long-lived user and attack sessions are forcibly closed in a narrow two-to-six-second band just before `18:00`. The corresponding Linux close bundles sometimes splice a current sshd PID and current user onto a stale or unrelated `systemd-logind` session ID. This cannot be explained merely by pre-window state because the current sessions’ visible starts and IDs are present in eCAR. The same closing pattern appears on three separate Linux servers.

The firewall reinforces the same boundary artifact. Every ASA build has an in-window teardown, including long-lived attack sessions and late-window connections. A production slice could be constructed from completed transaction records, but these are source-native ASA `Built` and `Teardown` messages interleaved as an event stream, not an aggregation that inherently excludes still-open connections. Zero right-censored connections across 6,994 builds is consequently a strong distribution-level signal.

Source volume and behavioral diversity otherwise score well. The evidence is not synthetic merely because the intrusion is discoverable; the verdict rests on identifier contradictions and repeated dataset-boundary termination behavior.

## Synthetic Indicator Summary

| Category | Source family | Scope | Score impact |
|---|---|---:|---:|
| hard_contradiction | Linux syslog + eCAR SSH | Repeated on PROXY, MAIL-EDGE, and APP-INT | Very high |
| distribution_texture | eCAR/syslog session lifecycles | Multi-host terminal-bin clustering | Very high |
| distribution_texture | Cisco ASA | Dataset-wide: 6,994/6,994 builds closed | High |
| contract_gap | Linux SSH/PAM/logind | Repeated orphaned lifecycle phases | Moderate |
| weak_signal | Linux cron/sysstat | Broad but source-plausible | Low |

## Realism Score by Category

- **Field format accuracy:** 8/10 — Most source-native schemas and values are convincing, but the SSH/logind identifier mismatches are material.
- **Temporal patterns:** 4/10 — Fine-grained attack ordering is good, but terminal-boundary session convergence and perfect connection closure are strong synthetic tells.
- **Cross-source correlation:** 8/10 — The main intrusion pivots correlate well across sources; the score is reduced by repeated SSH close-bundle inconsistencies.
- **Behavioral realism:** 8/10 — Host roles, administration, failures, scanner activity, and attack tradecraft are plausible.
- **Environmental consistency:** 6/10 — The source-family mix is credible, but collection-boundary behavior is inconsistent with a normal event-stream slice.

## Recommendations

If synthetic:

- Allow active TCP and application sessions to remain open beyond the collection boundary; do not synthesize terminal teardown/logoff events solely to complete lifecycles within the output window.
- Preserve one canonical SSH session identifier through eCAR login/logout and source-native PAM/logind open/removal records. A close bundle must never substitute a prior session ID.
- Apply source observation decisions coherently to the entire source-local SSH lifecycle so collection loss does not retain a close/removal while dropping all connection, acceptance, PAM-open, and new-session evidence for the same session.
- Add boundary-specific validation that checks terminal-bin spikes, percentage of firewall builds closed in-window, and multi-host convergence of unrelated session shutdowns.
- Retain the existing host-role, protocol, and attack-pivot modeling; those portions materially improve hunting realism.
