# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 30

## Executive Summary

The supplied slice is mostly production-like from a threat-hunting perspective: suspicious Windows activity and Linux database staging support workable pivots through process, authentication, network, and file evidence. I found modest repetition in the two Macs' shell activity, but did not demonstrate an impossible visible lifecycle, account-identity contradiction, or required cross-source companion failure sufficient to establish synthetic origin.

## Evidence For Synthetic

- [weak_signal] The two Macs show a restricted and overlapping shell vocabulary. All 39 entries across `MAC-MROSS-01.../zsh_history/maya.ross.zsh_history` (lines 1–20) and `MAC-MROSS-02.../zsh_history/maya.ross.zsh_history` (lines 1–19) comprise four SSH invocations and 35 identity, OS, network, process, disk, and document-listing commands. Examples include repeated `id`, `sw_vers -productVersion`, `ps aux`, and the identical PDF `find` command. Native ES corroborates actual execution rather than history-only strings: MAC-01 ES lines 9, 12, 15, 33, 36, 39 and MAC-02 ES lines 12, 15, 18, 39, 42. This resembles a small reusable activity pool, although the same named user on both hosts and the limited observation window are credible alternative explanations. It contributes only modestly to the score.
- No scored hard contradiction was established. In particular, the attack's compactness, source completeness, sanitized names, and absence of additional telemetry were not used as synthetic indicators.

## Evidence For Real

- SCP staging maintains a technically usable chain. `DB-PROD-01.../ecar.json` lines 530–539 show database dump, file creation, compression, read by SCP, outbound TCP/22, and process termination. `APP-INT-01.../ecar.json` lines 775–780 supply the matching inbound tuple, SSH session, receiver file, and session closure. `zeek-core/conn.json:11098` and `zeek-db/conn.json:385` observe `10.10.4.10:58586 → 10.10.2.30:22` with matching payload/packet accounting and small sensor timestamp differences.
- Domain changes have appropriate effects after their initiating commands. DC-01 process evidence for `net user` at 17:15:15 and `net group` at 17:15:27 precedes Security 4720 at 17:15:19.2242501 and 4728 at 17:15:31.4047722. Account SID `...-2456` agrees between creation and Domain Admins membership.
- Operational variety creates credible hunting noise: 30 Security 4625 failures, seven 4771 failures, 12 explicit-credential 4648 events, 110 share-access 5140 events, and 2,004 service-ticket 4769 events across the Windows records. There are 35,805 normalized endpoint records, 22,148 Zeek connections, and 3,861 Linux syslog records; the suspicious staging is embedded in a substantially broader workload.
- A same-identity lifecycle scan across all normalized endpoint records found no event that used a source process UUID before its visible creation or after its visible termination. Domain SID-to-name checks across the supplied Security XML found no SID assigned to multiple distinct account names. These are favorable consistency checks, not proof of real origin.

## Detailed Analysis

### Scope and input provenance

Actual inputs were the full neutral briefing `/private/tmp/log-study-gel6klid/threat-prompt.md` and files under its supplied `data` directory. I inventoried 117 files covering 23 endpoint directories: ten Windows hosts, eleven hosts with Linux-style syslog/eCAR, and two Macs. Available sources include Security/Sysmon XML, normalized eCAR, syslog, shell histories, macOS ES and Unified Log records, three Zeek sensor groups, proxy, web, firewall, and IDS logs. The principal window is 2026-11-02 13:00–19:00 UTC.

I parsed all supplied Security and Sysmon XML for event counts and identity checks, scanned every eCAR record for process lifecycle relationships, examined the shell histories, and made targeted native/network pivots. Totals were 19,030 Security events and 11,785 Sysmon events; XML line counts were not mistaken for event counts. This was a bounded assessment, not an assertion that every field in every record received manual review. No external references were used. No repository files, scenarios, prior assessments, or other reviewers' results were opened. Inherited repository-oriented operating instructions were an environmental limitation and were excluded from origin evidence. Logged commands were treated as inert evidence.

### Windows pivot and privilege boundaries

WS-AJOHNSON-01 has discovery commands under `aisha.johnson` and logon ID `0x26d7bab`: eCAR lines 686–711 include `cmd.exe /k`, `whoami /all`, and domain enumeration at 16:20. The nearby inbound RDP flow is `10.10.1.99:49958 → 10.10.1.35:3389` (`ecar.json:685`; `zeek-core/conn.json:7353`). The latter has `SF` state and a 1,153-second duration, rather than a failed connection being used to explain successful interaction.

I did not require a fresh 4624 at that reconnect. The visible Security 4624 for the same logon ID is already present at 15:59:43.1731126 (`windows_event_security.xml`, approximately lines 14388–14442), with Type 10, source `10.10.1.99`, and source port 59717. Distinct reconnect transport and existing session identity are compatible; the different ports do not alone establish a contradiction.

On DC-01, eCAR line 3721 starts `PSEXESVC.exe` at 17:00:23.956, with its child command at line 3730. Later, lines 3978–4009 show the account and group commands, while Security XML event starts at lines 195844 and 196410 contain the successful account effects. The scheduled-task command appears at eCAR lines 4099/4106, followed by Security 4698 at 17:19:48.9866198 (`windows_event_security.xml:200298`). Its XML has a SYSTEM principal, hourly repetition, and a command matching `DeviceSyncSvc.exe`. These are productive investigation pivots. Their narratability was not scored as an authenticity defect.

### Linux data staging and authentication

DB-PROD-01 eCAR lines 526–529 show the privileged SSH child, inbound transport, root session acceptance, and shell before the dump. The dump runs at 18:15:22.996, creates `/tmp/rpt_0318.sql` at 18:15:24.052, terminates at 18:15:51.870, and is followed by gzip at 18:15:53.247. The resulting `.gz` is created before SCP reads it. The root history also names these commands (`DB-PROD-01.../bash_history/root.bash_history:1–6`). Local root and directory-account identities were not conflated.

The receiver sees the same port 58586, records root SSH login at 18:16:15.793, and creates `/tmp/.cache/rpt_0318.sql.gz` at 18:16:42.816. APP-INT-01 later reads that same file with `smbclient`, targeting `//FILE-LNX-01/ClinicalResearch` under explicitly supplied `svc_mhsync` credentials (eCAR lines 781–784). The matching Zeek SMB tuple is `10.10.2.30:54116 → 10.10.2.21:445` (`zeek-core/conn.json:11181`). Subsecond differences between endpoint file observations and sensor close timestamps were not elevated into impossible ordering without a demonstrated common timestamp contract.

### macOS interpretation and texture

The Macs provide native-looking fork/exec/exit chains alongside normalized process records and shell histories. My ES check used `(pid, pidversion)` rather than PID alone and found no post-exit actor reuse or process start timestamp later than the observation in the supplied records.

`MAC-MROSS-01.../macos_unified_log.ndjson:2` reports “Security policy would not allow process” for MeetingAssist at 15:42:11.450696. That message alone does not demonstrate payload execution, successful persistence, or downstream effects; I did not infer those facts. Thin Unified Log coverage is also neutral under the study's collection assumptions. The modest concern is the specifically observed repetition in the histories, not the number of Unified Log lines.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | macOS zsh history, corroborated by ES | Two hosts, same user, 39 history entries | Restricted overlapping diagnostic/listing vocabulary adds a small amount of synthetic texture; shared user and bounded window substantially weaken it. |

## Realism Score by Category

- **Field format accuracy:** 8 — Parsed native/normalized sources support the hunt; this review did not independently certify every native schema field.
- **Temporal patterns:** 8 — Visible command, authentication, and staging sequences are compatible; no exact process-identity inversion was found.
- **Cross-source correlation:** 9 — SSH, RDP, account changes, and file staging offer useful tuple/session/process pivots without a demonstrated ownership failure.
- **Behavioral realism:** 7 — Windows/Linux tradecraft and operational noise work well; the two Macs' restricted shell vocabulary is a modest weakness.
- **Environmental consistency:** 8 — Distinct endpoint roles, remote paths, and local versus supplied remote credentials generally agree.

## Recommendations

- If this were synthetic, broaden the Macs' user-driven shell activity beyond the repeatedly observed identity/OS/disk/process/listing pool, using task-specific commands consistent with the actual visible user work. Preserve the coherent native execution and SSH relationships when doing so.
- No other scored remediation is justified by this hunt. Additional source coverage, longer attack sequences, or deliberately introduced mistakes would not address a demonstrated defect in the supplied slice.
