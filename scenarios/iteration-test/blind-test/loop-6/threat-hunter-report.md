# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 67

## Executive Summary

The collection supports credible hunting across Windows, Linux, macOS, network, proxy, and file-sharing evidence, and the investigated activity generally respects observable process and transport lifetimes. I nevertheless judge it likely synthetic because ten separate Linux hosts share a pronounced, identical lower-bound PID progression: 67 of 350 successive sysstat-job PID differences are exactly 940, and 940 is the minimum on every host. This is a concrete distribution artifact, rather than a judgment about how neatly the suspicious activity can be narrated; I did not establish an impossible visible ordering in the relationships I checked.

## Evidence For Synthetic

- [distribution_texture] **Repeated PID-allocation floor across unrelated Linux hosts.** Each of ten hosts has 36 visible creations of `/bin/sh -c 'command -v debian-sa1 > /dev/null && debian-sa1 1 1'`. Across their 350 adjacent within-host job pairs, 67 PID increments equal exactly 940; every host has the same minimum increment, 940, despite varied workloads and roles. Examples include APP-INT-01 eCAR lines 204/221, PID 2942647 at 14:05:01.018 to 2943587 at 14:15:01.058; LT-MRIVERA-02 lines 44/56, 3178864 at 14:05:00.394 to 3179804 at 14:15:00.318; and LOG-MON-01 lines 416/442, 711413 at 15:05:59.397 to 712353 at 15:15:59.500. All times are UTC on 2026-11-02. Native syslog corroborates the APP and LT process IDs, so this is not solely a normalization quirk. The periodic cron schedule itself is normal; the common numerical PID floor and repeated exact increments are the anomaly.
- [weak_signal] **Repeated command-line treatment of binary office documents on a Mac.** MAC-MROSS-02 eCAR shows `/bin/cat` reading `project-plan.pdf` at 13:37:29.955, `service-review.xlsx` at 16:05:57.618, `project-plan.docx` at 17:10:47.398, `onboarding.docx` at 17:12:31.889, `draft-draft.pdf` at 18:37:52.303, `project-plan-review.docx` at 18:42:15.750, and `meeting-notes.docx` at 18:45:05.542. These are all seven FILE/READ rows attributed to cat on this host. Such commands work, but repeatedly streaming binary office files to a terminal is unusual user behavior. This contributes only slight weight: collection selection, diagnostic activity, or explicit user behavior could explain it, and I do not infer absent GUI activity from this selection.

## Evidence For Real

- **The SSH pivot between Macs has technically useful transport, account, and execution continuity.** MAC-MROSS-01 runs `/usr/bin/ssh maya.ross@MAC-MROSS-02.meridianhcs.local` as PID 51623; its eCAR FLOW at 14:24:30.924 uses `10.10.1.41:60904 -> 10.10.1.42:22`. `zeek-core/conn.json` line 2323 observes the same tuple at 14:24:29.158851 with a 629.693532-second successful SSH connection. MAC-MROSS-02 Unified Log records acceptance for maya.ross from that exact source/port at 14:24:36.977642. Native Endpoint Security records show a subsequent shell exec, rather than treating network visibility alone as proof of a shell.
- **The database transfer has plausible ordering and byte magnitudes.** DB-PROD-01 shows root login, `mysqldump`, SQL-file creation, gzip, and scp in that order. The scp process exists before its outbound TCP/22 observation, reads the compressed path while alive, and exits after the transfer interval. The 141,964-byte SMB file subsequently staged from APP-INT-01 is compatible in magnitude with the earlier SSH connection's 165,750 originator payload bytes.
- **Multi-sensor observations contain plausible differences.** The same DB-to-APP scp tuple appears in zeek-db and zeek-core with slightly different timestamps and packet observation. The core copy reports 1,016 missed bytes and a gap-marked history; the DB copy reports no missed bytes. This is more credible than assuming every sensor has an identical view.
- **The environment has substantive ordinary activity.** There are 37,537 normalized endpoint records across 23 endpoint host directories, including 17,832 Windows Security events, 4,423 Linux syslog lines, 22,358 Zeek connection rows across three sensors, 3,895 proxy rows, 765 web-access rows, and 146 IDS alerts. Windows evidence includes machine-account authentication, Kerberos tickets, WFP connections, process activity, share auditing, and some failures; Linux evidence includes service, cron, mail, SSH, and Samba activity. Those numbers describe the supplied slice, not a claim of full collection.
- **macOS process events retain fork/exec distinctions.** The native records distinguish the old executing image from an exec target, preserve audit-token identities and credential changes, and show launchd/xpcproxy and login-shell transitions. A normalized PROCESS/MODIFY is therefore not automatically a second new process. The policy message concerning MeetingAssist is not sufficient evidence of successful execution or child effects, and I did not treat it as such.

## Detailed Analysis

### Scope, method, and hunting conditions

I examined only the supplied data directory and the assigned instructions. The collection contains 119 files under 29 top-level directories: 23 endpoint hosts plus three Zeek sensors, two IDS placements, and a perimeter firewall directory. The endpoint records span approximately 13:00–19:00 UTC on 2026-11-02. Apparent addresses include workstation subnet 10.10.1.x, infrastructure subnet 10.10.2.x, DMZ/application subnet 10.10.3.x, and database subnet 10.10.4.x. Host names and the observed services support these role inferences; no scenario or ground truth was used.

I inventoried source volumes, inspected commands and host roles, followed suspicious process/network/file sequences, and programmatically compared visible eCAR actor identities against visible process-create/terminate identities. I also checked UID-matched Zeek DNS/HTTP/TLS/SMB and other available protocol timestamps against the associated connection interval, allowing one second for boundary differences. That protocol check found no rows beyond that tolerance among matched records. These checks are bounded to the supplied schemas and visible identifiers; they are not proof that every possible correlation is correct.

The source mixture presents workable hunting conditions. A small number of clear commands do not by themselves make the data artificial. In particular, the malicious-looking activities being followable, compact, or successful do not contribute to my score.

### Linux process identity texture

The strongest authenticity concern is measurable without knowing which actions are malicious. The sysstat command appears on APP-INT-01, FILE-LNX-01, LOG-MON-01, LT-MRIVERA-02, MAIL-CLIN-01, MAIL-EDGE-01, PROXY-01, WEB-EXT-01, WS-LNGUYEN-01, and WS-OHADDAD-01. There are 35 adjacent pairs per host and 350 overall. Exact increments of 940 occur respectively 5, 8, 8, 12, 6, 5, 6, 6, 5, and 6 times. The remaining increments vary, up to 5,545; overall there are 261 distinct increment values. Thus this is not merely a constant sequence or an unnoticed duplicate file. Instead a common numerical floor recurs beneath otherwise variable activity.

For an explicit native-source cross-check, APP-INT-01 `syslog.log` line 88 records CRON PID 2942647 at 14:05:00.235012 and line 92 records PID 2943587 at 14:15:00.326156. LT-MRIVERA-02 `syslog.log` lines 30/33 record PIDs 3178864/3179804 at 14:05:00.300910 and 14:15:00.185299. Both native-source deltas are exactly 940, agreeing with the normalized records despite normal timestamp differences.

Cron naturally explains ten-minute periodicity and a common sysstat command on centrally managed Linux systems. It does not readily explain the same exact minimum PID increment across ten distinct hosts and 67 repeated hits at that minimum. A standardized hidden workload is a conceivable alternative, but the shared allocation texture across mail, proxy, web, workstation, and monitoring hosts is much more suggestive of a common synthetic identity allocator. I classify this as distribution evidence, not a mathematically impossible kernel behavior.

### Remote sessions and transport-before-auth ordering

The Mac-to-Mac SSH pivot is useful counterevidence to a simplistic synthetic verdict. The native MAC-MROSS-02 Endpoint Security stream shows PID 30038 moving through xpcproxy, sshd-keygen-wrapper, sshd, and sshd-session. It execs sshd-session at 14:24:34.243909, before the Unified Log acceptance message at 14:24:36.977642. PID 30047 execs `/bin/zsh` at 14:24:37.117659 and exits at 14:34:59.248574; the session parent exits at 14:34:59.997721. The network connection lasts until approximately 14:34:58.852383. The small endpoint/transport close differences are plausible source observations.

The normalized eCAR view reports several of those transitions later than native Endpoint Security. For example, eCAR's sshd-session transition is at 14:24:38.057, while the native transition is at 14:24:34.243909. Comparing eCAR's delayed time directly to the earlier Unified Log acceptance could produce a false ordering accusation. The native stream resolves it: sshd-session was already running before acceptance. I therefore do not score this as a contradiction.

### Web execution and database staging

On WEB-EXT-01, eCAR line 873 at 14:20:18.319 records a www-data bash child of apache2 PID 23966 with an encoded pipeline. The visible children are `base64 -d` PID 2702845 and bash PID 2702846. The latter owns an outbound FLOW to `45.33.32.30:8443` at 14:20:29.880, matching zeek-dmz connection UID `Cj2ylGB9IR03zXnHw8e` at 14:20:29.525765. The connection has a 1.994667-second successful interval, 620 originator bytes, and 1,840 responder bytes. Both shell processes terminate later, around 14:20:36. These records support an executed shell/network attempt; the short connection does not prove a sustained interactive compromise.

On DB-PROD-01, eCAR lines 525–529 show inbound SSH, root login at 18:15:04.597, a bash process at 18:15:06.500, and mysqldump at 18:15:08.750. The gzip process starts at 18:15:32.980 and exits at 18:16:01.127. The subsequent scp PID 1089171 starts at 18:16:02.840, has an outbound FLOW at 18:16:06.512, reads `/tmp/rpt_0318.sql.gz` at 18:16:13.736, and exits at 18:16:37.821. The zeek-db transfer begins at 18:16:05.912335 and lasts 30.555910 seconds; APP-INT-01 syslog shows the root SSH session opening at 18:16:12.968063 and closing at 18:16:36.987236. These are compatible phases.

Later `zeek-core/smb_files.json` lines 226/227 show APP-INT-01 writing `Integration\\DB-Staging\\rpt_0318.sql.gz` to FILE-LNX-01's ClinicalResearch share. The corresponding `files.json` line 632 reports 141,964 observed/total bytes with no missing bytes. FILE-LNX-01 native Samba audit at 18:18:57 records successful open/write/close for the same path and source address. The file path provides a defensible pivot; I do not infer file-content identity solely from a reused filename.

### macOS behavior and limits of inference

The Mac workflow includes shell history, normalized endpoint records, native Endpoint Security, and a very small Unified Log selection. I did not demand broad Unified Log volume, a particular audit facility, missing Sysmon types, or endpoint evidence for every network observation.

MAC-MROSS-01 visibly downloads connector-check.sh with Homebrew curl and subsequently invokes it with bash; those are separate observations. The download is visible as a FILE/CREATE at 14:01:13.164 and the bash exec as PROCESS/MODIFY at 14:01:21.965. A proxy access timestamp around 14:01:14 is compatible with access logging near transaction completion and does not establish that the file was created before the request began. Similarly, creation/deletion of the endpoint-inventory plist is not, by itself, proof of registration, activation, or unload.

The repeated binary-document cat commands on MAC-MROSS-02 are a much weaker issue than the Linux PID distribution. They make the observed file-access behavior feel mechanically selected, but they are executable commands and could be intentional. I give them little score weight and make no claim that office applications must have been collected.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Linux eCAR process records, corroborated by native CRON syslog | Ten hosts; 360 jobs; 350 adjacent pairs; 67 exact +940 increments; identical minimum on every host | Primary reason for a likely-synthetic score: a shared numerical allocation pattern across independent host workloads. Periodic scheduling itself is not penalized. |
| weak_signal | macOS normalized process/file records | Seven cat-attributed binary-document reads on MAC-MROSS-02 | Small contribution only; unusual repeated observed behavior, with plausible alternative explanations. |

No demonstrated hard contradiction or required-companion contract gap is asserted in this assessment. The score is below the 81–100 range because the principal defect is statistical identity texture and the reviewed operational relationships are mostly coherent.

## Realism Score by Category

- **Field format accuracy:** 8 — Windows XML, Zeek JSON, RFC5424-like syslog, shell histories, and versioned macOS records are usable; no decisive native-schema defect was demonstrated.
- **Temporal patterns:** 8 — Service periodicity, activity bursts, and investigated transport/auth/file lifetimes are plausible; native versus normalized timestamp differences require care.
- **Cross-source correlation:** 9 — Exact tuples, paths, process identities, and session boundaries support the investigated pivots, including sensible sensor-specific observation differences.
- **Behavioral realism:** 7 — Executed commands and staging operations generally work together; repeated cat use on binary office files is an odd but possible behavior pattern.
- **Environmental consistency:** 6 — The roles and source mixture are credible, but the identical Linux PID floor across very different hosts is a substantial environment-wide authenticity defect.

## Recommendations

- If this were synthetic, replace the shared PID progression floor with host-specific process-allocation behavior driven by each host's task activity, uptime, and background process churn. Validate the distribution of successive sysstat-job PID deltas across hosts; the exact +940 minimum should not recur in 19.1% of adjacent pairs across ten independent machines. Preserve the valid cron periodicity and cross-source identity agreement.
- If this were synthetic, revisit the repeated `/bin/cat` reads of PDF, DOCX, and XLSX files on MAC-MROSS-02. Tie the observed commands to a defensible user workflow or use actions that suit the document type; do not add arbitrary sources merely to increase coverage.
- Retain the useful SSH, file-transfer, and multi-sensor distinctions demonstrated here. Evaluate ordering with source-native occurrence timestamps before comparing it with delayed normalized observations, so improvements do not erase realistic collection differences.
