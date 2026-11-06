# Assessment

**Verdict:** Mostly coherent host telemetry, with one moderate eCAR/Endpoint Security ordering inconsistency and a smaller login-failure texture concern. I found no confirmed hard contradiction in the reviewed host records.

**Verdict Confidence:** 0.86  
**Synthetic-Confidence Score (lower = more production-like):** 5/10

## Executive summary

The host evidence has credible OS-specific shapes and process/session relationships. macOS Endpoint Security records use distinct fork, exec, and exit observations; process identity carries audit tokens, PID versions, credentials, and parent/responsible process information. The SSH examples follow a believable client-flow-to-server-session chain. Windows Security and Sysmon records have familiar event/provider layouts and consistent process-start timing in sampled pairs. Linux records use RFC 5424-style syslog lines, PAM/systemd session messages, and timestamped shell histories.

The main issue is that the macOS eCAR projection can put a successful SSH `USER_SESSION LOGIN` just before its process-create rows, while the raw Endpoint Security sequence shows the shell/session process already starting earlier. This may be source publication delay, but the eCAR timeline does not make that delay explicit and its ordering can mislead an analyst. A four-event local bad-password burst on MAC-MROSS-01 also has a notably regular cadence. Neither finding alone establishes an impossible event.

## Concrete evidence for production-like behavior

- **macOS local shell lineage:** On MAC-MROSS-01, `macos_endpoint_security.ndjson` lines 1–7 (13:08:00.998–13:08:01.085Z) move from launchd/xpcproxy through Terminal and `login` to `/bin/zsh`. The process changes privilege from root login helper to UID 501 shell while retaining audit identity. Lines 8–16 then show zsh spawning `id`, `sw_vers`, and `uname`, with matching exits. The zsh history lines 1–3 record the same commands at 13:08:07, 13:08:26, and 13:09:14.
- **macOS outbound/inbound SSH correlation:** MAC-MROSS-01 history line 7 and Endpoint Security line 47 place `ssh maya.ross@MAC-MROSS-02...` at about 14:24:37Z. Its eCAR `ecar.json` line 98 records TCP 10.10.1.41:59129 → 10.10.1.42:22 at 14:24:47.996Z. On MAC-MROSS-02, Unified Log line 2 records `Accepted keyboard-interactive/pam for maya.ross from 10.10.1.41 port 59129` at 14:24:53.650676Z; eCAR line 146 records the matching SSH login at 14:24:54.383Z. The remote session then has an sshd-session-to-zsh chain in Endpoint Security lines 63–71 and a corresponding zsh history beginning at 14:26:40.
- **Windows native records:** XML parses successfully for the sampled Security/Sysmon files. A sampled FILE-SRV-01 Security 4688 at 13:00:23.856Z is adjacent to Sysmon Event 1 at 13:00:23.681Z for `conhost.exe`; the Sysmon record has a full image, command line, parent, user, integrity level, and hash set. Security 4688's process-ID field is the creator PID, so it should not be read as the new process PID. Across sampled endpoints, Sysmon Event 5 and Security 4689 provide process-termination evidence, and Security 4624 records include logon type and source address where applicable.
- **Linux-native shape and lifecycle:** Syslog samples use priority, RFC 5424 version, UTC timestamp, host, daemon, PID, and message fields. Examples include APP-INT-01 syslog lines 249–250 (18:57Z), pairing SSH PAM session close with systemd-logind removal, and LOG-MON-01 lines 248–249 (18:58Z), pairing PAM open with a new logind session. Linux shell histories use epoch timestamp comment lines followed by commands, e.g. APP-INT-01's timestamped history. These are coherent endpoint artifacts.
- **Unknowns are preserved:** The macOS records leave some `team_id`, command `script`, and connection process identities null/absent. Those omissions are plausible collection limits and are not treated as proof of missing authorization or missing activity.

## Detailed raw-file / line / time analysis

1. **macOS SSH session ordering — moderate contract gap.** On MAC-MROSS-01, Endpoint Security lines 76–88 show launchd/XPC activation of sshd at 16:02:16.214Z, sshd/session/auth forks and exits through 16:02:16.301Z, then a user-context session fork and zsh exec at 16:02:17.691–16:02:17.723Z. In `ecar.json`, lines 248–260 place the matching inbound source tuple (10.10.1.42:62470) and session/process rows at 16:02:19.207–16:02:19.222Z; the login row at line 248 precedes the eCAR child-process rows by 1–15 ms. The source tuple and identity are useful, and the raw ES timeline supports a successful session. The difference is a few seconds, so delayed source publication is possible; however, the eCAR event times and ordering currently look like occurrence times and do not expose a lag marker. This is a timeline-contract gap, not a claim that the SSH login failed.
2. **Mac local login failure texture — weak signal.** MAC-MROSS-01 `ecar.json` lines 140–143 show four failed local `maya.ross` attempts at 15:03:36.968, 15:03:42.968, 15:03:48.969, and 15:04:00.968Z, each with `bad_password` and `attempt_failed`. The near-6-second cadence followed by 12 seconds is possible for a person retrying, but looks templated. `macos_unified_log.ndjson` contains only two records, neither in this interval; given the sparse Unified Log sample, this absence is neutral and is not a companion-source failure finding.
3. **Window/coverage boundaries — neutral.** Several activity chains begin before the first host-specific record or lack an earlier parent/session observation within the file. I treated those as bounded collection starts. For example, MAC-MROSS-01 begins with launchd/Terminal evidence at 13:08 while its eCAR local session login is at 13:03; an earlier session start is compatible with this window. I did not infer a broken parent from an absent pre-window start.
4. **Cross-platform spot checks.** Windows file paths, event IDs, event XML structure, and timestamps are OS-native in sampled records; Linux syslog uses Linux daemon names and PAM/logind semantics rather than Windows conventions. The sample shows process correlation and lifecycle companions without requiring every endpoint event to be repeated in every source. No version-specific macOS contradiction was established from the version-11 Endpoint Security event envelope or the observed `/usr/libexec/sshd-session` process path.

## Categorized indicator summary

- **hard_contradiction:** None confirmed in the reviewed host evidence.
- **contract_gap:** MAC-MROSS-01 eCAR SSH login/process sequence (eCAR lines 248–263) is timestamped several seconds after the underlying Endpoint Security sequence (lines 76–88), and its login row appears before its own child-process rows. The session tuple/user are coherent; preserve occurrence ordering or identify source observation delay.
- **distribution_texture:** Four local bad-password events at eCAR lines 140–143 are spaced about 6, 6, and 12 seconds apart. Plausible retries, with a somewhat regular pattern.
- **schema_or_format:** None found in sampled XML, NDJSON, syslog, or history records.
- **environment_or_collection_plausibility:** No confirmed issue. Null signing/team metadata and sparse Unified Log coverage remain unknowns, not negative evidence. Launchd/xpcproxy and per-user shell process shapes are plausible.
- **weak_signal:** Login-failure cadence above; low weight without broader native loginwindow evidence.

## Realism scores (1–10)

- **Temporal ordering:** 7/10
- **Process and session identity:** 7/10
- **OS-native event shape:** 8/10
- **Cross-source coherence:** 7/10
- **Collection and coverage plausibility:** 7/10

## Recommendations

1. Keep eCAR occurrence timestamps tied to the canonical host event and apply any collector delay as separate observation metadata. Preserve process/session ordering when producing the eCAR view; this would prevent the 16:02 MAC-MROSS-01 SSH login from preceding its rendered process chain.
2. Add a bounded acceptance check for macOS SSH that compares the client tuple, Unified Log accepted-user/source tuple, Endpoint Security session process lineage, and eCAR login/process order when those observations exist. Treat absent pre-window records as unknown.
3. For local authentication failures, derive retry spacing from the same host/user attempt sequence and add modest jitter; retain the current failure reason and outcome fields. Do not infer that Endpoint Security authorization metadata means a human approved the action.
