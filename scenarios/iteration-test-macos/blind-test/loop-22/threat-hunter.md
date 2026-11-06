# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 75
**Synthetic-Confidence Score:** 44

## Executive Summary

The slice supports practical threat hunting: credential use, Windows collection and proxy upload, Linux database staging, and SSH transfers can be followed through technically coherent host and network evidence. A small, sharply separated HTTP timing population and repetitive background command vocabulary suggest synthesis, but I did not verify an impossible lifecycle or source-native contradiction strong enough to distinguish a capable simulation from selectively collected production telemetry.

## Evidence For Synthetic

- [distribution_texture] Exactly 37 of 2,261 DMZ HTTP records have an HTTP timestamp precisely 0.001000 seconds after the matching Zeek connection timestamp, to the available microsecond precision. All 37 originate from proxy address `10.10.3.20`, despite representing numerous destinations and 16 distinct user-agent strings. Examples are `zeek-dmz/http.json:6` versus `zeek-dmz/conn.json:30`, HTTP line 28 versus connection line 107, and HTTP line 567 versus connection line 3782. This distinct timing floor across different applications looks like a separate construction rule. It is a moderate distribution indicator, not proof that any individual 1 ms interval is impossible.
- [distribution_texture] The two Macs show a narrow, repeatedly reused shell exploration vocabulary. For example, `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history:4`–`:6` contains `pwd`, `ls -la .../Documents`, and `du -sh .../Documents`; the same trio appears across the second Mac's history lines 3–5. `ps aux`, `df -h`, `id`, `sw_vers`, and the same PDF `find` recur later on both machines. This is a low-weight background-texture signal because the same administrator owns both machines and could genuinely repeat these commands.
- [environment_or_collection_plausibility] Some apparently ordinary document handling is rendered through raw shell utilities: the first Mac's `ecar.json:81`–`:82` forks and executes `tee /Volumes/ResearchShared/Reference/team-roadmap.pptx`, while lines 111–112 execute `cat /Volumes/Users/Documents/contacts.xlsx`; lines 164–165 similarly execute `cat .../action-items-review.pdf`. These commands can run, and could be tests or scripted transfers, but a recurring shell treatment of office documents makes this part of the activity model less convincing than the actual SSH and proxy workflows. I do not infer that missing GUI telemetry is itself a defect.

## Evidence For Real

- SSH client, transport, receiver authentication, shell, and closure identities are usable pivots. For the first Mac to second Mac session, `MAC-MROSS-01.../ecar.json:97`–`:100`, `zeek-core/conn.json:2115`, and `MAC-MROSS-02.../macos_unified_log.ndjson:2` agree on the hosts and source port `59129`; the session lasts approximately ten minutes rather than ending with the initial command creation.
- The database copy has coherent artifact and account ownership: `DB-PROD-01.../ecar.json:669`–`:679` shows root's dump, compression, file read and SCP; `APP-INT-01.../syslog.log:222`–`:223` accepts root from `10.10.4.10:54865`, and receiver `ecar.json:740` records the destination file. This can be investigated without assuming the local user and directory account namespaces are interchangeable.
- Network observations are not simply identical copies. For that SCP tuple, `zeek-db/conn.json:441` reports 4,242 responder bytes and 22 responder packets, while `zeek-core/conn.json:10581` reports 4,198 responder bytes, 21 responder packets, `missed_bytes=44`, and a gap marker in history. The small observation discrepancy is internally meaningful.
- Windows `/netonly` use preserves the local principal: `WS-AJOHNSON-01.../windows_event_security.xml:22629` records `runas.exe /netonly /user:marcus.chen`, while subsequent host processes remain `aisha.johnson` under a new logon ID. Changing network credentials does not incorrectly rename all local processes to Marcus.
- Successful Windows archive upload is supported by an actual proxy request, rather than inferred from execution alone: `PROXY-01.../proxy_access.log:2790` records the archive POST, status 200, `cs_bytes=18782914`, client source port `64200`, and an explicit SSL inspection tunnel identity.
- The Mac policy warning does not falsely prove execution. `MAC-MROSS-01.../macos_unified_log.ndjson:2` names a MeetingAssist policy rejection, and I found no MeetingAssist execution in either supplied native ES stream. I did not attribute child execution or persistence effects to that warning.

## Detailed Analysis

### Orientation and hunting scope

All evidence references below are relative to `/private/tmp/log-study-20261105-r22/data/`; line numbers refer to raw files. I examined only that directory after reading the study briefing.

There are 23 endpoint directories with 35,086 normalized eCAR records. The normalized window runs from 2026-11-02 13:00:01.077 through 18:59:59.687 UTC. Hostnames and evidence suggest Windows workstations and domain controllers, Linux mail/file/application/database/proxy/web systems, and two Macs. Internal addresses occupy at least `10.10.1.*`, `10.10.2.*`, `10.10.3.*`, and `10.10.4.*`. I did not equate a network address with a native endpoint platform without endpoint support.

Available families include Windows Security/Sysmon XML, eCAR, Linux RFC 5424-style syslog, bash/zsh histories, native-style macOS ES and Unified Log records, three Zeek sensor directories, two Snort streams, ASA firewall records, proxy and web access logs. The Zeek directories contain 21,412 connection records in total; that is a sensor observation count, not a count of unique enterprise connections. The normalized mix is dominated by 26,271 FLOW records, with 2,130 process creates, 2,002 process terminations and 956 session login records. Those volumes do not make the visible activity implausibly dominant by themselves.

### Windows credential and collection pivots

At 18:00:31, Aisha runs `runas /netonly /user:marcus.chen`. Security 4648 at 18:00:34.7426512 names Marcus as the target credential and identifies the caller `runas.exe` PID `0x1960`. The resulting `cmd.exe` is PID `0x1964` and the new local logon ID is `0x27c956e`; the local subject remains Aisha. This distinction matters: a hunter must pivot to network authentication separately instead of interpreting every child process as an interactive Marcus session.

The resulting chain in `WS-AJOHNSON-01.../ecar.json:1054`–`:1121` creates the VaultCache directories, inspects and copies Finance/Clinical/Research paths, then invokes Compress-Archive. At 18:25:10.430, line 1181 creates PID 6760, `curl.exe`, with the explicit proxy and archive upload command. The file read at line 1188 precedes the process's observed proxy connection at line 1189 (`10.10.1.35:64200 -> 10.10.3.20:8080`). The proxy POST at line 2790 provides application-level success and matching client port. This is feasible pivoting with sensible local process ownership; I found no need to invent a direct external connection from the workstation.

Separately, the DC contains suspicious account management: the `svc_dirsync` creation has a concrete SID ending `-1688`, followed by password/account update and Domain Admins membership records around 17:15. The cleanup command `wevtutil cl Security` appears at Security XML lines 268194 and 268237, and Event 1102 is present at line 268294. That required companion exists. Retained earlier records do not contradict clearing a local log, since the slice can contain records forwarded before the clearing.

### Linux database staging and SCP

On DB-PROD-01, the root SSH login from `10.10.2.30:39092` is followed by a root bash and `mysqldump --single-transaction ehr patients insurance_claims`. The dump process PID 1088953 creates `/tmp/rpt_0318.sql`; gzip PID 1089045 creates `/tmp/rpt_0318.sql.gz`. SCP PID 1089114 subsequently reads the same compressed artifact identity and opens the reverse-direction SSH transport to `10.10.2.30:22` using source port 54865.

The target's flow, accepted public key, root session and `/tmp/.cache/rpt_0318.sql.gz` creation are visible. The core and DB sensor views preserve the same tuple while differing slightly in packet visibility, as described above. The normalized receiver file timestamp is slightly later than the final network packets; that alone is not impossible because endpoint observation/flush and transport observation need not have identical timestamps. Similarly, I did not score an absent shell redirection character in the child's argv: redirection may be owned by the shell rather than appear in `mysqldump` argv.

### macOS interpretation and bounded lifecycle checks

The Mac ES streams contain 291 records in total: fork/exec/exit events with audit identities, parent information and executable details. I treated these as native notification evidence distinct from the normalized eCAR process CREATE/MODIFY model. The first Mac's native ES lines 47–48 show SSH exec at 14:24:37.113883 and successful exit at 14:34:59.249280; its normalized FLOW at 14:24:47.996 is a connection observation, not process termination. The corresponding receiver authentication at 14:24:53.650676 fits inside that client lifetime. The reverse session around 16:02 similarly has a long-lived client, a matching tuple, and target public-key acceptance.

The only MeetingAssist evidence I found is the Unified Log policy message. It does not establish that the app executed successfully, installed persistence, or caused downstream activity. The very small Unified Log excerpt is not penalized because its collection filter is unknown.

I also performed bounded identity checks across all 23 eCAR streams: no visible event used an actor object after that object's visible process termination, with a 100 ms tolerance. Across 11,542 Sysmon events, the checked process/source/target/parent GUID-image relationships did not conflict with available Event 1 identities, and no checked GUID was referenced after its visible Event 5 timestamp. These checks cannot validate missing out-of-window state, but they materially reduce the case for impossible lifecycle synthesis.

### Timing texture and limits of the verdict

The strongest negative finding is a limited timing population, not dataset-wide regularity. The 37 exact 1 ms HTTP offsets occur only on the proxy-originating DMZ side. They include agents from browsers, APT, CryptoAPI, Zscaler and other software; examples span HTTP lines 6, 28, 105, 124, 187, 254, 331, 333, 441 and 497. In contrast, the remaining HTTP traffic has varied delays: the core's 2,059 HTTP records range from approximately 3.6 ms to 5.10 seconds relative to connection start, and the DB sensor's 26 range from approximately 34 ms to 170 ms. A common proxy or export convention could explain a subset, so I assign moderate rather than decisive weight.

The command repetition is weaker still: it is log-visible and reduces background richness, but the shared user and administrative context offer a plausible production explanation. I found no verified hard contradiction. Consequently the score remains in the mixed/inconclusive range, below a confident synthetic verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Zeek HTTP/connection timing | 37 of 2,261 DMZ HTTP rows, all proxy-originating | Moderate: an exact shared delay across different applications contrasts with the remaining traffic's variable delays. |
| distribution_texture | Mac zsh history and normalized process activity | Two hosts owned by the same user | Low: repeated command vocabulary and short bundles, partly explainable by the shared administrator. |
| environment_or_collection_plausibility | Mac normalized process/file behavior | Several office-document reads/writes | Low: raw `cat`/`tee` treatment of PPTX/XLSX/PDF activity is odd as routine work, but technically possible. |

## Realism Score by Category

- **Field format accuracy:** 8 — The examined fields are interpretable and retain source-specific identity and action semantics; no verified native schema contradiction was established.
- **Temporal patterns:** 7 — Most checked lifecycle timing works, but a distinct 37-record exact 1 ms HTTP timing population deserves investigation.
- **Cross-source correlation:** 9 — Credential, transport, file and proxy pivots work, with realistic sensor visibility differences and no checked same-GUID lifecycle violation.
- **Behavioral realism:** 7 — Intrusion-related command effects are technically plausible; repetitive shell discovery and office-document handling weaken the baseline.
- **Environmental consistency:** 8 — Mixed operating systems, accounts, topology and proxy-mediated access generally agree with the visible evidence.

## Recommendations

- If this were synthetic, derive the proxy-originating HTTP request timestamps from connection/request timing appropriate to each activity instead of the exact 1 ms offset shared by the identified 37-row population. Preserve realistic reuse and proxy behavior rather than adding arbitrary independent timestamp jitter.
- If this were synthetic, diversify the repeated Mac background command bundles in the two supplied zsh histories using plausible user work and session context. Repetition by one user is reasonable; the particular small shared vocabulary should not carry most of the visible shell texture.
- If this were synthetic, model normal office-document interaction with commands and effects suitable for the actual activity, or retain visible script context explaining the `cat`/`tee` use. Do not add unrelated log sources merely to increase volume.
- Preserve the existing strong behaviors: distinct local/network credential ownership, process lifetimes spanning SSH use, actual proxy success evidence, source-level packet-loss differences, and restraint around policy warnings that do not prove execution.
