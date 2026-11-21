# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 64

## Executive Summary

The dataset supports credible investigations across a mixed enterprise fleet, with substantial background traffic and generally coherent authentication, process, and transport lifecycles. I lean synthetic because a database export and transfer flatten several distinct operating-system operations into incorrect or incomplete process ownership, with additional weaker evidence of package names being substituted into service-management commands. These findings are localized; I did not find a dataset-wide impossible ordering pattern, and interpretation of the normalized endpoint schema remains a material uncertainty.

## Evidence For Synthetic

- [contract_gap] On `DB-PROD-01.meridianhcs.local`, shell history records `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql` at epoch `1793643315` (18:15:15 UTC). However, `ecar.json` lines 622–623 show the `mysqldump` process created at 18:15:15.997 and then creating `/tmp/rpt_0318.sql` at 18:15:18.198 under PID `1418113`. With the visible command, the shell opens the redirected output before executing the program; this is not a `mysqldump --result-file` invocation. A late first-write notification could explain an approximate creation timestamp, but would mean that normalized `FILE/CREATE` is not preserving the actual creation operation or ownership.
- [contract_gap] The subsequent SCP transport is attributed directly to `/usr/bin/scp`, PID `1418198`, in `DB-PROD-01.../ecar.json` line 627 at 18:16:11.413: `10.10.4.10:56898 -> 10.10.2.30:22`. Standard OpenSSH SCP uses an SSH helper for this network connection. No child process of PID `1418198` appears in the supplied endpoint records. At the receiver, `APP-INT-01.../ecar.json` line 856 attributes creation of `/tmp/.cache/rpt_0318.sql.gz` at 18:16:41.209 directly to `/usr/sbin/sshd` PID `3431585`, while the surrounding records show a privileged SSH monitor. These are suspiciously simplified endpoint ownership relationships. Attribution to a launching ancestor by an undocumented normalizer could explain some of this; I therefore classify it as a contract gap rather than a proven native-schema impossibility.
- [contract_gap] The same database shell history explicitly records `gzip -9 /tmp/rpt_0318.sql` at epoch `1793643340` (18:15:40), between the dump and the SCP command. The endpoint stream captures both neighboring commands, the uncompressed file creation, and the compressed file read at 18:16:16.946, but contains no gzip process or corresponding compression/rename operation. This is a bounded discrepancy between visible activity and its otherwise detailed endpoint reconstruction. A selective collection policy could account for it, so it receives less weight than the incorrect ownership above.
- [weak_signal] `APP-INT-01.../bash_history/marcus.chen.bash_history` contains `systemctl is-active smbclient` at 15:19:30, `journalctl -u cifs-utils ...` at 15:24:51, `ss -ltnp | grep cifs-utils` at 15:30:42, and `journalctl -u smbclient -n 200` at 15:44:40. These refer to client tools/package names as if they were service or listening-daemon names. The corresponding executable commands appear in endpoint telemetry. An administrator can issue unsuccessful commands, but the repeated substitution across several command forms resembles a reusable baseline template more than an isolated typo. This contributes only slightly to the score.

## Evidence For Real

- The fleet is heterogeneous: ten Windows endpoints, eleven Linux-like endpoints, and two Macs have distinguishable telemetry. Domain controllers carry authentication-heavy traffic; the proxy and exposed web server carry substantially more flows than ordinary workstations.
- There is real investigative background volume: 36,715 normalized endpoint records, 17,375 Windows Security events, 11,315 Sysmon events, and 22,408 Zeek connection observations across three sensors. The latter include overlapping sensor views and must not be treated as 22,408 distinct connections.
- The web compromise pivot works technically. `WEB-EXT-01.../web_access.log` line 467 records the 14:20:17 POST to `/ehr/admin/upload.php` from `185.70.41.45`; endpoint lines 930–933 show an Apache child shell, `base64 -d`, a downstream bash process, and its connection to `45.33.32.30:8443`. `zeek-dmz/conn.json` line 2003 corroborates the exact `10.10.3.10:52175` transport with 24.772326 seconds duration.
- The database transfer has coherent network and authentication evidence despite the process-attribution concerns: Zeek observes a roughly 30-second SSH transfer with about 2.15 MB sent, while the receiving application host logs public-key authentication, PAM session open, and session close for the matching source tuple.
- A check of all normalized process actor references found no visible actor-dependent event preceding its matching process creation or following its matching process termination; no matching normalized process termination preceded its creation. This check uses exact process object identifiers, rather than conflating reused PIDs.
- Mac records distinguish fork/exec transitions and carry consistent executable metadata within each host. The MeetingAssist policy message is not followed by an assumed execution chain in my findings; a policy message alone does not establish either successful execution or an enforced denial.

## Detailed Analysis

### Scope and collection

The supplied endpoint streams cover approximately 13:00–19:00 UTC on 2 November 2026. Twenty-three host directories expose normalized endpoint records, with host-specific Windows XML, Linux syslog and shell histories, or macOS Endpoint Security, Unified Log, and zsh history sources. The network side includes three Zeek sensor views, perimeter firewall events, two IDS alert streams, proxy records, and an exposed web server access log.

Windows Security is dominated by 11,640 filtering-platform connection events, with 877 process starts, 749 process ends, 827 successful logons, and 2,006 service-ticket events. Sysmon includes 873 process starts and 747 terminations alongside other selected event families. Differences between these totals are not inherently defects: sources have distinct collection and timing behavior, and this is a windowed sample.

Zeek connection states are varied rather than uniformly successful. For example, the core sensor has 9,654 `SF`, 1,631 `S0`, 454 `OTH`, 151 `RSTO`, and 102 `RSTR` observations. The DMZ includes 2,385 `S0` observations. These mixes, exposed-host scan noise, scheduled sysstat activity, service-account failures, and routine application traffic provide plausible hunting clutter. Scheduled recurring commands are not themselves synthetic evidence.

### Hunting pivots

The web upload-to-shell sequence is supported by process parentage and network identity. The Apache parent is PID `23966`, the decoded-command shell is PID `3044146`, the decoder is PID `3044147`, and the downstream bash is PID `3044148`. The outbound endpoint flow at 14:20:20.715 uses source port `52175`, matching the DMZ Zeek observation at 14:20:20.568885. Those subsecond source differences do not constitute impossible ordering.

There is also a distinct Windows remote-access pivot. On `WS-AJOHNSON-01`, Security 4624 at 16:01:24.3550624 records a successful Type 10 logon for `aisha.johnson` from `10.10.1.99:60560`, with logon ID `0x26db315`. Endpoint discovery commands later share that identity. On `DC-01`, Security 4697 at 17:00:16.7874022 records PSEXESVC installation under `aisha.johnson`, and Sysmon shows `C:\Windows\PSEXESVC.exe` PID `4996` at 17:00:16.899. These are useful pivots; I do not infer that every nearby action necessarily belongs to one actor without further evidence.

At 18:25:17.758, the AJohnson endpoint records `curl.exe` uploading `C:\ProgramData\Microsoft\cache_7f3a.zip` through `10.10.3.20:8080`. Proxy line 3512 at 18:25:21 records the matching destination `/upload/telemetry/7f3a2b19`, authenticated user, HTTP 200, and `cs_bytes=18783258`, explicitly identifying SSL inspection. Thus visibility of the HTTPS upload path has an explanation in the records rather than implying that an ordinary encrypted tunnel exposed its contents.

### Database export: evidence versus execution semantics

The database history supplies the shell redirection and gzip step, so it would be wrong to say that compression never happened or that the compressed file could not exist. The problem is narrower: the endpoint reconstruction does not preserve the operations and executable ownership implied by that history.

The SCP network tuple is independently corroborated by `zeek-core/conn.json` line 10721 and `zeek-db/conn.json` line 433, with different sensor UIDs and slightly different observation timestamps. At the target, `APP-INT-01.../syslog.log` lines 240–245 show connection, public-key authentication, PAM open, logind session `407`, and close. The target normalized session also has a matching logout at 18:17:01.597. Consequently, there is no missing-session-close finding here, and the source-native timing differences are not sufficient to allege an impossible lifecycle.

My concern is the endpoint actor model: stdout redirection is represented as a later dump-owned create, gzip is skipped, SCP owns the socket, and the privileged SSH process owns the target file create. This concentration of simplified semantics around one file-transfer activity is the strongest reason to lean synthetic. Because the data does not document the normalization rules, it does not justify an 81–100 score or absolute certainty.

### Limits and alternative explanations

The source-native XML parses, including the embedded scheduled-task XML. Checks of the Mac Endpoint Security records found no event whose reporting process start time lay after the event; repeated executable paths retained consistent inode/size pairs within each Mac. These checks are useful counterevidence, not certification of every native field.

A normalizer that deliberately reports parent attribution, first-write timestamps as creation, and selectively drops utilities could produce the database discrepancies from real telemetry. That alternative keeps verdict confidence below 80. I did not score domain sanitization, filesystem timestamps, complete source matching, a compact intrusion sequence, or absent event families. I also did not penalize sessions or processes simply because their starts or ends fall outside the visible window.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Shell history and normalized endpoint file/process events | One database export | Visible redirection and later dump-owned creation disagree about operation ownership; moderate weight. |
| contract_gap | Normalized endpoint network/file events and SSH transport | One SCP transfer spanning DB-PROD-01 and APP-INT-01 | Direct SCP socket ownership and privileged SSH file ownership simplify helper/process boundaries; strongest concern, qualified by unknown normalization rules. |
| contract_gap | Shell history versus normalized process/file coverage | One gzip operation inside that export | Explicit in-window command missing between captured neighboring operations; limited additional weight because collection may be selective. |
| weak_signal | Linux shell history and normalized process events | Four commands by one administrator on APP-INT-01 | Repeated client/package-as-service substitutions; small contribution only. |

## Realism Score by Category

Rate each category 1-10 (10 = indistinguishable from real):

- **Field format accuracy:** 9 — Parsed source records are detailed and internally well formed; no demonstrated native parser failure.
- **Temporal patterns:** 8 — Plausible background variation and coherent visible process lifecycles; file-creation semantics remain questionable.
- **Cross-source correlation:** 7 — Strong tuple/session pivots, with a concentrated endpoint ownership gap in the export and SCP activity.
- **Behavioral realism:** 7 — Investigable tradecraft and useful background noise; several package/service command substitutions weaken baseline texture.
- **Environmental consistency:** 8 — Mixed platforms and role-dependent volumes are plausible; the available collection description cannot fully explain endpoint normalization choices.

## Recommendations

- If this were synthetic, preserve the shell-owned output open before `mysqldump` execution, distinguish first write from file creation, and include the observed gzip operation in the same process/file lifecycle.
- If this were synthetic, model the SCP client SSH helper and the receiving file-transfer execution context explicitly, assigning socket and file operations to their actual owning processes. If ancestor attribution is intentional, expose that as a documented normalization choice rather than presenting it as direct executable ownership.
- If this were synthetic, review package-to-command substitutions: `smbclient` and `cifs-utils` should not automatically become daemon names in `systemctl`, `journalctl -u`, and listening-process searches. Preserve occasional failed administrator commands only with a plausible operational context.
- Retain the existing transport/session correlation, differentiated source volumes, and platform-specific process lifecycles; these already make the data substantially more credible and huntable.
