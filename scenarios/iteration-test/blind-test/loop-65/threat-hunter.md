# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 27

## Executive Summary

The supplied slice is mostly production-like: suspicious activity can be followed across endpoint, authentication, network, SMB, and proxy records without a demonstrated impossible same-identity lifecycle. The strongest reservations are modest repetition in the interactive command vocabulary; these are explainable by a common user or operational procedures and do not establish synthetic origin. The low synthetic-confidence score reflects the quality of the visible telemetry, while the inconclusive verdict reflects insufficient evidence to distinguish a well-built synthetic collection from production data.

## Evidence For Synthetic

- [weak_signal] Both Mac shell histories repeatedly use a small, overlapping set of inspection commands. `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history` contains 24 entries and 14 distinct complete commands; the corresponding MAC-MROSS-02 history contains 19 entries and 12 distinct commands. Repeated examples include `sw_vers -productVersion`, `uname -a`, `ps aux`, and the identical `find /Users/maya.ross/Documents -maxdepth 2 -type f -name '*.pdf'` command. This is compatible with a small command pool, but the same named user and repeated operational checks provide a credible real explanation. It receives little weight.
- [weak_signal] Repeated browser invocations also revisit a small vocabulary of internal pages. In MAC-MROSS-01's `ecar.json`, PROCESS/CREATE records include five identical Chrome invocations of the architecture wiki and three each of Jira tickets PROJ-2387, PROJ-3129, and PROJ-1465. Fork records can inherit a parent's command, so these counts are not counts of independent human browser launches. The repeated vocabulary is a texture concern only, not a demonstrated behavioral or lifecycle defect.
- No `hard_contradiction` or material `contract_gap` was demonstrated in the relationships checked. Neither the existence of a readable intrusion sequence nor extensive cross-source matching was counted as evidence for synthetic origin.

## Evidence For Real

- The source mix follows visible roles rather than an identical per-host volume. For example, the core sensor contains 12,286 connection records, the DMZ sensor 9,634, and the database sensor 485. Database-sensor traffic includes 315 MySQL connections; the core sees substantial Kerberos, LDAP, DNS, SMB, and HTTP traffic. These are credible differences for the apparent segmentation.
- Windows outbound-credential semantics are preserved. On WS-AJOHNSON-01, Security 4648 at `18:00:57.8562684Z` records local subject `aisha.johnson` using `marcus.chen` credentials through `runas.exe`. The following 4624 is Type 9 with local target `aisha.johnson`, outbound user `marcus.chen`, and new LogonID `0x27c9d2e`, rather than incorrectly replacing the local identity.
- RDP has a usable transport and session lifecycle. `zeek-core/conn.json:6630` records `10.10.1.99:47366 -> 10.10.1.35:3389`, state `SF`, opening at `16:00:17.647371Z` and lasting 896.020733 seconds. The target's Type 10 logon follows at `16:00:23.2419213Z`; Security 4779/4778 records preserve the same LogonID across disconnection and reconnection.
- The Linux database staging trail has mutually usable host, account, path, and network pivots: root SSH into DB-PROD-01, database dump and gzip processes, SCP to APP-INT-01, and a subsequent SMB upload to FILE-LNX-01. The SMB write names the same staged archive and has substantial matching connection payload.
- Noise has operational variety: failed authentication, firewall blocks, DNS negative replies, DNS AAAA/NODATA behavior, sysstat cron activity, systemd/resolver messages, service maintenance, updater processes, and both successful and incomplete network connections. This is positive visible evidence, not a requirement that every possible noise family be present.
- The Mac records distinguish process fork, exec, privilege/session changes, and exit; the two Macs use different Terminal/iTerm startup chains. Native ES records checked did not reuse a visibly exited PID later in the slice.

## Detailed Analysis

### Scope, sources, and method

Input provenance was limited to the supplied neutral briefing and files beneath `/private/tmp/log-study-sucvw85x/data`. No project files, scenario, prior assessment, or other reviewer report was examined. System Python was run with the explicit neutral working directory. One direct upstream Zeek source page was consulted solely to verify DNS answer rendering.

The data covers approximately `2026-11-02 13:00–19:00 UTC`. There are 23 endpoint directories: ten with Windows Security/Sysmon XML, eleven with Linux-style syslog, and two with native-looking macOS ES and Unified Log exports. Additional sources include three Zeek sensor directories, two IDS feeds, a perimeter ASA feed, proxy access, web access, and shell histories. The endpoint-normalized eCAR files contain 36,352 records; Windows exports contain 19,234 Security events and 11,972 Sysmon events. The three sensor connection counts sum to 22,405 observations, not necessarily unique connections because sensor coverage overlaps.

Visible addressing separates workstation/client `10.10.1.x`, internal services `10.10.2.x`, DMZ `10.10.3.x`, and a database host at `10.10.4.10`. Endpoint FLOW records associate DC-01/DC-02 with `.2.10/.2.11`, FILE-SRV-01/FILE-LNX-01 with `.2.20/.2.21`, APP-INT-01 with `.2.30`, WEB-EXT-01 with `.3.10`, and PROXY-01 with `.3.20`. These host-role inferences agree with major visible traffic families.

I parsed endpoint JSON and Windows XML, counted the source families, inspected shell and syslog records, and followed selected authentication, process, transfer, and remote-session chains. An eCAR identity check across all endpoint files found no actor use preceding that actor's visible PROCESS/CREATE record. It also found no actor use more than two seconds after the actor's visible PROCESS/TERMINATE record. That tolerance is explicitly a screening choice, not proof that every subsecond relationship is correct. A separate native ES scan found no later record for a PID after its visible exit. Pre-window processes and post-window survivors were treated as neutral.

### Windows credential use, collection, and exfiltration

The most useful Windows pivot is the distinction between a local token and credentials used remotely. `WS-AJOHNSON-01.meridianhcs.local/ecar.json:951` creates `runas.exe /netonly /user:marcus.chen "cmd.exe /d /q"` at `18:00:55.014Z`. Security XML time lines 23895 and 23937 identify the corresponding 4648 and Type 9 4624 records. The latter retains local target `aisha.johnson`, outgoing account `marcus.chen`, and LogonID `0x27c9d2e`. eCAR line 964 creates the child command shell under that new logon context.

Subsequent PowerShell processes reference real UNC syntax with two leading backslashes. For example, eCAR line 990 enumerates `\\FILE-SRV-01\Finance\Q1`, copies a maximum of five files into VaultCache, and is followed by five named local FILE/CREATE records at lines 1000, 1001, 1003, 1004, and 1005. The Linux share collection command at line 1026 similarly precedes three local creates at lines 1036–1038. I did not treat the compactness or completeness of this sequence as an authenticity indicator.

At line 1040, PID 6364 invokes `Compress-Archive`; line 1047 records the ZIP create at `18:01:46.778Z`. PID 6376 later runs curl with an explicit proxy, reads that ZIP at line 1117, and terminates at `18:25:36.493Z`. `PROXY-01.meridianhcs.local/proxy_access.log:3422` records the corresponding POST at `18:24:54`, including `cs_bytes=18783258`, HTTP 200, `proxy_action=ssl-inspect`, and a client source-port/tunnel reference. This supports a substantial upload through the stated proxy; HTTP 200 alone does not prove what the remote operator subsequently did with the content.

A separate DC trail is visible in native audit data: PSEXESVC installation at `16:59:48.8025423Z`, creation of `svc_dirsync` at `17:15:27.8521702Z`, DeviceSyncSvc installation at `17:20:17.8841689Z`, scheduled task registration at `17:20:19.9748786Z`, Security-log clear at `18:42:32.1179883Z`, and deletion of the same account SID at `18:49:56.1992126Z`. The task registration does not by itself prove that its action executed. The observations provide credible hunt pivots without requiring an invented account or privilege namespace.

### Linux staging and remote-session coherence

`DB-PROD-01.meridianhcs.local/syslog.log:184–187` records root authentication from `10.10.2.30:41518`, followed by PAM session opening and logind session 279140. Its eCAR lines 522–524 preserve that source tuple and session, then show a root shell and `mysqldump --single-transaction ehr patients insurance_claims`. Lines 525–529 show SQL-file creation, completion of the dump process, gzip creation, and compressed-file creation. The process command line need not include shell redirection, so the lack of `>` in the mysqldump process argv is not a defect.

The SCP process at eCAR line 530 names `/tmp/rpt_0318.sql.gz` and the destination `/tmp/.cache/rpt_0318.sql.gz` on APP-INT-01. The receiving host's syslog lines 197–200 show the same root SSH source tuple `10.10.4.10:53014`, and eCAR line 766 records the destination file. Subsecond-to-few-second differences between native syslog, normalized endpoint observations, and network timing are not enough here to establish a causal violation.

APP-INT-01 then invokes smbclient at eCAR line 772, explicitly using SMB identity `svc_mhsync` while its local process remains root. `zeek-core/smb_mapping.json:124` maps `\\FILE-LNX-01\ClinicalResearch`; `smb_files.json:221–222` opens and writes `Integration\DB-Staging\rpt_0318.sql.gz`. Its files record at line 603 has 5,094,159 bytes, while `conn.json:10979` has 5,097,557 originator application bytes and state SF. The connection carries more bytes than the transferred file, as expected once SMB overhead is included.

APP-INT-01 also originates 285 TXT lookups; most are conspicuous high-entropy names under `ns1.westbridge-services.cloud`, such as DNS lines 2199–2202. Short TTLs, varying names, failures, and later isolated lookups make this an actionable DNS-channel hunt. The fact that suspicious names are recognizable is not an authenticity defect.

### macOS evidence boundaries

The native ES records support process analysis rather than being interchangeable with Unified Log or eCAR. MAC-MROSS-01's first native records show launchd fork, xpcproxy exec, and Terminal exec with a stable PID and changing pidversion. MAC-MROSS-02 instead shows iTerm, its server helper, login, ShellLauncher, and zsh. These distinctions are credible and materially better than a single generic shell-launch pattern.

`MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson:2` reports an AppleSystemPolicy message concerning MeetingAssist at `15:41:55.909819Z`. This line alone does not establish successful execution, denial of every related action, or subsequent child behavior. I did not attribute effects to it. Similarly, normalized creation of an endpoint-inventory plist is not equivalent to proof of registration and activation.

The histories' repeated inspection vocabulary is the main residual texture reservation, but it is weak evidence: the same user is present on both machines, several activities are recognizable administration, and the native process chains provide substantially more detail than those histories alone.

### Source-native checks and counterevidence

The DNS TXT answer strings initially deserve verification because they contain explicit `TXT <length>` markers and split long DKIM values. Those are consistent with the upstream Zeek `dns_TXT_reply` implementation, which includes a length for each TXT string; SRV answers likewise summarize target names. They are therefore not counted as format defects. [Upstream Zeek DNS logging implementation](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/dns/main.zeek)

I also checked repeated Sysmon process images for inconsistent visible hash values within each host; none had multiple hashes in the inspected Event 1 records. Mac executable paths likewise retained stable cdhash/signing identity/inode combinations in the native records. This does not authenticate the data, but removes plausible field-consistency objections.

The observed connection-state distributions are varied rather than universally successful: the core has 1,660 S0 and 428 OTH records in addition to 9,847 SF records; the DMZ has 2,396 S0 and 308 OTH alongside 6,699 SF records. The supplied records support scanning, incomplete observations, and ordinary failures. I did not penalize deliberate Sysmon event-type selection, sparse Unified Log exports, or the absence of additional products.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Mac zsh histories, supported by native process records | 43 history entries across two machines for one named user; small overlapping inspection vocabulary | Small upward adjustment for repeated texture; common-user/procedure explanation remains strong |
| weak_signal | Mac normalized process command vocabulary | Repeated architecture-wiki and three Jira-ticket command strings on MAC-MROSS-01 | Very small weight; inherited fork command lines prevent interpreting raw counts as independent user launches |
| None demonstrated | Checked authentication/process/network/SMB/proxy lifecycles | Selected hunt chains plus endpoint identity screening | No high-impact synthetic penalty supported |

## Realism Score by Category

- **Field format accuracy:** 9 — Native XML, JSON, DNS representations, identities, and repeated executable metadata are convincing in the checks performed.
- **Temporal patterns:** 8 — Transport-before-auth and visible process lifecycles work; the command repertoire remains somewhat repetitive.
- **Cross-source correlation:** 9 — Remote credentials, source tuples, staged filenames, SMB payload, and proxy upload provide usable pivots without a demonstrated material contradiction.
- **Behavioral realism:** 8 — Administrative and suspicious activity coexist; repeated Mac inspection commands are a mild reservation.
- **Environmental consistency:** 8 — Roles, segmentation, and source volumes align; exact collection policy is not independently available.

## Recommendations

- If this were synthetic, widen the manually entered Mac command vocabulary where the intended behavior is general user activity. The concrete target is the repeated inspection commands in the 43 history entries, not legitimate repetition from inventory jobs or shared procedures.
- If this were synthetic, retain the existing distinction between fork-inherited command lines and independent exec actions when assessing browser activity. Vary actual interactive page use only where desired; raw PROCESS/CREATE counts alone should not drive extra browser launches.
- No additional source family, extra failed attack step, or generic retry noise is justified as a required repair by this review. Preserve the demonstrated credential, process, session, transfer, and proxy relationships when making any texture changes.
