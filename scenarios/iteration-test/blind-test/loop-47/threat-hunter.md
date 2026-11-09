# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 24

## Executive Summary

The supplied slice is mostly production-like from a threat-hunting perspective: I could follow suspicious activity through process, authentication, network, and file evidence without establishing an impossible visible same-identity lifecycle. A limited repeated-command texture on the two Macs is a weak synthetic clue, but shared-user administration can explain it; the observable evidence does not reliably distinguish real collection from a capable simulation. The score describes appearance, not an estimated probability of synthetic origin.

## Evidence For Synthetic

- [weak_signal] The two Macs' shell histories rely on a small, overlapping set of informational commands. `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history` contains 20 commands, including three `/usr/bin/id`, two `sw_vers -productVersion`, two `df -h`, two `ps aux`, and two identical PDF searches. The second Mac's 19 commands likewise include three `ps aux` and repeated version, directory, disk, and PDF-search commands. For reproducible examples, compare Mac 01 lines 8–10 and 18–20 with Mac 02 lines 7–8 and 14–19. This resembles a compact command palette, but both hosts belong to the same visible user, and diagnostic repetition is entirely possible. It receives little weight and is not a demonstrated behavioral contradiction.
- No hard contradiction, required-companion gap, or source-volume defect was substantiated in the operational relationships tested below. I do not treat the comprehensibility of the intrusion, complete pivots, selected Sysmon event types, thin Unified Log coverage, sanitized domain names, or filesystem timestamps as synthetic evidence.

## Evidence For Real

- The DB staging trail preserves protocol and identity boundaries. A root SSH login from APP-INT precedes the dump and compression on DB-PROD; the reverse-direction SCP authenticates separately on APP-INT; the later SMB operation uses directory account `svc_mhsync`, not root. See `DB-PROD-01.meridianhcs.local/ecar.json:526–539`, `APP-INT-01.meridianhcs.local/ecar.json:774–784`, and `FILE-LNX-01.meridianhcs.local/ecar.json:1231–1236`.
- Independent source timing is credible in the examined pivots. For example, the SCP tuple `10.10.4.10:58586 -> 10.10.2.30:22` appears with distinct sensor UIDs and slightly different timestamps in `zeek-core/conn.json:11098` and `zeek-db/conn.json:385`, while retaining consistent byte and packet accounting. Matching alone is neutral; plausible observation differences support operational credibility.
- The background has heterogeneous services, outcomes, and rates. The three conn files contain 12,314 core, 9,401 DMZ, and 433 DB records. Core traffic includes DNS, Kerberos, LDAP, proxy HTTP, SMB, syslog, mail, SSH, and RDP; DB traffic is dominated by MySQL. Hourly core counts are 1,849, 3,233, 1,757, 1,698, 2,068, and 1,709, rather than a fixed hourly quota.
- Native domain evidence supports the meaning of the suspicious commands: DC-01 Security event 4697 record 28256455 identifies Aisha's PSEXESVC installation; events 4720, 4724, and 4728 identify creation, password setting, and Domain Admins membership for the same `svc_dirsync` SID. The audit-clear event resets the visible record numbering, and the later account-deletion record retains that SID. These are meaningful pivots, not just coincident timestamps.
- Routine command and service noise includes errors and harmless actions. For example, DB-PROD's Marcus history includes the typo `loginctll` at timestamp 1793636786; WS-LNGUYEN's support upload is supported by a tar process and a multipart HTTP POST with metadata and gzip file parts, rather than being automatically classified as exfiltration because it uses curl.

## Detailed Analysis

### Inputs, provenance, and method

I read the complete supplied neutral briefing `/private/tmp/log-study-p29dfwbp/threat-prompt.md` and examined only `/private/tmp/log-study-p29dfwbp/data`. I enumerated its 117 files, counted/read first and last records across those files, processed all 35,805 eCAR JSON records, read the shell histories, parsed the Windows Security XML files, inspected selected Windows Sysmon records, and cross-referenced selected Linux syslog, Zeek, web/proxy, and alert evidence. This was a targeted operational review, not a complete native-schema certification of every record. No external reference pages were accessed, and no logged commands were executed.

No project files, scenario files, TODO/AGENTS/worklogs, previous assessments, other reviewers' work, or parent inventories were opened. Generic project metadata inherited in the operating environment is a study limitation and was not used as origin evidence. All evidence paths below are relative to the supplied data directory; XML EventRecordID values are given where they identify records more reliably than multi-line ranges.

The 23 endpoint directories comprise ten hosts with Windows Security/Sysmon sources, eleven with Linux-style syslog, and two with macOS Endpoint Security/Unified Log sources. The normalized endpoint window is 2026-11-02 13:00:00.492 through 18:59:57.955 UTC. Visible addresses span client `10.10.1.*`, server `10.10.2.*`, DMZ `10.10.3.*`, and DB `10.10.4.*` networks. Hostnames and actual service traffic support the role inference; I do not infer endpoint platform from a network sensor alone.

Besides endpoint evidence, the slice includes three Zeek sensor groups, ASA firewall messages, two alert streams, a proxy log, and a web access log. Counts include 3,861 syslog lines, 3,524 proxy lines, 757 web-access lines, 175 IDS alerts, 283 macOS ES notifications, and six Unified Log records. Those counts describe the supplied collection, not an assertion that all possible host activity was collected.

### Process and session lifecycle checks

For every eCAR file, I matched visible PROCESS CREATE and TERMINATE records by process `objectID`, and checked actor references against those same identities. I found no actor event more than one second before its visible creation or after its visible termination. Where a referenced actor had a visible creation, parent PIDs on child creates and actor PIDs on dependent events were consistent. These checks deliberately permit ordinary subsecond source observation offsets; they do not prove absence of every timing defect.

I also checked successful SSH and Type 10 sessions that had matching endpoint FLOW tuples. I found no case where every matching SSH/RDP FLOW observation occurred after the session LOGIN. Processes and sessions lacking an in-window initiator or closer were not penalized. Network-duration checks on the selected suspicious hosts did not establish a matching process-owned connection extending more than five seconds beyond visible process termination.

### Web compromise and interpretation limits

`WEB-EXT-01.meridianhcs.local/ecar.json:840` records a www-data bash process at 14:20:06.317, parented by Apache. Its encoded text describes a reverse-shell command; line 841 observes that process opening `10.10.3.10:41647 -> 45.33.32.30:8443` at 14:20:09.662. `zeek-dmz/conn.json:1625` observes that tuple at 14:20:09.585467, state SF, duration 29.415661, with 620 originator and 1,840 responder bytes; endpoint process termination follows at 14:20:59.504, line 843. The ordering is feasible, and the connection closes before the process.

The nearby Apache error at `WEB-EXT-01.meridianhcs.local/syslog.log:294`, 14:20:09.046615, reports a SQL syntax/access error near a UNION query from `185.70.41.45:53218`. It is suspicious context, but I do not claim that this error alone proves the mechanism that launched the shell. An observed failed SQL operation and an observed child process are distinct facts.

### Windows privilege, lateral movement, and collection pivots

On DC-01, `ecar.json:3715` records a successful Aisha network session from `10.10.1.35`, LogonID `0x5554b15`. Lines 3716–3730 then show SMB transport, PSEXESVC file/service creation, services.exe starting PSEXESVC, and its child command. Native Security event 4697, record 28256455 at 17:00:21.9994534, uses the same subject and LogonID. The service is LocalSystem, consistent with its subsequent SYSTEM process context. I did not mistake the network-session principal for the eventual service execution account.

DC-01 event 4720 record 28257154 at 17:15:19.2242501 creates `svc_dirsync` with SID ending `-2456`; event 4724 record 28257156 and event 4728 record 28257173 carry that SID through password setting and Domain Admins membership. Later event 4726 record 444 at 18:49:53.4619920 deletes the same SID. Event 1102 appears at 18:42:11.6676456 as record 1. I inspected the 4698 task record as well: its decoded TaskContent parses as XML, so escaped XML display is not a format defect.

On WS-AJOHNSON, the archive staging can be followed by process and file ownership: `ecar.json:1025–1082` covers directory creation, SMB selections/copies, compression, and `cache_7f3a.zip` creation. Native Sysmon event 1 records 31464, 31472, 31474, 31480, and 31483 preserve the corresponding commands and session. Sysmon record 31568 at 18:24:35.8254961 records curl using the explicit proxy; eCAR lines 1131 and 1138 show that process and its archive read. `zeek-dmz/http.json:2225` records the CONNECT to `api.westbridge-services.net:443` from `10.10.1.35:56429`. Because this is an encrypted tunnel, I do not require a plaintext HTTP multipart body in Zeek or claim it proves the precise uploaded content by itself.

### DB-to-application-to-SMB staging

The DB root session is technically usable before its commands: DB-PROD eCAR line 527 observes TCP/22, line 528 logs in root, line 529 creates the shell, and lines 530–539 cover mysqldump, SQL file creation, gzip, SCP, and file read. Native syslog lines 180–183 record the matching tuple, password acceptance, PAM opening, and logind session.

The SCP receiver has its own authentication. APP-INT syslog lines 200–203 show `10.10.4.10:58586` authenticating by public key and opening session 378723. Its endpoint lines 775–780 preserve that tuple and place the received `/tmp/.cache/rpt_0318.sql.gz` before receiver termination. The sending process ends at 18:16:43.464. The two Zeek views describe about 34.18 seconds of SSH transport, compatible with these close times rather than an unrelated tiny flow.

APP-INT later starts smbclient, explicitly disabling Kerberos and using `svc_mhsync`, at eCAR line 781. The endpoint tuple is `10.10.2.30:54116 -> 10.10.2.21:445`. FILE-LNX eCAR lines 1233–1235 identify `auth_protocol=ntlmssp`, `account_scope=directory`, and the same session reference for login, write, and logout. FILE-LNX syslog lines 460–465 independently show NTLMSSP success, the ClinicalResearch share, and open/write/close of the matching path. `zeek-core/smb_files.json:215–216` uses the matching tuple and filename and reports a 57,275-byte write. Cross-source timestamps differ by collection delay; the examined same-source sequences remain sensible.

### Baseline, false positives, and mixed-platform restraint

The network is not just attack-related traffic. The DB sensor contains 260 MySQL and 51 DNS connections; core has 3,193 DNS, 2,479 Kerberos, 1,208 LDAP, 465 SMB, and 332 syslog connections; DMZ has 2,847 SSL connections plus substantial HTTP and scanning noise. The elevated 14:00 hour has corresponding failed-flow activity, rather than requiring a conclusion from the hourly spike alone. Collection selection and overlapping sensors make a simple attack-to-total-record percentage misleading.

WS-LNGUYEN's diagnostic upload is an instructive false-positive pivot. Its history records the ticket-named archive and multipart curl at timestamps 1793637108 and 1793637134; eCAR lines 399 and 403 identify the associated processes. `zeek-dmz/http.json:1416–1417` shows client-proxy and proxy-origin POST views with metadata JSON, gzip file content, matching ticket path, and a 200 response. This is distinguishable from the Windows encrypted CONNECT using visible context, without declaring every administrative upload benign by definition.

The Macs expose native ES notifications, a very narrow Unified Log selection, normalized endpoint rows, and shell history. I did not equate those formats, treat a notification as an authorization denial, or infer launch-item activation from a plist write. The repeated diagnostic shell vocabulary is the only scored reservation here; low Unified Log volume itself is neutral under the supplied collection briefing.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | macOS zsh histories | 39 commands across two hosts for the same user | Compact overlapping diagnostic palette slightly raises suspicion, but is compatible with ordinary administration and has little weight. |
| No substantiated hard contradiction or contract gap | Examined endpoint/network/auth/file relationships | All eCAR identities checked; selected native operational trails | Keeps the score in the mostly-realistic band. Successful checks do not establish production provenance. |

## Realism Score by Category

- **Field format accuracy:** 9 — Examined XML/JSON fields and decoded task XML are usable; full native-schema validation was outside this targeted hunt.
- **Temporal patterns:** 9 — Uneven hourly load, varied lifetimes, and tested transport/auth/process/file orderings are credible.
- **Cross-source correlation:** 9 — Operational pivots preserve tuples, accounts, session references, process ownership, and file paths with plausible source timing differences.
- **Behavioral realism:** 8 — Suspicious and routine activity are technically coherent; repeated informational Mac commands leave a limited texture reservation.
- **Environmental consistency:** 9 — Role-dependent network services and mixed platform evidence fit the visible topology and collection.

## Recommendations

- If this were synthetic, consider increasing the variety and task-specific context of the two Macs' repeated informational shell commands, especially repeated version and PDF-search invocations. This is a low-priority texture improvement tied to the 39 observed history commands, not a required missing log family or a claim that repetition cannot occur in production.
- I have no evidence-backed lifecycle repair to prescribe for the tested trails. Preserve the separate SSH/SCP authentications, the root-to-directory-account SMB boundary, explicit proxy behavior, and source-specific timing relationships rather than changing them merely to make pivots less complete.
