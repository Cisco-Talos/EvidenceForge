# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 36

## Executive Summary

The data is operationally convincing enough that I cannot confidently distinguish a constructed exercise from a production incident slice. I could follow suspicious activity through endpoint, authentication, network, SMB, and proxy records without finding a demonstrated impossible same-identity lifecycle; the main reservations concern repeated command vocabulary and an unusual concentration of shell-based document access, which are explainable rather than decisive.

## Evidence For Synthetic

- [distribution_texture] The two Macs' interactive histories draw heavily from the same small diagnostic vocabulary. `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history` lines 1–3 are `id`, `sw_vers -productVersion`, and `uname -a`; the second Mac's lines 1–3 rotate to `sw_vers -productVersion`, `uname -a`, and `pwd`. Across all 41 history lines, there are only 12 distinct executable paths, including SSH; repeated `find ... -maxdepth 2 -type f -name '*.pdf'`, `ps aux`, and `df -h` sequences give the visible interactive work a restricted vocabulary. This is a small distribution concern, substantially weakened by the same user operating both machines and by the possibility of selected collection.
- [weak_signal] `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` records eight `/bin/cat` executions against documents on mounted shares, including `service-review.xlsx` at line 108, `project-plan.docx` at line 118, `onboarding.docx` at line 121, and `meeting-notes.docx` at line 161. These are executable arguments, not merely normalized file labels. A repeated shell-reading pattern across Office documents and PDFs is an odd representation of routine document work, but it could reflect troubleshooting, inspection, or deliberate automation. It is not an impossible action.

## Evidence For Real

- The baseline has meaningful operational variety: domain Kerberos and LDAP traffic, SMB access, proxy tunnels, database traffic, scheduled sysstat activity, sudo sessions, SSH sessions, external web requests, and both successful and unsuccessful network outcomes. The three Zeek connection files contain 21,805 records, rather than only the handful of flows needed to explain suspicious activity.
- The reverse-shell evidence is technically compatible across sources. `WEB-EXT-01.meridianhcs.local/ecar.json` line 850 creates PID 2702836 as `www-data` from `apache2` at 14:20:13.292 UTC; line 852 connects `10.10.3.10:60165` to `45.33.32.30:8443`. `zeek-dmz/conn.json` line 1744 records that tuple at 14:20:21.064746, with a 24.462467-second successful TCP connection. The endpoint termination at line 855, 14:20:57.793, follows the connection interval.
- SSH has credible transport-before-authentication ordering. For example, `zeek-core/conn.json` line 1744 begins `10.10.1.41:62565 → 10.10.4.10:22` at 14:02:00.178974. The DB endpoint records its inbound flow at 14:02:01.275 and successful `maya.ross` login at 14:02:10.241 (`DB-PROD-01.meridianhcs.local/ecar.json`, lines 125–126).
- Windows network-only credentials preserve the local/remote identity boundary. `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml`, event beginning at line 28241, records a Type 9 logon at 18:01:00.9590909 with local `TargetUserName=aisha.johnson`, `TargetLogonId=0x27caa1f`, and `TargetOutboundUserName=marcus.chen`. This agrees with the preceding `runas.exe /netonly /user:marcus.chen` intent without incorrectly changing the local process owner to Marcus.
- Proxy visibility distinguishes the client CONNECT from inspected application traffic. `PROXY-01.meridianhcs.local/proxy_access.log` lines 3013–3014 link the 18:25:12 CONNECT and POST with `tunnel_id=PT-466a7e87c0d2d7c2` and `client_src_port=61459`; the CONNECT explicitly reports `peek`, while the POST explicitly reports `bump`. The logs therefore provide a plausible basis for seeing the HTTPS upload URL.
- The Security-log clearing record has appropriate channel behavior: DC-01's Event 1102 at 18:41:55.2301482 uses the Eventlog provider, `LogFileCleared` UserData, and `EventRecordID=1` (`DC-01.meridianhcs.local/windows_event_security.xml`, lines 278274–278305).

## Detailed Analysis

### Scope and method

The examined inputs were the supplied neutral briefing and files beneath `/private/tmp/log-study-kg97anv_/data` only. I used read-only system-Python parsing with `/private/tmp` as the working directory. No project files, scenarios, prior assessments, or other reviewers' reports were accessed; inherited generic operating instructions were not used as authenticity evidence. No external reference searches were needed for the findings reported here.

The endpoint inventory contains 23 host directories: ten Windows endpoints/servers with Security and Sysmon XML, eleven Linux hosts with syslog, and two Macs with Endpoint Security-shaped records, Unified Log-shaped records, shell histories, and normalized eCAR. The dominant visible window is 2026-11-02 13:00–19:00 UTC. Addressing suggests workstation space in `10.10.1.0/24`, directory/application/file services in `10.10.2.0/24`, a DMZ in `10.10.3.0/24`, and a database segment in `10.10.4.0/24`. Named human identities coexist with local root, Windows built-in identities, service identities, and machine accounts; these namespaces were not assumed interchangeable.

Actual record counts, rather than XML line counts, are 19,390 Security events and 12,079 Sysmon events. There are 35,635 eCAR records, 3,908 syslog lines, 3,321 proxy lines, 739 web-access lines, 303 Mac Endpoint Security records, and five Mac Unified Log records. The latter source is evidently narrow; its low count alone is not an authenticity finding. Zeek has 12,251 core connections, 9,122 DMZ connections, and 432 database-sensor connections. Counts from overlapping sensors are not treated as unique network activities.

### Hunting and pivot feasibility

The web endpoint provides a plausible initial suspicious pivot: a web-server child runs a base64-decoding Bash pipeline and makes an external connection. I did not infer an indefinitely surviving reverse shell from this record: its observed process ends at 14:20:57.793. Later remote activity needs its own evidence, which is present as separate SSH authentication/session activity rather than proof that this particular process remained alive.

At 18:14:57.610, DB-PROD-01 accepts a root SSH session from `10.10.2.30:45876` (eCAR line 474). A shell appears at line 475, followed by `mysqldump --single-transaction ehr patients insurance_claims` at line 476. The dump process ends at 18:15:31.332; `gzip -9 /tmp/rpt_0318.sql` starts at 18:15:32.421, and the visible compressed-file creation precedes the subsequent SCP read. This sequence is causally usable for a hunter. The absence of shell redirection from an executed program's argv is not, by itself, proof that output redirection never occurred.

The SCP pivot is especially useful: DB eCAR lines 482–484 connect `10.10.4.10:41723` to `10.10.2.30:22` and read `/tmp/rpt_0318.sql.gz`. `zeek-core/conn.json` line 10966 records UID `CXELYyFSP4pDoHcMAvx`, starting at 18:15:56.308583 with a 35.128784-second successful interval. APP-INT-01 syslog lines 206–207 record the same source port and accepted public-key authentication, and APP eCAR line 746 creates `/tmp/.cache/rpt_0318.sql.gz` at 18:16:32.205 before the receiver process ends at line 747.

The next hop is visible through `smbclient` on APP-INT-01 (eCAR lines 749–752), using `svc_mhsync` and writing to `ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz`. `zeek-core/smb_files.json` lines 228–229 record the corresponding `10.10.2.30:40364 → 10.10.2.21:445` open/write with UID `CUeHjW83VFwDO8jMRNQ`; FILE-LNX-01 syslog lines 462–464 record matching successful open/write/close operations. Small differences between endpoint observation times and server audit times are not sufficient to establish reversed causality.

A separate Windows staging/upload trail is similarly investigable. WS-AJOHNSON-01 creates staging directories, copies from named shares, invokes `Compress-Archive`, and later starts curl PID 6984 at 18:25:08.057 (eCAR line 1405). Its archive read at line 1413 precedes the proxy upload. `zeek-core/http.json` line 1934 sees the CONNECT to `api.westbridge-services.net` on source port 61459 at 18:25:11.981150; the proxy's two linked lines report both tunnel accounting and the inspected upload. `zeek-dmz/ssl.json` line 2343 provides the proxy's upstream TLS observation to `45.33.32.30:443` at 18:25:12.244101. These sources support the transport and upload interpretation without requiring an unseen plaintext POST in the passive TLS sensor.

### Lifecycle and platform boundaries

Across all 23 eCAR files, I checked visible process identities for use after a recorded termination and actor references preceding their visible creation. Those checks found no examples. This is evidence of coherent observable lifecycles, not proof of production origin and not a reason to penalize source completeness.

The Macs distinguish forked inherited images from later exec images. For example, MAC-MROSS-01 Endpoint Security lines 1–7 show the launchd/xpcproxy/Terminal/login/zsh chain, with distinct exec transitions and audit-token changes. I did not assume that every normalized PROCESS CREATE must be an exec, or that a notification's result field proves an authorization denial.

The Unified Log policy message for MeetingAssist at 15:42:20.850119 on MAC-MROSS-01 says the policy “would not allow” the process. It does not independently establish successful execution or downstream effects. Likewise, the endpoint-inventory plist creation at eCAR line 57 and deletion at line 517 are file events; registration and activation require their own evidence. These distinctions avoid manufacturing a contradiction from different event meanings.

### Distribution reservations and limits

The strongest remaining concern is texture rather than broken tradecraft. The Macs repeatedly invoke a compact set of diagnostic tools, and MAC-MROSS-02 repeatedly uses `cat` against binary document formats. Those are genuine visible patterns, but neither is conclusive: the same operator, automation, or filtered telemetry could produce them.

I found an endpoint/syslog root SSH tuple at 18:14 (`10.10.2.30:45876 → 10.10.4.10:22`) without an exact connection-file match. I did not score that absence: the supplied records do not establish lossless sensor capture, and neighboring flows being present cannot rule out a local observation gap. Similarly, I did not score missing Sysmon event families, five Unified Log rows, lack of a preferred source, compact attack sequencing, or complete correlations as synthetic tells.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Mac shell history and endpoint process telemetry | Both Macs; 41 history commands use 12 executable paths | Small increase for repeated diagnostic vocabulary; same user and collection selection are strong alternative explanations |
| weak_signal | Mac Endpoint Security exec arguments | Eight `cat` executions on MAC-MROSS-02, including Office documents and PDFs | Small increase for unusual document-access behavior; technically possible and not independently decisive |
| hard_contradiction / contract_gap | Reviewed endpoint, authentication, network, SMB, and proxy pivots | Checked visible identities and selected cross-source chains | No demonstrated finding supporting an increase |

## Realism Score by Category

- **Field format accuracy:** 9 — The inspected fields support source-appropriate interpretation; no demonstrated native-format contradiction was found, although this was not a comprehensive vendor-schema certification.
- **Temporal patterns:** 8 — Selected transport/authentication and process/file sequences work; repeated interactive command texture mildly reduces confidence.
- **Cross-source correlation:** 9 — Independent endpoint, SSH, SMB, proxy, and sensor pivots remain usable with plausible observation offsets.
- **Behavioral realism:** 7 — Suspicious commands and credential boundaries are credible, while repeated diagnostic pools and shell-based binary-document access warrant caution.
- **Environmental consistency:** 9 — Mixed operating systems, segmented services, identity namespaces, and dominant source volumes are mutually plausible.

## Recommendations

- If this were synthetic, expand the Macs' visible interactive work beyond the repeatedly reused diagnostic vocabulary, while preserving user-specific habits and legitimate repetition. The concrete target is the two supplied zsh histories, not an arbitrary requirement for more logs.
- If this were synthetic, ground repeated document reads in the actual application or task producing them. In particular, the eight `cat` executions on MAC-MROSS-02 should reflect a documented shell workflow if intentional; otherwise use the relevant document application's process/file activity rather than repeatedly substituting a terminal reader.
- Preserve the existing distinctions between local identity and outbound credentials, CONNECT control traffic and inspected uploads, fork and exec, and file placement versus activation. They make the visible evidence technically defensible and should survive any realism changes.
