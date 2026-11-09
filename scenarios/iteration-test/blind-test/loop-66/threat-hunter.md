# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 39

## Executive Summary

The supplied telemetry is mostly production-like: the investigated credential, file-staging, SSH-transfer and proxy-upload pivots retain plausible identity and timing relationships across sources. Recurrent, narrow background command distributions raise some suspicion, but I found no demonstrated impossible lifecycle or source-native contradiction strong enough to decide its origin.

## Evidence For Synthetic

- [distribution_texture] Windows server process starts are heavily concentrated in the same four executable families: `WmiPrvSE.exe`, `dllhost.exe`, `taskhostw.exe` and `conhost.exe` account for 113/152 starts on DC-01, 106/129 on DC-02 and 79/88 on FILE-SRV-01 in their respective `ecar.json` files. Examples include DC-01 lines 2, 53, 82, 198, 209 and 211; DC-02 lines 27, 45, 60, 113, 161 and 190; FILE-SRV-01 lines 10, 15, 56, 88 and 92. The similar narrow mixture across different server roles looks like a reusable background pool. This is a moderate texture concern, with an important alternative explanation: common management software or filtering could produce such a mixture.
- [weak_signal] Both Mac shell histories repeatedly cycle through the same small inventory-oriented vocabulary. MAC-MROSS-01 has 22 entries/14 distinct command strings and MAC-MROSS-02 has 20/13; the exact `find /Users/maya.ross/Documents -maxdepth 2 -type f -name '*.pdf'` command occurs twice on each machine. See their `zsh_history/maya.ross.zsh_history` files, MAC-01 lines 10 and 18 and MAC-02 lines 7 and 18. Repeated `sw_vers`, `id`, `ps aux`, `df` and `du` increase the pool-like impression. Because both hosts belong to the same visible user, this is weak corroboration, not independent proof.
- [weak_signal] Linux administrative commands sometimes use client/package labels as service names across hosts: APP-INT-01 `syslog.log` lines 4 and 54 reference `systemctl is-active/restart smb-client`; WS-LNGUYEN-01 lines 113 and 178 reference `service smb-client status` and `service smbclient status`; WS-OHADDAD-01 line 133 references `systemctl restart cifs-utils`. The related process executions are visible in eCAR, including WS-OHADDAD-01 lines 560–561. These labels suggest generic command substitution rather than host-specific service administration. They could also be unsuccessful operator commands or locally defined units; the logs do not demonstrate success, so this is not an impossible-action finding.

## Evidence For Real

- The SSH transfer has usable, technically coherent pivots. APP-INT-01 starts its root SSH client at 18:14:32.028 (`ecar.json` line 632); Zeek observes `10.10.2.30:38142 → 10.10.4.10:22` at 18:14:38.741946 (`zeek-core/conn.json` line 10680); DB-PROD-01 then records connection, password acceptance and PAM session opening at 18:14:42.562591, 18:14:52.342993 and 18:14:52.458595 (`syslog.log` lines 231–233). The destination shell follows at 18:14:54.019 (DB `ecar.json` line 512).
- Windows `/netonly` behavior preserves the distinction between local and outbound identity. WS-AJOHNSON-01 `ecar.json` line 1088 records `runas.exe /netonly /user:marcus.chen "cmd.exe /d /q"`; line 1096 records the child as local principal `aisha.johnson`. Security Event 4648, EventRecordID 131051, independently identifies subject `aisha.johnson`, target `marcus.chen`, and caller PID `0x1aa0` (6816), matching the runas process.
- The upload pivot preserves proxy topology and encryption boundaries. WS-AJOHNSON-01 `ecar.json` line 1279 shows curl using `10.10.3.20:8080`; `zeek-dmz/http.json` line 2398 shows the client CONNECT using source port 63290; `zeek-dmz/ssl.json` line 2642 shows the proxy's separate upstream TLS connection and matching server name. `PROXY-01.../proxy_access.log` line 3622 explicitly records `proxy_action=ssl-inspect ssl_bump=bump`, explaining the proxy's visibility of the POST path and upload size.
- Network records contain more than successful flows: Zeek core includes 1,698 S0, 418 OTH, 167 RSTO, 85 RSTR and 36 REJ records, alongside 9,690 SF records. A second sensor observes some same-tuple traffic with different UIDs, slight timestamp offsets and packet-loss differences rather than identical copied rows.
- DC-01 Security logging exhibits a coherent clear-and-continue sequence: Event 1102 has EventRecordID 1 at 18:42:16.3780569, and the subsequent account deletion at 18:49:51.7161915 has EventRecordID 347. The clear event uses the Eventlog provider and `UserData/LogFileCleared` structure rather than an invented Security-Auditing EventData shape.

## Detailed Analysis

### Scope, provenance and method

I examined the supplied briefing and files under `/private/tmp/log-study-uerqg1nx/data` only, plus the upstream Zeek DNS script to verify one native formatting question. No project files, scenario definitions, prior assessments or parent-directory inventories were accessed. Parsing used system Python from the neutral `/private/tmp` working directory; filesystem modification times were not used.

The directory contains 113 files spanning 23 endpoint host directories: ten with Windows Security/Sysmon XML, eleven with Linux-style syslog, and two with native macOS Endpoint Security and Unified Log exports. All 23 have normalized eCAR telemetry. Visible addresses occupy several segments, including `10.10.1.*`, `10.10.2.*`, `10.10.3.*` and `10.10.4.*`; host names and observed connections support workstation, directory, file, application, database, mail and proxy functions. Those names are useful orientation, not proof of exact organizational roles.

The eCAR window is 2026-11-02 13:00:01.077–18:59:49.413 UTC. Its 35,929 records include 26,892 FLOW/CONNECT, 2,118 PROCESS/CREATE, 1,943 PROCESS/TERMINATE and 959 USER_SESSION/LOGIN records. Forty principal strings appear, including machine accounts, system principals and service users; this is not a count of forty human users. The three network sensors contain 22,270 connection records in aggregate, including overlapping observations. Other substantial sources include 3,846 syslog lines, 3,929 proxy access rows and 722 web access rows. This is a believable volume for a bounded, selected collection, and suspicious actions are embedded among administrative, application, authentication and network activity.

I parsed all eCAR and Windows Security/Sysmon files and all Zeek connection/HTTP files for selected consistency checks, then followed specific hunts across endpoint, authentication, history, proxy and network records. These checks are bounded observations, not certification of every native schema field.

### Credential and persistence hunt

DC-01 records SYSTEM execution of domain account creation at 17:14:40.107 and its `net.exe` child at 17:14:40.260 (`ecar.json` lines 3696 and 3703). Security 4720, EventRecordID 28256794, creates `svc_dirsync` at 17:14:44.2435994. The command adding it to Domain Admins follows at 17:14:44.948/17:14:45.118 (eCAR lines 3715 and 3723), and Security 4728, EventRecordID 28256803, records that membership at 17:14:49.1715638 with the same account SID ending `-1266`.

Service creation commands appear at 17:19:45.306/17:19:45.429 (lines 3811 and 3818). Scheduled-task commands follow at 17:19:58.410/17:19:58.607 (lines 3834 and 3841). Security 4698, EventRecordID 28257054, records the matching task at 17:20:02.5218353, with `PT1H` repetition and the DeviceSyncSvc executable. These are investigate-worthy actions, but their narratability and sequence are not authenticity indicators.

At 18:42:12.166/18:42:12.350, command and child execution show `wevtutil cl Security` (eCAR lines 5425 and 5432); the 1102 record follows about four seconds later. I did not treat the existence of records from before the clear as impossible: forwarded/exported telemetry can preserve them.

### Collection, staging and exfiltration pivots

On WS-AJOHNSON-01, the `/netonly` pivot begins at 18:01:12.770. Subsequent PowerShell processes enumerate and copy Finance, ClinicalExports and ClinicalResearch content from Windows and Linux file servers (eCAR lines 1113, 1122, 1138, 1149 and 1158). The observed local staging files follow their corresponding copy commands. Compression starts at 18:02:08.375 (line 1171); the archive CREATE is at 18:02:12.055 (line 1178). Curl starts at 18:24:54.407 (line 1279) and reads the same archive object at 18:24:57.423 (line 1287). Thus the upload does not depend on an archive created after its use.

The client-to-proxy Zeek connection is `CnERZiI0gJrzsHBVH`, beginning at 18:24:58.269401 with tuple `10.10.1.35:63290 → 10.10.3.20:8080` (`zeek-dmz/conn.json` line 8969). The proxy-to-server connection is `CGNpaWYXw7fErxgMXh`, beginning at 18:24:58.478711 with tuple `10.10.3.20:38829 → 45.33.32.30:443` (line 8970). The approximately 18.8 MB sent upstream is consistent in scale with proxy `cs_bytes=18783258`; exact equality is not expected because CONNECT, TLS and HTTP introduce different accounting boundaries. Its 1.62-second connection duration is fast but feasible and is not an impossible-volume claim.

A separate support upload from WS-LNGUYEN-01 provides a useful comparison: its curl command carries a JSON metadata part and gzip diagnostics part (`ecar.json` line 574). `zeek-dmz/http.json` lines 2143–2144 preserve the client absolute URI versus upstream origin-form URI, two origin file references and mixed JSON/gzip MIME types. Proxy line 3226 reports 1,573,700 client bytes versus HTTP request-body length 1,573,258, a plausible header/body distinction. This supports pivot feasibility without assuming that every upload is malicious.

### Linux database and SSH lifecycle

DB-PROD-01's root session executes mysqldump at 18:15:00.382, gzip at 18:15:12.485 and scp at 18:15:21.321 (`ecar.json` lines 513, 516 and 519). Its root bash history lines 10, 12 and 14 preserve the redirect to `/tmp/rpt_0318.sql`, compression and transfer destination. The absence of the shell redirection from the mysqldump process argument vector is normal; the shell interprets it.

The return transfer uses `10.10.4.10:32894 → 10.10.2.30:22`, first observed at 18:15:24.325194 (`zeek-core/conn.json` line 10711). APP-INT-01 logs connection at 18:15:29.714206, public-key acceptance at 18:15:31.359810 and session opening at 18:15:31.510672 (`syslog.log` lines 193–195). APP eCAR line 647 records the received archive at 18:15:51.380. The network interval ends at approximately 18:15:50.499 and source-native session close is 18:15:51.122182. The subsecond difference between normalized file observation and native session close is not enough to establish impossible ordering across differently timed sources.

The DB sensor independently observes the transfer in `zeek-db/conn.json` line 365 with UID `C6LYa1A5gSR09EfnDF`, slightly later timestamp, 144 rather than 145 origin packets, and `missed_bytes=589`. Sensor-local UIDs need not match the core sensor's UID. Byte/packet differences support a plausible observation model.

### DNS and macOS interpretation

The core DNS source contains 222 TXT queries beneath `ns1.westbridge-services.cloud`, lines 2139–2487, from 17:45:12.090586 through 18:00:09.819189. Responses include 204 NOERROR, eleven NXDOMAIN, six SERVFAIL and one REFUSED. This is a strong hunting pivot because of encoded-looking labels and low TTLs, but suspicious DNS content itself does not establish synthetic origin. I did not infer a payload transfer of a particular file from these labels alone.

The `TXT <length> <value>` presentation is consistent with the [upstream Zeek DNS TXT handler](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/dns/main.zeek), which formats each character string with its length. Multiple character strings in DKIM answers require separate handling; a naive comparison of the first declared length with the entire answer would produce false defects. I therefore did not score this formatting as synthetic.

The Mac sources are native ES notifications, Unified Log records, shell history and normalized telemetry with different semantics. MAC-MROSS-01 Unified Log line 2 contains a policy message about MeetingAssist; that message alone does not demonstrate successful execution or effects. Likewise, the eCAR plist CREATE/DELETE pair (MAC-01 lines 52/528 and MAC-02 lines 32/511) establishes file observations, not launch-item registration or activation. I did not demand additional native families outside the supplied collection scope.

### Consistency checks and limitations

Across eCAR, no examined actor-linked operation occurred more than two seconds after its visible process termination, and no actor-linked operation preceded its visible process creation by more than two seconds. Parent-UUID checks found no child creation after a matching visible parent termination. The native Sysmon check likewise found no dependent operation timestamp later than the same visible process GUID's termination for the GUID fields examined. These are positive consistency observations, not a claim that all processes require in-window start and stop rows.

Successful Windows logons did not reuse one TargetLogonId for different usernames within a host. For every matched Zeek HTTP/connection row, logged request and response body lengths did not exceed the corresponding directional connection bytes. I also found no connection-side payload total exceeding its IP-byte total or exceeding the maximum possible byte capacity of its recorded packet count. These checks substantially weaken simple lifecycle/accounting arguments for synthetic origin.

The remaining concerns are distributional. A six-hour slice, collection filters and standardized enterprise tooling limit how confidently narrow pools can be distinguished from real standardization. I would not convert those observations into a high-confidence synthetic verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Windows normalized process starts | DC-01: 113/152; DC-02: 106/129; FILE-SRV-01: 79/88 in four executable families | Main concern: similar restricted background vocabulary across distinct server roles; filters and shared tooling remain credible alternatives. |
| weak_signal | macOS shell history and matching process activity | 42 history entries across two hosts, 14 and 13 distinct strings | Small contribution: repetitive inventory commands; same-user ownership reduces independence. |
| weak_signal | Linux sudo/syslog and normalized execution | Multiple service commands using smb-client/smbclient/cifs-utils labels | Small contribution: potentially generic substitution; successful execution is not established. |

No hard contradiction was demonstrated. Complete source matching, the attack's apparent organization, absent unselected Sysmon event types, out-of-window lifecycle endpoints and thin source families contributed no penalty.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source shapes and checked native examples are credible; no demonstrated format defect.
- **Temporal patterns:** 8 — Authentication, process and transfer ordering works in the investigated pivots, with realistic source offsets.
- **Cross-source correlation:** 9 — Credentials, file identities, proxy legs and SSH tuples remain investigable and coherent.
- **Behavioral realism:** 7 — Suspicious actions are technically plausible; background command vocabulary is narrower and more repetitive than expected.
- **Environmental consistency:** 8 — Mixed-fleet and segmented service relationships are credible, with minor service-name plausibility questions.

## Recommendations

- If this were synthetic, broaden the Windows server background process mixture in a role-specific way, addressing the measured 74–90% concentration in four executable families. Preserve any intended collection filtering explicitly so that apparent distribution artifacts can be interpreted correctly.
- If this were synthetic, diversify the Mac user's command vocabulary around the visible work rather than repeatedly selecting the same inventory commands. Keep repeated commands when they reflect an actual repeated task; the issue is the limited aggregate vocabulary across the supplied histories.
- If this were synthetic, distinguish Linux package/client labels from actual locally installed service units when constructing administrative commands. If the visible commands intentionally fail, preserve their failure semantics where the existing collection records results; do not invent successful service effects.
- Preserve the observed strengths: separate proxy legs and inspection policy, `/netonly` local-versus-network identity, shell-interpreted redirection, sensor-local UIDs, and transport-before-authentication ordering. None requires adding unrelated sources or manufacturing analyst-visible mistakes.
