# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 32

## Executive Summary

The records are mostly realistic from a threat-hunting perspective: the principal intrusion pivots work across endpoint, authentication, network, file-transfer and proxy evidence, and I did not establish an impossible visible same-identity lifecycle. A few repetitive background patterns and unusual service/share placement warrant scrutiny, but they are also consistent with centrally managed production systems. Those observations do not justify a confident synthetic verdict.

## Evidence For Synthetic

- [weak_signal] A very consistent background task profile recurs across heterogeneous Linux hosts: each of ten hosts has exactly twelve `/usr/lib/sysstat/debian-sa1` process creations in the six-hour slice, accompanied by the same `/bin/sh -c 'command -v debian-sa1 > /dev/null && debian-sa1 1 1'` wrapper. For example, `WEB-EXT-01.meridianhcs.local/ecar.json` lines 7, 191, 724 and 886 are successive half-hour executions, and `WS-LNGUYEN-01.meridianhcs.local/ecar.json` lines 4, 62, 116 and 144 show the same pattern with a different phase. This is a concrete repeated texture, but fleet-wide cron policy explains it well; I assign it little weight rather than treating periodic system traffic as inherently artificial.
- [environment_or_collection_plausibility] Domain controllers also appear to host application-content shares: `WEB-EXT-01.meridianhcs.local/ecar.json` line 136 launches `content-publisher --share smb://DC-02.meridianhcs.local/WebContent`; lines 770–771 target `DC-01/.../WebContent`; `APP-INT-01.meridianhcs.local/ecar.json` line 451 launches `document-sync --share smb://DC-02.meridianhcs.local/Integration --mode poll`. This is possible in a small or legacy organization, but applying the same content/integration-share pattern to DCs as ordinary file servers is an environmental plausibility concern. It is not an operating-system contradiction or evidence that the actions failed.
- [weak_signal] The two Macs show substantial overlap in their interactive command vocabulary: `id`, `sw_vers`, `uname`, `pwd`, `ls`, `du`, `df`, `ps`, `find` and `dscl`, repeated in both `MAC-MROSS-01.../zsh_history/maya.ross.zsh_history` and `MAC-MROSS-02.../zsh_history/maya.ross.zsh_history`. This gives the activity a narrow command-pool texture, but the same named user operates both hosts, so ordinary working habits are an especially strong alternative explanation. This does not support a synthetic verdict alone.

## Evidence For Real

- Lifecycle identity is unusually usable without a demonstrated contradiction. Across all 23 eCAR streams, I checked 1,821 process identities with both visible CREATE and TERMINATE records and checked actor/source-process references against visible process lifetimes. I found no terminate-before-create, child-after-visible-parent-exit, or dependent event outside its referenced visible process lifetime in those checks. Missing pre-window initiators and post-window exits were left neutral.
- The database collection and staging pivot works across distinct sources: `DB-PROD-01.../ecar.json` lines 530–539 show `mysqldump`, gzip, a file read and SCP in an existing root SSH session; `zeek-db/conn.json` line 385 identifies the outbound SCP transport as `10.10.4.10:58586 -> 10.10.2.30:22`; `APP-INT-01.../syslog.log` line 201 records accepted public-key authentication for root on exactly that source tuple; `APP-INT-01.../ecar.json` line 778 records the receiver-side staged file.
- Authentication semantics retain useful distinctions: `WS-AJOHNSON-01.../ecar.json` line 1013 describes a Type 9 session whose local principal is `aisha.johnson`, outbound principal is `marcus.chen`, and parent session is `0x26d7bab`. Subsequent local processes remain attributed to Aisha, which is consistent with NewCredentials semantics rather than incorrectly replacing the local process owner with the outbound username.
- Proxy evidence distinguishes CONNECT control traffic from inspected application traffic. `PROXY-01.../proxy_access.log` lines 3230–3231 tie the upload to tunnel `PT-28adc2f0252aa3eb`, client port 56429, a separate CONNECT setup, and an inspected POST with approximately 18.8 MB of client application traffic. `WS-AJOHNSON-01.../ecar.json` lines 1131, 1138 and 1140 provide the curl process, archive read and matching proxy socket; `zeek-core/http.json` line 1977 exposes the CONNECT, rather than pretending the encrypted upload is automatically plaintext at the passive sensor.
- The dataset includes potentially misleading but plausible benign activity. `WS-EBROOKS-01.../ecar.json` line 346 contains an encoded PowerShell command that decodes to a hotfix inventory query, whereas `DC-01.../ecar.json` line 5563 contains a download-and-execute command. Encoding alone is therefore not sufficient to separate benign and suspicious events.
- Native macOS records distinguish fork, exec and process identity changes. For example, `MAC-MROSS-01.../macos_endpoint_security.ndjson` lines 2–7 show the Terminal launch chain through xpcproxy and login; lines 9, 12 and 15 show successful exec targets for `id`, `sw_vers` and `uname`, matching the command history. This is richer than merely labelling a generic process row as macOS telemetry.

## Detailed Analysis

### Scope, collection and signal-to-noise

The supplied directory contains 117 files and 23 endpoint host collections: ten with Windows Security/Sysmon XML, eleven with Linux syslog, and two with macOS Endpoint Security and Unified Log exports. All have eCAR data. Hostnames and visible behavior support workstation, domain controller, file server, database, application, web, mail, proxy and monitoring roles. Visible addresses span at least `10.10.1.0/24`, `10.10.2.0/24`, `10.10.3.0/24` and `10.10.4.0/24`, as well as Internet peers.

The main window is November 2, 2026, approximately 13:00–19:00 UTC. There are 35,807 eCAR records, of which 27,154 are FLOW/CONNECT observations, 2,043 are PROCESS/CREATE and 1,904 PROCESS/TERMINATE. The three Zeek collections contain 22,148 conn records in total: 12,314 core, 9,401 DMZ and 433 database. These are observations from overlapping sensors, not 22,148 necessarily unique enterprise connections. The proxy has 3,524 access rows and the public web server has 757 access rows. I did not assume that this selected collection represented all production events or all employee machines.

The source mix fits the roles reasonably well. The proxy has 5,347 endpoint FLOW records, the domain controllers have 4,718 and 3,953, while the database has 431. The scan activity materially increases web-server and network-sensor volumes, so those volumes should not be interpreted as ordinary user browsing rates. There is enough background authentication, services, file sharing, web access, administrative work and update/maintenance activity that the investigation requires actual pivots. Thin Unified Log coverage by itself is not evidence of synthetic generation.

### Initial foothold and discovery

`WEB-EXT-01.../ecar.json` line 840 records a `www-data` bash process spawned from Apache at 14:20:06.317. The encoded shell text resolves to a bash reverse TCP connection to `45.33.32.30:8443`. Line 841 records the matching outbound socket from `10.10.3.10:41647` at 14:20:09.662, and `zeek-dmz/conn.json` line 1625 records the same tuple at 14:20:09.585467 with an established TCP session. Source-local observation times differ by milliseconds; that is not an impossible ordering.

Later, the root shell context in this host contains network and filesystem discovery: eCAR lines 917, 920, 923 and 926 show `ip addr`, hosts/resolver inspection and a credential-name search. Lines 928 and 1184 show a host-discovery scan and a TCP connect scan of ports 22, 80, 443, 445 and 3306 against `10.10.2.0/24`. These commands and the associated source network role are technically plausible. I do not infer that the earlier `www-data` shell itself achieved root merely from this sequence: the later root activity is associated with a separately visible root SSH login. A missing explanation for how an adversary obtained that credential is not, by itself, an authenticity defect.

### Directory operations and persistence

On DC-01, eCAR lines 3978 and 3985 show `cmd.exe` and `net.exe` creating `svc_dirsync`. Native Security XML contains Event 4720 at line 195844 and names that account at line 195863. Subsequent account-state events precede group membership change evidence: the account is created in a disabled state (`NewUacValue=0x15`) and then changed to `0x10`, before Event 4728 at line 196410 adds its SID to Domain Admins. That sequence avoids the common mistake of treating every account-creation record as immediately usable enabled credentials.

The subsequent service and task persistence have distinguishable artifacts. A `sc.exe create DeviceSyncSvc` process appears before the 4697 service-install record; the separate scheduled task command appears before 4698 at XML line 200298. The later service process is parented to `services.exe`, rather than to the task-creation utility. The presence of a scheduled task does not require every later execution of the same binary to be attributed to the task scheduler, because the dataset also visibly installs a service.

The WMI-parented command processes have SYSTEM child identities while the eCAR parent process is described as NETWORK SERVICE. Remote execution and impersonation can change the child security context; I did not score the username difference alone as an impossible privilege transition. Proving a contradiction would require token/authorization evidence beyond the parent image name.

### Database extraction and file staging

The database pivot provides a particularly useful operational check. The root SSH login from `10.10.2.30:44990` is at `DB-PROD-01.../ecar.json` line 528. `mysqldump` starts at 18:15:22.996, creates `/tmp/rpt_0318.sql`, and terminates at 18:15:51.870. Gzip starts at 18:15:53.247 and terminates at 18:16:03.964. SCP starts at 18:16:05.208 and reads the gzip output at 18:16:15.092. These visible process and artifact relationships are in a workable order.

The SCP connection uses `10.10.4.10:58586 -> 10.10.2.30:22`. The database sensor observes it at 18:16:08.010617 for 34.179892 seconds. On the receiver, public-key authentication is recorded at 18:16:14.267546 and the staged file appears at 18:16:42.816 (`APP-INT-01.../ecar.json` line 778). A later `smbclient` at line 781 reads that artifact and sends it to `FILE-LNX-01/ClinicalResearch`; `FILE-LNX-01.../ecar.json` line 1234 records the corresponding Samba-side path under `/srv/samba/ClinicalResearch/Integration/DB-Staging/` and directory account `svc_mhsync`. Root on the sending Linux host and a directory credential used for SMB are separate namespaces and need not be identical.

### Upload evidence and a benign comparator

On WS-AJOHNSON-01, eCAR line 1075 records archive creation intent, line 1082 the archive artifact, line 1131 curl upload intent, line 1138 the archive read and line 1140 the proxy transport. Proxy lines 3230–3231 and Zeek CONNECT evidence match the client port and destination. This supports a completed upload more strongly than a curl command line alone. The separate proxy setup and tunnel/application byte scopes also make the numerical fields interpretable.

A useful comparator is Lina's support upload. `WS-LNGUYEN-01.../ecar.json` line 403 contains a multipart support-ticket request with JSON metadata and a gzip diagnostic file. `zeek-core/http.json` line 1253 and `zeek-dmz/http.json` lines 1416–1417 preserve the POST, host and URI across client/proxy/server legs. `zeek-core/files.json` line 378 and `zeek-dmz/files.json` lines 1012–1013 identify a 1,572,864-byte gzip attachment. This demonstrates why data transfer alone is not an authenticity cue or an automatic exfiltration conclusion.

### macOS interpretation and lifecycle checks

The macOS source families were treated separately. Shell histories supply commands, Endpoint Security supplies exec/fork/file observations, Unified Log supplies subsystem messages and eCAR supplies normalized process/session/network views. An eCAR PROCESS/CREATE for a forked shell can be followed by PROCESS/MODIFY for exec; it should not be mistaken for a claim that the child remained zsh while executing `id`.

`MAC-MROSS-01.../macos_unified_log.ndjson` line 2 contains a policy message concerning MeetingAssist at 15:42:11.450696. I did not convert that message into proof of successful application execution, nor infer execution effects from its presence. I also did not score unfamiliar version-11 ES serialization details as schema defects without evidence establishing the applicable native contract.

I parsed the Windows XML and checked visible Sysmon process lifetimes and parent GUID relationships as well as all eCAR process lifetime references. The examined identities did not reveal an impossible visible parent/child ordering. This establishes internal coherence in those checks, not provenance: a sufficiently careful synthetic producer could achieve the same result.

### Weight of the remaining concerns

The repeated half-hour sysstat jobs are routine scheduler behavior and can follow a shared enterprise build. Similarly, repeated commands by one user on two Macs are weak evidence because user habits transfer between hosts. The unusual use of DCs for WebContent and Integration shares has more environmental relevance, but nothing in the logs makes such deployment impossible. These observations keep the appearance score above the indistinguishable range; they are too explainable to override the substantial lifecycle and pivot coherence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Linux eCAR process telemetry | Ten hosts, twelve identical sysstat task occurrences per host | Small upward pressure from repeated background texture; shared cron policy is a strong alternative explanation. |
| environment_or_collection_plausibility | Linux application processes and SMB destinations | Web/application processes target content/integration shares on domain controllers | Modest upward pressure from unusual role overlap; possible legacy deployment, not a hard contradiction. |
| weak_signal | macOS shell histories | Same user on two hosts | Very small upward pressure from narrow, repeated vocabulary; same-user habits substantially weaken it. |

No verified hard contradiction, required missing companion, or generator identity leak was established. Completeness of matching, attack narratability and out-of-window lifecycle omissions were not scored.

## Realism Score by Category

- **Field format accuracy:** 8 — Examined JSON/XML and native process/event structures were usable; no demonstrated source-native field impossibility.
- **Temporal patterns:** 8 — Process and transfer sequences work, with plausible source observation differences; repetitive timer texture remains a weak concern.
- **Cross-source correlation:** 9 — SSH/SCP, SMB staging and proxy uploads support useful, technically coherent pivots.
- **Behavioral realism:** 8 — Administrative noise, benign encoded PowerShell and support transfers provide credible hunting alternatives; Mac command vocabulary is narrow.
- **Environmental consistency:** 7 — Mixed fleet and traffic volumes are plausible, while DC content/integration shares merit clarification.

## Recommendations

- If this were synthetic, make share placement follow an explicitly consistent service role: either reserve ordinary content/integration shares for designated file/application hosts or provide log-visible service evidence supporting their deployment on DC-01 and DC-02.
- If this were synthetic, preserve per-host scheduled-task phase and regularity when justified by management policy, but broaden other background activity according to actual host roles rather than increasing arbitrary randomness. The repeated twelve-task sysstat profile is the visible pattern motivating this recommendation.
- If this were synthetic, expand the two Macs' command/workflow vocabulary only where their visible user roles justify it. Keep the existing successful-exec evidence and distinguish process forks from subsequent exec transitions.
- Preserve the existing identity, authentication, artifact and proxy-byte relationships. The strongest result of this review is that the main operational pivots work; changing those to manufacture messiness would reduce realism.
