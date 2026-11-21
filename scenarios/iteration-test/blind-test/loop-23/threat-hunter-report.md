# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 48

## Executive Summary

The dataset supports credible investigations across Windows, Linux, macOS, network sensors, proxy, firewall, and authentication evidence, with strong visible lifecycle and transport coherence. A systematic Windows process-creation identity pattern and a smaller ambiguity in SCP socket attribution suggest possible synthetic simplification or export normalization, but I did not establish a hard contradiction sufficient to confidently classify the dataset as synthetic or real.

## Evidence For Synthetic

- [contract_gap] **Windows creator/target identity appears flattened.** Across all 992 Security event 4688 records, `TargetUserSid=S-1-0-0` and `TargetLogonId=0x0`. Matching the process IDs to Sysmon event 1 identifies 49 creations with different `ParentUser` and `User` values, yet the Security subject is populated as the child identity and the target remains empty. For example, `DC-02.meridianhcs.local/windows_event_security.xml`, RecordID **25379823**, at **2026-11-02T14:30:10.9851099Z** identifies aisha.johnson/LUID `0xcc070d9` as subject for `userinit.exe` PID `0x1d88`, created by `winlogon.exe` PID `0x1d80`; the companion Sysmon record identifies the parent as SYSTEM. This is suggestive of a renderer mapping the new process principal into the creator fields without separately representing the target token. Parent account alone does not prove the effective thread token, so the 49 matches are a screening population, not 49 independently proven impossible events.
- [contract_gap] **The new-credentials boundary is particularly poorly expressed in Security process creation.** On `WS-AJOHNSON-01`, `runas.exe` PID 6676 belongs to aisha.johnson/LUID `0x26db422`, while its new `cmd.exe` PID 6700 belongs to cloned LUID `0x27c990d`. Nevertheless, Security 4688 RecordID **131052**, **18:00:45.7971925Z**, uses `SubjectLogonId=0x27c990d` and empty target fields while naming creator PID `0x1a14` (6676). This reinforces the creator-versus-new-process concern above; it is the same underlying indicator, not an additional independent defect. Impersonation or an export transformation could affect the interpretation, so I do not label it a hard contradiction.
- [weak_signal] **SCP flow attribution looks like activity-level attribution rather than literal socket ownership.** `DB-PROD-01.meridianhcs.local/ecar.json`, line **616**, at **18:15:30.350Z** attributes the TCP connection `10.10.4.10:35881 -> 10.10.2.30:22` directly to `/usr/bin/scp`, PID **1418126**, object `c87bdc4c-d1dd-4ea8-854b-401436e4cddd`. Standard OpenSSH SCP normally delegates the SSH transport to an SSH child. The supplied process records show the SCP process but no corresponding client SSH child for this transfer. A normalizer can intentionally attribute traffic to an initiating ancestor, so this is an unresolved ownership-semantic issue, not proof that the transfer could not occur.

## Evidence For Real

- **Visible process lifecycles withstand direct checking.** Across the 38,311 eCAR records, checking actor references against same-host visible process creates and exits found no dependent event more than one second before its actor's creation or after its termination. A separate check of native Sysmon `UtcTime` and process GUID relationships found no process-dependent event before its visible event 1 or after its visible event 5. These are bounded checks, not a claim that every possible lifecycle is complete.
- **SSH transport precedes successful authentication in the available endpoint observations.** Matching successful SSH session logins to inbound eCAR FLOW tuples produced no matched case where the FLOW appeared after the login. The DB root session gives a concrete example: network transport begins around **18:14:51Z**, syslog records the connection at **18:14:54.975364Z**, password acceptance at **18:15:02.668685Z**, and the shell at **18:15:04.317Z**.
- **The SCP transfer is otherwise well supported and temporally workable.** Both core and DB sensors observe the same tuple and payload counts with sensor-specific UIDs. APP-INT-01 records root public-key acceptance, PAM session opening, receipt of the named file, and session closure. The approximately 1.16 MB originator payload over roughly 34 seconds is operationally plausible.
- **Windows credential boundaries are usefully represented outside the suspect 4688 fields.** The **18:00:45Z** Type 9 event on WS-AJOHNSON-01 preserves local identity aisha.johnson while recording outbound identity marcus.chen. This permits a realistic hunt for credential reuse without incorrectly treating the local process user and remote network credentials as the same identity.
- **The proxy path respects encryption visibility.** The **18:25:22Z** connection from WS-AJOHNSON-01 to the suspicious external service is an HTTP CONNECT to the proxy, not an invented plaintext POST of the encrypted URI. The detailed upload intent is visible in the endpoint curl command, where it belongs.
- **Benign-looking and suspicious activities require discrimination.** The valeworks support activity includes separate macOS, Windows, and Linux downloads and a Linux multipart support attachment; encoded PowerShell on WS-EBROOKS-01 decodes to ordinary file enumeration. This gives concrete false-positive opportunities rather than equating encoding, curl, or external uploads with compromise.
- **Background telemetry fits several distinct roles.** The file server has SMB access and object-access evidence; the DB sensor is dominated by appropriate database and supporting traffic; the web host has 861 access-log records; the proxy has 4,471 access records; and Linux hosts include cron, sudo/PAM, SSH, service and kernel messages. I do not interpret different source coverage or low native macOS message counts as synthetic evidence by themselves.

## Detailed Analysis

### Scope and collection assumptions

I examined only the supplied data directory. There are **23 endpoint host directories**: ten with Windows Security/Sysmon XML, eleven with Linux-like syslog and eCAR, and two with macOS Endpoint Security, Unified Log, eCAR, and zsh histories. Endpoint FLOW direction identifies four internal subnets: `10.10.1.0/24`, `10.10.2.0/24`, `10.10.3.0/24`, and `10.10.4.0/24`. These are observed host counts, not a claim that the organization's whole fleet is present.

The common window is approximately **2026-11-02 13:00–19:00 UTC**. eCAR has **38,311** rows. The three network sensors contain **12,325** core, **10,533** DMZ, and **454** DB connection records; these must not be summed as unique network activities because multiple sensors observe some of the same tuples. There are **25,753** firewall lines and **145** combined IDS alerts. Security XML contains **18,076** events and Sysmon XML **11,747** events. The source mix is compatible with a deliberately collected investigation slice; its completeness is not itself an authenticity clue.

I parsed the XML and JSON records, counted source/event families, sampled native messages and histories, followed suspicious commands and their endpoint/network pivots, and checked process lifecycle and successful SSH transport ordering. I did not require boot-time initiators, out-of-window closes, unselected Sysmon families, or unavailable products.

### Hunting through remote access and credential reuse

The WS-AJOHNSON-01 trail begins with activity from `10.10.1.99`, including failed SMB authentications, a successful Type 3 logon at **16:00:45.068Z**, and a Type 10 logon at **16:01:25.964Z** with source port **47343**, LUID **0x26db422**, and session **4**. The endpoint records subsequent session initialization and an Explorer process. This provides usable pivots from source address to remote session to user processes.

At **16:45:04.107Z** in Sysmon, PID **6164**, `ms-index-service.exe`, starts with the arguments `privilege::debug` and `sekurlsa::logonpasswords`, under aisha.johnson, **High** integrity, in that same remote session. The eCAR records show a process open to LSASS PID **4292** with access **0x1FFFFF** and a remote thread shortly afterward, followed by process exit. This is suspicious credential-access evidence. The high integrity label avoids an immediate contradiction in which an ordinary medium-integrity process supposedly obtains unrestricted LSASS access. I do not infer actual credential recovery solely from the command name or access event.

DC-01 subsequently contains a coherent service-execution and persistence investigation path: `PSEXESVC.exe` at approximately **17:00:14Z**, `net user ... /add /domain` around **17:15:02Z**, a Domain Admins membership command at **17:15:15Z**, and DeviceSyncSvc/service and scheduled-task creation commands around **17:19:40–42Z**. The accompanying Security event families include account creation, membership change, service creation and task creation. These are useful corroborating pivots. Their sequence or narratability is not scored as synthetic.

The new-credentials session at **18:00:45Z** is an important distinction: aisha.johnson remains the local process identity while marcus.chen is the outbound principal. File collection commands then refer to Finance, ClinicalExports, and ClinicalResearch shares before archive creation. This is operationally plausible account reuse; a local/remote username difference is not inherently contradictory. The concern is specifically that Security 4688 appears to lose the creator/target distinction at the transition, while the session records preserve it.

### Proxy and exfiltration pivots

WS-AJOHNSON-01's curl process PID **6852** starts at **18:25:17.759Z**, reads the archive at **18:25:21.015Z**, and connects to `10.10.3.20:8080` using source port **57912** at **18:25:21.323Z**. The endpoint command supplies a multipart archive and the external HTTPS destination. In `zeek-core/http.json`, UID **CNd6TtHg1UY3C0xfC**, timestamp **1793643922.016357**, records the matching client/proxy tuple, `method=CONNECT`, `host=api.westbridge-services.net`, and success status **200**. The DMZ sensor observes it with UID **CJr9YGYe6w8rlY3Ab** and a modest timestamp offset. Distinct sensor UIDs are expected, and the tuple supports the pivot.

The Linux support upload provides a useful comparison. `WS-LNGUYEN-01` creates `/tmp/mhs-support-48217.tar.gz` with tar and later invokes curl with JSON metadata plus a gzip diagnostics part. Core HTTP UID **CYZ4lUTDwS7TXNy4Ss1**, at timestamp **1793639648.262463** (**17:14:08.262463Z**), records a plaintext proxy POST with **1,573,258** request-body bytes, filename `mhs-support-48217.tar.gz`, and JSON/gzip MIME parts. The DMZ outbound proxy leg uses an origin-form URI while the client-facing proxy leg uses an absolute URI. This is more credible than treating every proxy-mediated upload identically.

### Linux SSH and transfer lifecycle

APP-INT-01 starts `ssh -l root 10.10.4.10` at **18:14:40.520Z**. Core UID **CHO6cGZ5SnHDiKkcFJ** observes `10.10.2.30:53632 -> 10.10.4.10:22` at **18:14:51.363477Z**. DB-PROD-01 syslog then records Connection, Accepted password, PAM opening and logind session **481**; eCAR creates the shell before the mysqldump process. The chain is technically feasible.

The return SCP transfer starts at **18:15:26.544Z**. Core UID **CSC28ajfKMsKKuArfX3** begins at **18:15:29.393896Z**, lasts **33.698784** seconds, and records **1,157,671** originator bytes plus **38,674** responder bytes. The DB sensor agrees on tuple, byte counts, and nearly the same duration with its own UID **Cj8BOQdQVYFG3LgfXMi**. APP-INT-01 syslog records root public-key acceptance at **18:15:35.383375Z** and session closure at **18:16:03.535590Z**; its eCAR file creation is **18:16:03.768Z**. Subsecond differences between normalized endpoint and native syslog observations are not evidence of an impossible sequence.

My ownership concern is narrower: the client FLOW directly identifies SCP as the transport process. This could reflect normalization to the initiating program. Without a schema statement defining whether FLOW process identity means socket owner or initiating ancestor, I cannot turn it into a hard contradiction. Likewise, I do not conclude that `/tmp/rpt_0318.sql.gz` could not exist merely because a compression process is not in the supplied slice.

### macOS and alternative explanations

The macOS records distinguish fork from exec using eCAR CREATE/MODIFY and native Endpoint Security events. On MAC-MROSS-01, PID **29678** forks from zsh, execs Homebrew curl, downloads a support script, and exits. A later, different PID **29725** executes bash with the script's `--check-config` argument. This supports execution independently of the download; it does not rely on assuming that a downloaded file automatically ran. Histories and process arguments also show separate administrative SSH activity from both Macs.

I found no basis in this review to allege a macOS version-specific schema defect, denied execution followed by impossible effects, or required missing launch-item behavior. The small Unified Log export can be filtered and does not establish an inherently impossible source volume.

### Weight of evidence and uncertainty

The Windows identity pattern is the most substantial tell because it recurs across the entire process-creation event family and affects a practical hunter's attribution of who requested a process versus whose token the new process uses. However, process parent identity does not always equal the effective creator identity: impersonation, service-mediated launches, and normalization can complicate that relationship. I therefore score this as a meaningful contract concern rather than certainty of fabrication.

The SCP observation is a second, weaker attribution concern. Against these stand robust tuple pivots, sound visible process ordering, appropriate credential separation, plausible role-specific background sources, and proper encrypted-proxy visibility. I found **no demonstrated hard contradiction or generator identity leak**. These competing observations support an inconclusive classification near the middle of the rubric rather than a high-confidence synthetic verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Windows Security 4688 versus Sysmon process identity | All 992 4688 records leave target identity empty; 49 matched creations have different parent/child accounts; explicit Type 9 example also changes LUID | Primary reason the score is above the mostly-production-like band; possible creator/target flattening affects attribution. Effective creator tokens and export semantics remain uncertain. |
| weak_signal | Linux normalized eCAR FLOW/process ownership | One directly examined DB-to-APP SCP transfer, PID 1418126 and tuple port 35881 | Small upward weight: direct SCP socket attribution may simplify the SSH subprocess relationship, but ancestor attribution is a viable normalizer explanation. |

## Realism Score by Category

- **Field format accuracy:** 7 — Native files parse, hashes have valid lengths, and event fields are largely credible; repeated 4688 creator/target identity treatment remains suspect.
- **Temporal patterns:** 9 — Visible process and successful SSH ordering hold up; sampled transport, authentication, shell and close intervals are feasible.
- **Cross-source correlation:** 8 — Endpoint, network, proxy and session pivots work well; creator/target and SCP socket ownership need semantic clarification.
- **Behavioral realism:** 8 — Credential access, remote services, administrative sessions and uploads have workable commands and account boundaries; observed actions do not alone prove their intended success.
- **Environmental consistency:** 8 — Mixed platforms, server roles, four internal segments and supporting source families fit the observed activity without requiring uniform collection.

## Recommendations

- If this were synthetic, represent **Security 4688 Creator Subject and Target Subject separately**, including distinct logon IDs when a process is launched under a new token. Validate userinit and new-credentials transitions against the parent, requesting identity, and actual new-process identity rather than filling all identity fields from the child principal.
- If this were synthetic and eCAR FLOW identity is intended to identify the **actual socket owner**, model the SCP client's SSH subprocess and attach the connection to that process. If initiating-ancestor attribution is intentional, make that collection semantic explicit instead of leaving it indistinguishable from socket ownership.
- Preserve the successful distinctions already present: local versus outbound credentials, download versus execution, separate sensor UIDs, and plaintext proxy requests versus opaque HTTPS CONNECT traffic. These make the dataset useful for a real hunt and should survive any ownership-field correction.
