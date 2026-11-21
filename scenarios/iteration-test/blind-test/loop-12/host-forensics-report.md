# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 48

## Executive Summary

The endpoint evidence is substantially coherent across Windows, Linux and macOS, with consistent process identities, stable hashes and credible session ordering. Repeated shell-based reads of binary business documents on one Mac and unusually frequent server service authentications raise authenticity questions, but neither establishes fabrication. I found no demonstrated hard endpoint contradiction sufficient to distinguish a carefully modeled dataset from a sanitized production collection.

## Evidence For Synthetic

- [distribution_texture] `MAC-MROSS-02.meridianhcs.local/ecar.json` attributes seven reads of PDF, DOCX or XLSX files to `/bin/cat`, including `project-plan.pdf` at 13:37:29.955Z, `service-review.xlsx` at 16:05:57.353Z, `project-plan.docx` at 17:10:47.996Z and `onboarding.docx` at 17:12:32.454Z on 2026-11-02. The corresponding Endpoint Security exec records contain literal `cat` arguments rather than document-viewer commands. Repeated raw reads of compressed Office documents and PDFs are an odd substitute for ordinary document use; the recurrence across seven paths suggests a generic file-read behavior. This is possible shell activity, not an impossible execution or a native-schema error.
- [weak_signal] Windows server service authentications are unusually numerous relative to the visible process activity. `DC-01.meridianhcs.local/windows_event_security.xml` contains 155 Type 5 successes in six hours: 59 for NETWORK SERVICE, 50 for SYSTEM and 46 for LOCAL SERVICE; `MAIL-FIN-01` contains 66 with a similarly balanced 24/21/21 split. For example, MAIL-FIN records service logons at 13:03:48.7531054Z, 13:04:21.2487454Z and 13:07:43.0692467Z, all through the same `services.exe` PID `0x948`. That resembles a generic service-authentication noise stream. Services sharing existing hosts and collection filtering are viable explanations, so I give this only slight weight and do not require unavailable System-channel service-control events.

## Evidence For Real

- Across all ten Windows hosts, all 873 visible Sysmon Event 1 records have a Security 4688 record with the same PID, executable, command line and parent PID. There are 877 Security 4688 records overall; small source differences do not constitute a defect.
- Windows executable and module hashes remain stable for a given host/path. Across the visible process-creation hash sets, I found no identical hash set paired with conflicting `FileVersion` values, including when comparing hosts with different Windows build families.
- Identity-based checks of all 23 eCAR host files found no process termination before its visible creation, no visible child assigned to a conflicting parent PID, and no dependent use of a known actor more than 500 ms after its visible termination. The comparable Sysmon check also found no dependent occurrence outside a visible process lifetime beyond that tolerance.
- Linux sessions contain real operational detail: for example, DB-PROD SSH PID `1369962` progresses from connection at 13:26:13.677283Z to public-key acceptance at 13:26:19.866241Z, PAM session open at 13:26:19.924343Z and PAM close at 14:00:35.921400Z. The same user's ED25519 key fingerprint remains consistent.
- macOS distinguishes process lifetimes from successive executable images. MAC-MROSS-01 PID `25527` visibly transitions from launchd's fork image to `xpcproxy` to Terminal while retaining its start time and advancing `pidversion`; separate child lifetimes implement login and zsh.
- Administrative and desktop activity varies by host. Lina Nguyen's shell history contains Git, Docker, editors and test commands; Omar Haddad's includes Python/pandas, CSV inspection and SQL; Linux server telemetry includes cron, authentication and service-specific evidence rather than Windows process defaults.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. The endpoint inventory contains 23 eCAR host streams with 36,715 rows, ten Windows Security XML streams with 17,375 events, ten Sysmon XML streams with 11,315 events, eleven Linux syslog streams, two macOS Endpoint Security streams totaling 322 records, two Unified Log streams totaling six records, and shell histories. The common observation period is approximately 2026-11-02 13:00–19:00 UTC.

I parsed the XML and JSON records, inventoried source and event families, checked visible process lifetimes and actor references, compared Windows creation records, grouped hashes and inspected actual native records and shell commands. These checks establish internal consistency, not provenance. They do not prove that every expected operating-system event was collected. I did not use file modification times, domain validity, intrusion narrative shape, completeness of cross-source matching or absence of selected Sysmon types as authenticity indicators.

### Windows processes and source correlation

On WS-MCHEN-01, Sysmon Event 1 at `UtcTime=2026-11-02 13:03:50.517` creates Firefox PID `7184`, parent explorer PID `6780`, under `MERIDIANHCS\marcus.chen`, LogonId `0x6c29844`, TerminalSessionId `5`. Its ProcessGuid is `{7b2a0e3f-8a36-6ae8-b602-001074ae919d}`. Security 4688 at 13:03:50.6321476Z records NewProcessId `0x1c10`, creator PID `0x1a7c`, the same URL command and the same user session. The eCAR creation at 13:03:50.631Z agrees on PID, parent and principal. A subsequent Sysmon module load uses that same ProcessGuid for `mozglue.dll`.

All 873 Sysmon creations passed the equivalent PID/path/command/parent comparison. Matching was by host and numeric PID; this is a useful bounded check, not a universal lifetime proof under arbitrary PID reuse. Separate GUID-based Sysmon checks covered creation, termination and dependent records for identities whose boundaries are visible. No ordering contradiction exceeding 500 ms appeared. Small inter-source timestamp differences are credible collection behavior.

The Windows process families include service hosts, WMI providers, COM surrogates, task hosts, console hosts, search workers, service children and user-launched applications. The build metadata distinguishes 19041, 20348, 22621 and 17763 families across hosts. I found no same-host executable hash drift or cross-host same-hash/different-version conflict in the examined process-creation records.

This coherence is evidence of realistic construction or real collection; its completeness is not evidence for synthetic origin.

### Logon and session lifecycle

The Windows Security streams include network, service, interactive, remote-interactive, new-credentials and unlock types. WS-AJOHNSON has a Type 2 session followed later by a Type 7 authentication using the existing logon identifier. A naive comparison against every later 4624 would incorrectly flag earlier processes as preceding authentication. I excluded such cases because unlocks do not establish a new process-owning session lifetime.

For example, WS-MCHEN records a lock at 17:24:03.8775948Z and unlock at 17:33:56.1597296Z for LogonId `0x6c29844`, SessionId `5`; that identifier already owns earlier desktop activity. Pre-window sessions and post-window survivors were also allowed.

The main reservation is the server service-authentication volume described above. DC-01 has 155 Type 5 logons but 148 total 4688 creations, much of the latter consisting of WMI, COM and task hosts. MAIL-FIN has 66 Type 5 logons and 77 creations. This does not prove a missing companion: service authentication can occur within existing shared processes, and the System channel is outside the visible collection. The relative frequency and balanced built-in-account mix justify only a weak texture concern. Repeated well-known LUIDs `0x3e4`, `0x3e5` and `0x3e7` are not themselves invalid reuse.

### Linux authentication, commands and maintenance

DB-PROD's SSH example above has transport-related connection text before authentication and PAM opening, followed by a realistic session duration. A failed `svc_mgmt` attempt at 16:28:23.504203Z is followed by preauthentication closure at 16:28:26.091226Z rather than a successful user session. Where an eCAR SSH/RDP login and matching endpoint transport tuple were both visible, the matched transport did not begin after the login.

Sudo activity is also coordinated. APP-INT's Aisha Johnson shell PID `3374833`, process object `3ce60fc5-3516-4e8c-b5ea-f0df08a87277`, parents sudo invocations whose syslog records consistently use `TTY=pts/1`; changing working directories alone is not an inconsistency. Across examined sudo parent-shell groups, I did not find the same visible shell randomly switching sudo TTYs.

The repeated sysstat jobs are not a synthetic tell: approximately 36 executions in six hours with ten-minute scheduling are consistent with cron configuration. Cron-to-shell-to-`debian-sa1` process relationships accompany the CRON messages. DHCP renewals on WS-LNGUYEN provide another positive example: a bound message at 13:01:19.570445Z advertises renewal in 1,886 seconds, and the next request appears at 13:32:45.944110Z, approximately that interval later.

### macOS process, policy and document behavior

The ES records declare message `version=11`; I treated those records separately from Unified Log and normalized eCAR. On MAC-MROSS-01, launchd forks PID `25527` at 13:07:32.811343Z. That lifetime execs `xpcproxy` and Terminal; Terminal then forks PID `25528`, which execs `/usr/bin/login`, and login forks the shell PID `25529`. On MAC-MROSS-02, the corresponding visible chain includes iTerm2, iTermServer, login, ShellLauncher and zsh. These are materially different terminal models rather than one generic shell tree.

File identities remain stable in the examined ES snapshots: I found no same-device/inode size mutation or unexplained path collision, and no cdhash associated with conflicting paths within either host's stream. Identical software on the two Macs can legitimately share cdhashes while having different filesystem identities.

MAC-MROSS-01 Unified Log at 15:42:09.009673Z records `ASP: Security policy would not allow process: 42008, /Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`. I found no successful ES exec or child/effect sequence attributed to that rejected image. A policy message must not be equated with a successful child process merely because unrelated activity follows it. Similarly, the inventory plist's creation and deletion are distinct facts; plist deletion alone does not prove an unload or demand an immediate process exit.

The material behavioral reservation is MAC-MROSS-02's binary-document reading pattern. The seven `cat` reads span more than five hours and multiple shared-volume locations. Native exec observations corroborate the commands: for example, ES PID `17627` execs `cat` with the XLSX path at 16:05:48.676562Z, and eCAR reports the associated read at 16:05:57.353Z. A Word process is separately visible on this host, so these raw shell reads are not simply labels for Word opening its documents. Shell inspection, scripts or redirected output could explain them; the records do not show file contents or complete shell syntax. I therefore treat this as a recurring behavioral texture, not an impossible file access or a proven user-intent contradiction.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS eCAR FILE plus ES exec | Seven binary-document `cat` reads on MAC-MROSS-02, 13:37–18:45 UTC | Main upward influence: repeated generic shell reads are an unusual representation of business-document activity; still operationally possible. |
| weak_signal | Windows Security 4624 | DC-01: 155 Type 5 successes; MAIL-FIN: 66 in six hours | Small upward influence: frequent, similarly balanced built-in-account authentications; shared service hosting and collection scope limit the inference. |

No hard contradiction is included. Positive process, hash and session evidence offsets the behavioral concerns, leaving the score near the uncertain midpoint rather than in the confidently synthetic range.

## Realism Score by Category

- **Field format accuracy:** 9 — XML/JSON parse cleanly; identifiers, hashes, process fields and distinct macOS source shapes are coherent in the checked records.
- **Temporal patterns:** 8 — Visible process boundaries, SSH sequencing, cron scheduling and a checked DHCP renewal are credible; service-authentication frequency deserves scrutiny.
- **Cross-source correlation:** 9 — All visible Sysmon creations match Security creation identity fields; checked eCAR ownership and remote transport ordering are coherent.
- **Behavioral realism:** 6 — Host-specific tools and administration are convincing, but seven shell reads of binary business documents are conspicuously generic.
- **Environmental consistency:** 8 — Platform distinctions and server/desktop behavior are mostly credible; server service-authentication volumes remain unexplained rather than contradictory.

## Recommendations

- If this were synthetic, base shared-document access on the actual intended application or script behavior. The seven MAC-MROSS-02 binary-document reads should use document viewers, meaningful extraction tools or explicit shell-processing workflows when those match the intended activity; preserve `cat` where a raw read is actually intended.
- If this were synthetic, derive server Type 5 authentication frequency from specific service starts, credential operations and shared-host behavior. Review DC-01's 155 and MAIL-FIN's 66 successes against that underlying activity instead of emitting an independent generic authentication stream. The current logs alone do not establish that these volumes are wrong.
- Preserve the observed separation between process lifetime and exec image, the stable file/hash identities, and the existing session/transport ordering. No change is warranted merely to make source matching less complete or to force every lifecycle boundary inside this six-hour slice.
