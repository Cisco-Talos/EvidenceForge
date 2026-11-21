# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 44

## Executive Summary

The dataset supports credible threat hunting across Windows, Linux, macOS, network sensors, and an explicit proxy, with useful process, identity, transport, and file pivots. Repeated command choices for opening binary documents and their associated timing give parts of the Mac activity a templated texture, but I did not establish a hard contradiction sufficient to distinguish a generated exercise from a deliberately scoped production collection. My score reflects those bounded concerns, not the completeness or compactness of the suspicious activity.

## Evidence For Synthetic

- [distribution_texture] `MAC-MROSS-02.meridianhcs.local/ecar.json` attributes seven reads of PDF, DOCX, or XLSX files to `/bin/cat`, across several shares and folders: lines 67, 357, 430, 435, 517, 536, and 544. Examples include `/Volumes/ClinicalResearch/Team/2026/project-plan.pdf` at 13:37:29.989 UTC and `/Volumes/Shared/Reference/onboarding.docx` at 17:12:32.289. These commands can execute, but repeatedly treating binary business documents as terminal text is an unusual user-workload distribution. A scanner or deliberate file inspection could explain it; this is a moderate behavioral-texture concern, not an impossible action.
- [distribution_texture] In the same host's native `macos_endpoint_security.ndjson`, those seven `cat` executions last approximately 29.761, 21.625, 13.133, 13.988, 16.024, 10.624, and 19.433 seconds. By comparison, visible local `pwd`, `ps`, `id`, and `uname` commands generally finish in fractions of a second. Network storage and terminal output can account for longer durations, but the repeated tens-of-seconds treatment across unrelated binary-document reads reinforces the preceding workload concern. These are related observations, not two independent strong indicators.
- [weak_signal] The paired Mac histories repeatedly return to a narrow set of inventory and document-discovery commands: `id`, `uname -a`, `sw_vers -productVersion`, `ps aux`, `df -h`, `du -sh .../Documents`, and `find .../Documents -maxdepth 2 -type f -name '*.pdf'`. For example, native process evidence contains the latter command three times on Mac 02 and once on Mac 01, including execution inside an SSH session. This could reflect a real operator or support workflow and carries little weight alone.

## Evidence For Real

- The available source mix and volumes support actual investigation rather than leaving suspicious processes isolated: 37,911 normalized eCAR rows, 17,484 Windows Security events, 11,489 Sysmon events, and 23,088 Zeek connection records across three sensors. These are record counts; the much larger XML line counts were not mistaken for event counts.
- The Mac download is distinguishable from execution. On Mac 01, native ES line 39 executes Homebrew curl at 14:00:45.212308 UTC, line 42 executes `/bin/bash .../connector-check.sh --check-config` at 14:01:04.079625, and line 57 later executes the script with `--check-network`. A shell-history entry or downloaded file alone was not used to claim execution.
- Mac-to-Mac SSH transport precedes authentication in both directions, with stable tuples and differing authentication methods. The Mac 01 to Mac 02 session uses `10.10.1.41:62896 -> 10.10.1.42:22`; the reverse session uses `10.10.1.42:53362 -> 10.10.1.41:22`.
- Windows remote execution has technically useful supporting evidence: on DC 01, a network logon by `aisha.johnson` is followed by `PSEXESVC.exe` placement, service creation, service process execution under SYSTEM, and its child command. This supports privilege transition and attribution rather than merely associating neighboring timestamps.
- Zeek connection states are varied. The core sensor includes 9,917 `SF`, 1,629 `S0`, 443 `OTH`, 166 `RSTO`, 102 `RSTR`, and 40 `REJ` records, with additional partial states. Across all three connection files I found no record whose application byte count exceeded its corresponding IP byte count.
- Exact normalized process-identity checks across all 23 endpoint files found no actor event more than 10 ms before its visible process creation or more than 10 ms after its visible termination. Native Mac process identities were also stable for the observed `(pid, pidversion)` pairs, and no process had a visible start time later than its observing ES record.

## Detailed Analysis

### Scope and method

I examined only the assigned data and briefing. There are 117 files covering 23 endpoint host directories, three Zeek sensors, perimeter/core alert sources, a firewall, proxy access, shell histories, and web access. Endpoint evidence spans 2026-11-02 13:00:01.151 through 18:59:56.312 UTC. The endpoint data contains 38 distinct principal strings, including humans, service identities, machine accounts, and built-in principals; these are not 38 unique human users.

The visible addressing separates workstation traffic in `10.10.1.*`, infrastructure in `10.10.2.*`, DMZ/proxy activity in `10.10.3.*`, and database activity at `10.10.4.10`. Names and traffic suggest domain controllers, file servers, a database, an integration application, mail services, web publishing, monitoring, and mixed workstation platforms. I inferred these roles from the records rather than treating hostname prefixes as proof of an operating system.

I parsed all eCAR files for event-family distributions and visible process dependencies, parsed Windows XML for event counts and representative source-native fields, and examined Mac ES, Unified Log, shell history, Linux syslog, Zeek connections, HTTP, and SMB for selected investigative pivots. The native Mac ES coverage consists of fork, exec, and exit notifications: 48/55/47 on Mac 01 and 56/65/55 on Mac 02. I did not demand file or authorization notifications from that selected process-focused export.

### Download and execution across platforms

On Mac 01, native ES establishes curl execution at 14:00:45.212308. The normalized file creation at 14:00:48.098 names `/Users/maya.ross/Downloads/connector-check.sh`, and `zeek-core/http.json` line 297 shows the same workstation opening an explicit-proxy CONNECT to `support.valeworks-health.net:443` with source port 55746. This is a tunnel observation; it does not expose the encrypted request body or prove a response payload's content.

The subsequent native bash execution at 14:01:04.079625 is distinct from the download, and the later `--check-network` execution occurs at 14:37:50.497846. Neighboring `cat /etc/resolv.conf` and `cat /etc/hosts` commands plausibly fit network troubleshooting. Comparable connector downloads appear in Windows and Linux process evidence, but shared naming alone does not establish the same binary or maliciousness.

On Linux workstation WS-LNGUYEN-01, a later support upload has an unusually good semantic pivot. Its process command at 16:32:45.131 explicitly sends a JSON metadata form and a gzip diagnostics form through the proxy. `zeek-core/http.json` line 1567 records the corresponding HTTP POST with a 1,573,258-byte request, MIME types `application/json` and `application/gzip`, and filename `mhs-support-48217.tar.gz`. The DMZ sensor separately records client-to-proxy and proxy-to-server views, using an absolute URI on the explicit-proxy request and a relative URI on the outbound request. That is technically plausible visibility, rather than evidence that every upload is hostile.

### Mac shared-storage actions and workload texture

Mac 01 performs a visible read/modify sequence against the integration manifest. Native ES executes `cat /Volumes/ClinicalResearch/Integration/Manifests/pipeline-manifest.json` at 15:11:12.531077 and `tee` against the same path at 15:12:56.921758. `zeek-core/smb_files.json` lines 98–99 contain an open/read for the manifest from `10.10.1.41` to `10.10.2.21`, and lines 102–103 contain the later open/write. These support a file-access pivot; they do not reveal the modification's contents or prove its intended effect.

The binary-document command distribution on Mac 02 is less convincing. The seven PDF/DOCX/XLSX reads listed above all use `cat`, rather than varying among application opens, indexing processes, previews, or text extraction. Native ES independently confirms the executable choices, so this is not merely a normalization label. For example, ES lines 32–33 show the PDF command running from 13:37:11.223221 for 29.760887 seconds; lines 118–119 show `cat .../project-plan.docx` running from 17:10:43.520711 for 13.133286 seconds.

The SMB rows confirm real file-transfer semantics in the provided evidence: the PDF read is 986,890 bytes, and the XLSX read is 949,435 bytes. Sending roughly a megabyte of binary data to a terminal or waiting on network storage can be slow, so these durations are not hard contradictions. My concern is the repeated workload pattern across unrelated documents and folders, not any single command's legality.

### Remote-session lifecycle

For Mac 01 to Mac 02, `zeek-core/conn.json` line 2256 starts the SSH flow at 14:24:27.752520, UID `CqTSExGpbbbpnpB4Yv`, duration 631.786365 seconds, state `SF`. Mac 02 native ES starts the launchd-owned server chain at 14:24:32.693936. Its Unified Log accepts keyboard-interactive/PAM authentication at 14:24:38.748958, and native ES starts the authenticated shell at 14:24:38.914909. Commands in that session follow afterward.

The reverse connection begins at 16:02:00.857717, UID `C4ZfopiJXvU28JX8bA`, state `SF`, duration 958.189197 seconds. Mac 01's native server chain begins at 16:02:05.895451; public-key authentication is accepted at 16:02:06.270473; the shell exec follows at 16:02:06.440808. The use of public key in one direction and PAM in the other is not contradictory.

Native and normalized timestamps are not interchangeable here. Some normalized process rows appear after the native authentication message, but the native fork/exec records show the server already running beforehand. Calling that an impossible authentication-before-process relationship would disregard the supplied native evidence. Likewise, endpoint process exit and normalized session logout need not be bit-identical to a network sensor's close timestamp.

The Mac 01 Unified Log message at 15:42:09.009673 says security policy “would not allow” MeetingAssist. I did not infer successful execution, child effects, or an installed persistence mechanism from that message. There is no need to turn this standalone policy observation into an authenticity defect.

### Windows intrusion pivots and Linux staging

On DC 01, normalized eCAR line 3479 records `aisha.johnson` authenticating from `10.10.1.35:51613` at 17:00:10.895 with logon ID `0x555493f`. File placement at 17:00:11.826 and service creation at 17:00:12.093 precede SYSTEM execution of `C:\Windows\PSEXESVC.exe` at 17:00:14.076. PID 5428 then executes `cmd.exe /c whoami && hostname` as a child of service PID 5424 at 17:00:14.773. These are sensible service-based remote-execution relationships. I did not score their completeness or ease of narration as synthetic evidence.

On DB-PROD-01, Linux syslog records root SSH authentication from `10.10.2.30:39678` at 18:15:03.165682 and a session opening immediately afterward. Normalized evidence then shows mysqldump, gzip, and SCP execution. APP-INT-01 separately records a root SSH session from the database host and receipt of `/tmp/.cache/rpt_0318.sql.gz`, followed by `smbclient` uploading that path to the ClinicalResearch share under the supplied `svc_mhsync` remote credentials. The local root identity and SMB service-account identity need not be the same namespace or principal.

One detail deserves care without becoming a scored contradiction: the normalized mysqldump command omits shell redirection while a FILE/CREATE row is attributed to it. Process argv normally omits shell redirection, and normalization may attribute the first observed output to its writer. These logs do not establish that a literal mysqldump invocation independently chose its output filename. Without a documented stronger create/open attribution contract, I cannot call this impossible.

### Signal, noise, and limits

The normalized dataset contains 27,650 FLOW/CONNECT rows, 2,637 process creations, 2,462 process terminations, 1,010 login rows, and 548 logout rows. These are observations across hosts and can include both ends of an activity; they are not counts of unique network actions. Domain controllers and the proxy carry markedly larger volumes than individual workstations, which fits their apparent roles.

The different creation/termination and login/logout totals are not defects by themselves in a six-hour slice. Some initiators and closures are outside the window, failed attempts need no successful-session closure, and service identities can have different logging semantics. Nor do I penalize the five selected Mac Unified Log rows merely for being sparse.

All 4,129 checked Sysmon hash components had valid hexadecimal contents and expected lengths. This checks syntax, not correspondence to real vendor binaries. My exact-ID eCAR lifecycle pass found no process-dependent actor rows outside the visible process lifetime beyond a 10 ms comparison allowance, and native ES did not show mutable executable/start-time values for the same `(pid, pidversion)` observation identity. These negative findings materially limit the strength of a synthetic verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Mac ES and eCAR file/process activity | Seven binary-document `cat` reads on Mac 02 across several shares | Moderate concern about how ordinary document access is represented; technically possible and potentially operator-driven. |
| distribution_texture | Mac native process timing | Those same seven reads last roughly 10.6–29.8 seconds | Reinforces the first concern; network storage and terminal output remain plausible explanations, so this was not double-counted as independent strong evidence. |
| weak_signal | Mac shell histories and ES | Recurrent inventory/document-discovery command vocabulary on two hosts | Small contribution only; consistent with legitimate support or administration. |

No demonstrated hard contradiction or generator-identity leak was used in this assessment.

## Realism Score by Category

- **Field format accuracy:** 9 — Examined XML, JSON, process identities, tuples, and hash strings are well formed; native Mac and normalized evidence were interpreted separately.
- **Temporal patterns:** 8 — Investigated remote-session and execution ordering works; repeated longer binary-file reads create a bounded timing concern.
- **Cross-source correlation:** 9 — Proxy, SSH, SMB, service-execution, and Linux staging pivots are usable without demonstrated impossible relationships.
- **Behavioral realism:** 6 — The repeated `cat` treatment of binary office/PDF documents and narrow Mac inventory vocabulary weaken ordinary-workload realism.
- **Environmental consistency:** 8 — Visible roles and source volumes largely fit the observed traffic; collection boundaries prevent stronger conclusions about unobserved facilities.

## Recommendations

- If this were synthetic, diversify the visible mechanisms for ordinary Mac document access. The seven `cat` reads should represent a specific terminal-inspection workflow if intentional; otherwise, use application, preview, or extraction processes appropriate to the actual action being modeled, preserving their file and network relationships.
- If this were synthetic, tie the duration of those document reads to file size, storage response, and terminal/output behavior rather than assigning a generic human document-interaction duration to the process. Preserve genuine network delays where they are supported.
- If this were synthetic, broaden repeated inventory/document-discovery commands where the visible workload is intended to represent general user activity. Retain repetition where an actual support or administrative procedure explains it; repetition alone is not a defect.
