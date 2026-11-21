# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 79
**Synthetic-Confidence Score:** 36

## Executive Summary

The data supports practical threat hunting across Windows, Linux, macOS, network sensors, and a forward proxy, with mostly coherent operational relationships. I found suspicious activity that can be followed through credentials, persistence, collection, and transfer, but did not establish an impossible visible lifecycle or a decisive source-native contradiction. Two distribution observations warrant scrutiny, but both have plausible production explanations and are insufficient to determine origin.

## Evidence For Synthetic

- [weak_signal] Cross-sensor timestamp differences have an unusually narrow distribution: for 5,277 five-tuples occurring exactly once in both `zeek-core/conn.json` and `zeek-dmz/conn.json`, core timestamps are consistently later by 109.821–118.613 ms, with mean 114.275 ms and standard deviation 1.109 ms. This could reflect a fixed-offset timing model, but stable sensor clock skew also explains it; matching coverage itself is not evidence of synthesis.
- [weak_signal] Windows process-creation vocabulary is concentrated: nine exact command lines account for 471 of 901 Sysmon Event 1 records, including 81 `WmiPrvSE.exe -secured -Embedding`, 78 `taskhostw.exe`, 67 `taskhostw.exe /Run`, and three `dllhost.exe /Processid:{...}` variants totaling 110 records. This is compatible with a small process pool, but these are legitimate repetitive Windows background commands, and filtering or quiet workstations could produce the same result. I assign this observation little weight.

## Evidence For Real

- Transport precedes authentication in the examined RDP pivot. `zeek-core/conn.json` records `10.10.1.99:33758 → 10.10.1.35:3389` at 16:01:18.944417 UTC, successful state `SF`; `WS-AJOHNSON-01.../windows_event_security.xml` records Type 10 logon for `aisha.johnson` at 16:01:25.7743120, with matching remote port and logon ID `0x26db42e`.
- The database collection/transfer sequence has usable endpoint and receiver pivots. DB root authentication from `10.10.2.30:44407` precedes a root shell, `mysqldump`, `gzip`, and `scp`. The reverse transfer `10.10.4.10:38904 → 10.10.2.30:22` has a successful Zeek transport, matching APP SSH authentication, and receiver file creation at `/tmp/.cache/rpt_0318.sql.gz`.
- Suspicious credential access has appropriate local relationships: on WS-AJOHNSON, PID 5916 runs `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` at 16:45:04, under High integrity in Sysmon. The same process identity later opens LSASS with `0x1FFFFF`, creates a remote thread, and terminates at 16:45:32. This is actionable telemetry, rather than merely a suspicious command without associated effects.
- The Linux diagnostics upload is represented as a multipart request, rather than a generic outbound connection: the curl command, archive read, proxy POST, Zeek request body, MIME types, and uploaded filename agree on the operation.
- The network background contains meaningful variety. Across 22,613 Zeek connections there are successful sessions, resets, rejections, unanswered SYNs, partial sessions, and midstream observations. Examples include core counts of 9,607 `SF`, 1,583 `S0`, 447 `OTH`, 157 `RSTO`, and 95 `RSTR`; this is not a wholly successful traffic population.
- macOS telemetry distinguishes fork, exec, and exit. In the examined download sequence, downloading a script and subsequently executing it are separate observations, with zsh history and endpoint process state supporting the distinction.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. It contains 113 files, about 80.5 MB, and endpoint directories for 23 hosts: ten Windows, eleven Linux endpoints including a Linux laptop, and two Macs. The visible eCAR window is 2026-11-02 13:00:01.267–18:59:45.590 UTC. The internal address space includes client `10.10.1.x`, infrastructure `10.10.2.x`, DMZ `10.10.3.x`, and database `10.10.4.x` segments.

Available records include 36,628 eCAR rows, Windows Security/Sysmon XML, 4,061 Linux syslog lines, shell histories, 317 macOS Endpoint Security rows, five Unified Log rows, three Zeek sensor directories, 25,002 ASA lines, 154 IDS alerts, 4,519 proxy rows, and 733 web access rows. I parsed endpoint event populations and XML, checked process identity relationships, inspected suspicious command lines and shell histories, and pivoted selected activities through network and receiver evidence. Counts are observations of this supplied slice, not estimates of complete organizational telemetry.

### Windows access, credential access, and persistence

The external-origin RDP observation on WS-AJOHNSON uses address `10.10.1.99`, with the receiving host `10.10.1.35`. The successful transport at 16:01:18.944417 has duration 64.204630 seconds and precedes the Type 10 logon at 16:01:25.7743120. Later process observations under the resulting logon ID are not intrinsically impossible after the transport ends: RDP disconnect and Windows logoff are distinct events, and a disconnected session may retain processes.

At 16:20:24.605 in eCAR, PowerShell PID 5840 starts under `aisha.johnson`, followed by `net group "Domain Admins" /domain`, `net user /domain`, `whoami /all`, and `net view /domain`. At 16:45:04.439 in Sysmon, PID 5916 starts as a child of PID 5840. Its High integrity level makes privileged LSASS access materially more plausible than an unelevated token would. eCAR shows access to LSASS PID 4292 at 16:45:07.734 and remote-thread creation at 16:45:07.763, followed by termination at 16:45:32.357. The maliciousness of the command is not itself an authenticity clue.

DC-01 supplies persistence and account-management evidence. At 17:15:01.901 in Sysmon, WMI-hosted activity starts a SYSTEM `cmd.exe` that creates `svc_dirsync` through a `net.exe` child. At 17:19:40, `sc.exe create DeviceSyncSvc` specifies a LocalSystem automatic service; at 17:19:45, `schtasks.exe` registers the named maintenance task. At 17:29:17.449, `DeviceSyncSvc.exe` starts under `services.exe`. The Security population includes account creation/deletion, group modification, service installation, and task creation events. I do not infer missing execution or failed privilege boundaries solely from absent records outside this selected scope.

### Linux collection and receiver-side verification

DB-PROD syslog shows `Accepted password for root from 10.10.2.30 port 44407` at 18:15:04.892667, followed by PAM session opening at 18:15:04.974862. eCAR then shows shell PID 1418098 at 18:15:07.216, `mysqldump --single-transaction ehr patients insurance_claims` at 18:15:12.810, SQL file creation at 18:15:14.471, gzip at 18:15:25.672, compressed-file creation at 18:15:29.619, and scp at 18:15:35.951. Root shell history preserves the original redirection into `/tmp/rpt_0318.sql`, while the process argv omits shell redirection, a sensible distinction.

The scp flow is observed by core at 18:15:38.898410 and database Zeek at 18:15:38.969302. The core record has duration 17.897851 seconds and 3,413,767 originator bytes. APP syslog records the incoming tuple at 18:15:44.314827, public-key acceptance at 18:15:45.458565, and PAM session opening at 18:15:45.565936. APP eCAR records `/tmp/.cache/rpt_0318.sql.gz` creation at 18:15:57.563. Small differences among host/sensor event times are compatible with independent observation clocks and delivery delays; they do not establish impossible ordering.

The initial root login's tuple is visible in both source and destination eCAR and DB syslog, although I did not find it in the supplied Zeek connection files. I treat that as an observation gap, not an authenticity defect: complete network collection is not established merely because other connections are visible.

### Proxy upload and macOS execution distinctions

WS-LNGUYEN history records tar creation of `/tmp/mhs-support-48217.tar.gz`, then a curl multipart upload with JSON metadata and gzip diagnostics to `/api/v1/cases/MHS-48217/attachments`. In `zeek-core/http.json`, UID `C4SOlCQ5kANxQ0iQSM` at 16:32:00.433422 carries request body length 1,573,258, filename `mhs-support-48217.tar.gz`, and `application/json` plus `application/gzip` originator MIME types. Proxy line 2658 reports the same POST, HTTP 200, and `cs_bytes=1573700`. Wire/request overhead explains why that value exceeds the HTTP body length. DMZ shows both client-to-proxy and proxy-to-server observations, with the latter using origin-form URI.

MAC-MROSS-01 history records the connector-check script download around 13:48:41. Endpoint telemetry separately shows curl execution and connection, then `/bin/bash .../connector-check.sh --check-config` at 13:49:09.687. I do not equate the initial download with execution or infer persistence merely from a script path. Native ES populations contain fork/exec/exit events, while eCAR additionally represents normalized process state; those are different evidence formats and need not share identical event shapes.

### Broader consistency checks and limitations

Across the eCAR files, I compared visible actor process references against visible process creation and termination records. With a two-second allowance for source observation differences, I found no actor operation preceding its visible creation or following its visible termination. This is a bounded check of exported process identities, not proof that every possible process/session relationship is valid.

I also checked all Zeek connection rows for payload/IP-byte accounting below a conservative minimum of 20 header bytes per observed packet, and for TCP `SF` records with fewer than two packets on either side; those checks returned no contradictions. Sysmon hash fields using named hash algorithms had the expected textual lengths in the examined XML population.

The narrow intersensor offset and concentrated Windows background command vocabulary are the only repeatable authenticity concerns I could substantiate here, and neither excludes production data. Therefore the score remains in the mostly realistic band, while the origin verdict remains inconclusive.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek core/DMZ timestamps | 5,277 uniquely matched five-tuples | Narrow 114.275 ms mean offset could arise from modeled timing; stable real clock skew remains a strong alternative. Small increase only. |
| weak_signal | Windows Sysmon process creation | Nine exact commands comprise 471/901 Event 1 records | Potential bounded command vocabulary; ordinary repetitive service processes make this weak. Small increase only. |

No demonstrated hard contradiction, required-companion failure, or verified native-schema defect is included in the score.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source formats and checked fields are plausible; unfamiliar native details were not treated as errors.
- **Temporal patterns:** 8 — Examined access and transfer ordering works; narrow sensor-offset variability warrants limited scrutiny.
- **Cross-source correlation:** 9 — Concrete RDP, SSH, export, receiver, and multipart-upload pivots work with plausible observation differences.
- **Behavioral realism:** 8 — Privileges, argv, shell redirection, and transfer direction are credible; Windows background command vocabulary is concentrated.
- **Environmental consistency:** 9 — Mixed operating systems, segmented network roles, and proxy traversal are coherent within the observed slice.

## Recommendations

- If this were synthetic, validate the Windows background process frequency profile against a comparable collection policy: the observed 52.3% concentration in nine exact commands is the specific distribution to test before expanding any command vocabulary.
- If this were synthetic, validate the intended sensor clock model against the measured cross-sensor offset distribution. Preserve stable offsets when appropriate; introduce clock drift or variable timing only when supported by the modeled collectors, rather than adding arbitrary noise.
- No lifecycle repair is justified by the examined pivots. Additional improvements should follow a demonstrated log-visible defect rather than presumed missing telemetry, domain naming, or how easy the intrusion is to describe.
