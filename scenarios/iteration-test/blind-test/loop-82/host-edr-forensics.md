# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 62
**Synthetic-Confidence Score:** 36

## Executive Summary

The host telemetry is mostly internally coherent: Windows Security process creation records align closely with Sysmon, Linux and Windows eCAR process trees have plausible ownership, and macOS Endpoint Security transitions agree with eCAR process histories. I found no hard source-native contradiction in the reviewed endpoint evidence; the available records support a realistic interpretation but do not establish provenance, so the verdict remains inconclusive.

## Evidence For Synthetic

- [weak_signal] The endpoint collection is unusually rich across Windows Security, Sysmon, eCAR, macOS Endpoint Security, and Linux syslog, with process and session activity often joining cleanly. This is only a weak signal: the observed joins are internally consistent, and collection completeness alone is not evidence of synthesis.

## Evidence For Real

- Windows process creation is strongly cross-correlated. On WS-EBROOKS-01, WS-MCHEN-01, WS-PPATEL-01, WS-SMARTINEZ-01, DC-01, and MAIL-FIN-01, Security 4688 and Sysmon Event 1 records match on every observed `(PID, image)` pair (58/58, 120/120, 69/69, 54/54, 169/169, and 102/102 respectively). WS-AJOHNSON-01 has 100 matching pairs out of 101 Sysmon starts; WS-DRAMIREZ-01 has 56 matches out of 58 Security starts. These small unmatched tails are compatible with source coverage differences.
- Process termination records also agree across sources. For example, WS-AJOHNSON-01 has 91 Security 4689 records and 94 Sysmon Event 5 records; the sample entries at 13:00:22 UTC identify the same `ssh.exe` PID 5116, user `aisha.johnson`, and time within a fraction of a second. The 13:01:17 UTC pair similarly agrees on PID 5124.
- macOS process transitions preserve executable and session context. On MAC-MROSS-01 at 13:07:54.825 UTC, Endpoint Security shows PID 42186, parent PID 1, and `/sbin/launchd`; within milliseconds it records the same PID executing as `/usr/libexec/xpcproxy`. eCAR represents the fork/exec and subsequent Terminal/login child transitions for that process, with matching PID, parent PID, paths, and user session. This is coherent with successive exec images in one process lifetime.
- Windows endpoint process trees include recognizable service and user-session relationships, such as `services.exe` parenting service processes and `explorer.exe` associated with named interactive users. Linux records show expected `sshd` → shell and `sudo` → command relationships, with user principals and process/session identifiers carried into eCAR.
- eCAR process lifecycles show varied durations rather than one fixed lifetime: paired Windows and Linux process records range from fractions of a second to hours. Visible start or termination records absent at a collection boundary are not treated as defects.

## Detailed Analysis

### Windows process and session evidence

I examined Security and Sysmon XML on the domain controllers, file server, mail server, and sampled workstations. XML namespaces were present and the records parsed as event records. Security Event 4688 and Sysmon Event 1 process IDs and image paths were highly consistent across hosts. Security 4689 and Sysmon Event 5 also agreed on visible process exits; the WS-AJOHNSON-01 `ssh.exe` examples at 13:00:22 and 13:01:17 UTC show matching user, PID, image, and near-identical timestamps. The few process-start count differences (for example, two additional Security 4688 records on WS-DRAMIREZ-01 and three on DC-02) are not impossible relationships and could reflect collection or event-family coverage.

Windows event families include logons/logoffs, process starts/exits, network filtering, DNS queries, and host-specific file access. Their volumes differ by role: DCs contain many Kerberos and filtering records, while the file server includes share and object-access events. Interactive workstation records include user processes and lock/unlock activity where present. I did not infer a defect from an absent event family.

### Linux and eCAR process ownership

Linux eCAR records show plausible service and user process trees: `/usr/sbin/sshd` parent records precede user shells, and `sudo` processes precede their privileged command children. Process create/terminate durations vary widely by host and process. PIDs in the millions are within the Linux PID range and are not, by themselves, an impossible field value. Some eCAR file-write entries name service executables in their contextual properties; I did not treat those labels alone as proof of a mismatch without a demonstrated source-native contradiction.

### macOS Endpoint Security and eCAR

The two Mac hosts expose Endpoint Security NDJSON plus eCAR and a small Unified Log export. Endpoint Security uses version 11 records with audit tokens, executable paths, parent tokens, and timestamps. At MAC-MROSS-01, PID 42186 begins as a fork from PID 1 running the inherited `/sbin/launchd` image, then executes `/usr/libexec/xpcproxy`; later records continue into Terminal, `login`, and `zsh`. eCAR shows the same PID and successive image transitions, then child process PIDs and parent links. I treated each `MODIFY`/exec image change as a transition in one process lifetime, not as an independent process, and did not interpret the action result field as an authorization decision. The small Unified Log volume limits conclusions about broader macOS coverage, but thin coverage alone is not a synthetic indicator.

### Window boundaries and joins

The visible endpoint records cover a bounded period. A process or session may have started before collection or continue after it; missing pre-window starts or post-window closings alone are not synthetic evidence. Conversely, complete PID/image joins across Security, Sysmon, and eCAR are not synthetic evidence by themselves. I scored only contradictions or distribution defects that could be demonstrated from the visible records and found none strong enough to decide provenance.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `weak_signal` | Endpoint/eCAR collection | Broad host coverage | Rich cross-source coverage can be consistent with a curated synthetic export, but it is also consistent with deliberate production collection. Clean joins alone are not diagnostic, so this contributes only a small amount. |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows XML and macOS Endpoint Security records have coherent source-native field shapes and values.
- **Temporal patterns:** 8 — Process lifetimes and event timings vary; visible cross-source pairs are close in time.
- **Cross-source correlation:** 9 — Windows process starts/exits and macOS process transitions correlate strongly across endpoint sources.
- **Behavioral realism:** 7 — Service, interactive, SSH, shell, and administrative process relationships are plausible in the visible host records.
- **Environmental consistency:** 7 — Host roles and platform-specific process paths are generally coherent; broader collection scope cannot be established from endpoint logs alone.

## Recommendations

If this were synthetic, the clearest improvement would be to preserve the already strong process identity and timing joins while making collection coverage differences explicit in the data itself, especially for the small number of Security/Sysmon start and exit count mismatches. No repair is warranted from the reviewed evidence alone.
