# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 99
**Synthetic-Confidence Score:** 99

## Executive Summary

The dataset contains two independent hard contradictions: impossible Linux PID-allocation sequences and Windows EDR module-load events placing mandatory startup DLLs hours after process creation. These are dataset-wide rather than isolated defects, despite exceptionally strong Windows/Sysmon/eCAR and SSH cross-source correlation. The evidence is confidently synthetic.

## Evidence For Synthetic

- `hard_contradiction` — Linux `PROCESS CREATE` records use interleaved PID streams on each host. On `PROXY-BO-01`, PID 233855 is created at 12:01:02, followed by newly forked PID 232295 at 12:01:54; higher PIDs then continue without a wrap. Seventy of 121 creates fall below the prior observed maximum.
- `hard_contradiction` — `WEB-BO-01` has the same defect: PID 749498 at 12:01:35 is followed by cron child PID 749092 at 12:03:00 and PID 749831 at 12:03:23. There are 26 adjacent reversals and 73 of 153 creates below the prior maximum.
- `hard_contradiction` — eCAR reports mandatory `ntdll.dll` loading long after process creation. Of 56 `ntdll.dll` loads tied to processes created inside the window, 52 occur more than ten minutes later and 31 more than one hour later.
- `distribution_texture` — Across Windows eCAR, 605 of 708 module loads tied to visible process starts occur over ten minutes later, and 397 occur over an hour later. The affected modules include `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, and other foundational libraries, indicating randomized placement across process lifetimes.
- `environment_or_collection_plausibility` — Sysmon Event 7 repeatedly places narrow third-party modules in unrelated generic processes: AnyConnect `vpnapi.dll` in `svchost.exe`, Defender `SenseCncProxy.dll` in `svchost.exe`/`taskhostw.exe`, and Dell SupportAssist `pcdrsysinfosoftware.p5x` in generic server processes.
- `weak_signal` — `kubectl.exe logs web-frontend-8c9a1 --tail=100` remains alive for approximately 4 hours 40 minutes without a visible Kubernetes API flow. This is not independently decisive, but compounds that process’s impossible late module-load lifecycle.

## Evidence For Real

- All 668 visible Sysmon Event 1 records have matching Security 4688 records with the same PID, executable, and command line, within approximately one second.
- Of 664 Windows eCAR process creates, 663 correlate exactly with Sysmon process creation; the unmatched record is consistent with a plausible source-local collection gap.
- The SSH session using source port 58093 correlates across Sysmon, Security 5156, eCAR, Zeek, target syslog, PAM, systemd-logind, and session closure with correct ordering.
- Windows process GUIDs, decimal/hex PID representations, SIDs, logon IDs, integrity levels, hashes, and version metadata are internally consistent.
- No eCAR process terminates before its create event, no known actor is used before creation or after termination, and no PID lifecycles visibly overlap.
- Repeated binaries have stable hashes for a given image/version both within and across hosts.
- Linux shell pipelines are decomposed credibly into parent and child processes, including `journalctl | tail`, `find | head`, and `grep | wc`, and align with the bash histories.

## Detailed Analysis

The clearest Linux contradiction appears in `PROXY-BO-01.northstar-branch.local/ecar.json`:

- Line 11, 12:01:02.360: cron creates `/bin/sh`, PID 233767.
- Line 12, 12:01:02.620: that shell creates `debian-sa1`, PID 233855.
- Line 18, 12:01:54.854: an existing interactive bash newly executes `nmcli`, but receives PID 232295.
- Line 30, 12:06:15.427: PackageKit starts as PID 234160.
- Line 70, 12:10:06.016: a newly forked SSH handler is assigned PID 233723. Target syslog independently records that PID receiving the connection at 12:10:03.573.
- Line 174, 12:23:50.052: `systemctl` receives PID 234458.
- Line 193, 12:25:57.530: a newly created `login` process receives PID 232545.

A Linux PID namespace allocates cyclically from a host-local cursor. A wrap cannot explain the data because the higher 233xxx/234xxx stream continues after lower 232xxx allocations. Ordinary SSH and cron children also do not use independent PID namespaces here: their parent PIDs and host identities place them in the same observed process tree.

`WEB-BO-01.northstar-branch.local/ecar.json` independently repeats the defect. `pkcon update` is created as PID 749498 at 12:01:35.990, a cron-launched shell is created as PID 749092 at 12:03:00.038, and a systemd-launched Java worker then receives PID 749831 at 12:03:23.659. A single wrap cannot produce that down-up sequence.

The Windows module chronology is equally decisive. In `WS-NKAPOOR-01.northstar-branch.local`:

- Sysmon Event 1 records `kubectl.exe` PID 6820 at 12:21:34.984.
- eCAR records its create at 12:21:35.537.
- eCAR records `ntdll.dll` loading at 13:13:24.372, 3,108.835 seconds later.
- It records `rpcrt4.dll` at 15:28:34.031.
- Sysmon Event 5 and eCAR terminate the same process at approximately 17:01:17–17:01:18.

`ntdll.dll` is mapped before a Windows process begins user-mode execution; it cannot first load 51 minutes after creation. Similar examples include `GoogleUpdater.exe` PID 6904 loading `ntdll.dll` 18,997.227 seconds after creation, and DC `taskhostw.exe` PID 7192 loading `kernel32.dll` at 17:20:38 after being created at 12:27:09, followed by `kernelbase.dll` at 17:42:44.

Delayed ingestion does not adequately explain this pattern. Process-create timestamps align across eCAR, Sysmon, and Security within roughly one second, while other eCAR module loads occur only 1 ms after creation. The extreme delays selectively affecting most module events therefore appear to be event-time scheduling rather than uniform collector latency.

The dataset nevertheless demonstrates strong correlation engineering. For the SSH session from `10.44.10.24:58093` to `10.44.20.30:22`:

- Sysmon creates `ssh.exe` PID 7000 at 12:09:48.778 and records its flow at 12:10:03.982.
- Security 5156 records the identical PID and tuple at 12:10:04.160.
- Zeek opens UID `CAE2dXWvnIepVFBIVm` at 12:10:03.447 with a 3,036.643-second `SF` connection.
- Proxy syslog records connection at 12:10:03.573, password acceptance at 12:10:05.801, PAM open at 12:10:05.900, logind session creation at 12:10:06.564, and PAM close at 13:00:48.697.

That correlation materially raises the realism score, but it cannot outweigh impossible kernel-level PID behavior and mandatory-module ordering.

## Synthetic Indicator Summary

| Category | Source | Scope | Impact |
|---|---|---:|---|
| `hard_contradiction` | Linux eCAR PID allocation | Both Linux hosts; 47 adjacent reversals | Decisive |
| `hard_contradiction` | eCAR mandatory DLL loads | 52/56 visible `ntdll.dll` loads delayed over 10 minutes | Decisive |
| `distribution_texture` | Windows eCAR module scheduling | 605/708 loads delayed over 10 minutes | High |
| `environment_or_collection_plausibility` | Sysmon Event 7 module ownership | Windows clients and servers | Moderate |
| `contract_gap` | `kubectl logs` lifecycle/flow | One process | Low |
| Realism counterweight | Process, logon, SSH correlation | Dataset-wide | Strong but non-exculpatory |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Windows, Sysmon, eCAR, and syslog fields are structurally convincing.
- **Temporal patterns:** 2/10 — PID allocation and foundational DLL timing contain impossible ordering.
- **Cross-source correlation:** 9/10 — Process and SSH identities, tuples, and timing correlate exceptionally well.
- **Behavioral realism:** 5/10 — Shell activity and lifecycles are plausible, but several process/module behaviors are not.
- **Environmental consistency:** 4/10 — Host roles and identities are coherent, but module ownership is repeatedly implausible.

## Recommendations

- Allocate Linux PIDs through one host-scoped cyclic allocator shared by baseline, SSH, interactive, cron, and service activity. Test that new processes do not move backward absent an explicitly modeled wrap.
- Emit `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, and imported runtime libraries at process initialization, before dependent activity. Keep collection delay separate from event time.
- Restrict dynamic modules to compatible owning processes and installed host software; specifically review AnyConnect, Defender Sensor, VMware, and Dell SupportAssist mappings.
- Give one-shot tools realistic durations. If `kubectl logs` is intentionally hung, emit the API connection, retries/timeouts, and termination outcome that explain it.
- Preserve the existing process, logon, and SSH cross-source correlation, which is the strongest aspect of the dataset.
