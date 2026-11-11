# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 30

## Executive Summary

The inspected evidence is mostly production-like, with technically coherent SSH and process-identity pivots and a plausible mixture of routine endpoint and network activity. A bounded review of 18 representative records and aggregate summaries found no demonstrated impossible ordering, invalid identity relationship, or required-companion gap; the principal weak suspicion is a uniform fleet-wide sysstat command pattern, which also has a straightforward operational explanation.

## Evidence For Synthetic

- [weak_signal] Across all 2,683 eCAR `PROCESS/CREATE` records, exactly 360 use `/bin/sh -c 'command -v debian-sa1 > /dev/null && debian-sa1 1 1'` and another 360 use `debian-sa1 1 1`: 36 of each on each of ten hosts. The hosts span mail, web, proxy, logging, file, application, workstation and laptop naming roles. This establishes common background texture rather than a contradiction. Shared Debian packaging and a ten-minute sysstat schedule could fully explain it; scheduled-task regularity itself is not a synthetic defect. I give this only slight weight, not the weight of a demonstrated distribution artifact.
- [weak_signal] The two Mac command aggregates share repeated small inventory command families (`id`, `sw_vers`, `ps aux`, `find ... '*.pdf'`) in the same six-hour collection. For example, the `find` command occurs twice on MAC-MROSS-01 and three times on MAC-MROSS-02. The common user and visible endpoint-inventory naming make this explainable. This is a limited vocabulary observation, not evidence of impossible activity or proof of templating.

## Evidence For Real

- The exact SSH tuple `10.10.1.41:63450 → 10.10.1.42:22` matches source eCAR, core Zeek and target eCAR session evidence, in the technically appropriate order. The connection lasts about 590.5 seconds and records a completed `SF` transport rather than a failed placeholder.
- A separate identity pivot from a native Endpoint Security exec notification to normalized eCAR preserves PID 51725, parent PID 42207, UID 501, audit session 100002 and the exec transition from `/bin/zsh` to `/usr/bin/ssh`. The normalized record follows the native observation by about 1.074 seconds, which is compatible with collection latency.
- Routine evidence is substantial and varied: 39,151 eCAR records across 23 endpoint directories, 23,644 Zeek connection records across sensors, 4,463 Linux syslog lines, 4,316 proxy-access lines and 25,085 ASA lines. Those quantities alone neither prove authenticity nor imply unrealistic coverage.
- The sampled Linux records include a UFW block of inbound TCP/3389 and a denied sudo command. These provide ordinary operational friction without needing to infer whether they belong to an intrusion.
- The Windows sample contains a source-native Sysmon process-termination shape, including provider/channel, event ID 5, process GUID, PID, image and user, with a plausible difference between precise SystemTime and millisecond UtcTime. No pre-window creator is required to explain that early-window termination.

## Detailed Analysis

### Scope and limitations

I inspected only the assigned data directory and briefing. The review includes 18 unique representative records, with duplicated command output counted once, and aggregate scans for counts, command frequencies and time ranges. Samples covered Mac eCAR, Mac Endpoint Security, shell history, Linux syslog, core Zeek connection records, one Windows Sysmon event and one ASA message. Detailed conclusions are strongest for the Mac SSH/process pivots; this is not an exhaustive Windows, TLS, native macOS schema or attack-chain audit.

The endpoint eCAR collection spans 2026-11-02 13:00:00.756Z through 18:59:50.485Z. The core Zeek connection timestamps similarly span approximately 13:00 through 18:59:44Z. Paths and records support Windows, Linux and Mac endpoint collections plus core, DMZ and database network observations. They do not establish that all sources collect all event classes. In particular, only exec/fork/exit event numbers occur in the supplied Mac ES files; I do not demand native file or socket notifications from that limited source.

Aggregate eCAR mix is 28,678 FLOW/CONNECT, 2,683 PROCESS/CREATE, 2,541 PROCESS/TERMINATE, 2,228 MODULE/LOAD, 1,007 USER_SESSION/LOGIN and 532 USER_SESSION/LOGOUT, with smaller file, registry, service and remote-thread populations. The login/logout and process create/terminate counts are not required to balance in a slice collection; I did not treat their differences as defects. The mix offers many usable routine pivots, but a six-hour count alone cannot establish the correct daily workload for an unfamiliar organization.

### Exact cross-source pivot 1: SSH transport and remote authentication

The source `MAC-MROSS-01.meridianhcs.local/ecar.json` contains exec object `fe3cd3c2-784a-4a83-8fe9-ebcace00c39a`, PID 51725, principal `maya.ross`, command `/usr/bin/ssh maya.ross@MAC-MROSS-02.meridianhcs.local`, at epoch milliseconds `1793629499622` (14:24:59.622Z).

`zeek-core/conn.json` UID `C0iAZFQ8y0tA6AcQ2S` begins at `1793629508.357404` (14:25:08.357404Z), with `10.10.1.41:63450 → 10.10.1.42:22`, TCP, SSH, duration `590.530608`, `SF`, history `ShADadfF`, 49,699 originator bytes and 112,176 responder bytes.

The source eCAR FLOW at `1793629509799` (14:25:09.799Z) preserves that exact tuple and associates it with the same process UUID/PID and command. The target `MAC-MROSS-02.meridianhcs.local/ecar.json` records USER_SESSION/LOGIN at `1793629517384` (14:25:17.384Z), principal `maya.ross`, source `10.10.1.41:63450`, outcome `success`, session type `ssh`, logon ID `0x138a3100`. Transport is visible about nine seconds before target login and source process execution precedes both. This is a useful, technically coherent hunting pivot. I make no claim about authorization, password versus key authentication, or benign versus malicious intent from these records alone.

### Exact cross-source pivot 2: native exec and normalized process identity

`MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` has an exec-shaped record at `2026-11-02T14:24:58.548043000Z`, event type 9, message version 11. Its current process is PID 51725, parent 42207, `/bin/zsh`, audit UID/effective UID 501, audit session 100002, PID version 51. The exec target remains PID 51725, changes image to `/usr/bin/ssh`, increments PID version to 52 and supplies argv for the exact destination host above. Process-group and POSIX session IDs remain 42206.

The eCAR process record at 14:24:59.622Z preserves that PID, parent, principal, group/session and before/after PID versions, and represents exec as MODIFY on the same object. Its `previous_execution_id` ends `:exec:0` and new execution ID ends `:exec:1`. These are internally compatible representations of image replacement. The approximately 1.074-second timestamp difference does not reverse any observed dependency. This pivot is distinct from the network/session join, although it uses the same initiating process to retain exact identity.

### Bounded operational texture checks

The two sampled Linux syslog records are on WEB-EXT-01: at 13:00:20.665947Z a kernel UFW message blocks source `185.220.88.13` to local `10.10.3.10:3389`; at 13:00:24.147714Z sudo rejects `lina.nguyen` running `/usr/bin/journalctl -u apache2 -n 20`. Their occurrence is technically possible on a Linux web host. A blocked Windows service port is neither evidence of Windows on that host nor evidence that a remote session succeeded.

The first sampled core Zeek records describe UDP DNS to internal addresses, with `Dd` history, one packet in each direction and byte counts compatible with UDP/IP overhead. The sampled ASA message is an inbound UDP build from DMZ `10.10.3.20:49120` to inside `10.10.2.10:53`. It supports ordinary cross-segment name-service activity; I did not silently join it to a different DNS tuple.

The sampled Windows record is WS-AJOHNSON-01 event 5 at 13:00:22.0699245Z, terminating `C:\Windows\System32\OpenSSH\ssh.exe`, PID 5116, user `MERIDIANHCS\aisha.johnson`, GUID `{fd907e59-80e4-6ae8-f202-00002f6cddc7}`. Because collection starts at 13:00, an earlier creator may be outside the slice. I did not label that absence an orphan process.

Mac file-create samples on both hosts name `/Library/LaunchDaemons/com.meridianhcs.endpoint-inventory.plist` and root-owned `/bin/sh` actors. Those records establish file creation only. I did not infer registration, launch, execution, persistence success or a policy decision from them. A separate native fork record for MAC-MROSS-01 PID 43313 shows a root `/bin/sh` parent and child; its existence does not enlarge the ES source into a native file-auditing collection.

### Distribution interpretation

The fleet sysstat pattern is reproducible by filtering eCAR PROCESS/CREATE on the two command strings above and grouping by hostname. On the ten matching hosts, the 35 consecutive shell-task gaps per host range from 599,421 to 600,455 milliseconds across the collection. A ten-minute cron job should be regular; independent jitter of hundreds of milliseconds and equal counts in an aligned six-hour window are plausible. There is no basis here for demanding randomized cron counts or missing executions. The identical package footprint across ten differently named host roles remains a weak environmental question, not a verified defect.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
| --- | --- | --- | --- |
| weak_signal | Normalized eCAR process background | 720 of 2,683 creates are the paired sysstat shell/child commands, 36 pairs on each of ten hosts | Slight suspicion of reused background texture; ordinary shared packaging/scheduling is a strong alternative explanation |
| weak_signal | Mac eCAR command vocabulary | Two Mac hosts, repeated small inventory command families | Slight suspicion only; same user and inventory activity make repetition explainable |

No hard contradiction, demonstrated contract gap or source-native schema defect was established in this review. The score of 30 reflects mostly realistic observed evidence with small unresolved texture concerns, not certainty that the provenance is real.

## Realism Score by Category

- **Field format accuracy:** 8 — Sampled source shapes and identifiers are plausible; full native schema validation was outside the bounded review.
- **Temporal patterns:** 8 — Exact SSH/exec dependencies are coherent, and regular sysstat timing has an ordinary scheduled-task explanation.
- **Cross-source correlation:** 9 — Two exact pivots preserve tuple or process identity and valid ordering; broader coverage was not exhaustively audited.
- **Behavioral realism:** 8 — Remote administration and routine noise technically fit; the small shared inventory vocabulary is a weak reservation.
- **Environmental consistency:** 8 — Mixed endpoint roles and network segments are plausible, with a fleet-uniform sysstat package footprint left unresolved.

## Recommendations

- If this were synthetic, retain the demonstrated exec identity and transport-before-auth relationships when extending the collection; they make pivots operationally credible.
- If this were synthetic, ensure the ten-host sysstat footprint follows each host's installed package and actual scheduler configuration. Keep legitimate periodicity rather than adding arbitrary jitter or missing events solely to look messy.
- If this were synthetic, ensure recurring Mac inventory commands are owned by the displayed user/session or management task and reflect that task's real scope. The inspected records do not justify adding attack mistakes, unrelated noise, or extra native event families.
