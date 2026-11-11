# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 60
**Synthetic-Confidence Score:** 25

## Executive Summary

The bounded sample is mostly consistent with production telemetry: a mixed fleet has credible service traffic, routine processes, and investigable suspicious activity whose observed network and authentication ordering works. I found no demonstrated source-native contradiction in the two exact pivots; the modest Real verdict reflects this sample, not proof of provenance or a comprehensive lifecycle audit.

## Evidence For Synthetic

- No substantiated synthetic indicator emerged from the 19 inspected representative records and supporting aggregates. The lower confidence reflects limited review breadth rather than a hidden defect claim.
- An initial distribution question was the 360 occurrences of `debian-sa1 1 1` among 2,683 eCAR PROCESS/CREATE records. Aggregate verification showed exactly 36 per host on ten Linux hosts, at approximately ten-minute intervals; this is compatible with a managed sysstat timer. It is therefore excluded from the synthetic score and indicator summary.

## Evidence For Real

- A middle-window PowerShell pivot agrees on host, exact command, PID 6356, parent PID 5896, principal, and logon ID `0xd934088` between WS-PPATEL-01 eCAR and Sysmon Event 1. The native process time precedes the normalized observation by about 136 milliseconds.
- A later-window SCP process on DB-PROD-01 has a matching outbound TCP tuple and two network-sensor observations; APP-INT-01 then records an SSH connection followed by successful public-key authentication on that same source port. The evidence permits the observed transfer instead of placing authentication before visible transport.
- Routine early-window observations include APP-INT-01 `rsyslogd -n` traffic to `10.10.2.40:514`, WEB-EXT-01 health checking, and browser-shaped web access. At 18:59:43, WEB-EXT-01 still shows a local `/health` curl check, providing late-window ordinary activity.
- Two macOS-native samples retain audit identity, PID version, parent/responsible attribution, executable signing metadata, and distinct fork versus exit payloads. These coexist with normalized eCAR rather than being treated as interchangeable source types.

## Detailed Analysis

### Scope and bounded method

I inspected only the assigned data directory and supplied briefing. Nineteen representative records were read in detail, spanning early, middle, and late activity, with two exact cross-source pivots. Broader reads were limited to source inventories, counts, timestamps, targeted predicates, and process-command frequency aggregates. This was not an exhaustive event or process-graph audit.

The directory has 29 top-level source/host folders: endpoint records, three Zeek sensor folders, two Snort folders, and a perimeter firewall folder. Across eCAR files, the observed window is 2026-11-02 13:00:00.756–18:59:50.485 UTC. Aggregate volumes include 39,151 eCAR records, 19,623 Windows Security XML events, 23,644 Zeek connection records across three sensors, 4,463 syslog lines, 4,316 proxy-access lines, 786 web-access lines, and 160 Snort alert lines. XML line counts were not treated as event counts. Sensor overlaps were not interpreted as unique connections. These volumes are adequate background for a small mixed enterprise slice and do not demonstrate implausible signal concentration.

### Exact pivot 1: middle-window encoded PowerShell

`WS-PPATEL-01.meridianhcs.local/ecar.json` contains PROCESS/CREATE at `1793631677960` (15:01:17.960 UTC), PID 6356, parent 5896, user `priya.patel`, logon ID `0xd934088`, image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, and an encoded PowerShell command beginning `RwBlAHQALQBDAGkAbQBJAG4AcwB0AGEAbgBjAGUAIABXAGkAbgAzADIAXwBTAGUAcgB2AGkAYwBl`.

`WS-PPATEL-01.meridianhcs.local/windows_event_sysmon.xml`, EventRecordID 739946, EventID 1, has `UtcTime=2026-11-02 15:01:17.824`, matching the complete encoded command, process/parent PIDs, image, `MERIDIANHCS\priya.patel`, and `LogonId=0xd934088`. Its ProcessGuid is `{398565f9-a5bd-6ae8-c002-00108de87a4c}`; eCAR uses objectID `12017a47-a5b0-42cc-9527-5e591c8511e5`. These different source identifiers are not assumed equal. The pivot rests on the combined exact process attributes and time, not GUID substitution. The command is a hunt lead, not proof of malicious execution effects.

### Exact pivot 2: late-window SCP and SSH

`DB-PROD-01.meridianhcs.local/ecar.json` records root's PID 1089180 creation at `1793643365383` (18:16:05.383 UTC), objectID `a689ee9c-c74d-4545-bcdd-00cca3c16a77`, running:

`scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`

Its FLOW at `1793643368968` references that exact actorID/PID and tuple `10.10.4.10:37862 → 10.10.2.30:22`. `zeek-db/conn.json` UID `CFUyTxkZcnCp5VrbXx` opens at `1793643368.431932`; `zeek-core/conn.json` UID `CKrloaHiL9PiHXUDkx` opens at `1793643368.360165`. Both report SSH, SF, about 18.83 seconds, 931,308 origin bytes and 29,855 response bytes. Distinct sensor UIDs are expected local identifiers.

`APP-INT-01.meridianhcs.local/syslog.log` records sshd PID 2984040, `Connection from 10.10.4.10 port 37862 on 10.10.2.30 port 22` at 18:16:13.796468Z, followed at 18:16:16.277719Z by `Accepted publickey for root from 10.10.4.10 port 37862 ssh2`. This is within the observed successful transport interval. A delayed server message relative to the sensor open is not impossible ordering. These records establish process/transport/authentication feasibility; I did not claim file receipt, SSH shutdown, or transfer integrity without inspecting those records.

### Background texture and platform limits

The two sysstat command variants each occur 360 times: the shell wrapper and its child are separate process creations, not 720 independent scheduled tasks. For `debian-sa1 1 1`, each of ten hosts contributes 36 executions. Host-local adjacent intervals range approximately 599.28–600.577 seconds, which fits periodic collection with small observation variation. Such a service timer should not be judged using expectations for irregular human activity.

The macOS samples were one native exit on MAC-MROSS-01 at 15:47:27.139380Z for `/usr/bin/ssh`, PID 58035, and one fork on MAC-MROSS-02 at 15:31:24.135933Z, parent `/bin/zsh` PID 19001 and child 42512. Neither demonstrates a denied execution followed by effects or another lifecycle contradiction. I did not independently verify every version-11 native field against vendor documentation and assign no native-schema defect based on unfamiliarity. Early-window terminations and logouts were not penalized for lacking pre-window initiators.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| None demonstrated | eCAR, Sysmon, Zeek, sshd, sampled macOS ES | 19 representative records; two exact pivots; supporting aggregates | No concrete defect raises the score into the mixed or likely-synthetic bands. The score remains 25 because this limited sample cannot establish indistinguishability. |

## Realism Score by Category

- **Field format accuracy:** 8 — Sampled native and normalized records are structurally credible; full vendor-schema verification was outside this bounded review.
- **Temporal patterns:** 8 — Two pivots have plausible observation offsets and transport-before-authentication ordering; ordinary activity spans the window.
- **Cross-source correlation:** 9 — Exact command/process and transport/authentication pivots agree without conflating source-local identifiers.
- **Behavioral realism:** 8 — Service forwarding, timers, health checking, process ancestry, and an SCP path are technically workable in the inspected evidence.
- **Environmental consistency:** 8 — Mixed endpoint and sensor sources support their observed activities; no role or collection-profile contradiction was demonstrated.

## Recommendations

No corrective change is supported by a demonstrated defect in this bounded sample. If this were synthetic, preserve the observed per-source identifier distinctions, realistic observation offsets, and timer-specific cadence; adding arbitrary retries or noise merely to obscure the suspicious commands would not remedy an evidenced issue. Further authenticity claims would require a separately authorized broader lifecycle sample rather than changes based on unverified missing companions.
