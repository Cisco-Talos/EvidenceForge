# Blind Host/EDR Forensics Assessment — Loop 79

## Verdict

**Synthetic**

- **Verdict Confidence:** 82% (moderately high)
- **Synthetic-Confidence Score:** 78/100 (higher means more synthetic)
- **Scope:** Host and endpoint evidence in the specified `data` directory only. Review treats the logs as a six-hour slice; absent initiators/endings outside the window are not defects.

## Executive Summary

The host telemetry is internally coherent in the relationships that can be checked. Windows Security and Sysmon process/session lifecycles mostly preserve forward ordering; eCAR process and session identifiers generally have matching starts and ends, with no observed within-slice reverse lifecycle pairs. Linux shell history timestamps land inside the observed syslog interval, and macOS Endpoint Security sequence/time ordering is monotonic. Cross-source timestamp alignment is not counted as an artificiality signal.

The synthetic verdict rests mainly on distribution texture: ten Linux hosts each emit exactly 36 `sysstat` cron records in a six-hour interval, at a precisely repeated ten-minute cadence with very small subsecond jitter. The same cadence begins at either minute :05 or :06 on every host and runs to :55 or :56. This is plausible as configured scheduled work, but its identical six-hour count and near-identical timing shape across a varied fleet looks templated. The highly normalized and regular endpoint evidence also contributes modestly. I found no decisive host-side causal impossibility.

## Categorized Evidence

### `hard_contradiction`

- **None found.** No observed process termination preceded its corresponding creation; no paired session logout preceded login; no clear parent/child or timestamp contradiction was strong enough to establish impossibility within the six-hour boundary.

### `contract_gap`

- **No high-confidence lifecycle contract failure found.** Windows Sysmon Event IDs 1/5 and Security 4624/4634 pairs that were both visible had forward ordering. eCAR `PROCESS` and `USER_SESSION` entries likewise had no reversed pairs.
- Some starts and stops lack an in-slice counterpart. This is expected at a bounded window edge and can also reflect source coverage; it is not treated as a defect.
- macOS Unified Log coverage is very sparse (3 rows on `MAC-MROSS-01`, 2 on `MAC-MROSS-02`) relative to the 128/182 Endpoint Security rows and hundreds of eCAR records per host. Without a stated collection contract, this is a coverage caveat rather than a required-companion failure.

### `distribution_texture`

- **Strongest synthetic signal:** all ten Linux `syslog.log` hosts have exactly 36 `sysstat`/`debian-sa1` cron entries. Each host repeats the job every ten minutes for the sampled interval, with entries landing around `:05` or `:06` plus roughly 0.1–0.3 seconds. Examples include `APP-INT-01` (13:05:00.196 through 18:55:00.264), `FILE-LNX-01` (13:06:00.237 through 18:56:00.222), and `WEB-EXT-01` (13:06:00.255 through 18:56:00.137). A ten-minute sysstat schedule is individually plausible; the exact same count and near-identical timing texture on every sampled Linux host is the fleet-level tell.
- Windows event volume varies substantially by role: the DCs have thousands of Security/Sysmon rows, while workstations have hundreds; server-specific file auditing appears on `FILE-SRV-01`. This heterogeneity argues against a simplistic uniform-volume generator and is a positive realism signal.
- eCAR process create/terminate counts are close across most hosts, and session lifecycle records are usually paired when both endpoints fall inside the slice. This regular pairing is not itself a contradiction, but contributes slight synthetic texture when viewed across the entire fleet.

### `schema_or_format`

- Windows XML is parseable event XML with source-specific providers, channels, Event IDs, and host names. Sysmon and Security streams carry plausible fields for their event types; no broad malformed-format issue was observed.
- eCAR is line-delimited JSON with stable event fields (`timestamp_ms`, `object`, `action`, IDs, and properties). Linux history files use timestamped bash/zsh-history forms; macOS Endpoint Security and Unified Log are NDJSON.
- No material schema/format defect found in this review.

### `environment_or_collection_plausibility`

- Windows domain controllers have dense network, Kerberos, logon, and process telemetry; the file server has SMB/share auditing; user workstations have lower event counts. Linux hosts show service, sudo, SSH, cron, and in one case SMB audit activity. The broad host-role distribution is credible.
- The two macOS Endpoint Security streams contain only event types 9, 11, and 15 (exec/fork/exit-shaped activity), with event times and `global_seq_num` values monotonically increasing. This is plausible filtered endpoint collection, though the narrow event-type mix is less convincing as an unfiltered stream.
- `DC-01` Security log has Event ID 1102 at `2026-11-02T18:41:38.6607175Z` with `EventRecordID=1`. This explains the single record-ID inversion/reset and is consistent with a log-clear boundary, not an independent timestamp contradiction.

### `weak_signal`

- Unified Log has only 2–3 records per Mac host, separated by hours. That may indicate filtered collection or sparse capture; the dataset provides no contract that makes this a failure.
- Several endpoints show more process starts than in-window terminations, or the reverse. Given the bounded time slice and pre-window/post-window activity, this is weak evidence only.

## Detailed Analysis

### Windows Security and Sysmon

The Windows XML reviewed spans roughly 13:00–19:00 UTC on 2026-11-02. DC Security streams contain about 6,026–6,780 events and Sysmon streams about 3,674–4,541. The DC event mix is weighted toward Filtering Platform connections (5156), Kerberos (4768/4769), successful logons (4624), logoffs (4634), and process creation/termination (4688/4689). Workstation and mail-server volumes are lower, broadly a plausible role effect. `FILE-SRV-01` includes SMB access/share and object-access records (5140/5145/4656/4658/4663), which fit its endpoint role.

Across the Sysmon hosts, Event ID 1 process starts and Event ID 5 terminations have only a small number of unmatched IDs in the slice. Every matching `ProcessGuid` pair examined was ordered start-before-end. Security logon/logoff ID pairs were likewise forward ordered. This is strong positive lifecycle evidence; unmatched rows are not penalized at the window boundary.

`DC-01` has one Security EventRecordID order inversion, explained by Event ID 1102 at 18:41:38.660 with record ID 1. The reset interpretation is materially more plausible than treating it as a synthetic ordering failure.

### eCAR process and session trees

Per-host eCAR streams are line-delimited and use stable `objectID` values to link process/session lifecycle records. Across the fleet, process create/terminate counts are generally close (for example, `APP-INT-01`: 159/167; `FILE-LNX-01`: 224/225; `MAC-MROSS-01`: 41/40). I checked paired process IDs for reverse ordering and found none. Session IDs were also forward ordered wherever both login and logout were present. Logins without logouts and the converse were retained as window/coverage cases.

Windows eCAR activity includes process, module, registry, thread, file, network-flow, and session objects; Linux activity includes shell/process/session/file/flow classes. Their host-specific mix is more credible than a fleet-wide fixed event count. The eCAR observations broadly agree with the native host-log roles. Per task instruction, cross-source correlation by itself is not considered evidence of synthetic generation.

### Linux syslog and shell history

There are 4,111 syslog rows across the eleven Linux syslog hosts, spanning routine service/system messages, sudo, SSH, PAM/logind session events, cron and SMB audit activity. Timestamped bash histories on relevant hosts fall within the same review window and contain a mixture of identity/host checks, package/service diagnostics, database checks, shell exploration, and file-transfer or administrative commands. No impossible session ordering was identified from the visible excerpts.

The recurring `sysstat` cadence is the main texture concern. Ten hosts each produce 36 executions over the same six-hour window, every ten minutes, at virtually identical minute phases and very small subsecond offsets. Such a timer can exist in a real fleet, so this is not a hard contradiction. Fleet-wide exactness at this scale is nevertheless the clearest indication that this host slice was generated or normalized from a common schedule template.

### macOS Endpoint Security and Unified Log

`MAC-MROSS-01` has 128 Endpoint Security rows and `MAC-MROSS-02` has 182. Their `global_seq_num` and event times increase monotonically (ranges 0–128 and 13–194, respectively). The sampled types are limited to 9/11/15, which resemble exec/fork/exit lifecycle coverage. eCAR has 566 and 887 rows for the corresponding hosts, with process create/terminate records mostly paired and no reversed pair observed.

Unified Log contributes only three rows on the first Mac and two on the second. That is too little to assess broad process-tree consistency or normal background-log texture. I do not elevate its sparsity to a contract gap without a declared collection profile.

## Realism Scores

Scores are 1 (poor) to 5 (strong). They describe the reviewed host/EDR slice, not the full dataset.

| Dimension | Score | Rationale |
|---|---:|---|
| Process lifecycle and ordering | 4/5 | Matching process starts/ends and sessions are forward ordered; slice-edge unmatched records are expected. |
| Cross-source host coherence | 4/5 | Native Windows/Linux sources and eCAR show plausible role-specific, temporally coherent activity. |
| OS/source formatting | 4/5 | Multiple native-shaped formats and plausible host-specific schemas; no major parse defect. |
| Distribution and timing texture | 2/5 | Identical 36-entry, ten-minute sysstat cadence across all ten Linux hosts is conspicuously regular. |
| Coverage/collection plausibility | 3/5 | Windows/Linux source breadth is good; macOS Unified Log is sparse and ES event types are narrow, with no explicit collection contract. |
| **Overall host/EDR realism** | **3/5** | Mostly coherent evidence, reduced by repeated fleet-wide timing texture and limited macOS log breadth. |

## Recommendations

1. Vary whether sysstat runs on each Linux host, its schedule phase, and collection completeness; preserve realistic cron schedules where configured, but avoid identical six-hour counts and jitter shapes fleet-wide.
2. Retain the strong process/session lifecycle behavior and role-specific Windows Security/Sysmon and SMB audit mix.
3. If broad macOS collection is intended, add a more representative Unified Log sample and a wider Endpoint Security event mix; if it is intentionally filtered, document that profile so sparse rows are interpretable.
4. Keep window-edge lifecycle truncation as a supported condition in any future quality checks; the reviewed unmatched starts/stops do not establish faults.
