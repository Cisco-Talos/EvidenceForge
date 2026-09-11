# Iteration Test Blind Assessment — Loop 76

## Outcome

Loop 76 reviewed the post-loop-75 targeted repair bundle. The automated evaluation scored
96.780584 PASS across 123,267 records. Blind synthetic-confidence scores were 74, 64, 74, and 84
(mean 74.00). All four reviewers returned Synthetic verdicts; the 20-point score spread did not
trigger deliberation.

The four repaired hard-contradiction families passed their rendered probes with zero violations.
No reviewer reported recurrence of process-owned activity after termination, post-date Zoom/Webex/
Postman metadata, Samba `opendir` on regular files, or compressed/inverted workstation lock cycles.

## Individual Expert Summaries

**Threat Hunter:** Synthetic, 82 verdict confidence, 74 synthetic-confidence. Cross-source attack
and lifecycle coherence were strong, with no established hard contradiction. Repeated Linux
hardware tuples, millisecond-quantized cron timestamps, thinned periodic jobs, and scanner-request
texture drove the verdict.

**Detection Engineer:** Synthetic, 76 verdict confidence, 64 synthetic-confidence. Process,
session, network, and firewall correlation held up well, and no post-termination actor references
were found. Selective Sysmon metadata gaps, pristine Windows base-build versions, one legacy 4698
shape, and missing `PE` analyzer declarations were the primary defects.

**Network Forensics:** Synthetic, 86 verdict confidence, 74 synthetic-confidence. DNS, TCP state,
proxy chains, TLS identities, and ASA accounting were coherent. A broad 1.200-second TLS duration
mode, nearly uniform tiny capture-loss injection, infrastructure-host user agents, and four missing
HTTP file references drove the score.

**Host/EDR Forensics:** Synthetic, 88 verdict confidence, 84 synthetic-confidence. The reviewer
found credible lock/unlock, RDP, SSH, process, and session lifecycles with no impossible timestamps.
Sparse Windows process populations, missing browser/Electron helper trees, bounded thread-ID
texture, homogeneous PE metadata, and fixed Linux resolver-event quotas remained strong tells.

## Targeted Repair Verification

- Process ownership: 13,478 process-attributed eCAR rows and 4,797 Zeek rows across 3,646 joined
  transports produced zero activity-after-termination violations.
- Software chronology: 24 Zoom Meetings, Cisco Webex, and Postman Sysmon rows matched the
  scenario-date-valid versions; all five future-release/product markers were absent.
- Samba semantics: all five successful `opendir` rows targeted directories; none matched the 14
  file names resolved in the storage manifest.
- Workstation state: all four 4800→Type 7→4801 cycles were ordered and matched by host/session;
  minimum visible lock dwell was 127.953321 seconds.
- Frozen review corpus: 108 files, 74 MiB, path-independent SHA-256
  `1b935cc51842d5f97cad8b1b16aed2708229eb3844bd80f5c60e89a1161c2075`.

## Score Movement

The initial blind mean moved from 74.25 in loop 75 to 74.00 in loop 76, effectively flat. The
roles moved differently: Threat Hunter +6, Detection +11, Network -8, and Host/EDR -10. The fixed
hard contradictions disappeared, especially from Host/EDR, but reviewers shifted their weight to
pre-existing population-wide timing, hardware, process-volume, and metadata texture. This is
deeper-issue surfacing plus reviewer variance, not a latest-fix regression.

## Prioritized Improvements

### P1 — Bind endpoint process populations and PE identity to installed software

**Reviewers:** Host/EDR and Detection. **Scope:** dataset-wide Windows fleet. **Leverage:** high.
Generate application-native browser/Electron child trees and file-specific serviced PE metadata,
including hashes for readable signed binaries. Own this in deployment/content identity plus the
process-family planner, with source observation applied coherently to sibling process rows.

### P1 — Replace shared network timing and loss textures with causal sensor behavior

**Reviewer:** Network. **Scope:** all Zeek sensors. **Leverage:** high. Derive TLS close timing from
protocol work rather than a common 1.200-second floor, and model capture loss from sensor-local
packet pressure and packet sizes rather than an almost uniform per-connection probability.

### P1 — Derive Linux background evidence from persistent host hardware and schedules

**Reviewers:** Threat Hunter and Host/EDR. **Scope:** most Linux/syslog hosts. **Leverage:** high.
Bind IRQ/interface/NUMA vocabulary, resolver state, and cron execution to host-specific hardware,
role, schedule, availability, and collection state instead of shared exact tuples or quotas.

### P1 — Scope client software and user agents by host role and inventory

**Reviewer:** Network. **Scope:** domain controllers and proxy. **Leverage:** medium-high. Prevent
competing endpoint/VPN client user agents from appearing on infrastructure hosts unless the same
software is installed and visible in their modeled inventory.

### P2 — Complete source-native analyzer and event-version contracts

**Reviewers:** Detection and Network. **Scope:** 15 PE rows, four HTTP file references, and one
scheduled-task event. **Leverage:** medium. Ensure every PE output is declared by its files analyzer
set, completed no-loss HTTP FUIDs resolve, and Windows event versions follow the modeled host build.

### P2 — Tighten isolated process-parent and scanner semantics

**Reviewers:** Host/EDR and Threat Hunter. **Scope:** isolated parentage plus one scan population.
**Leverage:** low-medium. Constrain interactive `runas.exe` parent selection to plausible shell
owners and use tool/version-specific ordered scanner corpora with stable test identifiers.

## Comparison with Quantitative Eval

The deterministic evaluator scored 96.780584: 99.999189 parseability, 96.895981 plausibility,
95.568523 causality, and 93.323508 timing. All hard acceptance gates passed. As in prior loops, the
automated evaluator did not penalize the main population-wide timing, inventory, hardware, and
metadata textures that drove blind scores.
