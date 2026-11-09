# Mac-heavy iteration-test — initial diagnostic assessment

The first standalone panel averages **79.25/100 synthetic confidence (likely synthetic;
lower is better)**. All four reviewers judged the dataset Synthetic. Deterministic
evaluation scores **96.30/100, PASS**, under the user-approved **partial-coverage
diagnostic policy**. This is a useful initial measurement, **not complete Mac process
coverage or native realism acceptance**.

## Scope and reproducibility

- Main authored scenario: `../../scenario.yaml`; it still requires complete Mac coverage.
- Assessed input: `../../diagnostic-scenario.yaml`. The user approved this diagnostic
  after the full workload exposed missing native SMB helper starts. Its only semantic
  difference from the main input is `macos_process_coverage: partial`; see
  `diagnostic-scope.json`.
- Seed 42; behavior revision 392; November 2, 2026, 13:00–19:00 UTC, with two-hour
  warmup. Scenario 2.0, exact packaged technology industry pack and original
  Windows/Linux workload are preserved. The epoch moved from March 18, 2024 to
  support macOS 27. All original authored source hashes still match `../../ORIGIN.json`.
- Added two macOS 27 arm64 workstations, 58 storyline entries / 103 typed events,
  including 65 process events. Apple Terminal and iTerm2, Finder apps, Chrome helpers,
  local commands, PTY/non-PTY SSH, Mac-to-Linux SSH, launch-job lifecycles and a policy
  refusal are represented. Original low baseline and enterprise_standard observation
  remain; no traffic, process family or requested source group was removed.
- Successful authoritative bundle:
  `/private/tmp/eforge-iteration-macos-loop1-njdnyda_/bundle-diagnostic-assessment-2`.
  Generation took 185.86 seconds. There are 118 data files / 82,523,104 bytes.
- One JSON eval completed in 13.73 seconds; `eval-report.txt` was rendered from that
  saved report without reevaluating. All 138,347 records pass the evaluator's schema
  and format constraints. It identifies 25 concrete sources across 12 requested groups.
- Four fresh reviewers received only hash-verified neutral copied `data/`, the entire
  shared briefing and their individual persona. They received no scenario, ground truth,
  manifests, eval scores, census, prior findings or code. The copy seal and report hashes
  are in `blind-copy-seal.json` and `panel-provenance.json`.
- This is a new benchmark series. Earlier iteration-test scores are a different input
  and epoch; they are not used as a before/after comparison. No A/B or realism repair
  loop ran. Findings below were not repaired before scoring.

No private/native capture, installed application inspection, live probe or collector
was used. `generation.log` was not opened. Raw synthetic bundles and CLI diagnostics
remain outside Git. Source changes and reports from this task are local and uncommitted;
no PR or merge is part of this assessment.

## Initial scores

Synthetic-confidence scores measure the reviewers' impression of synthetic character;
they are separate from confidence in their verdict and are not calibrated probabilities.

| Loop | Automated eval | Threat Hunter | Detection Engineer | Network Forensics | Host/EDR | Mean synthetic confidence | Interpretation | Deliberation | Five-score rolling mean |
|---|---:|---:|---:|---:|---:|---:|---|---|---:|
| 1 | 96.30 PASS* | 82 | 86 | 64 | 85 | **79.25** | likely synthetic | Not triggered | 79.25 (n=1) |

\* PASS applies to the partial diagnostic policy. The main scenario's complete native
coverage gate fails. A single loop establishes a baseline and supports no trend claim.

| Reviewer | Verdict | Verdict confidence | Synthetic confidence | Main contribution |
|---|---|---:|---:|---|
| Threat Hunter | Synthetic | 93 | 82 | Zero-byte file hashes and repeated Mac/Windows command timing |
| Detection Engineer | Synthetic | 94 | 86 | Mac PID-version chronology and executable timestamp texture |
| Network Forensics | Synthetic | 78 | 64 | Qualified TLS handshake/packet-budget mismatch |
| Host/EDR | Synthetic | 96 | 85 | Mac PID-version chronology and uniform shutdown timing |

Deliberation was not triggered: verdicts are unanimous, mean verdict confidence is 90.25,
and the synthetic-confidence spread is 22 points. No extra panel cycle was needed.

## Mac evidence and the outstanding completeness contract

| Host | ES forks | ES execs / canonical expected | Native known-result exits / canonical expected | ULF | zsh history |
|---|---:|---:|---:|---:|---:|
| MAC-MROSS-01 | 44 | 50 / 57 | 42 / 50 | 3 | 25 |
| MAC-MROSS-02 | 54 | 65 / 70 | 52 / 58 | 2 | 25 |
| Total | **98** | **115 / 127** | **94 / 108** | **5** | **50** |

The 307 ES rows contain fork, exec and known-result exit notifications. The complete
census identifies **12 aggregate mounted-SMB helper starts** outside the qualified native
publication path: seven on Mac 1 (`ls`, `tee`, `cat`) and five on Mac 2 (`cat`). These
are real producer gaps, not intentional collection loss. All 108 canonical exit
observations are accounted for, but 12 lack qualified executable/security metadata and
two have unknown outcomes. Those are different causes; none is replaced by invented success.

The SMB recipe currently carries credentials/executable-version facts while materializing
generic process state, rather than composing the native process-start publication contract.
Finishing that producer and the two unknown-result close cases remains an engineering
acceptance priority. The panel did not receive this census, and its scores do not silently
penalize the diagnostic's known coverage exception. Sparse ULF alone was not scored;
launchd ULF remains gated and this assessment admits no new template.

## Individual expert summaries

**Threat Hunter — 82.** The reviewer found a coherent export/compression/scp sequence,
useful proxy-byte accounting, correct Windows /netonly local identity and meaningful
native Mac exec/audit-session distinctions. One zero-byte SMB file carries non-empty
content digests, and arithmetic Mac command schedules plus repeated precise Windows SSH
launch delays provide independent timing evidence. The hash defect is one of 2,488 file
rows; enrichment and automation alternatives are explicitly acknowledged. See
[the full report](threat-hunter-report.md).

**Detection Engineer — 86.** Windows XML shapes, PID/GUID joins, logon boundaries, log-clear
provider handling and most protocol relationships were convincing. The decisive Mac
finding is five backward new fork/exec PID-version allocations despite advancing native
clocks and child birth times. All 228 distinct executable stat timestamp observations also
occupy the first microsecond of their seconds, and repeated command schedules support a
construction fingerprint. Undocumented identity remapping or timestamp sanitization are
qualified alternatives. See [the full report](detection-engineer-report.md).

**Network Forensics — 64.** The specialist found strong DNS, certificate, protocol UID/tuple,
file-byte and SSH ownership relationships. The main concern is 77 TLS 1.2 sessions with
four originator packets despite a full non-resumed handshake and responder-first close.
TCP Fast Open or transformed counters remain viable alternatives, so this is a qualified
contract gap, not a universal-impossibility claim. The Mac mobile user agent has negligible
weight because emulation is possible and the FLOW lacks a process owner. See
[the full report](network-forensics-report.md).

**Host/EDR — 85.** All 813 visible Sysmon process starts match Security 4688 image, command
and parent PID; tested Windows/Linux and normalized endpoint lifetimes are coherent. The
reviewer independently confirmed the five native Mac identity allocation reversals,
matched arithmetic schedules across 36 local commands, and exact 100 ms exit staircases
across eight and fifteen varied processes. Terminal/iTerm2, Finder/xpcproxy and SSH chains
retain substantial correct detail. See [the full report](host-forensics-report.md).

## Prioritized reported improvements

These are proposed next work, not changes made during the assessment. Priorities below
are the synthesis ranking; original reviewer labels are retained separately.

| Priority / order | Issue and category | Reviewer original ratings | Scope / leverage | Owning layer and concrete direction | Fix risk |
|---|---|---|---|---|---|
| P0 / 1 | Mac PID-version allocation chronology — `hard_contradiction` | Detection P1; Host P1 | Five reversals across two hosts / high | Canonical process identity and timeline planning: allocate fork/exec versions in host occurrence order and preserve actor/parent/responsible references. Sorting native output cannot repair versions already assigned to the wrong times. | High: shared durable identities and recovery |
| P0 / 2 | Zero-byte file with non-empty-content hashes — `hard_contradiction` | Threat P1 | One of 2,488 files / medium-high disbelief anchor | Canonical file/content/transfer facts: reconcile size, content version and hashes once; zero content needs empty-content digests or legitimately absent hashes. Preserve siblings and source byte scopes. | Medium |
| P1 / 3 | Mirrored arithmetic Mac command timing — `distribution_texture` | Threat P2; Detection P2; Host P2 | Six paired blocks, 36 commands / high | **Scenario authoring**: these intervals are explicit offsets in this new variant. Author task-specific independent interaction patterns, or visibly model intended automation; do not patch emitter timestamps. | Low |
| P1 / 4 | Executable stat fractions always below one microsecond — `distribution_texture` | Detection P2 | 228 distinct observations / medium-high | Installed-file metadata and timestamp modeling: correct units if erroneous, or choose a coherent declared precision/distribution. Do not add arbitrary emitter jitter to immutable file identities. | Medium |
| P2 / 5 | Qualified TLS handshake/packet-budget mismatch — `contract_gap` | Network P2 | 77 / 736 eligible TLS 1.2 observations / medium | Network/protocol facts: reconcile handshake flights, ACKs, packet counts and close direction. First resolve intended Fast Open/counter semantics; do not treat the current evidence as categorical proof. | Medium |
| P1 / 6 | Native logout exits at exact 100 ms spacing — `distribution_texture` | Host P2 | Eight and fifteen exits / medium | Canonical ordinary-close timing: retain child-before-parent dependencies, with process-specific completion timing; source delivery delay stays separate from native occurrence time. | Medium |
| P2 / 7 | Reused precise Windows shell-to-SSH delay — `distribution_texture` | Threat P2 | Four 4.460 s pairs; smaller sibling pairs / low-medium | Session/source-client timing owner: check whether a stable per-user/target delay is being reused across occurrences; keep explicit automation attributable when intended. | Medium |
| P4 / 8 | Mac proxy traffic mostly uses mobile UA — `weak_signal` | Network P4 | 641 / 707 proxy rows for one Mac / low | Application/network ownership: determine emulation versus a mismatched UA pool before changing behavior. No owning PID was visible on the cited FLOW, so this is not a proved desktop-browser contradiction. | Low if diagnosis; avoid speculative correction |

The separate **P0 engineering gate** is complete native SMB-helper start/exit coverage,
plus explicit resolution of the two unknown exit outcomes. It was measured by the census,
not assigned a blind-review priority. It remains first for the user's all-process contract.

Priority rationale: confirmed native identity and file-content contradictions come before
qualified packet-budget interpretations. Three independent reviewers saw the Mac schedule,
and its low-risk authoring owner is known, so it has unusually good score leverage. The
network specialist's qualified issue merits a bounded investigation, not another native
capture campaign or immediate renderer patch. Severity alone does not determine this order.

## Verification and alternatives

Root checks independently reproduce all five PID-version reversals and 228/228 narrow stat
fractions (`macos-metadata-verification.json`). The public Apple
[fork](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c#L923)
and [exec](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c#L6630)
implementations use the same incrementing identity-version counter. This is a semantics
reference, not an inspection of a private host or proof of an exact macOS build. Minute-scale
reversals with increasing mach time and newly born children do not fit ordinary export
reordering; undisclosed token remapping remains a theoretical data-transformation alternative.

The zero-byte file `FZgEgCqVzTxAGQgCiu` is reproduced at core files line 625 and SMB files
line 181. All three digests differ from standard empty-content values, with zero missing
and overflow bytes (`zero-file-verification.json`, `zero-file-scope.json`).
[Zeek's file metadata contract](https://docs.zeek.org/en/current/scripts/base/frameworks/files/main.zeek.html#type-Files::Info)
defines the relevant byte counters and content digests. External hash enrichment would
need distinct provenance; the row lists native hash analyzers.

The TLS selector independently reproduces 5 core and 72 DMZ cases
(`tls-budget-verification.json`). Its interpretation retains the specialist's Fast Open
and counter-transformation qualifications. Unmatched SMB connection UID
`CfwamgYPNpASbWX3cXo` is excluded from the scored findings: an unfinished/out-of-window
connection or export policy remains a valid explanation. Thin ULF coverage, missing
selected Sysmon families, out-of-window initiators, perfect correlations and narrative
linearity do not contribute to the scores.

## Quantitative evaluation versus the blind panel

| Pillar | Score |
|---|---:|
| Parseability | 100.00 |
| Plausibility | 94.61 |
| Causality | 96.84 |
| Timing | 92.18 |

The deterministic PASS measures syntax, supported field constraints, declared observation
contracts and broad correlation. It does not validate global kernel identity allocation
chronology, realistic filesystem fractional timestamp distributions, cryptographic
empty-content consistency, every TLS packet-flight budget or realistic logout spacing.
Those gaps explain why a 96.30 guardrail score coexists with a 79.25 blind synthetic score.

Subscores at or below 90 remain visible in `eval-summary.json`: distribution fit 78.79,
anomaly rate 78.00, system regularity 77.06, inferred pivot linkability 87.05 and attack-chain
timing 84.91. Several inferred chain/pivot penalties span independent benign Mac tasks or
explicit paired stages, so they are not automatically log authenticity defects. Temporal
integrity is 95.00 for this input; the original benchmark's historical failure was not
assumed to recur. No threshold, weight or intensity was tuned to improve these numbers.

## Recommended next sequence

1. Finish the native SMB helper publication contract and close-result gaps, retaining this
   unchanged complete-coverage benchmark as the acceptance test.
2. Repair host-wide PID-version chronology at the canonical identity/timeline owner, with
   interleaved terminal, GUI, SSH and job sibling tests and recovery checks.
3. Correct the new benchmark's mirrored explicit command schedules. Keep that authoring
   correction separate from engine realism changes.
4. Address the confirmed zero-file hash and native metadata/shutdown timing owners, then
   investigate the qualified TLS budget and repeated Windows SSH delays in bounded scope.
5. Regenerate and run another assessment only when requested. This initial round is complete.

Generation preflight exposed and repaired concrete storage-admission, SSH warmup timing,
file identity/publication and authored terminal-owner failures; an extra ground-truth label
introduced during those repairs was removed. The full history and failed attempts are
preserved in the worklog and loop JSON artifacts. Final focused validation: 401 routine
checks pass (one existing slow deselected), four targeted slow checks pass, the final
RDP-serialization regression passes, and Ruff/format/behavior/diff checks pass. This is
focused change validation, not a claim that the entire repository test suite ran.
