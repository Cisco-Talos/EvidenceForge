# Loop 83 — typed Linux pipeline process ownership

Loop 83 completed generation, evaluation, and four fresh blind reviews on a neutral, data-only copy. The authoritative bundle contains 148,787 records. Automated evaluation is **96.2810 PASS** (parseability 100.00, plausibility 96.86, causality 95.03, timing 91.54), down 0.28 from loop82 and above the assessment guardrail. The final fixed-seed output is byte-identical to the reviewed copy.

## Findings and actions

| Priority | Finding | Classification | Status |
|---|---|---|---|
| P2 | WEB-EXT-01 typed `bash -c 'echo … | base64 -d | bash'` lacked executable pipeline stage records and attributed callback FLOW to Apache | `sibling_defect` / `adapter_to_family_model` | Fixed for typed storyline paths; root now resolves to canonical `base64` and nested `bash` process children and the reverse-shell FLOW uses the final Bash PID. |
| P2 | Parent Bash terminates before its still-running final pipeline child | `contract_gap` | Verified residual lifecycle defect; remains the first pipeline-family follow-up for loop84. The authored foreground pipeline should keep the outer shell alive through child completion. |
| P1 candidate | 142 close same-account/client/source-port Security 4769→4768 pairs across both DCs | `sibling_defect` / suspected Kerberos ordering contract | Detection's claim was confirmed in the rendered XML: 62 pairs on DC-01 and 80 on DC-02, generally within 100 ms. The sample order places 4769 ahead of a matching 4768. Trace causal expansion, Windows Security timing, and Kerberos/DC bundle ownership in loop84 before changing an emitter. |
| explained | Near-complete internal multi-port scan of 10.10.2.0/24 observed at core and DMZ sensors | `false_positive_or_unproven` | The scenario explicitly authors `nmap -sn 10.10.2.0/24` and `nmap -Pn -sT -p 22,80,443,445,3306 10.10.2.0/24` on WEB-EXT-01. Do not vary it solely from this blind-review finding. |
| weak | Similar six-hour file windows and narrow 4688↔Sysmon 1 offsets | `false_positive_or_unproven` | Plausible bounded collection and a shared timing path remain; no change selected. |

## Fix contract and implementation

The owning path is the canonical process execution action and its shared Linux pipeline parser/timing planner; `typed_handlers.process` adapts typed storyline commands into that family. The invariant is that explicit, bounded shell pipelines create executable child identities under the authored shell, preserve unrelated RNG, direct later network work to the actual effect-owning child, and keep child/parent lifecycle compatible with dependent activity.

Added typed-process pipeline expansion using `_linux_command_process_groups_from_shell` and `plan_linux_pipeline_stage_times`, mapped the cataloged Linux `base64` executable through `system_processes.yaml`, preserved the shared storyline RNG around child rendering, and extended the final child's process finalizer through the planned parent close. Added behavior-manifest revision 497 (`preserve-typed-linux-pipeline-process-stages`). The review probe confirms root PID 2702831 creates `/usr/bin/base64` PID 2702832 and nested `/bin/bash` PID 2702833; callback FLOW at 14:20:21.349Z is owned by PID 2702833, which terminates at 14:20:35.700Z.

The process-parent extension did not enforce full shell waiting: the outer PID 2702831 terminates at 14:20:24.165Z, before child PID 2702833. The loop is therefore a **partial family fix**; loop84 must first establish how the shared process lifecycle owner can extend the foreground parent through a dependent child's transport and close. Baseline Bash-history/catalog paths continue to use the shared pipeline resolver; ordinary single-process events remain unexpanded.

## Blind panel

Standalone synthetic-confidence scores are Threat Hunter **53**, Detection Engineer **76**, Network Forensics **68**, and Host/EDR Forensics **36** (mean **58.25**, spread **40**). The split (two Synthetic, two Inconclusive) and spread triggered deliberation. The facilitated final mean is **62.50** (two Synthetic, two Inconclusive). All reviewers found source formats and sampled cross-source pivots broadly coherent. Detection identified the Kerberos reversal; Network identified the explicitly authored scan; Threat Hunter and Host/EDR emphasized bounded-window and timestamp texture without hard contradictions.

The panel's strongest unverified architectural target is the repeated Kerberos event ordering. Loop84 will inspect the family owner and verify exchange pairing before implementing a timing/order fix. Do not infer that the full dataset must have boot-to-shutdown telemetry or treat complete source joins as synthetic.

## Validation

- Focused typed-pipeline tests: **2 passed**.
- Existing Bash pipeline and stage tests: **23 passed** in the earlier focused family run.
- Ruff check and format checks on changed Python/test files: passed.
- `scripts/check_generation_behavior.py`: current at revision 497.
- Scenario validation: no schema errors; existing scenario advisories remain.
- Human-readable and JSON evaluation both completed; JSON saved as `eval_results.json`.
- A/B comparison: not run.

Artifacts: `pipeline-lifecycle-probe.json`, `family-contract.md`, four blind reports, deliberation, and evaluation output.
