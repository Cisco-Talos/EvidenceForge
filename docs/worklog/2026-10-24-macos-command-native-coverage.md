# Mac command execution and native coverage follow-through

The user authorized fixing the findings in the latest `MacOS-test` review.
The reference bundle is generation `100c26d7cdba40b1be15c6d1cef183c4`; its
verified review copy and findings remain under `/private/tmp/eforge-macos-test-review-*`.
The original bundle and authored draft remain intact. Work is on
`codex/macos-workstation-support` after `e07bbe4a`.

## Acceptance scope

- Reproduce and repair Mac foreground command loss through the owning profile,
  scheduling and lifecycle layers. Preserve explicit long-running commands.
- Stop treating rejected process launches as successful execution. Catch legacy
  zero-PID successes in deterministic evaluation as well as new generation.
- Bind authored interactive Mac command history to the actual live shell and
  execution time, including SSH receivers; avoid history for noninteractive
  executions and unexecuted commands.
- Correct source collection and evaluation reporting for native Mac sources,
  optional shell histories and actual capabilities. Describe native event
  coverage separately from selecting or discovering a format.
- Expand native projection only through qualified canonical occurrences and
  complete metadata. Native ES exec/exit and Gatekeeper denial remain gated by
  the user's prior decision; no new capture is authorized. Ordinary process
  CREATE records must not be relabeled as native forks.
- Regenerate into a fresh temporary bundle and compare the concrete Mac process,
  history and native-source results. Keep a reproducible test and report for
  coverage that remains unavailable.

## Initial reference

Across the two Macs: 154 eCAR process creations, of which 12 are modeled forks;
12 matching native ES fork records; four Unified Log workspace-entry records;
25 zsh commands on MAC-01 and none on MAC-02. Ground truth falsely reports 34
zero-PID process requests emitted (nine storyline, 25 comparison red herrings).
The old deterministic evaluation passed at 95.066867 over 235,727 records.
That result does not establish broad native coverage.

## Implementation

The shared foreground owner now schedules authored Mac work against live and retained
child lifetimes in the exact shell session. A later baseline watermark cannot move an
earlier authored command to the end of that work. Initial local commands can wait for
the catalog-backed terminal chain. Explicit short utility templates cover id, sw_vers,
ifconfig, ps, dscl, pwd, ls, du, df and bounded find. Unknown invocations retain their
modeled release requirement; duration bounds remain synthetic, not calibrated captures.

The typed handler rejects nonpositive PID results before references, effects or success
bookkeeping, closes profiled utilities through their canonical finalizer, and submits
Mac history through the actual live shell. Forked commands submit history at the birth
anchor, before their image replacement. Evaluation accepts semantic quote equivalence
and eCAR exec modifications without accepting unrelated process modifications.

The installed catalog now identifies those ten native utilities without automatically
selecting them as persona noise. The independently corroborated zsh signer vocabulary
allows metadata-complete SSH shells to own real fork/exec chains in the existing process
bundle. The exact source journal commits canonical fork and exec plus the fork-only
native observation together. Native write failure recovery does not repeat State or
collector counters. New runtime artifacts, incomplete GUI metadata, unresolved shell
expansion and effect-bearing launches keep aggregate birth semantics. No aggregate
CREATE is renamed to manufacture a native fork. Native exec/exit stay unavailable.

Collection metadata now includes native formats and zsh. The informational evaluator
profile uses exact source deployment where available, reports native and history sources
as conditional, and separates process creations/forks/execs from endpoint FLOW volume.
The zsh schema recognizes its parser's duration_seconds. Source skill references were
updated and the ignored project skills regenerated through install-skills.

## Verification

The unchanged captured authored source was extracted to
`/private/tmp/eforge-macos-command-regression/scenario.yaml`. It has no packs or project
overlay dependencies. Validation passed with two existing informational pivot notes;
configuration validation passed all 99 files. Fresh outputs use separate directories,
with no overwrite or edits to the original scenario or bundle.

The first comparison repaired all 85 Mac process requests and increased history from
25 to 109 records, but exposed a later-baseline scheduling delay and utility binary
admission gap. These were repaired; a further full run found a canonical argv quoting
failure, now covered by the quoted-find regression. Failed/intermediate outputs remain
separate from the final comparison.

The old bundle now correctly fails the unchanged intent-reconciliation hard gate at
68.80733944954129 because of its invalid PID-0 success records. It is still manifest-verified;
this is an evaluation defect detection, not an integrity failure or a lowered threshold.
The original 95.066867 PASS must not be used as evidence that those commands executed.

The user reiterated on this turn that native capture remains deferred. No local native
capture, personal log inspection, collector permission change or gate-opening work was run.

The final lifecycle pass also removes the generic Windows/Linux story-duration
fallback from unknown Mac invocations: an unprofiled watch command remains alive
after deferred storyline terminations are flushed. Complete native row inventory
uses the known source-directory provenance, without adding a hostname to the native
payload or pretending its audit token identifies a host.

Validation: 2,496 selected Mac/process/evaluation/coverage regression tests pass
(30 extended tests excluded); three relevant extended CLI/fresh-process determinism
checks pass without coverage. The session-index contract also passes. Focused native
write failures before/after append, source absence/disablement, quoted find, local
startup, future baseline reservations and unknown foreground ownership are covered.
Full Ruff check and format checks pass (1,326 Python files), as does git diff --check.
Generation behavior revision 332 is declared and its surface digest is verified against
HEAD: `d46420e9c3b4352bc27eb26aeec158693a5c375c3cb9d982b5e20abc9fb3503e`.

## Final same-scenario comparison

Final output: `/private/tmp/eforge-macos-command-regression/verified`.
Comparison data: `verified-comparison.json`; evaluator JSON and stderr are kept
outside the bundle as `verified-eval.json` and `verified-eval.stderr` in its parent.
All source records and authoritative files remain together in the fresh bundle.

| Measurement | Original | Final |
|---|---:|---:|
| Mac authored process requests with positive emitted PIDs | 51/85 | 85/85 |
| False successful PID-0 requests | 34 | 0 |
| MAC-01 zsh history | 25 | 64 |
| MAC-02 zsh history | 0 | 43 |
| MAC-01 native ES forks | 3 | 9 |
| MAC-02 native ES forks | 9 | 22 |
| Unified Log workspace entries | 4 | 4 |

Every one of the 84 interactive authored Mac commands has a matching history
submission within two seconds of execution (the source uses whole seconds).
The remaining authored process is a noninteractive root caller and correctly
adds no interactive history. All 31 native fork PID/parent pairs match canonical
eCAR forks. All native ES rows remain event type 11; no exec, exit or Gatekeeper
records were fabricated. The final history total is 107; intermediate runs had
109 before the final unknown-lifetime ownership repair changed baseline choices.

The original scenario and bundle are unchanged. Studio must generate a new run
with this branch's engine to show the fixes; historical bundles are not rewritten.
Native GUI audit/responsibility completion, broader Unified Log callsites and
native exec/exit/Gatekeeper output remain outside this bounded coverage. These
are limits of the existing model/admission gates, not missing process execution
or a reason to relabel aggregate records as native evidence.

Final evaluation: **PASS**, overall **95.43621961255634**, 224,125 parsed records
from 12 sources, no failed hard criteria. Authoritative manifest/resolved content
and file hashes verified. Both Mac profiles now correctly list ES, Unified Log,
eCAR and zsh as present; only unmodeled interactive Bash is inactive. Evaluation
stderr contains no unknown-duration-field warning. The generation used seed 42
and the default output target. This is a deterministic correctness result, not
an independent native realism/capture acceptance or a new blind panel.
