# Experimental scenario-agent acceptance harness

## Scope

This branch prototypes a clean-room, deterministic acceptance harness for live Codex and Claude
scenario-authoring sessions. It is intentionally isolated under
`experiments/scenario_agent_acceptance/` and is not part of the EvidenceForge package, public CLI,
CI, or release gate.

The durable P1 in `TODO.md` remains open. Completing this branch does not establish that the
experiment is effective or suitable for integration.

## Contracts

- Live model execution is the only online or nondeterministic stage.
- Replay, completeness checks, scoring, report verification, and baseline comparison are offline.
- Sessions are isolated from project and user context as far as the provider CLIs permit; reports
  say `session-isolated`, never credential-isolated.
- The instrumented `eforge` executable permits only schema/info/validation, non-writing resolve,
  and read-only pack inspection.
- Unsupported provider versions and transcript shapes are infrastructure errors.
- The baseline contains aggregate metrics and input digests, never authored YAML or transcripts.
- The per-session timeout defaults to 45 minutes. It is an infrastructure safety bound for hung
  provider processes, not an expected authoring duration or an agent-quality threshold. A timeout
  always produces `INFRASTRUCTURE_ERROR` and invalidates that sample.

## Acceptance boundary

After one full 16-session run, review the aggregate report, representative traces, false-positive
and false-negative risks, runtime, and provider usage. Only explicit maintainer approval may move
this into shipped code or close the P1.

## First full-run review

Run `20260827T121514-98c00bdd` completed all 16 sessions in 2,732 seconds without an
infrastructure error or timeout. The immutable report is stored under ignored
`.eforge/agent-acceptance/full.json`; its artifact digest verified successfully, while its strict
verification correctly returned nonzero.

The report's apparent 5 PASS / 11 FAIL result exposed deterministic oracle defects:

- output requirements used generic `windows` and `zeek` labels instead of runtime formats such as
  `windows_event_security` and `zeek_conn`;
- RDP and SSH receiver-service checks used spellings inconsistent with the accepted authoring
  contract;
- the SMB oracle looked for `share_overrides` above its owning storage-server entry;
- the unchanged-loop detector counted an intentional repeat validation of already-valid YAML.

All 16 final scenarios independently ended with zero validator errors. After correcting those
oracles and restricting loop detection to unchanged error-bearing attempts, offline rescoring gives
16/16 strict passes, 12/16 valid first complete drafts, 19 total passes to zero errors (median 1,
maximum 3), zero unchanged-error loops, zero repair drift, and zero isolation violations. The
original report is intentionally not rewritten, and no baseline is created from it.

The run recorded 252 agent tool calls. Codex sessions totaled 1,127 seconds; Claude sessions totaled
1,606 seconds. Provider-reported usage included 3,578,557 input tokens, 3,092,224 cached input
tokens, 2,305,720 cache-read input tokens, 122,797 output tokens, and $3.12 of Claude-reported cost;
Codex did not report a dollar cost. Warning metrics found two introduced and five unexpected
warnings, dominated by expected no-firewall guidance and one Zeek SPAN-placement warning.

Recommendation: revise and run another full sample before considering a baseline or integration.
The harness successfully preserved artifacts, detected its own strict failures, and supported
offline diagnosis, but this first run is also direct evidence that untested oracle vocabulary can
create severe false positives. Remaining false-negative risk includes semantic quality outside the
explicit predicates, correct prerequisites attached to the intended receiver rather than merely
present somewhere in the document, and realism judgments intentionally excluded from this
experiment.
