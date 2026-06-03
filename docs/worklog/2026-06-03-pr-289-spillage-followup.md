# PR #289 Spillage Follow-Up

Date: 2026-06-03
PR: `#289` (`feat: add spillage event type for synthetic credential leakage`)

## Decision

Merge the contributor PR into `dev`, then handle the remaining architecture-specific
cleanup as maintainer follow-up work.

Reasoning:
- The contributor addressed most review points from the June 2, 2026 follow-up comments.
- The remaining `process_command_line` gap is narrow but tied to EvidenceForge's
  canonical auth/session/process ownership model.
- It is faster and lower-risk for maintainers to finish that integration on `dev`
  than to push another contributor review round for a subtle architecture-specific fix.

## Remaining Maintainer Follow-Up

1. Fix `process_command_line` spillage so the emitted live process record uses a real
   actor session/logon context instead of the current placeholder/default path.
2. Add regression coverage for that fix, especially Windows `4688` / `ecar`
   session/logon linkage.
3. Keep vendor-published official test secrets, including the Stripe test key.
4. Broaden `GROUND_TRUTH.jsonl` in a separate PR so it becomes the machine-readable
   companion to `GROUND_TRUTH.md` for all event types, not just spillage.

## Notes For Future Agents

- Do not treat the broader `GROUND_TRUTH.jsonl` expansion as part of the same
  narrow maintainer fix; it is a separate contract change.
- If the `GROUND_TRUTH.jsonl` scope is expanded, update writer behavior, docs,
  eval assumptions, and tests together.
