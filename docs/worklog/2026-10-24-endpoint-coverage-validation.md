# Endpoint coverage validation across platforms

The user requested equivalent capability-aware validation for Windows, Linux,
and macOS after Studio warned that the network-only `MacOS-test` draft had no
Mac evidence selected. Work remains on `codex/macos-workstation-support`.

## Changes

- Removed the OS-specific expected-format table and duplicate storyline rule.
  Neither an OS nor a storyline host requires every native format or a specific
  endpoint format. Existing incompatible-format errors remain in place.
- Added informational coverage notes for hosts without any potentially
  observable endpoint collection, using the canonical source catalog and
  compiled deployment. Decisions include exact host ownership, platform/role
  applicability, enabled state, effective capabilities, deterministic versus
  probabilistic missingness, per-format loss, and collection-window overlap.
  Network sensors and application access logs do not imply endpoint collection.
- eCAR counts on all three platforms. Native Mac and shell-history sources
  count within their bounded applicability, without claiming complete coverage
  or guaranteed records. Unified Log eligibility shares the existing native
  workspace profile predicate; its rendering predicate is unchanged.
- Existing behavior reachability contracts retain action-specific warnings and
  runtime prerequisite errors. An explicit SSH receiver-session contract accepts
  eCAR or Linux syslog; history, Unified Log workspace entry, and ES fork
  notifications do not stand in for SSH authentication/session evidence.
  A source format must itself support the required capability, as well as its
  effective source policy.
- Updated the scenario manual and canonical validator skill. Regenerated the
  99 ignored installed skill files through the normal installer.

## Verification

- Validator, coverage, native/profile, history, failed-exec, behavior manifest,
  and desktop display checks: **297 passed, 1 slow case deselected**.
- CLI, admission, coverage, skill installer, and schema CLI checks:
  **232 passed, 14 slow cases deselected**. The coverage suite overlaps the
  preceding run; the two runs cover **453 distinct tests**.
- Ruff check and format check pass (**1,325 Python files**); whitespace checks
  pass. The generation behavior surface is revision **331**, with declared
  impact `none`, digest
  `cd9d0f7153193e362af02c3d025de3242c8446262accb7b678c666ade20cda95`.
  The declaration covers the new validation contract and shared unchanged
  predicate; it does not claim new rendered evidence or close native gates.
- Ran the updated CLI validator against the previously inspected, byte-matched
  authored `MacOS-test` copy under `/private/tmp`, using the explicitly displayed
  checkout project context and no packs. Result: **valid, zero errors, zero
  warnings, two info notes**, one for each Mac without endpoint collection.
  Its Linux syslog and Zeek/firewall selections remain unchanged. The original
  draft was not edited or re-recorded through Studio.

Initial regression tests reproduced the old generic OS warnings. Two existing
tests were updated to expect an informational coverage note and an action-level
SSH warning respectively. An initial new red-herring fixture omitted its
required explanation; fixing that fixture left the complete focused gates green.
No existing local logs were inspected, and no generation, native capture,
product-version change, tag, or release was performed.
