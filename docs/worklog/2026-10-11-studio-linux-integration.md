# Studio Linux integration into dev

The user authorized creating a PR for the complete local Studio/Linux work and merging
into `dev` after CI is green. PR: https://github.com/Cisco-Talos/EvidenceForge/pull/445.
Initial head: `5b9adf4b`, following implementation commit `3c6ac0d7`. This is an unpublished
2.2.0a2 source integration; it does not authorize a release tag or publication.

## Initial CI and correction

CI run `38155999383` passed lint and Windows checkpoint durability. The macOS native
state-recovery job failed in `test_finder_codex_discovery_and_explicit_setting_precedence`:
its old one-argument `shutil.which` lambda did not accept the `path` keyword now used
to discover Codex with Studio's subprocess PATH. The other 69 native lifecycle/ownership
tests in that step passed. State preservation/fault tests passed before that step.

Updated the existing test double to `Mock(return_value=None)` and asserted the exact
Codex lookup with the subprocess PATH. This preserves Finder fallback and explicit
setting precedence coverage without changing product behavior. No new tests were added.
The frontend suite passed locally (29 files, 296 tests) while CI ran. An optional local
backend run was rejected by automatic approval review because it did not consider the
PR request authorization for extra local tests; that run did not start. Further backend
validation uses the PR's CI gates.

Merge must wait for successful checks on the final PR head, including the `Required CI`
aggregate. Preserve the implementation/version commits with a merge commit; do not push
release tags or publish installers as part of this request.
