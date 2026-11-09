# macOS release readiness review

Reviewed `codex/macos-workstation-support` at `42d6440a` on November 6, 2026.
The user requested an assessment of generated Mac data, Studio integration,
automated tests and remaining release work. This review does not authorize a
version bump, PR, merge, native collection or release.

The implementation has strong bounded process-evidence contracts. It needs a
finite stabilization and release-validation pass before publication. A release
can retain an explicitly experimental macOS 27 arm64 workstation scope; claiming
broad native Mac fidelity would require substantially more capability work.

## Supported quality and its limits

The [current delivery plan](../design/macos-workstation-feasibility/endpoint-delivery-acceptance.md)
and [process coverage worklog](2026-10-28-macos-es-exec-completeness.md) record
229/229 forks, 291/291 execs and 200/200 native exits for the unchanged MacOS-test
workload at behavior revision 384. Independent eCAR joins match the executions and
terminal lifetimes. The 23 existing failed PostgreSQL/MySQL attempts have nonzero
outcomes. This is historical scenario evidence, not a fresh run at revision 471.

The current implementation routes process, terminal, Finder, SSH and selected
system-job evidence through canonical owners, preserves unknown facts, rejects
unsupported complete-start requests, and tests rollback, publication retry,
filtering and checkpoint recovery. These are meaningful engineering strengths.

Complete process coverage means every eligible **modeled** fork/exec is accounted
for. It does not establish that every helper or background process a real Mac
would create is modeled. Likewise, the selected ordinary-close results are
explicit simulation policy, not universally measured macOS shutdown behavior.

The [latest mixed-fleet worklog](2026-11-06-iteration-test-loops64-68.md) records
hard acceptance PASS and an approximately 96.51 deterministic score, while the
final four reviewers all returned Inconclusive authenticity verdicts. Their mean
synthetic-confidence score is 36/100; it is not a percentage accuracy measure or
a controlled estimate of improvement. Passing evaluation establishes its bounded
contracts, not all workload realism.

## Recommended priorities before a stable release

1. **Restore a clean automated gate on the final integrated snapshot.** The current
   timing inventory guard fails, and selected older Mac slow regressions fail.
   Repair stale contracts while retaining independent coverage; investigate missing
   positive evidence instead of removing assertions. Run the full routine suite,
   all slow shards, required coverage and platform checks after those repairs.
2. **Reconcile release scope and acceptance.** The existing user-review hold before
   a PR into dev remains open. Launchd ULF remains unqualified under the agreed
   stopping rule. Release documentation should explicitly state that exception;
   this review does not request another capture or an invented message family.
3. **Repair the strongest supported-workload realism findings.** Prioritize shared
   interactive task pacing and profile-scoped browser instance/reuse semantics.
   The assessment repeatedly finds approximately 96-second developer launch gaps
   and overlapping browser roots. Preserve authored intent and profile-isolation
   alternatives; fix the planner/application owner rather than adding emitter
   jitter or suppressing inconvenient starts.
4. **Check application intent and shared regressions.** Zoom/default browser headers,
   shell-owned document operations and long trivial commands need bounded owner-level
   diagnosis. UDP firewall expiry, Windows session ancestry and Linux logind numbering
   are shared mixed-fleet findings, not established Mac-introduced defects. Their
   significance should be decided by concrete contradictions and release claims.
5. **Exercise the installed product with Mac data.** Add a small Mac-native generation
   and evaluation smoke to packaged-runtime verification, and perform one bounded
   Studio journey on the candidate installer: import/edit, validate, generate,
   inspect ES/ULF/history, evaluate, and interrupt/resume. Include one unsupported
   launch with an actionable error. Existing packaging verification generates the
   Windows-only minimal fixture.

A next prerelease need not wait for every qualitative lead. A stable release
advertising realistic Mac workstation simulation should close or explicitly
resolve the strongest recurring supported-workload findings.

## Studio findings

The frontend changes relative to dev are small: platform choices, Mac host help,
source names and NDJSON highlighting, plus typed backend platform-key exposure.
The frontend suite, type generation and production build pass in this review.
No broad Studio regression was demonstrated by these checks.

There are concrete presentation gaps:

- `desktop-ui/src/AssetBrowser.tsx:96` omits supported SSH authentication from its
  ULF summary and says unknown exec metadata omits native phases. The default
  complete-start contract instead rejects missing required exec evidence.
- `desktop-ui/src/ScorecardPanel.tsx` and the bounded `ScorecardDetail` service
  model do not expose the dedicated native coverage summary. A compact host-level
  fork/exec/known-exit/unknown-result summary would make the coverage boundary
  visible without requiring the user to read raw reports or ground truth.
- Public guidance needs one reconciliation pass. The example README still says
  PTY startup and native SSH ULF are unavailable. `docs/studio.md` says the
  published installer is macOS-only, whereas `docs/releases.md` describes the
  published macOS and two Linux installers. Clearly separate the host that runs
  Studio from the OS being simulated.

Native interactive acceptance, installer upgrade behavior and separate-account
acceptance are not established by frontend tests. Separate-account testing remains
explicitly deferred; do not create accounts or silently turn that deferral into a
new release requirement.

## Automated coverage and remaining gaps

There is substantial useful coverage: native wire contracts, canonical census,
eCAR joins, parent/audit/credential ownership, failure outcomes, source selection,
mixed fleets, publication faults, rollback and exact recovery. The Mac-focused
routine selection contains 4,691 selected cases. Quantity is not the primary gap.

The CI configuration runs the general engine suite on Linux and Windows, Studio
and state-recovery jobs on macOS and both Linux architectures, and all slow tests
in four Linux release shards. The macOS Studio job does not run the general engine
suite. Add a compact native Mac generation smoke on that host rather than assuming
the Studio suite supplies it. The Python 3.12-to-3.13 portability script also uses
the Windows-only minimal fixture; a Mac state-bearing case would strengthen that
specific boundary.

One representative longer Mac/mixed-fleet run should also record runtime, peak
memory, temporary disk and checkpoint size after the new lifecycle/identity work.
Existing retention-unit contracts are useful, but they do not supply that workload
measurement. This does not require a million-record or exhaustive soak campaign.

Use a small declared seed/persona/baseline matrix with positive workload assertions
to supplement fixed acceptance seeds. Include both terminal variants, local and
SSH commands, supported apps, and unsupported admission. Broader native consumer
ingestion remains unqualified: one external ingestion/query smoke would support a
specific SIEM integration claim, while the internal codec score alone cannot.

Read-only GitHub queries returned no PR and no Actions runs for this feature
branch. This is consistent with CI being triggered on PRs to dev/main rather than
ordinary feature-branch pushes. It is not a failed remote CI result; the current
snapshot has no corresponding remote integration result to cite.

## Capability work that can follow the bounded release

Native ES file create/write/rename/unlink evidence is the most useful next source
expansion for filesystem-oriented hunts. Current native generation is restricted
to process phases; eCAR file observations are a different evidence source.
General Unified Log, GUI LaunchAgents/automatic activation, richer app/helper
graphs, complex shell execution plans, Intel/Rosetta, sleep/wake, roaming, binary
log archives/APFS artifacts and Mac SMB serving remain outside the bounded scope.
These are capability limits to document, not an automatic requirement to implement
every family before an experimental release.

Developer ID signing/notarization remains a deliberate deferral in the release
policy. Revisit it for a broad public stable distribution because it affects the
installation experience; it is not a newly imposed gate in this review. Apple's
[distribution guidance](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
describes the intended Developer ID/notarization path.

## Validation in this review

Completed:

- Frontend: 347 tests across 33 files pass.
- Mac-focused routine selection and Studio asset backend: **4,691 passed,
  124 deselected in 685.34 seconds**. Selection:
  `uv run pytest --no-cov tests/unit/test_macos_*.py tests/unit/test_studio_assets.py`.
- Generated API types and TypeScript/Vite production build pass; existing large
  JavaScript chunk advisory remains.
- Whole-repository Ruff check and formatting pass, with 1,479 Python files formatted.
- Shared product/Studio version check passes at 2.2.0a4. The behavior check against
  origin/dev passes at revision 471, digest
  `1b7a5f585d8e50a95ca53b6b7ddf76a5794070ae7505fb9a57bfbc318b8c0af3`.
- Combined Mac exact checkpoint/resume and native-filter equivalence passes.
- Timing policy selection: two pass and the inventory guard fails. Together with
  the recovery case, the command reports three passed, one failed in 56.70 seconds.
  A direct inventory comparison finds 11 continuous-RNG calls above the selector
  allowances, compared with nine in the older worklog. Two current selectors concern
  process/runtime executable sizing, so review selector scope as well as real timing
  ownership; do not assume every excess call is a timing defect or raise all caps.
- Older native CLI and mixed-fleet selection: four failures in 154.87 seconds.
  The two native failures expect three/six fork-only receiver records but receive
  37/57 mixed native process records. The mixed-fleet ordinary case has no expected
  zsh history file, and the helper case has no matching helper CREATE rows. The
  helper output does contain 48 helper MODIFY records (16 renderer and 32 generic
  helper execs); its CREATE-only assertion predates explicit fork/exec modeling.
  The quiet ordinary sample has one visible command execution, a noninteractive
  `zsh -c` invocation, so history presence is not a valid unconditional positive
  coverage assertion. Keep a quiet negative case and add explicit positive
  interactive intent; join helper fork/exec/lifetime facts rather than weakening
  either test to accept arbitrary absent evidence. No production omission is
  established by these four assertion failures.

These checks do not substitute for the full release suite, coverage, Rust/native
packaging, cross-platform CI or interactive installer acceptance. Test transcripts
are under `/tmp/eforge-release-review-*.log` for this session. Local uv commands used
a temporary cache and `--no-sync` because the default cache is outside the writable
sandbox. GitHub queries were read-only. Only this worklog was added; existing local
assessment reports were preserved.
