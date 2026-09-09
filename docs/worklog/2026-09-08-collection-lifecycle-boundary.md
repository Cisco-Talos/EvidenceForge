# Collection/lifecycle boundary root fix

## Family contract

- **Owning abstractions:** action bundles own modeled lifecycle deadlines; `EventDispatcher`
  owns the exclusive collection window; engine terminalization settles already-planned lifecycle
  work at its natural time while source admission omits observations after collection closes.
- **Invariant:** an occurrence may start before collection ends and remain active afterward.
  Collection admission must omit post-cutoff source rows without shortening the canonical session,
  process, connection, or application lifecycle.
- **Entry paths:** baseline and storyline SSH/RDP session bootstrap, foreground process lifetime
  scheduling, canonical network connections, and terminal lifecycle journals.
- **Consumers:** State/lifecycle registries, application/network channel managers, eCAR, Syslog,
  Windows/Sysmon, Zeek, checkpoint ownership, and ground-truth generation.
- **Layer rationale:** the collection cutoff is routing/observation policy; it is not a valid
  `SessionEndPlan`. Action bundles must provide exact natural or authored deadlines, and the
  internal settlement frontier must be derived from those retained plans rather than from a fixed
  duration after collection.
- **Sibling risks:** late SSH is the reported blocker. RDP, generic process, and network owners share
  the same internal lifecycle window and terminal frontier. Other terminal-pass admission helpers
  remain in scope only when they still synthesize a collection-boundary close.

## Review reset

The first implementation was discarded before commit. It used a fixed two-hour lifecycle tail and
accumulated downstream parent/process/test accommodations. The replacement must derive terminal
settlement from actual planned deadlines and must not weaken unrelated tests.

The second draft made the common application registry unbounded without removing RDP's historical
use of that registry fence as an implicit logical-session deadline. Warm-up RDP sessions therefore
lost sane generation ownership. That draft was also discarded. The corrected design must give RDP
an action-owned natural deadline before enlarging the shared registry's internal capacity fence.

## Final implementation

- The engine now gives application and remote-session registries an internal capacity horizon that
  is independent of the public collection end. At shutdown it derives the settlement frontier from
  retained SSH, RDP, process, connection, sudo, and application lifecycle plans.
- SSH and RDP sessions that begin before the exclusive collection cutoff keep their natural or
  authored action-owned deadlines. Baseline and storyline planning no longer skip late starts or
  shorten them merely to fit the collection window.
- `EventDispatcher` remains the sole source-observation gate. Post-cutoff rows are omitted, including
  Zeek connection records whose close-time publication falls after collection, while canonical
  state still settles at the modeled future time.
- Exact RDP terminal publication now distinguishes durable visible rows, warm-up suppression,
  collection suppression, and coherent observation-profile suppression. Mixed or unexplained
  zero-row results continue to fail closed.
- SSH child process planning waits for the receiver shell to exist, and session/process state rejects
  activity or termination outside the owning lifecycle. This removes the near-boundary ordering
  defect without manufacturing an early close.
- Dispatcher network-identifier lookup retains a bounded recent history so a composite proxy action
  cannot overwrite the first transport's source-native UID before ground truth records it.

## Report conclusions

- TEST1's historical `GROUND_TRUTH.md` and JSON contained the same unsupported transport UID because
  both serialize the same canonical ground-truth document. Current reproduction confirms every UID
  in both files exists in generated evidence and the two representations agree.
- TEST1's Sysmon Event 1/5 `UtcTime` ordering issue is already fixed on the untouched `dev` base:
  a fresh reproduction found zero `UtcTime > SystemTime` rows in 1,837 applicable records before
  this branch and zero in 1,864 records afterward.
- TEST1's authored `parent_ref` chain and skipped LSASS access are still reproducible on both the
  untouched base and this branch. They are correctness defects, not merely aesthetic realism, and
  remain a separate P1 backlog item. User-field strictness, syslog timestamp consistency, scenario
  briefing UX, and evaluator coverage likewise remain separate non-blocking follow-ups.
- TEST2 was the session-boundary family: the generator treated collection end as a lifecycle end and
  either skipped late SSH activity or forced its terminal graph into the remaining window. The fix
  separates those concepts at their owning layers.
- TEST2's installer-shaped endpoint-effect reconciliation failure is fixed by normalizing prepared
  effect fields before deriving the immutable action identity. The dense authored SSH lead is also
  covered by deriving the session horizon from its remaining child cadence and process lifetimes.
- A full-format TEST1 smoke run is currently blocked by a pre-existing Snort output-ownership
  regression that reproduces unchanged at base commit `0b42e52e1`. Re-running TEST1 without only
  Snort completes; the Snort regression is recorded separately in `TODO.md` and is not caused by
  this change.

## Final verification

- `uv run ruff check .` — passed.
- `uv run ruff format --check .` — 759 files already formatted.
- `uv run pytest` — 8,305 passed, 5 skipped, 2,007 deselected in 248.49 seconds.
- `uv run pytest -m slow --no-cov` — 1,778 passed, 8,539 deselected in 1,001.43 seconds.
- The representative iteration scenario SIGINT/resume test separately passed byte-identically in
  340.89 seconds before the final full gates.
