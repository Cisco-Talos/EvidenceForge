# SSH Deferred-Session Production Migration

Date: 2026-08-20  
Integration base: `dae2a87088f984e10228bbb3632d5fd71777313c`  
Scope: SSH new-session opens through the exact eCAR + Zeek deferred-session bridge.

## Objective

Move the real `ActivityGenerator` SSH action-bundle entrypoint onto the existing exact
deferred-session publication bridge without activating RDP, SMB, Syslog, Sysmon, SQLite, or
other source targets. Cover the actual WorldPlanner bootstrap/deferred-close caller and modeled
storyline SCP source-process caller while preserving the authored/preallocated-session compatibility
path.

## Architecture

- The SSH caller prepares one uncommitted strict State batch containing the new SSH session and its
  target-side `sshd` process. Tuple selection is preview-only; rejection does not publish the
  compatibility source-port cache, runtime tuple, State, lifecycle, application, timing, or source
  state.
- Frozen dependent specifications carry only typed semantic facts. The canonical network owner
  resolves them into process-start and SSH-login occurrences after the exact transport tuple is
  frozen and before any owner transfers.
- The network root, source timing, State, lifecycle, SSH application channel, network runtime,
  eCAR, and Zeek publications enter one deferred composition. The exact source cohort is closed
  to concrete built-in eCAR and Zeek emitters.
- SSH authentication draws are first computed with a detached stateless sampler carrying the exact
  engine namespace/seed, then replayed and equality-checked inside the network-owned SourceTiming
  preparation. Success commits each auth relationship once with the composite; any later target,
  cap, authority, or source failure cancels the staged audit with the rest of the owner graph.
- Target transport FLOW precedes target process start, which precedes SSH USER_SESSION LOGIN.
- The application intent never auto-materializes a source process. A caller-supplied PID/image may
  enter the exact path only when it resolves to one already-live State process and its owning State
  session; that exact identity is shared by the source FLOW, SSH channel, State activity patch, and
  lifecycle hold. Unresolved explicit identity stays on the compatibility path.
- WorldPlanner's real `emit_session_close=True,defer_session_close=True` path now opens through the
  exact bridge, then uses the existing typed deferred-close owner to retire the SSH channel and
  endpoint lifecycle. Storyline SCP uses the same exact open and pure source-port preview before its
  separately owned receiver file effects. Unmodeled/non-Linux SCP keeps the legacy reserving port
  path and its original duration range.
- Unsupported required sources fail before State publication. Exceptional bridge returns
  re-enable exact-token cleanup so reversible preparations cancel, while committed canonical
  truth and exact source recovery reject cancellation and remain recoverable. A committed State
  transport can reconstruct a lost identity-capture return at the network boundary. Receipt
  authentication and capture publication share that committed recovery window, so a false return,
  fail-before exception, or call-original-then-raise cannot release the committed capture.
- Every bundle-owned exact close is reduced to bounded immutable host/session/process/auth facts
  before State preparation. After commit, those facts bind to the captured frozen transaction and
  enter an idempotent typed journal before responder/readiness compatibility caches or source
  teardown run. Journal fail-before and lost-return recover the same continuation without a
  duplicate. Postcommit errors never retry source-native teardown while a sink still has an
  unresolved exact projection; the installed journal performs teardown after source recovery and
  before target channel/process/session retirement. Immediate closes use the same journal and
  acknowledge it only after successful retirement. Aborted engine finalization drains source
  recovery, runs the SSH close journal, drains any terminal-source recovery produced by the close,
  and only then closes source sinks.
- Source-client termination, receiver-worker termination, and target-session logout each publish
  through a separate one-member exact action cohort. The dispatcher accepts only the closed SSH
  process/session shapes, one concrete built-in eCAR target, and no effect/artifact owners; a
  required Syslog or Sysmon terminal target rejects before State. Each phase binds its root action,
  State semantic ID, occurrence, and exact ProcessIdentity/SessionIdentity before commit. Failed
  sink receipts and successful-but-lost owner returns resume from those retained facts without
  reading consumed State. The exact eCAR row and State/lifecycle terminalization therefore commit
  together, while the application/channel journal remains the outer retry owner.
- A modeled explicit source PID/image may enter the exact path only while both the canonical
  process and its owning session remain live at the request time. Retained ended identities fall
  back to the unchanged compatibility path without partial exact work.
- A live canonical global target `sshd` remains the parent of the per-session worker and supplies
  its lifecycle parent group; the exact worker renders root, `System`, and that global PID. The
  no-parent fallback remains PID 0. The production regression injects the parent through real
  lifecycle publication and asserts registry ownership before the exact call. This slice does not
  weaken the composite-parent invariant or compensate for an engine that seeded boot State without
  the matching lifecycle owner.
- Executor, dispatcher, and source timing planner must retain the same exact `TimingRuntime`
  object before preview and again at network use. The authority also identity-binds that runtime to
  the active planning overlay, so copied, foreign, stale, or use-time-swapped runtime owners reject
  before State with both audit streams unchanged.
- Dependent role and ordinal are bound together: receiver PROCESS is ordinal 1 and LOGIN is
  ordinal 2. Merely preserving contiguous ordinals while swapping their roles is rejected before
  State publication.
- No protocol callback runs while State or lifecycle locks are held.

An initial frozen candidate was invalidated before review verdict after an adversarial rejection
probe found eight canonical SSH-auth timing samples surviving an unsupported-target failure. The
repair above reduces that rejection to an identical pre/post `TimingRuntime.state_digest()` and
zero audit samples, and a use-time plan-tamper test now exercises replay mismatch after staging to
prove the shared preparation cancels cleanly. No evidence from the invalidated hashes is counted.

A later frozen candidate was also invalidated after fresh review reproduced four post-freeze
issues: a stranded deferred close on committed sink/lost-return failures; retained-ended SCP actor
admission; loss of the global `sshd` parent and `System` integrity; and copied/foreign timing owner
acceptance. Each repair was developed against a focused failing regression before the green gates
below. All hashes from both earlier snapshots, and all partial moving-tree inspections, are
superseded.

The next frozen candidate was rejected after exact review found three remaining postcommit gaps:
the planner's second receipt authentication sat outside capture recovery; compatibility caches ran
before close ownership was journaled; and close-event construction, journal installation, and
source teardown could fail after commit without a durable continuation. Thirteen focused negative
controls initially produced 12 failures (the existing journal lost-return append was incidentally
idempotent). The repair moves receipt authentication and capture publication into one committed
recovery window, prebuilds immutable close facts before State preparation, and enforces the order
`commit -> capture -> adopt -> journal -> caches -> source teardown -> return`. During the repair,
the full sink-failure gate exposed and fixed an additional lock wait caused by retrying source
teardown before exact sink recovery. All hashes and review evidence from that rejected candidate
are invalid.

A moving-tree adversarial preflight then found two more recovery-boundary defects before refreeze.
First, the SSH catch path queried State before checking an already-published capture; a failed
recovery-only State read masked the primary journal error and skipped close installation. The new
negative control reproduced `RuntimeError` masking the expected `OSError`; capture-first detection,
guarded fallback inspection, and guarded RNG rollback now preserve the primary and install the
journal. Second, the frozen request retained mutable nested `User` and `System` aliases. Mutating
those models after open produced `LOGIN analyst` followed by `LOGOUT intruder`. The close plan now
owns bounded immutable scalar copies and materializes detached terminal-only models, giving exact
byte parity after mutation. Both focused controls are green.

The next exact snapshot was rejected on two further postcommit boundaries. The prepared close
continuation was still instantiated after the transport commit and its constructor reread nested
request models; the complete scalar-only continuation, capacity reservation, and one-shot binding
are now created before the transport mutation. Engine finalization also closed emitters and marked
itself complete after a close-journal error. Finalization now performs the bounded sequence
`SSH journal -> terminal exact recovery -> both zero assertions -> source/emitter close`; a
failure preserves the journal and open sinks, leaves finalization incomplete, and a retry converges.
The first/middle/last fail-before and lost-return matrices cover both success and abort paths.

Final hardening moved each canonical terminal mutation into the exact action-cohort owner instead
of an ordinary dispatch followed by a separate State call. Source, receiver, and target sink
fail-before/lost-return tests prove one retained result, no State reread after consumption, byte
deduplication, and zero recovery residue. A successful action-cohort owner-context lost return and
a forged postcommit return reuse the canonical result. The committed network-capture publisher is
also postcondition-checked, so no-op and forged returns cannot release its already-committed claim.

The `ffc850...` review snapshot was rejected after reproducing an exact transport whose close time
equaled the exclusive generation-window end. Its journal installed successfully, but the later
PAM/logout offset fell outside the SSH application manager's half-open window, so every finalizer
retry retained the same uncloseable owner. The repaired close plan now precomputes and freezes the
source-client termination, receiver-worker termination, PAM/logout, and logind-removal times before
canonical mutation. Admission reserves the whole 3.5-second maximum terminal family against the
application registry's exact window and rejects before State when it cannot fit. Every retry
reauthenticates both the deterministic timestamps and the original window owner. Boundary controls
cover the exact maximum, ±1 microsecond, +1 millisecond, the original end-time reproduction,
pre-use tail tampering, and fail-before/lost-return recovery at the maximum admitted boundary.

The following `793ad4...` frozen snapshot was rejected after a same-window foreign SSH channel
manager was substituted before finalization. The terminal continuation authenticated only the
replacement registry's window value, silently found no matching sidecar, and acknowledged the
journal while the original manager retained an open session. The repaired precommit continuation
identity-binds the exact original `SshApplicationChannelManager` and shared
`ApplicationChannelRegistry`; after commit it binds the exact SSH sidecar and application identity.
Retirement retains the manager's canonical close time before the fallible call, authenticates its
lock-free closure or the original registry's exact lost-return proof, proves the original sidecar is
absent, and repeats that proof immediately before journal acknowledgement. Foreign/copied manager
and foreign/copied-registry substitutions now reject before terminal State mutation with the
journal intact. Restoring the original owner converges, while fail-before, lost-return, and a
deliberately unavailable lost-return proof remain retryable without acknowledging the journal.
The `793ad4...` hashes and review evidence are invalid.

The `27a708...` manifest was rejected after the public application-channel watermark closed the
exact original SSH sidecar at its transport deadline before the deferred journal ran. Although the
original registry retained the canonical closed snapshot, the journal accepted only a close it had
itself attempted, so every retry failed with the journal permanently pending. The retirement proof
now accepts only the original registry's exact immutable application identity, exact derived close
time, and built-in `deadline` reason when the original sidecar is already absent. It retains that
reason alongside the close time, then reauthenticates the same original snapshot before journal
acknowledgement. Public watermark controls at one microsecond before, exactly at, and one
microsecond after transport close cover both direct convergence and a post-retirement failed-first
retry; all six cases terminalize the remaining State/lifecycle cohorts once and leave zero journal
or dispatcher residue. The `27a708...` hashes and review evidence are invalid.

## Red Negative Control

Both the public adapter-shaped regression and the stronger WorldPlanner internal-call regression
were run against the untouched integration head. Each failed as expected at
`bridge_calls == 0`, proving neither prior production path entered the exact bridge:

```text
tests/unit/test_ssh_deferred_production.py::
test_real_ssh_caller_reaches_exact_bridge_and_publishes_transport_first[direct]
FAILED: assert 0 == 1

tests/unit/test_ssh_deferred_production.py::
test_world_planner_real_ssh_bootstrap_uses_exact_bridge_and_defers_close[direct]
FAILED: assert 0 == 1
```

## Verification

- `309 passed`: 95 real SSH production tests plus deferred-session composition/preseal foundations
  and engine projection-recovery tests. The production file covers the public adapter, actual
  WorldPlanner deferred-close, modeled-process SCP, direct/threaded byte parity, each canonical
  owner and concrete sink fail-before/lost-return boundary, committed close-journal recovery,
  unsupported target, cap, copy/tamper/foreign/stale authority and runtime ownership, exact timing
  replay/audit rollback, dependent role/ordinal binding, global `sshd` parent semantics, second
  receipt false/fail/lost-return, both postcommit compatibility caches, close-plan construction,
  journal installation, source teardown, capture-first exception preservation, immutable nested
  owner facts, exact action-cohort source/receiver/logout terminalization, successful owner-context
  lost returns, forged terminal returns, exact census cleanup, and ended-process/session
  compatibility. The added application-owner matrix covers the original manager/registry,
  foreign and copied managers, foreign and copied registries, manager-close fail-before and
  lost-return, exact retained closed-channel proof, proof unavailability, restored-owner retry,
  pre-ack sidecar retirement, and public SSH watermark convergence immediately before/at/after
  transport close in direct and failed-first retry modes. The engine tests
  prove abort ordering across source recovery, SSH close finalization, the second source drain, and
  sink close.
- `367 passed`: SSH authentication timing, application channel, prepared admission, source-port
  retention, legacy timing-runtime migration, network prepared-runtime integration, transaction
  contracts, connection identity, network timing runtime, network runtime, exact dispatcher
  recovery, and action-cohort coverage.
- `92 passed`: generation-engine, engine projection-recovery, and WorldPlanner coverage, including
  the actual SSH bootstrap caller.
- `76 passed, 4 failed`: storyline command-network coverage. The four failures are unchanged on
  the integration base (`_CapturingDispatcher` lacks the independently required
  `source_timing_planner`); the three SCP tuple/receiver regressions pass.
- Repository lint and formatting: `ruff check .`, `ruff format --check .`, and
  `git diff --check` all pass.

The selected integration base has known unrelated failures, including the storyline dispatcher
double above. The frozen SSH gates are reported separately from those inherited failures.

Commands used from the repository root:

```bash
UV_CACHE_DIR=/private/tmp/eforge-ssh-uv-cache uv run pytest --no-cov -q \
  tests/unit/test_ssh_deferred_production.py \
  tests/unit/test_deferred_session_composition.py \
  tests/unit/test_deferred_session_preseal.py \
  tests/unit/test_engine_projection_recovery.py
UV_CACHE_DIR=/private/tmp/eforge-ssh-uv-cache uv run pytest --no-cov -q \
  tests/unit/test_ssh_auth_timing_runtime.py tests/unit/test_ssh_channels.py \
  tests/unit/test_ssh_prepared_admission.py tests/unit/test_ssh_source_port_retention.py \
  tests/unit/test_legacy_timing_runtime_migration.py \
  tests/unit/test_network_prepared_runtime_integration.py \
  tests/unit/test_network_transaction_contract.py tests/unit/test_network_connection_identity.py \
  tests/unit/test_network_timing_runtime.py tests/unit/test_network_runtime.py \
  tests/unit/test_dispatcher_exact_projection_recovery.py \
  tests/unit/test_dispatcher_action_cohort.py
UV_CACHE_DIR=/private/tmp/eforge-ssh-uv-cache uv run pytest --no-cov -q \
  tests/unit/test_engine.py tests/unit/test_engine_projection_recovery.py \
  tests/unit/test_world_model.py
UV_CACHE_DIR=/private/tmp/eforge-ssh-uv-cache uv run pytest --no-cov -q \
  tests/unit/test_storyline_command_networks.py
UV_CACHE_DIR=/private/tmp/eforge-ssh-uv-cache uv run ruff check .
UV_CACHE_DIR=/private/tmp/eforge-ssh-uv-cache uv run ruff format --check .
git diff --check
```

The source and test hashes below will identify the immutable tree submitted for fresh independent
review. Earlier moving-tree inspections and their partial evidence are explicitly superseded.

## Frozen Review Snapshot

Base/HEAD: `dae2a87088f984e10228bbb3632d5fd71777313c`

```text
8afd9bf7829a79bf8a7c2c8406cb7259eabeeb418b20785e50b0c06c067a0119  src/evidenceforge/events/dispatcher.py
5cc1ff4cd29f7e8df78f99f7905bc375409364087615d5dc34bdb62a981bada3  src/evidenceforge/generation/actions/network_connection.py
3065b02b8ce29ede68d82ff4ca4cdee05107353a782646fe3a2d84461c34d177  src/evidenceforge/generation/actions/network_transaction_planner.py
7777bd60447206bfd6a7979c3914a25b6e35c34e9ae7414abf8150a58105fddd  src/evidenceforge/generation/actions/ssh_session.py
fb385d0bfc2d67202c1b7cb724411ea3481fdfb4fb965cefcba4f609ff6d0865  src/evidenceforge/generation/activity/generator.py
019bcb521ba2276d0f78d2738c4446e4da6150feb8e020c696bd3a9b47ab002f  src/evidenceforge/generation/engine/core.py
39c9c2f20ec0864766e29c735b4de704f6638b3ee39eb9a654ce2d24693a3020  src/evidenceforge/generation/engine/storyline.py
62237c9426ff7c626180f039f081f8290060f0a401f83c24284f40e0811a98f0  tests/unit/test_engine_projection_recovery.py
206d6be858034e7d5e2871461f54dcc17f735267d0c9fa5e99ea1d71ba02319c  tests/unit/test_storyline_command_networks.py
d8fb09b043f8c8878719b33a5ee9229bdc88415ca3a34ec6bacefc2491719243  tests/unit/test_ssh_deferred_production.py
```

The SHA-256 of the ten-line manifest above is
`ee1b8231f7a96903c8d42ef023f1b87be572ee68deb791013aa279182ce3b79e`.
The rejected `27a708...`, `793ad4...`, `ffc850...`, and every earlier moving-tree hash are invalid.
No commit is permitted until one fresh independent review of this exact snapshot returns CLEAR.
