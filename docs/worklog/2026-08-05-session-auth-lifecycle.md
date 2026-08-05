# Session and Authentication Lifecycle Realism Worklog

## Status

Implementation completed on 2026-08-05 after the user approved proceeding from the canonical
contract foundation into the first output-changing realism slice. The feature changes generated
records and clears the targeted rendered-invariant findings; generated datasets remain untracked.

Branch: `codex/session-auth-lifecycle`

Stacked on: `codex/canonical-contract-foundation` at `0b0ad32c`

## Targeted validated findings

- `REAL-001`: connection-owner processes can cross session boundaries or outlive their owner.
- `REAL-002`: one Windows LogonID can change from a null to non-null LogonGuid.
- `REAL-003`: distinct same-timestamp failed authentication attempts can share an eCAR object ID.
- `REAL-004`: Linux server local-session ancestry reverses `/bin/login` and `systemd --user`.
- `REAL-006`: an RDP source endpoint FLOW can render after target authentication.
- Foundation shadow debt: machine-account start/closure occurrences bypass registered session
  identity; some successful logon/SSH paths also need exact trace verification.

## Slice invariants

1. A published session identity, including LogonGuid nullability, never changes.
2. A user process can be reused only within its exact owning LogonID and valid session interval.
3. SSH client processes are one-shot per transport unless explicit multiplexing is modeled.
4. Every failed authentication attempt has a stable, distinct action-relative occurrence ID.
5. Linux server console ancestry is system manager -> login -> shell; a per-user system manager is
   not the parent of `/bin/login`. Desktop terminal ancestry remains session appropriate.
6. Every successful RDP target authentication observation follows both admitted endpoint FLOW
   observations for its exact transport.
7. Machine-account type-3 start/logoff evidence resolves one registered session identity and then
   closes it through the normal state transition.

## Validation strategy

- Add focused unit tests at each owning layer and entry-path sibling tests for SSH, proxy,
  browser, and mail-client process reuse.
- Re-run the integrated review topology and the expanded rendered-invariant probe.
- Compare before/after output and account for every changed source family; byte identity is not an
  acceptance criterion for this output-changing slice.
- Run Ruff, the complete non-slow suite, and targeted slow tests relevant to lifecycle behavior.

## Implemented ownership changes

- `StateManager` now finalizes a session's null/non-null LogonGuid policy at allocation, retains
  that identity after closure, rejects replacement, and allocates deterministic peer ordinals for
  otherwise identical semantic attempts.
- Connection-owner reuse requires the exact active LogonID. SSH, SCP, and SFTP client processes
  are one-shot per transport until explicit multiplexing is modeled.
- Failed authentication attempts receive action-relative occurrence keys, so identical retries at
  one timestamp remain distinct without depending on unrelated generation order.
- Linux server console sessions now use system manager -> `/bin/login` -> shell ancestry. Desktop
  terminal sessions retain their per-user system-manager ancestry.
- Source timing anchors remote authentication after the later admitted source or target eCAR FLOW,
  preventing source-visible RDP/SSH transport from appearing after target authentication.
- Baseline logoff plans are published to canonical session state before activity fan-out, so every
  consumer rejects reuse after the planned closure rather than relying on a local deadline map.
- Anonymous and machine-account Type 3 logons now use registered, state-backed start/closure
  lifecycles with one identity object. Sysmon projects the canonical session LogonGuid, including
  ended sessions, and no longer invents emitter-owned shared truth.
- The SSH contract treats a modeled source host as optional because inbound traffic from an
  unmodeled external client is a supported partial-observation path.

## Empirical before/after evidence

Scenario: the review branch-office enterprise topology, using the same scenario, observation
profile, and seed as the frozen review output.

- Frozen output: `/private/tmp/eforge-realism-review/branch-enterprise`
- Final output: `/private/tmp/eforge-session-auth-v3/branch-enterprise`
- Final probe: `/private/tmp/eforge-session-auth-v3/probe-branch-enterprise.json`
- The frozen probe reported 46 findings (44 errors and 2 warnings). Fourteen findings belonged to
  the six targeted checks: failed-attempt identity (1), Linux login parentage (1), process after
  logout (3), RDP transport-before-authentication (2), overlapping SSH actor transports (5), and
  mutable Sysmon LogonGuid (2).
- The final probe reports zero findings for all six targeted checks. It reports 32 unrelated
  findings (30 errors and 2 warnings): Windows 4648 native fields, Zeek AAAA success distribution,
  Zeek file intervals, and Zeek OCSP duration distribution. Its nonzero exit is therefore expected
  and preserved as input to later remediation slices.
- Two independent post-change runs at
  `/private/tmp/eforge-session-auth-v2/branch-enterprise` and
  `/private/tmp/eforge-session-auth-v3/branch-enterprise` are fully byte-identical (`diff -qr`
  exit 0), confirming that the changed output remains deterministic.
- The integrated shadow-contract pass initially exposed one external-client SSH occurrence as
  missing a source-host context. The reviewed contract now records that context as optional, with
  an exact registry regression test. No generated records were weakened or fabricated to satisfy
  the contract.
- Generation retained the scenario's pre-existing undeclared-domain warning for
  `portal.northstarclaims.net`; this slice does not change that scenario input.

The post-change package is intentionally not expected to be byte-identical to the frozen output:
one-shot SSH processes, corrected ancestry, immutable session identity, and changed source timing
all alter rendered evidence. Some later record IDs and RNG-dependent values can consequently move
even when the direct fix owns only one event family; the rendered invariant probe is the acceptance
boundary for this slice.

## Validation results

- Focused tests cover immutable LogonGuid policy, ended-session lookup, scoped semantic ordinals,
  same-timestamp failed attempts, exact-session and one-shot process ownership, Linux server
  ancestry, published baseline closures, state-backed anonymous/machine logons, external SSH
  sources, and later-endpoint RDP timing.
- The first complete non-slow run reached 5,106 passed and 41 skipped, with one stale
  `test_world_model` assertion that still required a server's system manager to share the user
  session lifecycle. The assertion was corrected to distinguish the boot lifecycle from the
  `/bin/login` and shell lifecycle; the affected world-model and generator tests both pass.
- `uv run ruff check .`: passed.
- `uv run ruff format --check .`: passed; 452 files already formatted.
- `git diff --check`: passed.
- `uv run pytest --no-cov -q`: 5,107 passed and 41 skipped in 215.89 seconds.
- `uv run pytest --no-cov --include-slow -q tests/integration/test_parallel_generation.py`:
  5 passed in 3.36 seconds, covering threaded temporal consistency, cross-log identity,
  corruption checks, storyline generation, and performance.
