# Iteration-Test-Expanded-IDS Assessment Loops 15-24

## Scope

Run ten iterative family-level realism assessment loops against
`iteration-test-expanded-ids`, continuing the existing benchmark after loop 14.
The scenario remains unchanged. New generated data and blind-review artifacts
are stored under `scenarios/iteration-test-expanded-ids/blind-test/loop-N/` in
this worktree; the pre-existing loops 1-14 in the primary checkout are treated
as read-only history.

## Loop 15 Baseline

Because the generator changed substantially after the previous assessment, loop
15 begins with fresh generation and a standalone blind panel. No prior-loop
finding is carried forward into target selection.

## Loop 15 Baseline Outcome

- Generated 86,744 records; automated evaluation passed at 96.27780948253039
  with exact IDS integrity at 213/213.
- Standalone blind scores were Threat 79, Detection 69, Network 65, and Host 94;
  average 76.75 (`likely synthetic`). All verdicts were Synthetic, so no
  deliberation ran.
- The highest validated next contract is Linux APT process ownership: 72 APT
  method helpers across seven hosts were rendered as direct PID-1/systemd
  children rather than children of an APT frontend.

## Loop 16 Family Contract

- **Selected family:** Debian APT frontend and transport-method process ownership.
- **Finding classification:** `new_family` hard contradiction.
- **Owning abstraction:** canonical Linux system connection-owner process planning.
- **Invariant:** every modeled `/usr/lib/apt/methods/http*` helper must have a
  live `/usr/bin/apt-get` frontend parent created first on the same host. The
  frontend remains systemd-owned; helpers never attach directly to PID 1.
- **Entry paths:** explicit-proxy package traffic, direct high-confidence package
  connections, background package refreshes, and HTTP/HTTPS method siblings.
- **Consumers:** canonical process state, eCAR PROCESS/FLOW, proxy/Zeek joins,
  lifecycle finalization, and endpoint blind review.
- **Layer rationale:** the impossible parent is created when canonical process
  ownership is materialized, before eCAR rendering. The renderer is exposing
  supplied truth correctly.
- **Sibling risks:** cover both `http` and `https` helpers, frontend reuse only
  while active, ordering before the helper, and unchanged DNF/YUM ownership.
