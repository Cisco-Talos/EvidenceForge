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

## Loop 16 Outcome

- Commit `490e363b`; full suite 5,077 passed and 41 skipped; Ruff passed.
- Rendered probe: 62/62 helpers had a visible preceding `apt-get` parent; zero
  direct PID-1 helper ancestry remained.
- Automated evaluation passed at 96.47643566860552 over 87,468 records.
- Blind scores were 83/88/72/95, average 84.5. The direct parent defect was
  fixed, but the new frontend lacked a bounded serialized lifecycle and exposed
  APT-to-DNF state mixing. Loop 17 remains on the package-manager family to fix
  this latest-change regression before selecting an unrelated target.

## Loop 17 Family Contract

- **Selected family:** serialized package-manager frontend lifecycle and
  distro-native state effects.
- **Finding classification:** `exact_regression` plus `sibling_defect` from loop 16.
- **Owning abstraction:** canonical Linux package-manager process lifecycle;
  data-driven EDR package-state profiles.
- **Invariant:** a host has at most one visible APT frontend transaction at a
  time; helpers extend that transaction briefly, and the frontend terminates
  after its last helper. APT/dpkg write only Debian state, while DNF/YUM/RPM
  write only RPM state.
- **Entry paths:** proxy/direct APT HTTP and HTTPS helpers, repeated repository
  requests, foreground package commands, and generic file side effects.
- **Consumers:** process state, eCAR PROCESS/FLOW/FILE, lifecycle probes, config
  validation, and endpoint/detection review.
- **Layer rationale:** transaction concurrency and closure belong to canonical
  process lifecycle state; path enumerables belong to config. Renderers own
  neither fact.
- **Sibling risks:** helper fan-out must reuse a still-live frontend, requests
  after closure must create a new frontend, parent termination must follow all
  children, and RPM-family behavior must remain unchanged.

### Loop 17 rendered-data closure

The first post-commit hard probe caught a second entry path before blind review:
explicit-proxy repair materialized APT method helpers as system connection owners
without registering their one-shot finalizers. Those helpers were closed only by
later lifecycle cleanup, stretching both helper and parent intervals for hours.
The family fix now registers bounded helper closure at the canonical system-owner
boundary and extends the serialized APT frontend just beyond its last helper.
The next rendered probe exposed a higher-priority consumer of the same state:
hourly stale-process cleanup ignored registered foreground deadlines and replaced
them with its generic 30-minute-to-hours policy. Stale cleanup now consumes the
canonical bounded deadline when present, and out-of-order generation anchors a
deadline to the actual process start rather than an earlier intent timestamp.
