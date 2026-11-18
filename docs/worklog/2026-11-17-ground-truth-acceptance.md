# Ground-truth acceptance for 3.0 (November 17)

## Current handoff

P0 release blocker: the unchanged canonical `scenarios/iteration-test` benchmark (seed 42,
default target) must meet the 95% schema-v5 Ground Truth Agreement gate. Work is on branch
`chore/3.0-release-blockers`, uncommitted. Generated bundles live under the ignored
`scenarios/iteration-test/blind-test/gt-recheck-20261117/`.

| Run | Behavior | Records | Agreement | Overall | Incorrect checks |
|---|---|---|---|---|---|
| Loop 95 (Nov 11) | 509 | 147,759 | 88.36 | 94.61 | 2,831 |
| Re-run on dev | 522 | 139,906 | 88.32 | 96.52 | 1,928 |
| `r523b` (this branch) | 523 | 143,433 | 92.24 | 97.54 | 413 |
| `r524` + NAT root match | 524 | 143,433 | 93.59 | 97.81 | 400 |
| `r525` | 525 | 143,433 | 94.98 | 98.10 | 341 |
| `r526` | 526 | 143,433 | **96.37 (PASS)** | 98.37 | 327 |

The agreement score is the mean of 222 per-action scores, so many small actions with one to
three misses dominate; failure counts alone do not predict it. Diagnostics used an evaluation
wrapper that removes the 100-finding sample cap (diagnostic only, not committed).

## Repaired in behavior revision 523

1. **Firewall path ownership.** `VisibilityEngine` treated a firewall like a tap and ignored its
   interface map, so segments sharing one ASA interface (`corporate_lan`/`server_vlan` →
   `inside`) were "observed" although the ASA never forwards them; the emitter then rendered
   nothing. `firewall_traverses()` now owns the rule (different interfaces, or a static-NAT VIP
   including hairpin). Observation, source-side denies and baseline policy enforcement use it;
   the evaluator's independent `_sensor_visible` mirrors the declared interfaces.
2. **ASA NAT view.** Ground-truth sensor views now carry the observation's NAT receipt
   (`GroundTruthNatView`). ASA requirements use real endpoints for Built/Teardown and the mapped
   address only on Built rows, matching the emitter.
3. **ASA ICMP contract.** ICMP used to fall through to UDP 302015. Requirements now use
   302020/302021 without ports; the parser exposes faddr/gaddr/laddr and pairs teardowns with
   their Built direction by native address triple.
4. **eCAR FLOW endpoint view.** One shared helper pair (`endpoint_local_destination_ip`,
   `ecar_flow_endpoint_fields` in `events/evidence_source_rules.py`) now drives both the eCAR
   emitter and the projection: responders see their real address behind static NAT, and ICMP
   FLOW rows carry no ports.
5. **Host-clock-aware predecessor proofs.** Endpoint clocks drift up to ±8 ppm without resync,
   so warm-up parents born weeks earlier carry several seconds of skew. Timing receipts now name
   `clock_adjustment_us` for predecessor births; the proof verifies `anchor − (start + adjustment)`
   against the declared eCAR create-latency bound instead of a flat ±2 s window.

## Repaired in behavior revision 524 (user chose "record derived argv")

6. **Authored command derivations.** `ProcessContext.command_derivation` (provenance, excluded
   from identity/equality) records the authored command and ordered, parameterized rules:
   `placeholder_substitution`, `posix_shell_argv`, `posix_shell_program`, `catalog_direct_exec`,
   `windows_process_normalization`, `macos_launch_descriptor`. The rule functions in
   `generation/command_derivation.py` are the implementations generation now calls; the
   evaluator accepts a native command only when replaying them from the exact authored text
   reproduces it. Storyline handler, Finder/direct exec, Windows actor normalization and the Mac
   browser helper record their steps. Typed-fact disagreements fell from 13 to 3.
7. **NAT-served authored destinations (evaluator).** Authored connections naming the real server
   behind a static-NAT VIP now match through `endpoint_local_destination_ip`; the remaining
   three typed-fact disagreements cleared.

## Repaired in behavior revision 525 (eCAR session/file residue)

8. **Samba session identity.** Samba sessions have no Windows logon ID; the emitter keys them by
   `auth_session_ref`/`smb.session_id`. Shared `ecar_samba_session*` rules now drive both the
   emitter and the USER_SESSION projection.
9. **SMB file paths.** SMB occurrences also carry a generic `file` context, which the FILE
   projection preferred, losing `server_path` and sending the server path to clients. SMB facts
   now take precedence, so server rows use `server_path` and client rows `client_path`/`local_path`.
10. **Stale eCAR action contract.** `process_access` and `create_remote_thread` now use the native
    `PROCESS/OPEN` and `THREAD/REMOTE_CREATE` actions the emitter and format docs use.
11. **No-source placeholder.** A failed logon's `-` source is no longer a `src_ip` selector (the
    parser normalizes it to null).
12. **Receipt-less timing points (evaluator).** Points for rows without a process receipt use the
    recorded window `admission_time`; the old `expected_time − delay` reconstruction matched no
    session anchor in the bundle (593 match admission exactly).

eCAR missing evidence fell from 62 to 0. Remaining anchor proofs (traced through the real
evaluator) are generation-side: in-window `parent_create` anchors on Mac SSH forks differ from
the parents' published create receipts (likely a later visibility-floor repair of the cached
create time), `runas` children pair the interactive group's login time with the new-credentials
logon ID, and a few frontier/children anchors have no matching point.

## Repaired in behavior revision 526 (history clears; user kept the destruction rule)

13. **Canonical history destruction.** `config/activity/shell_history_effects.yaml` (overlayable
    `append-list` family) owns the destructive-command patterns. Bash/zsh history producers record
    `ShellContext.history_effect` on the occurrence; the emitter's clear check applies the same
    function to the same canonical command (no journal or exact-publication envelope change).
    Ledger finalization marks entries destroyed by a later admitted clear of the same file absent
    (`retention` stage, `destroyed_by_later_action`, `provenance.retention.destroyed_by`); the
    evaluator builds its own clears index and requires exactly those exclusions. Rendered history
    is byte-identical; 14 expectations became verified absences.

The canonical benchmark now passes acceptance (agreement 96.37 against 95; overall 98.37).

## Remaining scope (r523b, updated by r524-r526)

At r525 (94.98), single-family estimates: bash history 96.38, Windows Security 95.83, timing
anchors 95.54, ASA 95.52, authored facts 95.50, syslog 95.39.


After r524, the cumulative estimate is eCAR residue 95.60 → + eCAR timing 95.99 → + ASA
96.53 → + bash history 98.44. The authored-command family below is resolved.


Estimated agreement if each family were fully resolved (proportional attribution, cumulative):
eCAR residue 94.25 → + ASA residue 95.18 → + authored typed facts 97.03 → + bash history 98.44.

- **Authored shell syntax vs native argv (13 actions, ~+1.9).** Authored commands are shell
  syntax; canonical facts hold exec argv (quotes removed, redirections dropped, `bash -c`
  wrapping, Mac helper `--seatbelt-client=3`, PSEXESVC normalization). Owning fix belongs with
  the P1 canonical shell execution model: derive native argv once, record the derivation in
  ground truth, and verify it. Needs a design decision.
- **History destroyed by later authored clears (14 actions, ~+1.4).** evt-028/evt-029 shred or
  clear root history; the emitter correctly drops earlier entries, but expectations stay
  `present`. Move `_CLEAR_PATTERNS` to shared source rules and mark destroyed entries absent at
  truth finalization.
- **eCAR residue (18 actions, ~+2.0).** USER_SESSION LOGIN/LOGOUT (mac-2-login, evt-022b),
  FILE READ/WRITE (rh-007, rh-008, evt-023b), plus the session-anchor receipts: anchors are keyed
  by lifecycle group while the proof keys sessions by the process `logon_id` (runas new
  credentials, SSH fork, RDP with empty logon ID). Not yet diagnosed in detail.
- **ASA scan denies to VIP (1 action).** evt-001 denied probes to 203.14.220.10 render no
  106023 rows; pre-existing.
- Smaller: Windows Security unjustified source time / missing, syslog unexpected expectations,
  proxy, Zeek DNS (SRV projection still requires `priority weight port host`; HTTP CONNECT
  expectation on plain HTTP is still set at `generator.py` `tunnel_status_code`).

## Release slow-tier findings (November 18)

The rc1 slow tier on the gated `dev` tree passed 2,228 cases and failed four; the coverage gate
passed at 78.75%. Three macOS SSH cases bisected to 447a7087. Its corrected firewall traversal
rule removes firewall-observation draws for traffic the firewall never carries, which moves every
later draw from the shared generation stream. An unauthored SSH session's sampled duration moved
with it: the client held the shell until 10:29 instead of 10:22. Reverting only the rule restores
the old outcome, so the tests, not generation, were fragile: they asserted released, still-open
or checkpoint-open sessions without authoring the end they depended on. They now author that
close, or (for the unauthored-close checkpoint case) require the session through the checkpoint
with a later in-step command while its end stays sampled with no owner. The shared stream feeds
85 call sites in 12 generation modules; any unrelated draw change can move unauthored samples.

The fourth case asserted that a warm-up transport with visible SSH members must be rejected,
the shape eb3d85fc admits. History says only that the rejection was preserved. It is replaced by
a positive test (only the in-window receiver process and login render; no FLOW or Zeek row) and
fail-before/lost-return eCAR sink recovery that drains exactly once.
