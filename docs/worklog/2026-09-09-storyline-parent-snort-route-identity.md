# Storyline Process References and Sensor Route Identity

## Scope

Root-cause repairs for the two remaining correctness findings reproduced from the rc2 TEST1
scenario in `~/TEMP/eforge_report`.

## Family contracts

### Authored process-reference lifecycle

- **Owner:** storyline scheduling owns authored dependency order; canonical process state owns
  whether a referenced process is live; emitters only render the resulting process context.
- **Invariant:** a `parent_ref` either resolves to the exact live process named by the earlier
  `process_ref`, or the authored child fails closed. It must never silently acquire an inferred
  shell parent.
- **Lifecycle:** a named process remains live through its last explicit `parent_ref` consumer and
  through a later `process_access` or `create_remote_thread` that implicitly selects the most
  recently named process on the same actor and host. Its termination may follow that dependent,
  even when the ordinary executable lifetime estimate is shorter.
- **Ordering:** equal nominal timestamps preserve authored scenario order after jitter. A child's
  actual process-create time must follow its referenced parent's actual process-create time.
- **Entry paths:** full storyline execution and hour-interleaved storyline execution share the
  same retention and ordering contract. Red herrings may not prematurely release retained
  storyline processes.
- **Consumers:** Windows Security 4688, Sysmon 1/5/8/10, eCAR process/thread/open records,
  canonical process state, ground truth, checkpoints, and later process-owned effects.
- **Sibling regression:** ordinary unreferenced short-lived processes still terminate normally;
  stale or missing explicit references still fail closed rather than fabricating lineage.

### Canonical sensor route identity

- **Owner:** `SourceInstanceIdentity` owns normalized source identity. Emitter setup consumes that
  identity before creating any sensor-native output route.
- **Invariant:** one configured sensor has one hostname identity and one physical output path,
  regardless of authored letter case or host filesystem case sensitivity.
- **Safety:** Snort exact-publication collision detection remains strict for genuinely distinct
  sensors. The repair removes the raw/canonical alias for one sensor; it does not multiplex or
  weaken ownership checks.
- **Entry paths:** Snort, Zeek, and Cisco ASA sensor emitters receive the same canonical hostname
  spelling used by deployment compilation, observation envelopes, checkpoint state, and exact
  publication.
- **Consumers:** emitter route maps, sensor interface maps, network visibility, source projection,
  exact publication, output directory naming, and cross-platform generation.
- **Sibling regression:** two genuinely distinct sensor identities continue to produce distinct
  output routes and retain independent ownership.

## Confirmed pre-fix reproductions

- TEST1 independently jittered `evt-003` before equal-time `evt-002`; `invoiceviewer` was already
  removed from live process state when its child resolved `parent_ref`. The child silently fell
  back to `explorer.exe`, `schtasks.exe` later fell back to `cmd.exe`, and `evt-006` recorded
  `no_live_source_process`.
- TEST1 configures one Snort sensor as `IDS-NG-EDGE`. Deployment projection canonicalized it to
  `ids-ng-edge`, while emitter setup retained the authored case. On a case-insensitive filesystem
  both logical strings claimed the same inode, correctly tripping Snort's exact-output collision
  guard. A case-sensitive filesystem masked the same identity split by creating two directories.

## Verification record

- Added focused contracts for exact authored parent preservation, stale-reference rejection,
  implicit process-access retention, canonical sensor emitter routes, and checkpoint round trips.
- Regenerated the exact rc2 TEST1 scenario across every requested format. The resulting process
  chain is `explorer.exe` -> `InvoiceViewer.exe` -> `powershell.exe` -> `schtasks.exe` with exact
  PIDs preserved, and the later Sysmon process-access row attributes LSASS access to that same
  PowerShell PID. Ground truth contains no skipped intents.
- The generated sensor tree contains only canonical `ids-ng-edge`, `fw-ng-edge`, and
  `zeek-ng-core` directories. The Snort route no longer collides, while strict collision tests for
  distinct owners still pass.
- Recursively checked both ground-truth UID references: 2 unique references, 0 missing from the
  generated data.
- Deterministic evaluation of 48,234 records across 17 sources scored 95/100 and passed acceptance:
  event presence 9/9, causal ordering 100, intent reconciliation 100, and IDS integrity 100.
- `uv run python scripts/check_generation_behavior.py --base-ref HEAD`: revision 6 and behavior
  digest `3afa9eb858b48576f263f55c1ceada082faa686d41fb6ef27495b0f40798996f` validated.
- Full default suite: 8,308 passed, 5 skipped, 2,008 deselected.
- Full slow release tier: 1,779 passed, 8,542 deselected (`--no-cov`).
