# Human-only controlled launcher experiment

Use a **new prepared kit**, never an earlier kit containing private evidence. Agents may prepare
code and run invented-input tests. Only you run the commands below, with agents closed. Do not
share native records, paths, own-process snapshots, transcripts or screenshots.

This extends the successful Finder experiment to the missing **first xpcproxy activation**.
The default launcher setup adds **no synthetic entitlement**. In the October 30 collector-free
diagnostic, the variant signed with the synthetic marker was killed, while the same diagnostic
without that marker passed. Explicit DER generation did not fix it. No system/security policy
was changed, and no security log was inspected to attribute the kill to a specific component.
The separate marker experiment must not block launcher collection.

The probe reads only its own identity/descriptors, opens its small temporary window and exits;
it reads no personal documents and makes no network requests. No server, download, new privilege,
historical log read or system/security setting change is needed.

Apple documents an XPC dictionary or NULL for
[exec entitlements](https://developer.apple.com/documentation/endpointsecurity/es_exec_entitlements(_:)).
That does not establish eslogger's JSON representation. This diagnostic returns fixed
representation labels for the observed entitlements. It does not enable native generation.
The separate `setup --launch-chain --synthetic-entitlement` option requests only the fixed marker
`org.evidenceforge.reference.synthetic: true`; do not use it for this launcher collection. The
setup/provenance and report explicitly retain whether the marker was requested. Older manifests
without that field retain an unknown choice, rather than inventing an absent marker.

The collector's machine-wide stream remains transient in the existing bounded filter. In this
opt-in variant, a second ring holds at most 64 xpcproxy exec candidates and 4 MiB **in memory**.
It spans readiness, control and Finder phases, because a matched launcher's activation can
precede the manual Finder step. Older kits buffered launcher candidates only during Finder;
their missing-prefix result cannot distinguish that blind spot from other causes.
A candidate is written only after the controlled app's exact device/inode proves ownership
and its preimage matches the candidate's full eight-word audit token, PID version, birth time,
native file object and code identity. A preceding fork is retained only if its full child token
and lifetime match that same launcher preimage. No PID-only or path-only persistence is used.
Unrelated candidates are discarded. The original fork ring remains capped at 64 rows/4 MiB;
the entire stream remains capped at 32 MiB and retained evidence at 16 rows per case.

Matched launcher/app records can still contain sensitive environment, ancestry and identity
values. They remain private in the owner-only kit outside Git. The exported report contains
only fixed classes/comparisons, including whether the known synthetic marker agrees. Native
entitlement names/values and arbitrary input strings are never exported. OS swap/crash reports,
backups and existing endpoint software remain separate from this filter's persistence controls.

## Procedure

1. In a standalone Terminal, change to the **new prepared kit folder**. Keep every old capture
   untouched. Build as your normal user:

   ```sh
   /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B private_gui_launch.py setup --launch-chain --private-run
   ```

   Expect `kit_version: 2`, `synthetic_entitlement: false`, `stage: SETUP_READY`, `error: NONE`.
   This builds/signs only the
   test app and collector guard; it starts no collector and launches no app. If setup fails,
   keep the fixed error report and use a fresh kit rather than replacing private files.

2. Open this kit in Finder. Select `GUIProbe.app` without launching it. Leave Finder beside
   Terminal. Close Codex and other agents before collecting.

3. Run as your normal user, preserving `&&`:

   ```sh
   sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B private_gui_launch.py capture --finder --private-run
   ```

   Only the fixed internal collector guard uses sudo. Never put sudo before Python. Do not
   add `tee`, shell tracing or recording wrappers.

   Run this command only once, in one Terminal. An existing `SESSION-LOCK` returns
   `SESSION_LOCKED` before starting any collector; older copies report `INCOMPLETE` with
   default inconclusive fields instead. Stop the earlier attempt with one Ctrl+C and wait
   for its prompt and cleanup result. Do not delete the lock or modify an old capture to
   force a retry. If cleanup failed or the earlier attempt is unavailable, wait for the
   55-second collector watchdog and cleanup interval to finish, then use a newly prepared
   kit. A fresh setup alone does not establish that an older collector has stopped.

4. The command first runs a short **non-GUI** probe check without a collector. A killed,
   failed or timed-out probe reports `PROBE_KILLED`, `PROBE_FAILED` or `PROBE_TIMEOUT` at
   `PROBE_CHECK`, before opening capture files or starting eslogger. Stop on those errors;
   do not change security policy or retry with the synthetic marker. Readiness also requires
   successful native and subprocess exit status, rather than accepting any exec/exit pair.

   Wait for `COLLECTOR_READY`; the command-line control window appears and closes itself.
   Wait for the distinct `FINDER_READY` message, then double-click the app in Finder within
   30 seconds. Its second small window closes itself. No policy alert is expected; stop
   rather than overriding one. The guard's 55-second watchdog and existing cleanup apply.
   One Ctrl+C requests cleanup. Keep agents closed if `collector_cleanup` fails, let the guard
   expire and resolve cleanup privately before another attempt.

5. Review the final fixed JSON. `error: NONE`, `collector_cleanup: PASS`, collection controls
   and `launch_chain` are the relevant diagnostics. A nonzero, killed, timed-out or
   non-completing automatic control now reports a specific `CONTROL_*` error. The current
   production codec still rejects populated entitlements, but this default variant adds no
   marker; do not automatically dismiss a shape failure as expected. The
   `*_shape_excluding_entitlements` checks deliberately isolate that one field and are
   **not** a full shape pass or a generation admission decision. No fork retained means
   `NOT_RETAINED`; it never proves that no fork happened.

   A missing Finder completion before its deadline reports `FINDER_TIMEOUT` with stage
   `FINDER_READY`. A failure before starting the collector reports sequence continuity as
   inconclusive, rather than claiming a pass on an empty stream.

6. Share only the reviewed fixed JSON. If needed, rerun the offline-only reporter as your
   normal user while agents remain closed:

   ```sh
   /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B private_gui_launch.py report --private-run
   ```

   This reads only this kit's bounded current capture and provenance; it starts no collector,
   app or live role query.

## Offline supplement for an existing capture

A separately prepared version-5 reviewer supports both original app-only and launcher-chain
kits. Do not copy it over the original helper or run setup in a used kit. From the new
reviewer directory, run `private_gui_launch.py review-existing --private-run` with the same
isolated Python command. At its hidden prompt choose the original outer kit, not its run
subfolder. Share only the fixed JSON. No sudo, collection, app launch, role query or file
mutation occurs during review.

The supplement classifies the already-retained app preimage, environment changes and whether
its process lifetime began before, during or after the control lifetime. These are relationship
labels; no timestamps, identifiers, private names or values are exported. It also preserves
the retained launch-chain result. `NONE` still does not establish no launcher exec: a reviewer
cannot reconstruct the discarded transient ring, prove a collection subscription time from a
control timestamp, or justify a fabricated missing phase. Review the existing capture before
considering another collection.

The result may qualify the bounded controlled launcher after review and tests. Populated
entitlement qualification remains separate. It does not by itself qualify Terminal, vendor entitlements,
services, PTY helpers, Dock, Spotlight or Unified Log families.
