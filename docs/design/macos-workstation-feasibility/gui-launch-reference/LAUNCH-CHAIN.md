# Human-only controlled launcher and entitlement experiment

Use a **new prepared kit**, never an earlier kit containing private evidence. Agents may prepare
code and run invented-input tests. Only you run the commands below, with agents closed. Do not
share native records, paths, own-process snapshots, transcripts or screenshots.

This extends the successful Finder experiment to the missing **first xpcproxy activation**.
It also signs the same harmless local probe with one fixed synthetic marker entitlement,
`org.evidenceforge.reference.synthetic: true`. The marker requests no Apple service or security
capability. The probe still reads only its own identity/descriptors, opens its small temporary
window and exits; it reads no personal documents and makes no network requests. No server,
download, new privilege, historical log read or system/security setting change is needed.

Apple documents an XPC dictionary or NULL for
[exec entitlements](https://developer.apple.com/documentation/endpointsecurity/es_exec_entitlements(_:)).
That does not establish eslogger's JSON representation. This diagnostic compares the known
marker locally and returns fixed representation labels. It does not enable native generation.

The collector's machine-wide stream remains transient in the existing bounded filter. In this
opt-in variant, a second ring holds at most 64 xpcproxy exec candidates and 4 MiB **in memory**.
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

   Expect `kit_version: 2`, `stage: SETUP_READY`, `error: NONE`. This builds/signs only the
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

4. Wait for `COLLECTOR_READY`; the command-line control window appears and closes itself.
   Wait for the distinct `FINDER_READY` message, then double-click the app in Finder within
   30 seconds. Its second small window closes itself. No policy alert is expected; stop
   rather than overriding one. The guard's 55-second watchdog and existing cleanup apply.
   One Ctrl+C requests cleanup. Keep agents closed if `collector_cleanup` fails, let the guard
   expire and resolve cleanup privately before another attempt.

5. Review the final fixed JSON. `error: NONE`, `collector_cleanup: PASS`, collection controls
   and `launch_chain` are the relevant diagnostics. The current production codec rejects
   populated entitlements, so the older app-only `native_shapes: FAIL` is expected in this
   variant. `*_shape_excluding_entitlements` deliberately isolates that one field and is
   **not** a full shape pass or a generation admission decision. No fork retained means
   `NOT_RETAINED`; it never proves that no fork happened.

6. Share only the reviewed fixed JSON. If needed, rerun the offline-only reporter as your
   normal user while agents remain closed:

   ```sh
   /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B private_gui_launch.py report --private-run
   ```

   Use `report`, not the older v4 `review-existing` command. This reads only this kit's bounded
   current capture and provenance; it starts no collector, app or live role query.

The result may qualify the bounded controlled launcher and entitlement representation after
review and tests. It does not by itself qualify Terminal, arbitrary vendor entitlements,
services, PTY helpers, Dock, Spotlight or Unified Log families.
