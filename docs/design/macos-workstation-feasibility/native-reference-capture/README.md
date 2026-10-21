# Proposed bounded native reference capture

**Status: prepared for review; capture is not authorized or running.** This closes
the remaining reference questions ES-R1 and GK-R1, not general workstation
calibration. The Mac fork/v10 benchmark can run independently.

## Required lab and permission

Use a disposable macOS 26 arm64 VM or a separate clean lab account containing only
invented names/files. Specify the exact lab before collection. The user's existing
instruction prohibits local-log inspection without asking first; approval must
name this bounded capture and the resulting directory. Do not read older archives,
personal logs, shell history, browser history, application inventories or other
accounts. No production device or service changes are part of this proposal.

The lab must already have the access needed by `/usr/bin/eslogger`. If collector
access or Full Disk Access is missing, stop and ask before changing permissions.
Do not disable Gatekeeper, SIP, quarantine enforcement or trust checks.

## Prepared artifacts

- `process_probe.c`: harmless fork/exec, normal exit 7, SIGTERM termination, and
  returning failed-exec control. Its own stdout labels PID, case, wall time,
  Mach ticks, timebase and raw child wait status.
- `launch_marker.c`: harmless app executable whose sole effect is creating one
  caller-specified marker file. A marker proves that code actually ran; its
  absence alone never proves a policy denial.

Both sources are independently authored. They have been compiled for syntax and
warnings only; neither has been run for this proposal. Their compiled programs
are temporary and are not product binaries or reference evidence.

## ES-R1: one short process experiment

1. Create a new empty directory in the approved lab, outside the repository.
   Record `sw_vers`, `uname -m`, exact collector command, UTC start/end, privacy
   settings and redaction decisions in a text provenance file. Hash both probe
   sources and compiled executables.
2. Compile `process_probe.c` there with `clang -std=c11 -Wall -Wextra -Werror`.
3. Start `/usr/bin/eslogger fork exec exit` in the approved lab, redirecting complete
   unmodified NDJSON to that new directory. This ordinarily needs elevated access.
4. Run the probe once, saving only its own labeled stdout/stderr beside the capture.
   Stop the collector immediately after completion; target capture is under 20 s.
5. Inspect only these newly created files after approval. Identify probe-related
   records by the recorded parent/child PIDs and birth times. Retain full nested
   native records, not an abbreviated field extraction. Check message versions,
   audit token shapes, parent/responsible roles, null/absent fields, descriptors,
   image replacement and raw exit status against the independently observed cases.

Do not require that a failed exec produce an exec notification. Record the actual
result. Kernel delivery, export filtering and observed absence remain distinct.

## GK-R1: successful control and actual rejected launch

1. Build a minimal `.app` around `launch_marker.c` in the same approved lab. Supply
   one marker path under the new capture directory via the launch argument. Record
   the app's hash, bundle metadata and signing assessment for that exact app only.
2. Launch the local control using the chosen method (`open`/LaunchServices or direct
   execution) and verify its marker. Record the precise method and outcome.
3. Download a zip of the same harmless app through the lab browser from an approved
   test URL. A loopback-only temporary server may be proposed separately if needed.
   Preserve the OS-created quarantine attributes and compare executable hashes.
4. Start a short live Unified Log stream limited to the relevant policy writers
   (for example `syspolicyd`, `amfid`, `runningboardd`) and ES exec/exit subscriptions.
   Pin the exact predicates/commands to the approved lab's supported CLI options.
5. Attempt the same launch without bypassing a rejection. Save the terminal result,
   full newly collected records and marker outcome. An allow, prompt, user cancel,
   timeout, crash or collection failure does **not** satisfy the denial gate. Stop
   rather than forcing or repeatedly changing the environment to obtain a denial.

Review native writer paths, message shape and actual process consequences together.
Do not infer a named security-product decision from a numeric result alone.

## Retention and use

Keep raw captures outside Git in the approved lab directory until reviewed. Any
copy into ignored `sample_data/macos/` needs an explicit path and preservation/
redaction record. Captured records do not become fixtures or product templates;
new tests remain independently authored. Approval of this proposal does not
authorize unrelated captures or committing personal/native records.
