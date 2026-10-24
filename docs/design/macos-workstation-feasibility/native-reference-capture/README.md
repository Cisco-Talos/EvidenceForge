# Private native reference testing

**Status, 2026-10-24: the user reports a successful bounded v11 capture through
the version-3 fixed report. Full v11 layout qualification remains pending.
No agent-run capture or native-record inspection is authorized.**
Native exec/exit (ES-R1) and Gatekeeper denial (GK-R1) remain gated. This kit
supplies no reference evidence by itself. The Mac fork/v10 benchmark runs
independently. The user's overriding requirements are that no potentially
sensitive information is seen by the agent and no captured logs enter the repo.

Read [PRIVATE-RUN.md](PRIVATE-RUN.md) for the human procedure and privacy limits.
The helper is [scripts/macos_reference_capture.py](../../../../scripts/macos_reference_capture.py).
Agents may run `prepare` and invented-input tests, **never `preflight` or `capture`**. Preparation
copies only code and instructions to a new private directory outside Git.

```sh
UV_CACHE_DIR=/private/tmp/eforge-macos-316-uv-cache uv run --no-sync python scripts/macos_reference_capture.py prepare
```

Do not run the old full-stream capture proposal. The human-run filter keeps only
the exact probe family, using PID version and start time as well as PID. Raw
matched rows and provenance remain private outside Git; the agent receives only
human-reviewed fixed check codes. A candidate field check does not open a gate.
The human-only `preflight` command distinguishes root-user, OS-family,
Python-process-architecture and malformed version-output errors using fixed codes without
compiling, collecting, writing data or disclosing actual platform values.
Reference acquisition no longer requires OS major 26; macOS 27 can be tested
privately. The actual build stays in private provenance. Matched message headers
select the candidate check; unsupported or mixed versions remain unqualified,
without rewriting records, claiming cross-version equivalence or opening a
production source gate. The version-3 fixed report explains this distinction;
see PRIVATE-RUN.md for `wire_profile` and `WIRE_PROFILE` outcomes.

The version-3 kit waits for an observed warm-up fork/exit before starting the
four cases, replacing the old half-second startup assumption. Fixed checks
distinguish stream delivery, full probe identity, exact executable ownership and
readiness without exporting native values. Acquisition recognizes explicit
array/named/val audit tokens and string/timeval births; executable aliases must
match file objects sampled only for the two planned test images. Unknown full
wire layouts remain unqualified. No earlier private directory may be inspected
or modified by an agent during troubleshooting; prepare a fresh code-only kit.

The user-reported version-3 run passes every controlled behavior and delivery
check, with `V11_UNQUALIFIED`, `WIRE_PROFILE` and inconclusive full message
shapes. This is successful acquisition for the bounded experiment, not full
wire qualification or production source admission. Do not repeat collection
solely for WIRE_PROFILE. The next step is a separate human-run offline checker
for the existing private capture's complete v11 layout; that checker has not
yet been implemented. Keep the user's macOS 27 evidence distinct from macOS 26
coverage. See the [handoff](../../../worklog/2026-10-24-macos-private-reference-kit.md).

## Required lab and permission

No VM is available. A clean external installation with personal volumes unmounted
provides stronger separation; a separate account alone does not isolate the
system-wide stream. A daily-use Mac can process unrelated activity locally even
when a filter discards it before disk. The user must run and review privately.
Do not read older archives,
personal logs, shell history, browser history, application inventories or other
accounts. No production device or service changes are part of this proposal.

The lab must already have the access needed by `/usr/bin/eslogger`. If collector
access or Full Disk Access is missing, stop and ask before changing permissions.
Do not disable Gatekeeper, SIP, quarantine enforcement or trust checks.

## Prepared artifacts

- `process_probe.c`: harmless fork/exec, normal exit 7, SIGTERM termination,
  returning failed-exec and Apple `/usr/bin/true` controls. Its stdout is a private
  JSON protocol containing only case, PID and independently observed wait/errno.
  Before the cases, a bounded parent-controlled warm-up can fork/reap without exec.
- `launch_marker.c`: harmless app executable whose sole effect is creating one
  caller-specified marker file. A marker proves that code actually ran; its
  absence alone never proves a policy denial.

Both sources are independently authored. They have been compiled for syntax and
warnings only; neither has been run for this proposal. Their compiled programs
are temporary and are not product binaries or reference evidence.

## ES-R1: bounded human-run process experiment

Follow PRIVATE-RUN.md. The script checks the target platform privately, compiles
the probe, captures via a pipe into a bounded in-memory filter, retains only
unmodified matched records, compares their lifecycle with probe controls and
writes private provenance plus a fixed shareable report. No historical logs,
host inventory, network service or automatic permission changes are involved.

Do not require that a failed exec produce an exec notification. Record the actual
result. Kernel delivery, export filtering and observed absence remain distinct.

## GK-R1: future, separately reviewed human-run protocol

The following describes the evidence needed, **not commands authorized for agent
execution or a procedure ready to run on a daily-use Mac**. A private collector,
item-specific filter and fixed report checker must be prepared before this stage.

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

The human reviews native writer paths, message shape and process consequences
privately; the agent never opens the captures.
Do not infer a named security-product decision from a numeric result alone.

## Retention and use

Keep every native capture and private provenance outside all Git trees. No
copies into ignored `sample_data/macos/`, fixtures, worklogs, attachments or CI
artifacts. No raw or redacted record sharing with agents. Only human-reviewed
fixed reports may be shared. Captured records do not become fixtures or product
templates; new tests remain independently authored. Human verification of
private evidence must be distinguished from an agent personally inspecting it.
