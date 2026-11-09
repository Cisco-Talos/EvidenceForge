# Private launchd Unified Log reference

Preparation copies public code to a fresh mode-0700 directory under `/private/tmp`.
It reads no captures and runs no native commands. Setup and capture are human-run;
the agent must not start them under the existing privacy boundary.

This checks one temporary system job with an unpredictable generated label. The
existing restricted job guard creates an exact root-owned temporary plist, registers
it without `RunAtLoad`, starts `/usr/bin/true`, then removes the job and plist. It
does not enable/disable services, install in startup directories, inspect real jobs
or boot out an entire domain. Every child launchctl command has a deadline; the
guard has a separate cancellation/watchdog cleanup path. Machine failure/SIGKILL or
launchctl failure can still prevent cleanup and must not be reported as success.

The version-2 normal-user `log stream` predicate selects only launchd rows containing
that generated label in `eventMessage` or `category`, plus an own-process readiness
marker. Retention independently requires PID 1, `/sbin/launchd` and the exact generated
label in one of those same fields. Unrelated input is
discarded in memory. Input, record and total-time limits are fixed. No ES collector,
browser, SSH connection, real app or installed-code query is used. Native rows stay
in this private kit, never in the repository. Reports contain only fixed labels and
bounded counts. Unknown subsystem/category/format/message values are not disclosed.

## First verify job controls without collection

The next requested run is the version-4 collector-free control test. Use only the
fresh control kit supplied in chat; older kits remain unchanged. Run as your normal
user in one window:

```sh
cd CONTROL_KIT
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ulf_launchd.py setup --private-run
```

Continue only for SETUP_READY/NONE:

```sh
sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ulf_launchd.py self-test --private-run
```

This executes only the restricted temporary-job guard. No ES/ULF collector or
readiness marker starts, no job query runs and no native record is opened. The
guard keeps its cancellation pipe open through normal completion, requests the
same fixed `/usr/bin/true` job, and performs exact-label removal and file cleanup.
Each launchctl command retains its deadline and the guard retains its watchdog.
The returned JSON is also saved as SHAREABLE-ACTIVATION-REPORT.json. Share only that
fixed report, including failures. Unknown command output and numeric error values
are suppressed. A `control_failures` entry identifies a fixed stage and coarse
reason, for example DIRECTORY_CREATE/PERMISSION_DENIED or REGISTRATION/COMMAND_EXIT.

PASS requires all creation, lease, registration, activation, job-removal and file-
removal fields PASS, guard_exit ZERO and result PASS. Activation here means the
launchctl acknowledgement; native execution evidence remains NOT_COLLECTED and
gate_status stays NOT_EVALUATED. A timeout or signal cannot pass based on success-
looking status text. Failed cleanup remains unverified and requires its own fixed
report; do not delete the kit.

The attempt marker makes this kit one-use and prevents later capture in it. Even a
passing test needs a separate fresh capture kit. Do not run the capture instructions
below until the control report is reviewed and a fresh kit is supplied. No new
capture is requested by preparation or a passing control test alone.

## Capture in a separate fresh kit after the control test

Use the fresh kit path supplied in chat as `KIT`. Close agents before collection.
These are separate commands; the entire Python helper must not run under sudo.

```sh
cd KIT
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ulf_launchd.py setup --private-run
```

Continue only for `stage: SETUP_READY` and `error: NONE`. Setup compiles controls
without executing them. It reads no native records. Then:

```sh
sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ulf_launchd.py capture --private-run
```

One window only. Readiness normally appears within eight seconds; the collector
window is at most 35 seconds, followed by bounded cleanup. No dialog, additional
command, browser action or password entry after `sudo -v` is expected. The helper
automatically prints fixed JSON. Share only that JSON, or the saved
`SHAREABLE-ULF-REPORT.json`; do not share native rows, screenshots or private paths.
The saved fixed report can be printed again with:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ulf_launchd.py report --private-run
```

`gate_status: NOT_EVALUATED` is expected. An empty result or `OTHER` classification
does not qualify a template. This is a finite shape diagnostic, not automatic
permission to enable launchd generation. SSH ULF qualification is a separate bounded
reference; this test does not establish SSH messages.

`collector_ready: PASS` proves only the own-process marker channel. It does not prove
that launchd writes to ULF or that the reader can observe launchd's output. Version 2
states this as `readiness_scope: OWN_PROCESS_MARKER_ONLY`, reports message/category
label matches separately and labels empty retention as `NO_MATCHING_ROWS`.

The first human-run version-1 attempt completed every control and cleanup but
retained zero rows. It selected the label only in message text, so it could not
test category-labelled output. The corrected-selector attempt subsequently failed
activation controls; the grouped read-only check verified its directory and exact
service absent. That attempt does not establish ULF visibility. **Do not repeat
collection solely to turn a zero into a positive result.** The [reference note](REFERENCE.md) records the limitation
and the distinction between ULF and launchd's separate diagnostic file.

If removal or temporary-file cleanup fails, retain the kit and report only those
fixed statuses. Run the exact-label recovery as your normal user:

```sh
sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ulf_launchd.py cleanup --private-run
```

This starts no collector or new job, performs no job query, and cannot remove an
entire domain. Do not delete the kit or assume the job is absent. A cancelled run
must not be reused for a second capture; prepare a fresh kit after resolving cleanup.

Version 3 treats failed job controls or nonzero guard exit as CONTROL/ERROR with
CONTROL_INCOMPLETE, never a valid empty-source observation. Cleanup returns the
guard's allowlisted literal status and a cached-sudo comparison; unknown command
output remains hidden. If a used older kit hides the failure stage, the current
repository helper supports `cleanup --kit-root KIT --private-run`. This validates
the original kit's control hashes and runs its original exact-label cleanup guard,
without changing the kit or reading records. `--kit-root` is forbidden for setup,
capture and report. Do not replace files or rerun setup in the used kit.

If cleanup reports `sudo_credentials: PASS` and `job_control: LOCATION_FAIL`, the
root guard ran but could not validate the exact directory or recovery lease. This
can also mean the directory is already absent; it does not prove leftovers exist.
Use the current repository helper's `check-cleanup --kit-root KIT --private-run`
only when requested. Run Python as your normal user after `sudo -v`. This groups
directory ownership/mode, lease type/linkage/content and exact system-service
existence comparisons. It compiles a temporary inspection helper outside the used
kit, reads no native logs, starts no collector or job and removes no test resources.
Service details are discarded and unknown error text stays hidden. Only simultaneous
directory absence and an exact-label missing-service diagnostic yield
`cleanup_state: ABSENCE_VERIFIED`; other results retain their explicit uncertainty.
Do not rerun setup/capture or replace used-kit files to work around a rejected lease.

New version-4 configurations select detailed guard statuses explicitly. Historical
configurations keep their original run/cleanup protocol and remain readable. New
reports add fixed control failure labels without changing old hash-bound kits.
