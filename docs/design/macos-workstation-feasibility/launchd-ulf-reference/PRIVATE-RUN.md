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

## Run as your normal user

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
test category-labelled output. The filter correction is code-tested; it has not
been run against native data. **Do not repeat collection solely to turn a zero
into a positive result.** The [reference note](REFERENCE.md) records the limitation
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
