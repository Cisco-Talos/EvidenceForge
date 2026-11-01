# Private launchd activation reference

This is a **human-run experiment on macOS 27 arm64**. Close agents before setup
and collection. Do not run the Python helper with sudo. Do not paste terminal
records, private paths, screenshots, provenance or native files into chat.

The experiment temporarily registers **one root/system-domain launchd job** and
explicitly activates it once. Its only program is Apple's `/usr/bin/true`, which
returns zero without producing output or reading user files. A random test token
is passed in its arguments and controlled environment. No account, Remote Login,
privacy setting, shell configuration, existing job or application is modified.

The root guard constructs its own fixed plist in a fresh root-owned, mode-0700
directory under `/private/var/tmp/eforge-launchd-reference-…`. It uses an explicit
path for `bootstrap system`, then exact `system/<test-label>` targets for
`kickstart` and `bootout`. It installs nothing in startup directories, never
enables/disables jobs, and never removes an entire launchd domain. The plist's
`RunAtLoad` and `KeepAlive` are false; standards point to `/dev/null` and the
working directory is `/`. Registration is distinct from activation.

The eslogger collector sees machine-wide fork/exec/exit input for a bounded
period. Unrelated records remain in a bounded in-memory ring and are never
saved. Only one token-authenticated true execution, its exact ancestry back to
the verified launchd image/PID 1, and its exit can reach the private native file.
No sibling or descendant scan is used. A normal-user readiness marker proves the
collector is delivering events before the job starts.

## Run once in one terminal window

Use the terminal already authorized for eslogger through Full Disk Access. Keep
the prepared directory in `/private/tmp`; do not copy it into the repository.
Replace `KIT` below with the fresh kit path supplied in chat. These are separate
commands, all run as your normal user:

```sh
cd KIT
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_launchd.py setup --private-run
```

Continue only if setup returns `stage: SETUP_READY` and `error: NONE`.
Setup only compiles/signs controls and snapshots public executable identities;
it starts no collector or test job. Then run:

```sh
sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_launchd.py capture --private-run
```

After a short `COLLECTOR_READY` message, everything is automatic. There is no
second window, password-bearing SSH command, Finder action or interactive app.
The usual run takes about 10–20 seconds. No output from the test program is
expected. Capture prints a compact fixed status; it deliberately does not print
the full report into scrollback.

When it returns, save the full fixed report without opening native files:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_launchd.py report --private-run > SHAREABLE-LAUNCHD-REPORT.json
```

Share **only `SHAREABLE-LAUNCHD-REPORT.json`**. `report` reads the saved fixed JSON,
not native logs, and starts no commands, probes, jobs or collectors. The report
includes source controls, full selected topology with opaque aliases, native
shapes, credentials/audit origin, parent/responsibility tokens, group/session,
terminal/descriptors, signing, image slice, public argument layout, environment
comparisons and exit status. It contains no observed identifiers, paths, names,
argument/environment text or native message text. `gate_status: NOT_EVALUATED`
is expected; a fixed report is evidence for review, not automatic admission.

## Interruption or failure

One Ctrl+C requests cancellation. The root guard independently attempts exact
job removal on parent-pipe EOF, SIGINT, SIGTERM, SIGHUP or its deadline. Each launchctl
child has a five-second deadline and only that child group can be terminated.
The collector has its own 55-second watchdog. **SIGKILL, machine failure or a
launchctl failure cannot guarantee cleanup**; failures remain visible in the
fixed report. Never treat a failed bootout as proof that the job is absent.

If the report says `job_removed: FAIL` or `temporary_files_removed: FAIL`, keep
the kit and run this human-only recovery command as your normal user:

```sh
sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_launchd.py cleanup --private-run
```

Recovery verifies the exact root-owned scratch plist against the guard's fixed
content, then retries removal of that test label only. It starts no test program
or collector and returns fixed labels. It refuses a missing/altered lease. If it
still fails, share only its fixed JSON and retain the kit for diagnosis. Do not
broaden the bootout target, inspect other jobs or run cleanup against another kit.
The job is not installed for boot and does not relaunch/keep alive its program.

Kits are single-use. Do not remove SETUP-LOCK or SESSION-LOCK, modify controls,
rerun setup/capture or reuse a failed kit. A failed attempt needs a fresh kit.
No native row file is saved unless target/ancestry/sequence checks and both job
and collector cleanup pass. A later native-log review requires separate explicit
permission. Do not commit native records or share the entire directory.

## Scope and references

This tests one explicitly activated system job, not user LaunchAgents, timers,
sockets, restart policy, `launchctl` process-list output, GUI login or Unified
Log messages. Other triggers and domains remain unqualified.

- [Apple security compliance tutorial](https://it-training.apple.com/compliance/tutorials/course/sec050/)
  documents system-domain bootstrap, explicit kickstart and exact-service bootout.
- [Apple's launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
  describes launchd job definitions and on-demand behavior.
- [Apple's published true source](https://github.com/apple-oss-distributions/shell_cmds/blob/main/true/true.c)
  implements an immediate zero return; the test token does not change its work.
- The installed public `launchctl(1)` and `launchd.plist(5)` manuals describe the
  exact command targets and plist keys. No logs are consulted for these rules.
