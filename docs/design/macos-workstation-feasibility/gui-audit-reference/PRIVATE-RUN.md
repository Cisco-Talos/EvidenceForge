# Private GUI audit identity experiment

HUMAN ONLY. Agents may prepare this kit, syntax-check the C source without
executing it, and test the Python wrapper with invented inputs. Agents must
never run `record`, `report`, or the compiled probe, or inspect this kit after
handoff. Close Codex and other agents before running the experiment. Do not use
an agent-controlled terminal, share a screen, or paste terminal history.

## Scope and privacy

This experiment reads the controlled probe's **own** Mach audit token and
POSIX process/session IDs. It compares Terminal windows/tabs and a tiny
fork/exec family. It does not read system logs, inspect other processes,
enumerate environment variables, collect command lines, use the network,
request privileges, or alter audit/security settings. **Do not use sudo.**
Only the human starts collection. There is no eslogger subscription or log
stream. Numeric user/group/process/session IDs and code digests stay in
owner-only files in `private/`, under this kit outside any Git checkout.
Subprocesses receive a fixed minimal environment. Compiler/probe output is
captured privately; the wrapper prints a fixed success marker or a report
whose values are drawn from an explicit vocabulary. No native IDs, hashes,
paths, names, timestamps, or unknown fields can enter that report.

The system's existing endpoint monitoring may observe the probe's execution,
as it may observe any program. This kit does not disable or reconfigure it.
Do not run the binary directly or share files from `private/`. Never move the
kit into a repository, including an ignored folder. The kit refuses Git
locations, duplicate samples and changed code between samples. A retry uses
a freshly prepared kit; do not overwrite samples to make a result pass.

## First three samples: current GUI login

Use macOS 27 arm64 as your normal user, signed in at the desktop. Use Apple's
Terminal app, with a normal local shell, outside SSH, tmux, screen, an IDE,
or an agent terminal. Keep the sampled windows/tabs open until reporting.
No logout or other disruption is necessary for these initial samples.

In the commands below replace `KIT` with the new code-only kit's absolute
path supplied by Codex. Use the existing project interpreter; the script
does not import the project or write to its tree. The `-I -B` flags isolate
Python's import path and prevent bytecode writes.

1. Close Codex and other agents. In an existing normal Terminal window run:

   ```sh
   /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B KIT/private_gui_audit.py record window_a --private-run
   ```

   Compilation takes place on this first invocation, bounded to 30 seconds.
   The probe itself has an eight-second alarm and a twelve-second wrapper
   timeout. Successful sampling prints only `SAMPLE_SAVED_PRIVATELY`.

2. Open a **new Terminal window** with Command-N and run:

   ```sh
   /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B KIT/private_gui_audit.py record window_b --private-run
   ```

3. In that window open a **new tab** with Command-T and run:

   ```sh
   /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B KIT/private_gui_audit.py record tab --private-run
   ```

4. In the same tab run the private comparison:

   ```sh
   /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B KIT/private_gui_audit.py report --private-run
   ```

5. Review that JSON yourself before reopening Codex. Share **only that JSON**.
   It should identify `collection: OWN_PROCESS_ONLY`, `error: NONE` and
   `terminal_contexts: COMPLETE`. `SAME`, `DIFFERENT` and `MIXED` describe
   observations; they are not prescribed outcomes. Do not change a result.
   If a command fails, share only its fixed JSON error report. Do not paste
   compiler output, screenshots, shell output, paths from private files,
   the private files themselves, or a traceback.

## Optional fourth sample: fresh GUI login

The first three samples cannot establish the boundary between two GUI login
sessions. After reviewing them, this additional sample can test that boundary.
It requires saving your work and logging out of the GUI; do it only when
convenient. Do not restart, reboot, change users, use fast user switching,
or alter security settings. The wrapper records your explicit same-boot
GUI-relogin attestation; it does not independently inspect boot or login logs.

1. Keep the private kit in place. Save work and close Codex and other agents.
2. Log out of the desktop, then log in as the **same user without rebooting**.
3. Open Terminal and run, using the same kit path:

   ```sh
   /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B KIT/private_gui_audit.py record fresh_login --private-run --same-boot-gui-relogin
   /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B KIT/private_gui_audit.py report --private-run
   ```

4. Privately review the fixed report, then share only that report. If any
   prerequisite was not met, do not attest or reuse the experiment. Request
   a new code-only kit instead; never ask an agent to inspect old samples.

## Interpretation and limits

Own-token/POSIX agreement, controlled parent linkage, source/binary provenance,
distinct shells, attributed identities and consistent real-user context gate
cross-context comparisons. Fork/exec inheritance is reported independently.
A fresh-login audit-session comparison remains inconclusive when the initial
three samples do not share one audit identity. An unset audit user/session
is reported as a failed control, never substituted with the effective user
or a POSIX session ID.

This verifies selected identity relationships in the tested Terminal context.
It does not inspect Terminal.app's own token, establish every GUI application's
behavior, observe loginwindow startup, qualify a Unified Log layout, or repeat
Endpoint Security JSON collection. `reference_review: REQUIRED` and
`gate_status: NOT_EVALUATED` remain present. Generation admission requires
separate review and implementation; this kit never changes a generator gate.

The public API basis is Apple's
[TASK_AUDIT_TOKEN declaration](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/osfmk/mach/task_info.h)
and the
[task_info implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/osfmk/kern/task.c).
The probe queries only `mach_task_self()`. Public source establishes API
meaning; the human-run experiment supplies the macOS 27 relationship evidence.
