# Human-run private exec/exit experiment

This kit is for **you to run privately, after closing Codex and other agents**.
Agents may prepare code and test invented inputs. They must not run `preflight` or `capture`,
open its private output, or ask you to send captured records or screenshots.

The checker requires this checkout's existing Python environment (Python 3.12+
with EvidenceForge and Pydantic installed). It does not install dependencies,
contact a service, enable logging, or change system security settings. The copied
script imports the checkout's native field models; keep that checkout/environment
unchanged while performing and reviewing the experiment.

## Before running

- Use a standalone Terminal window, **not Codex's terminal**. Capture is never
  run through agent tools. The Python script itself must run as your normal user.
- Reference acquisition accepts Apple Silicon macOS without pinning the OS
  major version. The checker records the actual OS/build privately. This does
  not declare macOS 26 and 27 equivalent or enable a production source profile.
- Command Line Tools must already be installed. `eslogger` needs superuser access
  and Terminal needs Full Disk Access. If these are absent, stop; the kit does not
  install tools or change permissions. Review any permission changes yourself.
- Keep the kit on local, private, nonsynced storage outside **every Git working
  tree**. The prepared directory is mode 0700. Treat backups and any other local
  monitoring software as separate privacy considerations.
- A clean external macOS installation with personal volumes unmounted provides
  stronger separation. A separate account alone does not isolate system-wide ES
  activity.

`eslogger` receives system-wide events. Unrelated records pass through the local
filter's memory before being discarded; they are never written by this kit. Full
matched records can still contain real UID/audit, parent/responsible process,
path, signing and timing information. **Even matched records stay private.**
This is not a guarantee that the operating system, swap, crash reporting, an
existing security agent or backups never retain data. Never send a crash report,
terminal transcript or entire kit directory to an agent.

## Check the target first

In standalone Terminal, run the new prepared copy as your normal user:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B private_capture.py preflight
```

This does not compile the probe, start eslogger, collect logs or write any data.
It checks only the target conditions below and prints the same fixed JSON report
vocabulary. Native values and exception text are never included. Privately
review the report, then share only its text or its fixed `error` code.

| Fixed error code | Meaning |
| --- | --- |
| `ROOT_USER` | The Python process runs as root; run it as your normal user |
| `OS_FAMILY` | This Python process does not identify its OS family as Darwin |
| `PYTHON_ARCH` | This Python process does not identify its architecture as arm64; this can include a process under Rosetta and does not identify the physical CPU |
| `OS_VERSION` | The local version command did not return a numeric version; its actual output stays private |
| `LOCATION` | The kit location fails its private-directory/outside-Git checks |
| `NONE`, with `target_platform: PASS` | Target prechecks pass; no collection or evidence acceptance is implied |

Do not bypass an OS-family or architecture mismatch or paste `sw_vers`, `uname`, user
IDs, interpreter paths from your configuration, or other system inventories.
These fixed codes suffice to choose the next step. The older `PLATFORM` and
`OS_MAJOR` codes remain readable for previous reports; this kit no longer
requires macOS 26. Its report carries `kit_version: 3`.

## Run once after preflight passes

1. Privately read `private_capture.py` and `process_probe.c`. The four cases are:
   self-exec followed by exit 7; self-exec followed by SIGTERM; a nonexistent
   executable returning ENOENT, followed by exit 3; and `/usr/bin/true` exiting 0.
   They do not enumerate users, files, processes, services or network activity.
   The probe receives only PATH/LANG/LC_ALL and explicit invented arguments.
   Before these cases, it can fork/reap up to eight harmless warm-up children
   without exec. The checker samples file-object identity for only its newly
   compiled probe and the explicitly planned `/usr/bin/true`. It never resolves
   arbitrary paths from the event stream or scans directories for matches.
2. Close Codex and other agents. In standalone Terminal, `cd` to the **prepared
   kit directory**, not the repository. Save the following fixed Python path in
   your command; do not use `uv run` to fetch anything during capture:

   On a clean external installation, prepare an independent reviewed checkout
   and environment there first, and substitute its Python path below. The
   example uses the existing checkout on this workstation.

   ```sh
   sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B private_capture.py capture --private-run
   ```

   `sudo -v` authenticates privately; `&&` then runs Python as your normal user.
   Do not remove `&&` or put sudo directly before Python. The kit invokes only
   `/usr/bin/sudo -n /usr/bin/eslogger fork exec exit` with those elevated
   credentials; the probe remains your ordinary user. Do not run the whole kit
   with sudo. No capture is sent to Unified Log or displayed in Terminal.
3. The checker waits up to 10 seconds for a matched warm-up fork and child exit
   before starting the four cases. It sends at most eight warm-up requests,
   spaced at least one second apart. There is no fixed startup sleep or assumed
   readiness. If readiness fails, the four cases never start and their checks
   stay `INCONCLUSIVE`. Collection then has a 15-second deadline once the cases
   start, with bounded shutdown waits. Compilation has separate bounded waits.
   A fixed failure report is safe to inspect. If interrupted or the collector
   does not stop, keep the session
   private and stop it manually before reopening agents; do not share its PID
   or an unfiltered process listing.
4. Inspect the new `private-run-*` directory **yourself**. It contains:

   | File | Treatment |
   | --- | --- |
   | `probe-events.jsonl` | Private, full original matched ES lines; never share |
   | `probe-controls.jsonl` | Private probe PIDs and independently observed statuses |
   | `private-provenance.json` | Private exact OS/build, command, timing and probe hashes |
   | `process-probe` | Harmless compiled test binary; keep outside Git |
   | `SHAREABLE-REPORT.json` | Only fixed keys and PASS/FAIL/INCONCLUSIVE codes; review before sharing |

   A failed/interrupted run can retain a partial private directory without all
   these files. Error text, raw records and tracebacks are never added to the
   public report. Only the fixed report is printed on stdout. Do not add `tee`,
   logging wrappers, shell tracing, `--oslog`, historical `log show`, or archives.
5. Only after personally checking the **contents** of `SHAREABLE-REPORT.json`,
   reopen Codex and paste that report's text. Do not attach the file's directory
   or grant an agent access to the private files. If the run fails before writing
   that file, only the fixed JSON error report printed by this kit may be shared.

The run uses new private files (0600), preserves matched JSON lines without
redaction, and refuses to collect inside a Git tree. Nothing automatically
uploads, stages, commits, deletes or copies evidence into the repository,
including ignored directories. Retention/deletion of private evidence is your
decision; the agent will not inspect or remove it.

## Interpreting results

All checks use a fixed vocabulary. A malformed/unknown shape, sequence gap,
missing lifecycle, unexpected input/environment, mismatched exit status or
incomplete run cannot count as passing evidence. No record or exception is
embedded in a diagnostic. A shape mismatch stays private; do not paste its
Pydantic validation error. We can investigate using independently invented
examples and the already-public field vocabulary.

Version 3 adds four fixed diagnostics; none exports record counts, identifiers,
paths, native values or snippets:

| Check | Meaning of PASS |
| --- | --- |
| `stream_delivery` | At least one complete JSON event line reached the filter |
| `probe_identity_seen` | A full PID/PID-version/birth identity for the known probe PID was recognized |
| `probe_image_seen` | That identity also identified the exact owned probe file object |
| `collector_ready` | A matched warm-up fork and child exit were observed, allowing the cases to start |

Read these in order when readiness fails. A missing stream differs from an
unrecognized identity representation or an unmatched executable. These checks
do not identify the specific cause of missing delivery or authorize changing
permissions. `bounded_delivery: FAIL` still prevents an incomplete experiment
from passing. Case-specific checks stay inconclusive when readiness prevents
them from running.

The acquisition filter understands explicit eight-word audit tokens as an
array, an exact `val` wrapper, or a complete named mapping, with a string or
explicit timeval process birth. It still requires PID version, birth identity,
exact executable ownership and tracked fork ancestry; PID-only matching and
path-prefix matching are forbidden. Known executable file objects can match
their native path aliases. This does not qualify these representations for a
production wire codec or silently change captured bytes. Pre-start warm-up
records are discarded in memory; a delayed warm-up row delivered after the
start barrier can appear among the bounded private probe-family records.

The report's `wire_profile` is determined from the matched records' actual
schema/message headers, never inferred from the OS major and never rewritten:

| Fixed profile label | Meaning |
| --- | --- |
| `V10_CANDIDATE` | All matched headers select the known schema-1/message-10 candidate |
| `V11_UNQUALIFIED` | Matched headers select schema 1/message 11; its full wire contract is unqualified |
| `OTHER_UNQUALIFIED` | A different positive message version was observed; no arbitrary native number is exported |
| `SCHEMA_UNQUALIFIED` | The serialization schema differs from the known schema |
| `MIXED` | Matched records contain different schema/message pairs |
| `INVALID` | A header lacks valid positive integer discriminants |
| `NOT_OBSERVED` | No safely matched probe records were retained |

Readiness records discarded before the start barrier do not select a wire
profile. A failed warm-up can therefore leave `wire_profile: NOT_OBSERVED` even
when `stream_delivery` or a probe-identity diagnostic passes.

`message_shapes` selects validation by that observed profile. Only
`V10_CANDIDATE` has an implemented full candidate layout today. Newer,
mixed and unknown profiles yield `INCONCLUSIVE` with fixed `error: WIRE_PROFILE`;
invalid discriminants yield a failed shape check. The legacy
`candidate_v10_shapes` field is inconclusive outside the v10 candidate. No
unknown record is coerced into v10 or accepted because its OS looks similar.

**WIRE_PROFILE is not a reason to repeat collection.** If scoped records were
retained, they remain private and unmodified for local qualification. Share
only the reviewed report. Controlled lifecycle/exit/argv checks can pass while
full wire qualification remains inconclusive. If the identity/path layout
cannot be safely scoped, records are discarded and delivery checks fail.

For a successful version-3/v11 capture, the next step is the separate
[human-only offline diagnostic](OFFLINE-REVIEW.md). It reuses the existing
private evidence without running another capture. Agents may prepare its code
only; they must not inspect or review the private run.

These checks are not an assertion that unseen native records conform, a complete
API survey, or production exec/exit admission. The private provenance includes
the actual OS/build and observed message versions. A macOS 27 experiment is
macOS 27 evidence; shared checks do not establish macOS 26 native fidelity.
The fixed report always says `reference_review: REQUIRED` and
`gate_status: NOT_EVALUATED`, even if every check passes. Review exact build
scope, field absence/null semantics and retained evidence privately before
accepting ES-R1. Any subsequent implementation needs independently authored
fixtures and parser/generation/filter/checkpoint acceptance. Never commit native
records or use them as test fixtures, PR attachments or CI artifacts.

These cases do not cover script interpreters, PTYs, every descriptor variant,
credential transitions or arbitrary apps. Extra families need separate evidence.

## Gatekeeper is separate

This kit does **not** collect Unified Log or perform a Gatekeeper experiment.
Start with exec/exit. The next private protocol would use a harmless app with a
successful launch control, a separately quarantined copy and an actual blocked
launch without overrides. It must distinguish affirmative policy rejection from
a prompt, cancellation, missing marker, crash or collection failure. No malware,
Gatekeeper/SIP changes, private logging configuration, or broad system-log
archive is needed or authorized by preparing this kit. Native denial remains
gated until that separate private procedure and its report checker are reviewed.
