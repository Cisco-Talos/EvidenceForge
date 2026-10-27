# Private Gatekeeper reference — human only

## Offline diagnosis of `unified_log_shapes: FAIL`

Keep the existing capture. Do not repeat setup, download or capture, or replace files in the
original kit. A separately prepared code-only copy now supplies `review-shapes`:

```sh
"$PY" -I -B "$NEW_KIT/private_gatekeeper.py" review-shapes --private-run
```

Enter the original kit folder at the hidden prompt. As with the earlier diagnostic, the path
must not echo. Normally run this privately with agents closed. If you explicitly authorize an
agent to run this audited offline checker, it may supply the already known original folder with
`--existing-kit`; that permission covers local processing and only the fixed JSON output. It does
not authorize opening record contents in an agent tool or displaying any native error text.

The checker runs no native commands, collectors, server, app or network requests. It writes no
files. It verifies the original kit's recorded code/binary provenance and successful bounded
capture summary, then reads only `private/test-ul.jsonl`, with the original byte/line/record
limits and an additional nesting limit. Every row must still match the exact test name or
CDHash and the permitted policy writer. It does not open ES records, control summaries or
execution markers. A failed prerequisite returns an empty field diagnostic.

The output contains only predefined schema field names, presence/type labels and failure
classes (`MISSING`, `TYPE`, `VALUE`, `UNSUPPORTED`, `MULTIPLE`). Unknown field names, message
content, paths, timestamps, identifiers, counts, exception details and hashes never appear.
`additional_fields` reports presence only, and `additional_value_types` reports JSON types only.
Version 2 also probes a fixed list of candidate API/export names without printing any discovered
name or value. Candidate validation stays INCONCLUSIVE: presence does not establish field meaning,
equivalence or native codec admission. `unrecognized_fields` reports whether anything remains
outside both predefined lists. Candidate spellings include the directly documented NXLog
[TTL/export fields](https://docs.nxlog.co/agent/v6.5/im/maculs.html) and separate Apple API-style
names; they are hypotheses to distinguish, not aliases to normalize automatically.
These are structural checks; no message is interpreted as allow/deny. Even a complete shape
diagnostic retains `message_meaning: NOT_REVIEWED` and `gate_status: NOT_EVALUATED`.

The human-approved macOS 27 persona field names are now part of the known closed schema:
`personaID`, `personaName`, `personaType`, `launchPersonaID`, `launchPersonaName` and
`launchPersonaType`. The fixed review checks their primitive types without exposing values;
numeric candidate diagnostics additionally distinguish unsigned/signed 32-bit bounds. The codec
preserves absence and rejects explicit null for these fields. It does not infer persona meaning,
bind them to a user/audit identity or add them to generated events. An old capture summary may
still say FAIL because it records the acquisition-time decoder; the new read-only shape report
can pass without rewriting that historical summary or changing native evidence.

### If additional names remain unrecognized

Only the human may run this next command, in a standalone private terminal with agents closed:

```sh
"$PY" -I -B "$NEW_KIT/private_gatekeeper.py" inspect-field-names --private-run
```

Enter the original kit folder at the hidden prompt. This uses the same read-only provenance,
summary, bounds and exact-item checks, then displays only additional top-level field names.
No values, nested keys or messages are displayed. It refuses non-TTY input/output, redirects,
more than 32 additional names, long names and names containing non-identifier/control characters.
It starts nothing and writes nothing. Never run it through an agent's terminal tool or share a
screenshot/full terminal transcript. Privately check whether each name is purely a technical
schema field. You may share only names you have checked contain no identifying information.
If a name appears sensitive, do not share it; report that fact instead. The fixed-output checker
never automatically promotes these names into public output or accepts them into the codec.

### After shape review passes: private policy layout review

Keep the same capture. A separate human-only command lists unique writer/subsystem/category/
format-template combinations after the same provenance, scope and full-schema checks:

```sh
"$PY" -I -B "$NEW_KIT/private_gatekeeper.py" inspect-policy-layouts --private-run
```

Run in a standalone private terminal with agents closed. The original kit is entered at the
hidden prompt, or via `--existing-kit` using the already known kit folder. No new collection,
launch, native command or file write occurs. TTY input/output is required. No rendered message,
process path, PID, timestamp, hash, persona value or raw record is displayed. Layout counts and
literal lengths are bounded, and JSON escaping prevents terminal control characters.

These literals are not automatically safe: a program can embed private text in a format string,
subsystem or category. Privately inspect every component before sharing any of it. Share only
technical layout literals you verify contain no account/host names, paths, identifiers, secrets
or other sensitive information. Do not share screenshots or full terminal output. If uncertain,
say that the layout contains private text instead. No redacted message or record is needed.
The layout identifies potential templates; it does not prove which verdict was rendered or open
GK-R1. Private decision review must still distinguish a terminal denial from assessment, allow,
cache activity or an evaluator failure before native generation can use any template.

### Fixed review of the approved ASP refusal template

The human approved the kernel template `ASP: Security policy would not allow process: %d, %s`
with its native trailing newline. `review-denial` processes the same bounded test UL file and
the already authorized fixed capture/control summaries. With explicit fixed-checker permission,
an agent may run this offline command; otherwise run privately with agents closed:

```sh
"$PY" -I -B "$NEW_KIT/private_gatekeeper.py" review-denial --private-run --outcome BLOCK_ALERT
```

Use BLOCK_ALERT only for the human-observed downloaded test block. An optional `--existing-kit`
supplies the already known original kit folder instead of the hidden prompt. Nothing launches,
collects, writes or accesses the network. No ES file or execution marker is opened.

The fixed report checks every acquisition prerequisite, exact capture/control summary agreement,
successful local control, current UL decoding, exact template/rendering, positive uint32 target
PID shape, unique test-bundle executable suffix, kernel PID-zero writer and AppleSystemPolicy
sender image. Identifiers and message arguments remain private; only fixed comparison labels
return. Multiple reported target PIDs remain a fixed MULTIPLE classification, never an assumed
single child. ES nonobservation is read from the acquisition summary, not upgraded into proof
of no process allocation or successful exec.

`BOUNDED_REFERENCE_SUPPORTED` establishes only this controlled LaunchServices app-policy refusal.
It does not identify malware, a notarization verdict, the AMFI error reason or a fork/exec stage.
The full generation gate stays NOT_EVALUATED. Native integration must first model the reported
failed-launch PID separately from a successful execution and support a kernel writer with its
distinct AppleSystemPolicy sender. The existing pre-child `outcome: denied` must not be silently
reinterpreted using this observation. No repeat capture is needed for the bounded reference.

Apple's [Gatekeeper investigation discussion](https://developer.apple.com/forums/thread/766466)
contains the same kernel refusal family alongside a distinct syspolicyd terminal decision.
Another [Apple-hosted firsthand report](https://developer.apple.com/forums/thread/742974) shows
that family with an AMFI entitlement-validation failure. These support a refusal interpretation,
not a unique cause or allocation-stage rule. Apple's
[notarization source](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/notarization.cpp)
separates ticket extraction/checking from their outcomes; those diagnostic templates alone are
not terminal refusal evidence. No public native record was copied into tests.

## Version 2: diagnosing a version-1 verification error

If the earlier kit stopped at `PRIVATE_STEP_VERIFYING_DOWNLOAD` with `INTERNAL`, do not
rebuild, redownload or repeat capture yet. Version 1 obscured filesystem failures behind that
generic code. A version-2 code-only kit can replay verification against your existing kit.

1. Stop the old server with Ctrl+C. Read this section, then close Codex and all other agents.
2. Run the **new** prepared helper with your normal-user Python:

   ```sh
   "$PY" -I -B "$NEW_KIT/private_gatekeeper.py" diagnose --private-run
   ```

3. At the hidden prompt, enter the **old kit folder**, not its `private` or `downloads`
   subfolder. The input must not echo. Do not paste that path into this chat.
4. Privately inspect and share only the resulting fixed JSON. `step` identifies the check;
   `error` distinguishes a missing file, access failure, type mismatch or verification failure.

This does not write/change your old kit, start a server/collector, rebuild or launch the test
app, or open any retained record file. It verifies the existing private provenance and exact
expected files, then runs only read-only code-signature and quarantine checks using the
already verified metadata helper. Exact names, hashes, OS build and native error text remain
private. No directory search or listing is performed. Even a successful diagnostic does not
run capture or establish denial evidence; wait for the result to determine the next step.

The original kit remains untouched. All operations below are for a fresh acquisition, not
instructions to repeat an interrupted experiment.

Close Codex and every other agent before **setup, serve, capture, control, report or diagnose**.
Agents may copy this code-only kit, syntax-check sources without execution and run invented-input
tests. Any agent execution of a private operation requires your explicit authorization; the
offline exception above permits only the fixed diagnostic output. No captures, redacted
copies, screenshots, alert text, paths, hashes or native records may be shared with an agent or
copied into Git, including ignored directories. Share only the final fixed JSON after privately
checking it. The gate stays `NOT_EVALUATED` until that evidence is reviewed.

This kit targets your macOS 27 arm64 normal-user Python. **Do not sudo Python.** It never changes
Gatekeeper, SIP, quarantine, trust caches, privacy redaction, Full Disk Access or services. It
does not inspect historical logs, other files/accounts, browser history or installed applications.
Setup uses the existing Apple compiler; if tools or collector access are missing, stop and share
only the fixed error report. Do not install/grant/change anything to force a result.
Exact OS release/build, architecture and code hashes are retained privately for reference
provenance; none appear in the shared report. Capture and control reject a build changed since setup.

## What runs

- A fresh, ad-hoc-signed, non-notarized test app writes one exclusive marker inside this private
  kit and exits. It reads no personal files and has no network code. The exact same binary and
  bundle metadata form the downloaded item and local control. New kits use new names/content.
- A separate Foundation helper checks **presence only** of quarantine via the documented URL
  resource property; it never prints or saves its contents. Its public readiness message contains
  only this test's random tag. It does not run the app or assess Gatekeeper policy.
- The included Python server binds only `127.0.0.1` on an available temporary port for at most
  15 minutes. It serves one archive and a minimal static download page under a random URL.
  No directory listing, access logs,
  uploads, redirects, external resources or public hosting are used. Closing it removes the
  listener; it installs no service. No existing web server is needed.
- During capture only, `log stream` uses a predicate for the readiness tag or specified policy
  writers mentioning this app's unique name/CDHash. Default privacy redaction stays enabled.
  An additional in-memory exact-item filter discards unrelated records before disk.
- ES exec/exit is system-wide at the API: unrelated activity can pass through the private
  process's memory, but is discarded before disk. Nothing streams to Codex. Only matching test
  target records are retained, with PID/version/start correlation for subsequent exits.
- Only a small, auditable `collector-guard` runs under internal `sudo -n`. It has no arguments
  and launches exactly `/usr/bin/eslogger exec exit`. It owns that child's separate process
  group, stops/reaps it on interrupt, and has an independent 55-second watchdog plus bounded
  cleanup. It has no
  file or network operations. This prevents an orphan privileged collector even if Python exits.
  Python, the HTTP server, app and metadata helper all run as your normal user.

This is a bounded acquisition diagnostic, not automatic Gatekeeper qualification. Matching
policy messages can be assessment or allow messages. Neither an exit code nor a missing marker
proves denial. ES records may legitimately be unobserved when rejection precedes execution;
absence of matched records alone cannot prove that happened.

## Before starting

Use two standalone iTerm2/Terminal windows. Keep all terminal output private. Substitute the
prepared kit folder for `KIT` below, and use the same Python that worked for your previous kits:

```sh
PY=/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python
KIT=/private/tmp/eforge-gatekeeper-kit-REPLACE_ME
```

Run these two assignments in each window. The Python process must remain your normal user.
You may privately inspect the kit's code/instructions before proceeding.

## 1. Build, without launching

In window A:

```sh
"$PY" -I -B "$KIT/private_gatekeeper.py" setup --private-run
```

Expect `PRIVATE_SETUP_READY`. This creates the app and archive, but does not execute the app,
start a listener, launch a browser or collect logs. Do not open the original app yourself.

Each kit is single-use. If setup fails, keep its output private and share only the fixed JSON.
Do not reuse earlier capture directories or try repairing native evidence by hand.

## 2. Start the supplied server and download privately

In window A:

```sh
"$PY" -I -B "$KIT/private_gatekeeper.py" serve --private-run
```

Leave this running. It prints `PRIVATE_DOWNLOAD_URL` and `PRIVATE_SAVE_FOLDER`. These are for
you only; do not paste them here. The URL always starts `http://127.0.0.1:`.

1. Open a Safari private window and visit that exact URL. Right-click **Download test ZIP**,
   choose **Download Linked File As…**, and save **`probe.zip` directly into `PRIVATE_SAVE_FOLDER`**. In a chooser,
   Command-Shift-G lets you enter that private folder. Do not use curl, a Python HTTP client,
   command-line unzip or manually add/remove quarantine.
2. If the browser saves elsewhere, move just this archive in Finder into the printed folder;
   do not copy any other files. Keep its name `probe.zip`. The helper never searches Downloads.
3. In Finder, double-click that ZIP so Archive Utility extracts the uniquely named
   `EForgeGatekeeperProbe-…app` beside it, inside the printed folder. If Safari already extracted
   it, retain the original ZIP there too. Both must be present. Do not launch the app yet.

The kit verifies its own server delivery, exact archive/binary/Info.plist hashes, signature
integrity and OS quarantine presence on both ZIP and app. If either is unquarantined, it stops
before launch or collection with `QUARANTINE`. A loopback download is not guaranteed to trigger
the desired policy on every configuration. Do not manufacture flags or change security settings.

## 3. Collect the single downloaded-app attempt

In window B, refresh sudo separately, then run Python normally:

```sh
sudo -v
"$PY" -I -B "$KIT/private_gatekeeper.py" capture --private-run --browser-download
```

The `--browser-download` flag is your attestation that you used the browser procedure above.
Only the internal collector guard uses sudo. No passwords are collected or stored by this kit.

The helper checks both collectors using its separate harmless readiness program before it opens
the test app. Expect `PRIVATE_STEP_COLLECTORS_READY`, then `PRIVATE_STEP_TEST_LAUNCH`.

The app is opened once through LaunchServices (`open -n -W`). Privately observe what happens:

- If a security block alert appears, dismiss with **OK/Done**. Do not choose Open Anyway,
  override it through Settings, remove quarantine, or repeatedly relaunch.
- If ordinary consent appears, decline/cancel rather than approving a run; classify this as
  `CONSENT_PROMPT`, not a denial.
- If it runs, crashes or behaves differently, retain that actual outcome. Do not force denial.

Collection lasts 30 seconds after launch and retains at most 128 records and 4 MiB per source,
with a 1 MiB line limit and 100,000-record input limit. Only exact-item records are saved under this kit's private directory.
Both collectors are then stopped. A failed cleanup is reported; the privileged guard also
has its independent timeout. A collector readiness error stops before the app launch.

Do not share this intermediate output. Keep the fixed `error` code and last `PRIVATE_STEP_…`
marker if troubleshooting is needed. Never paste native output or screenshots.

## 4. Stop the server, then run the local control

After download/capture, press Ctrl+C in window A to stop the supplied server. It should print
`PRIVATE_SERVER_STOPPED`. It also stops automatically after 15 minutes.

Dismiss any remaining test prompt before continuing. If capture reported an error, failed
cleanup or a timed-out launch, skip the control and use the report command for an inconclusive
diagnostic instead. The report can read the capture summary when no control has been run.
Otherwise in window B:

```sh
"$PY" -I -B "$KIT/private_gatekeeper.py" control --private-run
```

This verifies the original app is unquarantined and runs it with the same LaunchServices method.
The test's prior marker, if present, is preserved separately; the control must create a fresh
marker. Running the control after the test reduces prior-execution interference. Do not remove
quarantine from the downloaded item to make the control work. No collector runs during control.

## 5. Privately review and share only the fixed report

Choose the outcome of the **downloaded test attempt**, not the local control:

| Fixed choice | Your private observation |
| --- | --- |
| `BLOCK_ALERT` | A security block prevented launching; you dismissed it without override |
| `CONSENT_PROMPT` | Ordinary confirmation/consent appeared; no established denial |
| `RAN` | The downloaded app ran |
| `CANCELLED` | You cancelled; do not reinterpret cancellation as a policy denial |
| `CRASH_OR_ERROR` | A crash or other launch error, without a confirmed security block |
| `OTHER` | Unclear or none of these |

For example, only if you observed a block:

```sh
"$PY" -I -B "$KIT/private_gatekeeper.py" report --private-run --outcome BLOCK_ALERT
```

Privately inspect the JSON before sharing it. Every field must be a fixed label such as PASS,
FAIL, PRESENT or INCONCLUSIVE; there must be no paths, hashes, UUIDs, times, usernames or messages.
Share only that JSON. The report command never opens native record files. The retained captures
remain yours for a later, separately prepared private shape/decision review; do not attach them.
`PRIVATE_REVIEW_CANDIDATE` does not mean denial fidelity passed: full native decision meaning,
layout and process consequences still need qualification. A missing/redacted correlation stays
inconclusive and never broadens collection or enables private data automatically.

## References and limits

Apple's [trusted-execution guidance](https://developer.apple.com/forums/thread/706442) describes
browser quarantine, Archive Utility propagation, separate controls and cache-related false
negatives. Its [Gatekeeper diagnostics](https://developer.apple.com/forums/thread/706379) distinguish
signature/notarization issues and per-item CDHash correlation. The documented Foundation
[`quarantinePropertiesKey`](https://developer.apple.com/documentation/foundation/urlresourcekey/quarantinepropertieskey)
is queried without exporting its values. These establish procedure/API meaning, not a macOS 27
native record template. Default redaction is preserved even though Apple describes broader
diagnostic options. No VM exists here, no trust cache is reset, and neither refusal nor useful
native policy evidence is guaranteed.
