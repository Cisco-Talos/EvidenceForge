# Private Gatekeeper reference — human only

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
tests. They must never open the handed-off kit after you start using it. No captures, redacted
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
