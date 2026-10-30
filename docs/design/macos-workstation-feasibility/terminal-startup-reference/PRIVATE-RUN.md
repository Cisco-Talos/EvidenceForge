# Private terminal startup reference

This is a human-only diagnostic for **both Apple Terminal and iTerm2**, run separately on
macOS 27 arm64. Agents prepare code and test invented inputs only. Close Codex and other
agents before setup or capture. Never share native records, screenshots, terminal contents,
provenance, hashes or the whole kit. Share only the fixed final JSON after reviewing it.

Use a fresh **version-2 kit**. Version 1 mistakenly applied private-file permission checks
to installed app binaries, causing setup `LOCATION` and a subsequent capture `IO` from the
missing setup manifest. Do not repair permissions on Terminal/iTerm2 or overwrite an old kit.
Version 2 hashes the installed app separately, preserves strict private-file checks, and
adds a fixed `step` label to failures. Failed commands return a nonzero exit status.

The question is which actual fork/exec transitions connect a newly launched terminal app,
any helpers, login, the initial shell and one harmless marker. We must distinguish new PIDs
from same-PID image replacements. Matching behavior in our engine does not establish that
the real apps use identical helper trees or signing metadata.

## Privacy and collection scope

The existing root guard runs `eslogger fork exec exit` for at most 55 seconds. The normal-user
filter keeps a bounded transient candidate ring in memory. It writes **only** the native launch
chain proved by a compiled marker's device/inode and audit execution identity, and only if an exec of
the exact selected app binary is in its ancestry or is its kernel-attributed responsible owner.
The fixed `app_link` label distinguishes these relationships; responsibility never proves parentage.
Siblings, descendants unrelated to that marker
and other machine-wide candidates are never written. A reused app cannot prove fresh startup;
it returns `APP_START_NOT_OBSERVED`. Ring eviction makes missing phases inconclusive.

Retained ancestors can contain private paths, credentials and environment values. They stay in
0700/0600 files outside Git. Only fixed roles, ABI labels and relationship comparisons are
exported. No historical logs, Unified Log, process listing, network server, personal document
read or security-setting change is involved. OS swap/crash reports, backups and other endpoint
software remain outside the kit's control. This is not a claim that the local files are public.

Use a clean ordinary login-shell profile in the selected terminal: no startup commands,
restored sessions, tmux/screen or custom shell helpers. Do not edit personal dotfiles for this
test. If a clean profile is not available, stop and discuss a private setup first. This kit
does not create profiles, change preferences, close apps or type commands for you.

## Run separately for each app

Use a **fresh prepared kit for each terminal**. Keep the controller in the *other* app:
control the Apple Terminal test from iTerm2, and the iTerm2 test from Apple Terminal. Save your
work and fully quit the app being tested before collection. Do not quit the controller app.

1. `cd` to the prepared code-only kit. As your normal user, compile and sign its marker and
   guard (this launches neither and starts no collector):

   ```sh
   /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B private_terminal_startup.py setup --terminal apple --private-run
   ```

   For the iTerm2 kit, use `--terminal iterm2`. Expect `kit_version: 2`,
   `stage: SETUP_READY`, and `error: NONE`. **Stop if setup reports any error; do not run
   capture.** Share only its fixed JSON. A failed setup needs another fresh kit.
   The iTerm2 executable must be `/Applications/iTerm.app/Contents/MacOS/iTerm2`.

2. Have Finder ready to launch the selected app. Prepare the following marker command using
   the **absolute prepared-kit path**, keeping it private. Do not run it yet:

   ```sh
   /private/tmp/REPLACE_WITH_THIS_KIT/terminal-marker --sample
   ```

3. Start the controller, keeping Python as your ordinary user:

   ```sh
   sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B private_terminal_startup.py capture --fresh-launch --private-run
   ```

   Only the internal guard uses sudo. The flag attests to the fresh, clean launch procedure.
   Do not add tee, shell tracing, redirection or transcript recording.

4. Wait for **`TERMINAL_READY`**. You now have 30 seconds to launch the selected app from
   Finder, open its clean ordinary login shell, and run the prepared marker command **once**
   in that shell. The marker prints nothing and returns after approximately 250 ms. Leave
   that window open until the controller prints the final JSON. No alert is expected.

5. Read the final fixed report in the controller. Check error `NONE`, cleanup `PASS`, app
   exec retained `PASS`, marker exit zero `PASS`, sequence continuity and any ring eviction.
   A failed native shape is diagnostic information, not permission to repair native files.
   `reference_review: REQUIRED` and `gate_status: NOT_EVALUATED` are intentional.

6. Review and share **only the final JSON**. Repeat using a different fresh kit for the other
   terminal. No logout/reboot, fresh GUI login or additional Finder reference-app capture is
   required. The existing GUI audit experiment already establishes the login-origin boundary.

The private `run-…` directory has `SHAREABLE-REPORT.json`, provenance, and (only after successful
chain proof and cleanup) `launch-chain-events.jsonl`. Do not copy these files into the repository.
If a command fails, share only its fixed JSON; keep every other output private.
`SETUP_REQUIRED` at `SETUP_MANIFEST` means no successful setup is available; no collection
is started. `KIT_ALREADY_USED` means the one-shot setup or capture was already attempted;
leave that kit intact and request a fresh code-only copy.
You can replay a saved fixed report with `private_terminal_startup.py report --private-run`;
that command reads only the saved allowlisted JSON, not native records, and starts nothing.
