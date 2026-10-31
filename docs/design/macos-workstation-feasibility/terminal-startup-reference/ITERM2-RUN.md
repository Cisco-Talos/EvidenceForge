# Paired iTerm2 startup reference

Use this fresh kit to collect the equivalent of the completed Apple Terminal test before
implementing either startup producer. It bundles the version-2 capture and version-3 offline
detail reviewer. Agents prepare/test code only; the human performs setup, collection and
review privately with agents closed. No further Apple Terminal capture is needed now.

The comparison covers actual fork versus same-PID exec, intermediary helpers, GUI audit
origin, parent/responsible identity, credentials, POSIX sessions/groups, controlling terminals,
argv, environment relationships, native signing/slice/entitlement shapes and descriptor
inventory. The detailed reviewer additionally groups pipe descriptors by equality using only
fixed FD slots; it never exports native pipe IDs. Apple vendor-template checks apply only
to their named Apple images, never to iTerm2 or its helpers.

iTerm2 documents long-lived session servers in its
[session-restoration guide](https://iterm2.com/documentation-restoration.html). Preserve the
normal implementation and its helpers; do not turn off its server feature to force the same
chain as Terminal. This experiment observes one fresh ordinary login shell, not a reattached
job. Save work, close existing iTerm2 sessions, then quit iTerm2 normally with Cmd-Q. Do not
force-quit or use a custom command/tmux profile. No personal dotfile edits are required.

## Procedure

1. Keep the controller in **Apple Terminal**, with iTerm2 fully quit. Close agents. The selected
   executable must be `/Applications/iTerm.app/Contents/MacOS/iTerm2`. In Apple Terminal, `cd`
   to this fresh prepared-kit directory. As the normal user, run:

   ```sh
   /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_terminal_startup.py setup --terminal iterm2 --private-run
   ```

   Expect `kit_version: 2`, `stage: SETUP_READY`, `error: NONE`. Stop after any setup error
   and share only its fixed JSON. Do not run capture against an unsuccessful setup.

2. Before collecting, prepare the marker command with this kit's **absolute path** so it can
   be entered promptly in the new iTerm2 window. Do not execute it in Apple Terminal:

   ```sh
   /private/tmp/REPLACE_WITH_THIS_KIT/terminal-marker --sample
   ```

3. In the Apple Terminal controller, run:

   ```sh
   sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_terminal_startup.py capture --fresh-launch --private-run
   ```

   Python stays the normal user; only the internal guard elevates. Wait for `TERMINAL_READY`.
   Then, within 30 seconds, launch iTerm2 from Finder and run the prepared marker command once
   in its fresh ordinary login shell. The marker prints nothing and returns in about 250 ms.
   Leave that window open until the controller finishes. No alert is expected.

4. Check the controller's final JSON. A usable capture has `error: NONE`, `stage: COMPLETE`,
   platform/provenance/readiness/cleanup/sequence/bounded-delivery checks PASS, app exec retained
   PASS, marker exit zero PASS and no ring eviction. If collection fails, keep its files and
   share only that fixed report; do not immediately repeat capture or repair native files.

5. After a successful capture, run the already bundled offline reviewer from the same
   controller directory, without sudo:

   ```sh
   /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_terminal_review.py review-existing --private-run
   ```

   At `Original terminal kit (hidden):`, enter **this same outer kit directory** containing
   `SETUP.json` and `ACTIVE-RUN`, not the inner `run-...` directory. This review starts nothing
   and changes no files. Expect `review_version: 3`, error NONE, step COMPLETE and the three
   provenance/controls/retained-chain checks PASS. Individual differences and OTHER roles are
   observations; do not try to change iTerm2 to make those labels match Terminal.

6. Review and share **both final fixed JSON reports only**. No native records, provenance,
   screenshots, terminal transcripts, directory listing or saved-file upload is needed.
   Keep all private files outside Git. For more scope details see `PRIVATE-RUN.md` and
   `OFFLINE-REVIEW.md` in this kit.

The comparison will select shared canonical process/lifecycle/credential/descriptor code
where the evidence agrees, with explicit application policy or helper stages where it differs.
One successful marker chain does not claim every iTerm2 helper or restoration mode is covered.
