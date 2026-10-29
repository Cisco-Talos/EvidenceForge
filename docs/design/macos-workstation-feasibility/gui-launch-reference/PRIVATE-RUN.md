# Human-only private Finder launch reference

For a **new** opt-in launcher/entitlement experiment, use [LAUNCH-CHAIN.md](LAUNCH-CHAIN.md).
The original procedure below remains the app-only mode and must not be applied to old private
kits as an upgrade. Agents prepare a fresh code-only copy for the new experiment.

Agents may prepare this kit, compile its sources without executing, and test invented inputs.
**Only you run `setup`, `capture`, `report` and `review-existing`, privately after closing
Codex and other agents.**
Do not attach this directory, native records, own-process snapshots, terminal transcripts or
screenshots. Share only the fixed final JSON report after reviewing it yourself.

## Scope and privacy boundary

This experiment targets macOS 27 arm64, one harmless, locally built AppKit app and two launches:
a direct command-line control followed by your manual Finder launch of the **same executable**.
During its main launch the app observes only itself, writes into this owner-only kit and shows a small window that
closes automatically after approximately two seconds. It enumerates no other processes,
opens no personal documents and makes no network requests. AppKit and macOS can perform their
normal preference, LaunchServices, security-agent or OS logging activity; this kit cannot prevent
that. Normal app launch can leave OS-managed application registration/recent-item state.

The app's own snapshot is taken at **main entry**, after the loader has run and before its own
output file or window is opened. Differences from the kernel exec notification are reported,
not silently treated as identical. This is an ad-hoc-signed, non-sandboxed test app, not proof of
every vendor app's behavior. Dock, Spotlight, Apple Terminal, GUI helper classes and Unified Log
messages are outside this experiment.

`eslogger` receives machine-wide fork/exec/exit notifications in the local filter's memory.
**Unrelated rows are never written by this kit.** A bounded in-memory fork buffer lets a later
exact test-executable exec prove which earlier child belongs to the experiment. Admission uses
the executable's device/inode plus audit PID version and process birth, never a path prefix or
PID alone. Matched rows still contain potentially sensitive parent/responsible identities,
paths and environment values; those stay private. The report exports only fixed labels.
OS swap/crash reports, backups and existing security software remain separate considerations.

After stopping the collector, the controller may make up to four **audit-token-bound role
queries**: the parent and responsible tokens from the two matched app execs. The same probe's
non-GUI `--classify` mode uses `proc_pidpath_audittoken`, with no PID-only fallback or enumeration.
It compares the returned path only in memory with fixed system-app paths and emits a label such
as `FINDER`, `LAUNCHD`, `OTHER` or `UNAVAILABLE`; it never prints or saves that native path.
Each query has a three-second deadline. Exited, replaced or inaccessible processes can remain
unavailable. Offline `report` reuses those fixed observations and makes no live role queries.

Keep the kit on local nonsynced storage outside every Git working tree. It uses 0700 directories
and private 0600 output files. No dependency install, network server, security-setting change,
historical log read or Unified Log collector is part of the procedure. Command Line Tools,
`eslogger` access and the needed existing Terminal permissions must already be available;
otherwise stop and keep the fixed failure report private until you review it.

## Step 1: build without launching

In a standalone Terminal, `cd` to the **prepared kit directory**. Run Python as your normal user:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B private_gui_launch.py setup --private-run
```

Expected fixed result: `stage: SETUP_READY`, `error: NONE`. This compiles the app and bounded
collector guard, ad-hoc signs the app and records hashes. It starts no collector and launches
no app. Keep the checkout/venv and kit code unchanged through collection and offline review.
If setup partially fails, prepare a fresh kit rather than replacing private files in this one.

## Step 2: have Finder ready

Open the prepared kit folder in Finder yourself. You should see **GUIProbe.app** directly inside
it. Select it, but **do not launch it yet**. Leave this Finder window ready beside Terminal.
Do not download the app, add quarantine attributes, override an alert or change security policy.
This is a successful local launch test, not a repeat Gatekeeper experiment.

## Step 3: collect the control, then launch through Finder

Close Codex and other agents before running this command in the standalone Terminal:

```sh
sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B private_gui_launch.py capture --finder --private-run
```

Keep the `&&`: Python stays your ordinary user. Only its fixed collector guard runs under sudo.
The `--finder` flag attests that you will use Finder for the second launch. Never run the whole
Python command under sudo or add `tee`, shell tracing or output logging wrappers.

1. The helper waits up to ten seconds for a matching harmless readiness exec/exit. It makes at
   most eight attempts and prints `COLLECTOR_READY` only after observing a controlled pair.
2. It launches the command-line control automatically. **A small test window should appear and
   close by itself. Do not launch the Finder copy during this stage.** No policy alert is expected.
3. Wait for the separate fixed JSON block with **`stage: FINDER_READY`**. You now have **30 seconds**
   to double-click **GUIProbe.app in the already-open Finder window**. Do not use `open`, Spotlight,
   Dock or a terminal command. That launches the same test executable using the selected method.
4. The second small window closes automatically. The helper observes the native exit, stops and
   reaps the collector, and prints the final JSON. Read `error` and `collector_cleanup` before
   considering anything complete. `gate_status: NOT_EVALUATED` and `reference_review: REQUIRED`
   are intentional: this tool diagnoses evidence; it never enables generation automatically.

The readiness/control/Finder windows have ten/eight/thirty-second deadlines. Independently, the
root guard has a 55-second limit and watches its parent pipe; parent exit or cancellation triggers
child cleanup. Input is bounded to 32 MiB, one line to 1 MiB, the transient fork buffer to 4 MiB/64
rows and retained evidence to 16 rows per launch. Collector errors, gaps or exhausted bounds do
not count as successful evidence. If `collector_cleanup` fails, keep agents closed; allow the
55-second guard to finish and privately resolve cleanup before using a fresh kit. The kit keeps
its lock on cleanup failure. Do not paste process listings or private error output.

One Ctrl+C cancels the Python run and requests collector cleanup. The app also has its own
eight-second watchdog. Do not open another capture while a previous run or test app is active.
If a policy dialog appears instead of the expected small window, do not override it: stop and
review the fixed report privately. That outcome does not qualify successful GUI launch.

## Step 4: review and share only the final fixed report

Each attempt creates a fresh `run-…` directory. Nothing overwrites or deletes earlier evidence.
You do not need to select that directory or type its path into the checker. This command reads
the latest run through the kit's private pointer, starts no collector or app, and prints labels:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B private_gui_launch.py report --private-run
```

Review the final JSON yourself, then reopen Codex and paste **only that JSON**. All other files,
including `control-events.jsonl`, `finder-events.jsonl`, `*-self.json`, provenance and the whole
run directory, remain private and outside Git. The app stores its own argv/environment privately
as byte-preserving hex; **hex is not redaction**. Do not share those files.

Fixed checks describe audit/lifetime agreement, fork→exec linkage, parent/original-parent and
responsible identity relationships, POSIX session, descriptor kinds/access/tty, argv/environment
agreement and known test completion/exit. A missing fork can remain `INCONCLUSIVE`. Descriptor
or environment differences between native exec and main entry are observations requiring review.
No report contains identifiers, native counts, paths, variable values, hashes or raw fragments.

Privacy-preserving human review may establish a bounded launch contract after we inspect the
fixed results. It does not generalize Finder evidence to other launch methods or enable broader
ES/Unified Log families. Private retention/deletion is your decision; agents will not inspect
or remove the evidence.

## Offline follow-up for an existing capture

Use a **new prepared code-only reviewer** for this step. Leave the original kit, its helper,
compiled app, manifest and run files unchanged. Do not run setup or capture again. This
follow-up starts no collector, app, preflight command or live parent/responsible lookup, and
changes no files. It locally reads the original provenance and bounded controlled evidence.

After closing agents, run from the new reviewer's directory, as your normal user:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B private_gui_launch.py review-existing --private-run
```

At the hidden prompt, enter the **original outer kit folder** that contains `SETUP.json`,
`ACTIVE-RUN` and `GUIProbe.app`. Do not enter an inner `run-…` folder or the new reviewer's
folder. Your input will not echo. The checker refuses noninteractive input or an echo fallback.
No sudo, Finder interaction or new small window is needed. The original kit's frozen codec
and files must still match their setup manifest.

The report distinguishes exact/order-only environment agreement from added/removed variable
names and changed values on common names, preserving duplicate-assignment multiplicity. Only
the known technical variable `__CF_USER_TEXT_ENCODING` gets a dedicated presence/change label;
its value is never exported. No other variable names, values, counts, lengths or hashes appear.
The direct control's native exec vector is also checked against the kit's declared clean input.
These checks compare kernel exec evidence with a later main-entry snapshot; they do not assume
that a difference invalidates the kernel vector or that application startup made a specific change.

The version-2 and later supplemental reports also include `control_launch` and `finder_launch`. These
classify existing native process/image relationships, whether session/group IDs identify the
child as leader, controlling-tty presence (separate from stdio), standard-only FD inventory and
extent, cwd as root/declared HOME/other, script absence, native slice, null entitlements and
signature agreement. No raw IDs, paths, signature/flag values, environment keys or counts appear.
These distinctions were absent from the original fixed report but are needed before constructing
a canonical GUI birth-to-exec contract. They use the same already captured controlled evidence;
do not repeat setup, capture, Finder launch or any live lookup for this follow-up.

Version 3 adds the launcher's **before-exec** audit-origin and responsibility classes plus its
individual session/group relationships. A changed audit origin alone does not identify its old
class. The checker reports sentinel/root/real-user/target/other relationships and default-zero/
target/other audit-session classes, without exporting numbers. Responsibility distinguishes the
before snapshot, parent, target execution, same PID with a different identity, and unrelated or
unset tokens. Matching a PID does not establish a lifetime. These labels help finish the launcher
producer without guessing its prior attribution. They read the same existing bounded evidence;
no additional capture, app launch or variable-name/value disclosure is needed.

Version 4 explains an ambiguous same-PID responsibility token field by field. Both the
message process and exec target receive a fixed comparison for audit user, effective/real
user/group, PID, audit session and PID version. Labels are only `BOTH`, `BEFORE`, `TARGET`,
`ZERO`, `MAX_WORD`, `OTHER` or `INCONCLUSIVE`. The maximum-word label gives no field-specific
meaning to that technical constant. For the controlled PID only, PID-version
position can be before/target/equal/between/less-than-both/greater-than-both. This is a numeric
comparison, not proof of temporal order or an explanation of the exporter's sampling. No token
words, account names, IDs, counts, paths, timestamps or foreign-process version positions appear.
It reads the same bounded original capture with the same provenance controls and starts nothing.

`RETAINED_MATCH` establishes a matching retained fork. `NOT_RETAINED` says only that the bounded
evidence contains none; it does not prove no fork happened or distinguish launch mechanism from
filter/buffer limitations. Failed original collection controls leave supplemental comparisons
inconclusive. Every result retains `reference_review: REQUIRED` and `gate_status: NOT_EVALUATED`.
Review and share only this fixed supplemental JSON; keep the original path and evidence private.
