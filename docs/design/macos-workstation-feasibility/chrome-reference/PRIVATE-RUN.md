# Private Chrome main/helper reference

This is one fresh Chrome startup, an invented local page with a WebGL canvas and
local fetch, and a manual quit. It gathers the main, renderer, GPU and network
helper relationships needed by the fixed workstation workload. It is **not** a
blind assessment, an ordinary browsing sample or automatic generation admission.

**Use a fresh version-2 kit.** Version 1 passed inline signing requirements as
filenames and did not explicitly select XML entitlement output. Version 2 fixes
both, verifies app code through its containing signed bundle, binds the returned
metadata to the hashed executable, and returns only fixed diagnostic labels for
any installed-code failure. Do not overwrite or retry the partially set-up v1 kit.

Agents may prepare this code-only kit and test invented records. **Only the human
runs setup, capture and report**, privately after closing agents. No existing
capture, personal browser profile, historical logs or installed Chrome metadata
were read while preparing it. Do not run this inside a Git checkout or synced
folder. Keep the kit and its parent directories on trusted local storage.

One separate exception is available for `diagnose-code`: an agent may run it
**only after explicit permission for that bounded installed-code check**. It is
read-only and does not run setup, compile a probe or retry collection.

## Diagnose a signing-check failure without another setup attempt

If setup fails at MAIN / SIGNATURE_VERIFY / COMMAND_EXIT, the original combined
check does not distinguish signature/resource validity from the explicit signer
requirement. A fresh prepared code-only copy supports:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_chrome.py diagnose-code --private-run
```

This runs exactly six fixed, read-only `codesign` commands against only the
standard Chrome app bundle and its main executable. It reports basic bundle
verification, strict verification, strict verification with the Google signer
requirement, that requirement on the main executable, a **separate diagnostic**
that validates executable code without its resources, and XML metadata parsing.
The last comparison does not change or bypass the capture admission checks.
Apple documents executable-only verification in its
[Apple Silicon release notes](https://developer.apple.com/documentation/macos-release-notes/macos-big-sur-11_0_1-universal-apps-release-notes).
Each command has a 15-second timeout, so a stalled run can take approximately
90 seconds. No sudo, `spctl`, online notarization request, re-signing, permission
change or app execution is requested.

It compares main-executable hashes privately before/after and reports only
whether they agree. Signer, identifier and executable-binding values are compared
with fixed public templates and are never exported. Known public error phrases
map to closed labels; arbitrary command output, private paths, certificate names,
hashes and unknown messages stay hidden. A diagnostic `error: NONE` means it ran,
not that its independent checks passed. A message class is a tool observation,
not an independent root-cause conclusion.

It reads no prior kit file, setup manifest, native record, browser profile or log,
writes no helper files, and starts no collector, server, probe or browser. Normal
macOS tool/security-service activity may still occur. Human may run it privately
and share only its fixed JSON, or explicitly authorize the agent to run this
specific command and receive only that JSON.

## Privacy and exact scope

- Setup reads installed code, signed-bundle resources and Info.plist/signature metadata in
  `/Applications/Google Chrome.app` and `/usr/libexec/xpcproxy`. It compiles the
  existing harmless readiness marker and 55-second collector guard. It does not
  launch Chrome, start a collector, enumerate processes or open any Chrome profile.
- Capture launches **a new instance through LaunchServices (`open -n -a`)**, with
  an explicit new `--user-data-dir` inside the private run. Do not use this profile
  for anything else, sign in, open personal pages or use restored tabs. Do not
  change or re-sign the installed app. Quit ordinary Chrome first.
- Disconnect Wi-Fi/Ethernet before capture; loopback still works. The flags reduce
  background networking, extensions, sync and first-run prompts, and request the
  mock keychain. They are **not a network sandbox or a promise that every Chrome
  version honors them**. Physical network disconnection supplies that boundary.
  No sandbox-disabling or remote-debugging flag is used. Browser/OS integrations
  may still touch OS-managed preferences, registrations or logs.
- The supplied tiny server binds only `127.0.0.1`, chooses a free port and serves
  fixed nonce routes from memory. It serves no files, reads no profile, logs no
  requests, stores no headers and accepts no submitted content. It stops at the
  end of capture. You need no web server or second terminal window.
- The existing guarded `eslogger` receives machine-wide fork/exec/exit events in
  bounded memory. Nothing ambient is written to disk. Admission requires the
  exact installed main executable, expected signature and unique test-profile
  argument plus local URL and controlled arguments. File-object identity admits
  alternate native path spellings but reports them separately. Its xpcproxy ancestry and descendants require exact
  execution/image or kernel parent-token linkage; PID or path prefixes alone do
  not admit rows. An unrelated personal Chrome instance is not the test browser.
- **Matched native rows can contain sensitive parent/responsible identities,
  paths and environment values.** They remain local in owner-only files. Never
  send the whole kit, provenance, profile, native records, transcripts or screen
  captures. OS swap, backup, crash reporting and other endpoint agents are outside
  this helper's control.
- Only `SHAREABLE-CHROME-REPORT.json` is intended to leave the kit. It contains
  closed labels, public entitlement/switch names from an independent allowlist
  and opaque sequential execution/pipe aliases. Unknown names and values stay
  hidden. Review it yourself before sharing it. No observed UID, PID, hostname,
  home, path, environment value, URL, profile data or signature hash is exported.

The reference targets macOS 27 arm64. The installed Chrome version stays private;
the report says only whether it exactly matches catalog release 155.0.8059.80.
Another release remains useful, but is not evidence of exact catalog parity.
LaunchServices arguments are needed to select a disposable profile, so this does
not by itself qualify a direct Finder double-click, Dock, Spotlight, app reuse or
session restoration. Terminal/iTerm2/SSH/launchd references remain separate.

## 1. Setup (normal user, no sudo)

In the standalone terminal that already has Full Disk Access for eslogger, enter
the **new prepared kit directory**. Keep the repo/venv and kit code unchanged.
Close Codex and other agents before running:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_chrome.py setup --private-run
```

Expected: `stage: SETUP_READY`, `error: NONE`, `provenance: PASS`. Setup starts no
apps or collectors. `APP_MISSING` means the standard installed location is absent;
do not move Chrome or paste a private path. A build or metadata error reports a
fixed label, never native command output. Stop on any error and share only that
fixed JSON; the version-2 fields `installed_code_item`, `installed_code_check`
and `installed_code_failure` identify the failed stage without exporting paths,
command text or stderr. Do not run capture after failed setup. Do not repair a partial kit by
overwriting private files: use a new code-only kit.

## 2. Prepare the controlled launch

1. Save ordinary work and **fully quit all Chrome windows** yourself. The helper
   does not inspect personal browser processes or issue bundle-wide quit commands.
2. Disconnect Wi-Fi and Ethernet. Keep them disconnected until Chrome has quit.
3. Leave the standalone terminal visible beside the space where Chrome will open.
   Do not browse or start unrelated work during the approximately 45-second test.

## 3. Capture, then quit the test Chrome

One command, in the same kit directory:

```sh
sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_chrome.py capture --private-run --chrome-closed --network-disconnected
```

Keep `&&`. **Python must run as your ordinary user**; only its collector guard
uses sudo. The two final flags attest to the manual preparations above. Do not
add `tee`, shell tracing, output redirection or a transcript wrapper.

1. `COLLECTOR_READY` means the harmless marker exec/zero exit was observed.
   Readiness takes up to ten seconds and uses at most eight attempts.
2. `BROWSER_READY` means the controller has issued the new-instance launch. A
   Chrome window should show **EvidenceForge private reference**, an invented
   page and green canvas. No personal tabs, login or policy override is needed.
3. After the local fetch and at least five seconds, the terminal prints
   **`stage: QUIT_CHROME`**. Click the **test Chrome window** and press **Command-Q**.
   Do not just close the window. You have roughly 25 seconds to quit.
4. Capture observes the main exit, stops/reaps eslogger and stops the server.
   The final **short** JSON summary appears. It saves full fixed details as
   **`SHAREABLE-CHROME-REPORT.json` directly in the outer kit directory**.

If no expected test window appears, a private profile error appears, an alert
requests a policy override, or personal tabs appear: stop with one Ctrl+C, quit
the test app manually, and keep the fixed failure report. Do not override security
policy, change system permissions during collection, or paste the browser UI.

The root collector has its existing independent 55-second watchdog and parent
pipe cancellation. Python collection is bounded to 32 seconds after launch;
whole stream 256 MiB, single row 1 MiB, ambient ring 16 MiB/1,024 rows, retained
graph 32 MiB/256 rows, execution aliases 64. Exhaustion/gaps are reported and do
not establish complete evidence. The server has a per-connection timeout, at
most 128 meaningful requests, no directory traversal or disk-serving route.
The shareable report has a 4 MiB limit; exhaustion returns LIMIT and omits phase
details rather than presenting a truncated graph as complete. Summary counts
distinguish forks, execs and exits, including lifetimes without a corresponding
fork/exec/exit. Counts describe retained evidence, not an independent OS census.

On interruption/timeout the helper stops the collector/server but **never kills
Chrome by PID or issues a quit affecting other browser instances**. Quit the test
browser yourself before reconnecting your network. A missing observed exit or
cleanup failure keeps the capture lock; do not retry in that kit. If collector
cleanup fails, keep agents closed, allow the 55-second guard to finish and
privately resolve cleanup before preparing a new kit. Do not paste process lists.

## 4. Share only the fixed report

After Chrome has quit and `collector_cleanup` and `server_cleanup` are PASS,
reconnect your network. Privately review **`SHAREABLE-CHROME-REPORT.json` in the
outer kit folder**, reopen Codex and attach **only that file**. The native records
and test profile are inside `run-…`; do not attach them or the whole directory.
The summary alone omits the per-process details required for implementation.

There is no need to run a second checker. If you want to recompute the latest
report offline yourself:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_chrome.py report --private-run
```

It reads only that kit's bounded files/code and makes no live queries, starts
nothing and writes nothing. It prints the short summary. `--full-report` also
prints all fixed details if desired; the saved file avoids scrollback limits.
`gate_status: NOT_EVALUATED` and `reference_review: REQUIRED` are intentional.
Missing helper roles or unknown fields remain explicit gaps, not automatic passes.

## Public design inputs

The runtime experiment tests these leads; public source is not an installed
release observation:

- Apple's [requirement syntax](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)
  uses a leading `=` on an inline `-R` argument; its
  [entitlement extraction instructions](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
  explicitly select `--entitlements - --xml` for XML parsing. Human-readable DER
  display is not accepted as a plist or silently replaced by empty entitlements.

- [Google's tooling flag documentation](https://github.com/GoogleChrome/chrome-launcher/blob/main/docs/chrome-flags-for-tools.md)
  describes profile separation, first-run/background-networking controls and mock
  keychain. This kit retains normal GPU and sandbox paths.
- [Chromium macOS signing](https://chromium.googlesource.com/chromium/src/+/main/chrome/installer/mac/signing/README.md)
  distinguishes official/development builds; local static signatures are compared
  with native snapshots without exporting signatures.
- Chromium's [common app](https://chromium.googlesource.com/chromium/src/+/main/chrome/app/app-entitlements.plist),
  [branded app](https://chromium.googlesource.com/chromium/src/+/main/chrome/app/app-entitlements-chrome.plist),
  [renderer](https://chromium.googlesource.com/chromium/src/+/main/chrome/app/helper-renderer-entitlements.plist)
  and [GPU](https://chromium.googlesource.com/chromium/src/+/main/chrome/app/helper-gpu-entitlements.plist)
  templates supply the independent public key allowlist. Unexpected keys are
  summarized only as PRESENT; their names and values remain private.
