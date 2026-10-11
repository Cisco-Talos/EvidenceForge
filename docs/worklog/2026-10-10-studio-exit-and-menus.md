# Studio explicit helper exit and shared menus

The user requested helper shutdown when the main app exits on every platform, with running
jobs draining first, reopening cancelling the pending exit, and each subsequent quit repeating
that behavior. They clarified that proactive notification should be primary, with heartbeat and
timeout fallback retained. They also requested the same About window as macOS on all platforms
and a Linux menu Quit action.

## Implementation

- Native bootstrap supplies one stable application session based on the native shell's PID and
  creation time, verifies same-account ownership, and immediately attaches before renderer load.
  Renderer reload/reconnect uses that same session instead of leaving extra renderer leases.
- The native shell retains its private connection in memory and explicitly detaches on
  `studio_exit` and final native exit, awaiting a bounded acknowledgement. This supplements the
  existing durable renderer quit-policy handoff, including maintenance/early-boot exits.
- Native notification uses the dedicated authenticated `/v1/session/app-exit` endpoint.
  Legacy renderer detach retains its crash/close grace policy; native exit explicitly requests
  shutdown as soon as protected work drains, without waiting for heartbeat expiry.
- Explicit last-app detach requests prompt idle shutdown; busy work remains protected by the
  existing request/job/authoring/worker/upgrade fences. Reattachment cancels pending shutdown.
- Process identity and heartbeat expiry remain fallbacks for unexpected exits. Native sessions
  remain owned by a verified live shell even if a minimized renderer stops sending heartbeats.
  Uncertain process inspection retains ownership; PID reuse never counts as the original shell.
- Routine reconciliation locking defers the idle check rather than restarting the grace period
  on every poll. The final locked worker/queue check remains authoritative before shutdown.
- Linux's predefined About label is `&About`; normalize menu mnemonic markers before replacing
  it with the existing branded `#about` window. Wayland position failures no longer prevent
  showing that shared window. Add File → Quit EvidenceForge Studio with Ctrl+Q, routing through
  the same main-window handoff as closing the window and macOS Quit.

## Build status

Frontend TypeScript/Vite compilation, macOS Rust compilation, full repository Ruff lint and
format checks, and whitespace checks pass. Updated the existing polling-lock assertion to
reflect deferral without restarting the grace period. No tests were added or run for this request.
Native running-job/reconnect and Linux menu acceptance remain for user review.
Current source changes are on `codex/studio-linux-usability`, version 2.2.0a2; no release
publication, tag or version bump is authorized by this change request.

## Local build completion

Rebuilt the macOS source `.app`, Linux source executable, native Linux AppImage, and macOS
standalone `.app`/DMG successfully. Generated API types include native identity headers and
the app-exit endpoint. Both installer checksum files pass. Packaging validates the installed
generation behavior declaration before assembling runtimes; it remains revision 161 / `bd9e...`.

| Local installer | Bytes | SHA256 |
| --- | ---: | --- |
| `dist/linux/EvidenceForge-Studio-2.2.0a2-aarch64-test.AppImage` | 135330312 | `96aba3175eb396b6eae7095f88dd8cb304c9132318506cf574ab7585b72a9b76` |
| `dist/macos/EvidenceForge-Studio-2.2.0a2-aarch64-test.dmg` | 37701446 | `bdf6ce9961a4e608f305f585309138289a7e2a63d83200e4fc56e9ed08a8eebe` |

AppImage is present at the same path under the VM's `~/EvidenceForge/dist/linux/` and copied
back to the Mac. Previous local installers are backed up under
`/private/tmp/eforge-a2-installers-before-exit/` on the Mac and
`~/eforge-build-setup/a2-appimage-before-exit/` on the VM. Source replacements are backed up
under `~/EvidenceForge.sync-backups/a2-explicit-helper-exit*`.

Build logs: `/private/tmp/eforge-studio-a2-exit-macos-build.log` and the VM's
`~/eforge-build-setup/studio-2.2.0a2-appimage-exit-final.log` /
`studio-2.2.0a2-source-exit.log`. The first sandboxed Mac packaging attempt could not resolve
PyPI DNS; the network-authorized retry succeeded. Native builds do not establish runtime
acceptance: jobs-draining/reopen behavior and menu interaction still require user review.
No Windows native build or execution was performed.

The user authorized stopping all Studio helpers. Same-account process inspections on both
machines found none still running, so no process was terminated. Existing Studio app sessions,
detached generation workers, user data and settings were not modified. Installers remain local,
unsigned previews at 2.2.0a2; no release publication, tag, push or commit was performed.
