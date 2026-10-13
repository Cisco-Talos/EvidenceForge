# Studio Codex connection and account status

The user requested this follow-up after the Studio object-action refactor. That refactor was
committed locally as `27ccd099` (`feat: unify Studio object actions`), without pushing. The Codex
indicator change was kept separate in the working tree for review. The user has now authorized
committing it with the completed UI work and publishing the 2.2.0a2 prerelease.

## Requirements and implementation

- Red means Codex is not connected. Yellow means connected but signed out or unavailable for
  work. Green means connected, signed in and ready for work.
- Clicking the indicator opens details in every state, including service disconnection. The
  dialog shows connection, account identity and current work status or failure details.
- Login uses the same browser authentication flow as Settings. It is grey and disabled while
  disconnected, and enabled in yellow and green states. Green-state Login starts sign-in,
  without invoking logout. It is temporarily disabled while opening login or reconnecting.
- Reconnect retains active-turn interruption warnings and the existing service safeguard.
  Every active turn is counted, including turns running while the indicator is green. Failed
  reconnection leaves details open. Escape dismisses the dialog and restores indicator focus.

The existing service heartbeat now reads account, model and tool availability with bounded requests.
Readiness is separate from transport state so account status does not change existing active-turn
reconciliation. Repeated unchanged heartbeats do not add events. Settings status reads and logout
also update the live indicator. Account labels are display identities; credential data is excluded
from health snapshots and events. Disconnected transport errors have their own exception subtype
so a rejected request or timeout can remain yellow rather than incorrectly appearing disconnected.
Login, logout, reconnect and status reads share the health lock to avoid conflicting updates.
Readiness is published after model and tool discovery both succeed, avoiding a transient green
state when tool discovery fails. Open chats refresh their account/model status after login or
logout while preserving the message draft and history.

Green reflects the current account, model catalog, tool discovery and responding local Codex transport. These
checks do not start an AI turn or consume model tokens. The normal heartbeat refreshes external
account changes; the shared login flow also polls for completion while its UI is open.

## Verification

- The final full frontend suite passed 317 tests across 31 files, including details, all three colors,
  Login availability in yellow/green, native/browser login opening, error recovery and keyboard
  dismissal. The existing Settings pending-login completion test still passes. The new open-chat
  regression verifies login/logout refresh, model choices, preserved draft text and unchanged history.
- The service suite passed 92 tests, including ten new account/readiness and login/logout cases.
  Subsequent focused checks passed all 24 Codex-related service cases, including actual fake-process
  RPC rejection, timeout and exit classification. An additional case checks failed tool discovery
  without any transient ready event; the final availability/transport check passed all 11 selected cases.
- Production build, generated API type checks, Ruff and whitespace checks passed.
- Browser inspection uses the real React indicator and styles with isolated sample state at
  1280, 736 and 320 px. No Studio database, credentials or actual authentication is used.
  The dialog remains within the viewport, account/status text wraps, and red Login is disabled.

Release preparation reran the full frontend suite: all 326 tests pass. Shared product metadata
already uses 2.2.0a2. Integration and publication are recorded in the
[release worklog](2026-10-12-release-2.2.0a2.md).
