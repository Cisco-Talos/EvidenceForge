# Studio chat experience

## Authorized scope

Implement the October 13 chat plan in the source checkout. Keep the installed Studio session
running; no installer replacement, release bump, tag or publication is authorized.

- Fix interrupt requests using the actual active turn ID, including quit handling.
- Default active follow-ups to Queue; configurable Steer default; Cmd/Ctrl+Enter uses the other
  mode. FIFO queues hold after Stop, failure, uncertainty, closing the last window or workspace
  changes. Reopening never resumes a held queue automatically.
- Preserve chronological item identities and message phases. Commentary/partial answers use
  normal text; user/final messages use bubbles. Keep all commentary after completion.
- Follow new content unless the user scrolls up; restore anchored reading positions and drafts.
- Show live Working for and terminal Worked for durations, without resetting on steering.
- Render each clarification separately with a UI-provided Other/free-text choice.
- Add verified result links, expandable tool summaries, and message/code copying.
- Collapse the conversation list completely; remove fixed message width caps while retaining
  proportional 79% bubble widths.
- Append database v3 and settings v2 contracts; preserve released migration fingerprints.

Conversation search, broader delivery-status UI and additional work-status descriptions are deferred.

## Grounding

The installed Codex CLI is 0.162.1. Its generated protocol has `phase` (commentary,
partial_answer, final_answer), `clientUserMessageId`, `expectedTurnId`, and native turn timestamps
and duration. Request-user-input responses accept a distinct string list for each question ID.
Schema inspection used a disposable directory and did not contact the running Studio chat.

## Implementation and verification

Source implementation is complete. The installed Studio session has not been contacted,
interrupted, restarted or replaced. Product and installer versions remain `2.2.0a2`.

### Changes

- `chat.py`, `chat_store.py` and the service routes own active turn identities, persistent
  FIFO queues, per-conversation dispatch locks and stable client message receipts. Stop waits
  up to two seconds for a pending turn ID. Steer uses the exact `expectedTurnId` and preserves
  the current turn clock. Source permissions and skills are resolved again when a queued
  message is dispatched through the existing turn-submission path.
- Queue state is held after Stop, failure, uncertain delivery, workspace changes, last-window
  close and service restart. Uncertain receipts reconcile against native `userMessage.clientId`;
  they are never replayed automatically. Composer and asynchronous-card submission identities
  survive restoration. Concurrent view saves merge atomically with queue controls so saving a
  draft cannot accidentally clear a queue hold.
- `/chat` provides an ordered native-item snapshot, replay cursor, timing, results, queue and
  private view state. The existing `/turns` and `/history` routes remain supported. Completed
  payloads replace deltas, and partial history snapshots retain already observed item order.
- The frontend renders commentary and partial answers plainly, alongside individually
  expandable tools. User messages and final answers use proportional, content-fitting bubbles.
  Commentary is retained after completion. Legacy unclassified messages only become final
  answers after successful completion. Markdown, safe links, highlighted code and raw-text
  copying remain supported, including the existing WebView clipboard fallback.
- Working timers tick once per second; terminal durations use native times or retained service
  observations. Scrolling follows new content at the bottom, pauses during reading and restores
  stable item anchors. Composer text, skill, nonsecret answers and submission identity are saved
  privately with a short debounce and navigation flush. Draft text typed during snapshot loading
  or delivery is retained.
- Blocking and structured asynchronous questions retain separate answers, initial suggested
  choices, a UI-owned Other option and masked secret input. Resolved server requests disappear.
  Asynchronous answers become guidance to the current turn or an ordinary idle follow-up.
- Verified source changes appear under final answers. Open source/View changes reuse the shared
  source text viewer; Validate calls the existing scenario/pack validation services and displays
  their structured outcome. Paths are checked against the permitted source directory. No
  automatic validation or acceptance was added.
- Follow-up behavior is configurable under Authoring & tools. Enter/button use the default;
  Cmd+Enter on macOS or Ctrl+Enter elsewhere use the other mode. Shift/Alt+Enter remain newlines,
  and IME composition does not send. The send menu supports keyboard navigation.
- The conversation list has a workspace-persisted accessible toggle and leaves no grid column
  when hidden. Fixed 920px timeline, 690px bubble and 1440px focused-workspace caps are removed;
  bubble maximum width remains 79%. Code and tables scroll within their containers.
- Appended `studio-db-0003` and `studio-settings-0002` use the existing verified-backup upgrade
  and recovery path. Released database/settings/layout fingerprints match the original checkout
  and now have an explicit regression test. Scenario and pack files store no chat UI state.

### Verification

All runs used disposable private app state or an isolated UI fixture; no LLM inference was used.

- Frontend: `npm --prefix desktop-ui run test -- --reporter=dot`: **340 passed**, 33 files.
- Relevant service, chat, contract, durability and state upgrade/migration/recovery suites:
  **287 passed**, one Windows ACL case skipped on macOS, 145 extended cases deselected.
  Command:
  ```sh
  UV_CACHE_DIR=/private/tmp/eforge-uv-cache uv run --no-sync pytest \
    tests/unit/test_studio_service.py tests/unit/test_studio_chat.py \
    tests/unit/test_studio_state_contracts.py tests/unit/test_studio_state_durability.py \
    tests/integration/test_studio_state_upgrade.py \
    tests/integration/test_studio_state_migrations.py \
    tests/integration/test_studio_state_edges.py \
    tests/integration/test_studio_state_crashes.py -q --no-cov
  ```
- Native macOS crash matrix:
  `uv run --no-sync pytest tests/integration/test_studio_state_crashes.py -m slow --no-cov -q`:
  **99 passed**. Includes native termination during upgrade, restore and fresh initialization.
- Fake app-server coverage checks exact Stop/Steer parameters, start/completion races, stable IDs,
  FIFO edits/removal, duplicate requests, source policy at dispatch, held queues and explicit
  resumption after restart. Other regressions cover secret filtering, stale questions, item
  reconciliation, result paths, asynchronous questions, clipboard code text and draft races.
- `npm --prefix desktop-ui run types:check`, production build, `uv run --no-sync ruff check .`,
  `uv run --no-sync ruff format --check .` and `git diff --check` pass. Vite retains the existing
  warning about its application chunk exceeding 500 kB.
- Real in-app browser acceptance used the actual ChatView/ScenarioWorkspace components with
  synthetic API data. At viewport widths 736, 1280 and 2000, long bubbles expanded proportionally
  without page horizontal overflow. At 1280, collapsing the rail expanded the chat to 1269px;
  at 2000 its long bubble reached about 1532px.
- New commentary/tools/final text followed the bottom (gap 0–0.5px). Scrolling up preserved the
  reading position when new output arrived; Jump to latest restored following. Reload restored
  the exact `reply-7` anchor and -278px offset, composer draft and collapsed list. The live counter
  advanced through seconds/minutes and became the fixed `Worked for 1m 6s`; commentary remained.
  Queue/Steer menu navigation and Escape were exercised in the browser.

### Delivery boundary before source commit

No commit, installer build/install, version bump, release tag or publication was performed.
The temporary browser fixture, server and browser tab were removed after acceptance. Installed-app/package
acceptance and rollout can follow after the user's active Studio work has finished; this source
change does not update that running instance. Search, broader delivery-status UI and additional
working-status descriptions remain deferred.

The user subsequently authorized committing and pushing the combined chat and pack-discovery
work on the existing `dev` branch. Pre-commit Ruff, generated API types, product-version
synchronization and generation behavior-manifest checks passed. This authorization does not
include an installer replacement, release bump, release tag or publication.
