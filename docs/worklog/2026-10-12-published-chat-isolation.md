# Read-only conversations after publication

## Accepted workflow

Publishing a scenario, industry pack or organization pack retains its existing conversations
and Codex thread IDs. Existing and newly opened conversations on a published version can answer
questions but cannot edit files. Revisions require the user to select **New draft** and start a
new conversation on that separate draft. Chat never creates a revision automatically. Legacy
unmanaged sources are discussion-only until explicitly adopted into a managed draft.

## Permission ownership

Studio derives each turn's permissions from the canonical file-backed lifecycle, verifies release
receipts and checks active drafts against their owning managed container. It grants no write
access to the enclosing workspace, completed drafts, dependencies or other releases. New pack
conversations now start in canonical Schema 3 draft containers, matching scenarios.

Each thread start/resume uses approval policy **never** and an explicit read-only or narrowly
scoped workspace-write sandbox. Studio checks Codex's acknowledgment before sending a turn and
sends the same sandbox policy on every turn. Missing, ignored or widened policies fail closed.
Shell network access and temporary-directory write exemptions are disabled. Hooks, plugins,
apps, multi-agent, browser/computer/code-mode features and configured MCP servers are disabled;
client-side tool calls and permission approvals are refused. User questions remain answerable.

Native testing found that Codex 0.162 retains a loaded thread's previous cwd/policy during
`thread/resume`. Studio first unsubscribes the idle thread, then resumes its persisted history
with the new policy and verifies it. No history injection, thread fork or database migration is
used. The UI obtains computed access and refreshes it when publication changes the source path.

## Validation and release handoff

Model-free native sandbox probes pass on macOS with Codex 0.162.1, Linux x86_64 with 0.162.1,
and Linux ARM64 with 0.162.0. They resume the same formerly writable thread as read-only and
deny chmod, writes from child Python processes, deletion and replacement. New draft writes
succeed while release/completed-draft writes and symlink/hard-link attempts fail. Probes use an
isolated temporary Codex home, synthetic files and no model calls. Both VMs' tracked sources and
user data remain unchanged. CI pins Codex 0.162.1 and requires this native probe on all three
Studio platforms. Setup and test commands are maintained only in CONTRIBUTING.md.

Service regressions cover all three artifact kinds, retained thread identity, denied escalation,
bad-policy acknowledgment stopping before turn/start, explicit revision/new-chat separation,
and refusing a workspace-wide fake draft container. Frontend tests cover discussion labels,
enabled question composition and the publication transition without reopening the chat.
The broad local Studio/desktop/completion run passed 479 tests and exposed two corrected
compatibility expectations. The final affected service/chat group passes all 101 tests.
All 299 frontend tests passed before the additional publication-transition test; the final
ChatView group passes all 13 tests. Generated API freshness, production build, Ruff and version/
generation-manifest checks pass. The macOS native probe must run outside an enclosing agent
sandbox; otherwise nested `sandbox-exec` fails even for the positive read check.

Product version remains 2.2.0a2 and generation behavior is unchanged. No tag or release is
published. Native interactive acceptance of the updated conversations remains necessary before
the user authorizes publication; earlier installer previews predate this change.

## Local acceptance follow-up

The user declined pushing this branch, opening a PR or merging into dev. Keep subsequent changes
local until explicitly authorized. macOS source-launch testing confirmed that the read-only chat
warning appears. The user requested shorter text without a New draft instruction inside chat,
where that action is unavailable. The read-only warning remains visible; editable drafts no
longer show their publication-origin notice. These are presentation changes only.

Previous-version access already exists through **Show previous versions (N)** in the Scenarios
and Packs library toolbar, outside the selected item's conversation. The Studio guide now
specifies that location and the current-filter condition for showing the toggle.
The affected ChatView/App test groups pass all 114 tests, including the existing previous-version
toggle contract. Production frontend build, Ruff and diff hygiene checks pass.
