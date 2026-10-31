# Mac process producer inventory and finite acceptance matrix

The completeness contract counts **modeled starts and successful image activations** in the
half-open simulation window. It does not attempt a census of unmodeled host activity.

The two State mutation owners are
`StateManager._commit_prevalidated_process_materialization` (all births) and
`StateManager._commit_prevalidated_action_cohort` (all image replacements). Repository searches
for assignments to the running-process table and execution ordinal identify no other generation
mutation owner. Registration, compatibility creation, ordinary materialization batches and action
cohorts converge here. Checkpoint restore hydrates the persisted counters rather than counting
restored processes again. Source qualification, routing and rendering do not create expectations.

Per host, accounting retains two counts and SHA-256 multiset fingerprints, an aggregate-start
count and at most eight examples. It does not retain a process history proportional to scenario
duration. The ordinary per-cohort rollback journal captures the counters with process State.
Exact source preparation still owns field-level canonical identity proofs. Finalization compares
independent occurrence fingerprints, committed native journal counts and the streamed synthetic
export against publication receipts. A complete bundle cannot be accepted after a mismatch.

## Allocation and execution entry points

| Producer family | Owning entry points | Current classification in the complete contract |
| --- | --- | --- |
| Boot, long-lived system tree and collector | `engine/emitter_setup.py` Mac host bootstrap and boot batches | Actual pre-window starts are existing state; in-window starts are counted. No retrospective exec is invented. |
| Ordinary local and non-PTY SSH commands | `actions/process_execution_service.py` shell root | Qualified fork plus exec for supported literal argv and known metadata. Each activation has its own identity, including nested supported shells. |
| Finder reference app | Same process service and retained `actions/macos_finder.py` coordinator | Qualified canonical/native boot-parent fork, root xpcproxy exec, GUI-account credential binding and app exec replace the aggregate birth. Known app exit uses the existing completion owner. Revision 357 closes the no-parent token gate with approved fixed-output evidence and an assigned canonical boot audit origin. Complete census, phase recovery, filtering and checkpoint/resume cover this bounded producer. |
| Fresh Terminal/iTerm2, login and initial shell | `actions/macos_terminal.py`; `activity/generator.py:ensure_macos_session_shell` | Revision 364 replaces the current-profile aggregate with retained native startup. Apple has 3 forks/4 execs; iTerm2 3.7.6 has 4 forks/6 execs. Public complete workloads, exact interruption recovery, filtering and checkpoint/resume pass. Existing shells reuse identity; new windows/restored jobs in an existing app remain unsupported. |
| Generic apps | Process service generic root | Unqualified aggregate starts remain counted and reject complete mode; other applications do not inherit the reference app's signing or launch facts. |
| Parent-chain repair/implicit parents | `actions/process_support/parents.py` | Canonical starts are counted even when a producer suppresses a CREATE row as “pre-existing.” Only the actual start time decides window eligibility. |
| System/service worker reuse or creation | `actions/process_support/system.py` | Reuse adds no start. New aggregate workers are unresolved and reject complete coverage. |
| launchd jobs and persistence activation | `actions/macos_launch_item.py` and process/service composite | Registering/loading a job is not a process start. An actual job process is counted and currently lacks a qualified initial exec producer. |
| SSH receiver fork/exec roles | `actions/macos_ssh_receiver.py` | Explicit forks/execs are counted independently. A small receiver startup has 3 native forks but 5 expected execs: the wrapper is still an aggregate birth, and helper/shell exec descriptors remain unknown. Revision 365 supplies verified static helper entitlements without inventing FD tables. A partial phase pass cannot satisfy the whole session census. |
| Native SSH client | `activity/generator.py:_ensure_macos_ssh_client_process` | Shares the qualified local terminal/command owner. Its verified vendor signature includes a signed integer entitlement. Canonical values, checkpoints and decoder preserve that type; the current generation profile still gates its native export until a reference confirms the wire shape. |
| Generic SSH receiver compatibility | `actions/ssh_session.py` | Mac receivers delegate to the Mac owner. Linux-only aggregate receiver code does not qualify a Mac helper. |
| Persistent SMB client materialization | `actions/network_connection.py` | Existing client reuse adds no start. A newly materialized Mac client is counted; a generic aggregate client cannot silently pass complete mode. |
| Generic network responder preparation | `activity/generator.py` network responder batches | Linux receiver branches remain Linux-specific. Any actual modeled Mac aggregate reached through compatibility paths is still counted. Mac SMB serving remains outside the supported capability set. |
| Explicit retained scripts and runtime-image processes | Shared shell execution and artifact owners | A qualified literal shell launch with explicit retained shebang facts now uses the same fork/exec transaction. Script-looking argv alone keeps a null script fact. Exact interpreter and script retention remain separate. |
| Endpoint/effect-bearing processes | Shared process execution/effect owners | Qualified literal shell launches with planned file effects, including authenticated retained creation/modification/removal, publish fork, exec and dependent files in one exact transaction. Writes to the executing image, unrelated mixed effect plans, scanners and unsupported launch metadata retain their gates. All actual births/execs still count. File effects are canonical/eCAR evidence; this does not qualify native ES file callbacks. |
| Windows/Linux-only session helpers | `actions/rdp_session.py`, `process_support/parent_windows.py`, `parent_linux.py`, OS-specific logon branches | Outside the Mac census. Their generation semantics are unchanged. |
| Context factories and lifecycle registration | `events/contexts.py`, lifecycle registry/shadow/head | Context construction and lifecycle bookkeeping are not additional State births; counting them would duplicate obligations. |
| Failed exec, denied launch, policy refusal | Typed process outcome owners and transient PID reservation | No successful image activation is invented. If a caller/launcher actually starts, that separate process still counts. |

Every new producer must converge on the existing State mutation owners. Writing process tables
directly or manufacturing native rows outside the authenticated source publication contract is
not a supported extension path.

## Finite acceptance matrix

| Contract | Verification |
| --- | --- |
| Useful complete workload | Eleven local commands from an explicitly modeled pre-window terminal: all eleven canonical forks and execs match native publication and export. |
| File-producing workload | A literal shell command with one or several planned file reads has one fork and exec, with every file effect bound to the executed identity. Selected/filtered output, immediate/ordered source publication and interrupted journal acknowledgement are covered. Invalid effect timing and capacity reject before process allocation. |
| Retained file mutation | Qualified interpreter commands create, modify or remove a retained synthetic file in the same fork/exec transaction. Native-only and eCAR-filtered output, full State/artifact checkpoint restoration, artifact-tail rollback and interrupted journal recovery retain exact identities and versions. A mismatched file publication time or unrelated effect plan cannot claim native completeness. |
| Producer bypass | Disable the qualified shell producer: aggregate starts remain in the census and complete finalization rejects. |
| Session boundary | Fresh terminal startup inside the window reconciles every fork/exec for both apps. Pre-window startup contributes no retrospective native rows. Unsupported aggregate families still reject even when their subsequent commands have native execs. |
| Same PID, multiple execs | Each execution identity counts independently; full State checkpoint round-trip and subsequent exec agree. |
| PID reuse | A new lifetime with the same PID has a different obligation. |
| Window boundaries | Pre-window births and end-boundary starts are excluded; an in-window exec in an old lifetime is included. |
| Rollback/retry | Provisional exec abort restores census; retry adds exactly one obligation. Existing exact native write recovery avoids duplicate delivery. |
| Legacy registration | Direct aggregate materialization without any ES factory still adds an exec obligation. |
| Publication faults | Omitted/doubled native writes reject; physical export duplication or alteration rejects against receipt fingerprints. |
| Collection policy | Disabled source, removed process capability, loss and shortened windows reject during preflight, even with no process events. Partial collection requires an explicit partial policy. |
| Filter/recovery regression | Finder and paired-terminal public CLI workloads pass complete reconciliation and nonempty checkpoint/resume. SSH receiver/helper workloads remain bounded partial diagnostics until their remaining metadata/startup contracts are qualified. |

The source profile and native reference gates remain separate. Qualified Finder/terminal
startup does not qualify other application/service activations, SSH helper tables, integer
entitlement export, PTY helpers or Dock/Spotlight attribution. Unresolved starts remain in the
denominator. The prepared human-only [SSH reference](ssh-startup-reference/PRIVATE-RUN.md)
targets one whole non-PTY loopback connection. No new blind assessment panel is required.
