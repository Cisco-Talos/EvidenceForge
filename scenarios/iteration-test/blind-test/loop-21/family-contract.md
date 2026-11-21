# Linux console authentication lifecycle — proposed contract before code

Classification: adapter_to_family_model, with shared process-execution and auth/session owners.
The confirmed new-family defect is ordinary util-linux agetty modeled as the direct parent of a separate login process. The selected ordinary path must instead consume a free getty lifetime and execute login in place, preserving PID, object identity, original init parent and birth. A terminal cannot be reassigned while its login lifetime remains active. Login's authenticated user shell forks as a separate process; normal local session close must close its root-owned login process and PAM/logind lifecycle before a fresh getty can take that terminal. Never close another session's getty/login. No renderer changes may invent or rewrite lineage.

Entry inventory: shared generate_logon -> local auth adapter for server/root local sessions; baseline persona and maintenance/bootstrap callers; explicit storyline local logon. GDM workstation, network/service, SSH/RDP, sudo sessions and raw syslog remain separate. Shared ProcessExecutionService should expose an authenticated POSIX image replacement using existing State action-cohort execution, exact source projection and lifecycle registry. The console adapter delegates to it rather than duplicating exec mutation/publication. Missing optional frozen console policy must retain legacy behavior for old bundles.

Consumer inventory: State immutable/historical ProcessIdentity epochs, lifecycle registry/shadow, process parent selection, local shell bootstrap, source timing/observation, eCAR exec/process create/terminate and session records, native login PAM/logind syslog, checkpoint/resume and format filtering. A console process stays root-owned despite the human session association; session's process_tree_root owns cross-principal teardown just as Windows session pointers do. TTY occupancy and getty command facts come from canonical process state, not output parsing or new unbounded caches.

Data policy: configured virtual-terminal inventory and native getty/login image/arguments; profile-driven startup/teardown times. Model default Linux virtual-console inventory conservatively; distinguish configured availability from empirical calibration. Validate policy, terminal uniqueness and bounded inventory. Do not add per-host/time/sample exceptions or random PID fixes.

Sibling risks: GDM has a distinct PAM lifetime, SSH bundle exclusively owns remote PAM/transport, pre-window gettys may validly lack visible birth. Existing strict sudo close continuations cannot be bypassed. Out-of-order generation must use process-at-time identities; completed getty exec epochs cannot be selected as live gettys. Reused boot PID aliases must verify current image. Exact source filtering/replay/checkpoint and failed publication must preserve existing transaction guarantees. Unknown/crashed process termination must not automatically fabricate a successful PAM close.

Qualification: immutable util-linux v2.40.2 term-utils/agetty.c invokes execv(options.login, login_argv). Existing State execute_process supports Linux same-lifetime epochs; eCAR process_exec renders them. Current auth adapter explicitly creates a separate child. The session close adapter currently adds syslog only for SSH, confirming no local normal-close companion in that path. Further inspect/qualify normal console root teardown and terminal admission before coding; do not mark full family repaired by a PPID patch.

Source 555 remains frozen until loop20 generation and postprocessing exit successfully. No loop21 engine code has been applied at this contract stage.

Implementation scope refinement before generation: the adapter covers free-terminal
admission, ordinary getty->login exec, exact root-owned shell parentage and normal
session membership in process teardown. The pure LinuxConsoleAdmission planner
reads current and bounded retained canonical lifetimes, including future reserved
executions, without allocating a cache. It is directly checkpoint-invariant.
Native PAM closing and a complete idle-getty supervisor/respawn model remain
explicit residual siblings; do not report them as repaired. systemd's on-demand
AutoVT default is six; Linux's virtual-console maximum is63. Both are native
platform semantics, not raised engine resource quotas. Profile duration is a
modeled startup budget, not a measured native latency distribution.

New optional linux_console.terminals replaces that inventory as a unit when
present in an overlay. All established sibling list merge semantics remain
unchanged. Qualified images are bounded to /sbin/agetty and /bin/login; arbitrary
custom authentication wrappers are not admitted by this adapter. The absent
frozen policy uses the older creation adapter. Source-visible exec must precede
its dependent PAM evidence; incompatible admission rejects before exec commit.

Primary references:
https://www.freedesktop.org/software/systemd/man/latest/logind.conf.html
https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/vt.h
https://raw.githubusercontent.com/util-linux/util-linux/v2.40.2/term-utils/agetty.c

Full canonical generation at556 rejected a new cross-principal console root in
strict sudo-session close planning. Preserve that entire failed attempt, no eval
or panel. Focused same-family repair: console action owns an exact root predicate
(host/PID session pointer, root principal, qualified getty lifetime -> login exec,
exact username argv and pre-auth execution). Both generic membership and strict
close planning consume that predicate. The process keeps its root/system token;
the human session owns teardown without becoming its authentication identity.
The strict continuation's process-termination identity plan must omit a foreign
human authentication-session binding for that root. Preserve all nonmatching
foreign-process rejection and existing journal/retry/cleanup checks. No resource
ceiling or stale-owner bypass. Add a real strict close/retry regression test.

Refinement from strict physical projection checks: omitting the owning session
from the root phase made its activity patch lack a canonical member binding, and
then failed the closed sudo projection shape. Those guards correctly rejected the
prototype. The accepted model retains the exact human session as the teardown
owner and its activity patch, while AuthContext and ProcessIdentity keep the
unchanged root token (including an uncaptured empty boot logon ID). The closed
sudo projection validator consumes the shared exact-console-root predicate and
requires the supplied session identity to match current authoritative State.
Other foreign process/session combinations still reject. Lifecycle membership
continues resolving the process's own authentication context; no root reauth.
The earlier proposal to omit that logical session role is superseded.

## Retry558: exact already-completed RDP authored intent

Full557 generation preserved an existing exact RDP close at18:55 under its
opening intent before the authored closing intent ran. Existing handler verifies
retained RDP identity, exact host, exact authoritative plan and exact end time,
but returns only logon_id. GroundTruthLedger correctly rejects a closing intent
with no new occurrence or modeled outcome. Own the acknowledgement in the typed
authentication intent adapter: report already_completed only after those exact
checks. Never duplicate close rows, relabel an old occurrence, accept early or
foreign session completion, or weaken the ledger. Test through the real ledger,
including negative identity/plan/time cases and live-session normal close. This
is a bounded adapter_to_family_model repair, not a new RDP lifecycle owner.
