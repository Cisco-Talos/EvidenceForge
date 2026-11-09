# Reviewed macOS 27 SSH PTY relationships

The human supplied the version-3 fixed SHAREABLE-SSH-PTY-REPORT.json from the fresh PTY
experiment. Only that report was read. No native capture, provenance, client control,
directory inventory or other private kit file was inspected or copied. The report itself
stays outside Git; these are bounded relationship findings, not native fixtures.

All acquisition controls pass: provenance, collector readiness/cleanup, bounded collection,
sequence continuity, controlled client, receiver lineage and marker exit. No ring eviction
or safety limit occurred. PTY is observed; the controlled command has a retained actual fork.
All eight retained client/receiver/command exec shapes pass the v11 contract.

## Shared receiver and PTY-specific facts

The receiver prefix matches the reviewed non-PTY core: a launchd fork executes xpcproxy,
creates a new POSIX session/group, then executes basename-argument wrapper, sshd and
sshd-session in that lifetime. Short daemon/session children are actual forks without exec;
the authentication child executes sshd-auth, drops to `_sshd` and exits zero. The privileged
worker adopts the authenticated audit origin before forking the user worker. That worker
drops all four POSIX credentials, then forks the login shell. The root receiver remains
responsible for descendants. Initial startup has six forks and six execs.

Helper exec FD tables, code-security flags, CPU slice and public entitlement templates match
the earlier non-PTY qualification. xpcproxy's public argument form is the per-instance SSH
service label. Its entitlement-template comparison is not performed by this kit; its Boolean
shape and existing independent launcher qualification remain distinct. The shell has explicit
null entitlements, the existing Apple zsh runtime policy and arm64e/PTRAUTH ABI. The ad-hoc
marker image measures relationships, not trust or security defaults for unrelated binaries.

| Boundary | Observed relationship |
| --- | --- |
| User-worker fork to shell | Inherits worker group/session and has no controlling terminal at fork |
| Before shell exec | Own POSIX session/group; controlling terminal equals the controlled command's terminal |
| Initial shell exec | `-zsh`; authenticated user/audit origin; HOME cwd; three vnode standards and last FD 2; same terminal/session/group across exec |
| Shell forks command | New lifetime inherits shell execution, group, session, credentials, audit origin, receiver responsibility and terminal |
| Before command exec | Command has its own process group and stays in the shell's POSIX session |
| Command exec | Same child lifetime; three vnode standards, last FD 2, HOME cwd and same controlling terminal as shell |
| Command exit | Zero in this controlled workload; terminal remains present |
| Shell exit | Zero after the explicit following `exit`; controlling terminal is absent in its exit snapshot |
| Final user/root worker exits | 255 in this controlled connection; not generic teardown defaults |

The earlier independent own-process descriptor experiment establishes read/write standard
vnode handles referring to the same terminal node for the tested PTY command. It does not
prove shared open-file descriptions or offsets. This report adds the actual native helper,
shell and command lineage and terminal-equivalence relationships without exposing paths,
device numbers, identities, environment values or argument text.

The controlled command adds one genuine fork and one exec to the receiver's six/six startup.
The following shell builtin `exit` adds no process or exec. The local SSH client's terminal
differs from the remote shell/command terminal. Shell-private startup child trees are excluded
from this bounded reference; every process actually modeled by the simulator still belongs
in its independent completeness census.

## Implementation and limits

Use the existing receiver phase journal for PTY shell setsid/device allocation and authenticated
shell file actions. Direct foreground commands require three separate canonical transitions:
fork with inherited membership, setpgid, then exec with preserved new membership. Reuse existing
State, terminal/FD, native ingress, publication, lifecycle and checkpoint owners. Source renderers
must not invent groups, terminals or additional execs.

This qualifies the measured initial zsh and literal external foreground command pattern.
It does not establish pipelines, redirections, substitutions, nested shell programs, alternate
login shells, background jobs or every shell-initialization program. Generic final outcomes
remain unknown; successful exec does not imply exit zero. No SSH Unified Log was collected.
The report's REQUIRED/NOT_EVALUATED labels reserve implementation review and tests; they do
not auto-enable a generation gate or authorize another local-log read.
