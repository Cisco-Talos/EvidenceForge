# Reviewed non-PTY SSH reference

The human supplied the fixed `SSH_STARTUP_CHAIN_DIAGNOSTIC` report on October 31, 2026.
Acquisition completed with error NONE, v11, passing provenance/readiness/cleanup, bounded
collection, sequence continuity, controlled client, receiver lineage and marker completion.
No candidate-ring eviction occurred. The agent read only the explicitly supplied shareable
report. Native records, setup/provenance and all other private kit files remain unread.

## Established exec facts

| Role | Before image role | Native descriptors | Entitlement template |
| --- | --- | --- | --- |
| SSH client | Instrumentation/OTHER | VNODE 0/1/2; controlling terminal present | Public SSH array plus integer template matches |
| xpcproxy | launchd | VNODE 0/1/2; no controlling terminal | Boolean object; template not compared by this kit |
| Startup wrapper | xpcproxy | SOCKET 0/1 and VNODE 2 | Public wrapper template matches |
| sshd | wrapper | SOCKET 0/1 and VNODE 2 | Public daemon template matches |
| sshd-session | sshd | SOCKET 0/1/4 and VNODE 2/3 | Public session-worker template matches |
| sshd-auth | forked session image | SOCKET 0/1/3, VNODE 2 and PIPE 4 | Public authentication-worker template matches |
| Initial zsh | forked session image | Three distinct PIPE objects at 0/1/2; no controlling terminal | Explicit null |

All listed native exec shapes, same-lifetime replacements, exact FD inventories/last-FD bounds,
script absence and dyld/target agreement pass. The client and four SSH helper images report
Apple platform validation and arm64e with PTRAUTH ABI. Their observed known flags correspond
to `0x26015b11`; the initial zsh retains its separate reviewed runtime policy. The native SSH
client explicitly confirms an integer, not a Boolean, in the verified vendor template.

The client is a controlled re-exec of the instrumentation process. Its own process group was
already established before that exec. This sample qualifies its exec metadata; it does not
independently establish how a direct shell fork assigns foreground job control. Canonical
parent/group/session ownership remains an independent process contract.

## Receiver relationships and remaining classification

The receiver prefix includes a launchd fork and same-lifetime xpcproxy → wrapper → sshd →
sshd-session activations. xpcproxy begins in its parent's POSIX membership; the wrapper's
pre-exec and target snapshots instead have their own group/session, requiring a separate
membership transition before wrapper exec. The wrapper's arguments do not match the old
bare-path-only catalog template. The xpcproxy launch arguments were not classified by the
original kit. These differences must be resolved before production admission.

The report also retains fork-only children under sshd/sshd-session. An absence of a child exec
does not justify inventing one. The exact execution/lifetime join and native order of these
branches need fixed offline classification from the existing capture. The authentication helper
exits with the `_sshd` credential class and zero status. Final session processes report exit
255 even though the controlled client/marker exit zero; successful command completion must not
be used as their exit status. Audit adoption, responsible-token ownership, job membership and
descriptor sharing must follow the native graph rather than the previous simplified producer.

Additional zsh/bash/OTHER activity occurs before the marker. These roles may include system
or local shell startup activity; their private paths/arguments were not exported and are not
inferred here. They do not establish a portable default application tree. Every process that
the simulator actually models still belongs in the independent all-start census.

No new live collection is needed for the identified classification gaps. Any offline reader
of the native capture requires separate explicit permission, must return fixed labels only,
and must start no commands, collectors, applications or live queries. PTY behavior and Unified
Log were not collected and are not qualified by this report.

## Approved core-graph review

The human approved the prepared version-1 offline reviewer against the existing completed
capture. It ran once, read only the bounded records and controlled provenance/metadata, and
returned fixed labels. Provenance, original collection controls and exact core lineage pass.
No files changed and no command, collector, app, probe or live query started. That permission
is consumed; it does not authorize another review or direct native-record inspection.

The resolved core has six actual forks and six successful execs before the controlled
marker's later replacement. Its relationships are:

| Lifetime role | Parent | Executions and observed completion |
| --- | --- | --- |
| Per-connection privileged receiver | launchd | Inherited launchd → xpcproxy → wrapper → sshd → sshd-session; final exit 255 |
| Short sshd child | Privileged receiver in sshd image | Fork only; unchanged execution and loaded image through exit zero |
| Authentication worker | Privileged receiver in session image | Inherited session → sshd-auth; drops to `_sshd`; exits zero |
| Short session child | Privileged receiver before audit adoption | Fork only; unchanged execution and loaded image through exit zero |
| Authenticated user worker | Privileged receiver after audit adoption | Fork only; drops to user credentials; final exit 255 |
| Login shell | Authenticated user worker | Inherited session → `-zsh`; controlled marker replaces that shell and exits zero |

The receiver begins in launchd's group/session, executes xpcproxy, then establishes its own
group/session before wrapper exec. xpcproxy uses a per-instance `com.openssh.sshd.` service
label. Wrapper argv is the basename-only vector `['sshd-keygen-wrapper']`, independently
matching Apple's current [launch daemon definition](https://github.com/apple-oss-distributions/OpenSSH/blob/main/com.openssh.sshd.plist).
The wrapper, daemon, session and authentication worker vectors otherwise match their existing
public catalog profiles. The shell establishes its own group/session after fork and before
exec, while retaining the remote audit origin and receiver responsibility.

The privileged receiver adopts the authenticated user's audit origin before forking the user
worker. The user worker drops all four POSIX credential words before forking the shell. The
receiver remains responsible for every descendant; it is self-responsible. Launchd and its
initial fork child also export their own identities as the responsibility fallback. No extra
exec is added for the two short-lived children or the authenticated worker. Exact exit 255 is
an observation of this controlled connection, not a success default for arbitrary cancellation,
deadline truncation or unrelated SSH failure. Private shell startup commands remain excluded
from the portable default workload, not from the simulator's process-start census.
