# Paired Terminal and iTerm2 startup reference

The human supplied successful, bounded macOS 27 arm64 reports for each app. The iTerm2
version-2 capture and version-3 offline review both report error NONE; provenance, collection
controls, cleanup, sequence continuity and retained ancestry pass, with no ring eviction.
Only the shared fixed JSON was inspected. Private capture files remain outside this review.

## Observed comparison

| Fact | Apple Terminal | iTerm2 |
| --- | --- | --- |
| GUI prefix | launchd fork, xpcproxy exec, GUI credential binding, same-PID app exec | Same reported relationship classes |
| Pre-login stages | App forks login child | App forks iTermServer; server forks login child |
| Session setup | Login child forms its own session/group and gets a TTY before exec | Helper A forms its own session/group without a TTY; login child then forms another session/group and gets a TTY |
| Login credentials | Real user UID/groups; effective UID zero after exec | Same |
| Login arguments | Basename login, `-pf`, user | Executable path, `-fpl`, user, bundled ShellLauncher path, `--launch_shell` |
| Login descriptors | VNODE 0/1/2 plus PIPE 4/5 sharing one pipe ID | VNODE 0/1/2 only |
| Initial shell | Login forks; child drops effective UID zero before zsh exec | Login forks; child drops effective UID zero before ShellLauncher exec, then same-PID zsh exec |
| Responsibility | Login, shell and command retain the Terminal execution | Helpers, login, shell and command retain the iTerm2 execution |
| Entitlement shapes | Booleans and string arrays; explicit null on zsh | Main app also has scalar strings; helper A has `{}`; helper B has scalar strings |
| Fresh startup obligations, excluding marker | 3 actual forks, 4 execs | 4 actual forks, 6 execs |

iTermServer's post-exec inventory is SOCKET FDs 0/1, two different PIPE identities at FDs 2/3,
and a VNODE at FD 4, with last FD 4. ShellLauncher and zsh have only standard VNODE descriptors.
No missing fork is inferred for the helper-B-to-zsh image replacement. A positive shape or
collection check is distinct from a property label: false ES-client or platform-binary flags
can be correct. The original three native-shape failures isolate to entitlement shapes;
all shapes excluding entitlements pass.

## Safe implementation boundary

Use one startup implementation with shared canonical GUI launch, fork/exec identity, audit
origin, responsibility, job-control/TTY, setuid/drop, descriptor allocation and recovery.
Select explicit app-specific stages, arguments and FD tables. Do not force identical trees,
inherit Apple signer/runtime flags into iTerm2, or retain an aggregate fallback in complete mode.
App reuse and restoration of existing jobs remain distinct from this fresh-start workload.

Revisions 362–363 qualified immutable entitlement values, installed helper placement, runtime
security, setuid/drop and session/TTY prerequisites. Explicit empty, explicit null and unknown
entitlements stay distinct. New checkpoint tags preserve those states; earlier encodings and
frozen profile restrictions are retained. Verified vendor templates supply signer and entitlement
definitions independently of captured values.

Revision 364 implements both fresh startups through `MacosTerminalStartup`, sharing the retained
GUI-prefix publisher and canonical lifecycle owners. Each measured tail selects its own stages,
arguments and exec-owned FD actions. Complete collection reconciles every fork and exec with
the canonical census; no aggregate birth bypasses admission. Public CLI workloads cover both
apps, one subsequent command, format filtering and checkpoint/resume. Existing-app windows,
restored jobs and arbitrary launch-shell customization still require separate qualified plans.

## Helper qualification

Public upstream sources identify candidate programs
[`iTermServer`](https://github.com/gnachman/iTerm2/blob/master/sources/Tasks/iTermFileDescriptorMultiServer.c)
and [`ShellLauncher`](https://github.com/gnachman/iTerm2/blob/master/ShellLauncher/main.c).
The [shell-launch implementation](https://github.com/gnachman/iTerm2/blob/master/sources/Tasks/shell_launcher.c)
documents login with `-fpl`, the ShellLauncher executable and `--launch_shell`; the helper
executes the selected login shell. These supplied independent candidate identities for the
approved offline comparison, rather than names inferred merely from position in the chain.

Independent static signature checks verified all three installed bundle executables against
the published vendor team H7V7XYVQ7D. Their signing IDs are com.googlecode.iterm2, iTermServer
and ShellLauncher. The server has an explicit empty entitlement dictionary. ShellLauncher's
sole static entitlement is the literal vendor application identifier `H7V7XYVQ7D.`; its trailing
dot is retained, not completed with an invented bundle name. These are vendor code facts,
not extracted private log values.

The user explicitly approved the version-4 offline reviewer against the existing iTerm2 kit.
It ran once with provenance, collection controls, retained chain and all three vendor signing/
entitlement comparisons PASS. iTermServer is a USER_SUPPORT_COPY with one absolute-path argument;
ShellLauncher is in the APP_BUNDLE and has basename argv0 plus `--launch_shell`. The login
argument classes match the public implementation above. No native path, argument value,
identity, entitlement definition or other private value was exported by the reviewer.

The app's xpcproxy preimage responsibility token has four zero POSIX credential words while
its PID/PID-version/audit words match the preimage. The app target's responsible token equals
its complete own token. This confirms the qualified GUI-prefix relationship for iTerm2. The
review started no commands, apps, probes or collectors, queried no live roles and changed no
files. No further native collection is currently needed to implement these bounded starts.
