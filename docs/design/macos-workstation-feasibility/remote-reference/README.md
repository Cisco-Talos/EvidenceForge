# Remote Mac reference collector setup

The second-host reference plan uses an SSH-driven filtered runner and a narrow
privileged collector. `collector_guard.c` runs only `/usr/bin/eslogger` with fixed
event lists. It accepts exactly `filesystem` (30 seconds) or `process` (180 seconds),
stops on parent-pipe closure or SIGINT/SIGTERM, and reaps its child. It launches no
workloads, reads no reference files and changes no system policy. Its raw stdout
must go into the bounded filter, never a terminal or an ambient capture file.

The `EFORGE_GUARD_TEST` build is exclusively for invented-input process-control
tests. Production compilation must not define that macro or replace the collector.
The standalone filesystem and Code runners apply separate bounded ownership
filters. Guard setup alone does not establish collection readiness; each runner
requires an independently observed readiness control before launching its workload.

## Current staged kit

An unprivileged production build and a syntax-checked proposed sudo policy are
staged on the authorized reference Mac at:

```text
/private/tmp/eforge-remote-reference.RiKEy0
```

The deployed source's SHA256 matches the repository source:

```text
a40eabe242b02a034688bec306ab0921c81ad5288624e7c9f28828448dbf8c98
```

The user completed administrator setup. The installed helper is root-owned mode
0755 and the sudo rule root-owned mode 0440; both literal commands are available
non-interactively. Two filtered filesystem references have now completed, and
Full Disk Access already permits collection through this SSH context.

The helper destination did not exist during preflight. `/Library/PrivilegedHelperTools`
was absent; `/private/etc/sudoers.d` was root-owned with mode 0755. The staged
`collector.sudoers` authorizes only the test account's two literal guard commands,
not a shell, arbitrary command or argument, and has passed `visudo -cf`.

## One time administrator setup

Setup is complete; these commands are retained for review, not for rerunning
against existing destinations. Run them in an interactive shell on the second Mac, after reviewing the
staged source and policy. They require that account's administrator authorization;
the agent cannot supply it through the current non-interactive SSH connection.
Do not enter credentials into chat.

```sh
set -e
kit=/private/tmp/eforge-remote-reference.RiKEy0
helper=/Library/PrivilegedHelperTools/org.evidenceforge.reference-collector
policy=/private/etc/sudoers.d/eforge-reference-collector
test ! -e "$helper" && test ! -L "$helper"
test ! -e "$policy" && test ! -L "$policy"
sudo /usr/sbin/visudo -cf "$kit/collector.sudoers"
if test ! -d /Library/PrivilegedHelperTools; then
    sudo /usr/bin/install -d -o root -g wheel -m 0755 /Library/PrivilegedHelperTools
fi
test ! -L /Library/PrivilegedHelperTools
test "$(/usr/bin/stat -f '%u:%Lp' /Library/PrivilegedHelperTools)" = 0:755
test ! -L /private/etc/sudoers.d
test "$(/usr/bin/stat -f '%u:%Lp' /private/etc/sudoers.d)" = 0:755
sudo /usr/bin/install -o root -g wheel -m 0755 "$kit/collector-guard" "$helper"
sudo /usr/bin/install -o root -g wheel -m 0440 "$kit/collector.sudoers" "$policy"
sudo /usr/sbin/visudo -c
```

The same reviewed commands are staged as `enable-collector.sh` inside the kit.
Running `/bin/sh /private/tmp/eforge-remote-reference.RiKEy0/enable-collector.sh`
in an interactive shell performs that setup and requests administrator credentials
through sudo. The script is not itself run as root.

These commands install a root-owned helper and the proposed narrowly scoped rule;
they do not run the collector. A pre-existing destination is a stop condition,
not permission to overwrite it. A failed validation or partial installation must
be resolved before collection. The final validation also checks the host's broader
sudo configuration; do not modify unrelated rules to make this kit pass.

The agent can then verify non-interactive access to those exact commands and run
a filtered readiness control. Full Disk Access for the responsible SSH process is
a separate OS requirement. Check actual readiness before requesting a privacy
setting change. Apple documents the responsible-process requirement in its
[Endpoint Security tooling presentation](https://developer.apple.com/videos/play/wwdc2022/110345/?time=488)
and the remote-user option in
[Remote Login settings](https://support.apple.com/en-au/guide/mac-help/mchlp1066/mac).

## Removal after the reference effort

Once all runs and guards have stopped, an administrator can remove the two exact
installed kit files. Retain the staged kit and evidence according to the reference
retention decision; do not delete other helpers or the shared directories.

```sh
sudo /bin/rm /private/etc/sudoers.d/eforge-reference-collector
sudo /bin/rm /Library/PrivilegedHelperTools/org.evidenceforge.reference-collector
sudo /usr/sbin/visudo -c
```

This helper is temporary study tooling, not a product daemon or a release artifact.

## Filesystem reference results

The standalone filesystem runner uses `filesystem_probe.c` and admits native rows
only for its independently reported full audit token, birth time, executable file
object and exact scratch names. Raw records and controls stay in new owner-only
remote run directories. The offline checker verifies artifact hashes and returns
fixed technical findings.

Both macOS 27.0.1 arm64 runs retained 3 creates, 5 closes, 2 renames, 2 unlinks and
1 normal exit, all source version 11. All eight controlled operations completed,
actor/file identities joined, wire shape checks passed, and no stream sequence
gaps or reordering were observed. Warm-up is separate from the controlled creates.

In these primitive workflows, create describes an empty file before the write;
write-close is modified, read-only close is unmodified, replacement describes the
old destination object, and unlink retains the pre-removal link count. No writable
mapping was used or observed. Application saves and broader filesystem behavior
need their own qualification; production generation is not enabled by these results.

The first offline check hit Python 3.9's limited fractional timestamp parser. The
checker now validates calendar fields independently of the preserved nine-digit
spelling. All raw records remain unchanged.

The production wire decoder now admits the measured v11 create, close, rename and
unlink layouts. This enables ingestion and validation of those records. Canonical
file-operation ownership and native generation remain separate implementation work.

### Directory-stat follow-up and generation integration

Two additional bounded scratch-file captures completed on 2026-11-06 at
`/private/tmp/eforge-fs-parent-reference.9avbwqq7`. Controls now include exact
source and parent mtime/ctime before and after each operation. Raw controls,
records and provenance remain owner-only on the reference Mac; no ambient rows
or private paths were returned. Each run again retained 3 creates, 5 closes,
2 renames, 2 unlinks and 1 normal exit, all v11, with complete controls, clean
shutdown and no stream gaps or reordering.

In both runs, the fresh-destination rename's parent matched its **before** stat;
both rename sources matched their **before** stat. Both unlink parents and both
unlink targets also matched their **before** stat. All measured phase comparisons
matched; none was unmatched or unmeasured. Replacement continues to describe the
old destination object. The reviewer returns only fixed phase labels/counts.

Ordinary generation now uses these primitive contracts for a bounded, nominal
application-owned document workload: empty create, modified close, optional
same-directory atomic replacement and optional unlink. Shared file placements,
content versions, inode allocation and changing directory stat enter canonical
State/artifact ownership before native/eCAR rendering, and checkpoint together.
The selected application is an actually live qualified Code main. Workload
frequency, sizes, allocation and save strategy are modeled configuration, **not**
a measurement of Code's exact default save implementation, APFS allocation, or
ambient filesystem activity. This does not enable mappings, broad file reads,
arbitrary paths or universal conversion of generic file effects.

## Code reference results

The separate owner-only Code kit is at
`/private/tmp/eforge-vscode-reference.4KJyaE`. The selected app is VS Code 1.143.0
on macOS 27.0.1 arm64. It is a different build from the existing 1.142.0 catalog
entry; the reference does not silently qualify that older build.

The user cleared the OS first-launch confirmation. Earlier attempts accepted the
launch request but could not complete that dialog automatically. Once cleared,
the reference extension saved an invented file, opened a second window and
requested ordinary quit. That quick close is intentional. It uses only its fresh
profile, extensions directory and two invented workspaces; no sign-in is required.

An initial filter failure compared hexadecimal CDHash strings case-sensitively.
The corrected filter compares strictly validated twenty-byte values, retaining
file-object, exact path, signer and unique profile checks. A subsequent experiment
showed that a fresh editor profile still permits normal shell-environment discovery
and account startup scripts. Those cases remain preserved and unqualified. The
final two repeats use `--force-disable-user-env`, a controlled launch environment
and an empty `ZDOTDIR`, independently verified in the root exec record. The
experiment excludes ordinary account shell startup behavior deliberately.

Both final repeats pass independent native shape, exact execution-edge, source
sequence, shell-isolation and workflow-control checks. Each observes:

- One main, two renderers, one GPU and one network helper.
- Six Node utility executions: one shared process, one agent host, two extension
  hosts and two file watchers. No PTY-host claim follows from this no-terminal case.
- Three other execs, including two still-unclassified descendant executables.
- Main exit and closure of every observed lifetime; no source sequence gap or
  reordering, and successful collector/workload cleanup.

The main's initial fork is **not observed**. These results qualify the measured
execution relationships and workflow; they do not establish complete main startup
or authorize guessed templates for the two unknown descendants. Original reports
retain `reference_admission: NOT_EVALUATED`. Each final run preserves its tool
sources/binaries, OS/build, image metadata, controls and native hashes privately.
No raw native rows or captured environment values are copied into the repository.

Shared OS-service qualification remains pending. The existing launchd Unified Log
collection stopping rule remains in force.

## Docker reference results

The user installed and initialized Docker Desktop, including optional sign-in.
The selected build is 4.98.0 (245422), with a responding Linux arm64 Engine 29.9.2.
The separate private kit is `/private/tmp/eforge-docker-reference.k6kgpz_e`.
Docker is a reference target for its host helpers, not an EvidenceForge dependency.

The runner uses a fresh CLI config and an explicit local Engine socket. It does
not read the account's Docker login config, pull images, create containers, publish
ports or change Docker settings. Every shutdown requires an empty-container
control. Public installed images are signature-verified and pinned by file object
and hash. A unique injected launch marker authenticates the fresh backend; retained
rows then require exact fork/exec ancestry. Earlier attempts and final per-run
tool snapshots remain private and unchanged.

Desktop's CLI reported `stopped` under these isolated SSH settings while the
explicit local Engine API responded. That inconsistent control path is unused.
Normal macOS application quit/open controls instead bind the exact root/UI bundle
and executable objects. They account for multiple matching application instances,
request ordinary quit and wait on those application objects; they never force-quit
Docker. Native collection is limited to 150 seconds inside the existing 180-second
guard. The marker probe and application control have separate 170-second limits.

Both final repeats verify native shapes, exact retained execution edges, launch
ownership, source ordering and positive Linux guest-engine readiness. Each retains
55 fork births, 61 execs and 50 terminal lifetimes, with no observed source sequence
gap or reordering. The selected host images account for:

- Three backend executions, one build-service execution and one virtualization
  executable. These are executions, not three independently modeled resident mains.
- One Desktop GUI, two renderer executions and two generic helper executions. Role
  switches identify GPU and network utilities; the separately named GPU binary did
  not execute in these cases.
- Another 51 execs are not qualified by the selected static-image inventory; fixed
  labels identify some standard OS tools, while 35 remain unclassified.

There are **six unclosed lifetimes at the cutoff** in each final run, and the
authenticated graph root's initial fork is unobserved. The six are an observation
gap, not proof that those processes remained alive or permission to invent exits.
The generic retained graph alone cannot distinguish late termination from a
snapshot/filter mismatch. Native full-lifecycle admission therefore remains gated.
Of the 50 observed terminal lifetimes, 48 use normal wait results and two are
signalled; ordinary application quit does not imply exit code zero for every helper.

The empty ZDOTDIR control isolates zsh startup-file lookup, not every possible
account-specific behavior of a signed-in application. The Engine runs inside the
Linux VM; this host-only process reference does not qualify container processes,
network traffic, filesystem effects or a different VMM configuration. Neither
`com.docker.vmnetd` nor the privileged `com.docker.socket` helper is installed at
its standard helper destination on this host. Absent helpers must not become
unconditional synthetic startup children.

After collection, a separate non-capture restoration verified empty inventory,
ordinary quit, Engine unavailability, normal launch without the experiment's
environment overrides, and restored Engine readiness. Docker is running; no
collector/control workload remains active. Sign-in was not changed. Original
reports keep `reference_admission: NOT_EVALUATED`; no Docker templates are enabled.
