# Unselected local Mac terminal job-control follow-up

20 Host's weak signal: 55 direct local zsh command execs retain the login group;
qualified SSH PTY commands use separate groups. Disabled MONITOR remains a genuine
alternative explanation, so this is not a native-schema impossibility.

Official zsh manual says MONITOR enables job control and is the interactive default:
https://zsh.sourceforge.io/Doc/Release/Options.html#Job-Control

Read-only qualification on this macOS27.2.1arm64 host used ONLY our own new private
PTY, /bin/zsh -f -i with private ZDOTDIR/HISTFILE, and two controlled Python child
commands. No user processes, user rc/history, commands, filesystem contents or raw
prompt/transcript were captured. The JSON stores controlled child relationship
facts. Default reported MONITORon: shellPID2719, child2720, PGID2720, SID2719,
foregroundPGID2720. Explicit unsetopt MONITOR: child2721 retained PGID2719 and
foregroundPGID2719. Both had real private tty stdin. Child/session PIDs are ephemeral
probe identifiers, never constants to copy into generation. This is NOT an ES
capture or proof of every Terminal/iTerm/user-rc configuration. Native probe script
/private/tmp/eforge-own-zsh-job-control-probe.py creates/cleans only its own child
processes; successful selected JSON saved alongside these notes.

Existing canonical owner MacosPtyCommandStartup already models fork -> foreground
setpgid -> exec with exact retained phase/recovery via MacosFinderStartup. Its
admission is intentionally initial-SSH-only, including parent.session.sid==parent.pid
and active SSH context. Local shells can retain a login-owned SID distinct from the
shell PID; DO NOT weaken SSH guards or copy that SID assumption into local logic.
A future bounded adapter could reuse the generic canonical job-group/phase path
with an explicitly qualified LOCAL initial interactive-zsh intent and known local
terminal observation. Keep same SID/TTY, create one job PGID owned by the child,
apply it canonically between fork and exec, and leave native renderer fields to
those snapshots. Fork timestamps, native wall/Mach truth and approved exact authored
offsets must remain unchanged. Do not add timing jitter to disguise the benchmark.

Use explicit profile/config intent for normal interactive MONITOR semantics while
preserving legacy frozen policy and unqualified/nested/noninteractive paths. A
noninteractive downloaded Bash script is itself one foreground local job; its
inner commands normally inherit that job group rather than each becoming a new
interactive job. Keep SSH profile/timing/source behavior intact; source filtering,
process census, release/cleanup, checkpoint and exact source retry must remain
coherent. Existing parent-shell/TTY/group identity and descriptor contracts need
inventory before code. Do not claim a full terminal emulator or arbitrary user
shell configuration. This remains unselected preparation; no local job-control
production or benchmark changes have been applied.

Further owner inventory: generic _prepare_macos_shell_root currently seals fork+exec
(and exact file dependents) in one closed Mac cohort; its native contract explicitly
requires exactly the canonical process phases and does not admit job-control patches.
Adding a setpgid by mutating the exec snapshot or merely appending a renderer row
would bypass that closed contract. Existing retained PTY path safely commits fork,
job-control and exec as separate exact phases but rejects file/script effects.
A future local adapter must preserve those effect/artifact/recovery bindings rather
than weakening the SSH producer or copying around the canonical cohort validator.
This risk reinforces that this weak signal remains unselected for now.
