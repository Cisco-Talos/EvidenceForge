# Loop 13 family contract — Linux storyline shell-history ownership

## Owning layer

`StorylineMixin._emit_linux_storyline_shell_friction` and the typed process handler own the
optional preparatory shell-history events emitted before an authored Linux process. They must
bind those events to the exact session that owns the process and fit them after that session's
source-ready time.

## Invariant

Preparatory Linux shell-history entries for a remote process never precede SSH authentication,
PAM/session open, or shell readiness. They use the owning session's identity; if there is
insufficient time between session readiness and the authored process, omit the optional friction
entries rather than emit them before login or move the authored process.

## Entry paths and consumers

Typed Linux storyline process events call the friction scheduler, which emits canonical
`bash_command` events to shell-history sources. SSH session events may have already installed an
exact session in `StateManager`; baseline shell history and other storyline behavior remain
separate entry paths. The fix must preserve valid pre-process friction on an already-ready local
interactive session while preventing remote-session history from appearing before auth.

## Why this layer owns the truth

The finding originates from an optional history schedule created by storyline execution. The
scenario's `ssh_session` event, `SshSessionActionBundle`, and source readiness are already known
before the subsequent typed process runs. Rewriting emitted timestamps in an emitter would lose
that session ownership and leave the shared event chronology wrong.

## Sibling risks and verification

Cover remote SSH and local interactive session paths, plus insufficient post-auth runway. Keep the
authored process anchor and transfer tuple stable. Verify that no preparatory history event for a
remote Linux process is earlier than its exact session readiness in a fresh generated bundle.
