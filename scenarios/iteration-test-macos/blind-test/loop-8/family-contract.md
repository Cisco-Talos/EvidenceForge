# Loop 8 family contract

## Family A: SSH server auth and source-observation coherence

- **Candidate owner:** the canonical SSH action bundle plus source-observation planner, which own tuple/auth/session lifecycle and coherent source-local drop/delay decisions.
- **Entry paths:** typed storyline SSH sessions; baseline remote-admin/session bootstrap; compatibility Linux remote-interactive logons; failed SSH attempts; transfer sessions routed through SSH.
- **Invariant:** a visible successful eCAR SSH LOGIN and server session has source-native sshd acceptance/PAM-open evidence under the modeled collection profile, unless an explicit coherent source-level gap suppresses the same session group. A retained close must not orphan an unobserved start without a coherent collection explanation.
- **Consumers / sibling risks:** Linux syslog sshd/PAM/logind, eCAR USER_SESSION/FLOW/process rows, Zeek transport, SSH/scp transfer evidence.
- **Layer rationale:** session/auth intent and source observation precede rendering; emitter-only log synthesis or scenario-specific patches would miss sibling entry paths.

## Family B: native macOS transition time in eCAR

- **Candidate owner:** source timing / macOS process-event projection, which maps distinct Endpoint Security fork/exec/exit transitions into eCAR process lifecycle timestamps.
- **Entry paths:** process bootstrap, fork, exec image replacement, process exit, baseline and storyline process creation.
- **Invariant:** distinct native transition times remain ordered in the normalized eCAR source unless actual source-observation batching is explicitly modeled; timestamp quantization or process lifecycle grouping must not collapse a multi-transition sequence into one timestamp.
- **Consumers / sibling risks:** eCAR PROCESS CREATE/MODIFY/TERMINATE rows, Endpoint Security exports, process lifecycle probes and time-window detections across both Mac hosts.
- **Layer rationale:** preserve canonical source timing/precision before serialization; do not invent ordering in the emitter after native event truth is known.
