# Loop 71 family contract: Windows session-specific SMSS ownership

## Evidence and scope

The loop65 Detection review found Winlogon Event ID 1 rows for distinct Windows terminal
sessions reusing the same exact SMSS parent process identity. The same relationship persists in
the loop70 fixed-seed output: 17 Winlogon creates across ten hosts include three parent GUIDs
reused across visible session IDs on `DC-01`, `MAIL-FIN-01`, and `FILE-SRV-01`. For example,
`DC-01` Winlogon PIDs 3992, 4300, and 5336 in TerminalSessionIDs 6, 7, and 8 share parent
SMSS GUID `{83eb9c06-a054-6ae0-6700-0000016d5d7c}` (PID 2228).

## Intended change

Correct the canonical Windows session bootstrap owner so every newly created interactive or RDP
session gets a session-specific SMSS process identity, parented by the host's boot SMSS. The
session's Winlogon must use that exact SMSS identity as its parent, with the same relationship
rendered in Windows Security, Sysmon, and eCAR. Session reuse and unlock must retain existing
session process identities; no duplicate bootstrap should be emitted for an existing session.
The RDP action bundle must preserve this relationship within its materialization transaction.

## Guardrails

- Keep the primary boot SMSS identity and unrelated service/session processes unchanged.
- Keep session type, LogonID, TerminalSessionID, process GUIDs, and lifecycle ownership coherent.
- Give every newly created process an appropriate lifecycle; test visible create/termination and
  checkpoint/replay paths where this process is retained.
- Correct parent ownership at the canonical session/process layer, not separately in emitters.

## Acceptance probe

For every visible Winlogon create with a known parent, group by host and parent process identity.
Distinct terminal session IDs must not reuse one session-specific SMSS identity. Each new
session-specific SMSS must itself be a child of the host boot SMSS, and all rendered parent
image/PID/GUID values must agree across sources. Preserve source-native ordering and process
lifecycle semantics across the six-hour window.
