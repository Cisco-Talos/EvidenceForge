# Loop 20 family contract: SMB transport before network authentication

- **Owning layer:** `SourceTimingPlanner`, which owns source-local timestamp relationships for canonical endpoint events.
- **Invariant:** A visible successful Windows network logon for an exact inbound SMB tuple must serialize after that target host's admitted eCAR inbound FLOW, including compatibility logon paths without a `RemoteAuthenticationPlan` or explicit SMB session kind.
- **Entry paths:** Bundled SMB action events with remote-auth context, plus ordinary Windows network logon events created through baseline/generic authentication paths.
- **Consumers:** eCAR USER_SESSION/LOGIN and FLOW/CONNECT rendering; other source families continue to use their existing transport/auth timing contracts.
- **Sibling risks:** Preserve existing strict SSH/RDP/SMB bundle timing, do not bind a logon to an unrelated flow sharing only a host or port, and retain the exact source IP, source port, destination IP, destination port, protocol, target host, and event-time window checks.
- **Why this layer owns the truth:** The observed LOGIN and inbound FLOW are canonical siblings with exact tuple identity, and the planner already records admitted SMB endpoint FLOW timestamps. Equal millisecond timestamps persisted because this Windows network-auth path did not carry the optional bundle metadata used by the current SMB-specific anchor check.

## Evidence

Loop 19's automated causality probe found `DC-02.meridianhcs.local/ecar.json` lines 1035–1036: a type-3 successful login for `10.10.1.34:55083 -> 10.10.2.11:445` and the exact inbound FLOW have the same `timestamp_ms` (`1793629313776`), while the LOGIN appears first. The source workstation's outbound FLOW is visible at `1793629313452`, and Zeek records the matching established SMB connection. The current planner's SMB anchor is only consulted when `event.auth.session_kind == "smb"`; the observed generic Windows network logon has no such marker.

## Verification

Add a focused planner regression using an admitted target-side SMB FLOW followed by a successful type-3 logon with the exact tuple but no `RemoteAuthenticationPlan`/SMB session marker. Assert strict target FLOW-before-LOGIN ordering and verify unrelated tuples do not acquire the anchor. Then run the focused source-timing tests, Ruff checks, behavior manifest validation, one fresh generation/evaluation, and the independent blind panel.
