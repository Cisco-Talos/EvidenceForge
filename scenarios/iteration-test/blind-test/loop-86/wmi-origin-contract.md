# Loop 86 — WMI Source/Effect Trace Contract

## Question

Do the DC-01 account and persistence effects have a demonstrably inconsistent initiating identity or missing required transport in the visible records?

## Evidence contract inspected

- Security 4688 establishes SYSTEM (LUID `0x3e7`) launching `cmd.exe` from `WmiPrvSE.exe` for account creation, Domain Admins membership, service creation and task creation.
- Security 4720/4728 records follow those commands under SYSTEM and in causal order.
- The two nearby WS-PPATEL/DC-01 SMB sessions each have their own matching type-3 4624 and eCAR FLOW tuples; neither has the execution time or identity of the WMI command sequence.
- The typed scenario models the account and persistence actions with actor `SYSTEM` and does not declare a remote WMI source.

## Result

No visible source-native contradiction or impossible order was proven. The WMI initiating actor/source remains unclear to an analyst, but the visible canonical records agree on the SYSTEM execution context, and the authored event does not require a specific remote initiator. Classify as an attribution gap / unproven contract gap, not a generation defect. No code or scenario change is justified by this trace.

## Verification

Focused XML/eCAR extraction is recorded in `wmi-origin-probe.json`. The Loop 86 panel uses a byte-identical copy of Loop 84 output, permitting an independent fresh assessment without implying any data change.
