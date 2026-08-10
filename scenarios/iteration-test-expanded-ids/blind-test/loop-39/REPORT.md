# Loop 39 Assessment Report

## Outcome

Loop 39 generated 83,175 new records after the canonical Zeek state/history
fix. Only neutral data copies were given to four fresh blind reviewers; no
previous-loop finding or implementation context was available to them.

The hard probe passed: all RSTR rows use a responder reset marker, all RSTO rows
use an originator reset marker, and no S1 row contains an observed reset or
close. The Network reviewer independently described the resulting
state/history combinations as plausible and did not repeat the prior defect.
Automated evaluation rose to 96.3023 and fails only pivot linkability at
51.61/100.

Initial verdicts were Real/Inconclusive/Inconclusive/Synthetic at 35/42/43/67,
average 46.75. Disagreement and a 32-point spread triggered deliberation. After
reviewing only each other's reports, the panel was unanimously Synthetic at
72/66/69/86, average 73.25.

## Fresh Findings

- All 31 Event 4648 records put destination-like addresses into Network
  Information and sampled ephemeral ports that did not join to transport.
- Twelve Windows `ssh.exe` launches used unrelated Firefox, Edge, or Outlook
  parents consistently across Security, Sysmon, and eCAR.
- All 896 SMB and 594 LDAP Zeek connections ended below a sharp 45-second
  ceiling.
- Secondary patterns included fixed-phase Linux jobs, concentrated scanner
  populations, generic diagnostic command reuse, and a scripted stale-account
  failure sweep.

## Next Backlog Family

Correct Event 4648 at the canonical authentication/action-bundle boundary.
Network Address must represent the machine from which the explicit-credential
attempt originated, never the target server, and Port must be zero/blank for
local interactive use or reuse a real source port from the owned remote
transport rather than an independently sampled value.
