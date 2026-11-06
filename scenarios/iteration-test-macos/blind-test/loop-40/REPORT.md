# Loop 40: decoded DNS payload survives transport-state selection

Implicit DNS context is finalized after transport-state selection. Half-close/reset
sampling can shrink its earlier byte estimate below the final decoded answer. Final
TCP DNS content now feeds the shared canonical application-payload floor used by
HTTP/file evidence. The adapter includes the TCP length prefix and supports data-
carrying partial-close/reset/midstream states without forcing them to SF. Packet/IP
budgets recompute before immutable transaction/source observation publication.
Provided and inferred DNS share this path; denied/handshake-only and raw no-decoder
traffic stay outside it. UDP retains its established path. No source row is patched.

190 focused DNS, framing, physical-transport and proxy tests pass. They cover six
TCP states, supplied AAAA and inferred A/SERVFAIL responses, packet/header bounds,
and existing deny/unanswered siblings. Ruff/format pass. The39probe confirms one
impossible clean TCP response among8address-answer observations:25response bytes
versus29absolute minimum, independent of domain length. The rendered post-fix probe
will check the family rather than only this UID. Modeled sizes include padding and
are not native PCAP measurements.

Next: P1 Mac mounted helper terminal result adapter (Host36,qualifiedcontractgap),
P2 baseline SMB cadence and P2 Windows4658 native payload shape (Detection38,minor
schema/format). Application-child capture ledger consistency remains an architectural
candidate: changing the random key alone cannot prove agreement when child and parent
ledgers differ. Original reviewer priority labels were not assigned.

Validation/generation/eval pass96.0944,135877records,119files. ImpossiblecleanTCPDNS
responses1->0 across8address-answer observations. Browser0/267,HTTPwholems0/169core
and0/362DMZ,sudowholems0/99,CIMinvalid0; bothtransportprobes0. Counts/evalunchanged
from39; directmessage/packet probesverifythisselectedfamily.


## Family contract

# Final decoded DNS transport payload

Classification: sibling_defect; adapter_to_family_model. Owner: canonical network transaction application's payload floor. Implicit DNS context is completed after transport-state selection; partial-close/reset sampling can shrink the earlier estimate beneath that final decoded message. Route final DNS content through the same canonical application-payload reconciliation already used by HTTP/file evidence. Every fully decoded TCP DNS message must fit its direction's stream payload, including its two-byte frame, even when one close is absent or a later reset occurs. Cover provided and inferred DNS, A/AAAA/failure responses, successful/half-close/reset/midstream states and deny/unanswered siblings. Canonical packet/IP budgets are recomputed from corrected payload before immutable transaction/observation publication. All sources consume that ledger. UDP retains its current accounting path and raw no-decoder traffic remains outside this adapter. This uses modeled wire sizes (including padding), not captured packet bytes. It does not rewrite source rows or pretend all partial-close traffic completed successfully.


## Individual expert summaries

**Threat Hunter:** Inconclusive; verdict confidence 82; synthetic-confidence score 43. The collection is operationally convincing: remote credential boundaries, SSH transport/authentication, file staging and inspected proxy uploads generally support feasible investigative pivots. A small, unusually regular sequence of shell-driven document accesses on one Mac raises a concrete workload-texture concern, but I did not establish an impossible lifecycle or cross-source contradiction in the checks performed. This looks mostly realistic, with insufficient evidence to confidently distinguish production telemetry from a careful simulation.

**Detection Engineer:** Inconclusive; verdict confidence 84; synthetic-confidence score 35. The supplied telemetry is largely credible as SIEM input: Windows records parse correctly, process identities remain stable, and the network and endpoint lifecycle checks found no demonstrated impossible ordering. A few localized metadata patterns look simplified, but they are insufficient to distinguish a carefully constructed dataset from filtered or sanitized production telemetry.

**Network Forensics:** Synthetic; verdict confidence 70; synthetic-confidence score 56. The network evidence is technically coherent and substantially production-like, but a repeated hourly concentration of SSH connection endings across different clients and servers makes synthetic generation somewhat more likely. This is a distribution finding, not an impossible protocol relationship: I found no comparable hard contradiction in the checked UID relationships, flow accounting, protocol timestamps, or TLS certificate identities.

**Host Forensics:** Inconclusive; verdict confidence 78; synthetic-confidence score 44. The endpoint evidence is substantially coherent across Windows, Linux and macOS, with credible process identities, parentage and session lifecycles. A few Linux background-state messages and closely repeated macOS command timing patterns suggest constructed background texture, but I did not establish an impossible process lifetime, a demonstrated native-schema violation, or a decisive cross-source contradiction. Those limited indicators justify a mixed score rather than a confident synthetic verdict.


## Scores and comparison

Automated eval 96.0944; standalone synthetic-confidence average 44.50 (mixed/inconclusive), prior loop 40. Lower is more production-like. Scores are standalone reviewer measurements; physical/semantic probe outcomes independently verify the selected family.

Facilitator-modeled deliberation averages 49.50; see deliberation.md. Modeled revised positions are excluded from standalone and rolling averages and are not reconvened expert votes.
