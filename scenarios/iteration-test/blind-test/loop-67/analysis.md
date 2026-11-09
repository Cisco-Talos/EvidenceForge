## Family repairs and verification

HTTP resource sizes and file content seeds now share origin/path ownership by default;
only explicitly configured shared content crosses origin boundaries. The existing Inter
font is declared as one modeled shared resource. Default favicon/logo/CSS resources are
site-owned, repeat retrieval remains stable, URI path case and dynamic query identity
are retained, and proxy client/origin content pairing consumes the same identity.
Explicit supplied content identities survive proxy context construction. This fixes
the content owner, not renderer-local randomized sizes or hashes.

A second primary-qualified repair composes Windows failure status, substatus and native
resource reason as one canonical typed condition. Microsoft4625defines FailureReason
as text describing mainStatus and pairs2307withlockout in its official example. The
old disabled branch combined generic006dstatus, disabled0072substatus andlocked2307
reason. It now retains generic2313reason plus the specific substatus; eCAR normalization
continues to distinguish disabled/unknown/password by numeric condition. Resource-only
fallback2307nowmeanslocked, notdisabled; generic2313doesnotbyitselfprovebadpassword.
No account state, SID, cadence, RNG or intended failure outcome is invented.

Fresh135,285records/119files pass96.509863 andhardacceptance.47favicon hosts have47
sizes;8logo hosts8sizes.4sharedfont hosts keep1size. Source content hashes are not
available for these sampled assets, so rendered proof is size/ownership consistency;
focused tests separately prove canonical shared versus site content seeds. All20
native Windows failures have consistent main status/reason, with3disabled substatuses
still normalized asdisabled.187content/native checks and190family-producer/proxy
checks pass (overlap), plus101configfiles andRuff. PID0reversals across209allocations,
113eCAR/nativeexecpairs, complete nativecensus/mountedexits,0browser-family mismatches
across802joins, and0HTTPcapturebudget defects across501qualified entities remain.
All nine carried repair probes pass. Changed content sizing shifts subsequent work;
unchanged six authored files/seed are verified, not a claim of a byte-only paired trial.

## Blind findings, movement and priorities

Initial63/38/55/46 mean50.50 is down2.50from66. Threat andHost independently report
one repeated96second editor cadence; their views are two investigations of the same
behavior, not two distinct defects. Network finds UDP state lifetime/optional-duration
issues. Native process identities and source distinctions remain strong in all reports.
The panel did not revisit MySQL, but coordinator19failed prerequisite observations
remain on67; silence is not evidence against the carriedP0. OriginalP0–P4labels are
not assigned by reviewers; priorities below are coordinator synthesis.

| Priority | Finding/category | Reviewer original rating | Scope/leverage/owner/risk | Disposition |
|---|---|---|---|---|
| P0 | MySQL confirmation prerequisites; hard_contradiction |66Network: not labeled |Repeated63–67; high; canonical protocol finalization; low-medium | Verified taggedZeek8.0.5 source and current19bad observations; select68. Keep data/history, do not fabricate greeting bytes. |
| P1 |96second interactive cadence; distribution_texture | Threat/Host: not labeled |10of16gaps near96s, one developer; high; task/workflow timing; medium | Repeated across66/67, strongest independently noticed current family. Scripted/timed real-workflow alternative stays explicit. |
| P1 | UDP firewall state expiry and Zeek duration; contract_gap/schema_or_format | Network: not labeled |11matched ASA flows,283oneway S0observations/200multipacket; high; source state/time and native optional fields; medium | New family. Source inspection finds datagram teardown83–8500us after application close, rather than an idle timer. Qualify DNS inspection, exceptional removal and exporter policy. |
| P1 | Mac inode lexical allocation; distribution_texture |64Host: not labeled |Two inventories,26/32paths; medium-high; canonical installed filesystem; low-medium | Currentmetadata probe confirms0lexical inversions and13/10birth-order inversions. Select68using existing modeled birth chronology. |
| P1 | Windows SMSS ownership, browser singleton, logind numbering; contract_gap/distribution_texture | Earlier specialists: not labeled |Repeated; high; session/application/identity owners; high | Carry qualified evidence; require dedicated lifecycle contracts. No scenario edits or fabricated unsupported native launch families. |
| P2 | Windows handle-use/request source order; contract_gap | Detection: not labeled |1of44groups,11.7488ms; low-medium; object action/source timing; medium | Qualified new lead. Different writer threads/asynchronous reporting remain plausible; verify semantic times before changing observations. |
| P2 | Mac nonbrowser/mobile headers, slow utilities and closure fences; weak_signal/contract_gap | Prior specialists: not labeled |Repeated owners/outlier/fences; medium; application and process lifecycle; medium | Known browser-family repair remains0;44Zoom-owned browser headers remain separate. Preserve intentional override/blocking alternatives. |
| P3 | thermald/irqbalance/snapd texture; distribution_texture/weak_signal | Detection: not labeled |Small messages pools andsamePID initialization text; low; daemon state/collection; medium | Do not add arbitrary noise; confirm selected release/lifecycle and task IDs. Missing optional files references are unproven/neutral. |

Fresh facilitator models66/49/60/53 mean57.00, explicitly hypothetical andexcluded
from initial/rolling trends. It retains the actual2Synthetic/2Inconclusive split.
Evaluation remains a guardrail; it misses activity cadence and source-state lifetimes.
Baseline-volume warning remains user-deferredP1 without changing benchmark intensity.
