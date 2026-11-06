# Loop 36: bounded daemon counts and whole-window arrivals

Configured bounded extra-syslog entries now plan scoped binomial target counts below
the safety cap and triangular arrival opportunities over the visible window. The
shared baseline admission path consumes the next opportunity using existing persisted
counters; pure schedule recomputation preserves replay/checkpoint ownership. D-Bus and
both server/workstation polkit profiles opt in through validated YAML. Other literal
caps and multi-row maintenance lifecycles retain their existing owners. Opportunity
availability may leave part of a target unobserved; the cap is not a required quota.

108 focused tests pass, including host/seed/window separation, late-window eligibility,
profile validation and unconfigured sibling behavior. validate-config reports0errors;
Ruff/format pass. Generation/eval pass96.0944,135878records,119files. Across11Linuxhosts,
D-Bus counts now range4–7 instead of8onallhosts, and polkit1–5 instead of3oneveryserver
and6oneveryworkstation. Both continue through later hours rather than saturating early.
The rendered counts/hour histogram is retained. Browser version mismatches remain0
among267matchedrows; TCP history/data and clean-to-partial header probes remain0.

This is a distribution-family change, not measured fleet calibration. The count/phase
probe verifies the selected defect independently of fresh panel scores and activity
changes. Remaining high-leverage targets are P1 first-HTTP whole-millisecond phase
quantization (Network34), P1 sudo/PAM whole-millisecond phase arithmetic (Detection35),
and protocol/file capture semantics (Network35, qualified); exact source owners must
resolve these without per-emitter jitter or fabricated missingness. Original reviewer
priority labels were not assigned. Preserve scenario-authored Mac command timings.


## Family contract

# Bounded Linux health-noise arrivals

Classification: sibling_defect; family_level. Owner: baseline bounded-noise arrival planning plus typed entry configuration. A maximum per-host/window is a ceiling, not a quota to fill at the first available Hawkes slots. Configured bounded entries sample independent host/window/seed occurrence counts and spread eligibility over the visible window using a triangular arrival profile. Both server and workstation polkit and DBus enter through the same extra-syslog selection path; existing literal-cap entries and maintenance bundles are unchanged. Consumers: native syslog, canonical daemon/process evidence, checkpointed admission counters. The schedule is pure recomputation from host/entry/window/seed; counters remain the only admitted-count state. Warm-up does not consume visible counts. Preserve complete anacron lifecycle bundles. Verify count diversity, late-window eligibility, replay, seed separation, config validation and literal-cap siblings. Medium risk: available Hawkes opportunities may leave scheduled events unobserved; caps are not guarantees.


## Individual expert summaries

**Threat Hunter:** Synthetic; verdict confidence 77; synthetic-confidence score 57. The collection is highly usable for hunting, with credible transport-before-authentication relationships, durable process identities, and coherent proxy and endpoint pivots. I lean synthetic because one native Windows process is credited with explicit credential use despite a command line that should fail parameter binding, with a smaller supporting signal from repeated command timing on the two Macs. The score remains in the mixed band because broad checks did not uncover widespread lifecycle or network contradictions.

**Detection Engineer:** Real; verdict confidence 65; synthetic-confidence score 18. The supplied records appear production-like from a detection engineering perspective: the examined native schemas parse, identities remain consistent, and the visible process, authentication, file-access, and network relationships survive substantive checks. I did not establish a hard contradiction or a material source-native defect; the verdict is a modest preference for real data, not a claim that a sufficiently capable synthetic system could not produce this collection.

**Network Forensics:** Synthetic; verdict confidence 76; synthetic-confidence score 62. Most network evidence is convincing: transport state, protocol timing, DNS diversity, TLS negotiation, proxy topology, and long-lived administration flows fit a mixed enterprise network. My synthetic verdict rests on a narrow but repeated inconsistency: four HTTP file transfers report missing content without the corresponding same-sensor TCP gap accounting, including one transfer whose complete observation at a second sensor isolates the discrepancy.

**Host Forensics:** Synthetic; verdict confidence 82; synthetic-confidence score 65. The endpoint evidence has strong identity and lifecycle consistency, with realistic Windows session bootstrap and detailed macOS fork/exec semantics. My synthetic verdict rests on repeatable, millisecond-exact process timing patterns and an implausible accumulation of independent Chrome browser process trees using the same macOS user/profile context; I did not establish a hard impossible-ordering contradiction.


## Scores and comparison

Automated eval 96.0944; standalone synthetic-confidence average 50.50 (mixed/inconclusive), prior loop 52.5. Lower is more production-like. Scores are standalone reviewer measurements; physical/semantic probe outcomes independently verify the selected family.

Facilitator-modeled deliberation averages 64.50; see deliberation.md. Modeled revised positions are excluded from standalone and rolling averages and are not reconvened expert votes.
