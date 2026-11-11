# Deliberation Summary

## Scope and status

This is a facilitator synthesis of the four independent reports in this directory, guided by the expert-deliberation reference. No repository, scenario, evaluation, or other assessment was consulted, and no additional record inspection was needed. Counts and examples below are **reported measurements**, not new facilitator measurements. The reviewers have not participated in a subsequent discussion or re-vote: no revised positions or collective endorsements are attributed to them.

## Original panel positions

| Expert | Original verdict | Verdict confidence | Synthetic-confidence | Revised position |
|---|---|---:|---:|---|
| Threat Hunter | Inconclusive | 78 | 28 | Not solicited; original retained |
| Detection Engineer | Real | 65 | 18 | Not solicited; original retained |
| Network Forensics | Real | 75 | 19 | Not solicited; original retained |
| Host/EDR Forensics | Inconclusive | 80 | 42 | Not solicited; original retained |

The original, unweighted synthetic-confidence mean is **26.75/100**: `(28 + 18 + 19 + 42) / 4`. The score range is 18–42. Verdict confidence is a separate measure and has not been averaged into synthetic-confidence. There is no revised mean and no unanimous provenance verdict.

## Round 1 — Findings represented in the reports

- **Threat Hunter:** Exact-tuple SSH and return SCP investigations, NewCredentials local/outbound identity separation, and reconciled proxy upload accounting support technically workable evidence. Weak concerns are ten identical search referrers on DC API check-ins and one runas process under winlogon among five observed runas creates.
- **Detection Engineer:** Event-specific Windows encodings, correctly sized hash strings, exact-GUID lifecycle checks, and SSH/RDP joins support production-like structure. The report established no score-bearing synthetic indicator. Its notable RDP example distinguishes transport disconnection from a later final Windows logoff.
- **Network Forensics:** DNS outcomes, state/history diversity, TLS visibility distinctions, certificate/file relationships, proxy accounting, and a NAT lifecycle support network coherence. Brief DMZ TLS durations receive negligible weight because proxy request traffic and the observed long tail supply a reasonable explanation.
- **Host/EDR Forensics:** Exact process lifecycles, Linux sudo ownership, and macOS fork/exec/exit identity transitions support technical coherence. The higher score reflects qualified concern about 41 Windows creator/target subject patterns and seven cat-on-binary-document executions on one Mac, rather than an established impossible relationship.

## Round 2 — Evidence-based cross-examination

### Windows parent owner, creator subject, and impersonation

The Host report identifies 41 of 913 Sysmon creates with differing child and parent users; matching Security 4688 rows all name the child account as Creator Subject and leave Target Subject null. Sixteen are userinit launches under SYSTEM-owned winlogon. That repetitive observation is more specific than an impression of an unusual process tree, and it warrants investigation of the actual creation mechanism.

It does **not** establish that Creator Subject must equal Sysmon ParentUser. A parent process's primary owner does not reveal the effective token of its calling thread; impersonation can make the requesting account differ from the parent's owner. Creator Subject, target process owner, and parent owner are distinct facts. The Host report itself makes this qualification. The Detection report's native-format and lifecycle successes do not settle effective token semantics, but neither does the Host observation overturn those successes. The defensible facilitator resolution is a qualified semantic question, not 41 hard contradictions or a mandatory rewrite to SYSTEM subjects. Populate Target Subject only where the actual creator/target logon relationship requires it.

The Threat Hunter's single runas/winlogon lineage is likewise an unusual-launcher question, not proof of impossible execution. It is not established to share the root cause of the 4688 pattern. Preserve the separately demonstrated Type 9 distinction between local aisha.johnson and outbound marcus.chen.

### Repeated commands and referrers

The Host report measures seven cat-on-DOCX/XLSX/PDF execs among 64 execs on MAC-MROSS-02 and attributes seven of nine eCAR FILE READs to those operations. The narrow denominator and exact examples support a local behavior-texture concern. They do not establish ordinary document editing as the intended behavior, and cat remains possible for inspection, transfer, or automation. Valid fork/exec/file joins establish coherence, not that this command mix is representative of office work. No GUI source or extra source volume is required by the evidence.

The Threat Hunter measures the same Google search referrer and Chrome/121 user agent on all ten DC check-in GETs. This is specific evidence of repeated metadata, but a real automated client or implant can intentionally use a static camouflage profile. It therefore supports a narrowly scoped header-origin check, not a protocol contradiction. Neither repetition finding justifies indiscriminate randomization of commands or headers: intentional automation should remain stable.

### Clean joins, successful investigations, and duration distributions

The Detection and Network reports both enumerate 13,662 successful same-sensor protocol-parent tuple joins. This overlapping measurement must not be counted as two independent samples. Likewise, their process-lifecycle sweeps use different denominators and tolerances and cannot be summed. Their strength is the identity and semantic specificity of the checks, not the mere presence of all companions.

Reconstructable SSH/RDP actions and upload accounting support internal compatibility; neither a complete incident narrative nor complete joins establishes artificial origin. Sparse native sources, window-crossing lifetimes, sanitized names, and collection duration receive no penalty. The Network report's brief TLS concern is weaker than the Windows/behavior questions: request-oriented traffic and a 165.676599-second maximum already defeat a claimed hard duration cap. No repair target follows from that duration statistic alone.

## Round 3 — Position revisions

No reviewer revisions were requested or received. Original verdicts, verdict confidences, scores, and category ratings remain as submitted. The discussion above is facilitator reasoning about the strength and limits of their evidence; it is not a transcript, new measurement, or panel re-vote.

## Round 4 — Facilitator conclusions

### Agreements supported by the reports

All four reports describe predominantly production-like evidence and establish no hard contradiction in their bounded reviews. Exact identity ownership, transport-before-authentication ordering, source-specific observation timing, and native lifecycle distinctions recur as strengths. The differing Real/Inconclusive labels reflect residual uncertainty and specialty-specific weak concerns rather than incompatible raw findings. Good internal coherence remains compatible with either origin.

### Most convincing observations, ranked by evidentiary strength

1. **Concrete cross-source accounting and identities:** independently rendered proxy control/tunnel totals reconcile with transport bytes; exact SSH/RDP tuples and sessions retain compatible ordering. These are strong compatibility findings, not provenance proof.
2. **Exact process and execution lifecycles:** GUID/object-based Windows/eCAR checks and macOS fork/exec/exit examples avoid PID-only reasoning and reveal no demonstrated inversion under stated tolerances. Scope limits still apply.
3. **Windows creator/target pattern:** the 41-case pattern is the most substantial unresolved semantic candidate, but invisible effective thread identity prevents elevation to a hard contradiction.
4. **Local repeated behavior and metadata:** seven cat document operations and ten identical search referrers are concrete, limited texture concerns with credible real-world explanations.
5. **Brief DMZ TLS concentration:** weak and adequately explained by the visible traffic context; it supplies no justified correction.

### Justified next targets

These are facilitator priorities inferred from the reports, not newly voted consensus recommendations:

1. **Resolve Windows creation semantics before changing them.** Trace the intended creation API, effective calling token, child token, and logon relationship for the 41 cases, especially userinit. Retain separate creator and target identities when warranted; do not infer creator identity solely from parent ownership. Inspect the single runas/winlogon launch separately and preserve NewCredentials semantics.
2. **Check the meaning of the seven Mac document commands.** If they represent ordinary document consumption, use the actual consuming application's execution/file behavior. If they represent binary inspection or transfer, retain cat. Address behavior ownership rather than adding cosmetic GUI telemetry.
3. **Check the originating client profile of the ten DC API requests.** Use a search-navigation referrer only where the navigation or intentional camouflage explains it. Preserve deliberate static automation profiles; remove generic browser decoration only if unsupported by that mechanism.

Preserve the demonstrated native field shapes, SSH/SCP and RDP lifecycle relationships, disconnected-session semantics, macOS execution identities, TLS visibility distinctions, and proxy byte scopes. Do not introduce retries, missingness, disorder, new source families, or arbitrary variation merely to reduce cleanliness. The original mean remains **26.75/100 synthetic-confidence**, with two Real and two Inconclusive verdicts; the justified work is bounded investigation of the three targets above, not a claim that a new defect or revised consensus has been measured.
