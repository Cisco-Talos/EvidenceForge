# Mac-series loop54: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop11 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **95.5090**, 140,141 records. Hard acceptance status **REVIEW**; criteria are recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat62 / Detection84 / Network66 / Host84**, mean **74.00** (likely synthetic); lower is more production-like. Prior mean46.75; current rolling5 **52.30**. Verdict confidence is separate.

Deliberation was not triggered by the recorded verdict/confidence/spread criteria.

## Canonical inspected-client TLS wire repair

The owner is the proxy action bundle's physical client transport and the authenticated application-channel admission ledger. CONNECT control and decrypted HTTP totals do not include encrypted handshake/record bytes. The bundle now computes a scoped fresh client-leg TLS1.3 handshake budget from validated configuration and expands complete plaintext messages into TLS records (16384-byte fragments plus5-byte header,1-byte inner content type and16-byte AEAD tag). Setup wire totals are frozen into the private open preparation; reused requests reserve encrypted application bytes without repeating the handshake. Plain HTTP and opaque CONNECT retain their separate contracts. Denied/auth-required setup does not acquire successful TLS framing. This is transport sizing, not a claimed recovered PCAP transcript or an exported client-negotiation field absent from the data.

The pure aggregate reservation upper bound covers per-message partial records; actual reused admissions consume request-local wire budgets. Source proxy cs/sc totals remain plaintext local message totals; canonical client TCP/ASA/eCAR consumers receive the physical ledger. No log row generates sibling evidence, no emitter independently invents overhead, and the source request-header fix from53 remains intact.

## Tests and complete output probes

The combined221proxy/channel/browser/HTTP/TLS/config checks passed; after two further reuse-handoff siblings were added,150related tests passed. Three proxy checkpoint tests passed. New cases cover fragment boundaries, exact integer validation, aggregate capacity, transport-scoped determinism, absent repeated handshake, plaintext controls and inverted profile validation. Existing upload/request-local fixtures now verify complete physical manager/network byte equality and bounded handshake/record expansion, rather than asserting plaintext equals encrypted TCP.101configfiles are clean; Ruff check/format passed before behavior453 and fresh generation.

The fresh complete-flow probe qualifies987unique core inspected tunnels with SYN/SYNACK/bothFIN and SF. **Zero** equal CONNECT control plus visible plaintext alone and **zero** fall below the conservative fresh handshake/record floor;53had543exact plaintext sums and815floor failures among977qualifiedtunnels.1450inspectedrequests retain zero conservative serialized-header failures. Capture/source gaps remain modeled; excluded partial/ambiguous flows are not silently counted as passing. Full canonical lifecycle/checkpoint tests support single physical setup ownership and reused reservation integrity.

## Scope and unresolved guardrail

The bundle has140141records/117files; the union comparison records119changed paths and2unchanged paths because some history paths are added/removed. Increased client transport sizes change reuse/physical leg decisions and subsequent canonical child activities; do not claim localized data effects or causally attribute a standalone score movement solely to TLS. Authored input hashes, seed42, coverage profile and baseline warning policy are unchanged. Native Mac census remains complete95forks111execs93exits, zeroaggregatebirths;11mounted helpers have exits. Eight native Mac02 adjacent fork-version reversals remain a manifestation of the existing allocator defect. Network native ICMP, capture/history minima, ASA semantics and fragment contracts pass.

Automated95.5090 remains REVIEW: hard pivot linkability139/191=72.7749 fails80. This original criterion is retained without threshold changes or seed rerolls. The next selected55repair honors frozen Windows source timestamps during legacy lock repair; native-only Mac launch trace matching and large foreground-planner time shifts remain distinct reconciliation concerns. No reviewer is told this context.

## Verified next priorities

P0 native Mac allocation chronology remains high-risk canonical state work. P0source file-locality is verified against pinned Zeek8.0.5 semantics:54has1417mismatches/2434comparable rows (SSL1191,HTTP226);56targets shared sender-direction selection in native/sensor projection. P0/P1frozen Windows lock times and native-only trace matching drive the hard guard. P1exact per-request User-Agent shared truth is independently reported by both TH and Network54:57unique-second pairs across8clients and59time-tolerant pairs across7clients, with different join criteria, the same defect family. CryptoAPI/GoogleUpdate requests become browser identities in sensor/endpoint views, while proxy retains the original product. Inspect the canonical process/protocol owner and preserve explicit authored header overrides. P1SAM mask/token,4672sensitive rights, Chrome profile singleton and connect-only scan semantics remain open. Weak diagnostic/daemon vocabulary concerns stay qualified; no arbitrary noise is added.

## Accepted independent scoring

TH62 / Detection84 / Network66 / Host84 mean74.00, versus53mean46.75. All four verdicts areSynthetic with averageverdictconfidence86.25 and22pointspread, so nofacilitatortrigger. Detection and Host independently proved the native Mac allocator reversal, making this repeated P0 the dominant shared evidence; TH and Network independently verified the UA disagreement family. The TLS objective probe passes and no reviewer alleges its wire model failed. The increased score reflects newly examined deeper contracts and expanded manifestations of a pre-existing allocation bug in a changed canonical activity population; it is not evidence that TLS plaintext accounting should be restored.

Both Mac specialists also retain exact1ms handoffs as limited supporting texture, with automation alternatives. Host's gapless10–133allocation range is corroborative of the allocator family and is not counted as a separate defect. All accepted provenance is neutral data/briefings plus primary references; no forbidden actual reads were reported. Inherited generic instructions remain a blinding limitation. Reviewer original P0-P4 ratings were not labeled; coordinator priorities above remain distinct synthesis. REVIEWhardpivotstatus stays visible beside the blind score; no claimedpassfromhigheraggregateeval.


## Independent reviewer summaries

**Threat Hunter:** Synthetic; verdict confidence 77; synthetic-confidence score 62. The operational evidence is unusually competent: Windows credential abuse, remote administration, Linux SSH activity, file staging and proxy traffic generally support workable investigative pivots with plausible lifecycle ordering. My synthetic verdict rests on a specific repeated discrepancy, rather than the storyline: 57 unambiguous same-request joins report conflicting client User-Agent values between Zeek and the proxy, including browser-versus-service identities, across eight client IPs. This is a likely shared-truth defect, but unknown proxy enrichment or normalization prevents a definitive hard-contradiction finding.

**Detection Engineer:** Synthetic; verdict confidence 91; synthetic-confidence score 84. The data is highly usable for detection engineering: the XML and JSON parse, Windows schemas are largely faithful, process identities correlate, and network protocol records retain coherent connection tuples. My synthetic verdict rests primarily on native macOS process-generation identities moving backwards across newly created processes, reinforced by repeated exact one-millisecond process handoffs; it does not rest on the suspicious activity's completeness or narrative shape.

**Network Forensics:** Synthetic; verdict confidence 85; synthetic-confidence score 66. The network records are substantially production-like: connection states, byte accounting, DNS diversity, TLS visibility, certificate reuse, and sensor clock relationships mostly withstand cross-checking. The strongest contrary evidence is a repeated request-identity inconsistency: the proxy and both Zeek sensors attribute different User-Agent values to otherwise matching client-to-proxy requests, including updater traffic being represented as browser traffic. This is a recurring cross-source contract defect, rather than proof of impossible TCP behavior, so the score stays below the hard-contradiction band.

**Host Forensics:** Synthetic; verdict confidence 92; synthetic-confidence score 84. The Windows and Linux evidence has substantial endpoint realism, including credible process ancestry, varied session types, stable executable hashes, and coherent SSH lifecycles. The decisive contrary evidence is in MAC-MROSS-02's native Endpoint Security audit tokens: newly created process/execution identities repeatedly receive lower `pidversion` values than identities already created earlier on the same boot, while both wall-clock and Mach time advance. Repeated exact one-millisecond shell scheduling boundaries provide a smaller, separate indication of constructed timing.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 45 | 96.31 | 35 | 34 | 65 | 29 | 40.75 | mixed/inconclusive | 49.50 | 53.50 |
| 46 | 96.31 | 38 | 67 | 20 | 82 | 51.75 | mixed/inconclusive | 76.25 | 50.15 |
| 47 | 96.31 | 24 | 45 | 90 | 78 | 59.25 | mixed/inconclusive | 84.00 | 52.60 |
| 48 | 96.45 | 30 | 54 | 74 | 38 | 49.00 | mixed/inconclusive | 64.75 | 51.60 |
| 49 | 96.45 | 46 | 82 | 56 | 82 | 66.50 | likely synthetic | 83.00 | 53.45 |
| 50 | 96.47 | 46 | 82 | 72 | 32 | 58.00 | mixed/inconclusive | 79.00 | 56.90 |
| 51 | 96.47 | 67 | 28 | 58 | 32 | 46.25 | mixed/inconclusive | 58.75 | 55.80 |
| 52 | 95.78 | 35 | 36 | 32 | 43 | 36.50 | mostly realistic | — | 51.25 |
| 53 | 95.78 | 28 | 34 | 82 | 43 | 46.75 | mixed/inconclusive | 71.50 | 50.80 |
| 54 | 95.51 | 62 | 84 | 66 | 84 | 74.00 | likely synthetic | — | 52.30 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all recorded data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.
