# Root-cause fixes, loops 23–32

| Loop | Owning layer | Change | Verification |
|---|---|---|---|
|23|Canonical TLS planning|Budget responder bytes for real certificate framing, signatures and handshake material|460 RSA2048 ECDHE observations fit physical budget|
|24|Network timing|Remove certificate-count duration floor; use analyzer readiness|Former near 1.2 s cluster 122 to 0;1241 TLSfiles inside flows|
|25|Canonical Mac installed provisioning|Full-range filesystem timestamp precision, stable shared build metadata|260 times; zero tiny 1–999 ns tails;83 tests|
|26|Shared TCP wire accounting|Word-align headers within MTU budget rather than clipping total bytes|85 clean header alignment failures to 0|
|27|Canonical session state|Allocate logind IDs with future reservations; remove renderer renumbering|64 matched SSH starts; ID mismatches 1 to 0|
|28|Schedule intent/config|Separate user-unit scope from machine scheduling|Automatic Tracker starts 0; system-maintenance eligibility retained|
|29|Proxy phase planner/config|Sample origin request readiness after setup|Exact 1 ms origin HTTP offsets 40 to 0;143 tests|
|30|Canonical TCP/TLS accounting|Include retransmitted payload in wire budget and reconcile TLS growth|2341 clean retransmitting directions; failures 2 to 0;187 tests|
|31|World model/baseline|Select compatible Windows targets for native management|Native commands 4 to 5; Linux targets 2 to 0;73 tests|
|32|Preauth semantics and DNS planning|Separate TCP probes from userauth; account for TCP DNS prefixes|Invented scan-host auth rows 8 to 0,4 preauth closures; DNS directional failures 14 to 0 across 11 observations;52 tests|

All ten scenario validations, generations and automated evaluations passed. Each run used four fresh data-only reviewers; one contaminated loop 29 reviewer was discarded and replaced. Changes remain in the worktree, and the benchmark scenario was preserved. Focused checks were used; this set is not a release/full-suite certification.

Scores have substantial reviewer variance. For example, loop 26 changed only network/ASA files while the endpoint score moved 25 to 68. Higher scores in later rounds also reflect newly discovered concrete defects. These standalone panels do not establish a causal model-capability comparison.
