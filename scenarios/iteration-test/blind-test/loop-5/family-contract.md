# Application exchange is independent of TCP teardown

Classification: family_level / new_family (present in behavior535 and536).
Owner: NetworkTransactionPlanner's canonical transport/protocol preparation and
payload reconciliation. No emitter-local companion synthesis.

Invariant: a modeled request/response or TLS handshake may precede TCP reset or
one-sided FIN. Preserve data-capable TCP termination facts while constructing
supported protocol evidence; never force normal SF solely because an HTTP context
exists. Unanswered/rejected/pre-establishment probes and opaque midstream traffic
must not acquire completed handshake/transaction evidence merely from a port.
Keep raw/suppressed contexts, explicit HTTP, packet/history accounting, native
source windows and tuple/close admission contracts coherent.

Entry paths: baseline service/generic connection noise, authored connection,
browser/proxy transport requests, HTTP transfers, explicit caller contexts, and
DNS/TLS causal prerequisites. All converge on the canonical network planner;
persistent HTTP channel reuse remains limited by its own reusable-flow contract.
Consumers: Zeek conn/SSL/HTTP/files/x509, normalized endpoint FLOW, firewall/proxy,
OCSP children, deterministic eval, IDS predicates and network runtime retention.

Scope for first repair: SF plus payload-bearing established reset/half-closed
states (RSTO/RSTR/S2/S3), with automatic exchange eligible only where bidirectional
payload intent exists. OTH stays partial/midstream; no fresh handshake is invented
from mere observed encrypted application bytes. Existing failed TLS handshake
model can retain S1 and partial SSL history. Preserve SF failure sampling;
non-SF eligible exchanges must not be randomly converted to S1 or SF.

Verification: actual canonical and rendered TLS and HTTP on reset/half-close,
explicit HTTP outcomes preserve state/history, zero-response/pre-handshake and
raw/suppressed requests retain negative evidence, TLS1.2 certificate wire/time
budgets and TLS1.3 encrypted certificate suppression, source close fences and
normal browser/proxy siblings. Probe per-sensor protocol availability against
states without treating missingness alone as an authenticity contradiction.

Evidence: loop3's 3,531 SF +13 S1 SSL observations all have SSL rows; 177 other
state observations have none. Loop2 reproduces the same partition. All four actual
reviewers rechecked during deliberation; export-filter alternatives remain.
Primary Zeek source logs SSL handshake establishment/finalization independently
of TCP SF: https://github.com/zeek/zeek/blob/master/scripts/base/protocols/ssl/main.zeek
This source supports the semantics; constructing the bounded synthetic exchange
plan is an engineering decision, not an inference that bytes prove a handshake.

Prototype result (subprocess-only monkeypatch; production remains537 during
loop4): reset/half-close flows retain original states while TLS/HTTP context can
be constructed; explicit HTTP previously promoted RSTO/RSTR/S2/S3/OTH toSF and
now retains each. A first prototype revealed an important sibling: HTTP response
payload added to a reset needs canonical D/d markers inserted before its reset,
not a successful FIN history. The corrected prototype preserves ShADadR.
Before/after matrix: /private/tmp/eforge-protocol-progress-prototype.json.

Implementation follow-ups before generation: typed shared TCP-state/exchange
eligibility and canonical application-payload history helper, used by protocol
construction, HTTP accounting and final payload reconciliation. Preserve raw and
application-layer-only requests and existing partial TLS failures. Extend the
existing TLS/HTTP duration-floor admission contracts to newly eligible automatic
exchanges; check baseline HTTP absolute close bound (TLS is already bounded for
all states). Do not edit any engine file while generation4 is live.
