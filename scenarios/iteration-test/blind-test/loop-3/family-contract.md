# Independent session observations and RSA derivation completion

## Session observation family

Classification: `family_level`; finding classification: `sibling_defect`.
Owner: `SourceTimingPlanner._apply_runtime_session_constraints`.

Invariant: independent observations of one durable authentication session retain
source-native occurrence timing after their real login. A later unrelated
session-dependent maximum is a closure frontier, not a causal predecessor of
every earlier observation. Preserve genuine ordered action/transport groups and
source login/close bounds. Do not retime Windows rows in the emitter.

Entry paths: authored and baseline workstation lock/unlock, account-audit and
remote-session observations acquire the same durable SessionIdentity through
IdentityLifecyclePlanner. Process-owned observations already have separate
process constraints. Network/action groups that differ from the durable auth
session keep their typed ordering. Consumers include Windows Security and eCAR,
source-finalization sorting, session closure and lifecycle integrity checks.

Evidence: the isolated current planner collapses a canonical ten-minute lock
interval to zero after an unrelated later frontier; an account-change sibling is
also displaced. A temporary copy with the proposed durable-session discriminator
preserves 600.025743 seconds and normal millisecond observation latency. Current
production code was not changed during loop 2 generation. Verify source login
floor, retained closure maximum, network/Kerberos sibling constraints, actual
bundle-to-rendered observations and frozen Windows finalization.

## RSA identity and computation family

Classification: `family_level`; follow-up to the shared RSA builder from loop 2.
The modulus must remain mathematically valid, uniquely scoped by full semantic
identity/public generation seed, and stable through repeated canonical binding
checks. A concrete engineering probe found two identities with the same 32-bit
seed and therefore the same prime stream. Keep full identity width in the RSA
owner; preserve the global utility API.

The shared derivation helper will memoize only immutable public moduli under
fixed-width full-scope digests and a fixed finite capacity. This is explicitly a
new bounded computation memo, revising loop 2's initial no-new-cache design; it
adds no registry/checkpoint schema state and retains no factors or private keys.
It must not cache or bypass acceptance of untrusted patches: canonical material
binding still derives and compares the expected bytes through the same builder.

Entry paths/consumers: direct registry, DKIM, authority/certificate construction,
prepared TLS material and binding revalidation all call the public-key builder.
Verify native prime-factor/key validation, cross-registry reuse, distinct
identities under forced 32-bit collisions, public-seed separation, bounded memo
size and fixed-width keys, existing capacity/adversarial binding/checkpoint tests.
Measure first versus repeated derivation. Existing immutable outputs are not
rewritten. No scenario or reviewer-instruction changes.
