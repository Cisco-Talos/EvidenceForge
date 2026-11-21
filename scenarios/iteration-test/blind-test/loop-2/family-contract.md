# Machine-account Kerberos ticket reuse

Classification: `family_level` with baseline adapters into the existing shared
Kerberos/DC cache owner. Finding classification: `sibling_defect`.

The new-epoch loop 1 rendered-output probe counted 798 fresh TGT audits, including
62–111 requests per ordinary Windows machine over six hours. The main baseline
cycle and machine-logon paths force AS exchanges without consulting reusable
cache state. This is a distribution/operational-model issue, not a crash test.

## Owner and invariant

The Kerberos/DC activity/action-bundle cache owns whether an implicit machine
request needs a fresh TGT. A valid cached machine TGT is reused for later service
ticket requests. A baseline AS exchange must be planned only when needed; do not
create an AS-only transport and then hide its audit row. Explicitly requested
TGT/paired exchanges remain explicit intent and are not silently suppressed.

## Entry paths and consumers

- Baseline DC Kerberos cycles: adapt the AS-only transport decision to the shared
  cache predicate; existing service-ticket transports remain independent.
- Machine-account logon bundle: choose paired AS+TGS or TGS-only evidence through
  the same cache predicate, including the unmodeled-source compatibility path.
- Automatic KDC-flow audit: use the existing shared predicate, now consistently
  reusing a valid machine cache. User-principal heuristics remain as before.
- Explicit TGT and renewal action bundles: continue to publish/remember cache
  truth only after primary dispatch. Explicit forced `tgt`/`pair` modes persist.
- Consumers: Windows 4768/4769, canonical KDC transports and network/endpoint
  companion evidence, session bootstrap, checkpoint/cache serialization.

## Sibling verification and residual risk

Test valid cache reuse across automatic transport, machine-logon and baseline
paths; expiry and explicit forced requests; preserve new-account prerequisites
and existing primary-dispatch rejection/cache tests. No new checkpoint field or
format is introduced. The existing cache remains client/principal/DC scoped;
realm-wide cache sharing, per-LUID user cache modeling and service-ticket reuse
are separate follow-ups, not claimed by this change. Baseline scheduling may be
out of order; this change keeps the existing cache's expiry semantics and does
not claim to reconstruct arbitrary historical cache intervals.
