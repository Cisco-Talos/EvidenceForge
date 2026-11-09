# Loop 12 family contract — certificate issuer validity

## Owning layer

Data-driven TLS issuer and certificate-chain configuration, consumed by
`TlsCertificatePlanner`. The issuer catalogue and `tls_realism.yaml` authority profiles own the
issuer identity and validity interval; a leaf's validity is already bounded to its issuer when
the issuer is valid at the event time.

## Invariant

Every generated certificate chain presented for an observed TLS connection uses issuer
certificates valid at that connection timestamp, and the leaf validity interval contains that
timestamp while fitting inside its issuer's validity interval.

## Entry paths and consumers

Zeek-visible TLS generated from baseline and storyline connections selects public issuers through
`tls_issuers.yaml`; `tls_realism.yaml` supplies public CA chain templates and fixed authority
validity. Zeek x509/SSL records consume the same planned chain. The fix must cover the default pool
and domain overrides, not only the observed Reddit record.

## Why this layer owns the truth

The observed leaf and CA dates are both generated from shared data profiles. Correcting only the
Zeek emitter would preserve an internally inconsistent canonical TLS plan and leave other sinks
exposed. The durable fix belongs in issuer selection/configuration and its validation.

## Sibling risks and verification

Changing public CA entries may affect other external SNI names and deterministic issuer selection.
Add config validation for stale public issuer profiles and focused certificate-planner coverage,
then regenerate the full benchmark and inspect all generated external TLS issuer chains against
their connection times. Keep enterprise/private CA behavior unchanged.
