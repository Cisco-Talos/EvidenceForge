# Deterministic RSA public material

Classification: `family_level`; finding classification: `new_family`.

The blind network reviewer found tiny prime factors in nine of twelve distinct
DKIM public-key moduli. The shared registry builds arbitrary odd modulus-shaped
bytes, so the same mathematical defect can affect RSA certificate public keys.

## Owner, invariant and rationale

`CryptographicMaterialRegistry._build_public_key_spki` owns the public key before
DNS TXT, certificate identity and fingerprints are derived. Its RSA branch must
construct a modulus from two independently scoped large primes, with the declared
bit size and exponent 65537, deterministically for one identity/profile. Valid
ASN.1 syntax alone is insufficient. Fixing DNS formatting would leave certificate
and transactional-preparation siblings defective.

## Entry paths and consumers

Direct public-key resolution and prepared TLS-material overlays use the same
builder. DKIM selector/domain resolution, CA identity and TLS certificate identity
consume it. DNS TXT chunks, certificate SPKI/fingerprint/hash evidence and registry
checkpoint heads consume the resulting canonical plans. ECDSA already derives a
valid curve point and is outside the changed algorithm.

## Verification and residual risk

Use an independently implemented native RSA private-key validation in focused
tests to verify generated factors, public size and exponent; exercise multiple
sizes, identities and selector/CA siblings, determinism, and existing bounded
registry/checkpoint tests. Prime search is pure and locally scoped, retaining no
new cache or checkpoint fields. Synthetic deterministic keys are public evidence,
not keys for securing communications. Existing immutable outputs and retained
old-behavior checkpoint material are not rewritten. Prime generation adds CPU
cost; measure a representative first resolution and retain registry reuse.
