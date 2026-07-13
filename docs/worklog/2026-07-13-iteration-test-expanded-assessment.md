# Iteration-Test-Expanded Assessment Loops 62-71

## Scope

Run ten iterative realism fix loops against
`scenarios/iteration-test-expanded/scenario.yaml`, preserving prior artifacts and
writing new results under `scenarios/iteration-test-expanded/blind-test/loop-N/`.
Each loop selects concrete blind-review evidence, fixes the highest owning layer,
verifies a sibling path, regenerates, evaluates, and runs a standalone blind panel.

## Loop 62 Family Contract

- **Selected family:** Zeek TLS resumption, handshake-history, and certificate fan-out
  coherence.
- **Finding classification:** `sibling_defect` in the existing canonical TLS/X.509 family.
- **Owning abstraction:** the shared TLS handshake-history sampler and canonical TLS context
  construction in `ActivityGenerator`.
- **Invariant:** `SslContext.resumed` must agree with the Zeek `ssl_history` handshake messages.
  Abbreviated TLS 1.2 and PSK-style TLS 1.3 histories must not contain certificate or full key
  exchange messages, while non-resumed handshakes must not use abbreviated-session histories.
  Resumed sessions must continue to omit fresh certificate/file/x509 fan-out.
- **Entry paths:** ordinary TLS connections, explicit-proxy origin TLS, inbound TLS, SMTP
  STARTTLS, and any caller that uses `_choose_ssl_history()` or `_attach_ssl_context()`.
- **Consumers:** Zeek `ssl.json`, `files.json`, and `x509.json`; automated correlation checks;
  network-forensics review; TLS hard probes.
- **Layer rationale:** the contradiction is created when canonical `SslContext` fields are
  sampled, before Zeek rendering. The emitter correctly serializes the supplied values and the
  certificate builder correctly omits chains for resumed sessions, so an emitter patch would
  preserve the inconsistent source truth.
- **Sibling risks:** this fix covers both TLS 1.2 and TLS 1.3 plus SMTP STARTTLS. It does not
  attempt to model every Zeek handshake-history permutation, TLS renegotiation, decrypted TLS
  1.3 certificate visibility, or packet-loss-driven partial histories.

