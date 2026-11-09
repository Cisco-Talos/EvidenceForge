# Loop 22 root-cause probes

Fresh generation, loop21 data, and neutral review input match byte for byte across 117 files. Evaluation remains 96.34950094006459 over 132,196 records. Generator and scenario are held unchanged for the requested model comparison.

## Previous port-0 diagnosis is false

All 254 alleged port-0 probes use ICMP (IP protocol 1), type 8/code 0; 245 are unanswered and nine answered. Zeek stores ICMP type/code in the port fields. See [official Zeek documentation](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html). The scenario separately authors ICMP discovery and a five-port TCP scan. The canonical scanner discovery owner deliberately produces these echo probes. No sixth TCP service port exists in this cohort. This supersedes loop21's diagnosis; historical scores are preserved. Reviewers received neither this finding nor historical scores.

## Proxy HTTP timing floor reproduced

A decimal-arithmetic UID join reproduces 37 of 2,261 DMZ HTTP records exactly 0.001000 seconds after their matching connection, all from proxy 10.10.3.20 across 16 user agents. Counts and sample UIDs are in root-cause-probes.json. The canonical network/application planner applies a 1 ms minimum request gap to application-only events without canonical request time. This is a concrete distribution artifact candidate, not an impossible protocol interval. A future fix belongs in shared proxy/application request planning, covering HTTP, CONNECT, reuse and short connections; emitter jitter would only mask it.

## TLS byte and duration owner verified

UID `ClI8KmgRGHYsTDasQq` has 3,348 server payload bytes, two complete DER files totaling 3,068, and a successful non-resumed TLS 1.2 ECDHE_RSA handshake with an RSA-2048 leaf. Only 280 bytes remain; the RSA signature uses 256 before mandatory ServerHello, exchange parameters, certificate framing, records and Finished. The lower bound is violated even before SMTP dialogue. See [TLS 1.2 handshake structures](https://www.rfc-editor.org/rfc/rfc5246) and [ECDHE structures](https://www.rfc-editor.org/rfc/rfc4492).

Independent parent probes reproduce 22 core and 15 DMZ RSA-2048 ECDHE_RSA rows at chain-size plus 280; 36 have zero missed bytes. These counts are sensor observations, not necessarily distinct sessions. The shared `_ensure_tls_conn_covers_certificate_bytes` in generation/activity/generator.py uses exactly `cert_bytes + 280` and `max(min_duration, 1.05 + 0.075 * chain_length)`. Two certificates yield a 1.2-second duration floor. This canonical accounting owner explains both new network findings and is the highest-priority next family fix. The DMZ spike is independently reproduced: 152 of 2,516 successful HTTPS observations in 1.200070–1.201719 seconds.

## macOS executable metadata owner verified

The installed-file provisioning owner in generation/macos_installed_provisioning.py subtracts integer seconds from the whole-second scenario anchor, then `_time` adds only `rng.randrange(1000)` nanoseconds. This explains the Host/EDR finding that all 232 deduplicated executable stat timestamps have fractions below 1,000 ns. Repair should distinguish package-preserved build timestamps from host install/change/access time through canonical installed-file metadata, preserving shared file identity and chronology.

## Interpretation limits

The adjacent loop21/22 pair controls data. Earlier loops changed generation, so the 20-loop mean is historical context. One fresh panel cannot establish a reliable model effect or comparative accuracy from scores alone. Reviewers inherit the current session model; prior model identity is user-reported and unverified.
