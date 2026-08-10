# Loop 59 Blind Network Forensics Review

## Verdict

- **Verdict:** Real
- **Verdict confidence:** 82/100
- **Synthetic confidence:** 24/100

The capture is more consistent with a real, bounded enterprise collection than with a simply generated dataset. Its strongest evidence is not surface formatting but the preservation of network state and source-native relationships across Zeek protocol logs, two independent sensor views, Cisco ASA lifecycle messages, proxy records, and IDS alerts. The remaining synthetic probability comes mainly from unusually tidy population-level coverage and repetition, not from a decisive protocol contradiction.

## Category scores

| Category | Score | Assessment |
|---|---:|---|
| Cross-source network coherence | 93/100 | Strong tuple, state, timing, and lifecycle agreement across network sources |
| Protocol semantics | 91/100 | DNS, HTTP, TLS, DHCP, SMTP, and connection-state relationships are credible |
| Temporal realism | 87/100 | Microsecond texture, sensor delay, connection duration, and cache behavior are convincing |
| Traffic population realism | 78/100 | Broad service mix, but some actors and request families are unusually concentrated |
| Sensor/source authenticity | 90/100 | Source-specific identifiers, precision, omissions, and field sets look native |
| Investigative utility | 92/100 | Sufficient correlated evidence exists to reconstruct transport and application activity |

## Supporting evidence

1. **Connection lifecycle is internally disciplined without being perfectly uniform.** The core sensor contains 6,055 connections and the DMZ sensor 5,180 across roughly six hours. Core traffic spans DNS, Kerberos, SMB, HTTP, LDAP, TLS, DHCP, SMTP, SSH, RDP, and RPC. DMZ traffic contains a credible mixture of successful sessions and 1,381 unanswered `S0` attempts. `S0` records have no response packets or bytes, while successful and reset states carry compatible histories and accounting.

2. **Independent sensor observations behave like independent observations.** There are no reused Zeek UIDs between the core and DMZ sensors. Nevertheless, approximately 1,740 same-five-tuple observations align within two seconds, with matching connection state and service. Their timestamps generally differ by tens of milliseconds rather than being copied exactly. That combination—independent identity, small observation delay, and semantic agreement—is a particularly strong realism signal.

3. **Protocol fan-out is coherent.** Every checked DNS, HTTP, TLS, and SMTP UID resolves to a connection on its own sensor. DNS response time and UDP connection duration agree; HTTP request timestamps range from connection-open time to several seconds later; TLS handshakes occur after transport open rather than at a fixed copied timestamp. File records use `conn_uids` and preserve transmitter/receiver orientation.

4. **DNS behavior has stateful texture.** Records include A, AAAA, PTR, authoritative internal answers, recursive external answers, negative/no-answer behavior, variable RTTs, and realistic TTL behavior. Repeated cached-looking answers sometimes show decreasing TTLs—for example, an answer observed at 1,649 seconds later appears at 849 seconds after roughly 800 elapsed seconds—rather than resetting mechanically on every query.

5. **TLS evidence has plausible depth.** The data distinguishes resumed and full handshakes, TLS 1.2 and 1.3, compatible cipher suites and histories, leaf/intermediate certificate relationships, X.509 validity periods, OCSP artifacts, and certificate file extraction. Resumed sessions generally omit full certificate fan-out, as expected.

6. **Perimeter lifecycles are unusually strong.** The ASA data contains 3,911 TCP build messages and 3,910 matching teardowns by connection ID. The sole unmatched build occurs near the end of the capture and is therefore consistent with a session extending beyond the collection boundary. NAT translations and teardowns follow the corresponding outbound DMZ sessions, and denied flows do not acquire normal successful lifecycles.

7. **The collection includes believable imperfections.** File records include partial captures and nonzero missing bytes, reset and rejected sessions coexist with clean closes, sensor timestamps are not identical, protocol companions are not present for every transport, and the final capture boundary leaves an open perimeter connection. These are useful counter-signals to a perfectly assembled synthetic corpus.

## Synthetic indicators and caveats

- The capture has a hard, nearly exact six-hour window with broad activity from nearly every source. This may simply be intentional collection scoping, but it makes the dataset feel curated.
- A few public clients contribute hundreds of connections to the same web service, and proxy-origin traffic is dominated by a relatively small application/domain pool. Bot traffic and enterprise software can produce this, but the concentration and reuse make population construction more visible than in a noisy production capture.
- Several common DNS answer families map domains into compact, adjacent address groups and recur with very stable application characteristics. CDN behavior can explain this, though more resolver, edge, and client diversity would reduce the residual synthetic impression.
- Cross-source lifecycle completeness is excellent—perhaps cleaner than many production deployments. The independent sensor delays, missing file bytes, resets, and capture-boundary orphan keep this from becoming a contradiction.

## Recommendations

1. Increase population-level diversity for high-volume external web clients: vary session persistence, request cadence, TLS resumption streaks, path progression, failure rates, and client return intervals by actor.
2. Broaden proxy destination and CDN edge behavior, including larger address rotation, multiple answer-set sizes, resolver-cache states, and occasional connection fallback to another returned address.
3. Preserve the current cross-sensor contract. Independent UIDs, small sensor-relative delay, matching five-tuples, and compatible state are among the dataset's strongest realism features.
4. Add a little more collection-operational texture at the source level—short sensor gaps, selectively missing protocol analysis, or host-specific visibility differences—while keeping lifecycle groups coherent.

## Final assessment

No hard network-forensic contradiction was found. The network layer is technically rich, source-native, and strongly correlated. The main opportunity is to make the *population* less curated, not to repair basic protocol or lifecycle semantics.
