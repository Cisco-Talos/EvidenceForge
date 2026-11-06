## Prioritized reported issues

Priorities/categories are synthesis judgments. Original reviewers did not assign
P0–P4 labels; the table preserves differing evidence strength.

| Priority | Issue / category | Original reviewer rating | Scope / score impact | Owning layer / fix risk | Evidence and next action |
|---|---|---|---|---|---|
| P0 | Zeek stream extent versus capture totals / hard_contradiction | Network 41: not labeled | 580 completed sensor pairs in loop 41; high | Canonical transport source-observation contract; high | Sequence-derived stream totals shrink by exactly modeled capture gaps despite visible handshake/FIN coverage. Separate stream extent from captured packet/payload and file-completeness ledgers, including application children; preserve loop 34's physical partition guarantees. |
| P1 | Client-only URL fragments in HTTP targets / hard_contradiction | Detection 42: not labeled | Five requests, two users, Chrome/Firefox; high local leverage | Canonical browser/HTTP request-target construction; medium | Five quoted proxy GET request lines include `#/conversations`; ordinary browsers exclude fragments from network targets. Separate navigation URL from HTTP target before shared evidence construction, retaining full URLs only in an appropriate client source. |
| P1 | Repeated authored Mac timing / distribution_texture | Host/Threat/Detection 41; Host/Threat 42: not labeled | Repeated fork fractions and six exact 2-second inventory lifetimes; high observed score effect | Authored scenario; benchmark changes outside this task | The pattern is visible and repeatedly drives specialist confidence. It is explicitly authored; preserve it during engine repair rather than adding jitter that contradicts canonical timing. |
| P2 | SSH hour-boundary closes / distribution_texture | Network 40: not labeled | 18/48 longer core SSH sessions close within first 90 seconds of an hour; medium | Session planner/teardown; medium | Closes cluster across five hours, suggesting an hour-fence lifecycle effect. Inspect the shared close owner against role schedules before changing distributions; this is a qualified lead. |
| P2 | HTTP child/parent capture consistency / contract_gap | Network 35–36: not labeled | Repeated qualified source-local file gaps; medium | Application identity and source observation; high | Child capture and parent transport need coherent source-local ownership; independently partial sensors need not be nested. Establish immutable transaction identity and a shared observation contract instead of changing only a seed or file emitter. |
| P3 | Host health-age resets / environment_or_collection_plausibility | Host 40: not labeled | fwupd ages 2/6/14 days within hours, same PID on three hosts; low/medium | Host-local metadata/state; medium | The ages deserve stateful review, but multiple remotes or distinct metadata can explain them. Qualify native semantics before treating this as a proven contradiction. |

Counter and proxy semantics outrank texture because they are reproducible source-native
contradictions. The request-target repair is narrower and lower risk, so it can lead
the next implementation pass while the stream/capture contract is designed.
[Zeek documentation](https://docs.zeek.org/en/v8.0.5/scripts/base/protocols/conn/main.zeek.html)
defines TCP byte totals from sequence numbers; captured IP/packet counters have a
different meaning. [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1)
excludes fragments from the target URI. Both durable defects are tracked in TODO.md.
Neither belongs in an emitter-only rewrite.

Private module inventories, inode texture, optional collection gaps and possible
4658 field extensions remain weak or unverified. No additional hard contradiction
is claimed from those observations. Complete coverage, compact narratives and absent
pre-window initiators were excluded as synthetic indicators.

## Quantitative versus blind evidence

Quantitative evaluation protects parseability, existing relationships and bounded
ordering contracts. It does not yet enforce the native stream/capture distinction,
fragment-free request targets or every timing distribution. Reviewers likewise did
not consistently detect the pivot-linkability hard failure in loops 33–34. Neither
high aggregate evaluation nor low blind confidence overrides a demonstrated failure.
