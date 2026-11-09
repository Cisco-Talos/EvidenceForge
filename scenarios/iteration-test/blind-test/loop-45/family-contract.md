# Loop45 family contract: TCP stream extent and captured traffic

Classification: `family_level`; source renderers and legacy codec migration are
adapters into the source-observation contract.

Owner: `NetworkSensorObservation` and the shared observation planner. Canonical
network traffic supplies full-wire payload truth. A source observation must retain
physical captured packets/IP/payload separately from known TCP sequence-space
extent. The native Zeek conn projection renders the explicit extent; application
and extracted-file projections retain their captured-content semantics. An emitter
must not invent a missing-byte addback or mutate the captured ledger.

Invariant: when source-visible SYN/FIN boundaries establish a direction's complete
sequence range, an interior capture gap does not reduce its stream extent. Packet
counts, captured IP/payload, content gaps, HTTP body observations and extracted-file
completeness may differ by sensor. Unknown/partial boundary coverage does not claim
a complete extent. All physical retained/missing packet and header partitions,
source timing, identifiers and canonical transport/lifecycle ownership remain valid.

Entry paths: ordinary baseline/storyline/causal network planning; proxy/browser,
HTTP/TLS/SSH and database transports; persistent SMB observation snapshots and
terminal traffic rebinding; direct renderer compatibility; checkpoint round trips.
Inventory found two production observation constructors and the persistent authority's
replace/rebind path. Consumers include Zeek conn, HTTP/files and protocol companions,
ASA/eCAR captured-byte views, exact publication/retained digests, persistent SMB scalar
preflight/authentication and explicit allowlisted checkpoint values.

Introduce a typed frozen stream-extent value at the observation owner. Compute it
once from canonical traffic and source boundary evidence, and route ordinary and
persistent callers through the same policy. Preserve unknowns for legacy snapshots;
use an explicit versioned checkpoint tag/migration, not a generic dataclass fallback.
Update persistent scalar snapshots, bounds/digests and final cumulative reconstruction
so a stale opening extent cannot leak into a terminal record.

Sibling tests: plaintext/encrypted/service-independent TCP with one- and two-sided
gaps, clean/gapped sensor pairs, high capture loss, partial/unknown and one-sided
boundaries, UDP/ICMP unchanged, file/HTTP loss unchanged, physical packet partitions,
persistent SMB terminal rebinding/restore and hostile or stale scalar values. Probes
must remove the completed-stream contradiction across all sensor pairs while keeping
gaps and physical capture differences. Recheck ASA repair and complete Mac census.

Evidence: Network44 independently reports412 core–DMZ,10 core–DB and47 DMZ–DB affected
conservative pairs (overlapping populations). The broader coordinator probe finds
514 core–DMZ plus56 DB–DMZ comparisons. This is a carried sibling contract defect,
not regression from the verified ASA-only repair. Zeek's official Conn::Info defines
TCP payload totals through sequence numbers and distinguishes IP/capture counters.

Risk: high because retained/persistent observations and codecs share this model.
Do not flatten the physical ledger into native stream totals or weaken source-local
file/application loss to satisfy an accounting check. HTTP fragments, multipart
relay timing and runtime populations are separate later families.

## Implemented and fresh verification

Typed frozen `TcpStreamExtent` on source observations distinguishes directional
unknowns from zero. Ordinary planning and persistent SMB terminal rebinding use the
same boundary policy. The renderer validates IP budgets against captured payload,
not sequence extent; a high-loss test permits known stream bytes above captured IP
volume without inventing packets/bytes. File/HTTP completeness retains captured
content semantics. Versioned explicit checkpoint migration preserves unknown legacy
extent; bounded SMB scalar/admission graph codecs include the typed leaf.

372 owner/protocol/checkpoint tests and133 ASA regression tests pass, as do Ruff and
behavior-surface checks at revision444. Fresh output changes only three conn files;
114 other files match44. Every non-stream conn field is unchanged, including capture
packets/IP bytes, gaps, history, timing and identifiers. There are1319 modified stream
rows. Conservative prior affected pairs412/10/47 become0/0/0 at eligibility1824/41/191;
the broader514+56 probe is alsozero. ASA and complete Mac census/timing remain clean.

Partial/missing boundaries retain conservative compatibility behavior; no full
packet-by-packet model for every partial/reset stream is claimed. The fresh panel is complete; stream contradictions were not re-reported. No analyzer content is recovered solely from sequence extent.
