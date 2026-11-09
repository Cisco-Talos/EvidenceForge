# TCP source-observation semantics

[Zeek Conn::Info](https://docs.zeek.org/en/v8.0.5/scripts/base/protocols/conn/main.zeek.html)
defines TCP payload totals through sequence numbers, separately from captured
packet/IP volume and content gaps. A source can know the full sequence range
while missing interior payload and failing extraction or protocol analysis.

The model therefore stores a typed `TcpStreamExtent` beside captured traffic.
Known directional SYN/FIN boundaries retain canonical wire payload extent. Missing
boundary proof remains unknown; it does not assert zero or manufacture a complete
range. Existing partial/direct compatibility retains its conservative behavior.
Native conn rendering consumes the explicit extent, while packet-budget validation
uses captured payload. It must not inflate IP bytes to fit a sequence counter.

Persistent SMB finalization recomputes extent from final canonical traffic using
the same boundary policy. Scalar admission bounds and allowlisted graph/checkpoint
codecs include the new value. Legacy observation snapshots migrate with unknown
extent, preserving their captured counters rather than inventing missing truth.

HTTP body and file completeness still use captured content. No payload is recovered
for an analyzer merely because TCP sequence numbers establish how much was sent.
