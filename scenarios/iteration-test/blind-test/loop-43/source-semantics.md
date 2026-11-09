# Carried source-contract findings on the fresh run

Coordinator probes were not disclosed to the blind panel.

Zeek TCP orig_bytes/resp_bytes represent sequence-derived payload extent, separately
from captured packet/IP counters and missed_bytes. Joining unique completed TCP
five-tuples with visible SYN/SYN-ACK and both FINs within one second yields 514
core–DMZ plus 56 DB–DMZ pairs whose stream-total differences equal relative capture
gaps. This reproduces the deferred stream/capture projection issue; independent
partial packet captures need not be nested or identical.
Primary definition verified November 5, 2026:
https://docs.zeek.org/en/v8.0.5/scripts/base/protocols/conn/main.zeek.html

RFC9110§7.1 excludes client-side fragments from HTTP target URIs. Thirteen quoted
proxy request lines contain literal fragments in their targets. Browser enrichment
could explain a separately labeled navigation field, but these are request lines.
Exact records and line references are in residual-contract-probes.json.
Primary definition verified November 5, 2026:
https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1

No post-generation repair was made. These are carried issues, not new Mac-timing
regressions. Coordinator findings remain separate from independent panel evidence.
