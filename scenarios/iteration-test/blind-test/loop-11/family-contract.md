# Attack-independent DNS activity ownership (draft)

Finding: earlier Network reviews noted ordinary TXT on many hosts only near the
DNS tunnel. Rendered timing is a weak clue with scheduled-task alternatives, but
root inspection proves the tunnel handler itself injects 12–36 benign TXT requests
from unrelated environment hosts in its attack window. It also includes a named
organization in a Python domain pool. Classify the implementation issue as a
shared ownership gap, not an impossible observed DNS record.

Owner/invariant: typed dns_tunnel action owns its explicit source/campaign and
required transport/DNS/IDS companions. It must not create unrelated client activity
as camouflage. Genuine baseline DNS, email/workload lookup intent and explicitly
authored traffic retain ownership of benign observations across the full window.
Do not replace a late burst with another ungrounded fleet-wide TXT timer.

Entry inventory: typed dns_tunnel handler; legacy storyline delegates here.
Generic DNS lookup bundle and baseline system DNS paths are separate consumers
and should remain intact. Existing benign TXT answer helpers remain available for
real request intent; deleting stale private shims is optional, not this invariant.
Consumers: Zeek DNS/conn, endpoint query observations, firewall/IDS, TTL/cache state,
source-native query identity and ground-truth tunnel byte/count accounting.

Verification proposed: tunnel-only harness with multiple unrelated hosts emits
only authored source traffic; changing unrelated host count does not create extra
flows or alter campaign payload/tick counts. Verify single/multi-sensor paths,
start/end fences, encoded payload accounting, explicit attached IDS and ordinary
baseline TXT/answer semantics. No scenario/reviewer changes. New routine tests
must check semantic source ownership rather than assert a particular answer pool.

Production entry-path verification: engine/storyline.py._execute_typed_event
constructs TypedEventContext and delegates typed dns_tunnel to
engine/typed_handlers/periodic.py.handle_dns_tunnel. That single handler owns the
unrelated-host publication block. Baseline DNS and explicit dns_query handlers
are separate. Existing _dns_tunnel_background_txt_record compatibility alias and
shared answer builder remain for existing callers/tests; removing an unused
private shim is not required to enforce intent ownership. Payload, pacing, IDS
attachment, collection fences and query accounting remain in the same handler.

Before-repair tests: all3 TXT/CNAME/NULL peer-independence checks failed on actual
behavior543. Production change removes the entire unrelated-host activity block,
not just a domain/host-specific sample. Rest of campaign RNG can change because
camouflage no longer consumes it; scenario hashes and explicit campaign parameters
are unchanged. Full replay and peer-count independence are required after repair.
