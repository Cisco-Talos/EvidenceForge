# Unselected browser request-phase candidate

23NF identifies one1microsecond initial HTML/CSS gap among19multi-request pages,
observed twice by sensors. Cached knowledge/preloading/pipelining remains valid;
this is a weak signal, not a hard ordering contradiction. No engine edit while
24generation/post-processing is frozen. Baseline browser action is not in the
bounded authored GTstream; searching its native UID there returned0, not proof
that its canonical occurrence was missing. Empty diagnostic retained explicitly.

Owner inventory: BrowserSessionActionBundle._plan_http_request_groups samples
persistent gaps from a timing profile relative to group intent. Network planner
then materializes first HTTP canonical_request_time after actual transport/setup
and readiness. HttpApplicationChannelManager.prepare_reuse correctly guarantees
only strict ordering via last_activity_at+1microsecond; it does not own browser
resource discovery or claim normal HTTP cannot pipeline. Clamping that manager
to a global fixed delay would be the wrong repair. The browser owner must retain
its modeled group delays relative to actual canonical HTTP phase, including any
first transport/process readiness shift. Need preserve HTTP cache/speculation
semantics and transport byte/span/capacity contracts, not add arbitrary latency.

Existing NetworkConnectionIdentityCapture.prepared_root.result is an immutable
NetworkConnectionCommitResult carrying resolved HTTP context and file transfers.
A future browser adapter may consume that canonical result (never rendered Zeek
or access records), rebase later group requests, and retire acknowledged one-shot
proofs through their existing authority after semantic handoff. It must not retain
full prepared graphs in a new cache or bypass source publication/recovery. Frozen
network parent span/budget, independent groups, filtering, late deadlines and
replacement/reuse failure need proof. Existing generation timing/RNG and quotas
must remain; do not mutate already committed parent transports to make children fit.

Controlled private prototype runs12fresh browser bundles under seeds42–53 through
the actual network owner, without modifying source. Results pending in
before-browser-phase-probe.json; not yet a selected or implemented repair.

Qualification result: the first twelve-seed probe had one landing request per
seed and did not exercise the hypothesis. Corrected explicit three-request
private probe traversed the actual browser/network bundles:36requests,24same-UID
gaps,6one-microsecond gaps. This confirms the browser owner's requested pacing
can be lost after transport-phase displacement; it remains a weak authenticity
signal because HTTP preloading/pipelining is possible. Proper canonical phase
handoff and proof retirement need broader recovery coverage. Unselected for26;
the stronger, bounded canonical Finder phase artifact was selected instead.
