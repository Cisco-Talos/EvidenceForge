# Shared HTTP capture accounting

Classification: sibling_defect / family_level. Owner: canonical HTTP channel
reservations and source-observation planner, before source rendering.

Invariant: requests sharing a physical transport use that transport's immutable
traffic, history and capture identity. File gaps consume disjoint directional byte
spans within the one physical loss budget. Recognized gaps retain HTTP message-body
length, as qualified by Zeek v8.0.5 HTTP_Entity::Undelivered; files distinguish seen
and missing bytes and suppress complete-content analyzers when incomplete.

Entry paths: first direct HTTP/HTTPS request, persistent HTTP application children,
explicit-proxy children, request uploads and multipart leaves. Channel reservations
own byte offsets; children carry a frozen physical-capture basis. Observation owns
capture-loss projection; renderers only consume those frozen facts. Canonical bytes,
timing, source policy, scenario and seed remain unchanged.

Sibling risks: opposite-direction loss, several entities sharing one connection,
multipart wire/decoded lengths, certificate files, raw incomplete transfers, retained
checkpoint objects and replay. Tests must cover repeated children, upload and response
directions, no-loss and incomplete canonical files. The byte-span allocation is a
conservative aggregate capture model, not a packet trace or compressed-body decoder.
Do not claim arbitrary missing file bytes must always equal TCP gaps; qualify only
the supported recognized transport-loss family.
