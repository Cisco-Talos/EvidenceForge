# Loop47 contract: HTTP wire URI and referrer semantics

Selected carried sibling defect:13 literal fragments in proxy request URLs remain in46. Detection42 found the class; coordinator probes reproduce it across subsequent outputs. This target was selected from verified carried evidence while46's independent panel ran, without awaiting or supplying its scores.

Owner: shared canonical HTTP wire semantics consumed by frozen HttpContext and ProxyContext at construction. Invariant: request-targets and transmitted Referer values never carry a literal client-side fragment; Referer also omits userinfo. Preserve encoded%23, query ordering and empty delimiters, absolute/origin/authority/asterisk forms, client navigation intent in authored/browser request and command objects, and response Location values where fragments are legal. Do not mutate client commands or response redirects.

Entry paths: baseline generated HTTP/proxy metadata, typed storyline HTTP, browser sessions, proxy client/upstream phases, process-command-derived HTTP and direct context consumers. All create canonical HttpContext/ProxyContext; dataclass replace also validates through construction. Raw already-native records are intentionally outside canonical normalization. No context fields or codec schemas change. StateManager standalone value codec does not accept HttpContext/ProxyContext; no new checkpoint support is claimed.

Consumers: Zeek HTTP, proxy access, web logs, transaction planning, request/file identity and byte sizing. Normalize before shared fan-out so sibling sources agree by construction; a source-specific string strip would leave contradictory canonical truth. Shared helper belongs to the event semantic layer without generation dependencies. Classification family_level with two context adapters. No sample-specific hostname/URI branch.

Risks: fragment stripping must not decode%23, alter query or CONNECT authority, drop legal Location fragments, or remove the original navigation request held by higher-level intent. Referrer userinfo removal must preserve host/port/IPv6 spelling. Invalid absolute referrers should not invent a wire header. Tests cover both contexts, replace siblings, escaped/query/IPv6/CONNECT/OPTIONS and intact source intent. Actual transaction identity/counter changes, if any, will be reported rather than assumed absent.

Primary source: RFC9110 §§7.1 and10.1.3. Target URI excludes the fragment component; Referer must omit fragments and userinfo. Response Location is a URI-reference with different fragment semantics (§10.2.2).
