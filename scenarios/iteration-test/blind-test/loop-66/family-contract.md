# Browser application identity before proxy freeze

Classification: sibling_defect / family_level. Owner: canonical application identity
and proxy request construction, before affinity, header byte budgets and phase plans.

Invariant: a known browser process, including supported Mac helper executables,
supplies its stable family/release-derived default header before an inferred proxy
request is frozen. Proxy and HTTP views retain that one header, and byte accounting
includes its actual length. Explicit finalized proxy headers, tool requests, known
absent headers and raw custom requests preserve their authority. Domain defaults
must not silently replace a selected process identity after ownership is known.

Entry paths: direct browser sessions, browser-owned opaque CONNECT without prebuilt
HTTP context, Windows/Linux browser parents and Mac native networking helpers.
Consumers: client/origin HTTP, proxy rows, request budgets and channel affinity.
Inventory helper aliases centrally in YAML with validation; do not key repairs on
reviewed hostnames or tuples. Sibling tests include helper/main/other browsers,
unknown processes, explicit override and default context paths.

This scope does not presume every browser-looking header on a nonbrowser app is
impossible. Zoom's mixed destination/application binding remains a separately
qualified planner lead unless actual application intent can be resolved without
inventing a vendor header or unqualified native process family.
