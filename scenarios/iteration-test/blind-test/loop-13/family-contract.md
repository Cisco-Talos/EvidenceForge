# Canonical file elapsed time through sensor clocks and bounded phases

Classification family_level. New panel11 contract_gap confirmed in unchanged
loop10support-upload rows. Strict root probe has20unambiguousHTTPpairs,16same-
packet/payload/statezero-reported-losscontrols;4controlsdiffer>100ms,max1.271054s
whileconnection-duration differences≤.924ms. Reviewer266broaderpairs are a
separate population. Distinct proxy client/origin tuples are never paired.

Owner: FileTransferContext.duration already owns one canonical elapsed analysis
value from the file-transfer/SMB owners. NetworkObservationPlanner owns its sensor
clock projection and admissible source phase interval. It currently invents a
new speed by sampling duration independently inside each sensor scope. Change
this shared observation owner; renderers continue consuming frozen source times.

Invariant: preserve canonical elapsed through the actual sensor clock, without
independent source duration noise. Place source file start only where the full
projected elapsed fits, express start/end/fixed transport close in a constraint
graph, and preserve source HTTP/SSL/OCSP/PE/multipart ordering. Source-specific
absolute phase preferences/IDs remain source-local; this does not claim a new
complete packet-level physical first-byte model. Event timestamp and existing
not-before facts supply the known canonical phase anchor for clock measurement;
not-before remains a lower bound rather than an exact start declaration.

Implementation selected after prototype: project canonical anchor/end via the
existing sensor clock API; reserve maximum linked elapsed before choosing HTTP
source time, reserve each file's full elapsed in its latest-start bound, and graph
start/end/owning close. Do not backdate an exact canonical HTTP request to conceal
an impossible interval. Clip only existing preferred analyzer stage slack to its
admissible window; do not change the shared file speed. Zero-duration certificate
views keep their existing behavior. Existing intentional direct-emitter c009
micro-window compatibility stays separate and unchanged. No new random selector,
resource/trust ceiling, source schema, or authored/pack/reviewer changes.

Primary semantics: Zeek's own set_info initializes first-seen time from last_active
and updates elapsed from last_active minus initial ts. It is not independently
sampled CPU time for each analyzer. Capture/clock/collector differences remain
valid alternatives when judging real logs; no unconditional origin proof.
https://github.com/zeek/zeek/blob/release/9.0/scripts/base/frameworks/files/main.zeek
https://docs.zeek.org/en/current/scripts/base/frameworks/files/main.zeek.html

Entry inventory: HTTP request/response, multipart, browser/process/storyline,
proxy client/egress legs, SMB file operations/host file sets, SMTP attachments,
SSL certificates and OCSP/PE companions all arrive through canonical contexts
and the shared NetworkObservationPlanner. Legacy direct emitter compatibility
uses separate _compatibility_legacy_transfer_observation and retains its raw
bounds contract. Consumers: NetworkSensorObservation frozen time/duration maps,
Zeek files/HTTP/SSL/x509/OCSP/PE, collection-window admission, prepared source
receipts/recovery/checkpoint and deterministic evaluation. No rendered artifact
triggers new generation.

Before tests:5new valid central invariants fail on545 (two sensors/twoelapsed
values,±2000ppm clocks,short valid parent requiring full-span reservation).
Clock+reservation+graph prototype passes99/100(5new+95existing),sole failure old
test demanding downstream stochastic variation on fixed canonical.2sinputs.
Replace that invalid-owner expectation; five invariants retain source fidelity.
The simpler scalar prototype was only feasibility, not accepted production design.

Risks/gates: source clock planning budget/detached bindings, source hard windows,
canonical request near-close, observation lower bounds, multiple file ordering,
SSL/OCSP/PE and zero durations, different physical proxy legs, loss profiles,
prepared/direct parity, legacy byte compatibility and checkpoint/fresh-process
replay. Full canonical source span must fit; investigate actual admission failures
at the upstream owner rather than reintroducing a source-local speed clamp.
No final repair claim until actual new-generation data-only paired probe and
blind assessment finish. Remaining Mac fork phase anchors and binary-document
workload choice are separate; do not alter frozen scenario timing for this fix.
