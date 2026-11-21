# Canonical TLS detection phase and source-native share-audit shape — draft

Primary family: sibling_defect/contract_gap newly found by13Network, samecoreSSL
SHA12/13. Matching40TLSflows25>50ms/21>100ms in ssl.ts minusconn.ts across sensors;
opposite588.515/486.607ms examples have matching tuple/packet/payload/history/TLS
facts and no reported loss. Fixed clock offset cannot explain within-flow relative
phase differences. Capture/normalization alternatives remain; no unconditional
origin proof. OfficialZeekSSL.Info.ts is timeSSLfirstdetected, not log writing CPU:
https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html

Owner candidate: canonical NetworkTransactionPlanner._plan_network_protocol_evidence
already owns NetworkTransactionPlan.phase_times before frozen publication/source
planning. Add one TLS detection phase there using typed/scoped temporal sampling;
NetworkObservationPlanner projects the existing canonical phase through each
sensor's clock and transport-route offset, instead of choosing independent 3–650ms
analyzer times. No source row triggers generation. Do not put per-sensor phase draws
in emitters or hide the difference with fixed timestamps/dropped rows.

Existing phase_times includes transport_start, generic application_request (currently
start forSSL), application_response and close. A tls_detected phase can be another
bounded fact without new context/trust fields. ForSSL-only genericrequest should
refer to that same physicalfirstdetection; forHTTP+TLS detection must precede the
canonicalHTTPrequest. Preserve enclosing transport, HTTP/file/cert/x509/OCSP/PE,
source admission/visibility and negative/short/reset semantics. STARTTLS must remain
compatible with SMTP plaintext/upgrade meaning; a detection phase does not claim
full handshake completion/cryptographic packet lifecycle. Inspect bundle-owned
existing timing and avoid inventing contradictory higher-level semantics.

Possible config: optional typed tls_detection_phase under existing network_params,
with continuous bounded lognormal policy derived from old modeled support(3–650ms,
median119.46ms,sigma.78), explicitly not empirical calibration. Preserve old frozen
inlined config without new policy via documented legacy/no-phase behavior, reject
malformed present/null policy; partialoverlaymerge/schema/validate-config/reference
must agree. Actualnewdefaultcanonical scenario gets the policy. Need decide this
compatibility before coding; no new continuousRNG calls outside TimingRuntime or
resource/inventory ceiling growth. Sample only once per immutable physical root,
scoped stable request/transport; consistent across sensor/filter/replay variants.

Legacy/raw CanonicalOccurrence with no new phase can keep explicit compatibility
projection rather than silently reinterpret its facts. Main standard network bundle
must populate canonical phase, including baseline/storyline/browser/download,
proxy TLS egress and IMAPS. Distinct proxy client/egress physical legs never share
onephase. Explicit supplied canonical phase authoritative where supported. Do not
reuse each sensor's conn duration ratio asclockrate(close processing contaminates).

Gates before production: true before-failing two-sensor flatclock/exactknownphase,
clockrate/differentoffset, canonicalrootphasepresence/order/HTTPupperbound/shortflow,
TLS1.2/1.3/reset/negative/STARTTLS visibility,cert/file/OCSP/PE/c009compatibility,
source timingpreparation/detached/budgets/filter/replay/checkpoint, native strict
cross-sensor probe with matching control counters. No new configcache or runtime
trust exceptions. Engineering probes separate from unchanged fullblindpanel.

Secondary isolated source-native fallback, if qualified: modern5140 XMLshape uses
AccessMask/AccessList+Version1 perMicrosoftofficialexample; currentglobalformatYAML
Versionmapdefaults5140to0for105records. Source-format header/payload consistency is
owned there, notcanonical activity orscenario. Inspectlegacyversions/doclist(stale
proseonlymentions0)andavoidunqualifiedclaimsallhistoricalv0invalid. Smallcurrent
shapeVersion1mapping plus unchanged5145/object-access sibling/provider/fields;
meaningful nativeXMLrender+metadata test, validate-config, no unrelated versionbump.
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140

No15production code while14retry548generation/post active. This outranks rootMac
ordinary-filetaskdraft; exactMacfork anchors remain semantically risky authored
creation times, not an invitation to emitterjitter. New13qualifiedPOSIXredirection/
SCPhelper/gzipownership stays separate pending trace/normalization proof.
