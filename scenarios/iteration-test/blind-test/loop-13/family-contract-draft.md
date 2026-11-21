# Shared physical file-analysis interval and sensor projection (draft)

Priority changed after fresh panel11: the Network analyst found same-physical-
transfer HTTP file durations differing by1.271s/0.552s across sensors despite
near-identical transport intervals and identical coverage/bytes/packets. Actual
Detection/other deliberators reproduced examples. Root confirms the specific
support-upload rows are BYTE-FOR-BYTE identical in loops10and11, so not a544DNS
regression. Treat as one contract_gap with collector/capture alternatives, not
an unconditional native impossibility. Prior automatic Mac file-task draft moved
to ../macos-mounted-task-eligibility-draft.md; it remains a lower-priority target.

Primary-source semantics verified: Zeek Files::Info documents file analysis
elapsed time; official release/9.0 main.zeek set_info initializes ts from first
last_active and updates duration from last_active minus initial ts. This is not
independent CPU wall time for each hash analyzer.
https://docs.zeek.org/en/current/scripts/base/frameworks/files/main.zeek.html
https://github.com/zeek/zeek/blob/release/9.0/scripts/base/frameworks/files/main.zeek
(implementation aroundset_info; source line values visible via official docs link).
Do not overclaim identical sensor times under loss, clock drift or different
analysis policies. Cite primary semantics near claims in final synthesis.

Root owner: FileTransferContext already carries canonical duration and optional
observation_not_before. File-transfer bundles choose shared duration once (HTTP
_http_response_file_duration). NetworkObservationPlanner._source_native_protocol_timing
then calls _sample_file_duration separately inside each sensor's TimingScope.
That helper resamples~0.55–1.55x canonical duration with sigma.42 and source-local
close slack, creating the new variation before rendering. Zeek emitter consumes
already-planned source times/durations. Fix the shared source-observation contract,
not an emitter seed keyed on one observed FUID/sample.

Candidate invariant: a physical transfer has one analysis interval; map its
elapsed time/phase through each sensor's actual clock/path/coverage model, retain
sensor-local IDs/absolute timestamps, but do not independently choose its speed.
Canonical/lifecycle bounds, HTTP-before-file, SSL/OCSP/certificate/PE ordering,
multiple-transfer rows, source/native collection gaps and zero-duration certificate
views must remain coherent. Preserve separate proxy client/origin physical legs.

Need full inventory/prototype before coding. Useful owning code:
 network_observation.py plan2460 iterates sensors; _source_native_protocol_timing
 starts3240; per-file starts3519–3595; _project_phase_time3720 applies SAME sensor
 clock + owning connection route delta; _sample_file_duration3788–3850 independently
 resamples duration. OCSP reservation~3440 currentlyuses.55*canonical duration.
 FileTransferContext contexts.py830; HTTP duration helper actions/file_transfer.py220,
 parent duration support helper208 with.75s analyzer margin. File source times
 currently sample HTTP afterSSL/request and file afterHTTP, bounded byclose; need
 reserve full projected duration BEFORE placing source start, not truncate one
 sensor's tail. Avoid changing fixed canonical values after identities/effects.

Potential bounded shared approach to investigate: reuse canonical transfer duration
(project elapsed through clock at canonical phase anchor using _project_phase_time),
reserve that duration when computing file start's admissible upper bound; graph
start/end/close. If a source interval is genuinely impossible, establish correct
pre-mutation canonical admission/legacy policy instead of inventing missingness or
silently changing file speed. Need prove parent-duration floors leave room and
handle SSL/OCSP/PE dependent reservations. Context observation_not_before is a
lower bound, not automatically an exact canonical start. Do not claim complete
physical interval modeling just by changing a scalar RNG key. A full once-planned
canonical phase span before sensor loop may be preferable; qualify before choosing.

Consumers: allHTTPresponse/request/multipart/proxy/SMB/SMTP/SSLcert/OCSPfile bundles,
network source planning, Zeek files.log timing, linkedHTTPfuids/cert/OCSP/PE views,
collectors with clock drift/loss, preview/prepared/recovery/checkpoint/evaluation.
Raw/legacy direct emitter paths need explicit inventory; compatibility helpers
network_observation.py4461+ already return transfer.duration without this sampler.

Verification: generic same-physical tuple/direction/content/size/connection pairing
across sensors, unambiguous pair guards, sensor-local IDs, exact allfile-inside-flow
and protocol ordering, clock offset/drift/wander, loss profiles and tiny windows,
multipleparts/certOCSPPE, baseline/storyline/proxy and prepared/direct parity,
RNGpolicy/config/deadline/checkpoint. No authored YAML/pack/reviewer changes.
NO13PRODUCTIONCODEuntil12generationANDevalcomplete; current545sourcefrozen.
