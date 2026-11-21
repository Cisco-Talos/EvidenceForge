# Candidate contract — Windows process creator and new-process token

Selected next candidate from23TH/DE and actual deliberation, ahead of the wider
unselected Defender installation work. No engine changes while24revision562
canonical generation/post-processing are active. ParentUser differing from User
is a screening observation, not proof of the requesting thread token. All992
native4688targets are empty;49joined parent/child account differences plus a
same-account/different-LUID runas boundary merit owner inspection.

Primary source: Microsoft4688v2 separates Creator Subject from Target Subject
when the creator and new process have different logons:
https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688
Do not manufacture impersonation or infer it solely from parent account names.
The generated process action already declares an immutable parent actor and
child subject in EventIdentityPlan. This modeled ordinary creation path has no
separate impersonated requesting-thread token intent. A repair may project that
explicit canonical actor into AuthContext.subject_* and the child token into
existing ProcessTargetSecurityContext when SID/logon differ. Preserve primary
AuthContext/ProcessContext child principal and LUID for Sysmon/eCAR/4689. A future
impersonated creation must supply its actual requesting context explicitly; this
bounded repair is not proof that every real parent account equals creator token.

Owner: one stateless canonical Windows process-creation security policy, called by
process action builders before source preparation/sealing. Invariant: known
ordinary requesting actor and child token remain distinct, including same SID
with a new logon. Same-context launches keep null TargetSubject. Unknown creator
contexts retain legacy unknown behavior; no invented SID/LUID. Existing raw or
explicit source-native target contexts outside the modeled planner stay intact.
Windows emitter renders these already-resolved facts with legacy fallback only;
it must not query State, derive a parent token or independently invent identity.

Entry inventory: ProcessExecutionService._prepare_evidence (baseline/storyline/
RDP/newcredentials/shared user process); ProcessSystemProcesses system creates;
ProcessParents parent-chain materialization; ActivityGenerator existing Windows
session bootstrap create (userinit); persistent SMB client process creates.
Linux-only network responder and Mac-only persistence builders do not acquire
Windows semantics. Use exact plan parent identities where available; any
compatibility builder reads its canonical State actor once before source prep.

Consumers: native Security4688v2 Creator/TargetSubject, Security4689 child token,
Sysmon User/ParentUser/LogonId and eCAR process identity, canonical GT projections,
prepared fingerprints, lifecycle/identity validation, checkpoint/source retry.
Do not change PID/parent/child/session ownership, clock offsets, frozen authored
phases, eval rules, source missingness, quotas, retention, RNG or State fields.

Sibling proof: SYSTEM→human userinit, ordinary same-context GUI launch, same-user
new-LUID runas, SYSTEM→LOCAL SERVICE system child, implicit parent-chain and SMB
entry paths, unknown/raw compatibility, native XML rendering and unchanged
Sysmon/eCAR child identity. Exact prepared publication/retry and source filtering
must remain consistent. If the existing strict context/identity validator cannot
represent separate creator facts without moving child identity, downscope or
defer rather than rewriting identities in the emitter. Inventory all production
builders before selecting any implementation. No code is applied by this note.

Planned adapter detail: use existing AuthContext.subject_* and optional target
context before any source preparation. Keep primary auth/process child facts and
identity-plan actor/subject unchanged. SID resolution remains the existing injected
identity owner; the policy introduces no identifier allocator. Known ordinary
actor+child SID/LUID facts produce the two token views; unknown/null SID or missing
LUID remains legacy unknown, and an already explicit target context is preserved.
Native source adapter only renders resolved subject facts with legacy fallback.
Local-SAM account-alias/authority expansion is not claimed by this bounded repair.
Before controls against frozen562:3FAIL1PASS across SYSTEM→LOCAL SERVICE, existing
bootstrap create and real typed new-credentials controller;16deselected. Native23
census9924688/0targets/990uniqueSysmonmatches/49differentparent-childaccounts and
0effective-childLUIDmismatches. This is a screening census, not49proven errors.
