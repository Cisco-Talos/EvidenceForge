# Candidate contract — installed OS file chronology and canonical host boot

Selected candidate from actual25 Detection Engineer and actual peer rechecks.
MAC-MROSS-02 PID1 start2026-10-06 precedes the provisioned launchd file birth
2026-10-29. Metadata restoration/alteration can explain a real stat birthtime;
the engine's own model, however, currently independently samples an immutable
installed-object age without consuming known canonical boot facts. This is a
qualified contract gap, not proof that POSIX birthtime is an immutable clock.

Owner: shared installed-file provisioning, with canonical boot facts supplied by
the engine boot owner. Add optional typed, data-driven preboot product IDs to the
existing installed-file profile; enable the modeled OS product apple-macos.
Preserve legacy profiles without the selector and direct callers with unknown
boot facts; do not invent boot history from a filename. Machine installations
of selected products with a known boot must predate that boot. Third-party and
user installs remain eligible for later pre-window installation.

Plan: move the existing kernel-boot-uptime preparation earlier in engine
initialization, before its first lazy metadata compilation, without changing the
host seed policy or adding state. Pass those already-owned host boot facts into
compile_macos_installed_provisioning. At its existing installation-age sampler,
condition the lower age bound on the latest permissible preboot installation;
retain the configured upper age bound and release availability floor. Reject an
incompatible finite age support or release date rather than clamp all files to
boot, shift process start, fabricate history or inflate support/retention. Keep
release build timestamps shared by content and existing size/hash/identity truth.

No emitter patch, new cache/state owner, extra raw RNG site, source clock jitter,
scenario edits or broad OS update/restore simulation. Existing canonical host
uptimes remain the source of truth; do not independently rederive the boot seed
inside the file producer. All native stat consumers must see one same provisioned
object (fork actor, exec target, loaded image, normalized owner, source retry).
Directory birth histories and empirical executable sizes are separate limits.

Validation before implementation: bounded native census of installation birth
versus process start; selected preboot product owner test and unchanged third-party
sibling; legacy profile/unknown boot, incompatible support/release, deterministic
cross-host/checkpoint behavior; public engine initialization proof and native ES
same-object consumers; loader/config validation plus existing Mac installed-file,
metadata, boot, source preparation, RNG census, manifest and Ruff. Source564
currently frozen during26gen/post; candidate not implemented. Confirm earliest
boot-fact ordering before editing to avoid freezing an unknown snapshot too soon.

Scope clarification: existing release-availability timestamp floors remain a
separate inherited policy. The new preboot check rejects a selected OS release
that cannot exist by known boot; it does not redesign future-release installation
or empirically calibrate build timestamps. The unrelated equal-four-stat-times
floor effect is deferred rather than silently broadening this repair. The
existing installation-age randint site is reused with a conditional lower bound;
no new raw sampling call or support expansion is introduced.
