# Cisco IOS platform classification

The user reported a newly authored scenario rejecting Cisco IOS XE appliances as
unsupported macOS targets. The shared `platform_for_os` classifier searched for
`os x` anywhere in an OS label, matching both Cisco IOS XE and IOS XR. Its result
feeds validation, generation, source/deployment planning and evaluation.

Seven new regressions reproduced the failure before the fix: four platform/
deployment classification cases and three appliance-in-scenario validation cases.
Legacy OS X recognition now requires word boundaries. `Mac OS X` remains covered
by the existing `mac os` marker; standalone `OS X` is still recognized so it gets
the correct unsupported-Mac-target finding rather than bypassing that guard as
an unknown platform. Network appliance labels retain unknown-platform semantics;
this does not introduce a native IOS platform or renderer.

The correction is in the shared classifier, with no validator/emitter exception
and no user-scenario edits. Generation behavior revision 499 records the localized
classification/source-deployment change and updates the surface digest. Product
version and earlier uncommitted Studio acceptance changes are preserved.

Validation: 204 tests pass across Mac foundations, target admission, generation
behavior, evaluation cross-source mapping and evidence reachability. The original
seven regressions pass alongside legacy aliases, unsupported-target rejection and
Windows/Linux classification controls. Repository Ruff lint/format and whitespace
checks pass. Restart the source-launched Studio helper before repeating validation.
