# Bounded system-job activation reference

On November 2, 2026 the human supplied the fixed report from the private macOS 27
arm64 launchd kit. It reports COMPLETE/NONE, v11 shapes, no eviction/limit and
passing provenance, readiness, sequence, target authentication, exact root
lineage, zero exit, job removal, scratch-file removal and collector cleanup.
Only that shareable report was opened. A separately authorized offline reviewer
subsequently verified the same retained graph and returned fixed environment
comparisons. Raw records, observed identifiers, native values and provenance
are not copied here or committed.

## Observed process and identity relationships

The controlled experiment registers and explicitly activates one root system job.
It uses Apple's `/usr/bin/true`, a fresh test label, controlled arguments and four
explicit environment assignments. KeepAlive and RunAtLoad are false; cwd is root
and three standard paths are `/dev/null`. These controls define the experiment;
they are not claims about every job's default configuration.

The selected native sequence is:

1. The PID-1 launchd forks a child retaining launchd's image and signature.
2. That child execs `/usr/libexec/xpcproxy`, with basename argv[0] and the exact
   test job label as its second argument.
3. The same lifetime acquires its own POSIX group and session between the
   launcher exec and target exec. Its next before-image is still xpcproxy.
4. It execs `/usr/bin/true` with the exact controlled argv, preserving that new
   group/session, then exits zero.

There is one fork and two successful execs in one child lifetime. Each exec
increments the native PID version. The parent remains launchd; original and
current parent IDs agree. The child has zero real/effective UID/GID, unattributed
audit user and the same assigned nonzero audit session as launchd throughout.
This agrees with the already qualified boot audit origin; it does not identify
the raw ASID or infer an authenticated login. Responsibility is self, including
the launchd-image child; each exec's responsibility token follows its execution
token. No controlling terminal is observed. Both execs have exactly FD0–FD2 as
vnodes, last_fd 2, root cwd, no script and dyld path matching their exact target.

The report's es_client FAIL means the Boolean is false, not a malformed record.
Likewise audit_session_zero FAIL establishes a nonzero assigned origin. A target
retained_fork INCONCLUSIVE does not require a second fork: that exec follows the
already retained xpcproxy exec in the same lifetime.

## Runtime executable facts

Launchd and xpcproxy retain the already reviewed Apple platform security template,
including ENTITLEMENTS_VALIDATED. Xpcproxy's Boolean entitlements match the
independent static vendor template. Its slice is ARM64E with pointer-auth ABI.

The target signing identifier matches `com.apple.true`, team identifier is null,
cdhash has its expected hexadecimal form, and entitlements are null. Its reviewed
security flags are VALID, FORCED_LV, HARD, KILL, RESTRICT, ENFORCEMENT, RUNTIME,
NO_UNTRUSTED_HELPERS, PLATFORM_BINARY and SIGNED (`0x26011b11`), with platform
validation category. Its slice is ARM64E with pointer-auth ABI. These runtime
facts qualify that installed image policy. Synthetic hashes, UUIDs, stat values
and nominal timing remain owned by the existing deployment/filesystem policies.

The true catalog entry has no personas or automatic baseline activation. The
selected bare `/usr/bin/true` command has an explicit zero-result policy and
short nominal lifecycle. The experiment's private token is never a scenario
default or catalog argument. Other invocations retain their separate admission
and completion requirements.

## Environment and remaining boundary

The first approved offline review reports xpcproxy's sole environment entry as
`XPC_FLAGS=0x0`. The target retains the four controlled assignments, receives
`XPC_FLAGS=1` and XPC_SERVICE_NAME equal to the exact test label, and has an
additional key outside that reviewer's public allowlist. Unknown key names and
values remain hidden. They are not silently assumed absent or modeled from a
guess. A further comparison requires its own permission under the local-log rule.

The selected root job's full native activation producer is not yet admitted.
Reviewing the bounded process relationships and qualifying one binary does not
close service-binding/publication/recovery or remaining environment requirements.
No further collection is currently requested. User LaunchAgents, privilege
drops, other triggers/restart policies, arbitrary helpers and launchd Unified
Log messages were not observed and remain outside this reference.

The [private instructions](PRIVATE-RUN.md) retain experiment controls and primary
Apple sources. No reread of the original capture is authorized by this document.
