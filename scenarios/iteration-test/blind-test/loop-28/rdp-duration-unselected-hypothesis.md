# Unselected RDP duration hypothesis

Actual24 TH found three nearly equal887.866s transports on one reconnecting pair.
Canonical GT qualification confirms three corresponding network occurrences;
source offsets alone do not explain the shared interval. This is not proof of a
bad timer: exact RDP reconnection deliberately caps a new transport by the same
logical session idle_timeout. The bundle also caps against hard deadlines and
network ownership may impose further session limits. A proposed truncated
transport distribution at execute() is not selected: the actual source of this
specific repeated interval has not yet been proved, and a legitimate shared idle
timer must not be jittered. No RDP code or scenario change is applied.

To advance, capture the actual request, selected duration, logical idle policy,
canonical committed interval and any source-session clamp from one bounded public
RDP generation. Then distinguish an unintended clamp atom from an explicit
policy timer before choosing its owning family. The retained GT JSON is bounded
to the three cited rows; it contains expectation metadata, not reviewer input.
