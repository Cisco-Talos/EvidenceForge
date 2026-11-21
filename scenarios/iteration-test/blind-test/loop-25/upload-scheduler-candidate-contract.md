# Unselected hypothesis: dependent transport must not wait for its owner to exit

21ThreatHunter's upload concern is qualified from logs alone: curl exits before
response/file observation, but buffering/cancellation can be real. Reproduce an
ordinary successful authored upload in a reduced diagnostic scenario before any
repair. Do not alter canonical scenario or invent client cancellation.

Owner hypothesis: StorylineMixin calls _apply_storyline_shell_availability for
every typed sibling, including network evidence belonging to the current command.
The helper combines host/remote-session readiness and foreground shell availability.
Process handler recognizes following same-host connection and avoids immediate
termination, but still publishes foreground completion/readiness. A connection
could thus be delayed until its owning curl has completed, causing attribution to
be dropped and existing canonical transport holds never to bind that actor.

Invariant: new foreground commands wait for prior foreground completion; correlated
network evidence can occur while its process is running. Preserve host/remote-session
readiness, source timing, ordinary independent commands, explicit time offsets,
existing network/process holds and authoritative session deadlines. Do not paper
over this by independently extending one emitted process timestamp or adding a
second cache. New connection timing must come from the canonical action scheduler.

Inventory: normal storyline, interleaved storyline and red-herring typed-child
loops all call the same helper. Connection/beacon/DNS are evidence-producing
network actions, not automatically new foreground command invocations. Qualify
which tags consume foreground readiness, leaving host readiness in place and
preserving legacy direct helper defaults. Existing canonical network process and
multipart holds already exist; first identify why they were absent rather than
blindly adding duplicate holds. Cross-platform non-sample and visible native
request/response/process interval tests are required before selection.

Reduced diagnostic qualification: actual private engine generation succeeded;
analysis initially searched root/data while this direct API fixture writes at
root, giving No support curl create. Re-parsed the existing output without rerun:
curl begins1728900135.997, closes1728900171.260; client HTTP starts147.901227,
transport147.796841→167.098018; origin147.974203, transport147.956553→167.098018.
Curl thus survives both full reduced transfers by4.16s. This does NOT reproduce
the canonical reviewer example. Preserve the hypothesis as unselected and inspect
exact authored/automatic companion duplication and holds before changing helper
scheduling. No claim of a confirmed shell-gating root cause or implemented fix.
