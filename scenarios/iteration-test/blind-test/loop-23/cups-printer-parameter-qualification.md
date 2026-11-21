# Unselected future candidate: printer endpoint parameters

20 Detection's weak signal is reproducible at the owning data layer:
extra_syslog_messages.yaml cups-browsed includes `Browse remote printer
{printer_name} at {}`. Baseline's generic renderer supplies the anonymous positional
argument from randint(100000,999999). Thus an endpoint-like slot receives an opaque
integer, not a random native printer identifier inferred from data. Current named
printer/queue pools already exist. This is a source-profile semantic defect, not
an invitation to increase the message pool or add arbitrary rare errors.

Shared render_extra_syslog_message already supports named params, nested named
parameter expansion and correlated parameter_profiles. Prefer adapting the source
profile to those existing owners. A named printer_endpoint/URI must correlate with
printer_name rather than choosing unrelated names/addresses per row. Preserve
operator overlays: introducing default parameter_profiles would take precedence
over a pre-existing params.printer_name pool through setdefault; consider a named
nested endpoint default and explicit override, or an explicitly designed correlated
profile contract. A bounded source_native_single_schema repair is acceptable if
labeled honestly, with whole native daemon/collector shape left unclaimed.

Primary qualification:
https://raw.githubusercontent.com/OpenPrinting/cups-browsed/2.1.1/daemon/cups-browsed.c
https://raw.githubusercontent.com/OpenPrinting/cups-filters/1.28.17/utils/cups-browsed.c

The first primary source's discovered printer structure has separate host, IP,
port, resource and URI fields. Its diagnostic queue/discovery messages use those
values. The current three generated message bodies are not corroborated verbatim
by the searched 2.1.1 source; absence of search matches alone is not proof of every
version's impossibility. Bound any native-shape claim to verified versions.
IMPORTANT: debug_printf writes stderr and/or its diagnostic file with its own
timestamp/thread prefix; it does not call syslog/LOG_DEBUG in this verified source.
Do NOT infer native syslog priority7 merely from the function's name or add a new
severity field on that unsupported assumption. Collector forwarding/normalization
requires its own qualified contract. This candidate may fix endpoint-value semantics
within the existing source-local health-message adapter without claiming a complete
native CUPS collector model. No production/source/scenario changes applied here.

Other anonymous placeholders in the same catalog are not equivalent defects:
NetworkManager supplies epoch-style time explicitly; D-Bus supplies connection IDs;
PackageKit transaction markers and run/timeout counters can legitimately be numeric.
Do not replace every positional value with a hostname or remove the generic renderer.
This remains an unselected follow-up; source557 is frozen for actual21 generation
and no22production fix has yet been applied.
