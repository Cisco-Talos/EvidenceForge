# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Adversarial-payload event CODE layer: synthesis, safety, per-surface encoding.

The COUNTERPART to ``generation/spillage.py``. Where spillage emits a provably-fake
*credential* and its safety contract FORBIDS control bytes (its docstring notes
that log-injection "is the separate ``adversarial_payload`` work"), this module
OWNS controlled injection of a log-pipeline weakness primitive (ANSI escape, CRLF
log-forging, CSV formula, JNDI/Log4Shell lookup, reflected-XSS markup) so defenders
can test that their parsers / SIEMs / shippers / terminals / CSV exports handle
untrusted log content safely.

The two reusable safety invariants are kept verbatim from spillage:
  * every rendered payload must carry a poison marker (``EFORGE_TEST`` by default),
    on EVERY physical line, so a CRLF split can never orphan an unmarked line; and
  * any host embedded in a payload must be the canary (``canary.eforge.invalid``,
    RFC 6761 reserved / non-resolving) or an RFC 2606/6761/5737/3849/1918 address —
    enforced by reusing spillage's hardened ``_extract_hosts`` / ``_host_allowed``.

What is INVERTED is the control-byte policy: instead of a blanket ban, a per-surface
encoder emits the weakness byte RAW only where the surface is the realistic
observation point (``syslog_message``), and escapes/percent-encodes it elsewhere so
it preserves the detection SIGNAL without corrupting an unrelated record.
"""

from __future__ import annotations

import random
import re
import shlex
import string
import urllib.parse
from dataclasses import dataclass, field

from evidenceforge.config.payload_families import (
    allowlisted_domains,
    canary_host,
    default_marker,
    get_family,
    payload_markers,
)
from evidenceforge.generation.spillage import (
    _escape_controls,
    _extract_hosts,
    _host_allowed,
    _quote_windows,
)
from evidenceforge.utils.rng import _stable_seed

# Implemented semantic surfaces. Keep in sync with AdversarialPayloadEventSpec.surface.
VALID_SURFACES: tuple[str, ...] = (
    "http_user_agent",
    "http_request_url",
    "http_referrer",
    "syslog_message",
    "process_command_line",
)

# Web-request surfaces: the payload rides in an outbound HTTP/S request field and is
# recorded by the destination web server's access log. Cross-OS; require a
# web_server-role host in the environment (the generator/validator enforce this).
HTTP_SURFACES: frozenset[str] = frozenset({"http_user_agent", "http_request_url", "http_referrer"})

# Surfaces that only model on Linux hosts. process_command_line and the http_*
# surfaces are cross-OS.
LINUX_ONLY_SURFACES: frozenset[str] = frozenset({"syslog_message"})

# Single source of truth: surface -> the output format that records it (also its
# ground-truth expected_sources). Validation and the eval matcher consume this map.
SURFACE_FORMATS: dict[str, str] = {
    "http_user_agent": "web_access",
    "http_request_url": "web_access",
    "http_referrer": "web_access",
    "syslog_message": "syslog",
    "process_command_line": "ecar",
}

# Benign surrounding-field carriers (the realistic context the payload rides in).
# Each must contain the {value} placeholder; a family MAY override per surface.
# process_command_line carriers are LOCAL commands only (env/printenv/echo) — a
# command line is a live in-window EDR record, so it must not imply a side-effect
# the engine never produces (e.g. `logger`, which would write the payload to syslog).
# {value} sits in an UNQUOTED slot so the surface shell-quoting is the sole quoter.
_GENERIC_CARRIERS: dict[str, tuple[str, ...]] = {
    "http_user_agent": ("{value}",),  # the User-Agent header IS the payload
    "http_request_url": ("/search?q={value}", "/api/v1/items?filter={value}"),
    "http_referrer": ("https://{host}/login?next={value}",),
    "syslog_message": (
        "nginx: rejected request field: {value}",
        "webapp: invalid user input: {value}",
    ),
    "process_command_line": (
        "/usr/bin/env LOG_FIELD={value} printenv LOG_FIELD",
        "/usr/bin/env USER_INPUT={value} true",
    ),
}

# Windows-native fallback so a Windows actor never renders a Linux command line for
# process_command_line. Local commands only (no implied side-effect); a family MAY
# override with a `process_command_line_windows` carrier list. The binary is the FULL
# System32 path (not a bare ``cmd.exe``) so the rendered process image matches real
# Sysmon/eCAR telemetry (which always carries the full path) and baseline cmd.exe —
# a bare image would make the adversarial record trivially filterable.
_GENERIC_CARRIERS_WINDOWS: dict[str, tuple[str, ...]] = {
    "process_command_line": (
        r"C:\Windows\System32\cmd.exe /c set LOG_FIELD={value}",
        r"C:\Windows\System32\cmd.exe /c echo {value}",
    ),
}

_TOKEN_RE = re.compile(r"\{(\w+)(?::(\d+))?\}")
_CONTROL_TOKENS = {"esc": "\x1b", "cr": "\r", "lf": "\n", "tab": "\t"}

# Safe set for the http_user_agent surface: keep every printable char (so ${jndi:…},
# <script>…, spaces stay literal in the UA) but percent-encode control bytes, '"' and
# '\'. The web emitter wraps the UA in a combined-log field and applies its OWN
# control/backslash/quote escaping; percent-encoding exactly those three makes that
# emitter transform a no-op, so the recorded rendered_value equals the on-disk bytes.
_UA_SAFE = "".join(c for c in string.printable if c not in '"\\\t\n\r\x0b\x0c')


class AdversarialPayloadSafetyError(ValueError):
    """Raised when an adversarial payload fails a safety guardrail.

    Subclasses ValueError so existing scenario-validation paths catch it.
    """


@dataclass
class SurfaceRender:
    """What generate_adversarial_payload should emit for a resolved payload."""

    surface: str
    encoded_value: str  # the canonical payload with surface encoding applied
    expected_sources: tuple[str, ...]
    command: str | None = None  # process_command_line (the line)
    process_name: str | None = None  # process_command_line (the binary)
    syslog_app: str | None = None  # syslog_message
    syslog_message: str | None = None  # syslog_message
    http_method: str | None = None  # http_* surfaces
    http_uri: str | None = None  # http_* (request path+query)
    http_referrer: str | None = None  # http_referrer (Referer header URL)
    user_agent: str | None = None  # http_user_agent (User-Agent header)
    tags: list[str] = field(default_factory=list)


def expected_sources_for_surface(surface: str) -> tuple[str, ...]:
    """Return the log source(s) a surface is expected to produce."""
    fmt = SURFACE_FORMATS.get(surface)
    return (fmt,) if fmt else ()


# --- Safety guardrails ---------------------------------------------------------


def check_payload_safety(
    value: str, family: str | None = None, *, oob_hosts: tuple[str, ...] = ()
) -> None:
    """Validate an adversarial payload against the safety guardrails. Raises on failure.

    Unlike spillage, control bytes are PERMITTED (they are the modeled weakness) —
    the encoder decides per surface whether they land raw. The invariants enforced
    here are: a poison marker on EVERY physical line (so a CRLF split cannot orphan
    an unmarked line), only allowlisted/canary hosts, and a known family.

    ``oob_hosts`` is an explicit live-callback opt-in (e.g. a Burp Collaborator /
    interactsh / sinkhole domain the operator registered at generation time). When
    set, those host(s) are additionally accepted so a real out-of-band test can fire;
    every OTHER non-reserved host is still rejected, and the marker is still required.
    """
    if not value:
        raise AdversarialPayloadSafetyError("adversarial payload must be non-empty")

    markers = payload_markers()
    # A marker must appear on every physical line: a CRLF-forging payload splits the
    # record, and each resulting line must be self-evidently synthetic test content.
    # NUL is also treated as a boundary so a NUL-delimiting downstream consumer cannot
    # see an unmarked trailing segment that str.splitlines() alone would miss.
    for line in value.replace("\x00", "\n").splitlines() or [value]:
        if line.strip() and not any(m in line for m in markers):
            raise AdversarialPayloadSafetyError(
                f"every line of an adversarial payload must contain a poison marker "
                f"(one of {markers}); line {line!r} has none — a forged/split line must "
                "stay clearly synthetic"
            )

    # Hosts compare case-insensitively (_extract_hosts lowercases), so lowercase the
    # registered OOB hosts too — a caller (or an uppercase --oob-host) must not fail the
    # allowlist match on case alone.
    domains = [*allowlisted_domains(), *(h.lower() for h in oob_hosts)]
    for host in _extract_hosts(value):
        if not _host_allowed(host, domains):
            raise AdversarialPayloadSafetyError(
                f"adversarial payload embeds non-allowlisted host {host!r}; use the canary "
                f"({canary_host()}) or an RFC 2606/6761 reserved domain / RFC 5737/3849/1918 "
                "address (or register it as an --oob-host live callback)"
            )

    if family is not None and get_family(family) is None:
        raise AdversarialPayloadSafetyError(f"unknown adversarial payload family: {family!r}")


# --- Synthesis -----------------------------------------------------------------


def _expand_template(
    template: str, rng: random.Random, *, keep_value: bool = False, oob_host: str | None = None
) -> str:
    """Expand template tokens deterministically using ``rng``.

    Tokens: {marker} {canary} {esc} {cr} {lf} {tab} {alnum:N} {host}. With
    ``keep_value`` the literal {value} placeholder is preserved for later carrier
    substitution. When ``oob_host`` is set (a registered live-callback host) the
    {canary} token resolves to it instead of the inert canary, so the payload calls
    back to the operator's out-of-band server.
    """

    def _repl(match: re.Match) -> str:
        name = match.group(1)
        count = int(match.group(2)) if match.group(2) else 0
        if name == "value" and keep_value:
            return match.group(0)
        if name == "marker":
            return default_marker()
        if name == "canary":
            return oob_host or canary_host()
        if name in _CONTROL_TOKENS:
            return _CONTROL_TOKENS[name]
        if name == "alnum":
            return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(count))
        if name == "host":
            # Use only multi-label reserved domains (example.com/.org/.net/.test) for a
            # cosmetic host; a single-label pseudo-TLD like `invalid`/`local` is reserved
            # for the canary, not for a plausible-looking carrier host.
            domains = [d for d in (allowlisted_domains() or ["example.com"]) if "." in d]
            domains = domains or ["example.com"]
            label = rng.choice(("portal", "app", "cdn", "intranet", "files"))
            return f"{label}.{rng.choice(domains)}"
        return match.group(0)

    return _TOKEN_RE.sub(_repl, template)


def synthesize_value(family_name: str, seed_key: str, *, oob_host: str | None = None) -> str:
    """Synthesize one payload for a family, deterministically by seed.

    A family declares exactly one of: ``value_template`` (one form), ``value_templates``
    (a variant list — one is chosen per event by seed so a dataset spans the canonical
    form and its evasion variants), or ``examples`` (literal values, not token-expanded).
    """
    fam = get_family(family_name)
    if fam is None:
        raise AdversarialPayloadSafetyError(f"unknown adversarial payload family: {family_name!r}")
    rng = random.Random(_stable_seed(f"{seed_key}:value:{family_name}"))
    template = fam.get("value_template")
    if template:
        return _expand_template(template, rng, oob_host=oob_host)
    templates = fam.get("value_templates") or []
    if templates:
        return _expand_template(rng.choice(sorted(templates)), rng, oob_host=oob_host)
    examples = fam.get("examples") or []
    if examples:
        return rng.choice(sorted(examples))
    raise AdversarialPayloadSafetyError(
        f"adversarial payload family {family_name!r} has no value_template/value_templates/examples"
    )


def expand_family_variants(family_name: str, seed_key: str) -> list[str]:
    """Return one expanded value per declared variant (every value_templates entry, or
    every example, or the single value_template) — so validate-config can safety-check
    ALL variants, not just the one a single synthesis happened to sample."""
    fam = get_family(family_name) or {}
    if fam.get("value_template"):
        return [_expand_template(fam["value_template"], random.Random(_stable_seed(seed_key)))]
    templates = fam.get("value_templates") or []
    if templates:
        return [
            _expand_template(t, random.Random(_stable_seed(f"{seed_key}:{i}")))
            for i, t in enumerate(templates)
        ]
    return list(fam.get("examples") or [])


def ids_signature_for_payload(family_name: str | None, value: str) -> int | None:
    """Return the on-wire Snort/Suricata SID a sensor should fire for THIS rendered
    payload, or None if it should NOT alert.

    A family maps a flat ET signature via ``ids_sid``, but the alert fires only when the
    (URL/UA-normalized) payload STILL contains the signature's content token
    (``ids_fires_on``). An evasion variant that splits the token — Log4Shell
    ``${lower:j}ndi`` / ``${::-j}``, SQLi ``UNION/**/SELECT``, a CR-only forge — therefore
    produces NO alert, faithfully modeling a flat-content rule's blind spot (a real
    sensor would miss it). Matching the canonical value models a sensor that URL/UA-
    decodes before content-matching; the obfuscation still evades after decoding, which
    is the detection-gap the dataset is meant to exercise. A literal ``value:`` (no
    family) never auto-fires — we cannot know which signature it would trip.
    """
    if not family_name:
        return None
    fam = get_family(family_name) or {}
    sid = fam.get("ids_sid")
    if not sid:
        return None
    token = fam.get("ids_fires_on")
    if token and token.lower() not in value.lower():
        return None
    return int(sid)


def resolve_value(
    family: str | None, value: str | None, *, seed_key: str, oob_hosts: tuple[str, ...] = ()
) -> tuple[str, str]:
    """Return (canonical_value, resolved_family) after safety-checking.

    Exactly one of ``family`` / ``value`` must be supplied (the model enforces this
    too); a literal ``value`` is safety-checked as-is, a family value is synthesized.
    ``oob_hosts`` registers operator-controlled live-callback host(s): a family's
    {canary} resolves to the first, and all are accepted by the safety host check (so
    a fuzzer's own ``value:`` payload pointing at the operator's Collaborator passes).
    """
    if value is not None and family is not None:
        raise AdversarialPayloadSafetyError(
            "adversarial payload requires exactly one of 'family' or 'value'"
        )
    if value is not None:
        check_payload_safety(value, family=None, oob_hosts=oob_hosts)
        return value, ""
    if family is not None:
        synthesized = synthesize_value(
            family, seed_key, oob_host=oob_hosts[0] if oob_hosts else None
        )
        check_payload_safety(synthesized, family=family, oob_hosts=oob_hosts)
        return synthesized, family
    raise AdversarialPayloadSafetyError(
        "adversarial payload requires exactly one of 'family' or 'value'"
    )


# --- Per-surface rendering -----------------------------------------------------


def _raw_surfaces_for(family: str | None) -> set[str]:
    """Surfaces where this family's control bytes are emitted raw.

    For a family, the declared ``raw_surfaces``; for a literal ``value:`` (no
    family), default to syslog_message so a custom payload can still inject raw
    there. Control bytes are escaped on every other surface.
    """
    if family:
        fam = get_family(family) or {}
        return set(fam.get("raw_surfaces") or ())
    return {"syslog_message"}


def _encode_for_surface(
    value: str, surface: str, family: str | None, os_category: str = "linux"
) -> str:
    """Surface-appropriate encoding that PRESERVES the injection while keeping the
    payload from corrupting an unrelated record.

    - http_request_url / http_referrer: percent-encode (a raw CR becomes %0d, which
      still tests a URL-decode-then-log pipeline) so the payload is one URI component.
    - http_user_agent: a quoted combined-log field whose emitter re-escapes control
      bytes / backslashes / quotes — so percent-encode exactly those (keeping printables
      like ${jndi:.../<script> literal) to make the emitter transform a no-op and keep
      the recorded rendered_value byte-equal to the on-disk UA field.
    - process_command_line: escape control bytes to a literal FIRST (so no raw control
      byte reaches the eCAR command_line), then shell-quote so it is a single arg.
    - syslog_message: emit raw where this family declares it (the realistic weakness),
      else escape control bytes to a literal.
    """
    raw_surfaces = _raw_surfaces_for(family)
    if surface in ("http_request_url", "http_referrer"):
        return urllib.parse.quote(value, safe="/?:&=@.~_-")
    if surface == "http_user_agent":
        return urllib.parse.quote(value, safe=_UA_SAFE)
    if surface == "process_command_line":
        escaped = _escape_controls(value)
        return _quote_windows(escaped) if os_category == "windows" else shlex.quote(escaped)
    if surface == "syslog_message":
        return value if surface in raw_surfaces else _escape_controls(value)
    return value


# scheme://authority OR scheme-relative //authority — both are callback vectors the
# value extractor (_extract_hosts) also covers; the optional scheme means a bare
# `cmd.exe` (no `//`) is never matched, so the valid Windows process carriers are safe.
_SCHEME_HOST_RE = re.compile(r"(?:[a-zA-Z][a-zA-Z0-9+.\-]*:)?//([^/\s\"'>}\\]+)")
# userinfo callback without a scheme, e.g. `exfil to user@evil.com` or `user@8.8.8.8`.
# The final label may be an alphabetic TLD or a numeric octet (a dotted IPv4 host);
# _host_allowed then rejects any non-reserved domain or public IP.
_USERINFO_HOST_RE = re.compile(r"[\w.\-]+@([A-Za-z0-9.\-]+\.(?:[A-Za-z]{2,}|\d{1,3}))")


def _carrier_callback_hosts(line: str) -> set[str]:
    """Hosts in a callback position within a rendered line.

    Covers ``scheme://[user@]host[:port]``, scheme-relative ``//host``, and userinfo
    ``user@host`` (domain or dotted-IPv4) — the realistic vectors a carrier could
    embed (a URL/authority a vulnerable consumer might fetch). Bare binary tokens like
    ``cmd.exe`` (no ``//`` and no ``@``) are intentionally excluded, since they are not
    network hosts. This is a defense-in-depth check on carrier text; the payload value
    itself is host-checked by :func:`check_payload_safety` via ``_extract_hosts``.
    """
    # Both patterns require a literal delimiter (``//`` resp. ``@``); gate on a cheap
    # substring test so a long delimiter-free token (e.g. an oversized_field payload)
    # cannot drive their `[\w.\-]+`/authority runs into O(n^2) backtracking.
    hosts: set[str] = set()
    if "//" in line:
        for match in _SCHEME_HOST_RE.finditer(line):
            authority = match.group(1)
            host = authority.rsplit("@", 1)[-1].split(":", 1)[0]
            if host:
                hosts.add(host)
    if "@" in line:
        for match in _USERINFO_HOST_RE.finditer(line):
            hosts.add(match.group(1))
    return hosts


def _choose_carrier(
    family: str | None, surface: str, rng: random.Random, os_category: str = "linux"
) -> str:
    """Pick a carrier-line template for (family, surface), OS-aware, else a generic one."""
    fam_carriers = (get_family(family) or {}).get("carriers") or {} if family else {}
    # A Windows process command line must render a native command, never a Linux one.
    if surface == "process_command_line" and os_category == "windows":
        carriers = (
            fam_carriers.get("process_command_line_windows")
            or fam_carriers.get(surface)
            or list(_GENERIC_CARRIERS_WINDOWS.get(surface, ("{value}",)))
        )
    else:
        carriers = fam_carriers.get(surface) or list(_GENERIC_CARRIERS.get(surface, ("{value}",)))
    return rng.choice(sorted(carriers))


def render_for_surface(
    value: str,
    surface: str,
    family: str | None,
    seed_key: str,
    os_category: str = "linux",
    *,
    oob_hosts: tuple[str, ...] = (),
) -> SurfaceRender:
    """Render the payload into a per-surface carrier with surface encoding."""
    if surface not in VALID_SURFACES:
        raise AdversarialPayloadSafetyError(f"unsupported adversarial payload surface: {surface!r}")
    if family and surface not in set((get_family(family) or {}).get("surfaces") or ()):
        raise AdversarialPayloadSafetyError(
            f"family {family!r} is not valid on surface {surface!r}"
        )

    encoded = _encode_for_surface(value, surface, family, os_category)
    expected_sources = expected_sources_for_surface(surface)
    rng = random.Random(_stable_seed(f"{seed_key}:carrier:{surface}"))
    carrier = _choose_carrier(family, surface, rng, os_category)
    line = _expand_template(
        carrier, rng, keep_value=True, oob_host=oob_hosts[0] if oob_hosts else None
    ).replace("{value}", encoded)

    # Defense in depth: a carrier (especially a user overlay) must not introduce a
    # non-allowlisted callback host. The value's own hosts were vetted in
    # check_payload_safety, but a carrier-embedded URL host is not part of the value
    # and would otherwise never be checked. Scope to scheme://host positions (the real
    # callback vector) so a benign binary token like ``cmd.exe`` is not misread as a host.
    _domains = [*allowlisted_domains(), *(h.lower() for h in oob_hosts)]
    for _host in _carrier_callback_hosts(line):
        if not _host_allowed(_host, _domains):
            raise AdversarialPayloadSafetyError(
                f"carrier for surface {surface!r} embeds non-allowlisted host {_host!r}; "
                f"use the canary ({canary_host()}) or an RFC-reserved domain/address"
            )

    if surface == "syslog_message":
        # Keep APP-NAME coherent with the message: a carrier like "nginx: <field>"
        # should render APP-NAME=nginx, not a fixed "webapp" that contradicts it. A
        # prefix-less carrier (e.g. csv_formula's bare formula) falls back to "webapp".
        tag_match = re.match(r"([A-Za-z][\w-]*):", line)
        syslog_app = tag_match.group(1) if tag_match else "webapp"
        return SurfaceRender(
            surface=surface,
            encoded_value=encoded,
            expected_sources=expected_sources,
            syslog_app=syslog_app,
            syslog_message=line,
        )
    if surface == "process_command_line":
        tokens = line.split()
        default_proc = r"C:\Windows\System32\cmd.exe" if os_category == "windows" else "/usr/bin/sh"
        return SurfaceRender(
            surface=surface,
            encoded_value=encoded,
            expected_sources=expected_sources,
            command=line,
            process_name=tokens[0] if tokens else default_proc,
        )
    if surface == "http_user_agent":
        # The payload IS the User-Agent header; the request path is benign.
        return SurfaceRender(
            surface=surface,
            encoded_value=encoded,
            expected_sources=expected_sources,
            http_method="GET",
            http_uri=_expand_template(rng.choice(("/", "/index.html", "/login")), rng),
            http_referrer="",
            user_agent=line,
        )
    if surface == "http_request_url":
        return SurfaceRender(
            surface=surface,
            encoded_value=encoded,
            expected_sources=expected_sources,
            http_method="GET",
            http_uri=line,
            http_referrer="",
        )
    # http_referrer — the payload rides in the Referer header URL; path is benign.
    return SurfaceRender(
        surface=surface,
        encoded_value=encoded,
        expected_sources=expected_sources,
        http_method="GET",
        http_uri=_expand_template(rng.choice(("/", "/dashboard", "/app/home")), rng),
        http_referrer=line,
    )
