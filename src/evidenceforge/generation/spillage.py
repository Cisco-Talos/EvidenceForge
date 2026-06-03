# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Spillage event CODE layer: synthesis, safety guardrails, per-surface encoding.

The credential *families* and safety *markers* are DATA and live in the
user-customizable overlay config (config/activity/secret_families.yaml). This
module is the CODE layer the maintainer asked for in
https://github.com/Cisco-Talos/EvidenceForge/issues/283 — it owns:

  * deterministic synthesis of one canonical fake value from a family,
  * the safety guardrails that prove every emitted value is synthetic, and
  * surface-appropriate encoding/rendering of that single canonical value.

Guardrails (enforced for both synthesized and user-supplied literal values, so
unsafe values never reach generation):

  1. Marker/allowlist — value contains a poison marker OR is a vendor-published
     fake. This is the hard "no real credential" guarantee.
  2. Host allowlist — any host embedded in a URL-shaped value is an RFC 2606 /
     RFC 6761 reserved domain or an RFC 5737 / RFC 3849 / RFC 1918 address.
     Alternate encodings a real client would undo (percent-encoding, Unicode
     label separators, obfuscated / zone-tagged IPs, backslash and scheme-relative
     URLs) are normalized first so a real host cannot hide behind one.
  3. Family regex — a value declared for a family must match that family's regex.
  4. Single-line / control-free — the value carries no CR/LF or other line
     separator (so a credential cannot be split across log lines) and no other
     control character such as ESC/NUL/BEL (so it cannot inject a terminal escape
     sequence or confuse a parser when rendered raw into a command line). Only tab
     is allowed. Spilling a credential is not a log-injection primitive; that is
     the separate `adversarial_payload` work.
"""

from __future__ import annotations

import ipaddress
import math
import random
import re
import shlex
import socket
import string
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field

from evidenceforge.config.secret_families import (
    allowlisted_domains,
    get_family,
    load_secret_families,
    poison_markers,
    vendor_fakes,
)
from evidenceforge.utils.rng import _stable_seed

# Implemented semantic surfaces. Keep in sync with SpillageEventSpec.surface.
VALID_SURFACES: tuple[str, ...] = (
    "shell_history",
    "process_command_line",
    "syslog_message",
    "http_request_url",
    "http_referrer",
)

# Web-request surfaces: the credential rides in an outbound HTTP/S request (URL
# query string or Referer header) and is recorded by the destination web
# server's access log. Cross-OS, and they require a web_server-role host in the
# environment to receive the request (the generator/validator enforce this).
HTTP_SURFACES: frozenset[str] = frozenset({"http_request_url", "http_referrer"})
HTTP_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# Surfaces that only model on Linux hosts (syslog/bash). process_command_line
# and the http_* surfaces are cross-OS (process telemetry and web requests exist
# on Windows and Linux).
LINUX_ONLY_SURFACES: frozenset[str] = frozenset({"shell_history", "syslog_message"})

# Unicode label separators that IDNA / UTS-46 map to ASCII '.' — a real resolver
# or browser treats "host．tld" as "host.tld". Normalized before host extraction
# so a non-allowlisted host cannot hide behind a fullwidth/ideographic dot.
_UNICODE_DOT_MAP = {0x3002: ".", 0xFF0E: ".", 0xFF61: "."}

# Every character str.splitlines() treats as a line boundary. A spilled value
# carrying any of these could split a credential across log lines, so they are
# rejected outright (tab is allowed and escaped at render time).
_LINE_BOUNDARY_CHARS = "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"

# (The non-interactive bash-user set lives in the generator as the canonical
# _NONINTERACTIVE_BASH_USERS; the spillage validator imports it directly so it
# cannot drift from the actual bash-history suppression behaviour.)

# RFC 5737 (IPv4 doc) + RFC 3849 (IPv6 doc) ranges, accepted in addition to the
# private/loopback/link-local ranges that ipaddress recognises directly.
_RESERVED_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]

# Single source of truth: semantic surface -> the output format that must be
# enabled for the credential to land (also its ground-truth `expected_sources`).
# Validation and the eval matcher both consume this map.
SURFACE_FORMATS: dict[str, str] = {
    "shell_history": "bash_history",
    "process_command_line": "ecar",
    "syslog_message": "syslog",
    "http_request_url": "web_access",
    "http_referrer": "web_access",
}

# Pools for template tokens (generation mechanics, not credential DATA).
_HOST_LABELS = ("db", "api", "vault", "cache", "auth", "svc", "app", "ci", "mq", "edge")
# Engine-neutral so a host label never contradicts the URI scheme (e.g. no
# "mongodb://...@postgres4").
_DB_HOST_LABELS = ("db", "data", "cache", "store", "primary", "replica", "records", "cluster")
_FAKE_USERS = ("svc_app", "deploy", "ci-runner", "dbadmin", "appuser", "backup", "ops")
_FAKE_DBS = ("appdb", "payments", "users", "orders", "analytics", "inventory")
_DB_SCHEMES = ("postgresql", "mysql", "mongodb")

# Benign request paths used as the visible URL when the credential rides in the
# Referer header (http_referrer) — the path itself carries no secret.
_BENIGN_HTTP_PATHS = ("/", "/dashboard", "/app/home", "/account/settings", "/portal")

# Fallback carrier lines for a surface a family does not specify (and for literal
# `value:` spills). Each must contain the {value} placeholder. For http_request_url
# the carrier is the request URI (path+query); for http_referrer it is the full
# Referer URL (the {host} token resolves to an allowlisted domain).
_GENERIC_CARRIERS: dict[str, tuple[str, ...]] = {
    "shell_history": ("export SECRET={value}", "echo {value} >> .env"),
    # process_command_line carriers are LOCAL commands only — a process_command_line
    # spill is a live in-window EDR process record, so it must not imply an outbound
    # connection it doesn't have. (Network-tool leaks are modeled by shell_history,
    # a history-file artifact, and the correlated http_* surfaces.) {value} sits in
    # an UNQUOTED slot so shell-quoting is the single quoter (no nested quoting when
    # a value carries a shell metacharacter, e.g. password_generic's trailing '!').
    "process_command_line": (
        "/usr/bin/env API_TOKEN={value} printenv API_TOKEN",
        "/usr/bin/env SECRET={value} env",
    ),
    "syslog_message": ("app: loaded credential {value}", "config: secret={value}"),
    "http_request_url": (
        "/api/v1/resource?token={value}",
        "/download?key={value}&id={hex:8}",
    ),
    "http_referrer": (
        "https://portal.{host}/login?token={value}",
        "https://sso.{host}/callback?ticket={value}",
    ),
}

# Windows-native fallback for process_command_line so a Windows host never renders
# a Linux command line. shell_history/syslog_message are Linux-only and the http_*
# carriers are OS-neutral URLs, so only process_command_line needs an OS split.
# Families MAY override with a `process_command_line_windows` carrier list. Local
# commands only (see _GENERIC_CARRIERS comment above) — no implied outbound network.
_GENERIC_CARRIERS_WINDOWS: dict[str, tuple[str, ...]] = {
    # {value} sits in an UNQUOTED slot so per-OS quoting (_quote_windows) is the
    # single quoter — a carrier must not pre-wrap {value} in quotes or a literal
    # value with a shell metacharacter would render doubled/nested quotes.
    "process_command_line": (
        "cmd.exe /c set API_TOKEN={value}",
        "cmd.exe /c set SECRET={value}",
    ),
}

_TOKEN_RE = re.compile(r"\{(\w+)(?::(\d+))?\}")


_WEB_HTTP_SERVICE_TOKENS = frozenset({"http"})
_WEB_HTTPS_SERVICE_TOKENS = frozenset({"https", "ssl", "tls"})
_WEB_GENERIC_SERVICE_TOKENS = frozenset(
    {"apache", "apache2", "nginx", "httpd", "iis", "tomcat", "gunicorn"}
)
_WEB_SCHEME_ORDER = ("https", "http")


def _inventory_token(value: str) -> str:
    """Normalize scenario inventory labels for lightweight matching."""
    return value.lower().replace(" ", "-").replace("_", "-")


def web_server_supported_schemes(system: object) -> frozenset[str]:
    """Return HTTP schemes a web-server system plausibly serves.

    Explicit service tokens are authoritative: ``http`` means HTTP-only unless
    an HTTPS token is also present, and ``https``/``ssl``/``tls`` means
    HTTPS-only unless ``http`` is also present. Legacy generic web servers keep
    both schemes unless they opt into explicit scheme markers.
    """
    roles = {_inventory_token(str(role)) for role in (getattr(system, "roles", None) or [])}
    if "web-server" not in roles:
        return frozenset()

    services = {
        _inventory_token(str(service)) for service in (getattr(system, "services", None) or [])
    }
    explicit: set[str] = set()
    if services & _WEB_HTTP_SERVICE_TOKENS:
        explicit.add("http")
    if services & _WEB_HTTPS_SERVICE_TOKENS:
        explicit.add("https")
    if explicit:
        return frozenset(explicit)

    if not services or services & _WEB_GENERIC_SERVICE_TOKENS or "web-server" in roles:
        return HTTP_SCHEMES
    return frozenset()


def choose_web_spillage_scheme(system: object, requested_scheme: str | None) -> str | None:
    """Return the effective scheme for a web spillage target, or None."""
    supported = web_server_supported_schemes(system)
    if requested_scheme is not None:
        return requested_scheme if requested_scheme in supported else None
    for scheme in _WEB_SCHEME_ORDER:
        if scheme in supported:
            return scheme
    return None


def expected_sources_for_surface(surface: str) -> tuple[str, ...]:
    """Return the log source(s) a surface is expected to produce."""
    fmt = SURFACE_FORMATS.get(surface)
    return (fmt,) if fmt else ()


class SpillageSafetyError(ValueError):
    """Raised when a spillage value fails a safety guardrail.

    Subclasses ValueError so existing scenario-validation paths catch it.
    """


@dataclass
class SurfaceRender:
    """What generate_spillage should emit for a resolved spillage value."""

    surface: str
    encoded_value: str  # the canonical value with surface encoding applied
    expected_sources: tuple[str, ...]
    command: str | None = None  # shell_history / process_command_line (the line)
    process_name: str | None = None  # process_command_line (the binary)
    syslog_app: str | None = None  # syslog_message
    syslog_message: str | None = None  # syslog_message
    http_method: str | None = None  # http_request_url / http_referrer
    http_uri: str | None = None  # http_request_url / http_referrer (request path+query)
    http_referrer: str | None = None  # http_referrer (Referer header URL)
    tags: list[str] = field(default_factory=list)


# --- Safety guardrails ---------------------------------------------------------

# Final-label tokens that look domain-ish but are filenames, not hosts.
_FILE_EXT_EXEMPT = frozenset(
    {
        "conf",
        "cfg",
        "ini",
        "env",
        "db",
        "log",
        "txt",
        "json",
        "yaml",
        "yml",
        "py",
        "sh",
        "pem",
        "key",
        "crt",
        "csr",
        "p12",
        "jks",
        "sql",
        "bak",
        "md",
    }
)


def _extract_hosts(value: str) -> list[str]:
    """Return candidate hosts embedded in ``value``.

    Inspects URL netlocs (every ``@``-separated segment, to catch userinfo and
    double-``@`` smuggling), the host after any ``@`` (``user@host`` forms,
    including IPv4 / bracketed IPv6 / domain, so a real IP cannot hide behind
    userinfo), and bare dotted domains. Single-label tokens and obvious filenames
    are ignored to limit false positives. The caller validates each host against
    the allowlist.

    Encodings a real client would undo are normalized first so a non-allowlisted
    host cannot hide behind one: percent-encoding (``https://%65vil.com``) and
    Unicode label separators IDNA maps to ``.`` (``host．tld``).
    """
    value = urllib.parse.unquote(value).translate(_UNICODE_DOT_MAP)
    hosts: set[str] = set()

    def _add(candidate: str, *, host_position: bool = False) -> None:
        candidate = candidate.strip().lower()
        if candidate.startswith("["):  # bracketed IPv6 [..]:port or [..%zone]
            candidate = candidate[1:].split("]", 1)[0]
            candidate = candidate.split("%", 1)[0]  # drop IPv6 zone id (fe80::1%eth0)
        elif candidate.count(":") == 1:  # host:port (not IPv6, which has >1 colon)
            candidate = candidate.rsplit(":", 1)[0]
        candidate = candidate.strip(".")
        if not candidate:
            return
        # A surviving non-ASCII codepoint in an unambiguous host position is an
        # IDN/homoglyph host a real resolver maps to a registrable domain; treat it
        # as a host so the allowlist rejects it rather than silently dropping it.
        if host_position and any(ord(c) > 127 for c in candidate):
            hosts.add(candidate)
            return
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            pass
        else:
            hosts.add(candidate)  # canonical IP literal — validated downstream
            return
        # Obfuscated IPv4 a real resolver accepts but ipaddress rejects (dotless
        # decimal/hex, octal/hex octets), so a real public IP cannot hide as
        # http://134744072/ or user@0x8.0x8.0x8.0x8.
        normalized = _resolver_ipv4(candidate, host_position=host_position)
        if normalized:
            hosts.add(normalized)
            return
        if "." not in candidate:
            return  # single label / username / bare integer — not a host here
        last = candidate.rsplit(".", 1)[-1]
        if last in _FILE_EXT_EXEMPT and not host_position:
            return  # a filename like deploy.sh in a command (but a URL host is a host)
        if not (re.fullmatch(r"[a-z]{2,24}", last) or re.fullmatch(r"xn--[a-z0-9-]+", last)):
            return  # final label is not a plausible/IDN TLD (e.g. a JWT/base64 segment)
        hosts.add(candidate)

    # Hosts in unambiguous host positions (URL netloc, userinfo) are validated even
    # if they are IPs or carry a TLD that also looks like a file extension. The
    # netloc ends at the first '/', '?', '#', '\' (WHATWG treats '\' as '/'), or
    # whitespace; the scheme is optional so scheme-relative URLs ("//evil.com/x",
    # which resolve to the surrounding scheme) are host-checked too.
    for match in re.finditer(r"(?:[a-zA-Z][a-zA-Z0-9+.\-]*:)?//([^/?#\\\s]+)", value):
        for segment in match.group(1).split("@"):
            _add(segment, host_position=True)
    # Host after any "@" — IPv4, bracketed IPv6 (incl. zone id), or domain — so an
    # IP cannot slip past the allowlist by hiding behind userinfo (e.g.
    # "user@8.8.8.8"); _add classifies and validates each. Non-overlapping matching
    # walks chained "@"s.
    for match in re.finditer(r"@(\[[^\]]+\]|[A-Za-z0-9.\-]+)", value):
        _add(match.group(1), host_position=True)
    for match in re.finditer(r"(?<![\w@.\-/])([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)", value):
        _add(match.group(1))
    # IDN / homoglyph hosts a real resolver IDNA-encodes to a registrable domain —
    # e.g. "paуpal.com" (Cyrillic 'у'), "пример.рф", a fullwidth-digit IPv4 — are
    # missed by the ASCII-only extractors above (and the unicode-dot map only
    # normalizes separators, not labels). Scan any dotted token carrying a non-ASCII
    # codepoint and host-check it, so it is rejected unless it is a non-ASCII
    # subdomain of an allowlisted domain. Pure-ASCII values produce no match here.
    for match in re.finditer(r"[^\s/]*[^\x00-\x7f][^\s/]*", value):
        if "." not in match.group(0):
            continue  # a non-ASCII word with no dot is not a host
        for segment in match.group(0).split("@"):
            if "." in segment and any(ord(c) > 127 for c in segment):
                _add(segment, host_position=True)

    return sorted(hosts)


def _resolver_ipv4(candidate: str, *, host_position: bool) -> str | None:
    """Dotted-quad for an obfuscated IPv4 literal that ``inet_aton`` (and curl /
    browsers / log-replay clients) accepts but ``ipaddress`` rejects.

    Gated so ordinary numbers are not misread as hosts: a bare single integer is
    only treated as an IP in a host position (URL netloc / userinfo); a dotted
    form is only normalized when it has four numeric octets and at least one is
    octal (leading zero) or hex — a plain decimal quad is already handled by
    ``ipaddress``.
    """
    token = r"0x[0-9a-f]+|\d+"
    is_single = bool(re.fullmatch(token, candidate))
    labels = candidate.split(".")
    is_obfuscated_quad = (
        len(labels) == 4
        and all(re.fullmatch(token, lab) for lab in labels)
        and any(lab.startswith("0x") or (lab.startswith("0") and lab != "0") for lab in labels)
    )
    if not ((is_single and host_position) or is_obfuscated_quad):
        return None
    try:
        return socket.inet_ntoa(socket.inet_aton(candidate))
    except OSError:
        return None


def _credential_shaped_tokens(value: str) -> list[str]:
    """Substrings of ``value`` that match any known family regex.

    These look like real secrets, so each must independently prove it is
    synthetic (carry a marker, or overlap a vendor fake) — a marker tacked on
    elsewhere in the string does not vouch for a credential-shaped token.
    """
    tokens: set[str] = set()
    for fam in load_secret_families().get("families", []):
        # Only high-entropy, distinctively-shaped families participate. Broad
        # catch-all shapes (structured: false, e.g. password_generic) would
        # false-match ordinary words and frustrate legitimate literals.
        if not fam.get("structured", True):
            continue
        try:
            pattern = re.compile(fam["regex"])
        except (re.error, KeyError, TypeError):
            continue
        for match in pattern.finditer(value):
            if match.group(0):
                tokens.add(match.group(0))
    # Generic high-entropy secret shapes not covered by a structured family
    # (e.g. OpenAI sk-proj-, SendGrid SG., Azure keys, 40-hex tokens): a long,
    # random-looking token mixing letters and digits is treated as
    # credential-shaped, so it too must carry an in-token marker. Tokens that are
    # themselves hosts (e.g. a db_uri's server) are validated by the host
    # allowlist, not here. "/" is excluded from the charset so URL paths are not
    # mistaken for secrets.
    for tok in re.findall(r"[A-Za-z0-9_\-+=.]{20,}", value):
        if _looks_high_entropy(tok) and not _extract_hosts(tok):
            tokens.add(tok)
    return sorted(tokens)


def _looks_high_entropy(token: str) -> bool:
    """True for a long, random-looking token (>=2 character classes, high Shannon
    entropy) — distinguishes a real key from a dictionary word/phrase or a long
    repetitive non-secret, without an external wordlist."""
    if len(token) < 20:
        return False
    # Require >=2 distinct classes among {lower, upper, digit}. A mixed-case
    # letters-only token (lower+upper) IS flagged — a real key need not contain a
    # digit — while a single-class run (a lowercase word, an all-caps constant, a
    # pure-numeric id) is spared to avoid false-positives on dictionary content.
    classes = (
        any(c.islower() for c in token)
        + any(c.isupper() for c in token)
        + any(c.isdigit() for c in token)
    )
    if classes < 2:
        return False
    counts = Counter(token)
    n = len(token)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return entropy >= 3.0


def _host_allowed(host: str, domains: list[str]) -> bool:
    """True when host is a reserved/private IP or an allowlisted domain."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
        return any(ip in net for net in _RESERVED_NETS)

    normalized = host.lower().rstrip(".")
    return any(normalized == d or normalized.endswith("." + d) for d in domains)


def check_spillage_safety(value: str, family: str | None = None) -> None:
    """Validate a spillage value against all guardrails. Raises on failure."""
    if not value:
        raise SpillageSafetyError("spillage value must be non-empty")

    # Reject control characters: line separators (CR/LF/VT/FF/FS/GS/RS/NEL/LS/PS)
    # that could split a credential across log lines, AND other C0/C1/DEL controls
    # (ESC, NUL, BEL, …) that could inject terminal escape sequences or confuse a
    # parser when the value is rendered raw into a shell/process command line. Tab
    # is the one allowed control (whitespace; escaped for syslog, shell-quoted
    # elsewhere). Spillage is not a log-injection primitive.
    if any(
        (ord(ch) < 0x20 and ch != "\t")
        or ord(ch) == 0x7F
        or 0x80 <= ord(ch) <= 0x9F
        or ch in _LINE_BOUNDARY_CHARS
        for ch in value
    ):
        raise SpillageSafetyError(
            "spillage value must be single-line and free of control characters "
            "(no CR/LF/VT/FF/NEL/LS/PS/ESC/NUL/…); only tab is allowed"
        )

    markers = poison_markers()
    fakes = vendor_fakes()
    if not (any(m in value for m in markers) or any(f in value for f in fakes)):
        raise SpillageSafetyError(
            "spillage value must contain a poison marker "
            f"(one of {markers}) or be a vendor-published fake"
        )

    # Every credential-shaped token must itself prove synthetic — a marker
    # appended elsewhere does not vouch for a real-key-shaped substring.
    for token in _credential_shaped_tokens(value):
        token_ok = any(m in token for m in markers) or any(
            (f in token) or (token in f) for f in fakes
        )
        if not token_ok:
            raise SpillageSafetyError(
                f"spillage value contains a credential-shaped token {token!r} with no poison "
                "marker; embed a marker inside the credential itself or add it to vendor_fakes"
            )

    domains = allowlisted_domains()
    for host in _extract_hosts(value):
        if not _host_allowed(host, domains):
            raise SpillageSafetyError(
                f"spillage value embeds non-allowlisted host {host!r}; use an "
                "RFC 2606/6761 reserved domain or an RFC 5737/3849/1918 address"
            )

    if family:
        fam = get_family(family)
        if fam is None:
            raise SpillageSafetyError(f"unknown spillage family: {family!r}")
        if not re.search(fam["regex"], value):
            raise SpillageSafetyError(
                f"spillage value does not match family {family!r} regex {fam['regex']!r}"
            )


# --- Synthesis -----------------------------------------------------------------


def _expand_template(template: str, rng: random.Random, *, keep_value: bool = False) -> str:
    """Expand template tokens deterministically using ``rng``.

    With ``keep_value`` the ``{value}`` placeholder is left intact for later
    substitution of the (surface-encoded) secret.
    """
    domains = allowlisted_domains() or ["example.com"]

    def _repl(match: re.Match) -> str:
        token, count = match.group(1), match.group(2)
        n = int(count) if count else 0
        if token == "value":
            return "{value}" if keep_value else match.group(0)
        if token == "upper":
            return "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(n))
        if token == "alnum":
            return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(n))
        if token == "lower":
            return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))
        if token == "hex":
            return "".join(rng.choice("0123456789abcdef") for _ in range(n))
        if token == "digits":
            return "".join(rng.choice(string.digits) for _ in range(n))
        if token == "host":
            return f"{rng.choice(_HOST_LABELS)}{rng.randint(1, 9)}.{rng.choice(domains)}"
        if token == "dbhost":
            return f"{rng.choice(_DB_HOST_LABELS)}{rng.randint(1, 9)}.{rng.choice(domains)}"
        if token == "user":
            return rng.choice(_FAKE_USERS)
        if token == "db":
            return rng.choice(_FAKE_DBS)
        if token == "dbscheme":
            return rng.choice(_DB_SCHEMES)
        if token == "marker":
            return rng.choice(poison_markers())
        return match.group(0)  # unknown token — leave literal

    return _TOKEN_RE.sub(_repl, template)


def synthesize_value(family_name: str, seed_key: str) -> str:
    """Synthesize a fresh, safe, per-event value for a family from its template."""
    fam = get_family(family_name)
    if fam is None:
        raise SpillageSafetyError(f"unknown spillage family: {family_name!r}")
    rng = random.Random(_stable_seed(f"{seed_key}:value"))
    template = fam.get("value_template")
    if template:
        return _expand_template(template, rng)
    examples = list(fam.get("examples") or [])  # back-compat with example-only families
    if examples:
        return rng.choice(sorted(examples))
    raise SpillageSafetyError(
        f"spillage family {family_name!r} has no value_template to synthesize from"
    )


def resolve_value(family: str | None, value: str | None, *, seed_key: str) -> tuple[str, str]:
    """Resolve a spillage spec to (canonical_value, family_name), safety-checked.

    Exactly one of family/value must be provided (the model enforces this; this
    is the defense-in-depth path for programmatic callers).
    """
    if value is not None and family is None:
        check_spillage_safety(value, family=None)
        return value, ""
    if family is not None and value is None:
        synthesized = synthesize_value(family, seed_key)
        check_spillage_safety(synthesized, family=family)
        return synthesized, family
    raise SpillageSafetyError("spillage requires exactly one of 'family' or 'value'")


# --- Per-surface rendering -----------------------------------------------------


def _escape_controls(value: str) -> str:
    """Escape control characters so the value is safe on a single syslog line.

    Covers C0 (<0x20) and DEL, the C1 controls (0x80-0x9F, e.g. NEL), and the
    Unicode line/paragraph separators (U+2028/U+2029) — all of which a viewer or
    parser could treat as a line break.
    """
    out: list[str] = []
    for ch in value:
        codepoint = ord(ch)
        if codepoint < 0x20 or codepoint == 0x7F or 0x80 <= codepoint <= 0x9F:
            out.append(f"\\x{codepoint:02x}")
        elif codepoint in (0x2028, 0x2029):
            out.append(f"\\u{codepoint:04x}")
        else:
            out.append(ch)
    return "".join(out)


def _quote_windows(value: str) -> str:
    """Quote a value for a Windows command line (cmd / PowerShell): wrap in double
    quotes and double any embedded quote when it contains shell metacharacters."""
    if value and not any(c in value for c in ' \t"&|<>^()'):
        return value
    return '"' + value.replace('"', '""') + '"'


def _encode_for_surface(value: str, surface: str, os_category: str = "linux") -> str:
    """Surface-appropriate encoding of the raw secret value."""
    if surface == "process_command_line" and os_category == "windows":
        return _quote_windows(value)  # cmd/PowerShell, not POSIX shell quoting
    if surface in ("shell_history", "process_command_line"):
        return shlex.quote(value)
    if surface == "syslog_message":
        return _escape_controls(value)
    if surface in HTTP_SURFACES:
        # Percent-encode for use inside a URL query string / Referer header, so a
        # value containing URL metacharacters (e.g. a db_uri's :// and @) survives
        # as one component instead of corrupting the request line.
        return urllib.parse.quote(value, safe="")
    return value


def _choose_carrier(
    family: str, surface: str, rng: random.Random, os_category: str = "linux"
) -> str:
    """Pick a carrier-line template for (family, surface, os), else a generic one."""
    fam_carriers = (get_family(family) or {}).get("carriers") or {} if family else {}
    if surface == "process_command_line" and os_category == "windows":
        # OS-native command so a Windows host renders cmd/PowerShell/.exe, not a
        # Linux /usr/bin command line (would be implausible in Windows 4688/eCAR).
        carriers = fam_carriers.get("process_command_line_windows") or list(
            _GENERIC_CARRIERS_WINDOWS["process_command_line"]
        )
    else:
        carriers = fam_carriers.get(surface) or list(_GENERIC_CARRIERS.get(surface, ("{value}",)))
    return rng.choice(sorted(carriers))


def render_for_surface(
    value: str, surface: str, family: str, seed_key: str, os_category: str = "linux"
) -> SurfaceRender:
    """Render the secret into a per-event carrier line with surface encoding."""
    if surface not in VALID_SURFACES:
        raise SpillageSafetyError(f"unsupported spillage surface: {surface!r}")

    encoded = _encode_for_surface(value, surface, os_category)
    expected_sources = expected_sources_for_surface(surface)
    rng = random.Random(_stable_seed(f"{seed_key}:carrier:{surface}"))
    carrier = _choose_carrier(family, surface, rng, os_category)
    line = _expand_template(carrier, rng, keep_value=True).replace("{value}", encoded)

    if surface == "shell_history":
        return SurfaceRender(
            surface=surface,
            encoded_value=encoded,
            expected_sources=expected_sources,
            command=line,
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

    if surface == "http_request_url":
        # The credential rides in the request URI (path+query); the Referer is empty.
        return SurfaceRender(
            surface=surface,
            encoded_value=encoded,
            expected_sources=expected_sources,
            http_method="GET",
            http_uri=line,
            http_referrer="",
        )

    if surface == "http_referrer":
        # The credential rides in the Referer header URL; the request path is benign.
        benign_uri = _expand_template(rng.choice(_BENIGN_HTTP_PATHS), rng)
        return SurfaceRender(
            surface=surface,
            encoded_value=encoded,
            expected_sources=expected_sources,
            http_method="GET",
            http_uri=benign_uri,
            http_referrer=line,
        )

    # syslog_message
    app = (get_family(family) or {}).get("default_app", "app") if family else "app"
    return SurfaceRender(
        surface=surface,
        encoded_value=encoded,
        expected_sources=expected_sources,
        syslog_app=app,
        syslog_message=line,
    )
