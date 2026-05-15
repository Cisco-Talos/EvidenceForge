# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""TLS realism configuration loader."""

import fnmatch
import hashlib
import random
from datetime import datetime, timedelta
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.generation.activity.timing_profiles import (
    sample_packet_timing_delta,
    sample_timing_delta,
)
from evidenceforge.utils.rng import _stable_seed

_CONFIG_PATH = get_activity_directory() / "tls_realism.yaml"
_CACHED_DATA: dict[str, Any] | None = None
_CLEARTEXT_CERT_INFRA_DOMAIN_CLASSES = {"crl", "ocsp"}


def _merge_tls_realism(default: dict, overlay: dict) -> dict:
    """Merge TLS realism overlay with package defaults."""
    return deep_merge_dict(default, overlay)


def load_tls_realism() -> dict[str, Any]:
    """Load TLS realism config from YAML, merged with overlay. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA

    _CACHED_DATA = load_with_overlay(
        _CONFIG_PATH,
        "activity/tls_realism.yaml",
        _merge_tls_realism,
    )
    return _CACHED_DATA


def reset_tls_realism_cache() -> None:
    """Clear cached TLS realism config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def multi_label_public_suffixes() -> set[str]:
    """Return configured multi-label public suffixes for wildcard SAN generation."""
    data = load_tls_realism()
    suffixes = data.get("san", {}).get("multi_label_public_suffixes", [])
    return {str(suffix).lower() for suffix in suffixes}


def serial_number_config() -> dict[str, Any]:
    """Return certificate serial-number behavior config."""
    return load_tls_realism().get("serial_numbers", {})


def ocsp_config() -> dict[str, Any]:
    """Return OCSP behavior config."""
    return load_tls_realism().get("ocsp", {})


def pick_ocsp_responder(issuer_name: str, rng: random.Random) -> str:
    """Pick an OCSP responder hostname for a certificate issuer."""
    responders = ocsp_config().get("responders", [])
    fallback_domains: list[str] = []
    for responder in responders:
        if not isinstance(responder, dict):
            continue
        domains = [str(domain) for domain in responder.get("domains", []) if domain]
        if not domains:
            continue
        patterns = [str(pattern) for pattern in responder.get("issuer_patterns", [])]
        if patterns == ["*"] or "*" in patterns:
            fallback_domains = domains
            continue
        if any(fnmatch.fnmatch(issuer_name, pattern) for pattern in patterns):
            return rng.choice(domains)
    if fallback_domains:
        return rng.choice(fallback_domains)
    return "ocsp.digicert.com"


def certificate_chain_config() -> dict[str, Any]:
    """Return TLS certificate chain behavior config."""
    return load_tls_realism().get("certificate_chains", {})


def _subject_key_profile(subject_name: str) -> dict[str, Any] | None:
    """Return the configured CA key profile matching a subject/issuer name."""
    for profile in certificate_chain_config().get("subject_key_profiles", []):
        if not isinstance(profile, dict):
            continue
        patterns = [str(pattern) for pattern in profile.get("subject_patterns", [])]
        if any(fnmatch.fnmatch(subject_name, pattern) for pattern in patterns):
            return profile
    return None


def certificate_subject_key_profile(
    subject_name: str,
    fallback_type: str = "rsa",
    fallback_length: int = 2048,
) -> tuple[str, int]:
    """Return the configured key profile for a CA subject or issuer name.

    X.509 ``certificate.sig_alg`` describes the issuer's signing key, not the
    child certificate's own public key. These profiles let chain construction
    choose that issuer key from source-owned CA metadata instead of inferring it
    from the child row.
    """
    key_type = fallback_type
    key_length = fallback_length
    profile = _subject_key_profile(subject_name)
    if profile is not None:
        key_type = str(profile.get("key_type", key_type))
        key_length = int(profile.get("key_length", key_length))
    return key_type, key_length


def signature_algorithm_for_issuer(
    issuer_name: str,
    fallback_type: str = "rsa",
    fallback_length: int = 2048,
) -> str:
    """Return a Zeek x509 ``certificate.sig_alg`` value for an issuer key."""
    profile = _subject_key_profile(issuer_name)
    if profile is not None:
        algorithms = [str(algorithm) for algorithm in profile.get("child_signature_algorithms", [])]
        if algorithms:
            return algorithms[0]
    issuer_key_type, _issuer_key_length = certificate_subject_key_profile(
        issuer_name,
        fallback_type=fallback_type,
        fallback_length=fallback_length,
    )
    if issuer_key_type == "ecdsa" and _issuer_key_length >= 384:
        return "ecdsa-with-SHA384"
    return "ecdsa-with-SHA256" if issuer_key_type == "ecdsa" else "sha256WithRSAEncryption"


def certificate_analyzer_delay_ms(
    *,
    zeek_uid: str,
    event_timestamp: datetime,
    fuid: str,
    position: int,
) -> int:
    """Return a deterministic, non-uniform Zeek TLS certificate analyzer offset."""
    del fuid
    base_delay_ms = ssl_analyzer_delay_ms(zeek_uid=zeek_uid, event_timestamp=event_timestamp)
    base_delay_ms += int(
        sample_timing_delta(
            "source.zeek_x509_analyzer",
            seed_parts=(zeek_uid, event_timestamp),
        ).total_seconds()
        * 1000
    )
    if position <= 0:
        return base_delay_ms

    gap_ms = 0
    for depth in range(1, position + 1):
        gap_seed = f"tls_cert_chain_gap:{zeek_uid}:{event_timestamp.isoformat()}:{depth}"
        rng = random.Random(_stable_seed(gap_seed))
        gap_ms += rng.randint(3, 45)
    return base_delay_ms + gap_ms


def ssl_analyzer_delay_ms(*, zeek_uid: str, event_timestamp: datetime) -> int:
    """Return the deterministic Zeek ssl.log analyzer offset for a flow."""
    delay = ssl_analyzer_delay(zeek_uid=zeek_uid, event_timestamp=event_timestamp)
    return int(delay.total_seconds() * 1000)


def ssl_analyzer_delay(*, zeek_uid: str, event_timestamp: datetime) -> timedelta:
    """Return the deterministic Zeek ssl.log analyzer offset for a flow."""
    return sample_packet_timing_delta(
        "source.zeek_ssl_analyzer",
        seed_parts=(zeek_uid, event_timestamp),
    )


def certificate_file_size(cert: object) -> int:
    """Return a stable file-analysis byte size for a rendered certificate."""
    identity = "|".join(
        [
            str(getattr(cert, "fingerprint", "")),
            str(getattr(cert, "certificate_subject", "")),
            str(getattr(cert, "certificate_issuer", "")),
            ",".join(str(name) for name in getattr(cert, "san_dns", []) or []),
        ]
    )
    rng = hashlib.sha256(identity.encode()).digest()
    key_overhead = int(getattr(cert, "certificate_key_length", 2048)) // 8
    san_overhead = 18 * len(getattr(cert, "san_dns", []) or [])
    ca_overhead = 220 if not getattr(cert, "host_cert", False) else 0
    subject_overhead = min(180, len(str(getattr(cert, "certificate_subject", ""))) * 2)
    issuer_overhead = min(220, len(str(getattr(cert, "certificate_issuer", ""))) * 2)
    jitter = _stable_seed(f"zeek-cert-size:{identity}:{rng.hex()}") % 420
    return (
        720
        + key_overhead
        + san_overhead
        + ca_overhead
        + subject_overhead
        + issuer_overhead
        + jitter
    )


def tls_destination_config() -> dict[str, Any]:
    """Return TLS destination profile config."""
    return load_tls_realism().get("destinations", {})


def chain_template_for_issuer(issuer_name: str) -> dict[str, Any]:
    """Return the configured certificate-chain template for an issuer."""
    templates = certificate_chain_config().get("templates", [])
    fallback: dict[str, Any] = {}
    for template in templates:
        if not isinstance(template, dict):
            continue
        patterns = template.get("issuer_patterns", [])
        if "*" in patterns and not fallback:
            fallback = template
        if any(fnmatch.fnmatch(issuer_name, str(pattern)) for pattern in patterns):
            return template
    return fallback


def pick_tls_destination(
    rng: random.Random,
    *,
    src_host: str = "",
    source_os: str | None = None,
    persona: str | None = None,
    system_type: str | None = None,
    purpose_tags: tuple[str, ...] = (),
) -> tuple[str, str]:
    """Pick a TLS destination using profile-aware, host-stable preferences.

    The picker keeps enterprise heavy hitters common while avoiding global
    repetition of the same few SNI identities. Each host gets deterministic
    preferred domains per profile, with occasional full-pool selection for
    long-tail variety.
    """
    from evidenceforge.generation.activity.dns_registry import (
        generate_long_tail_domain,
        resolve_domain_ip,
    )

    cfg = tls_destination_config()
    if not cfg.get("enabled", True):
        domain = generate_long_tail_domain(rng)
        return domain, resolve_domain_ip(domain, src_host=src_host)

    source_os_norm = (source_os or "").lower()
    persona_norm = (persona or "").lower()
    system_type_norm = (system_type or "").lower()
    purpose_set = {tag for tag in purpose_tags if tag}

    profiles = [
        profile
        for profile in cfg.get("profiles", [])
        if isinstance(profile, dict)
        and _tls_profile_applies(
            profile,
            source_os=source_os_norm,
            persona=persona_norm,
            system_type=system_type_norm,
            purpose_tags=purpose_set,
        )
    ]
    if not profiles:
        domain = generate_long_tail_domain(rng)
        return domain, resolve_domain_ip(domain, src_host=src_host)

    weights = [
        max(1, int(profile.get("weight", 1)))
        * _host_profile_affinity(src_host=src_host, profile_name=str(profile.get("name", "")))
        for profile in profiles
    ]
    profile = rng.choices(profiles, weights=weights, k=1)[0]
    domains = _tls_profile_domains(profile, rng, source_os=source_os_norm)
    if not domains:
        domain = generate_long_tail_domain(rng)
        return domain, resolve_domain_ip(domain, src_host=src_host)

    preferred_count = max(1, int(cfg.get("host_preferred_domain_count", 6)))
    preferred_probability = float(cfg.get("host_preferred_probability", 0.68))
    if len(domains) > preferred_count and rng.random() < preferred_probability:
        ordered = sorted(
            domains,
            key=lambda domain: _stable_seed(
                f"tls_domain_affinity:{src_host}:{profile.get('name', '')}:{domain}"
            ),
        )
        domains = ordered[:preferred_count]

    domain = rng.choice(domains)
    return domain, resolve_domain_ip(domain, src_host=src_host)


def _tls_profile_applies(
    profile: dict[str, Any],
    *,
    source_os: str,
    persona: str,
    system_type: str,
    purpose_tags: set[str],
) -> bool:
    """Return whether a TLS destination profile applies to this source."""
    os_values = {str(value).lower() for value in profile.get("os", [])}
    persona_values = {str(value).lower() for value in profile.get("personas", [])}
    system_type_values = {str(value).lower() for value in profile.get("system_types", [])}
    purpose_values = {str(value) for value in profile.get("purpose_tags", [])}
    if os_values and source_os not in os_values:
        return False
    if persona_values and persona not in persona_values:
        return False
    if system_type_values and system_type not in system_type_values:
        return False
    if purpose_values and purpose_tags and not purpose_values.intersection(purpose_tags):
        return False
    return True


def _host_profile_affinity(*, src_host: str, profile_name: str) -> float:
    """Deterministic host/profile multiplier in the 0.75-1.25 range."""
    seed = _stable_seed(f"tls_profile_affinity:{src_host}:{profile_name}")
    return 0.75 + (seed % 51) / 100


def _tls_profile_domains(
    profile: dict[str, Any],
    rng: random.Random,
    *,
    source_os: str,
) -> list[str]:
    """Build a profile domain pool from explicit domains, OS overrides, and DNS tags."""
    from evidenceforge.generation.activity.dns_registry import get_domain_tags, get_domains_by_tag
    from evidenceforge.generation.activity.proxy_uri import get_proxy_domain_class

    override: dict[str, Any] = {}
    os_overrides = profile.get("os_overrides", {})
    if isinstance(os_overrides, dict) and source_os in os_overrides:
        configured_override = os_overrides.get(source_os, {})
        if isinstance(configured_override, dict):
            override = configured_override

    if override.get("domains"):
        domains = [str(domain) for domain in override.get("domains", []) if domain]
    else:
        domains = [str(domain) for domain in profile.get("domains", []) if domain]

    override_dns_tags = False
    if override and "dns_tags" in override:
        override_dns_tags = True
        dns_tags = [str(tag) for tag in override.get("dns_tags", []) if tag]
    else:
        dns_tags = [str(tag) for tag in profile.get("dns_tags", []) if tag]
    if dns_tags:
        tag_query = tuple(dns_tags) if override_dns_tags else (rng.choice(dns_tags),)
        for entry in get_domains_by_tag(*tag_query):
            domain = entry.get("domain")
            if domain:
                domains.append(str(domain))

    seen: set[str] = set()
    unique_domains: list[str] = []
    for domain in domains:
        domain_tags = set(get_domain_tags(domain))
        os_tags = domain_tags & {"windows", "linux"}
        if source_os in {"windows", "linux"} and os_tags and source_os not in os_tags:
            continue
        if get_proxy_domain_class(domain) in _CLEARTEXT_CERT_INFRA_DOMAIN_CLASSES:
            continue
        if domain not in seen:
            seen.add(domain)
            unique_domains.append(domain)
    return unique_domains
