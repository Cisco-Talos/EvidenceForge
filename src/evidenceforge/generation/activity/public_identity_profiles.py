# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Scenario-scoped canonical public identity registry and 2.x compatibility adapters."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import random
from copy import deepcopy
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import get_overlay_directory, merge_keyed_list
from evidenceforge.config.provider import (
    current_effective_config,
    packaged_default_document,
    project_overlay_document,
    uses_ambient_overlay_compat,
)
from evidenceforge.config.schemas import PublicIdentityProfilesConfig
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.yaml_loader import load_yaml_file

PublicIdentityRole = Literal[
    "scanner",
    "external_logon",
    "failed_logon",
    "c2",
    "human",
    "crawler",
    "api_client",
    "ordinary_responder",
    "cdn",
    "dns",
    "ntp",
    "mail",
]

_CONFIG_RELATIVE_PATH = "activity/public_identity_profiles.yaml"
_LEGACY_EXTERNAL_PATH = "activity/external_actor_profiles.yaml"
_LEGACY_MAIL_PATH = "activity/mail_public_identities.yaml"
_NETWORK_PARAMS_PATH = "activity/network_params.yaml"
_DNS_REGISTRY_PATH = "activity/dns_registry.yaml"
_CONFIG_PATH = get_activity_directory() / "public_identity_profiles.yaml"
_CACHED_DATA: dict[str, Any] | None = None
_RESERVED_PUBLIC_SUFFIXES = ("example", "test", "invalid", "localhost")
_RESERVED_DOCUMENTATION_DOMAINS = ("example.com", "example.net", "example.org")


@dataclass(frozen=True, slots=True)
class PublicIdentityBinding:
    """One complete immutable role/provider binding shared by every consumer."""

    semantic_key: str
    ip: str
    role: str
    provider: str
    forward_names: tuple[str, ...]
    ptr: str
    tls_profile: str
    traits: tuple[tuple[str, Any], ...]
    authored: bool
    provenance: tuple[str, ...]
    fingerprint: str

    def trait(self, name: str, default: Any = None) -> Any:
        """Return one frozen provider/persona trait."""

        return dict(self.traits).get(name, default)


@dataclass(frozen=True, slots=True)
class AuthoredPublicIdentityReuse:
    """One contradictory cross-role reuse found in authored scenario events."""

    ip: str
    roles: tuple[str, ...]
    field_paths: tuple[str, ...]


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _merge_registry(
    lower: dict[str, Any],
    higher: dict[str, Any],
    *,
    canonical_overlay: bool,
) -> dict[str, Any]:
    """Merge canonical providers and roles by id with the higher layer authoritative."""

    result = dict(lower)
    for field in ("providers", "roles"):
        if field not in higher:
            continue
        merged = merge_keyed_list(result.get(field, []), higher[field], "id")
        higher_by_id = {
            str(entry.get("id")): entry for entry in higher[field] if isinstance(entry, dict)
        }
        if canonical_overlay:
            # Canonical overlays own explicitly supplied list fields instead of appending
            # translated compatibility values to them.
            merged = [
                {
                    **entry,
                    **{
                        key: value
                        for key, value in higher_by_id.get(str(entry.get("id")), {}).items()
                        if key != "_replace"
                    },
                }
                for entry in merged
            ]
        result[field] = merged
    if "reserved_replacement_domains" in higher:
        result["reserved_replacement_domains"] = list(higher["reserved_replacement_domains"])
    if "schema_version" in higher:
        result["schema_version"] = higher["schema_version"]
    return result


def translate_external_actor_profiles(document: dict[str, Any]) -> dict[str, Any]:
    """Translate one deprecated external-actor overlay into canonical role patches."""

    role_fields = {
        "logon_source_ips": "external_logon",
        "failed_logon_source_ips": "failed_logon",
        "connection_c2_ips": "c2",
    }
    roles: list[dict[str, Any]] = []
    for legacy_field, role in role_fields.items():
        raw_entries = document.get(legacy_field)
        if not isinstance(raw_entries, list):
            continue
        identities = [
            {
                "ip": str(entry.get("ip", "")),
                "provider": "legacy-external-actor",
                "weight": int(entry.get("weight", 1)),
                "source": f"legacy:{_LEGACY_EXTERNAL_PATH}",
            }
            for entry in raw_entries
            if isinstance(entry, dict) and entry.get("ip")
        ]
        roles.append(
            {
                "id": role,
                "providers": ["legacy-external-actor"],
                "identities": identities,
            }
        )
    return {"roles": roles}


def translate_mail_public_identities(document: dict[str, Any]) -> dict[str, Any]:
    """Translate one deprecated mail identity overlay into canonical provider patches."""

    providers: list[dict[str, Any]] = []
    for entry in document.get("providers", []):
        if not isinstance(entry, dict) or not entry.get("name"):
            continue
        providers.append(
            {
                "id": str(entry["name"]).replace("_", "-"),
                "roles": ["mail"],
                "weight": int(entry.get("weight", 1)),
                "hostname_patterns": list(entry.get("hostname_patterns", [])),
                "ipv4_prefixes": list(entry.get("prefixes", [])),
                "ptr_templates": list(entry.get("ptr_templates", [])),
                "tls_profile": "public-mail",
                "traits": {"persona": "mail_relay", "user_agent_family": "smtp"},
                "source": f"legacy:{_LEGACY_MAIL_PATH}",
            }
        )
    translated: dict[str, Any] = {"providers": providers}
    if "reserved_replacement_domains" in document:
        translated["reserved_replacement_domains"] = list(document["reserved_replacement_domains"])
    return translated


def _translate_network_identity_entries(
    entries: object,
    *,
    role: str,
    provider: str,
    relative_path: str,
) -> dict[str, Any]:
    identities: list[dict[str, Any]] = []
    if not isinstance(entries, list):
        return {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("ip"):
            continue
        name = str(entry.get("name") or "").strip().lower().rstrip(".")
        traits = {key: value for key, value in entry.items() if key not in {"ip", "weight", "name"}}
        if name:
            traits["name"] = name
        identities.append(
            {
                "ip": str(entry["ip"]),
                "provider": provider,
                "weight": int(entry.get("weight", 1)),
                "forward_names": [name] if name else [],
                "ptr": name,
                "traits": traits,
                "source": f"compatibility:{relative_path}",
            }
        )
    return {"roles": [{"id": role, "identities": identities}]} if identities else {}


def translate_dns_registry_public_identities(document: dict[str, Any]) -> dict[str, Any]:
    """Translate the former DNS-registry CDN range field into a canonical patch."""

    ranges = document.get("cdn_ranges")
    if not isinstance(ranges, list):
        return {}
    prefixes = [
        [int(value[0]), int(value[1]), 0, 255]
        for value in ranges
        if isinstance(value, list) and len(value) == 2
    ]
    if not prefixes:
        return {}
    return {
        "providers": [
            {
                "id": "compatibility-cdn",
                "roles": ["cdn"],
                "ipv4_prefixes": prefixes,
                "tls_profile": "cdn-edge",
                "traits": {"persona": "cdn_edge", "user_agent_family": "none"},
                "source": f"compatibility:{_DNS_REGISTRY_PATH}",
            }
        ],
        "roles": [{"id": "cdn", "providers": ["compatibility-cdn"]}],
    }


def _overlay_document(relative_path: str) -> dict[str, Any] | None:
    effective = current_effective_config()
    if effective is not None and not uses_ambient_overlay_compat():
        return project_overlay_document(relative_path)
    overlay_root = get_overlay_directory()
    if overlay_root is None:
        return None
    path = overlay_root / relative_path
    if not path.is_file() or not path.resolve().is_relative_to(overlay_root.resolve()):
        return None
    value = load_yaml_file(path)
    return value if isinstance(value, dict) else None


def _with_overlay_provenance(document: dict[str, Any], relative_path: str) -> dict[str, Any]:
    """Attach canonical project-overlay provenance to supplied identity records."""

    annotated = deepcopy(document)
    source = f"project-overlay:{relative_path}"
    for provider in annotated.get("providers", []):
        if isinstance(provider, dict):
            provider.setdefault("source", source)
    for role in annotated.get("roles", []):
        if not isinstance(role, dict):
            continue
        for identity in role.get("identities", []):
            if isinstance(identity, dict):
                identity.setdefault("source", source)
    return annotated


def load_public_identity_profiles() -> dict[str, Any]:
    """Load and validate the canonical registry with translated 2.x overlays."""

    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    found, packaged = packaged_default_document(_CONFIG_PATH)
    data = packaged if found else load_yaml_file(_CONFIG_PATH)
    if not isinstance(data, dict):
        raise ValueError("public_identity_profiles.yaml must contain a mapping")
    legacy_external = _overlay_document(_LEGACY_EXTERNAL_PATH)
    if legacy_external is not None:
        data = _merge_registry(
            data,
            translate_external_actor_profiles(legacy_external),
            canonical_overlay=False,
        )
    legacy_mail = _overlay_document(_LEGACY_MAIL_PATH)
    if legacy_mail is not None:
        data = _merge_registry(
            data,
            translate_mail_public_identities(legacy_mail),
            canonical_overlay=False,
        )
    network_params = _overlay_document(_NETWORK_PARAMS_PATH)
    if network_params is not None:
        for field, role, provider in (
            ("public_dns_resolvers", "dns", "public-dns"),
            ("public_ntp_servers", "ntp", "public-ntp"),
        ):
            patch = _translate_network_identity_entries(
                network_params.get(field),
                role=role,
                provider=provider,
                relative_path=_NETWORK_PARAMS_PATH,
            )
            if patch:
                data = _merge_registry(data, patch, canonical_overlay=False)
    dns_registry = _overlay_document(_DNS_REGISTRY_PATH)
    if dns_registry is not None:
        patch = translate_dns_registry_public_identities(dns_registry)
        if patch:
            data = _merge_registry(data, patch, canonical_overlay=False)
    canonical = _overlay_document(_CONFIG_RELATIVE_PATH)
    if canonical is not None:
        data = _merge_registry(
            data,
            _with_overlay_provenance(canonical, _CONFIG_RELATIVE_PATH),
            canonical_overlay=True,
        )
    validated = PublicIdentityProfilesConfig.model_validate(data)
    _CACHED_DATA = validated.model_dump(mode="python")
    return _CACHED_DATA


def reset_public_identity_profiles_cache() -> None:
    """Clear the compatibility loader cache for tests and effective-config scopes."""

    global _CACHED_DATA
    _CACHED_DATA = None


def consumed_legacy_public_identity_overlays() -> tuple[str, ...]:
    """Return user-owned legacy identity files present in the active project snapshot."""

    consumed: list[str] = []
    external = _overlay_document(_LEGACY_EXTERNAL_PATH)
    if external is not None and any(
        isinstance(external.get(field), list) and bool(external[field])
        for field in ("logon_source_ips", "failed_logon_source_ips", "connection_c2_ips")
    ):
        consumed.append(_LEGACY_EXTERNAL_PATH)
    mail = _overlay_document(_LEGACY_MAIL_PATH)
    if mail is not None and bool(mail.get("providers") or mail.get("reserved_replacement_domains")):
        consumed.append(_LEGACY_MAIL_PATH)
    return tuple(consumed)


class PublicIdentityRegistry:
    """Immutable deterministic public identity resolver for one scenario run."""

    __slots__ = ("_document", "_providers", "_roles", "_sealed")

    def __init__(self, document: dict[str, Any] | None = None) -> None:
        validated = PublicIdentityProfilesConfig.model_validate(
            document if document is not None else load_public_identity_profiles()
        )
        object.__setattr__(self, "_document", validated)
        object.__setattr__(
            self,
            "_providers",
            MappingProxyType({entry.id: entry for entry in validated.providers}),
        )
        object.__setattr__(
            self,
            "_roles",
            MappingProxyType({entry.id: entry for entry in validated.roles}),
        )
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("PublicIdentityRegistry is immutable")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        raise AttributeError("PublicIdentityRegistry is immutable")

    @classmethod
    def from_scenario(cls, _scenario: object) -> PublicIdentityRegistry:
        """Create the scenario-scoped registry; authored bindings are supplied at use sites."""

        return cls()

    @property
    def role_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._roles))

    @property
    def provider_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))

    @property
    def reserved_replacement_domains(self) -> tuple[str, ...]:
        return tuple(self._document.reserved_replacement_domains)

    def _provider_for_hostname(self, role: str, hostname: str) -> str | None:
        lowered = hostname.lower().rstrip(".")
        for provider_id in self._roles[role].providers:
            provider = self._providers[provider_id]
            if any(
                lowered == pattern or lowered.endswith(f".{pattern}") or pattern in lowered
                for pattern in provider.hostname_patterns
            ):
                return provider_id
        return None

    def _provider_for_ip(self, role: str, ip: str) -> str | None:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        try:
            first, second, third, _fourth = (int(value) for value in parts)
        except ValueError:
            return None
        for provider_id in self._roles[role].providers:
            for p_first, p_second, third_min, third_max in self._providers[
                provider_id
            ].ipv4_prefixes:
                if first == p_first and second == p_second and third_min <= third <= third_max:
                    return provider_id
        return None

    def bind(
        self,
        role: PublicIdentityRole | str,
        semantic_key: str,
        *,
        authored_ip: str | None = None,
        forward_hostname: str | None = None,
        provider_hint: str | None = None,
        prefer_fixed: bool = True,
        authored: bool | None = None,
    ) -> PublicIdentityBinding:
        """Resolve one role through a stable semantic key without mutable RNG state."""

        if role not in self._roles:
            raise KeyError(f"unknown public identity role: {role}")
        role_profile = self._roles[role]
        seed = _stable_seed(f"public_identity:{role}:{semantic_key}")
        identity = next(
            (entry for entry in role_profile.identities if authored_ip and entry.ip == authored_ip),
            None,
        )
        if authored_ip is None and prefer_fixed and role_profile.identities:
            rng = random.Random(seed)
            weights = [entry.weight for entry in role_profile.identities]
            identity = rng.choices(role_profile.identities, weights=weights, k=1)[0]
        provider_id = provider_hint
        if provider_id is None and forward_hostname:
            provider_id = self._provider_for_hostname(str(role), forward_hostname)
        if provider_id is None and authored_ip:
            provider_id = self._provider_for_ip(str(role), authored_ip)
        if provider_id is None and identity is not None:
            provider_id = identity.provider
        if provider_id not in role_profile.providers:
            providers = [self._providers[value] for value in role_profile.providers]
            rng = random.Random(seed ^ 0xA17C0DE)
            provider_id = rng.choices(providers, weights=[p.weight for p in providers], k=1)[0].id
        provider = self._providers[provider_id]
        ip = authored_ip or (identity.ip if identity is not None else "")
        if not ip:
            if not provider.ipv4_prefixes:
                raise ValueError(f"provider {provider.id!r} has no address pool for role {role!r}")
            rng = random.Random(seed ^ 0x1D3A71F1)
            first, second, third_min, third_max = rng.choice(provider.ipv4_prefixes)
            ip = f"{first}.{second}.{rng.randint(third_min, third_max)}.{rng.randint(1, 254)}"
        forward_names = tuple(identity.forward_names if identity else provider.forward_names)
        if forward_hostname:
            forward_names = (forward_hostname.lower().rstrip("."),)
        ptr = identity.ptr if identity else ""
        if not ptr and provider.ptr_templates:
            octets = ip.split(".")
            rng = random.Random(seed ^ 0x5072)
            domain = _domain_from_hostname(forward_names[0] if forward_names else provider.id)
            ptr = rng.choice(provider.ptr_templates).format(
                domain=domain,
                third=octets[2],
                fourth=octets[3],
                slot=1 + rng.randrange(4),
            )
        traits = dict(provider.traits)
        if identity is not None:
            traits.update(identity.traits)
        provenance_values = [
            provider.source,
            identity.source if identity is not None else provider.source,
        ]
        is_authored = authored_ip is not None if authored is None else authored
        if is_authored:
            provenance_values.append("scenario-authored")
        provenance = tuple(dict.fromkeys(provenance_values))
        payload = {
            "semantic_key": semantic_key,
            "ip": ip,
            "role": role,
            "provider": provider.id,
            "forward_names": forward_names,
            "ptr": ptr,
            "tls_profile": identity.tls_profile
            if identity and identity.tls_profile
            else provider.tls_profile,
            "traits": traits,
            "authored": is_authored,
            "provenance": provenance,
        }
        return PublicIdentityBinding(
            semantic_key=semantic_key,
            ip=ip,
            role=str(role),
            provider=provider.id,
            forward_names=forward_names,
            ptr=ptr,
            tls_profile=str(payload["tls_profile"]),
            traits=tuple(sorted(traits.items())),
            authored=is_authored,
            provenance=provenance,
            fingerprint=_canonical_hash(payload),
        )

    def fixed_bindings(self, role: PublicIdentityRole | str) -> tuple[PublicIdentityBinding, ...]:
        """Return every fixed identity for information and infrastructure consumers."""

        profile = self._roles[role]
        return tuple(
            self.bind(role, f"fixed:{entry.ip}", authored_ip=entry.ip, authored=False)
            for entry in profile.identities
        )

    def fixed_binding_records(
        self,
        role: PublicIdentityRole | str,
    ) -> tuple[tuple[PublicIdentityBinding, int], ...]:
        """Return immutable fixed bindings with their configured weights."""

        profile = self._roles[role]
        return tuple(
            (
                self.bind(
                    role,
                    f"fixed:{entry.ip}",
                    authored_ip=entry.ip,
                    authored=False,
                ),
                entry.weight,
            )
            for entry in profile.identities
        )

    def provider_prefixes(
        self, role: PublicIdentityRole | str
    ) -> tuple[tuple[int, int, int, int], ...]:
        """Return role-scoped provider ranges without exposing mutable config lists."""

        return tuple(
            prefix
            for provider_id in self._roles[role].providers
            for prefix in self._providers[provider_id].ipv4_prefixes
        )

    def roles_may_share(self, left: str, right: str) -> bool:
        """Return whether the registry explicitly permits cross-role infrastructure reuse."""

        return (
            left == right
            or right in self._roles[left].share_with_roles
            or left in self._roles[right].share_with_roles
        )


def default_public_identity_registry() -> PublicIdentityRegistry:
    """Return a registry view over the active scenario/effective-config scope."""

    return PublicIdentityRegistry()


def _domain_from_hostname(hostname: str) -> str:
    lowered = public_safe_mail_hostname(hostname)
    labels = [label for label in lowered.split(".") if label]
    if len(labels) <= 2:
        return lowered or "mail.postrelay.net"
    if labels[0] in {"mail", "mail1", "mail2", "mx", "mx1", "mx2", "smtp", "smtp1", "smtp2"}:
        return ".".join(labels[1:])
    return ".".join(labels[-2:])


def public_safe_mail_hostname(hostname: str) -> str:
    """Move reserved authored mail names into a stable realistic public namespace."""

    lowered = hostname.lower().rstrip(".")
    if not lowered:
        return "mail.postrelay.net"
    for suffix in (*_RESERVED_DOCUMENTATION_DOMAINS, *_RESERVED_PUBLIC_SUFFIXES):
        if lowered == suffix or lowered.endswith(f".{suffix}"):
            prefix = lowered[: -len(suffix)].strip(".")
            replacements = default_public_identity_registry().reserved_replacement_domains
            domain = replacements[
                _stable_seed(f"mail_reserved_replacement:{lowered}") % len(replacements)
            ]
            return f"{prefix}.{domain}" if prefix else f"mail.{domain}"
    return lowered


def generate_public_mail_ip(identity_key: str, forward_hostname: str | None = None) -> str:
    """Return a stable mail-role IP from the canonical registry."""

    safe_hostname = public_safe_mail_hostname(forward_hostname or "") if forward_hostname else None
    return (
        default_public_identity_registry()
        .bind(
            "mail",
            identity_key.lower(),
            forward_hostname=safe_hostname,
        )
        .ip
    )


def public_mail_ptr_name(ip: str, forward_hostname: str | None) -> str:
    """Return the canonical mail binding's PTR name."""

    safe_hostname = public_safe_mail_hostname(forward_hostname or "") if forward_hostname else None
    registry = default_public_identity_registry()
    provider = registry._provider_for_ip("mail", ip)
    if provider is None:
        return ""
    binding = registry.bind(
        "mail",
        f"mail-ptr:{ip}:{safe_hostname or ''}",
        authored_ip=ip,
        forward_hostname=safe_hostname,
        provider_hint=provider,
        authored=False,
    )
    return binding.ptr


def public_mail_provider_name_for_ip(ip: str) -> str:
    registry = default_public_identity_registry()
    return _legacy_mail_provider_name(registry._provider_for_ip("mail", ip))


def public_mail_provider_name_for_hostname(hostname: str) -> str:
    registry = default_public_identity_registry()
    return _legacy_mail_provider_name(
        registry._provider_for_hostname("mail", public_safe_mail_hostname(hostname))
    )


def is_public_mail_ip(ip: str) -> bool:
    return bool(public_mail_provider_name_for_ip(ip))


def _legacy_mail_provider_name(provider_id: str | None) -> str:
    return {
        "google-workspace": "google_workspace",
        "microsoft-365": "microsoft_365",
        "amazon-ses": "amazon_ses",
    }.get(provider_id or "", provider_id or "")


def legacy_external_actor_projection() -> dict[str, Any]:
    """Project canonical role entries through the retained 2.x Python API."""

    registry = default_public_identity_registry()
    return {
        legacy: [
            {"ip": binding.ip, "weight": entry.weight}
            for entry, binding in zip(
                registry._roles[role].identities,
                registry.fixed_bindings(role),
                strict=True,
            )
        ]
        for legacy, role in {
            "logon_source_ips": "external_logon",
            "failed_logon_source_ips": "failed_logon",
            "connection_c2_ips": "c2",
        }.items()
    }


def legacy_mail_projection() -> dict[str, Any]:
    """Project canonical mail providers through the retained 2.x Python API."""

    registry = default_public_identity_registry()
    providers = []
    for provider_id in registry._roles["mail"].providers:
        provider = registry._providers[provider_id]
        providers.append(
            {
                "name": _legacy_mail_provider_name(provider.id),
                "weight": provider.weight,
                "hostname_patterns": list(provider.hostname_patterns),
                "prefixes": [list(prefix) for prefix in provider.ipv4_prefixes],
                "ptr_templates": list(provider.ptr_templates),
            }
        )
    return {
        "reserved_replacement_domains": list(registry.reserved_replacement_domains),
        "providers": providers,
    }


def pick_public_identity_ip(role: PublicIdentityRole | str, semantic_key: str) -> str:
    """Return the canonical role binding's IP for production consumers."""

    return default_public_identity_registry().bind(role, semantic_key).ip


def legacy_pool_role(pool: str) -> str:
    """Map the retained external-actor helper's pool name to a canonical role."""

    return {
        "logon_source_ips": "external_logon",
        "failed_logon_source_ips": "failed_logon",
        "connection_c2_ips": "c2",
    }[pool]


def authored_public_identity_reuse(
    scenario: object,
    registry: PublicIdentityRegistry | None = None,
) -> tuple[AuthoredPublicIdentityReuse, ...]:
    """Find authored public IPs reused across contradictory semantic roles."""

    active_registry = registry or PublicIdentityRegistry.from_scenario(scenario)
    uses: dict[str, list[tuple[str, str]]] = {}

    def record(value: object, role: str, field_path: str) -> None:
        if not isinstance(value, str) or not value:
            return
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return
        if address.is_global:
            uses.setdefault(str(address), []).append((role, field_path))

    for group_name in ("storyline", "red_herrings"):
        group = getattr(scenario, group_name, None)
        if not isinstance(group, list):
            continue
        for event_index, event in enumerate(group):
            specs = getattr(event, "events", None)
            if not isinstance(specs, list):
                continue
            for spec_index, spec in enumerate(specs):
                event_type = getattr(spec, "type", "")
                base = f"{group_name}[{event_index}].events[{spec_index}]"
                if event_type == "logon":
                    record(getattr(spec, "source_ip", None), "external_logon", f"{base}.source_ip")
                elif event_type == "failed_logon":
                    record(getattr(spec, "source_ip", None), "failed_logon", f"{base}.source_ip")
                elif event_type in {"port_scan", "web_scan"}:
                    record(getattr(spec, "source_ip", None), "scanner", f"{base}.source_ip")
                elif event_type == "connection":
                    record(getattr(spec, "dst_ip", None), "c2", f"{base}.dst_ip")

    findings: list[AuthoredPublicIdentityReuse] = []
    for ip, entries in sorted(uses.items()):
        roles = tuple(sorted({role for role, _path in entries}))
        if len(roles) < 2:
            continue
        contradictory = any(
            not active_registry.roles_may_share(left, right)
            for index, left in enumerate(roles)
            for right in roles[index + 1 :]
        )
        if contradictory:
            findings.append(
                AuthoredPublicIdentityReuse(
                    ip=ip,
                    roles=roles,
                    field_paths=tuple(path for _role, path in entries),
                )
            )
    return tuple(findings)
