# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Validate EvidenceForge config files for integrity and cross-references.

Runs 27 checks across all config YAML files (activity, personas, formats,
evaluation) and reports errors, warnings, and info items.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from evidenceforge.config import (
    get_activity_directory,
    get_evaluation_directory,
    get_formats_directory,
    get_personas_directory,
)

VALID_DNS_TAGS = frozenset(
    {
        "web",
        "saas",
        "cdn",
        "email",
        "git",
        "background",
        "windows",
        "linux",
        "internal",
        "storage",
        "dev",
        "social",
    }
)

VALID_RISK_PROFILES = frozenset({"low", "medium", "high"})
VALID_BROWSING_INTENSITIES = frozenset({"light", "normal", "heavy"})

REQUIRED_PERSONA_FIELDS = frozenset(
    {
        "name",
        "description",
        "typical_activities",
        "work_hours",
        "application_usage",
        "risk_profile",
        "browsing_intensity",
    }
)


@dataclass
class Issue:
    """A single validation issue."""

    severity: str  # ERROR, WARNING, INFO
    file: str
    message: str


@dataclass
class ValidationResult:
    """Result of config validation."""

    issues: list[Issue] = field(default_factory=list)
    files_checked: int = 0

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "ERROR"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "WARNING"]

    @property
    def infos(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "INFO"]


def _safe_load_yaml(path: Path) -> tuple[Any, str | None]:
    """Load YAML file, returning (data, error_message)."""
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        return data, None
    except Exception as e:
        return None, str(e)


def validate_config() -> ValidationResult:
    """Run all 27 validation checks across config files.

    Uses the same loader paths the engine uses (including overlay merges).
    """
    result = ValidationResult()
    activity_dir = get_activity_directory()
    personas_dir = get_personas_directory()
    formats_dir = get_formats_directory()
    evaluation_dir = get_evaluation_directory()

    # Load all the data we need (through the loaders, which include overlay merges)
    from evidenceforge.generation.activity.application_catalog import load_catalog
    from evidenceforge.generation.activity.dns_registry import load_dns_registry
    from evidenceforge.generation.activity.process_network import load_process_network_map
    from evidenceforge.generation.activity.spawn_rules import load_spawn_rules
    from evidenceforge.generation.activity.traffic_profiles import load_traffic_profiles

    dns_data = load_dns_registry()
    catalog_data = load_catalog()
    traffic_data = load_traffic_profiles()
    spawn_data = load_spawn_rules()
    process_net_data = load_process_network_map()

    # Collect file count
    yaml_files: list[Path] = []
    for d in [activity_dir, personas_dir, formats_dir, evaluation_dir]:
        if d.is_dir():
            yaml_files.extend(d.glob("*.yaml"))
    result.files_checked = len(yaml_files)

    # --- Checks 1-2: YAML Health ---
    for path in yaml_files:
        data, err = _safe_load_yaml(path)
        if err:
            result.issues.append(Issue("ERROR", path.name, f"YAML parse error: {err}"))
        elif data is None:
            result.issues.append(Issue("ERROR", path.name, "File is empty"))

    # --- Checks 3-6: DNS Registry Integrity ---
    domains = dns_data.get("domains", [])
    seen_domains: dict[str, int] = {}
    dns_domain_set: set[str] = set()
    all_dns_tags: set[str] = set()

    for i, entry in enumerate(domains):
        domain = entry.get("domain", "")
        tags = entry.get("tags", [])
        ips = entry.get("ips", [])

        # Check 3: Duplicate domains
        if domain in seen_domains:
            result.issues.append(
                Issue("ERROR", "dns_registry.yaml", f'Duplicate domain "{domain}"')
            )
        seen_domains[domain] = i
        dns_domain_set.add(domain)

        # Check 4: Empty tags
        if not tags:
            result.issues.append(
                Issue("ERROR", "dns_registry.yaml", f'Domain "{domain}" has empty tags')
            )

        # Check 5: Empty IPs
        if not ips:
            result.issues.append(
                Issue("ERROR", "dns_registry.yaml", f'Domain "{domain}" has empty IPs')
            )

        # Check 6: Invalid tags
        for tag in tags:
            all_dns_tags.add(tag)
            if tag not in VALID_DNS_TAGS:
                result.issues.append(
                    Issue(
                        "WARNING", "dns_registry.yaml", f'Domain "{domain}" has invalid tag "{tag}"'
                    )
                )

    # --- Checks 7-10: DNS → Downstream Cascade ---
    # Load proxy templates and site maps
    proxy_data, _ = _safe_load_yaml(activity_dir / "proxy_uri_templates.yaml")
    site_data, _ = _safe_load_yaml(activity_dir / "site_maps.yaml")

    proxy_domains = (
        set((proxy_data or {}).get("domains", {}).keys())
        if isinstance((proxy_data or {}).get("domains"), dict)
        else set()
    )
    site_domains = (
        set((site_data or {}).get("domains", {}).keys())
        if isinstance((site_data or {}).get("domains"), dict)
        else set()
    )

    # Check 7: Orphaned proxy templates
    for domain in proxy_domains - dns_domain_set:
        result.issues.append(
            Issue(
                "WARNING",
                "proxy_uri_templates.yaml",
                f'Domain "{domain}" not found in dns_registry',
            )
        )

    # Check 8: Orphaned site maps
    for domain in site_domains - dns_domain_set:
        result.issues.append(
            Issue("WARNING", "site_maps.yaml", f'Domain "{domain}" not found in dns_registry')
        )

    # Checks 9-10: Missing proxy templates / site maps for web/saas domains
    web_saas_domains = {
        entry["domain"] for entry in domains if set(entry.get("tags", [])) & {"web", "saas"}
    }
    for domain in web_saas_domains - proxy_domains:
        result.issues.append(
            Issue(
                "INFO",
                "dns_registry.yaml",
                f'Domain "{domain}" (web/saas) has no proxy_uri_templates entry',
            )
        )

    for domain in web_saas_domains - site_domains:
        result.issues.append(
            Issue(
                "INFO", "dns_registry.yaml", f'Domain "{domain}" (web/saas) has no site_maps entry'
            )
        )

    # --- Checks 11-13: Traffic Profile Integrity ---
    role_traffic = traffic_data.get("role_traffic", {})
    persona_traffic = traffic_data.get("persona_traffic", {})

    # Collect all dns_tags used in traffic profiles
    all_traffic_entries = []
    for _role_name, role_data in role_traffic.items():
        for direction in ["outbound", "inbound"]:
            entries = role_data.get(direction, []) if isinstance(role_data, dict) else []
            all_traffic_entries.extend(entries)
    for _persona_name, persona_entries in persona_traffic.items():
        if isinstance(persona_entries, dict):
            for direction in ["outbound", "inbound"]:
                all_traffic_entries.extend(persona_entries.get(direction, []))
        elif isinstance(persona_entries, list):
            all_traffic_entries.extend(persona_entries)

    # Check 11: Orphaned dns_tags
    for entry in all_traffic_entries:
        for tag in entry.get("dns_tags", []):
            if tag not in all_dns_tags:
                result.issues.append(
                    Issue(
                        "WARNING",
                        "traffic_profiles.yaml",
                        f'dns_tag "{tag}" not used by any domain in dns_registry',
                    )
                )

    # Check 12: Orphaned persona_traffic keys
    persona_names = _get_persona_names(personas_dir)
    for persona_name in persona_traffic:
        if persona_name not in persona_names and persona_name != "_default":
            result.issues.append(
                Issue(
                    "WARNING",
                    "traffic_profiles.yaml",
                    f'persona_traffic key "{persona_name}" has no matching persona file',
                )
            )

    # Check 13: Missing required fields in connection entries
    for entry in all_traffic_entries:
        for field_name in ["role", "port", "weight"]:
            if field_name not in entry and entry.get("proto") != "icmp":
                result.issues.append(
                    Issue(
                        "ERROR",
                        "traffic_profiles.yaml",
                        f"Connection entry missing required field: {field_name}",
                    )
                )

    # --- Checks 14-17: Application Catalog Integrity ---
    apps = catalog_data.get("applications", [])
    seen_app_ids: set[str] = set()
    all_app_ids: set[str] = set()

    for app in apps:
        app_id = app.get("id", "")

        # Check 14: Duplicate app IDs
        if app_id in seen_app_ids:
            result.issues.append(
                Issue("ERROR", "application_catalog.yaml", f'Duplicate app id "{app_id}"')
            )
        seen_app_ids.add(app_id)
        all_app_ids.add(app_id)

        # Check 15: Orphaned persona references
        for persona in app.get("personas", []):
            if persona not in persona_names and persona != "default":
                result.issues.append(
                    Issue(
                        "WARNING",
                        "application_catalog.yaml",
                        f'App "{app_id}" references persona "{persona}" with no matching file',
                    )
                )

        # Check 16-17: Image paths
        for os_name, platform in app.get("platforms", {}).items():
            image_path = platform.get("image_path", "")
            if not image_path:
                # Check 16: Missing image path
                result.issues.append(
                    Issue(
                        "ERROR",
                        "application_catalog.yaml",
                        f'App "{app_id}" missing image_path for {os_name}',
                    )
                )
            elif "/" not in image_path and "\\" not in image_path:
                # Check 17: Bare filename
                result.issues.append(
                    Issue(
                        "WARNING",
                        "application_catalog.yaml",
                        f'App "{app_id}" has bare filename image_path for {os_name}: "{image_path}"',
                    )
                )

    # --- Checks 18-20: Process Chain ---
    # Collect all exe basenames from spawn rules
    spawn_children: set[str] = set()
    for os_rules in [spawn_data.get("windows", {}), spawn_data.get("linux", {})]:
        for _parent, parent_data in os_rules.items():
            if isinstance(parent_data, dict):
                for child in parent_data.get("children", []):
                    spawn_children.add(child)

    # Collect all exe basenames from app catalog
    catalog_exes: set[str] = set()
    for app in apps:
        for platform in app.get("platforms", {}).values():
            image_path = platform.get("image_path", "")
            if image_path:
                basename = image_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                catalog_exes.add(basename)

    # Load system process exes
    sys_proc_data, _ = _safe_load_yaml(activity_dir / "system_processes.yaml")
    system_exes: set[str] = set()
    if sys_proc_data:
        for task in sys_proc_data.get("scheduled_tasks", []):
            image = task.get("image", "")
            if image:
                system_exes.add(image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1])
        for role_data in sys_proc_data.get("system_services", {}).values():
            if isinstance(role_data, list):
                for proc in role_data:
                    image = proc.get("image", "")
                    if image:
                        system_exes.add(image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1])

    known_exes = catalog_exes | system_exes

    # Check 18: Orphaned spawn rule children
    for child in spawn_children - known_exes:
        result.issues.append(
            Issue(
                "WARNING",
                "spawn_rules.yaml",
                f'Child "{child}" not found in application_catalog or system_processes',
            )
        )

    # Check 19: Missing spawn rules (apps not in any spawn rule)
    spawn_all_entries: set[str] = set()
    for os_rules in [spawn_data.get("windows", {}), spawn_data.get("linux", {})]:
        spawn_all_entries.update(os_rules.keys())
        for parent_data in os_rules.values():
            if isinstance(parent_data, dict):
                spawn_all_entries.update(parent_data.get("children", []))

    for exe in catalog_exes - spawn_all_entries:
        result.issues.append(
            Issue(
                "INFO", "application_catalog.yaml", f'App exe "{exe}" not listed in any spawn rule'
            )
        )

    # Check 20: Orphaned process_network_map entries
    pnm_exes: set[str] = set()
    if isinstance(process_net_data, list):
        for mapping in process_net_data:
            pnm_exes.update(mapping.get("exe", []))
    for exe in pnm_exes - known_exes:
        result.issues.append(
            Issue(
                "WARNING",
                "process_network_map.yaml",
                f'Exe "{exe}" not found in application_catalog or system_processes',
            )
        )

    # --- Checks 21-25: Persona Integrity ---
    for yaml_file in sorted(personas_dir.glob("*.yaml")):
        data, err = _safe_load_yaml(yaml_file)
        if err or not data:
            continue  # Already caught in YAML health check

        name = data.get("name", "")
        stem = yaml_file.stem

        # Check 21: Filename/name mismatch
        if name and name != stem:
            result.issues.append(
                Issue(
                    "ERROR",
                    yaml_file.name,
                    f'Persona name "{name}" does not match filename "{stem}"',
                )
            )

        # Check 22: Missing required fields
        for req_field in REQUIRED_PERSONA_FIELDS:
            if req_field not in data:
                result.issues.append(
                    Issue("ERROR", yaml_file.name, f"Missing required field: {req_field}")
                )

        # Check 23: Invalid risk_profile
        risk = data.get("risk_profile", "")
        if risk and risk not in VALID_RISK_PROFILES:
            result.issues.append(Issue("ERROR", yaml_file.name, f'Invalid risk_profile: "{risk}"'))

        # Check 24: Invalid browsing_intensity
        intensity = data.get("browsing_intensity", "")
        if intensity and intensity not in VALID_BROWSING_INTENSITIES:
            result.issues.append(
                Issue("ERROR", yaml_file.name, f'Invalid browsing_intensity: "{intensity}"')
            )

    # Check 25: Phantom personas (referenced but no file)
    all_referenced_personas: set[str] = set()
    for app in apps:
        all_referenced_personas.update(app.get("personas", []))
    for persona_name in persona_traffic:
        all_referenced_personas.add(persona_name)
    all_referenced_personas.discard("default")
    all_referenced_personas.discard("_default")

    for persona in all_referenced_personas - persona_names:
        result.issues.append(
            Issue(
                "WARNING",
                "application_catalog/traffic_profiles",
                f'Persona "{persona}" referenced but no persona file exists',
            )
        )

    # --- Checks 26-27: Evaluation Rule Integrity ---
    format_names = {f.stem for f in formats_dir.glob("*.yaml")}
    format_fields: dict[str, set[str]] = {}
    for fmt_file in formats_dir.glob("*.yaml"):
        fmt_data, _ = _safe_load_yaml(fmt_file)
        if fmt_data:
            fields = set()
            for f in fmt_data.get("fields", []):
                if isinstance(f, dict) and "name" in f:
                    fields.add(f["name"])
            format_fields[fmt_file.stem] = fields

    for eval_file in evaluation_dir.glob("*.yaml"):
        eval_data, err = _safe_load_yaml(eval_file)
        if err or not eval_data:
            continue

        if eval_file.stem == "causal_pairs":
            # causal_pairs has a different structure
            for pair in eval_data.get("pairs", []):
                for direction in ["before", "after"]:
                    fmt = pair.get(direction, {}).get("format", "")
                    if fmt and fmt not in format_names:
                        result.issues.append(
                            Issue(
                                "ERROR",
                                eval_file.name,
                                f'Causal pair references unknown format "{fmt}"',
                            )
                        )
        else:
            # co_occurrence and distributions are keyed by format name
            for fmt_key in eval_data:
                # Check 27: Invalid format references
                if fmt_key not in format_names:
                    result.issues.append(
                        Issue(
                            "ERROR", eval_file.name, f'Rules under unknown format key "{fmt_key}"'
                        )
                    )
                    continue

                # Check 26: Invalid field references
                known_fields = format_fields.get(fmt_key, set())
                if not known_fields:
                    continue

                rules = eval_data[fmt_key]
                if isinstance(rules, list):
                    for rule in rules:
                        # co_occurrence rules reference fields in condition and checks
                        for check_field in _extract_field_refs(rule):
                            if check_field not in known_fields:
                                result.issues.append(
                                    Issue(
                                        "WARNING",
                                        eval_file.name,
                                        f'Rule references field "{check_field}" not in {fmt_key} format',
                                    )
                                )

    # Deduplicate issues (some checks may flag the same thing multiple times)
    seen_issues: set[tuple[str, str, str]] = set()
    deduped: list[Issue] = []
    for issue in result.issues:
        key = (issue.severity, issue.file, issue.message)
        if key not in seen_issues:
            seen_issues.add(key)
            deduped.append(issue)
    result.issues = deduped

    return result


def _get_persona_names(personas_dir: Path) -> set[str]:
    """Get set of all persona names from the personas directory."""
    from evidenceforge.utils.personas import load_builtin_personas

    return {p["name"] for p in load_builtin_personas() if "name" in p}


def _extract_field_refs(rule: dict) -> list[str]:
    """Extract field name references from a co_occurrence or distribution rule."""
    fields = []
    # Distribution rules have a "field" key
    if "field" in rule:
        fields.append(rule["field"])
    # Co-occurrence rules have "condition" fields and "checks" with "field"
    if "condition" in rule:
        for key in rule["condition"]:
            if key != "exclude":
                fields.append(key)
    if "checks" in rule:
        for check in rule["checks"]:
            if "field" in check:
                fields.append(check["field"])
    return fields
