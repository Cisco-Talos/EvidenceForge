# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for Scenario 2.0 composition, packs, and authoritative artifacts."""

from __future__ import annotations

import copy
import random
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml

from evidenceforge.composition import compile_scenario
from evidenceforge.composition.artifacts import (
    build_resolved_document,
    serialize_resolved_document,
    verify_generation_bundle,
    write_generation_manifest,
    write_resolved_scenario,
)
from evidenceforge.composition.models import EffectiveConfig, PackReference
from evidenceforge.composition.packs import CATALOG_FILES, PackRepository
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.generation.activity.dns_registry import load_dns_registry, pick_domain_and_ip
from evidenceforge.generation.activity.network import REVERSE_DNS
from evidenceforge.generation.activity.traffic_profiles import load_traffic_profiles
from evidenceforge.generation.storage_world import StorageWorldModel, _load_catalog_config
from evidenceforge.models.exceptions import PackError, SchemaValidationError
from evidenceforge.utils import load_yaml
from evidenceforge.utils.assets import load_email_corpus_yaml

_MINIMAL = Path("tests/fixtures/scenarios/minimal.yaml")
_FINANCE = Path("tests/fixtures/scenarios/finance-industry-pack.yaml")
_NORTHSTAR = Path("tests/fixtures/scenarios/northstar-health-pack.yaml")
_NORTHSTAR_LINUX = Path("tests/fixtures/scenarios/northstar-health-linux-pack.yaml")
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ITERATION_ARCHIVE = _PROJECT_ROOT / "scenarios/iteration-test-1_0/scenario.yaml"
_ITERATION_PACKED = _PROJECT_ROOT / "scenarios/iteration-test/scenario.yaml"


def _write_yaml(path: Path, data: dict) -> Path:
    """Write one test YAML mapping."""

    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def test_v1_compilation_never_constructs_pack_repository(monkeypatch) -> None:
    """Scenario 1.0 must remain pack-silent even when no repository is usable."""

    def fail_repository(*args, **kwargs):
        raise AssertionError("Scenario 1.0 attempted pack discovery")

    monkeypatch.setattr(PackRepository, "__init__", fail_repository)
    compiled = compile_scenario(_MINIMAL)

    assert compiled.authored_kind == "scenario-1.0"
    assert compiled.selected_packs == ()


def test_v2_monolithic_matches_v1_runtime_model(tmp_path: Path) -> None:
    """A no-pack Scenario 2.0 document retains monolithic authoring."""

    v1 = load_yaml(_MINIMAL)
    v2 = copy.deepcopy(v1)
    v2.pop("version", None)
    v2["scenario_version"] = "2.0"
    path = _write_yaml(tmp_path / "scenario.yaml", v2)

    compiled_v1 = compile_scenario(_MINIMAL)
    compiled_v2 = compile_scenario(path)
    v1_payload = compiled_v1.scenario.model_dump(mode="json")
    v2_payload = compiled_v2.scenario.model_dump(mode="json")
    v1_payload["version"] = "2.0"

    assert v2_payload == v1_payload
    assert compiled_v2.selected_packs == ()


def test_iteration_pack_migration_preserves_assessment_semantics() -> None:
    """The pack-backed assessment differs only in its intentional wrapper identity."""

    archived = compile_scenario(_ITERATION_ARCHIVE, project_root=_PROJECT_ROOT)
    packed = compile_scenario(_ITERATION_PACKED, project_root=_PROJECT_ROOT)

    assert packed.scenario.environment == archived.scenario.environment
    assert packed.scenario.baseline_activity == archived.scenario.baseline_activity
    assert packed.scenario.storyline == archived.scenario.storyline
    assert packed.scenario.red_herrings == archived.scenario.red_herrings
    assert packed.scenario.time_window == archived.scenario.time_window
    assert packed.scenario.generation_seed == archived.scenario.generation_seed
    assert packed.scenario.observation_profile == archived.scenario.observation_profile
    assert packed.scenario.output.logs == archived.scenario.output.logs
    assert packed.scenario.output.compression == archived.scenario.output.compression

    archived_payload = archived.scenario.model_dump(mode="json")
    packed_payload = packed.scenario.model_dump(mode="json")
    for payload in (archived_payload, packed_payload):
        payload.pop("version")
        payload.pop("name")
        payload["output"].pop("destination")
        assigned_personas = {
            user["persona"] for user in payload["environment"]["users"] if user["persona"]
        }
        payload["personas"] = sorted(
            (persona for persona in payload["personas"] if persona["name"] in assigned_personas),
            key=lambda persona: persona["name"],
        )

    assert packed_payload == archived_payload
    assert {
        (pack.source, pack.type, pack.name, pack.version) for pack in packed.selected_packs
    } == {
        ("package", "industry", "technology", "1.0.0"),
        (
            "project",
            "organization",
            "meridian-healthcare-solutions",
            "1.0.0",
        ),
    }
    assert {pack.location for pack in packed.selected_packs} == {
        "package:industry:technology@1.0.0",
        "project:organization:meridian-healthcare-solutions@1.0.0",
    }
    assert packed.provenance["organization_model_origins"]["environment.domain"] == (
        "model/environment.yaml"
    )
    assert packed.provenance["organization_model_origins"]["baseline_activity.intensity"] == (
        "model/baseline_activity.yaml"
    )
    assert (
        packed.provenance["catalog_origins"]["persona_catalog.technology:platform_engineer"]
        == "technology@1.0.0"
    )

    archived_personas = {persona.name for persona in archived.scenario.personas}
    packed_personas = {persona.name for persona in packed.scenario.personas}
    assigned_personas = {user.persona for user in packed.scenario.environment.users}
    assert packed_personas - archived_personas == {"technology:platform_engineer"}
    assert (packed_personas - archived_personas).isdisjoint(assigned_personas)
    assert all(
        assigned_personas.isdisjoint(traffic["data"]["audience"])
        for traffic in packed.effective_config.catalogs["traffic_catalog"].values()
    )


def test_organization_pack_brings_exact_industry_and_environment() -> None:
    """The sample organization resolves its pinned industry before its own model."""

    compiled = compile_scenario(_NORTHSTAR)

    assert [pack.name for pack in compiled.selected_packs] == [
        "healthcare",
        "northstar-health",
    ]
    assert {system.hostname for system in compiled.scenario.environment.systems} >= {
        "NSH-FILE-01",
        "NSH-MAIL-01",
    }
    assert compiled.scenario.environment.email is not None
    assert compiled.scenario.environment.storage.servers[0].system == "NSH-FILE-01"
    assert {user.persona for user in compiled.scenario.environment.users} == {
        "healthcare:clinical_coordinator",
        "northstar-health:northstar_it",
    }
    assert (
        compiled.scenario.environment.storage.servers[0].shares[0].preset
        == "healthcare:clinical-department"
    )
    with effective_config_scope(compiled.effective_config):
        assert "healthcare:clinical-department" in _load_catalog_config()["profiles"]
        assert any(
            entry["domain"] == "claims.healthcare.example"
            for entry in load_dns_registry()["domains"]
        )
        assert load_traffic_profiles()["pack_persona_traffic"]["healthcare:clinical_coordinator"][
            "healthcare:clinical-shift"
        ]["outbound"]

    with effective_config_scope(compiled.effective_config):
        world = StorageWorldModel.compile(compiled.scenario)
    assert all(share.system != "NSH-MAIL-01" for share in world.shares)


def test_northstar_linux_pack_compiles_cross_platform_storage() -> None:
    """Northstar 1.1 adds Samba and dual presentations while retaining Windows SMB."""

    compiled = compile_scenario(_NORTHSTAR_LINUX)
    with effective_config_scope(compiled.effective_config):
        world = StorageWorldModel.compile(compiled.scenario)

    assert [(pack.name, pack.version) for pack in compiled.selected_packs] == [
        ("healthcare", "1.0.0"),
        ("northstar-health", "1.1.0"),
    ]
    assert {user.username for user in compiled.scenario.environment.users} >= {
        "jordan.lee",
    }
    assert {system.hostname for system in compiled.scenario.environment.systems} >= {
        "NSH-CLIN-LNX-01",
        "NSH-FILE-01",
        "NSH-SAMBA-01",
    }
    assert all(share.system != "NSH-MAIL-01" for share in world.shares)
    samba = world.share("NSH-SAMBA-01.clinical_archive")
    assert samba.preset == "healthcare:clinical-department"
    assert samba.smb_native_filesystem == "NTFS"
    assert world.server_local_path(samba, "Policies\\care-plan.docx") == (
        "/srv/samba/Departments/ClinicalArchive/Policies/care-plan.docx"
    )
    mappings = {mapping.id: mapping for mapping in world.mappings}
    assert (mappings["clinical_ops_drive"].drive, mappings["clinical_ops_drive"].mount) == (
        "H:",
        "/mnt/clinical-ops",
    )
    assert (
        mappings["clinical_archive_mapping"].drive,
        mappings["clinical_archive_mapping"].mount,
    ) == ("I:", "/mnt/clinical-archive")
    assert (
        compiled.provenance["organization_model_origins"][
            "environment.storage.servers.1.shares.0.preset"
        ]
        == "model/environment.yaml"
    )


@pytest.mark.parametrize(
    ("industry", "preset"),
    [
        ("finance", "finance:finance-department"),
        ("healthcare", "healthcare:clinical-department"),
        ("technology", "technology:engineering-share"),
    ],
)
def test_industry_storage_presets_compile_unchanged_on_samba(
    tmp_path: Path,
    industry: str,
    preset: str,
) -> None:
    """Industry storage vocabulary stays portable; topology remains scenario-owned."""

    raw = load_yaml(_MINIMAL)
    raw.pop("version", None)
    raw["scenario_version"] = "2.0"
    raw["composition"] = {
        "industries": [{"source": "package", "name": industry, "version": "1.0.0"}]
    }
    raw["environment"]["domain"] = "example.test"
    raw["environment"]["systems"].append(
        {
            "hostname": "SAMBA-01",
            "ip": "10.0.0.20",
            "os": "Ubuntu Server 24.04",
            "type": "server",
            "services": ["samba", "smbd"],
            "roles": ["smb_server"],
        }
    )
    raw["environment"]["storage"] = {
        "population": "small",
        "servers": [
            {
                "system": "SAMBA-01",
                "presets": [],
                "volumes": [{"id": "data", "mount": "/srv/samba", "filesystem": "ext4"}],
                "shares": [
                    {
                        "id": "portable",
                        "name": "Portable",
                        "volume": "data",
                        "preset": preset,
                        "population": "small",
                        "access": {"read": ["test_user"], "modify": ["test_user"]},
                    }
                ],
            }
        ],
    }
    path = _write_yaml(tmp_path / f"{industry}-samba.yaml", raw)

    compiled = compile_scenario(path)
    with effective_config_scope(compiled.effective_config):
        world = StorageWorldModel.compile(compiled.scenario)

    share = world.share("SAMBA-01.portable")
    assert share.preset == preset
    assert share.files
    assert world.server_local_path(share, share.files[0].path).startswith("/srv/samba/")


def test_all_packaged_samples_have_the_fixed_catalog_contract() -> None:
    """Every shipped pack exposes every canonical catalog, including empty ones."""

    packs = PackRepository(Path.cwd()).list()
    packaged = [pack for pack in packs if pack.source == "package"]

    assert {pack.manifest.name for pack in packaged} == {
        "finance",
        "healthcare",
        "technology",
        "northstar-health",
    }
    expected_catalogs = {name for name, _path, _model in CATALOG_FILES}
    assert all(set(pack.catalogs) == expected_catalogs for pack in packs)


def test_direct_industry_sample_compiles_with_qualified_catalog_references() -> None:
    """The direct-industry fixture demonstrates composition without an org pack."""

    compiled = compile_scenario(_FINANCE)

    assert [pack.name for pack in compiled.selected_packs] == ["finance"]
    assert {user.persona for user in compiled.scenario.environment.users} == {
        "finance:finance_operations"
    }


def test_v2_rejects_mixed_industry_and_organization_modes(tmp_path: Path) -> None:
    """Composition selects direct industries or an organization, never both."""

    raw = load_yaml(_MINIMAL)
    raw.pop("version", None)
    raw["scenario_version"] = "2.0"
    raw["composition"] = {
        "industries": [{"source": "package", "name": "finance", "version": "1.0.0"}],
        "organization": {
            "source": "package",
            "name": "northstar-health",
            "version": "1.0.0",
        },
    }
    path = _write_yaml(tmp_path / "scenario.yaml", raw)

    with pytest.raises(SchemaValidationError, match="not both"):
        compile_scenario(path)


def test_peer_industry_namespace_collision_is_not_order_resolved(tmp_path: Path) -> None:
    """Two sources exporting one qualified identity fail instead of using list order."""

    repository = PackRepository(tmp_path)
    root = repository.create_skeleton("industry", "healthcare", "1.0.0")
    packaged_persona = load_yaml(
        Path(
            "src/evidenceforge/config/packs/industry/healthcare/1.0.0/catalogs/persona_catalog.yaml"
        )
    )
    _write_yaml(root / "catalogs" / "persona_catalog.yaml", packaged_persona)
    raw = load_yaml(_MINIMAL)
    raw.pop("version", None)
    raw["scenario_version"] = "2.0"
    raw["composition"] = {
        "industries": [
            {"source": "package", "name": "healthcare", "version": "1.0.0"},
            {"source": "project", "name": "healthcare", "version": "1.0.0"},
        ]
    }
    path = _write_yaml(tmp_path / "scenario.yaml", raw)

    with pytest.raises(PackError, match="share namespace 'healthcare'.*different exact identities"):
        compile_scenario(path)


def test_project_overlay_precedes_pack_adapter(tmp_path: Path) -> None:
    """Existing per-file overlay semantics apply after pack-derived configuration."""

    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    _write_yaml(
        overlay / "dns_registry.yaml",
        {
            "domains": [
                {
                    "domain": "claims.healthcare.example",
                    "ips": ["203.0.113.44"],
                    "tags": ["healthcare"],
                    "_replace": True,
                }
            ]
        },
    )
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text(_NORTHSTAR.read_text(encoding="utf-8"), encoding="utf-8")

    compiled = compile_scenario(scenario)
    with effective_config_scope(compiled.effective_config):
        traffic = load_traffic_profiles()["pack_persona_traffic"]
        application_connection = next(
            connection
            for connection in traffic["healthcare:clinical_coordinator"][
                "healthcare:clinical-shift"
            ]["outbound"]
            if connection.get("pack_application")
        )
        entry = next(
            item
            for item in load_dns_registry()["domains"]
            if item["domain"] == "claims.healthcare.example"
        )
        resolved_domain, resolved_ip = pick_domain_and_ip(
            random.Random(42),
            *application_connection["dns_tags"],
            src_host="NSH-CLIN-01",
        )
    assert entry["ips"] == ["203.0.113.44"]
    assert entry["tags"] == ["healthcare"]
    assert (resolved_domain, resolved_ip) == (
        "claims.healthcare.example",
        "203.0.113.44",
    )


def test_pack_init_creates_complete_non_overwriting_skeleton(tmp_path: Path) -> None:
    """Pack init creates every fixed section and refuses an existing destination."""

    repository = PackRepository(tmp_path)
    destination = repository.create_skeleton("organization", "example-org", "1.2.3")

    assert all((destination / relative_path).is_file() for _, relative_path, _ in CATALOG_FILES)
    assert (destination / "model/environment.yaml").is_file()
    assert (destination / "model/baseline_activity.yaml").is_file()
    with pytest.raises(Exception, match="already exists"):
        repository.create_skeleton("organization", "example-org", "1.2.3")


def test_effective_config_scopes_do_not_leak_sequentially_or_concurrently() -> None:
    """Legacy loader caches are isolated by each immutable provider scope."""

    def configured_domain(name: str, ip: str) -> str:
        effective = EffectiveConfig(
            project_root=".",
            project_overlays={
                "activity/dns_registry.yaml": {
                    "domains": [{"domain": name, "ips": [ip], "tags": ["web"]}]
                }
            },
        )
        with effective_config_scope(effective):
            domains = {entry["domain"] for entry in load_dns_registry()["domains"]}
            assert name in domains
            assert REVERSE_DNS[ip] == name
            return name

    assert configured_domain("one.test", "10.0.0.1") == "one.test"
    assert configured_domain("two.test", "10.0.0.2") == "two.test"
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = set(
            executor.map(
                lambda item: configured_domain(*item),
                [("three.test", "10.0.0.3"), ("four.test", "10.0.0.4")],
            )
        )
    assert results == {"three.test", "four.test"}
    assert not any(name in REVERSE_DNS.values() for name in ("one.test", "two.test"))


def test_resolved_document_round_trip_bypasses_removed_pack_sources(tmp_path: Path) -> None:
    """Authoritative YAML retains the canonical compiled digest without pack discovery."""

    compiled = compile_scenario(_NORTHSTAR)
    resolved_path = tmp_path / "RESOLVED_SCENARIO.yaml"
    resolved_path.write_bytes(serialize_resolved_document(build_resolved_document(compiled)))

    authoritative = compile_scenario(resolved_path)

    assert authoritative.authored_kind == "resolved"
    assert authoritative.digests["compiled_sha256"] == compiled.digests["compiled_sha256"]
    assert authoritative.scenario.model_dump(mode="json") == compiled.scenario.model_dump(
        mode="json"
    )


def test_pack_internal_include_is_semantic_and_digest_tracked(tmp_path: Path) -> None:
    """A contained include is accepted as pack content rather than rejected as an orphan."""

    repository = PackRepository(tmp_path)
    root = repository.create_skeleton("industry", "included", "1.0.0")
    _write_yaml(root / "catalogs" / "storage_catalog.yaml", {"includes": ["storage.yaml"]})
    _write_yaml(
        root / "catalogs" / "storage.yaml",
        {
            "storage_catalog": {
                "records": {
                    "description": "Records vocabulary",
                    "data": {
                        "directories": ["Records"],
                        "subjects": ["case-file"],
                        "files": [{"extension": ".pdf", "mime": "application/pdf", "weight": 1}],
                    },
                }
            }
        },
    )

    pack = repository.resolve(
        reference=PackReference(source="project", name="included", version="1.0.0"),
        expected_type="industry",
    )

    assert "included:records" in pack.catalogs["storage_catalog"]
    assert "catalogs/storage.yaml" in pack.assets

    scenario_document = load_yaml(_MINIMAL)
    scenario_document.pop("version")
    scenario_document["scenario_version"] = "2.0"
    scenario_document["composition"] = {
        "industries": [
            {
                "source": "project",
                "name": "included",
                "version": "1.0.0",
            }
        ]
    }
    scenario_path = _write_yaml(tmp_path / "included-scenario.yaml", scenario_document)
    compiled = compile_scenario(scenario_path, project_root=tmp_path)

    assert (
        compiled.provenance["catalog_field_origins"][
            "storage_catalog.included:records.data.files.0.mime"
        ]
        == "catalogs/storage.yaml"
    )


def test_organization_model_origins_retain_included_pack_paths(tmp_path: Path) -> None:
    """Organization provenance points to the exact portable model include source."""

    repository = PackRepository(tmp_path)
    packaged = repository.resolve(
        PackReference(source="package", name="northstar-health", version="1.0.0"),
        expected_type="organization",
    )
    root = repository.copy(packaged, name="included-northstar", version="1.0.0")
    fragments = root / "model" / "fragments"
    fragments.mkdir()

    environment_path = root / "model" / "environment.yaml"
    environment_document = yaml.safe_load(environment_path.read_text(encoding="utf-8"))
    domain = environment_document["environment"].pop("domain")
    environment_document["includes"] = ["fragments/domain.yaml"]
    _write_yaml(environment_path, environment_document)
    _write_yaml(fragments / "domain.yaml", {"environment": {"domain": domain}})

    baseline_path = root / "model" / "baseline_activity.yaml"
    baseline_document = yaml.safe_load(baseline_path.read_text(encoding="utf-8"))
    intensity = baseline_document["baseline_activity"].pop("intensity")
    baseline_document["includes"] = ["fragments/baseline.yaml"]
    _write_yaml(baseline_path, baseline_document)
    _write_yaml(
        fragments / "baseline.yaml",
        {"baseline_activity": {"intensity": intensity}},
    )

    scenario_document = load_yaml(_NORTHSTAR)
    scenario_document["composition"]["organization"] = {
        "source": "project",
        "name": "included-northstar",
        "version": "1.0.0",
    }
    scenario_document.pop("environment", None)
    scenario_document.pop("baseline_activity", None)
    scenario_path = _write_yaml(tmp_path / "included-org-scenario.yaml", scenario_document)

    compiled = compile_scenario(scenario_path, project_root=tmp_path)

    origins = compiled.provenance["organization_model_origins"]
    assert origins["environment.domain"] == "model/fragments/domain.yaml"
    assert origins["baseline_activity.intensity"] == "model/fragments/baseline.yaml"
    assert all(not Path(origin).is_absolute() for origin in origins.values())


def test_pack_rejects_unconstrained_assets(tmp_path: Path) -> None:
    """Data-only packs cannot smuggle arbitrary files or executable hooks."""

    repository = PackRepository(tmp_path)
    root = repository.create_skeleton("industry", "unsafe", "1.0.0")
    (root / "hook.py").write_text("raise SystemExit\n", encoding="utf-8")

    with pytest.raises(PackError, match="forbidden unconstrained asset"):
        repository.resolve(
            PackReference(source="project", name="unsafe", version="1.0.0"),
            expected_type="industry",
        )


def test_path_pack_reference_uses_declaring_include_origin(monkeypatch, tmp_path: Path) -> None:
    """A path pack in an include is independent of both root YAML location and CWD."""

    repository = PackRepository(tmp_path)
    pack_root = repository.create_skeleton("industry", "local-industry", "1.0.0")
    fragments = tmp_path / "fragments"
    fragments.mkdir()
    _write_yaml(
        fragments / "composition.yaml",
        {
            "composition": {
                "industries": [
                    {
                        "source": "path",
                        "path": "../.eforge/packs/industry/local-industry/1.0.0",
                        "name": "local-industry",
                        "version": "1.0.0",
                    }
                ]
            }
        },
    )
    raw = load_yaml(_MINIMAL)
    raw.pop("version", None)
    raw["scenario_version"] = "2.0"
    raw["includes"] = ["fragments/composition.yaml"]
    root = _write_yaml(tmp_path / "scenario.yaml", raw)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    compiled = compile_scenario(root)

    assert compiled.selected_packs[0].name == "local-industry"
    assert pack_root.is_dir()


def test_email_corpus_is_inlined_for_authoritative_reruns(tmp_path: Path) -> None:
    """Resolved input retains a declaring-file-relative email corpus after deletion."""

    included = tmp_path / "fragments"
    included.mkdir()
    corpus = included / "email_corpus.yaml"
    corpus.write_text(
        "messages:\n  - id: notice\n    subject: Notice\n    body: Read this.\n",
        encoding="utf-8",
    )
    _write_yaml(
        included / "email.yaml",
        {"environment": {"email": {"corpus": "email_corpus.yaml"}}},
    )
    raw = load_yaml(_NORTHSTAR)
    raw["includes"] = ["fragments/email.yaml"]
    root = _write_yaml(tmp_path / "scenario.yaml", raw)

    compiled = compile_scenario(root)
    reference = compiled.scenario.environment.email.corpus
    assert reference is not None and reference.startswith("embedded:")
    resolved_path = tmp_path / "RESOLVED_SCENARIO.yaml"
    resolved_path.write_bytes(serialize_resolved_document(build_resolved_document(compiled)))
    corpus.unlink()

    authoritative = compile_scenario(resolved_path)
    with effective_config_scope(authoritative.effective_config):
        loaded = load_email_corpus_yaml(tmp_path / "does-not-matter", reference)
    assert loaded["messages"][0]["id"] == "notice"


def test_resolved_provider_does_not_reread_packaged_yaml(monkeypatch, tmp_path: Path) -> None:
    """Authoritative loading serves packaged defaults from the compiled snapshot."""

    compiled = compile_scenario(_MINIMAL)
    resolved_path = tmp_path / "RESOLVED_SCENARIO.yaml"
    resolved_path.write_bytes(serialize_resolved_document(build_resolved_document(compiled)))
    authoritative = compile_scenario(resolved_path)
    config_root = Path("src/evidenceforge/config").resolve()
    original_read_text = Path.read_text

    def guarded_read_text(path: Path, *args, **kwargs):
        if path.resolve().is_relative_to(config_root) and path.suffix == ".yaml":
            raise AssertionError(f"authoritative run reread packaged config: {path}")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    with effective_config_scope(authoritative.effective_config):
        assert load_dns_registry()["domains"]
        monkeypatch.setattr(Path, "read_text", original_read_text)


def test_generation_manifest_detects_bundle_corruption(tmp_path: Path) -> None:
    """Every generated file is hashed and intrinsic corruption fails before evaluation."""

    compiled = compile_scenario(_MINIMAL)
    data = tmp_path / "data"
    data.mkdir()
    log = data / "events.json"
    log.write_text('{"event": 1}\n', encoding="utf-8")
    write_resolved_scenario(compiled, tmp_path)
    write_generation_manifest(
        compiled,
        tmp_path,
        output_target="default",
        formats=["zeek_conn"],
    )

    assert verify_generation_bundle(tmp_path)["scenario"] == compiled.scenario.name
    log.write_text('{"event": 2}\n', encoding="utf-8")
    with pytest.raises(SchemaValidationError, match="hash verification failed"):
        verify_generation_bundle(tmp_path)


def test_generation_manifest_hashes_registered_sidecars_not_author_collateral(
    tmp_path: Path,
) -> None:
    """Bundle identity includes storage metadata while ignoring unrelated root files."""

    compiled = compile_scenario(_MINIMAL)
    data = tmp_path / "data"
    data.mkdir()
    (data / "events.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "STORAGE_MANIFEST.json").write_text("{}\n", encoding="utf-8")
    collateral = tmp_path / "AUTHOR_NOTES.md"
    collateral.write_text("draft\n", encoding="utf-8")
    write_resolved_scenario(compiled, tmp_path)
    write_generation_manifest(
        compiled,
        tmp_path,
        output_target="default",
        formats=["zeek_conn"],
    )

    manifest = verify_generation_bundle(tmp_path)
    assert "STORAGE_MANIFEST.json" in manifest["files"]
    assert "AUTHOR_NOTES.md" not in manifest["files"]
    collateral.write_text("edited after generation\n", encoding="utf-8")
    assert verify_generation_bundle(tmp_path)["scenario"] == compiled.scenario.name
