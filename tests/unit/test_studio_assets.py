"""Asset inventories preserve keyed origins, edit ownership, and version immutability."""

from __future__ import annotations

import copy
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from evidenceforge.composition.models import DestinationCatalogEntry, PackReference
from evidenceforge.composition.packs import PackRepository
from evidenceforge.models.exceptions import PackError
from evidenceforge.studio.assets import (
    AssetEdit,
    Inventory,
    _editor_schema,
    build_inventory,
    inventory_revision,
    save_asset,
)
from evidenceforge.studio.contexts import scenario_context_path, scenario_overlay_root


def source_file(root: Path) -> Path:
    root = root.resolve()
    root.mkdir(exist_ok=True)
    source = root / "scenario.yaml"
    shutil.copyfile(Path(__file__).parents[1] / "fixtures/scenarios/minimal.yaml", source)
    return source


def test_structured_service_definitions_keep_their_nested_fields() -> None:
    schema = _editor_schema(DestinationCatalogEntry, "destination_catalog")
    data = schema["$defs"]["DestinationCatalogData"]["properties"]
    assert "x-asset-choices" not in data["services"]
    assert next(iter(data["services"]["patternProperties"].values()))["$ref"].endswith(
        "DestinationService"
    )


def organization(root: Path) -> Path:
    repository = PackRepository(root)
    pack = repository.create_skeleton(
        "organization", "office", "1.0.0", publisher="training", publisher_display_name="Training"
    )
    (pack / "model/environment.yaml").write_text(
        yaml.safe_dump(
            {
                "environment": {
                    "users": [
                        {
                            "username": "zoe",
                            "full_name": "Zoe Pack",
                            "email": "zoe@example.com",
                            "primary_system": "TEST-01",
                        },
                        {
                            "username": "amy",
                            "full_name": "Amy Pack",
                            "email": "amy@example.com",
                            "primary_system": "TEST-01",
                        },
                    ]
                }
            }
        )
    )
    return pack


def edit_for(inventory: Inventory, category: str, key: str, **changes: Any) -> AssetEdit:
    row = next(row for row in inventory.rows[category] if row.key == key)
    detail = inventory.detail(category, row.id)
    return AssetEdit(
        revision=inventory.revision,
        category=category,
        asset_id=row.id,
        key=row.key,
        value={**copy.deepcopy(detail.value), **changes},
    )


def test_search_filters_entire_inventory_before_bounded_pages(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    data = yaml.safe_load(source.read_text())
    data["environment"]["users"] = [
        {
            "username": f"user{index:04}",
            "full_name": f"User {index}",
            "email": f"user{index}@example.com",
        }
        for index in range(1205)
    ]
    source.write_text(yaml.safe_dump(data))
    inventory = build_inventory(source, tmp_path, False)
    page = inventory.page("users", "", "", "", 200, 50)
    assert page.page == 24
    assert page.matching == page.total == 1205
    assert len(page.entries) == 5
    assert "value" not in page.entries[0].model_dump()
    filtered = inventory.page("users", "user1204@example.com", "scenario", "scenario.yaml", 24, 25)
    assert filtered.page == 0
    assert filtered.matching == 1
    assert filtered.entries[0].key == "user1204"


def test_users_view_combines_account_statuses_and_keeps_stale_edit_ownership(
    tmp_path: Path,
) -> None:
    source = source_file(tmp_path)
    data = yaml.safe_load(source.read_text())
    data["environment"]["users"].append(
        {
            "username": "disabled.user",
            "full_name": "Disabled User",
            "email": "disabled@example.com",
            "enabled": False,
        }
    )
    data["environment"]["stale_accounts"] = [
        {
            "username": "former.employee",
            "last_active": "2025-01-01",
            "reason": "Former employee",
        }
    ]
    source.write_text(yaml.safe_dump(data))
    inventory = build_inventory(source, tmp_path, False)
    page = inventory.page("users", "", "", "", 0, 50)
    assert page.total == len(data["environment"]["users"]) + 1
    assert {row.account_status for row in page.entries} == {"active", "disabled", "stale"}
    assert "stale_accounts" not in {category.key for category in page.categories}
    filtered = inventory.page("users", "", "", "", 0, 50, "stale")
    assert filtered.matching == 1 and filtered.entries[0].key == "former.employee"
    detail = inventory.detail("users", filtered.entries[0].id)
    assert detail.category == "stale_accounts"
    assert "last_active" in detail.schema_document["properties"]
    save_asset(
        source,
        tmp_path,
        inventory,
        AssetEdit(
            revision=detail.revision,
            category=detail.category,
            asset_id=detail.summary.id,
            key=detail.summary.key,
            value={**detail.value, "reason": "Retired credentials"},
        ),
    )
    saved = yaml.safe_load(source.read_text())["environment"]
    assert saved["stale_accounts"][0]["reason"] == "Retired credentials"
    assert not any(user["username"] == "former.employee" for user in saved["users"])


def test_reference_choices_search_all_entries_and_annotate_nested_editors(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    data = yaml.safe_load(source.read_text())
    data["environment"]["systems"] = [
        {
            "hostname": f"HOST-{index:04}",
            "ip": f"10.10.{index // 250}.{index % 250 + 1}",
            "os": "Windows 11",
            "type": "workstation",
        }
        for index in range(1205)
    ]
    source.write_text(yaml.safe_dump(data))
    inventory = build_inventory(source, tmp_path, False)
    choices = inventory.choices("systems", "", 0, 50)
    assert len(choices.entries) == 50 and choices.matching == 1205
    assert inventory.choices("systems", "HOST-1204", 24, 50).entries == ["HOST-1204"]
    assert "former.employee" not in inventory.choice_values["users"]
    assert "developer" in inventory.choice_values["personas"]
    assert "forward_proxy" in inventory.choice_values["roles"]
    user_schema = inventory.detail("users", None).schema_document
    assert user_schema["properties"]["primary_system"]["x-asset-choices"] == "systems"
    assert not user_schema["properties"]["groups"]["x-asset-custom"]
    assert inventory.detail("groups", None).schema_document["properties"]["permissions"][
        "x-asset-custom"
    ]
    application_schema = inventory.detail("applications", None).schema_document
    assert application_schema["properties"]["platforms"]["additionalProperties"]["$ref"].endswith(
        "PlatformConfig"
    )
    assert "image_path" in application_schema["$defs"]["PlatformConfig"]["properties"]
    with pytest.raises(ValueError, match="vocabulary"):
        inventory.choices("unknown", "", 0, 50)


def test_keyed_pack_origin_and_sparse_scenario_override(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    pack = organization(tmp_path)
    pack_bytes = {path: path.read_bytes() for path in pack.rglob("*") if path.is_file()}
    data = yaml.safe_load(source.read_text())
    data.pop("version")
    data["scenario_version"] = "2.0"
    data["composition"] = {
        "organization": {
            "source": "project",
            "publisher": "training",
            "name": "office",
            "version": "1.0.0",
        }
    }
    data["environment"]["users"] = [{"username": "amy", "full_name": "Amy Scenario"}]
    source.write_text(yaml.safe_dump(data))
    inventory = build_inventory(source, tmp_path, False)
    amy, zoe = inventory.rows["users"]
    assert amy.origin.kind == "mixed"
    assert zoe.origin.kind == "pack"
    fields = inventory.detail("users", amy.id).field_origins
    assert fields["email"].kind == "pack"
    assert fields["full_name"].kind == "scenario"
    save_asset(
        source, tmp_path, inventory, edit_for(inventory, "users", "zoe", full_name="Zoe Local")
    )
    authored = yaml.safe_load(source.read_text())["environment"]["users"]
    assert authored[-1] == {"username": "zoe", "full_name": "Zoe Local"}
    assert pack_bytes == {path: path.read_bytes() for path in pack.rglob("*") if path.is_file()}
    assert build_inventory(source, tmp_path, False).rows["users"][1].origin.kind == "mixed"


@pytest.mark.parametrize("included", [False, True])
def test_restore_pack_fields_removes_overrides_and_preserves_other_edits(
    tmp_path: Path, included: bool
) -> None:
    source = source_file(tmp_path)
    pack = organization(tmp_path)
    pack_bytes = {path: path.read_bytes() for path in pack.rglob("*") if path.is_file()}
    data = yaml.safe_load(source.read_text())
    data.pop("version")
    data["scenario_version"] = "2.0"
    data["composition"] = {
        "organization": {
            "source": "project",
            "publisher": "training",
            "name": "office",
            "version": "1.0.0",
        }
    }
    overrides = [{"username": "amy", "full_name": "Local name", "email": "local@example.com"}]
    owner = tmp_path / "users.yaml" if included else source
    if included:
        data["composition"]["organization"].update(source="path", path=str(pack))
        owner.write_text(yaml.safe_dump({"environment": {"users": overrides}}))
        data["environment"].pop("users")
        data["includes"] = [owner.name]
    else:
        data["environment"]["users"] = overrides
    source.write_text(yaml.safe_dump(data))
    source_before = source.read_bytes()
    inventory = build_inventory(source, tmp_path, False)
    detail = inventory.detail("users", inventory.rows["users"][0].id)
    assert detail.inherited_value["full_name"] == "Amy Pack"
    assert detail.override_fields == ["email", "full_name"]
    edit = edit_for(inventory, "users", "amy")
    saved = save_asset(
        source, tmp_path, inventory, edit.model_copy(update={"restore_fields": ["full_name"]})
    )
    assert saved.path == owner
    stored = yaml.safe_load(owner.read_text())["environment"]["users"]
    assert stored == [{"username": "amy", "email": "local@example.com"}]
    if included:
        assert source.read_bytes() == source_before
    current = build_inventory(source, tmp_path, False)
    restored = current.detail("users", detail.summary.id)
    assert restored.value["full_name"] == "Amy Pack"
    assert restored.value["email"] == "local@example.com"
    assert restored.override_fields == ["email"]
    save_asset(
        source,
        tmp_path,
        current,
        edit_for(current, "users", "amy").model_copy(update={"restore_fields": ["*"]}),
    )
    assert yaml.safe_load(owner.read_text())["environment"]["users"] == []
    inherited = build_inventory(source, tmp_path, False).detail("users", detail.summary.id)
    assert inherited.summary.origin.kind == "pack"
    assert inherited.override_fields == []
    assert inherited.value == inherited.inherited_value
    assert pack_bytes == {path: path.read_bytes() for path in pack.rglob("*") if path.is_file()}


def test_restore_nested_runtime_list_drops_private_patch_without_losing_other_edits(
    tmp_path: Path,
) -> None:
    source = source_file(tmp_path)
    original = source.read_bytes()
    inventory = build_inventory(source, tmp_path, False)
    row = next(row for row in inventory.rows["applications"] if row.key == "chrome")
    detail = inventory.detail("applications", row.id)
    value = copy.deepcopy(detail.value)
    windows = value["platforms"]["windows"]
    windows["command_templates"].append('"chrome.exe" --custom')
    windows["image_path"] = r"C:\Custom\chrome.exe"
    value["display_name"] = "Custom Chrome"
    save_asset(
        source,
        tmp_path,
        inventory,
        edit_for(inventory, "applications", "chrome").model_copy(update={"value": value}),
    )
    current = build_inventory(source, tmp_path, False)
    save_asset(
        source,
        tmp_path,
        current,
        edit_for(current, "applications", "chrome").model_copy(
            update={"restore_fields": ["platforms.windows.command_templates"]}
        ),
    )
    after = build_inventory(source, tmp_path, False)
    restored = after.detail("applications", row.id)
    assert restored.value["display_name"] == "Custom Chrome"
    assert restored.value["platforms"]["windows"]["image_path"] == r"C:\Custom\chrome.exe"
    assert (
        restored.value["platforms"]["windows"]["command_templates"]
        == detail.value["platforms"]["windows"]["command_templates"]
    )
    overlay = scenario_overlay_root(source, tmp_path) / "activity/application_catalog.yaml"
    entry = yaml.safe_load(overlay.read_text())["applications"][0]
    assert "command_templates" not in entry["platforms"]["windows"]
    save_asset(
        source,
        tmp_path,
        after,
        edit_for(after, "applications", "chrome").model_copy(
            update={"restore_fields": ["platforms.windows.image_path"]}
        ),
    )
    after = build_inventory(source, tmp_path, False)
    assert after.detail("applications", row.id).override_fields == ["display_name"]
    save_asset(
        source,
        tmp_path,
        after,
        edit_for(after, "applications", "chrome").model_copy(update={"restore_fields": ["*"]}),
    )
    final = build_inventory(source, tmp_path, False).detail("applications", row.id)
    assert final.value == detail.value
    assert final.override_fields == []
    assert final.summary.origin.kind == "configuration"
    assert source.read_bytes() == original


def test_restore_rejects_scenario_owned_assets_and_identity_fields(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    inventory = build_inventory(source, tmp_path, False)
    before = source.read_bytes()
    with pytest.raises(ValueError, match="no inherited"):
        save_asset(
            source,
            tmp_path,
            inventory,
            edit_for(inventory, "users", "test_user").model_copy(update={"restore_fields": ["*"]}),
        )
    row = inventory.rows["applications"][0]
    with pytest.raises(ValueError, match="editable field"):
        save_asset(
            source,
            tmp_path,
            inventory,
            edit_for(inventory, "applications", row.key).model_copy(
                update={"restore_fields": ["id"]}
            ),
        )
    assert source.read_bytes() == before
    assert not scenario_context_path(source, tmp_path).exists()


def test_edit_included_owner_and_stale_revision_rejection(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    data = yaml.safe_load(source.read_text())
    users = data["environment"].pop("users")
    included = tmp_path / "users.yaml"
    included.write_text(yaml.safe_dump({"environment": {"users": users}}))
    data["includes"] = [included.name]
    source.write_text(yaml.safe_dump(data))
    root_before = source.read_bytes()
    inventory = build_inventory(source, tmp_path, False)
    edit = edit_for(inventory, "users", "test_user", full_name="Included edit")
    saved = save_asset(source, tmp_path, inventory, edit)
    assert saved.path == included
    assert source.read_bytes() == root_before
    assert (
        yaml.safe_load(included.read_text())["environment"]["users"][0]["full_name"]
        == "Included edit"
    )
    with pytest.raises(FileExistsError, match="Inputs changed"):
        save_asset(source, tmp_path, inventory, edit)


def test_invalid_cross_reference_does_not_write(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    inventory = build_inventory(source, tmp_path, False)
    before = source.read_bytes()
    with pytest.raises(ValueError, match="MISSING"):
        save_asset(
            source,
            tmp_path,
            inventory,
            edit_for(inventory, "users", "test_user", primary_system="MISSING"),
        )
    assert source.read_bytes() == before


def test_dns_edit_uses_private_optional_context(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    inventory = build_inventory(source, tmp_path, False)
    key = inventory.rows["dns"][0].key
    edit = edit_for(inventory, "dns", key, ips=["203.0.113.40"])
    before = source.read_bytes()
    save_asset(source, tmp_path, inventory, edit)
    assert source.read_bytes() == before
    assert not (tmp_path / ".eforge/config").exists()
    assert scenario_context_path(source, tmp_path).is_file()
    assert (scenario_overlay_root(source, tmp_path) / "activity/dns_registry.yaml").is_file()
    changed = build_inventory(source, tmp_path, False)
    row = next(row for row in changed.rows["dns"] if row.key == key)
    assert changed.detail("dns", row.id).value["ips"] == ["203.0.113.40"]
    assert row.origin.kind == "scenario"


def test_pack_edits_publish_new_version_and_preserve_original(tmp_path: Path) -> None:
    pack = organization(tmp_path)
    source = pack / "pack.yaml"
    inventory = build_inventory(source, tmp_path, True)
    before = inventory_revision(source, tmp_path, True)
    edit = edit_for(inventory, "users", "amy", full_name="Amy Revision")
    saved = save_asset(source, tmp_path, inventory, edit)
    assert saved.version == "1.0.1"
    assert inventory_revision(source, tmp_path, True) == before
    revised = build_inventory(saved.path, tmp_path, True)
    assert revised.detail("users", revised.rows["users"][0].id).value["full_name"] == "Amy Revision"
    with pytest.raises(PackError, match="exist"):
        save_asset(source, tmp_path, inventory, edit)


def test_invalid_new_pack_version_is_rolled_back(tmp_path: Path) -> None:
    pack = organization(tmp_path)
    repository = PackRepository(tmp_path)
    original = repository.resolve(
        PackReference(source="project", publisher="training", name="office", version="1.0.0"),
        expected_type="organization",
    )
    with pytest.raises(PackError):
        repository.copy(
            original,
            name="office",
            version="1.0.1",
            publisher="training",
            publisher_display_name="Training",
            updates={"model/environment.yaml": b"environment:\n  users: invalid\n"},
        )
    assert not (pack.parent / "1.0.1").exists()
    assert inventory_revision(pack / "pack.yaml", tmp_path, True)


def test_asset_api_bounds_details_auth_and_revision(tmp_path: Path) -> None:

    from fastapi.testclient import TestClient

    from evidenceforge.studio.service import create_app
    from evidenceforge.studio.settings import SettingsStore, StudioSettings
    from tests.unit.test_studio_service import _paths

    workspace = tmp_path / "workspace"
    source = source_file(workspace)
    paths = _paths(tmp_path / "app")
    SettingsStore(paths).save(StudioSettings(workspace=workspace))
    app = create_app(paths=paths, token="asset-test")
    studio = app.state.studio
    # Register without starting background Codex or job workers.
    from evidenceforge.desktop.library import _scenario_item

    library_item = _scenario_item(source)
    assert library_item is not None
    item = studio.store.upsert_item(workspace, "scenario", library_item)
    client = TestClient(app)
    path = f"/v1/items/{item.id}/assets"
    headers = {"X-EForge-Token": "asset-test"}
    assert client.get(path).status_code == 401
    response = client.get(
        path, params={"category": "applications", "page_size": "25", "page": "0"}, headers=headers
    )
    assert response.status_code == 200, response.text
    page = response.json()
    assert len(page["entries"]) == 25
    assert "value" not in page["entries"][0]
    assert client.get(path, params={"page_size": 51}, headers=headers).status_code == 400
    choices_path = path + "/choices"
    params = {"source": "application_ids", "revision": page["revision"], "page_size": 10}
    assert client.get(choices_path, params=params).status_code == 401
    choices = client.get(choices_path, params=params, headers=headers)
    assert choices.status_code == 200 and len(choices.json()["entries"]) == 10
    assert (
        client.get(choices_path, params={**params, "page_size": 101}, headers=headers).status_code
        == 422
    )
    row = page["entries"][0]
    expanded = client.get(
        path + "/detail",
        params={"category": "applications", "asset_id": row["id"], "revision": page["revision"]},
        headers=headers,
    )
    assert expanded.status_code == 200, expanded.text
    assert expanded.json()["value"]["id"] == row["key"]
    source.write_text(source.read_text() + "\n# New revision\n")
    assert client.get(choices_path, params=params, headers=headers).status_code == 409
    stale = client.get(
        path + "/detail",
        params={"category": "applications", "asset_id": row["id"], "revision": page["revision"]},
        headers=headers,
    )
    assert stale.status_code == 409
    assert not studio.asset_lock.locked()


def test_runtime_application_edit_retains_other_values_and_origins(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    inventory = build_inventory(source, tmp_path, False)
    row = inventory.rows["applications"][0]
    previous = inventory.detail("applications", row.id).value
    save_asset(
        source,
        tmp_path,
        inventory,
        edit_for(inventory, "applications", row.key, display_name="Scenario application"),
    )
    changed = build_inventory(source, tmp_path, False)
    detail = changed.detail("applications", row.id)
    assert detail.value == {**previous, "display_name": "Scenario application"}
    assert detail.field_origins["display_name"].kind == "scenario"
    assert all(
        origin.kind == "configuration"
        for path, origin in detail.field_origins.items()
        if path.startswith("platforms.")
    )
    save_asset(
        source, tmp_path, changed, edit_for(changed, "applications", row.key, selection_weight=17)
    )
    current = build_inventory(source, tmp_path, False).detail("applications", row.id)
    assert current.value["display_name"] == "Scenario application"
    assert current.value["selection_weight"] == 17


def test_config_transaction_rolls_back_when_context_publication_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.studio import assets as asset_module

    source = source_file(tmp_path)
    inventory = build_inventory(source, tmp_path, False)
    original = asset_module._write_atomic
    context = scenario_context_path(source, tmp_path)

    def fail_context(path: Path, content: bytes) -> None:
        if path == context:
            raise OSError("Context publication failed")
        original(path, content)

    monkeypatch.setattr(asset_module, "_write_atomic", fail_context)
    with pytest.raises(OSError, match="Context publication failed"):
        save_asset(
            source,
            tmp_path,
            inventory,
            edit_for(inventory, "dns", inventory.rows["dns"][0].key, ips=["203.0.113.41"]),
        )
    assert not context.exists()
    assert not (scenario_overlay_root(source, tmp_path) / "activity/dns_registry.yaml").exists()


def test_pack_catalog_edit_validates_references_before_publish(tmp_path: Path) -> None:
    package = (
        Path(__file__).parents[2]
        / "src/evidenceforge/config/packs/evidenceforge/industry/finance/1.0.0/pack.yaml"
    )
    inventory = build_inventory(package, tmp_path, True)
    row = inventory.rows["process_catalog"][0]
    detail = inventory.detail("process_catalog", row.id)
    edit = edit_for(inventory, "process_catalog", row.key, description="Reviewed process profile")
    saved = save_asset(package, tmp_path, inventory, edit)
    assert saved.version == "1.0.1"
    assert (
        build_inventory(saved.path, tmp_path, True)
        .detail("process_catalog", row.id)
        .value["description"]
        == "Reviewed process profile"
    )
    invalid = copy.deepcopy(detail.value)
    invalid["data"]["builtins"] = ["nonexistent-built-in"]
    rejected = edit.model_copy(update={"value": invalid, "version": "1.0.2"})
    with pytest.raises(PackError):
        save_asset(package, tmp_path, inventory, rejected)
    assert not (saved.path.parent.parent / "1.0.2").exists()


def conversion_edit(
    inventory: Inventory, category: str, key: str, *, preview: bool = False, **changes: Any
) -> AssetEdit:
    row = next(row for row in inventory.rows[category] if row.key == key)
    draft = inventory.conversion_detail(category, row.id)
    return AssetEdit(
        revision=inventory.revision,
        category=draft.category,
        asset_id=row.id,
        key=key,
        value={**draft.value, **changes},
        convert_from=category,
        preview=preview,
    )


@pytest.mark.parametrize("inherited", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
def test_account_conversion_round_trip_preserves_details_links_and_pack(
    tmp_path: Path,
    inherited: bool,
    enabled: bool,
) -> None:
    from evidenceforge.composition.compiler import compile_scenario

    source = source_file(tmp_path)
    data = yaml.safe_load(source.read_text())
    key = "amy" if inherited else "test_user"
    pack_bytes = None
    if inherited:
        pack = organization(tmp_path)
        pack_bytes = (pack / "model/environment.yaml").read_bytes()
        data.pop("version")
        data["scenario_version"] = "2.0"
        data["composition"] = {
            "organization": {
                "source": "project",
                "publisher": "training",
                "name": "office",
                "version": "1.0.0",
            }
        }
        data["environment"]["users"] = [
            {"username": key, "enabled": enabled, "full_name": "Amy customized"}
        ]
    else:
        data["environment"]["users"][0]["enabled"] = enabled
    if not inherited:
        data["environment"]["users"].append(
            {
                "username": "remaining",
                "full_name": "Remaining User",
                "email": "remaining@example.com",
            }
        )
    data["environment"]["groups"] = [{"name": "staff", "members": [key]}]
    data["environment"]["systems"][0]["assigned_user"] = key
    included = tmp_path / "directory.yaml"
    included.write_text(yaml.safe_dump({"environment": data.pop("environment")}))
    data["includes"] = ["directory.yaml"]
    source.write_text(yaml.safe_dump(data))
    original = compile_scenario(source, project_root=tmp_path).scenario.environment
    user = next(user for user in original.users if user.username == key)
    inventory = build_inventory(source, tmp_path, False)
    before = {path: path.read_bytes() for path in (source, included)}
    preview = save_asset(
        source, tmp_path, inventory, conversion_edit(inventory, "users", key, preview=True)
    )
    assert not preview.validation_errors
    assert preview.effects == [
        "Remove membership in group staff",
        "Clear assigned user on system TEST-01",
    ]
    assert before == {path: path.read_bytes() for path in before}
    save_asset(source, tmp_path, inventory, conversion_edit(inventory, "users", key))
    compiled = compile_scenario(source, project_root=tmp_path)
    assert key not in [user.username for user in compiled.scenario.environment.users]
    assert key in [user.username for user in compiled.scenario.environment.stale_accounts]
    assert compiled.scenario.environment.groups[0].members == []
    assert compiled.scenario.environment.systems[0].assigned_user is None
    assert "account_transitions" not in compiled.scenario.model_dump()
    from evidenceforge.composition.artifacts import (
        build_resolved_document,
        serialize_resolved_document,
    )

    resolved = tmp_path / "RESOLVED_SCENARIO.yaml"
    resolved.write_bytes(serialize_resolved_document(build_resolved_document(compiled)))
    assert (
        compile_scenario(resolved, project_root=tmp_path).scenario.environment
        == compiled.scenario.environment
    )
    inventory = build_inventory(source, tmp_path, False)
    restoring = conversion_edit(inventory, "stale_accounts", key)
    assert restoring.value == user.model_dump(mode="json")
    save_asset(source, tmp_path, inventory, restoring)
    restored = compile_scenario(source, project_root=tmp_path).scenario.environment
    assert next(current for current in restored.users if current.username == key) == user
    assert restored.groups[0].members == [key]
    assert restored.systems[0].assigned_user == key
    assert key not in [account.username for account in restored.stale_accounts]
    if inherited:
        assert (pack / "model/environment.yaml").read_bytes() == pack_bytes
        restored_inventory = build_inventory(source, tmp_path, False)
        restored_detail = restored_inventory.detail(
            "users", next(row.id for row in restored_inventory.rows["users"] if row.key == key)
        )
        assert restored_detail.summary.origin.kind == "mixed"
        assert restored_detail.field_origins["email"].kind == "pack"
        assert restored_detail.field_origins["primary_system"].kind == "pack"
    # Subsequent ordinary editing and a second retirement retain the latest details.
    inventory = build_inventory(source, tmp_path, False)
    save_asset(
        source, tmp_path, inventory, edit_for(inventory, "users", key, full_name="Revised User")
    )
    inventory = build_inventory(source, tmp_path, False)
    save_asset(source, tmp_path, inventory, conversion_edit(inventory, "users", key))
    inventory = build_inventory(source, tmp_path, False)
    assert conversion_edit(inventory, "stale_accounts", key).value["full_name"] == "Revised User"


def test_account_conversion_preflight_blocks_storyline_and_retains_sources(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    data = yaml.safe_load(source.read_text())
    data["environment"]["users"].append(
        {"username": "remaining", "full_name": "Remaining User", "email": "remaining@example.com"}
    )
    data["storyline"] = [
        {
            "id": "work",
            "time": "+15m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Work",
            "events": [
                {"type": "process", "process_name": "cmd.exe", "command_line": "cmd.exe /c whoami"}
            ],
        }
    ]
    source.write_text(yaml.safe_dump(data))
    before = source.read_bytes()
    inventory = build_inventory(source, tmp_path, False)
    preview = save_asset(
        source, tmp_path, inventory, conversion_edit(inventory, "users", "test_user", preview=True)
    )
    assert any("actor" in error and "test_user" in error for error in preview.validation_errors)
    with pytest.raises(ValueError, match="test_user"):
        save_asset(source, tmp_path, inventory, conversion_edit(inventory, "users", "test_user"))
    assert source.read_bytes() == before


def test_original_stale_account_can_be_restored_and_stale_revision_rejected(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    data = yaml.safe_load(source.read_text())
    data["environment"]["stale_accounts"] = [
        {"username": "former", "last_active": "2023-11-01", "reason": "Former employee"}
    ]
    source.write_text(yaml.safe_dump(data))
    inventory = build_inventory(source, tmp_path, False)
    request = conversion_edit(
        inventory,
        "stale_accounts",
        "former",
        full_name="Former User",
        email="former@example.com",
        enabled=False,
    )
    save_asset(source, tmp_path, inventory, request)
    inventory = build_inventory(source, tmp_path, False)
    row = next(row for row in inventory.rows["users"] if row.key == "former")
    assert row.account_status == "disabled"
    retirement = conversion_edit(inventory, "users", "former")
    assert retirement.value["reason"] == "Former employee"
    source.write_text(source.read_text() + "\n# External change\n")
    with pytest.raises(FileExistsError, match="Inputs changed"):
        save_asset(source, tmp_path, inventory, retirement)


@pytest.mark.parametrize(
    "records",
    [
        [{"username": "test_user", "target": "other"}],
        [{"username": "test_user", "target": "stale_accounts"}],
        [
            {"username": "test_user", "target": "users"},
            {"username": "TEST_USER", "target": "users"},
        ],
        [
            {
                "username": "test_user",
                "target": "users",
                "previous_user": {
                    "username": "other",
                    "full_name": "Other",
                    "email": "other@example.com",
                },
            }
        ],
    ],
)
def test_compiler_rejects_invalid_account_transition_contracts(
    tmp_path: Path, records: list[dict[str, Any]]
) -> None:
    from evidenceforge.composition.compiler import compile_scenario
    from evidenceforge.models.exceptions import SchemaValidationError

    source = source_file(tmp_path)
    data = yaml.safe_load(source.read_text())
    data["account_transitions"] = records
    source.write_text(yaml.safe_dump(data))
    with pytest.raises(SchemaValidationError, match="account transition"):
        compile_scenario(source, project_root=tmp_path)


def test_account_retirement_cannot_remove_last_regular_user(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    inventory = build_inventory(source, tmp_path, False)
    before = source.read_bytes()
    result = save_asset(
        source, tmp_path, inventory, conversion_edit(inventory, "users", "test_user", preview=True)
    )
    assert any("at least one user" in error for error in result.validation_errors)
    assert source.read_bytes() == before


def test_conversion_transaction_rolls_back_both_included_and_root_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.studio import assets

    source = source_file(tmp_path)
    data = yaml.safe_load(source.read_text())
    data["environment"]["users"].append(
        {"username": "former", "full_name": "Former", "email": "former@example.com"}
    )
    data["environment"]["stale_accounts"] = [
        {"username": "former", "last_active": "2023-11-01", "reason": "Former employee"}
    ]
    data["account_transitions"] = [{"username": "former", "target": "stale_accounts"}]
    included = tmp_path / "users.yaml"
    included.write_text(
        yaml.safe_dump({"environment": {"users": data["environment"].pop("users")}})
    )
    data["includes"] = [included.name]
    source.write_text(yaml.safe_dump(data))
    inventory = build_inventory(source, tmp_path, False)
    before = {path: path.read_bytes() for path in (source, included)}
    real_write = assets._write_atomic
    calls = 0

    def fail_second(path: Path, content: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("Controlled second-file failure")
        real_write(path, content)

    monkeypatch.setattr(assets, "_write_atomic", fail_second)
    with pytest.raises(OSError, match="second-file"):
        save_asset(
            source,
            tmp_path,
            inventory,
            conversion_edit(
                inventory,
                "stale_accounts",
                "former",
                full_name="Former",
                email="former@example.com",
                enabled=False,
            ),
        )
    assert before == {path: path.read_bytes() for path in before}


def test_restoring_group_customizations_while_pack_user_is_retired(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    pack = organization(tmp_path)
    environment_file = pack / "model/environment.yaml"
    pack_data = yaml.safe_load(environment_file.read_text())
    pack_data["environment"]["groups"] = [
        {"name": "staff", "members": ["amy", "zoe"], "permissions": ["read"]}
    ]
    environment_file.write_text(yaml.safe_dump(pack_data))
    data = yaml.safe_load(source.read_text())
    data.pop("version")
    data["scenario_version"] = "2.0"
    data["composition"] = {
        "organization": {
            "source": "project",
            "publisher": "training",
            "name": "office",
            "version": "1.0.0",
        }
    }
    data["environment"]["users"] = []
    data["environment"]["groups"] = [{"name": "staff", "permissions": ["write"]}]
    source.write_text(yaml.safe_dump(data))
    inventory = build_inventory(source, tmp_path, False)
    save_asset(source, tmp_path, inventory, conversion_edit(inventory, "users", "amy"))
    inventory = build_inventory(source, tmp_path, False)
    row = inventory.rows["groups"][0]
    detail = inventory.detail("groups", row.id)
    assert detail.inherited_value["members"] == ["zoe"]
    save_asset(
        source,
        tmp_path,
        inventory,
        edit_for(inventory, "groups", "staff").model_copy(update={"restore_fields": ["*"]}),
    )
    inventory = build_inventory(source, tmp_path, False)
    assert inventory.detail("groups", row.id).value["members"] == ["zoe"]
    assert inventory.detail("groups", row.id).value["permissions"] == ["read"]


def test_pack_stale_account_restoration_is_a_scenario_override(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    pack = organization(tmp_path)
    environment_file = pack / "model/environment.yaml"
    pack_data = yaml.safe_load(environment_file.read_text())
    pack_data["environment"]["stale_accounts"] = [
        {"username": "former", "last_active": "2023-11-01", "reason": "Former employee"}
    ]
    environment_file.write_text(yaml.safe_dump(pack_data))
    pack_bytes = environment_file.read_bytes()
    data = yaml.safe_load(source.read_text())
    data.pop("version")
    data["scenario_version"] = "2.0"
    data["composition"] = {
        "organization": {
            "source": "project",
            "publisher": "training",
            "name": "office",
            "version": "1.0.0",
        }
    }
    source.write_text(yaml.safe_dump(data))
    inventory = build_inventory(source, tmp_path, False)
    save_asset(
        source,
        tmp_path,
        inventory,
        conversion_edit(
            inventory,
            "stale_accounts",
            "former",
            full_name="Former User",
            email="former@example.com",
            enabled=False,
        ),
    )
    inventory = build_inventory(source, tmp_path, False)
    assert "former" not in [row.key for row in inventory.rows.get("stale_accounts", [])]
    assert (
        next(row for row in inventory.rows["users"] if row.key == "former").origin.kind == "mixed"
    )
    save_asset(source, tmp_path, inventory, conversion_edit(inventory, "users", "former"))
    assert environment_file.read_bytes() == pack_bytes


def test_engine_retains_stale_service_account_collision_guard(tmp_path: Path) -> None:
    source = source_file(tmp_path)
    data = yaml.safe_load(source.read_text())
    data["environment"]["users"].append(
        {"username": "remaining", "full_name": "Remaining", "email": "remaining@example.com"}
    )
    data["environment"]["service_accounts"] = ["test_user"]
    source.write_text(yaml.safe_dump(data))
    inventory = build_inventory(source, tmp_path, False)
    result = save_asset(
        source, tmp_path, inventory, conversion_edit(inventory, "users", "test_user", preview=True)
    )
    assert any("service" in error and "test_user" in error for error in result.validation_errors)
