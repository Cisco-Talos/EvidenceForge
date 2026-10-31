# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Independently authored release/signing identities through compiled deployment."""

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import ApplicationEntry, MacCodeSignatureEntry
from evidenceforge.events.content_identity import (
    BinaryReleaseIdentity,
    BinaryReleaseKey,
    MachOCodeSignature,
)
from evidenceforge.events.contexts import EmailContext
from evidenceforge.generation.actions.network_connection import NetworkConnectionRequest
from evidenceforge.generation.activity.application_catalog import application_descriptor
from evidenceforge.generation.deployment_compiler import (
    _intern_release,
    _release_for_application_artifact,
)
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    _pack_binary_release,
    _unpack_binary_release,
)


def _application() -> ApplicationEntry:
    return ApplicationEntry.model_validate(
        {
            "id": "example-editor",
            "display_name": "Example Editor",
            "categories": ["code"],
            "personas": ["developer"],
            "platforms": {
                "macos": {
                    "image_path": "/Applications/Example.app/Contents/MacOS/Example",
                    "deployment": {
                        "kind": "managed",
                        "product_id": "example-editor",
                        "version": "1.0",
                        "build": "1",
                        "architectures": ["arm64"],
                        "scope": "machine",
                    },
                    "code_signature": {
                        "signing_id": "test.example.editor",
                        "team_id": "EXAMPLE123",
                    },
                }
            },
        }
    )


def _release(
    application: ApplicationEntry, path: str | None = None, architecture: str = "arm64"
) -> BinaryReleaseIdentity:
    platform = application.platforms["macos"]
    return _release_for_application_artifact(
        application, "macos", platform, path or platform.image_path, None, architecture, "26.0"
    )


def _network_request(binary: BinaryReleaseIdentity) -> NetworkConnectionRequest:
    return NetworkConnectionRequest(
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        time=datetime(2026, 7, 14, 12, tzinfo=UTC),
        email=EmailContext(
            message_id="message-1",
            artifact_id="artifact-1",
            envelope_from="sender@example.test",
            header_from="sender@example.test",
            attachments=[{"payload": binary}],
        ),
    )


def test_durable_network_identity_authenticates_nested_signing_metadata() -> None:
    binary = _release(_application())
    restored = _unpack_binary_release(_pack_binary_release(binary))
    original = _network_request(binary).stable_id
    assert _network_request(restored).stable_id == original
    for signature in (
        None,
        replace(binary.code_signature, team_id="DIFFERENT1"),
        replace(binary.code_signature, cdhash="1" * 40),
    ):
        assert _network_request(replace(binary, code_signature=signature)).stable_id != original


def test_explicit_no_entitlements_has_distinct_identity_and_roundtrips() -> None:
    application = _application()
    unknown = _release(application)
    application.platforms["macos"].code_signature = MacCodeSignatureEntry(
        signing_id="test.example.editor", team_id="EXAMPLE123", entitlements="absent"
    )
    known = _release(application)
    assert unknown.code_signature.entitlements is None
    assert known.code_signature.entitlements == "absent"
    assert known.code_signature.cdhash != unknown.code_signature.cdhash
    assert len(unknown.code_signature.serialized_values()) == 3
    assert len(known.code_signature.serialized_values()) == 4
    assert _unpack_binary_release(_pack_binary_release(known)) == known
    assert _network_request(unknown).stable_id != _network_request(known).stable_id


def test_boolean_entitlements_are_detached_canonical_and_checkpoint_roundtrippable() -> None:
    app = _application()
    values = {"invented.enabled": True, "invented.disabled": False}
    app.platforms["macos"].code_signature = MacCodeSignatureEntry(
        signing_id="test.example.editor", entitlements=values
    )
    binary = _release(app)
    signature = binary.code_signature
    assert signature.entitlements == (("invented.disabled", False), ("invented.enabled", True))
    values["invented.enabled"] = False
    assert dict(signature.entitlements)["invented.enabled"] is True
    assert _unpack_binary_release(_pack_binary_release(binary)) == binary
    encoded = json.loads(json.dumps(signature.serialized_values()))
    assert MachOCodeSignature.from_serialized_values(encoded) == signature
    assert (
        _network_request(binary).stable_id != _network_request(_release(_application())).stable_id
    )


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"a": 1},
        {"a": "true"},
        {"a": None},
        {"a": [1]},
        {"a": [True]},
        {"a": {"nested": True}},
        {"\0": True},
    ],
)
def test_catalog_boolean_entitlements_reject_unreviewed_or_coerced_values(value: object) -> None:
    with pytest.raises(ValidationError):
        MacCodeSignatureEntry(signing_id="test.example.editor", entitlements=value)


@pytest.mark.parametrize("value", [[], (("a", 1),), (("a", True), ("a", False)), (("a", []),)])
def test_canonical_entitlements_cannot_retain_mutable_or_ambiguous_data(value: object) -> None:
    with pytest.raises(ValueError):
        MachOCodeSignature("invented", None, "a" * 40, value)


def test_string_array_entitlements_are_immutable_and_use_an_explicit_checkpoint_tag() -> None:
    app = _application()
    values = {
        "invented.allowed": ["example.one", "example.two"],
        "invented.enabled": True,
        "invented.empty": [],
    }
    entry = MacCodeSignatureEntry(signing_id="test.example.editor", entitlements=values)
    app.platforms["macos"].code_signature = entry
    binary = _release(app)
    signature = binary.code_signature
    values["invented.allowed"].append("mutated")
    assert dict(signature.entitlements)["invented.allowed"] == ("example.one", "example.two")
    assert signature.serialized_values()[3][0] == "boolean-string-array-v1"
    assert _unpack_binary_release(_pack_binary_release(binary)) == binary
    assert (
        MachOCodeSignature.from_serialized_values(
            json.loads(json.dumps(signature.serialized_values()))
        )
        == signature
    )
    changed = replace(
        signature,
        entitlements=(
            ("invented.allowed", ("example.two", "example.one")),
            ("invented.enabled", True),
            ("invented.empty", ()),
        ),
    )
    assert (
        _network_request(replace(binary, code_signature=changed)).stable_id
        != _network_request(binary).stable_id
    )


@pytest.mark.parametrize("application_id", ["macos-terminal", "macos-login"])
def test_vendor_terminal_signatures_compile_without_propagating_to_helpers(
    application_id: str,
) -> None:
    app = ApplicationEntry.model_validate(application_descriptor(application_id))
    release = _release(app)
    signature = release.code_signature
    assert signature is not None and signature.team_id is None
    assert (
        signature.signing_id
        == {
            "macos-terminal": "com.apple.Terminal",
            "macos-login": "com.apple.login",
        }[application_id]
    )
    entitlements = dict(signature.entitlements)
    if application_id == "macos-terminal":
        assert entitlements["com.apple.private.tcc.allow-prompting"] == ("kTCCServiceAll",)
        assert all(type(value) is bool for key, value in entitlements.items() if "tcc" not in key)
    else:
        assert all(type(value) is bool for value in entitlements.values())
    assert _unpack_binary_release(_pack_binary_release(release)) == release
    helper = _release(app, "/invented/helper")
    assert helper.code_signature is None


@pytest.mark.parametrize(
    "tag,values",
    [
        ("boolean-v1", [["invented.array", ["value"]]]),
        ("boolean-string-array-v1", [["invented.enabled", True]]),
        ("unqualified", [["invented.array", ["value"]]]),
    ],
)
def test_entitlement_serialization_rejects_downgraded_or_ambiguous_tags(
    tag: str, values: list
) -> None:
    with pytest.raises(ValueError):
        MachOCodeSignature.from_serialized_values(("invented", None, "a" * 40, (tag, values)))


@pytest.mark.parametrize(
    "platform,architecture,expected",
    [
        ("windows", "x64", "network-connection-a2bc3914-d47e-4264-a4a4-282c73476b9c"),
        ("linux", "x64", "network-connection-2dfbd11d-3641-44d8-b828-e2e33b6c4443"),
        ("macos", "arm64", "network-connection-65136c76-fb87-4204-8bf9-144f87696659"),
    ],
)
def test_absent_signer_preserves_pre_extension_network_request_identity(
    platform: str, architecture: str, expected: str
) -> None:
    # IDs independently calculated against the dev checkout with the same invented request.
    binary = BinaryReleaseIdentity(
        BinaryReleaseKey(
            product_id="example",
            version="1",
            build="1",
            architecture=architecture,
            platform=platform,
            artifact_name="example",
            variant="release",
        )
    )
    assert binary.code_signature is None
    assert _network_request(binary).stable_id == expected


def test_signing_identity_is_release_scoped_separate_from_content_and_bundle_path() -> None:
    app = _application()
    binary = _release(app)
    assert binary.code_signature.signing_id == "test.example.editor"
    assert binary.key.architecture == "arm64"
    assert len(binary.code_signature.cdhash) == 40
    assert binary.code_signature.cdhash != binary.digests.sha1
    moved = app.model_copy(deep=True)
    moved.platforms[
        "macos"
    ].image_path = "/Users/casey/Applications/Example.app/Contents/MacOS/Example"
    assert _release(moved) == binary
    upgraded = app.model_copy(deep=True)
    upgraded.platforms["macos"].deployment = app.platforms["macos"].deployment.model_copy(
        update={"build": "2"}
    )
    assert _release(upgraded).code_signature.cdhash != binary.code_signature.cdhash
    assert _release(app, architecture="x64").code_signature.cdhash != binary.code_signature.cdhash


def test_missing_metadata_and_helpers_do_not_inherit_owner_signature() -> None:
    app = _application()
    helper = _release(app, "/Applications/Example.app/Contents/Helpers/Worker")
    assert helper.code_signature is None
    app.platforms["macos"].code_signature = None
    assert _release(app).code_signature is None


def test_null_team_survives_existing_exclude_none_catalog_roundtrip() -> None:
    app = _application()
    app.platforms["macos"].code_signature = MacCodeSignatureEntry(signing_id="test.example.editor")
    restored = ApplicationEntry.model_validate(
        app.model_dump(exclude_none=True, exclude_unset=True)
    )
    assert _release(restored).code_signature.team_id is None


def test_compact_registry_roundtrip_preserves_signature_with_and_without_identity_cache() -> None:
    binary = _release(_application())
    assert _unpack_binary_release(_pack_binary_release(binary)) == binary
    # Iterator input exercises packed reconstruction instead of retaining source objects.
    registry = DeploymentContentRegistry(binary_releases=iter([binary]))
    restored = registry.binary_release_by_content_id(binary.content_id)
    assert restored == binary and restored.code_signature == binary.code_signature
    unknown = replace(binary, code_signature=None)
    packed = _pack_binary_release(unknown)
    assert len(json.loads(packed)) == 14  # Preserve old rows when the new optional fact is absent.
    assert _unpack_binary_release(packed) == unknown


def test_conflicting_signer_for_one_binary_requires_distinct_release_identity() -> None:
    binary = _release(_application())
    alternate = replace(
        binary,
        code_signature=MachOCodeSignature.derive(
            binary.key, signing_id="test.example.other", team_id="OTHERTEAM1"
        ),
    )
    releases = {binary.canonical_key: binary}
    with pytest.raises(ValueError, match="contradictory code_signature"):
        _intern_release(releases, alternate)
    assert releases[binary.canonical_key] == binary
    releases = {binary.canonical_key: replace(binary, code_signature=None)}
    assert _intern_release(releases, binary) == binary


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_mac_signature_cannot_be_configured_or_bound_to_another_platform(platform: str) -> None:
    payload = _application().model_dump()
    payload["platforms"] = {platform: payload["platforms"]["macos"]}
    with pytest.raises(ValidationError, match="code_signature requires macos"):
        ApplicationEntry.model_validate(payload)
    binary = _release(_application())
    key = replace(binary.key, platform=platform)
    with pytest.raises(ValueError, match="macOS binary"):
        replace(binary, key=key)
    with pytest.raises(ValueError, match="macOS binary"):
        MachOCodeSignature.derive(key, signing_id="test.example.editor", team_id=None)


@pytest.mark.parametrize("value", ["", " ", "test.example\0editor", " padded "])
def test_catalog_rejects_ambiguous_signing_identifiers(value: str) -> None:
    with pytest.raises(ValidationError):
        MacCodeSignatureEntry(signing_id=value)


def test_code_signature_validates_hash_without_using_whole_file_hash() -> None:
    key = BinaryReleaseKey("example-editor", "1", "1", "arm64", "macos", "Example")
    signature = MachOCodeSignature.derive(key, signing_id="test.example.editor", team_id=None)
    assert signature == MachOCodeSignature.derive(
        key, signing_id="test.example.editor", team_id=None
    )
    with pytest.raises(ValueError, match="hexadecimal"):
        replace(signature, cdhash="not-a-code-directory-hash")


def test_packaged_terminal_signer_reaches_compiled_process_binary(scenarios_dir: Path) -> None:
    from evidenceforge.generation.deployment_compiler import compile_native_deployment_registry
    from evidenceforge.generation.world_model import WorldModel
    from tests.support.macos_ssh import macos_ssh_scenario

    scenario = macos_ssh_scenario(scenarios_dir)
    registry = compile_native_deployment_registry(scenario, WorldModel(scenario, "example.test"))
    terminal = registry.resolve_binary(
        "TEST-01", "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", "macos"
    )
    assert terminal is not None and terminal.key.architecture == "arm64"
    assert terminal.code_signature.signing_id == "com.apple.Terminal"
    assert terminal.code_signature.team_id is None
    assert terminal.code_signature.cdhash != terminal.digests.sha1
    assert registry.resolve_binary("SSH-TEST", terminal.key.artifact_name, "linux") is None
