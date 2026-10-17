# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Frozen helper intent remains bounded and tied to an eligible installation."""

import json
import random
import shlex
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from evidenceforge.generation.deployment_compiler import compile_deployment_registry
from evidenceforge.generation.deployment_registry import (
    CompiledApplicationDescriptor,
    DeploymentContentRegistry,
    _pack_application_descriptor,
    _unpack_application_descriptor,
)
from evidenceforge.generation.world_model import WorldModel
from tests.support.macos_ssh import macos_ssh_scenario
from tests.unit.test_macos_code_signature import _application

_HELPER = "/Applications/Example.app/Contents/Helpers/Worker"


def _descriptor() -> CompiledApplicationDescriptor:
    return CompiledApplicationDescriptor(
        application_id="example-editor",
        platform="macos",
        image_path="/Applications/Example.app/Contents/MacOS/Example",
        command_templates=('"/Applications/Example.app/Contents/MacOS/Example"',),
        categories=("user_app",),
        command_parameter_pools=(("mode", ("render", "network")),),
        child_commands=((_HELPER, f'"{_HELPER}" --mode={{mode}} --user={{username}}'),),
    )


def test_compiled_helper_materializes_from_frozen_assignment_without_mutable_catalog(
    scenarios_dir: Path,
) -> None:
    scenario = macos_ssh_scenario(scenarios_dir)
    user = scenario.environment.users[0]
    user.persona = "developer"
    app = _application()
    platform = app.platforms["macos"]
    platform.command_templates = [f'"{platform.image_path}"']
    platform.children = [f'"{_HELPER}" --mode={{mode}} --user={{username}}']
    platform.command_parameter_pools = {"mode": ["render", "network"]}
    registry = compile_deployment_registry(
        scenario, WorldModel(scenario, "example.test"), application_entries=(app,)
    )
    profile = registry.user_profile_for("TEST-01", user.username, "macos")
    assert profile is not None
    assignment = registry.user_application_assignment_for_application(profile.profile_id, app.id)
    assert assignment is not None
    platform.children[:] = ['"/tmp/replacement"']
    platform.command_parameter_pools["mode"][:] = ["replacement"]
    rng = random.Random(719)
    modes: set[str] = set()
    for _ in range(24):
        image, command = registry.materialize_application_child_command(
            rng, assignment, child_index=0, username=user.username
        )
        assert image == _HELPER
        arguments = shlex.split(command)
        assert arguments[0] == image and arguments[2] == f"--user={user.username}"
        modes.add(arguments[1])
        assert registry.resolve_binary("TEST-01", image, "macos") is not None
    assert modes == {"--mode=render", "--mode=network"}
    before = rng.getstate()
    for index in (-1, 1, True):
        assert (
            registry.materialize_application_child_command(rng, assignment, child_index=index)
            is None
        )
    assert (
        registry.materialize_application_child_command(
            rng, assignment, child_index=0, username="another-user"
        )
        is None
    )
    forged = replace(assignment, principal="another-user", materialization_principal="another-user")
    assert registry.materialize_application_child_command(rng, forged, child_index=0) is None
    assert rng.getstate() == before


def test_helper_packing_preserves_old_rows_and_detaches_public_descriptor_views() -> None:
    descriptor = _descriptor()
    assert _unpack_application_descriptor(_pack_application_descriptor(descriptor)) == descriptor
    legacy = replace(descriptor, child_commands=())
    assert len(json.loads(_pack_application_descriptor(legacy))) == 8
    assert _unpack_application_descriptor(_pack_application_descriptor(legacy)) == legacy
    registry = DeploymentContentRegistry(application_descriptors=(descriptor,))
    retained = registry.application_descriptor(descriptor.application_id, "macos")
    assert retained.child_commands == descriptor.child_commands
    object.__setattr__(retained, "child_commands", (("/tmp/replacement", "/tmp/replacement"),))
    object.__setattr__(descriptor, "child_commands", ())
    assert registry.application_descriptor("example-editor", "macos").child_commands == (
        (_HELPER, f'"{_HELPER}" --mode={{mode}} --user={{username}}'),
    )


@pytest.mark.parametrize(
    "children",
    [
        [],
        (("only-image",),),
        (("/bin/a", 42),),
        (("/bin/a", "/bin/b"),),
        (("/bin/{arbitrary}", "/bin/{arbitrary}"),),
        ((_HELPER, ""),),
        ((_HELPER, _HELPER + " x" * 65536),),
    ],
)
def test_helper_admission_rejects_invalid_or_unbounded_intent(children: object) -> None:
    with pytest.raises(ValueError):
        replace(_descriptor(), child_commands=children)


def test_helper_strings_are_charged_to_shared_descriptor_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation import deployment_registry as module

    descriptor = _descriptor()
    legacy = replace(descriptor, child_commands=())
    assert descriptor.retained_text_bytes == legacy.retained_text_bytes + sum(
        len(text.encode("utf-8")) for child in descriptor.child_commands for text in child
    )
    monkeypatch.setattr(
        module, "_MAX_APPLICATION_DESCRIPTOR_TEXT_BYTES", legacy.retained_text_bytes
    )
    with pytest.raises(ValueError, match="bounded text budget"):
        _descriptor()


def test_helper_graph_rejects_subclass_callbacks_and_excessive_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation import deployment_registry as module

    class CallbackString(str):
        def strip(self, *_args: object, **_kwargs: object) -> str:
            raise AssertionError("Untrusted helper string callback ran")

    class CallbackTuple(tuple[object, ...]):
        def __iter__(self) -> Iterator[object]:
            raise AssertionError("Untrusted helper tuple callback ran")

    for children in (
        CallbackTuple(),
        (CallbackTuple((_HELPER, _HELPER)),),
        ((CallbackString(_HELPER), _HELPER),),
    ):
        with pytest.raises(ValueError, match="exact"):
            replace(_descriptor(), child_commands=children)
    valid = _descriptor()
    monkeypatch.setattr(module, "_MAX_APPLICATION_COMMAND_TEMPLATES", 1)
    with pytest.raises(ValueError, match="bounded limit"):
        replace(valid, child_commands=valid.child_commands * 2)


@pytest.mark.parametrize("children", [None, [1], [["/bin/a"]], [["/bin/a", 3]]])
def test_helper_packed_rows_reject_malformed_optional_tail(children: object) -> None:
    row = json.loads(_pack_application_descriptor(replace(_descriptor(), child_commands=())))
    with pytest.raises(ValueError, match="child command"):
        _unpack_application_descriptor(json.dumps([*row, children]).encode())


def test_helper_cannot_materialize_an_uninstalled_path_or_change_windows_principal() -> None:
    from evidenceforge.generation.deployment_registry import (
        HostDeploymentSpec,
        UserApplicationAssignmentSpec,
    )
    from tests.unit.test_deployment_registry import (
        _application_profile,
        _user_installation,
        _user_profile,
        _windows_release,
    )

    profile = _user_profile("WS-01", "Alice")
    release = _windows_release(product_id="example", artifact_name="example.exe", variant="test")
    image = r"C:\Users\Alice\Apps\example.exe"
    installation = _user_installation(release, profile, image, application_id="example")
    app_profile = _application_profile(profile, installation, application_id="example")
    template = r"C:\Users\{username}\Apps\example.exe"
    missing = r"C:\Users\{username}\Apps\missing.exe"
    descriptor = CompiledApplicationDescriptor(
        application_id="example",
        platform="windows",
        image_path=template,
        command_templates=(f'"{template}"',),
        categories=("user_app",),
        child_commands=((missing, f'"{missing}"'), (template, f'"{template}" --user {{username}}')),
    )
    spec = UserApplicationAssignmentSpec(
        hostname="WS-01",
        principal="alice",
        platform="windows",
        user_profile_id=profile.profile_id,
        application_profile_id=app_profile.application_profile_id,
        persona="developer",
        eligible_categories=("user_app",),
        intensity=1.0,
    )
    registry = DeploymentContentRegistry(
        binary_releases=(release,),
        user_profiles=(profile,),
        installations=(installation,),
        application_profiles=(app_profile,),
        application_descriptors=(descriptor,),
        host_deployments=(
            HostDeploymentSpec(
                hostname="WS-01",
                roles=("workstation",),
                platform="windows",
                os_build="22621.3155",
                architecture="x64",
                installation_ids=(installation.installation_id,),
            ),
        ),
        user_application_assignments=(spec,),
    )
    assignment = registry.user_application_assignment(spec.assignment_id)
    rng = random.Random(27)
    before = rng.getstate()
    assert registry.materialize_application_child_command(rng, assignment, child_index=0) is None
    assert rng.getstate() == before
    assert registry.materialize_application_child_command(
        rng, assignment, child_index=1, username="ALICE"
    ) == (image, f'"{image}" --user Alice')
