"""Docker reference ownership tests never invoke Docker, SSH or native capture."""

import ast
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts import macos_remote_docker_reference as kit

from tests.unit.test_macos_remote_process_reference import ROOT, experiment


def docker_experiment() -> tuple[kit.DockerGraph, list[dict]]:
    graph, rows = experiment()
    payload = rows[1]["event"]["exec"]
    payload["args"] = [graph.images[0]["paths"][0]]
    payload["env"] = ["EFORGE_REFERENCE_RUN=" + ROOT]
    return kit.DockerGraph(graph.images, ROOT), rows


def test_exact_injected_marker_and_signed_image_authenticate_only_owned_descendants() -> None:
    graph, rows = docker_experiment()
    for row in rows:
        graph.accept(json.dumps(row).encode())
    assert graph.main is not None
    assert sorted(graph.rows) == [1, 2, 4, 5, 6, 7]
    assert kit.process.identity(rows[0]["process"]) not in graph.known
    assert graph.births == graph.closed


@pytest.mark.parametrize("change", ["missing", "other_run", "duplicate", "file_object", "signer"])
def test_same_app_or_pid_alone_cannot_authenticate_a_docker_run(change: str) -> None:
    graph, rows = docker_experiment()
    row = deepcopy(rows[1])
    payload = row["event"]["exec"]
    if change == "missing":
        payload["env"] = []
    elif change == "other_run":
        payload["env"][0] += "-other"
    elif change == "duplicate":
        payload["env"].append(payload["env"][0])
    elif change == "file_object":
        payload["target"]["executable"]["stat"]["st_ino"] += 1
    else:
        payload["target"]["team_id"] = "INVENTED_CANARY"
    graph.accept(json.dumps(row).encode())
    assert graph.main is None and not graph.rows and not graph.known


def test_container_inventory_rejects_every_nonempty_result() -> None:
    assert kit.inventory_empty(b"")
    assert kit.inventory_empty(b"\n")
    assert not kit.inventory_empty(b"invented-container-id\n")
    with pytest.raises(ValueError, match="CLI_CONTROL"):
        kit.inventory_empty(b"x" * 65537)


def test_cli_uses_explicit_local_socket_and_fresh_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kit, "_current_account", lambda: SimpleNamespace(pw_dir="/Users/invented"))
    args = kit.cli_arguments(tmp_path)
    assert args[1:] == [
        "--host",
        "unix:///Users/invented/.docker/run/docker.sock",
        "--config",
        str(tmp_path / "cli-config"),
    ]


def test_runner_parses_on_reference_hosts_python39() -> None:
    ast.parse(Path(kit.__file__).read_text(), feature_version=(3, 9))
