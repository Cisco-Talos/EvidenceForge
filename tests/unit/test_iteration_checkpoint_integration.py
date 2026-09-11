"""Checkpoint coverage for state added by the iteration-test improvements."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from evidenceforge.formats import load_format
from evidenceforge.generation.checkpoints.emitter_spools import EmitterSpoolParticipant
from evidenceforge.generation.emitters.cisco_asa import CiscoAsaEmitter
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter


def test_emitter_spool_invokes_sorted_runtime_restore_hook(tmp_path: Path) -> None:
    def checkpoint_emitter(root: Path) -> tuple[object, ExternalSortedLineWriter]:
        output = root / "sensor" / "conn.log"
        sorted_writer = ExternalSortedLineWriter(
            output,
            sort_key=lambda line: line,
            checkpoint_mode=True,
        )
        route_writer = SimpleNamespace(
            _sorted_writer=sorted_writer,
            event_count=0,
            output_path=output,
        )
        emitter = SimpleNamespace(_writers={"sensor": route_writer}, restored_paths=())
        emitter._get_writer = lambda route: emitter._writers[route]
        emitter.checkpoint_sorted_runs_restored = lambda paths: setattr(
            emitter, "restored_paths", paths
        )
        return emitter, sorted_writer

    source_root = tmp_path / "source"
    source_emitter, source_writer = checkpoint_emitter(source_root)
    source = EmitterSpoolParticipant(
        emitters={"cisco_asa": source_emitter},
        output_root=source_root,
    )
    source_writer.write("first")
    source_writer.flush()
    seal = source.prepare_checkpoint(0)
    source.checkpoint_committed(0)

    restored_root = tmp_path / "restored"
    restored_emitter, _restored_writer = checkpoint_emitter(restored_root)
    restored = EmitterSpoolParticipant(
        emitters={"cisco_asa": restored_emitter},
        output_root=restored_root,
    )
    restored.restore_checkpoint(
        seal.head.payload,
        tuple(segment.payload for segment in seal.segments),
    )

    assert len(restored_emitter.restored_paths) == 1
    assert restored_emitter.restored_paths[0].read_text(encoding="utf-8") == "first\n"


def test_cisco_asa_rebuilds_canonical_connection_ids_from_restored_runs(
    tmp_path: Path,
) -> None:
    emitter = CiscoAsaEmitter(load_format("cisco_asa"), tmp_path / "output")
    run = tmp_path / "checkpoint-run.log"
    run.write_text(
        "<166>Mar 18 12:00:03 fw-perimeter %ASA-6-302013: Built inbound TCP connection "
        "1681559 for outside:192.0.2.2/50001 to inside:10.0.0.1/443\n"
        "<166>Mar 18 12:00:03 fw-perimeter %ASA-6-302013: Built inbound TCP connection "
        "1681558 for outside:192.0.2.1/50000 to inside:10.0.0.1/443\n"
        "<166>Mar 18 12:00:04 fw-perimeter %ASA-6-302014: Teardown TCP connection "
        "1681558 for outside:192.0.2.1/50000 to inside:10.0.0.1/443\n",
        encoding="utf-8",
    )

    emitter.checkpoint_sorted_runs_restored((run,))

    lines = run.read_text(encoding="utf-8").splitlines()
    assert "1681558" in lines[0]
    assert "1681559" in lines[1]
    assert emitter._canonical_connection_ids == {
        ("fw-perimeter", 1_681_558),
        ("fw-perimeter", 1_681_559),
    }
