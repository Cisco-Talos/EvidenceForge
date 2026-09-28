"""Desktop library navigation and scorecard persistence."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication, QInputDialog, QMessageBox

from evidenceforge.desktop.app_server import CodexBridge
from evidenceforge.desktop.main import _STYLE, MainWindow
from evidenceforge.desktop.state import DesktopState, GenerationJob, StateStore


def test_library_is_landing_page_and_saves_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    app.setStyle("Fusion")
    app.setStyleSheet(_STYLE)
    workspace = tmp_path / "workspace"
    scenario = workspace / "scenarios" / "demo" / "scenario.yaml"
    scenario.parent.mkdir(parents=True)
    scenario.write_text("version: '1.0'\nname: demo\nenvironment: {}\n", encoding="utf-8")
    executable = tmp_path / "fake-eforge"
    executable.write_text(
        f"#!{sys.executable}\n"
        'print(\'{"scenario_name":"demo","evaluated_at":"2026-09-28T12:00:00Z",'
        '"overall_score":84,"acceptance_passed":true,"total_records":123}\')\n',
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("EFORGE_DESKTOP_EFORGE_BIN", str(executable))
    job = GenerationJob(
        id="job1",
        scenario=scenario,
        output_root=tmp_path / "bundle",
        progress_file=tmp_path / "progress.jsonl",
        log_file=tmp_path / "generation.log",
        pid=1,
        process_created_at=0,
        started_at=time.time(),
        status="completed",
    )
    store = StateStore(tmp_path / "state")
    window = MainWindow(store, DesktopState(workspace=workspace, jobs=[job]))
    try:
        assert window.pages.currentIndex() == 0
        item = window.scenario_library.selected_item()
        assert item is not None and item.name == "demo"
        window._evaluate_latest(item)
        deadline = time.monotonic() + 5
        while window.evaluation_processes and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        assert not window.evaluation_processes
        assert "84/100" in window.scenario_library.score.text()
        assert (store.directory / "evaluations" / "job1.json").is_file()
    finally:
        window.close()


def test_folder_and_content_filters_work_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "workspace"
    for name, version, host in (
        ("alpha", "1.0", "WS-MAYA-01"),
        ("beta", "2.0", "WS-BEN-01"),
    ):
        path = workspace / "scenarios" / name / "scenario.yaml"
        path.parent.mkdir(parents=True)
        path.write_text(
            f"version: '{version}'\nname: {name}\ndescription: Training case\n"
            f"environment:\n  users:\n    - username: {name}\n"
            f"  systems:\n    - hostname: {host}\n",
            encoding="utf-8",
        )
    store = StateStore(tmp_path / "state")
    window = MainWindow(store, DesktopState(workspace=workspace))
    try:
        pane = window.scenario_library
        assert pane.list.count() == 2
        pane.search.setText("WS-MAYA-01")
        assert pane.list.count() == 1
        assert pane.selected_item() is not None and pane.selected_item().name == "alpha"

        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("Project A", True))
        window._create_scenario_folder()
        assert pane.folder_filter.currentData() == "Project A"
        assert pane.list.count() == 1
        assert store.load(workspace).scenario_folders[str(workspace)].names == ["Project A"]

        pane.search.clear()
        pane.version_filter.setCurrentIndex(pane.version_filter.findData("2.0"))
        assert pane.list.count() == 0
        pane.folder_filter.setCurrentIndex(0)
        assert pane.list.count() == 1
        assert pane.selected_item() is not None and pane.selected_item().name == "beta"

        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("Casework", True))
        window._rename_scenario_folder("Project A")
        assert (
            window._folder_state().assignments[
                str(workspace / "scenarios" / "alpha" / "scenario.yaml")
            ]
            == "Casework"
        )
        monkeypatch.setattr(
            QMessageBox,
            "question",
            lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
        )
        window._delete_scenario_folder("Casework")
        assert not window._folder_state().assignments
        assert (workspace / "scenarios" / "alpha" / "scenario.yaml").is_file()
    finally:
        window.close()
        app.processEvents()
