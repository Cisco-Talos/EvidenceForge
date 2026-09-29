"""Runs page uses the available space for findings and concurrent jobs."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from evidenceforge.desktop.main import _STYLE, JobsPane
from evidenceforge.desktop.state import GenerationJob


def test_runs_page_expands_findings_and_adapts_to_window_width(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    app.setStyle("Fusion")
    app.setStyleSheet(_STYLE)
    pane = JobsPane(tmp_path / "runs")
    job = GenerationJob(
        id="first",
        scenario=tmp_path / "scenario.yaml",
        output_root=tmp_path / "runs" / "first",
        progress_file=tmp_path / "progress.jsonl",
        log_file=tmp_path / "generation.log",
        started_at=time.time(),
        status="completed",
    )
    pane.add_job(job)
    try:
        pane.resize(1400, 800)
        pane.show()
        app.processEvents()
        assert not pane.validation_panel.isVisible()
        assert pane.job_count.text() == "1 run"
        pane.validation.setPlainText("VALID WITH WARNINGS\n" + "Finding details\n" * 40)
        app.processEvents()
        assert pane.work_area.orientation() == Qt.Orientation.Horizontal
        assert pane.validation.height() > 500
        assert pane.cards["first"].width() < pane.width() * 0.75

        pane.resize(820, 700)
        app.processEvents()
        assert pane.work_area.orientation() == Qt.Orientation.Vertical
        assert pane.validation.height() > 150
        pane.validation.clear()
        app.processEvents()
        assert not pane.validation_panel.isVisible()
        assert pane.cards["first"].width() > pane.width() * 0.8
    finally:
        pane.close()
        app.processEvents()
