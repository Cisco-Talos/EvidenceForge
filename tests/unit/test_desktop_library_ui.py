"""Desktop library navigation and scorecard persistence."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QAccessible, QColor
from PySide6.QtTest import QSignalSpy, QTest
from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog, QMessageBox, QTabBar

from evidenceforge.desktop.app_server import CodexBridge
from evidenceforge.desktop.main import _STYLE, MainWindow
from evidenceforge.desktop.state import DesktopState, GenerationJob, ScenarioFolders, StateStore


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
        assert "name: demo" in window.scenario_library.source_preview.toPlainText()
        assert not window.scenario_library.source_preview.isHidden()
        window._evaluate_latest(item)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            app.processEvents()
            window._poll_jobs()
            if any(job.status == "completed" for job in window.evaluation_jobs.values()):
                break
            time.sleep(0.01)
        assert any(job.status == "completed" for job in window.evaluation_jobs.values())
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
        assert len(pane._tree_items) == 2
        alpha_path = workspace / "scenarios" / "alpha" / "scenario.yaml"
        alpha_row = pane._tree_items[alpha_path]
        rows_removed = QSignalSpy(pane.tree.model().rowsRemoved)
        pane.search.setText("WS-MAYA-01")
        assert len(pane._tree_items) == 1
        assert pane.selected_item() is not None and pane.selected_item().name == "alpha"
        assert pane._tree_items[alpha_path] is alpha_row
        pane.search.setText("no matching scenario")
        assert not pane._tree_items
        pane.search.setText("WS-MAYA-01")
        assert pane._tree_items[alpha_path] is alpha_row
        assert rows_removed.count() == 0

        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("Project A", True))
        window._create_scenario_folder()
        assert pane.selected_folder_name() == "Project A"
        pane.select_folder("Project A")
        assert pane.source_preview.isHidden()
        assert len(pane._tree_items) == 1
        assert store.load(workspace).scenario_folders[str(workspace)].names == ["Project A"]

        pane.search.clear()
        pane._build_filter_menu()
        version_menu = next(
            action.menu() for action in pane.filter_menu.actions() if action.text() == "Version"
        )
        assert version_menu is not None
        next(action for action in version_menu.actions() if action.text() == "2.0").trigger()
        assert len(pane._tree_items) == 1
        assert pane.filter_button.text() == "Filters · 1"
        assert pane.selected_item() is not None and pane.selected_item().name == "beta"
        beta_path = workspace / "scenarios" / "beta" / "scenario.yaml"
        more = pane.tree.itemWidget(pane._tree_items[beta_path], 1)
        assert more is not None
        menu = more.menu()
        assert menu is not None
        move_menu = menu.actions()[0].menu()
        assert move_menu is not None
        next(action for action in move_menu.actions() if action.text() == "Project A").trigger()
        assert window._folder_state().assignments[str(beta_path)] == "Project A"

        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("Casework", True))
        folder_more = pane.tree.itemWidget(pane._folder_items["Project A"], 1)
        assert folder_more is not None and folder_more.menu() is not None
        folder_more.menu().actions()[0].trigger()
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
        folder_more = pane.tree.itemWidget(pane._folder_items["Casework"], 1)
        assert folder_more is not None and folder_more.menu() is not None
        folder_more.menu().actions()[1].trigger()
        assert not window._folder_state().assignments
        assert (workspace / "scenarios" / "alpha" / "scenario.yaml").is_file()
        pane.clear_filters()
        assert len(pane._tree_items) == 2
    finally:
        window.close()
        app.processEvents()


@pytest.mark.skipif(sys.platform != "darwin", reason="Cocoa accessibility workaround")
def test_accessible_library_selection_keeps_visible_highlight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "workspace"
    for name in ("alpha", "beta"):
        scenario = workspace / "scenarios" / name / "scenario.yaml"
        scenario.parent.mkdir(parents=True)
        scenario.write_text(f"version: '1.0'\nname: {name}\nenvironment: {{}}\n")
    accessibility_was_active = QAccessible.isActive()
    QAccessible.setActive(True)
    window = MainWindow(StateStore(tmp_path / "state"), DesktopState(workspace=workspace))
    try:
        window.show()
        app.processEvents()
        pane = window.scenario_library
        first = pane.tree.currentItem()
        assert first is not None
        assert first.background(0).color() == QColor("#293959")
        beta = workspace / "scenarios" / "beta" / "scenario.yaml"
        pane.select_path(beta)
        assert pane.tree.currentItem() is pane._tree_items[beta]
        assert pane._tree_items[beta].background(0).color() == QColor("#293959")
        assert first.background(0).color() != QColor("#293959")
        rectangle = pane.tree.visualItemRect(first)
        QTest.mouseClick(pane.tree.viewport(), Qt.MouseButton.LeftButton, pos=rectangle.center())
        assert pane.tree.selectedItems() == [first]
        assert pane._programmatic_highlight is None
    finally:
        window.close()
        QAccessible.setActive(accessibility_was_active)
        app.processEvents()


def test_authoring_tab_close_is_saved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    store = StateStore(tmp_path / "state")
    window = MainWindow(store, DesktopState(workspace=tmp_path))
    try:
        window._new_chat()
        assert window.tabs.count() == 1
        pane = window.tabs.widget(0)
        pane.record.thread_id = "thread-1"
        pane.set_busy(True)
        requests: list[tuple[str, object]] = []
        monkeypatch.setattr(
            window.bridge, "request", lambda method, params: requests.append((method, params))
        )
        close_button = window.tabs.tabBar().tabButton(0, QTabBar.ButtonPosition.RightSide)
        assert close_button is not None
        close_button.click()
        assert window.tabs.count() == 0
        assert not window.author_empty.isHidden()
        assert window.tabs.isHidden()
        closed = store.load(tmp_path).chats
        assert len(closed) == 1 and not closed[0].open
        assert window.recent_button.isEnabled()
        assert requests == [("turn/interrupt", {"threadId": "thread-1"})]
        window._populate_recent_menu()
        window.recent_menu.actions()[0].trigger()
        assert window.tabs.count() == 1
        assert store.load(tmp_path).chats[0].open
        window._close_chat_tab(0)
        restarted = MainWindow(store, store.load(tmp_path))
        try:
            assert restarted.tabs.count() == 0
            assert restarted.recent_button.isEnabled()
        finally:
            restarted.close()
    finally:
        window.close()
        app.processEvents()


def test_stage_one_status_snippets_folder_overview_and_saved_views(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    monkeypatch.setattr("evidenceforge.desktop.main.ensure_controller", lambda _path: None)
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "workspace"
    scenario = workspace / "scenarios" / "alpha" / "scenario.yaml"
    scenario.parent.mkdir(parents=True)
    scenario.write_text(
        "version: '1.0'\nname: alpha\ndescription: Insider case\n"
        "environment:\n  systems:\n    - hostname: WS-MAYA-01\n",
        encoding="utf-8",
    )
    job = GenerationJob(
        id="queued-alpha",
        scenario=scenario,
        output_root=tmp_path / "run",
        progress_file=tmp_path / "progress.jsonl",
        log_file=tmp_path / "run.log",
        started_at=time.time(),
        status="queued",
    )
    key = str(workspace.resolve())
    state = DesktopState(
        workspace=workspace,
        jobs=[job],
        scenario_folders={
            key: ScenarioFolders(names=["Research"], assignments={str(scenario): "Research"})
        },
    )
    store = StateStore(tmp_path / "state")
    window = MainWindow(store, state)
    try:
        pane = window.scenario_library
        row = pane._tree_items[scenario]
        assert "Queued" in row.text(0)
        pane.search.setText("WS-MAYA-01")
        assert "YAML line 6" in pane._tree_items[scenario].text(0)
        assert "hostname: WS-MAYA-01" in pane.search_match.text()
        pane.select_folder("Research")
        assert "1 active" in pane.metadata.text()
        assert "alpha" in pane.folder_recent.item(0).text()
        recent_row = pane.folder_recent.item(0)
        scenario_row = pane._tree_items[scenario]
        window._refresh_libraries()
        assert pane.folder_recent.item(0) is recent_row
        assert pane._tree_items[scenario] is scenario_row
        pane.folder_recent.itemClicked.emit(pane.folder_recent.item(0))
        assert pane.selected_item().path == scenario
        pane.select_folder("Research")
        pane.search.clear()
        pane.search.setText("WS-MAYA-01")
        assert pane.selected_item().path == scenario
        pane.select_folder("Research")
        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("Maya hosts", True))
        pane._save_current_view()
        assert store.load(workspace).library_views[key].saved[0].name == "Maya hosts"
        assert store.load(workspace).library_views[key].last.selected_folder == "Research"
        window.state.jobs[0].status = "completed"
        window.state.jobs[0].started_at = scenario.stat().st_mtime - 60
        window.job_store.save_generation(window.state.jobs[0])
        window._refresh_libraries()
        assert "Changed · Complete" in pane._tree_items[scenario].text(0)
    finally:
        window.job_store.save_generation(window.state.jobs[0])
        window._save()
        window.close()
        app.processEvents()
    reopened = MainWindow(store, store.load(workspace))
    try:
        assert reopened.scenario_library.search.text() == "WS-MAYA-01"
        assert reopened.scenario_library.selected_folder_name() == "Research"
        assert reopened.scenario_library.active_view_name == "Maya hosts"
        reopened.state.jobs[0].status = "failed"
        reopened.job_store.save_generation(reopened.state.jobs[0])
        reopened._refresh_libraries()
        reopened.scenario_library._build_views_menu()
        next(
            action
            for action in reopened.scenario_library.views_menu.actions()
            if action.text() == "Needs attention"
        ).trigger()
        assert len(reopened.scenario_library._tree_items) == 1
        assert reopened.scenario_library.active_view_name == "Needs attention"
        reopened.settings_page.remember_library_view.setChecked(False)
    finally:
        reopened.close()
        app.processEvents()
    no_restore = MainWindow(store, store.load(workspace))
    try:
        assert no_restore.scenario_library.search.text() == ""
        assert len(no_restore.scenario_library.saved_views) == 1
        no_restore._rename_library_view("Maya hosts", "Maya review")
        assert no_restore.scenario_library.saved_views[0].name == "Maya review"
        no_restore._delete_library_view("Maya review")
        assert not no_restore.scenario_library.saved_views
    finally:
        no_restore.close()
        app.processEvents()


def test_command_palette_finds_and_opens_scenario_with_keyboard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    scenario = tmp_path / "scenarios" / "alpha" / "scenario.yaml"
    scenario.parent.mkdir(parents=True)
    scenario.write_text("version: '1.0'\nname: alpha\nenvironment: {}\n", encoding="utf-8")
    window = MainWindow(StateStore(tmp_path / "state"), DesktopState(workspace=tmp_path))
    try:
        window.show()
        app.processEvents()
        QTest.keyClick(window, Qt.Key.Key_K, Qt.KeyboardModifier.ControlModifier)
        app.processEvents()
        palette = window.command_palette
        assert palette.isVisible()
        palette.search.setText("open scenario alpha")
        assert palette.results.count() == 1
        QTest.keyClick(palette.search, Qt.Key.Key_Return)
        assert not palette.isVisible()
        assert window.pages.currentIndex() == 0
        assert window.scenario_library.selected_item().path == scenario
        window.state.hidden_items = [scenario]
        window._refresh_libraries()
        assert scenario not in window.scenario_library._tree_items
        window._open_command_palette()
        palette.search.setText("open scenario alpha")
        QTest.keyClick(palette.search, Qt.Key.Key_Return)
        assert window.scenario_library.selected_item().path == scenario
        assert window.scenario_library.show_hidden_value
    finally:
        window.close()
        app.processEvents()


def test_last_library_view_is_scoped_to_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    first = tmp_path / "first"
    second = tmp_path / "second"
    for workspace, name in ((first, "alpha"), (second, "beta")):
        path = workspace / "scenarios" / name / "scenario.yaml"
        path.parent.mkdir(parents=True)
        path.write_text(f"version: '1.0'\nname: {name}\nenvironment: {{}}\n", encoding="utf-8")
    window = MainWindow(StateStore(tmp_path / "state"), DesktopState(workspace=first))
    try:
        window.scenario_library.search.setText("alpha")
        monkeypatch.setattr(
            QFileDialog, "getExistingDirectory", lambda *args, **kwargs: str(second)
        )
        window._choose_workspace()
        assert window.scenario_library.search.text() == ""
        window.scenario_library.search.setText("beta")
        monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *args, **kwargs: str(first))
        window._choose_workspace()
        assert window.scenario_library.search.text() == "alpha"
        assert window.scenario_library.selected_item().name == "alpha"
    finally:
        window.close()
        app.processEvents()
