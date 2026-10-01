"""Keyboard behavior in the optional desktop chat composer."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest


def test_enter_sends_and_modified_enter_adds_newlines() -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    qt = pytest.importorskip("PySide6.QtCore")
    widgets = pytest.importorskip("PySide6.QtWidgets")
    qtest = pytest.importorskip("PySide6.QtTest")
    from evidenceforge.desktop.main import ChatPane
    from evidenceforge.desktop.state import ChatRecord

    application = widgets.QApplication.instance() or widgets.QApplication([])
    pane = ChatPane(ChatRecord(id="keyboard", title="Keyboard"))
    sent: list[str] = []
    pane.send_requested.connect(lambda _pane, text: sent.append(text))
    pane.show()
    pane.prompt.setFocus()
    qtest.QTest.keyClicks(pane.prompt, "First")
    qtest.QTest.keyClick(pane.prompt, qt.Qt.Key.Key_Return, qt.Qt.KeyboardModifier.ShiftModifier)
    qtest.QTest.keyClicks(pane.prompt, "Second")
    qtest.QTest.keyClick(pane.prompt, qt.Qt.Key.Key_Return, qt.Qt.KeyboardModifier.AltModifier)
    qtest.QTest.keyClicks(pane.prompt, "Third")
    assert not sent

    qtest.QTest.keyClick(pane.prompt, qt.Qt.Key.Key_Return)

    assert sent == ["First\nSecond\nThird"]
    assert pane.prompt.toPlainText() == ""
    pane.close()
    application.processEvents()


def test_chat_skill_override_applies_to_one_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from evidenceforge.desktop.app_server import CodexBridge
    from evidenceforge.desktop.main import MainWindow
    from evidenceforge.desktop.state import DesktopState, StateStore

    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    window = MainWindow(
        StateStore(tmp_path / "state"), DesktopState(workspace=tmp_path / "workspace")
    )
    try:
        window._new_chat()
        pane = next(iter(window.chat_panes.values()))
        window.skills = {
            "eforge-scenario": "/skills/scenario",
            "eforge-validate": "/skills/validate",
        }
        pane.set_skills(window.skills)
        assert pane.skill.currentText() == "eforge-scenario"
        requests: list[dict[str, object]] = []

        def request(
            _method: str,
            parameters: dict[str, object],
            callback: Callable[[dict[str, object]], None],
        ) -> None:
            requests.append(parameters)
            callback({"result": {}})

        monkeypatch.setattr(
            window.bridge,
            "request",
            request,
        )
        window._start_turn(pane, "Create a scenario")
        assert requests[0]["input"] == [
            {"type": "text", "text": "Create a scenario"},
            {"type": "skill", "name": "eforge-scenario", "path": "/skills/scenario"},
        ]
        assert pane.skill.currentText() == "Automatic"
        window._start_turn(pane, "Now validate it")
        assert requests[1]["input"] == [{"type": "text", "text": "Now validate it"}]
    finally:
        window.close()
        app.processEvents()


def test_existing_scenario_context_is_thread_metadata_not_a_drafted_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from evidenceforge.desktop.app_server import CodexBridge
    from evidenceforge.desktop.library import LibraryItem
    from evidenceforge.desktop.main import MainWindow
    from evidenceforge.desktop.state import DesktopState, StateStore

    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "workspace"
    scenario = workspace / "scenarios" / "case" / "scenario.yaml"
    scenario.parent.mkdir(parents=True)
    scenario.write_text("version: '1.0'\nname: case\nenvironment: {}\n")
    store = StateStore(tmp_path / "state")
    window = MainWindow(store, DesktopState(workspace=workspace))
    try:
        window._author_scenario(LibraryItem(path=scenario, name="case"))
        pane = next(iter(window.chat_panes.values()))
        assert pane.prompt.toPlainText() == ""
        assert str(scenario) in pane.context.text()
        assert store.load(workspace).chats[0].context_path == scenario

        requests: list[tuple[str, dict[str, Any]]] = []

        def request(
            method: str,
            parameters: dict[str, Any],
            callback: Callable[[dict[str, Any]], None] | None = None,
        ) -> None:
            requests.append((method, parameters))
            if callback is not None:
                result = (
                    {"thread": {"id": "thread-1"}}
                    if method == "thread/start"
                    else {"turn": {"id": "turn-1"}}
                )
                callback({"result": result})

        monkeypatch.setattr(window.bridge, "request", request)
        window.bridge.initialized = True
        window._send_chat(pane, "Please add a Linux host")
        assert [method for method, _ in requests] == [
            "thread/start",
            "thread/name/set",
            "turn/start",
        ]
        assert str(scenario) in requests[0][1]["developerInstructions"]
        assert requests[2][1]["input"][0] == {
            "type": "text",
            "text": "Please add a Linux host",
        }
        assert str(scenario) not in pane.transcript.toPlainText()
    finally:
        window.close()
        app.processEvents()


def test_model_effort_picker_uses_catalog_and_saves_per_tab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from evidenceforge.desktop.app_server import CodexBridge
    from evidenceforge.desktop.main import MainWindow
    from evidenceforge.desktop.state import DesktopState, StateStore

    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "workspace"
    store = StateStore(tmp_path / "state")
    window = MainWindow(store, DesktopState(workspace=workspace))
    try:
        window._new_chat()
        pane = next(iter(window.chat_panes.values()))
        window._models_response(
            {
                "result": {
                    "data": [
                        {
                            "id": "fast",
                            "displayName": "Fast",
                            "isDefault": True,
                            "defaultReasoningEffort": "medium",
                            "supportedReasoningEfforts": [
                                {"reasoningEffort": "low"},
                                {"reasoningEffort": "medium"},
                            ],
                        },
                        {
                            "id": "deep",
                            "displayName": "Deep",
                            "supportedReasoningEfforts": [
                                {"reasoningEffort": "high"},
                            ],
                        },
                    ],
                    "nextCursor": None,
                }
            }
        )
        pane.model.setCurrentIndex(pane.model.findData("fast"))
        pane.reasoning.setCurrentIndex(pane.reasoning.findData("medium"))
        assert store.load(workspace).chats[0].model_id == "fast"
        assert store.load(workspace).chats[0].reasoning_effort == "medium"
        pane.model.setCurrentIndex(pane.model.findData("deep"))
        assert pane.reasoning.findData("medium") == -1
        assert pane.record.reasoning_effort == "high"
        assert pane.model.currentText() == "Deep"
        assert pane.reasoning.currentText() == "High"
        pane.reasoning.setCurrentIndex(pane.reasoning.findData("high"))
        window._new_chat()
        second = next(
            current for current in window.chat_panes.values() if current.record.id != pane.record.id
        )
        assert second.record.model_id == "fast"
        assert second.record.reasoning_effort == "medium"
        assert second.model.currentText() == "Fast"
        assert second.reasoning.currentText() == "Medium"
        assert store.load(workspace).chats[0].reasoning_effort == "high"
        parameters: list[dict[str, Any]] = []
        monkeypatch.setattr(
            window.bridge,
            "request",
            lambda method, params, callback: parameters.append(params),
        )
        window._start_turn(pane, "Review this")
        assert parameters[0]["model"] == "deep"
        assert parameters[0]["effort"] == "high"
    finally:
        window.close()
        app.processEvents()


def test_tool_activity_collapses_into_one_link_and_restores_from_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QTimer, QUrl
    from PySide6.QtWidgets import QApplication, QDialog, QPlainTextEdit

    from evidenceforge.desktop.app_server import CodexBridge
    from evidenceforge.desktop.main import MainWindow
    from evidenceforge.desktop.state import DesktopState, StateStore

    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    window = MainWindow(StateStore(tmp_path / "state"), DesktopState(workspace=tmp_path))
    try:
        window._new_chat()
        pane = next(iter(window.chat_panes.values()))
        pane.record.thread_id = "thread-1"
        command = {
            "id": "step-1",
            "type": "commandExecution",
            "command": "eforge validate case.yaml",
        }
        change = {"id": "step-2", "type": "fileChange", "changes": [{"path": "case.yaml"}]}
        for item in (command, change):
            window._codex_event(
                "item/started", {"threadId": "thread-1", "turnId": "turn-1", "item": item}
            )
        window._codex_event(
            "item/completed",
            {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "item": {**command, "aggregatedOutput": "Validation passed"},
            },
        )
        assert pane.transcript.toPlainText().count("View activity") == 1
        assert "activity:turn-1" in pane.transcript.toHtml()
        assert "Running:" not in pane.transcript.toPlainText()
        assert "Validation passed" in pane._activity["turn-1"][0]["aggregatedOutput"]
        details: list[str] = []

        def inspect_activity() -> None:
            dialog = QApplication.activeModalWidget()
            assert isinstance(dialog, QDialog)
            output = dialog.findChild(QPlainTextEdit)
            assert output is not None
            details.append(output.toPlainText())
            dialog.accept()

        QTimer.singleShot(0, inspect_activity)
        pane._show_activity(QUrl("activity:turn-1"))
        assert "Validation passed" in details[0]

        pane.transcript.clear()
        pane._activity.clear()
        pane._activity_items.clear()
        window._history_response(
            pane,
            {
                "result": {
                    "thread": {
                        "turns": [
                            {
                                "id": "turn-1",
                                "items": [
                                    {
                                        "type": "userMessage",
                                        "content": [{"type": "text", "text": "Validate"}],
                                    },
                                    command,
                                    change,
                                    {"type": "agentMessage", "text": "Valid."},
                                ],
                            }
                        ]
                    }
                }
            },
        )
        assert pane.transcript.toPlainText().count("View activity") == 1
        assert "eforge validate case.yaml" not in pane.transcript.toPlainText()
        assert "Valid." in pane.transcript.toPlainText()
        assert len(pane._activity["turn-1"]) == 2
        assert pane.record.conversation_title == "Validate"
    finally:
        window.close()
        app.processEvents()


def test_continue_authoring_reuses_open_and_closed_scenario_chat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from evidenceforge.desktop.app_server import CodexBridge
    from evidenceforge.desktop.library import LibraryItem
    from evidenceforge.desktop.main import MainWindow
    from evidenceforge.desktop.state import DesktopState, StateStore

    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "workspace"
    path = workspace / "scenarios" / "case" / "scenario.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("version: '1.0'\nname: case\nenvironment: {}\n")
    window = MainWindow(StateStore(tmp_path / "state"), DesktopState(workspace=workspace))
    item = LibraryItem(path=path, name="case")
    try:
        window._author_scenario(item)
        first = window.tabs.currentWidget()
        assert first is not None
        first.record.thread_id = "existing-thread"
        window._author_scenario(item)
        assert len(window.state.chats) == 1
        assert window.tabs.count() == 1
        assert window.tabs.currentWidget() is first

        window._close_chat_tab(0)
        assert window.tabs.count() == 0
        window._author_scenario(item)
        assert len(window.state.chats) == 1
        assert window.tabs.count() == 1
        assert window.tabs.currentWidget().record.thread_id == "existing-thread"
    finally:
        window.close()
        app.processEvents()


def test_continue_authoring_reuses_existing_tab_through_path_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication

    from evidenceforge.desktop.app_server import CodexBridge
    from evidenceforge.desktop.main import MainWindow
    from evidenceforge.desktop.state import ChatRecord, DesktopState, StateStore

    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "workspace"
    paths = [workspace / "scenarios" / name / "scenario.yaml" for name in ("alpha", "bravo")]
    for path in paths:
        path.parent.mkdir(parents=True)
        path.write_text(f"version: '1.0'\nname: {path.parent.name}\nenvironment: {{}}\n")
    alias = tmp_path / "workspace-alias"
    alias.symlink_to(workspace, target_is_directory=True)
    chats = [
        ChatRecord(
            id=path.parent.name,
            title=path.parent.name,
            context_path=alias / "scenarios" / path.parent.name / "scenario.yaml",
            context_kind="scenario",
            thread_id=f"thread-{path.parent.name}",
        )
        for path in paths
    ]
    window = MainWindow(
        StateStore(tmp_path / "state"), DesktopState(workspace=workspace, chats=chats)
    )
    try:
        window.show()
        app.processEvents()
        library = window.scenario_library
        original_tabs = window.tabs.count()
        for path in reversed(paths):
            window._navigate(0)
            app.processEvents()
            row = library._tree_items[path.resolve()]
            QTest.mouseClick(
                library.tree.viewport(),
                Qt.MouseButton.LeftButton,
                pos=library.tree.visualItemRect(row).center(),
            )
            QTest.mouseClick(library.edit, Qt.MouseButton.LeftButton)
            app.processEvents()
            assert window.tabs.currentWidget().record.id == path.parent.name
            assert window.tabs.count() == original_tabs
    finally:
        window.close()
        app.processEvents()


def test_legacy_title_only_chat_is_relinked_when_scenario_name_is_unique(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from evidenceforge.desktop.app_server import CodexBridge
    from evidenceforge.desktop.library import LibraryItem
    from evidenceforge.desktop.main import MainWindow
    from evidenceforge.desktop.state import ChatRecord, DesktopState, StateStore

    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "workspace"
    path = workspace / "scenarios" / "case" / "scenario.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("version: '1.0'\nname: case\nenvironment: {}\n")
    old = ChatRecord(id="old", title="case", thread_id="existing-thread", skill_name="Automatic")
    store = StateStore(tmp_path / "state")
    window = MainWindow(store, DesktopState(workspace=workspace, chats=[old]))
    try:
        window._author_scenario(LibraryItem(path=path, name="case"))
        assert len(window.state.chats) == 1
        assert window.tabs.count() == 1
        assert old.context_path == path
        assert old.context_kind == "scenario"
        assert str(path) in window.tabs.currentWidget().context.text()
        assert store.load(workspace).chats[0].context_path == path
    finally:
        window.close()
        app.processEvents()


def test_legacy_chat_with_ambiguous_name_is_not_attached_to_wrong_scenario(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from evidenceforge.desktop.app_server import CodexBridge
    from evidenceforge.desktop.library import LibraryItem
    from evidenceforge.desktop.main import MainWindow
    from evidenceforge.desktop.state import ChatRecord, DesktopState, StateStore

    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "workspace"
    paths = [workspace / "scenarios" / folder / "scenario.yaml" for folder in ("a", "b")]
    for path in paths:
        path.parent.mkdir(parents=True)
        path.write_text("version: '1.0'\nname: case\nenvironment: {}\n")
    old = ChatRecord(id="old", title="case", skill_name="Automatic")
    window = MainWindow(
        StateStore(tmp_path / "state"), DesktopState(workspace=workspace, chats=[old])
    )
    try:
        window._author_scenario(LibraryItem(path=paths[0], name="case"))
        assert len(window.state.chats) == 2
        assert old.context_path is None
        assert window.tabs.currentWidget().record.context_path == paths[0]
    finally:
        window.close()
        app.processEvents()


def test_scenario_conversation_menu_starts_and_switches_chats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from evidenceforge.desktop.app_server import CodexBridge
    from evidenceforge.desktop.library import LibraryItem
    from evidenceforge.desktop.main import MainWindow
    from evidenceforge.desktop.state import DesktopState, StateStore

    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "workspace"
    path = workspace / "scenarios" / "case" / "scenario.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("version: '1.0'\nname: case\nenvironment: {}\n")
    window = MainWindow(StateStore(tmp_path / "state"), DesktopState(workspace=workspace))
    try:
        window._author_scenario(LibraryItem(path=path, name="case"))
        first = window.tabs.currentWidget()
        window._populate_context_conversations(first)
        first.conversations_menu.actions()[0].trigger()
        assert len(window.state.chats) == 2
        assert window.tabs.count() == 2
        second = window.tabs.currentWidget()
        assert second is not first
        assert window.tabs.tabText(window.tabs.indexOf(first)) == "case"
        assert window.tabs.tabText(window.tabs.indexOf(second)) == "case"
        window._populate_context_conversations(second)
        next(
            action
            for action in second.conversations_menu.actions()
            if action.text() == "New conversation 1"
        ).trigger()
        assert window.tabs.currentWidget() is first
        window._author_scenario(LibraryItem(path=path, name="case"))
        assert len(window.state.chats) == 2
    finally:
        window.close()
        app.processEvents()


def test_conversations_get_fast_model_titles_and_keep_them_after_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from evidenceforge.desktop.app_server import CodexBridge, CodexModel
    from evidenceforge.desktop.library import LibraryItem
    from evidenceforge.desktop.main import MainWindow
    from evidenceforge.desktop.state import DesktopState, StateStore

    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "workspace"
    path = workspace / "scenarios" / "case" / "scenario.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("version: '1.0'\nname: case\nenvironment: {}\n")
    store = StateStore(tmp_path / "state")
    window = MainWindow(store, DesktopState(workspace=workspace))
    try:
        window._author_scenario(LibraryItem(path=path, name="case"))
        pane = window.tabs.currentWidget()
        window.models = [CodexModel(id="gpt-6-luna", displayName="GPT-6 Luna")]
        window.bridge.initialized = True
        requests: list[tuple[str, dict[str, Any]]] = []

        def request(
            method: str,
            parameters: dict[str, Any],
            callback: Callable[[dict[str, Any]], None] | None = None,
        ) -> None:
            requests.append((method, parameters))
            if callback and method == "thread/start":
                thread_id = "title-thread" if parameters.get("ephemeral") else "authoring-thread"
                callback({"result": {"thread": {"id": thread_id}}})
            elif callback and method == "turn/start":
                callback({"result": {"turn": {"id": "turn-1"}}})

        monkeypatch.setattr(window.bridge, "request", request)
        window._send_chat(pane, "Add Linux hosts and SSH evidence")
        assert any(
            method == "thread/start"
            and params.get("ephemeral") is True
            and params.get("model") == "gpt-6-luna"
            for method, params in requests
        )
        window._codex_event(
            "item/agentMessage/delta",
            {"threadId": "title-thread", "itemId": "title", "delta": "Linux SSH Evidence"},
        )
        window._codex_event(
            "turn/completed", {"threadId": "title-thread", "turn": {"status": "completed"}}
        )
        assert pane.record.conversation_title == "Linux SSH Evidence"
        assert window.tabs.tabText(window.tabs.indexOf(pane)) == "case"
        assert (
            "thread/name/set",
            {"threadId": "authoring-thread", "name": "Linux SSH Evidence"},
        ) in requests
        window._populate_context_conversations(pane)
        assert any(
            action.text() == "Linux SSH Evidence" for action in pane.conversations_menu.actions()
        )
        assert store.load(workspace).chats[0].conversation_title == "Linux SSH Evidence"
    finally:
        window.close()
        app.processEvents()


def test_closed_conversation_gets_title_from_saved_thread_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from evidenceforge.desktop.app_server import CodexBridge
    from evidenceforge.desktop.library import LibraryItem
    from evidenceforge.desktop.main import MainWindow
    from evidenceforge.desktop.state import DesktopState, StateStore

    monkeypatch.setattr(CodexBridge, "start", lambda self: None)
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "workspace"
    path = workspace / "scenarios" / "case" / "scenario.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("version: '1.0'\nname: case\nenvironment: {}\n")
    window = MainWindow(StateStore(tmp_path / "state"), DesktopState(workspace=workspace))
    try:
        window._author_scenario(LibraryItem(path=path, name="case"))
        first = window.tabs.currentWidget()
        first.record.thread_id = "saved-thread"
        window._close_chat_tab(window.tabs.indexOf(first))
        second = window._create_context_chat("case", path, "scenario", "eforge-scenario")
        window.bridge.initialized = True

        def request(
            method: str,
            _parameters: dict[str, Any],
            callback: Callable[[dict[str, Any]], None] | None = None,
        ) -> None:
            if method == "thread/read" and callback:
                callback(
                    {
                        "result": {
                            "thread": {
                                "name": "Revise SSH Evidence",
                                "turns": [],
                            }
                        }
                    }
                )

        monkeypatch.setattr(window.bridge, "request", request)
        window._populate_context_conversations(second)
        assert first.record.conversation_title == "Revise SSH Evidence"
        assert any(
            action.text() == "Revise SSH Evidence" for action in second.conversations_menu.actions()
        )
    finally:
        window.close()
        app.processEvents()


def test_user_and_codex_messages_have_distinct_alignment_and_colors() -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor
    from PySide6.QtWidgets import QApplication

    from evidenceforge.desktop.main import ChatPane
    from evidenceforge.desktop.state import ChatRecord

    app = QApplication.instance() or QApplication([])
    pane = ChatPane(ChatRecord(id="visual", title="Visual"))
    try:
        pane.add_user("Please revise this scenario")
        pane.add_agent_delta("reply-1", "I can revise it")
        pane.add_agent_delta("reply-1", " and validate it.")
        document = pane.transcript.document()
        user_label = document.find("You").block()
        user_body = document.find("Please revise this scenario").block()
        agent_label = document.find("Codex").block()
        agent_body = document.find("I can revise it").block()
        assert user_label.blockFormat().alignment() == Qt.AlignmentFlag.AlignRight
        assert user_body.blockFormat().alignment() == Qt.AlignmentFlag.AlignRight
        assert agent_label.blockFormat().alignment() == Qt.AlignmentFlag.AlignLeft
        assert agent_body.blockFormat().alignment() == Qt.AlignmentFlag.AlignLeft
        assert document.find(
            "Please revise this scenario"
        ).charFormat().background().color() == QColor("#223454")
        assert document.find("I can revise it").charFormat().background().color() == QColor(
            "#19302f"
        )
        assert "I can revise it and validate it." in pane.transcript.toPlainText()
    finally:
        pane.close()
        app.processEvents()
