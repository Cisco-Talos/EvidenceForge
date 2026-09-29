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
        assert [method for method, _ in requests] == ["thread/start", "turn/start"]
        assert str(scenario) in requests[0][1]["developerInstructions"]
        assert requests[1][1]["input"][0] == {
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
        assert pane.record.reasoning_effort is None
        pane.reasoning.setCurrentIndex(pane.reasoning.findData("high"))
        window._new_chat()
        second = next(
            current for current in window.chat_panes.values() if current.record.id != pane.record.id
        )
        assert second.record.model_id is None
        assert second.record.reasoning_effort is None
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
    finally:
        window.close()
        app.processEvents()
