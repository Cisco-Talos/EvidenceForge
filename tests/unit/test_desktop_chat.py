"""Keyboard behavior in the optional desktop chat composer."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

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
