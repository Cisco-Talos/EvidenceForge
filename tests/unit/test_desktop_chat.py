"""Keyboard behavior in the optional desktop chat composer."""

from __future__ import annotations

import os

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
