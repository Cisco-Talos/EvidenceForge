"""Keyboard command menu for resuming EvidenceForge work."""

from __future__ import annotations

from collections.abc import Callable
from typing import override

from PySide6.QtCore import QEvent, QObject, QSize, Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QWidget,
)

Command = tuple[str, str, Callable[[], None]]


class CommandPalette(QDialog):
    """Search actions and run the selected action with Return."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("commandPalette")
        self.setWindowTitle("Commands")
        self.setModal(True)
        self.resize(620, 460)
        self.commands: list[Command] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(10)
        heading = QLabel("Find a command or scenario")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Type an action, scenario, or folder…")
        self.search.setAccessibleName("Search commands")
        self.search.installEventFilter(self)
        self.search.textChanged.connect(self._filter)
        layout.addWidget(self.search)
        self.results = QListWidget()
        self.results.setObjectName("commandResults")
        self.results.itemActivated.connect(self._activate)
        layout.addWidget(self.results, 1)
        hint = QLabel("↑ ↓ navigate   ·   Enter run   ·   Esc close")
        hint.setObjectName("muted")
        layout.addWidget(hint)

    def show_commands(self, commands: list[Command]) -> None:
        """Refresh actions for the active workspace and focus the query."""
        self.commands = commands
        self.search.clear()
        self._filter("")
        self.show()
        self.raise_()
        self.search.setFocus()

    def _filter(self, query: str) -> None:
        terms = query.casefold().split()
        self.results.clear()
        for index, (label, detail, _action) in enumerate(self.commands):
            text = f"{label} {detail}".casefold()
            if not all(term in text for term in terms):
                continue
            item = QListWidgetItem(f"{label}\n{detail}")
            item.setData(Qt.ItemDataRole.UserRole, index)
            item.setSizeHint(QSize(0, 48))
            self.results.addItem(item)
        if self.results.count():
            self.results.setCurrentRow(0)

    def _activate(self, item: QListWidgetItem) -> None:
        index = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(index, int) or index >= len(self.commands):
            return
        action = self.commands[index][2]
        self.accept()
        action()

    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if watched is self.search and event.type() == QEvent.Type.KeyPress:
            key_event = event
            if isinstance(key_event, QKeyEvent):
                if key_event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                    current = self.results.currentItem()
                    if current is not None:
                        self._activate(current)
                    return True
                if key_event.key() in (Qt.Key.Key_Down, Qt.Key.Key_Up):
                    step = 1 if key_event.key() == Qt.Key.Key_Down else -1
                    count = self.results.count()
                    if count:
                        self.results.setCurrentRow(
                            max(0, min(count - 1, self.results.currentRow() + step))
                        )
                    return True
        return super().eventFilter(watched, event)
