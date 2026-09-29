"""Launch the optional EvidenceForge desktop prototype."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, override
from uuid import uuid4

from pydantic import ValidationError
from PySide6.QtCore import QProcess, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import (
    QColor,
    QDesktopServices,
    QFont,
    QFontDatabase,
    QKeyEvent,
    QKeySequence,
    QResizeEvent,
    QShortcut,
    QTextCharFormat,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QProgressDialog,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QTabBar,
    QTabWidget,
    QTextBrowser,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from evidenceforge.cli.install_skills import (
    find_evidenceforge_chatgpt_skills,
    install_chatgpt_skills,
    install_skills,
)
from evidenceforge.desktop.app_server import CodexBridge, CodexModel
from evidenceforge.desktop.command_palette import Command, CommandPalette
from evidenceforge.desktop.controller import ensure_controller
from evidenceforge.desktop.icons import icon
from evidenceforge.desktop.job_store import ControlIntent, JobStore
from evidenceforge.desktop.jobs import (
    queue_evaluation,
    queue_generation,
    refresh_status,
    request_suspension,
)
from evidenceforge.desktop.library import LibraryItem, discover_packs, discover_scenarios
from evidenceforge.desktop.library_ui import LibraryPane
from evidenceforge.desktop.progress import GenerationProgress, parse_progress_line
from evidenceforge.desktop.settings_ui import SettingsPane
from evidenceforge.desktop.skill_setup import skill_targets
from evidenceforge.desktop.state import (
    ChatRecord,
    DesktopState,
    EvaluationJob,
    GenerationJob,
    LibraryView,
    ScenarioFolders,
    StateStore,
    WorkspaceLibraryViews,
    state_directory,
)
from evidenceforge.desktop.validation import format_validation_output
from evidenceforge.evaluation.models import QualityReport

_STYLE = """
QWidget { background: #0d111a; color: #e9edf5; font-size: 13px; }
QLabel { background: transparent; }
QMainWindow, QTabWidget::pane { background: #0d111a; }
QFrame#sidebar { background: #111722; border-right: 1px solid #263040; }
QFrame#panel { background: #151d2a; border: 1px solid #2b3648; border-radius: 14px; }
QFrame#jobCard { background: #151d2a; border: 1px solid #35445b; border-radius: 12px; }
QScrollArea#jobsScroll { background: transparent; border: none; }
QWidget#inlineControls { background: transparent; }
QLabel#brand { font-size: 19px; font-weight: 800; color: #f5f8fd; }
QLabel#pageTitle { font-size: 32px; font-weight: 750; color: #f5f8fd; }
QLabel#detailTitle { font-size: 25px; font-weight: 750; color: #f5f8fd; }
QLabel#heading { font-size: 20px; font-weight: 700; color: #f3f6fb; }
QLabel#eyebrow { font-size: 10px; font-weight: 800; letter-spacing: 2px; color: #6ed3b7; }
QLabel#muted, QLabel#subtle { color: #9caabe; }
QLabel#metadata { color: #b9c7d8; line-height: 1.5; }
QPushButton { background: #233044; border: 1px solid #39475b; border-radius: 9px;
              padding: 9px 13px; font-weight: 650; }
QPushButton:hover { background: #31415a; }
QPushButton:disabled { color: #69778b; background: #1b2635; }
QPushButton#primary { background: #5a6ff0; border-color: #7182fc; color: white; }
QPushButton#primary:hover { background: #7185ff; }
QPushButton#nav { text-align: left; background: transparent; border: none; color: #b8c4d5;
                  padding: 12px 14px; font-size: 14px; }
QPushButton#nav:hover { background: #202c3e; color: white; }
QPushButton#nav:checked { background: #293959; color: white; border-left: 3px solid #77a6ff; }
QToolButton#iconAction, QToolButton#filterButton { background: #233044; border: 1px solid #39475b;
    border-radius: 9px; padding: 8px; }
QToolButton#iconAction:hover, QToolButton#filterButton:hover { background: #344760; }
QToolButton#treeMenu { background: transparent; border: none; padding: 2px; }
QToolButton#treeMenu:hover { background: #344760; border-radius: 6px; }
QToolButton#treeMenu::menu-indicator { image: none; width: 0; }
QToolButton#tabClose { background: transparent; border: none; padding: 2px; }
QToolButton#tabClose:hover { background: #40516a; border-radius: 5px; }
QMenu { background: #1b2534; border: 1px solid #3a4b61; border-radius: 9px; padding: 6px; }
QMenu::item { padding: 8px 28px 8px 12px; border-radius: 5px; }
QMenu::item:selected { background: #334462; }
QMenu::separator { height: 1px; background: #35445b; margin: 5px 8px; }
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox {
    background: #101723; border: 1px solid #35445b; border-radius: 9px;
    padding: 9px; selection-background-color: #5369db;
}
QCheckBox { background: transparent; spacing: 8px; }
QCheckBox::indicator { width: 18px; height: 18px; border: 2px solid #97a9c3;
                       border-radius: 5px; background: #101723; }
QCheckBox::indicator:hover { border-color: #c7d8f5; }
QCheckBox::indicator:checked { background: #6386f3; border-color: #a9bcff; }
QFrame#settingsRail { background: #131e2c; border: 1px solid #33445b; border-radius: 11px; }
QFrame#settingsSurface { background: #151d2a; border: 1px solid #29384e; border-radius: 11px; }
QWidget#settingsRow { background: transparent; }
QFrame#settingsDivider { color: #334157; background: #334157; max-height: 1px; }
QLabel#settingsHint { color: #9caabe; padding: 0 0 8px 0; }
QPushButton#settingsCategory { text-align: left; background: transparent; border: none;
    color: #b8c4d5; padding: 10px 12px; }
QPushButton#settingsCategory:hover { background: #233249; }
QPushButton#settingsCategory:checked { background: #293959; color: white;
    border-left: 3px solid #77a6ff; }
QToolButton#settingsHelp { background: transparent; border: none; padding: 1px; }
QToolButton#settingsHelp:hover { background: #31415a; border-radius: 8px; }
QListWidget#libraryList { background: transparent; border: none; outline: none; }
QListWidget#libraryList::item { padding: 14px 12px; margin: 3px 0; border-radius: 9px; }
QListWidget#libraryList::item:selected { background: #293959; color: #ffffff; }
QListWidget#libraryList::item:hover { background: #202c3e; }
QListWidget#folderRecent { background: #111722; border: 1px solid #35445b; border-radius: 9px; }
QListWidget#folderRecent::item { padding: 9px; margin: 2px; border-radius: 6px; }
QListWidget#folderRecent::item:hover { background: #293959; }
QDialog#commandPalette { background: #151d2a; color: #e9edf5; }
QListWidget#commandResults { background: #111722; border: 1px solid #35445b; border-radius: 9px; }
QListWidget#commandResults::item { padding: 5px 10px; margin: 2px; border-radius: 6px; }
QListWidget#commandResults::item:selected { background: #293959; color: white; }
QTreeWidget#libraryTree { background: transparent; border: none; outline: none; show-decoration-selected: 1; }
QTreeWidget#libraryTree::item { padding: 7px 5px; }
QTreeWidget#libraryTree::item:selected { background: #293959; color: white; }
QTreeWidget#libraryTree::item:hover { background: #202c3e; }
QScrollBar:vertical { background: #151d2a; width: 8px; margin: 0; }
QScrollBar::handle:vertical { background: #40516a; border-radius: 4px; min-height: 28px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QTabBar::tab { background: #1a2432; border: 1px solid #35445b; border-bottom: none;
               padding: 10px 16px; margin-right: 3px; border-top-left-radius: 8px;
               border-top-right-radius: 8px; }
QTabBar::tab:selected { background: #283a54; color: #ffffff; }
QProgressBar { background: #1a2432; border: 1px solid #35445b; border-radius: 6px;
               text-align: center; height: 18px; }
QProgressBar::chunk { background: #5b80f0; border-radius: 5px; }
QScrollArea { border: none; }
"""


def _error_text(message: dict[str, Any]) -> str:
    error = message.get("error")
    if isinstance(error, dict):
        return str(error.get("message", error))
    return str(error or "Unknown Codex error")


class ChatComposer(QPlainTextEdit):
    """Send on Return, leaving modified Return for multiline prompts."""

    submit_requested = Signal()

    @override
    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            if event.modifiers() & (
                Qt.KeyboardModifier.ShiftModifier
                | Qt.KeyboardModifier.AltModifier
                | Qt.KeyboardModifier.ControlModifier
                | Qt.KeyboardModifier.MetaModifier
            ):
                self.insertPlainText("\n")
            else:
                self.submit_requested.emit()
            event.accept()
            return
        super().keyPressEvent(event)


class ChatPane(QWidget):
    """One conversation with its own context, model choices, and skill override."""

    send_requested = Signal(object, str)
    interrupt_requested = Signal(object)
    configuration_changed = Signal()

    def __init__(self, record: ChatRecord) -> None:
        super().__init__()
        self.record = record
        self._stream_item: str | None = None
        self._models: dict[str, CodexModel] = {}
        self._activity: dict[str, list[dict[str, Any]]] = {}
        self._activity_items: dict[tuple[str, str], int] = {}
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        self.context = QLabel()
        self.context.setObjectName("subtle")
        self.context.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if record.context_kind:
            target = str(record.context_path) if record.context_path else "this workspace"
            self.context.setText(f"{record.context_kind.title()} · {target}")
            self.context.setToolTip(target)
        else:
            self.context.hide()
        layout.addWidget(self.context)
        header = QHBoxLayout()
        header.addStretch()
        header.addWidget(QLabel("Model"))
        self.model = QComboBox()
        self.model.setAccessibleName("Codex model")
        self.model.setToolTip("Choose the model for the next message in this chat")
        self.model.addItem("Default model", None)
        self.model.setEnabled(False)
        self.model.currentIndexChanged.connect(self._model_changed)
        header.addWidget(self.model)
        header.addWidget(QLabel("Reasoning"))
        self.reasoning = QComboBox()
        self.reasoning.setAccessibleName("Reasoning effort")
        self.reasoning.setToolTip("Choose how much reasoning to use for the next message")
        self.reasoning.addItem("Default", None)
        self.reasoning.setEnabled(False)
        self.reasoning.currentIndexChanged.connect(self._reasoning_changed)
        header.addWidget(self.reasoning)
        header.addWidget(QLabel("Skill for this message"))
        self.skill = QComboBox()
        self.skill.setMinimumWidth(190)
        self.skill.addItem(record.skill_name, None)
        header.addWidget(self.skill)
        layout.addLayout(header)
        self.transcript = QTextBrowser()
        self.transcript.setOpenLinks(False)
        self.transcript.anchorClicked.connect(self._show_activity)
        self.transcript.setPlaceholderText("Describe the scenario you want to create or revise.")
        layout.addWidget(self.transcript, 1)
        self.prompt = ChatComposer()
        self.prompt.setPlaceholderText(
            "Ask EvidenceForge…  Enter to send · Shift/Option+Enter for a new line"
        )
        self.prompt.setFixedHeight(90)
        self.prompt.submit_requested.connect(self._send)
        layout.addWidget(self.prompt)
        controls = QHBoxLayout()
        self.status = QLabel("Ready")
        self.status.setObjectName("subtle")
        controls.addWidget(self.status)
        controls.addStretch()
        self.interrupt = QPushButton("Interrupt")
        self.interrupt.setIcon(icon("close"))
        self.interrupt.setEnabled(False)
        self.interrupt.clicked.connect(lambda: self.interrupt_requested.emit(self))
        controls.addWidget(self.interrupt)
        self.send = QPushButton("Send")
        self.send.setObjectName("primary")
        self.send.setIcon(icon("play", color="#ffffff"))
        self.send.clicked.connect(self._send)
        controls.addWidget(self.send)
        layout.addLayout(controls)

    def set_models(self, models: list[CodexModel]) -> None:
        """Show only model and effort combinations advertised by app-server."""
        previous = (self.record.model_id, self.record.reasoning_effort)
        self._models = {model.id: model for model in models}
        default = next((model for model in models if model.is_default), None)
        self.model.blockSignals(True)
        self.model.clear()
        self.model.addItem(
            f"Default · {default.display_name}" if default is not None else "Default model", None
        )
        for option in models:
            self.model.addItem(option.display_name, option.id)
        index = self.model.findData(self.record.model_id)
        self.model.setCurrentIndex(index if index >= 0 else 0)
        if models:
            self.record.model_id = self.model.currentData()
        self.model.blockSignals(False)
        self.model.setEnabled(bool(models))
        self._refresh_efforts()
        if previous != (self.record.model_id, self.record.reasoning_effort):
            self.configuration_changed.emit()

    def _model_changed(self) -> None:
        self.record.model_id = self.model.currentData()
        self._refresh_efforts()
        self.configuration_changed.emit()

    def _refresh_efforts(self) -> None:
        chosen = self._models.get(self.record.model_id or "")
        if chosen is None:
            chosen = next((model for model in self._models.values() if model.is_default), None)
        self.reasoning.blockSignals(True)
        self.reasoning.clear()
        self.reasoning.addItem("Default", None)
        if chosen is not None:
            for effort in chosen.efforts:
                self.reasoning.addItem(effort.value.title(), effort.value)
                self.reasoning.setItemData(
                    self.reasoning.count() - 1, effort.description, Qt.ItemDataRole.ToolTipRole
                )
        index = self.reasoning.findData(self.record.reasoning_effort)
        self.reasoning.setCurrentIndex(index if index >= 0 else 0)
        if self._models:
            self.record.reasoning_effort = self.reasoning.currentData()
        self.reasoning.blockSignals(False)
        self.reasoning.setEnabled(chosen is not None and bool(chosen.efforts))

    def _reasoning_changed(self) -> None:
        self.record.reasoning_effort = self.reasoning.currentData()
        self.configuration_changed.emit()

    def set_skills(self, skills: dict[str, str]) -> None:
        """Refresh skill choices while retaining this tab's selection."""
        selected = self.record.skill_name
        self.skill.clear()
        self.skill.addItem("Automatic", None)
        for name, path in sorted(skills.items()):
            self.skill.addItem(name, path)
        index = self.skill.findText(selected)
        self.skill.setCurrentIndex(index if index >= 0 else 0)

    def _send(self) -> None:
        if not self.send.isEnabled():
            return
        text = self.prompt.toPlainText().strip()
        if not text:
            return
        self.prompt.clear()
        self.send_requested.emit(self, text)

    def _append(self, label: str, text: str, color: str) -> None:
        cursor = self.transcript.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        label_format = QTextCharFormat()
        label_format.setForeground(QColor(color))
        label_format.setFontWeight(QFont.Weight.Bold)
        cursor.insertText(f"\n{label}\n", label_format)
        body_format = QTextCharFormat()
        body_format.setForeground(QColor("#e8edf6"))
        cursor.insertText(text + "\n", body_format)
        self.transcript.setTextCursor(cursor)
        self.transcript.ensureCursorVisible()

    def add_user(self, text: str) -> None:
        self._stream_item = None
        self._append("You", text, "#8bbcf6")

    def add_system(self, text: str) -> None:
        self._stream_item = None
        self._append("Activity", text, "#aab7c9")

    def add_agent_text(self, text: str) -> None:
        self._stream_item = None
        self._append("Codex", text, "#83d5bd")

    def add_agent_delta(self, item_id: str, delta: str) -> None:
        cursor = self.transcript.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        if self._stream_item != item_id:
            label_format = QTextCharFormat()
            label_format.setForeground(QColor("#83d5bd"))
            label_format.setFontWeight(QFont.Weight.Bold)
            cursor.insertText("\nCodex\n", label_format)
            self._stream_item = item_id
        body_format = QTextCharFormat()
        body_format.setForeground(QColor("#e8edf6"))
        cursor.insertText(delta, body_format)
        self.transcript.setTextCursor(cursor)
        self.transcript.ensureCursorVisible()

    def add_activity(self, turn_id: str, item: dict[str, Any]) -> None:
        """Keep tool and reasoning details behind one link per turn."""
        item_id = str(item.get("id") or len(self._activity.get(turn_id, [])))
        entries = self._activity.setdefault(turn_id, [])
        key = (turn_id, item_id)
        if key in self._activity_items:
            entries[self._activity_items[key]] = item
            return
        self._activity_items[key] = len(entries)
        entries.append(item)
        if len(entries) != 1:
            return
        self._stream_item = None
        cursor = self.transcript.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        link_format = QTextCharFormat()
        link_format.setForeground(QColor("#9caabe"))
        link_format.setAnchor(True)
        link_format.setAnchorHref(f"activity:{turn_id}")
        link_format.setFontUnderline(True)
        cursor.insertText("\nView activity\n", link_format)
        self.transcript.setTextCursor(cursor)
        self.transcript.ensureCursorVisible()

    def _show_activity(self, url: QUrl) -> None:
        turn_id = url.toString().removeprefix("activity:")
        entries = self._activity.get(turn_id, [])
        if not entries:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Codex activity")
        dialog.resize(760, 500)
        layout = QVBoxLayout(dialog)
        detail = QPlainTextEdit(dialog)
        detail.setReadOnly(True)
        detail.setPlainText("\n\n".join(self._activity_text(entry) for entry in entries))
        layout.addWidget(detail)
        close = QPushButton("Close", dialog)
        close.clicked.connect(dialog.accept)
        layout.addWidget(close)
        dialog.exec()

    @staticmethod
    def _activity_text(item: dict[str, Any]) -> str:
        kind = str(item.get("type", "Activity"))
        if kind == "commandExecution":
            lines = [f"Command · {item.get('command', 'Unknown command')}"]
            if item.get("cwd"):
                lines.append(f"Directory: {item['cwd']}")
            if item.get("exitCode") is not None:
                lines.append(f"Exit code: {item['exitCode']}")
            output = item.get("aggregatedOutput") or item.get("output")
            if output:
                lines.extend(("", str(output)))
            return "\n".join(lines)
        if kind == "fileChange":
            changes = item.get("changes")
            return "File changes\n" + json.dumps(changes, indent=2, ensure_ascii=False)
        if kind == "reasoning":
            summary = item.get("summary") or item.get("text")
            return "Reasoning summary\n" + (str(summary) if summary else "No summary was provided.")
        return f"{kind}\n" + json.dumps(item, indent=2, ensure_ascii=False)

    def set_busy(self, busy: bool) -> None:
        self.send.setEnabled(not busy)
        self.interrupt.setEnabled(busy)
        self.status.setText("Codex is working…" if busy else "Ready")


class JobCard(QFrame):
    """Live progress and controls for one detached generation."""

    suspend_requested = Signal(object)
    resume_requested = Signal(object)

    def __init__(self, job: GenerationJob) -> None:
        super().__init__()
        self.job = job
        self.setObjectName("jobCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)
        top = QHBoxLayout()
        title = QLabel(job.scenario.stem)
        title.setObjectName("heading")
        top.addWidget(title)
        top.addStretch()
        self.status = QLabel(job.status.title())
        top.addWidget(self.status)
        layout.addLayout(top)
        self.output = QLabel(str(job.output_root))
        self.output.setObjectName("subtle")
        self.output.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.output)
        self.detail = QLabel("Waiting for engine progress")
        layout.addWidget(self.detail)
        self.hours = QProgressBar()
        self.hours.setRange(0, 0)
        layout.addWidget(self.hours)
        self.storyline_label = QLabel("Storyline")
        self.storyline_label.setObjectName("subtle")
        self.storyline_label.hide()
        layout.addWidget(self.storyline_label)
        self.storyline = QProgressBar()
        self.storyline.hide()
        layout.addWidget(self.storyline)
        controls = QHBoxLayout()
        open_output = QPushButton("Open Bundle")
        open_output.setIcon(icon("folder"))
        open_output.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(job.output_root)))
        )
        controls.addWidget(open_output)
        open_log = QPushButton("Open Log")
        open_log.setIcon(icon("file"))
        open_log.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(job.log_file)))
        )
        controls.addWidget(open_log)
        controls.addStretch()
        self.suspend = QPushButton("Suspend")
        self.suspend.setIcon(icon("pause"))
        self.suspend.clicked.connect(lambda: self.suspend_requested.emit(self.job))
        controls.addWidget(self.suspend)
        self.resume = QPushButton("Resume")
        self.resume.setIcon(icon("play"))
        self.resume.clicked.connect(lambda: self.resume_requested.emit(self.job))
        controls.addWidget(self.resume)
        layout.addLayout(controls)
        self.update_display(GenerationProgress())

    def update_display(self, progress: GenerationProgress) -> None:
        """Render the current hour and storyline bars."""
        self.status.setText(self.job.status.title())
        self.detail.setText(self.job.status_message or progress.detail)
        if progress.total_hours:
            self.hours.setRange(0, progress.total_hours)
            self.hours.setValue(progress.completed_hours)
            self.hours.setFormat("%v of %m simulated hours · %p%")
        elif self.job.status == "running":
            self.hours.setRange(0, 0)
        elif self.job.status == "queued":
            self.hours.setRange(0, 1)
            self.hours.setValue(0)
        else:
            self.hours.setRange(0, 1)
            self.hours.setValue(1 if self.job.status == "completed" else 0)
        if progress.storyline_total:
            self.storyline_label.show()
            self.storyline.show()
            self.storyline.setRange(0, progress.storyline_total)
            self.storyline.setValue(progress.storyline_event)
            self.storyline.setFormat("%v of %m events · %p%")
        self.suspend.setEnabled(self.job.status == "running")
        self.resume.setEnabled(
            self.job.status in {"paused", "stopped"}
            and (self.job.output_root / ".eforge-generation").exists()
        )


class JobsPane(QWidget):
    """Scenario selection and a scrollable set of generation jobs."""

    validate_requested = Signal(str)
    generate_requested = Signal(str, str)
    output_changed = Signal(str)
    suspend_requested = Signal(object)
    resume_requested = Signal(object)
    resume_all_requested = Signal()

    def __init__(self, output_directory: Path) -> None:
        super().__init__()
        self.cards: dict[str, JobCard] = {}
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        title = QLabel("Generation jobs")
        title.setObjectName("heading")
        header = QHBoxLayout()
        header.addWidget(title)
        header.addStretch()
        resume_all = QPushButton("Resume paused jobs")
        resume_all.setIcon(icon("play"))
        resume_all.clicked.connect(self.resume_all_requested.emit)
        header.addWidget(resume_all)
        layout.addLayout(header)
        input_row = QHBoxLayout()
        self.scenario = QLineEdit()
        self.scenario.setPlaceholderText("Choose a scenario YAML file")
        input_row.addWidget(self.scenario, 1)
        browse = QPushButton("Browse")
        browse.setIcon(icon("folder"))
        browse.clicked.connect(self._browse)
        input_row.addWidget(browse)
        validate = QPushButton("Validate")
        validate.setIcon(icon("check"))
        validate.clicked.connect(lambda: self.validate_requested.emit(self.scenario.text()))
        input_row.addWidget(validate)
        layout.addLayout(input_row)
        destination_row = QHBoxLayout()
        destination_row.addWidget(QLabel("Save new runs in"))
        self.output_directory = QLineEdit(str(output_directory))
        self.output_directory.setPlaceholderText("Choose a parent folder for generated bundles")
        self.output_directory.editingFinished.connect(
            lambda: self.output_changed.emit(self.output_directory.text())
        )
        destination_row.addWidget(self.output_directory, 1)
        browse_output = QPushButton("Browse")
        browse_output.setIcon(icon("folder"))
        browse_output.clicked.connect(self._browse_output)
        destination_row.addWidget(browse_output)
        generate = QPushButton("Generate")
        generate.setObjectName("primary")
        generate.setIcon(icon("play", color="#ffffff"))
        generate.clicked.connect(
            lambda: self.generate_requested.emit(self.scenario.text(), self.output_directory.text())
        )
        destination_row.addWidget(generate)
        layout.addLayout(destination_row)
        self.work_area = QSplitter(Qt.Orientation.Horizontal)
        self.work_area.setChildrenCollapsible(False)
        validation_panel = QWidget()
        validation_layout = QVBoxLayout(validation_panel)
        validation_layout.setContentsMargins(0, 0, 8, 0)
        validation_layout.setSpacing(8)
        validation_heading = QLabel("VALIDATION FINDINGS")
        validation_heading.setObjectName("eyebrow")
        validation_layout.addWidget(validation_heading)
        self.validation = QPlainTextEdit()
        self.validation.setReadOnly(True)
        self.validation.setPlaceholderText("Validation results appear here.")
        self.validation.setAccessibleName("Validation findings")
        self.validation.textChanged.connect(self._update_validation_visibility)
        validation_layout.addWidget(self.validation, 1)
        self.validation_panel = validation_panel
        self.work_area.addWidget(validation_panel)
        jobs_panel = QWidget()
        jobs_layout = QVBoxLayout(jobs_panel)
        jobs_layout.setContentsMargins(8, 0, 0, 0)
        jobs_layout.setSpacing(8)
        jobs_heading = QHBoxLayout()
        jobs_label = QLabel("RUN HISTORY")
        jobs_label.setObjectName("eyebrow")
        jobs_heading.addWidget(jobs_label)
        jobs_heading.addStretch()
        self.job_count = QLabel("0 runs")
        self.job_count.setObjectName("subtle")
        jobs_heading.addWidget(self.job_count)
        jobs_layout.addLayout(jobs_heading)
        scroll = QScrollArea()
        scroll.setObjectName("jobsScroll")
        scroll.setWidgetResizable(True)
        container = QWidget()
        self.card_layout = QVBoxLayout(container)
        self.card_layout.setContentsMargins(0, 0, 8, 0)
        self.card_layout.setSpacing(12)
        self.card_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.empty_jobs = QLabel("No generation jobs yet. Choose a scenario and generate a run.")
        self.empty_jobs.setObjectName("subtle")
        self.card_layout.addWidget(self.empty_jobs)
        scroll.setWidget(container)
        jobs_layout.addWidget(scroll, 1)
        self.work_area.addWidget(jobs_panel)
        self.work_area.setStretchFactor(0, 3)
        self.work_area.setStretchFactor(1, 2)
        self.work_area.setSizes([900, 600])
        layout.addWidget(self.work_area, 1)
        self._update_validation_visibility()

    def _update_validation_visibility(self) -> None:
        self.validation_panel.setVisible(bool(self.validation.toPlainText().strip()))

    @override
    def resizeEvent(self, event: QResizeEvent) -> None:
        """Keep both work areas usable when the desktop window is narrow."""
        orientation = Qt.Orientation.Horizontal if self.width() >= 980 else Qt.Orientation.Vertical
        if self.work_area.orientation() != orientation:
            self.work_area.setOrientation(orientation)
            self.work_area.setSizes(
                [900, 600] if orientation == Qt.Orientation.Horizontal else [350, 550]
            )
        super().resizeEvent(event)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select EvidenceForge scenario", "", "YAML files (*.yaml *.yml)"
        )
        if path:
            self.scenario.setText(path)

    def _browse_output(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self, "Choose output folder", self.output_directory.text()
        )
        if selected:
            self.output_directory.setText(selected)
            self.output_changed.emit(selected)

    def add_job(self, job: GenerationJob) -> None:
        card = JobCard(job)
        card.suspend_requested.connect(self.suspend_requested.emit)
        card.resume_requested.connect(self.resume_requested.emit)
        self.cards[job.id] = card
        self.card_layout.insertWidget(0, card)
        self.empty_jobs.hide()
        count = len(self.cards)
        self.job_count.setText(f"{count} {'run' if count == 1 else 'runs'}")


class MainWindow(QMainWindow):
    """Prototype desktop shell around Codex authoring and CLI jobs."""

    def __init__(self, store: StateStore, state: DesktopState) -> None:
        super().__init__()
        self.store = store
        self.state = state
        self.job_store = JobStore(store.directory)
        self.job_store.migrate_generations(state.jobs)
        self.state.jobs = self.job_store.load_generations()
        self.skills: dict[str, str] = {}
        self.models: list[CodexModel] = []
        self.chat_panes: dict[str, ChatPane] = {}
        self.job_progress: dict[str, GenerationProgress] = {}
        self.evaluation_jobs: dict[str, EvaluationJob] = {
            job.id: job for job in self.job_store.load_evaluations()
        }
        self._closing = False
        self.progress_offsets: dict[str, int] = {}
        self.progress_partial: dict[str, bytes] = {}
        self.bridge = CodexBridge(self, self.state.settings)
        self.bridge.ready.connect(self._codex_ready)
        self.bridge.event.connect(self._codex_event)
        self.bridge.server_request.connect(self._server_request)
        self.bridge.failed.connect(self._codex_failed)
        self.setWindowTitle("EvidenceForge")
        self.resize(1350, 840)
        central = QWidget()
        self.setCentralWidget(central)
        shell = QHBoxLayout(central)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(16, 24, 16, 18)
        side.setSpacing(8)
        brand = QLabel("EvidenceForge")
        brand.setObjectName("brand")
        side.addWidget(brand)
        tagline = QLabel("LOCAL STUDIO")
        tagline.setObjectName("eyebrow")
        side.addWidget(tagline)
        side.addSpacing(27)
        self.nav_buttons: list[QPushButton] = []
        for index, label in enumerate(
            ("Scenarios", "Authoring", "Industry packs", "Org packs", "Runs")
        ):
            button = QPushButton(label)
            button.setObjectName("nav")
            button.setIcon(icon(("file", "chat", "layers", "folder", "runs")[index]))
            button.setCheckable(True)
            button.clicked.connect(lambda _checked=False, page=index: self._navigate(page))
            side.addWidget(button)
            self.nav_buttons.append(button)
        side.addStretch()
        self.workspace_label = QLabel(self.state.workspace.name)
        self.workspace_label.setToolTip(str(self.state.workspace))
        self.workspace_label.setObjectName("muted")
        self.workspace_label.setWordWrap(True)
        side.addWidget(self.workspace_label)
        self.settings_button = QPushButton("Settings")
        self.settings_button.setObjectName("nav")
        self.settings_button.setIcon(icon("settings"))
        self.settings_button.setCheckable(True)
        self.settings_button.clicked.connect(lambda: self._navigate(5))
        side.addWidget(self.settings_button)
        shell.addWidget(sidebar)
        self.pages = QStackedWidget()
        shell.addWidget(self.pages, 1)

        self.scenario_library = LibraryPane("Scenarios", scenario_mode=True)
        self.scenario_library.import_requested.connect(self._import_scenario)
        self.scenario_library.create_requested.connect(self._new_chat)
        self.scenario_library.edit_requested.connect(self._author_scenario)
        self.scenario_library.clone_requested.connect(self._clone_scenario)
        self.scenario_library.hide_requested.connect(self._toggle_hidden)
        self.scenario_library.validate_requested.connect(self._validate_library_item)
        self.scenario_library.generate_requested.connect(self._generate_library_item)
        self.scenario_library.evaluate_requested.connect(self._evaluate_latest)
        self.scenario_library.refresh_requested.connect(self._refresh_libraries)
        self.scenario_library.folder_create_requested.connect(self._create_scenario_folder)
        self.scenario_library.folder_rename_requested.connect(self._rename_scenario_folder)
        self.scenario_library.folder_delete_requested.connect(self._delete_scenario_folder)
        self.scenario_library.folder_assignment_requested.connect(self._assign_scenario_folder)
        self.scenario_library.view_changed.connect(self._remember_library_view)
        self.scenario_library.view_save_requested.connect(self._save_library_view)
        self.scenario_library.view_rename_requested.connect(self._rename_library_view)
        self.scenario_library.view_delete_requested.connect(self._delete_library_view)
        self.pages.addWidget(self.scenario_library)

        authoring = QWidget()
        author_layout = QVBoxLayout(authoring)
        author_layout.setContentsMargins(25, 24, 25, 24)
        author_top = QHBoxLayout()
        author_title = QLabel("Authoring")
        author_title.setObjectName("pageTitle")
        author_top.addWidget(author_title)
        author_top.addStretch()
        self.recent_button = QToolButton()
        self.recent_button.setObjectName("filterButton")
        self.recent_button.setIcon(icon("chat"))
        self.recent_button.setText("Recent")
        self.recent_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.recent_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.recent_menu = QMenu(self.recent_button)
        self.recent_menu.aboutToShow.connect(self._populate_recent_menu)
        self.recent_button.setMenu(self.recent_menu)
        author_top.addWidget(self.recent_button)
        new_chat = QPushButton("New authoring tab")
        new_chat.setObjectName("primary")
        new_chat.setIcon(icon("add", color="#ffffff"))
        new_chat.clicked.connect(self._new_chat)
        author_top.addWidget(new_chat)
        author_layout.addLayout(author_top)
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self._close_chat_tab)
        self.author_empty = QLabel(
            "No authoring tabs open. Start a new scenario or open one from the library."
        )
        self.author_empty.setObjectName("muted")
        self.author_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        author_layout.addWidget(self.author_empty, 1)
        author_layout.addWidget(self.tabs, 1)
        self.pages.addWidget(authoring)
        for record in self.state.chats:
            if record.open:
                self._add_chat_pane(record)
        self._update_authoring_empty()
        self._update_recent_button()
        self.industry_library = LibraryPane("Industry packs", scenario_mode=False)
        self.organization_library = LibraryPane("Organization packs", scenario_mode=False)
        self.industry_library.create_requested.connect(lambda: self._new_pack_chat("industry"))
        self.organization_library.create_requested.connect(
            lambda: self._new_pack_chat("organization")
        )
        for pane in (self.industry_library, self.organization_library):
            pane.refresh_requested.connect(self._refresh_libraries)
            pane.import_requested.connect(self._import_pack)
            pane.edit_requested.connect(self._author_pack)
            pane.clone_requested.connect(self._clone_pack)
            pane.hide_requested.connect(self._toggle_hidden)
            self.pages.addWidget(pane)
        self.jobs = JobsPane(self._default_output_directory())
        self.jobs.validate_requested.connect(self._validate)
        self.jobs.generate_requested.connect(self._generate)
        self.jobs.output_changed.connect(self._remember_output_directory)
        self.jobs.suspend_requested.connect(self._suspend)
        self.jobs.resume_requested.connect(self._resume)
        self.jobs.resume_all_requested.connect(self._resume_all)
        self.pages.addWidget(self.jobs)
        self.settings_page = SettingsPane(
            self.state.settings, self.state.workspace, self._default_output_directory()
        )
        self.settings_page.changed.connect(self._save)
        self.settings_page.workspace_requested.connect(self._choose_workspace)
        self.settings_page.output_requested.connect(self._remember_output_directory)
        self.settings_page.sign_in_requested.connect(self._sign_in)
        self.settings_page.sign_out_requested.connect(self._sign_out)
        self.settings_page.install_skills_requested.connect(self._install_skills)
        self.pages.addWidget(self.settings_page)
        self.account_label = self.settings_page.account_status
        self.settings_shortcut = QShortcut(QKeySequence("Ctrl+,"), self)
        self.settings_shortcut.activated.connect(lambda: self._navigate(5))
        self.command_palette = CommandPalette(self)
        self.command_shortcut = QShortcut(QKeySequence("Ctrl+K"), self)
        self.command_shortcut.activated.connect(self._open_command_palette)
        for job in self.state.jobs:
            self.jobs.add_job(job)
            self.job_progress[job.id] = GenerationProgress()
        self._refresh_libraries()
        self._restore_library_view()
        self._navigate(0)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll_jobs)
        self.timer.start(1000)
        self._poll_jobs()
        self.validation_process: QProcess | None = None
        control = self.job_store.read_control()
        if control.action != "pause":
            self.job_store.write_control(ControlIntent(action="open", settings=self.state.settings))
        if any(job.status in {"running", "queued"} for job in self.state.jobs) or any(
            job.status in {"running", "queued"} for job in self.evaluation_jobs.values()
        ):
            ensure_controller(self.store.directory)
        self.bridge.start()

    def _save(self) -> None:
        self.store.save(self.state)

    def _default_output_directory(self) -> Path:
        key = str(self.state.workspace.resolve())
        if key in self.state.output_directories:
            return self.state.output_directories[key]
        if not self.state.output_directories and self.state.output_directory is not None:
            return self.state.output_directory
        return self.state.workspace / "runs"

    def _navigate(self, page: int) -> None:
        self.pages.setCurrentIndex(page)
        for index, button in enumerate(self.nav_buttons):
            button.setChecked(index == page)
        self.settings_button.setChecked(page == 5)
        if page in (0, 2, 3):
            self._refresh_libraries()

    def _open_command_palette(self) -> None:
        """Offer workspace navigation and scenario actions from the keyboard."""
        commands: list[Command] = [
            ("New scenario", "Start a new authoring chat", self._new_chat),
            ("Scenarios", "Open the scenario library", lambda: self._navigate(0)),
            ("Authoring", "Open chat tabs", lambda: self._navigate(1)),
            ("Industry packs", "Open reusable industry packs", lambda: self._navigate(2)),
            ("Organization packs", "Open reusable organization packs", lambda: self._navigate(3)),
            ("Runs", "Open generation and evaluation jobs", lambda: self._navigate(4)),
            ("Settings", "Open app preferences", lambda: self._navigate(5)),
            ("Refresh library", "Rescan scenario and pack files", self._refresh_libraries),
        ]
        for folder in self._folder_state().names:
            commands.append(
                (
                    f"Open folder: {folder}",
                    "Show the project folder overview",
                    lambda name=folder: self._open_folder_from_command(name),
                )
            )
        for item in self.scenario_library.items:
            detail = item.description or f"Scenario {item.version}"
            commands.extend(
                [
                    (
                        f"Open scenario: {item.name}",
                        detail,
                        lambda entry=item: self._open_scenario_from_command(entry),
                    ),
                    (
                        f"Continue authoring: {item.name}",
                        detail,
                        lambda entry=item: self._author_scenario(entry),
                    ),
                    (
                        f"Validate: {item.name}",
                        detail,
                        lambda entry=item: self._validate_library_item(entry),
                    ),
                    (
                        f"Generate: {item.name}",
                        detail,
                        lambda entry=item: self._generate_library_item(entry),
                    ),
                ]
            )
        for record in self.state.chats:
            if not record.open:
                commands.append(
                    (
                        f"Resume chat: {record.title}",
                        "Reopen a recent authoring tab",
                        lambda record_id=record.id: self._reopen_chat(record_id),
                    )
                )
        self.command_palette.show_commands(commands)

    def _open_scenario_from_command(self, item: LibraryItem) -> None:
        self._navigate(0)
        if item.path not in self.scenario_library._tree_items:
            hidden = item.path in {path.resolve() for path in self.state.hidden_items}
            self.scenario_library.apply_view(LibraryView(show_hidden=hidden))
        self.scenario_library.select_path(item.path)

    def _open_folder_from_command(self, folder: str) -> None:
        self._navigate(0)
        if folder not in self.scenario_library._folder_items:
            self.scenario_library.apply_view(LibraryView())
        self.scenario_library.select_folder(folder)

    def _folder_state(self) -> ScenarioFolders:
        key = str(self.state.workspace.resolve())
        return self.state.scenario_folders.setdefault(key, ScenarioFolders())

    def _library_view_state(self) -> WorkspaceLibraryViews:
        key = str(self.state.workspace.resolve())
        return self.state.library_views.setdefault(key, WorkspaceLibraryViews())

    def _restore_library_view(self) -> None:
        views = self._library_view_state()
        self.scenario_library.set_saved_views(views.saved)
        current = views.last if self.state.settings.remember_library_view else LibraryView()
        self.scenario_library.apply_view(current, notify=False)

    def _remember_library_view(self, view: LibraryView) -> None:
        if self.state.settings.remember_library_view:
            self._library_view_state().last = view.model_copy(deep=True)
            self._save()

    def _save_library_view(self, view: LibraryView) -> None:
        views = self._library_view_state()
        views.saved.append(view.model_copy(deep=True))
        self.scenario_library.set_saved_views(views.saved)
        self._save()

    def _rename_library_view(self, old: str, new: str) -> None:
        views = self._library_view_state()
        for view in views.saved:
            if view.name == old:
                view.name = new
                break
        if views.last.name == old:
            views.last.name = new
        if self.scenario_library.active_view_name == old:
            self.scenario_library.active_view_name = new
            self.scenario_library._update_views_button()
        self.scenario_library.set_saved_views(views.saved)
        self._save()

    def _delete_library_view(self, name: str) -> None:
        views = self._library_view_state()
        views.saved = [view for view in views.saved if view.name != name]
        if views.last.name == name:
            views.last.name = ""
        if self.scenario_library.active_view_name == name:
            self.scenario_library.active_view_name = ""
            self.scenario_library._update_views_button()
        self.scenario_library.set_saved_views(views.saved)
        self._save()

    def _refresh_libraries(self) -> None:
        hidden = {path.resolve() for path in self.state.hidden_items}
        scorecards: dict[str, str] = {}
        for job in self.state.jobs:
            path = self.store.directory / "evaluations" / f"{job.id}.json"
            if not path.is_file():
                continue
            try:
                report = QualityReport.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError):
                scorecards[job.id] = "Saved evaluation cannot be read"
                continue
            score = f"{report.overall_score:.0f}/100" if report.overall_score is not None else "N/A"
            verdict = (
                "PASS"
                if report.acceptance_passed is True
                else "FAIL"
                if report.acceptance_passed is False
                else "INDETERMINATE"
            )
            scorecards[job.id] = f"{score}  ·  {verdict}  ·  {report.total_records:,} records"
        for evaluation in self.evaluation_jobs.values():
            if evaluation.status in {"running", "queued", "paused"}:
                scorecards[evaluation.generation_id] = (
                    "Evaluating…"
                    if evaluation.status == "running"
                    else f"Evaluation {evaluation.status}"
                )
        self.scenario_library.destination.setText(str(self._default_output_directory()))
        self.scenario_library.set_items(
            discover_scenarios(self.state.workspace, self.state.imported_scenarios),
            hidden,
            self.state.jobs,
            scorecards,
            self._folder_state().names,
            self._folder_state().assignments,
        )
        self.industry_library.set_items(
            discover_packs(self.state.workspace, "industry"), hidden, []
        )
        self.organization_library.set_items(
            discover_packs(self.state.workspace, "organization"), hidden, []
        )

    def _valid_folder_name(self, proposed: str, *, previous: str | None = None) -> str | None:
        name = proposed.strip()
        if not re.fullmatch(r"[^/\\\x00-\x1f]{1,60}", name):
            QMessageBox.warning(
                self, "Invalid folder name", "Use 1–60 characters without slashes or controls."
            )
            return None
        if name.casefold() in {"all folders", "unfiled"}:
            QMessageBox.warning(self, "Reserved folder name", "Choose another folder name.")
            return None
        if any(
            existing.casefold() == name.casefold() and existing != previous
            for existing in self._folder_state().names
        ):
            QMessageBox.warning(self, "Folder exists", "Choose a different folder name.")
            return None
        return name

    def _create_scenario_folder(self) -> None:
        selected = self.scenario_library.selected_item()
        proposed, accepted = QInputDialog.getText(self, "New folder", "Folder name:")
        if not accepted:
            return
        name = self._valid_folder_name(proposed)
        if name is None:
            return
        folders = self._folder_state()
        folders.names.append(name)
        if selected is not None:
            folders.assignments[str(selected.path)] = name
        self._save()
        self._refresh_libraries()
        self.scenario_library.select_folder(name)
        if selected is not None:
            self.scenario_library.select_path(selected.path)

    def _rename_scenario_folder(self, previous: str) -> None:
        folders = self._folder_state()
        if previous not in folders.names:
            return
        proposed, accepted = QInputDialog.getText(
            self, "Rename folder", "Folder name:", text=previous
        )
        if not accepted:
            return
        name = self._valid_folder_name(proposed, previous=previous)
        if name is None or name == previous:
            return
        folders.names[folders.names.index(previous)] = name
        folders.assignments = {
            path: name if assigned == previous else assigned
            for path, assigned in folders.assignments.items()
        }
        self._save()
        self._refresh_libraries()
        self.scenario_library.select_folder(name)

    def _delete_scenario_folder(self, name: str) -> None:
        folders = self._folder_state()
        if name not in folders.names:
            return
        answer = QMessageBox.question(
            self,
            "Delete folder",
            f"Delete virtual folder '{name}'? Its scenarios will become Unfiled."
            "\nScenario files will stay on disk.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        folders.names.remove(name)
        folders.assignments = {
            path: assigned for path, assigned in folders.assignments.items() if assigned != name
        }
        self._save()
        self._refresh_libraries()

    def _assign_scenario_folder(self, item: LibraryItem, name: str) -> None:
        folders = self._folder_state()
        if name and name not in folders.names:
            return
        if name:
            folders.assignments[str(item.path)] = name
        else:
            folders.assignments.pop(str(item.path), None)
        self._save()
        self._refresh_libraries()
        self.scenario_library.select_path(item.path)

    def _toggle_hidden(self, item: LibraryItem) -> None:
        hidden = {path.resolve() for path in self.state.hidden_items}
        if item.path in hidden:
            hidden.remove(item.path)
        else:
            hidden.add(item.path)
        self.state.hidden_items = sorted(hidden)
        self._save()
        self._refresh_libraries()

    def _import_scenario(self) -> None:
        path = self.scenario_library.choose_import()
        if path is None:
            return
        items = discover_scenarios(self.state.workspace, [path])
        if not any(item.path == path for item in items):
            QMessageBox.warning(
                self, "Not a scenario", "Choose an authored EvidenceForge scenario YAML."
            )
            return
        if path not in self.state.imported_scenarios:
            self.state.imported_scenarios.append(path)
            folder = self.scenario_library.selected_folder_name()
            if isinstance(folder, str) and folder:
                self._folder_state().assignments[str(path)] = folder
            self._save()
        self._refresh_libraries()

    def _author_scenario(self, item: LibraryItem) -> None:
        record = ChatRecord(
            id=uuid4().hex,
            title=item.name,
            skill_name="eforge-scenario",
            context_path=item.path,
            context_kind="scenario",
        )
        self.state.chats.append(record)
        pane = self._add_chat_pane(record)
        pane.prompt.setPlaceholderText("What would you like to change in this scenario?")
        self.tabs.setCurrentWidget(pane)
        self._navigate(1)
        self._save()

    def _validate_library_item(self, item: LibraryItem) -> None:
        self.jobs.scenario.setText(str(item.path))
        self._navigate(4)
        self._validate(str(item.path))

    def _generate_library_item(self, item: LibraryItem) -> None:
        self.jobs.scenario.setText(str(item.path))
        self._navigate(4)
        self.jobs.scenario.setFocus()
        self.statusBar().showMessage("Choose an output folder, then click Generate", 8000)

    def _evaluate_latest(self, item: LibraryItem) -> None:
        related = sorted(
            (
                job
                for job in self.state.jobs
                if job.scenario.resolve() == item.path and job.status == "completed"
            ),
            key=lambda job: job.started_at,
            reverse=True,
        )
        if not related:
            return
        job = related[0]
        if any(
            evaluation.generation_id == job.id
            and evaluation.status in {"queued", "running", "paused"}
            for evaluation in self.evaluation_jobs.values()
        ):
            self.statusBar().showMessage("Evaluation is already running", 5000)
            return
        try:
            evaluation = queue_evaluation(job, self.store.directory, settings=self.state.settings)
        except (FileNotFoundError, OSError) as error:
            QMessageBox.warning(self, "Evaluation could not start", str(error))
            return
        self.job_store.save_evaluation(evaluation)
        self.evaluation_jobs[evaluation.id] = evaluation
        ensure_controller(self.store.directory)
        self._refresh_libraries()

    def _author_pack(self, item: LibraryItem) -> None:
        skill = "eforge-industry-pack" if item.kind == "industry" else "eforge-organization-pack"
        record = ChatRecord(
            id=uuid4().hex,
            title=item.name,
            skill_name=skill,
            context_path=item.path,
            context_kind="industry pack" if item.kind == "industry" else "organization pack",
        )
        self.state.chats.append(record)
        pane = self._add_chat_pane(record)
        pane.prompt.setPlaceholderText(f"What would you like to change in this {item.kind} pack?")
        self.tabs.setCurrentWidget(pane)
        self._navigate(1)
        self._save()

    def _new_pack_chat(self, kind: str) -> None:
        skill = "eforge-industry-pack" if kind == "industry" else "eforge-organization-pack"
        record = ChatRecord(
            id=uuid4().hex,
            title=f"New {kind} pack",
            skill_name=skill,
            context_kind="industry pack" if kind == "industry" else "organization pack",
        )
        self.state.chats.append(record)
        pane = self._add_chat_pane(record)
        pane.prompt.setPlaceholderText(f"Describe the {kind} pack you want to create…")
        self.tabs.setCurrentWidget(pane)
        self._navigate(1)
        self._save()

    def _clone_scenario(self, item: LibraryItem) -> None:
        name, accepted = QInputDialog.getText(
            self, "Clone scenario", "New scenario name:", text=f"{item.name}-copy"
        )
        if not accepted:
            return
        slug = name.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", slug):
            QMessageBox.warning(
                self, "Invalid name", "Use letters, digits, hyphens, or underscores."
            )
            return
        destination = self.state.workspace / "scenarios" / slug / "scenario.yaml"
        if destination.exists():
            QMessageBox.warning(self, "Already exists", str(destination))
            return
        try:
            source = item.path.read_text(encoding="utf-8")
            clone = re.sub(r"(?m)^name:\s*[^\n]*$", f"name: {slug}", source, count=1)
            destination.parent.mkdir(parents=True, exist_ok=False)
            destination.write_text(clone, encoding="utf-8")
        except (OSError, UnicodeError) as error:
            QMessageBox.warning(self, "Clone failed", str(error))
            return
        source_folder = self._folder_state().assignments.get(str(item.path))
        if source_folder:
            self._folder_state().assignments[str(destination.resolve())] = source_folder
            self._save()
        self._refresh_libraries()
        self.scenario_library.select_path(destination.resolve())
        self.statusBar().showMessage(f"Created {destination}", 7000)

    def _import_pack(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Select a pack version folder")
        if not selected:
            return
        source = Path(selected).resolve()
        pack_file = source / "pack.yaml"
        if not pack_file.is_file():
            QMessageBox.warning(
                self, "Pack missing", "Choose a version folder containing pack.yaml."
            )
            return
        import yaml

        try:
            data = yaml.safe_load(pack_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("type") not in {"industry", "organization"}:
                raise ValueError("pack.yaml must declare an industry or organization pack")
            publisher = str(data["publisher"])
            kind = str(data["type"])
            name = str(data["name"])
            version = str(data["version"])
            if not all(
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value)
                for value in (publisher, name, version)
            ):
                raise ValueError("Pack identity contains invalid path characters")
            destination = (
                self.state.workspace / ".eforge" / "packs" / publisher / kind / name / version
            )
            if destination.exists():
                raise FileExistsError(f"Pack already exists: {destination}")
            shutil.copytree(source, destination)
        except (OSError, ValueError, KeyError, yaml.YAMLError) as error:
            QMessageBox.warning(self, "Import failed", str(error))
            return
        self._refresh_libraries()

    def _clone_pack(self, item: LibraryItem) -> None:
        name, accepted = QInputDialog.getText(
            self, "Clone pack", "New pack name:", text=f"{item.name}-copy"
        )
        if not accepted:
            return
        slug = name.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", slug):
            QMessageBox.warning(
                self, "Invalid name", "Use letters, digits, hyphens, dots, or underscores."
            )
            return
        destination = (
            self.state.workspace / ".eforge" / "packs" / "local" / item.kind / slug / item.version
        )
        if destination.exists():
            QMessageBox.warning(self, "Already exists", str(destination))
            return
        try:
            shutil.copytree(item.path.parent, destination)
            pack_file = destination / "pack.yaml"
            source = pack_file.read_text(encoding="utf-8")
            source = re.sub(r"(?m)^name:\s*[^\n]*$", f"name: {slug}", source, count=1)
            source = re.sub(r"(?m)^publisher:\s*[^\n]*$", "publisher: local", source, count=1)
            pack_file.write_text(source, encoding="utf-8")
        except (OSError, UnicodeError) as error:
            QMessageBox.warning(self, "Clone failed", str(error))
            return
        self._refresh_libraries()

    def _add_chat_pane(self, record: ChatRecord) -> ChatPane:
        pane = ChatPane(record)
        pane.set_skills(self.skills)
        pane.set_models(self.models)
        pane.send_requested.connect(self._send_chat)
        pane.interrupt_requested.connect(self._interrupt_chat)
        pane.configuration_changed.connect(self._save)
        self.chat_panes[record.id] = pane
        index = self.tabs.addTab(pane, record.title)
        close_tab = QToolButton(self.tabs)
        close_tab.setObjectName("tabClose")
        close_tab.setIcon(icon("close"))
        close_tab.setToolTip(f"Close {record.title}")
        close_tab.setAccessibleName(close_tab.toolTip())
        close_tab.clicked.connect(lambda: self._close_chat_tab(self.tabs.indexOf(pane)))
        self.tabs.tabBar().setTabButton(index, QTabBar.ButtonPosition.RightSide, close_tab)
        self._update_authoring_empty()
        return pane

    def _update_authoring_empty(self) -> None:
        has_tabs = self.tabs.count() > 0
        self.tabs.setVisible(has_tabs)
        self.author_empty.setVisible(not has_tabs)

    def _update_recent_button(self) -> None:
        self.recent_button.setEnabled(any(not record.open for record in self.state.chats))

    def _populate_recent_menu(self) -> None:
        self.recent_menu.clear()
        for record in reversed(self.state.chats):
            if not record.open:
                self.recent_menu.addAction(
                    record.title,
                    lambda _checked=False, record_id=record.id: self._reopen_chat(record_id),
                )

    def _reopen_chat(self, record_id: str) -> None:
        record = next((entry for entry in self.state.chats if entry.id == record_id), None)
        if record is None or record.open:
            return
        record.open = True
        pane = self._add_chat_pane(record)
        self.tabs.setCurrentWidget(pane)
        self._navigate(1)
        if self.bridge.initialized and record.thread_id:
            self.bridge.request(
                "thread/resume",
                {"threadId": record.thread_id},
                lambda response, current=pane: self._resumed(current, response),
            )
        self._update_recent_button()
        self._save()

    def _close_chat_tab(self, index: int) -> None:
        pane = self.tabs.widget(index)
        if not isinstance(pane, ChatPane):
            return
        close_button = self.tabs.tabBar().tabButton(index, QTabBar.ButtonPosition.RightSide)
        if pane.record.thread_id and pane.interrupt.isEnabled():
            self.bridge.request("turn/interrupt", {"threadId": pane.record.thread_id})
        self.tabs.removeTab(index)
        if close_button is not None:
            close_button.deleteLater()
        self.chat_panes.pop(pane.record.id, None)
        pane.record.open = False
        self._update_authoring_empty()
        self._update_recent_button()
        self._save()

    def _new_chat(self) -> None:
        number = len(self.state.chats) + 1
        record = ChatRecord(
            id=uuid4().hex,
            title=f"Authoring {number}",
            skill_name="eforge-scenario",
        )
        self.state.chats.append(record)
        pane = self._add_chat_pane(record)
        self.tabs.setCurrentWidget(pane)
        self._navigate(1)
        self._save()

    def _choose_workspace(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self, "Choose EvidenceForge workspace", str(self.state.workspace)
        )
        if not selected:
            return
        if any(job.status in {"running", "queued"} for job in self.state.jobs):
            QMessageBox.warning(
                self, "Jobs running", "Wait for active jobs before changing workspace."
            )
            return
        self.state.workspace = Path(selected).resolve()
        self.workspace_label.setText(self.state.workspace.name)
        self.workspace_label.setToolTip(str(self.state.workspace))
        self.jobs.output_directory.setText(str(self._default_output_directory()))
        self.settings_page.set_workspace(self.state.workspace, self._default_output_directory())
        self._save()
        self._refresh_libraries()
        self._restore_library_view()
        if self.bridge.initialized:
            self._refresh_skills()

    def _codex_ready(self) -> None:
        self.account_label.setText("Checking sign-in…")
        self.bridge.request("account/read", {"refreshToken": False}, self._account_response)
        self._refresh_skills()
        self._refresh_models()
        for pane in self.chat_panes.values():
            if pane.record.thread_id:
                self.bridge.request(
                    "thread/resume",
                    {"threadId": pane.record.thread_id},
                    lambda response, p=pane: self._resumed(p, response),
                )

    def _refresh_models(self) -> None:
        self.models = []
        self.bridge.request("model/list", {"limit": 100}, self._models_response)

    def _models_response(self, response: dict[str, Any]) -> None:
        if "error" in response:
            self.statusBar().showMessage(f"Models unavailable: {_error_text(response)}", 8000)
            return
        result = response.get("result", {})
        if not isinstance(result, dict):
            return
        for entry in result.get("data", []):
            try:
                model = CodexModel.model_validate(entry)
            except ValidationError:
                continue
            if model.id not in {known.id for known in self.models}:
                self.models.append(model)
        cursor = result.get("nextCursor")
        if cursor:
            self.bridge.request(
                "model/list", {"limit": 100, "cursor": cursor}, self._models_response
            )
            return
        for pane in self.chat_panes.values():
            pane.set_models(self.models)

    def _account_response(self, response: dict[str, Any]) -> None:
        if "error" in response:
            self.settings_page.set_account_unavailable()
            return
        result = response.get("result")
        account = result.get("account") if isinstance(result, dict) else None
        self.settings_page.set_account(account if isinstance(account, dict) else None)

    def _sign_in(self) -> None:
        if not self.bridge.initialized:
            QMessageBox.warning(self, "Codex unavailable", "The Codex app-server is not ready.")
            return
        self.bridge.request(
            "account/login/start",
            {"type": "chatgpt", "useHostedLoginSuccessPage": True, "appBrand": "codex"},
            self._login_started,
        )

    def _login_started(self, response: dict[str, Any]) -> None:
        if "error" in response:
            QMessageBox.warning(self, "Sign-in failed", _error_text(response))
            return
        url = response.get("result", {}).get("authUrl")
        if url:
            QDesktopServices.openUrl(QUrl(str(url)))
            self.account_label.setText("Complete sign-in in your browser")
            self.settings_page.account_action.setEnabled(False)

    def _sign_out(self) -> None:
        if not self.bridge.initialized:
            QMessageBox.warning(self, "Codex unavailable", "The Codex app-server is not ready.")
            return
        self.settings_page.account_action.setEnabled(False)
        self.bridge.request("account/logout", None, self._logout_finished)

    def _logout_finished(self, response: dict[str, Any]) -> None:
        if "error" in response:
            self.settings_page.account_action.setEnabled(True)
            QMessageBox.warning(self, "Sign-out failed", _error_text(response))
            return
        self.bridge.request("account/read", {"refreshToken": False}, self._account_response)

    def _refresh_skills(self) -> None:
        self.bridge.request(
            "skills/list",
            {"cwds": [str(self.state.workspace)], "forceReload": True},
            self._skills_response,
        )

    def _skills_response(self, response: dict[str, Any]) -> None:
        if "error" in response:
            self.statusBar().showMessage(_error_text(response), 8000)
            return
        skills: dict[str, str] = {}
        for group in response.get("result", {}).get("data", []):
            for skill in group.get("skills", []):
                name = str(skill.get("name", ""))
                path = skill.get("path")
                if name.startswith("eforge-") and path and skill.get("enabled", True):
                    skills[name] = str(path)
        self.skills = skills
        for pane in self.chat_panes.values():
            pane.set_skills(skills)
        self.statusBar().showMessage(f"{len(skills)} EvidenceForge skills available", 5000)

    def _install_skills(self) -> None:
        targets = skill_targets(
            self.state.settings.skill_install_scope,
            self.state.settings.skill_install_agent,
            self.state.workspace,
        )
        installed_files = 0
        successful_agents: set[str] = set()
        failures: list[str] = []
        for agent, target in targets:
            try:
                installed, _removed = (
                    install_skills(target) if agent == "claude" else install_chatgpt_skills(target)
                )
            except (OSError, PermissionError, ValueError) as error:
                failures.append(f"{agent}: {error}")
                continue
            installed_files += len(installed)
            successful_agents.add(agent)
        self.settings_page.refresh_skill_installation()
        if self.bridge.initialized and "chatgpt" in successful_agents:
            self._refresh_skills()
        if failures:
            QMessageBox.warning(
                self,
                "Skill installation incomplete",
                "Some selected targets could not be installed:\n" + "\n".join(failures),
            )
        if self.state.settings.skill_install_scope == "global" and "chatgpt" in successful_agents:
            legacy = Path.home() / ".codex" / "skills"
            if find_evidenceforge_chatgpt_skills(legacy):
                self.statusBar().showMessage(
                    f"Installed {installed_files} files. Legacy copies also exist in {legacy}.",
                    10000,
                )
                return
        if successful_agents:
            self.statusBar().showMessage(
                f"Installed {installed_files} EvidenceForge skill files", 6000
            )

    def _resumed(self, pane: ChatPane, response: dict[str, Any]) -> None:
        if "error" in response:
            pane.add_system(f"Could not resume conversation: {_error_text(response)}")
            return
        self.bridge.request(
            "thread/read",
            {"threadId": pane.record.thread_id, "includeTurns": True},
            lambda result, p=pane: self._history_response(p, result),
        )

    def _history_response(self, pane: ChatPane, response: dict[str, Any]) -> None:
        if "error" in response:
            return
        thread = response.get("result", {}).get("thread", {})
        for turn in thread.get("turns", []):
            turn_id = str(turn.get("id", "history"))
            for item in turn.get("items", []):
                if item.get("type") == "userMessage":
                    text = "\n".join(
                        str(part.get("text", ""))
                        for part in item.get("content", [])
                        if part.get("type") == "text"
                    )
                    if text:
                        pane.add_user(text)
                elif item.get("type") == "agentMessage" and item.get("text"):
                    pane.add_agent_text(str(item["text"]))
                elif item.get("type") not in {"userMessage", "agentMessage"}:
                    pane.add_activity(turn_id, item)

    def _send_chat(self, pane: ChatPane, text: str) -> None:
        if not self.bridge.initialized:
            pane.add_system("Codex is not connected.")
            return
        pane.add_user(text)
        pane.set_busy(True)
        pane.record.skill_name = pane.skill.currentText()
        self._save()
        if pane.record.thread_id is None:
            parameters: dict[str, Any] = {
                "cwd": str(self.state.workspace),
                "sandbox": "workspace-write",
            }
            if pane.record.context_kind:
                target = (
                    f" at {json.dumps(str(pane.record.context_path))}"
                    if pane.record.context_path
                    else ""
                )
                parameters["developerInstructions"] = (
                    f"This conversation was opened for the EvidenceForge {pane.record.context_kind}"
                    f"{target}. This is context for the user's later requests, not a request to "
                    "edit anything. Wait for the user's message before taking action."
                )
            if pane.record.model_id:
                parameters["model"] = pane.record.model_id
            self.bridge.request(
                "thread/start",
                parameters,
                lambda response, p=pane, t=text: self._thread_started(p, t, response),
            )
        else:
            self._start_turn(pane, text)

    def _thread_started(self, pane: ChatPane, text: str, response: dict[str, Any]) -> None:
        if "error" in response:
            pane.add_system(_error_text(response))
            pane.set_busy(False)
            return
        pane.record.thread_id = str(response["result"]["thread"]["id"])
        self._save()
        self._start_turn(pane, text)

    def _start_turn(self, pane: ChatPane, text: str) -> None:
        skill_name = pane.skill.currentText()
        skill_path = self.skills.get(skill_name)
        inputs: list[dict[str, str]] = [{"type": "text", "text": text}]
        if skill_path:
            inputs.append({"type": "skill", "name": skill_name, "path": skill_path})
        parameters: dict[str, Any] = {"threadId": pane.record.thread_id, "input": inputs}
        if pane.record.model_id:
            parameters["model"] = pane.record.model_id
        if pane.record.reasoning_effort:
            parameters["effort"] = pane.record.reasoning_effort
        self.bridge.request(
            "turn/start",
            parameters,
            lambda response, p=pane: self._turn_started(p, response),
        )

    def _turn_started(self, pane: ChatPane, response: dict[str, Any]) -> None:
        if "error" in response:
            pane.add_system(_error_text(response))
            pane.set_busy(False)
            return
        automatic = pane.skill.findText("Automatic")
        if automatic >= 0:
            pane.skill.setCurrentIndex(automatic)
            pane.record.skill_name = "Automatic"
            self._save()

    def _interrupt_chat(self, pane: ChatPane) -> None:
        if pane.record.thread_id:
            self.bridge.request("turn/interrupt", {"threadId": pane.record.thread_id})

    def _pane_for_thread(self, thread_id: str | None) -> ChatPane | None:
        if thread_id is None:
            return None
        return next(
            (pane for pane in self.chat_panes.values() if pane.record.thread_id == thread_id),
            None,
        )

    def _codex_event(self, method: str, params: object) -> None:
        if not isinstance(params, dict):
            return
        if method in {"account/updated", "account/login/completed"}:
            self.bridge.request("account/read", {"refreshToken": False}, self._account_response)
            self._refresh_models()
            return
        if method == "skills/changed":
            self._refresh_skills()
            return
        pane = self._pane_for_thread(params.get("threadId"))
        if pane is None:
            return
        if method == "item/agentMessage/delta":
            pane.add_agent_delta(str(params.get("itemId", "message")), str(params.get("delta", "")))
        elif method in {"item/started", "item/completed"}:
            item = params.get("item", {})
            if isinstance(item, dict) and item.get("type") not in {
                "userMessage",
                "agentMessage",
            }:
                pane.add_activity(str(params.get("turnId") or "active"), item)
                if method == "item/started":
                    activity = {
                        "commandExecution": "Running a command…",
                        "fileChange": "Editing files…",
                        "reasoning": "Reasoning…",
                    }
                    pane.status.setText(activity.get(str(item.get("type")), "Using a tool…"))
                elif pane.send.isEnabled() is False:
                    pane.status.setText("Codex is working…")
        elif method == "turn/completed":
            pane.set_busy(False)
            self._refresh_libraries()
            turn = params.get("turn", {})
            if turn.get("status") != "completed":
                pane.add_system(f"Turn {turn.get('status', 'ended')}")
        elif method == "warning":
            pane.add_system(str(params.get("message", "Codex warning")))

    def _server_request(self, request: object) -> None:
        if not isinstance(request, dict):
            return
        method = str(request.get("method", ""))
        params = request.get("params", {})
        request_id = request.get("id")
        if not isinstance(params, dict) or request_id is None:
            return
        if method in {"item/commandExecution/requestApproval", "item/fileChange/requestApproval"}:
            subject = params.get("command") or params.get("reason") or method
            answer = QMessageBox.question(
                self,
                "Codex approval",
                f"Allow this action in {params.get('cwd', self.state.workspace)}?\n\n{subject}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            decision = "accept" if answer == QMessageBox.StandardButton.Yes else "decline"
            self.bridge.respond(request_id, {"decision": decision})
        elif method == "item/permissions/requestApproval":
            answer = QMessageBox.question(
                self,
                "Additional permissions",
                f"Codex requests additional access:\n\n{params.get('reason', params.get('permissions'))}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            permissions = (
                params.get("permissions", {}) if answer == QMessageBox.StandardButton.Yes else {}
            )
            self.bridge.respond(request_id, {"permissions": permissions})
        elif method == "item/tool/requestUserInput":
            answers: dict[str, dict[str, list[str]]] = {}
            for question in params.get("questions", []):
                answer, accepted = QInputDialog.getText(
                    self,
                    str(question.get("header", "Codex question")),
                    str(question.get("question", "")),
                )
                answers[str(question.get("id", "question"))] = {
                    "answers": [answer] if accepted else []
                }
            self.bridge.respond(request_id, {"answers": answers})
        else:
            self.bridge.respond(request_id, {})

    def _codex_failed(self, message: str) -> None:
        self.settings_page.set_account_unavailable()
        self.statusBar().showMessage(message, 12000)

    def _validate(self, scenario_text: str) -> None:
        scenario = Path(scenario_text).expanduser().resolve()
        if not scenario.is_file():
            QMessageBox.warning(self, "Scenario missing", "Choose an existing scenario YAML file.")
            return
        if self.validation_process is not None:
            QMessageBox.information(self, "Validation running", "Wait for validation to finish.")
            return
        from evidenceforge.desktop.jobs import _eforge_command

        process = QProcess(self)
        self.validation_process = process
        process.setWorkingDirectory(str(self.state.workspace))
        command = _eforge_command()
        process.setProgram(command[0])
        process.setArguments(
            [
                *command[1:],
                "validate",
                str(scenario),
                "--project-root",
                str(self.state.workspace),
                "--json",
            ]
        )
        self.jobs.validation.setPlainText("Validating scenario…")
        process.finished.connect(lambda _code, _status: self._validation_finished(process))
        process.start()

    def _validation_finished(self, process: QProcess) -> None:
        output = bytes(process.readAllStandardOutput()).decode("utf-8", "replace")
        errors = bytes(process.readAllStandardError()).decode("utf-8", "replace")
        self.jobs.validation.setPlainText(
            format_validation_output(output, errors, process.exitCode())
        )
        self.validation_process = None
        process.deleteLater()

    def _remember_output_directory(self, value: str) -> None:
        destination = self._output_directory(value)
        self.state.output_directory = destination
        if destination is not None:
            self.state.output_directories[str(self.state.workspace.resolve())] = destination
        self.jobs.output_directory.setText(str(destination or self.state.workspace / "runs"))
        self.settings_page.output_value.setText(self.jobs.output_directory.text())
        self._save()
        self._refresh_libraries()

    def _output_directory(self, value: str) -> Path | None:
        if not value.strip():
            return None
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = self.state.workspace / path
        return path.resolve()

    def _generate(self, scenario_text: str, destination_text: str) -> None:
        destination = self._output_directory(destination_text)
        try:
            job = queue_generation(
                Path(scenario_text).expanduser(),
                self.state.workspace,
                self.store.directory,
                output_parent=destination,
                settings=self.state.settings,
            )
        except (OSError, RuntimeError, ValueError) as error:
            QMessageBox.warning(self, "Generation could not start", str(error))
            return
        self.state.jobs.append(job)
        self.job_store.save_generation(job)
        self.state.output_directory = destination
        if destination is not None:
            self.state.output_directories[str(self.state.workspace.resolve())] = destination
        self.job_progress[job.id] = GenerationProgress()
        self.jobs.add_job(job)
        self._save()
        ensure_controller(self.store.directory)
        self._refresh_libraries()
        self._poll_jobs()

    def _suspend(self, job: GenerationJob) -> None:
        try:
            result = request_suspension(job, self.state.workspace)
        except (OSError, subprocess.TimeoutExpired) as error:
            QMessageBox.warning(self, "Suspend failed", str(error))
            return
        if result.returncode:
            QMessageBox.warning(self, "Suspend failed", result.stderr or result.stdout)
        else:
            self.statusBar().showMessage("Suspension requested; the current hour will finish", 8000)

    def _resume(self, job: GenerationJob) -> None:
        self.job_store.write_control(
            ControlIntent(
                action="resume",
                settings=self.state.settings,
                resume_generation_id=job.id,
            )
        )
        ensure_controller(self.store.directory)
        self.statusBar().showMessage(f"Resuming {job.scenario.stem}", 6000)

    def _resume_all(self) -> None:
        self.job_store.write_control(ControlIntent(action="resume", settings=self.state.settings))
        ensure_controller(self.store.directory)
        self.statusBar().showMessage("Resuming paused jobs", 6000)

    def _poll_jobs(self) -> None:
        changed = False
        records = {job.id: job for job in self.job_store.load_generations()}
        for job in self.state.jobs:
            current = records.get(job.id)
            if current is not None:
                changed |= job.model_dump() != current.model_dump()
                for field in type(job).model_fields:
                    setattr(job, field, getattr(current, field))
            elif refresh_status(job):
                changed = True
            progress = self.job_progress.setdefault(job.id, GenerationProgress())
            if job.progress_file.is_file():
                with job.progress_file.open("rb") as stream:
                    stream.seek(self.progress_offsets.get(job.id, 0))
                    chunk = stream.read()
                    self.progress_offsets[job.id] = stream.tell()
                combined = self.progress_partial.get(job.id, b"") + chunk
                lines = combined.split(b"\n")
                self.progress_partial[job.id] = lines.pop()
                for line in lines:
                    event = parse_progress_line(line.decode("utf-8", "replace"))
                    if event is not None:
                        progress.apply(event)
            card = self.jobs.cards.get(job.id)
            if card:
                card.update_display(progress)
        evaluations = {job.id: job for job in self.job_store.load_evaluations()}
        if evaluations != self.evaluation_jobs:
            self.evaluation_jobs = evaluations
            changed = True
        if changed:
            self._save()
            self._refresh_libraries()

    def _close_exceptions(self) -> dict[str, str] | None:
        exceptions: dict[str, str] = {}
        if self.state.settings.close_action != "pause":
            return exceptions
        for job in self.job_store.load_generations():
            if job.status != "running" or job.checkpoint_hours != 0:
                continue
            answer = QMessageBox.question(
                self,
                "This job cannot checkpoint",
                f"{job.scenario.name} was started with checkpointing disabled.\n\n"
                "Yes: let this job continue. No: stop it and preserve its files. "
                "Cancel: keep the app open.",
                QMessageBox.StandardButton.Yes
                | QMessageBox.StandardButton.No
                | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer == QMessageBox.StandardButton.Cancel:
                return None
            exceptions[job.id] = "continue" if answer == QMessageBox.StandardButton.Yes else "stop"
        return exceptions

    def _wait_for_handoff(self, intent: ControlIntent) -> bool:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.job_store.acknowledged(intent.id):
                return True
            QApplication.processEvents()
            time.sleep(0.05)
        return False

    def _wait_for_checkpoints(self, exceptions: dict[str, str]) -> bool:
        dialog = QProgressDialog(
            "Waiting for active generations to checkpoint and stop…", "Cancel close", 0, 0, self
        )
        dialog.setWindowTitle("Pausing jobs")
        dialog.setMinimumDuration(0)
        dialog.show()
        try:
            while True:
                running = [
                    job
                    for job in self.job_store.load_generations()
                    if job.status == "running" and exceptions.get(job.id) != "continue"
                ]
                if not running:
                    return True
                failures = [
                    f"{job.scenario.name}: {job.status_message}"
                    for job in running
                    if job.status_message.startswith("Pause request failed")
                ]
                if failures:
                    QMessageBox.warning(self, "Could not pause jobs", "\n".join(failures))
                    return False
                if dialog.wasCanceled():
                    return False
                QApplication.processEvents()
                time.sleep(0.2)
        finally:
            dialog.close()

    @override
    def closeEvent(self, event: Any) -> None:
        """Hand the selected close policy to the durable local controller."""
        settings = self.state.settings
        exceptions = self._close_exceptions()
        if exceptions is None:
            event.ignore()
            return
        if settings.close_action == "kill" and settings.kill_incomplete_bundles == "delete":
            answer = QMessageBox.question(
                self,
                "Delete incomplete bundles?",
                "This will delete incomplete bundles created by this app after their jobs stop. "
                "Completed and imported bundles are preserved.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        pending = any(
            job.status in {"queued", "running", "paused"}
            for job in self.job_store.load_generations()
        ) or any(
            job.status in {"queued", "running", "paused"}
            for job in self.job_store.load_evaluations()
        )
        if settings.close_action == "kill" and settings.kill_incomplete_bundles == "delete":
            pending = True
        if pending:
            intent = ControlIntent(
                action=settings.close_action,
                settings=settings.model_copy(deep=True),
                generation_exceptions=exceptions,
            )
            self.job_store.write_control(intent)
            ensure_controller(self.store.directory)
            if not self._wait_for_handoff(intent):
                self.job_store.write_control(
                    ControlIntent(action="open", settings=self.state.settings)
                )
                QMessageBox.warning(
                    self, "Could not close safely", "The local job controller did not respond."
                )
                event.ignore()
                return
            if settings.close_action == "pause" and settings.pause_close_timing == "wait":
                if not self._wait_for_checkpoints(exceptions):
                    event.ignore()
                    return
        self._closing = True
        self._save()
        if self.validation_process is not None:
            self.validation_process.terminate()
            self.validation_process.waitForFinished(1000)
        self.bridge.close()
        super().closeEvent(event)


def _configure_font(application: QApplication) -> None:
    """Use an installed UI font instead of a missing family or Qt alias."""
    available = set(QFontDatabase.families())
    system_family = QFontDatabase.systemFont(QFontDatabase.SystemFont.GeneralFont).family()
    if sys.platform == "darwin":
        preferred = [system_family, ".AppleSystemUIFont", "Helvetica Neue", "Arial"]
    elif sys.platform == "win32":
        preferred = [system_family, "Segoe UI", "Arial"]
    else:
        preferred = [system_family, "Noto Sans", "DejaVu Sans", "Liberation Sans", "Arial"]
    family = next((candidate for candidate in preferred if candidate in available), None)
    if family is None and available:
        family = sorted(available)[0]
    if family is not None:
        application.setFont(QFont(family))


def main() -> None:
    """Start the local desktop prototype."""
    application = QApplication(sys.argv)
    application.setApplicationName("EvidenceForge")
    application.setStyle("Fusion")
    _configure_font(application)
    application.setStyleSheet(_STYLE)
    store = StateStore(state_directory())
    default_workspace = Path.cwd()
    try:
        state = store.load(default_workspace)
    except (OSError, ValueError) as error:
        QMessageBox.critical(None, "EvidenceForge state error", str(error))
        raise SystemExit(1) from error
    window = MainWindow(store, state)
    window.show()
    raise SystemExit(application.exec())


if __name__ == "__main__":
    main()
