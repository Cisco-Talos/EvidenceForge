"""Launch the optional EvidenceForge desktop prototype."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, override
from uuid import uuid4

from PySide6.QtCore import QProcess, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont, QKeyEvent, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
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
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTabBar,
    QTabWidget,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from evidenceforge.cli.install_skills import install_chatgpt_skills
from evidenceforge.desktop.app_server import CodexBridge
from evidenceforge.desktop.icons import icon
from evidenceforge.desktop.jobs import (
    process_running,
    refresh_status,
    request_suspension,
    resume_generation,
    start_generation,
)
from evidenceforge.desktop.library import LibraryItem, discover_packs, discover_scenarios
from evidenceforge.desktop.library_ui import LibraryPane
from evidenceforge.desktop.progress import GenerationProgress, parse_progress_line
from evidenceforge.desktop.state import (
    ChatRecord,
    DesktopState,
    GenerationJob,
    ScenarioFolders,
    StateStore,
    state_directory,
)
from evidenceforge.desktop.validation import format_validation_output
from evidenceforge.evaluation.models import QualityReport

_STYLE = """
QWidget { background: #0d111a; color: #e9edf5; font-size: 13px; font-family: "Inter", "SF Pro Text", sans-serif; }
QLabel { background: transparent; }
QMainWindow, QTabWidget::pane { background: #0d111a; }
QFrame#sidebar { background: #111722; border-right: 1px solid #263040; }
QFrame#panel { background: #151d2a; border: 1px solid #2b3648; border-radius: 14px; }
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
QListWidget#libraryList { background: transparent; border: none; outline: none; }
QListWidget#libraryList::item { padding: 14px 12px; margin: 3px 0; border-radius: 9px; }
QListWidget#libraryList::item:selected { background: #293959; color: #ffffff; }
QListWidget#libraryList::item:hover { background: #202c3e; }
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
    """One authoring conversation with its own selected EvidenceForge skill."""

    send_requested = Signal(object, str)
    interrupt_requested = Signal(object)

    def __init__(self, record: ChatRecord) -> None:
        super().__init__()
        self.record = record
        self._stream_item: str | None = None
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        header = QHBoxLayout()
        header.addStretch()
        header.addWidget(QLabel("Authoring skill"))
        self.skill = QComboBox()
        self.skill.setMinimumWidth(190)
        self.skill.addItem(record.skill_name, None)
        header.addWidget(self.skill)
        layout.addLayout(header)
        self.transcript = QTextEdit()
        self.transcript.setReadOnly(True)
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

    def set_busy(self, busy: bool) -> None:
        self.send.setEnabled(not busy)
        self.interrupt.setEnabled(busy)
        self.status.setText("Codex is working…" if busy else "Ready")


class JobCard(QWidget):
    """Live progress and controls for one detached generation."""

    suspend_requested = Signal(object)
    resume_requested = Signal(object)

    def __init__(self, job: GenerationJob) -> None:
        super().__init__()
        self.job = job
        self.setStyleSheet(
            "JobCard { background: #192334; border: 1px solid #35445b; border-radius: 12px; }"
        )
        layout = QVBoxLayout(self)
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
        self.detail.setText(progress.detail)
        if progress.total_hours:
            self.hours.setRange(0, progress.total_hours)
            self.hours.setValue(progress.completed_hours)
            self.hours.setFormat("%v of %m simulated hours · %p%")
        elif self.job.status == "running":
            self.hours.setRange(0, 0)
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
            self.job.status == "stopped" and (self.job.output_root / ".eforge-generation").exists()
        )


class JobsPane(QWidget):
    """Scenario selection and a scrollable set of generation jobs."""

    validate_requested = Signal(str)
    generate_requested = Signal(str, str)
    output_changed = Signal(str)
    suspend_requested = Signal(object)
    resume_requested = Signal(object)

    def __init__(self, output_directory: Path) -> None:
        super().__init__()
        self.cards: dict[str, JobCard] = {}
        layout = QVBoxLayout(self)
        title = QLabel("Generation jobs")
        title.setObjectName("heading")
        layout.addWidget(title)
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
        self.validation = QPlainTextEdit()
        self.validation.setReadOnly(True)
        self.validation.setPlaceholderText("Validation results appear here.")
        self.validation.setFixedHeight(190)
        layout.addWidget(self.validation)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        self.card_layout = QVBoxLayout(container)
        self.card_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        scroll.setWidget(container)
        layout.addWidget(scroll, 1)

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


class MainWindow(QMainWindow):
    """Prototype desktop shell around Codex authoring and CLI jobs."""

    def __init__(self, store: StateStore, state: DesktopState) -> None:
        super().__init__()
        self.store = store
        self.state = state
        self.skills: dict[str, str] = {}
        self.chat_panes: dict[str, ChatPane] = {}
        self.job_progress: dict[str, GenerationProgress] = {}
        self.evaluation_processes: dict[str, QProcess] = {}
        self._closing = False
        self.progress_offsets: dict[str, int] = {}
        self.progress_partial: dict[str, bytes] = {}
        self.bridge = CodexBridge(self)
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
        install_skills = QPushButton("Install skills")
        install_skills.setIcon(icon("add"))
        install_skills.clicked.connect(self._install_skills)
        side.addWidget(install_skills)
        self.workspace_label = QLabel(self.state.workspace.name)
        self.workspace_label.setToolTip(str(self.state.workspace))
        self.workspace_label.setObjectName("muted")
        side.addWidget(self.workspace_label)
        workspace_button = QPushButton("Workspace…")
        workspace_button.setIcon(icon("folder"))
        workspace_button.clicked.connect(self._choose_workspace)
        side.addWidget(workspace_button)
        self.account_label = QLabel("Connecting to Codex…")
        self.account_label.setObjectName("subtle")
        side.addWidget(self.account_label)
        sign_in = QPushButton("Sign in")
        sign_in.setIcon(icon("external"))
        sign_in.clicked.connect(self._sign_in)
        side.addWidget(sign_in)
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
        self.jobs = JobsPane(self.state.output_directory or self.state.workspace / "runs")
        self.jobs.validate_requested.connect(self._validate)
        self.jobs.generate_requested.connect(self._generate)
        self.jobs.output_changed.connect(self._remember_output_directory)
        self.jobs.suspend_requested.connect(self._suspend)
        self.jobs.resume_requested.connect(self._resume)
        self.pages.addWidget(self.jobs)
        for job in self.state.jobs:
            self.jobs.add_job(job)
            self.job_progress[job.id] = GenerationProgress()
        self._refresh_libraries()
        self._navigate(0)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll_jobs)
        self.timer.start(1000)
        self._poll_jobs()
        self.validation_process: QProcess | None = None
        self.bridge.start()

    def _save(self) -> None:
        self.store.save(self.state)

    def _navigate(self, page: int) -> None:
        self.pages.setCurrentIndex(page)
        for index, button in enumerate(self.nav_buttons):
            button.setChecked(index == page)
        if page in (0, 2, 3):
            self._refresh_libraries()

    def _folder_state(self) -> ScenarioFolders:
        key = str(self.state.workspace.resolve())
        return self.state.scenario_folders.setdefault(key, ScenarioFolders())

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
        for job_id in self.evaluation_processes:
            scorecards[job_id] = "Evaluating…"
        self.scenario_library.destination.setText(
            str(self.state.output_directory or self.state.workspace / "runs")
        )
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
        )
        self.state.chats.append(record)
        pane = self._add_chat_pane(record)
        pane.prompt.setPlainText(f"Help me revise the scenario at {item.path}. ")
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
        if job.id in self.evaluation_processes:
            self.statusBar().showMessage("Evaluation is already running", 5000)
            return
        from evidenceforge.desktop.jobs import _eforge_command

        try:
            command = _eforge_command()
        except FileNotFoundError as error:
            QMessageBox.warning(self, "Evaluation could not start", str(error))
            return
        process = QProcess(self)
        process.setWorkingDirectory(str(self.state.workspace))
        process.setProgram(command[0])
        process.setArguments([*command[1:], "eval", str(job.output_root), "--format", "json"])
        process.finished.connect(
            lambda _code, _status, current=job.id: self._evaluation_finished(current)
        )
        process.errorOccurred.connect(
            lambda _error, current=job.id: self._evaluation_start_error(current)
        )
        self.evaluation_processes[job.id] = process
        process.start()
        self._refresh_libraries()

    def _evaluation_finished(self, job_id: str) -> None:
        process = self.evaluation_processes.pop(job_id, None)
        if process is None:
            return
        if self._closing:
            process.deleteLater()
            return
        output = bytes(process.readAllStandardOutput()).decode("utf-8", "replace")
        errors = bytes(process.readAllStandardError()).decode("utf-8", "replace")
        if process.exitCode() == 0:
            try:
                report = QualityReport.model_validate_json(output)
                directory = self.store.directory / "evaluations"
                directory.mkdir(parents=True, exist_ok=True)
                path = directory / f"{job_id}.json"
                temporary = path.with_suffix(".json.tmp")
                temporary.write_text(report.model_dump_json(indent=2), encoding="utf-8")
                os.replace(temporary, path)
                self.statusBar().showMessage("Evaluation scorecard saved", 8000)
            except (OSError, UnicodeError, ValueError) as error:
                QMessageBox.warning(self, "Evaluation report could not be saved", str(error))
        else:
            QMessageBox.warning(
                self,
                "Evaluation failed",
                errors[-3000:] or output[-3000:] or f"eforge eval exited {process.exitCode()}",
            )
        process.deleteLater()
        self._refresh_libraries()

    def _evaluation_start_error(self, job_id: str) -> None:
        process = self.evaluation_processes.get(job_id)
        if process is None or process.error() != QProcess.ProcessError.FailedToStart:
            return
        self.evaluation_processes.pop(job_id)
        QMessageBox.warning(self, "Evaluation could not start", process.errorString())
        process.deleteLater()
        self._refresh_libraries()

    def _author_pack(self, item: LibraryItem) -> None:
        skill = "eforge-industry-pack" if item.kind == "industry" else "eforge-organization-pack"
        record = ChatRecord(id=uuid4().hex, title=item.name, skill_name=skill)
        self.state.chats.append(record)
        pane = self._add_chat_pane(record)
        pane.prompt.setPlainText(f"Help me revise the {item.kind} pack at {item.path}. ")
        self.tabs.setCurrentWidget(pane)
        self._navigate(1)
        self._save()

    def _new_pack_chat(self, kind: str) -> None:
        skill = "eforge-industry-pack" if kind == "industry" else "eforge-organization-pack"
        record = ChatRecord(id=uuid4().hex, title=f"New {kind} pack", skill_name=skill)
        self.state.chats.append(record)
        pane = self._add_chat_pane(record)
        pane.prompt.setPlainText(f"Help me create a new {kind} pack in this workspace. ")
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
        pane.send_requested.connect(self._send_chat)
        pane.interrupt_requested.connect(self._interrupt_chat)
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
        record = ChatRecord(id=uuid4().hex, title=f"Authoring {number}")
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
        if any(process_running(job) for job in self.state.jobs):
            QMessageBox.warning(
                self, "Jobs running", "Wait for active jobs before changing workspace."
            )
            return
        self.state.workspace = Path(selected).resolve()
        self.workspace_label.setText(self.state.workspace.name)
        self.workspace_label.setToolTip(str(self.state.workspace))
        if self.state.output_directory is None:
            self.jobs.output_directory.setText(str(self.state.workspace / "runs"))
        self._save()
        self._refresh_libraries()
        if self.bridge.initialized:
            self._refresh_skills()

    def _codex_ready(self) -> None:
        self.account_label.setText("Checking sign-in…")
        self.bridge.request("account/read", {"refreshToken": False}, self._account_response)
        self._refresh_skills()
        for pane in self.chat_panes.values():
            if pane.record.thread_id:
                self.bridge.request(
                    "thread/resume",
                    {"threadId": pane.record.thread_id},
                    lambda response, p=pane: self._resumed(p, response),
                )

    def _account_response(self, response: dict[str, Any]) -> None:
        if "error" in response:
            self.account_label.setText("Codex sign-in unavailable")
            return
        account = response.get("result", {}).get("account")
        self.account_label.setText("Codex signed in" if account else "Codex signed out")

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
        try:
            installed, _removed = install_chatgpt_skills(
                self.state.workspace / ".agents" / "skills"
            )
        except (OSError, PermissionError, ValueError) as error:
            QMessageBox.warning(self, "Skill installation failed", str(error))
            return
        self.statusBar().showMessage(f"Installed {len(installed)} skill files", 6000)
        if self.bridge.initialized:
            self._refresh_skills()

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

    def _send_chat(self, pane: ChatPane, text: str) -> None:
        if not self.bridge.initialized:
            pane.add_system("Codex is not connected.")
            return
        pane.add_user(text)
        pane.set_busy(True)
        pane.record.skill_name = pane.skill.currentText()
        self._save()
        if pane.record.thread_id is None:
            self.bridge.request(
                "thread/start",
                {"cwd": str(self.state.workspace), "sandbox": "workspace-write"},
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
        self.bridge.request(
            "turn/start",
            {"threadId": pane.record.thread_id, "input": inputs},
            lambda response, p=pane: self._turn_started(p, response),
        )

    def _turn_started(self, pane: ChatPane, response: dict[str, Any]) -> None:
        if "error" in response:
            pane.add_system(_error_text(response))
            pane.set_busy(False)

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
            return
        if method == "skills/changed":
            self._refresh_skills()
            return
        pane = self._pane_for_thread(params.get("threadId"))
        if pane is None:
            return
        if method == "item/agentMessage/delta":
            pane.add_agent_delta(str(params.get("itemId", "message")), str(params.get("delta", "")))
        elif method == "item/started":
            item = params.get("item", {})
            if item.get("type") == "commandExecution":
                pane.add_system(f"Running: {item.get('command', 'command')}")
            elif item.get("type") == "fileChange":
                pane.add_system("Editing scenario files")
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
        self.account_label.setText("Codex disconnected")
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
        self.state.output_directory = self._output_directory(value)
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
            job = start_generation(
                Path(scenario_text).expanduser(),
                self.state.workspace,
                self.store.directory,
                output_parent=destination,
            )
        except (OSError, RuntimeError, ValueError) as error:
            QMessageBox.warning(self, "Generation could not start", str(error))
            return
        self.state.jobs.append(job)
        self.state.output_directory = destination
        self.job_progress[job.id] = GenerationProgress()
        self.jobs.add_job(job)
        self._save()
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
        try:
            resume_generation(job, self.state.workspace, self.store.directory)
        except (OSError, RuntimeError, ValueError) as error:
            QMessageBox.warning(self, "Resume failed", str(error))
            return
        self.job_progress[job.id] = GenerationProgress()
        self.progress_offsets[job.id] = 0
        self.progress_partial[job.id] = b""
        self._save()
        self._poll_jobs()

    def _poll_jobs(self) -> None:
        changed = False
        for job in self.state.jobs:
            changed |= refresh_status(job)
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
        if changed:
            self._save()
            self._refresh_libraries()

    @override
    def closeEvent(self, event: Any) -> None:
        """Leave generation detached; stop in-window evaluations and chat transport."""
        self._closing = True
        self._save()
        for process in list(self.evaluation_processes.values()):
            process.terminate()
            if not process.waitForFinished(1000):
                process.kill()
                process.waitForFinished(1000)
        self.bridge.close()
        super().closeEvent(event)


def main() -> None:
    """Start the local desktop prototype."""
    application = QApplication(sys.argv)
    application.setApplicationName("EvidenceForge")
    application.setStyle("Fusion")
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
