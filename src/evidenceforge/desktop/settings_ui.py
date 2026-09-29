"""Compact, categorized preferences for the local desktop app."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import override

from PySide6.QtCore import QPointF, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPaintEvent, QPen
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from evidenceforge.desktop.icons import icon
from evidenceforge.desktop.state import AppSettings


def _choice(items: list[tuple[str, str]]) -> QComboBox:
    combo = QComboBox()
    combo.setFixedWidth(360)
    for label, value in items:
        combo.addItem(label, value)
    return combo


def _control_row(title: str, help_text: str, control: QWidget) -> QWidget:
    row = QWidget()
    row.setObjectName("settingsRow")
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 11, 0, 11)
    layout.setSpacing(10)
    label = QLabel(title)
    layout.addWidget(label)
    help_button = QToolButton()
    help_button.setObjectName("settingsHelp")
    help_button.setIcon(icon("help"))
    help_button.setToolTip(help_text)
    help_button.setAccessibleName(f"Help: {title}")
    help_button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    layout.addWidget(help_button)
    layout.addStretch(1)
    layout.addWidget(control)
    return row


def _divider() -> QFrame:
    line = QFrame()
    line.setObjectName("settingsDivider")
    line.setFrameShape(QFrame.Shape.HLine)
    return line


def _section_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("eyebrow")
    return label


class VisibleCheckBox(QCheckBox):
    """Draw a high-contrast tick over the themed checkbox indicator."""

    @override
    def paintEvent(self, event: QPaintEvent) -> None:
        super().paintEvent(event)
        if not self.isChecked():
            return
        center = self.rect().center()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor("#ffffff"), 2.3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawLine(
            QPointF(center.x() - 5, center.y()), QPointF(center.x() - 1, center.y() + 4)
        )
        painter.drawLine(
            QPointF(center.x() - 1, center.y() + 4), QPointF(center.x() + 6, center.y() - 5)
        )
        painter.end()


class SettingsPane(QWidget):
    """Editable preferences with compact rows and a category rail."""

    changed = Signal()
    workspace_requested = Signal()
    output_requested = Signal(str)
    sign_in_requested = Signal()
    install_skills_requested = Signal()

    def __init__(self, settings: AppSettings, workspace: Path, output: Path) -> None:
        super().__init__()
        self.settings = settings
        outer = QVBoxLayout(self)
        outer.setContentsMargins(25, 24, 25, 24)
        title = QLabel("Settings")
        title.setObjectName("pageTitle")
        outer.addWidget(title)

        body = QHBoxLayout()
        body.setSpacing(18)
        rail = QFrame()
        rail.setObjectName("settingsRail")
        rail.setFixedWidth(190)
        rail_layout = QVBoxLayout(rail)
        rail_layout.setContentsMargins(8, 8, 8, 8)
        rail_layout.setSpacing(3)
        self.category_buttons: list[QPushButton] = []
        self.pages = QStackedWidget()
        for index, (label, symbol) in enumerate(
            (("Workspace", "folder"), ("Jobs", "runs"), ("Authoring & tools", "chat"))
        ):
            button = QPushButton(label)
            button.setObjectName("settingsCategory")
            button.setIcon(icon(symbol))
            button.setCheckable(True)
            button.clicked.connect(lambda _checked=False, page=index: self.select_category(page))
            rail_layout.addWidget(button)
            self.category_buttons.append(button)
        rail_layout.addStretch()
        body.addWidget(rail)
        body.addWidget(self.pages, 1)
        outer.addLayout(body, 1)

        workspace_page, workspace_layout = self._page(
            "Workspace", "Where your scenario files live and where new bundles go."
        )
        workspace_control = QWidget()
        workspace_control.setObjectName("inlineControls")
        workspace_row = QHBoxLayout(workspace_control)
        workspace_row.setContentsMargins(0, 0, 0, 0)
        self.workspace_value = QLineEdit(str(workspace))
        self.workspace_value.setReadOnly(True)
        self.workspace_value.setFixedWidth(360)
        workspace_row.addWidget(self.workspace_value)
        choose_workspace = QPushButton("Change…")
        choose_workspace.setIcon(icon("folder"))
        choose_workspace.clicked.connect(self.workspace_requested.emit)
        workspace_row.addWidget(choose_workspace)
        workspace_layout.addWidget(
            _control_row(
                "Workspace folder",
                "The project root containing your authored scenarios and local packs. "
                "Changing it does not move existing files.",
                workspace_control,
            )
        )
        workspace_layout.addWidget(_divider())
        output_control = QWidget()
        output_control.setObjectName("inlineControls")
        output_row = QHBoxLayout(output_control)
        output_row.setContentsMargins(0, 0, 0, 0)
        self.output_value = QLineEdit(str(output))
        self.output_value.setFixedWidth(360)
        self.output_value.editingFinished.connect(
            lambda: self.output_requested.emit(self.output_value.text())
        )
        output_row.addWidget(self.output_value)
        choose_output = QPushButton("Browse…")
        choose_output.setIcon(icon("folder"))
        choose_output.clicked.connect(self._browse_output)
        output_row.addWidget(choose_output)
        workspace_layout.addWidget(
            _control_row(
                "Default output parent",
                "New generation bundles go under this folder unless you choose another "
                "destination for a run. The app remembers one default per workspace.",
                output_control,
            )
        )
        workspace_layout.addStretch()
        self.pages.addWidget(workspace_page)

        jobs_page, jobs_layout = self._page(
            "Jobs", "Choose what happens to jobs launched by this app when you quit."
        )
        jobs_layout.addWidget(_section_label("WHEN I QUIT"))
        self.close_action = _choice(
            [
                ("Continue background jobs", "continue"),
                ("Checkpoint and pause", "pause"),
                ("Kill app-owned jobs", "kill"),
            ]
        )
        jobs_layout.addWidget(
            _control_row(
                "Main action",
                "Applies on the next quit. It affects only jobs started by this GUI, "
                "never an unrelated terminal eforge process.",
                self.close_action,
            )
        )
        self.action_explanation = QLabel()
        self.action_explanation.setObjectName("muted")
        self.action_explanation.setWordWrap(True)
        jobs_layout.addWidget(self.action_explanation)
        jobs_layout.addWidget(_divider())

        self.continue_group = QWidget()
        self.continue_group.setObjectName("inlineControls")
        continue_layout = QVBoxLayout(self.continue_group)
        continue_layout.setContentsMargins(0, 0, 0, 0)
        continue_layout.setSpacing(0)
        continue_layout.addWidget(_section_label("WHEN CONTINUING"))
        self.continue_queued = VisibleCheckBox()
        continue_layout.addWidget(
            _control_row(
                "Start queued generations",
                "If enabled, generations still queued when you quit can start while "
                "the app is closed. Otherwise they wait until it reopens.",
                self.continue_queued,
            )
        )
        continue_layout.addWidget(_divider())
        self.continue_evaluations = _choice(
            [
                ("Continue in the background", "continue"),
                ("Hold and restart on reopen", "hold"),
                ("Stop; restart manually", "manual"),
            ]
        )
        continue_layout.addWidget(
            _control_row(
                "Evaluations",
                "Continue runs them after quit. Hold stops and restarts them on reopen. "
                "Manual stops them until you request another evaluation.",
                self.continue_evaluations,
            )
        )
        jobs_layout.addWidget(self.continue_group)

        self.pause_group = QWidget()
        self.pause_group.setObjectName("inlineControls")
        pause_layout = QVBoxLayout(self.pause_group)
        pause_layout.setContentsMargins(0, 0, 0, 0)
        pause_layout.setSpacing(0)
        pause_layout.addWidget(_section_label("WHEN PAUSING"))
        self.pause_timing = _choice(
            [
                ("Close after handoff", "handoff"),
                ("Wait for checkpoints", "wait"),
            ]
        )
        pause_layout.addWidget(
            _control_row(
                "Close timing",
                "Close after the controller receives durable pause requests, or keep "
                "the window open until running generations checkpoint and stop.",
                self.pause_timing,
            )
        )
        pause_layout.addWidget(_divider())
        self.pause_evaluations = _choice(
            [("Let them finish", "finish"), ("Stop and rerun on resume", "restart")]
        )
        pause_layout.addWidget(
            _control_row(
                "Active evaluations",
                "A running evaluation can finish after quit, or stop and run again "
                "when you explicitly resume paused work.",
                self.pause_evaluations,
            )
        )
        jobs_layout.addWidget(self.pause_group)

        self.kill_group = QWidget()
        self.kill_group.setObjectName("inlineControls")
        kill_layout = QVBoxLayout(self.kill_group)
        kill_layout.setContentsMargins(0, 0, 0, 0)
        kill_layout.setSpacing(0)
        kill_layout.addWidget(_section_label("WHEN STOPPING"))
        self.kill_files = _choice(
            [
                ("Preserve files and checkpoints", "preserve"),
                ("Delete incomplete app-created bundles", "delete"),
            ]
        )
        kill_layout.addWidget(
            _control_row(
                "Incomplete bundles",
                "Preserve partial files for inspection or recovery. Deletion requires "
                "confirmation and never removes completed or imported bundles.",
                self.kill_files,
            )
        )
        jobs_layout.addWidget(self.kill_group)
        jobs_layout.addStretch()
        self.pages.addWidget(jobs_page)

        tools_page, tools_layout = self._page(
            "Authoring & tools", "Codex account and local executables used by this app."
        )
        self.account_status = QLabel("Connecting to Codex…")
        self.account_status.setObjectName("muted")
        tools_layout.addWidget(
            _control_row(
                "Codex account",
                "The local Codex CLI account used for interactive chats and installed skills.",
                self.account_status,
            )
        )
        tools_layout.addWidget(_divider())
        account_actions = QWidget()
        account_actions.setObjectName("inlineControls")
        action_row = QHBoxLayout(account_actions)
        action_row.setContentsMargins(0, 0, 0, 0)
        sign_in = QPushButton("Sign in")
        sign_in.setIcon(icon("external"))
        sign_in.clicked.connect(self.sign_in_requested.emit)
        action_row.addWidget(sign_in)
        install = QPushButton("Install skills")
        install.setIcon(icon("add"))
        install.clicked.connect(self.install_skills_requested.emit)
        action_row.addWidget(install)
        tools_layout.addWidget(
            _control_row(
                "Account actions",
                "Sign in to Codex or install the EvidenceForge skills for chat workflows.",
                account_actions,
            )
        )
        tools_layout.addWidget(_divider())
        self.codex_path = self._tool_picker(
            tools_layout,
            "Codex executable",
            "Optional path to the Codex CLI. Leave blank to detect codex on PATH.",
            settings.codex_path,
        )
        tools_layout.addWidget(_divider())
        self.eforge_path = self._tool_picker(
            tools_layout,
            "EvidenceForge CLI",
            "Optional path to eforge. Leave blank to use this Python environment's CLI.",
            settings.eforge_path,
        )
        tools_layout.addStretch()
        self.pages.addWidget(tools_page)

        self._set_choice(self.close_action, settings.close_action)
        self.continue_queued.setChecked(settings.continue_queued_generations)
        self._set_choice(self.continue_evaluations, settings.continue_evaluations)
        self._set_choice(self.pause_timing, settings.pause_close_timing)
        self._set_choice(self.pause_evaluations, settings.pause_evaluations)
        self._set_choice(self.kill_files, settings.kill_incomplete_bundles)
        self.close_action.currentIndexChanged.connect(self._settings_changed)
        self.continue_queued.toggled.connect(self._settings_changed)
        for combo in (
            self.continue_evaluations,
            self.pause_timing,
            self.pause_evaluations,
            self.kill_files,
        ):
            combo.currentIndexChanged.connect(self._settings_changed)
        self.codex_path.editingFinished.connect(self._settings_changed)
        self.eforge_path.editingFinished.connect(self._settings_changed)
        self._show_close_options()
        self.select_category(0)

    def _page(self, title: str, description: str) -> tuple[QScrollArea, QVBoxLayout]:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        surface = QFrame()
        surface.setObjectName("settingsSurface")
        layout = QVBoxLayout(surface)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(4)
        heading = QLabel(title)
        heading.setObjectName("heading")
        layout.addWidget(heading)
        caption = QLabel(description)
        caption.setObjectName("muted")
        caption.setWordWrap(True)
        layout.addWidget(caption)
        layout.addSpacing(12)
        content_layout.addWidget(surface)
        content_layout.addStretch()
        scroll.setWidget(content)
        return scroll, layout

    def _tool_picker(
        self, layout: QVBoxLayout, name: str, help_text: str, value: Path | None
    ) -> QLineEdit:
        control = QWidget()
        control.setObjectName("inlineControls")
        row = QHBoxLayout(control)
        row.setContentsMargins(0, 0, 0, 0)
        field = QLineEdit(str(value) if value else "")
        field.setFixedWidth(360)
        field.setPlaceholderText("Auto-detect")
        row.addWidget(field)
        browse = QPushButton("Browse…")
        browse.setIcon(icon("folder"))
        browse.clicked.connect(lambda: self._browse_tool(field))
        row.addWidget(browse)
        layout.addWidget(_control_row(name, help_text, control))
        effective = QLabel(self._effective_tool(name, value))
        effective.setObjectName("settingsHint")
        effective.setWordWrap(True)
        layout.addWidget(effective)
        field.textChanged.connect(
            lambda: effective.setText(self._effective_tool(name, self._path(field)))
        )
        return field

    def _effective_tool(self, name: str, value: Path | None) -> str:
        environment = (
            "EFORGE_DESKTOP_CODEX_BIN"
            if name == "Codex executable"
            else "EFORGE_DESKTOP_EFORGE_BIN"
        )
        configured = os.environ.get(environment)
        if configured:
            return f"Effective path: {configured} (environment override)"
        if value:
            return f"Effective path: {value}"
        if name == "Codex executable":
            return f"Detected: {shutil.which('codex') or 'not found'}"
        return f"Detected: {sys.executable} -m evidenceforge"

    @staticmethod
    def _path(field: QLineEdit) -> Path | None:
        value = field.text().strip()
        return Path(value).expanduser().resolve() if value else None

    @staticmethod
    def _set_choice(combo: QComboBox, value: str) -> None:
        index = combo.findData(value)
        combo.setCurrentIndex(index if index >= 0 else 0)

    def _browse_output(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self, "Default output parent", self.output_value.text()
        )
        if selected:
            self.output_value.setText(selected)
            self.output_requested.emit(selected)

    def _browse_tool(self, field: QLineEdit) -> None:
        selected, _ = QFileDialog.getOpenFileName(self, "Choose executable", field.text())
        if selected:
            field.setText(selected)
            self._settings_changed()

    def select_category(self, index: int) -> None:
        """Show a settings category and update its navigation state."""
        self.pages.setCurrentIndex(index)
        for position, button in enumerate(self.category_buttons):
            button.setChecked(position == index)

    def set_workspace(self, workspace: Path, output: Path) -> None:
        """Refresh workspace-scoped controls after a workspace switch."""
        self.workspace_value.setText(str(workspace))
        self.output_value.setText(str(output))

    def _show_close_options(self) -> None:
        action = self.close_action.currentData()
        self.action_explanation.setText(
            {
                "continue": "Your jobs can continue without this window.",
                "pause": "Queued work waits; active generations stop at their next checkpoint.",
                "kill": "Queued jobs are canceled and active app-owned processes are stopped.",
            }[action]
        )
        self.continue_group.setVisible(action == "continue")
        self.pause_group.setVisible(action == "pause")
        self.kill_group.setVisible(action == "kill")

    def _settings_changed(self, *_args: object) -> None:
        self.settings.close_action = self.close_action.currentData()
        self.settings.continue_queued_generations = self.continue_queued.isChecked()
        self.settings.continue_evaluations = self.continue_evaluations.currentData()
        self.settings.pause_close_timing = self.pause_timing.currentData()
        self.settings.pause_evaluations = self.pause_evaluations.currentData()
        self.settings.kill_incomplete_bundles = self.kill_files.currentData()
        self.settings.codex_path = self._path(self.codex_path)
        self.settings.eforge_path = self._path(self.eforge_path)
        self._show_close_options()
        self.changed.emit()
