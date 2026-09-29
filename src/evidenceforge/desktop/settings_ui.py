"""Local desktop preferences and job-close behavior controls."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from PySide6.QtCore import Qt, Signal
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
    QVBoxLayout,
    QWidget,
)

from evidenceforge.desktop.icons import icon
from evidenceforge.desktop.state import AppSettings


def _section(title: str, description: str) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(23, 21, 23, 21)
    layout.setSpacing(12)
    heading = QLabel(title)
    heading.setObjectName("heading")
    layout.addWidget(heading)
    caption = QLabel(description)
    caption.setObjectName("muted")
    caption.setWordWrap(True)
    layout.addWidget(caption)
    return frame, layout


def _choice(items: list[tuple[str, str]]) -> QComboBox:
    combo = QComboBox()
    for label, value in items:
        combo.addItem(label, value)
    combo.setMinimumWidth(280)
    combo.setMaximumWidth(440)
    return combo


class SettingsPane(QWidget):
    """Editable, app-local preferences with contextual close options."""

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
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(16)

        workspace_frame, workspace_layout = _section(
            "Workspace", "Choose where authored scenarios live and where new bundles go by default."
        )
        workspace_row = QHBoxLayout()
        self.workspace_value = QLabel(str(workspace))
        self.workspace_value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        workspace_row.addWidget(self.workspace_value, 1)
        choose_workspace = QPushButton("Change…")
        choose_workspace.setIcon(icon("folder"))
        choose_workspace.clicked.connect(self.workspace_requested.emit)
        workspace_row.addWidget(choose_workspace)
        workspace_layout.addLayout(workspace_row)
        workspace_layout.addWidget(QLabel("Default output parent"))
        output_row = QHBoxLayout()
        self.output_value = QLineEdit(str(output))
        self.output_value.editingFinished.connect(
            lambda: self.output_requested.emit(self.output_value.text())
        )
        output_row.addWidget(self.output_value, 1)
        choose_output = QPushButton("Browse…")
        choose_output.setIcon(icon("folder"))
        choose_output.clicked.connect(self._browse_output)
        output_row.addWidget(choose_output)
        workspace_layout.addLayout(output_row)
        content_layout.addWidget(workspace_frame)

        jobs_frame, jobs_layout = _section(
            "Jobs · When I quit",
            "These preferences apply when you quit or close the last window. Only jobs started "
            "by this app are affected.",
        )
        jobs_layout.addWidget(QLabel("Main action"))
        self.close_action = _choice(
            [
                ("Continue background jobs", "continue"),
                ("Checkpoint and pause", "pause"),
                ("Kill app-owned jobs", "kill"),
            ]
        )
        jobs_layout.addWidget(self.close_action)
        self.action_explanation = QLabel()
        self.action_explanation.setObjectName("muted")
        self.action_explanation.setWordWrap(True)
        jobs_layout.addWidget(self.action_explanation)
        self.continue_group = QWidget()
        self.continue_group.setObjectName("inlineControls")
        continue_layout = QVBoxLayout(self.continue_group)
        continue_layout.setContentsMargins(0, 8, 0, 0)
        self.continue_queued = QCheckBox("Start queued generations after I quit")
        continue_layout.addWidget(self.continue_queued)
        continue_layout.addWidget(QLabel("Evaluations after I quit"))
        self.continue_evaluations = _choice(
            [
                ("Continue in the background", "continue"),
                ("Hold and restart when I reopen", "hold"),
                ("Stop; I will restart them manually", "manual"),
            ]
        )
        continue_layout.addWidget(self.continue_evaluations)
        jobs_layout.addWidget(self.continue_group)
        self.pause_group = QWidget()
        self.pause_group.setObjectName("inlineControls")
        pause_layout = QVBoxLayout(self.pause_group)
        pause_layout.setContentsMargins(0, 8, 0, 0)
        pause_layout.addWidget(QLabel("Close timing"))
        self.pause_timing = _choice(
            [
                ("Close after pause requests are handed off", "handoff"),
                ("Wait until generations checkpoint and stop", "wait"),
            ]
        )
        pause_layout.addWidget(self.pause_timing)
        pause_layout.addWidget(QLabel("Evaluations already running"))
        self.pause_evaluations = _choice(
            [
                ("Let them finish", "finish"),
                ("Stop and rerun when I resume", "restart"),
            ]
        )
        pause_layout.addWidget(self.pause_evaluations)
        note = QLabel("Queued work stays paused until you explicitly resume it.")
        note.setObjectName("muted")
        pause_layout.addWidget(note)
        jobs_layout.addWidget(self.pause_group)
        self.kill_group = QWidget()
        self.kill_group.setObjectName("inlineControls")
        kill_layout = QVBoxLayout(self.kill_group)
        kill_layout.setContentsMargins(0, 8, 0, 0)
        kill_layout.addWidget(QLabel("Incomplete bundles"))
        self.kill_files = _choice(
            [
                ("Preserve files and checkpoints", "preserve"),
                ("Delete incomplete app-created bundles", "delete"),
            ]
        )
        kill_layout.addWidget(self.kill_files)
        warning = QLabel("Completed and imported bundles are never deleted by this option.")
        warning.setObjectName("muted")
        kill_layout.addWidget(warning)
        jobs_layout.addWidget(self.kill_group)
        content_layout.addWidget(jobs_frame)

        author_frame, author_layout = _section(
            "Authoring & tools", "Choose the default skill for new chats and check local tools."
        )
        author_layout.addWidget(QLabel("Default authoring skill"))
        self.default_skill = QComboBox()
        self.default_skill.setMaximumWidth(440)
        self.default_skill.addItem(settings.default_authoring_skill)
        author_layout.addWidget(self.default_skill)
        self.account_status = QLabel("Connecting to Codex…")
        self.account_status.setObjectName("muted")
        author_layout.addWidget(self.account_status)
        action_row = QHBoxLayout()
        sign_in = QPushButton("Sign in")
        sign_in.setIcon(icon("external"))
        sign_in.clicked.connect(self.sign_in_requested.emit)
        action_row.addWidget(sign_in)
        install = QPushButton("Install skills")
        install.setIcon(icon("add"))
        install.clicked.connect(self.install_skills_requested.emit)
        action_row.addWidget(install)
        action_row.addStretch()
        author_layout.addLayout(action_row)
        self.codex_path = self._tool_picker(author_layout, "Codex", settings.codex_path)
        self.eforge_path = self._tool_picker(
            author_layout, "EvidenceForge CLI", settings.eforge_path
        )
        content_layout.addWidget(author_frame)
        content_layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

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
            self.default_skill,
        ):
            combo.currentIndexChanged.connect(self._settings_changed)
        self.codex_path.editingFinished.connect(self._settings_changed)
        self.eforge_path.editingFinished.connect(self._settings_changed)
        self._show_close_options()

    def _tool_picker(self, layout: QVBoxLayout, name: str, value: Path | None) -> QLineEdit:
        layout.addWidget(QLabel(name))
        row = QHBoxLayout()
        field = QLineEdit(str(value) if value else "")
        field.setPlaceholderText("Auto-detect on PATH")
        row.addWidget(field, 1)
        browse = QPushButton("Browse…")
        browse.setIcon(icon("folder"))
        browse.clicked.connect(lambda: self._browse_tool(field))
        row.addWidget(browse)
        layout.addLayout(row)
        effective = QLabel(self._effective_tool(name, value))
        effective.setObjectName("muted")
        effective.setWordWrap(True)
        layout.addWidget(effective)
        field.textChanged.connect(
            lambda: effective.setText(self._effective_tool(name, self._path(field)))
        )
        return field

    def _effective_tool(self, name: str, value: Path | None) -> str:
        environment = "EFORGE_DESKTOP_CODEX_BIN" if name == "Codex" else "EFORGE_DESKTOP_EFORGE_BIN"
        configured = os.environ.get(environment)
        if configured:
            return f"Effective path: {configured} (environment override)"
        if value:
            return f"Effective path: {value}"
        if name == "Codex":
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

    def set_workspace(self, workspace: Path, output: Path) -> None:
        """Refresh workspace-scoped controls after a workspace switch."""
        self.workspace_value.setText(str(workspace))
        self.output_value.setText(str(output))

    def set_skills(self, skills: list[str]) -> None:
        """Refresh installed skill choices without losing the selected default."""
        selected = self.settings.default_authoring_skill
        self.default_skill.blockSignals(True)
        self.default_skill.clear()
        for name in sorted(set([selected, *skills])):
            self.default_skill.addItem(name)
        self.default_skill.setCurrentText(selected)
        self.default_skill.blockSignals(False)

    def _show_close_options(self) -> None:
        action = self.close_action.currentData()
        self.action_explanation.setText(
            {
                "continue": "Your jobs keep running without this window. Held work starts when "
                "you reopen the app.",
                "pause": "Queued work waits. Running generations stop at their next safe checkpoint; "
                "resume them explicitly after reopening.",
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
        self.settings.default_authoring_skill = self.default_skill.currentText()
        self.settings.codex_path = self._path(self.codex_path)
        self.settings.eforge_path = self._path(self.eforge_path)
        self._show_close_options()
        self.changed.emit()
