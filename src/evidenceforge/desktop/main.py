"""Launch the optional EvidenceForge desktop prototype."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any, override
from uuid import uuid4

from PySide6.QtCore import QProcess, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from evidenceforge.cli.install_skills import install_chatgpt_skills
from evidenceforge.desktop.app_server import CodexBridge
from evidenceforge.desktop.jobs import (
    process_running,
    refresh_status,
    request_suspension,
    resume_generation,
    start_generation,
)
from evidenceforge.desktop.progress import GenerationProgress, parse_progress_line
from evidenceforge.desktop.state import (
    ChatRecord,
    DesktopState,
    GenerationJob,
    StateStore,
    state_directory,
)

_STYLE = """
QWidget { background: #10141d; color: #e8edf6; font-size: 13px; }
QMainWindow, QTabWidget::pane { background: #10141d; }
QLabel#heading { font-size: 20px; font-weight: 700; color: #f3f6fb; }
QLabel#subtle { color: #93a2b7; }
QPushButton { background: #273449; border: 1px solid #3b4b62; border-radius: 8px;
              padding: 8px 12px; font-weight: 600; }
QPushButton:hover { background: #344760; }
QPushButton:disabled { color: #778399; background: #1c2635; }
QPushButton#primary { background: #3477c4; border-color: #448ddd; color: white; }
QPushButton#primary:hover { background: #4187d8; }
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox {
    background: #171f2c; border: 1px solid #35445b; border-radius: 8px;
    padding: 8px; selection-background-color: #3477c4;
}
QTabBar::tab { background: #1a2432; border: 1px solid #35445b; border-bottom: none;
               padding: 10px 16px; margin-right: 3px; border-top-left-radius: 8px;
               border-top-right-radius: 8px; }
QTabBar::tab:selected { background: #283a54; color: #ffffff; }
QProgressBar { background: #1a2432; border: 1px solid #35445b; border-radius: 6px;
               text-align: center; height: 18px; }
QProgressBar::chunk { background: #4a9beb; border-radius: 5px; }
QScrollArea { border: none; }
"""


def _error_text(message: dict[str, Any]) -> str:
    error = message.get("error")
    if isinstance(error, dict):
        return str(error.get("message", error))
    return str(error or "Unknown Codex error")


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
        heading = QLabel(record.title)
        heading.setObjectName("heading")
        header.addWidget(heading)
        header.addStretch()
        header.addWidget(QLabel("Skill"))
        self.skill = QComboBox()
        self.skill.setMinimumWidth(190)
        self.skill.addItem(record.skill_name, None)
        header.addWidget(self.skill)
        layout.addLayout(header)
        self.transcript = QTextEdit()
        self.transcript.setReadOnly(True)
        self.transcript.setPlaceholderText("Describe the scenario you want to create or revise.")
        layout.addWidget(self.transcript, 1)
        self.prompt = QPlainTextEdit()
        self.prompt.setPlaceholderText("Ask EvidenceForge…")
        self.prompt.setFixedHeight(90)
        layout.addWidget(self.prompt)
        controls = QHBoxLayout()
        self.status = QLabel("Ready")
        self.status.setObjectName("subtle")
        controls.addWidget(self.status)
        controls.addStretch()
        self.interrupt = QPushButton("Interrupt")
        self.interrupt.setEnabled(False)
        self.interrupt.clicked.connect(lambda: self.interrupt_requested.emit(self))
        controls.addWidget(self.interrupt)
        self.send = QPushButton("Send")
        self.send.setObjectName("primary")
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
        open_output.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(job.output_root)))
        )
        controls.addWidget(open_output)
        open_log = QPushButton("Open Log")
        open_log.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(job.log_file)))
        )
        controls.addWidget(open_log)
        controls.addStretch()
        self.suspend = QPushButton("Suspend")
        self.suspend.clicked.connect(lambda: self.suspend_requested.emit(self.job))
        controls.addWidget(self.suspend)
        self.resume = QPushButton("Resume")
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
    generate_requested = Signal(str)
    suspend_requested = Signal(object)
    resume_requested = Signal(object)

    def __init__(self) -> None:
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
        browse.clicked.connect(self._browse)
        input_row.addWidget(browse)
        validate = QPushButton("Validate")
        validate.clicked.connect(lambda: self.validate_requested.emit(self.scenario.text()))
        input_row.addWidget(validate)
        generate = QPushButton("Generate")
        generate.setObjectName("primary")
        generate.clicked.connect(lambda: self.generate_requested.emit(self.scenario.text()))
        input_row.addWidget(generate)
        layout.addLayout(input_row)
        self.validation = QPlainTextEdit()
        self.validation.setReadOnly(True)
        self.validation.setPlaceholderText("Validation results appear here.")
        self.validation.setFixedHeight(110)
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
        self.progress_offsets: dict[str, int] = {}
        self.progress_partial: dict[str, bytes] = {}
        self.bridge = CodexBridge(self)
        self.bridge.ready.connect(self._codex_ready)
        self.bridge.event.connect(self._codex_event)
        self.bridge.server_request.connect(self._server_request)
        self.bridge.failed.connect(self._codex_failed)
        self.setWindowTitle("EvidenceForge")
        self.resize(1120, 820)
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(20, 18, 20, 18)
        top = QHBoxLayout()
        brand = QLabel("EvidenceForge")
        brand.setObjectName("heading")
        top.addWidget(brand)
        top.addStretch()
        self.workspace_label = QLabel(self.state.workspace.name)
        self.workspace_label.setToolTip(str(self.state.workspace))
        top.addWidget(self.workspace_label)
        workspace_button = QPushButton("Workspace…")
        workspace_button.clicked.connect(self._choose_workspace)
        top.addWidget(workspace_button)
        self.account_label = QLabel("Connecting to Codex…")
        self.account_label.setObjectName("subtle")
        top.addWidget(self.account_label)
        sign_in = QPushButton("Sign in")
        sign_in.clicked.connect(self._sign_in)
        top.addWidget(sign_in)
        layout.addLayout(top)
        controls = QHBoxLayout()
        new_chat = QPushButton("New authoring tab")
        new_chat.clicked.connect(self._new_chat)
        controls.addWidget(new_chat)
        install_skills = QPushButton("Install EvidenceForge skills")
        install_skills.clicked.connect(self._install_skills)
        controls.addWidget(install_skills)
        controls.addStretch()
        layout.addLayout(controls)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        for record in self.state.chats:
            self._add_chat_pane(record)
        self.jobs = JobsPane()
        self.jobs.validate_requested.connect(self._validate)
        self.jobs.generate_requested.connect(self._generate)
        self.jobs.suspend_requested.connect(self._suspend)
        self.jobs.resume_requested.connect(self._resume)
        self.tabs.addTab(self.jobs, "Jobs")
        for job in self.state.jobs:
            self.jobs.add_job(job)
            self.job_progress[job.id] = GenerationProgress()
        if not self.state.chats:
            self._new_chat()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll_jobs)
        self.timer.start(1000)
        self._poll_jobs()
        self.validation_process: QProcess | None = None
        self.bridge.start()

    def _save(self) -> None:
        self.store.save(self.state)

    def _add_chat_pane(self, record: ChatRecord) -> ChatPane:
        pane = ChatPane(record)
        pane.set_skills(self.skills)
        pane.send_requested.connect(self._send_chat)
        pane.interrupt_requested.connect(self._interrupt_chat)
        self.chat_panes[record.id] = pane
        self.tabs.addTab(pane, record.title)
        return pane

    def _new_chat(self) -> None:
        number = len(self.state.chats) + 1
        record = ChatRecord(id=uuid4().hex, title=f"Authoring {number}")
        self.state.chats.append(record)
        pane = self._add_chat_pane(record)
        self.tabs.setCurrentWidget(pane)
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
        self._save()
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
        self.jobs.validation.setPlainText(output or errors or "Validation produced no output")
        self.validation_process = None
        process.deleteLater()

    def _generate(self, scenario_text: str) -> None:
        try:
            job = start_generation(
                Path(scenario_text).expanduser(), self.state.workspace, self.store.directory
            )
        except (OSError, RuntimeError, ValueError) as error:
            QMessageBox.warning(self, "Generation could not start", str(error))
            return
        self.state.jobs.append(job)
        self.job_progress[job.id] = GenerationProgress()
        self.jobs.add_job(job)
        self._save()
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

    @override
    def closeEvent(self, event: Any) -> None:
        """Leave detached generation jobs running while closing chat transport."""
        self._save()
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
