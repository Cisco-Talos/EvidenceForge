"""Library-first Qt views for authored scenarios and reusable packs."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from evidenceforge.desktop.library import LibraryItem
from evidenceforge.desktop.state import GenerationJob


class LibraryPane(QWidget):
    """Searchable library with an actionable selected-item detail pane."""

    import_requested = Signal()
    create_requested = Signal()
    edit_requested = Signal(object)
    clone_requested = Signal(object)
    hide_requested = Signal(object)
    validate_requested = Signal(object)
    generate_requested = Signal(object)
    jobs_requested = Signal(object)
    evaluate_requested = Signal(object)
    refresh_requested = Signal()

    def __init__(self, title: str, *, scenario_mode: bool) -> None:
        super().__init__()
        self.scenario_mode = scenario_mode
        self.items: list[LibraryItem] = []
        self.jobs: list[GenerationJob] = []
        self.hidden_paths: set[Path] = set()
        self.scorecards: dict[str, str] = {}
        outer = QVBoxLayout(self)
        outer.setContentsMargins(25, 24, 25, 24)
        outer.setSpacing(20)
        top = QHBoxLayout()
        headings = QVBoxLayout()
        eyebrow = QLabel("YOUR WORKSPACE")
        eyebrow.setObjectName("eyebrow")
        headings.addWidget(eyebrow)
        self.title = QLabel(title)
        self.title.setObjectName("pageTitle")
        headings.addWidget(self.title)
        top.addLayout(headings)
        top.addStretch()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh_requested.emit)
        top.addWidget(refresh)
        self.primary = QPushButton("+ New scenario" if scenario_mode else "+ New pack")
        self.primary.setObjectName("primary")
        self.primary.clicked.connect(self.create_requested.emit)
        top.addWidget(self.primary)
        import_button = QPushButton("Import YAML…" if scenario_mode else "Import pack…")
        import_button.clicked.connect(self.import_requested.emit)
        top.addWidget(import_button)
        outer.addLayout(top)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        left = QFrame()
        left.setObjectName("panel")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(17, 17, 17, 17)
        left_layout.setSpacing(12)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search by name or description…")
        self.search.textChanged.connect(self._populate)
        left_layout.addWidget(self.search)
        self.show_hidden = QPushButton("Show hidden")
        self.show_hidden.setCheckable(True)
        self.show_hidden.toggled.connect(self._populate)
        left_layout.addWidget(self.show_hidden)
        self.list = QListWidget()
        self.list.setObjectName("libraryList")
        self.list.currentRowChanged.connect(self._selection_changed)
        left_layout.addWidget(self.list, 1)
        splitter.addWidget(left)

        right = QFrame()
        right.setObjectName("panel")
        details = QVBoxLayout(right)
        details.setContentsMargins(26, 24, 26, 24)
        details.setSpacing(14)
        self.kind_label = QLabel("SELECT AN ITEM")
        self.kind_label.setObjectName("eyebrow")
        details.addWidget(self.kind_label)
        self.name = QLabel("Choose an item from the library")
        self.name.setObjectName("detailTitle")
        self.name.setWordWrap(True)
        details.addWidget(self.name)
        self.description = QLabel("")
        self.description.setObjectName("muted")
        self.description.setWordWrap(True)
        details.addWidget(self.description)
        self.metadata = QLabel("")
        self.metadata.setObjectName("metadata")
        self.metadata.setWordWrap(True)
        details.addWidget(self.metadata)
        self.run_heading = QLabel("LATEST RUN")
        self.run_heading.setObjectName("eyebrow")
        details.addWidget(self.run_heading)
        self.run_status = QLabel("No runs yet")
        details.addWidget(self.run_status)
        self.score_heading = QLabel("SCORECARD")
        self.score_heading.setObjectName("eyebrow")
        details.addWidget(self.score_heading)
        self.score = QLabel("No saved evaluation yet")
        self.score.setObjectName("muted")
        details.addWidget(self.score)
        self.evaluate = QPushButton("Evaluate latest run")
        self.evaluate.clicked.connect(lambda: self._emit_selected(self.evaluate_requested))
        details.addWidget(self.evaluate)
        self.destination_heading = QLabel("OUTPUT DESTINATION")
        self.destination_heading.setObjectName("eyebrow")
        details.addWidget(self.destination_heading)
        self.destination = QLabel("")
        self.destination.setObjectName("muted")
        self.destination.setWordWrap(True)
        details.addWidget(self.destination)
        details.addStretch()
        action_row = QHBoxLayout()
        self.edit = QPushButton("Continue authoring")
        self.edit.setObjectName("primary")
        self.edit.clicked.connect(lambda: self._emit_selected(self.edit_requested))
        action_row.addWidget(self.edit)
        self.validate = QPushButton("Validate")
        self.validate.clicked.connect(lambda: self._emit_selected(self.validate_requested))
        if scenario_mode:
            action_row.addWidget(self.validate)
        self.generate = QPushButton("Generate…")
        self.generate.clicked.connect(lambda: self._emit_selected(self.generate_requested))
        if scenario_mode:
            action_row.addWidget(self.generate)
        details.addLayout(action_row)
        secondary = QHBoxLayout()
        self.clone = QPushButton("Clone")
        self.clone.clicked.connect(lambda: self._emit_selected(self.clone_requested))
        secondary.addWidget(self.clone)
        self.hide = QPushButton("Hide")
        self.hide.clicked.connect(lambda: self._emit_selected(self.hide_requested))
        secondary.addWidget(self.hide)
        self.open_file = QPushButton("Open file")
        self.open_file.clicked.connect(self._open_selected)
        secondary.addWidget(self.open_file)
        secondary.addStretch()
        details.addLayout(secondary)
        splitter.addWidget(right)
        splitter.setSizes([420, 660])
        outer.addWidget(splitter, 1)
        self._selection_changed(-1)

    def set_items(
        self,
        items: list[LibraryItem],
        hidden_paths: set[Path],
        jobs: list[GenerationJob],
        scorecards: dict[str, str] | None = None,
    ) -> None:
        """Refresh content while preserving a selected path where possible."""
        selected = self.selected_item()
        self.items = items
        self.hidden_paths = hidden_paths
        self.jobs = jobs
        self.scorecards = scorecards or {}
        self._populate()
        if selected is not None:
            for row in range(self.list.count()):
                if self.list.item(row).data(Qt.ItemDataRole.UserRole) == selected.path:
                    self.list.setCurrentRow(row)
                    break

    def selected_item(self) -> LibraryItem | None:
        current = self.list.currentItem()
        if current is None:
            return None
        path = current.data(Qt.ItemDataRole.UserRole)
        return next((item for item in self.items if item.path == path), None)

    def _populate(self) -> None:
        selected = self.selected_item()
        term = self.search.text().strip().casefold()
        self.list.clear()
        for item in self.items:
            if item.path in self.hidden_paths and not self.show_hidden.isChecked():
                continue
            if term and term not in f"{item.name} {item.description}".casefold():
                continue
            label = f"{item.name}\n{item.kind.title()}  ·  v{item.version}"
            if item.path in self.hidden_paths:
                label += "  ·  Hidden"
            entry = QListWidgetItem(label)
            entry.setData(Qt.ItemDataRole.UserRole, item.path)
            entry.setToolTip(str(item.path))
            self.list.addItem(entry)
        if selected is not None:
            for row in range(self.list.count()):
                if self.list.item(row).data(Qt.ItemDataRole.UserRole) == selected.path:
                    self.list.setCurrentRow(row)
                    break
        if self.list.currentRow() < 0 and self.list.count():
            self.list.setCurrentRow(0)
        if not self.list.count():
            self._selection_changed(-1)

    def _selection_changed(self, _row: int) -> None:
        item = self.selected_item()
        enabled = item is not None
        for button in (
            self.edit,
            self.validate,
            self.generate,
            self.clone,
            self.hide,
            self.open_file,
        ):
            button.setEnabled(enabled)
        if item is None:
            self.name.setText("Choose an item from the library")
            self.description.setText(
                "Import a YAML file or start a new scenario."
                if self.scenario_mode
                else "Import a pack or author a new one."
            )
            self.metadata.setText("")
            self.run_status.setText("No runs yet")
            self.score.setText("No saved evaluation yet")
            self.evaluate.setEnabled(False)
            return
        self.kind_label.setText(item.kind.upper())
        self.name.setText(item.name)
        self.description.setText(item.description or "No description provided.")
        self.metadata.setText(
            f"Version {item.version}  ·  {item.users} users  ·  {item.systems} systems  ·  "
            f"{item.events} storyline events\n{item.path}"
            if self.scenario_mode
            else f"Version {item.version}\n{item.path}"
        )
        related = sorted(
            (job for job in self.jobs if job.scenario.resolve() == item.path),
            key=lambda job: job.started_at,
            reverse=True,
        )
        self.run_status.setText(
            f"{related[0].status.title()}  ·  {related[0].output_root}"
            if related
            else "No runs yet"
        )
        self.score.setText(
            next(
                (self.scorecards[job.id] for job in related if job.id in self.scorecards),
                "No saved evaluation yet",
            )
        )
        self.evaluate.setEnabled(any(job.status == "completed" for job in related))
        self.hide.setText("Unhide" if item.path in self.hidden_paths else "Hide")
        self.run_heading.setVisible(self.scenario_mode)
        self.run_status.setVisible(self.scenario_mode)
        self.score_heading.setVisible(self.scenario_mode)
        self.score.setVisible(self.scenario_mode)
        self.evaluate.setVisible(self.scenario_mode)
        self.destination_heading.setVisible(self.scenario_mode)
        self.destination.setVisible(self.scenario_mode)

    def _emit_selected(self, signal: Signal) -> None:
        item = self.selected_item()
        if item is not None:
            signal.emit(item)

    def _open_selected(self) -> None:
        item = self.selected_item()
        if item is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(item.path)))

    def choose_import(self) -> Path | None:
        """Choose a YAML file to add by reference to the local library."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Import EvidenceForge YAML", "", "YAML files (*.yaml *.yml)"
        )
        return Path(path).resolve() if path else None
