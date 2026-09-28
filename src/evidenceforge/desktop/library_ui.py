"""Library-first Qt views for authored scenarios and reusable packs."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QComboBox,
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

from evidenceforge.desktop.library import LibraryItem, matches_search
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
    folder_create_requested = Signal()
    folder_rename_requested = Signal(str)
    folder_delete_requested = Signal(str)
    folder_assignment_requested = Signal(object, str)

    def __init__(self, title: str, *, scenario_mode: bool) -> None:
        super().__init__()
        self.scenario_mode = scenario_mode
        self.items: list[LibraryItem] = []
        self.jobs: list[GenerationJob] = []
        self.hidden_paths: set[Path] = set()
        self.scorecards: dict[str, str] = {}
        self.folder_names: list[str] = []
        self.folder_assignments: dict[str, str] = {}
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
        self.search.setPlaceholderText(
            "Search names, descriptions, YAML, users, hosts…" if scenario_mode else "Search packs…"
        )
        if scenario_mode:
            self.search.setToolTip(
                "All words must match. Use quotes for a phrase, or name:, description:, "
                "and yaml: to search one field."
            )
        self.search.textChanged.connect(self._populate)
        left_layout.addWidget(self.search)
        folder_row = QHBoxLayout()
        self.folder_filter = QComboBox()
        self.folder_filter.currentIndexChanged.connect(self._populate)
        folder_row.addWidget(self.folder_filter, 1)
        self.new_folder = QPushButton("+ Folder")
        self.new_folder.clicked.connect(self.folder_create_requested.emit)
        folder_row.addWidget(self.new_folder)
        self.rename_folder = QPushButton("Rename")
        self.rename_folder.clicked.connect(self._request_rename_folder)
        folder_row.addWidget(self.rename_folder)
        self.delete_folder = QPushButton("Delete")
        self.delete_folder.clicked.connect(self._request_delete_folder)
        folder_row.addWidget(self.delete_folder)
        self.folder_controls = QWidget()
        self.folder_controls.setObjectName("inlineControls")
        self.folder_controls.setLayout(folder_row)
        self.folder_controls.setVisible(scenario_mode)
        left_layout.addWidget(self.folder_controls)
        filter_row = QHBoxLayout()
        self.version_filter = QComboBox()
        self.version_filter.currentIndexChanged.connect(self._populate)
        filter_row.addWidget(self.version_filter)
        self.run_filter = QComboBox()
        for label, value in (
            ("Any run status", "all"),
            ("Never run", "never"),
            ("Running", "running"),
            ("Completed", "completed"),
            ("Stopped", "stopped"),
        ):
            self.run_filter.addItem(label, value)
        self.run_filter.currentIndexChanged.connect(self._populate)
        filter_row.addWidget(self.run_filter)
        self.filter_controls = QWidget()
        self.filter_controls.setObjectName("inlineControls")
        self.filter_controls.setLayout(filter_row)
        self.filter_controls.setVisible(scenario_mode)
        left_layout.addWidget(self.filter_controls)
        self.show_hidden = QPushButton("Show hidden")
        self.show_hidden.setCheckable(True)
        self.show_hidden.toggled.connect(self._populate)
        left_layout.addWidget(self.show_hidden)
        self.result_count = QLabel("0 items")
        self.result_count.setObjectName("muted")
        left_layout.addWidget(self.result_count)
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
        self.assignment_heading = QLabel("FOLDER")
        self.assignment_heading.setObjectName("eyebrow")
        self.assignment_heading.setVisible(scenario_mode)
        details.addWidget(self.assignment_heading)
        self.folder_assignment = QComboBox()
        self.folder_assignment.currentIndexChanged.connect(self._assignment_changed)
        self.folder_assignment.setVisible(scenario_mode)
        details.addWidget(self.folder_assignment)
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
        folder_names: list[str] | None = None,
        folder_assignments: dict[str, str] | None = None,
    ) -> None:
        """Refresh content while preserving a selected path where possible."""
        selected = self.selected_item()
        self.items = items
        self.hidden_paths = hidden_paths
        self.jobs = jobs
        self.scorecards = scorecards or {}
        self.folder_names = sorted(folder_names or [], key=str.casefold)
        self.folder_assignments = folder_assignments or {}
        self._refresh_filters()
        self._populate()
        if selected is not None:
            self.select_path(selected.path)

    def select_path(self, path: Path) -> None:
        """Select a visible item after a refresh or folder operation."""
        for row in range(self.list.count()):
            if self.list.item(row).data(Qt.ItemDataRole.UserRole) == path:
                self.list.setCurrentRow(row)
                break

    def select_folder(self, name: str) -> None:
        """Show one virtual folder, including the unfiled view."""
        index = self.folder_filter.findData(name)
        if index >= 0:
            self.folder_filter.setCurrentIndex(index)

    def _refresh_filters(self) -> None:
        folder = self.folder_filter.currentData()
        version = self.version_filter.currentData()
        self.folder_filter.blockSignals(True)
        self.folder_filter.clear()
        self.folder_filter.addItem("All folders", None)
        self.folder_filter.addItem("Unfiled", "")
        for name in self.folder_names:
            self.folder_filter.addItem(name, name)
        index = self.folder_filter.findData(folder)
        self.folder_filter.setCurrentIndex(index if index >= 0 else 0)
        self.folder_filter.blockSignals(False)
        self.version_filter.blockSignals(True)
        self.version_filter.clear()
        self.version_filter.addItem("All versions", None)
        for value in sorted({item.version for item in self.items if item.version}):
            self.version_filter.addItem(f"Version {value}", value)
        index = self.version_filter.findData(version)
        self.version_filter.setCurrentIndex(index if index >= 0 else 0)
        self.version_filter.blockSignals(False)
        self._update_folder_actions()

    def selected_item(self) -> LibraryItem | None:
        current = self.list.currentItem()
        if current is None:
            return None
        path = current.data(Qt.ItemDataRole.UserRole)
        return next((item for item in self.items if item.path == path), None)

    def _populate(self) -> None:
        selected = self.selected_item()
        query = self.search.text().strip()
        folder = self.folder_filter.currentData()
        version = self.version_filter.currentData()
        run_filter = self.run_filter.currentData()
        self.list.clear()
        visible = 0
        for item in sorted(
            self.items,
            key=lambda entry: (
                self.folder_assignments.get(str(entry.path), "").casefold(),
                entry.name.casefold(),
            ),
        ):
            if item.path in self.hidden_paths and not self.show_hidden.isChecked():
                continue
            if query and not matches_search(item, query):
                continue
            assigned = self.folder_assignments.get(str(item.path), "")
            if folder is not None and assigned != folder:
                continue
            if version is not None and item.version != version:
                continue
            related = [job for job in self.jobs if job.scenario.resolve() == item.path]
            latest = max(related, key=lambda job: job.started_at) if related else None
            if run_filter == "never" and latest is not None:
                continue
            if run_filter not in {"all", "never"} and (
                latest is None or latest.status != run_filter
            ):
                continue
            location = assigned or "Unfiled"
            label = f"{item.name}\n{location if self.scenario_mode else item.kind.title()}  ·  v{item.version}"
            if item.path in self.hidden_paths:
                label += "  ·  Hidden"
            entry = QListWidgetItem(label)
            entry.setData(Qt.ItemDataRole.UserRole, item.path)
            entry.setToolTip(str(item.path))
            self.list.addItem(entry)
            visible += 1
        if selected is not None:
            for row in range(self.list.count()):
                if self.list.item(row).data(Qt.ItemDataRole.UserRole) == selected.path:
                    self.list.setCurrentRow(row)
                    break
        if self.list.currentRow() < 0 and self.list.count():
            self.list.setCurrentRow(0)
        if not self.list.count():
            self._selection_changed(-1)
        self.result_count.setText(
            f"{visible} {'scenario' if visible == 1 else 'scenarios'}"
            if self.scenario_mode
            else f"{visible} packs"
        )
        self._update_folder_actions()

    def _update_folder_actions(self) -> None:
        folder = self.folder_filter.currentData()
        enabled = isinstance(folder, str) and bool(folder)
        self.rename_folder.setEnabled(enabled)
        self.delete_folder.setEnabled(enabled)

    def _request_rename_folder(self) -> None:
        folder = self.folder_filter.currentData()
        if isinstance(folder, str) and folder:
            self.folder_rename_requested.emit(folder)

    def _request_delete_folder(self) -> None:
        folder = self.folder_filter.currentData()
        if isinstance(folder, str) and folder:
            self.folder_delete_requested.emit(folder)

    def _assignment_changed(self) -> None:
        item = self.selected_item()
        folder = self.folder_assignment.currentData()
        if item is not None and isinstance(folder, str):
            self.folder_assignment_requested.emit(item, folder)

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
            self.folder_assignment.setEnabled(False)
            return
        self.folder_assignment.blockSignals(True)
        self.folder_assignment.clear()
        self.folder_assignment.addItem("Unfiled", "")
        for name in self.folder_names:
            self.folder_assignment.addItem(name, name)
        assigned = self.folder_assignments.get(str(item.path), "")
        index = self.folder_assignment.findData(assigned)
        self.folder_assignment.setCurrentIndex(index if index >= 0 else 0)
        self.folder_assignment.setEnabled(True)
        self.folder_assignment.blockSignals(False)
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
