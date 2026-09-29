"""Library-first Qt views for authored scenarios and reusable packs."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import override

from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPoint, QSize, Qt, QUrl, Signal
from PySide6.QtGui import (
    QAccessible,
    QActionGroup,
    QColor,
    QDesktopServices,
    QDropEvent,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from evidenceforge.desktop.icons import icon
from evidenceforge.desktop.library import LibraryItem, matches_search, search_snippet
from evidenceforge.desktop.state import GenerationJob, LibraryView


class ScenarioTree(QTreeWidget):
    """Scenario list with folder drop targets."""

    move_requested = Signal(object, str)

    def __init__(self) -> None:
        super().__init__()
        self.setColumnCount(2)
        self.setHeaderHidden(True)
        self.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.header().setStretchLastSection(False)
        self.header().resizeSection(1, 38)
        self.setRootIsDecorated(True)
        self.setIndentation(18)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)

    @override
    def dropEvent(self, event: QDropEvent) -> None:
        """Move one scenario to a virtual folder without touching its YAML file."""
        source = self.currentItem()
        if (
            event.source() is not self
            or source is None
            or source.data(0, Qt.ItemDataRole.UserRole) != "scenario"
        ):
            event.ignore()
            return
        target = self.itemAt(event.position().toPoint())
        if target is None:
            event.ignore()
            return
        folder_item = (
            target if target.data(0, Qt.ItemDataRole.UserRole) == "folder" else target.parent()
        )
        if folder_item is None:
            event.ignore()
            return
        path = source.data(0, Qt.ItemDataRole.UserRole + 1)
        folder = folder_item.data(0, Qt.ItemDataRole.UserRole + 1)
        if isinstance(path, Path) and isinstance(folder, str):
            self.move_requested.emit(path, folder)
            event.acceptProposedAction()
        else:
            event.ignore()


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
    view_changed = Signal(object)
    view_save_requested = Signal(object)
    view_rename_requested = Signal(str, str)
    view_delete_requested = Signal(str)

    def __init__(self, title: str, *, scenario_mode: bool) -> None:
        super().__init__()
        self.scenario_mode = scenario_mode
        self.items: list[LibraryItem] = []
        self.jobs: list[GenerationJob] = []
        self._latest_jobs: dict[Path, GenerationJob] = {}
        self.hidden_paths: set[Path] = set()
        self.scorecards: dict[str, str] = {}
        self.folder_names: list[str] = []
        self.folder_assignments: dict[str, str] = {}
        self.run_filter_value = "all"
        self.version_filter_value: str | None = None
        self.show_hidden_value = False
        self.saved_views: list[LibraryView] = []
        self.active_view_name = ""
        self._populating = False
        self._applying_view = False
        self._last_selected_folder: str | None = None
        self._tree_items: dict[Path, QTreeWidgetItem] = {}
        self._folder_items: dict[str, QTreeWidgetItem] = {}
        self._all_tree_items: dict[Path, QTreeWidgetItem] = {}
        self._all_folder_items: dict[str, QTreeWidgetItem] = {}
        self._tree_signature: tuple[object, ...] | None = None
        self._expanded_before_search: set[str] | None = None
        self._recent_paths: tuple[Path, ...] = ()
        self._programmatic_highlight: QTreeWidgetItem | None = None
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
        refresh = QToolButton()
        refresh.setIcon(icon("refresh"))
        refresh.setToolTip("Refresh library")
        refresh.setAccessibleName("Refresh library")
        refresh.setObjectName("iconAction")
        refresh.clicked.connect(self.refresh_requested.emit)
        top.addWidget(refresh)
        self.primary = QPushButton("New scenario" if scenario_mode else "New pack")
        self.primary.setObjectName("primary")
        self.primary.setIcon(icon("add", color="#ffffff"))
        self.primary.clicked.connect(self.create_requested.emit)
        top.addWidget(self.primary)
        import_button = QToolButton()
        import_button.setIcon(icon("import"))
        import_button.setToolTip("Import YAML" if scenario_mode else "Import pack")
        import_button.setAccessibleName(import_button.toolTip())
        import_button.setObjectName("iconAction")
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
        self.search.textChanged.connect(self._search_changed)
        search_row = QHBoxLayout()
        search_row.addWidget(self.search, 1)
        self.views_button = QToolButton()
        self.views_button.setObjectName("filterButton")
        self.views_button.setText("Views")
        self.views_button.setToolTip("Open or save a scenario view")
        self.views_button.setAccessibleName("Scenario views")
        self.views_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.views_menu = QMenu(self.views_button)
        self.views_menu.aboutToShow.connect(self._build_views_menu)
        self.views_button.setMenu(self.views_menu)
        self.views_button.setVisible(scenario_mode)
        self.filter_button = QToolButton()
        self.filter_button.setObjectName("filterButton")
        self.filter_button.setIcon(icon("filter"))
        self.filter_button.setText("Filters")
        self.filter_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.filter_button.setToolTip("Filter the library")
        self.filter_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.filter_menu = QMenu(self.filter_button)
        self.filter_menu.aboutToShow.connect(self._build_filter_menu)
        self.filter_button.setMenu(self.filter_menu)
        search_row.addWidget(self.filter_button)
        left_layout.addLayout(search_row)
        list_header = QHBoxLayout()
        label = QLabel("SCENARIOS" if scenario_mode else "PACKS")
        label.setObjectName("eyebrow")
        list_header.addWidget(label)
        list_header.addStretch()
        if scenario_mode:
            list_header.addWidget(self.views_button)
        self.result_count = QLabel("0 items")
        self.result_count.setObjectName("muted")
        list_header.addWidget(self.result_count)
        self.new_folder = QToolButton()
        self.new_folder.setIcon(icon("add"))
        self.new_folder.setObjectName("iconAction")
        self.new_folder.setToolTip("Create folder")
        self.new_folder.setAccessibleName("Create folder")
        self.new_folder.clicked.connect(self.folder_create_requested.emit)
        self.new_folder.setVisible(scenario_mode)
        list_header.addWidget(self.new_folder)
        left_layout.addLayout(list_header)
        self.tree = ScenarioTree()
        self.tree.setObjectName("libraryTree")
        self.tree.currentItemChanged.connect(self._selection_changed)
        self.tree.itemSelectionChanged.connect(self._clear_programmatic_highlight)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._open_context_menu)
        self.tree.move_requested.connect(self._move_path)
        left_layout.addWidget(self.tree, 1)
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
        self.search_match = QLabel("")
        self.search_match.setObjectName("settingsHint")
        self.search_match.setWordWrap(True)
        details.addWidget(self.search_match)
        self.metadata = QLabel("")
        self.metadata.setObjectName("metadata")
        self.metadata.setWordWrap(True)
        details.addWidget(self.metadata)
        self.folder_recent_heading = QLabel("RECENT SCENARIOS")
        self.folder_recent_heading.setObjectName("eyebrow")
        self.folder_recent_heading.setVisible(False)
        details.addWidget(self.folder_recent_heading)
        self.folder_recent = QListWidget()
        self.folder_recent.setObjectName("folderRecent")
        self.folder_recent.setMaximumHeight(210)
        self.folder_recent.setVisible(False)
        self.folder_recent.itemClicked.connect(self._open_folder_recent)
        details.addWidget(self.folder_recent)
        self.assignment_heading = QLabel("FOLDER")
        self.assignment_heading.setObjectName("eyebrow")
        self.assignment_heading.setVisible(scenario_mode)
        details.addWidget(self.assignment_heading)
        self.folder_value = QLabel("Unfiled")
        self.folder_value.setObjectName("muted")
        self.folder_value.setVisible(scenario_mode)
        details.addWidget(self.folder_value)
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
        self.evaluate.setIcon(icon("runs"))
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
        self.action_controls = QWidget()
        self.action_controls.setObjectName("inlineControls")
        action_row = QHBoxLayout(self.action_controls)
        action_row.setContentsMargins(0, 0, 0, 0)
        self.edit = QPushButton("Continue authoring")
        self.edit.setObjectName("primary")
        self.edit.setIcon(icon("edit", color="#ffffff"))
        self.edit.clicked.connect(lambda: self._emit_selected(self.edit_requested))
        action_row.addWidget(self.edit)
        self.validate = QPushButton("Validate")
        self.validate.setIcon(icon("check"))
        self.validate.clicked.connect(lambda: self._emit_selected(self.validate_requested))
        if scenario_mode:
            action_row.addWidget(self.validate)
        self.generate = QPushButton("Generate…")
        self.generate.setIcon(icon("play"))
        self.generate.clicked.connect(lambda: self._emit_selected(self.generate_requested))
        if scenario_mode:
            action_row.addWidget(self.generate)
        details.addWidget(self.action_controls)
        self.secondary_controls = QWidget()
        self.secondary_controls.setObjectName("inlineControls")
        secondary = QHBoxLayout(self.secondary_controls)
        secondary.setContentsMargins(0, 0, 0, 0)
        self.clone = QToolButton()
        self.clone.setIcon(icon("copy"))
        self.clone.setObjectName("iconAction")
        self.clone.setToolTip("Clone")
        self.clone.setAccessibleName("Clone")
        self.clone.clicked.connect(lambda: self._emit_selected(self.clone_requested))
        secondary.addWidget(self.clone)
        self.hide = QToolButton()
        self.hide.setIcon(icon("hide"))
        self.hide.setObjectName("iconAction")
        self.hide.setToolTip("Hide")
        self.hide.setAccessibleName("Hide")
        self.hide.clicked.connect(lambda: self._emit_selected(self.hide_requested))
        secondary.addWidget(self.hide)
        self.open_file = QToolButton()
        self.open_file.setIcon(icon("external"))
        self.open_file.setObjectName("iconAction")
        self.open_file.setToolTip("Open YAML file")
        self.open_file.setAccessibleName("Open YAML file")
        self.open_file.clicked.connect(self._open_selected)
        secondary.addWidget(self.open_file)
        secondary.addStretch()
        details.addWidget(self.secondary_controls)
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
        self.items = items
        self.hidden_paths = hidden_paths
        self.jobs = jobs
        self._latest_jobs.clear()
        for job in jobs:
            path = job.scenario.resolve()
            current = self._latest_jobs.get(path)
            if current is None or job.started_at > current.started_at:
                self._latest_jobs[path] = job
        self.scorecards = scorecards or {}
        self.folder_names = sorted(folder_names or [], key=str.casefold)
        self.folder_assignments = {
            str(Path(path).expanduser().resolve()): folder
            for path, folder in (folder_assignments or {}).items()
        }
        self._populate()

    def set_saved_views(self, views: list[LibraryView]) -> None:
        """Replace the workspace's named views without changing the current query."""
        self.saved_views = [view.model_copy(deep=True) for view in views]

    def current_view(self) -> LibraryView:
        """Capture the current search, filters, and folder selection."""
        current = self.tree.currentItem()
        folder = (
            self.selected_folder_name()
            if current is not None and current.data(0, Qt.ItemDataRole.UserRole) == "folder"
            else None
        )
        return LibraryView(
            name=self.active_view_name,
            search=self.search.text(),
            run_filter=self.run_filter_value,
            version_filter=self.version_filter_value,
            show_hidden=self.show_hidden_value,
            selected_folder=folder,
        )

    def apply_view(self, view: LibraryView, *, notify: bool = True) -> None:
        """Apply a saved query and select its folder overview when available."""
        self._applying_view = True
        self.search.blockSignals(True)
        self.search.setText(view.search)
        self.search.blockSignals(False)
        self.run_filter_value = view.run_filter
        self.version_filter_value = view.version_filter
        self.show_hidden_value = view.show_hidden
        self.active_view_name = view.name
        self._populate()
        if view.selected_folder is not None:
            self.select_folder(view.selected_folder)
        self._applying_view = False
        self._update_views_button()
        if notify:
            self.view_changed.emit(self.current_view())

    def _update_views_button(self) -> None:
        name = self.active_view_name
        if len(name) > 18:
            name = name[:17] + "…"
        self.views_button.setText(f"Views · {name}" if self.active_view_name else "Views")
        self.views_button.setToolTip(
            f"Current view: {self.active_view_name}"
            if self.active_view_name
            else "Open or save a scenario view"
        )

    def _build_views_menu(self) -> None:
        self.views_menu.clear()
        self.views_menu.addAction("All scenarios", lambda: self.apply_view(LibraryView()))
        self.views_menu.addAction(
            "In progress",
            lambda: self.apply_view(LibraryView(name="In progress", run_filter="active")),
        )
        self.views_menu.addAction(
            "Needs attention",
            lambda: self.apply_view(
                LibraryView(name="Needs attention", run_filter="needs_attention")
            ),
        )
        self.views_menu.addAction(
            "Never run",
            lambda: self.apply_view(LibraryView(name="Never run", run_filter="never")),
        )
        if self.saved_views:
            self.views_menu.addSeparator()
        for view in self.saved_views:
            action = self.views_menu.addAction(view.name)
            action.setCheckable(True)
            action.setChecked(self.active_view_name == view.name)
            action.triggered.connect(
                lambda _checked=False, selected=view: self.apply_view(selected)
            )
        self.views_menu.addSeparator()
        self.views_menu.addAction("Save current view…", self._save_current_view)
        if self.saved_views:
            manage = self.views_menu.addMenu("Manage saved views")
            for view in self.saved_views:
                submenu = manage.addMenu(view.name)
                submenu.addAction(
                    "Rename…", lambda _checked=False, old=view.name: self._rename_view(old)
                )
                submenu.addAction(
                    "Delete",
                    lambda _checked=False, name=view.name: self.view_delete_requested.emit(name),
                )

    def _save_current_view(self) -> None:
        name, accepted = QInputDialog.getText(self, "Save scenario view", "View name:")
        name = name.strip()
        if not accepted or not name:
            return
        if self._view_name_taken(name):
            QMessageBox.warning(self, "View already exists", "Choose another view name.")
            return
        view = self.current_view()
        view.name = name
        self.view_save_requested.emit(view)
        self.apply_view(view)

    def _rename_view(self, old: str) -> None:
        name, accepted = QInputDialog.getText(self, "Rename scenario view", "View name:", text=old)
        name = name.strip()
        if not accepted or not name or name == old:
            return
        if self._view_name_taken(name):
            QMessageBox.warning(self, "View already exists", "Choose another view name.")
            return
        self.view_rename_requested.emit(old, name)

    def _view_name_taken(self, name: str) -> bool:
        reserved = {"in progress", "needs attention", "never run", "all scenarios"}
        return name.casefold() in reserved or any(
            view.name.casefold() == name.casefold() for view in self.saved_views
        )

    def _search_changed(self, _text: str) -> None:
        self._populate()
        self._view_modified()

    def _view_modified(self) -> None:
        if self.scenario_mode:
            self.active_view_name = ""
            self._update_views_button()
            self.view_changed.emit(self.current_view())

    def select_path(self, path: Path) -> None:
        """Select a visible item after a refresh or folder operation."""
        target = self._tree_items.get(path)
        if target is not None:
            if target.parent() is not None:
                target.parent().setExpanded(True)
            self._set_current_item(target)
            self.tree.scrollToItem(target)

    def select_folder(self, name: str) -> None:
        """Select a virtual folder row in the scenario tree."""
        target = self._folder_items.get(name)
        if target is not None:
            target.setExpanded(True)
            self._set_current_item(target)

    def selected_folder_name(self) -> str | None:
        """Return the selected row's folder, or None when nothing is selected."""
        current = self.tree.currentItem()
        if current is None or not self.scenario_mode:
            return None
        if current.data(0, Qt.ItemDataRole.UserRole) == "folder":
            return current.data(0, Qt.ItemDataRole.UserRole + 1)
        parent = current.parent()
        return parent.data(0, Qt.ItemDataRole.UserRole + 1) if parent is not None else None

    def selected_item(self) -> LibraryItem | None:
        current = self.tree.currentItem()
        if current is None or current.data(0, Qt.ItemDataRole.UserRole) != "scenario":
            return None
        path = current.data(0, Qt.ItemDataRole.UserRole + 1)
        return next((item for item in self.items if item.path == path), None)

    def _build_filter_menu(self) -> None:
        self.filter_menu.clear()
        if self.scenario_mode:
            status_menu = self.filter_menu.addMenu("Latest run")
            group = QActionGroup(status_menu)
            group.setExclusive(True)
            for label, value in (
                ("Any status", "all"),
                ("Never run", "never"),
                ("In progress", "active"),
                ("Needs attention", "needs_attention"),
                ("Queued", "queued"),
                ("Running", "running"),
                ("Paused", "paused"),
                ("Completed", "completed"),
                ("Failed", "failed"),
                ("Stopped", "stopped"),
                ("Cancelled", "cancelled"),
            ):
                action = status_menu.addAction(label)
                action.setCheckable(True)
                action.setChecked(self.run_filter_value == value)
                group.addAction(action)
                action.triggered.connect(
                    lambda _checked=False, selected=value: self._set_run_filter(selected)
                )
            self.filter_menu.addSeparator()
        versions = sorted({item.version for item in self.items if item.version})
        version_menu = self.filter_menu.addMenu("Version")
        group = QActionGroup(version_menu)
        group.setExclusive(True)
        for label, value in [("All versions", None), *[(v, v) for v in versions]]:
            action = version_menu.addAction(label)
            action.setCheckable(True)
            action.setChecked(self.version_filter_value == value)
            group.addAction(action)
            action.triggered.connect(
                lambda _checked=False, selected=value: self._set_version_filter(selected)
            )
        self.filter_menu.addSeparator()
        show_hidden = self.filter_menu.addAction("Show hidden items")
        show_hidden.setCheckable(True)
        show_hidden.setChecked(self.show_hidden_value)
        show_hidden.toggled.connect(self._set_show_hidden)
        if self._active_filter_count():
            clear = self.filter_menu.addAction("Clear filters")
            clear.triggered.connect(self.clear_filters)

    def _active_filter_count(self) -> int:
        return (
            int(self.run_filter_value != "all")
            + int(self.version_filter_value is not None)
            + int(self.show_hidden_value)
        )

    def _update_filter_button(self) -> None:
        count = self._active_filter_count()
        self.filter_button.setText(f"Filters · {count}" if count else "Filters")

    def _set_run_filter(self, value: str) -> None:
        self.run_filter_value = value
        self._populate()
        self._view_modified()

    def _set_version_filter(self, value: str | None) -> None:
        self.version_filter_value = value
        self._populate()
        self._view_modified()

    def _set_show_hidden(self, value: bool) -> None:
        self.show_hidden_value = value
        self._populate()
        self._view_modified()

    def clear_filters(self) -> None:
        """Reset filters while retaining the visible search text."""
        self.run_filter_value = "all"
        self.version_filter_value = None
        self.show_hidden_value = False
        self._populate()
        self._view_modified()

    def _visible_items(self) -> list[LibraryItem]:
        query = self.search.text().strip()
        visible: list[LibraryItem] = []
        for item in self.items:
            if item.path in self.hidden_paths and not self.show_hidden_value:
                continue
            if query and not matches_search(item, query):
                continue
            if self.version_filter_value is not None and item.version != self.version_filter_value:
                continue
            if self.scenario_mode:
                latest = self._latest_job(item)
                if self.run_filter_value == "never" and latest is not None:
                    continue
                if self.run_filter_value == "active" and (
                    latest is None or latest.status not in {"queued", "running", "paused"}
                ):
                    continue
                if self.run_filter_value == "needs_attention" and (
                    latest is None or latest.status not in {"failed", "stopped", "cancelled"}
                ):
                    continue
                if self.run_filter_value not in {"all", "never", "active", "needs_attention"}:
                    if latest is None or latest.status != self.run_filter_value:
                        continue
            visible.append(item)
        return visible

    def _latest_job(self, item: LibraryItem) -> GenerationJob | None:
        return self._latest_jobs.get(item.path)

    def _status_summary(self, item: LibraryItem) -> str:
        latest = self._latest_job(item)
        if latest is None:
            return "Never run"
        if latest.status in {"queued", "running", "paused"}:
            return latest.status.title()
        if latest.status == "completed":
            score = self.scorecards.get(latest.id, "")
            short_score = score.split("  ·  ", 1)[0]
            result = f"Complete · {short_score}" if score else "Complete"
        else:
            result = latest.status.title()
        if item.modified_at > latest.started_at + 1:
            return f"Changed · {result}"
        return result

    def _populate(self) -> None:
        self._populating = True
        selected = self.selected_item()
        selected_folder = self.selected_folder_name() if selected is None else None
        visible = self._visible_items()
        searching = bool(self.search.text().strip())
        if searching and self._expanded_before_search is None:
            self._expanded_before_search = {
                name for name, row in self._all_folder_items.items() if row.isExpanded()
            }
        restore_expansion = self._expanded_before_search if not searching else None
        self.tree.blockSignals(True)
        signature: tuple[object, ...] = (
            tuple(self.folder_names),
            tuple(
                (
                    item.path,
                    item.name,
                    item.description,
                    item.version,
                    item.modified_at,
                    self.folder_assignments.get(str(item.path), ""),
                    item.path in self.hidden_paths,
                )
                for item in self.items
            ),
        )
        if signature != self._tree_signature:
            expanded = {name for name, row in self._all_folder_items.items() if row.isExpanded()}
            first_render = self._tree_signature is None
            self._programmatic_highlight = None
            self.tree.clear()
            self._all_tree_items.clear()
            self._all_folder_items.clear()
            if self.scenario_mode:
                groups: dict[str, list[LibraryItem]] = {"": []}
                groups.update({name: [] for name in self.folder_names})
                for item in self.items:
                    folder = self.folder_assignments.get(str(item.path), "")
                    groups.setdefault(folder if folder in self.folder_names else "", []).append(
                        item
                    )
                for folder, members in groups.items():
                    self._add_folder_row(folder, members, first_render or folder in expanded)
            else:
                for item in sorted(self.items, key=lambda entry: entry.name.casefold()):
                    row = QTreeWidgetItem(self.tree, [self._row_text(item), ""])
                    row.setData(0, Qt.ItemDataRole.UserRole, "scenario")
                    row.setData(0, Qt.ItemDataRole.UserRole + 1, item.path)
                    row.setIcon(0, icon("file"))
                    row.setToolTip(0, f"{item.description}\n{item.path}")
                    self._all_tree_items[item.path] = row
                    self._add_row_menu(row, item)
            self._tree_signature = signature
        self._tree_items.clear()
        self._folder_items.clear()
        visible_paths = {item.path for item in visible}
        for item in self.items:
            row = self._all_tree_items[item.path]
            is_visible = item.path in visible_paths
            row.setHidden(not is_visible)
            if is_visible:
                row.setText(0, self._row_text(item))
                row.setSizeHint(0, QSize(0, 48) if self.search.text().strip() else QSize())
                self._tree_items[item.path] = row
        if self.scenario_mode:
            groups: dict[str, list[LibraryItem]] = {name: [] for name in self._all_folder_items}
            for item in visible:
                folder = self.folder_assignments.get(str(item.path), "")
                groups.setdefault(folder if folder in self.folder_names else "", []).append(item)
            for folder, members in groups.items():
                row = self._all_folder_items[folder]
                is_visible = bool(members) or not (
                    self.search.text().strip() or self._active_filter_count()
                )
                row.setHidden(not is_visible)
                if is_visible:
                    row.setText(0, self._folder_label(folder, members))
                    self._folder_items[folder] = row
                    if searching:
                        row.setExpanded(True)
                if restore_expansion is not None:
                    row.setExpanded(folder in restore_expansion)
            if restore_expansion is not None:
                self._expanded_before_search = None
        target = self._tree_items.get(selected.path) if selected is not None else None
        if target is None and selected_folder is not None and not self.search.text().strip():
            target = self._folder_items.get(selected_folder)
        if target is None and self._tree_items:
            target = next(iter(self._tree_items.values()))
        if target is None and self._folder_items:
            target = next(iter(self._folder_items.values()))
        if self.tree.currentItem() is not target:
            self._set_current_item(target)
        self.tree.blockSignals(False)
        self._selection_changed()
        self.result_count.setText(
            f"{len(visible)} {'scenario' if len(visible) == 1 else 'scenarios'}"
            if self.scenario_mode
            else f"{len(visible)} packs"
        )
        self._update_filter_button()
        current = self.tree.currentItem()
        self._last_selected_folder = (
            self.selected_folder_name()
            if current is not None and current.data(0, Qt.ItemDataRole.UserRole) == "folder"
            else None
        )
        self._populating = False

    def _set_current_item(self, target: QTreeWidgetItem | None) -> None:
        if self._programmatic_highlight is not None:
            self._programmatic_highlight.setData(0, Qt.ItemDataRole.BackgroundRole, None)
            self._programmatic_highlight.setData(0, Qt.ItemDataRole.ForegroundRole, None)
            self._programmatic_highlight = None
        if sys.platform != "darwin" or not QAccessible.isActive():
            self.tree.setCurrentItem(target)
            return
        # Cocoa's accessibility cache can still report zero rows here. A selection
        # event then produces a misleading out-of-bounds warning for a valid row.
        selection = self.tree.selectionModel()
        selection.clearSelection()
        index = self.tree.indexFromItem(target) if target is not None else QModelIndex()
        selection.setCurrentIndex(index, QItemSelectionModel.SelectionFlag.NoUpdate)
        if target is not None:
            target.setBackground(0, QColor("#293959"))
            target.setForeground(0, QColor("#ffffff"))
            self._programmatic_highlight = target

    def _add_folder_row(self, folder: str, members: list[LibraryItem], expand: bool) -> None:
        row = QTreeWidgetItem(self.tree, [self._folder_label(folder, members), ""])
        row.setData(0, Qt.ItemDataRole.UserRole, "folder")
        row.setData(0, Qt.ItemDataRole.UserRole + 1, folder)
        row.setIcon(0, icon("folder"))
        row.setFlags(
            Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsDropEnabled
        )
        row.setExpanded(expand or bool(self.search.text().strip()))
        self._all_folder_items[folder] = row
        if folder:
            more = QToolButton(self.tree)
            more.setIcon(icon("more"))
            more.setObjectName("treeMenu")
            more.setToolTip(f"Options for {folder}")
            more.setAccessibleName(f"Options for {folder}")
            more.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
            menu = QMenu(more)
            menu.addAction(
                "Rename folder",
                lambda _checked=False, name=folder: self.folder_rename_requested.emit(name),
            )
            menu.addAction(
                "Delete folder",
                lambda _checked=False, name=folder: self.folder_delete_requested.emit(name),
            )
            more.setMenu(menu)
            self.tree.setItemWidget(row, 1, more)
        for item in sorted(members, key=lambda entry: entry.name.casefold()):
            child = QTreeWidgetItem(row, [self._row_text(item), ""])
            child.setData(0, Qt.ItemDataRole.UserRole, "scenario")
            child.setData(0, Qt.ItemDataRole.UserRole + 1, item.path)
            child.setIcon(0, icon("file"))
            child.setFlags(
                Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsDragEnabled
            )
            child.setToolTip(0, f"{item.description}\n{item.path}")
            self._all_tree_items[item.path] = child
            self._add_row_menu(child, item)

    def _folder_label(self, folder: str, members: list[LibraryItem]) -> str:
        label = folder or "Unfiled"
        active = sum(
            self._latest_job(item) is not None
            and self._latest_job(item).status in {"queued", "running", "paused"}
            for item in members
        )
        attention = sum(
            self._latest_job(item) is not None
            and self._latest_job(item).status in {"failed", "stopped", "cancelled"}
            for item in members
        )
        suffix = f" · {active} active" if active else ""
        if attention:
            suffix += f" · {attention} need attention"
        return f"{label}  ({len(members)}){suffix}"

    def _row_text(self, item: LibraryItem) -> str:
        hidden = " · Hidden" if item.path in self.hidden_paths else ""
        status = f" · {self._status_summary(item)}" if self.scenario_mode else ""
        first = f"{item.name}{hidden}{status}"
        snippet = search_snippet(item, self.search.text()) if self.scenario_mode else ""
        return f"{first}\n{snippet}" if snippet else first

    def _add_row_menu(self, row: QTreeWidgetItem, item: LibraryItem) -> None:
        more = QToolButton(self.tree)
        more.setIcon(icon("more"))
        more.setObjectName("treeMenu")
        more.setToolTip(f"Options for {item.name}")
        more.setAccessibleName(more.toolTip())
        more.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        more.setMenu(self._scenario_menu(item, more))
        self.tree.setItemWidget(row, 1, more)

    def _folder_menu(self, folder: str) -> QMenu:
        menu = QMenu(self)
        menu.addAction("New folder", lambda _checked=False: self.folder_create_requested.emit())
        if folder:
            menu.addAction(
                "Rename folder",
                lambda _checked=False: self.folder_rename_requested.emit(folder),
            )
            menu.addAction(
                "Delete folder",
                lambda _checked=False: self.folder_delete_requested.emit(folder),
            )
        return menu

    def _open_context_menu(self, point: QPoint) -> None:
        row = self.tree.itemAt(point)
        if row is None:
            self._folder_menu("").exec(self.tree.viewport().mapToGlobal(point))
            return
        kind = row.data(0, Qt.ItemDataRole.UserRole)
        if kind == "folder":
            folder = row.data(0, Qt.ItemDataRole.UserRole + 1)
            self._folder_menu(folder).exec(self.tree.viewport().mapToGlobal(point))
            return
        path = row.data(0, Qt.ItemDataRole.UserRole + 1)
        item = next((entry for entry in self.items if entry.path == path), None)
        if item is None:
            return
        self._scenario_menu(item, self).exec(self.tree.viewport().mapToGlobal(point))

    def _scenario_menu(self, item: LibraryItem, parent: QWidget) -> QMenu:
        menu = QMenu(parent)
        path = item.path
        if self.scenario_mode:
            move = menu.addMenu("Move to folder")
            for label, folder in [("Unfiled", ""), *[(name, name) for name in self.folder_names]]:
                action = move.addAction(label)
                action.setCheckable(True)
                action.setChecked(self.folder_assignments.get(str(path), "") == folder)
                action.triggered.connect(
                    lambda _checked=False, target=folder: self.folder_assignment_requested.emit(
                        item, target
                    )
                )
            menu.addSeparator()
        menu.addAction("Clone", lambda _checked=False: self.clone_requested.emit(item))
        menu.addAction(
            "Unhide" if path in self.hidden_paths else "Hide",
            lambda _checked=False: self.hide_requested.emit(item),
        )
        menu.addAction(
            "Open file",
            lambda _checked=False: QDesktopServices.openUrl(QUrl.fromLocalFile(str(path))),
        )
        return menu

    def _move_path(self, path: Path, folder: str) -> None:
        item = next((entry for entry in self.items if entry.path == path), None)
        if item is not None:
            self.folder_assignment_requested.emit(item, folder)

    def _open_folder_recent(self, row: QListWidgetItem) -> None:
        path = row.data(Qt.ItemDataRole.UserRole)
        if isinstance(path, Path):
            if path not in self._tree_items:
                self.apply_view(LibraryView(show_hidden=path in self.hidden_paths))
            self.select_path(path)

    def _selection_changed(self, *_args: object) -> None:
        self._clear_programmatic_highlight()
        item = self.selected_item()
        current = self.tree.currentItem()
        selected_folder = (
            self.selected_folder_name()
            if current is not None and current.data(0, Qt.ItemDataRole.UserRole) == "folder"
            else None
        )
        if not self._populating and not self._applying_view:
            if selected_folder != self._last_selected_folder:
                self._last_selected_folder = selected_folder
                self._view_modified()
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
        self.action_controls.setVisible(enabled)
        self.secondary_controls.setVisible(enabled)
        if item is None:
            folder = self.selected_folder_name()
            self.kind_label.setText("FOLDER" if folder is not None else "SELECT AN ITEM")
            self.name.setText((folder or "Unfiled") if folder is not None else "Choose an item")
            self.description.setText(
                "Project overview · virtual folder; scenario files stay in their original locations."
                if folder is not None
                else "Select a scenario to view details and actions."
            )
            self.search_match.setVisible(False)
            members = (
                [
                    entry
                    for entry in self.items
                    if self.folder_assignments.get(str(entry.path), "") == folder
                    or (
                        folder == ""
                        and self.folder_assignments.get(str(entry.path), "")
                        not in self.folder_names
                    )
                ]
                if folder is not None
                else []
            )
            active = sum(
                self._latest_job(entry) is not None
                and self._latest_job(entry).status in {"queued", "running", "paused"}
                for entry in members
            )
            completed = sum(
                self._latest_job(entry) is not None
                and self._latest_job(entry).status == "completed"
                for entry in members
            )
            attention = sum(
                self._latest_job(entry) is not None
                and self._latest_job(entry).status in {"failed", "stopped", "cancelled"}
                for entry in members
            )
            never_run = sum(self._latest_job(entry) is None for entry in members)
            hidden = sum(entry.path in self.hidden_paths for entry in members)
            overview = (
                f"{len(members)} scenarios · {active} active · {completed} completed "
                f"· {never_run} never run"
            )
            if hidden:
                overview += f" · {hidden} hidden"
            if attention:
                overview += f" · {attention} need attention"
            self.metadata.setText(overview if folder is not None else "")
            recent = sorted(members, key=lambda candidate: candidate.modified_at, reverse=True)[:6]
            recent_paths = tuple(entry.path for entry in recent)
            if recent_paths != self._recent_paths:
                self.folder_recent.clear()
                for entry in recent:
                    row = QListWidgetItem()
                    row.setData(Qt.ItemDataRole.UserRole, entry.path)
                    row.setToolTip(str(entry.path))
                    self.folder_recent.addItem(row)
                self._recent_paths = recent_paths
            for index, entry in enumerate(recent):
                self.folder_recent.item(index).setText(
                    f"{entry.name}  ·  {self._status_summary(entry)}"
                )
            self.folder_recent.setFixedHeight(min(250, 12 + 45 * len(recent)))
            self.folder_recent_heading.setVisible(bool(members))
            self.folder_recent.setVisible(bool(members))
            self.run_status.setText("No runs yet")
            self.score.setText("No saved evaluation yet")
            self.evaluate.setEnabled(False)
            self._set_scenario_sections(False)
            return
        assigned = self.folder_assignments.get(str(item.path), "")
        self.folder_recent_heading.setVisible(False)
        self.folder_recent.setVisible(False)
        self.folder_value.setText(assigned or "Unfiled")
        self.kind_label.setText(item.kind.upper())
        self.name.setText(item.name)
        self.description.setText(item.description or "No description provided.")
        snippet = search_snippet(item, self.search.text())
        self.search_match.setText(f"Search match: {snippet}")
        self.search_match.setVisible(bool(snippet))
        edited = datetime.fromtimestamp(item.modified_at).strftime("%b %d, %Y %I:%M %p")
        self.metadata.setText(
            f"Version {item.version}  ·  {item.users} users  ·  {item.systems} systems  ·  "
            f"{item.events} storyline events\nUpdated {edited}  ·  {item.path}"
            if self.scenario_mode
            else f"Version {item.version}\n{item.path}"
        )
        related = sorted(
            (job for job in self.jobs if job.scenario.resolve() == item.path),
            key=lambda job: job.started_at,
            reverse=True,
        )
        self.run_status.setText(
            f"{self._status_summary(item)}  ·  "
            f"{datetime.fromtimestamp(related[0].started_at).strftime('%b %d, %Y %I:%M %p')}\n"
            f"{related[0].output_root}"
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
        self.hide.setToolTip("Unhide" if item.path in self.hidden_paths else "Hide")
        self.hide.setAccessibleName(self.hide.toolTip())
        self._set_scenario_sections(self.scenario_mode)

    def _clear_programmatic_highlight(self) -> None:
        if self._programmatic_highlight is None or not self.tree.selectedItems():
            return
        self._programmatic_highlight.setData(0, Qt.ItemDataRole.BackgroundRole, None)
        self._programmatic_highlight.setData(0, Qt.ItemDataRole.ForegroundRole, None)
        self._programmatic_highlight = None

    def _set_scenario_sections(self, visible: bool) -> None:
        for widget in (
            self.assignment_heading,
            self.folder_value,
            self.run_heading,
            self.run_status,
            self.score_heading,
            self.score,
            self.evaluate,
            self.destination_heading,
            self.destination,
        ):
            widget.setVisible(visible)

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
