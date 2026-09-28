"""Library-first Qt views for authored scenarios and reusable packs."""

from __future__ import annotations

from pathlib import Path
from typing import override

from PySide6.QtCore import QPoint, Qt, QUrl, Signal
from PySide6.QtGui import QActionGroup, QDesktopServices, QDropEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSplitter,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from evidenceforge.desktop.icons import icon
from evidenceforge.desktop.library import LibraryItem, matches_search
from evidenceforge.desktop.state import GenerationJob


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

    def __init__(self, title: str, *, scenario_mode: bool) -> None:
        super().__init__()
        self.scenario_mode = scenario_mode
        self.items: list[LibraryItem] = []
        self.jobs: list[GenerationJob] = []
        self.hidden_paths: set[Path] = set()
        self.scorecards: dict[str, str] = {}
        self.folder_names: list[str] = []
        self.folder_assignments: dict[str, str] = {}
        self.run_filter_value = "all"
        self.version_filter_value: str | None = None
        self.show_hidden_value = False
        self._tree_items: dict[Path, QTreeWidgetItem] = {}
        self._folder_items: dict[str, QTreeWidgetItem] = {}
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
        self.search.textChanged.connect(self._populate)
        search_row = QHBoxLayout()
        search_row.addWidget(self.search, 1)
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
        self.metadata = QLabel("")
        self.metadata.setObjectName("metadata")
        self.metadata.setWordWrap(True)
        details.addWidget(self.metadata)
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
        action_row = QHBoxLayout()
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
        details.addLayout(action_row)
        secondary = QHBoxLayout()
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
        self.items = items
        self.hidden_paths = hidden_paths
        self.jobs = jobs
        self.scorecards = scorecards or {}
        self.folder_names = sorted(folder_names or [], key=str.casefold)
        self.folder_assignments = folder_assignments or {}
        self._populate()

    def select_path(self, path: Path) -> None:
        """Select a visible item after a refresh or folder operation."""
        target = self._tree_items.get(path)
        if target is not None:
            if target.parent() is not None:
                target.parent().setExpanded(True)
            self.tree.setCurrentItem(target)
            self.tree.scrollToItem(target)

    def select_folder(self, name: str) -> None:
        """Select a virtual folder row in the scenario tree."""
        target = self._folder_items.get(name)
        if target is not None:
            target.setExpanded(True)
            self.tree.setCurrentItem(target)

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
                ("Running", "running"),
                ("Completed", "completed"),
                ("Stopped", "stopped"),
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

    def _set_version_filter(self, value: str | None) -> None:
        self.version_filter_value = value
        self._populate()

    def _set_show_hidden(self, value: bool) -> None:
        self.show_hidden_value = value
        self._populate()

    def clear_filters(self) -> None:
        """Reset filters while retaining the visible search text."""
        self.run_filter_value = "all"
        self.version_filter_value = None
        self.show_hidden_value = False
        self._populate()

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
                related = [job for job in self.jobs if job.scenario.resolve() == item.path]
                latest = max(related, key=lambda job: job.started_at) if related else None
                if self.run_filter_value == "never" and latest is not None:
                    continue
                if self.run_filter_value not in {"all", "never"} and (
                    latest is None or latest.status != self.run_filter_value
                ):
                    continue
            visible.append(item)
        return visible

    def _populate(self) -> None:
        selected = self.selected_item()
        selected_folder = self.selected_folder_name() if selected is None else None
        expanded = {name for name, row in self._folder_items.items() if row.isExpanded()}
        first_render = not self._folder_items
        visible = self._visible_items()
        self.tree.blockSignals(True)
        self.tree.clear()
        self._tree_items.clear()
        self._folder_items.clear()
        if self.scenario_mode:
            groups: dict[str, list[LibraryItem]] = {"": []}
            groups.update({name: [] for name in self.folder_names})
            for item in visible:
                folder = self.folder_assignments.get(str(item.path), "")
                groups.setdefault(folder if folder in self.folder_names else "", []).append(item)
            for folder, members in groups.items():
                if not members and (self.search.text().strip() or self._active_filter_count()):
                    continue
                self._add_folder_row(folder, members, first_render or folder in expanded)
        else:
            for item in sorted(visible, key=lambda entry: entry.name.casefold()):
                row = QTreeWidgetItem(self.tree, [item.name, ""])
                row.setData(0, Qt.ItemDataRole.UserRole, "scenario")
                row.setData(0, Qt.ItemDataRole.UserRole + 1, item.path)
                row.setIcon(0, icon("file"))
                row.setToolTip(0, str(item.path))
                self._tree_items[item.path] = row
                self._add_row_menu(row, item)
        target = self._tree_items.get(selected.path) if selected is not None else None
        if target is None and selected_folder is not None:
            target = self._folder_items.get(selected_folder)
        if target is None and self._tree_items:
            target = next(iter(self._tree_items.values()))
        if target is None and self._folder_items:
            target = next(iter(self._folder_items.values()))
        self.tree.setCurrentItem(target)
        self.tree.blockSignals(False)
        self._selection_changed()
        self.result_count.setText(
            f"{len(visible)} {'scenario' if len(visible) == 1 else 'scenarios'}"
            if self.scenario_mode
            else f"{len(visible)} packs"
        )
        self._update_filter_button()

    def _add_folder_row(self, folder: str, members: list[LibraryItem], expand: bool) -> None:
        label = folder or "Unfiled"
        row = QTreeWidgetItem(self.tree, [f"{label}  ({len(members)})", ""])
        row.setData(0, Qt.ItemDataRole.UserRole, "folder")
        row.setData(0, Qt.ItemDataRole.UserRole + 1, folder)
        row.setIcon(0, icon("folder"))
        row.setFlags(
            Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsDropEnabled
        )
        row.setExpanded(expand or bool(self.search.text().strip()))
        self._folder_items[folder] = row
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
            name = item.name + ("  ·  Hidden" if item.path in self.hidden_paths else "")
            child = QTreeWidgetItem(row, [name, ""])
            child.setData(0, Qt.ItemDataRole.UserRole, "scenario")
            child.setData(0, Qt.ItemDataRole.UserRole + 1, item.path)
            child.setIcon(0, icon("file"))
            child.setFlags(
                Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsDragEnabled
            )
            child.setToolTip(0, f"{item.description}\n{item.path}")
            self._tree_items[item.path] = child
            self._add_row_menu(child, item)

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

    def _selection_changed(self, *_args: object) -> None:
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
            folder = self.selected_folder_name()
            self.kind_label.setText("FOLDER" if folder is not None else "SELECT AN ITEM")
            self.name.setText((folder or "Unfiled") if folder is not None else "Choose an item")
            self.description.setText(
                "Virtual folder · files remain in their original locations."
                if folder is not None
                else "Select a scenario to view details and actions."
            )
            count = self._folder_items[folder].childCount() if folder in self._folder_items else 0
            self.metadata.setText(f"{count} scenarios" if folder is not None else "")
            self.run_status.setText("No runs yet")
            self.score.setText("No saved evaluation yet")
            self.evaluate.setEnabled(False)
            self._set_scenario_sections(False)
            return
        assigned = self.folder_assignments.get(str(item.path), "")
        self.folder_value.setText(assigned or "Unfiled")
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
        self.hide.setToolTip("Unhide" if item.path in self.hidden_paths else "Hide")
        self.hide.setAccessibleName(self.hide.toolTip())
        self._set_scenario_sections(self.scenario_mode)

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
