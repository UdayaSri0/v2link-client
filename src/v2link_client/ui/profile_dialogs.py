"""Dialogs for profile management."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from v2link_client.core.profile_store import Profile, ProfileStore, basic_url_prefix_valid, detect_protocol

ValidateFn = Callable[[str], tuple[bool, str]]


class ProfileEditorDialog(QDialog):
    def __init__(
        self,
        *,
        validate_fn: ValidateFn,
        profile: Profile | None = None,
        default_profile_id: str | None = None,
        preset_url: str = "",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._validate_fn = validate_fn
        self._profile = profile
        self._is_edit = profile is not None

        self.setWindowTitle("Edit Profile" if self._is_edit else "Add Profile")
        self.setModal(True)
        self.resize(560, 360)

        self.name_input = QLineEdit(profile.name if profile else "")
        self.url_input = QLineEdit(profile.url if profile else preset_url)
        self.notes_input = QPlainTextEdit(profile.notes if profile else "")
        self.favorite_checkbox = QCheckBox("Favorite")
        self.favorite_checkbox.setChecked(profile.favorite if profile else False)
        self.default_checkbox = QCheckBox("Set as default")
        self.default_checkbox.setChecked(
            bool(profile and default_profile_id and profile.id == default_profile_id)
        )

        self.url_input.setPlaceholderText("vless:// or vmess:// share URL")
        self.notes_input.setPlaceholderText("Optional notes")
        self.notes_input.setMaximumBlockCount(200)

        self.validation_label = QLabel("")
        self.validation_label.setWordWrap(True)

        self.validate_button = QPushButton("Validate")
        self.validate_button.setProperty("variant", "ghost")

        form = QGridLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)
        form.addWidget(QLabel("Name"), 0, 0)
        form.addWidget(self.name_input, 0, 1)
        form.addWidget(QLabel("URL"), 1, 0)
        form.addWidget(self.url_input, 1, 1)

        url_actions = QHBoxLayout()
        url_actions.setSpacing(8)
        url_actions.addWidget(self.validate_button)
        url_actions.addStretch(1)

        form.addWidget(QLabel("Notes"), 2, 0, alignment=Qt.AlignmentFlag.AlignTop)
        form.addWidget(self.notes_input, 2, 1)

        checks_row = QHBoxLayout()
        checks_row.setSpacing(12)
        checks_row.addWidget(self.favorite_checkbox)
        checks_row.addWidget(self.default_checkbox)
        checks_row.addStretch(1)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        self.save_button = self.buttons.button(QDialogButtonBox.StandardButton.Save)
        if self.save_button is not None:
            self.save_button.setProperty("variant", "primary")
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setProperty("variant", "ghost")

        layout = QVBoxLayout()
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        layout.addLayout(form)
        layout.addLayout(url_actions)
        layout.addWidget(self.validation_label)
        layout.addLayout(checks_row)
        layout.addWidget(self.buttons)
        self.setLayout(layout)

        self.validate_button.clicked.connect(self._on_validate_clicked)
        self.name_input.textChanged.connect(self._refresh_save_enabled)
        self.url_input.textChanged.connect(self._refresh_save_enabled)
        self.buttons.accepted.connect(self._on_accept_clicked)
        self.buttons.rejected.connect(self.reject)

        self._refresh_save_enabled()

    def _refresh_save_enabled(self) -> None:
        name_ok = bool(self.name_input.text().strip())
        url = self.url_input.text().strip()
        url_ok = bool(url) and basic_url_prefix_valid(url)
        if self.save_button is not None:
            self.save_button.setEnabled(name_ok and url_ok)

    def _on_validate_clicked(self) -> None:
        url = self.url_input.text().strip()
        if not url:
            self._set_validation_message("URL is required.", ok=False)
            return
        if not basic_url_prefix_valid(url):
            self._set_validation_message("URL must include a protocol prefix like vless://", ok=False)
            return

        ok, message = self._validate_fn(url)
        self._set_validation_message(message, ok=ok)

    def _set_validation_message(self, message: str, *, ok: bool) -> None:
        self.validation_label.setText(message)
        if ok:
            self.validation_label.setStyleSheet("color: #2e7d32; font-weight: 600;")
        else:
            self.validation_label.setStyleSheet("color: #c62828; font-weight: 600;")

    def _on_accept_clicked(self) -> None:
        self._refresh_save_enabled()
        if self.save_button is not None and not self.save_button.isEnabled():
            return
        self.accept()

    def build_profile(self) -> Profile:
        name = self.name_input.text().strip()
        url = self.url_input.text().strip()
        notes = self.notes_input.toPlainText().strip()
        favorite = bool(self.favorite_checkbox.isChecked())

        if self._profile is None:
            return Profile.create(name=name, url=url, notes=notes, favorite=favorite)

        return replace(
            self._profile,
            name=name,
            url=url,
            notes=notes,
            favorite=favorite,
            protocol=detect_protocol(url),
        )

    @property
    def set_as_default(self) -> bool:
        return bool(self.default_checkbox.isChecked())


class ProfileManagerDialog(QDialog):
    def __init__(self, *, store: ProfileStore, validate_fn: ValidateFn, parent=None) -> None:
        super().__init__(parent)
        self.store = store
        self._validate_fn = validate_fn
        self.changed = False
        self._row_profile_ids: list[str] = []

        self.setWindowTitle("Profile Manager")
        self.setModal(True)
        self.resize(760, 440)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search profiles")

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Name", "Protocol", "Last used", "Favorite"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(0, self.table.horizontalHeader().ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, self.table.horizontalHeader().ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, self.table.horizontalHeader().ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, self.table.horizontalHeader().ResizeMode.ResizeToContents)

        self.add_button = QPushButton("Add")
        self.edit_button = QPushButton("Edit")
        self.delete_button = QPushButton("Delete")
        self.default_button = QPushButton("Set as Default")
        self.duplicate_button = QPushButton("Duplicate")
        self.favorite_button = QPushButton("Toggle Favorite")
        self.close_button = QPushButton("Close")

        self.add_button.setProperty("variant", "primary")
        self.edit_button.setProperty("variant", "ghost")
        self.delete_button.setProperty("variant", "danger")
        self.default_button.setProperty("variant", "ghost")
        self.duplicate_button.setProperty("variant", "ghost")
        self.favorite_button.setProperty("variant", "ghost")
        self.close_button.setProperty("variant", "ghost")

        button_row = QHBoxLayout()
        button_row.setSpacing(8)
        button_row.addWidget(self.add_button)
        button_row.addWidget(self.edit_button)
        button_row.addWidget(self.delete_button)
        button_row.addWidget(self.default_button)
        button_row.addWidget(self.duplicate_button)
        button_row.addWidget(self.favorite_button)
        button_row.addStretch(1)
        button_row.addWidget(self.close_button)

        layout = QVBoxLayout()
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        layout.addWidget(self.search_input)
        layout.addWidget(self.table, 1)
        layout.addLayout(button_row)
        self.setLayout(layout)

        self.search_input.textChanged.connect(self._refresh_table)
        self.add_button.clicked.connect(self._on_add_clicked)
        self.edit_button.clicked.connect(self._on_edit_clicked)
        self.delete_button.clicked.connect(self._on_delete_clicked)
        self.default_button.clicked.connect(self._on_set_default_clicked)
        self.duplicate_button.clicked.connect(self._on_duplicate_clicked)
        self.favorite_button.clicked.connect(self._on_toggle_favorite_clicked)
        self.close_button.clicked.connect(self.accept)

        self._refresh_table()

    def _profiles_for_display(self) -> list[Profile]:
        term = self.search_input.text().strip().lower()
        profiles = sorted(
            self.store.profiles,
            key=lambda p: (not p.favorite, p.name.lower(), p.created_at),
        )
        if not term:
            return profiles
        return [
            profile
            for profile in profiles
            if term in profile.name.lower()
            or term in profile.protocol.lower()
            or term in profile.url.lower()
            or term in profile.notes.lower()
        ]

    def _refresh_table(self, select_profile_id: str | None = None) -> None:
        profiles = self._profiles_for_display()
        self._row_profile_ids = [p.id for p in profiles]
        self.table.setRowCount(len(profiles))

        selected_row = -1
        for row, profile in enumerate(profiles):
            name = profile.name
            if self.store.default_profile_id == profile.id:
                name = f"{name} (default)"
            last_used = self._format_dt(profile.last_used_at)

            self.table.setItem(row, 0, QTableWidgetItem(name))
            self.table.setItem(row, 1, QTableWidgetItem(profile.protocol))
            self.table.setItem(row, 2, QTableWidgetItem(last_used))
            self.table.setItem(row, 3, QTableWidgetItem("Yes" if profile.favorite else "No"))

            if select_profile_id and profile.id == select_profile_id:
                selected_row = row

        if selected_row >= 0:
            self.table.selectRow(selected_row)
        elif profiles:
            self.table.selectRow(0)

    def _selected_profile(self) -> Profile | None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._row_profile_ids):
            return None
        return self.store.get_by_id(self._row_profile_ids[row])

    def _on_add_clicked(self) -> None:
        dialog = ProfileEditorDialog(
            validate_fn=self._validate_fn,
            default_profile_id=self.store.default_profile_id,
            parent=self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        profile = self.store.add_profile(dialog.build_profile())
        if dialog.set_as_default:
            self.store.set_default(profile.id)
        self.changed = True
        self._refresh_table(select_profile_id=profile.id)

    def _on_edit_clicked(self) -> None:
        current = self._selected_profile()
        if current is None:
            return

        dialog = ProfileEditorDialog(
            validate_fn=self._validate_fn,
            profile=current,
            default_profile_id=self.store.default_profile_id,
            parent=self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        updated = self.store.update_profile(dialog.build_profile())
        if dialog.set_as_default:
            self.store.set_default(updated.id)
        self.changed = True
        self._refresh_table(select_profile_id=updated.id)

    def _on_delete_clicked(self) -> None:
        current = self._selected_profile()
        if current is None:
            return
        answer = QMessageBox.question(
            self,
            "Delete Profile",
            f"Delete profile '{current.name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self.store.delete_profile(current.id)
        self.changed = True
        self._refresh_table()

    def _on_set_default_clicked(self) -> None:
        current = self._selected_profile()
        if current is None:
            return
        self.store.set_default(current.id)
        self.changed = True
        self._refresh_table(select_profile_id=current.id)

    def _on_duplicate_clicked(self) -> None:
        current = self._selected_profile()
        if current is None:
            return

        dialog = ProfileEditorDialog(
            validate_fn=self._validate_fn,
            default_profile_id=self.store.default_profile_id,
            preset_url=current.url,
            parent=self,
        )
        dialog.name_input.setText(f"{current.name} Copy")
        dialog.notes_input.setPlainText(current.notes)
        dialog.favorite_checkbox.setChecked(current.favorite)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        saved = self.store.add_profile(dialog.build_profile())
        if dialog.set_as_default:
            self.store.set_default(saved.id)
        self.changed = True
        self._refresh_table(select_profile_id=saved.id)

    def _on_toggle_favorite_clicked(self) -> None:
        current = self._selected_profile()
        if current is None:
            return
        updated = replace(current, favorite=not current.favorite)
        self.store.update_profile(updated)
        self.changed = True
        self._refresh_table(select_profile_id=current.id)

    @staticmethod
    def _format_dt(value: str | None) -> str:
        if not value:
            return "Never"
        try:
            normalized = value.replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
            return dt.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            return value
