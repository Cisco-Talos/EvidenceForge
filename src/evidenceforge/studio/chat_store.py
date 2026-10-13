"""Durable private chat metadata using the Studio database transaction boundary."""

from __future__ import annotations

import sqlite3
import threading

from evidenceforge.studio.state_records_v3 import (
    ChatControl,
    ChatInput,
    ChatPreference,
    ChatTurn,
    ChatViewState,
)


class ChatStore:
    """Persist dispatch receipts and ordered source-native item projections."""

    def __init__(self, database: sqlite3.Connection, lock: threading.RLock) -> None:
        self.database = database
        self.lock = lock

    def turns(self, conversation_id: str) -> list[ChatTurn]:
        """Return turns in first-observed order."""
        with self.lock:
            rows = self.database.execute(
                "SELECT payload FROM chat_turns WHERE conversation_id=? ORDER BY rowid",
                (conversation_id,),
            ).fetchall()
        return [ChatTurn.model_validate_json(row[0]) for row in rows]

    def save_turn(self, turn: ChatTurn) -> None:
        """Replace one materialized turn without changing its timeline position."""
        with self.lock, self.database:
            self.database.execute(
                "INSERT INTO chat_turns(conversation_id,id,payload) VALUES (?,?,?) "
                "ON CONFLICT(conversation_id,id) DO UPDATE SET payload=excluded.payload",
                (turn.conversation_id, turn.id, turn.model_dump_json()),
            )

    def inputs(self, conversation_id: str) -> list[ChatInput]:
        """Read FIFO claims, including terminal receipts for deduplication."""
        with self.lock:
            rows = self.database.execute(
                "SELECT payload FROM chat_inputs WHERE conversation_id=? ORDER BY rowid",
                (conversation_id,),
            ).fetchall()
        return [ChatInput.model_validate_json(row[0]) for row in rows]

    def input(self, identity: str) -> ChatInput | None:
        """Look up a client ID globally so it cannot target two conversations."""
        with self.lock:
            row = self.database.execute(
                "SELECT payload FROM chat_inputs WHERE id=?", (identity,)
            ).fetchone()
        return ChatInput.model_validate_json(row[0]) if row else None

    def save_input(self, entry: ChatInput) -> None:
        """Durably claim a message before sending its RPC."""
        with self.lock, self.database:
            self.database.execute(
                "INSERT INTO chat_inputs(id,conversation_id,payload) VALUES (?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                (entry.id, entry.conversation_id, entry.model_dump_json()),
            )

    def remove_input(self, identity: str) -> None:
        """Remove an unsent queued message."""
        with self.lock, self.database:
            self.database.execute("DELETE FROM chat_inputs WHERE id=?", (identity,))

    def control(self, conversation_id: str) -> ChatControl:
        """Return default private UI state for a previously unvisited chat."""
        with self.lock:
            row = self.database.execute(
                "SELECT payload FROM chat_controls WHERE conversation_id=?", (conversation_id,)
            ).fetchone()
        return (
            ChatControl.model_validate_json(row[0])
            if row
            else ChatControl(conversation_id=conversation_id)
        )

    def save_control(self, control: ChatControl) -> None:
        """Save reading/composer state independently of the source file."""
        with self.lock, self.database:
            self.database.execute(
                "INSERT INTO chat_controls(conversation_id,payload) VALUES (?,?) "
                "ON CONFLICT(conversation_id) DO UPDATE SET payload=excluded.payload",
                (control.conversation_id, control.model_dump_json()),
            )

    def update_control(
        self,
        conversation_id: str,
        *,
        queue_paused: bool | None = None,
        view: ChatViewState | None = None,
    ) -> ChatControl:
        """Merge independent queue/view writes under one database ownership lock."""
        with self.lock:
            control = self.control(conversation_id)
            if queue_paused is not None:
                control.queue_paused = queue_paused
            if view is not None:
                control.view = view
            self.save_control(control)
            return control

    def preference(self, workspace: str) -> ChatPreference:
        """Read the workspace-specific conversation rail state."""
        with self.lock:
            row = self.database.execute(
                "SELECT payload FROM chat_preferences WHERE workspace=?", (workspace,)
            ).fetchone()
        return (
            ChatPreference.model_validate_json(row[0])
            if row
            else ChatPreference(workspace=workspace)
        )

    def save_preference(self, preference: ChatPreference) -> None:
        """Save layout preference outside authored artifacts."""
        with self.lock, self.database:
            self.database.execute(
                "INSERT INTO chat_preferences(workspace,payload) VALUES (?,?) "
                "ON CONFLICT(workspace) DO UPDATE SET payload=excluded.payload",
                (preference.workspace, preference.model_dump_json()),
            )

    def remove_conversation(self, conversation_id: str) -> None:
        """Remove all private chat state together with a Studio chat association."""
        with self.lock, self.database:
            for table in ("chat_turns", "chat_inputs", "chat_controls"):
                self.database.execute(
                    f"DELETE FROM {table} WHERE conversation_id=?", (conversation_id,)
                )
