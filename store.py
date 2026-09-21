"""
The app's own store: SQLite via the standard library.

This is where per-user state that PRA cannot hold lives — first-seen time, approval status,
and (from stage 3) approver, approval time and expiry. PRA is never asked to store any of it.

Stage 2 writes here only. Nothing in this module talks to PRA.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = PROJECT_DIR / "vendor_approver.db"  # *.db is gitignored

# Lifecycle of a vendor user as this app sees it.
STATUS_PENDING = "pending"            # seen in PRA, no group policy, approver not yet asked/answered
STATUS_PREEXISTING = "preexisting"    # already had a group policy the first time we saw them
STATUS_APPROVED = "approved"          # stage 3
STATUS_DENIED = "denied"              # stage 3
STATUS_REVOKED = "revoked"            # stage 3/4
STATUS_EXPIRED = "expired"            # stage 4

NOTIFICATION_NEW_USER = "new_user"

# "logged" means the message was composed and written here but not delivered — stage 2 behaviour.
DELIVERY_LOGGED = "logged"

SCHEMA = """
CREATE TABLE IF NOT EXISTS vendor_user (
    pra_user_id           INTEGER PRIMARY KEY,   -- User.id in PRA
    security_provider_id  INTEGER NOT NULL,      -- User.security_provider_id; always the one vendor
    username              TEXT,
    public_display_name   TEXT,
    email_address         TEXT,
    enabled               INTEGER,               -- 1/0 from User.enabled
    pra_created_at        TEXT,                  -- User.created_at: when PRA first saw them
    last_authentication   TEXT,                  -- User.last_authentication
    status                TEXT NOT NULL,
    first_seen_at         TEXT NOT NULL,         -- when THIS app first saw them
    last_seen_at          TEXT NOT NULL,         -- last poll that returned them
    pra_missing_since     TEXT,                  -- set when a poll stops returning them
    group_policies_seen   TEXT,                  -- JSON [{id,name}] at first sighting
    approved_at           TEXT,                  -- stage 3+
    approved_by           TEXT,                  -- stage 3+
    expires_at            TEXT,                  -- stage 3+; the date PRA has nowhere to keep
    note                  TEXT
);

CREATE TABLE IF NOT EXISTS notification (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    kind          TEXT NOT NULL,
    pra_user_id   INTEGER,
    recipients    TEXT,                          -- comma-separated
    subject       TEXT,
    body          TEXT,
    delivery      TEXT NOT NULL                  -- 'logged' (stage 2) or 'sent' (later)
);

CREATE TABLE IF NOT EXISTS poll_run (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    users_seen       INTEGER,
    new_pending      INTEGER,
    new_preexisting  INTEGER,
    error            TEXT
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path = DEFAULT_DB_PATH):
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # -- vendor_user ----------------------------------------------------------

    def get_user(self, pra_user_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM vendor_user WHERE pra_user_id = ?", (pra_user_id,)
        ).fetchone()

    def list_users(self, status: Optional[str] = None) -> List[sqlite3.Row]:
        if status is None:
            return self.conn.execute(
                "SELECT * FROM vendor_user ORDER BY first_seen_at, pra_user_id"
            ).fetchall()
        return self.conn.execute(
            "SELECT * FROM vendor_user WHERE status = ? ORDER BY first_seen_at, pra_user_id",
            (status,),
        ).fetchall()

    def known_user_ids(self) -> List[int]:
        return [r["pra_user_id"] for r in self.conn.execute("SELECT pra_user_id FROM vendor_user")]

    def insert_user(
        self,
        user: Dict[str, Any],
        status: str,
        group_policies: Iterable[Dict[str, Any]],
        note: Optional[str] = None,
    ) -> None:
        """First sighting. `user` is a PRA User resource; only the fields below are kept."""
        now = utcnow()
        policies = [{"id": p.get("id"), "name": p.get("name")} for p in group_policies]
        self.conn.execute(
            """
            INSERT INTO vendor_user (
                pra_user_id, security_provider_id, username, public_display_name, email_address,
                enabled, pra_created_at, last_authentication, status, first_seen_at, last_seen_at,
                group_policies_seen, note
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"],
                user["security_provider_id"],
                user.get("username"),
                user.get("public_display_name"),
                user.get("email_address"),
                1 if user.get("enabled") else 0,
                user.get("created_at"),
                user.get("last_authentication"),
                status,
                now,
                now,
                json.dumps(policies),
                note,
            ),
        )
        self.conn.commit()

    def touch_user(self, user: Dict[str, Any]) -> None:
        """Seen again: refresh the snapshot fields PRA owns and clear any missing marker."""
        self.conn.execute(
            """
            UPDATE vendor_user SET
                username = ?, public_display_name = ?, email_address = ?, enabled = ?,
                last_authentication = ?, last_seen_at = ?, pra_missing_since = NULL
            WHERE pra_user_id = ?
            """,
            (
                user.get("username"),
                user.get("public_display_name"),
                user.get("email_address"),
                1 if user.get("enabled") else 0,
                user.get("last_authentication"),
                utcnow(),
                user["id"],
            ),
        )
        self.conn.commit()

    def mark_missing(self, pra_user_id: int) -> bool:
        """Record that PRA no longer returns this user. Returns True only the first time."""
        cur = self.conn.execute(
            "UPDATE vendor_user SET pra_missing_since = ? "
            "WHERE pra_user_id = ? AND pra_missing_since IS NULL",
            (utcnow(), pra_user_id),
        )
        self.conn.commit()
        return cur.rowcount == 1

    def set_status(self, pra_user_id: int, status: str, note: Optional[str] = None) -> None:
        self.conn.execute(
            "UPDATE vendor_user SET status = ?, note = COALESCE(?, note) WHERE pra_user_id = ?",
            (status, note, pra_user_id),
        )
        self.conn.commit()

    # -- notification ---------------------------------------------------------

    def add_notification(
        self,
        kind: str,
        pra_user_id: Optional[int],
        recipients: Iterable[str],
        subject: str,
        body: str,
        delivery: str = DELIVERY_LOGGED,
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO notification (created_at, kind, pra_user_id, recipients, subject, body, delivery) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (utcnow(), kind, pra_user_id, ",".join(recipients), subject, body, delivery),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_notifications(self) -> List[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM notification ORDER BY id").fetchall()

    # -- poll_run -------------------------------------------------------------

    def start_poll(self) -> int:
        cur = self.conn.execute("INSERT INTO poll_run (started_at) VALUES (?)", (utcnow(),))
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_poll(
        self,
        run_id: int,
        users_seen: int,
        new_pending: int,
        new_preexisting: int,
        error: Optional[str] = None,
    ) -> None:
        self.conn.execute(
            "UPDATE poll_run SET finished_at = ?, users_seen = ?, new_pending = ?, "
            "new_preexisting = ?, error = ? WHERE id = ?",
            (utcnow(), users_seen, new_pending, new_preexisting, error, run_id),
        )
        self.conn.commit()

    def list_polls(self, limit: int = 20) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM poll_run ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
