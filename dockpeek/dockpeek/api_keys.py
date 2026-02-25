"""
API key authentication for DockPeek Security.

Provides:
- ApiKeyDB: SQLite-backed API key storage with SHA-256 hashing
- api_keys_bp: Flask blueprint exposing key management endpoints (session auth only)

Key format: dpk_<64 hex chars> (68 chars total, high-entropy random token)
Keys are stored as SHA-256 hashes — plaintext is only returned at creation time.
"""

import hashlib
import logging
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from threading import Lock
from typing import Optional

from flask import Blueprint, jsonify, request
from flask_login import login_required

logger = logging.getLogger(__name__)


class ApiKeyDB:
    """SQLite database for API key storage and validation."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_hash TEXT NOT NULL UNIQUE,
        key_prefix TEXT NOT NULL,
        label TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        last_used_at TEXT,
        is_active INTEGER DEFAULT 1,
        created_by TEXT DEFAULT 'admin'
    );
    """

    def __init__(self, db_path: str = None):
        self._db_path = db_path or os.environ.get(
            'API_KEYS_DB',
            '/app/data/dockpeek_api_keys.db'
        )
        # Ensure the directory exists
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._lock = Lock()
        self._initialized = False

    @contextmanager
    def _get_connection(self):
        """Get a database connection with automatic cleanup."""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def initialize(self) -> bool:
        """Initialize database schema if needed."""
        if self._initialized:
            return True

        with self._lock:
            if self._initialized:
                return True

            try:
                db_dir = os.path.dirname(self._db_path)
                if db_dir and not os.path.exists(db_dir):
                    os.makedirs(db_dir, exist_ok=True)

                with self._get_connection() as conn:
                    conn.executescript(self.SCHEMA)
                    conn.commit()

                self._initialized = True
                logger.info(f"API keys database initialized at {self._db_path}")
                return True

            except Exception as e:
                logger.error(f"Failed to initialize API keys database: {e}")
                return False

    @staticmethod
    def _hash_key(plaintext_key: str) -> str:
        """Return SHA-256 hex digest of a plaintext API key."""
        return hashlib.sha256(plaintext_key.encode()).hexdigest()

    @staticmethod
    def _generate_key() -> str:
        """Generate a new API key: dpk_ prefix + 64 hex chars."""
        return f"dpk_{secrets.token_hex(32)}"

    def create_key(self, label: str, expires_in_seconds: int) -> tuple[int, str]:
        """
        Create a new API key.

        Args:
            label: Human-readable label for this key.
            expires_in_seconds: TTL from now in seconds.

        Returns:
            (key_id, plaintext_key) — plaintext is only available here.
        """
        if not self.initialize():
            raise RuntimeError("API keys database unavailable")

        plaintext = self._generate_key()
        key_hash = self._hash_key(plaintext)
        key_prefix = plaintext[:8]  # "dpk_a1b2" — first 8 chars
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=expires_in_seconds)

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO api_keys
                        (key_hash, key_prefix, label, created_at, expires_at, is_active, created_by)
                    VALUES (?, ?, ?, ?, ?, 1, 'admin')
                    """,
                    (key_hash, key_prefix, label, now.isoformat(), expires_at.isoformat())
                )
                conn.commit()
                key_id = cursor.lastrowid

        logger.info(f"Created API key id={key_id} prefix={key_prefix} label='{label}'")
        return key_id, plaintext

    def validate_key(self, plaintext_key: str) -> Optional[dict]:
        """
        Validate a submitted API key.

        Hashes the submitted value, looks up by hash, checks expiry and active
        status, then updates last_used_at.

        Args:
            plaintext_key: The raw key value from the X-API-Key header.

        Returns:
            Key info dict (id, prefix, label, expires_at) on success, None on failure.
        """
        if not plaintext_key or not self.initialize():
            return None

        key_hash = self._hash_key(plaintext_key)
        now = datetime.utcnow().isoformat()

        try:
            with self._get_connection() as conn:
                row = conn.execute(
                    """
                    SELECT id, key_prefix, label, expires_at, is_active
                    FROM api_keys
                    WHERE key_hash = ?
                    """,
                    (key_hash,)
                ).fetchone()

                if row is None:
                    return None

                if not row['is_active']:
                    logger.debug(f"Rejected revoked API key prefix={row['key_prefix']}")
                    return None

                if row['expires_at'] < now:
                    logger.debug(f"Rejected expired API key prefix={row['key_prefix']}")
                    return None

                # Update last_used_at (best-effort, no lock needed for this update)
                conn.execute(
                    "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                    (now, row['id'])
                )
                conn.commit()

                return {
                    'id': row['id'],
                    'prefix': row['key_prefix'],
                    'label': row['label'],
                    'expires_at': row['expires_at'],
                }

        except Exception as e:
            logger.error(f"Error validating API key: {e}")
            return None

    def list_keys(self) -> list[dict]:
        """
        Return all API keys without their hashes.

        Returns:
            List of dicts with id, prefix, label, created_at, expires_at,
            last_used_at, is_active.
        """
        if not self.initialize():
            return []

        try:
            with self._get_connection() as conn:
                rows = conn.execute(
                    """
                    SELECT id, key_prefix, label, created_at, expires_at,
                           last_used_at, is_active
                    FROM api_keys
                    ORDER BY created_at DESC
                    """
                ).fetchall()
                result = []
                for row in rows:
                    d = dict(row)
                    # Normalise field names for the frontend
                    d['prefix'] = d.pop('key_prefix', '')
                    d['revoked'] = not d.get('is_active', 1)
                    result.append(d)
                return result

        except Exception as e:
            logger.error(f"Error listing API keys: {e}")
            return []

    def revoke_key(self, key_id: int) -> bool:
        """
        Deactivate an API key by ID.

        Args:
            key_id: Primary key of the key to revoke.

        Returns:
            True if a row was updated, False if key not found or error.
        """
        if not self.initialize():
            return False

        try:
            with self._lock:
                with self._get_connection() as conn:
                    cursor = conn.execute(
                        "UPDATE api_keys SET is_active = 0 WHERE id = ?",
                        (key_id,)
                    )
                    conn.commit()
                    updated = cursor.rowcount > 0

            if updated:
                logger.info(f"Revoked API key id={key_id}")
            else:
                logger.warning(f"Revoke requested for unknown API key id={key_id}")
            return updated

        except Exception as e:
            logger.error(f"Error revoking API key id={key_id}: {e}")
            return False

    def cleanup_expired(self) -> int:
        """
        Delete keys that expired more than 7 days ago.

        Returns:
            Number of rows deleted.
        """
        if not self.initialize():
            return 0

        cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()

        try:
            with self._lock:
                with self._get_connection() as conn:
                    cursor = conn.execute(
                        "DELETE FROM api_keys WHERE expires_at < ?",
                        (cutoff,)
                    )
                    conn.commit()
                    deleted = cursor.rowcount

            if deleted:
                logger.info(f"Cleaned up {deleted} expired API key(s)")
            return deleted

        except Exception as e:
            logger.error(f"Error cleaning up expired API keys: {e}")
            return 0


# Module-level singleton
api_key_db = ApiKeyDB()


# ---------------------------------------------------------------------------
# Flask blueprint — management endpoints (session auth only via @login_required)
# ---------------------------------------------------------------------------

api_keys_bp = Blueprint('api_keys', __name__)


@api_keys_bp.route("/api/keys", methods=["POST"])
@login_required
def create_key():
    """Create a new API key. Returns the plaintext key — store it immediately."""
    body = request.get_json(silent=True) or {}
    label = body.get('label', '').strip()
    expires_in = body.get('expires_in', 86400)

    if not label:
        return jsonify({"error": "label is required"}), 400

    try:
        expires_in = int(expires_in)
        if expires_in <= 0:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"error": "expires_in must be a positive integer (seconds)"}), 400

    try:
        key_id, plaintext = api_key_db.create_key(label=label, expires_in_seconds=expires_in)
    except RuntimeError as e:
        logger.error(f"create_key failed: {e}")
        return jsonify({"error": "Database unavailable"}), 503

    expires_at = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()

    return jsonify({
        "success": True,
        "key": plaintext,
        "id": key_id,
        "prefix": plaintext[:8],
        "label": label,
        "expires_at": expires_at,
    }), 201


@api_keys_bp.route("/api/keys", methods=["GET"])
@login_required
def list_keys():
    """List all API keys (no hashes returned)."""
    keys = api_key_db.list_keys()
    return jsonify({"keys": keys}), 200


@api_keys_bp.route("/api/keys/<int:key_id>", methods=["DELETE"])
@login_required
def revoke_key(key_id: int):
    """Revoke an API key by ID."""
    success = api_key_db.revoke_key(key_id)
    if not success:
        return jsonify({"error": f"Key {key_id} not found"}), 404
    return jsonify({"success": True}), 200
