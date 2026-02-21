"""
SQLite-based scan history persistence for vulnerability tracking.

Provides:
- ScanHistoryDB: Database operations for scan results
- Fingerprint tracking for NEW vulnerability detection
- Trend analysis (improving/degrading security posture)
"""

import os
import sqlite3
import logging
from datetime import datetime, timedelta
from threading import Lock
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TrendData:
    """Trend information for an image's security posture."""
    direction: str  # 'improving', 'degrading', 'stable', 'unknown'
    previous_total: int
    current_total: int
    delta_critical: int
    delta_high: int
    scan_count: int


class ScanHistoryDB:
    """SQLite database for persisting scan history and fingerprints."""

    SCHEMA = """
    -- Stores historical scan results
    CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image TEXT NOT NULL,
        image_digest TEXT NOT NULL,
        scan_timestamp DATETIME NOT NULL,
        scan_duration REAL,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        unknown_count INTEGER DEFAULT 0,
        total_count INTEGER DEFAULT 0,
        error TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_scan_image_digest ON scan_results(image_digest);
    CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_results(scan_timestamp);

    -- Tracks first detection of each fingerprint per image
    CREATE TABLE IF NOT EXISTS fingerprint_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image_digest TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        first_seen_at DATETIME NOT NULL,
        UNIQUE(image_digest, fingerprint)
    );

    CREATE INDEX IF NOT EXISTS idx_fingerprint_image ON fingerprint_history(image_digest);
    CREATE INDEX IF NOT EXISTS idx_fingerprint ON fingerprint_history(fingerprint);
    """

    def __init__(self, db_path: str = None):
        self._db_path = db_path or os.environ.get(
            'TRIVY_HISTORY_DB',
            '/data/scan_history.db'
        )
        self._lock = Lock()
        self._initialized = False
        self._enabled = os.environ.get('TRIVY_HISTORY_ENABLED', 'true').lower() == 'true'

    @property
    def is_enabled(self) -> bool:
        """Check if history tracking is enabled."""
        return self._enabled

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
        if not self._enabled:
            logger.debug("Scan history disabled, skipping initialization")
            return False

        if self._initialized:
            return True

        with self._lock:
            if self._initialized:
                return True

            try:
                # Ensure directory exists
                db_dir = os.path.dirname(self._db_path)
                if db_dir and not os.path.exists(db_dir):
                    os.makedirs(db_dir, exist_ok=True)

                with self._get_connection() as conn:
                    conn.executescript(self.SCHEMA)
                    conn.commit()

                self._initialized = True
                logger.info(f"Scan history database initialized at {self._db_path}")
                return True

            except Exception as e:
                logger.error(f"Failed to initialize scan history database: {e}")
                return False

    def save_scan_result(
        self,
        image: str,
        image_digest: str,
        scan_timestamp: datetime,
        scan_duration: float,
        critical: int,
        high: int,
        medium: int,
        low: int,
        unknown: int = 0,
        error: str = None
    ) -> Optional[int]:
        """
        Save scan result and return scan_result_id.

        Args:
            image: Image name
            image_digest: Image digest (sha256)
            scan_timestamp: When the scan was performed
            scan_duration: How long the scan took
            critical/high/medium/low/unknown: Vulnerability counts
            error: Error message if scan failed

        Returns:
            Scan result ID if saved, None if failed
        """
        if not self._enabled or not self.initialize():
            return None

        total = critical + high + medium + low + unknown

        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO scan_results
                    (image, image_digest, scan_timestamp, scan_duration,
                     critical_count, high_count, medium_count, low_count,
                     unknown_count, total_count, error)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (image, image_digest, scan_timestamp.isoformat(),
                     scan_duration, critical, high, medium, low, unknown, total, error)
                )
                conn.commit()
                return cursor.lastrowid

        except Exception as e:
            logger.error(f"Failed to save scan result for {image}: {e}")
            return None

    def check_fingerprint_is_new(
        self,
        image_digest: str,
        fingerprint: str
    ) -> Tuple[bool, Optional[datetime]]:
        """
        Check if a fingerprint is new for this image.

        Args:
            image_digest: Image digest to check
            fingerprint: Vulnerability fingerprint from Trivy

        Returns:
            (is_new, first_seen_at) tuple
        """
        if not self._enabled or not fingerprint or not self.initialize():
            return (False, None)

        try:
            with self._get_connection() as conn:
                row = conn.execute(
                    """
                    SELECT first_seen_at FROM fingerprint_history
                    WHERE image_digest = ? AND fingerprint = ?
                    """,
                    (image_digest, fingerprint)
                ).fetchone()

                if row:
                    return (False, datetime.fromisoformat(row['first_seen_at']))
                return (True, None)

        except Exception as e:
            logger.error(f"Failed to check fingerprint: {e}")
            return (False, None)

    def record_fingerprint(
        self,
        image_digest: str,
        fingerprint: str,
        cve_id: str,
        severity: str
    ) -> bool:
        """
        Record first detection of a fingerprint.

        Args:
            image_digest: Image digest
            fingerprint: Vulnerability fingerprint
            cve_id: CVE identifier
            severity: Vulnerability severity

        Returns:
            True if recorded, False if already exists or failed
        """
        if not self._enabled or not fingerprint or not self.initialize():
            return False

        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO fingerprint_history
                    (image_digest, fingerprint, cve_id, severity, first_seen_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (image_digest, fingerprint, cve_id, severity,
                     datetime.now().isoformat())
                )
                conn.commit()
                return True

        except Exception as e:
            logger.error(f"Failed to record fingerprint: {e}")
            return False

    def calculate_trend(self, image_digest: str) -> TrendData:
        """
        Calculate security trend based on last 2 scans.

        Args:
            image_digest: Image digest to analyze

        Returns:
            TrendData with direction and counts
        """
        if not self._enabled or not self.initialize():
            return TrendData('unknown', 0, 0, 0, 0, 0)

        try:
            with self._get_connection() as conn:
                rows = conn.execute(
                    """
                    SELECT critical_count, high_count, total_count
                    FROM scan_results
                    WHERE image_digest = ? AND error IS NULL
                    ORDER BY scan_timestamp DESC
                    LIMIT 2
                    """,
                    (image_digest,)
                ).fetchall()

                scan_count = len(rows)
                if scan_count < 2:
                    return TrendData('unknown', 0,
                                     rows[0]['total_count'] if rows else 0,
                                     0, 0, scan_count)

                current = rows[0]
                previous = rows[1]

                delta_critical = current['critical_count'] - previous['critical_count']
                delta_high = current['high_count'] - previous['high_count']
                delta_total = current['total_count'] - previous['total_count']

                if delta_total < 0:
                    direction = 'improving'
                elif delta_total > 0:
                    direction = 'degrading'
                else:
                    direction = 'stable'

                return TrendData(
                    direction=direction,
                    previous_total=previous['total_count'],
                    current_total=current['total_count'],
                    delta_critical=delta_critical,
                    delta_high=delta_high,
                    scan_count=scan_count
                )

        except Exception as e:
            logger.error(f"Failed to calculate trend: {e}")
            return TrendData('unknown', 0, 0, 0, 0, 0)

    def get_scan_history(
        self,
        image_digest: str,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Get recent scan history for an image.

        Args:
            image_digest: Image digest to query
            limit: Maximum number of results

        Returns:
            List of scan history entries
        """
        if not self._enabled or not self.initialize():
            return []

        try:
            with self._get_connection() as conn:
                rows = conn.execute(
                    """
                    SELECT image, image_digest, scan_timestamp, scan_duration,
                           critical_count, high_count, medium_count, low_count,
                           unknown_count, total_count, error
                    FROM scan_results
                    WHERE image_digest = ?
                    ORDER BY scan_timestamp DESC
                    LIMIT ?
                    """,
                    (image_digest, limit)
                ).fetchall()

                return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return []

    def get_new_vulnerabilities_since(
        self,
        hours: int = 24,
        severity: str = None
    ) -> List[Dict[str, Any]]:
        """
        Get fingerprints of vulnerabilities detected since a given time.

        Args:
            hours: Look back period in hours
            severity: Filter by severity (optional)

        Returns:
            List of new vulnerability records
        """
        if not self._enabled or not self.initialize():
            return []

        since = datetime.now() - timedelta(hours=hours)

        try:
            with self._get_connection() as conn:
                if severity:
                    rows = conn.execute(
                        """
                        SELECT image_digest, fingerprint, cve_id, severity, first_seen_at
                        FROM fingerprint_history
                        WHERE first_seen_at >= ? AND severity = ?
                        ORDER BY first_seen_at DESC
                        """,
                        (since.isoformat(), severity.upper())
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT image_digest, fingerprint, cve_id, severity, first_seen_at
                        FROM fingerprint_history
                        WHERE first_seen_at >= ?
                        ORDER BY first_seen_at DESC
                        """,
                        (since.isoformat(),)
                    ).fetchall()

                return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get new vulnerabilities: {e}")
            return []

    def cleanup_old_scans(self, days: int = 30) -> int:
        """
        Remove scan results older than specified days.

        Args:
            days: Keep scans newer than this many days

        Returns:
            Number of records removed
        """
        if not self._enabled or not self.initialize():
            return 0

        cutoff = datetime.now() - timedelta(days=days)

        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    DELETE FROM scan_results
                    WHERE scan_timestamp < ?
                    """,
                    (cutoff.isoformat(),)
                )
                conn.commit()
                return cursor.rowcount

        except Exception as e:
            logger.error(f"Failed to cleanup old scans: {e}")
            return 0

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        if not self._enabled or not self.initialize():
            return {'enabled': False}

        try:
            with self._get_connection() as conn:
                scan_count = conn.execute(
                    "SELECT COUNT(*) FROM scan_results"
                ).fetchone()[0]

                fingerprint_count = conn.execute(
                    "SELECT COUNT(*) FROM fingerprint_history"
                ).fetchone()[0]

                return {
                    'enabled': True,
                    'db_path': self._db_path,
                    'scan_results_count': scan_count,
                    'fingerprints_tracked': fingerprint_count
                }

        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {'enabled': True, 'error': str(e)}


# Singleton instance
scan_history_db = ScanHistoryDB()
