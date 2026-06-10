#!/usr/bin/env python3
"""
SQLite database layer for Falcon Sensor Billing Tracker.

Manages 5 tables:
- sensor_logs: Granular sensor activity per hour with full host details and tags
- hourly_counts: Aggregated sensor counts per hour per CID
- hourly_tag_counts: Aggregated sensor counts per hour per tag (for sub-CID billing)
- host_metadata_cache: Cache of host details to avoid repeated API calls
- billing_averages: Official billing API data for verification

Database uses WAL mode for concurrency and unlimited retention.
"""

import sqlite3
import json
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict, Tuple

logger = logging.getLogger(__name__)

# Schema version for database migrations
SCHEMA_VERSION = 2


class BillingDatabase:
    """SQLite database manager for sensor billing data."""

    def __init__(self, db_path: str = None):
        """
        Initialize database connection and create schema if needed.

        Args:
            db_path: Path to SQLite database file. Defaults to sensor_billing.db in current dir.
        """
        if db_path is None:
            db_path = Path(__file__).parent / "sensor_billing.db"

        self.db_path = Path(db_path)
        self._ensure_database()

        # Security: Set restrictive file permissions on database (owner read/write only)
        if self.db_path.exists():
            import os
            os.chmod(self.db_path, 0o600)

    @contextmanager
    def get_connection(self):
        """Context manager providing a SQLite connection with row_factory set."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _ensure_database(self):
        """Create tables if not exist."""
        with self.get_connection() as conn:
            self._configure(conn)

            # Check if schema_version table exists
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
            )
            if cursor.fetchone() is None:
                # Fresh database - create everything
                self._create_schema(conn)
            else:
                # Verify schema version
                row = conn.execute("SELECT version FROM schema_version").fetchone()
                if row is None or row["version"] != SCHEMA_VERSION:
                    logger.warning(
                        "Schema version mismatch (expected %d, got %s). May need migration.",
                        SCHEMA_VERSION,
                        row["version"] if row else "None",
                    )

        self._migrate_add_detection_metadata()

    def _migrate_add_detection_metadata(self):
        """Add detection_metadata column to host_metadata_cache if it doesn't exist."""
        with self.get_connection() as conn:
            # Check if column exists
            cursor = conn.execute("PRAGMA table_info(host_metadata_cache)")
            columns = [row[1] for row in cursor.fetchall()]

            if 'detection_metadata' not in columns:
                logger.info("Adding detection_metadata column to host_metadata_cache...")
                conn.execute("""
                    ALTER TABLE host_metadata_cache
                    ADD COLUMN detection_metadata TEXT
                """)
                # Update schema_version so startup no longer warns about a version mismatch
                conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))
                logger.info("✓ Schema migration complete (schema_version updated to %d)", SCHEMA_VERSION)
            else:
                logger.debug("detection_metadata column already exists")

    def _configure(self, conn: sqlite3.Connection):
        """Apply SQLite performance and reliability settings."""
        # WAL mode for better concurrency (readers don't block writers)
        conn.execute("PRAGMA journal_mode=WAL")
        # Foreign key enforcement
        conn.execute("PRAGMA foreign_keys=ON")

    def _create_schema(self, conn: sqlite3.Connection):
        """Create all tables and indexes from scratch."""

        # Schema version tracking
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            )
        """)

        # Table 1: sensor_logs - Granular sensor activity per hour
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sensor_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hour_timestamp TEXT NOT NULL,
                sensor_id TEXT NOT NULL,
                hostname TEXT,
                platform_name TEXT,
                platform_version TEXT,
                os_version TEXT,
                status TEXT,
                last_seen TEXT,
                groups TEXT,
                tags TEXT,
                cid TEXT,
                collected_at TEXT NOT NULL,
                UNIQUE (hour_timestamp, sensor_id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sensor_logs_hour_cid ON sensor_logs (hour_timestamp, cid)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sensor_logs_sensor_id ON sensor_logs (sensor_id)")

        # Table 2: hourly_counts - Aggregated sensor counts per hour per CID
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hourly_counts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hour_timestamp TEXT NOT NULL,
                cid TEXT NOT NULL,
                unique_sensor_count INTEGER NOT NULL,
                collected_at TEXT NOT NULL,
                UNIQUE (hour_timestamp, cid)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hourly_counts_hour ON hourly_counts (hour_timestamp)")

        # Table 3: hourly_tag_counts - Aggregated sensor counts per hour per tag
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hourly_tag_counts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hour_timestamp TEXT NOT NULL,
                tag TEXT NOT NULL,
                cid TEXT NOT NULL,
                unique_sensor_count INTEGER NOT NULL,
                collected_at TEXT NOT NULL,
                UNIQUE (hour_timestamp, tag, cid)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hourly_tag_counts_hour_cid ON hourly_tag_counts (hour_timestamp, cid)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hourly_tag_counts_tag ON hourly_tag_counts (tag)")

        # Table 4: host_metadata_cache - Cache of host details
        conn.execute("""
            CREATE TABLE IF NOT EXISTS host_metadata_cache (
                sensor_id TEXT PRIMARY KEY,
                hostname TEXT,
                platform_name TEXT,
                platform_version TEXT,
                os_version TEXT,
                status TEXT,
                groups TEXT,
                tags TEXT,
                cid TEXT,
                last_updated TEXT NOT NULL,
                last_seen TEXT,
                detection_metadata TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_host_cache_last_updated ON host_metadata_cache (last_updated)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_host_cache_sensor_cid ON host_metadata_cache (sensor_id, cid)")

        # Table 5: billing_averages - Official billing API data
        conn.execute("""
            CREATE TABLE IF NOT EXISTS billing_averages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                managed_containers REAL,
                cloud_vms REAL,
                container_hosts REAL,
                servers REAL,
                workstations REAL,
                mobile REAL,
                chrome_os REAL,
                public_cloud_containers REAL,
                server_containers REAL,
                cid TEXT,
                retrieved_at TEXT NOT NULL,
                UNIQUE (date, cid)
            )
        """)

        # Insert schema version
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))

        logger.info("Created database schema version %d at %s", SCHEMA_VERSION, self.db_path)

    # ========================================================================
    # Cache Management Functions
    # ========================================================================

    def get_cached_host(self, sensor_id: str, max_age_hours: int = 24) -> Optional[Dict]:
        """
        Retrieve host metadata from cache if fresh enough.

        Args:
            sensor_id: Agent ID / Host ID
            max_age_hours: Maximum age of cache entry in hours (default 24)

        Returns:
            dict: Host metadata if cache hit and fresh, None otherwise
        """
        with self.get_connection() as conn:
            cutoff_time = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()

            row = conn.execute("""
                SELECT * FROM host_metadata_cache
                WHERE sensor_id = ? AND last_updated >= ?
            """, (sensor_id, cutoff_time)).fetchone()

            if row:
                return dict(row)
            return None

    def update_host_cache(self, host_details: List[Dict]):
        """
        Bulk upsert host metadata into cache.

        Args:
            host_details: List of host detail dictionaries

        Note: detection_metadata is intentionally excluded from this upsert. It is a
        separate enrichment column populated by refine_cloud_classification.py (Task 6)
        after initial host discovery. Including it here would overwrite any previously
        enriched values with NULL on each cache refresh.
        """
        with self.get_connection() as conn:
            now = datetime.now(timezone.utc).isoformat()

            for host in host_details:
                conn.execute("""
                    INSERT INTO host_metadata_cache (
                        sensor_id, hostname, platform_name, platform_version,
                        os_version, status, groups, tags, cid, last_updated, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(sensor_id) DO UPDATE SET
                        hostname = excluded.hostname,
                        platform_name = excluded.platform_name,
                        platform_version = excluded.platform_version,
                        os_version = excluded.os_version,
                        status = excluded.status,
                        groups = excluded.groups,
                        tags = excluded.tags,
                        cid = excluded.cid,
                        last_updated = excluded.last_updated,
                        last_seen = excluded.last_seen
                """, (
                    host.get('sensor_id'),
                    host.get('hostname'),
                    host.get('platform_name'),
                    host.get('platform_version'),
                    host.get('os_version'),
                    host.get('status'),
                    json.dumps(host.get('groups', [])),
                    json.dumps(host.get('tags', [])),
                    host.get('cid'),
                    now,
                    host.get('last_seen')
                ))

    def get_stale_cache_count(self, max_age_hours: int = 24) -> int:
        """
        Count cache entries older than threshold.

        Args:
            max_age_hours: Maximum age in hours

        Returns:
            int: Number of stale cache entries
        """
        with self.get_connection() as conn:
            cutoff_time = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()
            row = conn.execute("""
                SELECT COUNT(*) as count FROM host_metadata_cache
                WHERE last_updated < ?
            """, (cutoff_time,)).fetchone()
            return row['count']

    def cache_hit_rate(self, sensor_ids: List[str], max_age_hours: int = 24) -> Tuple[int, int, float]:
        """
        Calculate cache hit rate for a list of sensor IDs.

        Args:
            sensor_ids: List of sensor IDs to check
            max_age_hours: Maximum age for cache hit

        Returns:
            tuple: (hits, misses, hit_rate_percentage)
        """
        if not sensor_ids:
            return 0, 0, 0.0

        with self.get_connection() as conn:
            cutoff_time = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()

            # Use parameterized query with IN clause
            placeholders = ','.join('?' * len(sensor_ids))
            row = conn.execute(f"""
                SELECT COUNT(*) as hits FROM host_metadata_cache
                WHERE sensor_id IN ({placeholders}) AND last_updated >= ?
            """, (*sensor_ids, cutoff_time)).fetchone()

            hits = row['hits']
            misses = len(sensor_ids) - hits
            hit_rate = (hits / len(sensor_ids)) * 100 if sensor_ids else 0.0

            return hits, misses, hit_rate

    # ========================================================================
    # Sensor Logs Functions
    # ========================================================================

    def insert_sensor_logs(self, hour_timestamp: str, sensors: List[Dict], cid: str = 'default'):
        """
        Bulk insert sensor logs for a specific hour.

        Args:
            hour_timestamp: Clock hour in UTC (YYYY-MM-DD HH:00:00)
            sensors: List of sensor detail dictionaries
            cid: Child CID or 'default'
        """
        with self.get_connection() as conn:
            now = datetime.now(timezone.utc).isoformat()

            for sensor in sensors:
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO sensor_logs (
                            hour_timestamp, sensor_id, hostname, platform_name,
                            platform_version, os_version, status, last_seen,
                            groups, tags, cid, collected_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        hour_timestamp,
                        sensor.get('sensor_id'),
                        sensor.get('hostname'),
                        sensor.get('platform_name'),
                        sensor.get('platform_version'),
                        sensor.get('os_version'),
                        sensor.get('status'),
                        sensor.get('last_seen'),
                        json.dumps(sensor.get('groups', [])),
                        json.dumps(sensor.get('tags', [])),
                        cid,
                        now
                    ))
                except Exception as e:
                    logger.error(f"Failed to insert sensor log for {sensor.get('sensor_id')}: {e}")

    def get_sensor_logs_for_range(
        self,
        start_hour: str,
        end_hour: str,
        tags: Optional[List[str]] = None,
        cid: str = 'default'
    ) -> List[Dict]:
        """
        Query sensor logs for a date range with optional tag filtering.

        Args:
            start_hour: Start hour (inclusive)
            end_hour: End hour (inclusive)
            tags: Optional list of tags to filter by
            cid: Child CID or 'default'

        Returns:
            list: Sensor log records
        """
        with self.get_connection() as conn:
            if tags:
                # Complex query - filter by tags in JSON array
                query = """
                    SELECT * FROM sensor_logs
                    WHERE hour_timestamp >= ? AND hour_timestamp <= ?
                    AND cid = ?
                """
                rows = conn.execute(query, (start_hour, end_hour, cid)).fetchall()

                # Post-filter by tags (SQLite doesn't have native JSON array search)
                results = []
                for row in rows:
                    sensor_tags = json.loads(row['tags'])
                    if any(tag in sensor_tags for tag in tags):
                        results.append(dict(row))
                return results
            else:
                # Simple query - no tag filtering
                rows = conn.execute("""
                    SELECT * FROM sensor_logs
                    WHERE hour_timestamp >= ? AND hour_timestamp <= ?
                    AND cid = ?
                    ORDER BY hour_timestamp, sensor_id
                """, (start_hour, end_hour, cid)).fetchall()
                return [dict(row) for row in rows]

    # ========================================================================
    # Hourly Counts Functions
    # ========================================================================

    def insert_hourly_count(self, hour_timestamp: str, count: int, cid: str = 'default'):
        """
        Insert aggregated sensor count for a specific hour.

        Args:
            hour_timestamp: Clock hour in UTC
            count: Unique sensor count
            cid: Child CID or 'default'
        """
        with self.get_connection() as conn:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                INSERT OR REPLACE INTO hourly_counts (
                    hour_timestamp, cid, unique_sensor_count, collected_at
                ) VALUES (?, ?, ?, ?)
            """, (hour_timestamp, cid, count, now))

    def get_hourly_counts_for_range(
        self,
        start_hour: str,
        end_hour: str,
        cid: str = 'default'
    ) -> List[Dict]:
        """
        Query hourly counts for a date range.

        Args:
            start_hour: Start hour (inclusive)
            end_hour: End hour (inclusive)
            cid: Child CID or 'default'

        Returns:
            list: Hourly count records
        """
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM hourly_counts
                WHERE hour_timestamp >= ? AND hour_timestamp <= ?
                AND cid = ?
                ORDER BY hour_timestamp
            """, (start_hour, end_hour, cid)).fetchall()
            return [dict(row) for row in rows]

    def calculate_28day_average(
        self,
        end_date: str,
        cid: str = 'default',
        tag: Optional[str] = None
    ) -> float:
        """
        Calculate 28-day rolling average (672 hours).

        Args:
            end_date: End date (YYYY-MM-DD)
            cid: Child CID or 'default'
            tag: Optional tag for sub-CID billing

        Returns:
            float: Average sensor count over 672 hours
        """
        # Calculate 28 days back from end_date
        end_dt = datetime.strptime(end_date, '%Y-%m-%d')
        start_dt = end_dt - timedelta(days=28)

        start_hour = start_dt.strftime('%Y-%m-%d 00:00:00')
        end_hour = end_dt.strftime('%Y-%m-%d 23:59:59')

        with self.get_connection() as conn:
            if tag:
                # Query tag counts
                row = conn.execute("""
                    SELECT SUM(unique_sensor_count) as total FROM hourly_tag_counts
                    WHERE hour_timestamp >= ? AND hour_timestamp <= ?
                    AND cid = ? AND tag = ?
                """, (start_hour, end_hour, cid, tag)).fetchone()
            else:
                # Query total counts
                row = conn.execute("""
                    SELECT SUM(unique_sensor_count) as total FROM hourly_counts
                    WHERE hour_timestamp >= ? AND hour_timestamp <= ?
                    AND cid = ?
                """, (start_hour, end_hour, cid)).fetchone()

            total = row['total'] if row['total'] else 0
            return total / 672.0  # 28 days * 24 hours = 672 hours

    # ========================================================================
    # Tag Counts Functions
    # ========================================================================

    def aggregate_tag_counts(self, hour_timestamp: str, cid: str = 'default'):
        """
        Process sensor_logs for a given hour and create tag count aggregations.

        Args:
            hour_timestamp: Clock hour to aggregate
            cid: Child CID or 'default'
        """
        with self.get_connection() as conn:
            # Get all sensor logs for this hour
            rows = conn.execute("""
                SELECT sensor_id, tags FROM sensor_logs
                WHERE hour_timestamp = ? AND cid = ?
            """, (hour_timestamp, cid)).fetchall()

            # Build tag -> set(sensor_ids) mapping
            tag_sensors = {}
            for row in rows:
                sensor_id = row['sensor_id']
                tags_json = row['tags']

                # Parse JSON array
                try:
                    tags = json.loads(tags_json) if tags_json else []
                except (json.JSONDecodeError, TypeError):
                    tags = []

                # Handle both list and string
                if isinstance(tags, str):
                    tags = [tags]
                elif not isinstance(tags, list):
                    tags = []

                for tag in tags:
                    if tag not in tag_sensors:
                        tag_sensors[tag] = set()
                    tag_sensors[tag].add(sensor_id)

            # Bulk insert tag counts
            now = datetime.now(timezone.utc).isoformat()
            for tag, sensor_set in tag_sensors.items():
                conn.execute("""
                    INSERT OR REPLACE INTO hourly_tag_counts (
                        hour_timestamp, tag, cid, unique_sensor_count, collected_at
                    ) VALUES (?, ?, ?, ?, ?)
                """, (hour_timestamp, tag, cid, len(sensor_set), now))

    def get_tag_counts_for_range(
        self,
        start_hour: str,
        end_hour: str,
        tags: Optional[List[str]] = None,
        cid: str = 'default'
    ) -> List[Dict]:
        """
        Query pre-aggregated tag counts for a date range.

        Args:
            start_hour: Start hour (inclusive)
            end_hour: End hour (inclusive)
            tags: Optional list of specific tags to query
            cid: Child CID or 'default'

        Returns:
            list: Tag count records
        """
        with self.get_connection() as conn:
            if tags:
                placeholders = ','.join('?' * len(tags))
                rows = conn.execute(f"""
                    SELECT * FROM hourly_tag_counts
                    WHERE hour_timestamp >= ? AND hour_timestamp <= ?
                    AND cid = ? AND tag IN ({placeholders})
                    ORDER BY hour_timestamp, tag
                """, (start_hour, end_hour, cid, *tags)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM hourly_tag_counts
                    WHERE hour_timestamp >= ? AND hour_timestamp <= ?
                    AND cid = ?
                    ORDER BY hour_timestamp, tag
                """, (start_hour, end_hour, cid)).fetchall()
            return [dict(row) for row in rows]

    # ========================================================================
    # Billing Averages Functions
    # ========================================================================

    def insert_billing_average(self, date: str, data: Dict, cid: str = 'default'):
        """
        Insert official billing API data.

        Args:
            date: Date from billing API
            data: Billing data dictionary
            cid: Child CID or 'default'
        """
        with self.get_connection() as conn:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                INSERT OR REPLACE INTO billing_averages (
                    date, managed_containers, cloud_vms, container_hosts,
                    servers, workstations, mobile, chrome_os,
                    public_cloud_containers, server_containers, cid, retrieved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                date,
                data.get('managed_containers'),
                data.get('cloud_vms'),
                data.get('container_hosts'),
                data.get('servers'),
                data.get('workstations'),
                data.get('mobile'),
                data.get('chrome_os'),
                data.get('public_cloud_containers'),
                data.get('server_containers'),
                cid,
                now
            ))

    def get_billing_average(self, date: str, cid: str = 'default') -> Optional[Dict]:
        """
        Retrieve billing API data for a specific date.

        Args:
            date: Date to query
            cid: Child CID or 'default'

        Returns:
            dict: Billing data if found, None otherwise
        """
        with self.get_connection() as conn:
            row = conn.execute("""
                SELECT * FROM billing_averages
                WHERE date = ? AND cid = ?
            """, (date, cid)).fetchone()
            return dict(row) if row else None

    def get_billing_summary(
        self,
        start_date: str,
        end_date: str,
        cid: str = 'default'
    ) -> List[Dict]:
        """
        Get billing summary for a date range.

        Args:
            start_date: Start date (inclusive)
            end_date: End date (inclusive)
            cid: Child CID or 'default'

        Returns:
            list: Billing average records
        """
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM billing_averages
                WHERE date >= ? AND date <= ? AND cid = ?
                ORDER BY date
            """, (start_date, end_date, cid)).fetchall()
            return [dict(row) for row in rows]

    # ========================================================================
    # Export Functions
    # ========================================================================

    def export_to_csv(self, query_result: List[Dict], output_path: str):
        """
        Export query results to CSV.

        Args:
            query_result: List of dictionaries
            output_path: Path to output CSV file
        """
        import csv

        if not query_result:
            logger.warning("No data to export")
            return

        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = query_result[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(query_result)

        logger.info(f"Exported {len(query_result)} rows to {output_path}")


if __name__ == "__main__":
    # Simple test
    logging.basicConfig(level=logging.INFO)
    db = BillingDatabase()
    print(f"✓ Database initialized at {db.db_path}")
