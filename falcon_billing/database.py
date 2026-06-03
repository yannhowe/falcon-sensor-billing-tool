#!/usr/bin/env python3
"""
SQLite database layer for Falcon Sensor Billing Tracker.

Manages 6 tables:
- sensor_logs: Granular sensor activity per hour with full host details and tags
- hourly_counts: Aggregated sensor counts per hour per CID
- hourly_tag_counts: Aggregated sensor counts per hour per tag (for sub-CID billing)
- host_metadata_cache: Cache of host details to avoid repeated API calls
- billing_averages: Official billing API data for verification
- audit_log: Audit trail of actions performed against the database

Database uses WAL mode for concurrency and configurable data retention.
"""

import os
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

    def __init__(self, db_path=None, cache_ttl_hours=None):
        """
        Initialize database connection and create schema if needed.

        Args:
            db_path: Path to SQLite database file. Defaults to sensor_billing.db in current dir.
            cache_ttl_hours: TTL for host metadata cache entries in hours. Defaults to
                             CACHE_TTL_HOURS env var or 24.
        """
        if db_path is None:
            db_path = Path(__file__).parent.parent / "sensor_billing.db"

        self.db_path = Path(db_path)
        self.cache_ttl_hours = cache_ttl_hours or int(os.environ.get("CACHE_TTL_HOURS", "24"))
        self._connection = None
        self._ensure_database()

        # Security: Set restrictive file permissions on database (owner read/write only)
        if self.db_path.exists():
            os.chmod(self.db_path, 0o600)

    def get_connection(self) -> sqlite3.Connection:
        """
        Return a persistent SQLite connection with row_factory set.

        The connection is created once and reused for the lifetime of this
        BillingDatabase instance.
        """
        if self._connection is None:
            self._connection = sqlite3.connect(self.db_path)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
        return self._connection

    @contextmanager
    def _transact(self):
        """Context manager providing a SQLite connection with auto commit/rollback."""
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _ensure_database(self):
        """Create tables if not exist."""
        conn = self.get_connection()
        self._configure(conn)

        # Check if schema_version table exists
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
        )
        if cursor.fetchone() is None:
            # Fresh database - create everything
            self._create_schema(conn)
            conn.commit()
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
        self._migrate_add_audit_log()
        self._migrate_add_fcsc_count()
        self._migrate_add_fmc_count()
        self._migrate_add_fcs_count()
        self._migrate_add_manufacturer_cloud_provider()
        self._migrate_add_epp_count()
        self._migrate_add_product_type_desc()

        # After all migrations, ensure schema_version reflects current version
        row = conn.execute("SELECT version FROM schema_version").fetchone()
        if row and row["version"] != SCHEMA_VERSION:
            conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))
            conn.commit()
            logger.info("Schema version updated to %d", SCHEMA_VERSION)

    def _migrate_add_detection_metadata(self):
        """Add detection_metadata column to host_metadata_cache if it doesn't exist."""
        conn = self.get_connection()
        cursor = conn.execute("PRAGMA table_info(host_metadata_cache)")
        columns = [row[1] for row in cursor.fetchall()]

        if "detection_metadata" not in columns:
            logger.info("Adding detection_metadata column to host_metadata_cache...")
            conn.execute("""
                ALTER TABLE host_metadata_cache
                ADD COLUMN detection_metadata TEXT
            """)
            conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))
            conn.commit()
            logger.info(
                "Schema migration complete (schema_version updated to %d)", SCHEMA_VERSION
            )
        else:
            logger.debug("detection_metadata column already exists")

    def _migrate_add_audit_log(self):
        """Add audit_log table if it doesn't exist (idempotent)."""
        conn = self.get_connection()
        conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            action TEXT NOT NULL,
            details TEXT,
            source TEXT
        )""")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)"
        )
        conn.commit()

    def _migrate_add_fcsc_count(self):
        """Add fcsc_count column to hourly_counts if it doesn't exist.

        Handles rename from old 'container_host_count' name.
        """
        conn = self.get_connection()
        cursor = conn.execute("PRAGMA table_info(hourly_counts)")
        columns = [row[1] for row in cursor.fetchall()]
        if "fcsc_count" not in columns and "container_host_count" in columns:
            logger.info("Renaming container_host_count → fcsc_count in hourly_counts...")
            conn.execute("ALTER TABLE hourly_counts RENAME COLUMN container_host_count TO fcsc_count")
            conn.commit()
            logger.info("Migration complete: container_host_count renamed to fcsc_count")
        elif "fcsc_count" not in columns:
            logger.info("Adding fcsc_count column to hourly_counts...")
            conn.execute("ALTER TABLE hourly_counts ADD COLUMN fcsc_count INTEGER")
            conn.commit()
            logger.info("Migration complete: fcsc_count added to hourly_counts")

    def _migrate_add_fmc_count(self):
        """Add fmc_count column to hourly_counts if it doesn't exist."""
        conn = self.get_connection()
        cursor = conn.execute("PRAGMA table_info(hourly_counts)")
        columns = [row[1] for row in cursor.fetchall()]
        if "fmc_count" not in columns:
            logger.info("Adding fmc_count column to hourly_counts...")
            conn.execute("ALTER TABLE hourly_counts ADD COLUMN fmc_count INTEGER")
            conn.commit()
            logger.info("Migration complete: fmc_count added to hourly_counts")

    def _migrate_add_fcs_count(self):
        """Add fcs_count column to hourly_counts if it doesn't exist."""
        conn = self.get_connection()
        cursor = conn.execute("PRAGMA table_info(hourly_counts)")
        columns = [row[1] for row in cursor.fetchall()]
        if "fcs_count" not in columns:
            logger.info("Adding fcs_count column to hourly_counts...")
            conn.execute("ALTER TABLE hourly_counts ADD COLUMN fcs_count INTEGER")
            conn.commit()
            logger.info("Migration complete: fcs_count added to hourly_counts")

    def _migrate_add_manufacturer_cloud_provider(self):
        """Add manufacturer and cloud_provider columns to host_metadata_cache if they don't exist."""
        conn = self.get_connection()
        cursor = conn.execute("PRAGMA table_info(host_metadata_cache)")
        columns = [row[1] for row in cursor.fetchall()]
        if "manufacturer" not in columns:
            logger.info("Adding manufacturer column to host_metadata_cache...")
            conn.execute("ALTER TABLE host_metadata_cache ADD COLUMN manufacturer TEXT")
            conn.commit()
            logger.info("Migration complete: manufacturer added to host_metadata_cache")
        else:
            logger.debug("manufacturer column already exists")
        if "cloud_provider" not in columns:
            logger.info("Adding cloud_provider column to host_metadata_cache...")
            conn.execute("ALTER TABLE host_metadata_cache ADD COLUMN cloud_provider TEXT")
            conn.commit()
            logger.info("Migration complete: cloud_provider added to host_metadata_cache")
        else:
            logger.debug("cloud_provider column already exists")

    def _migrate_add_epp_count(self):
        """Add epp_count column to hourly_counts if it doesn't exist."""
        conn = self.get_connection()
        cursor = conn.execute("PRAGMA table_info(hourly_counts)")
        columns = [row[1] for row in cursor.fetchall()]
        if "epp_count" not in columns:
            logger.info("Adding epp_count column to hourly_counts...")
            conn.execute("ALTER TABLE hourly_counts ADD COLUMN epp_count INTEGER")
            conn.commit()
            logger.info("Migration complete: epp_count added to hourly_counts")
        else:
            logger.debug("epp_count column already exists")

    def _migrate_add_product_type_desc(self):
        """Add product_type_desc column to host_metadata_cache if it doesn't exist."""
        conn = self.get_connection()
        cursor = conn.execute("PRAGMA table_info(host_metadata_cache)")
        columns = [row[1] for row in cursor.fetchall()]
        if "product_type_desc" not in columns:
            logger.info("Adding product_type_desc column to host_metadata_cache...")
            conn.execute("ALTER TABLE host_metadata_cache ADD COLUMN product_type_desc TEXT")
            conn.commit()
            logger.info("Migration complete: product_type_desc added to host_metadata_cache")
        else:
            logger.debug("product_type_desc column already exists")

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
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sensor_logs_hour_cid ON sensor_logs (hour_timestamp, cid)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sensor_logs_sensor_id ON sensor_logs (sensor_id)"
        )

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
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hourly_counts_hour ON hourly_counts (hour_timestamp)"
        )

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
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hourly_tag_counts_hour_cid "
            "ON hourly_tag_counts (hour_timestamp, cid)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hourly_tag_counts_tag ON hourly_tag_counts (tag)"
        )

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
                detection_metadata TEXT,
                manufacturer TEXT,
                cloud_provider TEXT,
                product_type_desc TEXT
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_host_cache_last_updated "
            "ON host_metadata_cache (last_updated)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_host_cache_sensor_cid "
            "ON host_metadata_cache (sensor_id, cid)"
        )

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

    def get_cached_host(self, sensor_id: str) -> Optional[Dict]:
        """
        Retrieve host metadata from cache if fresh enough.

        Uses self.cache_ttl_hours to determine freshness.

        Args:
            sensor_id: Agent ID / Host ID

        Returns:
            dict: Host metadata if cache hit and fresh, None otherwise
        """
        conn = self.get_connection()
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=self.cache_ttl_hours)
        ).strftime("%Y-%m-%d %H:%M:%S")

        row = conn.execute(
            """
            SELECT * FROM host_metadata_cache
            WHERE sensor_id = ? AND last_updated >= ?
            """,
            (sensor_id, cutoff),
        ).fetchone()

        if row:
            return dict(row)
        return None

    def update_host_cache(
        self,
        sensor_id: str,
        hostname: str = None,
        platform_name: str = None,
        platform_version: str = None,
        os_version: str = None,
        status: str = None,
        groups: str = None,
        tags: str = None,
        cid: str = None,
        last_seen: str = None,
        manufacturer: str = None,
        cloud_provider: str = None,
        product_type_desc: str = None,
    ):
        """
        Upsert a single host's metadata into the cache.

        Args:
            sensor_id: Agent ID / Host ID (primary key)
            hostname: Hostname
            platform_name: OS platform name
            platform_version: OS platform version
            os_version: OS version string
            status: Sensor status
            groups: JSON-encoded list of groups
            tags: JSON-encoded list of tags
            cid: Child CID
            last_seen: Last-seen timestamp from the API
            manufacturer: system_manufacturer DMI string from Hosts API
            cloud_provider: cloud_provider IMDS field from Hosts API
            product_type_desc: product_type_desc from Hosts API (Server, Workstation, etc.)

        Note: detection_metadata is intentionally excluded from this upsert. It is a
        separate enrichment column populated after initial host discovery. Including it
        here would overwrite any previously enriched values with NULL on each cache refresh.
        """
        conn = self.get_connection()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            """
            INSERT INTO host_metadata_cache (
                sensor_id, hostname, platform_name, platform_version,
                os_version, status, groups, tags, cid, last_updated, last_seen,
                manufacturer, cloud_provider, product_type_desc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                last_seen = excluded.last_seen,
                manufacturer = excluded.manufacturer,
                cloud_provider = excluded.cloud_provider,
                product_type_desc = excluded.product_type_desc
            """,
            (
                sensor_id,
                hostname,
                platform_name,
                platform_version,
                os_version,
                status,
                groups,
                tags,
                cid,
                now,
                last_seen,
                manufacturer,
                cloud_provider,
                product_type_desc,
            ),
        )
        conn.commit()

    def update_host_cache_bulk(self, host_details: List[Dict]):
        """
        Bulk upsert host metadata into cache from a list of dicts.

        Args:
            host_details: List of host detail dictionaries with keys matching
                          the host_metadata_cache columns.
        """
        conn = self.get_connection()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        for host in host_details:
            conn.execute(
                """
                INSERT INTO host_metadata_cache (
                    sensor_id, hostname, platform_name, platform_version,
                    os_version, status, groups, tags, cid, last_updated, last_seen,
                    manufacturer, cloud_provider, product_type_desc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    last_seen = excluded.last_seen,
                    manufacturer = excluded.manufacturer,
                    cloud_provider = excluded.cloud_provider,
                    product_type_desc = excluded.product_type_desc
                """,
                (
                    host.get("sensor_id"),
                    host.get("hostname"),
                    host.get("platform_name"),
                    host.get("platform_version"),
                    host.get("os_version"),
                    host.get("status"),
                    json.dumps(host.get("groups", [])),
                    json.dumps(host.get("tags", [])),
                    host.get("cid"),
                    now,
                    host.get("last_seen"),
                    host.get("manufacturer"),
                    host.get("cloud_provider"),
                    host.get("product_type_desc"),
                ),
            )
        conn.commit()

    def get_stale_cache_count(self, max_age_hours: int = 24) -> int:
        """
        Count cache entries older than threshold.

        Args:
            max_age_hours: Maximum age in hours

        Returns:
            int: Number of stale cache entries
        """
        conn = self.get_connection()
        cutoff_time = (
            datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        ).strftime("%Y-%m-%d %H:%M:%S")
        row = conn.execute(
            """
            SELECT COUNT(*) as count FROM host_metadata_cache
            WHERE last_updated < ?
            """,
            (cutoff_time,),
        ).fetchone()
        return row["count"]

    def cache_hit_rate(
        self, sensor_ids: List[str], max_age_hours: int = 24
    ) -> Tuple[int, int, float]:
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

        conn = self.get_connection()
        cutoff_time = (
            datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        ).strftime("%Y-%m-%d %H:%M:%S")

        placeholders = ",".join("?" * len(sensor_ids))
        row = conn.execute(
            f"""
            SELECT COUNT(*) as hits FROM host_metadata_cache
            WHERE sensor_id IN ({placeholders}) AND last_updated >= ?
            """,
            (*sensor_ids, cutoff_time),
        ).fetchone()

        hits = row["hits"]
        misses = len(sensor_ids) - hits
        hit_rate = (hits / len(sensor_ids)) * 100 if sensor_ids else 0.0

        return hits, misses, hit_rate

    # ========================================================================
    # Sensor Logs Functions
    # ========================================================================

    def insert_sensor_logs(
        self, hour_timestamp: str, sensors: List[Dict], cid: str = "default"
    ):
        """
        Bulk insert sensor logs for a specific hour.

        Args:
            hour_timestamp: Clock hour in UTC (YYYY-MM-DD HH:00:00)
            sensors: List of sensor detail dictionaries
            cid: Child CID or 'default'
        """
        conn = self.get_connection()
        now = datetime.now(timezone.utc).isoformat()

        for sensor in sensors:
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO sensor_logs (
                        hour_timestamp, sensor_id, hostname, platform_name,
                        platform_version, os_version, status, last_seen,
                        groups, tags, cid, collected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        hour_timestamp,
                        sensor.get("sensor_id"),
                        sensor.get("hostname"),
                        sensor.get("platform_name"),
                        sensor.get("platform_version"),
                        sensor.get("os_version"),
                        sensor.get("status"),
                        sensor.get("last_seen"),
                        json.dumps(sensor.get("groups", [])),
                        json.dumps(sensor.get("tags", []))
                        if isinstance(sensor.get("tags", []), list)
                        else sensor.get("tags", "[]"),
                        cid,
                        now,
                    ),
                )
            except Exception as e:
                logger.error(
                    "Failed to insert sensor log for %s: %s", sensor.get("sensor_id"), e
                )
        conn.commit()

    def get_sensor_logs_for_range(
        self,
        start_hour: str,
        end_hour: str,
        tags: Optional[List[str]] = None,
        cid: str = "default",
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
        conn = self.get_connection()
        if tags:
            # Complex query - filter by tags in JSON array
            rows = conn.execute(
                """
                SELECT * FROM sensor_logs
                WHERE hour_timestamp >= ? AND hour_timestamp <= ?
                AND cid = ?
                """,
                (start_hour, end_hour, cid),
            ).fetchall()

            # Post-filter by tags (SQLite doesn't have native JSON array search)
            results = []
            for row in rows:
                sensor_tags = json.loads(row["tags"])
                if any(tag in sensor_tags for tag in tags):
                    results.append(dict(row))
            return results
        else:
            # Simple query - no tag filtering
            rows = conn.execute(
                """
                SELECT * FROM sensor_logs
                WHERE hour_timestamp >= ? AND hour_timestamp <= ?
                AND cid = ?
                ORDER BY hour_timestamp, sensor_id
                """,
                (start_hour, end_hour, cid),
            ).fetchall()
            return [dict(row) for row in rows]

    # ========================================================================
    # Hourly Counts Functions
    # ========================================================================

    def insert_hourly_count(
        self, hour_timestamp: str, cid: str, count: int,
        fcsc_count: int = None, fmc_count: int = None, fcs_count: int = None,
        epp_count: int = None
    ):
        """
        Insert aggregated sensor count for a specific hour.

        Args:
            hour_timestamp: Clock hour in UTC
            cid: Child CID or 'default'
            count: Total unique sensor count (all SensorHeartbeat AIDs)
            fcsc_count: FCSC — OCI events with ProductType!=Pod
            fmc_count: FMC — SensorHeartbeat with ProductType=Pod
            fcs_count: FCS — cloud VMs only (classified via manufacturer/cloud_provider)
            epp_count: EPP — on-prem endpoints (fcs_ids minus cloud VMs)
        """
        conn = self.get_connection()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT OR REPLACE INTO hourly_counts (
                hour_timestamp, cid, unique_sensor_count,
                fcsc_count, fmc_count, fcs_count, epp_count, collected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (hour_timestamp, cid, count, fcsc_count, fmc_count, fcs_count, epp_count, now),
        )
        conn.commit()

    def get_hourly_counts_for_range(
        self, start_hour: str, end_hour: str, cid: str = "default"
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
        conn = self.get_connection()
        rows = conn.execute(
            """
            SELECT hour_timestamp, cid, unique_sensor_count, collected_at,
                   COALESCE(fcsc_count, 0) AS fcsc_count,
                   COALESCE(fmc_count, 0) AS fmc_count,
                   COALESCE(fcs_count, 0) AS fcs_count,
                   COALESCE(epp_count, 0) AS epp_count
            FROM hourly_counts
            WHERE hour_timestamp >= ? AND hour_timestamp <= ?
            AND cid = ?
            ORDER BY hour_timestamp
            """,
            (start_hour, end_hour, cid),
        ).fetchall()
        return [dict(row) for row in rows]

    def calculate_28day_average(
        self, cid: str = "default", tag: Optional[str] = None, days: int = 28
    ) -> dict:
        """
        Calculate rolling average (default 28 days / 672 hours) from hourly_counts.

        Returns a dict with per-category averages (total, fcs, fcsc, fmc) and
        metadata about the window and data coverage.

        Args:
            cid: Child CID or 'default'
            tag: Optional tag for sub-CID billing (total only; fcs/fcsc/fmc not tracked per-tag)
            days: Rolling window in days (default 28)

        Returns:
            dict with keys: cid, period_days, period_hours, period_start, period_end,
            hours_with_data, averages (total/fcs/fcsc/fmc)
        """
        now = datetime.now(timezone.utc)
        end_dt = now
        start_dt = datetime(now.year, now.month, now.day, tzinfo=timezone.utc) - timedelta(days=days)

        start_hour = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        end_hour = end_dt.strftime("%Y-%m-%d %H:%M:%S")
        period_hours = days * 24

        conn = self.get_connection()
        if tag:
            row = conn.execute(
                """
                SELECT COUNT(*) as hours_with_data,
                       SUM(unique_sensor_count) as total_sum
                FROM hourly_tag_counts
                WHERE hour_timestamp >= ? AND hour_timestamp <= ?
                AND cid = ? AND tag = ?
                """,
                (start_hour, end_hour, cid, tag),
            ).fetchone()
            total = (row["total_sum"] or 0) / period_hours
            return {
                "cid": cid,
                "period_days": days,
                "period_hours": period_hours,
                "period_start": start_hour,
                "period_end": end_hour,
                "hours_with_data": row["hours_with_data"] or 0,
                "averages": {"total": total, "fcs": 0.0, "fcsc": 0.0, "fmc": 0.0, "epp": 0.0},
            }

        row = conn.execute(
            """
            SELECT COUNT(*) as hours_with_data,
                   SUM(unique_sensor_count) as total_sum,
                   SUM(COALESCE(fcs_count, 0)) as fcs_sum,
                   SUM(COALESCE(fcsc_count, 0)) as fcsc_sum,
                   SUM(COALESCE(fmc_count, 0)) as fmc_sum,
                   SUM(COALESCE(epp_count, 0)) as epp_sum
            FROM hourly_counts
            WHERE hour_timestamp >= ? AND hour_timestamp <= ? AND cid = ?
            """,
            (start_hour, end_hour, cid),
        ).fetchone()

        return {
            "cid": cid,
            "period_days": days,
            "period_hours": period_hours,
            "period_start": start_hour,
            "period_end": end_hour,
            "hours_with_data": row["hours_with_data"] or 0,
            "averages": {
                "total": (row["total_sum"] or 0) / period_hours,
                "fcs": (row["fcs_sum"] or 0) / period_hours,
                "fcsc": (row["fcsc_sum"] or 0) / period_hours,
                "fmc": (row["fmc_sum"] or 0) / period_hours,
                "epp": (row["epp_sum"] or 0) / period_hours,
            },
        }

    # ========================================================================
    # Tag Counts Functions
    # ========================================================================

    def aggregate_tag_counts(self, hour_timestamp: str, cid: str = "default"):
        """
        Process sensor_logs for a given hour and create tag count aggregations.

        Args:
            hour_timestamp: Clock hour to aggregate
            cid: Child CID or 'default'
        """
        conn = self.get_connection()
        rows = conn.execute(
            """
            SELECT sensor_id, tags FROM sensor_logs
            WHERE hour_timestamp = ? AND cid = ?
            """,
            (hour_timestamp, cid),
        ).fetchall()

        # Build tag -> set(sensor_ids) mapping
        tag_sensors = {}
        for row in rows:
            sensor_id = row["sensor_id"]
            tags_json = row["tags"]

            try:
                tags = json.loads(tags_json) if tags_json else []
            except (json.JSONDecodeError, TypeError):
                tags = []

            # Handle double JSON-encoded tags: json.loads returns a string
            # that needs a second parse to get the actual list
            if isinstance(tags, str):
                try:
                    tags = json.loads(tags)
                except (json.JSONDecodeError, TypeError):
                    tags = [tags]

            if not isinstance(tags, list):
                tags = []

            # Filter out empty strings from tag list
            tags = [t for t in tags if t]

            if not tags:
                tag_sensors.setdefault("(No Tag)", set()).add(sensor_id)
            else:
                for tag in tags:
                    tag_sensors.setdefault(tag, set()).add(sensor_id)

        # Bulk insert tag counts
        now = datetime.now(timezone.utc).isoformat()
        for tag, sensor_set in tag_sensors.items():
            conn.execute(
                """
                INSERT OR REPLACE INTO hourly_tag_counts (
                    hour_timestamp, tag, cid, unique_sensor_count, collected_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (hour_timestamp, tag, cid, len(sensor_set), now),
            )
        conn.commit()

    def get_tag_counts_for_range(
        self,
        start_hour: str,
        end_hour: str,
        tags: Optional[List[str]] = None,
        cid: str = "default",
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
        conn = self.get_connection()
        if tags:
            placeholders = ",".join("?" * len(tags))
            rows = conn.execute(
                f"""
                SELECT * FROM hourly_tag_counts
                WHERE hour_timestamp >= ? AND hour_timestamp <= ?
                AND cid = ? AND tag IN ({placeholders})
                ORDER BY hour_timestamp, tag
                """,
                (start_hour, end_hour, cid, *tags),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM hourly_tag_counts
                WHERE hour_timestamp >= ? AND hour_timestamp <= ?
                AND cid = ?
                ORDER BY hour_timestamp, tag
                """,
                (start_hour, end_hour, cid),
            ).fetchall()
        return [dict(row) for row in rows]

    # ========================================================================
    # Billing Averages Functions
    # ========================================================================

    def insert_billing_average(self, date: str, data: Dict, cid: str = "default"):
        """
        Insert official billing API data.

        Args:
            date: Date from billing API
            data: Billing data dictionary
            cid: Child CID or 'default'
        """
        conn = self.get_connection()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT OR REPLACE INTO billing_averages (
                date, managed_containers, cloud_vms, container_hosts,
                servers, workstations, mobile, chrome_os,
                public_cloud_containers, server_containers, cid, retrieved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                date,
                data.get("managed_containers"),
                data.get("cloud_vms"),
                data.get("container_hosts"),
                data.get("servers"),
                data.get("workstations"),
                data.get("mobile"),
                data.get("chrome_os"),
                data.get("public_cloud_containers"),
                data.get("server_containers"),
                cid,
                now,
            ),
        )
        conn.commit()

    def get_billing_average(self, date: str, cid: str = "default") -> Optional[Dict]:
        """
        Retrieve billing API data for a specific date.

        Args:
            date: Date to query
            cid: Child CID or 'default'

        Returns:
            dict: Billing data if found, None otherwise
        """
        conn = self.get_connection()
        row = conn.execute(
            """
            SELECT * FROM billing_averages
            WHERE date = ? AND cid = ?
            """,
            (date, cid),
        ).fetchone()
        return dict(row) if row else None

    def get_billing_summary(
        self, start_date: str, end_date: str, cid: str = "default"
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
        conn = self.get_connection()
        rows = conn.execute(
            """
            SELECT * FROM billing_averages
            WHERE date >= ? AND date <= ? AND cid = ?
            ORDER BY date
            """,
            (start_date, end_date, cid),
        ).fetchall()
        return [dict(row) for row in rows]

    # ========================================================================
    # Pruning Functions
    # ========================================================================

    def prune(self, retain_days: int = 395, dry_run: bool = False) -> Dict:
        """
        Remove old records from time-series tables.

        Args:
            retain_days: Keep records newer than this many days. Default 395 (~13 months).
            dry_run: If True, count rows that would be deleted without actually deleting.

        Returns:
            dict: Mapping of table name -> number of rows deleted (or would be deleted).
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=retain_days)
        ).strftime("%Y-%m-%d %H:%M:%S")
        conn = self.get_connection()
        result = {}
        tables = ["sensor_logs", "hourly_counts", "hourly_tag_counts"]
        for table in tables:
            cursor = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE hour_timestamp < ?", (cutoff,)
            )
            count = cursor.fetchone()[0]
            result[table] = count
            if not dry_run and count > 0:
                conn.execute(
                    f"DELETE FROM {table} WHERE hour_timestamp < ?", (cutoff,)
                )
        if not dry_run:
            conn.commit()
            conn.execute("VACUUM")
        return result

    # ========================================================================
    # Audit Log Functions
    # ========================================================================

    def log_audit(self, action: str, details: str = "", source: str = "cli"):
        """
        Insert an entry into the audit log.

        Args:
            action: Short action name (e.g. 'collect', 'export', 'prune')
            details: Free-form details string
            source: Caller identifier (e.g. 'cli', 'dashboard', 'cron')
        """
        conn = self.get_connection()
        conn.execute(
            "INSERT INTO audit_log (action, details, source) VALUES (?, ?, ?)",
            (action, details, source),
        )
        conn.commit()

    def get_audit_log(
        self,
        limit: int = 100,
        action: Optional[str] = None,
        since: Optional[str] = None,
    ) -> List[Dict]:
        """
        Query the audit log with optional filters.

        Args:
            limit: Maximum number of entries to return (most recent first).
            action: If provided, filter to this action type.
            since: If provided, return only entries with timestamp >= this value.

        Returns:
            list: Audit log entries as dicts, ordered newest first.
        """
        conn = self.get_connection()
        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        if action:
            query += " AND action = ?"
            params.append(action)
        if since:
            query += " AND timestamp >= ?"
            params.append(since)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

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

        with open(output_path, "w", newline="") as csvfile:
            fieldnames = query_result[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(query_result)

        logger.info("Exported %d rows to %s", len(query_result), output_path)
