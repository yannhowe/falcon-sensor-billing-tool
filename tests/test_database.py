"""Tests for falcon_billing.database."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from falcon_billing.database import BillingDatabase


class TestSchemaCreation:
    def test_creates_all_tables(self, db):
        conn = db.get_connection()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = sorted(row[0] for row in cursor.fetchall())
        assert "audit_log" in tables
        assert "billing_averages" in tables
        assert "host_metadata_cache" in tables
        assert "hourly_counts" in tables
        assert "hourly_tag_counts" in tables
        assert "sensor_logs" in tables

    def test_wal_mode_enabled(self, db):
        conn = db.get_connection()
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"


class TestHostMetadataCache:
    def test_cache_miss_returns_none(self, db):
        result = db.get_cached_host("nonexistent-sensor")
        assert result is None

    def test_cache_round_trip(self, db):
        db.update_host_cache(
            sensor_id="sensor-1",
            hostname="web-01",
            platform_name="Linux",
            platform_version="5.15",
            os_version="Ubuntu 22.04",
            status="online",
            groups=json.dumps(["group1"]),
            tags=json.dumps(["SensorGroupingTag/prod"]),
            cid="abc123",
            last_seen="2026-04-21T10:00:00Z",
        )
        result = db.get_cached_host("sensor-1")
        assert result is not None
        assert result["hostname"] == "web-01"
        assert result["platform_name"] == "Linux"

    def test_cache_expired(self, db):
        conn = db.get_connection()
        old_time = (datetime.now(timezone.utc) - timedelta(hours=25)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        conn.execute(
            "INSERT INTO host_metadata_cache "
            "(sensor_id, hostname, platform_name, cid, last_updated) "
            "VALUES (?, ?, ?, ?, ?)",
            ("sensor-old", "old-host", "Linux", "cid1", old_time),
        )
        conn.commit()
        result = db.get_cached_host("sensor-old")
        assert result is None

    def test_configurable_ttl(self, tmp_db_path):
        db = BillingDatabase(tmp_db_path, cache_ttl_hours=48)
        conn = db.get_connection()
        old_time = (datetime.now(timezone.utc) - timedelta(hours=30)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        conn.execute(
            "INSERT INTO host_metadata_cache "
            "(sensor_id, hostname, platform_name, cid, last_updated) "
            "VALUES (?, ?, ?, ?, ?)",
            ("sensor-30h", "host-30h", "Linux", "cid1", old_time),
        )
        conn.commit()
        result = db.get_cached_host("sensor-30h")
        assert result is not None


class TestHourlyCounts:
    def test_insert_and_query(self, db):
        db.insert_hourly_count("2026-04-21 10:00:00", "default", 250)
        db.insert_hourly_count("2026-04-21 11:00:00", "default", 260)
        counts = db.get_hourly_counts_for_range(
            "2026-04-21 00:00:00", "2026-04-21 23:59:59", "default"
        )
        assert len(counts) == 2
        assert counts[0]["unique_sensor_count"] == 250

    def test_upsert_on_duplicate(self, db):
        db.insert_hourly_count("2026-04-21 10:00:00", "default", 250)
        db.insert_hourly_count("2026-04-21 10:00:00", "default", 300)
        counts = db.get_hourly_counts_for_range(
            "2026-04-21 00:00:00", "2026-04-21 23:59:59", "default"
        )
        assert len(counts) == 1
        assert counts[0]["unique_sensor_count"] == 300


class TestPruning:
    def test_prune_removes_old_data(self, db):
        old_ts = "2025-01-01 10:00:00"
        recent_ts = "2026-04-21 10:00:00"

        db.insert_hourly_count(old_ts, "default", 100)
        db.insert_hourly_count(recent_ts, "default", 200)

        result = db.prune(retain_days=30)
        assert result["hourly_counts"] >= 1

        counts = db.get_hourly_counts_for_range(
            "2025-01-01 00:00:00", "2026-12-31 23:59:59", "default"
        )
        assert len(counts) == 1
        assert counts[0]["unique_sensor_count"] == 200

    def test_prune_dry_run(self, db):
        db.insert_hourly_count("2025-01-01 10:00:00", "default", 100)

        result = db.prune(retain_days=30, dry_run=True)
        assert result["hourly_counts"] >= 1

        counts = db.get_hourly_counts_for_range(
            "2025-01-01 00:00:00", "2025-12-31 23:59:59", "default"
        )
        assert len(counts) == 1


class TestAuditLog:
    def test_log_audit_entry(self, db):
        db.log_audit("collect", "Collected 250 sensors for hour 10:00", "cli")
        entries = db.get_audit_log(limit=10)
        assert len(entries) == 1
        assert entries[0]["action"] == "collect"
        assert entries[0]["source"] == "cli"
        assert "250 sensors" in entries[0]["details"]

    def test_filter_by_action(self, db):
        db.log_audit("collect", "hour 10", "cli")
        db.log_audit("export", "hourly csv", "dashboard")
        db.log_audit("collect", "hour 11", "cli")

        entries = db.get_audit_log(action="collect")
        assert len(entries) == 2
        assert all(e["action"] == "collect" for e in entries)

    def test_filter_by_since(self, db):
        db.log_audit("collect", "recent", "cli")
        entries = db.get_audit_log(since="2026-04-20")
        assert len(entries) == 1


class TestCalculate28DayAverage:
    def test_average_calculation(self, db):
        base = datetime(2026, 3, 24, 0, 0, 0)
        for i in range(672):
            ts = (base + timedelta(hours=i)).strftime("%Y-%m-%d %H:%M:%S")
            db.insert_hourly_count(ts, "default", 100)

        avg = db.calculate_28day_average("default")
        assert avg == 100.0

    def test_average_with_partial_data(self, db):
        base = datetime(2026, 4, 7, 0, 0, 0)
        for i in range(336):
            ts = (base + timedelta(hours=i)).strftime("%Y-%m-%d %H:%M:%S")
            db.insert_hourly_count(ts, "default", 100)

        avg = db.calculate_28day_average("default")
        assert avg == pytest.approx(50.0, abs=0.1)
