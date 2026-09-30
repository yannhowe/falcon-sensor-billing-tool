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


class TestStoreHour:
    HOUR = "2026-04-21 10:00:00"

    def _sensors(self, ids):
        return [{"sensor_id": i, "tags": ["SensorGroupingTag/prod"]} for i in ids]

    def _log_ids(self, db, cid="cid1"):
        rows = db.get_connection().execute(
            "SELECT sensor_id FROM sensor_logs WHERE hour_timestamp = ? AND cid = ?",
            (self.HOUR, cid),
        ).fetchall()
        return sorted(r["sensor_id"] for r in rows)

    def test_writes_all_three_tables_in_one_hour(self, db):
        db.store_hour(self.HOUR, "cid1", self._sensors(["a", "b", "c"]), 3, 1, 0, 1, 1)

        [count] = db.get_hourly_counts_for_range(self.HOUR, self.HOUR, "cid1")
        tags = db.get_tag_counts_for_range(self.HOUR, self.HOUR, cid="cid1")
        assert self._log_ids(db) == ["a", "b", "c"]
        assert count["unique_sensor_count"] == 3
        assert count["fcsc_count"] == 1
        assert {t["tag"]: t["unique_sensor_count"] for t in tags} == {"SensorGroupingTag/prod": 3}

    def test_recollect_replaces_prior_rows(self, db):
        db.store_hour(self.HOUR, "cid1", self._sensors(["a", "b", "c"]), 3, 1, 0, 1, 1)
        db.store_hour(self.HOUR, "cid1", self._sensors(["a", "b"]), 2, 0, 0, 1, 1)

        [count] = db.get_hourly_counts_for_range(self.HOUR, self.HOUR, "cid1")
        assert self._log_ids(db) == ["a", "b"]
        assert count["unique_sensor_count"] == 2
        assert len(self._log_ids(db)) == count["unique_sensor_count"]

    def test_failure_midway_leaves_no_partial_or_orphan_rows(self, db, monkeypatch):
        # A good hour exists. A re-store fails after sensor_logs is written but before
        # hourly_counts, exactly where the non-transactional path left orphans.
        db.store_hour(self.HOUR, "cid1", self._sensors(["a", "b"]), 2, 0, 0, 1, 1)

        def boom(*args, **kwargs):
            raise RuntimeError("disk I/O error")

        monkeypatch.setattr(db, "_insert_hourly_count", boom)
        with pytest.raises(RuntimeError):
            db.store_hour(self.HOUR, "cid1", self._sensors(["a", "b", "c", "d"]), 4, 0, 0, 2, 2)

        # The whole re-store rolled back to the prior committed state.
        [count] = db.get_hourly_counts_for_range(self.HOUR, self.HOUR, "cid1")
        assert self._log_ids(db) == ["a", "b"]
        assert count["unique_sensor_count"] == 2
        assert len(self._log_ids(db)) == count["unique_sensor_count"]

    def _tag_sku_row(self, db, tag, cid="cid1"):
        return db.get_connection().execute(
            "SELECT unique_sensor_count, fcs_count, fcsc_count, fmc_count, epp_count "
            "FROM hourly_tag_counts WHERE hour_timestamp = ? AND tag = ? AND cid = ?",
            (self.HOUR, tag, cid),
        ).fetchone()

    def test_store_hour_records_per_tag_sku_breakdown(self, db):
        # Every sensor carries the same tag but a different SKU, so the tag's per-SKU
        # counts must split three ways and sum back to the unique sensor count.
        sensors = [{"sensor_id": i, "tags": ["prod"]} for i in ("a", "b", "c")]
        sku_by_sensor = {"a": "FCS", "b": "FCSC", "c": "FMC"}
        db.store_hour(self.HOUR, "cid1", sensors, 3, 1, 1, 1, 0, sku_by_sensor=sku_by_sensor)

        row = self._tag_sku_row(db, "prod")
        assert row["unique_sensor_count"] == 3
        assert (row["fcs_count"], row["fcsc_count"], row["fmc_count"], row["epp_count"]) == (1, 1, 1, 0)
        assert row["fcs_count"] + row["fcsc_count"] + row["fmc_count"] + row["epp_count"] == row["unique_sensor_count"]



class TestPruning:
    def test_prune_removes_old_data(self, db):
        old_ts = "2025-01-01 10:00:00"
        recent_ts = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")

        db.insert_hourly_count(old_ts, "default", 100)
        db.insert_hourly_count(recent_ts, "default", 200)

        result = db.prune(retain_days=30)
        assert result["hourly_counts"] >= 1

        counts = db.get_hourly_counts_for_range(
            "2025-01-01 00:00:00", "2099-12-31 23:59:59", "default"
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
        base = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) - timedelta(hours=671)
        for i in range(672):
            ts = (base + timedelta(hours=i)).strftime("%Y-%m-%d %H:%M:%S")
            db.insert_hourly_count(ts, "default", 100)

        avg = db.calculate_28day_average("default")["averages"]["total"]
        assert avg == 100.0

    def test_average_with_partial_data(self, db):
        base = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) - timedelta(hours=335)
        for i in range(336):
            ts = (base + timedelta(hours=i)).strftime("%Y-%m-%d %H:%M:%S")
            db.insert_hourly_count(ts, "default", 100)

        avg = db.calculate_28day_average("default")["averages"]["total"]
        assert avg == pytest.approx(50.0, abs=0.1)


class TestGetHostTagsForRange:
    def test_unions_tags_across_hours_and_normalizes_double_encoding(self, db):
        # Same host, two hours, different tags: the union is the attribution set.
        db.store_hour("2026-04-21 10:00:00", "cid1",
                      [{"sensor_id": "h1", "tags": ["team-a"]}], 1, 1, 0, 0, 0)
        db.store_hour("2026-04-21 11:00:00", "cid1",
                      [{"sensor_id": "h1", "tags": ["team-b"]}], 1, 1, 0, 0, 0)
        # A double-JSON-encoded tags column, as some collectors wrote.
        db.get_connection().execute(
            "UPDATE sensor_logs SET tags = ? WHERE sensor_id = 'h1' "
            "AND hour_timestamp = '2026-04-21 11:00:00'",
            (json.dumps(json.dumps(["team-b", "team-c"])),),
        )
        db.get_connection().commit()

        host_tags = db.get_host_tags_for_range(
            "2026-04-21 00:00:00", "2026-04-21 23:00:00", "cid1")

        assert sorted(host_tags["h1"]) == ["team-a", "team-b", "team-c"]

    def test_untagged_host_maps_to_empty_list(self, db):
        db.store_hour("2026-04-21 10:00:00", "cid1",
                      [{"sensor_id": "h1", "tags": []}], 1, 1, 0, 0, 0)

        host_tags = db.get_host_tags_for_range(
            "2026-04-21 00:00:00", "2026-04-21 23:00:00", "cid1")

        assert host_tags["h1"] == []
