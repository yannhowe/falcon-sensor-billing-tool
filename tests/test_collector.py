"""Tests for falcon_billing.collector (integration with mocked APIs)."""

import json
import sys
from datetime import datetime, timedelta, timezone
from types import ModuleType
from unittest.mock import create_autospec, patch, MagicMock

import pytest
from falconpy import Hosts


def _stub_falconpy():
    """Insert a minimal falconpy stub into sys.modules so collector can be imported."""
    if "falconpy" not in sys.modules:
        stub = ModuleType("falconpy")
        stub.Hosts = MagicMock
        stub.OAuth2 = MagicMock
        stub.SensorDownload = MagicMock
        sys.modules["falconpy"] = stub


class TestEnrichSensorsWithHostDetails:
    def test_uses_cache_for_known_sensors(self, db):
        _stub_falconpy()
        from falcon_billing.collector import enrich_sensors_with_host_details

        db.update_host_cache(
            sensor_id="cached-sensor",
            hostname="cached-host",
            platform_name="Linux",
            platform_version="5.15",
            os_version="Ubuntu 22.04",
            status="online",
            groups=json.dumps([]),
            tags=json.dumps(["SensorGroupingTag/prod"]),
            cid="default",
            last_seen="2026-04-21T10:00:00Z",
        )

        mock_client = MagicMock()
        result = enrich_sensors_with_host_details(mock_client, db, ["cached-sensor"])

        mock_client.get_device_details.assert_not_called()
        assert "cached-sensor" in result
        assert result["cached-sensor"]["hostname"] == "cached-host"

    def test_queries_api_for_cache_misses(self, db):
        _stub_falconpy()
        from falcon_billing.collector import enrich_sensors_with_host_details

        mock_client = MagicMock()
        mock_client.get_device_details.return_value = {
            "status_code": 200,
            "body": {
                "resources": [{
                    "device_id": "new-sensor",
                    "hostname": "new-host",
                    "platform_name": "Windows",
                    "platform_version": "10.0",
                    "os_version": "Windows Server 2022",
                    "status": "online",
                    "groups": [],
                    "tags": ["SensorGroupingTag/dev"],
                    "cid": "default",
                    "last_seen": "2026-04-21T10:00:00Z",
                }]
            },
        }

        result = enrich_sensors_with_host_details(mock_client, db, ["new-sensor"])
        mock_client.get_device_details.assert_called_once()
        assert "new-sensor" in result


HOUR = datetime(2026, 9, 28, 10, tzinfo=timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _hour_str(dt):
    return dt.strftime("%Y-%m-%d %H:00:00")


class FakeFalcon:
    def __init__(self):
        self.heartbeats = {}
        self.container_hosts = []
        self.devices = {}
        self.queries = []
        self.hosts = create_autospec(Hosts, instance=True)
        self.hosts.get_device_details.side_effect = self._device_details

    def sensor(self, hour, aid, **fields):
        self.heartbeats.setdefault(_iso(hour), []).append(aid)
        self.devices[aid] = {
            "device_id": aid, "hostname": f"host-{aid}", "platform_name": "Linux",
            "tags": [], "groups": [], "cid": "cid1", **fields,
        }

    def _device_details(self, ids):
        return {"status_code": 200, "body": {"resources": [self.devices[i] for i in ids if i in self.devices]}}

    def execute(self, hour_start, hour_end, cid, *, query_string, **_):
        self.queries.append((hour_start, hour_end, query_string))
        if "SensorHeartbeat" in query_string:
            if hour_start not in self.heartbeats:
                raise RuntimeError(f"NG-SIEM rejected query for {hour_start}")
            return self.heartbeats[hour_start]
        if self.container_hosts is None:
            raise TimeoutError("container host query timed out")
        return self.container_hosts


@pytest.fixture
def falcon(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "test-id")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("FALCON_CLOUD_REGION", "us-1")
    fake = FakeFalcon()
    monkeypatch.setattr("falcon_billing.ngsiem._execute_ngsiem_query", fake.execute)
    monkeypatch.setattr("falcon_billing.ngsiem.time.sleep", lambda _: None)
    return fake


def _logged_sensor_ids(db, hour):
    rows = db.get_connection().execute(
        "SELECT sensor_id FROM sensor_logs WHERE hour_timestamp = ?", (_hour_str(hour),)
    ).fetchall()
    return sorted(r["sensor_id"] for r in rows)


def _counted_hours(db):
    rows = db.get_connection().execute("SELECT hour_timestamp FROM hourly_counts").fetchall()
    return sorted(r["hour_timestamp"] for r in rows)


class TestProcessHourlyCollection:
    def test_stores_hourly_count_and_sensor_logs(self, db, falcon):
        from falcon_billing.collector import process_hourly_collection

        for aid in ("a", "b", "c"):
            falcon.sensor(HOUR, aid)
        falcon.container_hosts = ["a"]

        total, _, _ = process_hourly_collection(db, HOUR, "cid1", falcon.hosts)

        assert total == 3
        [row] = db.get_hourly_counts_for_range(_hour_str(HOUR), _hour_str(HOUR), cid="cid1")
        assert row["unique_sensor_count"] == 3
        assert _logged_sensor_ids(db, HOUR) == ["a", "b", "c"]


class TestParallelBackfill:
    def test_failed_hours_do_not_stop_the_rest_and_raise_at_the_end(self, db, falcon, monkeypatch):
        import falcon_billing.collector as collector

        hours = [HOUR + timedelta(hours=i) for i in range(4)]
        for hour in hours[:3]:
            falcon.sensor(hour, f"s{hour.hour}")

        real_store = collector.store_hour_data

        def store_failing_second_hour(db, hour, *args, **kwargs):
            if hour == hours[1]:
                raise RuntimeError("disk I/O error")
            return real_store(db, hour, *args, **kwargs)

        monkeypatch.setattr(collector, "store_hour_data", store_failing_second_hour)

        with pytest.raises(RuntimeError) as excinfo:
            collector.parallel_backfill(db, hours, "cid1", falcon.hosts, workers=2)

        assert _counted_hours(db) == [_hour_str(hours[0]), _hour_str(hours[2])]
        assert _hour_str(hours[1]) in str(excinfo.value)
        assert _hour_str(hours[3]) in str(excinfo.value)
