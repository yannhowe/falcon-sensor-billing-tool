"""Tests for falcon_billing.collector (integration with mocked APIs)."""

import csv
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


def _sku_counts(db, hour):
    [row] = db.get_hourly_counts_for_range(_hour_str(hour), _hour_str(hour), cid="cid1")
    counts = {sku: row[f"{sku}_count"] for sku in ("fcs", "epp", "fcsc", "fmc")}
    assert sum(counts.values()) == row["unique_sensor_count"]
    return counts


class TestContainerHostClassification:
    def test_no_container_hosts_means_zero_fcsc_not_substring_guesses(self, db, falcon):
        from falcon_billing.collector import process_hourly_collection

        falcon.sensor(HOUR, "office", tags=["SensorGroupingTag/oaks-office"],
                      product_type_desc="Workstation", system_manufacturer="Dell Inc.")
        falcon.sensor(HOUR, "vm", system_manufacturer="VMware, Inc.")
        falcon.container_hosts = []

        process_hourly_collection(db, HOUR, "cid1", falcon.hosts)

        assert _sku_counts(db, HOUR) == {"fcs": 1, "epp": 1, "fcsc": 0, "fmc": 0}

    def test_every_pod_sensor_is_fmc_with_or_without_container_events(self, db, falcon):
        from falcon_billing.collector import process_hourly_collection

        falcon.sensor(HOUR, "pod-quiet", product_type_desc="Pod")
        falcon.sensor(HOUR, "pod-oci", product_type_desc="Pod")
        falcon.sensor(HOUR, "node", product_type_desc="Server")
        falcon.sensor(HOUR, "laptop", product_type_desc="Workstation")
        falcon.container_hosts = ["node", "pod-oci"]

        process_hourly_collection(db, HOUR, "cid1", falcon.hosts)

        assert _sku_counts(db, HOUR) == {"fcs": 0, "epp": 1, "fcsc": 1, "fmc": 2}

    def test_failed_container_query_falls_back_to_metadata(self, db, falcon):
        from falcon_billing.collector import process_hourly_collection

        falcon.sensor(HOUR, "k8s-node", platform_name="K8S")
        falcon.sensor(HOUR, "laptop", platform_name="Windows", hostname="DESKTOP-1")
        falcon.container_hosts = None

        process_hourly_collection(db, HOUR, "cid1", falcon.hosts)

        assert _sku_counts(db, HOUR) == {"fcs": 0, "epp": 1, "fcsc": 1, "fmc": 0}

    def test_container_query_covers_25h_of_container_info_ending_at_hour_end(self, db, falcon):
        from falcon_billing.collector import process_hourly_collection

        falcon.sensor(HOUR, "a")
        hour_end = HOUR + timedelta(hours=1)

        process_hourly_collection(db, HOUR, "cid1", falcon.hosts)

        [(start, end, query)] = [q for q in falcon.queries if "SensorHeartbeat" not in q[2]]
        assert (start, end) == (_iso(hour_end - timedelta(hours=25)), _iso(hour_end))
        assert "#event_simpleName=OciContainerInfo" in query
        assert "Oci*" not in query


class TestGapDetection:
    def test_hours_already_in_sensor_logs_are_not_recollected(self, db):
        from falcon_billing.collector import get_hours_to_collect

        # Two complete hours inside the lookback, stored in the same "YYYY-MM-DD HH:00:00"
        # format store_hour_data writes. Gap detection must recognise and skip them.
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        stored = [now - timedelta(hours=2), now - timedelta(hours=3)]
        conn = db.get_connection()
        for h in stored:
            conn.execute(
                "INSERT INTO sensor_logs (hour_timestamp, sensor_id, cid, collected_at) "
                "VALUES (?, ?, ?, ?)",
                (_hour_str(h), f"s-{h.hour}", "default", "2026-01-01T00:00:00"),
            )
        conn.commit()

        missing = {_hour_str(h) for h in get_hours_to_collect(2, db)}

        for h in stored:
            assert _hour_str(h) not in missing

    def test_missing_hours_are_still_returned(self, db):
        from falcon_billing.collector import get_hours_to_collect

        # An empty db must report every complete hour in the window as missing.
        missing = get_hours_to_collect(1, db)
        assert len(missing) == 24


class TestReCollectReplacesHour:
    def test_recollect_replaces_sensor_logs_and_counts(self, db, falcon):
        from falcon_billing.collector import process_hourly_collection

        for aid in ("a", "b", "c"):
            falcon.sensor(HOUR, aid)
        falcon.container_hosts = []
        process_hourly_collection(db, HOUR, "cid1", falcon.hosts)

        # The fleet shrinks; re-collecting the same hour must drop the departed host,
        # not leave it behind the way INSERT OR IGNORE did.
        falcon.heartbeats.clear()
        falcon.devices.clear()
        for aid in ("a", "b"):
            falcon.sensor(HOUR, aid)
        process_hourly_collection(db, HOUR, "cid1", falcon.hosts)

        [row] = db.get_hourly_counts_for_range(_hour_str(HOUR), _hour_str(HOUR), cid="cid1")
        assert _logged_sensor_ids(db, HOUR) == ["a", "b"]
        assert row["unique_sensor_count"] == 2
        assert len(_logged_sensor_ids(db, HOUR)) == row["unique_sensor_count"]


def _seed_reconcile_hours(db, cid, total, fcsc, fmc, fcs, epp, n_hours=24):
    """Store n_hours identical recent hours. With a 1-day window (period_hours=24),
    24 equal hours make each SKU's rolling average equal its per-hour count, so the
    reconciliation gap against a billed row is trivial to reason about."""
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    for i in range(n_hours):
        hour = (now - timedelta(hours=i)).strftime("%Y-%m-%d %H:%M:%S")
        db.store_hour(hour, cid, [], total, fcsc, fmc, fcs, epp)


class TestGenerateReconciliation:
    def test_per_sku_gap_and_direction_against_billed(self, tmp_path, db):
        from falcon_billing.collector import generate_reconciliation

        # Tool estimate: FCS=2, FCSC=1, FMC=0, EPP=0 (24 equal hours, 1-day window).
        _seed_reconcile_hours(db, "cid1", total=3, fcsc=1, fmc=0, fcs=2, epp=0)
        # Billed: FCS=3, FCSC=1, FMC=0, EPP=servers 2 + workstations 1 = 3.
        db.insert_billing_average(
            "2026-09-28",
            {"cloud_vms": 3, "container_hosts": 1, "managed_containers": 0,
             "servers": 2, "workstations": 1},
            "cid1",
        )

        out = tmp_path / "recon.csv"
        result = generate_reconciliation(db, cid="cid1", days=1, output_path=str(out))

        assert result == str(out)
        with open(out) as f:
            rows = {r["sku"]: r for r in csv.DictReader(f)}

        assert rows["FCS"]["tool_estimate"] == "2.00"
        assert rows["FCS"]["billed"] == "3.00"
        assert rows["FCS"]["gap"] == "-1.00"
        assert rows["FCS"]["direction"] == "under"

        assert rows["FCSC"]["gap"] == "+0.00"
        assert rows["FCSC"]["direction"] == "match"

        # EPP is billed 3 (servers+workstations) but the tool collected none.
        assert rows["EPP"]["billed"] == "3.00"
        assert rows["EPP"]["tool_estimate"] == "0.00"
        assert rows["EPP"]["direction"] == "under"

    def test_hints_when_no_billed_row_stored(self, tmp_path, capsys, db):
        from falcon_billing.collector import generate_reconciliation

        _seed_reconcile_hours(db, "cid1", total=1, fcsc=1, fmc=0, fcs=0, epp=0)

        result = generate_reconciliation(db, cid="cid1", days=1,
                                         output_path=str(tmp_path / "recon.csv"))

        assert result is None
        assert not (tmp_path / "recon.csv").exists()
        err = capsys.readouterr().err
        assert "fetch-billing" in err


class TestGenerateFcscEvidence:
    def _seed_hosts(self, db, sensors, fcsc):
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        hour = now.strftime("%Y-%m-%d %H:%M:%S")
        db.store_hour(hour, "cid1", sensors, total=len(sensors),
                      fcsc_count=fcsc, fmc_count=0, fcs_count=0, epp_count=0)

    def test_rolls_evidence_up_per_tag_with_engines(self, tmp_path, db):
        from falcon_billing.collector import generate_fcsc_evidence

        self._seed_hosts(db, [
            {"sensor_id": "aid-docker", "tags": ["SensorGroupingTag/prod"]},
            {"sensor_id": "aid-started", "tags": ["SensorGroupingTag/prod"]},
        ], fcsc=2)

        evidence = {
            "aid-docker": {"names": ["web"], "images": ["sha256:aaa"],
                           "engines": ["docker"], "started_only": False},
            "aid-started": {"names": [], "images": [], "engines": [],
                            "started_only": True},
            # In NG-SIEM but never collected by the tool: a coverage gap.
            "aid-ghost": {"names": [], "images": [], "engines": [],
                          "started_only": True},
        }

        out = tmp_path / "evidence.csv"
        result = generate_fcsc_evidence(db, evidence, cid="cid1", days=1,
                                        output_path=str(out))

        assert result == str(out)
        with open(out) as f:
            rows = list(csv.DictReader(f))

        prod = [r for r in rows if r["tag"] == "SensorGroupingTag/prod"]
        assert {r["host"] for r in prod} == {"aid-dock…", "aid-star…"}
        docker_row = next(r for r in prod if r["engines"] == "docker")
        assert docker_row["images"] == "sha256:aaa"
        assert docker_row["started_only"] == "no"
        started_row = next(r for r in prod if r["started_only"] == "yes")
        assert started_row["engines"] == ""

        # The uncollected host is attributed to a distinct coverage bucket, not prod.
        ghost = [r for r in rows if r["tag"] == "(Not collected)"]
        assert len(ghost) == 1
        assert ghost[0]["host"] == "aid-ghos…"

    def test_masks_agent_ids_in_output(self, tmp_path, db):
        from falcon_billing.collector import generate_fcsc_evidence

        full_aid = "0123456789abcdef0123456789abcdef"
        self._seed_hosts(db, [{"sensor_id": full_aid,
                               "tags": ["SensorGroupingTag/prod"]}], fcsc=1)
        evidence = {full_aid: {"names": [], "images": ["img"],
                               "engines": ["docker"], "started_only": False}}

        out = tmp_path / "evidence.csv"
        generate_fcsc_evidence(db, evidence, cid="cid1", days=1, output_path=str(out))

        text = out.read_text()
        assert full_aid not in text
        assert "01234567…" in text
