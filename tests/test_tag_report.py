"""Tests for falcon-billing tag-report subcommand (per-tag showback).

Each tag shows the full licenses it consumes, dividing sensor-hours by the same
full-period denominator the CID total uses. A host with several tags counts
fully under each, so the tag totals deliberately sum to more than the CID total.
There is no allocation and no percentage column.
"""

import argparse
import csv
from datetime import datetime, timedelta, timezone

import pytest

from falcon_billing.database import BillingDatabase

PIVOT_FIELDS = ["tag", "fcs_28day_avg", "fcsc_28day_avg", "fmc_28day_avg",
                "epp_28day_avg", "total_28day_avg"]


def _seed_hours(db, cid, sensors, sku_by_sensor, total, fcsc, fmc, fcs, epp, n_hours=24):
    """Store n_hours recent identical hours so a day's average is trivial to reason
    about: with a 1-day window (period_hours=24), seeding 24 equal hours makes each
    tag's average equal its per-hour count."""
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    for i in range(n_hours):
        hour = (now - timedelta(hours=i)).strftime("%Y-%m-%d %H:%M:%S")
        db.store_hour(hour, cid, sensors, total, fcsc, fmc, fcs, epp,
                      sku_by_sensor=sku_by_sensor)


def _report_args(db, tmp_path, cid="default"):
    return argparse.Namespace(
        db=db.db_path, days=1, cid=cid,
        output=tmp_path / "tags.csv", format="pivot",
    )


class TestTagReportShowback:
    def test_pivot_columns_are_showback_not_allocation(self, tmp_path, db):
        from falcon_billing.cli.main import cmd_tag_report

        sensors = [
            {"sensor_id": "p1", "tags": ["SensorGroupingTag/prod"]},
            {"sensor_id": "p2", "tags": ["SensorGroupingTag/prod"]},
            {"sensor_id": "d1", "tags": ["SensorGroupingTag/dev"]},
        ]
        _seed_hours(db, "cid1", sensors, {"p1": "FCS", "p2": "FCS", "d1": "FCSC"},
                    total=3, fcsc=1, fmc=0, fcs=2, epp=0)

        cmd_tag_report(_report_args(db, tmp_path, cid="cid1"))

        with open(tmp_path / "tags.csv") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert reader.fieldnames == PIVOT_FIELDS
        assert "percentage" not in reader.fieldnames
        # Ordered by total consumption descending: prod (2 hosts) then dev (1).
        assert rows[0]["tag"] == "SensorGroupingTag/prod"
        assert rows[0]["total_28day_avg"] == "2.0"
        assert rows[0]["fcs_28day_avg"] == "2.0"
        assert rows[1]["tag"] == "SensorGroupingTag/dev"
        assert rows[1]["total_28day_avg"] == "1.0"
        assert rows[1]["fcsc_28day_avg"] == "1.0"

    def test_untagged_hosts_group_under_no_tag(self, tmp_path, db):
        from falcon_billing.cli.main import cmd_tag_report

        sensors = [{"sensor_id": "u1", "tags": []}]
        _seed_hours(db, "cid1", sensors, {"u1": "EPP"},
                    total=1, fcsc=0, fmc=0, fcs=0, epp=1)

        cmd_tag_report(_report_args(db, tmp_path, cid="cid1"))

        with open(tmp_path / "tags.csv") as f:
            rows = list(csv.DictReader(f))

        assert len(rows) == 1
        assert rows[0]["tag"] == "(No Tag)"
        assert rows[0]["total_28day_avg"] == "1.0"

    def test_multi_tag_host_counts_fully_under_each_tag(self, db):
        """A shared host is the whole point of showback: it counts fully under
        every tag, so the tag totals exceed the single host it actually is."""
        sensors = [{"sensor_id": "h1",
                    "tags": ["SensorGroupingTag/team-a", "SensorGroupingTag/team-b"]}]
        _seed_hours(db, "cid1", sensors, {"h1": "FCSC"},
                    total=1, fcsc=1, fmc=0, fcs=0, epp=0)

        showback = db.calculate_tag_showback(cid="cid1", days=1)
        by_tag = {t["tag"]: t for t in showback["tags"]}

        assert by_tag["SensorGroupingTag/team-a"]["total"] == pytest.approx(1.0)
        assert by_tag["SensorGroupingTag/team-b"]["total"] == pytest.approx(1.0)
        # One host, but the tag totals sum to two. Deliberate.
        assert sum(t["total"] for t in showback["tags"]) == pytest.approx(2.0)


class TestTagReportBilledContext:
    def test_shows_billed_cid_total_when_stored(self, tmp_path, db, capsys):
        from falcon_billing.cli.main import cmd_tag_report

        sensors = [{"sensor_id": "p1", "tags": ["SensorGroupingTag/prod"]}]
        _seed_hours(db, "cid1", sensors, {"p1": "FCSC"},
                    total=1, fcsc=1, fmc=0, fcs=0, epp=0)
        db.insert_billing_average(
            "2026-09-28",
            {"cloud_vms": 10, "container_hosts": 5, "managed_containers": 2,
             "servers": 3, "workstations": 4},
            "cid1",
        )

        cmd_tag_report(_report_args(db, tmp_path, cid="cid1"))

        err = capsys.readouterr().err
        assert "Billed CID total" in err
        assert "exceed this by design" in err

    def test_hints_to_fetch_when_billed_total_absent(self, tmp_path, db, capsys):
        from falcon_billing.cli.main import cmd_tag_report

        sensors = [{"sensor_id": "p1", "tags": ["SensorGroupingTag/prod"]}]
        _seed_hours(db, "cid1", sensors, {"p1": "FCSC"},
                    total=1, fcsc=1, fmc=0, fcs=0, epp=0)

        cmd_tag_report(_report_args(db, tmp_path, cid="cid1"))

        err = capsys.readouterr().err
        assert "fetch-billing" in err
