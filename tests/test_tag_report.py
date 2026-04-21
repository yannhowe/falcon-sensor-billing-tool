"""Tests for falcon-billing tag-report subcommand."""

import csv
import json
import sys
from types import ModuleType
from unittest.mock import patch, MagicMock

import pytest


def _stub_falconpy():
    """Insert a minimal falconpy stub into sys.modules so collector can be imported."""
    if "falconpy" not in sys.modules:
        stub = ModuleType("falconpy")
        stub.Hosts = MagicMock
        stub.OAuth2 = MagicMock
        stub.SensorDownload = MagicMock
        sys.modules["falconpy"] = stub


class TestTagReportCsvOutput:
    def test_csv_has_correct_headers(self, tmp_path, db):
        _stub_falconpy()
        from falcon_billing.cli.main import cmd_tag_report

        output_file = tmp_path / "tags.csv"
        args = MagicMock()
        args.db = db.db_path
        args.days = 1
        args.output = output_file
        args.cid = "default"

        with patch("falcon_billing.credentials.load_credentials") as mock_creds, \
             patch("falcon_billing.ngsiem.query_ngsiem_for_sensors") as mock_ngsiem, \
             patch("falcon_billing.collector.get_falcon_client") as mock_client, \
             patch("falcon_billing.collector.enrich_sensors_with_host_details") as mock_enrich:

            mock_creds.return_value = {"client_id": "id", "client_secret": "secret", "cloud_region": "us-1"}
            mock_ngsiem.return_value = ["sensor-1", "sensor-2", "sensor-3"]
            mock_client.return_value = MagicMock()
            mock_enrich.return_value = {
                "sensor-1": {"tags": json.dumps(["SensorGroupingTag/prod"])},
                "sensor-2": {"tags": json.dumps(["SensorGroupingTag/prod"])},
                "sensor-3": {"tags": json.dumps(["SensorGroupingTag/dev"])},
            }

            cmd_tag_report(args)

        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert reader.fieldnames == ["tag", "unique_hosts", "28day_avg_licenses", "percentage"]
        assert len(rows) == 2
        assert rows[0]["tag"] == "SensorGroupingTag/prod"
        assert rows[0]["unique_hosts"] == "2"
        assert rows[1]["tag"] == "SensorGroupingTag/dev"
        assert rows[1]["unique_hosts"] == "1"

    def test_untagged_sensors_grouped(self, tmp_path, db):
        _stub_falconpy()
        from falcon_billing.cli.main import cmd_tag_report

        output_file = tmp_path / "tags.csv"
        args = MagicMock()
        args.db = db.db_path
        args.days = 1
        args.output = output_file
        args.cid = "default"

        with patch("falcon_billing.credentials.load_credentials") as mock_creds, \
             patch("falcon_billing.ngsiem.query_ngsiem_for_sensors") as mock_ngsiem, \
             patch("falcon_billing.collector.get_falcon_client") as mock_client, \
             patch("falcon_billing.collector.enrich_sensors_with_host_details") as mock_enrich:

            mock_creds.return_value = {"client_id": "id", "client_secret": "secret", "cloud_region": "us-1"}
            mock_ngsiem.return_value = ["sensor-1"]
            mock_client.return_value = MagicMock()
            mock_enrich.return_value = {"sensor-1": {"tags": json.dumps(["OtherTag/something"])}}

            cmd_tag_report(args)

        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        assert rows[0]["tag"] == "(untagged)"
        assert rows[0]["unique_hosts"] == "1"
