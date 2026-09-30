import argparse
import csv
from pathlib import Path
from unittest.mock import create_autospec, patch

import pytest
from falconpy import SensorUsage

TENANT_CID = "5DDB" + "0" * 24 + "9A1F-90"

HOURLY_BODY = {
    "resources": [
        {
            "date": "2026-09-28",
            "containers": 72.875,
            "public_cloud_with_containers": 70.0,
            "servers_with_containers": 2.875,
            "public_cloud_without_containers": 214.58,
            "servers_without_containers": 7.98,
            "workstations": 16.09,
            "mobile": 0.85,
            "lumos": 8.81,
        },
        {
            "date": "2026-09-27",
            "containers": 71.0,
            "public_cloud_without_containers": 200.0,
            "servers_without_containers": 7.0,
            "workstations": 15.0,
            "mobile": 0.8,
            "lumos": 8.0,
        },
    ],
}


@pytest.fixture
def sensor_usage(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "test-id")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("FALCON_CLOUD_REGION", "us-1")
    client_class = create_autospec(SensorUsage)
    with patch("falcon_billing.billing.SensorUsage", client_class):
        yield client_class.return_value


def _read_rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


class TestGenerateMultitenantReport:
    def test_writes_newest_hourly_row_for_normalized_cid(self, sensor_usage, tmp_path):
        from falcon_billing.billing import generate_multitenant_report

        sensor_usage.get_hourly_usage.return_value = {"status_code": 200, "body": HOURLY_BODY}

        report = generate_multitenant_report([(TENANT_CID, "tenant-a")], output_path=str(tmp_path))

        sensor_usage.get_hourly_usage.assert_called_once()
        filter_string = sensor_usage.get_hourly_usage.call_args.kwargs["filter"]
        assert "selected_cids:'5ddb" + "0" * 24 + "9a1f'" in filter_string
        assert Path(report).name.startswith("multitenant_chargeback_hourly_")
        assert _read_rows(report) == [{
            "tenant_name": "tenant-a",
            "cid": TENANT_CID,
            "date": "2026-09-28",
            "container_hosts": "72.875",
            "managed_containers": "8.81",
            "cloud_vms": "214.58",
            "servers": "7.98",
            "workstations": "16.09",
        }]

    def test_api_error_raises_instead_of_writing_zero_row(self, sensor_usage, tmp_path):
        from falcon_billing.billing import generate_multitenant_report

        sensor_usage.get_hourly_usage.return_value = {
            "status_code": 403,
            "body": {"errors": [{"code": 403, "message": "unauthorized access for customer data"}]},
        }

        with pytest.raises(RuntimeError, match="tenant-a.*unauthorized access for customer data"):
            generate_multitenant_report([(TENANT_CID, "tenant-a")], output_path=str(tmp_path))

        assert list(tmp_path.iterdir()) == []


class TestCmdMultiTenant:
    def test_cids_flag_passes_cid_name_pairs(self):
        from falcon_billing.cli.main import cmd_multi_tenant

        args = argparse.Namespace(auto_discover=False, cids="cid-a, cid-b", cid_file=None, output=None)
        with patch("falcon_billing.billing.generate_multitenant_report") as report:
            cmd_multi_tenant(args)

        assert report.call_args.args[0] == [("cid-a", "cid-a"), ("cid-b", "cid-b")]
