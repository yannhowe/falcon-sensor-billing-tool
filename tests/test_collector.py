"""Tests for falcon_billing.collector (integration with mocked APIs)."""

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
