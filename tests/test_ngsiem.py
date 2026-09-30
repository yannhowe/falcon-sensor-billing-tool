"""Tests for falcon_billing.ngsiem."""

from unittest.mock import patch, MagicMock
import pytest
from falcon_billing.ngsiem import (
    query_ngsiem_for_sensors,
    query_ngsiem_for_container_hosts,
    query_ngsiem_for_container_evidence,
    parse_container_evidence,
    NgsiemQueryFailed,
)


class TestNgsiemRetry:
    @patch("falcon_billing.ngsiem._execute_ngsiem_query")
    def test_success_on_first_try(self, mock_query):
        mock_query.return_value = ["sensor-1", "sensor-2"]
        result = query_ngsiem_for_sensors(
            "2026-04-21T10:00:00Z", "2026-04-21T11:00:00Z", "abc123",
            client_id="id", client_secret="secret", cloud_region="us-1",
        )
        assert result == ["sensor-1", "sensor-2"]
        assert mock_query.call_count == 1

    @patch("falcon_billing.ngsiem._execute_ngsiem_query")
    def test_retries_on_timeout(self, mock_query):
        mock_query.side_effect = [TimeoutError("Query timed out"), ["sensor-1"]]
        result = query_ngsiem_for_sensors(
            "2026-04-21T10:00:00Z", "2026-04-21T11:00:00Z", "abc123",
            client_id="id", client_secret="secret", cloud_region="us-1",
        )
        assert result == ["sensor-1"]
        assert mock_query.call_count == 2

    @patch("falcon_billing.ngsiem._execute_ngsiem_query")
    def test_raises_after_all_retries(self, mock_query):
        mock_query.side_effect = TimeoutError("Query timed out")
        with pytest.raises(NgsiemQueryFailed, match="after 3 attempts"):
            query_ngsiem_for_sensors(
                "2026-04-21T10:00:00Z", "2026-04-21T11:00:00Z", "abc123",
                client_id="id", client_secret="secret", cloud_region="us-1",
            )
        assert mock_query.call_count == 3

    @patch("falcon_billing.ngsiem._execute_ngsiem_query")
    def test_escalating_timeouts(self, mock_query):
        mock_query.side_effect = TimeoutError("timeout")
        with pytest.raises(NgsiemQueryFailed):
            query_ngsiem_for_sensors(
                "2026-04-21T10:00:00Z", "2026-04-21T11:00:00Z", "abc123",
                client_id="id", client_secret="secret", cloud_region="us-1",
                timeout_sequence=(10, 20, 30),
            )
        # Verify each call got the escalating timeout
        timeouts = [call.kwargs.get("timeout") for call in mock_query.call_args_list]
        assert timeouts == [10, 20, 30]


class TestContainerHostQuerySelection:
    """The FCSC count query defaults to the Info∪Started union so older-build
    container hosts are counted, with an info_only flag for the billing-faithful
    OciContainerInfo-alone query."""

    @patch("falcon_billing.ngsiem.query_ngsiem_for_sensors")
    def test_default_counts_started_union(self, mock_sensors):
        mock_sensors.return_value = ["aid-1"]
        query_ngsiem_for_container_hosts(
            "2026-04-21T11:00:00Z", "abc123",
            client_id="id", client_secret="secret", cloud_region="us-1",
        )
        query = mock_sensors.call_args.kwargs["query_string"]
        assert "OciContainerInfo" in query
        assert "OciContainerStarted" in query

    @patch("falcon_billing.ngsiem.query_ngsiem_for_sensors")
    def test_info_only_excludes_started(self, mock_sensors):
        mock_sensors.return_value = ["aid-1"]
        query_ngsiem_for_container_hosts(
            "2026-04-21T11:00:00Z", "abc123",
            client_id="id", client_secret="secret", cloud_region="us-1",
            info_only=True,
        )
        query = mock_sensors.call_args.kwargs["query_string"]
        assert "OciContainerInfo" in query
        assert "OciContainerStarted" not in query


class TestContainerEvidence:
    """The evidence query collects the identity fields OciContainerInfo carries.
    A host seen only via OciContainerStarted has none, so it is flagged
    started_only from the absence of identity, not a second query."""

    def test_parse_splits_dedupes_and_flags_started_only(self):
        events = [
            {"aid": "host-with-images",
             "OciContainerName": "web\nweb\napi",
             "OciContainerImageId": "sha256:aaa\nsha256:bbb",
             "OciContainerEngineType": "docker\ndocker"},
            {"aid": "started-only-host",
             "OciContainerName": "",
             "OciContainerImageId": "",
             "OciContainerEngineType": ""},
            {"aid": None, "OciContainerImageId": "sha256:ccc"},
        ]
        parsed = parse_container_evidence(events)

        assert None not in parsed
        rich = parsed["host-with-images"]
        assert rich["names"] == ["web", "api"]
        assert rich["images"] == ["sha256:aaa", "sha256:bbb"]
        assert rich["engines"] == ["docker"]
        assert rich["started_only"] is False

        assert parsed["started-only-host"]["started_only"] is True
        assert parsed["started-only-host"]["images"] == []

    @patch("falcon_billing.ngsiem._execute_ngsiem_query")
    def test_evidence_query_collects_identity_and_returns_events(self, mock_exec):
        mock_exec.return_value = [
            {"aid": "h1", "OciContainerImageId": "sha256:aaa",
             "OciContainerEngineType": "containerd", "OciContainerName": "n"},
        ]
        result = query_ngsiem_for_container_evidence(
            "2026-04-21T11:00:00Z", "abc123",
            client_id="id", client_secret="secret", cloud_region="us-1",
        )
        kwargs = mock_exec.call_args.kwargs
        assert kwargs["return_events"] is True
        assert "collect(" in kwargs["query_string"]
        assert "OciContainerImageId" in kwargs["query_string"]
        assert result["h1"]["engines"] == ["containerd"]
        assert result["h1"]["started_only"] is False
