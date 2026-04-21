"""Tests for falcon_billing.ngsiem."""

from unittest.mock import patch, MagicMock
import pytest
from falcon_billing.ngsiem import query_ngsiem_for_sensors, NgsiemQueryFailed


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
