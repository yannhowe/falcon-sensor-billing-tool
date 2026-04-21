"""Shared test fixtures for falcon_billing tests."""

import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def tmp_db_path(tmp_path):
    """Return a temporary database file path."""
    return tmp_path / "test_billing.db"


@pytest.fixture
def db(tmp_db_path):
    """Create a BillingDatabase with a temporary file."""
    from falcon_billing.database import BillingDatabase

    return BillingDatabase(tmp_db_path)


@pytest.fixture
def mock_falcon_client():
    """Mock FalconPy Hosts client."""
    client = MagicMock()
    client.query_devices_by_filter_scroll.return_value = {
        "status_code": 200,
        "body": {"resources": []},
    }
    client.get_device_details.return_value = {
        "status_code": 200,
        "body": {"resources": []},
    }
    return client


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure credential env vars don't leak between tests."""
    for var in ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_CLOUD_REGION"):
        monkeypatch.delenv(var, raising=False)
