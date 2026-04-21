"""Tests for falcon_billing.credentials."""

import os
from unittest.mock import patch, MagicMock

import pytest

from falcon_billing.credentials import (
    load_credentials,
    get_active_cid_profile,
    CredentialError,
)


class TestLoadCredentials:
    def test_env_vars_take_priority(self, monkeypatch):
        monkeypatch.setenv("FALCON_CLIENT_ID", "env-id")
        monkeypatch.setenv("FALCON_CLIENT_SECRET", "env-secret")
        monkeypatch.setenv("FALCON_CLOUD_REGION", "eu-1")

        creds = load_credentials()
        assert creds["client_id"] == "env-id"
        assert creds["client_secret"] == "env-secret"
        assert creds["cloud_region"] == "eu-1"

    def test_env_vars_default_region(self, monkeypatch):
        monkeypatch.setenv("FALCON_CLIENT_ID", "env-id")
        monkeypatch.setenv("FALCON_CLIENT_SECRET", "env-secret")

        creds = load_credentials()
        assert creds["cloud_region"] == "us-1"

    def test_missing_credentials_raises(self):
        with pytest.raises(CredentialError, match="No Falcon API credentials found"):
            load_credentials()

    @patch("falcon_billing.credentials._query_keychain")
    def test_keychain_fallback(self, mock_keychain, monkeypatch, tmp_path):
        mock_keychain.side_effect = lambda service, account: {
            ("falcon_talon_1", "client_id"): "kc-id",
            ("falcon_talon_1", "client_secret"): "kc-secret",
            ("falcon_talon_1", "cloud"): "us-2",
        }.get((service, account), "")

        profile_file = tmp_path / ".falcon_profile"
        profile_file.write_text("talon_1")
        monkeypatch.setattr(
            "falcon_billing.credentials.PROFILE_PATH", profile_file
        )

        creds = load_credentials()
        assert creds["client_id"] == "kc-id"
        assert creds["client_secret"] == "kc-secret"
        assert creds["cloud_region"] == "us-2"

    @patch("falcon_billing.credentials._query_keychain")
    def test_reads_active_profile(self, mock_keychain, monkeypatch, tmp_path):
        mock_keychain.side_effect = lambda service, account: {
            ("falcon_prod_cid", "client_id"): "prod-id",
            ("falcon_prod_cid", "client_secret"): "prod-secret",
            ("falcon_prod_cid", "cloud"): "us-1",
        }.get((service, account), "")

        profile_file = tmp_path / ".falcon_profile"
        profile_file.write_text("prod_cid")
        monkeypatch.setattr(
            "falcon_billing.credentials.PROFILE_PATH", profile_file
        )

        creds = load_credentials()
        assert creds["client_id"] == "prod-id"


class TestGetActiveCidProfile:
    def test_reads_profile_file(self, tmp_path, monkeypatch):
        profile_file = tmp_path / ".falcon_profile"
        profile_file.write_text("my_profile\n")
        monkeypatch.setattr(
            "falcon_billing.credentials.PROFILE_PATH", profile_file
        )

        assert get_active_cid_profile() == "my_profile"

    def test_defaults_to_talon_1(self, tmp_path, monkeypatch):
        profile_file = tmp_path / ".falcon_profile_nonexistent"
        monkeypatch.setattr(
            "falcon_billing.credentials.PROFILE_PATH", profile_file
        )

        assert get_active_cid_profile() == "talon_1"
