"""Unified credential loading for Falcon API access.

Priority order:
1. Environment variables (FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, FALCON_CLOUD_REGION)
2. macOS Keychain via active /cid profile (~/.falcon_profile)
3. macOS Keychain via 'talon_1' fallback
"""

import os
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

PROFILE_PATH = Path.home() / ".falcon_profile"


class CredentialError(Exception):
    """Raised when no valid credentials can be found."""


def load_credentials() -> dict:
    """Load Falcon API credentials.

    Returns dict with keys: client_id, client_secret, cloud_region
    Raises CredentialError if no credentials found.
    """
    # Priority 1: Environment variables
    client_id = os.environ.get("FALCON_CLIENT_ID", "").strip()
    client_secret = os.environ.get("FALCON_CLIENT_SECRET", "").strip()

    if client_id and client_secret:
        cloud_region = os.environ.get("FALCON_CLOUD_REGION", "us-1").strip()
        logger.debug("Loaded credentials from environment variables")
        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "cloud_region": cloud_region,
        }

    # Priority 2+3: macOS Keychain
    profile = get_active_cid_profile()
    try:
        kc_id = _query_keychain(f"falcon_{profile}", "client_id")
        kc_secret = _query_keychain(f"falcon_{profile}", "client_secret")
        kc_cloud = _query_keychain(f"falcon_{profile}", "cloud") or "us-1"

        if kc_id and kc_secret:
            logger.debug("Loaded credentials from Keychain profile: %s", profile)
            return {
                "client_id": kc_id,
                "client_secret": kc_secret,
                "cloud_region": kc_cloud,
            }
    except (FileNotFoundError, subprocess.CalledProcessError, OSError) as e:
        logger.debug("Keychain query failed: %s", e)

    raise CredentialError(
        "No Falcon API credentials found. Set FALCON_CLIENT_ID and "
        "FALCON_CLIENT_SECRET environment variables, or configure a "
        "Keychain profile via the /cid skill."
    )


def get_active_cid_profile() -> str:
    """Read the active CID profile name from ~/.falcon_profile."""
    try:
        return PROFILE_PATH.read_text().strip()
    except (FileNotFoundError, OSError):
        return "talon_1"


def _query_keychain(service: str, account: str) -> str:
    """Query macOS Keychain for a generic password."""
    result = subprocess.run(
        ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return ""
