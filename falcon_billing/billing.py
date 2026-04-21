"""Sensor Usage API queries and multi-tenant chargeback reporting.

Interfaces with the CrowdStrike Sensor Usage API for official billing data.
Supports single-CID, multi-CID, and Flight Control auto-discovery modes.
"""

import csv
import io
import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from falconpy import SensorUsage, FlightControl, Hosts, OAuth2

from falcon_billing.credentials import load_credentials
from falcon_billing.database import BillingDatabase

logger = logging.getLogger(__name__)

# Map region to base URL
REGION_MAP = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}

# Output directory for logs
OUTPUT_DIR = os.environ.get("USAGE_LOG_DIR", "/var/log/falcon-usage")

# Number of days to retrieve (default: 28 days for standard billing period)
PERIOD_DAYS = int(os.environ.get("PERIOD_DAYS", "28"))

# Optional: Comma-separated list of child CIDs to query
SELECTED_CIDS = os.environ.get("SELECTED_CIDS", "")


def get_sensor_usage(hourly: bool = False) -> dict:
    """Query Sensor Usage API for single CID.

    Args:
        hourly: If True, retrieve hourly average; otherwise weekly average.

    Returns:
        API response body dict.

    Raises:
        SystemExit on API error.
    """
    creds = load_credentials()
    client_id = creds["client_id"]
    client_secret = creds["client_secret"]
    cloud_region = creds["cloud_region"]

    base_url = REGION_MAP.get(cloud_region)
    if not base_url:
        logger.error("Invalid cloud region: %s. Valid regions: %s", cloud_region, ", ".join(REGION_MAP.keys()))
        raise ValueError(f"Invalid cloud region: {cloud_region}")

    falcon = SensorUsage(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
    )

    end_date = (datetime.now() - timedelta(days=2)).strftime("%Y-%m-%d")
    filter_parts = [f"event_date:'{end_date}'", f"period:'{PERIOD_DAYS}'"]

    if SELECTED_CIDS:
        cids = SELECTED_CIDS.strip()
        filter_parts.append(f"selected_cids:'{cids}'")

    filter_string = ",".join(filter_parts)

    try:
        if hourly:
            response = falcon.get_hourly_usage(filter=filter_string)
        else:
            response = falcon.get_weekly_usage(filter=filter_string)

        if response["status_code"] != 200:
            error_msg = response.get("body", {}).get("errors", ["Unknown error"])
            logger.error("API request failed (HTTP %s): %s", response["status_code"], error_msg)
            raise RuntimeError(f"API request failed (HTTP {response['status_code']}): {error_msg}")

        return response["body"]

    except (RuntimeError, ValueError):
        raise
    except Exception as e:
        logger.error("Failed to retrieve usage data: %s", e)
        raise RuntimeError(f"Failed to retrieve usage data: {e}") from e


def get_sensor_usage_for_cid(cid: str, hourly: bool = False) -> Optional[dict]:
    """Query Sensor Usage API for a specific child CID.

    Args:
        cid: Child CID to query.
        hourly: If True, retrieve hourly average; otherwise weekly average.

    Returns:
        API response body dict, or None on failure.
    """
    creds = load_credentials()
    client_id = creds["client_id"]
    client_secret = creds["client_secret"]
    cloud_region = creds["cloud_region"]

    base_url = REGION_MAP.get(cloud_region)
    if not base_url:
        logger.warning("Invalid cloud region: %s", cloud_region)
        return None

    falcon = SensorUsage(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
    )

    end_date = (datetime.now() - timedelta(days=2)).strftime("%Y-%m-%d")
    filter_string = f"event_date:'{end_date}',period:'{PERIOD_DAYS}',selected_cids:'{cid}'"

    try:
        if hourly:
            response = falcon.get_sensor_usage_hourly_average(filter=filter_string)
        else:
            response = falcon.get_sensor_usage_weekly_average(filter=filter_string)

        if response["status_code"] != 200:
            error_msg = response.get("body", {}).get("errors", ["Unknown error"])
            logger.warning("Failed to query CID %s: %s", cid, error_msg)
            return None

        return response["body"]

    except Exception as e:
        logger.warning("Failed to query CID %s: %s", cid, e)
        return None


def auto_discover_child_cids() -> List[tuple]:
    """Auto-discover child CIDs from Flight Control parent CID.

    Returns:
        List of (cid, name) tuples. Returns empty list if not a Flight Control
        parent or if mssp:read scope is missing.

    Raises:
        RuntimeError on unexpected API failure.
    """
    creds = load_credentials()
    client_id = creds["client_id"]
    client_secret = creds["client_secret"]
    cloud_region = creds["cloud_region"]

    base_url = REGION_MAP.get(cloud_region)
    if not base_url:
        raise ValueError(f"Invalid cloud region: {cloud_region}")

    logger.info("Auto-discovering child CIDs from Flight Control parent...")

    try:
        mssp = FlightControl(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
        )

        response = mssp.query_children(limit=5000)

        if response["status_code"] == 403:
            logger.warning(
                "Cannot access Flight Control API (403 Forbidden). "
                "Possible reasons: API client missing 'mssp:read' scope, "
                "or this is not a Flight Control parent CID."
            )
            return []

        if response["status_code"] != 200:
            error_msg = response.get("body", {}).get("errors", ["Unknown error"])
            raise RuntimeError(f"Failed to query child CIDs: {error_msg}")

        child_cid_ids = response["body"].get("resources", [])

        if not child_cid_ids:
            logger.info("No child CIDs found. This is not a Flight Control parent CID.")
            return []

        logger.info("Found %d child CID(s)", len(child_cid_ids))

        child_response = mssp.get_children(ids=child_cid_ids)

        if child_response["status_code"] != 200:
            logger.warning("Could not fetch child CID details, using CID IDs only")
            return [(cid, cid) for cid in child_cid_ids]

        cids = []
        for child in child_response["body"].get("resources", []):
            cid = child.get("child_cid", "")
            name = child.get("name", cid)
            if cid:
                cids.append((cid, name))

        return cids

    except (RuntimeError, ValueError):
        raise
    except Exception as e:
        raise RuntimeError(
            f"Failed to auto-discover child CIDs: {e}. "
            "Auto-discovery requires a Flight Control parent CID with 'mssp:read' scope."
        ) from e


def generate_multitenant_report(
    cids: List[tuple],
    output_path: Optional[str] = None,
    hourly: bool = False,
) -> str:
    """Generate chargeback report for multiple tenants.

    Args:
        cids: List of (cid, name) tuples.
        output_path: Directory to write the report CSV. Defaults to OUTPUT_DIR.
        hourly: If True, use hourly averages; otherwise weekly.

    Returns:
        Path to the saved report CSV file.
    """
    endpoint_label = "hourly" if hourly else "weekly"
    output_dir = output_path or OUTPUT_DIR
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    logger.info("Querying %d tenant CIDs...", len(cids))

    results = []
    for idx, (cid, name) in enumerate(cids, 1):
        logger.info("[%d/%d] Querying %s (%s)...", idx, len(cids), name, cid)

        data = get_sensor_usage_for_cid(cid, hourly=hourly)

        if data and data.get("resources"):
            latest = data["resources"][0]
            results.append({
                "tenant_name": name,
                "cid": cid,
                "date": latest.get("date", ""),
                "managed_containers": latest.get("lumos", 0),
                "cloud_vms": latest.get("public_cloud_without_containers", 0),
                "servers": latest.get("servers_without_containers", 0),
                "workstations": latest.get("workstations", 0),
            })
        else:
            results.append({
                "tenant_name": name,
                "cid": cid,
                "date": "",
                "managed_containers": 0,
                "cloud_vms": 0,
                "servers": 0,
                "workstations": 0,
            })

    os.makedirs(output_dir, exist_ok=True)
    report_file = os.path.join(
        output_dir, f"multitenant_chargeback_{endpoint_label}_{timestamp}.csv"
    )

    fieldnames = ["tenant_name", "cid", "date", "managed_containers", "cloud_vms", "servers", "workstations"]
    with open(report_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    total_fmc = sum(r["managed_containers"] for r in results)
    logger.info("Multi-tenant report saved to %s (total billable: %.2f FMC sensors)", report_file, total_fmc)

    return report_file


def load_cid_list(input_str: str) -> List[tuple]:
    """Parse CID input from a comma-separated string or @filename.

    Args:
        input_str: Comma-separated CIDs, or '@filename' where file contains
                   one CID per line (optionally 'CID,TenantName').

    Returns:
        List of (cid, name) tuples.

    Raises:
        FileNotFoundError: If @filename does not exist.
    """
    cids = []

    if input_str.startswith("@"):
        filename = input_str[1:]
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",", 1)
                cid = parts[0].strip()
                name = parts[1].strip() if len(parts) > 1 else cid
                cids.append((cid, name))
    else:
        for cid in input_str.split(","):
            cid = cid.strip()
            if cid:
                cids.append((cid, cid))

    return cids


def log_to_csv(
    data: dict,
    output_path: Optional[str] = None,
    hourly: bool = False,
    db: Optional[object] = None,
    cid: str = "default",
) -> Optional[str]:
    """Export billing data to CSV and JSON files, and optionally to database.

    Args:
        data: API response body dict containing 'resources'.
        output_path: Directory to write output files. Defaults to OUTPUT_DIR.
        hourly: If True, label files as 'hourly'; otherwise 'weekly'.
        db: Optional BillingDatabase instance for database storage.
        cid: CID label used when writing to database.

    Returns:
        Path to the CSV file written, or None if no data.
    """
    output_dir = output_path or OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    endpoint_label = "hourly" if hourly else "weekly"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"falcon_usage_{endpoint_label}_{timestamp}.csv")

    resources = data.get("resources", [])
    if not resources:
        logger.warning("No usage data returned from API")
        return None

    fieldnames = [
        "date",
        "cloud_vms",
        "container_hosts",
        "managed_containers",
        "servers",
        "workstations",
        "mobile",
        "chrome_os",
        "public_cloud_containers",
        "server_containers",
        "retrieved_at",
    ]

    retrieved_at = datetime.now().isoformat()

    with open(filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for resource in resources:
            writer.writerow({
                "date": resource.get("date", ""),
                "cloud_vms": resource.get("public_cloud_without_containers", 0),
                "container_hosts": resource.get("containers", 0),
                "managed_containers": resource.get("lumos", 0),
                "servers": resource.get("servers_without_containers", 0),
                "workstations": resource.get("workstations", 0),
                "mobile": resource.get("mobile", 0),
                "chrome_os": resource.get("chrome_os", 0),
                "public_cloud_containers": resource.get("public_cloud_with_containers", 0),
                "server_containers": resource.get("servers_with_containers", 0),
                "retrieved_at": retrieved_at,
            })

    logger.info("Usage data logged to %s (%d records)", filename, len(resources))

    # Also save raw JSON for reference
    json_filename = filename.replace(".csv", ".json")
    with open(json_filename, "w") as jsonfile:
        json.dump(data, jsonfile, indent=2)
    logger.info("Raw JSON saved to %s", json_filename)

    # Store in database if provided
    if db is not None:
        logger.info("Storing billing API data in database...")
        for resource in resources:
            billing_data = {
                "managed_containers": resource.get("lumos", 0),
                "cloud_vms": resource.get("public_cloud_without_containers", 0),
                "container_hosts": resource.get("containers", 0),
                "servers": resource.get("servers_without_containers", 0),
                "workstations": resource.get("workstations", 0),
                "mobile": resource.get("mobile", 0),
                "chrome_os": resource.get("chrome_os", 0),
                "public_cloud_containers": resource.get("public_cloud_with_containers", 0),
                "server_containers": resource.get("servers_with_containers", 0),
            }
            db.insert_billing_average(resource.get("date", ""), billing_data, cid)
        logger.info("Billing data stored in database")

    return filename


def print_summary(data: dict, hourly: bool = False) -> None:
    """Format and display billing data summary.

    Args:
        data: API response body dict containing 'resources'.
        hourly: Included for API symmetry; currently informational only.
    """
    resources = data.get("resources", [])
    if not resources:
        return

    print("\n" + "=" * 70)
    print("USAGE SUMMARY")
    print("=" * 70)

    latest = resources[0]
    print(f"\nLatest data point: {latest.get('date')}")
    print(f"  Cloud VMs:          {latest.get('public_cloud_without_containers', 0):.2f}")
    print(f"  Container Hosts:    {latest.get('containers', 0):.2f}")
    print(f"  Managed Containers: {latest.get('lumos', 0):.2f} (FMC - for chargeback)")
    print(f"  Servers:            {latest.get('servers_without_containers', 0):.2f}")
    print(f"  Workstations:       {latest.get('workstations', 0):.2f}")
    print(f"  Mobile:             {latest.get('mobile', 0):.2f}")

    max_containers = max(r.get("lumos", 0) for r in resources)
    max_cloud_vms = max(r.get("public_cloud_without_containers", 0) for r in resources)
    max_servers = max(r.get("servers_without_containers", 0) for r in resources)
    max_workstations = max(r.get("workstations", 0) for r in resources)

    print(f"\nMax values over {len(resources)} days:")
    print(f"  Max Managed Containers: {max_containers:.2f}")
    print(f"  Max Cloud VMs:          {max_cloud_vms:.2f}")
    print(f"  Max Servers:            {max_servers:.2f}")
    print(f"  Max Workstations:       {max_workstations:.2f}")

    print(f"\nCHARGEBACK AMOUNT: {latest.get('lumos', 0):.2f} FMC sensors")
    print(f"   (Use latest value for billing)")

    print(f"\nTotal data points retrieved: {len(resources)}")
    print("=" * 70 + "\n")
