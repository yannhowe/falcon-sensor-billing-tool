"""Hourly sensor collection and enrichment with smart caching.

Collects active sensor data from NGSIEM (primary) or Hosts API (fallback),
enriches with host metadata, and stores in the billing database.
"""

import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from falconpy import Hosts, OAuth2

from falcon_billing.classifier import assign_skus
from falcon_billing.credentials import load_credentials
from falcon_billing.database import BillingDatabase
from falcon_billing.ngsiem import (
    query_ngsiem_for_sensors,
    query_ngsiem_for_container_hosts,
    NgsiemQueryFailed,
)

logger = logging.getLogger(__name__)

# Cache for CID to avoid repeated API calls
_cached_cid = None

# Cache for Falcon client
_falcon_client = None


def get_falcon_client() -> Hosts:
    global _falcon_client
    if _falcon_client is None:
        creds = load_credentials()
        base_urls = {
            "us-1": "https://api.crowdstrike.com",
            "us-2": "https://api.us-2.crowdstrike.com",
            "eu-1": "https://api.eu-1.crowdstrike.com",
            "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
        }
        _falcon_client = Hosts(
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            base_url=base_urls.get(creds["cloud_region"], base_urls["us-1"]),
        )
    return _falcon_client


# ============================================================================
# Gap Detection Functions
# ============================================================================


def hour_key(hour: datetime) -> str:
    """Canonical storage key for a clock hour: 'YYYY-MM-DD HH:00:00' in UTC.

    Gap detection and the store path must agree on this exact format, or every
    hour looks un-collected and gets re-collected on every run.
    """
    return hour.strftime("%Y-%m-%d %H:00:00")


def get_hours_to_collect(days_back: int, db) -> List[datetime]:
    """
    Determine which hours need collection.

    Rules:
    - Always skip current incomplete hour
    - End at previous complete hour
    - Check database for existing hours
    - Return only missing hours

    Args:
        days_back: Number of days to look back
        db: BillingDatabase instance

    Returns:
        List of datetime objects for missing hours
    """
    now = datetime.now(timezone.utc)
    current_hour = now.replace(minute=0, second=0, microsecond=0)

    # Skip current hour (incomplete), end at previous complete hour
    end_hour = current_hour - timedelta(hours=1)
    start_hour = end_hour - timedelta(days=days_back) + timedelta(hours=1)

    logger.info(f"Date range: {start_hour} to {end_hour}")

    # Query existing hours from database
    with db.get_connection() as conn:
        cursor = conn.execute("""
            SELECT DISTINCT hour_timestamp
            FROM sensor_logs
            WHERE hour_timestamp >= ? AND hour_timestamp <= ?
        """, (hour_key(start_hour), hour_key(end_hour)))
        existing = {row[0] for row in cursor.fetchall()}

    # Generate all hours in range
    all_hours = []
    hour = start_hour
    while hour <= end_hour:
        all_hours.append(hour)
        hour += timedelta(hours=1)

    # Filter to missing hours only
    missing_hours = [h for h in all_hours if hour_key(h) not in existing]

    logger.info(f"Total hours in range: {len(all_hours)}")
    logger.info(f"Already collected: {len(existing)}")
    logger.info(f"Missing hours to collect: {len(missing_hours)}")

    return missing_hours


# ============================================================================
# Hosts API Fallback Functions
# ============================================================================

def query_hosts_api_for_active_sensors(
    falcon_client: Hosts,
    hour_start: datetime,
    hour_end: datetime,
    cid: Optional[str] = None
) -> List[str]:
    """
    Fallback: Query Hosts API for sensors with last_seen in target hour.

    This is less accurate than NGSIEM because:
    - last_seen is the most recent check-in, not all check-ins
    - Hosts API may not show sensors that went offline
    - Pagination limit of 5000 devices

    Args:
        falcon_client: FalconPy Hosts client
        hour_start: Start of hour
        hour_end: End of hour
        cid: Optional child CID filter

    Returns:
        list: Sensor IDs with last_seen in target hour
    """
    sensor_ids = []

    # Build filter for last_seen in target hour
    # FQL filter format: last_seen:>'2026-04-14T14:00:00Z'+last_seen:<'2026-04-14T15:00:00Z'
    hour_start_str = hour_start.strftime('%Y-%m-%dT%H:%M:%SZ')
    hour_end_str = hour_end.strftime('%Y-%m-%dT%H:%M:%SZ')

    filter_parts = [
        f"last_seen:>'{hour_start_str}'",
        f"last_seen:<'{hour_end_str}'"
    ]

    # Note: Don't add CID filter for single-tenant (non-Flight Control)
    # Only Flight Control parent CIDs can filter by child CID
    # For single-tenant, the API automatically returns sensors for the authenticated CID

    fql_filter = '+'.join(filter_parts)

    try:
        # Query for device IDs
        offset = 0
        limit = 5000  # Max allowed by API

        while True:
            response = falcon_client.query_devices_by_filter(
                filter=fql_filter,
                offset=offset,
                limit=limit
            )

            if response['status_code'] != 200:
                error_msg = response.get('body', {}).get('errors', ['Unknown error'])
                logger.error(f"Failed to query devices: {error_msg}")
                break

            device_ids = response['body'].get('resources', [])
            if not device_ids:
                break

            sensor_ids.extend(device_ids)
            logger.info(f"Retrieved {len(device_ids)} devices (offset {offset})")

            # Check if there are more results
            total = response['body'].get('meta', {}).get('pagination', {}).get('total', 0)
            offset += len(device_ids)
            if offset >= total:
                break

        logger.info(f"Total sensors found with last_seen in target hour: {len(sensor_ids)}")
        return sensor_ids

    except Exception as e:
        logger.error(f"Failed to query Hosts API: {e}")
        return []


# ============================================================================
# Host Enrichment Functions
# ============================================================================

def enrich_sensors_with_host_details(
    falcon_client: Hosts,
    db: BillingDatabase,
    sensor_ids: List[str]
) -> Dict[str, Dict]:
    """
    Enrich sensor IDs with host metadata using smart caching.

    Cache strategy:
    1. Check cache for each sensor_id (24h TTL)
    2. Separate into cached (hit) and need_refresh (miss/stale)
    3. Batch API calls for need_refresh in groups of 100
    4. Update cache with fresh data
    5. Return combined results

    Args:
        falcon_client: FalconPy Hosts client
        db: BillingDatabase instance
        sensor_ids: List of sensor IDs to enrich

    Returns:
        dict: Mapping of sensor_id -> host_details
    """
    if not sensor_ids:
        return {}

    enriched = {}
    need_refresh = []

    # Check cache for each sensor
    for sensor_id in sensor_ids:
        cached = db.get_cached_host(sensor_id)
        if cached:
            enriched[sensor_id] = cached
        else:
            need_refresh.append(sensor_id)

    # Log cache statistics
    hits = len(enriched)
    misses = len(need_refresh)
    hit_rate = (hits / len(sensor_ids)) * 100 if sensor_ids else 0
    logger.info(f"Cache stats: {hits} hits, {misses} misses ({hit_rate:.1f}% hit rate)")

    # Fetch missing/stale hosts from API in batches of 100
    if need_refresh:
        batch_size = 100
        for i in range(0, len(need_refresh), batch_size):
            batch = need_refresh[i:i + batch_size]
            logger.info(f"Fetching host details for {len(batch)} sensors (batch {i//batch_size + 1})")

            try:
                response = falcon_client.get_device_details(ids=batch)

                if response['status_code'] != 200:
                    error_msg = response.get('body', {}).get('errors', ['Unknown error'])
                    logger.error(f"Failed to get device details: {error_msg}")
                    continue

                resources = response['body'].get('resources', [])

                # Parse host details
                host_details = []
                for resource in resources:
                    host_data = {
                        'sensor_id': resource.get('device_id'),
                        'hostname': resource.get('hostname'),
                        'platform_name': resource.get('platform_name'),
                        'platform_version': resource.get('platform_version'),
                        'os_version': resource.get('os_version'),
                        'status': resource.get('status'),
                        'last_seen': resource.get('last_seen'),
                        'groups': resource.get('groups', []),
                        'tags': resource.get('tags', []),
                        'cid': resource.get('cid', 'default'),
                        'manufacturer': resource.get('system_manufacturer'),
                        'cloud_provider': resource.get('cloud_provider'),
                        'product_type_desc': resource.get('product_type_desc'),
                    }
                    host_details.append(host_data)
                    enriched[host_data['sensor_id']] = host_data

                # Update cache with fresh data
                if host_details:
                    db.update_host_cache_bulk(host_details)
                    logger.info(f"Updated cache for {len(host_details)} hosts")

            except Exception as e:
                logger.error(f"Failed to fetch host details batch: {e}")
                continue

    return enriched


# ============================================================================
# Collection Functions
# ============================================================================

def process_hourly_collection(
    db: BillingDatabase,
    hour: datetime,
    cid: Optional[str] = None,
    falcon_client: Optional[Hosts] = None,
    fcsc_info_only: bool = False,
) -> Tuple[int, int, int]:
    """
    Args:
        db: BillingDatabase instance
        hour: Target clock hour to collect
        cid: Optional child CID
        fcsc_info_only: Count FCSC from OciContainerInfo alone (billing-faithful)
            instead of the OciContainerInfo ∪ OciContainerStarted union.

    Returns:
        tuple: (total_sensors, cache_hits, api_calls)
    """
    if falcon_client is None:
        falcon_client = get_falcon_client()
    _, cid, sensor_ids, container_ids = fetch_hour_sensors(
        hour, cid, falcon_client, fcsc_info_only=fcsc_info_only
    )
    return store_hour_data(db, hour, cid, sensor_ids, falcon_client, container_ids)


def fetch_hour_sensors(
    hour: datetime,
    cid: str,
    falcon_client,
    fcsc_info_only: bool = False,
) -> Tuple[datetime, str, List[str], Optional[List[str]]]:
    if not cid or cid == 'default':
        cid = get_falcon_cid()

    hour_end = hour + timedelta(hours=1)
    hour_start_iso = hour.strftime('%Y-%m-%dT%H:%M:%SZ')
    hour_end_iso = hour_end.strftime('%Y-%m-%dT%H:%M:%SZ')

    creds = load_credentials()
    try:
        sensor_ids = query_ngsiem_for_sensors(
            hour_start=hour_start_iso, hour_end=hour_end_iso, cid=cid,
            client_id=creds["client_id"], client_secret=creds["client_secret"],
            cloud_region=creds["cloud_region"],
        )
    except NgsiemQueryFailed:
        logger.warning("NGSIEM total query failed for %s, falling back to Hosts API", hour_start_iso)
        sensor_ids = query_hosts_api_for_active_sensors(falcon_client, hour, hour_end, cid)

    try:
        container_ids = query_ngsiem_for_container_hosts(
            hour_end_iso, cid,
            client_id=creds["client_id"], client_secret=creds["client_secret"],
            cloud_region=creds["cloud_region"],
            info_only=fcsc_info_only,
        )
    except NgsiemQueryFailed:
        logger.warning("Container host query failed for %s, classifying from host metadata", hour_start_iso)
        container_ids = None

    return hour, cid, sensor_ids, container_ids


def store_hour_data(
    db,
    hour: datetime,
    cid: str,
    sensor_ids: List[str],
    falcon_client,
    container_ids: Optional[List[str]],
) -> Tuple[int, int, int]:
    hour_str = hour_key(hour)
    if not sensor_ids:
        logger.warning("No sensors found for hour %s", hour_str)

    enriched = enrich_sensors_with_host_details(falcon_client, db, sensor_ids)
    cache_hits, cache_misses, _ = db.cache_hit_rate(sensor_ids, max_age_hours=24)

    sensors_to_insert = [
        enriched.get(sensor_id) or {
            'sensor_id': sensor_id,
            'hostname': None, 'platform_name': None, 'platform_version': None,
            'os_version': None, 'status': None, 'last_seen': None,
            'groups': [], 'tags': [], 'cid': cid,
        }
        for sensor_id in sensor_ids
    ]
    skus = assign_skus(sensor_ids, container_ids, enriched)
    counts = {sku: len(aids) for sku, aids in skus.items()}
    sku_by_sensor = {aid: sku for sku, aids in skus.items() for aid in aids}
    db.store_hour(
        hour_str, cid, sensors_to_insert, len(sensor_ids),
        counts["FCSC"], counts["FMC"], counts["FCS"], counts["EPP"],
        sku_by_sensor=sku_by_sensor,
    )
    logger.info("Stored %s: FCS=%d EPP=%d FCSC=%d FMC=%d Total=%d",
                hour_str, counts["FCS"], counts["EPP"], counts["FCSC"], counts["FMC"], len(sensor_ids))

    return len(sensor_ids), cache_hits, cache_misses


def parallel_backfill(
    db,
    hours: List[datetime],
    cid: str,
    falcon_client,
    workers: int = 10,
    fcsc_info_only: bool = False,
) -> None:
    """
    Fetch all NGSIEM queries concurrently, then store results sequentially.
    Keeps SQLite writes single-threaded while parallelising the slow network IO.
    """
    logger.info("Parallel backfill: %d hours with %d workers", len(hours), workers)

    # Phase 1: fetch all hours in parallel
    results: Dict[datetime, Tuple[str, List[str], Optional[List[str]]]] = {}
    fetch_errors: Dict[datetime, Exception] = {}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_hour = {
            executor.submit(
                fetch_hour_sensors, hour, cid, falcon_client,
                fcsc_info_only=fcsc_info_only,
            ): hour
            for hour in hours
        }
        completed = 0
        for future in as_completed(future_to_hour):
            hour = future_to_hour[future]
            completed += 1
            try:
                _, resolved_cid, sensor_ids, container_ids = future.result()
                results[hour] = (resolved_cid, sensor_ids, container_ids)
            except Exception as exc:
                logger.error("Fetch failed for %s: %s", hour, exc)
                fetch_errors[hour] = exc
            if completed % 24 == 0:
                logger.info("Fetched %d/%d hours", completed, len(hours))

    if fetch_errors:
        logger.warning("%d hours failed to fetch and will be skipped", len(fetch_errors))

    # Phase 2: store sequentially in chronological order
    logger.info("Storing %d hours to database...", len(results))
    store_errors: Dict[datetime, Exception] = {}
    for i, hour in enumerate(sorted(results.keys()), 1):
        resolved_cid, sensor_ids, container_ids = results[hour]
        try:
            store_hour_data(db, hour, resolved_cid, sensor_ids, falcon_client, container_ids)
        except Exception as exc:
            logger.error("Store failed for %s: %s", hour, exc)
            store_errors[hour] = exc
        if i % 24 == 0:
            logger.info("Stored %d/%d hours", i, len(results))

    failures = [
        f"{phase} {hour.strftime('%Y-%m-%d %H:00:00')}: {exc}"
        for phase, phase_errors in (("fetch", fetch_errors), ("store", store_errors))
        for hour, exc in sorted(phase_errors.items())
    ]
    if failures:
        raise RuntimeError(
            f"Backfill failed for {len(failures)} of {len(hours)} hours: " + "; ".join(failures)
        )


# ============================================================================
# Verification Functions
# ============================================================================

def verify_tag_counts(
    db: BillingDatabase,
    hour: datetime,
    cid: str = 'default'
) -> Tuple[bool, List[str]]:
    """
    Verify tag counts don't exceed total count for the hour.

    Args:
        db: BillingDatabase instance
        hour: Hour to verify
        cid: Child CID or 'default'

    Returns:
        tuple: (passed, list of errors)
    """
    hour_str = hour.strftime('%Y-%m-%d %H:00:00')
    errors = []

    # Get total count for hour
    hourly_counts = db.get_hourly_counts_for_range(hour_str, hour_str, cid)
    if not hourly_counts:
        errors.append(f"No hourly count found for {hour_str}")
        return False, errors

    total_count = hourly_counts[0]['unique_sensor_count']

    # Get all tag counts for hour
    tag_counts = db.get_tag_counts_for_range(hour_str, hour_str, cid=cid)

    # Verify no tag count exceeds total
    for tag_count in tag_counts:
        tag = tag_count['tag']
        count = tag_count['unique_sensor_count']
        if count > total_count:
            errors.append(
                f"Tag '{tag}' count ({count}) exceeds total count ({total_count})"
            )

    passed = len(errors) == 0

    if not passed:
        logger.warning(f"Tag count verification FAILED for {hour_str}: {errors}")
    else:
        logger.info(f"Tag count verification PASSED for {hour_str}")

    return passed, errors


def generate_reconciliation(
    db: BillingDatabase,
    cid: str = 'default',
    days: int = 28,
    output_path: Optional[str] = None,
) -> Optional[str]:
    """Reconcile the tool's NG-SIEM estimate against the billed total per SKU.

    Puts the tool's own rolling average beside the authoritative Sensor Usage
    API total for each SKU, with the direction and size of the gap. The billed
    total is the number that gets billed; the tool's estimate is a sanity check
    on collection, not a competing total. Both use the same period denominator,
    so the gap is meaningful. Compares against the most recent billed row.

    Returns the CSV path when output_path is given, else None.
    """
    from falcon_billing.billing import billing_row_to_skus

    summary = db.calculate_28day_average(cid, days=days)
    avgs = summary["averages"]

    billed_row = db.get_latest_billing_average(cid)
    if not billed_row:
        print(
            f"No billed total stored for CID {cid}. "
            f"Run 'falcon-billing fetch-billing --cid {cid}' first.",
            file=sys.stderr,
        )
        return None

    billed = billing_row_to_skus(billed_row)

    rows = []
    for label, key in [("FCS", "fcs"), ("FCSC", "fcsc"), ("FMC", "fmc"), ("EPP", "epp")]:
        tool_v = avgs.get(key, 0.0)
        api_v = float(billed.get(key, 0) or 0)
        gap = tool_v - api_v
        if api_v:
            gap_pct = gap / api_v * 100
        else:
            gap_pct = 100.0 if tool_v else 0.0
        direction = "over" if gap > 0 else "under" if gap < 0 else "match"
        rows.append({
            "sku": label,
            "tool_estimate": f"{tool_v:.2f}",
            "billed": f"{api_v:.2f}",
            "gap": f"{gap:+.2f}",
            "gap_pct": f"{gap_pct:+.1f}%",
            "direction": direction,
        })

    coverage = summary["hours_with_data"]
    period_hours = summary["period_hours"]

    print("\n" + "=" * 74)
    print(f"RECONCILIATION — tool estimate vs billed total (CID {cid}, "
          f"{summary['period_days']}-day)")
    print("=" * 74)
    print(f"Billed date: {billed_row.get('date')}   "
          f"Collection coverage: {coverage}/{period_hours} hours")
    print(f"\n  {'SKU':<6} {'Tool est.':>12} {'Billed':>12} {'Gap':>10} {'Gap %':>9}  Direction")
    print(f"  {'-'*6} {'-'*12} {'-'*12} {'-'*10} {'-'*9}  {'-'*9}")
    for r in rows:
        print(f"  {r['sku']:<6} {r['tool_estimate']:>12} {r['billed']:>12} "
              f"{r['gap']:>10} {r['gap_pct']:>9}  {r['direction']}")
    print("\nBilled is the authoritative number. The tool estimate is a "
          "collection sanity check, not a competing total.")
    print("=" * 74 + "\n")

    if output_path:
        import csv
        fieldnames = ["sku", "tool_estimate", "billed", "gap", "gap_pct", "direction"]
        with open(output_path, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        logger.info("Reconciliation written to %s", output_path)
        return str(output_path)

    return None


# ============================================================================
# Credential Helper
# ============================================================================

def get_falcon_cid() -> str:
    """
    Get the actual CID (Customer ID) from Falcon API.

    Caches the result to avoid repeated API calls.

    Returns:
        str: CID in format "32hexchars-2charChecksum" (e.g., "ABCDEF1234567890ABCDEF1234567890-XX")
    """
    global _cached_cid

    if _cached_cid:
        return _cached_cid

    try:
        from falconpy import SensorDownload, OAuth2

        creds = load_credentials()
        base_urls = {
            "us-1": "https://api.crowdstrike.com",
            "us-2": "https://api.us-2.crowdstrike.com",
            "eu-1": "https://api.eu-1.crowdstrike.com",
            "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
        }
        base_url = base_urls.get(creds["cloud_region"], base_urls["us-1"])

        auth = OAuth2(
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            base_url=base_url,
        )

        sensor_download = SensorDownload(auth_object=auth)
        response = sensor_download.get_sensor_installer_ccid()

        if response['status_code'] == 200 and response['body']['resources']:
            _cached_cid = response['body']['resources'][0]
            logger.info(f"Retrieved CID from Falcon API: {_cached_cid[:16]}...{_cached_cid[-2:]}")
            return _cached_cid
        else:
            logger.warning(f"Failed to retrieve CID from API: {response.get('body', {}).get('errors')}")
            return 'default'

    except Exception as e:
        logger.warning(f"Error retrieving CID from API: {e}")
        return 'default'
