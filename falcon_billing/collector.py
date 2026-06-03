"""Hourly sensor collection and enrichment with smart caching.

Collects active sensor data from NGSIEM (primary) or Hosts API (fallback),
enriches with host metadata, and stores in the billing database.
"""

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from falconpy import Hosts, OAuth2

from falcon_billing.credentials import load_credentials
from falcon_billing.database import BillingDatabase
from falcon_billing.ngsiem import (
    query_ngsiem_for_sensors,
    query_ngsiem_for_fcs,
    query_ngsiem_for_container_hosts,
    query_ngsiem_for_fmc,
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
        """, (start_hour.isoformat(), end_hour.isoformat()))
        existing = {row[0] for row in cursor.fetchall()}

    # Generate all hours in range
    all_hours = []
    hour = start_hour
    while hour <= end_hour:
        all_hours.append(hour)
        hour += timedelta(hours=1)

    # Filter to missing hours only
    missing_hours = [h for h in all_hours if h.isoformat() not in existing]

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
    falcon_client: Optional[Hosts] = None
) -> Tuple[int, int, int]:
    """
    Process hourly sensor collection for a specific clock hour.

    Workflow:
    1. Query NGSIEM for active sensors (fallback to Hosts API if unavailable)
    2. Enrich with host metadata using smart caching
    3. Store in sensor_logs table
    4. Calculate and store hourly_counts
    5. Aggregate and store hourly_tag_counts
    6. Return metrics

    Args:
        db: BillingDatabase instance
        hour: Target clock hour to collect
        cid: Optional child CID
        falcon_client: FalconPy Hosts client (only needed if NGSIEM unavailable)

    Returns:
        tuple: (total_sensors, cache_hits, api_calls)
    """
    # Get actual CID from API if not provided
    if not cid or cid == 'default':
        cid = get_falcon_cid()

    hour_str = hour.strftime('%Y-%m-%d %H:00:00')
    hour_end = hour + timedelta(hours=1)

    # Format ISO-8601 timestamps for NGSIEM module
    hour_start_iso = hour.strftime('%Y-%m-%dT%H:%M:%SZ')
    hour_end_iso = hour_end.strftime('%Y-%m-%dT%H:%M:%SZ')

    logger.info(f"Processing collection for hour: {hour_str} (CID: {cid})")

    # Step 1: Query for active sensors
    # Try NGSIEM first, fall back to Hosts API if NGSIEM fails
    sensor_ids = []

    try:
        logger.info("Attempting NGSIEM query for accurate sensor tracking...")
        creds = load_credentials()
        sensor_ids = query_ngsiem_for_sensors(
            hour_start=hour_start_iso,
            hour_end=hour_end_iso,
            cid=cid,
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            cloud_region=creds["cloud_region"],
        )
        logger.info(f"NGSIEM query successful: {len(sensor_ids)} sensors")

    except NgsiemQueryFailed:
        logger.warning("NGSIEM failed after retries, falling back to Hosts API")
        if falcon_client is None:
            falcon_client = get_falcon_client()
        sensor_ids = query_hosts_api_for_active_sensors(
            falcon_client, hour, hour_end, cid
        )

    if not sensor_ids:
        logger.warning(f"No sensors found for hour {hour_str}")
        # Still record zero count
        db.insert_hourly_count(hour_str, cid, 0)
        return 0, 0, 0

    logger.info(f"Found {len(sensor_ids)} unique sensors for hour {hour_str}")

    # Query FCSC — OCI container runtime hosts, ProductType!=Pod
    fcsc_count = None
    try:
        creds = load_credentials()
        container_ids = query_ngsiem_for_container_hosts(
            hour_start=hour_start_iso, hour_end=hour_end_iso, cid=cid,
            client_id=creds["client_id"], client_secret=creds["client_secret"],
            cloud_region=creds["cloud_region"],
        )
        fcsc_count = len(container_ids)
        logger.info(f"FCSC (container hosts): {fcsc_count} for hour {hour_str}")
    except NgsiemQueryFailed:
        logger.warning("FCSC query failed, fcsc_count will be NULL")

    # Query FMC — pod sensors, ProductType=Pod
    fmc_count = None
    try:
        creds = load_credentials()
        fmc_ids = query_ngsiem_for_fmc(
            hour_start=hour_start_iso, hour_end=hour_end_iso, cid=cid,
            client_id=creds["client_id"], client_secret=creds["client_secret"],
            cloud_region=creds["cloud_region"],
        )
        fmc_count = len(fmc_ids)
        logger.info(f"FMC (pod sensors): {fmc_count} for hour {hour_str}")
    except NgsiemQueryFailed:
        logger.warning("FMC query failed, fmc_count will be NULL")

    # Query FCS — SensorHeartbeat, not pod, !join to exclude OCI hosts
    fcs_ids = None
    fcs_count = None
    try:
        creds = load_credentials()
        fcs_ids = query_ngsiem_for_fcs(
            hour_start=hour_start_iso, hour_end=hour_end_iso, cid=cid,
            client_id=creds["client_id"], client_secret=creds["client_secret"],
            cloud_region=creds["cloud_region"],
        )
        fcs_count = len(fcs_ids)
        logger.info(f"FCS (raw, before classification): {fcs_count} for hour {hour_str}")
    except NgsiemQueryFailed:
        logger.warning("FCS query failed, fcs_count will be NULL")

    # Step 2: Enrich with host metadata (smart caching)
    if falcon_client is None:
        falcon_client = get_falcon_client()
    enriched = enrich_sensors_with_host_details(falcon_client, db, sensor_ids)

    # Classify fcs_ids into FCS (VMs/servers) vs EPP (user endpoints)
    from falcon_billing.classifier import is_cloud_vm
    fcs_final = None
    epp_count = None
    if fcs_ids is not None:
        fcs_final = 0
        epp_count = 0
        for aid in fcs_ids:
            meta = enriched.get(aid, {})
            if is_cloud_vm(
                manufacturer=meta.get('manufacturer'),
                cloud_provider=meta.get('cloud_provider'),
                tags=meta.get('tags'),
                product_type_desc=meta.get('product_type_desc'),
            ):
                fcs_final += 1
            else:
                epp_count += 1
        fcs_count = fcs_final
        logger.info(f"FCS (VMs/servers): {fcs_final}, EPP (endpoints): {epp_count} for hour {hour_str}")

    # Tally check
    if all(v is not None for v in [fcsc_count, fmc_count, fcs_final, epp_count]):
        tally = fcs_final + epp_count + fcsc_count + fmc_count
        total = len(sensor_ids)
        if tally == total:
            logger.info(f"Tally OK: FCS({fcs_final}) + EPP({epp_count}) + FCSC({fcsc_count}) + FMC({fmc_count}) = {tally} == Total({total})")
        else:
            logger.warning(f"Tally MISMATCH: FCS({fcs_final}) + EPP({epp_count}) + FCSC({fcsc_count}) + FMC({fmc_count}) = {tally} != Total({total})")

    # Calculate cache metrics
    cache_hits, cache_misses, hit_rate = db.cache_hit_rate(sensor_ids, max_age_hours=24)
    api_calls = cache_misses

    # Step 3: Bulk insert into sensor_logs
    sensors_to_insert = []
    for sensor_id in sensor_ids:
        if sensor_id in enriched:
            sensors_to_insert.append(enriched[sensor_id])
        else:
            # Sensor not enriched (API failure) - store minimal data
            logger.warning(f"Sensor {sensor_id} not enriched, storing minimal data")
            sensors_to_insert.append({
                'sensor_id': sensor_id,
                'hostname': None,
                'platform_name': None,
                'platform_version': None,
                'os_version': None,
                'status': None,
                'last_seen': None,
                'groups': [],
                'tags': [],
                'cid': cid
            })

    db.insert_sensor_logs(hour_str, sensors_to_insert, cid)
    logger.info(f"Inserted {len(sensors_to_insert)} sensor logs")

    # Step 4: Calculate and store hourly count
    unique_count = len(sensor_ids)
    db.insert_hourly_count(hour_str, cid, unique_count, fcsc_count, fmc_count, fcs_count, epp_count)
    logger.info(f"Stored hourly count: Total={unique_count}, FCS={fcs_count}, EPP={epp_count}, FCSC={fcsc_count}, FMC={fmc_count}")

    # Step 5: Aggregate tag counts
    db.aggregate_tag_counts(hour_str, cid)
    logger.info(f"Aggregated tag counts for hour {hour_str}")

    # Return metrics
    return unique_count, cache_hits, api_calls


def fetch_hour_sensors(
    hour: datetime,
    cid: str,
    falcon_client,
) -> Tuple[datetime, str, List[str], Optional[List[str]], Optional[List[str]], Optional[List[str]]]:
    """
    Query all 4 NGSIEM queries for a single hour. No DB interaction.
    Returns (hour, resolved_cid, sensor_ids, fcsc_ids, fmc_ids, fcs_ids).
    Individual lists are None if that query failed.
    """
    from falcon_billing.credentials import load_credentials

    if not cid or cid == 'default':
        cid = get_falcon_cid()

    hour_end = hour + timedelta(hours=1)
    hour_start_iso = hour.strftime('%Y-%m-%dT%H:%M:%SZ')
    hour_end_iso = hour_end.strftime('%Y-%m-%dT%H:%M:%SZ')

    # Q1: Total
    try:
        creds = load_credentials()
        sensor_ids = query_ngsiem_for_sensors(
            hour_start=hour_start_iso, hour_end=hour_end_iso, cid=cid,
            client_id=creds["client_id"], client_secret=creds["client_secret"],
            cloud_region=creds["cloud_region"],
        )
    except NgsiemQueryFailed:
        logger.warning("NGSIEM total query failed for %s, falling back to Hosts API", hour_start_iso)
        sensor_ids = query_hosts_api_for_active_sensors(falcon_client, hour, hour_end, cid)

    # Q2: FCSC
    fcsc_ids = None
    try:
        creds = load_credentials()
        fcsc_ids = query_ngsiem_for_container_hosts(
            hour_start=hour_start_iso, hour_end=hour_end_iso, cid=cid,
            client_id=creds["client_id"], client_secret=creds["client_secret"],
            cloud_region=creds["cloud_region"],
        )
    except NgsiemQueryFailed:
        logger.warning("FCSC query failed for %s", hour_start_iso)

    # Q3: FMC
    fmc_ids = None
    try:
        creds = load_credentials()
        fmc_ids = query_ngsiem_for_fmc(
            hour_start=hour_start_iso, hour_end=hour_end_iso, cid=cid,
            client_id=creds["client_id"], client_secret=creds["client_secret"],
            cloud_region=creds["cloud_region"],
        )
    except NgsiemQueryFailed:
        logger.warning("FMC query failed for %s", hour_start_iso)

    # Q4: FCS
    fcs_ids = None
    try:
        creds = load_credentials()
        fcs_ids = query_ngsiem_for_fcs(
            hour_start=hour_start_iso, hour_end=hour_end_iso, cid=cid,
            client_id=creds["client_id"], client_secret=creds["client_secret"],
            cloud_region=creds["cloud_region"],
        )
    except NgsiemQueryFailed:
        logger.warning("FCS query failed for %s", hour_start_iso)

    return hour, cid, sensor_ids, fcsc_ids, fmc_ids, fcs_ids


def store_hour_data(
    db,
    hour: datetime,
    cid: str,
    sensor_ids: List[str],
    falcon_client,
    fcsc_ids: Optional[List[str]] = None,
    fmc_ids: Optional[List[str]] = None,
    fcs_ids: Optional[List[str]] = None,
) -> Tuple[int, int, int]:
    """Store pre-fetched sensor IDs for a single hour. Returns (unique_count, cache_hits, api_calls)."""
    from falcon_billing.classifier import is_cloud_vm

    hour_str = hour.strftime('%Y-%m-%d %H:00:00')

    fcsc_count = len(fcsc_ids) if fcsc_ids is not None else None
    fmc_count = len(fmc_ids) if fmc_ids is not None else None

    if not sensor_ids:
        logger.warning("No sensors found for hour %s", hour_str)
        db.insert_hourly_count(hour_str, cid, 0, fcsc_count, fmc_count, None, None)
        return 0, 0, 0

    enriched = enrich_sensors_with_host_details(falcon_client, db, sensor_ids)
    cache_hits, cache_misses, _ = db.cache_hit_rate(sensor_ids, max_age_hours=24)

    sensors_to_insert = []
    for sensor_id in sensor_ids:
        if sensor_id in enriched:
            sensors_to_insert.append(enriched[sensor_id])
        else:
            sensors_to_insert.append({
                'sensor_id': sensor_id,
                'hostname': None, 'platform_name': None, 'platform_version': None,
                'os_version': None, 'status': None, 'last_seen': None,
                'groups': [], 'tags': [], 'cid': cid,
            })

    db.insert_sensor_logs(hour_str, sensors_to_insert, cid)
    unique_count = len(sensor_ids)

    # Classify fcs_ids into FCS (VMs/servers) vs EPP (user endpoints)
    fcs_final = None
    epp_count = None
    if fcs_ids is not None:
        fcs_final = 0
        epp_count = 0
        for aid in fcs_ids:
            meta = enriched.get(aid, {})
            if is_cloud_vm(
                manufacturer=meta.get('manufacturer'),
                cloud_provider=meta.get('cloud_provider'),
                tags=meta.get('tags'),
                product_type_desc=meta.get('product_type_desc'),
            ):
                fcs_final += 1
            else:
                epp_count += 1

    db.insert_hourly_count(hour_str, cid, unique_count, fcsc_count, fmc_count, fcs_final, epp_count)
    db.aggregate_tag_counts(hour_str, cid)

    if all(v is not None for v in [fcs_final, epp_count, fcsc_count, fmc_count]):
        tally = fcs_final + epp_count + fcsc_count + fmc_count
        if tally == unique_count:
            logger.info("Tally OK: FCS(%d) + EPP(%d) + FCSC(%d) + FMC(%d) = %d == Total(%d)",
                        fcs_final, epp_count, fcsc_count, fmc_count, tally, unique_count)
        else:
            logger.warning("Tally MISMATCH: FCS(%d) + EPP(%d) + FCSC(%d) + FMC(%d) = %d != Total(%d)",
                           fcs_final, epp_count, fcsc_count, fmc_count, tally, unique_count)

    return unique_count, cache_hits, cache_misses


def parallel_backfill(
    db,
    hours: List[datetime],
    cid: str,
    falcon_client,
    workers: int = 10,
) -> None:
    """
    Fetch all NGSIEM queries concurrently, then store results sequentially.
    Keeps SQLite writes single-threaded while parallelising the slow network IO.
    """
    logger.info("Parallel backfill: %d hours with %d workers", len(hours), workers)

    # Phase 1: fetch all hours in parallel
    results: Dict[datetime, Tuple[str, List[str]]] = {}
    errors: Dict[datetime, Exception] = {}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_hour = {
            executor.submit(fetch_hour_sensors, hour, cid, falcon_client): hour
            for hour in hours
        }
        completed = 0
        for future in as_completed(future_to_hour):
            hour = future_to_hour[future]
            completed += 1
            try:
                _, resolved_cid, sensor_ids, fcsc_ids, fmc_ids, fcs_ids = future.result()
                results[hour] = (resolved_cid, sensor_ids, fcsc_ids, fmc_ids, fcs_ids)
            except Exception as exc:
                logger.error("Fetch failed for %s: %s", hour, exc)
                errors[hour] = exc
            if completed % 24 == 0:
                logger.info("Fetched %d/%d hours", completed, len(hours))

    if errors:
        logger.warning("%d hours failed to fetch and will be skipped", len(errors))

    # Phase 2: store sequentially in chronological order
    logger.info("Storing %d hours to database...", len(results))
    for i, hour in enumerate(sorted(results.keys()), 1):
        resolved_cid, sensor_ids, fcsc_ids, fmc_ids, fcs_ids = results[hour]
        store_hour_data(db, hour, resolved_cid, sensor_ids, falcon_client, fcsc_ids, fmc_ids, fcs_ids)
        if i % 24 == 0:
            logger.info("Stored %d/%d hours", i, len(results))


# ============================================================================
# Verification Functions
# ============================================================================

def verify_billing_accuracy(
    db: BillingDatabase,
    date: str,
    cid: str = 'default'
) -> Tuple[float, float, float, bool]:
    """
    Verify calculated 28-day average matches billing API.

    Args:
        db: BillingDatabase instance
        date: Date to verify (YYYY-MM-DD)
        cid: Child CID or 'default'

    Returns:
        tuple: (calculated_avg, api_avg, diff_pct, passed)
    """
    # Calculate 28-day average from hourly_counts
    calculated_avg = db.calculate_28day_average(cid)["averages"]["total"]

    # Query billing API data
    billing_data = db.get_billing_average(date, cid)

    if not billing_data:
        logger.warning(f"No billing API data found for {date}")
        return calculated_avg, 0.0, 0.0, False

    # Use managed_containers as reference (primary billing number)
    api_avg = billing_data.get('managed_containers', 0) or 0

    # Calculate difference percentage
    if api_avg > 0:
        diff = calculated_avg - api_avg
        diff_pct = (diff / api_avg) * 100
    else:
        diff = calculated_avg
        diff_pct = 100.0 if calculated_avg > 0 else 0.0

    # Pass if within 1%
    passed = abs(diff_pct) < 1.0

    if not passed:
        logger.warning(
            f"Verification FAILED for {date}: "
            f"calculated={calculated_avg:.2f}, api={api_avg:.2f}, "
            f"diff={diff_pct:.2f}%"
        )
    else:
        logger.info(
            f"Verification PASSED for {date}: "
            f"calculated={calculated_avg:.2f}, api={api_avg:.2f}, "
            f"diff={diff_pct:.2f}%"
        )

    return calculated_avg, api_avg, diff_pct, passed


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


def generate_verification_report(
    db: BillingDatabase,
    start_date: str,
    end_date: str,
    output_path: Optional[str] = None,
    cid: str = 'default'
) -> str:
    """
    Generate daily verification report comparing calculated vs API values.

    Args:
        db: BillingDatabase instance
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)
        output_path: Optional output path (default: auto-generated)
        cid: Child CID or 'default'

    Returns:
        str: Path to generated report
    """
    if not output_path:
        output_dir = Path(__file__).parent.parent / "verification_reports"
        output_dir.mkdir(exist_ok=True)
        output_path = output_dir / f"verification_{start_date}_{end_date}.csv"

    # Generate report data
    import csv
    from datetime import datetime, timedelta

    start_dt = datetime.strptime(start_date, '%Y-%m-%d')
    end_dt = datetime.strptime(end_date, '%Y-%m-%d')

    results = []
    current_dt = start_dt

    while current_dt <= end_dt:
        date_str = current_dt.strftime('%Y-%m-%d')
        calculated, api, diff_pct, passed = verify_billing_accuracy(db, date_str, cid)

        results.append({
            'date': date_str,
            'calculated_avg': f"{calculated:.2f}",
            'api_avg': f"{api:.2f}",
            'diff': f"{calculated - api:.2f}",
            'diff_pct': f"{diff_pct:.2f}%",
            'status': 'PASS' if passed else 'FAIL'
        })

        current_dt += timedelta(days=1)

    # Write CSV
    with open(output_path, 'w', newline='') as csvfile:
        fieldnames = ['date', 'calculated_avg', 'api_avg', 'diff', 'diff_pct', 'status']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    logger.info(f"Verification report written to {output_path}")
    return str(output_path)


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
