"""NGSIEM/LogScale query functions with retry logic.

Queries CrowdStrike NG-SIEM (LogScale) for active sensor data.
Implements exponential timeout escalation with configurable retries.
"""

import logging
import time
from datetime import datetime, timedelta
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# LogScale query to find unique sensors (agent IDs) active during a time window
_SENSOR_QUERY = """
#event_simpleName=SensorHeartbeat
| groupBy(aid, function=count())
| select([aid])
"""

# Bulk query: format timestamp as hour key and return unique AIDs per hour
_BULK_SENSOR_QUERY = """
#event_simpleName=SensorHeartbeat
| hour_key := formatTime("%Y-%m-%d %H:00:00", field=@timestamp, timezone="UTC")
| groupBy([hour_key, aid], function=count())
"""

# OciContainerInfo fires when a container starts and is resent every 24h while
# it runs. It is KAC-independent and carries container identity, so it is the
# billing-faithful FCSC signal. Older sensor builds (and hosts with
# OciContainerSupport off) never emit it, so counting Info alone runs ~5 hosts
# low against the official number on talon_1.
_CONTAINER_HOST_QUERY_INFO_ONLY = """
#event_simpleName=OciContainerInfo
| groupBy(aid, function=count(), limit=max)
| select([aid])
"""

# Union with OciContainerStarted catches the older-build hosts that run
# containers but never emit OciContainerInfo. This is the showback default: it
# counts every host showing container activity and errs generous, which suits a
# per-tag view whose totals already exceed the CID total by design. The billed
# CID total comes from the Sensor Usage API, not from this query.
_CONTAINER_HOST_QUERY = """
#event_simpleName=OciContainerInfo or #event_simpleName=OciContainerStarted
| groupBy(aid, function=count(), limit=max)
| select([aid])
"""

# Evidence query: same union as the count, but collect the identity fields each
# OciContainerInfo carries so a host billed FCSC can be justified by the images
# and engines that ran on it. OciContainerStarted carries none of these, so a
# Started-only host groups here with empty identity, which is how it is flagged.
_CONTAINER_EVIDENCE_QUERY = """
#event_simpleName=OciContainerInfo or #event_simpleName=OciContainerStarted
| groupBy([aid], function=collect([OciContainerName, OciContainerImageId, OciContainerEngineType]), limit=max)
"""

CONTAINER_HOST_LOOKBACK = timedelta(hours=25)


class NgsiemQueryFailed(Exception):
    """Raised when all NGSIEM query attempts are exhausted."""


def get_access_token(
    client_id: str,
    client_secret: str,
    cloud_region: str = "us-1",
) -> str:
    """Retrieve an OAuth2 bearer token from the Falcon API.

    Args:
        client_id: Falcon API client ID.
        client_secret: Falcon API client secret.
        cloud_region: CrowdStrike cloud region (e.g. "us-1", "eu-1").

    Returns:
        Access token string.

    Raises:
        RuntimeError: If the token cannot be extracted from the API response.
    """
    try:
        from falconpy import OAuth2
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "falconpy is required for NGSIEM queries. "
            "Install it with: pip install crowdstrike-falconpy"
        ) from exc

    if cloud_region == "us-1":
        base_url = "https://api.crowdstrike.com"
    else:
        base_url = f"https://api.{cloud_region}.crowdstrike.com"

    auth = OAuth2(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
    )

    token_result = auth.token()

    if isinstance(token_result, dict):
        if "body" in token_result and isinstance(token_result["body"], dict):
            access_token = token_result["body"].get("access_token")
            if access_token:
                return access_token
        elif "access_token" in token_result:
            return token_result["access_token"]

    raise RuntimeError(
        f"Failed to extract access token from Falcon API response: {token_result}"
    )


def _execute_ngsiem_query(
    hour_start: str,
    hour_end: str,
    cid: str,
    *,
    client_id: str,
    client_secret: str,
    cloud_region: str = "us-1",
    view_name: str = "search-all",
    timeout: int = 30,
    query_string: str = _SENSOR_QUERY,
    return_events: bool = False,
) -> list:
    """Execute a single NGSIEM query and return unique sensor IDs.

    Submits a LogScale query job for the given time window, polls until
    completion, and returns the list of unique agent IDs found.

    Args:
        hour_start: ISO-8601 UTC start timestamp (e.g. "2026-04-21T10:00:00Z").
        hour_end: ISO-8601 UTC end timestamp (e.g. "2026-04-21T11:00:00Z").
        cid: Customer ID (used for logging context).
        client_id: Falcon API client ID.
        client_secret: Falcon API client secret.
        cloud_region: CrowdStrike cloud region (e.g. "us-1", "eu-1").
        view_name: LogScale repository/view to query.
        timeout: Per-request HTTP timeout in seconds (applied to job submission
            and each poll request).

    Returns:
        List of unique sensor IDs active during the requested window.

    Raises:
        TimeoutError: If the query job does not complete within the polling
            window (governed by the ``timeout`` parameter).
        RuntimeError: If the job is cancelled or enters a FAILED state, or if
            the HTTP response indicates an error.
        PermissionError: If the API returns a 403 Forbidden response.
    """
    access_token = get_access_token(
        client_id=client_id,
        client_secret=client_secret,
        cloud_region=cloud_region,
    )

    if cloud_region == "us-1":
        base_url = "https://api.crowdstrike.com"
    else:
        base_url = f"https://api.{cloud_region}.crowdstrike.com"

    endpoint = f"{base_url}/humio/api/v1/repositories/{view_name}/queryjobs"

    # Convert ISO-8601 strings to millisecond epoch timestamps for LogScale
    from datetime import datetime, timezone

    def _parse_ts(ts: str) -> int:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)

    start_ms = _parse_ts(hour_start)
    end_ms = _parse_ts(hour_end)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    body = {
        "queryString": query_string,
        "start": start_ms,
        "end": end_ms,
        "isLive": False,
    }

    logger.info(
        "Querying NGSIEM for sensors active between %s and %s (cid=%s)",
        hour_start,
        hour_end,
        cid,
    )

    # Submit query job
    response = requests.post(
        endpoint, headers=headers, json=body, timeout=timeout
    )

    if response.status_code == 403:
        raise PermissionError(
            f"NGSIEM query failed (403): Permission denied. "
            f"Add 'humio-auth-proxy:write' (Event Search: Write) scope to your Falcon API client."
        )

    if response.status_code != 200:
        raise RuntimeError(
            f"NGSIEM query submission failed ({response.status_code}): {response.text}"
        )

    job_data = response.json()
    job_id = job_data.get("id")

    if not job_id:
        raise RuntimeError(f"No job ID returned from NGSIEM: {job_data}")

    logger.info("NGSIEM query job submitted: %s", job_id)

    # Poll for results — honour the per-attempt timeout for each poll request
    poll_url = f"{endpoint}/{job_id}"
    max_polls = timeout  # 1 poll per second up to timeout seconds
    poll_timeout = min(timeout, 10)  # individual poll HTTP timeout

    for attempt in range(max_polls):
        time.sleep(1)

        poll_response = requests.get(poll_url, headers=headers, timeout=poll_timeout)

        if poll_response.status_code != 200:
            raise RuntimeError(
                f"NGSIEM poll failed ({poll_response.status_code}): {poll_response.text}"
            )

        poll_data = poll_response.json()
        done = poll_data.get("done", False)
        cancelled = poll_data.get("cancelled", False)
        state = poll_data.get("state", "UNKNOWN")

        if done and not cancelled:
            events = poll_data.get("events", [])
            if return_events:
                logger.info("NGSIEM query complete: %d grouped rows", len(events))
                return events
            sensor_ids = [
                event["aid"] for event in events if event.get("aid")
            ]
            logger.info(
                "NGSIEM query complete: found %d unique sensors", len(sensor_ids)
            )
            return sensor_ids

        if cancelled:
            error = poll_data.get("error", "Query was cancelled")
            raise RuntimeError(f"NGSIEM query cancelled: {error}")

        if state == "FAILED":
            error = poll_data.get("error", "Unknown error")
            raise RuntimeError(f"NGSIEM query failed: {error}")

        if attempt > 0 and attempt % 10 == 0:
            logger.info("NGSIEM query still running... (%ds)", attempt)

    raise TimeoutError(f"NGSIEM query timed out after {max_polls} seconds")


def query_ngsiem_for_sensors(
    hour_start: str,
    hour_end: str,
    cid: str,
    *,
    client_id: str,
    client_secret: str,
    cloud_region: str = "us-1",
    view_name: str = "search-all",
    max_retries: int = 3,
    timeout_sequence: tuple[int, ...] = (30, 60, 120),
    query_string: str = _SENSOR_QUERY,
) -> list[str]:
    """Query NGSIEM for sensors active during a given hour, with retry logic.

    Calls :func:`_execute_ngsiem_query` up to *max_retries* times, using
    escalating timeouts from *timeout_sequence*.  A :exc:`TimeoutError`,
    :exc:`requests.Timeout`, or :exc:`requests.ConnectionError` causes a
    retry after a brief pause.  Any other exception propagates immediately.

    Args:
        hour_start: ISO-8601 UTC start of the billing hour
            (e.g. "2026-04-21T10:00:00Z").
        hour_end: ISO-8601 UTC end of the billing hour.
        cid: Customer ID being queried (used for auth context).
        client_id: Falcon API client ID.
        client_secret: Falcon API client secret.
        cloud_region: CrowdStrike cloud region (default ``"us-1"``).
        view_name: LogScale repository/view to query (default ``"search-all"``).
        max_retries: Maximum number of attempts (default ``3``).
        timeout_sequence: Sequence of per-attempt timeout values in seconds.
            Must have at least *max_retries* elements (extras are ignored).

    Returns:
        List of unique sensor IDs active during the requested window.

    Raises:
        NgsiemQueryFailed: If all retries are exhausted without a successful
            result.
    """
    _retryable = (TimeoutError, requests.Timeout, requests.ConnectionError)
    last_exc: Optional[Exception] = None

    for attempt in range(max_retries):
        timeout = timeout_sequence[attempt]
        try:
            return _execute_ngsiem_query(
                hour_start,
                hour_end,
                cid,
                client_id=client_id,
                client_secret=client_secret,
                cloud_region=cloud_region,
                view_name=view_name,
                timeout=timeout,
                query_string=query_string,
            )
        except _retryable as exc:
            last_exc = exc
            logger.warning(
                "NGSIEM query attempt %d/%d failed (%s: %s). Retrying in 2s...",
                attempt + 1,
                max_retries,
                type(exc).__name__,
                exc,
            )
            if attempt < max_retries - 1:
                time.sleep(2)

    raise NgsiemQueryFailed(
        f"NGSIEM query failed after {max_retries} attempts: {last_exc}"
    )


def query_ngsiem_for_container_hosts(
    hour_end: str,
    cid: str,
    *,
    client_id: str,
    client_secret: str,
    cloud_region: str = "us-1",
    view_name: str = "search-all",
    max_retries: int = 3,
    timeout_sequence: tuple[int, ...] = (30, 60, 120),
    info_only: bool = False,
) -> list[str]:
    dt_end = datetime.fromisoformat(hour_end.replace("Z", "+00:00"))
    lookback_start = (dt_end - CONTAINER_HOST_LOOKBACK).strftime("%Y-%m-%dT%H:%M:%SZ")

    query_string = (
        _CONTAINER_HOST_QUERY_INFO_ONLY if info_only else _CONTAINER_HOST_QUERY
    )

    return query_ngsiem_for_sensors(
        lookback_start,
        hour_end,
        cid,
        client_id=client_id,
        client_secret=client_secret,
        cloud_region=cloud_region,
        view_name=view_name,
        max_retries=max_retries,
        timeout_sequence=timeout_sequence,
        query_string=query_string,
    )


# collect() joins each field's values with a newline in the humio events output.
_COLLECT_SEP = "\n"


def _split_collected(value: Optional[str]) -> list:
    """Split one collect()ed field into its distinct non-empty values, order kept."""
    if not value:
        return []
    seen = []
    for item in str(value).split(_COLLECT_SEP):
        item = item.strip()
        if item and item not in seen:
            seen.append(item)
    return seen


def parse_container_evidence(events: list) -> dict:
    """Turn grouped evidence rows into per-host container identity.

    Each row is one aid with its collected OciContainerName, OciContainerImageId,
    and OciContainerEngineType. A host seen only through OciContainerStarted has
    none of these, so it is marked started_only. That is the flag the design
    calls for, derived from the absence of identity rather than a second query.

    Returns aid -> {names, images, engines, started_only}.
    """
    evidence = {}
    for row in events:
        aid = row.get("aid")
        if not aid:
            continue
        names = _split_collected(row.get("OciContainerName"))
        images = _split_collected(row.get("OciContainerImageId"))
        engines = _split_collected(row.get("OciContainerEngineType"))
        evidence[aid] = {
            "names": names,
            "images": images,
            "engines": engines,
            "started_only": not (names or images or engines),
        }
    return evidence


def query_ngsiem_for_container_evidence(
    hour_end: str,
    cid: str,
    *,
    client_id: str,
    client_secret: str,
    cloud_region: str = "us-1",
    view_name: str = "search-all",
    max_retries: int = 3,
    timeout_sequence: tuple[int, ...] = (30, 60, 120),
) -> dict:
    """Query the FCSC evidence: per-host container names, images, and engines.

    Runs the OciContainerInfo ∪ OciContainerStarted union over the same 25h
    lookback as the count, collecting the identity fields. Returns the parsed
    aid -> identity mapping from :func:`parse_container_evidence`.
    """
    dt_end = datetime.fromisoformat(hour_end.replace("Z", "+00:00"))
    lookback_start = (dt_end - CONTAINER_HOST_LOOKBACK).strftime("%Y-%m-%dT%H:%M:%SZ")

    _retryable = (TimeoutError, requests.Timeout, requests.ConnectionError)
    last_exc: Optional[Exception] = None

    for attempt in range(max_retries):
        try:
            events = _execute_ngsiem_query(
                lookback_start,
                hour_end,
                cid,
                client_id=client_id,
                client_secret=client_secret,
                cloud_region=cloud_region,
                view_name=view_name,
                timeout=timeout_sequence[attempt],
                query_string=_CONTAINER_EVIDENCE_QUERY,
                return_events=True,
            )
            return parse_container_evidence(events)
        except _retryable as exc:
            last_exc = exc
            logger.warning(
                "FCSC evidence query attempt %d/%d failed (%s). Retrying in 2s...",
                attempt + 1, max_retries, type(exc).__name__,
            )
            if attempt < max_retries - 1:
                time.sleep(2)

    raise NgsiemQueryFailed(
        f"FCSC evidence query failed after {max_retries} attempts: {last_exc}"
    )


def query_ngsiem_bulk(
    start_iso: str,
    end_iso: str,
    cid: str,
    *,
    client_id: str,
    client_secret: str,
    cloud_region: str = "us-1",
    view_name: str = "search-all",
    timeout: int = 120,
) -> dict[str, list[str]]:
    """Query NGSIEM for all sensors across a date range in a single query.

    Instead of one query per hour, this submits a single query using
    ``bucket(span=1h)`` to aggregate unique AIDs per hour bucket.

    Args:
        start_iso: ISO-8601 UTC start (e.g. "2026-04-17T10:00:00Z").
        end_iso: ISO-8601 UTC end (e.g. "2026-04-24T10:00:00Z").
        cid: Customer ID (for logging).
        client_id: Falcon API client ID.
        client_secret: Falcon API client secret.
        cloud_region: CrowdStrike cloud region.
        view_name: LogScale repository/view to query.
        timeout: HTTP and poll timeout in seconds.

    Returns:
        Dict mapping hour timestamp string ("YYYY-MM-DD HH:00:00") to list of AIDs.
    """
    from datetime import datetime as _dt, timezone as _tz

    access_token = get_access_token(
        client_id=client_id,
        client_secret=client_secret,
        cloud_region=cloud_region,
    )

    if cloud_region == "us-1":
        base_url = "https://api.crowdstrike.com"
    else:
        base_url = f"https://api.{cloud_region}.crowdstrike.com"

    endpoint = f"{base_url}/humio/api/v1/repositories/{view_name}/queryjobs"

    def _parse_ts(ts: str) -> int:
        dt = _dt.fromisoformat(ts.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)

    start_ms = _parse_ts(start_iso)
    end_ms = _parse_ts(end_iso)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    body = {
        "queryString": _BULK_SENSOR_QUERY,
        "start": start_ms,
        "end": end_ms,
        "isLive": False,
    }

    logger.info(
        "NGSIEM bulk query: %s to %s (cid=%s)", start_iso, end_iso, cid
    )

    response = requests.post(endpoint, headers=headers, json=body, timeout=timeout)

    if response.status_code == 403:
        raise PermissionError(
            "NGSIEM query failed (403): Permission denied. "
            "Add 'ngsiem:write' (Event Search: Write) scope to your Falcon API client."
        )
    if response.status_code != 200:
        raise RuntimeError(
            f"NGSIEM bulk query submission failed ({response.status_code}): {response.text}"
        )

    job_data = response.json()
    job_id = job_data.get("id")
    if not job_id:
        raise RuntimeError(f"No job ID returned from NGSIEM: {job_data}")

    logger.info("NGSIEM bulk query job submitted: %s", job_id)

    # Poll for results
    poll_url = f"{endpoint}/{job_id}"
    max_polls = timeout
    poll_timeout = min(timeout, 10)

    for attempt in range(max_polls):
        time.sleep(1)
        poll_response = requests.get(poll_url, headers=headers, timeout=poll_timeout)

        if poll_response.status_code != 200:
            raise RuntimeError(
                f"NGSIEM poll failed ({poll_response.status_code}): {poll_response.text}"
            )

        poll_data = poll_response.json()
        done = poll_data.get("done", False)
        cancelled = poll_data.get("cancelled", False)
        state = poll_data.get("state", "UNKNOWN")

        if done and not cancelled:
            events = poll_data.get("events", [])
            # Group AIDs by hour key
            hourly: dict[str, list[str]] = {}
            for event in events:
                aid = event.get("aid")
                hour_key = event.get("hour_key")
                if not aid or not hour_key:
                    continue
                hourly.setdefault(hour_key, []).append(aid)

            logger.info(
                "NGSIEM bulk query complete: %d events across %d hours",
                len(events),
                len(hourly),
            )
            return hourly

        if cancelled:
            raise RuntimeError(f"NGSIEM query cancelled: {poll_data.get('error')}")
        if state == "FAILED":
            raise RuntimeError(f"NGSIEM query failed: {poll_data.get('error')}")
        if attempt > 0 and attempt % 10 == 0:
            logger.info("NGSIEM bulk query still running... (%ds)", attempt)

    raise TimeoutError(f"NGSIEM bulk query timed out after {max_polls}s")
