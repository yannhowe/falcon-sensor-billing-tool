#!/usr/bin/env python3
"""
NG SIEM Event Search API - Correct Implementation

Uses the LogScale API via /humio/api/v1/repositories/{view}/queryjobs
This is the correct endpoint for standard API clients (NOT Foundry-only).

Required API Scope: ngsiem:read (or ngsiem:write for full access)
"""
import os
import sys
import json
import time
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Add FalconPy to path for OAuth2
FALCONPY_PATH = Path(__file__).parent.parent.parent / "repos" / "falconpy" / "src"
sys.path.insert(0, str(FALCONPY_PATH))

try:
    from falconpy import OAuth2
except ImportError as e:
    print(f"Error: Cannot import FalconPy. Make sure it's at: {FALCONPY_PATH}")
    sys.exit(1)


def get_access_token():
    """Get OAuth2 access token from Falcon API."""
    client_id = os.environ.get('FALCON_CLIENT_ID')
    client_secret = os.environ.get('FALCON_CLIENT_SECRET')
    region = os.environ.get('FALCON_CLOUD_REGION', 'us-1')
    
    if not client_id or not client_secret:
        raise ValueError("Falcon credentials not set in environment")
    
    base_url = 'https://api.crowdstrike.com' if region == 'us-1' else f'https://api.{region}.crowdstrike.com'
    
    auth = OAuth2(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url
    )
    
    # Get token - FalconPy returns dict with body containing access_token
    token_result = auth.token()

    if isinstance(token_result, dict):
        # Check if it's a full response with body
        if 'body' in token_result and isinstance(token_result['body'], dict):
            access_token = token_result['body'].get('access_token')
            if access_token:
                return access_token, region
        # Or direct access_token in response
        elif 'access_token' in token_result:
            return token_result['access_token'], region

    raise RuntimeError(f"Failed to extract access token from response: {token_result}")


def query_ngsiem_for_sensors(
    hour_start: datetime,
    hour_end: datetime,
    view_name: str = "search-all"
) -> list:
    """
    Query NG SIEM Event Search API for unique sensors active during target hour.
    
    Uses the LogScale API endpoint:
    POST {cloud}.crowdstrike.com/humio/api/v1/repositories/{view-name}/queryjobs
    
    Args:
        hour_start: Start of clock hour (inclusive)
        hour_end: End of clock hour (exclusive)
        view_name: NGSIEM view to query:
            - "search-all" (default) - All events
            - "investigate_view" - Falcon events
            - "third-party" - Third party events
            - "falcon_for_it_view" - IT Automation
            - "forensics_view" - Forensics
    
    Returns:
        list: Unique sensor IDs (agent IDs) active during hour
    """
    # Get authentication
    access_token, region = get_access_token()
    
    # Build LogScale API URL
    # For us-1, use api.crowdstrike.com
    # For other regions, use api.{region}.crowdstrike.com
    if region == 'us-1':
        base_url = "https://api.crowdstrike.com"
    else:
        base_url = f"https://api.{region}.crowdstrike.com"

    endpoint = f"{base_url}/humio/api/v1/repositories/{view_name}/queryjobs"
    
    # Format timestamps (LogScale uses milliseconds since epoch)
    start_ms = int(hour_start.timestamp() * 1000)
    end_ms = int(hour_end.timestamp() * 1000)
    
    # Build LogScale query
    # Query for common heartbeat events and group by agent ID
    query = """
#event_simpleName=AgentOnline OR #event_simpleName=ProcessRollup2 OR #event_simpleName=UserLogon
| groupBy(aid, function=count())
| select([aid])
"""
    
    # Prepare request
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    body = {
        "queryString": query,
        "start": start_ms,
        "end": end_ms,
        "isLive": False  # Historical query, not live tail
    }
    
    print(f"Querying NG SIEM Event Search API...")
    print(f"  View: {view_name}")
    print(f"  Time range: {hour_start.strftime('%Y-%m-%d %H:%M:%S')} to {hour_end.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Endpoint: {endpoint}")
    print()
    
    # Submit query job
    response = requests.post(endpoint, headers=headers, json=body, timeout=30)
    
    if response.status_code != 200:
        error_msg = response.text
        if response.status_code == 403:
            raise PermissionError(
                f"Permission denied (403): {error_msg}\n\n"
                f"SOLUTION: Add 'ngsiem:read' or 'ngsiem:write' scope to your Falcon API client"
            )
        raise RuntimeError(f"Query submission failed ({response.status_code}): {error_msg}")
    
    # Get query job ID
    job_data = response.json()
    job_id = job_data.get("id")
    
    if not job_id:
        raise RuntimeError(f"No job ID returned: {job_data}")
    
    print(f"✓ Query job submitted: {job_id}")
    print(f"  Waiting for results...")
    
    # Poll for results
    poll_url = f"{endpoint}/{job_id}"
    max_polls = 120  # 120 seconds max wait
    poll_interval = 1  # seconds

    for attempt in range(max_polls):
        time.sleep(poll_interval)

        poll_response = requests.get(poll_url, headers=headers, timeout=10)

        if poll_response.status_code != 200:
            raise RuntimeError(f"Poll failed ({poll_response.status_code}): {poll_response.text}")

        poll_data = poll_response.json()
        done = poll_data.get("done", False)
        cancelled = poll_data.get("cancelled", False)
        state = poll_data.get("state")  # May not be present

        if done and not cancelled:
            # Query complete - get results
            events = poll_data.get("events", [])

            # Extract unique agent IDs
            sensor_ids = []
            for event in events:
                aid = event.get("aid")
                if aid:
                    sensor_ids.append(aid)

            print(f"✓ Query complete!")
            print(f"  Found {len(sensor_ids)} unique sensors active during hour")
            return sensor_ids

        elif cancelled:
            error = poll_data.get("error", "Query was cancelled")
            raise RuntimeError(f"Query cancelled: {error}")

        elif state == "FAILED":
            error = poll_data.get("error", "Unknown error")
            raise RuntimeError(f"Query failed: {error}")

        # Still running - continue polling
        if attempt % 5 == 0:
            print(f"  Still running... ({attempt}s)")
    
    raise TimeoutError(f"Query timed out after {max_polls} seconds")


def test_ngsiem_event_search():
    """Test NG SIEM Event Search API access."""
    print("Testing NG SIEM Event Search API")
    print("=" * 80)
    print()
    
    # Query for last hour
    now = datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)
    
    try:
        sensor_ids = query_ngsiem_for_sensors(hour_ago, now, view_name="search-all")
        
        print()
        print("=" * 80)
        print("✅ SUCCESS: NG SIEM Event Search API is working!")
        print(f"   Found {len(sensor_ids)} sensors in last hour")
        print()
        print("Sample sensor IDs:")
        for sid in sensor_ids[:5]:
            print(f"  - {sid}")
        if len(sensor_ids) > 5:
            print(f"  ... and {len(sensor_ids) - 5} more")
        
        return True, f"Found {len(sensor_ids)} sensors"
        
    except PermissionError as e:
        print()
        print("=" * 80)
        print("❌ PERMISSION DENIED")
        print()
        print(str(e))
        print()
        print("Next steps:")
        print("1. Go to Falcon Console → Support and resources → API clients and keys")
        print("2. Edit your API client")
        print("3. Add 'NGSIEM' scope with Read (or Write) permission")
        print("4. Regenerate your API secret")
        print("5. Update credentials in keychain")
        print("6. Re-run this test")
        return False, str(e)
        
    except Exception as e:
        print()
        print("=" * 80)
        print(f"❌ ERROR: {str(e)}")
        return False, str(e)


if __name__ == "__main__":
    success, message = test_ngsiem_event_search()
    sys.exit(0 if success else 1)
