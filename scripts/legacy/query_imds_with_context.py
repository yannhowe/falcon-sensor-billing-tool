#!/usr/bin/env python3
"""
Query NGSIEM for IMDS traffic with URL and process context.
Produces enhanced detection data for cloud provider classification.
"""
import os
import sys
import json
import time
import subprocess
import requests
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Optional

# Add FalconPy to path
FALCONPY_PATH = Path(__file__).parent.parent.parent / "repos" / "falconpy" / "src"
sys.path.insert(0, str(FALCONPY_PATH))

from falconpy import OAuth2

# URL path patterns for cloud provider detection
URL_PATTERNS = {
    'AWS': ['/latest/', '/meta-data/', '/dynamic/'],
    'Azure': ['/metadata/instance', '/metadata/identity'],
    'GCP': ['/computeMetadata/v1/', '/computeMetadata/v1beta1/'],
    'Oracle': ['/opc/v1/', '/opc/v2/'],
    'DigitalOcean': ['/metadata/v1/'],
    'Linode': ['/v1/instance', '/v1/network'],
    # NOTE: Vultr's /v1/ is intentionally generic — it must be checked LAST
    # in URL_PATTERNS iteration to avoid false positives against Linode (/v1/instance)
    # and other providers that version their APIs with /v1/.
    'Vultr': ['/v1/'],
}

# Process name indicators
PROCESS_INDICATORS = {
    # NOTE: 'cloud-init' is intentionally excluded from AWS indicators — it runs on
    # ALL cloud providers (AWS, Azure, GCP, Oracle, etc.) and would cause false positives.
    'AWS': ['ec2-metadata', 'ec2-', 'aws-', 'amazon-ssm-agent', 'ssm-agent', 'ssm-document'],
    'Azure': ['waagent', 'walinuxagent', 'azure-'],
    'GCP': ['gce-', 'google-', 'gcemetadata'],
    'Oracle': ['oci-', 'oracle-cloud-agent'],
}

# NGSIEM query for IMDS traffic with context
ENHANCED_IMDS_QUERY = """
#event_simpleName=NetworkConnectIP4 (RemoteAddressIP4="169.254.169.254" OR RemoteAddressIP4="100.100.100.200" OR RemoteAddressIP4="169.254.42.42")
| groupBy([aid, RemoteAddressIP4, ContextBaseFileName], function=[count(), collect(TargetFileName)])
"""


def get_keychain_value(service, account):
    """Get credential from macOS Keychain."""
    try:
        result = subprocess.run(
            ['security', 'find-generic-password', '-s', service, '-a', account, '-w'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def load_credentials():
    """Load Falcon API credentials from keychain."""
    profile = 'talon_1'

    client_id = get_keychain_value('falcon-client-id', profile)
    client_secret = get_keychain_value('falcon-client-secret', profile)
    region = get_keychain_value('falcon-cloud-region', profile) or 'us-1'

    if not client_id or not client_secret:
        print("❌ Falcon API credentials not found in keychain")
        print(f"Run: /cid use {profile}")
        sys.exit(1)

    return client_id, client_secret, region


def classify_from_evidence(evidence: Dict) -> Dict:
    """
    Determine cloud provider from URL paths and process names.

    Returns: {'name': str, 'confidence': str}
    """
    url_paths = evidence.get('url_paths', [])
    processes = evidence.get('processes', [])
    imds_ip = evidence.get('imds_ip')

    # Non-standard IMDS IPs (definitive)
    if imds_ip == '100.100.100.200':
        return {'name': 'Alibaba', 'confidence': 'high'}
    elif imds_ip == '169.254.42.42':
        return {'name': 'Scaleway', 'confidence': 'high'}

    # URL path matching (high confidence)
    for path in url_paths:
        for provider, patterns in URL_PATTERNS.items():
            if any(pattern in path for pattern in patterns):
                return {'name': provider, 'confidence': 'high'}

    # Process name matching (medium confidence)
    for proc in processes:
        proc_lower = proc.lower()
        for provider, indicators in PROCESS_INDICATORS.items():
            if any(ind in proc_lower for ind in indicators):
                return {'name': provider, 'confidence': 'medium'}

    # Unknown
    return {'name': 'Others-IMDS', 'confidence': 'low'}


def query_ngsiem_with_context(days_back=7):
    """
    Query NGSIEM for IMDS traffic with URL and process context.

    Returns: List of raw NGSIEM events
    """
    # Load credentials
    client_id, client_secret, region = load_credentials()

    # Build full base URL
    if region == 'us-1':
        base_url = 'https://api.crowdstrike.com'
    else:
        base_url = f'https://api.{region}.crowdstrike.com'

    # Get OAuth2 token
    auth = OAuth2(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url
    )

    token_result = auth.token()
    if isinstance(token_result, dict):
        # Extract access token from response
        if 'body' in token_result and 'access_token' in token_result['body']:
            access_token = token_result['body']['access_token']
        elif 'access_token' in token_result:
            access_token = token_result['access_token']
        else:
            print(f"❌ Failed to get OAuth2 token: {token_result}")
            sys.exit(1)
    else:
        raise RuntimeError("OAuth2 token() returned unexpected format")

    # Build NGSIEM query endpoint
    view_name = "search-all"  # Query all events
    endpoint = f"{base_url}/humio/api/v1/repositories/{view_name}/queryjobs"

    # Date range
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days_back)

    # Format timestamps for LogScale (milliseconds since epoch)
    start_ms = int(start_time.timestamp() * 1000)
    end_ms = int(end_time.timestamp() * 1000)

    print("=" * 80)
    print("ENHANCED IMDS DETECTION WITH URL/PROCESS CONTEXT")
    print("=" * 80)
    print(f"Cloud: {region}")
    print(f"Date range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Query period: {days_back} days")
    print()

    print("🌐 Querying NGSIEM for IMDS traffic...")
    print("-" * 80)
    print("Query:")
    print(ENHANCED_IMDS_QUERY)
    print()

    # Create async search job
    query_payload = {
        "queryString": ENHANCED_IMDS_QUERY.strip(),
        "start": start_ms,
        "end": end_ms,
        "isLive": False
    }

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    response = requests.post(endpoint, json=query_payload, headers=headers)

    if response.status_code != 200:
        print(f"❌ Failed to create NGSIEM query job: {response.status_code}")
        print(f"Response: {response.text}")
        sys.exit(1)

    job_data = response.json()
    job_id = job_data.get('id')
    print(f"✓ Job created: {job_id}")
    print()

    # Poll for completion
    print("=" * 80)
    print("MONITORING JOB")
    print("=" * 80)

    max_wait = 600  # 10 minutes
    start = time.time()
    poll_url = f"{endpoint}/{job_id}"

    while time.time() - start < max_wait:
        poll_response = requests.get(poll_url, headers=headers)

        if poll_response.status_code == 200:
            job_status = poll_response.json()
            done = job_status.get('done', False)
            events_count = job_status.get('metaData', {}).get('eventCount', 0)

            if done:
                print(f"✓ Query complete: {events_count} results")
                break
            else:
                progress = job_status.get('metaData', {}).get('pollStandard', {}).get('progress', 0)
                print(f"⏳ Progress: {int(progress * 100)}%")
        else:
            print(f"❌ Error checking status: {poll_response.status_code}")
            sys.exit(1)

        time.sleep(10)
    else:
        print("❌ Query timed out after 10 minutes")
        sys.exit(1)

    print()
    print("=" * 80)

    # Fetch results
    print("📥 Fetching IMDS traffic results...")

    all_results = []
    offset = 0
    limit = 1000

    while True:
        result_url = f"{poll_url}?offset={offset}&limit={limit}"
        result_response = requests.get(result_url, headers=headers)

        if result_response.status_code != 200:
            print(f"   ❌ Error fetching results at offset {offset}")
            break

        result_data = result_response.json()
        events = result_data.get('events', [])

        if not events:
            break

        all_results.extend(events)
        offset += len(events)
        print(f"   Fetched {len(all_results)} results...")

        # Check if we got all results
        done = result_data.get('done', False)
        if done:
            break

    print(f"   ✓ Total: {len(all_results)} IMDS connection patterns")
    print()

    return all_results


def transform_to_detections(raw_results: List[Dict]) -> Dict:
    """
    Transform NGSIEM results into detection format.

    Groups by AID and aggregates evidence.

    Returns: Dict[aid] -> detection info
    """
    detections = {}

    for event in raw_results:
        try:
            aid = event.get('aid')
            remote_ip = event.get('RemoteAddressIP4')
            process = event.get('ContextBaseFileName', '')
            url_paths_raw = event.get('TargetFileName', '')
            count = event.get('connection_count', 1)

            if not aid:
                continue

            # Parse URL paths (may be array string or single path)
            url_paths = []
            if url_paths_raw:
                # Handle both "['path1', 'path2']" and "path1" formats
                if url_paths_raw.startswith('['):
                    try:
                        # Replace single quotes with double quotes for JSON parsing
                        url_paths = json.loads(url_paths_raw.replace("'", '"'))
                    except json.JSONDecodeError:
                        url_paths = [url_paths_raw]
                else:
                    url_paths = [url_paths_raw]

            # Initialize or update detection for this AID
            if aid not in detections:
                detections[aid] = {
                    'imds_ip': remote_ip,
                    'url_paths': [],
                    'processes': [],
                    'sample_count': 0
                }

            # Aggregate evidence
            detection = detections[aid]
            detection['sample_count'] += count

            for path in url_paths:
                if path and path not in detection['url_paths']:
                    detection['url_paths'].append(path)

            if process and process not in detection['processes']:
                detection['processes'].append(process)

        except Exception as e:
            print(f"   ⚠️  Failed to process event: {e}")
            continue

    # Classify each detection
    classified = {}
    for aid, evidence in detections.items():
        classification = classify_from_evidence(evidence)
        classified[aid] = {
            'provider': classification['name'],
            'confidence': classification['confidence'],
            'evidence': evidence
        }

    return classified


def main():
    """Main entry point."""
    print("=" * 80)
    print("ENHANCED IMDS DETECTION WITH URL/PROCESS CONTEXT")
    print("=" * 80)
    print()

    # Query NGSIEM
    raw_results = query_ngsiem_with_context(days_back=7)

    # Transform to detections
    print("=" * 80)
    print("ANALYZING DETECTION PATTERNS")
    print("=" * 80)
    detections = transform_to_detections(raw_results)

    # Statistics
    provider_counts = {}
    confidence_counts = {'high': 0, 'medium': 0, 'low': 0}

    for detection in detections.values():
        provider = detection['provider']
        confidence = detection['confidence']

        provider_counts[provider] = provider_counts.get(provider, 0) + 1
        confidence_counts[confidence] += 1

    print(f"✓ Classified {len(detections)} hosts")
    print()

    print("By provider:")
    for provider, count in sorted(provider_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {provider:20s}: {count:4d}")
    print()

    print("By confidence:")
    for level, count in confidence_counts.items():
        print(f"  {level:10s}: {count:4d}")
    print()

    # Save results
    output = {
        'metadata': {
            'query_start': (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),
            'query_end': datetime.now(timezone.utc).isoformat(),
            'total_hosts': len(detections)
        },
        'detections': detections
    }

    output_file = 'imds_enhanced.json'
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"✓ Saved enhanced detection data to: {output_file}")
    print()
    print("=" * 80)
    print("NEXT STEPS")
    print("=" * 80)
    print("  1. python billing_collector.py --days 7")
    print("  2. python refine_cloud_classification.py")
    print("=" * 80)


if __name__ == '__main__':
    main()
