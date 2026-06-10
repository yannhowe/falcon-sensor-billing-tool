#!/usr/bin/env python3
"""
Query NGSIEM for container and cloud indicators.
"""
import os
import json
import time
from datetime import datetime, timedelta
from falconpy import APIHarness

# Get credentials from environment (set by /cid skill)
CLIENT_ID = os.getenv('FALCON_CLIENT_ID')
CLIENT_SECRET = os.getenv('FALCON_CLIENT_SECRET')
CLOUD = os.getenv('FALCON_CLOUD_REGION', 'us-1')

if not CLIENT_ID or not CLIENT_SECRET:
    print("❌ Falcon API credentials not found in environment")
    print("Run: /cid use <profile>")
    exit(1)

# Initialize Falcon API
falcon = APIHarness(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=CLOUD)

print("=" * 80)
print("NGSIEM INDICATOR QUERIES")
print("=" * 80)
print(f"Cloud: {CLOUD}")
print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print()

# Query 1: Container Hosts (OciContainerId field)
print("🐳 Query 1: Container Hosts (OciContainerId detection)")
print("-" * 80)

container_query = """
#event_simpleName=ProcessRollup2 OciContainerId=*
| groupBy([aid])
| select([aid, count() as event_count])
"""

print("Query:")
print(container_query)
print()

container_response = falcon.command(
    "CreateSearchJob",
    mode="async",
    filter="",
    query_string=container_query,
    start="2026-04-01T00:00:00Z",  # Last 2 weeks
    end=datetime.now().isoformat() + "Z"
)

if container_response['status_code'] != 201:
    print(f"❌ Failed to create container query job: {container_response}")
    exit(1)

container_job_id = container_response['body']['resources'][0]['job_id']
print(f"✓ Job created: {container_job_id}")
print()

# Query 2: IMDS Traffic (Cloud VM detection)
print("☁️  Query 2: Cloud VMs (IMDS traffic to 169.254.169.254)")
print("-" * 80)

imds_query = """
#event_simpleName=NetworkConnectIP4 RemoteAddressIP4="169.254.169.254"
| groupBy([aid])
| select([aid, count() as event_count])
"""

print("Query:")
print(imds_query)
print()

imds_response = falcon.command(
    "CreateSearchJob",
    mode="async",
    filter="",
    query_string=imds_query,
    start="2026-04-01T00:00:00Z",  # Last 2 weeks
    end=datetime.now().isoformat() + "Z"
)

if imds_response['status_code'] != 201:
    print(f"❌ Failed to create IMDS query job: {imds_response}")
    exit(1)

imds_job_id = imds_response['body']['resources'][0]['job_id']
print(f"✓ Job created: {imds_job_id}")
print()

# Monitor both jobs
print("=" * 80)
print("MONITORING JOBS")
print("=" * 80)

jobs = {
    'container': {'job_id': container_job_id, 'name': 'Container Hosts (OciContainerId)', 'status': 'running'},
    'imds': {'job_id': imds_job_id, 'name': 'Cloud VMs (IMDS traffic)', 'status': 'running'}
}

max_wait = 600  # 10 minutes
start_time = time.time()

while time.time() - start_time < max_wait:
    all_done = True

    for key, job in jobs.items():
        if job['status'] == 'running':
            # Check job status
            status_response = falcon.command(
                "GetSearchJobResults",
                job_id=job['job_id'],
                limit=0,
                offset=0
            )

            if status_response['status_code'] == 200:
                body = status_response['body']
                progress = body.get('meta', {}).get('powered_by', {}).get('query_completion_percentage', 0)

                if progress >= 100:
                    job['status'] = 'done'
                    result_count = body.get('meta', {}).get('result_count', 0)
                    print(f"✓ {job['name']}: DONE ({result_count} results)")
                else:
                    print(f"⏳ {job['name']}: {progress}%")
                    all_done = False
            else:
                print(f"❌ {job['name']}: Error checking status")
                job['status'] = 'error'

    if all_done:
        break

    time.sleep(10)  # Wait 10 seconds between checks

print()
print("=" * 80)

# Fetch results
results = {}

for key, job in jobs.items():
    if job['status'] != 'done':
        print(f"❌ {job['name']}: Did not complete")
        continue

    print(f"📥 Fetching results: {job['name']}")

    all_results = []
    offset = 0
    limit = 1000

    while True:
        result_response = falcon.command(
            "GetSearchJobResults",
            job_id=job['job_id'],
            limit=limit,
            offset=offset
        )

        if result_response['status_code'] != 200:
            print(f"   ❌ Error fetching results at offset {offset}")
            break

        body = result_response['body']
        events = body.get('resources', {}).get('events', [])

        if not events:
            break

        all_results.extend(events)
        offset += len(events)
        print(f"   Fetched {len(all_results)} results...")

        # Check if we got all results
        total_count = body.get('meta', {}).get('result_count', 0)
        if offset >= total_count:
            break

    results[key] = all_results
    print(f"   ✓ Total: {len(all_results)} AIDs")
    print()

# Save results
print("=" * 80)
print("SAVING RESULTS")
print("=" * 80)

# Container indicators
if 'container' in results:
    container_file = 'container_indicators_ngsiem.json'
    with open(container_file, 'w') as f:
        json.dump({
            'query': container_query,
            'timestamp': datetime.now().isoformat(),
            'count': len(results['container']),
            'aids': [event['aid'] for event in results['container']]
        }, f, indent=2)
    print(f"✓ Saved {len(results['container'])} container host AIDs to: {container_file}")

# IMDS indicators
if 'imds' in results:
    imds_file = 'imds_indicators_ngsiem.json'
    with open(imds_file, 'w') as f:
        json.dump({
            'query': imds_query,
            'timestamp': datetime.now().isoformat(),
            'count': len(results['imds']),
            'aids': [event['aid'] for event in results['imds']]
        }, f, indent=2)
    print(f"✓ Saved {len(results['imds'])} cloud VM AIDs to: {imds_file}")

print()
print("=" * 80)
print("SUMMARY")
print("=" * 80)
print(f"Container Hosts (OciContainerId): {len(results.get('container', []))} AIDs")
print(f"Cloud VMs (IMDS traffic):         {len(results.get('imds', []))} AIDs")
print()
print("Next steps:")
print("  1. python3 load_ngsiem_indicators.py")
print("  2. python3 classify_with_indicators.py")
print("=" * 80)
