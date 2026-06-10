#!/usr/bin/env python3
"""
Query NGSIEM for IMDS traffic to detect cloud providers.
"""
import os
import json
import time
from datetime import datetime
from falconpy import APIHarness

# Get credentials from environment (set by /cid skill)
CLIENT_ID = os.getenv('FALCON_CLIENT_ID')
CLIENT_SECRET = os.getenv('FALCON_CLIENT_SECRET')
CLOUD = os.getenv('FALCON_CLOUD_REGION', 'us-1')

if not CLIENT_ID or not CLIENT_SECRET:
    print("❌ Falcon API credentials not found in environment")
    print("Run: /cid use <profile>")
    exit(1)

# IMDS endpoint mappings
IMDS_ENDPOINTS = {
    # Standard 169.254.169.254 (AWS, Azure, GCP, Oracle, OCI, DigitalOcean, Linode, Vultr, UpCloud, Yandex)
    '169.254.169.254': 'Standard-IMDS',  # Need to differentiate by headers/paths later

    # Non-standard endpoints
    '100.100.100.200': 'Alibaba',        # Alibaba Cloud
    '169.254.42.42': 'Scaleway',         # Scaleway
    'metadata.google.internal': 'GCP',   # GCP alternate
    'metadata.tencentyun.com': 'Tencent', # Tencent Cloud
    'api.metadata.cloud.ibm.com': 'IBM'   # IBM Cloud
}

# Initialize Falcon API
falcon = APIHarness(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=CLOUD)

print("=" * 80)
print("IMDS TRAFFIC DETECTION")
print("=" * 80)
print(f"Cloud: {CLOUD}")
print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print()

# Build query for all IMDS endpoints
imds_ips = list(IMDS_ENDPOINTS.keys())
ip_conditions = ' OR '.join([f'RemoteAddressIP4="{ip}"' for ip in imds_ips if '.' in ip])  # Only IPs, not hostnames

imds_query = f"""
#event_simpleName=NetworkConnectIP4 ({ip_conditions})
| groupBy([aid, RemoteAddressIP4])
| select([aid, RemoteAddressIP4, count() as connection_count])
"""

print("🌐 Querying NGSIEM for IMDS traffic...")
print("-" * 80)
print("Query:")
print(imds_query)
print()

# Create async search job
response = falcon.command(
    "CreateSearchJob",
    mode="async",
    filter="",
    query_string=imds_query,
    start="2026-04-01T00:00:00Z",  # Last ~3 weeks
    end=datetime.now().isoformat() + "Z"
)

if response['status_code'] != 201:
    print(f"❌ Failed to create IMDS query job: {response}")
    exit(1)

job_id = response['body']['resources'][0]['job_id']
print(f"✓ Job created: {job_id}")
print()

# Monitor job
print("=" * 80)
print("MONITORING JOB")
print("=" * 80)

max_wait = 600  # 10 minutes
start_time = time.time()

while time.time() - start_time < max_wait:
    # Check job status
    status_response = falcon.command(
        "GetSearchJobResults",
        job_id=job_id,
        limit=0,
        offset=0
    )

    if status_response['status_code'] == 200:
        body = status_response['body']
        progress = body.get('meta', {}).get('powered_by', {}).get('query_completion_percentage', 0)

        if progress >= 100:
            result_count = body.get('meta', {}).get('result_count', 0)
            print(f"✓ Query complete: {result_count} results")
            break
        else:
            print(f"⏳ Progress: {progress}%")
    else:
        print(f"❌ Error checking status")
        break

    time.sleep(10)

print()
print("=" * 80)

# Fetch results
print("📥 Fetching IMDS traffic results...")

all_results = []
offset = 0
limit = 1000

while True:
    result_response = falcon.command(
        "GetSearchJobResults",
        job_id=job_id,
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

print(f"   ✓ Total: {len(all_results)} IMDS connections")
print()

# Organize results by AID and detect cloud provider
print("=" * 80)
print("ANALYZING IMDS TRAFFIC")
print("=" * 80)

imds_by_aid = {}
provider_counts = {}

for event in all_results:
    aid = event.get('aid')
    remote_ip = event.get('RemoteAddressIP4')
    count = event.get('connection_count', 1)

    if not aid or not remote_ip:
        continue

    # Map IP to cloud provider
    provider = IMDS_ENDPOINTS.get(remote_ip, 'Unknown')

    if aid not in imds_by_aid:
        imds_by_aid[aid] = []

    imds_by_aid[aid].append({
        'remote_ip': remote_ip,
        'provider': provider,
        'connection_count': count
    })

    # Count by provider
    if provider not in provider_counts:
        provider_counts[provider] = 0
    provider_counts[provider] += 1

print(f"Detected IMDS traffic from {len(imds_by_aid)} unique hosts")
print()

for provider, count in sorted(provider_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"  {provider:20s}: {count:4d} hosts")

print()

# Save results
output_file = 'imds_traffic_ngsiem.json'
with open(output_file, 'w') as f:
    json.dump({
        'query': imds_query,
        'timestamp': datetime.now().isoformat(),
        'total_connections': len(all_results),
        'unique_hosts': len(imds_by_aid),
        'imds_by_aid': imds_by_aid,
        'provider_counts': provider_counts
    }, f, indent=2)

print(f"✓ Saved IMDS traffic data to: {output_file}")
print()
print("=" * 80)
print("SUMMARY")
print("=" * 80)
print(f"Total IMDS connections:  {len(all_results)}")
print(f"Unique hosts detected:   {len(imds_by_aid)}")
print()
print("Next step:")
print("  python3 refine_cloud_classification.py")
print("=" * 80)
