#!/usr/bin/env python3
"""
Find hosts running containers by checking for OCI events or container activity.
The OciContainerId field might be in NGSIEM events, not host records.
"""
import os
import sys
from pathlib import Path

FALCONPY_PATH = Path(__file__).parent.parent.parent / "repos" / "falconpy" / "src"
sys.path.insert(0, str(FALCONPY_PATH))

from falconpy import EventSearch, ContainerImages
import subprocess
from datetime import datetime, timedelta

def get_falcon_credentials():
    client_id = subprocess.check_output(
        ['security', 'find-generic-password', '-s', 'falcon-client-id', '-a', 'talon_1', '-w'],
        text=True
    ).strip()
    client_secret = subprocess.check_output(
        ['security', 'find-generic-password', '-s', 'falcon-client-secret', '-a', 'talon_1', '-w'],
        text=True
    ).strip()
    region = subprocess.check_output(
        ['security', 'find-generic-password', '-s', 'falcon-cloud-region', '-a', 'talon_1', '-w'],
        text=True
    ).strip()
    return client_id, client_secret, region

client_id, client_secret, region = get_falcon_credentials()

# Try Event Search for OciContainerId
print("Searching for OciContainerId in events...\n")

event_search = EventSearch(
    client_id=client_id,
    client_secret=client_secret,
    base_url=f'https://api.{region}.crowdstrike.com' if region != 'us-1' else 'https://api.crowdstrike.com'
)

# Query for events with OciContainerId
end_time = datetime.now()
start_time = end_time - timedelta(days=7)

query = f"""
    OciContainerId=*
    | groupBy([aid])
    | select([aid])
"""

print(f"Query: {query}\n")
print("This will find all AIDs (agent IDs) that have OciContainerId field...")
print("(Container hosts are hosts that have spawned containers)\n")

response = event_search.aggregate_events(
    query=query,
    start=start_time.isoformat() + 'Z',
    end=end_time.isoformat() + 'Z',
    mode='async'
)

print(f"Response status: {response['status_code']}")
if response['status_code'] == 201:
    print("✓ Query submitted successfully")
    print(f"Search ID: {response['body'].get('id')}")
    print("\nNote: This is an async query. You would need to poll for results.")
else:
    print(f"Response: {response}")

# Try alternative: Check Container Images API
print("\n" + "="*70)
print("Checking Container Images API...\n")

containers = ContainerImages(
    client_id=client_id,
    client_secret=client_secret,
    base_url=f'https://api.{region}.crowdstrike.com' if region != 'us-1' else 'https://api.crowdstrike.com'
)

# This might show which hosts are running containers
response = containers.combined_base_images(limit=5)
print(f"Container Images API status: {response['status_code']}")

if response['status_code'] == 200:
    images = response['body'].get('resources', [])
    print(f"Found {len(images)} container images")
    if images:
        print("\nSample container image data:")
        for img in images[:2]:
            print(f"  Image: {img}")

print("\n" + "="*70)
print("KEY INSIGHT:")
print("=" *70)
print("""
To accurately detect FCSC (container hosts), you need to:

1. Run NGSIEM query: OciContainerId=* | groupBy([aid])
   This gives you AIDs of hosts that have spawned containers

2. Mark those AIDs as FCSC in your database

3. For now, we can use simpler heuristics:
   - platform_name='K8S' → FCSC (Kubernetes clusters)
   - product_type_desc='Kubernetes Cluster' → FCSC
   - Tags containing 'kubernetes', 'docker', 'openshift' → Likely FCSC

Alternative approach:
   - Run your billing collector with OciContainerId field included
   - Any hour where OciContainerId is present = FCSC
   - Track which AIDs have ever had OciContainerId
""")

