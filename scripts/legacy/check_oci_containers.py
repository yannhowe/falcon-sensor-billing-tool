#!/usr/bin/env python3
"""Check for OCI Container IDs in Falcon API."""
import os
import sys
from pathlib import Path

# Add FalconPy to path
FALCONPY_PATH = Path(__file__).parent.parent.parent / "repos" / "falconpy" / "src"
sys.path.insert(0, str(FALCONPY_PATH))

from falconpy import Hosts
import json

# Get credentials from keychain
def get_falcon_credentials():
    import subprocess
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

falcon = Hosts(
    client_id=client_id,
    client_secret=client_secret,
    base_url=f'https://api.{region}.crowdstrike.com' if region != 'us-1' else 'https://api.crowdstrike.com'
)

# Query a sample of hosts to check what fields are available
print("Querying hosts for available fields...\n")

# Get first 10 device IDs
response = falcon.query_devices_by_filter(limit=10)
if response['status_code'] != 200:
    print(f"Error: {response}")
    sys.exit(1)

device_ids = response['body']['resources']
print(f"Found {len(device_ids)} sample device IDs\n")

# Get detailed host info
response = falcon.get_device_details(ids=device_ids)
if response['status_code'] != 200:
    print(f"Error: {response}")
    sys.exit(1)

hosts = response['body']['resources']

# Check for OciContainerId and other relevant fields
print("Checking for container-related fields:\n")

container_hosts = []
for host in hosts:
    aid = host.get('device_id')
    hostname = host.get('hostname', 'Unknown')
    platform = host.get('platform_name', '?')
    product_type_desc = host.get('product_type_desc', '?')
    
    # Check for container indicators
    has_oci = 'oci_container_id' in host or 'OciContainerId' in host
    
    print(f"AID: {aid[:20]}...")
    print(f"  Hostname: {hostname}")
    print(f"  Platform: {platform}")
    print(f"  Product Type: {product_type_desc}")
    print(f"  Has OCI Container ID: {has_oci}")
    
    # Check all available fields
    if 'container' in str(host).lower() or 'oci' in str(host).lower():
        print(f"  Container-related fields found:")
        for key, value in host.items():
            if 'container' in key.lower() or 'oci' in key.lower():
                print(f"    {key}: {value}")
    
    print()
    
    if has_oci:
        container_hosts.append(aid)

print("="*70)
print(f"Hosts with OCI Container ID: {len(container_hosts)}")
if container_hosts:
    print("These should be classified as FCSC")

# Now check for product_type_desc values
print("\n" + "="*70)
print("Product Type Description breakdown:")
product_types = {}
for host in hosts:
    pt = host.get('product_type_desc', 'Unknown')
    product_types[pt] = product_types.get(pt, 0) + 1

for pt, count in sorted(product_types.items()):
    print(f"  {pt}: {count}")

