#!/usr/bin/env python3
"""
Check how to detect container hosts.
OciContainerId might be in events, not host records.
"""
import os
import sys
from pathlib import Path

# Add FalconPy to path
FALCONPY_PATH = Path(__file__).parent.parent.parent / "repos" / "falconpy" / "src"
sys.path.insert(0, str(FALCONPY_PATH))

from falconpy import Hosts
import json

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

# Query hosts with K8S platform (definitely container hosts)
print("Querying K8S platform hosts...\n")
response = falcon.query_devices_by_filter(
    filter="platform_name:'K8S'",
    limit=5
)

if response['status_code'] == 200 and response['body']['resources']:
    k8s_ids = response['body']['resources']
    print(f"Found {len(k8s_ids)} K8S hosts")
    
    # Get detailed info
    response = falcon.get_device_details(ids=k8s_ids)
    if response['status_code'] == 200:
        for host in response['body']['resources']:
            print(f"\nK8S Host: {host.get('hostname', 'Unknown')}")
            print(f"  Device ID: {host['device_id']}")
            print(f"  Product Type: {host.get('product_type_desc', '?')}")
            
            # Print ALL fields to see what's available
            print(f"  All available fields:")
            for key in sorted(host.keys()):
                if 'container' in key.lower() or 'k8' in key.lower() or 'oci' in key.lower():
                    print(f"    {key}: {host[key]}")

# Check what product_type_desc values exist
print("\n" + "="*70)
print("Checking all product_type_desc values in environment:\n")

response = falcon.query_devices_by_filter(limit=1000)
if response['status_code'] == 200:
    all_ids = response['body']['resources']
    
    response = falcon.get_device_details(ids=all_ids[:50])  # Sample 50
    if response['status_code'] == 200:
        product_types = {}
        platforms = {}
        
        for host in response['body']['resources']:
            pt = host.get('product_type_desc', 'Unknown')
            pf = host.get('platform_name', 'Unknown')
            
            product_types[pt] = product_types.get(pt, 0) + 1
            platforms[pf] = platforms.get(pf, 0) + 1
        
        print("Product Types:")
        for pt, count in sorted(product_types.items(), key=lambda x: -x[1]):
            print(f"  {pt}: {count}")
        
        print("\nPlatforms:")
        for pf, count in sorted(platforms.items(), key=lambda x: -x[1]):
            print(f"  {pf}: {count}")

print("\n" + "="*70)
print("Key Findings for Classification:\n")
print("1. FCSC Detection:")
print("   - Platform = 'K8S' → Kubernetes Cluster (FCSC)")
print("   - Product Type = 'Kubernetes Cluster' → FCSC")
print("   - Need to check if OciContainerId is in events/different API")
print("\n2. FCS vs EPP Detection:")
print("   - Product Type = 'Server' + Platform = 'Windows/Linux' → FCS or EPP?")
print("   - Product Type = 'Workstation' → EPP")
print("   - Product Type = 'Mobile' → EPP")
print("   - Need service_provider or other cloud indicators")

