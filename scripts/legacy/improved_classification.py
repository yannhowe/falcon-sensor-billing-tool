#!/usr/bin/env python3
"""
Improved classification logic based on actual Falcon API fields.

Classification Rules:
1. FCSC: Kubernetes Cluster + hosts running containers
   - product_type_desc = 'Kubernetes Cluster' OR platform_name = 'K8S'
   - Hosts with OciContainerId (need to check NGSIEM events)

2. FCS: Cloud-based servers and VMs
   - product_type_desc = 'Server' AND (Linux OR Windows Server)
   - Check service_provider for AWS/Azure/GCP

3. EPP: Traditional endpoints
   - product_type_desc = 'Workstation'
   - product_type_desc = 'Mobile'
   - product_type_desc = 'Domain Controller' (could be FCS if cloud)
   - Mac laptops

4. FMC: Fargate/serverless containers (TBD - need detection method)
"""
import os
import sys
from pathlib import Path

# Add FalconPy to path
FALCONPY_PATH = Path(__file__).parent.parent.parent / "repos" / "falconpy" / "src"
sys.path.insert(0, str(FALCONPY_PATH))

from falconpy import Hosts
import subprocess

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

def classify_host(host):
    """
    Classify host based on actual Falcon API fields.
    """
    product_type = host.get('product_type_desc', 'Unknown')
    platform = host.get('platform_name', 'Unknown')
    service_provider = host.get('service_provider', '')
    
    # FCSC: Kubernetes/Container Hosts
    if product_type == 'Kubernetes Cluster' or platform == 'K8S':
        return 'FCSC'
    
    # EPP: Clear endpoint indicators
    if product_type in ['Workstation', 'Mobile']:
        return 'EPP'
    
    if platform in ['Mac', 'iOS', 'Android', 'ChromeOS']:
        return 'EPP'
    
    # FCS vs EPP for Servers - check if cloud
    if product_type in ['Server', 'Domain Controller']:
        # Check if cloud-based
        if service_provider or is_cloud_host(host):
            return 'FCS'
        # Windows Desktop OS on Server hardware → EPP
        if platform == 'Windows':
            os_version = host.get('os_version', '').lower()
            if 'windows 10' in os_version or 'windows 11' in os_version:
                return 'EPP'
        # Linux servers default to FCS (could be on-prem but often cloud)
        if platform == 'Linux':
            return 'FCS'
        # Unknown server type
        return 'EPP'
    
    # Default
    return 'EPP'

def is_cloud_host(host):
    """Check if host is in cloud based on various indicators."""
    # Check service provider
    if host.get('service_provider'):
        return True
    
    # Check instance ID (AWS)
    if host.get('instance_id'):
        return True
    
    # Check hostname patterns
    hostname = host.get('hostname', '').lower()
    cloud_patterns = ['compute.amazonaws.com', 'azure.com', 'googleusercontent.com']
    if any(pattern in hostname for pattern in cloud_patterns):
        return True
    
    return False

# Test classification
print("Testing classification on sample hosts:\n")

client_id, client_secret, region = get_falcon_credentials()

falcon = Hosts(
    client_id=client_id,
    client_secret=client_secret,
    base_url=f'https://api.{region}.crowdstrike.com' if region != 'us-1' else 'https://api.crowdstrike.com'
)

# Get sample of hosts
response = falcon.query_devices_by_filter(limit=100)
if response['status_code'] == 200:
    device_ids = response['body']['resources'][:50]
    
    response = falcon.get_device_details(ids=device_ids)
    if response['status_code'] == 200:
        hosts = response['body']['resources']
        
        classifications = {'FCSC': 0, 'FMC': 0, 'FCS': 0, 'EPP': 0}
        
        print(f"{'Product':6} | {'Platform':8} | {'OS':20} | {'Cloud?':6} | Hostname")
        print("="*100)
        
        for host in hosts[:20]:
            classification = classify_host(host)
            classifications[classification] += 1
            
            product = host.get('product_type_desc', '?')[:5]
            platform = host.get('platform_name', '?')[:8]
            os_ver = host.get('os_version', '?')[:20]
            is_cloud = 'Yes' if is_cloud_host(host) else 'No'
            hostname = host.get('hostname', 'Unknown')[:40]
            
            print(f"{classification:6} | {platform:8} | {os_ver:20} | {is_cloud:6} | {hostname}")
        
        print("\n" + "="*100)
        print(f"Classification Summary (sample of {len(hosts)} hosts):")
        for product, count in sorted(classifications.items()):
            print(f"  {product}: {count}")

