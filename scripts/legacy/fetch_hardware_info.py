#!/usr/bin/env python3
"""
Fetch hardware information from Hosts API to detect cloud providers.

Checks:
- system_manufacturer (AWS, Azure, GCP indicators)
- bios_manufacturer
- chassis_type (Virtual Machine)
- service_provider
- instance_id
"""
import os
import sys
import json
from pathlib import Path

# Add FalconPy to path
FALCONPY_PATH = Path(__file__).parent.parent.parent / "repos" / "falconpy" / "src"
sys.path.insert(0, str(FALCONPY_PATH))

from falconpy import Hosts
import subprocess

def get_falcon_credentials():
    """Get credentials from macOS Keychain."""
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


def is_cloud_hardware(host):
    """Check if hardware indicates cloud VM."""
    system_mfg = host.get('system_manufacturer', '').lower()
    bios_mfg = host.get('bios_manufacturer', '').lower()
    chassis = host.get('chassis_type', '').lower()
    chassis_desc = host.get('chassis_type_desc', '').lower()
    
    # AWS indicators
    aws_indicators = ['amazon', 'ec2', 'xen']
    if any(ind in system_mfg for ind in aws_indicators):
        return 'AWS'
    if any(ind in bios_mfg for ind in aws_indicators):
        return 'AWS'
    
    # Azure indicators
    azure_indicators = ['microsoft corporation']
    if any(ind in system_mfg for ind in azure_indicators):
        if 'virtual' in chassis or 'virtual' in chassis_desc:
            return 'Azure'
    
    # GCP indicators
    gcp_indicators = ['google']
    if any(ind in system_mfg for ind in gcp_indicators):
        return 'GCP'
    if 'google compute engine' in system_mfg:
        return 'GCP'
    
    # Generic virtual machine
    if chassis == 'virtual machine' or 'virtual' in chassis_desc:
        return 'VM'  # Virtual but provider unknown
    
    return None


def main():
    print("Fetching Hardware Information from Hosts API")
    print("="*70)
    
    # Get credentials
    client_id, client_secret, region = get_falcon_credentials()
    
    # Initialize Falcon Hosts API
    base_url = f'https://api.{region}.crowdstrike.com' if region != 'us-1' else 'https://api.crowdstrike.com'
    
    falcon = Hosts(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url
    )
    
    # Get all device IDs
    print("\nQuerying device IDs...")
    response = falcon.query_devices_by_filter(limit=5000)
    
    if response['status_code'] != 200:
        print(f"❌ Error: {response['status_code']}")
        return
    
    device_ids = response['body']['resources']
    total = len(device_ids)
    print(f"✓ Found {total} devices")
    
    # Fetch hardware info in batches
    batch_size = 100
    hardware_data = []
    
    print(f"\nFetching hardware details (batch size: {batch_size})...")
    
    for i in range(0, total, batch_size):
        batch = device_ids[i:i+batch_size]
        print(f"  Batch {i//batch_size + 1}/{(total + batch_size - 1)//batch_size}...", end='\r')
        
        response = falcon.get_device_details(ids=batch)
        
        if response['status_code'] != 200:
            print(f"\n❌ Error in batch {i//batch_size + 1}")
            continue
        
        hosts = response['body']['resources']
        
        for host in hosts:
            cloud_provider = is_cloud_hardware(host)
            
            hardware_data.append({
                'aid': host['device_id'],
                'hostname': host.get('hostname', 'Unknown'),
                'platform_name': host.get('platform_name'),
                'product_type_desc': host.get('product_type_desc'),
                'os_version': host.get('os_version'),
                'system_manufacturer': host.get('system_manufacturer'),
                'bios_manufacturer': host.get('bios_manufacturer'),
                'chassis_type': host.get('chassis_type'),
                'chassis_type_desc': host.get('chassis_type_desc'),
                'service_provider': host.get('service_provider'),
                'instance_id': host.get('instance_id'),
                'service_provider_account_id': host.get('service_provider_account_id'),
                'cloud_provider': cloud_provider,
                'is_cloud': bool(cloud_provider or host.get('service_provider') or host.get('instance_id'))
            })
    
    print(f"\n✓ Fetched hardware info for {len(hardware_data)} devices")
    
    # Save results
    output_file = Path(__file__).parent / 'hardware_indicators.json'
    with open(output_file, 'w') as f:
        json.dump(hardware_data, f, indent=2)
    
    print(f"✓ Saved to: {output_file}")
    
    # Statistics
    print("\n" + "="*70)
    print("HARDWARE DETECTION SUMMARY")
    print("="*70)
    
    cloud_counts = {}
    for item in hardware_data:
        provider = item['cloud_provider'] or 'On-Premise'
        cloud_counts[provider] = cloud_counts.get(provider, 0) + 1
    
    for provider, count in sorted(cloud_counts.items(), key=lambda x: -x[1]):
        print(f"  {provider:20} {count:4} devices")
    
    # Show samples
    print("\n" + "="*70)
    print("SAMPLE CLOUD DETECTIONS")
    print("="*70)
    
    for provider in ['AWS', 'Azure', 'GCP']:
        samples = [h for h in hardware_data if h['cloud_provider'] == provider]
        if samples:
            print(f"\n{provider} Devices:")
            for sample in samples[:3]:
                print(f"  {sample['hostname'][:50]:50} | {sample['system_manufacturer']}")


if __name__ == '__main__':
    main()
