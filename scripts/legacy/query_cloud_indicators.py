#!/usr/bin/env python3
"""
Query NGSIEM to identify cloud workloads and container hosts.

Queries:
1. OciContainerId=* → Get AIDs that have spawned containers (FCSC)
2. RemoteAddressIP4="169.254.169.254" → Get AIDs that contacted IMDS (Cloud)
"""
import os
import sys
import time
import json
from pathlib import Path
from datetime import datetime, timedelta

# Add FalconPy to path
FALCONPY_PATH = Path(__file__).parent.parent.parent / "repos" / "falconpy" / "src"
sys.path.insert(0, str(FALCONPY_PATH))

from falconpy import OAuth2, APIHarness
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


def run_ngsiem_query(falcon, query, description, days=7):
    """Run NGSIEM query and return list of AIDs."""
    print(f"\n{'='*70}")
    print(f"Query: {description}")
    print(f"{'='*70}")
    
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    
    # Format times for Falcon API
    start_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    
    print(f"Time range: {start_str} to {end_str}")
    print(f"Query: {query}\n")
    
    # Submit async query
    response = falcon.command(
        'aggregate_events',
        body={
            'query': query,
            'start': start_str,
            'end': end_str,
            'mode': 'async'
        }
    )
    
    if response['status_code'] not in [200, 201]:
        print(f"❌ Error submitting query: {response['status_code']}")
        print(f"Response: {json.dumps(response['body'], indent=2)}")
        return []
    
    search_id = response['body'].get('search_id') or response['body'].get('id')
    if not search_id:
        print(f"❌ No search ID returned")
        return []
    
    print(f"✓ Query submitted. Search ID: {search_id}")
    print("Polling for results...")
    
    # Poll for results (max 5 minutes)
    max_attempts = 60
    attempt = 0
    
    while attempt < max_attempts:
        time.sleep(5)
        attempt += 1
        
        # Get query status
        status_response = falcon.command(
            'aggregate_events_get',
            search_id=search_id
        )
        
        if status_response['status_code'] != 200:
            print(f"❌ Error checking status: {status_response['status_code']}")
            return []
        
        status_data = status_response['body']
        status = status_data.get('status', 'UNKNOWN')
        
        print(f"  Attempt {attempt}: Status = {status}", end='\r')
        
        if status == 'DONE':
            print(f"\n✓ Query completed!")
            
            # Extract AIDs from results
            results = status_data.get('results', [])
            print(f"  Found {len(results)} result rows")
            
            aids = set()
            for row in results:
                # Results format: [{'name': 'aid', 'value': 'abc123...'}, ...]
                for field in row:
                    if field.get('name') == 'aid':
                        aids.add(field.get('value'))
            
            print(f"  Unique AIDs: {len(aids)}")
            return list(aids)
        
        elif status in ['FAILED', 'ERROR']:
            print(f"\n❌ Query failed: {status}")
            print(f"Response: {json.dumps(status_data, indent=2)}")
            return []
        
        # Still running...
        time.sleep(5)
    
    print(f"\n⚠️  Query timed out after {max_attempts * 5} seconds")
    return []


def main():
    print("Falcon Cloud Indicator Detection")
    print("="*70)
    
    # Get credentials
    client_id, client_secret, region = get_falcon_credentials()
    
    # Initialize Falcon API
    base_url = f'https://api.{region}.crowdstrike.com' if region != 'us-1' else 'https://api.crowdstrike.com'
    
    auth = OAuth2(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url
    )
    
    falcon = APIHarness(auth_object=auth)
    
    # Query 1: Container Hosts (OciContainerId)
    container_query = """
        OciContainerId=*
        | groupBy([aid])
    """
    
    container_aids = run_ngsiem_query(
        falcon,
        container_query,
        "Container Hosts (OciContainerId present)",
        days=7
    )
    
    # Query 2: Cloud Workloads (IMDS traffic)
    imds_query = """
        RemoteAddressIP4="169.254.169.254"
        | groupBy([aid])
    """
    
    cloud_aids = run_ngsiem_query(
        falcon,
        imds_query,
        "Cloud Workloads (IMDS traffic to 169.254.169.254)",
        days=7
    )
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Container Hosts (FCSC):  {len(container_aids)} unique AIDs")
    print(f"Cloud Workloads (IMDS):  {len(cloud_aids)} unique AIDs")
    
    # Save results to JSON
    output_file = Path(__file__).parent / 'cloud_indicators.json'
    results = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'container_hosts': {
            'aids': container_aids,
            'count': len(container_aids)
        },
        'cloud_workloads': {
            'aids': cloud_aids,
            'count': len(cloud_aids)
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✓ Results saved to: {output_file}")
    
    # Show sample AIDs
    if container_aids:
        print(f"\nSample Container Host AIDs:")
        for aid in container_aids[:5]:
            print(f"  {aid}")
        if len(container_aids) > 5:
            print(f"  ... and {len(container_aids) - 5} more")
    
    if cloud_aids:
        print(f"\nSample Cloud Workload AIDs:")
        for aid in cloud_aids[:5]:
            print(f"  {aid}")
        if len(cloud_aids) > 5:
            print(f"  ... and {len(cloud_aids) - 5} more")


if __name__ == '__main__':
    main()
