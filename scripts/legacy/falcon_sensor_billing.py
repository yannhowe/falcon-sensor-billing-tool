#!/usr/bin/env python3
"""
CrowdStrike Falcon Sensor Billing Tool for Multi-CID Chargeback
Retrieves sensor usage data (all types: containers, VMs, servers, workstations, mobile)
via Sensor Usage API for billing and chargeback reporting.

Usage:
    python falcon_sensor_billing.py [--hourly] [--multi-tenant CIDS]

    Default: Retrieves weekly average data (for traditional endpoints)
    --hourly: Retrieves hourly average data (for FCS/FMC/cloud workloads)
    --multi-tenant: Query multiple CIDs separately for per-tenant chargeback

Examples:
    # Single CID or parent aggregation
    python3 falcon_sensor_billing.py --hourly

    # Multi-tenant chargeback (comma-separated CIDs)
    python3 falcon_sensor_billing.py --hourly --multi-tenant "cid1,cid2,cid3"

    # Multi-tenant from file
    python3 falcon_sensor_billing.py --hourly --multi-tenant @tenants.txt
"""

import os
import sys
import json
import csv
from datetime import datetime, timedelta
import argparse

try:
    from falconpy import SensorUsage, FlightControl, Hosts, OAuth2
except ImportError:
    print("ERROR: falconpy library not installed. Run: pip install crowdstrike-falconpy")
    sys.exit(1)

# Import database and collection modules
try:
    from billing_database import BillingDatabase
    from billing_collector import (
        process_hourly_collection,
        verify_billing_accuracy,
        generate_verification_report,
        get_falcon_client
    )
except ImportError as e:
    print(f"WARNING: Database modules not available: {e}")
    print("Database features will be disabled")
    BillingDatabase = None

# ============================================================================
# CONFIGURATION
# ============================================================================

# API Credentials - Load from environment variables for security
CLIENT_ID = os.environ.get('FALCON_CLIENT_ID')
CLIENT_SECRET = os.environ.get('FALCON_CLIENT_SECRET')

# Falcon Cloud Region
CLOUD_REGION = os.environ.get('FALCON_CLOUD_REGION', 'us-1')

# Map region to base URL
REGION_MAP = {
    'us-1': 'https://api.crowdstrike.com',
    'us-2': 'https://api.us-2.crowdstrike.com',
    'eu-1': 'https://api.eu-1.crowdstrike.com',
    'us-gov-1': 'https://api.laggar.gcw.crowdstrike.com'
}

# Output directory for logs
OUTPUT_DIR = os.environ.get('USAGE_LOG_DIR', '/var/log/falcon-usage')

# Optional: Comma-separated list of child CIDs to query
# Leave empty to query all child CIDs (Flight Control parent CID)
SELECTED_CIDS = os.environ.get('SELECTED_CIDS', '')

# Number of days to retrieve (default: 28 days for standard billing period)
PERIOD_DAYS = int(os.environ.get('PERIOD_DAYS', '28'))

# CID name mapping (optional) - load from file or environment
CID_NAMES = {}  # Will be populated if names file provided

# ============================================================================
# FUNCTIONS
# ============================================================================

def load_cid_list(cid_input):
    """
    Load CID list from string or file

    Args:
        cid_input: Comma-separated CIDs or @filename

    Returns:
        list: List of (cid, name) tuples
    """
    cids = []

    # Check if input is a file reference
    if cid_input.startswith('@'):
        filename = cid_input[1:]
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # Support format: CID or CID,NAME
                    parts = line.split(',', 1)
                    cid = parts[0].strip()
                    name = parts[1].strip() if len(parts) > 1 else cid
                    cids.append((cid, name))
        except FileNotFoundError:
            print(f"ERROR: File not found: {filename}")
            sys.exit(1)
    else:
        # Comma-separated list
        for cid in cid_input.split(','):
            cid = cid.strip()
            if cid:
                cids.append((cid, cid))  # Use CID as name if no mapping

    return cids

def auto_discover_child_cids():
    """
    Auto-discover child CIDs from Flight Control parent CID

    Returns:
        list: List of (cid, name) tuples
    """
    if not CLIENT_ID or not CLIENT_SECRET:
        print("ERROR: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables must be set")
        sys.exit(1)

    base_url = REGION_MAP.get(CLOUD_REGION)
    if not base_url:
        print(f"ERROR: Invalid cloud region: {CLOUD_REGION}")
        sys.exit(1)

    print("🔍 Auto-discovering child CIDs from Flight Control parent...")

    try:
        # Initialize FlightControl client
        mssp = FlightControl(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            base_url=base_url
        )

        # Query for all child CIDs
        response = mssp.query_children(limit=5000)

        if response['status_code'] == 403:
            # Permission denied - either no mssp:read scope or not a Flight Control parent
            print("⚠️  Cannot access Flight Control API (403 Forbidden)")
            print("   Possible reasons:")
            print("   • API client missing 'mssp:read' scope")
            print("   • This is not a Flight Control parent CID")
            print()
            print("   Switching to single-CID mode...")
            print()
            return []

        if response['status_code'] != 200:
            error_msg = response.get('body', {}).get('errors', ['Unknown error'])
            print(f"ERROR: Failed to query child CIDs: {error_msg}")
            print("\nNote: This requires a Flight Control parent CID with 'mssp:read' API scope")
            sys.exit(1)

        child_cid_ids = response['body'].get('resources', [])

        if not child_cid_ids:
            print("⚠️  No child CIDs found.")
            print("   This is not a Flight Control parent CID.")
            print("   Switching to single-CID mode for the authenticated CID...")
            print()
            # Return empty list - caller will handle single CID mode
            return []

        print(f"✓ Found {len(child_cid_ids)} child CID(s)")

        # Get detailed information about each child CID
        child_response = mssp.get_children(ids=child_cid_ids)

        if child_response['status_code'] != 200:
            # Fall back to CID IDs only
            print("⚠️  Could not fetch child CID details, using CID IDs only")
            return [(cid, cid) for cid in child_cid_ids]

        # Extract CID and name
        cids = []
        for child in child_response['body'].get('resources', []):
            cid = child.get('child_cid', '')
            name = child.get('name', cid)  # Use name if available, else CID
            if cid:
                cids.append((cid, name))

        return cids

    except Exception as e:
        print(f"ERROR: Failed to auto-discover child CIDs: {e}")
        print("\nNote: Auto-discovery requires:")
        print("  1. Flight Control parent CID")
        print("  2. API credentials with 'mssp:read' scope")
        sys.exit(1)

def get_sensor_usage_for_cid(cid, endpoint_type='weekly'):
    """
    Retrieve sensor usage data for a specific CID

    Args:
        cid: Child CID to query
        endpoint_type: 'weekly' or 'hourly'

    Returns:
        dict: API response data
    """
    base_url = REGION_MAP.get(CLOUD_REGION)

    falcon = SensorUsage(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        base_url=base_url
    )

    end_date = (datetime.now() - timedelta(days=2)).strftime('%Y-%m-%d')
    filter_string = f"event_date:'{end_date}',period:'{PERIOD_DAYS}',selected_cids:'{cid}'"

    try:
        if endpoint_type == 'hourly':
            response = falcon.get_sensor_usage_hourly_average(filter=filter_string)
        else:
            response = falcon.get_sensor_usage_weekly_average(filter=filter_string)

        if response['status_code'] != 200:
            error_msg = response.get('body', {}).get('errors', ['Unknown error'])
            print(f"WARNING: Failed to query CID {cid}: {error_msg}")
            return None

        return response['body']

    except Exception as e:
        print(f"WARNING: Failed to query CID {cid}: {e}")
        return None

def get_sensor_usage(endpoint_type='weekly'):
    """
    Retrieve sensor usage data from API using FalconPy

    Args:
        endpoint_type: 'weekly' or 'hourly'

    Returns:
        dict: API response data
    """
    if not CLIENT_ID or not CLIENT_SECRET:
        print("ERROR: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables must be set")
        print("\nExample:")
        print("  export FALCON_CLIENT_ID='your_client_id'")
        print("  export FALCON_CLIENT_SECRET='your_client_secret'")
        sys.exit(1)

    # Get base URL for region
    base_url = REGION_MAP.get(CLOUD_REGION)
    if not base_url:
        print(f"ERROR: Invalid cloud region: {CLOUD_REGION}")
        print(f"Valid regions: {', '.join(REGION_MAP.keys())}")
        sys.exit(1)

    # Initialize FalconPy Sensor Usage client
    falcon = SensorUsage(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        base_url=base_url
    )

    # Build filter parameters
    # Get data ending 2 days ago (current date - 2 days per API requirements)
    end_date = (datetime.now() - timedelta(days=2)).strftime('%Y-%m-%d')
    filter_parts = [f"event_date:'{end_date}'", f"period:'{PERIOD_DAYS}'"]

    if SELECTED_CIDS:
        cids = SELECTED_CIDS.strip()
        filter_parts.append(f"selected_cids:'{cids}'")

    filter_string = ','.join(filter_parts)

    # Call appropriate endpoint
    try:
        if endpoint_type == 'hourly':
            response = falcon.get_hourly_usage(filter=filter_string)
        else:
            response = falcon.get_weekly_usage(filter=filter_string)

        # Check for errors
        if response['status_code'] != 200:
            error_msg = response.get('body', {}).get('errors', ['Unknown error'])
            print(f"ERROR: API request failed (HTTP {response['status_code']}): {error_msg}")
            sys.exit(1)

        return response['body']

    except Exception as e:
        print(f"ERROR: Failed to retrieve usage data: {e}")
        sys.exit(1)

def log_to_csv(data, endpoint_type='weekly', db=None, cid='default'):
    """
    Log usage data to CSV file and optionally to database.

    Args:
        data: API response data
        endpoint_type: 'weekly' or 'hourly'
        db: Optional BillingDatabase instance for database storage
        cid: Child CID or 'default'
    """

    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Generate filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(OUTPUT_DIR, f"falcon_usage_{endpoint_type}_{timestamp}.csv")

    # Extract resources from response
    resources = data.get('resources', [])
    if not resources:
        print("WARNING: No usage data returned from API")
        return

    # Define CSV columns
    fieldnames = [
        'date',
        'cloud_vms',
        'container_hosts',
        'managed_containers',
        'servers',
        'workstations',
        'mobile',
        'chrome_os',
        'public_cloud_containers',
        'server_containers',
        'retrieved_at'
    ]

    retrieved_at = datetime.now().isoformat()

    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for resource in resources:
            writer.writerow({
                'date': resource.get('date', ''),
                'cloud_vms': resource.get('public_cloud_without_containers', 0),
                'container_hosts': resource.get('containers', 0),
                'managed_containers': resource.get('lumos', 0),
                'servers': resource.get('servers_without_containers', 0),
                'workstations': resource.get('workstations', 0),
                'mobile': resource.get('mobile', 0),
                'chrome_os': resource.get('chrome_os', 0),
                'public_cloud_containers': resource.get('public_cloud_with_containers', 0),
                'server_containers': resource.get('servers_with_containers', 0),
                'retrieved_at': retrieved_at
            })

    print(f"SUCCESS: Usage data logged to {filename}")
    print(f"Records written: {len(resources)}")

    # Also save raw JSON for reference
    json_filename = filename.replace('.csv', '.json')
    with open(json_filename, 'w') as jsonfile:
        json.dump(data, jsonfile, indent=2)
    print(f"Raw JSON saved to {json_filename}")

    # Store in database if available
    if db and BillingDatabase:
        print("Storing billing API data in database...")
        for resource in resources:
            billing_data = {
                'managed_containers': resource.get('lumos', 0),
                'cloud_vms': resource.get('public_cloud_without_containers', 0),
                'container_hosts': resource.get('containers', 0),
                'servers': resource.get('servers_without_containers', 0),
                'workstations': resource.get('workstations', 0),
                'mobile': resource.get('mobile', 0),
                'chrome_os': resource.get('chrome_os', 0),
                'public_cloud_containers': resource.get('public_cloud_with_containers', 0),
                'server_containers': resource.get('servers_with_containers', 0)
            }
            db.insert_billing_average(resource.get('date', ''), billing_data, cid)
        print("✓ Billing data stored in database")

    return filename

def print_summary(data):
    """Print summary of retrieved data"""
    resources = data.get('resources', [])
    if not resources:
        return

    print("\n" + "="*70)
    print("USAGE SUMMARY")
    print("="*70)

    # Get most recent data point (latest billing number)
    latest = resources[0]
    print(f"\nLatest data point: {latest.get('date')}")
    print(f"  Cloud VMs:          {latest.get('public_cloud_without_containers', 0):.2f}")
    print(f"  Container Hosts:    {latest.get('containers', 0):.2f}")
    print(f"  Managed Containers: {latest.get('lumos', 0):.2f} (FMC - for chargeback)")
    print(f"  Servers:            {latest.get('servers_without_containers', 0):.2f}")
    print(f"  Workstations:       {latest.get('workstations', 0):.2f}")
    print(f"  Mobile:             {latest.get('mobile', 0):.2f}")

    # Calculate max values across the period
    max_containers = max(r.get('lumos', 0) for r in resources)
    max_cloud_vms = max(r.get('public_cloud_without_containers', 0) for r in resources)
    max_servers = max(r.get('servers_without_containers', 0) for r in resources)
    max_workstations = max(r.get('workstations', 0) for r in resources)

    print(f"\nMax values over {len(resources)} days:")
    print(f"  Max Managed Containers: {max_containers:.2f}")
    print(f"  Max Cloud VMs:          {max_cloud_vms:.2f}")
    print(f"  Max Servers:            {max_servers:.2f}")
    print(f"  Max Workstations:       {max_workstations:.2f}")

    print(f"\n💰 CHARGEBACK AMOUNT: {latest.get('lumos', 0):.2f} FMC sensors")
    print(f"   (Use latest value for billing)")

    print(f"\nTotal data points retrieved: {len(resources)}")
    print("="*70 + "\n")

def generate_multitenant_report(cid_list, endpoint_type='weekly'):
    """
    Generate chargeback report for multiple tenants

    Args:
        cid_list: List of (cid, name) tuples
        endpoint_type: 'weekly' or 'hourly'
    """
    print("\n" + "="*70)
    print("MULTI-TENANT CHARGEBACK REPORT")
    print("="*70)
    print(f"Querying {len(cid_list)} tenant CIDs...")
    print()

    results = []
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    for idx, (cid, name) in enumerate(cid_list, 1):
        print(f"[{idx}/{len(cid_list)}] Querying {name} ({cid})...", end=' ')

        data = get_sensor_usage_for_cid(cid, endpoint_type)

        if data and data.get('resources'):
            latest = data['resources'][0]
            managed_containers = latest.get('lumos', 0)
            cloud_vms = latest.get('public_cloud_without_containers', 0)
            servers = latest.get('servers_without_containers', 0)
            workstations = latest.get('workstations', 0)
            date = latest.get('date', '')

            results.append({
                'tenant_name': name,
                'cid': cid,
                'date': date,
                'managed_containers': managed_containers,
                'cloud_vms': cloud_vms,
                'servers': servers,
                'workstations': workstations
            })
            print(f"✓ {managed_containers:.2f} FMC")
        else:
            print("✗ No data")
            results.append({
                'tenant_name': name,
                'cid': cid,
                'date': '',
                'managed_containers': 0,
                'cloud_vms': 0,
                'servers': 0,
                'workstations': 0
            })

    # Save combined report
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    report_file = os.path.join(OUTPUT_DIR, f"multitenant_chargeback_{endpoint_type}_{timestamp}.csv")

    with open(report_file, 'w', newline='') as csvfile:
        fieldnames = ['tenant_name', 'cid', 'date', 'managed_containers', 'cloud_vms', 'servers', 'workstations']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print()
    print("="*70)
    print("CHARGEBACK SUMMARY")
    print("="*70)
    print(f"{'Tenant':<30} {'CID':<20} {'FMC Sensors':>15}")
    print("-"*70)

    total_fmc = 0
    for r in results:
        print(f"{r['tenant_name']:<30} {r['cid']:<20} {r['managed_containers']:>15.2f}")
        total_fmc += r['managed_containers']

    print("-"*70)
    print(f"{'TOTAL':<30} {'':<20} {total_fmc:>15.2f}")
    print("="*70)

    print(f"\n💰 Report saved to: {report_file}")
    print(f"   Total billable: {total_fmc:.2f} FMC sensors")
    print()

    return report_file

# ============================================================================
# MAIN
# ============================================================================

def collect_and_store_hourly_data(cid='default', hour=None):
    """
    Collect hourly sensor data and store in database.

    Args:
        cid: Child CID or 'default'
        hour: Target hour to collect (defaults to previous hour)
    """
    if not BillingDatabase:
        print("ERROR: Database modules not available")
        return

    # Initialize database
    db = BillingDatabase()
    print(f"✓ Database initialized at {db.db_path}")

    # Get Falcon client
    try:
        falcon_client = get_falcon_client()
        print(f"✓ Falcon API client initialized")
    except Exception as e:
        print(f"ERROR: Failed to initialize Falcon client: {e}")
        return

    # Determine target hour (default: previous hour)
    if hour is None:
        from datetime import timezone
        hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)

    print(f"\nCollecting sensor data for hour: {hour.strftime('%Y-%m-%d %H:00:00')}")

    try:
        total, cache_hits, api_calls = process_hourly_collection(
            db, hour, cid=cid, falcon_client=falcon_client
        )

        print(f"\n✓ Collection complete:")
        print(f"  Total sensors: {total}")
        print(f"  Cache hits: {cache_hits}")
        print(f"  API calls: {api_calls}")
        print(f"  Cache hit rate: {(cache_hits / (cache_hits + api_calls) * 100) if (cache_hits + api_calls) > 0 else 0:.1f}%")

    except Exception as e:
        print(f"\nERROR: Collection failed: {e}")
        import traceback
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(
        description='Fetch CrowdStrike sensor usage data for chargeback',
        epilog='Examples:\n'
               '  Single CID (API):         python3 falcon_sensor_billing.py --hourly\n'
               '  Collect hourly sensors:   python3 falcon_sensor_billing.py --collect-hourly\n'
               '  Both (API + collection):  python3 falcon_sensor_billing.py --hourly --collect-hourly\n'
               '  Verify billing accuracy:  python3 falcon_sensor_billing.py --verify --start-date 2026-04-01 --end-date 2026-04-30\n'
               '  Multi-tenant:             python3 falcon_sensor_billing.py --hourly --multi-tenant "cid1,cid2,cid3"\n'
               '  From file:                python3 falcon_sensor_billing.py --hourly --multi-tenant @tenants.txt\n'
               '  Auto-discover:            python3 falcon_sensor_billing.py --hourly --multi-tenant --auto-discover',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--hourly',
        action='store_true',
        help='Retrieve hourly average (for FCS/FMC billing) instead of weekly average'
    )
    parser.add_argument(
        '--multi-tenant',
        metavar='CIDS',
        nargs='?',
        const='',
        help='Query multiple CIDs separately for per-tenant chargeback. '
             'Provide comma-separated CIDs or @filename. '
             'File format: one CID per line or "CID,TenantName" per line. '
             'Use with --auto-discover to fetch CIDs automatically'
    )
    parser.add_argument(
        '--auto-discover',
        action='store_true',
        help='Auto-discover child CIDs from Flight Control parent. Requires --multi-tenant flag.'
    )
    parser.add_argument(
        '--collect-hourly',
        action='store_true',
        help='Collect granular hourly sensor data and store in database (requires database modules)'
    )
    parser.add_argument(
        '--verify',
        action='store_true',
        help='Generate verification report comparing calculated vs API billing data'
    )
    parser.add_argument(
        '--start-date',
        metavar='YYYY-MM-DD',
        help='Start date for verification report'
    )
    parser.add_argument(
        '--end-date',
        metavar='YYYY-MM-DD',
        help='End date for verification report'
    )
    parser.add_argument(
        '--cid',
        metavar='CID',
        help='Child CID for single-tenant operations (default: "default")'
    )
    args = parser.parse_args()

    # Validate arguments
    if args.auto_discover and not hasattr(args, 'multi_tenant'):
        print("ERROR: --auto-discover requires --multi-tenant flag")
        sys.exit(1)

    if args.verify:
        if not args.start_date or not args.end_date:
            print("ERROR: --verify requires --start-date and --end-date")
            sys.exit(1)

    cid = args.cid or 'default'
    endpoint_type = 'hourly' if args.hourly else 'weekly'

    print(f"CrowdStrike Falcon Sensor Billing Tool (FalconPy) - {datetime.now().isoformat()}")

    # Verification mode
    if args.verify:
        if not BillingDatabase:
            print("ERROR: Database modules not available - cannot verify")
            sys.exit(1)

        print(f"Mode: Verification Report")
        print(f"Period: {args.start_date} to {args.end_date}")
        print(f"CID: {cid}")
        print()

        db = BillingDatabase()
        report_path = generate_verification_report(db, args.start_date, args.end_date, cid=cid)
        print(f"\n✓ Verification report saved to: {report_path}")
        return

    # Hourly collection mode
    if args.collect_hourly:
        if not BillingDatabase:
            print("ERROR: Database modules not available - cannot collect hourly data")
            sys.exit(1)

        print(f"Mode: Hourly Collection")
        print(f"CID: {cid}")
        print()

        collect_and_store_hourly_data(cid=cid)

        # If --hourly also specified, continue to billing API query
        if not args.hourly:
            return

    # Continue with standard billing API query if --hourly specified
    if args.hourly or not args.collect_hourly:
        print(f"Endpoint: {endpoint_type} average")
        print(f"Period: {PERIOD_DAYS} days")
        print(f"Region: {CLOUD_REGION}")
        print(f"Output: {OUTPUT_DIR}")

        # Multi-tenant mode
        if args.multi_tenant is not None:
            print(f"Mode: Multi-tenant chargeback")
            print()

            if args.auto_discover:
                # Auto-discover child CIDs
                cid_list = auto_discover_child_cids()
                if not cid_list:
                    # No child CIDs found - fall back to single CID mode
                    print("Falling back to single-CID mode...")
                    print()
                else:
                    # Child CIDs found - proceed with multi-tenant
                    generate_multitenant_report(cid_list, endpoint_type)
                    return
            else:
                # Load from file or argument
                if not args.multi_tenant:
                    print("ERROR: --multi-tenant requires CID list or --auto-discover flag")
                    sys.exit(1)
                cid_list = load_cid_list(args.multi_tenant)
                if not cid_list:
                    print("ERROR: No valid CIDs provided")
                    sys.exit(1)

                generate_multitenant_report(cid_list, endpoint_type)
                return

        # Single CID mode
        if SELECTED_CIDS:
            print(f"CIDs: {SELECTED_CIDS}")
        print()

        # Retrieve usage data (FalconPy handles authentication automatically)
        print(f"Retrieving {endpoint_type} usage data...")
        data = get_sensor_usage(endpoint_type)
        print("Data retrieval successful")

        # Print summary
        print_summary(data)

        # Initialize database if available
        db = None
        if BillingDatabase:
            try:
                db = BillingDatabase()
                print(f"✓ Database available at {db.db_path}")
            except Exception as e:
                print(f"⚠️  Database initialization failed: {e}")

        # Log to CSV and database
        print("Logging data to CSV...")
        log_to_csv(data, endpoint_type, db=db, cid=cid)

    print("\nDone!")

if __name__ == '__main__':
    main()
