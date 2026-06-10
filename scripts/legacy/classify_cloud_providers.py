#!/usr/bin/env python3
"""
Classify cloud providers based on hardware signatures and IMDS traffic.
"""
import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "sensor_billing.db"

def classify_cloud_provider(host_row, hardware_indicator):
    """
    Classify cloud provider based on hardware signatures.

    Returns: AWS, Azure, GCP, Oracle, Alibaba, Others, On-Premise, End-User-Device
    """
    platform = host_row['platform_name'] if host_row['platform_name'] else ''
    os_version = (host_row['os_version'] if host_row['os_version'] else '').lower()

    # End-User Devices (mobile, desktops)
    if platform in ['Android', 'iOS', 'ChromeOS']:
        return 'End-User-Device'

    if platform == 'Mac':
        return 'End-User-Device'

    if platform == 'Windows':
        # Windows 10/11 are typically endpoints
        if 'windows 10' in os_version or 'windows 11' in os_version:
            return 'End-User-Device'

    # Check hardware signatures
    if hardware_indicator:
        service_provider = (hardware_indicator.get('service_provider') or '').upper()

        if service_provider == 'GCP':
            return 'GCP'
        elif service_provider == 'AWS':
            return 'AWS'
        elif service_provider == 'AZURE':
            return 'Azure'
        elif service_provider == 'ORACLE':
            return 'Oracle'
        elif service_provider == 'ALIBABA':
            return 'Alibaba'
        elif service_provider == 'TENCENT':
            return 'Others'
        elif service_provider == 'HUAWEI':
            return 'Others'
        elif service_provider == 'IBM':
            return 'Others'
        elif service_provider == 'DIGITALOCEAN':
            return 'Others'
        elif service_provider == 'LINODE':
            return 'Others'
        elif service_provider == 'VULTR':
            return 'Others'
        elif service_provider == 'ON-PREMISE' or not service_provider:
            # Check if it has cloud indicators
            if hardware_indicator.get('is_cloud'):
                return 'Others'  # Cloud but unknown provider
            return 'On-Premise'

    # Default for servers without clear indicators
    if platform in ['Linux', 'Windows']:
        return 'On-Premise'

    return 'Unknown'


def main():
    print("Classifying Cloud Providers")
    print("=" * 70)
    print()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Load hardware indicators
    hardware_file = Path(__file__).parent / "hardware_indicators.json"
    hardware_map = {}

    if hardware_file.exists():
        with open(hardware_file, 'r') as f:
            hardware_data = json.load(f)
            for device in hardware_data:
                aid = device['aid']
                hardware_map[aid] = device
        print(f"✓ Loaded {len(hardware_map)} hardware indicators")
    else:
        print("⚠️  No hardware indicators file found")

    print()

    # Get all hosts
    hosts = cursor.execute("""
        SELECT sensor_id, hostname, platform_name, os_version, product_type
        FROM host_metadata_cache
        ORDER BY sensor_id
    """).fetchall()

    print(f"Processing {len(hosts)} hosts...")
    print()

    # Classify cloud providers
    cloud_counts = {
        'AWS': 0,
        'Azure': 0,
        'GCP': 0,
        'Oracle': 0,
        'Alibaba': 0,
        'Others': 0,
        'On-Premise': 0,
        'End-User-Device': 0,
        'Unknown': 0
    }

    updated = 0
    for host in hosts:
        aid = host['sensor_id']
        hardware = hardware_map.get(aid)

        cloud_provider = classify_cloud_provider(host, hardware)
        cloud_counts[cloud_provider] += 1

        # Update database
        cursor.execute("""
            UPDATE host_metadata_cache
            SET cloud_provider = ?
            WHERE sensor_id = ?
        """, (cloud_provider, aid))

        updated += 1

        if updated % 100 == 0:
            print(f"  Processed {updated}/{len(hosts)} hosts...")

    # Also update sensor_logs table
    print()
    print("Updating sensor_logs table...")
    cursor.execute("""
        UPDATE sensor_logs
        SET cloud_provider = (
            SELECT cloud_provider
            FROM host_metadata_cache
            WHERE host_metadata_cache.sensor_id = sensor_logs.sensor_id
        )
    """)

    conn.commit()
    conn.close()

    print()
    print("=" * 70)
    print("CLASSIFICATION RESULTS")
    print("=" * 70)
    print()

    for provider in sorted(cloud_counts.keys()):
        count = cloud_counts[provider]
        pct = (count / len(hosts) * 100) if len(hosts) > 0 else 0
        print(f"  {provider:20s}: {count:4d} ({pct:5.1f}%)")

    print()
    print(f"✓ Updated {updated} hosts")
    print()


if __name__ == '__main__':
    main()
