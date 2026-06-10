#!/usr/bin/env python3
"""
Refine cloud provider classification using enhanced IMDS detection data.
Uses URL path patterns and process context for high-confidence classification.
"""
import json
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "sensor_billing.db"


def classify_with_url_and_process(aid, current_provider, enhanced_detection, hardware_indicator):
    """
    Classify cloud provider using enhanced IMDS detection data.

    Priority:
    1. Non-standard IMDS IPs (Alibaba, Scaleway, etc.) -> high confidence
    2. URL path patterns -> high confidence
    3. Process names -> medium confidence
    4. Hardware indicators -> low confidence
    5. Standard IMDS without context -> "Others"

    Args:
        aid: Agent ID
        current_provider: Current cloud provider classification
        enhanced_detection: Enhanced detection data from imds_enhanced.json
        hardware_indicator: Hardware indicator data (optional)

    Returns: (provider, confidence, reason)
    """

    # Don't override already confident classifications
    if current_provider in ['AWS', 'Azure', 'GCP', 'Oracle', 'Alibaba', 'End-User-Device']:
        return current_provider, 'high', 'Already classified'

    if not enhanced_detection:
        return current_provider, 'low', 'No enhanced detection data'

    evidence = enhanced_detection.get('evidence', {})
    imds_ip = evidence.get('imds_ip')
    url_paths = evidence.get('url_paths', [])
    processes = evidence.get('processes', [])

    # Non-standard IMDS endpoints (definitive)
    if imds_ip == '100.100.100.200':
        return 'Alibaba', 'high', 'Alibaba IMDS endpoint'
    elif imds_ip == '169.254.42.42':
        return 'Scaleway', 'high', 'Scaleway IMDS endpoint'

    # Standard IMDS - check URL patterns (high confidence)
    if imds_ip == '169.254.169.254':
        # Check URL path patterns
        for path in url_paths:
            if any(p in path for p in ['/latest/', '/meta-data/', '/dynamic/']):
                return 'AWS', 'high', f'AWS URL pattern: {path}'
            elif '/metadata/instance' in path or '/metadata/identity' in path:
                return 'Azure', 'high', f'Azure URL pattern: {path}'
            elif '/computeMetadata/' in path:
                return 'GCP', 'high', f'GCP URL pattern: {path}'
            elif '/opc/v' in path:
                return 'Oracle', 'high', f'Oracle URL pattern: {path}'
            elif '/metadata/v1/' in path:
                return 'DigitalOcean', 'high', f'DigitalOcean URL pattern: {path}'
            elif '/v1/instance' in path or '/v1/network' in path:
                return 'Linode', 'high', f'Linode URL pattern: {path}'

        # Check process names (medium confidence)
        for proc in processes:
            proc_lower = proc.lower()
            if any(p in proc_lower for p in ['amazon-ssm-agent', 'ssm-agent', 'ssm-document', 'ec2-', 'aws-']):
                return 'AWS', 'medium', f'AWS process: {proc}'
            elif any(p in proc_lower for p in ['waagent', 'walinux', 'azure-']):
                return 'Azure', 'medium', f'Azure process: {proc}'
            elif any(p in proc_lower for p in ['gce-', 'google-', 'gcemetadata']):
                return 'GCP', 'medium', f'GCP process: {proc}'
            elif any(p in proc_lower for p in ['oci-', 'oracle-cloud']):
                return 'Oracle', 'medium', f'Oracle process: {proc}'

        # Standard IMDS but no clear indicators
        return 'Others-IMDS', 'low', 'Standard IMDS, provider unclear'

    return current_provider, 'low', 'No classification possible'


def main():
    print("Enhanced Cloud Provider Classification")
    print("=" * 70)
    print()

    # Load enhanced IMDS data
    imds_file = Path(__file__).parent / "imds_enhanced.json"

    if not imds_file.exists():
        print("No enhanced IMDS data found")
        print("   Classification will use existing methods only")
        print("   Run: python3 query_imds_with_context.py")
        print()
        detections = {}
    else:
        with open(imds_file) as f:
            imds_data = json.load(f)

        detections = imds_data.get('detections', {})
        print(f"Loaded enhanced detection data for {len(detections)} hosts")
        print()

    # Load hardware indicators (optional)
    hardware_map = {}
    hardware_file = Path(__file__).parent / "hardware_indicators.json"

    if hardware_file.exists():
        with open(hardware_file) as f:
            hardware_data = json.load(f)
            for device in hardware_data:
                aid = device['aid']
                hardware_map[aid] = device
        print(f"Loaded {len(hardware_map)} hardware indicators")
    else:
        print("No hardware indicators file found (optional)")

    print()

    # Connect to database
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get all hosts
    hosts = cursor.execute("""
        SELECT sensor_id, hostname, cloud_provider
        FROM host_metadata_cache
        ORDER BY sensor_id
    """).fetchall()

    print(f"Analyzing {len(hosts)} hosts...")
    print()

    # Track changes
    stats = {
        'analyzed': 0,
        'updated': 0,
        'high_confidence': 0,
        'medium_confidence': 0,
        'low_confidence': 0,
        'by_provider': {}
    }

    for host in hosts:
        aid = host['sensor_id']
        current = host['cloud_provider']

        enhanced = detections.get(aid)
        hardware = hardware_map.get(aid)

        new_provider, confidence, reason = classify_with_url_and_process(
            aid, current, enhanced, hardware
        )

        stats['analyzed'] += 1

        if new_provider != current or enhanced:
            # Update classification
            metadata_json = None
            if enhanced:
                metadata_json = json.dumps({
                    'provider': new_provider,
                    'confidence': confidence,
                    'evidence': enhanced.get('evidence', {}),
                    'detected_at': datetime.now().isoformat()
                })

            cursor.execute("""
                UPDATE host_metadata_cache
                SET cloud_provider = ?,
                    detection_metadata = ?
                WHERE sensor_id = ?
            """, (new_provider, metadata_json, aid))

            stats['updated'] += 1
            stats[f'{confidence}_confidence'] += 1

            if new_provider not in stats['by_provider']:
                stats['by_provider'][new_provider] = 0
            stats['by_provider'][new_provider] += 1

            if new_provider != current:
                current_display = current if current else "Unknown"
                print(f"  {aid[:16]}... {current_display:15s} -> {new_provider:15s} ({confidence}, {reason})")

    # Update sensor_logs table
    if stats['updated'] > 0:
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

    # Print summary
    print()
    print("=" * 70)
    print("CLASSIFICATION RESULTS")
    print("=" * 70)
    print(f"Hosts analyzed:          {stats['analyzed']}")
    print(f"Classifications updated: {stats['updated']}")
    print()
    print(f"By confidence:")
    print(f"  High:   {stats['high_confidence']}")
    print(f"  Medium: {stats['medium_confidence']}")
    print(f"  Low:    {stats['low_confidence']}")
    print()

    if stats['by_provider']:
        print(f"By provider:")
        for provider, count in sorted(stats['by_provider'].items()):
            print(f"  {provider:20s}: {count:4d}")

    print()
    print("Enhanced classification complete")
    print()


if __name__ == '__main__':
    main()
