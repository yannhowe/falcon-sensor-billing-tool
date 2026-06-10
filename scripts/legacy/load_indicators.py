#!/usr/bin/env python3
"""
Load cloud and container indicators into database.
"""
import sqlite3
import json
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).parent / "sensor_billing.db"

def load_container_indicators():
    """Load container indicators from NGSIEM query results."""
    indicators_file = Path(__file__).parent / 'cloud_indicators.json'
    
    if not indicators_file.exists():
        print("⚠️  cloud_indicators.json not found")
        print("   Run: python3 query_cloud_indicators.py")
        return 0
    
    with open(indicators_file) as f:
        data = json.load(f)
    
    container_aids = data['container_hosts']['aids']
    
    if not container_aids:
        print("⚠️  No container hosts found in query results")
        return 0
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    timestamp = datetime.utcnow().isoformat() + 'Z'
    
    for aid in container_aids:
        cursor.execute("""
            INSERT OR REPLACE INTO container_indicators 
            (aid, has_oci_container_id, first_seen, last_seen, detection_method)
            VALUES (?, 1, 
                    COALESCE((SELECT first_seen FROM container_indicators WHERE aid = ?), ?),
                    ?, 'OciContainerId')
        """, (aid, aid, timestamp, timestamp))
    
    conn.commit()
    conn.close()
    
    print(f"✓ Loaded {len(container_aids)} container indicators")
    return len(container_aids)


def load_cloud_indicators_from_ngsiem():
    """Load cloud indicators from NGSIEM IMDS query."""
    indicators_file = Path(__file__).parent / 'cloud_indicators.json'
    
    if not indicators_file.exists():
        print("⚠️  cloud_indicators.json not found")
        return 0
    
    with open(indicators_file) as f:
        data = json.load(f)
    
    cloud_aids = data['cloud_workloads']['aids']
    
    if not cloud_aids:
        print("⚠️  No cloud workloads found in IMDS query")
        return 0
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    timestamp = datetime.utcnow().isoformat() + 'Z'
    
    for aid in cloud_aids:
        # Check if already exists
        existing = cursor.execute(
            "SELECT detection_methods FROM cloud_indicators WHERE aid = ?",
            (aid,)
        ).fetchone()
        
        if existing:
            # Update existing record
            methods = existing[0] or ''
            if 'IMDS' not in methods:
                methods = (methods + ',IMDS').lstrip(',')
            
            cursor.execute("""
                UPDATE cloud_indicators
                SET has_imds_traffic = 1,
                    is_cloud = 1,
                    detection_methods = ?,
                    last_updated = ?
                WHERE aid = ?
            """, (methods, timestamp, aid))
        else:
            # Insert new record
            cursor.execute("""
                INSERT INTO cloud_indicators
                (aid, is_cloud, has_imds_traffic, detection_methods, first_detected, last_updated)
                VALUES (?, 1, 1, 'IMDS', ?, ?)
            """, (aid, timestamp, timestamp))
    
    conn.commit()
    conn.close()
    
    print(f"✓ Loaded {len(cloud_aids)} cloud indicators from IMDS query")
    return len(cloud_aids)


def load_cloud_indicators_from_hardware():
    """Load cloud indicators from hardware detection."""
    hardware_file = Path(__file__).parent / 'hardware_indicators.json'
    
    if not hardware_file.exists():
        print("⚠️  hardware_indicators.json not found")
        print("   Run: python3 fetch_hardware_info.py")
        return 0
    
    with open(hardware_file) as f:
        hardware_data = json.load(f)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    timestamp = datetime.utcnow().isoformat() + 'Z'
    count = 0
    
    for item in hardware_data:
        if not item['is_cloud']:
            continue
        
        aid = item['aid']
        count += 1
        
        # Build detection methods
        methods = []
        if item.get('cloud_provider'):
            methods.append('Hardware')
        if item.get('service_provider'):
            methods.append('API-ServiceProvider')
        if item.get('instance_id'):
            methods.append('API-InstanceID')
        
        # Check if already exists
        existing = cursor.execute(
            "SELECT detection_methods FROM cloud_indicators WHERE aid = ?",
            (aid,)
        ).fetchone()
        
        if existing:
            # Merge methods
            existing_methods = set((existing[0] or '').split(','))
            all_methods = existing_methods.union(methods)
            methods_str = ','.join(sorted(all_methods))
            
            cursor.execute("""
                UPDATE cloud_indicators
                SET is_cloud = 1,
                    cloud_provider = ?,
                    service_provider = ?,
                    instance_id = ?,
                    system_manufacturer = ?,
                    chassis_type = ?,
                    detection_methods = ?,
                    last_updated = ?
                WHERE aid = ?
            """, (
                item.get('cloud_provider'),
                item.get('service_provider'),
                item.get('instance_id'),
                item.get('system_manufacturer'),
                item.get('chassis_type'),
                methods_str,
                timestamp,
                aid
            ))
        else:
            # Insert new
            cursor.execute("""
                INSERT INTO cloud_indicators
                (aid, is_cloud, cloud_provider, service_provider, instance_id,
                 system_manufacturer, chassis_type, detection_methods,
                 first_detected, last_updated)
                VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                aid,
                item.get('cloud_provider'),
                item.get('service_provider'),
                item.get('instance_id'),
                item.get('system_manufacturer'),
                item.get('chassis_type'),
                ','.join(methods),
                timestamp,
                timestamp
            ))
    
    conn.commit()
    conn.close()
    
    print(f"✓ Loaded {count} cloud indicators from hardware detection")
    return count


def main():
    print("Loading Cloud and Container Indicators")
    print("="*70)
    print()
    
    container_count = load_container_indicators()
    imds_count = load_cloud_indicators_from_ngsiem()
    hardware_count = load_cloud_indicators_from_hardware()
    
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Container indicators (OciContainerId): {container_count}")
    print(f"Cloud indicators (IMDS traffic):       {imds_count}")
    print(f"Cloud indicators (Hardware):           {hardware_count}")
    
    # Show database stats
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    total_container = cursor.execute("SELECT COUNT(*) FROM container_indicators").fetchone()[0]
    total_cloud = cursor.execute("SELECT COUNT(*) FROM cloud_indicators").fetchone()[0]
    
    print(f"\nTotal in database:")
    print(f"  Container indicators: {total_container}")
    print(f"  Cloud indicators:     {total_cloud}")
    
    conn.close()


if __name__ == '__main__':
    main()
