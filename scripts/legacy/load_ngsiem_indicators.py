#!/usr/bin/env python3
"""
Load NGSIEM indicator results into database.
"""
import json
import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).parent / "sensor_billing.db"

def load_container_indicators():
    """Load container indicators from NGSIEM query."""
    container_file = Path(__file__).parent / "container_indicators_ngsiem.json"

    if not container_file.exists():
        print("⚠️  Container indicators file not found")
        return 0

    with open(container_file, 'r') as f:
        data = json.load(f)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    loaded = 0
    for aid in data['aids']:
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO container_indicators
                (aid, has_oci_container_id, first_seen, last_seen, detection_method)
                VALUES (?, 1, ?, ?, 'NGSIEM-OciContainerId')
            """, (aid, data['timestamp'], data['timestamp']))
            loaded += 1
        except Exception as e:
            print(f"Error loading {aid}: {e}")

    conn.commit()
    conn.close()

    return loaded

def load_imds_indicators():
    """Load IMDS traffic indicators from NGSIEM query."""
    imds_file = Path(__file__).parent / "imds_indicators_ngsiem.json"

    if not imds_file.exists():
        print("⚠️  IMDS indicators file not found")
        return 0

    with open(imds_file, 'r') as f:
        data = json.load(f)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    loaded = 0
    updated = 0

    for aid in data['aids']:
        try:
            # Check if record exists
            existing = cursor.execute(
                "SELECT aid, detection_methods FROM cloud_indicators WHERE aid = ?",
                (aid,)
            ).fetchone()

            if existing:
                # Update existing record
                methods = existing[1] if existing[1] else ""
                if "IMDS" not in methods:
                    methods = (methods + ",IMDS" if methods else "IMDS")

                cursor.execute("""
                    UPDATE cloud_indicators
                    SET has_imds_traffic = 1,
                        detection_methods = ?,
                        last_updated = ?
                    WHERE aid = ?
                """, (methods, data['timestamp'], aid))
                updated += 1
            else:
                # Insert new record
                cursor.execute("""
                    INSERT INTO cloud_indicators
                    (aid, is_cloud, has_imds_traffic, detection_methods, first_detected, last_updated)
                    VALUES (?, 1, 1, 'IMDS', ?, ?)
                """, (aid, data['timestamp'], data['timestamp']))
                loaded += 1
        except Exception as e:
            print(f"Error loading {aid}: {e}")

    conn.commit()
    conn.close()

    return loaded, updated

if __name__ == '__main__':
    print("Loading NGSIEM Indicators into Database")
    print("=" * 70)
    print()

    # Load container indicators
    print("🐳 Loading container indicators (OciContainerId)...")
    container_count = load_container_indicators()
    print(f"   ✓ Loaded {container_count} container host AIDs")
    print()

    # Load IMDS indicators
    print("☁️  Loading IMDS indicators (cloud VMs)...")
    imds_new, imds_updated = load_imds_indicators()
    print(f"   ✓ Added {imds_new} new cloud VM AIDs")
    print(f"   ✓ Updated {imds_updated} existing cloud VM AIDs")
    print()

    print("=" * 70)
    print("✓ Indicators loaded successfully")
    print()
    print("Next step: python3 classify_with_indicators.py")
