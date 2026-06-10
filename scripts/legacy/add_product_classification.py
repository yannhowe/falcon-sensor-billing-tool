#!/usr/bin/env python3
"""
Add product_type column to database and classify all hosts.
"""
import sqlite3
from pathlib import Path
from classify_products import classify_sensor_from_row

DB_PATH = Path(__file__).parent / "sensor_billing.db"


def add_product_classification_column():
    """Add product_type column to tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Add column to sensor_logs
    try:
        cursor.execute("ALTER TABLE sensor_logs ADD COLUMN product_type TEXT")
        print("✓ Added product_type column to sensor_logs")
    except sqlite3.OperationalError as e:
        if "duplicate column" in str(e):
            print("  Column product_type already exists in sensor_logs")
        else:
            raise
    
    # Add column to host_metadata_cache
    try:
        cursor.execute("ALTER TABLE host_metadata_cache ADD COLUMN product_type TEXT")
        print("✓ Added product_type column to host_metadata_cache")
    except sqlite3.OperationalError as e:
        if "duplicate column" in str(e):
            print("  Column product_type already exists in host_metadata_cache")
        else:
            raise
    
    conn.commit()
    conn.close()


def classify_all_hosts():
    """Classify all hosts in host_metadata_cache."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all hosts
    hosts = cursor.execute("SELECT * FROM host_metadata_cache").fetchall()
    
    print(f"\nClassifying {len(hosts)} hosts...")
    
    classifications = {'FCSC': 0, 'FMC': 0, 'FCS': 0, 'EPP': 0}
    
    for host in hosts:
        product_type = classify_sensor_from_row(host)
        classifications[product_type] += 1
        
        cursor.execute(
            "UPDATE host_metadata_cache SET product_type = ? WHERE sensor_id = ?",
            (product_type, host['sensor_id'])
        )
    
    conn.commit()
    conn.close()
    
    print("\nClassification Summary:")
    print(f"  FCSC (Container Hosts):   {classifications['FCSC']:4}")
    print(f"  FMC  (Fargate/Sidecar):   {classifications['FMC']:4}")
    print(f"  FCS  (Cloud VMs):         {classifications['FCS']:4}")
    print(f"  EPP  (Endpoints):         {classifications['EPP']:4}")
    print(f"  Total:                    {sum(classifications.values()):4}")


def classify_sensor_logs():
    """Classify all sensor logs based on host metadata."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("\nUpdating sensor_logs with product classifications...")
    
    # Update sensor_logs from host_metadata_cache
    cursor.execute("""
        UPDATE sensor_logs
        SET product_type = (
            SELECT product_type 
            FROM host_metadata_cache 
            WHERE host_metadata_cache.sensor_id = sensor_logs.sensor_id
        )
    """)
    
    rows_updated = cursor.rowcount
    conn.commit()
    conn.close()
    
    print(f"✓ Updated {rows_updated} sensor log entries")


if __name__ == '__main__':
    print("Adding product classification to database...\n")
    add_product_classification_column()
    classify_all_hosts()
    classify_sensor_logs()
    print("\n✓ Classification complete!")
