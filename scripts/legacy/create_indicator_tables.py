#!/usr/bin/env python3
"""
Create database tables to store cloud and container indicators.
"""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "sensor_billing.db"

def create_tables():
    """Create indicator tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Table 1: Container indicators (from NGSIEM OciContainerId query)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS container_indicators (
            aid TEXT PRIMARY KEY,
            has_oci_container_id INTEGER DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            detection_method TEXT DEFAULT 'OciContainerId'
        )
    """)
    
    print("✓ Created table: container_indicators")
    
    # Table 2: Cloud indicators (from IMDS traffic, hardware, API fields)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cloud_indicators (
            aid TEXT PRIMARY KEY,
            is_cloud INTEGER DEFAULT 0,
            has_imds_traffic INTEGER DEFAULT 0,
            cloud_provider TEXT,
            service_provider TEXT,
            instance_id TEXT,
            system_manufacturer TEXT,
            chassis_type TEXT,
            detection_methods TEXT,
            first_detected TEXT NOT NULL,
            last_updated TEXT NOT NULL
        )
    """)
    
    print("✓ Created table: cloud_indicators")
    
    # Index for fast lookups
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_container_indicators_aid 
        ON container_indicators(aid)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_cloud_indicators_aid 
        ON cloud_indicators(aid)
    """)
    
    print("✓ Created indexes")
    
    conn.commit()
    conn.close()
    
    print("\n✓ Database schema updated")


if __name__ == '__main__':
    print("Creating indicator tables...\n")
    create_tables()
