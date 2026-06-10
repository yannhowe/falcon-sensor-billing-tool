#!/usr/bin/env python3
"""Test product classification directly."""
import sqlite3
from classify_products import classify_sensor_from_row

DB_PATH = "sensor_billing.db"

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

# Test classification on sample hosts
print("Testing product classification:\n")

samples = conn.execute(
    "SELECT * FROM host_metadata_cache WHERE product_type IS NOT NULL LIMIT 20"
).fetchall()

product_counts = {'FCSC': 0, 'FMC': 0, 'FCS': 0, 'EPP': 0}

for host in samples:
    product_type = host['product_type']
    product_counts[product_type] += 1
    hostname = host['hostname'][:50] if host['hostname'] else "Unknown"
    platform = host['platform_name'] or "?"
    print(f"{product_type:4} | {platform:8} | {hostname}")

print("\n" + "="*70)
print("Product Classification Summary:")
print(f"  FCSC (Container Hosts):   {product_counts['FCSC']}")
print(f"  FMC  (Fargate/Sidecars):   {product_counts['FMC']}")
print(f"  FCS  (Cloud VMs):          {product_counts['FCS']}")
print(f"  EPP  (Endpoints):          {product_counts['EPP']}")

# Test query for product breakdown
print("\n" + "="*70)
print("28-Day Average by Product Type:")

from datetime import datetime, timedelta
cutoff = datetime.now() - timedelta(days=28)

for product in ['FCSC', 'FMC', 'FCS', 'EPP']:
    rows = conn.execute(
        """
        SELECT hour_timestamp, COUNT(DISTINCT sensor_id) as count
        FROM sensor_logs
        WHERE product_type = ?
        ORDER BY hour_timestamp
        """,
        (product,)
    ).fetchall()
    
    if len(rows) > 0:
        recent = rows[-min(672, len(rows)):]
        total = sum(r['count'] for r in recent)
        avg = total / len(recent)
        print(f"  {product}: {avg:.2f}")
    else:
        print(f"  {product}: 0.00")

conn.close()
