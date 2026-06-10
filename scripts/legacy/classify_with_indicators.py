#!/usr/bin/env python3
"""
Improved classification using NGSIEM indicators and hardware detection.
"""
import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).parent / "sensor_billing.db"


def classify_host_improved(host_row, container_indicator, cloud_indicator):
    """
    Classify host using multiple data sources.

    Args:
        host_row: Row from host_metadata_cache
        container_indicator: Row from container_indicators (or None)
        cloud_indicator: Row from cloud_indicators (or None)

    Returns:
        str: Product classification (FCSC, FMC, FCS, EPP)
    """
    platform = host_row['platform_name'] if host_row['platform_name'] else ''
    os_version = (host_row['os_version'] if host_row['os_version'] else '').lower()

    # Priority 1: FCSC - Container Hosts
    # Check if AID has spawned containers (OciContainerId present)
    if container_indicator and container_indicator['has_oci_container_id']:
        return 'FCSC'

    # Kubernetes platform is always FCSC
    if platform == 'K8S':
        return 'FCSC'

    # Priority 2: EPP - Clear Endpoint Indicators
    # Mobile devices
    if platform in ['Android', 'iOS', 'ChromeOS']:
        return 'EPP'

    # Mac devices (laptops/desktops)
    if platform == 'Mac':
        return 'EPP'

    # Windows desktop OS (Windows 10/11)
    if platform == 'Windows':
        if 'windows 10' in os_version or 'windows 11' in os_version:
            return 'EPP'

    # Priority 3: FCS vs EPP for Servers/Linux/Windows
    # Check if cloud-based
    is_cloud = False

    if cloud_indicator:
        # Has IMDS traffic or hardware/API indicators
        is_cloud = (
            cloud_indicator['has_imds_traffic'] == 1 or
            cloud_indicator['is_cloud'] == 1
        )

    if platform in ['Linux', 'Windows']:
        if is_cloud:
            return 'FCS'  # Cloud VM
        else:
            return 'EPP'  # On-premise server/workstation

    # Default: Endpoint
    return 'EPP'


def reclassify_all_hosts():
    """Reclassify all hosts using improved logic."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    print("Reclassifying all hosts with improved logic...")
    print("="*70)
    print()
    
    # Get all hosts
    hosts = cursor.execute("SELECT * FROM host_metadata_cache").fetchall()
    
    print(f"Processing {len(hosts)} hosts...")
    
    classifications = {'FCSC': 0, 'FMC': 0, 'FCS': 0, 'EPP': 0}
    changed = 0
    
    for host in hosts:
        aid = host['sensor_id']
        
        # Get indicators
        container_ind = cursor.execute(
            "SELECT * FROM container_indicators WHERE aid = ?",
            (aid,)
        ).fetchone()
        
        cloud_ind = cursor.execute(
            "SELECT * FROM cloud_indicators WHERE aid = ?",
            (aid,)
        ).fetchone()
        
        # Classify
        old_classification = host['product_type']
        new_classification = classify_host_improved(host, container_ind, cloud_ind)
        
        classifications[new_classification] += 1
        
        if old_classification != new_classification:
            changed += 1
        
        # Update database
        cursor.execute(
            "UPDATE host_metadata_cache SET product_type = ? WHERE sensor_id = ?",
            (new_classification, aid)
        )
    
    # Update sensor_logs from host_metadata_cache
    cursor.execute("""
        UPDATE sensor_logs
        SET product_type = (
            SELECT product_type 
            FROM host_metadata_cache 
            WHERE host_metadata_cache.sensor_id = sensor_logs.sensor_id
        )
    """)
    
    conn.commit()
    
    print(f"\n✓ Reclassified {len(hosts)} hosts")
    print(f"  Changed: {changed} hosts")
    
    print("\n" + "="*70)
    print("CLASSIFICATION SUMMARY")
    print("="*70)
    print(f"  FCSC (Container Hosts):   {classifications['FCSC']:4}")
    print(f"  FMC  (Fargate/Sidecars):   {classifications['FMC']:4}")
    print(f"  FCS  (Cloud VMs):         {classifications['FCS']:4}")
    print(f"  EPP  (Endpoints):         {classifications['EPP']:4}")
    print(f"  Total:                    {sum(classifications.values()):4}")
    
    # Show detection method breakdown
    print("\n" + "="*70)
    print("DETECTION METHODS")
    print("="*70)
    
    fcsc_with_oci = cursor.execute("""
        SELECT COUNT(*) FROM host_metadata_cache hmc
        JOIN container_indicators ci ON hmc.sensor_id = ci.aid
        WHERE hmc.product_type = 'FCSC'
    """).fetchone()[0]
    
    fcsc_k8s = cursor.execute("""
        SELECT COUNT(*) FROM host_metadata_cache
        WHERE product_type = 'FCSC' AND platform_name = 'K8S'
    """).fetchone()[0]
    
    fcs_with_imds = cursor.execute("""
        SELECT COUNT(*) FROM host_metadata_cache hmc
        JOIN cloud_indicators ci ON hmc.sensor_id = ci.aid
        WHERE hmc.product_type = 'FCS' AND ci.has_imds_traffic = 1
    """).fetchone()[0]
    
    fcs_with_hardware = cursor.execute("""
        SELECT COUNT(*) FROM host_metadata_cache hmc
        JOIN cloud_indicators ci ON hmc.sensor_id = ci.aid
        WHERE hmc.product_type = 'FCS' AND ci.detection_methods LIKE '%Hardware%'
    """).fetchone()[0]
    
    print(f"FCSC Detection:")
    print(f"  OciContainerId present:     {fcsc_with_oci}")
    print(f"  K8S platform:                {fcsc_k8s}")
    print(f"\nFCS Detection:")
    print(f"  IMDS traffic (169.254...):   {fcs_with_imds}")
    print(f"  Hardware signatures:         {fcs_with_hardware}")
    
    conn.close()


if __name__ == '__main__':
    print("Improved Host Classification")
    print("="*70)
    print()
    reclassify_all_hosts()
    print("\n✓ Classification complete!")
