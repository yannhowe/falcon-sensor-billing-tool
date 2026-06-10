#!/usr/bin/env .venv/bin/python3
"""
Query Falcon Sensor Usage API for billing metrics.

This API provides hourly and weekly averages of unique sensors (AIDs)
for the previous 28 days. This is the official CrowdStrike billing metric.

Note: Reserved license quantities are NOT available via API.
These must be configured manually or obtained from your account manager.
"""
import os
import json
import subprocess
from datetime import datetime
from falconpy import APIHarness

# Load active CID profile
def get_active_profile():
    # Hardcode to talon_1 for now
    return 'talon_1'

# Get credentials from keychain
def get_keychain_value(service, account):
    try:
        result = subprocess.run(
            ['security', 'find-generic-password', '-s', service, '-a', account, '-w'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None

profile = get_active_profile()
print(f"Using CID profile: {profile}")

CLIENT_ID = get_keychain_value('falcon-client-id', profile)
CLIENT_SECRET = get_keychain_value('falcon-client-secret', profile)
CLOUD = get_keychain_value('falcon-cloud-region', profile) or 'us-1'

if not CLIENT_ID or not CLIENT_SECRET:
    print("❌ Falcon API credentials not found in keychain")
    print(f"Run: /cid use {profile}")
    exit(1)

# Initialize Falcon API
falcon = APIHarness(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=CLOUD)

print("=" * 80)
print("FALCON SENSOR USAGE API QUERY")
print("=" * 80)
print(f"Cloud: {CLOUD}")
print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print()

# Query Hourly Average
print("📊 Fetching Hourly Average (28-day rolling)...")
print("-" * 80)

hourly_response = falcon.command(
    "GetSensorUsageHourly",
    filter=""  # Default: 28 days, ending 2 days ago
)

if hourly_response['status_code'] != 200:
    print(f"❌ Failed to fetch hourly average: {hourly_response}")
    exit(1)

hourly_data = hourly_response['body']
print(f"✓ Fetched hourly average data")
print()

# Query Weekly Average
print("📊 Fetching Weekly Average (28-day rolling)...")
print("-" * 80)

weekly_response = falcon.command(
    "GetSensorUsageWeekly",
    filter=""  # Default: 28 days, ending 2 days ago
)

if weekly_response['status_code'] != 200:
    print(f"❌ Failed to fetch weekly average: {weekly_response}")
    exit(1)

weekly_data = weekly_response['body']
print(f"✓ Fetched weekly average data")
print()

# Display summary
print("=" * 80)
print("USAGE SUMMARY")
print("=" * 80)
print()

# Extract metrics from hourly data
if 'resources' in hourly_data and len(hourly_data['resources']) > 0:
    latest_hourly = hourly_data['resources'][-1]  # Most recent data point
    print(f"Latest Hourly Average:")
    print(f"  Date: {latest_hourly.get('event_date', 'N/A')}")
    print(f"  Unique Sensors: {latest_hourly.get('value', 'N/A')}")
    print()

# Extract metrics from weekly data
if 'resources' in weekly_data and len(weekly_data['resources']) > 0:
    latest_weekly = weekly_data['resources'][-1]  # Most recent data point
    print(f"Latest Weekly Average:")
    print(f"  Week Ending: {latest_weekly.get('event_date', 'N/A')}")
    print(f"  Unique Sensors: {latest_weekly.get('value', 'N/A')}")
    print()

# Save to file
output_data = {
    'timestamp': datetime.now().isoformat(),
    'cloud_region': CLOUD,
    'hourly_average': hourly_data.get('resources', []),
    'weekly_average': weekly_data.get('resources', [])
}

output_file = 'sensor_usage_api.json'
with open(output_file, 'w') as f:
    json.dump(output_data, f, indent=2)

print(f"✓ Saved usage data to: {output_file}")
print()

# Important note
print("=" * 80)
print("⚠️  IMPORTANT NOTE ON RESERVED LICENSES")
print("=" * 80)
print()
print("The Sensor Usage API provides ACTUAL usage (how many sensors you're using),")
print("but does NOT provide RESERVED license quantities (how many you purchased).")
print()
print("Reserved license counts must be:")
print("  1. Configured manually in your dashboard (as you have with the input field)")
print("  2. Obtained from your CrowdStrike account manager")
print("  3. Found in your CrowdStrike contract/subscription documentation")
print()
print("This is by design - license/subscription details are not exposed via API.")
print("=" * 80)
