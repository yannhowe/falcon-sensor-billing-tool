# Enhanced Cloud Provider Detection & Historical Data Collection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable accurate cloud provider detection using HTTP URL paths and process context, with 7-day historical data backfill capability.

**Architecture:** Two-phase approach: (1) Enhanced IMDS detection script queries NGSIEM for URL/process patterns and produces classification evidence, (2) Billing collector uses evidence for high-confidence classification. Gap detection prevents duplicate collection.

**Tech Stack:** Python 3.14, FalconPy SDK, SQLite, NGSIEM/LogScale

---

## File Structure

**New Files:**
- `query_imds_with_context.py` - Enhanced IMDS detection with URL/process analysis
- `tests/test_cloud_classification.py` - Unit tests for classification logic
- `tests/test_gap_detection.py` - Unit tests for historical backfill logic

**Modified Files:**
- `billing_collector.py` - Add --days parameter and gap detection
- `refine_cloud_classification.py` - Use enhanced detection data with URL/process context
- `billing_database.py` - Add detection_metadata column migration

**Output Files:**
- `imds_enhanced.json` - Detection evidence (generated at runtime)

---

## Task 1: Database Schema Migration

**Files:**
- Modify: `billing_database.py:1-50`
- Test: Manual verification via SQLite

- [ ] **Step 1: Add migration function to billing_database.py**

Open `billing_database.py` and add this function after the `__init__` method:

```python
def migrate_add_detection_metadata(self):
    """Add detection_metadata column to host_metadata_cache if it doesn't exist."""
    cursor = self.conn.cursor()

    # Check if column exists
    cursor.execute("PRAGMA table_info(host_metadata_cache)")
    columns = [row[1] for row in cursor.fetchall()]

    if 'detection_metadata' not in columns:
        logger.info("Adding detection_metadata column to host_metadata_cache...")
        cursor.execute("""
            ALTER TABLE host_metadata_cache
            ADD COLUMN detection_metadata TEXT
        """)
        self.conn.commit()
        logger.info("✓ Schema migration complete")
    else:
        logger.debug("detection_metadata column already exists")
```

- [ ] **Step 2: Call migration in __init__**

In `billing_database.py`, update the `__init__` method to call the migration:

Find the line after `self._create_tables()` and add:

```python
self._create_tables()
self.migrate_add_detection_metadata()  # Add this line
```

- [ ] **Step 3: Test migration manually**

Run:
```bash
cd /Users/ykwan/Documents/code/knowledgebase/projects/falcon-sensor-billing-tool
.venv/bin/python3 -c "from billing_database import BillingDatabase; db = BillingDatabase(); print('Migration successful')"
```

Expected: "✓ Schema migration complete" or "detection_metadata column already exists"

- [ ] **Step 4: Verify column exists**

Run:
```bash
sqlite3 sensor_billing.db "PRAGMA table_info(host_metadata_cache)" | grep detection_metadata
```

Expected: Output shows detection_metadata column with TEXT type

- [ ] **Step 5: Commit**

```bash
git add billing_database.py
git commit -m "feat(db): add detection_metadata column to host_metadata_cache

Add migration to support storing cloud detection evidence as JSON.
Includes automatic migration on database initialization.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 2: Enhanced IMDS Detection - Core Classification Logic

**Files:**
- Create: `query_imds_with_context.py`
- Test: Manual verification with sample data

- [ ] **Step 1: Create script file with imports and constants**

Create `query_imds_with_context.py`:

```python
#!/usr/bin/env python3
"""
Query NGSIEM for IMDS traffic with URL and process context.
Produces enhanced detection data for cloud provider classification.
"""
import os
import sys
import json
import time
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Optional

# Add FalconPy to path
FALCONPY_PATH = Path(__file__).parent.parent.parent / "repos" / "falconpy" / "src"
sys.path.insert(0, str(FALCONPY_PATH))

from falconpy import APIHarness

# URL path patterns for cloud provider detection
URL_PATTERNS = {
    'AWS': ['/latest/', '/meta-data/', '/dynamic/'],
    'Azure': ['/metadata/instance', '/metadata/identity'],
    'GCP': ['/computeMetadata/v1/', '/computeMetadata/v1beta1/'],
    'Oracle': ['/opc/v1/', '/opc/v2/'],
    'DigitalOcean': ['/metadata/v1/'],
    'Linode': ['/v1/instance', '/v1/network'],
    'Vultr': ['/v1/'],
}

# Process name indicators
PROCESS_INDICATORS = {
    'AWS': ['cloud-init', 'ec2-metadata', 'ec2-', 'aws-'],
    'Azure': ['waagent', 'walinuxagent', 'azure-'],
    'GCP': ['gce-', 'google-', 'gcemetadata'],
    'Oracle': ['oci-', 'oracle-cloud-agent'],
}

# NGSIEM query for IMDS traffic with context
ENHANCED_IMDS_QUERY = """
#event_simpleName=NetworkConnectIP4
(RemoteAddressIP4="169.254.169.254" OR
 RemoteAddressIP4="100.100.100.200" OR
 RemoteAddressIP4="169.254.42.42")
| RemoteAddressIP4=RemoteIP
| ContextBaseFileName=ImageFileName
| groupBy([aid, RemoteIP, ContextBaseFileName], function=[
    count(as=connection_count),
    collect([TargetFileName])
  ])
| TargetFileName := format("%s", field=TargetFileName)
"""
```

- [ ] **Step 2: Add credential loading functions**

Add these functions after the constants:

```python
def get_keychain_value(service, account):
    """Get credential from macOS Keychain."""
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


def load_credentials():
    """Load Falcon API credentials from keychain."""
    profile = 'talon_1'

    client_id = get_keychain_value('falcon-client-id', profile)
    client_secret = get_keychain_value('falcon-client-secret', profile)
    region = get_keychain_value('falcon-cloud-region', profile) or 'us-1'

    if not client_id or not client_secret:
        print("❌ Falcon API credentials not found in keychain")
        print(f"Run: /cid use {profile}")
        sys.exit(1)

    return client_id, client_secret, region
```

- [ ] **Step 3: Add classification function**

Add this function:

```python
def classify_from_evidence(evidence: Dict) -> Dict:
    """
    Determine cloud provider from URL paths and process names.

    Returns: {'name': str, 'confidence': str}
    """
    url_paths = evidence.get('url_paths', [])
    processes = evidence.get('processes', [])
    imds_ip = evidence.get('imds_ip')

    # Non-standard IMDS IPs (definitive)
    if imds_ip == '100.100.100.200':
        return {'name': 'Alibaba', 'confidence': 'high'}
    elif imds_ip == '169.254.42.42':
        return {'name': 'Scaleway', 'confidence': 'high'}

    # URL path matching (high confidence)
    for path in url_paths:
        for provider, patterns in URL_PATTERNS.items():
            if any(pattern in path for pattern in patterns):
                return {'name': provider, 'confidence': 'high'}

    # Process name matching (medium confidence)
    for proc in processes:
        proc_lower = proc.lower()
        for provider, indicators in PROCESS_INDICATORS.items():
            if any(ind in proc_lower for ind in indicators):
                return {'name': provider, 'confidence': 'medium'}

    # Unknown
    return {'name': 'Others', 'confidence': 'low'}
```

- [ ] **Step 4: Test classification function manually**

Add this temporary test code at the bottom:

```python
if __name__ == '__main__':
    # Test classification logic
    test_cases = [
        {
            'evidence': {'imds_ip': '169.254.169.254', 'url_paths': ['/latest/meta-data/'], 'processes': []},
            'expected': 'AWS'
        },
        {
            'evidence': {'imds_ip': '169.254.169.254', 'url_paths': ['/metadata/instance'], 'processes': []},
            'expected': 'Azure'
        },
        {
            'evidence': {'imds_ip': '100.100.100.200', 'url_paths': [], 'processes': []},
            'expected': 'Alibaba'
        },
    ]

    print("Testing classification logic...")
    for i, test in enumerate(test_cases, 1):
        result = classify_from_evidence(test['evidence'])
        status = "✓" if result['name'] == test['expected'] else "✗"
        print(f"{status} Test {i}: {result['name']} (expected {test['expected']})")
```

Run:
```bash
cd /Users/ykwan/Documents/code/knowledgebase/projects/falcon-sensor-billing-tool
.venv/bin/python3 query_imds_with_context.py
```

Expected: All tests pass with ✓

- [ ] **Step 5: Remove test code and commit**

Remove the test code (if __name__ == '__main__' block) and commit:

```bash
git add query_imds_with_context.py
git commit -m "feat(detection): add core cloud classification logic

- URL pattern matching for AWS, Azure, GCP, Oracle, DigitalOcean, Linode, Vultr
- Process name matching for supporting evidence
- Non-standard IMDS endpoint detection (Alibaba, Scaleway)

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 3: Enhanced IMDS Detection - NGSIEM Query

**Files:**
- Modify: `query_imds_with_context.py:50-200`

- [ ] **Step 1: Add NGSIEM query function**

Add this function to `query_imds_with_context.py`:

```python
def query_ngsiem_with_context(days_back=7):
    """
    Query NGSIEM for IMDS traffic with URL and process context.

    Returns: List of raw NGSIEM events
    """
    # Load credentials
    client_id, client_secret, region = load_credentials()
    falcon = APIHarness(client_id=client_id, client_secret=client_secret, base_url=region)

    # Date range
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days_back)

    print("=" * 80)
    print("ENHANCED IMDS DETECTION WITH URL/PROCESS CONTEXT")
    print("=" * 80)
    print(f"Cloud: {region}")
    print(f"Date range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Query period: {days_back} days")
    print()

    print("🌐 Querying NGSIEM for IMDS traffic...")
    print("-" * 80)
    print("Query:")
    print(ENHANCED_IMDS_QUERY)
    print()

    # Create async search job
    response = falcon.command(
        "CreateSearchJob",
        mode="async",
        filter="",
        query_string=ENHANCED_IMDS_QUERY,
        start=start_time.isoformat() + "Z",
        end=end_time.isoformat() + "Z"
    )

    if response['status_code'] != 201:
        print(f"❌ Failed to create NGSIEM query job: {response}")
        sys.exit(1)

    job_id = response['body']['resources'][0]['job_id']
    print(f"✓ Job created: {job_id}")
    print()

    # Poll for completion
    print("==" * 40)
    print("MONITORING JOB")
    print("=" * 80)

    max_wait = 600  # 10 minutes
    start = time.time()

    while time.time() - start < max_wait:
        status_response = falcon.command(
            "GetSearchJobResults",
            job_id=job_id,
            limit=0,
            offset=0
        )

        if status_response['status_code'] == 200:
            meta = status_response['body'].get('meta', {})
            progress = meta.get('powered_by', {}).get('query_completion_percentage', 0)

            if progress >= 100:
                result_count = meta.get('result_count', 0)
                print(f"✓ Query complete: {result_count} results")
                break
            else:
                print(f"⏳ Progress: {progress}%")
        else:
            print(f"❌ Error checking status: {status_response}")
            sys.exit(1)

        time.sleep(10)
    else:
        print("❌ Query timed out after 10 minutes")
        sys.exit(1)

    print()
    print("=" * 80)

    # Fetch results
    print("📥 Fetching IMDS traffic results...")

    all_results = []
    offset = 0
    limit = 1000

    while True:
        result_response = falcon.command(
            "GetSearchJobResults",
            job_id=job_id,
            limit=limit,
            offset=offset
        )

        if result_response['status_code'] != 200:
            print(f"   ❌ Error fetching results at offset {offset}")
            break

        body = result_response['body']
        events = body.get('resources', {}).get('events', [])

        if not events:
            break

        all_results.extend(events)
        offset += len(events)
        print(f"   Fetched {len(all_results)} results...")

        # Check if we got all results
        total_count = body.get('meta', {}).get('result_count', 0)
        if offset >= total_count:
            break

    print(f"   ✓ Total: {len(all_results)} IMDS connection patterns")
    print()

    return all_results
```

- [ ] **Step 2: Commit NGSIEM query function**

```bash
git add query_imds_with_context.py
git commit -m "feat(detection): add NGSIEM query for IMDS traffic

Query NetworkConnectIP4 events with URL path and process context.
Includes async job polling and paginated result fetching.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 4: Enhanced IMDS Detection - Result Transformation

**Files:**
- Modify: `query_imds_with_context.py:200-350`

- [ ] **Step 1: Add result transformation function**

Add this function to `query_imds_with_context.py`:

```python
def transform_to_detections(raw_results: List[Dict]) -> Dict:
    """
    Transform NGSIEM results into detection format.

    Groups by AID and aggregates evidence.

    Returns: Dict[aid] -> detection info
    """
    detections = {}

    for event in raw_results:
        try:
            aid = event.get('aid')
            remote_ip = event.get('RemoteIP')
            process = event.get('ContextBaseFileName', '')
            url_paths_raw = event.get('TargetFileName', '')
            count = event.get('connection_count', 1)

            if not aid:
                continue

            # Parse URL paths (may be array string or single path)
            url_paths = []
            if url_paths_raw:
                # Handle both "['path1', 'path2']" and "path1" formats
                if url_paths_raw.startswith('['):
                    try:
                        # Replace single quotes with double quotes for JSON parsing
                        url_paths = json.loads(url_paths_raw.replace("'", '"'))
                    except json.JSONDecodeError:
                        url_paths = [url_paths_raw]
                else:
                    url_paths = [url_paths_raw]

            # Initialize or update detection for this AID
            if aid not in detections:
                detections[aid] = {
                    'imds_ip': remote_ip,
                    'url_paths': [],
                    'processes': [],
                    'sample_count': 0
                }

            # Aggregate evidence
            detection = detections[aid]
            detection['sample_count'] += count

            for path in url_paths:
                if path and path not in detection['url_paths']:
                    detection['url_paths'].append(path)

            if process and process not in detection['processes']:
                detection['processes'].append(process)

        except Exception as e:
            print(f"   ⚠️  Failed to process event: {e}")
            continue

    # Classify each detection
    classified = {}
    for aid, evidence in detections.items():
        classification = classify_from_evidence(evidence)
        classified[aid] = {
            'provider': classification['name'],
            'confidence': classification['confidence'],
            'evidence': evidence
        }

    return classified
```

- [ ] **Step 2: Add main function**

Add this main function:

```python
def main():
    """Main entry point."""
    print("=" * 80)
    print("ENHANCED IMDS DETECTION WITH URL/PROCESS CONTEXT")
    print("=" * 80)
    print()

    # Query NGSIEM
    raw_results = query_ngsiem_with_context(days_back=7)

    # Transform to detections
    print("=" * 80)
    print("ANALYZING DETECTION PATTERNS")
    print("=" * 80)
    detections = transform_to_detections(raw_results)

    # Statistics
    provider_counts = {}
    confidence_counts = {'high': 0, 'medium': 0, 'low': 0}

    for detection in detections.values():
        provider = detection['provider']
        confidence = detection['confidence']

        provider_counts[provider] = provider_counts.get(provider, 0) + 1
        confidence_counts[confidence] += 1

    print(f"✓ Classified {len(detections)} hosts")
    print()

    print("By provider:")
    for provider, count in sorted(provider_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {provider:20s}: {count:4d}")
    print()

    print("By confidence:")
    for level, count in confidence_counts.items():
        print(f"  {level:10s}: {count:4d}")
    print()

    # Save results
    output = {
        'metadata': {
            'query_start': (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),
            'query_end': datetime.now(timezone.utc).isoformat(),
            'total_hosts': len(detections)
        },
        'detections': detections
    }

    output_file = 'imds_enhanced.json'
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"✓ Saved enhanced detection data to: {output_file}")
    print()
    print("=" * 80)
    print("NEXT STEPS")
    print("=" * 80)
    print("  1. python billing_collector.py --days 7")
    print("  2. python refine_cloud_classification.py")
    print("=" * 80)


if __name__ == '__main__':
    main()
```

- [ ] **Step 3: Make script executable**

```bash
chmod +x query_imds_with_context.py
```

- [ ] **Step 4: Commit transformation logic**

```bash
git add query_imds_with_context.py
git commit -m "feat(detection): add result transformation and main function

- Transform NGSIEM events into detection evidence by AID
- Aggregate URL paths and processes per host
- Generate statistics and save to imds_enhanced.json

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 5: Billing Collector - Gap Detection

**Files:**
- Modify: `billing_collector.py:1-100`
- Test: Manual verification

- [ ] **Step 1: Add import for argparse**

At the top of `billing_collector.py`, add argparse to the imports:

```python
import argparse  # Add this line
from datetime import datetime, timedelta, timezone
```

- [ ] **Step 2: Add gap detection function**

Add this function after the credential loading functions (around line 80):

```python
def get_hours_to_collect(days_back: int, db) -> List[datetime]:
    """
    Determine which hours need collection.

    Rules:
    - Always skip current incomplete hour
    - End at previous complete hour
    - Check database for existing hours
    - Return only missing hours

    Args:
        days_back: Number of days to look back
        db: BillingDatabase instance

    Returns:
        List of datetime objects for missing hours
    """
    now = datetime.now(timezone.utc)
    current_hour = now.replace(minute=0, second=0, microsecond=0)

    # Skip current hour (incomplete), end at previous complete hour
    end_hour = current_hour - timedelta(hours=1)
    start_hour = end_hour - timedelta(days=days_back) + timedelta(hours=1)

    logger.info(f"Date range: {start_hour} to {end_hour}")

    # Query existing hours from database
    cursor = db.conn.execute("""
        SELECT DISTINCT hour_timestamp
        FROM sensor_logs
        WHERE hour_timestamp >= ? AND hour_timestamp <= ?
    """, (start_hour.isoformat(), end_hour.isoformat()))

    existing = {row[0] for row in cursor.fetchall()}

    # Generate all hours in range
    all_hours = []
    hour = start_hour
    while hour <= end_hour:
        all_hours.append(hour)
        hour += timedelta(hours=1)

    # Filter to missing hours only
    missing_hours = [h for h in all_hours if h.isoformat() not in existing]

    logger.info(f"Total hours in range: {len(all_hours)}")
    logger.info(f"Already collected: {len(existing)}")
    logger.info(f"Missing hours to collect: {len(missing_hours)}")

    return missing_hours
```

- [ ] **Step 3: Update main function to support --days parameter**

Find the `main()` function and replace it with:

```python
def main():
    """Main entry point."""
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Falcon Sensor Billing - Hourly Collection'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=0,
        help='Collect last N days of data (0=current hour only, default)'
    )
    args = parser.parse_args()

    # Load credentials from keychain
    if not load_credentials_from_keychain():
        logger.error("Failed to load credentials from keychain")
        print("❌ Falcon API credentials not found in keychain")
        print("Run: /cid use talon_1")
        sys.exit(1)

    # Initialize database and API clients
    logger.info("Initializing database and API clients...")
    db = BillingDatabase()

    print("=" * 70)
    print("Falcon Sensor Billing - Collection Module")
    print("=" * 70)
    print("✓ Database initialized at", db.db_path)
    print("✓ Falcon API client initialized")
    print()

    # Get CID
    cid = get_cid()
    if not cid:
        logger.error("Failed to retrieve CID")
        print("❌ Could not retrieve CID from Falcon API")
        sys.exit(1)

    logger.info(f"Retrieved CID from Falcon API: {cid[:16]}...{cid[-2:]}")

    # Determine hours to collect
    if args.days == 0:
        # Single hour mode (current behavior)
        now = datetime.now(timezone.utc)
        target_hour = now.replace(minute=0, second=0, microsecond=0)
        hours_to_collect = [target_hour]

        print(f"Testing collection for hour: {target_hour}")
        print(f"Using CID: {cid[:16]}...{cid[-2:]}")
        print()
    else:
        # Multi-day backfill mode
        print(f"Backfill mode: Last {args.days} days")
        hours_to_collect = get_hours_to_collect(args.days, db)
        print()

        if not hours_to_collect:
            print("✓ No missing hours found - database is up to date")
            return

    # Collect each hour
    for i, hour_start in enumerate(hours_to_collect, 1):
        if len(hours_to_collect) > 1:
            print(f"[{i}/{len(hours_to_collect)}] Collecting hour: {hour_start}")

        try:
            hour_end = hour_start + timedelta(hours=1)

            # Query NGSIEM for unique sensors
            logger.info(f"Processing collection for hour: {hour_start} (CID: {cid})")
            unique_sensors = query_ngsiem_for_sensors(hour_start, hour_end, cid)

            if not unique_sensors:
                logger.warning(f"No sensors found for hour {hour_start}")
                print(f"  ⚠️  No sensors found for this hour")
                continue

            logger.info(f"Found {len(unique_sensors)} unique sensors for hour {hour_start}")

            # Enrich with host details
            host_details_list = enrich_with_host_details(unique_sensors, db)

            # Store in database
            db.insert_sensor_logs(hour_start, host_details_list, cid)
            logger.info(f"Inserted {len(host_details_list)} sensor logs")

            # Store hourly count
            db.insert_hourly_count(hour_start, len(unique_sensors), cid)
            logger.info(f"Stored hourly count: {len(unique_sensors)} sensors")

            # Aggregate tag counts
            db.aggregate_tag_counts(hour_start, host_details_list, cid)
            logger.info(f"Aggregated tag counts for hour {hour_start}")

            if len(hours_to_collect) > 1:
                print(f"  ✓ Collected {len(unique_sensors)} sensors")

        except Exception as e:
            logger.error(f"Failed to collect hour {hour_start}: {e}")
            print(f"  ❌ Collection failed: {e}")
            continue

    # Final summary
    print()
    if args.days == 0:
        # Single hour summary (existing behavior)
        cache_stats = db.get_cache_stats()
        print("✓ Collection complete:")
        print(f"  Total sensors: {len(unique_sensors)}")
        print(f"  Cache hits: {cache_stats['hits']}")
        print(f"  API calls: {cache_stats['misses']}")
    else:
        # Multi-day summary
        print(f"✓ Backfill complete: {len(hours_to_collect)} hours collected")

    print()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Test gap detection with --help**

Run:
```bash
cd /Users/ykwan/Documents/code/knowledgebase/projects/falcon-sensor-billing-tool
.venv/bin/python3 billing_collector.py --help
```

Expected: Shows usage with --days parameter

- [ ] **Step 5: Commit gap detection feature**

```bash
git add billing_collector.py
git commit -m "feat(collector): add --days parameter and gap detection

- Support historical backfill with --days N parameter
- Check database for existing hours, collect only missing
- Skip current incomplete hour
- Prevents duplicate collection

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 6: Cloud Classification - Enhanced Detection Integration

**Files:**
- Modify: `refine_cloud_classification.py:1-200`

- [ ] **Step 1: Update classification function with URL/process logic**

Replace the `refine_classification` function in `refine_cloud_classification.py` with:

```python
def classify_with_url_and_process(aid, current_provider, enhanced_detection, hardware_indicator):
    """
    Classify cloud provider using enhanced IMDS detection data.

    Priority:
    1. Non-standard IMDS IPs (Alibaba, Scaleway, etc.) → high confidence
    2. URL path patterns → high confidence
    3. Process names → medium confidence
    4. Hardware indicators → low confidence
    5. Standard IMDS without context → "Others"

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
            if any(p in proc_lower for p in ['cloud-init', 'ec2-', 'aws-']):
                return 'AWS', 'medium', f'AWS process: {proc}'
            elif any(p in proc_lower for p in ['waagent', 'walinux', 'azure-']):
                return 'Azure', 'medium', f'Azure process: {proc}'
            elif any(p in proc_lower for p in ['gce-', 'google-', 'gcemetadata']):
                return 'GCP', 'medium', f'GCP process: {proc}'
            elif any(p in proc_lower for p in ['oci-', 'oracle-cloud']):
                return 'Oracle', 'medium', f'Oracle process: {proc}'

        # Standard IMDS but no clear indicators
        return 'Others', 'low', 'Standard IMDS, provider unclear'

    return current_provider, 'low', 'No classification possible'
```

- [ ] **Step 2: Update main function to load enhanced detection data**

Find the `main()` function in `refine_cloud_classification.py` and update the IMDS loading section:

```python
def main():
    print("Enhanced Cloud Provider Classification")
    print("=" * 70)
    print()

    # Load enhanced IMDS data
    imds_file = Path(__file__).parent / "imds_enhanced.json"

    if not imds_file.exists():
        print("⚠️  No enhanced IMDS data found")
        print("   Classification will use existing methods only")
        print("   Run: python3 query_imds_with_context.py")
        print()
        detections = {}
    else:
        with open(imds_file) as f:
            imds_data = json.load(f)

        detections = imds_data.get('detections', {})
        print(f"✓ Loaded enhanced detection data for {len(detections)} hosts")
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
        print(f"✓ Loaded {len(hardware_map)} hardware indicators")
    else:
        print("ℹ️  No hardware indicators file found (optional)")

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
                print(f"  {aid[:16]}... {current:15s} → {new_provider:15s} ({confidence}, {reason})")

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
    print("✓ Enhanced classification complete")
    print()


if __name__ == '__main__':
    main()
```

- [ ] **Step 3: Add import for datetime at the top**

Add to the imports:

```python
from datetime import datetime  # Add this line
```

- [ ] **Step 4: Commit enhanced classification**

```bash
git add refine_cloud_classification.py
git commit -m "feat(classification): integrate enhanced detection with URL/process

- Use URL path patterns for high-confidence classification
- Support process name matching for medium confidence
- Store detection metadata in database
- Update sensor_logs table with refined classifications

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 7: Testing and Validation

**Files:**
- Manual testing with actual data

- [ ] **Step 1: Test enhanced IMDS detection**

Run:
```bash
cd /Users/ykwan/Documents/code/knowledgebase/projects/falcon-sensor-billing-tool
.venv/bin/python3 query_imds_with_context.py
```

Expected:
- Job created message
- Progress updates
- Query completion
- Classification by provider
- File saved: imds_enhanced.json

- [ ] **Step 2: Verify imds_enhanced.json format**

Run:
```bash
cat imds_enhanced.json | head -50
```

Expected: JSON with metadata and detections structure

- [ ] **Step 3: Test billing collector with --days parameter**

Run:
```bash
.venv/bin/python3 billing_collector.py --days 7
```

Expected:
- Gap detection output
- Missing hours count
- Collection progress for each hour
- No duplicate errors

- [ ] **Step 4: Test cloud classification refinement**

Run:
```bash
.venv/bin/python3 refine_cloud_classification.py
```

Expected:
- Loaded enhanced detection data
- Classification updates with reasons
- Statistics by confidence
- Statistics by provider

- [ ] **Step 5: Verify database updates**

Run:
```bash
sqlite3 sensor_billing.db "SELECT cloud_provider, COUNT(*) FROM host_metadata_cache GROUP BY cloud_provider"
```

Expected: Distribution showing AWS, Azure, GCP, Others, etc.

- [ ] **Step 6: Check detection metadata**

Run:
```bash
sqlite3 sensor_billing.db "SELECT sensor_id, detection_metadata FROM host_metadata_cache WHERE detection_metadata IS NOT NULL LIMIT 1" | python3 -m json.tool
```

Expected: JSON with provider, confidence, evidence fields

- [ ] **Step 7: Final commit**

```bash
git add -A
git commit -m "test: validate enhanced cloud detection and historical backfill

- Verified NGSIEM query execution
- Confirmed gap detection prevents duplicates
- Validated classification updates with evidence storage
- All components working end-to-end

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 8: Documentation

**Files:**
- Create: `docs/enhanced-cloud-detection-usage.md`

- [ ] **Step 1: Create usage documentation**

Create `docs/enhanced-cloud-detection-usage.md`:

```markdown
# Enhanced Cloud Detection & Historical Backfill Usage Guide

## Overview

Enhanced cloud provider detection uses HTTP URL paths and process context from NGSIEM to accurately classify cloud providers that share the standard IMDS endpoint (169.254.169.254).

## Workflow

### Step 1: Query NGSIEM for Enhanced Detection

Run once per analysis period to gather detection evidence:

```bash
python3 query_imds_with_context.py
```

**Output:**
- `imds_enhanced.json` with classification evidence for all hosts
- Statistics by provider and confidence level

**Query Period:** Last 7 days of IMDS traffic

### Step 2: Backfill Historical Sensor Data

Collect sensor data for multiple days with automatic gap detection:

```bash
# Collect last 7 days (only missing hours)
python3 billing_collector.py --days 7

# Collect last 24 hours
python3 billing_collector.py --days 1

# Collect current hour only (default)
python3 billing_collector.py
```

**Gap Detection:**
- Queries database for existing hours
- Collects only missing hours
- Skips current incomplete hour
- Prevents duplicates automatically

### Step 3: Apply Enhanced Cloud Classification

Update cloud provider classifications using detection evidence:

```bash
python3 refine_cloud_classification.py
```

**Behavior:**
- Loads `imds_enhanced.json`
- Updates host_metadata_cache with new classifications
- Stores detection metadata (evidence) in database
- Updates sensor_logs table

## Detection Accuracy

**High Confidence (Specific Provider):**
- Non-standard IMDS endpoints (Alibaba, Scaleway)
- URL path patterns match (AWS, Azure, GCP, Oracle, etc.)

**Medium Confidence (Process-based):**
- Process names indicate provider (cloud-init, waagent, gce-)

**Low Confidence (Generic):**
- Standard IMDS traffic without clear indicators → classified as "Others"

## Refreshing Incomplete Data

If you suspect an hour was collected while incomplete, manually delete and re-collect:

```bash
# Delete incomplete hour
sqlite3 sensor_billing.db "DELETE FROM sensor_logs WHERE hour_timestamp='2026-04-20T13:00:00+00:00'"
sqlite3 sensor_billing.db "DELETE FROM hourly_counts WHERE hour_timestamp='2026-04-20T13:00:00+00:00'"

# Re-collect
python3 billing_collector.py --days 1
```

## Troubleshooting

**"No IMDS data to process"**
- Run `python3 query_imds_with_context.py` first
- Check that `imds_enhanced.json` exists

**"No missing hours found"**
- Database already has complete data for requested range
- Use different --days value or manually delete hours

**NGSIEM query timeout**
- Reduce query period (query is for last 7 days by default)
- Check Falcon API connectivity

## Database Schema

**detection_metadata column format:**

```json
{
  "provider": "AWS",
  "confidence": "high",
  "evidence": {
    "imds_ip": "169.254.169.254",
    "url_paths": ["/latest/meta-data/"],
    "processes": ["cloud-init"],
    "sample_count": 1247
  },
  "detected_at": "2026-04-20T14:30:00Z"
}
```

Query detection metadata:

```sql
SELECT
    sensor_id,
    hostname,
    cloud_provider,
    json_extract(detection_metadata, '$.confidence') as confidence
FROM host_metadata_cache
WHERE detection_metadata IS NOT NULL;
```
```

- [ ] **Step 2: Commit documentation**

```bash
git add docs/enhanced-cloud-detection-usage.md
git commit -m "docs: add usage guide for enhanced cloud detection

Complete workflow documentation with examples, troubleshooting,
and database schema reference.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Self-Review Checklist

**Spec Coverage:**
- ✅ Enhanced IMDS detection script (Task 2-4)
- ✅ URL path and process classification (Task 2)
- ✅ NGSIEM query execution (Task 3)
- ✅ Result transformation (Task 4)
- ✅ Billing collector --days parameter (Task 5)
- ✅ Gap detection logic (Task 5)
- ✅ Skip current hour (Task 5)
- ✅ Cloud classification refinement (Task 6)
- ✅ Detection metadata storage (Task 1, 6)
- ✅ Database schema migration (Task 1)
- ✅ Testing and validation (Task 7)
- ✅ Documentation (Task 8)

**Placeholder Check:**
- ✅ No TBD or TODO items
- ✅ All code blocks complete
- ✅ All commands with expected output
- ✅ No "similar to Task N" references

**Type Consistency:**
- ✅ Function names consistent across tasks
- ✅ Variable names consistent (enhanced_detection, imds_enhanced.json)
- ✅ Database column names consistent (detection_metadata)

**Implementation Ready:**
- ✅ All file paths specified
- ✅ All functions have complete implementations
- ✅ Test commands provided
- ✅ Commit messages included
