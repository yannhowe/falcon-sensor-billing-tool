# Enhanced Cloud Provider Detection & Historical Data Collection

**Date:** 2026-04-20
**Author:** Claude Opus 4.6
**Status:** Approved

## Overview

Enhance the Falcon sensor billing collector to:
1. Accurately detect cloud providers using HTTP URL paths and process context from NGSIEM
2. Support 7-day historical data collection with gap detection
3. Store detection evidence for audit and debugging

## Goals

- Expand cloud provider detection beyond IP-based IMDS endpoints
- Differentiate providers that share the standard 169.254.169.254 endpoint (AWS, Azure, GCP, Oracle, etc.)
- Enable backfill of historical sensor data without duplicates
- Maintain high classification confidence (high-confidence only, otherwise "Others")

## Non-Goals

- Real-time streaming collection (batch hourly collection only)
- Detection of self-hosted cloud platforms (OpenStack, CloudStack)
- Container runtime detection (future enhancement)

## Architecture

### Component 1: Enhanced IMDS Detection Script

**File:** `query_imds_with_context.py`

**Purpose:** Query NGSIEM for IMDS traffic patterns and classify cloud providers using URL paths and process names.

**Inputs:**
- NGSIEM NetworkConnectIP4 events (last 7 days)
- Falcon API credentials from macOS Keychain

**Outputs:**
- `imds_enhanced.json` with detection evidence per host

**Key Functions:**
- `query_ngsiem_with_context(days_back=7)` - Execute NGSIEM query for IMDS traffic
- `transform_to_detections(raw_results)` - Parse results and aggregate evidence by AID
- `classify_from_evidence(evidence)` - Determine provider from URL/process patterns

### Component 2: Billing Collector Enhancements

**File:** `billing_collector.py`

**Changes:**
1. Add `--days N` parameter for historical backfill
2. Implement gap detection: query existing hours, collect only missing
3. Skip current incomplete hour (always end at previous complete hour)
4. Load enhanced IMDS data for cloud provider enrichment

**Key Functions:**
- `get_hours_to_collect(days_back, db)` - Identify missing hours in date range
- `main()` - Enhanced to support both single-hour and multi-day collection

### Component 3: Cloud Classification Refinement

**File:** `refine_cloud_classification.py`

**Changes:**
1. Load `imds_enhanced.json` instead of basic IMDS traffic
2. Use URL path and process context for classification
3. Store detection metadata in host_metadata_cache
4. Update sensor_logs table with refined classifications

**Key Functions:**
- `classify_with_url_and_process()` - Enhanced classification using detection evidence
- `migrate_schema()` - Add detection_metadata column to host_metadata_cache

## Data Model

### Enhanced IMDS Detection Data

**Format:** `imds_enhanced.json`

```json
{
  "metadata": {
    "query_start": "2026-04-13T00:00:00Z",
    "query_end": "2026-04-20T14:30:00Z",
    "total_hosts": 251
  },
  "detections": {
    "aid-12345...": {
      "provider": "AWS",
      "confidence": "high",
      "evidence": {
        "imds_ip": "169.254.169.254",
        "url_paths": ["/latest/meta-data/", "/latest/dynamic/"],
        "processes": ["cloud-init", "ec2-metadata"],
        "sample_count": 1247
      }
    }
  }
}
```

### Database Schema Changes

**Table:** `host_metadata_cache`

**New Column:**
```sql
ALTER TABLE host_metadata_cache
ADD COLUMN detection_metadata TEXT;  -- JSON string
```

**Example data:**
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

## Detection Logic

### URL Path Patterns (High Confidence)

| Provider | URL Patterns |
|----------|--------------|
| AWS | `/latest/`, `/meta-data/`, `/dynamic/` |
| Azure | `/metadata/instance`, `/metadata/identity` |
| GCP | `/computeMetadata/v1/`, `/computeMetadata/v1beta1/` |
| Oracle | `/opc/v1/`, `/opc/v2/` |
| DigitalOcean | `/metadata/v1/` |
| Linode | `/v1/instance`, `/v1/network` |
| Vultr | `/v1/` |

### Process Context (Medium Confidence)

| Provider | Process Names |
|----------|---------------|
| AWS | `cloud-init`, `ec2-metadata`, `aws-*` |
| Azure | `waagent`, `walinuxagent`, `azure-*` |
| GCP | `gce-*`, `google-*`, `gcemetadata` |
| Oracle | `oci-*`, `oracle-cloud-agent` |

### Non-Standard IMDS Endpoints (High Confidence)

| Provider | IMDS IP |
|----------|---------|
| Alibaba | 100.100.100.200 |
| Scaleway | 169.254.42.42 |
| Tencent | metadata.tencentyun.com |
| IBM | api.metadata.cloud.ibm.com |

### Classification Algorithm

**Priority Order:**
1. Non-standard IMDS IPs → High confidence, definitive
2. URL path patterns → High confidence
3. Process names → Medium confidence (supporting evidence)
4. Hardware indicators → Low confidence (fallback)
5. Standard IMDS without context → "Others"

**Confidence Levels:**
- **High:** URL pattern match or non-standard IMDS endpoint
- **Medium:** Process name match only
- **Low:** Generic IMDS traffic without clear indicators

**Classification Rule:**
- Only classify as specific provider (AWS/Azure/GCP/Oracle) if confidence is "high"
- Everything else → "Others"

## Historical Data Collection

### Gap Detection Strategy

**Behavior:**
1. User runs: `python billing_collector.py --days 7`
2. System calculates date range: `[now - 7 days, now - 1 hour]`
3. Query database for existing hours in range
4. Identify missing hours
5. Collect only missing hours

**Current Hour Exclusion:**
- Always skip current hour (incomplete by definition)
- End collection at previous complete hour

**Example:**
```
Current time: 2026-04-20 14:30:00
Date range: 2026-04-13 15:00:00 to 2026-04-20 13:00:00
Total hours: 168
Already collected: 145
Missing hours: 23
→ Collect only 23 missing hours
```

### Duplicate Prevention

**Method:** Check-then-insert

**Implementation:**
```python
def get_hours_to_collect(days_back, db):
    # Calculate date range (excluding current hour)
    now = datetime.now(timezone.utc)
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    end_hour = current_hour - timedelta(hours=1)
    start_hour = end_hour - timedelta(days=days_back) + timedelta(hours=1)

    # Query existing hours
    existing = db.query(
        "SELECT DISTINCT hour_timestamp FROM sensor_logs WHERE hour_timestamp >= ?",
        (start_hour.isoformat(),)
    )
    existing_set = {row[0] for row in existing}

    # Generate missing hours only
    all_hours = generate_hour_range(start_hour, end_hour)
    missing = [h for h in all_hours if h.isoformat() not in existing_set]

    return missing
```

**Refreshing Incomplete Data:**
If user suspects an hour was collected incomplete, they can manually delete and re-run:

```bash
sqlite3 sensor_billing.db "DELETE FROM sensor_logs WHERE hour_timestamp='2026-04-20T13:00:00+00:00'"
sqlite3 sensor_billing.db "DELETE FROM hourly_counts WHERE hour_timestamp='2026-04-20T13:00:00+00:00'"
python billing_collector.py --days 1
```

## NGSIEM Query

### Query Structure

```python
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

**Fields Extracted:**
- `aid` - Unique sensor identifier
- `RemoteIP` - IMDS endpoint IP
- `ImageFileName` - Process making IMDS request
- `TargetFileName` - URL path (array of paths)
- `connection_count` - Number of connections

**Query Period:** Last 7 days (configurable)

**Expected Volume:** ~5,000-10,000 events for 250 hosts over 7 days

## Workflow

### Complete End-to-End Process

```bash
# Step 1: Query NGSIEM for enhanced IMDS detection
python query_imds_with_context.py

# Output:
# ✓ Job created: P151-xyz...
# ✓ Query complete: 4,523 results
# ✓ Classified 251 hosts
# By provider:
#   AWS    : 127
#   Azure  :  68
#   GCP    :  31
#   Others :  25
# ✓ Saved: imds_enhanced.json

# Step 2: Backfill historical sensor data
python billing_collector.py --days 7

# Output:
# Backfill mode: Last 7 days
# Total hours in range: 168
# Already collected: 145
# Missing hours: 23
# [1/23] Collecting hour: 2026-04-13 15:00:00+00:00
#   Found 248 unique sensors
#   ✓ Inserted 248 sensor logs
# ...
# ✓ Collection complete: 23 hours

# Step 3: Apply enhanced cloud classification
python refine_cloud_classification.py

# Output:
# Enhanced Cloud Provider Classification
# ✓ Loaded enhanced detection data for 251 hosts
# Analyzing 251 hosts...
#   aid-12345... Unknown    → AWS    (high, AWS URL pattern)
#   aid-67890... On-Premise → Azure  (high, Azure URL pattern)
# Classifications updated: 142
# By confidence:
#   High:   127
#   Medium:  15
# ✓ Enhanced classification complete
```

## Error Handling

### NGSIEM Query Timeout
- Max wait: 10 minutes
- On timeout: Log error, suggest reducing date range
- Non-fatal: Can retry with smaller date range

### Missing IMDS Data
- If `imds_enhanced.json` doesn't exist, warn but continue
- Fall back to existing classification methods
- Non-fatal: System still functional

### Incomplete Hour Collection
- If NGSIEM query returns no sensors for an hour, log warning and continue
- Don't crash entire backfill on single hour failure
- Each hour is independent

### Database Lock (SQLite)
- Implement retry logic for locked database (3 retries, 1s delay)
- Only relevant if multiple processes access database simultaneously
- Rare in single-user scenario

### Malformed NGSIEM Results
- Parse URL paths safely with try/catch
- Skip malformed events, log warning
- Continue processing remaining events

## Testing Strategy

### Manual Validation

1. Query known AWS host from database
2. Check `detection_metadata` field contains correct evidence
3. Verify `cloud_provider` field updated to "AWS"
4. Confirm `sensor_logs` table also updated

### Gap Detection Test

1. Manually delete specific hours from database
2. Run `billing_collector.py --days 7`
3. Verify only missing hours are collected
4. Confirm no duplicates created

### Classification Accuracy Test

1. Select sample of 10 hosts per provider
2. Manually verify cloud provider via:
   - Hostname patterns
   - Tags
   - Instance metadata
3. Compare with automated classification
4. Calculate accuracy rate

## Success Metrics

- **Detection Coverage:** >90% of cloud hosts correctly classified
- **False Positive Rate:** <5% hosts misclassified
- **Backfill Efficiency:** Only missing hours collected (no duplicate work)
- **Query Performance:** NGSIEM query completes within 5 minutes for 7 days

## Future Enhancements

1. **Real-time classification:** Classify as data is collected
2. **Container runtime detection:** Identify ECS, EKS, AKS, GKE
3. **Self-hosted cloud support:** OpenStack, CloudStack detection
4. **Automatic re-classification:** Periodic refresh of low-confidence hosts
5. **Dashboard integration:** Visualize cloud provider distribution over time

## Implementation Notes

- All credential loading via macOS Keychain (no environment variables)
- JSON format for detection metadata (SQLite TEXT column)
- Check-then-insert pattern prevents duplicates
- Two-phase approach: detection separate from collection
- High confidence threshold for classification

## References

- Existing: `query_imds_traffic.py`
- Existing: `refine_cloud_classification.py`
- Existing: `billing_collector.py`
- Existing: `billing_database.py`
