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
- Standard IMDS traffic without clear indicators -> classified as "Others"

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

**"No enhanced IMDS data found"**
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
