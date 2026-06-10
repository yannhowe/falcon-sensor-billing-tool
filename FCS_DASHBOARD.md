# FCS Licensing Dashboard - Quick Start

Clean, focused dashboard for Falcon Cloud Security license calculation based on 28-day rolling averages.

## What It Shows

### 1. **Overall Summary**
- Total 28-day average sensors (licenses required)
- Peak hourly usage
- Hours of data collected (target: 672 hours = 28 days)

### 2. **Licensing by CID**
- 28-day average per Customer ID
- Max and min hourly usage per CID
- **Licenses Required** = rounded 28-day average

### 3. **Licensing by Tag** (Sub-CID Cost Allocation)
- 28-day average per sensor tag
- Use for department/team/environment billing
- **Licenses Required** = rounded 28-day average per tag

## How to Use

### Start the Dashboard

```bash
cd /Users/ykwan/Documents/code/knowledgebase/projects/falcon-sensor-billing-tool
python3 fcs_licensing_dashboard.py
```

Dashboard available at: **http://localhost:5001**

### Export License Calculations

Click export buttons in the UI or use API:

```bash
# Export per-CID licensing
curl "http://localhost:5001/api/fcs/export?type=cid" -o fcs_by_cid.csv

# Export per-tag licensing
curl "http://localhost:5001/api/fcs/export?type=tag" -o fcs_by_tag.csv
```

## Understanding the Numbers

### 28-Day Rolling Average Formula

```
28-Day Avg = Sum of 672 hourly sensor counts ÷ 672
```

- **672 hours** = 28 days × 24 hours/day
- **Clock-hour**: Each hour from :00:00 to :59:59 UTC
- **Sensor count**: Any sensor active during clock-hour = 1
- **Your licenses needed**: The 28-day average (rounded up)

### Example Calculation

```
Hour 1:  250 sensors
Hour 2:  245 sensors
Hour 3:  240 sensors
...
Hour 672: 260 sensors

28-Day Avg = (250 + 245 + 240 + ... + 260) ÷ 672 = 252.3
Licenses Required = 252 (rounded down) or 253 (rounded up for safety)
```

## FCS License Types

| License | Workload | When to Use |
|---------|----------|-------------|
| **FCS Runtime (CDR)** | Cloud VMs, servers | Runtime protection only |
| **FCS CNAPP** | Cloud VMs | Runtime + CSPM/ASPM/DSPM |
| **FCSC Runtime** | Container hosts | K8s/Docker hosts, runtime only |
| **FCSC CNAPP** | Container hosts | Container hosts + posture |
| **FMC Runtime** | Managed containers | Fargate, Lambda, serverless |

**Rule:** If you need ANY posture capability (CSPM/ASPM/DSPM/CIEM/IaC), use CNAPP.

## Tag-Based Cost Allocation

Use sensor tags to allocate licenses across:

- **Departments**: Finance (50 avg), Engineering (150 avg)
- **Environments**: Production (200 avg), Dev (50 avg), Test (30 avg)
- **Teams**: TeamA (80 avg), TeamB (60 avg)
- **Projects**: ProjectX (100 avg), ProjectY (75 avg)

**Example Tag Breakdown:**
```csv
Tag,28-Day Avg,Licenses Required
production,200.5,201
development,50.2,50
test,30.8,31
```

This allows you to:
- Bill departments accurately
- Track license usage by environment
- Justify license costs to stakeholders

## CSV Export Format

### By CID Export
```csv
CID,Hours Collected,28-Day Avg Sensors,Max Hourly,Min Hourly,Licenses Required
abc123...,672,238.40,258,210,238
```

### By Tag Export
```csv
Tag,Hours Active,28-Day Avg Sensors,Max Hourly,Licenses Required
production,672,200.50,220,201
dev,560,50.20,75,50
```

## API Endpoints

### Get Summary
```bash
GET http://localhost:5001/api/fcs/summary
```

Returns:
```json
{
  "overall_avg_sensors": 238.4,
  "overall_max_sensors": 258,
  "hours_in_window": 169,
  "target_hours": 672,
  "cids": [
    {
      "cid": "default",
      "avg_sensors": 238.4,
      "max_sensors": 258,
      "licenses_required": 238
    }
  ],
  "tags": [
    {
      "tag": "production",
      "avg_sensors": 200.5,
      "max_sensors": 220,
      "licenses_required": 201
    }
  ]
}
```

## Important Notes

### Rounding for Licenses

- Dashboard rounds **down** by default: 238.4 → 238 licenses
- For safety, consider rounding **up**: 238.4 → 239 licenses
- Check your contract terms for rounding rules

### Minimum Data Requirement

- **Target**: 672 hours (28 full days)
- **Minimum for accuracy**: 168 hours (7 days)
- Dashboard shows "X / 672" to indicate data completeness

### Multi-CID Environments

If you have multiple CIDs:
- Each CID is licensed separately
- Total licenses = sum of all CID averages
- Use tag breakdown for sub-CID allocation

## Files

- **fcs_licensing_dashboard.py** - Flask backend
- **templates_fcs/fcs_dashboard.html** - Dashboard UI
- **static_fcs/fcs_style.css** - Styling
- **static_fcs/fcs_app.js** - Frontend logic

## Comparison with Old Dashboard

| Feature | Old Dashboard | FCS Dashboard |
|---------|--------------|---------------|
| Focus | General billing | **FCS licensing only** |
| Complexity | Many features | **Simple & clean** |
| Key Metric | Various averages | **28-day avg per CID/tag** |
| License Output | Not explicit | **Licenses Required column** |
| Export | 4 types | **2 focused types** |
| Port | 5000 | **5001** |

Both dashboards can run simultaneously:
- **Port 5000**: Full billing dashboard
- **Port 5001**: FCS licensing dashboard

## Quick Example

**Scenario**: You have 3 environments

```
Production:  200 avg sensors → 200 FCS CNAPP licenses
Development: 50 avg sensors  → 50 FCS Runtime licenses
Test:        30 avg sensors  → 30 FCS Runtime licenses
──────────────────────────────────────────────────────
Total:       280 licenses needed
```

Export the tag breakdown CSV and send to finance for accurate cost allocation.
