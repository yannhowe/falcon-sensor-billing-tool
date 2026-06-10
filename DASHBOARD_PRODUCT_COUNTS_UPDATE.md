# Dashboard Update: Product Type Counts

## Changes Made ✅

### 1. Top Statistics Cards (index.html:18-49)
**Before**: Generic stats (Total Sensors, Hours, Average, Tags)

**After**: Product type breakdown with counts and colors
- 🐳 **FCSC** - Container Hosts (Blue border)
- 🚀 **FMC** - Fargate/Sidecars (Orange border)
- ☁️ **FCS** - Cloud VMs (Green border)
- 💻 **EPP** - Traditional Endpoints (Purple border)

Each card shows:
- Unique host count (large number)
- 28-day rolling average (small text below)

### 2. Info Bar (index.html:52-56)
**Updated** to show overall stats:
- Total Sensors
- 28-Day Average
- Data Range
- Hours Collected

### 3. JavaScript (app.js:7-75)
**Added** `loadProductCounts()` function:
- Fetches from `/api/product_breakdown`
- Updates all 4 product cards
- Runs on page load (first priority)

### 4. API Endpoint (web_dashboard.py:494-558)
**Simplified** `/api/product_breakdown`:
- Gets counts from `host_metadata_cache`
- Calculates 28-day rolling averages
- Returns all 4 product types (even if 0)

## Current Dashboard View

### Top Cards (Primary View)
```
┌─────────────────────────────────────────────────────────────┐
│  🐳 FCSC                 🚀 FMC                              │
│  8                       0                                   │
│  28-day avg: 8.0         28-day avg: 0.0                    │
│                                                              │
│  ☁️ FCS                  💻 EPP                              │
│  250                     221                                 │
│  28-day avg: 250.0       28-day avg: 221.0                  │
└─────────────────────────────────────────────────────────────┘
```

### Info Bar
```
📊 Total: 479  |  📈 28-Day Avg: 479.0  |  📅 Apr 7 - Apr 14  |  ⏱️ 169 hours
```

## API Response

```bash
curl "http://localhost:5000/api/product_breakdown"
```

Returns:
```json
{
  "products": [
    {
      "product_type": "EPP",
      "unique_sensors": 221,
      "avg_28day": 221.0
    },
    {
      "product_type": "FCS",
      "unique_sensors": 250,
      "avg_28day": 250.0
    },
    {
      "product_type": "FCSC",
      "unique_sensors": 8,
      "avg_28day": 8.0
    },
    {
      "product_type": "FMC",
      "unique_sensors": 0,
      "avg_28day": 0.0
    }
  ],
  "total_avg_28day": 479.0
}
```

## How to View

```bash
# Start the dashboard
./start_dashboard.sh

# Or manually:
python3 web_dashboard.py

# Open browser to:
http://localhost:5000
```

## Product Type Descriptions

| Icon | Code | Name | Description | Current Count |
|------|------|------|-------------|---------------|
| 🐳 | FCSC | Falcon Cloud Security Complete | Container hosts (K8s, Docker) | 8 |
| 🚀 | FMC | Falcon Managed Cloud | Fargate, sidecars, serverless | 0 |
| ☁️ | FCS | Falcon Cloud Security | Cloud VMs (AWS, Azure, GCP) | 250 |
| 💻 | EPP | Endpoint Protection Platform | Traditional endpoints, laptops, servers | 221 |

## Files Modified

1. **`templates/index.html`**
   - Replaced generic stats cards with product type cards
   - Added color-coded borders
   - Updated info bar

2. **`static/app.js`**
   - Added `loadProductCounts()` function
   - Removed references to deleted elements
   - Prioritized product counts on page load

3. **`web_dashboard.py`**
   - Simplified `/api/product_breakdown` endpoint
   - Uses `host_metadata_cache` for accurate counts
   - Calculates 28-day rolling averages from logs

4. **`start_dashboard.sh`** (NEW)
   - Quick start script with helpful info

## Testing

The API was tested and returns correct data:
- **FCSC**: 8 hosts (K8s platforms)
- **FCS**: 250 hosts (cloud VMs detected via hardware)
- **EPP**: 221 hosts (traditional endpoints)
- **FMC**: 0 hosts (pending detection method)

All data is live from the database and updates automatically.

## Next Steps

When NGSIEM queries complete:
1. Run `python3 load_indicators.py`
2. Run `python3 classify_with_indicators.py`
3. Refresh dashboard - counts will update automatically

The dashboard will show:
- More accurate FCSC counts (with OciContainerId data)
- More accurate FCS counts (with IMDS traffic data)
- Potentially some FMC hosts (if Fargate detection implemented)

