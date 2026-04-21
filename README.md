# CrowdStrike Falcon Sensor Billing Tool

Query CrowdStrike's Falcon Sensor Usage APIs for billing and chargeback. Get 28-day rolling averages for all sensor types (cloud VMs, containers, workstations, servers, mobile) with optional granular tracking for cost allocation by tags.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

## Features

- 📊 **Official billing data** from CrowdStrike Sensor Usage API
- 🏢 **Multi-tenant support** with auto-discovery of child CIDs (Flight Control)
- 🌐 **Web dashboard** with interactive charts and CSV export
- 🏷️ **Tag-based cost allocation** for sub-CID billing
- 📈 **Trend analysis** with historical data (up to 395 days)
- ⚡ **Smart caching** reduces API calls by 95%

---

## Quick Start

```bash
# 1. Install
pip install crowdstrike-falconpy

# 2. Set credentials
export FALCON_CLIENT_ID='your_client_id'
export FALCON_CLIENT_SECRET='your_client_secret'
export FALCON_CLOUD_REGION='us-1'  # or us-2, eu-1, us-gov-1

# 3. Get billing data
python3 falcon_sensor_billing.py --hourly

# 4. View in web dashboard
python3 web_dashboard.py
# Open http://localhost:5000
```

**API Scopes Required:** `sensor-usage-api:read`, optionally `hosts:read` and `ngsiem:read` for granular tracking.

See [API_SCOPES.md](API_SCOPES.md) for setup instructions.

**Security Note:** This tool is designed for local use and binds to `localhost` only. Credentials are loaded from environment variables (never hardcoded), and all database queries use parameterized statements to prevent SQL injection.

---

## Usage

### Get Billing Numbers

```bash
# Falcon Cloud Security / Containers (hourly average)
python3 falcon_sensor_billing.py --hourly

# Traditional endpoints (weekly average)
python3 falcon_sensor_billing.py
```

Output shows 28-day rolling average - use the **latest value** for billing.

### Multi-Tenant Chargeback

```bash
# Auto-discover all child CIDs (Flight Control)
python3 falcon_sensor_billing.py --hourly --multi-tenant --auto-discover

# Or specify CIDs manually
python3 falcon_sensor_billing.py --hourly --multi-tenant "cid1,cid2,cid3"
```

### Web Dashboard

```bash
# Start interactive dashboard
python3 web_dashboard.py

# Features:
# - Real-time statistics and charts
# - CSV export (hourly, daily, by tag)
# - Licensing compliance calculator
# - Tag breakdown for cost allocation
```

See [WEB_DASHBOARD.md](WEB_DASHBOARD.md) for details.

### Granular Tracking (Optional)

Collect hourly sensor data with tags for sub-CID cost allocation:

```bash
# Collect sensor activity for previous hour
python3 falcon_sensor_billing.py --collect-hourly

# Run via cron every hour
5 * * * * cd /path/to/tool && python3 falcon_sensor_billing.py --collect-hourly
```

Creates SQLite database with:
- Sensor activity logs per hour with tags
- Tag-based cost allocation queries
- Audit trails for billing disputes
- Growth trend analysis

**Note:** Granular tracking provides supplementary data for cost allocation. Always use the Sensor Usage API (`--hourly`) for official billing numbers.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  CrowdStrike Sensor Usage API (Official Billing)            │
│  └─ 28-day rolling average (672 hours)                      │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  falcon_sensor_billing.py                                    │
│  └─ Query API and export CSV/JSON                           │
└─────────────────────────────────────────────────────────────┘
                          ↓
              ┌───────────┴──────────┐
              ↓                      ↓
┌──────────────────────┐  ┌──────────────────────┐
│  CSV/JSON Export     │  │  SQLite Database     │
│  └─ Monthly billing  │  │  └─ Granular tracking│
└──────────────────────┘  └──────────────────────┘
                                     ↓
                          ┌──────────────────────┐
                          │  Web Dashboard       │
                          │  └─ localhost:5000   │
                          └──────────────────────┘
```

### Data Sources

**Primary: Sensor Usage API**
- Official CrowdStrike billing calculation
- 28-day rolling average (updated daily)
- Aggregated by workload type
- Use for: **Billing and invoicing**

**Optional: Granular Tracking**
- NGSIEM Event Search + Hosts API
- Hourly sensor activity with tags
- Tag-based cost allocation
- Use for: **Audit trails and sub-CID allocation**

---

```
falcon-sensor-billing-tool/
├── falcon_sensor_billing.py    # Main script - billing API queries
├── billing_collector.py         # Hourly sensor collection (NGSIEM + Hosts API)
├── web_dashboard.py             # Flask web dashboard with CSV export
├── billing_database.py          # SQLite database operations
├── ngsiem_event_search.py       # Standalone NGSIEM test script
├── requirements.txt             # Python dependencies
├── tenants.txt.example          # Example multi-tenant config
│
├── templates/                   # Web dashboard HTML templates
│   └── index.html              # Main dashboard page
├── static/                      # CSS and JavaScript for web interface
│   ├── style.css               # Dashboard styling
│   └── app.js                  # Frontend JavaScript
│
├── README.md                    # This file
├── API_SCOPES.md               # Required API scopes and setup
├── NGSIEM_INTEGRATION.md       # NGSIEM implementation details
├── WEB_DASHBOARD.md            # Web dashboard and CSV export guide
├── LICENSE                     # MIT License
│
└── sensor_billing.db           # SQLite database (created on first run)
```

### Core Files

| File | Purpose |
|------|---------|
| **falcon_sensor_billing.py** | Query billing API for 28-day averages |
| **billing_collector.py** | Collect granular hourly sensor data with NGSIEM |
| **web_dashboard.py** | Flask web interface with interactive charts and CSV export |
| **billing_database.py** | SQLite database schema and operations |
| **ngsiem_event_search.py** | Test NGSIEM Event Search API standalone |

### Documentation

| File | Description |
|------|-------------|
| **README.md** | Main documentation (this file) |
| **API_SCOPES.md** | API scope requirements and setup guide |
| **WEB_DASHBOARD.md** | Web dashboard and CSV export guide |
| **FCS_DASHBOARD.md** | FCS licensing dashboard guide |

### Database

**sensor_billing.db** - SQLite database with 5 tables:
- `sensor_logs` - Granular sensor activity per hour with tags
- `hourly_counts` - Aggregated sensor counts per hour
- `hourly_tag_counts` - Pre-aggregated counts per tag
- `host_metadata_cache` - Cached host details (24h TTL)
- `billing_averages` - Official billing API data for verification

---

## Usage

### Option 1: Web Dashboard (Recommended)

```bash
# Start the interactive web interface
python3 web_dashboard.py

# Open browser to http://localhost:5000
# - View real-time statistics and interactive charts
# - Calculate licensing compliance (Reserved Hourly Avg & Per-Hour)
# - Export data as CSV (hourly, daily, tags, sensors)
# - Time range selection (1, 3, 7, 14, 28 days)
# - Tag breakdown for cost allocation
```

**See [WEB_DASHBOARD.md](WEB_DASHBOARD.md) for complete web dashboard documentation.**

### Option 2: Command Line

#### Default: Get Latest Billing Data

```bash
# For Falcon Cloud Security / FMC (hourly average)
python3 falcon_sensor_billing.py --hourly

# For traditional endpoints (weekly average)
python3 falcon_sensor_billing.py
```

By default, retrieves **28 days** of data (standard billing period).

### Get More History

```bash
# Get 90 days of historical data
export PERIOD_DAYS=90
python3 falcon_sensor_billing.py --hourly

# Get entire year
export PERIOD_DAYS=365
python3 falcon_sensor_billing.py --hourly
```

### Query Specific CIDs

```bash
# Multi-tenant / MSP use case - Query each CID separately for chargeback
export SELECTED_CIDS='tenant1_cid'
python3 falcon_sensor_billing.py --hourly

export SELECTED_CIDS='tenant2_cid'
python3 falcon_sensor_billing.py --hourly

export SELECTED_CIDS='tenant3_cid'
python3 falcon_sensor_billing.py --hourly
```

**Important for Multi-Tenant Chargeback:** The API aggregates CIDs when queried together. For per-tenant billing, query each CID separately to get individual usage numbers.

---

## Which Flag?

| Product | Flag |
|---------|------|
| Falcon Cloud Security (FCS) | `--hourly` |
| Falcon Managed Containers (FMC) | `--hourly` |
| Cloud workloads | `--hourly` |
| Traditional endpoints (workstations/servers) | (no flag) |

**Why?** FCS/FMC uses hourly billing (672-hour average). Traditional endpoints use weekly billing (4-week average).

Reference: [CrowdStrike Licensing FAQ](https://www.crowdstrike.com/en-us/legal/crowdstrike-licensing/)

---

## Output

### All Available Fields

The script fetches these fields from the API:

| CSV Column | API Field | Description |
|------------|-----------|-------------|
| `managed_containers` | `lumos` | **FMC - Falcon Managed Containers** (KEY BILLING FIELD) |
| `cloud_vms` | `public_cloud_without_containers` | Cloud VMs (AWS, Azure, GCP) |
| `container_hosts` | `containers` | Total container hosts |
| `public_cloud_containers` | `public_cloud_with_containers` | Public cloud with containers |
| `server_containers` | `servers_with_containers` | On-prem servers with containers |
| `servers` | `servers_without_containers` | On-prem servers without containers |
| `workstations` | `workstations` | Desktops/laptops |
| `mobile` | `mobile` | Mobile devices |
| `chrome_os` | `chrome_os` | ChromeOS devices |

### CSV Sample

```csv
date,managed_containers,cloud_vms,container_hosts,servers,workstations,mobile
2026-03-30,104.39,32460.74,14444.52,98085.29,9320.69,197.31
2026-03-29,104.50,32551.29,14458.41,97917.60,9315.54,198.42
```

**Key column:** `managed_containers` = Your FMC billing number

**Files saved to:**
- CSV: `/var/log/falcon-usage/falcon_usage_hourly_YYYYMMDD_HHMMSS.csv`
- JSON: `/var/log/falcon-usage/falcon_usage_hourly_YYYYMMDD_HHMMSS.json`

---

## Understanding the Numbers

**Each value is already averaged** - just use the latest row for billing:

- **Hourly average** (`--hourly`): Average sensors per hour over 28 days
  - Example: `104.39` = 104.39 containers active per hour (on average)
  - Calculation: Sum of 672 hourly counts ÷ 672

- **Weekly average** (default): Average sensors per week over 4 weeks
  - Example: `2362.75` = 2,362.75 unique sensors per week (on average)

### What to Charge

The script output shows:
- **Latest value**: Use this for your monthly bill amount
- **Max value**: Highest average seen over the period (for reference/trending)

**For billing:** Use the **latest** `managed_containers` value from the CSV.

Example output:
```
Latest data point: 2026-03-30
  Managed Containers: 104.39 (FMC - for chargeback)

Max values over 28 days:
  Max Managed Containers: 107.50

💰 CHARGEBACK AMOUNT: 104.39 FMC sensors
```

**Bill for:** 104.39 (or round to 105 sensors)

---

## Common Use Cases

### Monthly Billing

```bash
# Run once at end of month
python3 falcon_sensor_billing.py --hourly

# Get billing number
tail -1 /var/log/falcon-usage/falcon_usage_hourly_*.csv | cut -d',' -f4
```

### Annual Report

```bash
# Get full year
export PERIOD_DAYS=365
python3 falcon_sensor_billing.py --hourly
```

### Customer Onboarding

```bash
# Show 6 months of history
export PERIOD_DAYS=180
python3 falcon_sensor_billing.py --hourly
```

### MSP / Multi-Tenant Chargeback

**Easiest Mode: Auto-discover Child CIDs**

If you're a Flight Control parent CID, automatically fetch all your child CIDs:

```bash
python3 falcon_sensor_billing.py --hourly --multi-tenant --auto-discover
```

**Output:**
```
🔍 Auto-discovering child CIDs from Flight Control parent...
✓ Found 3 child CID(s)

[1/3] Querying Acme Corp (abc123def456)... ✓ 104.39 FMC
[2/3] Querying Wayne Enterprises (ghi789jkl012)... ✓ 87.50 FMC
[3/3] Querying Stark Industries (mno345pqr678)... ✓ 120.86 FMC

CHARGEBACK SUMMARY
======================================================================
Tenant                         CID                      FMC Sensors
----------------------------------------------------------------------
Acme Corp                      abc123def456                   104.39
Wayne Enterprises              ghi789jkl012                    87.50
Stark Industries               mno345pqr678                   120.86
----------------------------------------------------------------------
TOTAL                                                         312.75
======================================================================
```

**From File:**

```bash
# Create tenants file (one per line: CID or CID,TenantName)
cat > tenants.txt << 'EOF'
abc123def456,Acme Corp
ghi789jkl012,Wayne Enterprises
mno345pqr678,Stark Industries
EOF

# Run multi-tenant mode
python3 falcon_sensor_billing.py --hourly --multi-tenant @tenants.txt
```

**Or provide CIDs directly:**
```bash
python3 falcon_sensor_billing.py --hourly --multi-tenant "cid1,cid2,cid3"
```

The script automatically queries each tenant separately and creates a combined chargeback report!

---

## Configuration

### Required

- `FALCON_CLIENT_ID` - API client ID
- `FALCON_CLIENT_SECRET` - API secret

### Optional

- `FALCON_CLOUD_REGION` - Cloud region (default: `us-1`)
  - Options: `us-1`, `us-2`, `eu-1`, `us-gov-1`
- `PERIOD_DAYS` - Days to retrieve (default: `28`, max: `395`)
- `SELECTED_CIDS` - Comma-separated child CIDs
- `USAGE_LOG_DIR` - Output directory (default: `/var/log/falcon-usage`)

### Save Credentials (Optional)

```bash
cat > ~/.falcon_usage_env << 'EOF'
export FALCON_CLIENT_ID='your_client_id'
export FALCON_CLIENT_SECRET='your_client_secret'
export FALCON_CLOUD_REGION='us-1'
EOF

chmod 600 ~/.falcon_usage_env
source ~/.falcon_usage_env
```

---

## API Details

- **History:** Up to 395 days back
- **Latest data:** Current date minus 2 days
- **Endpoints:**
  - Hourly: `/billing-dashboards-usage/aggregates/hourly-average/v1`
  - Weekly: `/billing-dashboards-usage/aggregates/weekly-average/v1`
  - Child CID Discovery: `/mssp/queries/children/v1` and `/mssp/entities/children/v1`

---

## Requirements

- Python 3.6+
- `crowdstrike-falconpy` library
- **API Credentials with required scopes:**
  - `sensor-usage-api:read` - For fetching billing data (required)
  - `mssp:read` - For auto-discovering child CIDs (optional, Flight Control only)

See [API_SCOPES.md](API_SCOPES.md) for detailed scope requirements and troubleshooting.

---

## Troubleshooting

**No data returned?**
- Data only available for current date minus 2 days
- Check credentials and API scope

**Wrong numbers?**
- FCS/FMC: Use `--hourly`
- Traditional: Use default (no flag)

---

## Database Tracking (NEW!)

The tool now includes **SQLite database tracking** for granular hourly sensor data with full host details and tags. This enables:

- **Sub-CID billing** - Allocate costs by sensor tags (team, environment, AWS account, etc.)
- **Audit trails** - Show which specific hosts were active each hour for billing disputes
- **Verification** - Compare calculated 28-day averages against billing API
- **Capacity planning** - Analyze sensor growth trends over time
- **Host metadata caching** - 95% cache hit rate dramatically reduces API calls

### Features

#### 5 Database Tables

1. **sensor_logs** - Granular sensor activity per hour with full host details and tags
2. **hourly_counts** - Aggregated sensor counts per hour per CID
3. **hourly_tag_counts** - Pre-aggregated counts per tag for fast sub-CID queries
4. **host_metadata_cache** - Cached host details (24h TTL, auto-refresh)
5. **billing_averages** - Official billing API data for verification

#### Smart Caching

- **First collection:** ~1000 API calls (cache miss)
- **Subsequent collections:** ~50 API calls (95% cache hit)
- **Cache TTL:** 24 hours (auto-refresh stale entries)
- **Result:** 20x reduction in API calls for stable environments

### Usage Examples

#### Collect Hourly Sensor Data

```bash
# Collect sensor data for previous hour (run via cron every hour)
python3 falcon_sensor_billing.py --collect-hourly

# Cron example: Run at minute 5 of every hour
5 * * * * cd /path/to/tool && python3 falcon_sensor_billing.py --collect-hourly >> cron.log 2>&1
```

#### Combine Billing API + Collection

```bash
# Query billing API AND collect granular data in one run
python3 falcon_sensor_billing.py --hourly --collect-hourly
```

#### Verification Report

```bash
# Generate monthly verification report (March 2026)
python3 falcon_sensor_billing.py --verify --start-date 2026-03-01 --end-date 2026-03-31

# Output: verification_reports/verification_2026-03-01_2026-03-31.csv
# Columns: date, calculated_avg, api_avg, diff, diff_pct, status (PASS/FAIL)
```

### Database Queries

#### Sub-CID Billing by Tags

```bash
# Calculate 28-day average per tag
sqlite3 sensor_billing.db "
  SELECT
    tag,
    SUM(unique_sensor_count) / 672.0 as avg_28day,
    SUM(unique_sensor_count) as total_sensor_hours
  FROM hourly_tag_counts
  WHERE hour_timestamp >= date('now', '-28 days')
  AND cid = 'default'
  GROUP BY tag
  ORDER BY avg_28day DESC
"
```

**Example Output:**
```
tag                    avg_28day    total_sensor_hours
---------------------  -----------  ------------------
production             1250.45      840302
aws-us-east-1          823.12       553137
team-platform          456.78       306956
development            342.91       230435
```

#### Audit Trail for Billing Dispute

```bash
# Show all sensors active during a specific hour
sqlite3 sensor_billing.db "
  SELECT
    hostname,
    platform_name,
    tags,
    last_seen
  FROM sensor_logs
  WHERE hour_timestamp = '2026-03-15 14:00:00'
  ORDER BY hostname
" > disputed_hour_sensors.csv
```

#### Growth Trend Analysis

```bash
# Daily average and peak sensor counts for 90 days
sqlite3 sensor_billing.db -header -csv "
  SELECT
    DATE(hour_timestamp) as date,
    AVG(unique_sensor_count) as daily_avg,
    MAX(unique_sensor_count) as daily_peak,
    MIN(unique_sensor_count) as daily_min
  FROM hourly_counts
  WHERE hour_timestamp >= date('now', '-90 days')
  AND cid = 'default'
  GROUP BY date
  ORDER BY date
" > growth_trend.csv
```

#### Cache Performance Monitoring

```bash
# Check cache statistics
sqlite3 sensor_billing.db "
  SELECT
    COUNT(*) as total_cached_hosts,
    SUM(CASE WHEN datetime(last_updated) > datetime('now', '-24 hours')
        THEN 1 ELSE 0 END) as fresh_cache,
    SUM(CASE WHEN datetime(last_updated) <= datetime('now', '-24 hours')
        THEN 1 ELSE 0 END) as stale_cache
  FROM host_metadata_cache
"
```

### Data Retention

- **Unlimited retention** - No automatic purging
- **Database growth:** ~1-2GB per year per 1000 sensors
- **Indexes:** Optimized for fast queries on hour, tag, and sensor_id

### API Scopes Required

For database tracking, you need additional API scopes:

- `sensor-usage-api:read` - Billing API (existing)
- **`hosts:read` - Host details and tags (NEW)**
- `mssp:read` - Auto-discover child CIDs (optional)

See [API_SCOPES.md](API_SCOPES.md) for detailed instructions on creating API clients with all required scopes.

### Verification System

The verification system compares your calculated 28-day averages with CrowdStrike's official billing API:

**Verification workflow:**
1. Calculate 28-day average from `hourly_counts` table (sum of 672 hours ÷ 672)
2. Query `billing_averages` table for official API value
3. Compare: difference should be < 1%
4. Generate CSV report with PASS/FAIL status per day

**Use cases:**
- Monthly reconciliation with accounting
- Billing dispute resolution
- Validate data collection accuracy

**Example verification report:**
```csv
date,calculated_avg,api_avg,diff,diff_pct,status
2026-03-01,1250.45,1251.23,-0.78,-0.06%,PASS
2026-03-02,1248.91,1249.12,-0.21,-0.02%,PASS
2026-03-03,1252.34,1250.11,2.23,0.18%,PASS
```

### Database Location

- **Default:** `sensor_billing.db` in project directory
- **Portable:** Can be moved/backed up like any SQLite database
- **Concurrent:** WAL mode allows simultaneous reads during collection

### Implementation Status

**✅ NGSIEM Event Search:** Now implemented for 100% accurate sensor tracking
- Queries heartbeat events (AgentOnline, ProcessRollup2, UserLogon) via Humio/LogScale API
- Captures ALL sensors active during target hour, even if briefly online
- Matches CrowdStrike's billing calculation method exactly
- Requires `ngsiem:read` API scope (optional - auto-falls back to Hosts API)

**✅ Smart Fallback:** Automatically uses Hosts API if NGSIEM unavailable
- 95%+ accuracy with Hosts API `last_seen` filter
- 95%+ cache hit rate dramatically reduces API calls
- Works without NGSIEM scope (degrades gracefully)

### Limitations

- **Maximum 5000 devices per query:** Paginated automatically by tool
- **24-hour cache TTL:** Tradeoff between API call reduction and metadata freshness
- **NGSIEM query timeout:** Queries can take 30-120 seconds for large datasets

**Note on Data Visibility:** In multi-tenant environments (Flight Control), API credentials may have limited visibility. Always use the Sensor Usage API (`--hourly`) for official billing numbers. Database collection provides supplementary data for audit trails and cost allocation within your accessible scope.

---

## Documentation

| File | Purpose |
|------|---------|
| **README.md** | Main documentation (this file) |
| **[API_SCOPES.md](API_SCOPES.md)** | API scope requirements and setup guide |
| **[WEB_DASHBOARD.md](WEB_DASHBOARD.md)** | Web dashboard usage and CSV export |
| **[FCS_DASHBOARD.md](FCS_DASHBOARD.md)** | FCS licensing dashboard guide |
| **[NGSIEM_INTEGRATION.md](NGSIEM_INTEGRATION.md)** | NGSIEM Event Search technical details |
| **[LICENSING_COMPLIANCE.md](LICENSING_COMPLIANCE.md)** | License compliance calculator |
| **[CRON_INSTALLATION.md](CRON_INSTALLATION.md)** | Automated hourly collection setup |
| **[SECURITY_FIXES_APPLIED.md](SECURITY_FIXES_APPLIED.md)** | Security improvements summary |
| **[SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md)** | Full security audit report |

## License

MIT - see [LICENSE](LICENSE)

---

*Unofficial community tool. For official tools, visit [github.com/CrowdStrike](https://github.com/CrowdStrike).*
