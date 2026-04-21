# Falcon Sensor Billing Tool

Collect CrowdStrike Falcon sensor data via NGSIEM event search and calculate 28-day rolling averages for FCS licensing and tag-based cost allocation.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Quick Start

```bash
# Set credentials
export FALCON_CLIENT_ID='your_client_id'
export FALCON_CLIENT_SECRET='your_client_secret'
export FALCON_CLOUD_REGION='us-1'  # or us-2, eu-1, us-gov-1

# Collect current hour
falcon-billing collect --days 0

# Start dashboard
falcon-billing dashboard
# Open http://127.0.0.1:8080
```

Or use the all-in-one script:

```bash
./run.sh                    # dashboard + collect every 4h
./run.sh --interval 2       # collect every 2h
```

**API Scopes Required:** `hosts:read` and `ngsiem:read`

## How It Works

1. **NGSIEM event search** queries heartbeat events (`AgentOnline`, `ProcessRollup2`, `UserLogon`) to find all sensors active in each clock hour
2. **Hosts API** enriches each sensor with hostname, platform, tags, and cloud metadata
3. **SQLite database** stores hourly sensor logs and pre-aggregated tag counts
4. **28-day rolling average** = SUM(hourly unique sensor counts) / hours collected
5. **Dashboard** displays per-CID and per-tag license requirements

## Installation

### From Binary (macOS ARM64)

Download from [Releases](https://github.com/yannhowe/falcon-sensor-billing-tool/releases):

```bash
chmod +x falcon-billing
./falcon-billing --help
```

### From Source

```bash
pip install -r requirements.txt
python -m falcon_billing.cli.main --help
```

### Build Binary

```bash
pip install pyinstaller
pyinstaller --clean falcon_billing.spec
# Output: dist/falcon-billing
```

## CLI Commands

```
falcon-billing collect     Collect sensor data from NGSIEM + Hosts API
falcon-billing query       Query Sensor Usage API for official billing numbers
falcon-billing multi-tenant  Multi-tenant chargeback report
falcon-billing tag-report  Per-tag host/license count via NGSIEM
falcon-billing verify      Compare calculated vs API billing averages
falcon-billing prune       Remove old data from database
falcon-billing dashboard   Start the web dashboard
```

### Collect

```bash
# Current hour only
falcon-billing collect --days 0

# Backfill last 7 days
falcon-billing collect --days 7

# Collect and auto-prune old data
falcon-billing collect --days 0 --prune
```

### Dashboard

```bash
falcon-billing dashboard              # default port 8080
falcon-billing dashboard --port 9090  # custom port

# Protect with API key
export DASHBOARD_API_KEY='your-secret-key'
falcon-billing dashboard
```

## Dashboard

The FCS Licensing dashboard shows:

- **Overall licensing summary** — 28-day avg, peak hourly, hours collected
- **Per-CID breakdown** — licenses required per child CID
- **Per-tag breakdown** — cost allocation by FalconGroupingTags / SensorGroupingTags
- **Filtering and sorting** on all tables
- **CSV export** for CID and tag data

Tag totals will exceed CID totals because hosts with multiple tags are counted in each tag. Use tags for cost allocation, not total license count.

## CSV Export

The dashboard exports two CSV types via **Export CSV** buttons:

### By CID

```csv
cid,28day_avg,max_hourly,min_hourly,hours_collected,licenses_required
5DDB0407BEF249C19C7A975F17979A1F-90,247.54,275,0,312,248
```

### By Tag

```csv
tag,28day_avg,max_hourly,hours_active,allocation_units
FalconGroupingTags/KGTestBulkTag,59.81,65,310,60
FalconGroupingTags/Linux86,50.74,52,310,51
FalconGroupingTags/SVCSDEPLOY-TEST,44.80,47,310,45
```

| Column | Description |
|--------|-------------|
| `28day_avg` | Average unique sensors per hour over the collection window |
| `max_hourly` | Peak sensors seen in any single hour |
| `hours_active` / `hours_collected` | Hours this tag/CID had data (out of collection window) |
| `allocation_units` / `licenses_required` | `ceil(28day_avg)` — licenses needed |

**Note:** Tag allocation units will sum to more than CID licenses because multi-tagged hosts count in each tag.

## Project Structure

```
falcon_billing/
  __init__.py
  billing.py          # Sensor Usage API queries
  classifier.py       # Product type classification (FCS/FCSC/FMC/EPP)
  collector.py        # NGSIEM + Hosts API data collection
  credentials.py      # Credential loading (env vars / macOS Keychain)
  database.py         # SQLite schema and operations
  ngsiem.py           # NGSIEM event search with retry
  cli/
    main.py           # CLI entry point with subcommands
  web/
    app.py            # Flask dashboard
    auth.py           # API key authentication
    templates/        # Jinja2 templates
    static/           # CSS and JS
tests/                # 40 unit tests
falcon_billing.spec   # PyInstaller build spec
run.sh                # Dashboard + periodic collection script
```

## Database

SQLite database (`sensor_billing.db`) with WAL mode:

| Table | Purpose |
|-------|---------|
| `sensor_logs` | Per-hour sensor activity with host details and tags |
| `hourly_counts` | Aggregated sensor counts per hour per CID |
| `hourly_tag_counts` | Pre-aggregated counts per tag |
| `host_metadata_cache` | Cached host details (configurable TTL) |
| `audit_log` | Operation audit trail |

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FALCON_CLIENT_ID` | Yes | — | API client ID |
| `FALCON_CLIENT_SECRET` | Yes | — | API client secret |
| `FALCON_CLOUD_REGION` | No | `us-1` | `us-1`, `us-2`, `eu-1`, `us-gov-1` |
| `FALCON_BILLING_DB` | No | `./sensor_billing.db` | Database path |
| `DASHBOARD_API_KEY` | No | — | API key for dashboard (disabled if unset) |
| `DASHBOARD_NO_AUTH` | No | — | Set to `1` to disable auth |

## Security

- Credentials loaded from environment variables (never hardcoded)
- API key comparison uses constant-time `hmac.compare_digest`
- All SQL queries use parameterized statements
- CSV exports sanitized against formula injection
- CDN scripts include Subresource Integrity hashes
- Dashboard binds to `127.0.0.1` only

## License

MIT — see [LICENSE](LICENSE)

---

*Unofficial community tool. Not affiliated with CrowdStrike. For official tools, visit [github.com/CrowdStrike](https://github.com/CrowdStrike).*
