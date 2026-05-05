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

# Start dashboard and open http://127.0.0.1:8080
falcon-billing dashboard
```

Or use the all-in-one script:

```bash
./run.sh                    # dashboard + collect every 4h
./run.sh --interval 2       # collect every 2h
```

**API Scopes Required:**

| Scope | Falcon Console Name | Used By | Required |
|-------|-------------------|---------|----------|
| `devices:read` | Host Management: Read | `collect` — device query and details | Yes |
| `humio-auth-proxy:write` | Event Search: Write | `collect` — NGSIEM query job submission | Yes |
| `humio-auth-proxy:read` | Event Search: Read | `collect` — NGSIEM query job status polling | Yes |
| `sensor-installers:read` | Sensor Download: Read | `collect` — CID auto-detection (optional, falls back to Hosts API) | No |
| `sensor-usage-api:read` | Sensor Usage API: Read | `query`, `verify` — official billing numbers | No (only for `query`/`verify` commands) |
| `mssp:read` | Flight Control: Read | `multi-tenant` — child CID discovery | No (only for MSSP/Flight Control) |

## How It Works

1. **NGSIEM event search** queries heartbeat events to find all sensors active in each clock hour
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

| Command | Description |
|---------|-------------|
| `collect` | Collect sensor data from NGSIEM + Hosts API |
| `query` | Query Sensor Usage API for official billing numbers |
| `multi-tenant` | Multi-tenant chargeback report |
| `tag-report` | Per-tag host/license count via NGSIEM |
| `verify` | Compare calculated vs API billing averages |
| `prune` | Remove old data from database |
| `dashboard` | Start the web dashboard |

```bash
# Current hour only
falcon-billing collect --days 0

# Backfill last 7 days
falcon-billing collect --days 7

# Collect and auto-prune old data
falcon-billing collect --days 0 --prune
```

## Dashboard

The FCS Licensing dashboard at `http://127.0.0.1:8080` shows:

- **Overall licensing summary** — 28-day avg, peak hourly, hours collected
- **Per-CID breakdown** — licenses required per child CID
- **Per-tag breakdown** — cost allocation by FalconGroupingTags / SensorGroupingTags
- **Filtering and sorting** on all tables
- **CSV export** for CID and tag data

Tag totals will exceed CID totals because hosts with multiple tags are counted in each tag. Use tags for cost allocation, not total license count.

### API Key Authentication

Set `DASHBOARD_API_KEY` to protect all `/api/*` endpoints:

```bash
export DASHBOARD_API_KEY='your-secret-key'
falcon-billing dashboard
```

- **Browser:** enter the key in the popup modal on first visit (stored in localStorage)
- **curl:** pass via header or query param:

```bash
# Header (preferred)
curl -s -H "X-API-Key: your-secret-key" http://127.0.0.1:8080/api/fcs/summary

# Query param (for downloads)
curl -s "http://127.0.0.1:8080/api/fcs/export?type=tag&api_key=your-secret-key" -o tags.csv
```

When `DASHBOARD_API_KEY` is not set, auth is disabled (all endpoints open).

## CSV Export

Export from the dashboard UI via **Export CSV** buttons, or from the command line:

```bash
# By tag
curl -s "http://127.0.0.1:8080/api/fcs/export?type=tag" -o fcs_tags.csv

# By CID
curl -s "http://127.0.0.1:8080/api/fcs/export?type=cid" -o fcs_cids.csv
```

### Sample Output — By CID

```csv
cid,28day_avg,max_hourly,min_hourly,hours_collected,licenses_required
5DDB0407BEF249C19C7A975F17979A1F-90,247.54,275,0,312,248
```

### Sample Output — By Tag

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
| `hours_active` / `hours_collected` | Hours with data in the 28-day window |
| `allocation_units` / `licenses_required` | `ceil(28day_avg)` — licenses needed |

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FALCON_CLIENT_ID` | Yes | — | API client ID |
| `FALCON_CLIENT_SECRET` | Yes | — | API client secret |
| `FALCON_CLOUD_REGION` | No | `us-1` | `us-1`, `us-2`, `eu-1`, `us-gov-1` |
| `FALCON_BILLING_DB` | No | `./sensor_billing.db` | Database path |
| `DASHBOARD_API_KEY` | No | — | API key for dashboard (disabled if unset) |

## NGSIEM Query

The tool queries CrowdStrike NG-SIEM (LogScale) directly via the Humio API to find all sensors active in each clock hour.

**Endpoint:**
```
POST https://api.crowdstrike.com/humio/api/v1/repositories/search-all/queryjobs
```
Region variants: `api.us-2.crowdstrike.com`, `api.eu-1.crowdstrike.com`, `api.laggar.gcw.crowdstrike.com`

**Required scope:** `ngsiem:read`

**Query:**
```
#event_simpleName=AgentOnline OR #event_simpleName=ProcessRollup2 OR #event_simpleName=UserLogon
| groupBy(aid, function=count())
| select([aid])
```

**Request body:**
```json
{
  "queryString": "<query above>",
  "start": 1746399600000,
  "end":   1746403200000,
  "isLive": false
}
```
`start` and `end` are milliseconds since epoch (UTC). Submit the job, then poll `GET {endpoint}/{job_id}` until `done` is `true`.

**Validated behaviour:**
- Active window → `done: true`, `events: [{aid: ...}, ...]`
- Empty/past window → `done: true`, `events: []` — **no error, no cancelled flag**
- The tool logs `NGSIEM query complete: found N unique sensors` on both outcomes

To test the query manually, run `falcon-billing collect --days 0 --verbose` and inspect the logs.

## Project Structure

```
falcon_billing/
  billing.py          # Sensor Usage API queries
  classifier.py       # Product type classification (FCS/FCSC/FMC/EPP)
  collector.py        # NGSIEM + Hosts API data collection
  credentials.py      # Credential loading (env vars / macOS Keychain)
  database.py         # SQLite schema and operations
  ngsiem.py           # NGSIEM event search with retry
  cli/main.py         # CLI entry point with subcommands
  web/
    app.py            # Flask dashboard
    auth.py           # API key authentication
    templates/        # Jinja2 templates
    static/           # CSS and JS
tests/                # 40 unit tests
falcon_billing.spec   # PyInstaller build spec
run.sh                # Dashboard + periodic collection script
```

## Security

- Credentials from environment variables only (never hardcoded)
- Constant-time API key comparison (`hmac.compare_digest`)
- Parameterized SQL queries throughout
- CSV exports sanitized against formula injection
- CDN scripts include Subresource Integrity hashes
- Dashboard binds to `127.0.0.1` only

## License

MIT — see [LICENSE](LICENSE)

---

*Unofficial community tool. Not affiliated with CrowdStrike.*
